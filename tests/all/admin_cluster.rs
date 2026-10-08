//! Cluster-wide admin listings (searchAccounts, getInviteCodes): in-process
//! nodes sharing one in-memory object store form a real cluster (leases,
//! shard handoff, forwarding); any node's admin listing scatter-gathers over
//! /internal/v1/admin/* and pages across every node's shards, and a dead peer
//! is reported instead of silently dropped.

use crate::common::*;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

const SHARDS: u32 = 8;

async fn node(id: &str, store: &Arc<object_store::memory::InMemory>) -> TestServer {
    cluster_node(id, store.clone(), SHARDS, |_| {}).await
}

/// Every page of `nsid` (key `items`) at `limit`, following cursors.
async fn all_pages(s: &TestServer, nsid: &str, items: &str, extra: &[(&str, &str)], limit: usize) -> (Vec<J>, Vec<J>) {
    let (mut out, mut pages) = (Vec::new(), Vec::new());
    let mut cursor: Option<String> = None;
    for _ in 0..100 {
        let lim = limit.to_string();
        let mut q: Vec<(&str, &str)> = extra.to_vec();
        q.push(("limit", &lim));
        if let Some(c) = &cursor {
            q.push(("cursor", c));
        }
        let r = s.xrpc.get(nsid, &q, &Auth::Admin).await.ok();
        assert!(r.get("unreachableNodes").is_none() && r.get("missingShards").is_none(), "complete cluster: {r}");
        let page = r[items].as_array().unwrap().clone();
        assert!(page.len() <= limit);
        out.extend(page);
        pages.push(r.clone());
        match r["cursor"].as_str() {
            Some(c) => cursor = Some(c.to_string()),
            None => return (out, pages),
        }
    }
    panic!("too many pages");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn admin_listings_scatter_gather_across_nodes() {
    let store = Arc::new(object_store::memory::InMemory::new());
    let a = node("adm-a", &store).await;
    let b = node("adm-b", &store).await;
    let c = node("adm-c", &store).await;
    balanced(&[&a, &b, &c]).await;

    // accounts minted on each node land on that node's shards
    let tag = unique_name("sg");
    let mut want = Vec::new();
    for (i, n) in [&a, &b, &c].iter().enumerate() {
        for j in 0..3 {
            let handle = format!("{tag}{i}x{j}.{HANDLE_DOMAIN}");
            want.push(n.create_account_with(&handle, PASSWORD).await);
        }
    }
    let owners: HashSet<String> = want.iter().map(|t| owner_of(&[&a, &b, &c], &t.did).url.clone()).collect();
    assert_eq!(owners.len(), 3, "accounts spread over all three nodes");

    // email-prefix search from any node, paged 2 at a time, sees all 9 in
    // (slot, did) order (layout-independent) with no duplicates
    let prefix = tag.to_ascii_lowercase();
    let slot = |d: &str| vlsync_store::slots::slot_of(d);
    for s in [&a, &b, &c] {
        let (got, pages) = all_pages(s, "com.atproto.admin.searchAccounts", "accounts", &[("email", &prefix)], 2).await;
        let dids: Vec<String> = got.iter().map(|v| v["did"].as_str().unwrap().to_string()).collect();
        let mut sorted = dids.clone();
        sorted.sort_by_key(|d| (slot(d), d.clone()));
        assert_eq!(dids, sorted, "merged in (slot, did) order");
        let mut expect: Vec<String> = want.iter().map(|t| t.did.clone()).collect();
        expect.sort_by_key(|d| (slot(d), d.clone()));
        assert_eq!(dids, expect, "every account exactly once");
        // the views come from the owning node (handle, email, invites)
        let h = got.iter().find(|v| v["did"] == want[4].did.as_str()).unwrap();
        assert_eq!(h["handle"], want[4].handle.as_str());
        assert_eq!(h["email"], want[4].email.to_ascii_lowercase().as_str());
        assert!(pages.len() >= 5, "9 accounts at 2 per page");
    }

    // invite codes, created through every node (stored on whichever shard
    // `_invite:{code}` hashes to, possibly a peer's)
    let mut codes = Vec::new();
    for s in [&a, &b, &c] {
        let r = s
            .xrpc
            .post("com.atproto.server.createInviteCodes", &json!({"codeCount": 3, "useCount": 1}), &Auth::Admin)
            .await
            .ok();
        for c in r["codes"][0]["codes"].as_array().unwrap() {
            codes.push(c.as_str().unwrap().to_string());
        }
        tokio::time::sleep(Duration::from_millis(5)).await; // distinct createdAt per batch
    }
    for sort in ["recent", "usage"] {
        for s in [&a, &c] {
            let (got, _) = all_pages(s, "com.atproto.admin.getInviteCodes", "codes", &[("sort", sort)], 2).await;
            let listed: Vec<String> = got.iter().map(|v| v["code"].as_str().unwrap().to_string()).collect();
            let uniq: HashSet<&String> = listed.iter().collect();
            assert_eq!(uniq.len(), listed.len(), "no duplicates across pages ({sort})");
            for c in &codes {
                assert!(listed.contains(c), "{c} missing from cluster-wide getInviteCodes ({sort})");
            }
            if sort == "recent" {
                let keys: Vec<(String, String)> = got
                    .iter()
                    .map(|v| (v["createdAt"].as_str().unwrap().to_string(), v["code"].as_str().unwrap().to_string()))
                    .collect();
                let mut desc = keys.clone();
                desc.sort_by(|x, y| y.cmp(x));
                assert_eq!(keys, desc, "createdAt desc, code desc");
            }
        }
    }

    // single page with room to spare: no cursor
    let r = a
        .xrpc
        .get("com.atproto.admin.searchAccounts", &[("email", &prefix), ("limit", "100")], &Auth::Admin)
        .await
        .ok();
    assert_eq!(r["accounts"].as_array().unwrap().len(), 9);
    // the internal endpoint wants the internal token, not admin credentials
    let rb = peer_client().get(format!("{}/internal/v1/admin/searchAccounts", b.peer_url));
    assert_eq!(a.xrpc.send(rb).await.status, 401);

    // a "live" peer that never answers: reported, not silently dropped. Its
    // lease keeps renewing for the rest of the test: a lease that goes quiet
    // for 1.5 renew intervals at an address refusing connections is presumed
    // dead (and dropped from the peers) within ~150 ms, which under load
    // could happen between the two listings below.
    let dead = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_addr = format!("https://{}", dead.local_addr().unwrap());
    drop(dead);
    let ghost = spawn_ghost(store.clone(), ghost_lease("adm-ghost", dead_addr));
    let reports_ghost = |r: &J| r["unreachableNodes"].as_array().is_some_and(|v| v.iter().any(|n| n == "adm-ghost"));
    // each node reports it once its membership step has seen the lease
    let r = retry("unreachable peer reported", || async {
        let r = a.xrpc.get("com.atproto.admin.searchAccounts", &[("email", &prefix)], &Auth::Admin).await.ok();
        reports_ghost(&r).then_some(r)
    })
    .await;
    assert!(r["accounts"].is_array(), "partial results still returned: {r}");
    retry("getInviteCodes reports the ghost", || async {
        reports_ghost(&b.xrpc.get("com.atproto.admin.getInviteCodes", &[], &Auth::Admin).await.ok()).then_some(())
    })
    .await;
    ghost.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn admin_listings_single_node_complete() {
    let s = TestServer::spawn().await;
    let tag = unique_name("sn");
    for j in 0..3 {
        s.create_account_with(&format!("{tag}x{j}.{HANDLE_DOMAIN}"), PASSWORD).await;
    }
    let prefix = tag.to_ascii_lowercase();
    let (got, pages) = all_pages(&s, "com.atproto.admin.searchAccounts", "accounts", &[("email", &prefix)], 2).await;
    assert_eq!(got.len(), 3);
    assert_eq!(pages.len(), 2);
    s.xrpc
        .get("com.atproto.admin.getInviteCodes", &[("cursor", "no-slash")], &Auth::Admin)
        .await
        .err(400, "InvalidRequest");
    s.xrpc
        .get("com.atproto.admin.searchAccounts", &[("cursor", "nope")], &Auth::Admin)
        .await
        .err(400, "InvalidRequest");
}

/// Signups using one code race on every node, each recording its use from
/// the node owning its new account: every use shows in every node's
/// listing (a node-local lock around the code's read-modify-write lost some).
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn invite_uses_recorded_on_any_node_all_show() {
    let store = Arc::new(object_store::memory::InMemory::new());
    let a = Arc::new(node("inv-a", &store).await);
    let b = Arc::new(node("inv-b", &store).await);
    let c = Arc::new(node("inv-c", &store).await);
    balanced(&[&a, &b, &c]).await;
    const USES: usize = 18;
    let r = a.xrpc.post("com.atproto.server.createInviteCode", &json!({"useCount": USES}), &Auth::Admin).await.ok();
    let code = r["code"].as_str().unwrap().to_string();
    let tag = unique_name("ir");
    let hs: Vec<_> = (0..USES)
        .map(|i| {
            let n = [&a, &b, &c][i % 3].clone();
            let handle = format!("{tag}x{i}.{HANDLE_DOMAIN}");
            let email = format!("{}@example.com", handle.replace('.', "-"));
            let body = json!({"handle": handle, "password": PASSWORD, "email": email, "inviteCode": code});
            tokio::spawn(async move {
                let t = std::time::Instant::now();
                loop {
                    let r = n.xrpc.post("com.atproto.server.createAccount", &body, &Auth::None).await;
                    if r.status != 503 || t.elapsed() > Duration::from_secs(60) {
                        return r.ok()["did"].as_str().unwrap().to_string();
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            })
        })
        .collect();
    let mut dids = HashSet::new();
    for h in hs {
        dids.insert(h.await.unwrap());
    }
    let owners: HashSet<String> = dids.iter().map(|d| owner_of(&[&a, &b, &c], d).url.clone()).collect();
    assert!(owners.len() > 1, "uses recorded from more than one node");
    for s in [&a, &b, &c] {
        let r = s.xrpc.get("com.atproto.admin.getInviteCodes", &[("limit", "500")], &Auth::Admin).await.ok();
        let v = r["codes"].as_array().unwrap().iter().find(|v| v["code"] == code.as_str()).unwrap().clone();
        let used: HashSet<String> =
            v["uses"].as_array().unwrap().iter().map(|u| u["usedBy"].as_str().unwrap().to_string()).collect();
        assert_eq!(used, dids, "every use listed on {}: {v}", s.url);
        assert_eq!(v["available"], json!(USES), "available is the total, as the reference: {v}");
    }
}
