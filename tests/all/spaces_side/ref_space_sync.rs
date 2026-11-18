//! Ported from the reference's `tests/space/sync.test.ts` and
//! `tests/space/notifications.test.ts` (67476105): how a syncer follows a
//! space, and how a writer's PDS tells the authority. Each test names its
//! reference case.
//!
//! Adaptations:
//! - The oplog paging and catch-up cases have the authority write and read
//!   with its own credential (the reference uses a co-located member). The
//!   oplog mechanics are the same, and they run from C1.
//! - notifications.test.ts drives the reference's lease-elected retry
//!   worker and its `space_notification_retry` table. vlpds's equivalent is
//!   the durable `sP` outbox (one row per repo and space, written in the
//!   write's own entry, single-flight, retried in memory, rescanned when a
//!   shard opens). The cases become outbox cases against a remote space host
//!   ([`MockService`]): what it receives, and what a restart resends. Retry
//!   timing (backoff, the cap, the 24 h deadline) waits minutes to hours and
//!   is left to the outbox's own tests.

use super::ref_net::*;
use crate::common::spaces::{commit_of, header_of, kem_key_at, resp, verify_star, xrpc_url, SpaceClient};
use crate::common::*;
use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;
use vlpds::space::lthash::LtHash;
use vlpds::space::token::space_host_aud;
use vlpds::space::{commit, mac};

const NOTIFY_WRITE: &str = "com.atproto.space.notifyRepoUpdate";
const UPDATE: &str = "com.atproto.space.notifySpaceUpdate";

/// listRepoOps as `cred` reads the actor's repo, with extra params.
async fn ops_page(net: &Net, cred: &Cred, space: &str, repo: &str, extra: &[(&str, &str)]) -> J {
    let mut q = vec![("space", space), ("repo", repo)];
    q.extend_from_slice(extra);
    cred.get(&net.host_of(repo), "com.atproto.space.listRepoOps", &q).await.ok()
}

async fn authority_space(net: &Net) -> (SpaceClient, String, Cred) {
    let alice = net.actor("alice", 0).await;
    let space = net.create_space(&alice, SpaceOpts::default()).await;
    let cred = net.credential_for(&alice, &space).await;
    (alice, space, cred)
}

// ---------------------------------------------------------------------------
// oplog paging
// ---------------------------------------------------------------------------

/// oplog paging: "pages through a single rev without dropping ops"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pages_through_a_single_rev_without_dropping_ops() {
    let net = Net::new(0).await;
    let (alice, space, cred) = authority_space(&net).await;
    let writes: Vec<J> = (0..5).map(|i| create_op(&format!("atomic-{i}"), &format!("atomic {i}"))).collect();
    alice.apply_writes(&space, json!(writes)).await.ok();
    let (mut rkeys, mut cursor) = (Vec::new(), None::<String>);
    for _ in 0..10 {
        let mut extra = vec![("limit", "2")];
        if let Some(c) = &cursor {
            extra.push(("cursor", c));
        }
        let page = ops_page(&net, &cred, &space, &alice.did, &extra).await;
        rkeys.extend(page["ops"].as_array().unwrap().iter().map(|o| o["rkey"].as_str().unwrap().to_string()));
        cursor = page["cursor"].as_str().map(String::from);
        if cursor.is_none() {
            break;
        }
    }
    assert_eq!(rkeys, (0..5).map(|i| format!("atomic-{i}")).collect::<Vec<_>>());
}

/// oplog paging: "carries the current commit on every page": the first
/// page leaves the replay behind the commit, and the last (no cursor)
/// matches it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn carries_the_current_commit_on_every_page() {
    let net = Net::new(0).await;
    let (alice, space, cred) = authority_space(&net).await;
    for i in 0..3 {
        write(&alice, &space, W::new().rkey(&format!("paged-{i}"))).await.ok();
    }
    let (rev, _) = repo_state(&alice, &space).await.unwrap();
    let (mut ops, mut seen, mut cursor) = (Vec::new(), Vec::new(), None::<String>);
    for i in 0..5 {
        let mut q = vec![("limit", "1")];
        if let Some(c) = &cursor {
            q.push(("cursor", c));
        }
        let page = ops_page(&net, &cred, &space, &alice.did, &q).await;
        assert_eq!(page["commit"]["rev"], json!(rev), "{page}");
        for op in page["ops"].as_array().unwrap() {
            seen.push(op["rev"].as_str().unwrap().to_string());
            ops.push(op.clone());
        }
        if i == 0 {
            assert!(!commit_matches(&replay(&ops), &page["commit"]), "behind after the first page");
        }
        cursor = page["cursor"].as_str().map(String::from);
        if cursor.is_none() {
            assert!(commit_matches(&replay(&ops), &page["commit"]));
            break;
        }
    }
    assert_eq!(seen.len(), 3);
    assert_eq!(seen.iter().collect::<BTreeSet<_>>().len(), seen.len(), "each page advances: {seen:?}");
    assert!(cursor.is_none());
}

/// oplog paging: "pages with since and cursor together"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pages_with_since_and_cursor_together() {
    let net = Net::new(0).await;
    let (alice, space, cred) = authority_space(&net).await;
    for i in 0..4 {
        write(&alice, &space, W::new().rkey(&format!("prec-{i}"))).await.ok();
    }
    let all = ops_page(&net, &cred, &space, &alice.did, &[("limit", "100")]).await;
    assert_eq!(all["ops"].as_array().unwrap().len(), 4);
    let since = all["ops"][0]["rev"].as_str().unwrap().to_string();
    let (mut rkeys, mut cursor) = (Vec::new(), None::<String>);
    for _ in 0..10 {
        let mut extra = vec![("since", since.as_str()), ("limit", "1")];
        if let Some(c) = &cursor {
            extra.push(("cursor", c));
        }
        let page = ops_page(&net, &cred, &space, &alice.did, &extra).await;
        rkeys.extend(page["ops"].as_array().unwrap().iter().map(|o| o["rkey"].as_str().unwrap().to_string()));
        cursor = page["cursor"].as_str().map(String::from);
        if cursor.is_none() {
            break;
        }
    }
    assert_eq!(rkeys, ["prec-1", "prec-2", "prec-3"]);
}

/// oplog paging: "inlines only a record current value"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn inlines_only_a_record_current_value() {
    let net = Net::new(0).await;
    let (alice, space, cred) = authority_space(&net).await;
    put(&alice, &space, W::new().rkey("inlined").text("first")).await.ok();
    put(&alice, &space, W::new().rkey("inlined").text("second")).await.ok();
    let page = ops_page(&net, &cred, &space, &alice.did, &[("limit", "100")]).await;
    let ops = page["ops"].as_array().unwrap();
    assert_eq!(ops.len(), 2);
    assert!(ops[0].get("value").is_none(), "a superseded op inlines nothing: {}", ops[0]);
    assert_eq!(ops[1]["value"]["text"], json!("second"));
}

/// oplog paging: "omits values entirely with excludeValues"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn omits_values_with_exclude_values() {
    let net = Net::new(0).await;
    let (alice, space, cred) = authority_space(&net).await;
    write(&alice, &space, W::new().rkey("no-value").text("body")).await.ok();
    let page = ops_page(&net, &cred, &space, &alice.did, &[("excludeValues", "true")]).await;
    let ops = page["ops"].as_array().unwrap();
    assert_eq!(ops.len(), 1);
    assert!(ops[0].get("value").is_none(), "{}", ops[0]);
    assert_eq!(ops[0]["rkey"], json!("no-value"));
}

/// oplog paging: "rejects a malformed cursor"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rejects_a_malformed_cursor() {
    let net = Net::new(0).await;
    let (alice, space, cred) = authority_space(&net).await;
    write(&alice, &space, W::new().rkey("cursor-check")).await.ok();
    let q = [("space", space.as_str()), ("repo", alice.did.as_str()), ("cursor", "not-a-cursor")];
    cred.get(&net.pds[0].url, "com.atproto.space.listRepoOps", &q).await.err(400, "InvalidCursor");
}

// ---------------------------------------------------------------------------
// incremental catch-up
// ---------------------------------------------------------------------------

/// incremental catch-up: "replays the oplog to the repo commit" (the
/// commit's MAC verified as it's served)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replays_the_oplog_to_the_repo_commit() {
    let net = Net::new(0).await;
    let (alice, space, cred) = authority_space(&net).await;
    write(&alice, &space, W::new().rkey("one").text("one")).await.ok();
    put(&alice, &space, W::new().rkey("two").text("two")).await.ok();
    put(&alice, &space, W::new().rkey("two").text("two revised")).await.ok();
    del(&alice, &space, None, "one").await.ok();
    let page = ops_page(&net, &cred, &space, &alice.did, &[("limit", "100")]).await;
    let c = commit_of(&page["commit"]);
    assert_eq!((c.space.as_str(), c.repo.as_str()), (space.as_str(), alice.did.as_str()));
    assert!(commit_matches(&replay(page["ops"].as_array().unwrap()), &page["commit"]));
}

/// incremental catch-up: "detects divergence when an op is missed"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn detects_divergence_when_an_op_is_missed() {
    let net = Net::new(0).await;
    let (alice, space, cred) = authority_space(&net).await;
    write(&alice, &space, W::new().rkey("kept").text("kept")).await.ok();
    write(&alice, &space, W::new().rkey("missed").text("missed")).await.ok();
    let page = ops_page(&net, &cred, &space, &alice.did, &[("limit", "100")]).await;
    let ops = page["ops"].as_array().unwrap();
    assert!(!commit_matches(&replay(&ops[..ops.len() - 1]), &page["commit"]));
}

/// incremental catch-up: "recovers from a pruned oplog via listRecords".
/// Only the recovery half: nothing over XRPC prunes the oplog early (C4's
/// 7-day window is the only pruning), so the incremental mismatch isn't
/// forced here. Paged listRecords folds to getLatestCommit's hash.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn recovers_full_state_via_list_records() {
    let net = Net::new(1).await;
    let (alice, bob) = (net.actor("alice", 0).await, net.actor("bob", 1).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&bob], ..Default::default() }).await;
    for t in ["pre 1", "pre 2", "pre 3", "post 1", "post 2"] {
        write(&bob, &space, W::new().text(t)).await.ok();
    }
    let cred = net.credential_for(&bob, &space).await;
    let pds2 = &net.pds[1].url;
    let (mut set, mut n, mut cursor) = (LtHash::default(), 0, None::<String>);
    for _ in 0..10 {
        let mut q = vec![("space", space.as_str()), ("repo", bob.did.as_str()), ("limit", "2")];
        if let Some(c) = &cursor {
            q.push(("cursor", c));
        }
        let r = cred.get(pds2, "com.atproto.space.listRecords", &q).await.ok();
        for rec in r["records"].as_array().unwrap() {
            let (coll, rkey) = (rec["collection"].as_str().unwrap(), rec["rkey"].as_str().unwrap());
            set.add(&commit::element(coll, rkey, rec["cid"].as_str().unwrap()));
            n += 1;
        }
        cursor = r["cursor"].as_str().map(String::from);
        if cursor.is_none() || r["records"].as_array().unwrap().is_empty() {
            break;
        }
    }
    assert_eq!(n, 5);
    let latest =
        cred.get(pds2, "com.atproto.space.getLatestCommit", &[("space", &space), ("repo", &bob.did)]).await.ok();
    assert!(commit_matches(&set, &latest["commit"]));
}

// ---------------------------------------------------------------------------
// getRepo
// ---------------------------------------------------------------------------

/// getRepo: "serves a verifiable STAR archive for full-state recovery"
/// (`verifyRepoStarFull`: the MAC as it's served, then the archive)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn get_repo_serves_a_verifiable_star_archive() {
    let net = Net::new(2).await;
    let (alice, bob, carol) = (net.actor("alice", 0).await, net.actor("bob", 1).await, net.actor("carol", 2).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&bob, &carol], ..Default::default() }).await;
    for coll in [TEST_COLLECTION, TEST_COLLECTION_ALT] {
        for i in 0..2 {
            write(&bob, &space, W::new().collection(coll).rkey(&format!("star-{i}")).text(&format!("star {i}")))
                .await
                .ok();
        }
    }
    let cred = net.credential_for(&carol, &space).await;
    let r = cred.get(&net.pds[1].url, "com.atproto.space.getRepo", &[("space", &space), ("repo", &bob.did)]).await;
    assert_eq!(r.status, 200, "{}", r.text());
    assert!(r.header("content-type").unwrap_or_default().contains("application/vnd.dasl.star"));
    assert!(r.headers.contains_key("atproto-space-commit") && r.headers.contains_key("signature"), "a MAC");
    let got = verify_star(&r.body, &space, &bob.did);
    assert_eq!(got.records.len(), 4);
    let (rev, hash) = repo_state(&bob, &space).await.unwrap();
    assert_eq!((got.commit.rev, got.commit.data.to_vec()), (rev, hash));
    let mut texts: Vec<String> = got
        .records
        .iter()
        .filter(|(p, _, _)| p.starts_with(&format!("{TEST_COLLECTION}/")))
        .map(|(_, _, b)| match Value::decode(b).unwrap().get("text") {
            Some(Value::Text(t)) => t.clone(),
            other => panic!("text: {other:?}"),
        })
        .collect();
    texts.sort();
    assert_eq!(texts, ["star 0", "star 1"]);
}

/// getRepo: "recovers a cleared repo, whose oplog is empty, from getRepo"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn recovers_a_cleared_repo_from_get_repo() {
    let net = Net::new(2).await;
    let (alice, bob, carol) = (net.actor("alice", 0).await, net.actor("bob", 1).await, net.actor("carol", 2).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&bob, &carol], ..Default::default() }).await;
    write(&bob, &space, W::new().rkey("one")).await.ok();
    write(&bob, &space, W::new().rkey("two")).await.ok();
    let cred = net.credential_for(&carol, &space).await;
    let synced = ops_page(&net, &cred, &space, &bob.did, &[]).await;
    let local = replay(synced["ops"].as_array().unwrap());
    assert!(commit_matches(&local, &synced["commit"]));

    clear(&bob, &space).await.ok();
    let since = synced["commit"]["rev"].as_str().unwrap();
    let incremental = ops_page(&net, &cred, &space, &bob.did, &[("since", since)]).await;
    assert_eq!(incremental["ops"], json!([]));
    assert!(!commit_matches(&local, &incremental["commit"]), "the replay can't follow a clear");

    let q = [("space", space.as_str()), ("repo", bob.did.as_str())];
    let r = cred.get(&net.pds[1].url, "com.atproto.space.getRepo", &q).await;
    assert_eq!(r.status, 200, "{}", r.text());
    let recovered = verify_star(&r.body, &space, &bob.did);
    assert_eq!(json!(recovered.commit.rev), incremental["commit"]["rev"]);
    assert!(recovered.records.is_empty());
}

/// getRepo: "refuses a repo without a credential for that space"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn get_repo_refuses_a_credential_for_another_space() {
    let net = Net::new(2).await;
    let (alice, bob, carol) = (net.actor("alice", 0).await, net.actor("bob", 1).await, net.actor("carol", 2).await);
    let space =
        net.create_space(&alice, SpaceOpts { skey: Some("car-auth"), members: &[&bob], ..Default::default() }).await;
    let other = net
        .create_space(&alice, SpaceOpts { skey: Some("car-auth-other"), members: &[&carol], ..Default::default() })
        .await;
    write(&bob, &space, W::new()).await.ok();
    let wrong = net.credential_for(&carol, &other).await;
    let r = wrong.get(&net.pds[1].url, "com.atproto.space.getRepo", &[("space", &space), ("repo", &bob.did)]).await;
    assert!(r.status >= 400, "{}", r.text());
}

/// getRepo: "reports RepoNotFound for an unwritten repo"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reports_repo_not_found_for_an_unwritten_repo() {
    let net = Net::new(2).await;
    let (alice, carol) = (net.actor("alice", 0).await, net.actor("carol", 2).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&carol], ..Default::default() }).await;
    let cred = net.credential_for(&carol, &space).await;
    let q = [("space", space.as_str()), ("repo", alice.did.as_str())];
    for nsid in ["getLatestCommit", "listRepoOps", "getRepo"] {
        cred.get(&net.pds[0].url, &format!("com.atproto.space.{nsid}"), &q).await.err(400, "RepoNotFound");
    }
}

// ---------------------------------------------------------------------------
// MACs
// ---------------------------------------------------------------------------

/// A GET on `sc`'s own OAuth grant with extra headers.
async fn oauth_get_with(sc: &SpaceClient, nsid: &str, query: &[(&str, &str)], extra: &[(String, String)]) -> Resp {
    let url = xrpc_url(&sc.srv.base, nsid, query);
    for attempt in 0..2 {
        let mut rb = sc
            .srv
            .http
            .get(&url)
            .header("dpop", sc.key.proof("GET", &url, Some(&sc.access)))
            .header("authorization", format!("DPoP {}", sc.access));
        for (k, v) in extra {
            rb = rb.header(k, v);
        }
        let r = resp(rb.send().await.unwrap()).await;
        sc.key.update_nonce(&r.headers);
        if attempt == 0 && r.json["error"] == "use_dpop_nonce" {
            continue;
        }
        return r;
    }
    unreachable!()
}

fn want_mac(ty: mac::Profile, share: &str) -> (String, String) {
    (mac::ACCEPT_SIGNATURE.to_string(), mac::format_request(ty, share))
}

/// MACs: "publishes a KEM key for each account": the key the account's
/// host holds is the one its DID document names and the one
/// getRecommendedDidCredentials recommends.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn publishes_a_kem_key_for_each_account() {
    let net = Net::new(0).await;
    let bob = net.actor("bob", 0).await;
    let s = &net.pds[0];
    let held = s.app.account(&bob.did).await.ok().unwrap().kem_pubkey.expect("a KEM key");
    let held = format!("did:key:{}", held.trim_start_matches("did:key:"));
    assert_eq!(kem_key_at(&bob.srv.http, &s.url, &bob.did).await, Some(held.clone()), "the DID document's");
    let rec = s
        .xrpc
        .get("com.atproto.identity.getRecommendedDidCredentials", &[], &Auth::Bearer(bob.session_jwt.clone()))
        .await
        .ok();
    assert_eq!(rec["verificationMethods"]["atproto_kem"], json!(held));
    assert_ne!(rec["verificationMethods"]["atproto_kem"], rec["verificationMethods"]["atproto"], "its own key");
}

/// MACs: "macs a record served to a syncer", and the MAC is bound to that
/// one record's URI.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn macs_a_record_served_to_a_syncer() {
    let net = Net::new(1).await;
    let (alice, bob, carol) = (net.actor("alice", 0).await, net.actor("bob", 1).await, net.actor("carol", 0).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&bob, &carol], ..Default::default() }).await;
    write(&bob, &space, W::new().rkey("maced")).await.ok();
    let cred = net.credential_for(&carol, &space).await;
    let host = &net.pds[1].url;
    let kem = kem_key_at(&cred.http, host, &bob.did).await.expect("bob's KEM key");
    let (share, secret) = mac::encapsulate(&kem).unwrap();
    let mut headers = cred.headers(&bob.did);
    headers.push(want_mac(mac::Profile::Record, &share));
    let q = [("space", space.as_str()), ("repo", bob.did.as_str()), ("collection", TEST_COLLECTION), ("rkey", "maced")];
    let r = raw_get(host, "com.atproto.space.getRecord", &q, &headers).await;
    assert_eq!(r.status, 200, "{}", r.text());
    let uri = format!("{space}/{}/{TEST_COLLECTION}/maced", bob.did);
    assert_eq!(r.json["uri"], json!(uri));
    let cid = r.json["cid"].as_str().unwrap();
    let h = |n: &str| header_of(&r, n);
    assert_eq!(h("atproto-space-record").unwrap(), format!("uri=\"{uri}\", cid=\"{cid}\""));
    mac::verify_record(&uri, cid, &share, &secret, &h).unwrap();
    assert!(mac::verify_record(&format!("{uri}x"), cid, &share, &secret, &h).is_err(), "bound to this one record");
    // and the record's encoding is the CID's
    let bytes = Value::from_json(&r.json["value"]).unwrap().to_cbor();
    assert_eq!(vlatproto::cid::Cid::dag_cbor(&bytes).to_string(), cid);
}

/// MACs: "macs every oplog page": a page with a cursor carries the commit
/// and its MAC too.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn macs_every_oplog_page() {
    let net = Net::new(0).await;
    let (alice, bob) = (net.actor("alice", 0).await, net.actor("bob", 0).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&bob], ..Default::default() }).await;
    write(&bob, &space, W::new().rkey("page-0")).await.ok();
    write(&bob, &space, W::new().rkey("page-1")).await.ok();
    let cred = net.credential_for(&bob, &space).await;
    let host = &net.pds[0].url;
    let q = [("space", space.as_str()), ("repo", bob.did.as_str()), ("limit", "1")];
    // the MAC is verified by the credential's read helper
    let page = cred.get(host, "com.atproto.space.listRepoOps", &q).await;
    assert!(page.ok()["cursor"].is_string(), "{}", page.text());
    assert!(page.json["commit"].is_object());
    // and every page needs the request
    let r = raw_get(host, "com.atproto.space.listRepoOps", &q, &cred.headers(&bob.did)).await;
    r.err(400, "InvalidSpaceMac");
}

/// MACs: "requires a MAC request with a space credential": none, a record
/// MAC asked of a method that returns a commit, and a key share that isn't
/// a key are each 400 InvalidSpaceMac.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn requires_a_mac_request_with_a_space_credential() {
    let net = Net::new(0).await;
    let (alice, bob) = (net.actor("alice", 0).await, net.actor("bob", 0).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&bob], ..Default::default() }).await;
    write(&bob, &space, W::new()).await.ok();
    let cred = net.credential_for(&bob, &space).await;
    let host = &net.pds[0].url;
    let q = [("space", space.as_str()), ("repo", bob.did.as_str())];
    let signed = cred.headers(&bob.did);
    raw_get(host, "com.atproto.space.getLatestCommit", &q, &signed).await.err(400, "InvalidSpaceMac");
    let kem = kem_key_at(&cred.http, host, &bob.did).await.unwrap();
    let (share, _) = mac::encapsulate(&kem).unwrap();
    for (what, header) in [
        ("a record MAC profile", want_mac(mac::Profile::Record, &share)),
        ("a key share that isn't a key", want_mac(mac::Profile::Commit, "did:key:nope")),
    ] {
        let mut h = signed.clone();
        h.push(header);
        let r = raw_get(host, "com.atproto.space.getLatestCommit", &q, &h).await;
        assert_eq!((r.status, r.error_name()), (400, Some("InvalidSpaceMac")), "{what}: {}", r.text());
    }
    // with the right one, it verifies
    cred.get(host, "com.atproto.space.getLatestCommit", &q).await.ok();
}

/// MACs: "macs an account its own data only when asked": OAuth reads of
/// its own repo carry no MAC (but `Vary`) unless asked, a request with
/// another tag is ignored, and an asked one verifies and a browser may read
/// it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn macs_an_account_its_own_data_only_when_asked() {
    let net = Net::new(0).await;
    let (alice, bob) = (net.actor("alice", 0).await, net.actor("bob", 0).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&bob], ..Default::default() }).await;
    write(&bob, &space, W::new()).await.ok();
    let q = [("space", space.as_str()), ("repo", bob.did.as_str())];
    let unasked = oauth_get_with(&bob, "com.atproto.space.getLatestCommit", &q, &[]).await;
    assert_eq!(unasked.status, 200, "{}", unasked.text());
    assert!(unasked.headers.get("signature").is_none());
    let vary = |r: &Resp| r.headers.get_all("vary").iter().any(|v| v.to_str().unwrap().contains("Accept-Signature"));
    assert!(vary(&unasked), "Vary names Accept-Signature");
    let other = [(mac::ACCEPT_SIGNATURE.to_string(), "other=(\"@status\");tag=\"other\"".to_string())];
    let other = oauth_get_with(&bob, "com.atproto.space.getLatestCommit", &q, &other).await;
    assert_eq!(other.status, 200, "{}", other.text());
    assert!(other.headers.get("signature").is_none());

    let kem = kem_key_at(&bob.srv.http, &net.pds[0].url, &bob.did).await.unwrap();
    let (share, secret) = mac::encapsulate(&kem).unwrap();
    let asked =
        oauth_get_with(&bob, "com.atproto.space.getLatestCommit", &q, &[want_mac(mac::Profile::Commit, &share)]).await;
    assert_eq!(asked.status, 200, "{}", asked.text());
    let expose = asked
        .headers
        .get_all("access-control-expose-headers")
        .iter()
        .map(|v| v.to_str().unwrap().to_lowercase())
        .collect::<Vec<_>>()
        .join(", ");
    assert!(expose.contains("atproto-space-commit") && expose.contains("signature-input"), "{expose}");
    let h = |n: &str| header_of(&asked, n);
    commit::verify(&commit_of(&asked.json["commit"]), &space, &bob.did, &share, &secret, &h).unwrap();
}

// ---------------------------------------------------------------------------
// writer set
// ---------------------------------------------------------------------------

/// writer set: "records a co-located writer without resolving its public PDS
/// endpoint" (the PLC directory is down during the write instead of a
/// mocked resolver)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn records_a_co_located_writer_without_resolving_it() {
    let net = Net::new(0).await;
    let (alice, dan) = (net.actor("alice", 0).await, net.actor("dan", 0).await);
    let space = net
        .create_space(
            &alice,
            SpaceOpts { policy: Some(memberspace(json!({"publicWrite": true}))), ..Default::default() },
        )
        .await;
    net.plc.set_down(true);
    write(&dan, &space, W::new().text("same PDS")).await.ok();
    net.plc.set_down(false);
    assert_eq!(net.await_writer(&alice, &space, &dan.did).await, [dan.did.as_str()]);
}

/// writer set: "records a writer from notifyRepoUpdate, and it is not the
/// member list"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn records_a_writer_from_notify_write() {
    let net = Net::new(1).await;
    let (alice, bob, carol) = (net.actor("alice", 0).await, net.actor("bob", 1).await, net.actor("carol", 1).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&bob, &carol], ..Default::default() }).await;
    write(&bob, &space, W::new().text("writer set entry")).await.ok();
    let dids = net.await_writer(&alice, &space, &bob.did).await;
    assert!(dids.contains(&bob.did) && !dids.contains(&alice.did), "{dids:?}");
    let cred = net.credential_for(&bob, &space).await;
    let repos = cred.get(&net.pds[0].url, "com.atproto.space.listWriters", &[("space", &space)]).await.ok();
    let listed = repos["repos"].as_array().unwrap();
    assert_eq!(listed.len(), 1, "a member who never wrote isn't a writer: {repos}");
    let entry = listed[0].clone();
    assert_eq!(entry["repo"], json!(bob.did));
    assert_eq!(entry["$type"], json!("com.atproto.space.defs#repoWrite"));
    let (rev, hash) = repo_state(&bob, &space).await.unwrap();
    assert_eq!(entry["repoRev"], json!(rev));
    assert_eq!(bytes_field(&entry["data"]), hash);
}

/// writer set: "records a writer admitted by public write policy, who was
/// never a member"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn records_a_public_policy_writer_who_was_never_a_member() {
    let net = Net::new(1).await;
    let (alice, bob) = (net.actor("alice", 0).await, net.actor("bob", 1).await);
    let space = net
        .create_space(
            &alice,
            SpaceOpts { policy: Some(memberspace(json!({"publicWrite": true}))), ..Default::default() },
        )
        .await;
    write(&bob, &space, W::new().text("from a non-member")).await.ok();
    assert_eq!(net.await_writer(&alice, &space, &bob.did).await, [bob.did.as_str()]);
}

/// writer set: "records a writer into an allowList space, whose PDS
/// presents no attestation"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn records_a_writer_into_an_allow_list_space() {
    let net = Net::new(1).await;
    let (alice, bob) = (net.actor("alice", 0).await, net.actor("bob", 1).await);
    let space = net
        .create_space(
            &alice,
            SpaceOpts {
                members: &[&bob],
                policy: Some(memberspace(json!({"allowedApps": ["https://app.example.com/client-metadata.json"]}))),
                ..Default::default()
            },
        )
        .await;
    write(&bob, &space, W::new().text("app-gated space")).await.ok();
    assert!(net.await_writer(&alice, &space, &bob.did).await.contains(&bob.did));
}

// ---------------------------------------------------------------------------
// space catch-up (listWriters)
// ---------------------------------------------------------------------------

async fn list_writers(net: &Net, cred: &Cred, space: &str, extra: &[(&str, &str)]) -> J {
    let mut q = vec![("space", space)];
    q.extend_from_slice(extra);
    cred.get(&net.pds[0].url, "com.atproto.space.listWriters", &q).await.ok()
}

fn repo_dids(page: &J) -> Vec<String> {
    page["repos"].as_array().unwrap().iter().map(|r| r["repo"].as_str().unwrap().to_string()).collect()
}

/// space catch-up: "recovers missed notifications with a space checkpoint"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn recovers_missed_notifications_with_a_space_checkpoint() {
    let net = Net::new(2).await;
    let (alice, bob) = (net.actor("alice", 0).await, net.actor("bob", 1).await);
    let (dan, carol) = (net.actor("dan", 0).await, net.actor("carol", 2).await);
    let syncer = MockService::syncer().await;
    syncer.respond(503, json!({}));
    let space = net.create_space(&alice, SpaceOpts { members: &[&bob, &dan, &carol], ..Default::default() }).await;
    net.credential_notify(&carol, &space, syncer.notify_registration("notify-token")).await.ok();
    let cred = net.credential_for(&carol, &space).await;
    assert_eq!(list_writers(&net, &cred, &space, &[]).await["repos"], json!([]));

    write(&bob, &space, W::new()).await.ok();
    net.await_writer(&alice, &space, &bob.did).await;
    let initial = list_writers(&net, &cred, &space, &[]).await;
    let cursor = initial["cursor"].as_str().unwrap().to_string();
    assert_eq!(initial["repos"].as_array().unwrap().last().unwrap()["spaceRev"], json!(cursor));
    write(&dan, &space, W::new()).await.ok();
    let (bob_rev, _) = {
        write(&bob, &space, W::new()).await.ok();
        repo_state(&bob, &space).await.unwrap()
    };
    retry("bob's second write reaches the authority", || {
        let (net, cred, space, bob_rev) = (&net, &cred, &space, &bob_rev);
        async move {
            let p = list_writers(net, cred, space, &[]).await;
            p["repos"].as_array().unwrap().iter().any(|r| r["repoRev"] == json!(bob_rev)).then_some(())
        }
    })
    .await;

    let first = list_writers(&net, &cred, &space, &[("cursor", &cursor), ("limit", "1")]).await;
    assert_eq!(repo_dids(&first), [dan.did.as_str()]);
    // A repo already returned can move forward while the caller pages.
    write(&dan, &space, W::new()).await.ok();
    let (dan_rev, _) = repo_state(&dan, &space).await.unwrap();
    retry("dan's second write reaches the authority", || {
        let (net, cred, space, dan_rev) = (&net, &cred, &space, &dan_rev);
        async move {
            let p = list_writers(net, cred, space, &[]).await;
            p["repos"].as_array().unwrap().iter().any(|r| r["repoRev"] == json!(dan_rev)).then_some(())
        }
    })
    .await;
    let second =
        list_writers(&net, &cred, &space, &[("cursor", first["cursor"].as_str().unwrap()), ("limit", "1")]).await;
    assert_eq!(repo_dids(&second), [bob.did.as_str()]);
    let last =
        list_writers(&net, &cred, &space, &[("cursor", second["cursor"].as_str().unwrap()), ("limit", "1")]).await;
    assert_eq!(repo_dids(&last), [dan.did.as_str()]);
    let next = last["cursor"].as_str().unwrap().to_string();
    assert_eq!(last["repos"][0]["spaceRev"], json!(next));
    let caught_up = list_writers(&net, &cred, &space, &[("cursor", &next)]).await;
    assert_eq!(caught_up["repos"], json!([]));
    assert!(caught_up.get("cursor").is_none(), "{caught_up}");
}

/// space catch-up: "resumes after an empty page using the last processed
/// repo revision"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn resumes_after_an_empty_page() {
    let net = Net::new(1).await;
    let (alice, bob) = (net.actor("alice", 0).await, net.actor("bob", 1).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&bob], ..Default::default() }).await;
    write(&bob, &space, W::new()).await.ok();
    net.await_writer(&alice, &space, &bob.did).await;
    let cred = net.credential_for(&alice, &space).await;
    let cursor = list_writers(&net, &cred, &space, &[]).await["cursor"].as_str().unwrap().to_string();
    let empty = list_writers(&net, &cred, &space, &[("cursor", &cursor)]).await;
    assert_eq!(empty["repos"], json!([]));
    assert!(empty.get("cursor").is_none());

    write(&bob, &space, W::new()).await.ok();
    let got = retry("the second write reaches the authority", || {
        let (net, cred, space, cursor) = (&net, &cred, &space, &cursor);
        async move {
            let p = list_writers(net, cred, space, &[("cursor", cursor)]).await;
            (!p["repos"].as_array().unwrap().is_empty()).then_some(p)
        }
    })
    .await;
    assert_eq!(repo_dids(&got), [bob.did.as_str()]);
    assert!(got["repos"][0]["spaceRev"].as_str().unwrap() > cursor.as_str());
}

/// space catch-up: "accepts arbitrary string listWriters cursors"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn accepts_arbitrary_string_list_repos_cursors() {
    let net = Net::new(0).await;
    let (alice, space, _) = authority_space(&net).await;
    write(&alice, &space, W::new()).await.ok();
    let cred = net.credential_for(&alice, &space).await;
    assert_eq!(repo_dids(&list_writers(&net, &cred, &space, &[("cursor", "0")]).await), [alice.did.as_str()]);
    let after = list_writers(&net, &cred, &space, &[("cursor", "not-a-tid")]).await;
    assert_eq!(after["repos"], json!([]));
    assert!(after.get("cursor").is_none());
}

/// space catch-up: "chains forwarded notifications across local and remote
/// writers" (vlpds also sends them in spaceRev order per registration)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn chains_forwarded_notifications() {
    let net = Net::new(2).await;
    let (alice, bob) = (net.actor("alice", 0).await, net.actor("bob", 1).await);
    let (dan, carol) = (net.actor("dan", 0).await, net.actor("carol", 2).await);
    let syncer = MockService::syncer().await;
    let space = net.create_space(&alice, SpaceOpts { members: &[&bob, &dan, &carol], ..Default::default() }).await;
    net.credential_notify(&carol, &space, syncer.notify_registration("notify-token")).await.ok();
    let cred = net.credential_for(&carol, &space).await;
    write(&alice, &space, W::new()).await.ok();
    let (b, d) = tokio::join!(write(&bob, &space, W::new()), write(&dan, &space, W::new()));
    b.ok();
    d.ok();
    syncer.await_calls(UPDATE, 3, Duration::from_secs(15)).await.expect("three forwards");
    tokio::time::sleep(Duration::from_millis(300)).await;
    let bodies = syncer.space_updates();
    assert_eq!(bodies.len(), 3, "{bodies:?}");
    let revs: Vec<&str> = bodies.iter().map(|b| b["spaceRev"].as_str().unwrap()).collect();
    let mut sorted = revs.clone();
    sorted.sort();
    assert_eq!(revs, sorted, "sent in spaceRev order");
    assert!(bodies[0].get("prevSpaceRev").is_none() || bodies[0]["prevSpaceRev"].is_null());
    assert_eq!(bodies[1]["prevSpaceRev"], bodies[0]["spaceRev"]);
    assert_eq!(bodies[2]["prevSpaceRev"], bodies[1]["spaceRev"]);
    let listed = list_writers(&net, &cred, &space, &[]).await;
    let repos = listed["repos"].as_array().unwrap();
    assert_eq!(repos.last().unwrap()["spaceRev"], bodies[2]["spaceRev"]);
    assert_eq!(repos.iter().map(|r| r["spaceRev"].as_str().unwrap()).collect::<BTreeSet<_>>().len(), 3);
}

/// space catch-up: "resolves a space host through the authority's
/// #atproto_pds entry". Observed at the hosts: a notify goes to the
/// authority's `#atproto_pds` with that as its audience, and an authority
/// naming only the retired `#atproto_space_host` hears nothing. (The
/// reference's other half, resolving a syncer's own service entry, is its
/// resolver's unit and has no wire effect here.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn notify_resolves_the_space_host_through_atproto_pds() {
    let net = Net::new(0).await;
    let writer = net.actor("writer", 0).await;
    let pds = MockService::spawn(&[("atproto_pds", "AtprotoPersonalDataServer")]).await;
    let retired = MockService::spawn(&[("atproto_space_host", "AtprotoSpaceHost")]).await;
    let space = format!("at://{}/space/{TEST_SPACE_TYPE}/resolve", pds.did);
    write(&writer, &space, W::new()).await.ok();
    let (rev, _) = repo_state(&writer, &space).await.unwrap();
    let got = pds.await_calls(NOTIFY_WRITE, 1, Duration::from_secs(10)).await.expect("notified");
    assert_eq!(got[0].body["repoRev"], json!(rev));
    let claims = jwt_claims(got[0].auth.as_deref().unwrap().trim_start_matches("Bearer "));
    assert_eq!(claims["aud"], json!(format!("{}#atproto_pds", pds.did)));
    assert_eq!(space_host_aud(&pds.did), format!("{}#atproto_pds", pds.did));

    let space = format!("at://{}/space/{TEST_SPACE_TYPE}/resolve", retired.did);
    write(&writer, &space, W::new()).await.ok();
    assert!(
        retired.await_calls(NOTIFY_WRITE, 1, Duration::from_secs(2)).await.is_none(),
        "#atproto_space_host is used"
    );
}

/// space catch-up: "retries the latest state after delivery failure and
/// worker restart": the authority refuses (503) two writes' notifies; after
/// a restart the node that opens the shard sends the newest repoRev.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn retries_the_latest_state_after_failure_and_restart() {
    let host = MockService::space_host().await;
    host.respond(503, json!({"error": "Unavailable"}));
    let store: Arc<dyn object_store::ObjectStore> = Arc::new(object_store::memory::InMemory::new());
    let first = cluster_node("rr", store.clone(), 8, |c| c.spaces = true).await;
    let w = SpaceClient::new(&first, "rrw", FULL_SCOPE).await;
    let space = format!("at://{}/space/{TEST_SPACE_TYPE}/retry", host.did);
    write(&w, &space, W::new()).await.ok();
    write(&w, &space, W::new()).await.ok();
    let (rev, hash) = repo_state(&w, &space).await.unwrap();
    retry("the newest rev refused once", || {
        std::future::ready(host.calls_to(NOTIFY_WRITE).iter().any(|c| c.body["repoRev"] == json!(rev)).then_some(()))
    })
    .await;
    vlpds::server::shutdown(&first.app).await;
    host.respond(200, json!({}));
    let refused = host.calls_to(NOTIFY_WRITE).len();
    let _second = cluster_node("rr", store, 8, |c| c.spaces = true).await;
    let calls =
        host.await_calls(NOTIFY_WRITE, refused + 1, Duration::from_secs(15)).await.expect("resent after restart");
    let last = calls.last().unwrap();
    assert_eq!(last.body["repoRev"], json!(rev));
    assert_eq!(bytes_field(&last.body["data"]), hash);
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(host.calls_to(NOTIFY_WRITE).len(), refused + 1, "delivered once");
}

// ---------------------------------------------------------------------------
// notifyRepoUpdate (inbound, at the authority)
// ---------------------------------------------------------------------------

/// notifyRepoUpdate at alice's PDS, signed by `signer`'s account key.
async fn notify(net: &Net, signer: &SpaceClient, aud: Option<&str>, body: J) -> Resp {
    let aud = aud.map(String::from).unwrap_or_else(|| space_host_aud(authority_of(body["space"].as_str().unwrap())));
    let jwt = service_jwt(signer, &aud, NOTIFY_WRITE).await;
    post_service(&net.pds[0].url, NOTIFY_WRITE, &jwt, body).await
}

fn notify_body(space: &str, repo: &str, rev: &str, hash: &[u8]) -> J {
    json!({"space": space, "repo": repo, "repoRev": rev, "data": json_bytes(hash)})
}

/// notifyRepoUpdate: "ignores duplicate and older revisions without forwarding
/// them"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn notify_write_ignores_duplicate_and_older_revisions() {
    let net = Net::new(1).await;
    let (alice, bob) = (net.actor("alice", 0).await, net.actor("bob", 1).await);
    let syncer = MockService::syncer().await;
    let space = net.create_space(&alice, SpaceOpts { members: &[&bob], ..Default::default() }).await;
    net.credential_notify(&alice, &space, syncer.notify_registration("notify-token")).await.ok();
    let cred = net.credential_for(&alice, &space).await;
    write(&bob, &space, W::new()).await.ok();
    let (older, _) = repo_state(&bob, &space).await.unwrap();
    write(&bob, &space, W::new()).await.ok();
    let (newest, _) = repo_state(&bob, &space).await.unwrap();
    syncer.await_calls(UPDATE, 2, Duration::from_secs(10)).await;
    retry("the newest rev at the authority", || {
        let (net, cred, space, newest) = (&net, &cred, &space, &newest);
        async move {
            let p = list_writers(net, cred, space, &[]).await;
            (p["repos"][0]["repoRev"] == json!(newest)).then_some(())
        }
    })
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let before = list_writers(&net, &cred, &space, &[]).await;
    let calls = syncer.calls_to(UPDATE).len();
    // a duplicate is the newest rev with the hash the authority holds: an
    // equal rev with another hash is a takedown's adjusted view, which vlpds
    // sequences again (a divergence, tests/REFERENCE_COVERAGE.md)
    let held = super::fuzz::bytes_field(&before["repos"][0]["data"]);
    notify(&net, &bob, None, notify_body(&space, &bob.did, &older, &[0; 32])).await.ok();
    notify(&net, &bob, None, notify_body(&space, &bob.did, &newest, &held)).await.ok();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(list_writers(&net, &cred, &space, &[]).await, before);
    assert_eq!(syncer.calls_to(UPDATE).len(), calls);
}

/// notifyRepoUpdate: "keeps the newest repo revision when notifications race"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn notify_write_keeps_the_newest_revision_when_racing() {
    let net = Net::new(1).await;
    let (alice, bob) = (net.actor("alice", 0).await, net.actor("bob", 1).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&bob], ..Default::default() }).await;
    let older = next_tid(None);
    let newer = next_tid(Some(&older));
    let empty = LtHash::default().digest();
    let (a, b) = tokio::join!(
        notify(&net, &bob, None, notify_body(&space, &bob.did, &newer, &empty)),
        notify(&net, &bob, None, notify_body(&space, &bob.did, &older, &[0; 32])),
    );
    a.ok();
    b.ok();
    let cred = net.credential_for(&alice, &space).await;
    let listed = list_writers(&net, &cred, &space, &[]).await;
    let repos = listed["repos"].as_array().unwrap();
    assert_eq!(repos.len(), 1);
    assert_eq!(repos[0]["repoRev"], json!(newer));
    assert_eq!(bytes_field(&repos[0]["data"]), empty.to_vec());
}

/// notifyRepoUpdate: "rejects future revisions while allowing a small clock skew"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn notify_write_rejects_future_revisions() {
    let net = Net::new(1).await;
    let (alice, bob) = (net.actor("alice", 0).await, net.actor("bob", 1).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&bob], ..Default::default() }).await;
    let empty = LtHash::default().digest();
    let r = notify(&net, &bob, None, notify_body(&space, &bob.did, &tid_at(10 * 60_000_000), &empty)).await;
    r.err(400, "FutureRev");
    assert!(net.writer_dids(&alice, &space).await.is_empty());
    notify(&net, &bob, None, notify_body(&space, &bob.did, &tid_at(60_000_000), &empty)).await.ok();
    assert_eq!(net.writer_dids(&alice, &space).await, [bob.did.as_str()]);
}

/// notifyRepoUpdate: "rejects one that spoofs the writer"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn notify_write_rejects_a_spoofed_writer() {
    let net = Net::new(2).await;
    let (alice, bob, carol) = (net.actor("alice", 0).await, net.actor("bob", 1).await, net.actor("carol", 2).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&bob, &carol], ..Default::default() }).await;
    let r =
        notify(&net, &bob, None, notify_body(&space, &carol.did, &next_tid(None), &LtHash::default().digest())).await;
    refused_mentioning(&r, &["iss does not match"]);
}

/// notifyRepoUpdate: "rejects one addressed to another authority"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn notify_write_rejects_one_addressed_to_another_authority() {
    let net = Net::new(2).await;
    let (alice, bob, carol) = (net.actor("alice", 0).await, net.actor("bob", 1).await, net.actor("carol", 2).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&bob], ..Default::default() }).await;
    write(&bob, &space, W::new().text("misaddressed")).await.ok();
    let (rev, hash) = repo_state(&bob, &space).await.unwrap();
    let r = notify(&net, &bob, Some(&carol.did), notify_body(&space, &bob.did, &rev, &hash)).await;
    refused_mentioning(&r, &["aud"]);
}

/// notifyRepoUpdate: "rejects one from a non-member"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn notify_write_rejects_a_non_member() {
    let net = Net::new(2).await;
    let (alice, bob, carol) = (net.actor("alice", 0).await, net.actor("bob", 1).await, net.actor("carol", 2).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&bob], ..Default::default() }).await;
    let r =
        notify(&net, &carol, None, notify_body(&space, &carol.did, &next_tid(None), &LtHash::default().digest())).await;
    refused_mentioning(&r, &["not authorized"]);
    assert!(net.writer_dids(&alice, &space).await.is_empty());
}

/// notifyRepoUpdate: "rejects a member without write access"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn notify_write_rejects_a_member_without_write_access() {
    let net = Net::new(1).await;
    let (alice, bob) = (net.actor("alice", 0).await, net.actor("bob", 1).await);
    let space = net.create_space(&alice, SpaceOpts::default()).await;
    put_member(&alice, &space, &bob, true, false).await.ok();
    let r = notify(&net, &bob, None, notify_body(&space, &bob.did, &next_tid(None), &LtHash::default().digest())).await;
    refused_mentioning(&r, &["not authorized"]);
}

/// notifyRepoUpdate: "rejects a member without write access even when
/// writes are public"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn notify_write_rejects_a_member_without_write_even_when_public() {
    let net = Net::new(1).await;
    let (alice, bob, carol) = (net.actor("alice", 0).await, net.actor("bob", 1).await, net.actor("carol", 1).await);
    let space = net
        .create_space(
            &alice,
            SpaceOpts { policy: Some(memberspace(json!({"publicWrite": true}))), ..Default::default() },
        )
        .await;
    put_member(&alice, &space, &bob, true, false).await.ok();
    let r = notify(&net, &bob, None, notify_body(&space, &bob.did, &next_tid(None), &LtHash::default().digest())).await;
    refused_mentioning(&r, &["not authorized"]);
    notify(&net, &carol, None, notify_body(&space, &carol.did, &next_tid(None), &LtHash::default().digest()))
        .await
        .ok();
    assert_eq!(net.writer_dids(&alice, &space).await, vec![carol.did.clone()]);
}

/// notifyRepoUpdate: "refuses one for a deleted space", and a reused URI
/// doesn't inherit the refused writer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn notify_write_refuses_one_for_a_deleted_space() {
    let net = Net::new(1).await;
    let (alice, bob) = (net.actor("alice", 0).await, net.actor("bob", 1).await);
    let opts = SpaceOpts { skey: Some("deleted"), members: &[&bob], ..Default::default() };
    let space = net.create_space(&alice, opts).await;
    alice.post("com.atproto.space.deleteSpace", json!({"space": space})).await.ok();
    let r = notify(&net, &bob, None, notify_body(&space, &bob.did, &next_tid(None), &LtHash::default().digest())).await;
    r.err(400, "SpaceNotFound");
    net.create_space(&alice, SpaceOpts { skey: Some("deleted"), ..Default::default() }).await;
    assert!(net.writer_dids(&alice, &space).await.is_empty());
}

/// notifyRepoUpdate: "rejects a rev that is not a TID before any auth check"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn notify_write_rejects_a_rev_that_is_not_a_tid() {
    let net = Net::new(1).await;
    let (alice, bob) = (net.actor("alice", 0).await, net.actor("bob", 1).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&bob], ..Default::default() }).await;
    let body = notify_body(&space, &bob.did, "not-a-tid", &LtHash::default().digest());
    let r = Xrpc::new(&net.pds[0].url).post(NOTIFY_WRITE, &body, &Auth::None).await;
    r.err(400, "InvalidRequest");
    refused_mentioning(&notify(&net, &bob, None, body).await, &["tid"]);
}

// ---------------------------------------------------------------------------
// notifications.test.ts: the outbox, against a remote space host
// ---------------------------------------------------------------------------

struct Outbox {
    net: Net,
    w: SpaceClient,
    host: MockService,
}

impl Outbox {
    async fn new() -> Outbox {
        let net = Net::new(0).await;
        let w = net.actor("writer", 0).await;
        Outbox { net, w, host: MockService::space_host().await }
    }

    /// The writer node's first retry pause (the reference's is 1 min).
    fn retry_after(&self, d: Duration) {
        self.net.pds[0].app.spaces.as_ref().unwrap().outbox.set_retry_base(d);
    }

    fn space(&self, skey: &str) -> String {
        format!("at://{}/space/{TEST_SPACE_TYPE}/{skey}", self.host.did)
    }

    /// One write; its head rev.
    async fn write(&self, space: &str) -> String {
        write(&self.w, space, W::new()).await.ok();
        repo_state(&self.w, space).await.unwrap().0
    }

    fn sends(&self, space: &str) -> Vec<J> {
        self.host.calls_to(NOTIFY_WRITE).into_iter().map(|c| c.body).filter(|b| b["space"] == json!(space)).collect()
    }

    async fn await_rev(&self, space: &str, rev: &str) -> bool {
        eventually(Duration::from_secs(10), || {
            std::future::ready(self.sends(space).iter().any(|b| b["repoRev"] == json!(rev)).then_some(()))
        })
        .await
        .is_some()
    }
}

/// "sends immediately without queueing a successful notification"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn outbox_sends_immediately() {
    let o = Outbox::new().await;
    let space = o.space("now");
    let rev = o.write(&space).await;
    assert!(o.await_rev(&space, &rev).await);
    tokio::time::sleep(Duration::from_millis(300)).await;
    let sends = o.sends(&space);
    assert_eq!(sends.len(), 1, "{sends:?}");
    assert_eq!((&sends[0]["repo"], &sends[0]["repoRev"]), (&json!(o.w.did), &json!(rev)));
}

/// "clears an older queued notification when a new write succeeds
/// immediately" and "starts a fresh retry flow for a newer revision": a
/// refused send leaves the row backing off, and the next write sends its
/// newer rev at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn outbox_a_newer_write_sends_at_once_after_a_refusal() {
    let o = Outbox::new().await;
    let space = o.space("fresh");
    o.host.respond(503, json!({}));
    let older = o.write(&space).await;
    assert!(o.await_rev(&space, &older).await);
    o.host.respond(200, json!({}));
    let newer = o.write(&space).await;
    assert!(o.await_rev(&space, &newer).await, "the newer rev waited out the backoff");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(o.sends(&space).len(), 2);
}

/// "persists an HTTP %s response for retry" (408, 425, 429, 500, 502, 503,
/// 504, 522, 524) and "uses the HTTP status even when the XRPC error name
/// suggests a rejection"; "stops retrying HTTP %s with an unfamiliar XRPC
/// error name" (400, 401, 403, 404, 422, 501), "does not queue a rejected
/// notification" (403 Forbidden, 400 SpaceNotFound). Each status gets its
/// own space; a restart resends exactly the retryable ones. A dropped row's
/// `sP` delete rides the author's next write (no PUT of its own), so one
/// last write lands before the restart.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn outbox_keeps_retryable_refusals_and_drops_permanent_ones() {
    let host = MockService::space_host().await;
    let store: Arc<dyn object_store::ObjectStore> = Arc::new(object_store::memory::InMemory::new());
    let first = cluster_node("ob", store.clone(), 8, |c| c.spaces = true).await;
    let w = SpaceClient::new(&first, "obw", FULL_SCOPE).await;
    let retryable = [408, 425, 429, 500, 502, 503, 504, 522, 524].map(|c| (c, "CustomRejection", true));
    let permanent = [400, 401, 403, 404, 422, 501].map(|c| (c, "CustomRejection", false));
    let named = [(503, "Forbidden", true), (403, "Forbidden", false), (400, "SpaceNotFound", false)];
    let cases: Vec<(String, u16, &str, bool)> = retryable
        .into_iter()
        .chain(permanent)
        .chain(named)
        .enumerate()
        .map(|(i, (code, name, again))| (format!("at://{}/space/{TEST_SPACE_TYPE}/s{i}", host.did), code, name, again))
        .collect();
    for (space, code, name, _) in &cases {
        host.respond(*code, json!({"error": name}));
        write(&w, space, W::new()).await.ok();
        retry("the send", || {
            std::future::ready(
                host.calls_to(NOTIFY_WRITE).iter().any(|c| c.body["space"] == json!(space)).then_some(()),
            )
        })
        .await;
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    host.respond(200, json!({}));
    let last = format!("at://{}/space/{TEST_SPACE_TYPE}/last", host.did);
    write(&w, &last, W::new()).await.ok();
    vlpds::server::shutdown(&first.app).await;
    let _second = cluster_node("ob", store, 8, |c| c.spaces = true).await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    for (space, code, name, again) in &cases {
        let n = host.calls_to(NOTIFY_WRITE).iter().filter(|c| c.body["space"] == json!(space)).count();
        assert_eq!(n, if *again { 2 } else { 1 }, "HTTP {code} {name}: sends");
    }
}

/// "persists failures before the HTTP request": the authority's DID
/// document doesn't resolve at write time; the row is in the write's own
/// entry, so a restart delivers it once the document is back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn outbox_persists_a_send_that_never_reached_the_host() {
    let host = MockService::space_host().await;
    host.serve_doc(false);
    let store: Arc<dyn object_store::ObjectStore> = Arc::new(object_store::memory::InMemory::new());
    let first = cluster_node("op", store.clone(), 8, |c| c.spaces = true).await;
    let w = SpaceClient::new(&first, "opw", FULL_SCOPE).await;
    let space = format!("at://{}/space/{TEST_SPACE_TYPE}/unresolved", host.did);
    write(&w, &space, W::new()).await.ok();
    let (rev, _) = repo_state(&w, &space).await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(host.calls_to(NOTIFY_WRITE).is_empty());
    vlpds::server::shutdown(&first.app).await;
    host.serve_doc(true);
    let _second = cluster_node("op", store, 8, |c| c.spaces = true).await;
    let got = host.await_calls(NOTIFY_WRITE, 1, Duration::from_secs(15)).await.expect("delivered after the restart");
    assert_eq!(got[0].body["repoRev"], json!(rev));
}

/// "keeps newer queued work when an older delivery finishes with $code"
/// (200, 403 Forbidden, 400 SpaceNotFound): a send stalls, two writes land,
/// the stalled one finishes with `code`, and the newest rev is still sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn outbox_keeps_newer_work_when_an_older_send_finishes() {
    for (code, name) in [(200u16, None), (403, Some("Forbidden")), (400, Some("SpaceNotFound"))] {
        let o = Outbox::new().await;
        let space = o.space("race");
        let gate = o.host.gate.clone().lock_owned().await;
        o.host.respond_once(code, name.map(|n| json!({"error": n})).unwrap_or(json!({})));
        let older = o.write(&space).await;
        retry("the first send in flight", || std::future::ready((!o.sends(&space).is_empty()).then_some(()))).await;
        o.write(&space).await;
        let newest = o.write(&space).await;
        assert_ne!(older, newest);
        drop(gate);
        assert!(o.await_rev(&space, &newest).await, "HTTP {code}: the newest rev was dropped");
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(o.sends(&space).len() <= 2, "HTTP {code}: coalesced: {:?}", o.sends(&space));
    }
}

/// "clears queued work when notify/retry is rejected" (403 Forbidden, 400
/// SpaceNotFound): a send fails with 503 and is queued for a retry; then
/// either a newer write's send or the retry itself is refused, and nothing
/// more is sent. The retry pause is shortened through the outbox's hook.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn outbox_clears_queued_work_when_a_send_is_refused() {
    for (code, name) in [(403u16, "Forbidden"), (400, "SpaceNotFound")] {
        for attempt in ["notify", "retry"] {
            let o = Outbox::new().await;
            let space = o.space("refused");
            o.retry_after(match attempt {
                "retry" => Duration::from_millis(300),
                _ => Duration::from_secs(60),
            });
            o.host.respond(503, json!({}));
            o.write(&space).await;
            retry("the first send", || std::future::ready((!o.sends(&space).is_empty()).then_some(()))).await;
            o.host.respond(code, json!({"error": name}));
            if attempt == "notify" {
                o.write(&space).await;
            }
            retry("the second send", || std::future::ready((o.sends(&space).len() >= 2).then_some(()))).await;
            tokio::time::sleep(Duration::from_millis(1500)).await;
            assert_eq!(o.sends(&space).len(), 2, "HTTP {code} on the {attempt}: sent again after a refusal");
            assert!(o.net.pds[0].app.spaces.as_ref().unwrap().outbox.is_empty(), "HTTP {code} on the {attempt}");
        }
    }
}

/// "preserves a fresh retry flow when an older retry finishes with $code"
/// (200, 503, 403 Forbidden, 400 SpaceNotFound): a retry stalls at the
/// host, a newer write lands, and whatever the stalled retry gets back,
/// the newer rev is still delivered.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn outbox_keeps_a_fresh_flow_when_an_older_retry_finishes() {
    for (code, name) in [(200u16, None), (503, None), (403, Some("Forbidden")), (400, Some("SpaceNotFound"))] {
        let o = Outbox::new().await;
        let space = o.space("fresh");
        o.retry_after(Duration::from_millis(200));
        o.host.respond(503, json!({}));
        o.write(&space).await;
        retry("the first send", || std::future::ready((!o.sends(&space).is_empty()).then_some(()))).await;
        let gate = o.host.gate.clone().lock_owned().await;
        retry("the retry in flight", || std::future::ready((o.sends(&space).len() >= 2).then_some(()))).await;
        let newer = o.write(&space).await;
        o.host.respond(200, json!({}));
        o.host.respond_once(code, name.map(|n| json!({"error": n})).unwrap_or(json!({})));
        drop(gate);
        assert!(o.await_rev(&space, &newer).await, "HTTP {code}: the newer rev was dropped");
    }
}

/// "stops on local authority rejections too": a local authority refusing a
/// writer (not admitted by its write policy, or a space it doesn't govern)
/// drops the row: nothing reaches the writer set, and a later admitted
/// write goes through.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn outbox_stops_on_local_authority_rejections() {
    let net = Net::new(0).await;
    let (writer, outsider) = (net.actor("writer", 0).await, net.actor("outsider", 0).await);
    let space = net.create_space(&writer, SpaceOpts { skey: Some("notifications"), ..Default::default() }).await;
    write(&outsider, &space, W::new()).await.ok();
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(!net.writer_dids(&writer, &space).await.contains(&outsider.did));
    put_member(&writer, &space, &outsider, true, true).await.ok();
    write(&outsider, &space, W::new()).await.ok();
    assert!(net.await_writer(&writer, &space, &outsider.did).await.contains(&outsider.did));
}

/// "delivers to a local authority that is $status without a request to
/// itself" (deactivated, takendown): the PLC directory is down, so only a
/// delivery that never resolves the authority's DID reaches its writer set.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn outbox_delivers_to_a_local_inactive_authority() {
    for status in ["deactivated", "takendown"] {
        let net = Net::new(0).await;
        let (alice, dan) = (net.actor("alice", 0).await, net.actor("dan", 0).await);
        let space = net.create_space(&alice, SpaceOpts { members: &[&dan], ..Default::default() }).await;
        match status {
            "takendown" => set_repo_takedown(&net.pds[0], &alice.did, true).await,
            _ => {
                let session = Auth::Bearer(alice.session_jwt.clone());
                net.pds[0].xrpc.post("com.atproto.server.deactivateAccount", &json!({}), &session).await.ok();
            }
        }
        net.plc.set_down(true);
        write(&dan, &space, W::new().text("to an inactive authority")).await.ok();
        let writers = net.await_writer(&alice, &space, &dan.did).await;
        net.plc.set_down(false);
        assert!(writers.contains(&dan.did), "{status}: {writers:?}");
        let outbox = net.pds[0].app.spaces.as_ref().unwrap().outbox.clone();
        retry("the outbox to empty", || async { outbox.is_empty().then_some(()) }).await;
    }
}

/// "defers retries for inactive accounts and resumes after activation"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn outbox_defers_inactive_accounts_and_resumes_on_activation() {
    let host = MockService::space_host().await;
    host.respond(503, json!({}));
    let store: Arc<dyn object_store::ObjectStore> = Arc::new(object_store::memory::InMemory::new());
    let first = cluster_node("oi", store.clone(), 8, |c| c.spaces = true).await;
    let w = SpaceClient::new(&first, "oiw", FULL_SCOPE).await;
    let space = format!("at://{}/space/{TEST_SPACE_TYPE}/inactive", host.did);
    write(&w, &space, W::new()).await.ok();
    host.await_calls(NOTIFY_WRITE, 1, Duration::from_secs(10)).await.expect("first send");
    let session = Auth::Bearer(w.session_jwt.clone());
    first.xrpc.post("com.atproto.server.deactivateAccount", &json!({}), &session).await.ok();
    vlpds::server::shutdown(&first.app).await;
    host.respond(200, json!({}));
    let second = cluster_node("oi", store, 8, |c| c.spaces = true).await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(host.calls_to(NOTIFY_WRITE).len(), 1, "sent for a deactivated account");
    let session = second.create_session(&w.did, oauth_password()).await.ok();
    second
        .xrpc
        .post(
            "com.atproto.server.activateAccount",
            &json!({}),
            &Auth::Bearer(session["accessJwt"].as_str().unwrap().into()),
        )
        .await
        .ok();
    host.await_calls(NOTIFY_WRITE, 2, Duration::from_secs(15)).await.expect("resumed on activation");
}

fn oauth_password() -> &'static str {
    crate::oauth::PASSWORD
}

/// writer set: "drops a writer on removeWriter, and tracks it again once it
/// writes": the removal is listed at a new spaceRev, so a syncer catching
/// up from its cursor learns of it
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn remove_writer_drops_it_until_it_writes_again() {
    let net = Net::new(1).await;
    let (alice, bob) = (net.actor("alice", 0).await, net.actor("bob", 1).await);
    let opts = SpaceOpts { policy: Some(memberspace(json!({"publicWrite": true}))), ..Default::default() };
    let space = net.create_space(&alice, opts).await;
    write(&bob, &space, W::new().text("before removal")).await.ok();
    net.await_writer(&alice, &space, &bob.did).await;
    let cred = net.credential_for(&alice, &space).await;
    let before = list_writers(&net, &cred, &space, &[]).await;
    remove_writer(&alice, &space, &bob).await.ok();
    assert!(net.writer_dids(&alice, &space).await.is_empty());
    let caught_up = list_writers(&net, &cred, &space, &[("cursor", before["cursor"].as_str().unwrap())]).await;
    assert_eq!(
        caught_up["repos"],
        json!([{"$type": "com.atproto.space.defs#repoRemoved", "repo": bob.did, "spaceRev": caught_up["cursor"]}])
    );
    // publicWrite still admits bob, so his next write tracks him again
    write(&bob, &space, W::new().text("after removal")).await.ok();
    assert_eq!(net.await_writer(&alice, &space, &bob.did).await, vec![bob.did.clone()]);
    let listed = list_writers(&net, &cred, &space, &[]).await;
    assert_eq!(repo_dids(&listed), [bob.did.as_str()]);
    assert_eq!(listed["repos"][0]["$type"], json!("com.atproto.space.defs#repoWrite"));
}

/// writer set: "ignores removeWriter for a repo outside the writer set":
/// neither one that never wrote nor one already removed advances the space
/// sequence
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn remove_writer_ignores_a_repo_outside_the_set() {
    let net = Net::new(0).await;
    let (alice, bob, dan) = (net.actor("alice", 0).await, net.actor("bob", 0).await, net.actor("dan", 0).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&bob, &dan], ..Default::default() }).await;
    write(&dan, &space, W::new()).await.ok();
    net.await_writer(&alice, &space, &dan.did).await;
    remove_writer(&alice, &space, &dan).await.ok();
    let cred = net.credential_for(&alice, &space).await;
    let before = list_writers(&net, &cred, &space, &[]).await;
    remove_writer(&alice, &space, &bob).await.ok();
    remove_writer(&alice, &space, &dan).await.ok();
    assert_eq!(list_writers(&net, &cred, &space, &[]).await, before);
}

/// space catch-up: "returns the space's current revision on each
/// authorization", a removal included
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn authorization_returns_the_current_space_rev() {
    let net = Net::new(2).await;
    let (alice, dan, carol) = (net.actor("alice", 0).await, net.actor("dan", 0).await, net.actor("carol", 2).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&dan, &carol], ..Default::default() }).await;
    let authorize = || async {
        let token = delegation_token(&carol, &space).await;
        net.mint_credential(&space, &token, None).await.0.ok()
    };
    assert!(authorize().await.get("spaceRev").is_none());
    write(&dan, &space, W::new()).await.ok();
    net.await_writer(&alice, &space, &dan.did).await;
    let cred = net.credential_for(&carol, &space).await;
    let written = list_writers(&net, &cred, &space, &[]).await;
    assert_eq!(authorize().await["spaceRev"], written["cursor"]);
    remove_writer(&alice, &space, &dan).await.ok();
    let removed = list_writers(&net, &cred, &space, &[]).await;
    assert!(removed["cursor"].as_str() > written["cursor"].as_str());
    assert_eq!(authorize().await["spaceRev"], removed["cursor"]);
}

/// space catch-up: "forwards a removal from the writer set, in the space
/// sequence"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forwards_a_removal_in_the_space_sequence() {
    let net = Net::new(2).await;
    let (alice, dan, carol) = (net.actor("alice", 0).await, net.actor("dan", 0).await, net.actor("carol", 2).await);
    let syncer = MockService::syncer().await;
    let space = net.create_space(&alice, SpaceOpts { members: &[&dan, &carol], ..Default::default() }).await;
    net.credential_notify(&carol, &space, syncer.notify_registration("notify-token")).await.ok();
    write(&dan, &space, W::new()).await.ok();
    net.await_writer(&alice, &space, &dan.did).await;
    remove_writer(&alice, &space, &dan).await.ok();
    syncer.await_calls(UPDATE, 2, Duration::from_secs(10)).await.expect("the write and the removal");
    let updates = syncer.space_updates();
    let write = updates.iter().find(|u| u["$type"] == "com.atproto.space.defs#repoWrite").unwrap();
    let removal = updates.iter().find(|u| u["$type"] == "com.atproto.space.defs#repoRemoved").unwrap();
    let cred = net.credential_for(&carol, &space).await;
    let listed = list_writers(&net, &cred, &space, &[]).await;
    assert_eq!(
        *removal,
        json!({"$type": "com.atproto.space.defs#repoRemoved", "repo": dan.did, "spaceRev": listed["cursor"], "prevSpaceRev": write["spaceRev"]})
    );
}

/// writer set: "refuses removeWriter from anyone but the authority"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn remove_writer_is_the_authoritys_alone() {
    let net = Net::new(0).await;
    let (alice, dan) = (net.actor("alice", 0).await, net.actor("dan", 0).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&dan], ..Default::default() }).await;
    write(&dan, &space, W::new().text("still tracked")).await.ok();
    net.await_writer(&alice, &space, &dan.did).await;
    remove_writer(&dan, &space, &dan).await.err(400, "NotAuthorized");
    assert_eq!(net.writer_dids(&alice, &space).await, vec![dan.did.clone()]);
}

/// writer set: "keeps a cleared repo in the writer set, at the empty
/// digest" (the authority's `sW` row, read from its store)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cleared_repo_stays_a_writer_at_the_empty_digest() {
    let net = Net::new(0).await;
    let (alice, dan) = (net.actor("alice", 0).await, net.actor("dan", 0).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&dan], ..Default::default() }).await;
    write(&dan, &space, W::new().text("to be cleared")).await.ok();
    net.await_writer(&alice, &space, &dan.did).await;
    clear(&dan, &space).await.ok();
    let (rev, _) = repo_state(&dan, &space).await.unwrap();
    let p = net.pds[0].app.partitions.for_key(&alice.did).unwrap();
    let key = vlpds::state::space_writer_key(&alice.did, &vlpds::state::space_id(&space), &dan.did);
    let mut row = None;
    for _ in 0..100 {
        row = p.db.get(key.clone()).await.unwrap().map(|v| vlpds::space::rows::WriterRow::decode(&v).unwrap());
        if row.is_some_and(|r| r.repo_rev.to_string() == rev) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let row = row.expect("dan is still a writer");
    assert!(!row.removed);
    assert_eq!(row.repo_rev.to_string(), rev);
    assert_eq!(row.hash, LtHash::default().digest());
    assert_eq!(net.writer_dids(&alice, &space).await, vec![dan.did.clone()]);
}
