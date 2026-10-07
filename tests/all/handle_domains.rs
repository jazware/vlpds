//! Handle domains added at runtime (src/handle_domains.rs,
//! src/xrpc/handle_domains.rs): describeServer lists them after the
//! primary, accounts are created and resolve under them (resolveHandle,
//! `/.well-known/atproto-did`, `/tls-check`), removal is refused while
//! accounts hold handles under a domain unless forced, the primary can't be
//! removed, bad domains are refused, invite codes can be limited to one
//! domain, and a change on one node is served by its peers at once. The
//! counts come from the kept totals (crate::totals): partial only while a
//! shard's totals load, equal to a `recount`, and seeded from the account
//! rows for rows written before handle suffixes were counted.

use crate::common::*;
use std::sync::Arc;
use std::time::Duration;

async fn add(s: &TestServer, domain: &str) -> Resp {
    s.xrpc.post("vlpds.admin.addHandleDomain", &json!({"domain": domain}), &Auth::Admin).await
}

async fn remove(s: &TestServer, domain: &str, force: bool) -> Resp {
    s.xrpc.post("vlpds.admin.removeHandleDomain", &json!({"domain": domain, "force": force}), &Auth::Admin).await
}

async fn list(s: &TestServer) -> J {
    s.xrpc.get("vlpds.admin.listHandleDomains", &[], &Auth::Admin).await.ok()
}

async fn recount(s: &TestServer) -> J {
    s.xrpc.get("vlpds.admin.listHandleDomains", &[("recount", "true")], &Auth::Admin).await.ok()
}

/// The kept counts, once complete and equal to a recount.
async fn settled(s: &TestServer) -> J {
    let l = eventually(Duration::from_secs(20), || async {
        let (l, r) = (list(s).await, recount(s).await);
        (l["countsPartial"].is_null() && r["countsPartial"].is_null() && l["domains"] == r["domains"]).then_some(l)
    })
    .await;
    l.expect("kept counts never complete and equal to a recount")
}

async fn domains(s: &TestServer) -> J {
    s.xrpc.get("com.atproto.server.describeServer", &[], &Auth::None).await.ok()["availableUserDomains"].clone()
}

fn accounts(l: &J, domain: &str) -> Option<u64> {
    l["domains"].as_array().unwrap().iter().find(|d| d["domain"] == json!(domain)).and_then(|d| d["accounts"].as_u64())
}

async fn well_known(s: &TestServer, host: &str) -> (u16, String) {
    let r = reqwest::Client::new()
        .get(format!("{}/.well-known/atproto-did", s.url))
        .header("host", host)
        .send()
        .await
        .unwrap();
    (r.status().as_u16(), r.text().await.unwrap())
}

async fn tls_check(s: &TestServer, domain: &str) -> u16 {
    reqwest::get(format!("{}/tls-check?domain={domain}", s.url)).await.unwrap().status().as_u16()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn added_domain_serves_handles() {
    let s = TestServer::spawn().await;
    let primary = s.create_account("hdp").await;
    // one domain: describeServer as before
    assert_eq!(domains(&s).await, json!([format!(".{HANDLE_DOMAIN}")]));
    let unknown = format!("{}.group-a.test", unique_name("hd"));
    s.xrpc
        .post(
            "com.atproto.server.createAccount",
            &json!({"handle": unknown, "email": "u@example.com", "password": PASSWORD}),
            &Auth::None,
        )
        .await
        .err(400, "UnsupportedDomain");

    let r = add(&s, "group-a.test").await.ok();
    assert_eq!(r["domain"], "group-a.test");
    assert_eq!(domains(&s).await, json!([format!(".{HANDLE_DOMAIN}"), ".group-a.test"]));

    let a = s.create_account_with(&format!("{}.group-a.test", unique_name("hd")), PASSWORD).await;
    assert_eq!(s.resolve_handle(&a.handle).await.ok()["did"], json!(a.did));
    assert_eq!(s.resolve_handle(&a.handle.to_uppercase()).await.ok()["did"], json!(a.did));
    s.resolve_handle(&format!("nobody{}.group-a.test", unique_name("x"))).await.err(400, "HandleNotFound");
    assert_eq!(well_known(&s, &a.handle).await, (200, a.did.clone()));
    assert_eq!(well_known(&s, &format!("{}:443", a.handle.to_uppercase())).await, (200, a.did.clone()));
    assert_eq!(well_known(&s, &format!("nobody{}.group-a.test", unique_name("x"))).await.0, 404);
    assert_eq!(tls_check(&s, &a.handle).await, 200);
    assert_eq!(tls_check(&s, &primary.handle).await, 200);
    assert_eq!(tls_check(&s, &format!("nobody{}.group-a.test", unique_name("x"))).await, 404);
    assert_eq!(tls_check(&s, "x.group-b.test").await, 400);

    // the same rules as the primary's: one label of 3-18
    for bad in ["ab.group-a.test", "a.b.c.group-a.test", "group-a.test"] {
        let body = json!({"handle": bad, "email": "x@example.com", "password": PASSWORD});
        let r = s.xrpc.post("com.atproto.server.createAccount", &body, &Auth::None).await;
        assert_eq!(r.status, 400, "{bad}: {}", r.text());
    }
    // a primary account can move to the new domain, and back
    let moved = format!("{}.group-a.test", unique_name("mv"));
    s.xrpc.post("com.atproto.identity.updateHandle", &json!({"handle": moved}), &primary.auth()).await.ok();
    assert_eq!(s.resolve_handle(&moved).await.ok()["did"], json!(primary.did));
    let c = s.xrpc.get("vlpds.identity.checkHandle", &[("name", "free-name.group-a.test")], &primary.auth()).await.ok();
    assert_eq!((c["kind"].as_str(), c["status"].as_str()), (Some("service"), Some("available")));
    s.xrpc.post("com.atproto.identity.updateHandle", &json!({"handle": primary.handle}), &primary.auth()).await.ok();

    // counts and removal
    let l = complete_domain_counts(&s).await;
    assert_eq!(l["primary"], json!(HANDLE_DOMAIN));
    assert_eq!(l["domains"][0]["primary"], json!(true));
    assert_eq!(accounts(&l, "group-a.test"), Some(1));
    assert_eq!(accounts(&l, HANDLE_DOMAIN), Some(1));
    let r = remove_handle_domain_unforced(&s, "group-a.test").await;
    r.err(409, "DomainInUse");
    assert!(r.text().contains("1 active account"), "{}", r.text());
    remove(&s, HANDLE_DOMAIN, true).await.err(400, "CannotRemovePrimary");
    remove(&s, "group-b.test", false).await.err(400, "DomainNotFound");
    let r = remove(&s, "group-a.test", true).await.ok();
    assert_eq!(r["accounts"], 1);
    assert_eq!(domains(&s).await, json!([format!(".{HANDLE_DOMAIN}")]));
    // the account stays and this PDS still knows its handle (resolveHandle
    // answers from local accounts first, as for any handle), but HTTPS
    // verification and certificates stop, so elsewhere it no longer resolves
    s.account_info(&a.did).await.ok();
    assert_eq!(s.resolve_handle(&a.handle).await.ok()["did"], json!(a.did));
    assert_eq!(well_known(&s, &a.handle).await.0, 404);
    assert_eq!(tls_check(&s, &a.handle).await, 400);
    // an unused domain goes without force
    add(&s, "group-c.test").await.ok();
    remove_handle_domain_unforced(&s, "group-c.test").await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bad_domains_are_refused() {
    let s = TestServer::spawn().await;
    for bad in ["Group.test", "10.0.0.1", "::1", "test", "fly.dev", "co.uk", "x.local", "a_b.test", " "] {
        let r = add(&s, bad).await;
        assert_eq!(r.status, 400, "{bad:?}: {}", r.text());
    }
    add(&s, HANDLE_DOMAIN).await.err(400, "DomainExists");
    add(&s, "group-a.test").await.ok();
    add(&s, "group-a.test").await.err(400, "DomainExists");
    // a domain nested in another is fine: the longest match wins
    add(&s, "at.group-a.test").await.ok();
    let a = s.create_account_with(&format!("{}.at.group-a.test", unique_name("nest")), PASSWORD).await;
    let l = complete_domain_counts(&s).await;
    assert_eq!((accounts(&l, "at.group-a.test"), accounts(&l, "group-a.test")), (Some(1), Some(0)));
    assert_eq!(s.resolve_handle(&a.handle).await.ok()["did"], json!(a.did));
    s.xrpc.post("vlpds.admin.addHandleDomain", &json!({"domain": "x.test"}), &Auth::None).await.err_status(401);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn invite_codes_can_be_limited_to_a_domain() {
    let s = TestServer::spawn_with(|c| c.invite_required = true).await;
    add(&s, "group-a.test").await.ok();
    s.xrpc
        .post(
            "com.atproto.server.createInviteCode",
            &json!({"useCount": 5, "handleDomain": "group-z.test"}),
            &Auth::Admin,
        )
        .await
        .err(400, "InvalidRequest");
    let code = s
        .xrpc
        .post(
            "com.atproto.server.createInviteCode",
            &json!({"useCount": 5, "handleDomain": "group-a.test"}),
            &Auth::Admin,
        )
        .await
        .ok()["code"]
        .as_str()
        .unwrap()
        .to_string();
    let s = &s;
    let create = |handle: String| {
        let body = json!({"handle": handle, "email": format!("{}@example.com", unique_name("e")), "password": PASSWORD, "inviteCode": code});
        async move { s.xrpc.post("com.atproto.server.createAccount", &body, &Auth::None).await }
    };
    let r = create(format!("{}.{HANDLE_DOMAIN}", unique_name("inv"))).await;
    r.err(400, "InvalidInviteCode");
    assert!(r.text().contains("group-a.test"), "{}", r.text());
    create(format!("{}.group-a.test", unique_name("inv"))).await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn peers_serve_a_change_at_once() {
    let store: Arc<dyn object_store::ObjectStore> = Arc::new(object_store::memory::InMemory::new());
    let a = cluster_node("hd-a", store.clone(), 4, |_| {}).await;
    let b = cluster_node("hd-b", store.clone(), 4, |_| {}).await;
    balanced(&[&a, &b]).await;
    add(&a, "group-a.test").await.ok();
    // nudged: no wait for b's refresh
    assert_eq!(domains(&b).await, json!([format!(".{HANDLE_DOMAIN}"), ".group-a.test"]));
    let acct = a.create_account_with(&format!("{}.group-a.test", unique_name("hdc")), PASSWORD).await;
    assert!(b.app.remote_owner(&acct.did).is_some(), "owned by a");
    assert_eq!(well_known(&b, &acct.handle).await, (200, acct.did.clone()));
    assert_eq!(tls_check(&b, &acct.handle).await, 200);
    // b counts a's shards
    assert_eq!(accounts(&complete_domain_counts(&b).await, "group-a.test"), Some(1));
    remove_handle_domain_unforced(&b, "group-a.test").await.err(409, "DomainInUse");
    remove(&b, "group-a.test", true).await.ok();
    assert_eq!(domains(&a).await, json!([format!(".{HANDLE_DOMAIN}")]));
    assert_eq!(tls_check(&a, &acct.handle).await, 400);
}

async fn admin_handle(s: &TestServer, did: &str, handle: &str) {
    let body = json!({"did": did, "handle": handle});
    s.xrpc.post("com.atproto.admin.updateAccountHandle", &body, &Auth::Admin).await.ok();
}

/// Every totals row of `p`, and whether it counts suffixes.
async fn totals_rows(p: &vlpds::partition::Partition) -> Vec<(bytes::Bytes, (vlpds::totals::Totals, bool))> {
    let opts = slatedb::config::ScanOptions::default();
    let mut out = Vec::new();
    let mut it = vlpds::state::FamilyScan::new(p.db.as_ref(), vlpds::totals::FAMILY, None, &opts).await.unwrap();
    while let Some(kv) = it.next().await.unwrap() {
        out.push((kv.key, vlpds::totals::Totals::decode_row(&kv.value).unwrap()));
    }
    out
}

/// A shard whose totals are loading leaves the counts partial and removal
/// refused (there may be accounts it holds); once they load, an unused
/// domain goes without force and the counts, read on either node, follow
/// handle moves between domains, to and from bring-your-own handles, and
/// status changes without a scan.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn counts_are_kept_and_partial_only_while_loading() {
    let store: Arc<dyn object_store::ObjectStore> = Arc::new(object_store::memory::InMemory::new());
    let a = cluster_node("hdk-a", store.clone(), 4, |_| {}).await;
    add(&a, "group-a.test").await.ok();
    add(&a, "group-b.test").await.ok();
    let mut accts = Vec::new();
    for i in 0..8 {
        accts.push(match i % 2 {
            0 => a.create_account_with(&format!("{}.group-a.test", unique_name("hdk")), PASSWORD).await,
            _ => a.create_account("hdk").await,
        });
    }
    let hold = vlpds::totals::hold_loads("hdk-b");
    let b = cluster_node("hdk-b", store.clone(), 4, |_| {}).await;
    balanced(&[&a, &b]).await;
    let l = list(&b).await;
    assert_eq!(l["countsPartial"], json!(true), "{l}");
    assert!(!l["loadingShards"].as_array().unwrap().is_empty(), "{l}");
    let r = remove(&b, "group-b.test", false).await;
    r.err(409, "DomainInUse");
    assert!(r.text().contains("still loading"), "{}", r.text());
    drop(hold);

    let l = settled(&b).await;
    assert_eq!((accounts(&l, "group-a.test"), accounts(&l, HANDLE_DOMAIN)), (Some(4), Some(4)));
    remove_handle_domain_unforced(&b, "group-b.test").await.ok();

    let byo = format!("{}.elsewhere.test", unique_name("byo"));
    admin_handle(&b, &accts[0].did, &byo).await;
    let moved = format!("{}.group-a.test", unique_name("hdk"));
    b.xrpc.post("com.atproto.identity.updateHandle", &json!({"handle": moved}), &accts[1].auth()).await.ok();
    b.xrpc.post("com.atproto.server.deactivateAccount", &json!({}), &accts[2].auth()).await.ok();
    set_repo_takedown(&b, &accts[3].did, true).await;
    b.xrpc.post("com.atproto.admin.deleteAccount", &json!({"did": accts[4].did}), &Auth::Admin).await.ok();
    let l = settled(&a).await;
    // group-a: 4 - byo - deactivated - deleted + moved; primary: 4 - moved - takedown
    assert_eq!((accounts(&l, "group-a.test"), accounts(&l, HANDLE_DOMAIN)), (Some(2), Some(2)));
    // a domain added later counts the handles already under it
    add(&a, "elsewhere.test").await.ok();
    assert_eq!(accounts(&settled(&b).await, "elsewhere.test"), Some(1));
    let back = format!("{}.{HANDLE_DOMAIN}", unique_name("hdk"));
    admin_handle(&b, &accts[0].did, &back).await;
    let l = settled(&b).await;
    assert_eq!((accounts(&l, "elsewhere.test"), accounts(&l, HANDLE_DOMAIN)), (Some(0), Some(3)));
    remove_handle_domain_unforced(&a, "elsewhere.test").await.ok();
}

/// Totals rows written before handle suffixes were counted: a shard that
/// opens over them counts its account rows once, and writes the result
/// back, so later opens read it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rows_without_suffixes_are_seeded() {
    let s = TestServer::spawn().await;
    add(&s, "group-a.test").await.ok();
    for i in 0..6 {
        match i % 3 {
            0 => _ = s.create_account_with(&format!("{}.group-a.test", unique_name("seed")), PASSWORD).await,
            _ => _ = s.create_account("seed").await,
        }
    }
    assert_eq!(accounts(&settled(&s).await, "group-a.test"), Some(2));
    // as an older build left them
    let mut stripped = 0;
    for p in s.app.partitions.owned() {
        for (k, (t, _)) in totals_rows(&p).await {
            let b = vlpds::totals::Totals { suffixes: Default::default(), unconfirmed: 0, no2fa: 0, ..t }.encode();
            // the suffix count and the two flag counts, all zero: one byte each
            p.db.put(&k, &b[..b.len() - 3]).await.unwrap();
            stripped += 1;
        }
        p.db.flush().await.unwrap();
    }
    assert!(stripped > 0);
    // reopened as split halves
    let l = s.app.cluster.as_ref().unwrap().layout();
    for sh in l.shards.iter() {
        let r = s.xrpc.post("vlpds.admin.splitShard", &json!({"shard": sh.id, "wait": true}), &Auth::Admin).await.ok();
        assert_eq!(r["done"], json!(true), "{r}");
    }
    let l = settled(&s).await;
    assert_eq!((accounts(&l, "group-a.test"), accounts(&l, HANDLE_DOMAIN)), (Some(2), Some(4)));
    let saved = eventually(Duration::from_secs(10), || async {
        let mut all = true;
        for p in s.app.partitions.owned() {
            all &= totals_rows(&p).await.iter().all(|(_, (_, counts))| *counts);
        }
        all.then_some(())
    })
    .await;
    assert!(saved.is_some(), "seeded rows never written back");
}
