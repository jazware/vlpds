//! Storage stats (vlsync-store/src/store_stats.rs, src/xrpc/console_storage.rs): object
//! counts by component kept from the node's own requests, seeded by one
//! capped backfill, gathered from every node; and getConfig's peer TLS and
//! secret-file extras.

use crate::common::*;
use futures::StreamExt;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

async fn admin_get(s: &TestServer, nsid: &str) -> J {
    s.xrpc.get(nsid, &[], &Auth::Admin).await.ok()
}

async fn backfill(s: &TestServer, body: J) -> J {
    s.xrpc.post("vlpds.admin.backfillStorageStats", &body, &Auth::Admin).await.ok()
}

/// What's in the bucket now, by component.
async fn listed(s: &TestServer) -> BTreeMap<String, (i64, i64)> {
    let store = object_store::path::Path::from(s.app.store.prefix.clone());
    let mut out: BTreeMap<String, (i64, i64)> = BTreeMap::new();
    let mut l = s.app.store.raw.list(Some(&store));
    while let Some(m) = l.next().await {
        let m = m.unwrap();
        let c = vlsync_store::objstats::component(&s.app.store.prefix, m.location.as_ref());
        let e = out.entry(c.to_string()).or_default();
        e.0 += 1;
        e.1 += m.size as i64;
    }
    out
}

fn counted(r: &J) -> BTreeMap<String, (i64, i64)> {
    r["components"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| {
            (
                c["component"].as_str().unwrap().to_string(),
                (c["objects"].as_i64().unwrap(), c["bytes"].as_i64().unwrap()),
            )
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn admin_only() {
    let s = TestServer::spawn().await;
    let a = s.create_account("sstat").await;
    s.xrpc.get("vlpds.admin.getStorageStats", &[], &a.auth()).await.err(401, "AuthenticationRequired");
    s.xrpc
        .post("vlpds.admin.backfillStorageStats", &json!({"dryRun": true}), &a.auth())
        .await
        .err(401, "AuthenticationRequired");
}

/// Before a backfill the counts are changes only; a dry run estimates, a
/// run without a budget is refused, a run seeds the counters, and from
/// then on writes keep them equal to a listing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn backfill_seeds_and_writes_keep_up() {
    let s = TestServer::spawn().await;
    let a = s.create_account("sstat").await;
    for i in 0..5 {
        s.post(&a, &format!("before {i}")).await;
    }
    let r = admin_get(&s, "vlpds.admin.getStorageStats").await;
    assert_eq!(r["seeded"], false, "{r}");
    assert_eq!(r["exact"], false);
    assert!(r["lastBackfillAt"].is_null());

    let dry = backfill(&s, json!({"dryRun": true})).await;
    assert_eq!(dry["dryRun"], true, "{dry}");
    assert!(dry["estimatedRequests"].as_u64().unwrap() >= 1, "{dry}");
    s.xrpc.post("vlpds.admin.backfillStorageStats", &json!({}), &Auth::Admin).await.err(400, "InvalidRequest");

    let started = backfill(&s, json!({"maxRequests": 100, "pagesPerSecond": 50})).await;
    assert_eq!(started["started"], true, "{started}");
    let r = eventually(Duration::from_secs(20), || async {
        let r = admin_get(&s, "vlpds.admin.getStorageStats").await;
        (r["backfill"]["phase"] == "done" && r["seeded"] == true).then_some(r)
    })
    .await
    .expect("backfill done");
    assert!(r["lastBackfillAt"].as_u64().unwrap() > 1_700_000_000_000, "{r}");

    for i in 0..5 {
        s.post(&a, &format!("after {i}")).await;
    }
    // idle again, the kept counts match what's there
    let last = Arc::new(parking_lot::Mutex::new(None));
    let (want, got) = eventually(Duration::from_secs(30), || async {
        let want = listed(&s).await;
        let r = admin_get(&s, "vlpds.admin.getStorageStats").await;
        let got = counted(&r);
        let unsure: Vec<&str> = r["components"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|c| c["uncertain"] != 0)
            .map(|c| c["component"].as_str().unwrap())
            .collect();
        // an exact component equals the listing, objects and bytes
        let same = want.keys().chain(got.keys()).filter(|k| !unsure.contains(&k.as_str())).all(|k| {
            let (w, g) = (want.get(k).copied().unwrap_or_default(), got.get(k).copied().unwrap_or_default());
            w == g
        });
        *last.lock() = Some((want.clone(), r.clone()));
        (same && unsure.is_empty()).then_some((want, r))
    })
    .await
    .unwrap_or_else(|| panic!("counts never matched a listing: {:?}", last.lock()));
    assert_eq!(got["totalObjects"].as_i64().unwrap(), want.values().map(|v| v.0).sum::<i64>(), "{got}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn config_extras() {
    let s = TestServer::spawn().await;
    let r = admin_get(&s, "vlpds.admin.getConfig").await;
    let tls = &r["peerTls"];
    assert_eq!(tls["nodeId"], "single", "{r}");
    assert!(tls["notAfter"].as_u64().unwrap() > tls["notBefore"].as_u64().unwrap(), "{r}");
    // the harness's CA is made once per test process, so it can end before a later node cert
    assert!(tls["caNotAfter"].as_u64().unwrap() > tls["notBefore"].as_u64().unwrap(), "{r}");
    // an in-process node has no command line, so no secret files
    assert_eq!(r["secretFiles"], json!([]), "{r}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gathers_every_node() {
    let store: Arc<object_store::memory::InMemory> = Arc::new(object_store::memory::InMemory::new());
    let a = cluster_node("sst-a", store.clone(), 4, |_| {}).await;
    let b = cluster_node("sst-b", store.clone(), 4, |_| {}).await;
    eventually(Duration::from_secs(20), || async {
        [&a, &b]
            .iter()
            .all(|s| {
                let c = s.app.cluster.as_ref().unwrap();
                c.peers().iter().any(|l| l.node_id != c.cfg.node_id)
            })
            .then_some(())
    })
    .await
    .expect("two-node cluster formed");
    let r = admin_get(&a, "vlpds.admin.getStorageStats").await;
    assert!(r.get("unreachableNodes").is_none(), "{r}");
    let mut ids: Vec<&str> = r["nodes"].as_array().unwrap().iter().map(|n| n["node"].as_str().unwrap()).collect();
    ids.sort();
    assert_eq!(ids, ["sst-a", "sst-b"], "{r}");
    // run on one node, seen from the other, with both windows closed
    backfill(&a, json!({"maxRequests": 100, "pagesPerSecond": 50})).await;
    eventually(Duration::from_secs(20), || async {
        let r = admin_get(&b, "vlpds.admin.getStorageStats").await;
        (r["seeded"] == true && r["backfill"]["phase"] == "done" && r["windowChanges"] == 0).then_some(())
    })
    .await
    .expect("seeded, seen from the other node");
    let acct = a.create_account("sstat").await;
    a.post(&acct, "x").await;
    let r = admin_get(&b, "vlpds.admin.getStorageStats").await;
    assert!(r["totalObjects"].as_i64().unwrap() > 0, "{r}");
}
