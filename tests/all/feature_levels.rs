//! Feature levels end to end (src/version.rs, DESIGN.md "Rolling upgrades
//! and format versioning"): in-process nodes posing as builds with
//! different level windows share one store. getClusterStatus shows the
//! active level, each node's rev and window and the banner fields; the
//! raise (`vlpds.admin.setFeatureLevel`, `vlpds admin cluster finalize`)
//! is refused while a live node can't run the level; metrics; and a peer
//! answering 404 to a scatter-gather leg reads as "unsupported", not
//! "unreachable". The raise itself, refusals (exit 7) and the joiner race
//! are covered in-process by src/cluster.rs tests (a successful raise here
//! would move this test binary's process-wide active level).

use crate::common::*;
use std::sync::Arc;
use vlsync_store::version::Window;

const SHARDS: u32 = 4;

async fn node(id: &str, store: &Arc<object_store::memory::InMemory>, levels: Window) -> TestServer {
    cluster_node(id, store.clone(), SHARDS, |c| lease(c).levels = levels).await
}

async fn status(s: &TestServer) -> J {
    s.xrpc.get("vlpds.admin.getClusterStatus", &[], &Auth::Admin).await.ok()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cluster_status_shows_levels_and_a_raise_waits_for_every_node() {
    let store = Arc::new(object_store::memory::InMemory::new());
    let a = node("fl-a", &store, Window { min: 1, max: 1 }).await;
    let b = node("fl-b", &store, Window { min: 1, max: 2 }).await;
    let st = retry("both nodes in the status", || async {
        let st = status(&a).await;
        (st["nodes"].as_array().unwrap().len() == 2).then_some(st)
    })
    .await;
    // the console builds invite links from it, wherever it's opened
    assert_eq!(st["publicUrl"], a.app.public_url.as_str(), "{st}");
    let v = &st["version"];
    assert_eq!((v["active"].as_u64(), &v["target"], v["binary"]["max"].as_u64()), (Some(1), &J::Null, Some(1)), "{st}");
    assert_eq!(
        (&v["mixedBuilds"], &v["finalizable"], &v["finalizedAt"]),
        (&json!(false), &J::Null, &J::Null),
        "one rev; fl-a can't run 2: {v}"
    );
    assert_eq!(v["history"][0]["by"], "fl-a", "created by the first node");
    let nodes = st["nodes"].as_array().unwrap();
    let n = |id: &str| nodes.iter().find(|n| n["node"] == id).unwrap_or_else(|| panic!("{id}: {st}")).clone();
    assert_eq!(
        (n("fl-a")["maxLevel"].as_u64(), n("fl-b")["maxLevel"].as_u64(), n("fl-b")["seenLevel"].as_u64()),
        (Some(1), Some(2), Some(1))
    );
    assert_eq!(n("fl-a")["rev"], json!(vlpds::build::rev()));

    // a raise to 2 from the node that can run it: fl-a can't, so nothing changes
    let r = b.xrpc.post("vlpds.admin.setFeatureLevel", &json!({"level": 2}), &Auth::Admin).await;
    r.err(409, "IncompatibleNodes");
    assert!(r.text().contains("fl-a"), "{}", r.text());
    let v = status(&b).await["version"].clone();
    assert_eq!((v["active"].as_u64(), &v["target"]), (Some(1), &J::Null), "aborted raise leaves no target: {v}");
    // fl-a's own build can't run 2; 1 is a no-op; levels never go down
    a.xrpc.post("vlpds.admin.setFeatureLevel", &json!({"level": 2}), &Auth::Admin).await.err(400, "InvalidRequest");
    assert_eq!(a.xrpc.post("vlpds.admin.setFeatureLevel", &json!({"level": 1}), &Auth::Admin).await.ok()["active"], 1);
    b.xrpc.post("vlpds.admin.setFeatureLevel", &json!({"level": 0}), &Auth::Admin).await.err(400, "InvalidRequest");
    a.xrpc.post("vlpds.admin.setFeatureLevel", &json!({"level": 1}), &Auth::None).await.err_status(401);

    // the CLI
    let (r, out) = admin_cli(&a.url, &["cluster", "status"]).await;
    r.unwrap();
    assert!(out.contains("Feature level: 1 active (this build 1..=1"), "{out}");
    assert!(out.contains("1..=2"), "per-node levels: {out}");
    let (r, out) = admin_cli(&a.url, &["cluster", "finalize", "--level", "1", "--yes"]).await;
    r.unwrap();
    assert!(out.contains("Feature level: 1 (was 1)"), "{out}");
    // `cluster lower`: to the active level is a no-op; past it (or past a
    // persistent level) it is refused
    let (r, out) = admin_cli(&a.url, &["cluster", "lower", "--level", "1", "--yes"]).await;
    r.unwrap();
    assert!(out.contains("Feature level: 1 (was 1)"), "{out}");
    a.xrpc
        .post("vlpds.admin.setFeatureLevel", &json!({"level": 0, "lower": true}), &Auth::Admin)
        .await
        .err(400, "InvalidRequest");
    a.xrpc
        .post("vlpds.admin.setFeatureLevel", &json!({"level": 2, "lower": true}), &Auth::Admin)
        .await
        .err(400, "InvalidRequest");
    let (r, _) = admin_cli(&b.url, &["cluster", "finalize", "--yes"]).await;
    let e = format!("{:#}", r.unwrap_err());
    assert!(e.contains("IncompatibleNodes") && e.contains("fl-a"), "{e}");

    // metrics
    let m = reqwest::get(format!("{}/metrics", a.url)).await.unwrap().text().await.unwrap();
    for line in [
        "vlpds_feature_level{kind=\"active\"} 1",
        "vlpds_feature_level{kind=\"binary_max\"} 1",
        "vlpds_format_errors_total{format=\"segment\"}",
    ] {
        assert!(m.contains(line), "{line} missing from /metrics");
    }
}

/// A live peer whose build lacks an internal endpoint answers 404: the
/// listing names it in `unsupportedNodes` (its shards in `missingShards`),
/// not as unreachable.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scatter_gather_404_is_unsupported_not_unreachable() {
    let store = Arc::new(object_store::memory::InMemory::new());
    let a = node("fl-sg", &store, Window::BUILD).await;
    // an "old build": a server that 404s every path, with a renewed (draining,
    // so it takes no shards) lease
    let old = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let old_addr = format!("https://{}", old.local_addr().unwrap());
    let opts = vlpds::server::ServeOptions { tls: Some(node_tls("fl-old").server_config()), ..Default::default() };
    tokio::spawn(vlpds::server::serve_with(old, axum::Router::new(), opts));
    let lease = vlpds::cluster::NodeLease {
        writer: 253,
        expires_ms: 0,
        draining: true,
        rev: "old".into(),
        ..ghost_lease("fl-old", old_addr)
    };
    let ghost = spawn_ghost(store.clone(), lease);
    let last = retry("the old build listed as unsupported", || async {
        let r = a.xrpc.get("com.atproto.admin.searchAccounts", &[("limit", "10")], &Auth::Admin).await.ok();
        r.get("unsupportedNodes").is_some().then_some(r)
    })
    .await;
    // getClusterStatus shows the mixed builds while the old one is live
    let v = status(&a).await["version"].clone();
    ghost.abort();
    assert_eq!(v["mixedBuilds"], json!(true), "{v}");
    assert!(v["revs"].as_array().unwrap().iter().any(|r| r == "old"), "{v}");
    assert_eq!(last["unsupportedNodes"], json!(["fl-old"]), "{last}");
    assert!(last.get("unreachableNodes").is_none(), "{last}");
}
