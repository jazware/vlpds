//! listRepos for relay backfill at scale: per-shard cursors served by the
//! cursor shard's owner (DESIGN.md "Planet scale"). In-process 3-node
//! clusters sharing one in-memory object store; repos are written straight
//! into the owners' shard DBs (heads + accounts), so enumeration is measured
//! without creating accounts through the API.

use crate::common::*;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};
use vlpds::state;

async fn cluster(prefix: &str, shards: u32) -> Vec<TestServer> {
    let store = Arc::new(object_store::memory::InMemory::new());
    let mut nodes = Vec::new();
    for x in ["a", "b", "c"] {
        nodes.push(cluster_node(&format!("{prefix}-{x}"), store.clone(), shards, |_| {}).await);
    }
    balanced(&nodes.iter().collect::<Vec<_>>()).await;
    nodes
}

/// Writes `n` synthetic repos (bulk DIDs; every 50th deactivated) into the
/// owning nodes' shard DBs. Returns (did -> rev).
async fn populate(nodes: &[TestServer], shards: u32, n: u64) -> std::collections::HashMap<String, String> {
    let mut by_shard: Vec<Vec<(String, u64)>> = vec![Vec::new(); shards as usize];
    for i in 0..n {
        let did = state::bulk_did(i);
        by_shard[vlsync_store::slots::shard_of(&did, shards).0 as usize].push((did, i));
    }
    let mut want = std::collections::HashMap::new();
    let commit = Cid::dag_cbor(b"commit");
    let data = Cid::dag_cbor(b"data");
    for (shard, dids) in by_shard.into_iter().enumerate() {
        let p = nodes
            .iter()
            .find_map(|s| s.app.partitions.get(vlsync_store::slots::ShardId(shard as u32)))
            .expect("shard owner");
        for chunk in dids.chunks(5000) {
            let mut wb = slatedb::WriteBatch::new();
            for (did, i) in chunk {
                let rev = vlsync_atproto::tid::Tid(1_000_000 + *i);
                let head = state::Head { commit, data, rev, commit_block: bytes::Bytes::new() };
                wb.put(state::head_key(did), head.encode());
                let acct = state::Account {
                    did: did.clone(),
                    handle: state::bulk_handle(*i),
                    status: (i % 50 == 0).then(|| "deactivated".to_string()),
                    ..Default::default()
                };
                wb.put(state::account_key(did), serde_json::to_vec(&acct).unwrap());
                want.insert(did.clone(), rev.to_string());
            }
            p.db.write(wb).await.unwrap();
        }
    }
    want
}

/// One listRepos page via `s`: (repos, cursor).
async fn page(s: &TestServer, limit: usize, cursor: Option<&str>) -> (Vec<J>, Option<String>) {
    let lim = limit.to_string();
    let mut q = vec![("limit", lim.as_str())];
    if let Some(c) = cursor {
        q.push(("cursor", c));
    }
    let r = s.xrpc.get("com.atproto.sync.listRepos", &q, &Auth::None).await.ok();
    (r["repos"].as_array().unwrap().clone(), r["cursor"].as_str().map(String::from))
}

/// Enumerates every repo through `nodes` (pages round-robin over the nodes,
/// as a relay behind a load balancer would): (repos, pages, per-page latencies).
async fn enumerate(nodes: &[TestServer], limit: usize) -> (Vec<J>, usize, Vec<Duration>) {
    let mut out = Vec::new();
    let mut cursor: Option<String> = None;
    let mut lat = Vec::new();
    for i in 0.. {
        let t = Instant::now();
        let (repos, next) = page(&nodes[i % nodes.len()], limit, cursor.as_deref()).await;
        lat.push(t.elapsed());
        assert!(repos.len() <= limit);
        out.extend(repos);
        match next {
            Some(c) => cursor = Some(c),
            None => return (out, i + 1, lat),
        }
        assert!(i < 1_000_000, "too many pages");
    }
    unreachable!()
}

fn check_complete(repos: &[J], want: &std::collections::HashMap<String, String>) {
    let mut seen = HashSet::new();
    for r in repos {
        let did = r["did"].as_str().unwrap();
        assert!(seen.insert(did.to_string()), "{did} listed twice");
        assert_eq!(r["rev"].as_str(), Some(want[did].as_str()), "rev of {did}");
        assert!(r["head"].as_str().is_some());
        let deactivated = r["status"].as_str() == Some("deactivated");
        assert_eq!(r["active"], json!(!deactivated));
    }
    assert_eq!(seen.len(), want.len(), "every repo listed");
}

/// Full enumeration through any node returns every repo exactly once with
/// its head, rev and status, at small and large limits, and pages never
/// exceed the limit (shards are split over three owners).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn enumeration_is_complete_across_owners() {
    let shards = 16;
    let nodes = cluster("lrs", shards).await;
    let want = populate(&nodes, shards, 3000).await;
    for limit in [7, 500, 1000] {
        let (repos, pages, _) = enumerate(&nodes, limit).await;
        check_complete(&repos, &want);
        // short pages only at ownership boundaries
        assert!(pages <= want.len() / limit + 1 + shards as usize, "limit {limit}: {pages} pages");
    }
    // a cursor works from any node and yields the same next page
    let (_, c) = page(&nodes[0], 100, None).await;
    let c = c.expect("cursor");
    let a = page(&nodes[1], 100, Some(&c)).await;
    let b = page(&nodes[2], 100, Some(&c)).await;
    assert_eq!(a, b);
    // malformed cursors and limits
    for (k, v) in [("cursor", "nope"), ("cursor", "99999:did:plc:x"), ("limit", "0"), ("limit", "1001")] {
        let r = nodes[0].xrpc.get("com.atproto.sync.listRepos", &[(k, v)], &Auth::None).await;
        assert_eq!(r.status, 400, "{k}={v}: {:?}", r.json);
    }
}

/// Repos created or deleted mid-enumeration: everything that existed for
/// the whole enumeration is listed exactly once (stable per-shard key order).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn enumeration_is_stable_under_writes() {
    let shards = 8;
    let nodes = cluster("lrw", shards).await;
    let want = populate(&nodes, shards, 1500).await;
    let (first, mut cursor) = page(&nodes[0], 200, None).await;
    let mut got: Vec<J> = first;
    // new accounts through the API on every node while paging
    let mut added = Vec::new();
    for n in &nodes {
        let a = n.create_account("lrw").await;
        added.push(a.did.clone());
    }
    let mut i = 1;
    while let Some(c) = cursor {
        let (repos, next) = page(&nodes[i % 3], 200, Some(&c)).await;
        got.extend(repos);
        cursor = next;
        i += 1;
    }
    let mut seen = HashSet::new();
    for r in &got {
        assert!(seen.insert(r["did"].as_str().unwrap().to_string()), "duplicate {}", r["did"]);
    }
    for did in want.keys() {
        assert!(seen.contains(did), "{did} skipped");
    }
    // new repos may or may not be listed (depends on their key vs the cursor)
    assert!(seen.len() >= 1500 && seen.len() <= 1500 + added.len());
}

/// Enumeration throughput (ignored; run with --ignored --nocapture):
/// VLPDS_LR_N repos (default 1M) over 64 shards on 3 in-process nodes.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
#[ignore]
async fn enumeration_bench() {
    let n: u64 = std::env::var("VLPDS_LR_N").ok().and_then(|v| v.parse().ok()).unwrap_or(1_000_000);
    let shards = 64;
    let nodes = cluster("lrb", shards).await;
    let t = Instant::now();
    let want = populate(&nodes, shards, n).await;
    eprintln!("populated {n} repos in {:.1?}", t.elapsed());
    for limit in [500, 1000] {
        let t = Instant::now();
        let (repos, pages, mut lat) = enumerate(&nodes, limit).await;
        let el = t.elapsed().as_secs_f64();
        check_complete(&repos, &want);
        lat.sort();
        let pct = |p: f64| lat[((lat.len() as f64 - 1.0) * p) as usize];
        eprintln!(
            "listRepos limit {limit}: {pages} pages in {el:.2}s = {:.0} pages/s, {:.0} repos/s; page p50 {:.1?} p99 {:.1?}",
            pages as f64 / el,
            repos.len() as f64 / el,
            pct(0.5),
            pct(0.99)
        );
    }
}
