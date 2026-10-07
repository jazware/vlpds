//! Rolling upgrades with a real format change (DESIGN.md "Rolling upgrades
//! and format versioning", "Tests and CI"), built only with the test-only
//! feature level: `cargo test --features test-level --test level_gating`.
//!
//! - `one_level_below_max_writes_nothing_new`, the level-gating test: a
//!   cluster of this build (`MAX_LEVEL` = the test level) running at
//!   `MAX_LEVEL - 1` writes, splits a shard, hands shards off and back, and
//!   every object it put in the bucket is the previous level's format
//!   (segment magic and header layout, control-object fields checked against
//!   `testdata/formats/L{MAX_LEVEL-1}`). Then it finalizes: new segments
//!   and `retain/` reports switch to the test level's formats, a restarted
//!   node replays logs holding both, and every acked write is readable and
//!   on every node's firehose exactly once, in order.
//! - `formats::` (tests/all/formats.rs, included here): the test level's
//!   fixtures (`testdata/formats/Ltest`) and every lower level decode.
//!
//! Its own binary because the active level is process-wide.

macro_rules! suite_only {
    ($($i:item)*) => {};
}

#[path = "all/common/mod.rs"]
mod common;
#[path = "all/formats.rs"]
mod formats;

use common::*;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::Arc;
use std::time::Duration;
use vlpds::version;

const SHARDS: u32 = 6;
const PREFIX: &str = "vlpds";

async fn node(id: &str, store: &Arc<object_store::memory::InMemory>) -> TestServer {
    cluster_node(id, store.clone(), SHARDS, |c| {
        // reports every 100 ms; nothing is old enough to prune
        c.log_retention = Some(vlpds::retention::Config {
            window: Duration::from_secs(3600),
            interval: Duration::from_millis(100),
            max_deletes: 100,
            fence_retention: None,
        });
    })
    .await
}

/// A graceful stop (SIGTERM): hand shards off, fence our log, drop the
/// lease. Its log streams end once the log is fenced, so peers drain it to
/// the fence while the in-process node lingers.
async fn stop(n: TestServer) {
    vlpds::server::shutdown(&n.app).await;
}

/// Every object under the prefix: (path relative to it, bytes).
async fn objects(store: &object_store::memory::InMemory) -> Vec<(String, bytes::Bytes)> {
    use futures::StreamExt;
    use object_store::{ObjectStore, ObjectStoreExt};
    let metas: Vec<_> =
        store.list(Some(&object_store::path::Path::from(PREFIX))).map(|m| m.unwrap().location).collect().await;
    let mut out = Vec::new();
    for p in metas {
        let Ok(r) = store.get(&p).await else { continue }; // deleted meanwhile
        let rel = p.as_ref().strip_prefix(&format!("{PREFIX}/")).unwrap().to_string();
        out.push((rel, r.bytes().await.unwrap()));
    }
    out
}

/// Top-level keys of a JSON object fixture of `level`.
fn fixture_keys(level: u32, name: &str) -> BTreeSet<String> {
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!("testdata/formats/L{level}"));
    let j: J = serde_json::from_slice(&std::fs::read(dir.join(name)).unwrap()).unwrap();
    j.as_object().unwrap().keys().cloned().collect()
}

#[derive(Default, Debug)]
struct Scan {
    /// segment level -> count
    segments: BTreeMap<u32, usize>,
    fences: usize,
    /// reports with / without the test level's field
    reports: (usize, usize),
    control: usize,
}

/// Classifies every object in the bucket. With `at_most = Some(l)`, fails
/// on any object in a format newer than level `l`: segments by magic and
/// header layout, control objects by their fields (only those the level-`l`
/// fixture has, plus the optional ones it leaves out). Unknown object
/// families fail too, so a new one gets a rule here.
async fn scan(store: &object_store::memory::InMemory, at_most: Option<u32>) -> Scan {
    use vlpds::segment;
    let mut s = Scan::default();
    // fields the fixtures leave out because they were None (or 0) there
    let optional: BTreeMap<&str, &[&str]> = [
        ("assign", &["frozen", "applied_epoch"][..]),
        ("layout", &["op"][..]),
        ("version", &["target"][..]),
        ("nodes", &[][..]),
        ("writers", &[][..]),
        ("retain", &[][..]),
    ]
    .into();
    let keys = |fixture: &str, family: &str, l: u32| -> BTreeSet<String> {
        let mut k = fixture_keys(l, fixture);
        k.extend(optional[family].iter().map(|s| s.to_string()));
        k
    };
    for (path, b) in objects(store).await {
        let family = path.split('/').next().unwrap();
        let check_json = |fixture: &str, fam: &str| {
            let Some(l) = at_most else { return };
            let j: J = serde_json::from_slice(&b).unwrap_or_else(|e| panic!("{path}: {e}"));
            let extra: Vec<&String> =
                j.as_object().unwrap().keys().filter(|k| !keys(fixture, fam, l).contains(*k)).collect();
            assert!(extra.is_empty(), "{path} has fields of a level above {l}: {extra:?}: {j}");
        };
        match family {
            "log" => match segment::parse_header(&b).unwrap_or_else(|e| panic!("{path}: {e:#}")) {
                None => s.fences += 1,
                Some((h, _)) => {
                    if let Some(l) = at_most {
                        assert!(
                            h.level <= l && &b[..8] == version::segment_magic(h.level),
                            "{path}: segment of level {} at most {l} expected",
                            h.level
                        );
                        assert!(h.checksum.is_none() || h.level >= version::TEST_LEVEL, "{path}");
                    }
                    // and the whole object parses (the test level's checksum verifies)
                    segment::parse(b.clone(), true, None).unwrap_or_else(|e| panic!("{path}: {e:#}"));
                    *s.segments.entry(h.level).or_default() += 1;
                }
            },
            "retain" => {
                check_json("control/retain_report.json", "retain");
                let r: vlpds::retention::Report = serde_json::from_slice(&b).unwrap();
                if r.min_seg_format.is_some() {
                    s.reports.0 += 1;
                } else {
                    s.reports.1 += 1;
                }
            }
            "nodes" => check_json("control/node_lease.json", "nodes"),
            "writers" => check_json("control/writer_claim.json", "writers"),
            "assign" if path == "assign/layout" => check_json("control/layout.json", "layout"),
            "assign" => check_json("control/assignment.json", "assign"),
            "cluster" if path == "cluster/version" => check_json("control/cluster_version.json", "version"),
            // SlateDB's own files (slatedb's format, pinned rev); state is a
            // function of the log, whose formats are checked above
            "state" => continue,
            // existence claims and content-addressed blobs: no level
            "handle" | "email" | "blob" | "blob-gc" | "blob-tmp" => continue,
            // storage counters and the backfill cursor: observability only, a
            // backfill rebuilds them, so an older build ignoring them is safe
            "stats" => continue,
            other => panic!("unclassified object family {other:?} ({path}): give it a rule in level_gating.rs"),
        }
        if !matches!(family, "log") {
            s.control += 1;
        }
    }
    s
}

/// Writes `n` posts per account, round-robin through `via`; returns (did, rev) per ack.
async fn write(via: &[&TestServer], accts: &[TestAccount], n: usize, tag: &str, acked: &mut Vec<(String, RecordRef)>) {
    for i in 0..n {
        for (j, a) in accts.iter().enumerate() {
            let s = via[(i + j) % via.len()];
            // a client retries the 503s of a shard moving (handoff, split)
            let mut tries = 0;
            let r = loop {
                let r = s.xrpc.post("com.atproto.repo.createRecord", &json!({"repo": a.did, "collection": "app.bsky.feed.post", "record": post_record(&format!("{tag} {i}"))}), &a.auth()).await;
                tries += 1;
                if r.status == 503 && tries < 100 {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
                break RecordRef::from_json(&r.ok());
            };
            acked.push((a.did.clone(), r));
        }
    }
}

/// Every acked write is readable through every node and on its firehose
/// from cursor 0 exactly once, seqs ascending.
async fn verify(nodes: &[&TestServer], acked: &[(String, RecordRef)]) {
    for n in nodes {
        for (did, r) in acked.iter().step_by(7) {
            n.get_record(did, r.collection(), r.rkey()).await.ok();
        }
        let want: HashSet<(String, String)> = acked.iter().map(|(d, r)| (d.clone(), r.rev.clone().unwrap())).collect();
        let mut sub = n.subscribe(Some(0)).await;
        let frames = sub
            .until(Duration::from_secs(30), |fs| {
                let seen: HashSet<(String, String)> =
                    fs.iter().filter_map(|f| f.commit()).map(|c| (c.repo, c.rev)).collect();
                want.is_subset(&seen)
            })
            .await;
        let (mut last, mut seen) = (0i64, HashSet::new());
        for f in &frames {
            let Some(seq) = f.seq() else { continue };
            assert!(seq > last, "{}: seq {seq} after {last}", n.url);
            last = seq;
            if let Some(c) = f.commit() {
                assert!(seen.insert((c.repo, c.rev)), "{}: duplicate commit at {seq}", n.url);
            }
        }
        let got: HashSet<(String, String)> = seen.into_iter().collect();
        assert!(
            want.is_subset(&got),
            "{}: {} acked commits missing from the firehose",
            n.url,
            want.difference(&got).count()
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn one_level_below_max_writes_nothing_new() {
    let _level = ACTIVE_LEVEL.lock().await;
    assert_eq!(version::MAX_LEVEL, version::TEST_LEVEL, "built with --features test-level");
    let below = version::MAX_LEVEL - 1;
    let store = Arc::new(object_store::memory::InMemory::new());
    // the cluster runs one level below this build's max (as after a rolling
    // upgrade to it, before finalize)
    {
        use object_store::ObjectStoreExt;
        let v = version::ClusterVersion::new(below, "test");
        store
            .put(
                &object_store::path::Path::from(format!("{PREFIX}/{}", version::OBJECT)),
                serde_json::to_vec(&v).unwrap().into(),
            )
            .await
            .unwrap();
    }
    let a = node("lg-a", &store).await;
    let b = node("lg-b", &store).await;
    let c = node("lg-c", &store).await;
    balanced(&[&a, &b, &c]).await;
    assert_eq!(version::active(), below);
    let mut accts = Vec::new();
    for (i, s) in [&a, &b, &c].iter().enumerate() {
        for _ in 0..3 {
            accts.push(s.create_account(&format!("lg{i}")).await);
        }
    }
    let mut acked = Vec::new();
    write(&[&a, &b, &c], &accts, 4, "before", &mut acked).await;

    // a split under writes
    let target = a.app.partitions.owned()[0].id;
    let r = a.xrpc.post("vlpds.admin.splitShard", &json!({"shard": target, "wait": true}), &Auth::Admin).await.ok();
    assert!(r["done"].as_bool().unwrap_or(true), "{r}");
    write(&[&a, &b, &c], &accts, 2, "after split", &mut acked).await;
    // a graceful handoff and back (c leaves, its shards move; it returns)
    stop(c).await;
    balanced(&[&a, &b]).await;
    write(&[&a, &b], &accts, 2, "c gone", &mut acked).await;
    let c = node("lg-c", &store).await;
    balanced(&[&a, &b, &c]).await;
    write(&[&a, &b, &c], &accts, 2, "c back", &mut acked).await;
    retry("every node's retention report", || async { (scan(&store, None).await.reports.1 >= 3).then_some(()) }).await;

    let s = scan(&store, Some(below)).await;
    eprintln!("at level {below}: {s:?}");
    assert!(s.segments.get(&below).is_some_and(|n| *n > 10) && s.segments.len() == 1, "{s:?}");
    assert!(s.fences >= 1, "c's graceful exit fenced its log: {s:?}");
    assert!(s.reports.1 >= 3 && s.reports.0 == 0, "{s:?}");
    verify(&[&a, &b, &c], &acked).await;

    // a persistent level is never lowered; finalize raises to the test level
    let v = b.xrpc.post("vlpds.admin.setFeatureLevel", &json!({"level": version::MAX_LEVEL}), &Auth::Admin).await.ok();
    assert_eq!(v["active"].as_u64(), Some(version::MAX_LEVEL as u64), "{v}");
    a.xrpc
        .post("vlpds.admin.setFeatureLevel", &json!({"level": below, "lower": true}), &Auth::Admin)
        .await
        .err(400, "InvalidRequest");
    // every node observes it within a TTL; writers switch at their next segment
    for n in [&a, &b, &c] {
        wait_until("nodes observing the raise", Duration::from_secs(10), || {
            cluster(n).own_lease().seen_level == version::MAX_LEVEL
        })
        .await;
    }
    write(&[&a, &b, &c], &accts, 3, "finalized", &mut acked).await;
    retry("test-level segments and reports", || async {
        let s = scan(&store, None).await;
        (s.segments.get(&version::TEST_LEVEL).is_some_and(|n| *n >= 3) && s.reports.0 >= 3).then_some(())
    })
    .await;
    verify(&[&a, &b, &c], &acked).await;

    // a restart replays logs holding both formats (b's shards move and back)
    stop(b).await;
    balanced(&[&a, &c]).await;
    write(&[&a, &c], &accts, 2, "b gone", &mut acked).await;
    let b = node("lg-b", &store).await;
    balanced(&[&a, &b, &c]).await;
    write(&[&a, &b, &c], &accts, 2, "b back", &mut acked).await;
    let s = scan(&store, None).await;
    eprintln!("after finalize: {s:?}");
    assert!(s.segments.contains_key(&below) && s.segments.contains_key(&version::TEST_LEVEL), "{s:?}");
    verify(&[&a, &b, &c], &acked).await;
    let m = reqwest::get(format!("{}/metrics", a.url)).await.unwrap().text().await.unwrap();
    assert!(m.contains("vlpds_format_errors_total{format=\"segment\"} 0"), "no format errors");
    for n in [&a, &b, &c] {
        vlpds::server::shutdown(&n.app).await;
    }
}
