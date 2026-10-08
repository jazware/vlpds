//! Latency-neutral object-store cost defaults (bench/results/cost-model-2026-10-02,
//! "Defaults changed"): a 10 s SlateDB manifest poll, 30 s compactor/worker
//! polls while L0 is shallow, and checkpoints that skip shards with nothing
//! new since their last one.
//!
//! - `own_writes_visible_with_slow_manifest_poll`: the node is its shards'
//!   only writer, so reads see its writes at once, through flushes and
//!   compactions, whatever the manifest poll.
//! - `idle_checkpoint_writes_nothing`: a checkpoint pass on an idle node
//!   PUTs nothing; once the log moves, every shard (even one with no new
//!   entries) is checkpointed again, so replay floors and retention move.
//! - `deep_l0_ingest_keeps_up` (ignored): an unpaced single-shard bulk
//!   ingest's write stalls with the new defaults, like
//!   compaction_polling.rs's `unpaced_ingest_per_mode`.

use crate::common::*;
use object_store::path::Path;
use object_store::{
    GetOptions, GetResult, ListResult, MultipartUpload, ObjectMeta, PutMultipartOptions, PutOptions, PutPayload,
    PutResult,
};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Counts PUTs under `*/state/*` (shard DBs: SSTs, manifests, compactions).
#[derive(Debug)]
struct StatePuts {
    inner: Arc<dyn object_store::ObjectStore>,
    puts: AtomicU64,
}

impl std::fmt::Display for StatePuts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "StatePuts")
    }
}

impl StatePuts {
    fn count(&self, p: &Path) {
        let s = p.as_ref();
        if s.contains("/state/") && !s.contains("/gc/") {
            self.puts.fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[async_trait::async_trait]
impl object_store::ObjectStore for StatePuts {
    async fn put_opts(
        &self,
        location: &Path,
        payload: PutPayload,
        opts: PutOptions,
    ) -> object_store::Result<PutResult> {
        self.count(location);
        self.inner.put_opts(location, payload, opts).await
    }
    async fn put_multipart_opts(
        &self,
        location: &Path,
        opts: PutMultipartOptions,
    ) -> object_store::Result<Box<dyn MultipartUpload>> {
        self.count(location);
        self.inner.put_multipart_opts(location, opts).await
    }
    async fn get_opts(&self, location: &Path, options: GetOptions) -> object_store::Result<GetResult> {
        self.inner.get_opts(location, options).await
    }
    fn delete_stream(
        &self,
        locations: futures::stream::BoxStream<'static, object_store::Result<Path>>,
    ) -> futures::stream::BoxStream<'static, object_store::Result<Path>> {
        self.inner.delete_stream(locations)
    }
    fn list(&self, prefix: Option<&Path>) -> futures::stream::BoxStream<'static, object_store::Result<ObjectMeta>> {
        self.inner.list(prefix)
    }
    async fn list_with_delimiter(&self, prefix: Option<&Path>) -> object_store::Result<ListResult> {
        self.inner.list_with_delimiter(prefix).await
    }
    async fn copy_opts(&self, from: &Path, to: &Path, options: object_store::CopyOptions) -> object_store::Result<()> {
        self.count(to);
        self.inner.copy_opts(from, to, options).await
    }
}

fn flush() -> slatedb::config::FlushOptions {
    slatedb::config::FlushOptions { flush_type: slatedb::config::FlushType::MemTable }
}

/// Reads see the writer's own writes immediately: from the memtable, from
/// L0s it flushed (its own manifest), and after the compactor rewrote them
/// (picked up by a flush's manifest CAS or the deep-L0 refresh, not the
/// 10 s poll). Overwrites and deletes included.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn own_writes_visible_with_slow_manifest_poll() {
    let store = vlsync_store::store::Store::memory(None);
    let db = vlpds::partition::open_db(&store, vlsync_store::slots::ShardId(0), None).await.unwrap();
    let key = |i: u32| format!("k{i:05}").into_bytes();
    let check = |db: &slatedb::Db, round: u32, upto: u32| {
        let db = db.clone();
        async move {
            for i in 0..upto {
                let got = db.get(key(i)).await.unwrap();
                if i % 7 == round % 7 {
                    assert_eq!(got, None, "round {round}: k{i} was deleted");
                } else {
                    assert_eq!(got.as_deref(), Some(format!("v{round}-{i}").as_bytes()), "round {round}: k{i}");
                }
            }
        }
    };
    // 12 rounds, each overwriting every key (and deleting a seventh) then
    // flushing an L0: L0 runs deep (>= 8), so compaction goes fast while
    // the writer keeps reading its own state
    for round in 0..12u32 {
        let mut wb = slatedb::WriteBatch::new();
        for i in 0..500u32 {
            if i % 7 == round % 7 {
                wb.delete(key(i));
            } else {
                wb.put(key(i), format!("v{round}-{i}").into_bytes());
            }
        }
        db.write(wb).await.unwrap();
        check(&db, round, 500).await; // memtable
        db.flush_with_options(flush()).await.unwrap();
        check(&db, round, 500).await; // its own L0
    }
    // compaction ran and the writer saw it well before a 10 s poll could
    // matter: L0 back under the deep mark, with sorted runs
    let t = Instant::now();
    let seen = eventually(Duration::from_secs(30), || async {
        (db.manifest().l0().len() < 8 && !db.manifest().compacted().is_empty()).then_some(())
    })
    .await;
    assert!(
        seen.is_some(),
        "writer never saw compaction: L0 {}, {} sorted runs",
        db.manifest().l0().len(),
        db.manifest().compacted().len()
    );
    eprintln!("writer saw compaction after {:?}", t.elapsed());
    check(&db, 11, 500).await;
    db.close().await.unwrap();
}

/// Applied markers of every owned shard.
async fn markers(s: &TestServer) -> Vec<(vlsync_store::slots::ShardId, Option<(String, u64)>)> {
    let mut v = Vec::new();
    for p in s.app.partitions.owned() {
        v.push((
            p.id,
            p.db.get(vlpds::nodelog::META_APPLIED).await.unwrap().map(|b| vlpds::nodelog::decode_marker(&b).unwrap()),
        ));
    }
    v
}

/// Checkpoints until a pass ran with the log at rest; returns its ordinal.
async fn settle(s: &TestServer) -> u64 {
    loop {
        let o = s.app.log.durable_ordinal.load(Ordering::Acquire);
        s.app.log.checkpoint_all().await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        if s.app.log.durable_ordinal.load(Ordering::Acquire) == o {
            return o;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn idle_checkpoint_writes_nothing() {
    let counting =
        Arc::new(StatePuts { inner: Arc::new(object_store::memory::InMemory::new()), puts: AtomicU64::new(0) });
    let store: Arc<dyn object_store::ObjectStore> = counting.clone();
    let s = TestServer::spawn_with(move |c| {
        c.memory_store = Some(store);
        c.shards = 4;
        // only the explicit passes below
        c.checkpoint_every = Duration::from_secs(3600);
    })
    .await;
    let a = s.create_account("idle").await;
    s.post(&a, "one").await;
    let ord = settle(&s).await;
    let log = s.app.log.log_id.to_string();
    for (shard, m) in markers(&s).await {
        assert_eq!(m, Some((log.clone(), ord)), "shard {shard} checkpointed at {ord}");
    }
    assert_eq!(s.app.log.sinks.replay_floor(), ord, "floor at the last durable segment");

    // idle: a pass flushes nothing
    let before = counting.puts.load(Ordering::Relaxed);
    for _ in 0..3 {
        s.app.log.checkpoint_all().await;
    }
    assert_eq!(s.app.log.durable_ordinal.load(Ordering::Acquire), ord, "the log stayed idle");
    assert_eq!(counting.puts.load(Ordering::Relaxed) - before, 0, "idle checkpoints wrote to shard DBs");

    // the log moves (one repo, one shard): every shard is checkpointed at
    // the new ordinal, including those with no new entries, so replay
    // bounds and the retention floor move with the log
    s.post(&a, "two").await;
    let ord2 = settle(&s).await;
    assert!(ord2 > ord);
    for (shard, m) in markers(&s).await {
        assert_eq!(m, Some((log.clone(), ord2)), "shard {shard} checkpointed at {ord2}");
    }
    assert_eq!(s.app.log.sinks.replay_floor(), ord2, "retention floor not pinned by idle shards");
    // and idle again: nothing
    let before = counting.puts.load(Ordering::Relaxed);
    s.app.log.checkpoint_all().await;
    assert_eq!(counting.puts.load(Ordering::Relaxed) - before, 0);
}

/// One shard, unpaced bulk ingest at 10 ms store calls with the default
/// (adaptive, 30 s slow) polling and a 10 s manifest poll: the longest
/// write and time in writes over 250 ms. Compare with compaction_polling.rs
/// `unpaced_ingest_per_mode` (adaptive: worst 6 ms at 50k records/s with
/// the old 1 s / 5 s polls).
/// `INGEST_RECORDS=2000000 cargo test --release --test all cost_defaults::deep_l0 -- --ignored --nocapture`
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore]
async fn deep_l0_ingest_keeps_up() {
    let records: u64 = env_or("INGEST_RECORDS", 2_000_000);
    if let Some(ms) = std::env::var("MANIFEST_POLL_MS").ok().and_then(|v| v.parse().ok()) {
        vlpds::partition::set_manifest_poll_interval(Duration::from_millis(ms));
    }
    if let Some(ms) = std::env::var("COMPACTION_POLL_MS").ok().and_then(|v| v.parse().ok()) {
        vlpds::partition::set_compaction_poll_interval(Duration::from_millis(ms));
    }
    let store = vlsync_store::store::Store {
        raw: Arc::new(throttled_store(env_or("INGEST_LATENCY_MS", 10))),
        ..vlsync_store::store::Store::memory(None)
    };
    let db = vlpds::partition::open_db(&store, vlsync_store::slots::ShardId(0), None).await.unwrap();
    let crate::compaction_polling::Ingest { secs, worst, slow, stalled, max_l0 } =
        crate::compaction_polling::unpaced_ingest(&db, records).await;
    eprintln!(
        "ingest: {records} records in {secs:.1} s ({:.0}/s), worst write {worst:?}, {slow} writes > 250 ms ({stalled:?} total), max L0 {max_l0}",
        records as f64 / secs
    );
    tokio::time::timeout(Duration::from_secs(60), db.close()).await.expect("close hung").unwrap();
}
