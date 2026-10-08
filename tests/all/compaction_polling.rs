//! Compaction polling (`--compaction-polling`, partition.rs): what each mode
//! costs idle (object-store requests per shard per second) and what an
//! unpaced single-shard bulk ingest stalls for. Ignored by
//! default (the ingest moves GBs); run alone, since the mode is process-wide:
//! `INGEST_RECORDS=3000000 cargo test --test all compaction_polling --
//! --ignored --nocapture --test-threads=1`.

use crate::common::{env_or, throttled_store};
use object_store::path::Path;
use object_store::{
    GetOptions, GetResult, ListResult, MultipartUpload, ObjectMeta, PutMultipartOptions, PutOptions, PutPayload,
    PutResult,
};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use vlpds::partition::CompactionPolling;

/// Counts requests (GET, PUT, LIST, DELETE) on top of another store.
#[derive(Debug)]
struct Counting {
    inner: Arc<dyn object_store::ObjectStore>,
    calls: [AtomicU64; 4],
}

impl std::fmt::Display for Counting {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Counting")
    }
}

impl Counting {
    fn new(inner: Arc<dyn object_store::ObjectStore>) -> Arc<Counting> {
        Arc::new(Counting { inner, calls: Default::default() })
    }
    fn take(&self) -> [u64; 4] {
        [0, 1, 2, 3].map(|i| self.calls[i].swap(0, Ordering::Relaxed))
    }
    fn hit(&self, i: usize) {
        self.calls[i].fetch_add(1, Ordering::Relaxed);
    }
}

#[async_trait::async_trait]
impl object_store::ObjectStore for Counting {
    async fn put_opts(
        &self,
        location: &Path,
        payload: PutPayload,
        opts: PutOptions,
    ) -> object_store::Result<PutResult> {
        self.hit(1);
        self.inner.put_opts(location, payload, opts).await
    }
    async fn put_multipart_opts(
        &self,
        location: &Path,
        opts: PutMultipartOptions,
    ) -> object_store::Result<Box<dyn MultipartUpload>> {
        self.hit(1);
        self.inner.put_multipart_opts(location, opts).await
    }
    async fn get_opts(&self, location: &Path, options: GetOptions) -> object_store::Result<GetResult> {
        self.hit(0);
        self.inner.get_opts(location, options).await
    }
    fn delete_stream(
        &self,
        locations: futures::stream::BoxStream<'static, object_store::Result<Path>>,
    ) -> futures::stream::BoxStream<'static, object_store::Result<Path>> {
        self.hit(3);
        self.inner.delete_stream(locations)
    }
    fn list(&self, prefix: Option<&Path>) -> futures::stream::BoxStream<'static, object_store::Result<ObjectMeta>> {
        self.hit(2);
        self.inner.list(prefix)
    }
    async fn list_with_delimiter(&self, prefix: Option<&Path>) -> object_store::Result<ListResult> {
        self.hit(2);
        self.inner.list_with_delimiter(prefix).await
    }
    async fn copy_opts(&self, from: &Path, to: &Path, options: object_store::CopyOptions) -> object_store::Result<()> {
        self.hit(1);
        self.inner.copy_opts(from, to, options).await
    }
}

pub(crate) struct Ingest {
    pub secs: f64,
    pub worst: Duration,
    /// Writes over 250 ms, and the time spent in them.
    pub slow: u64,
    pub stalled: Duration,
    pub max_l0: usize,
}

/// Writes `records` record rows (with their CID index rows) to one shard
/// DB as fast as it takes them, 1,000 per WriteBatch like the finalizer.
pub(crate) async fn unpaced_ingest(db: &slatedb::Db, records: u64) -> Ingest {
    let did = "did:plc:ingestingestingestingest";
    let record = vec![0xa5u8; 260];
    let started = Instant::now();
    let mut out = Ingest { secs: 0.0, worst: Duration::ZERO, slow: 0, stalled: Duration::ZERO, max_l0: 0 };
    let mut written = 0u64;
    while written < records {
        let mut wb = slatedb::WriteBatch::new();
        for i in 0..1000u64 {
            let n = written + i;
            let path = format!("app.bsky.feed.post/{n:013}");
            let cid: [u8; 32] = <sha2::Sha256 as sha2::Digest>::digest(n.to_le_bytes()).into();
            let mut val = cid.to_vec();
            val.extend_from_slice(&record);
            wb.put(vlpds::state::record_key(did, 0, &path), val);
            let c = vlsync_atproto::cid::Cid::dag_cbor(&cid);
            wb.put(vlpds::state::record_cid_key(did, 0, &c, &path), b"");
        }
        let t = Instant::now();
        if tokio::time::timeout(Duration::from_secs(60), db.write(wb)).await.is_err() {
            panic!("a write hung for 60 s at {written} records (L0 {})", db.manifest().l0().len());
        }
        let took = t.elapsed();
        out.worst = out.worst.max(took);
        if took > Duration::from_millis(250) {
            out.slow += 1;
            out.stalled += took;
        }
        out.max_l0 = out.max_l0.max(db.manifest().l0().len());
        written += 1000;
    }
    out.secs = started.elapsed().as_secs_f64();
    out
}

const MODES: [(&str, CompactionPolling); 3] =
    [("slow", CompactionPolling::Slow), ("adaptive", CompactionPolling::Adaptive), ("fast", CompactionPolling::Fast)];

/// Idle shards: requests per shard per second by mode.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn idle_requests_per_mode() {
    let shards = env_or("IDLE_SHARDS", 8) as u32;
    let secs: u64 = env_or("IDLE_SECS", 20);
    for (name, mode) in MODES {
        vlpds::partition::set_compaction_polling(mode);
        let counting = Counting::new(Arc::new(object_store::memory::InMemory::new()));
        let store = vlsync_store::store::Store { raw: counting.clone(), ..vlsync_store::store::Store::memory(None) };
        let mut dbs = Vec::new();
        for s in 0..shards {
            let db = vlpds::partition::open_db(&store, vlsync_store::slots::ShardId(s), None).await.unwrap();
            db.put(b"k", b"v").await.unwrap();
            db.flush_with_options(slatedb::config::FlushOptions { flush_type: slatedb::config::FlushType::MemTable })
                .await
                .unwrap();
            dbs.push(db);
        }
        tokio::time::sleep(Duration::from_secs(6)).await;
        counting.take();
        tokio::time::sleep(Duration::from_secs(secs)).await;
        let [g, p, l, d] = counting.take();
        let per = |n: u64| n as f64 / secs as f64 / shards as f64;
        eprintln!(
            "idle {name}: per shard per second: {:.2} GET, {:.2} PUT, {:.2} LIST, {:.2} DELETE ({:.2} total)",
            per(g),
            per(p),
            per(l),
            per(d),
            per(g + p + l + d)
        );
        for db in dbs {
            db.close().await.unwrap();
        }
    }
    vlpds::partition::set_compaction_polling(CompactionPolling::Adaptive);
}

/// One shard, unpaced bulk ingest (one WriteBatch of 1,000 records per
/// "segment", like the finalizer), store calls at INGEST_LATENCY_MS: the
/// longest single write and the time spent in writes over 250 ms, by mode.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore]
async fn unpaced_ingest_per_mode() {
    let records: u64 = env_or("INGEST_RECORDS", 3_000_000);
    let latency_ms = env_or("INGEST_LATENCY_MS", 10);
    crate::common::init_tracing();
    let only = std::env::var("INGEST_MODES").unwrap_or_default();
    for (name, mode) in MODES {
        if !only.is_empty() && !only.split(',').any(|m| m == name) {
            continue;
        }
        vlpds::partition::set_compaction_polling(mode);
        let counting = Counting::new(Arc::new(throttled_store(latency_ms)));
        let store = vlsync_store::store::Store { raw: counting.clone(), ..vlsync_store::store::Store::memory(None) };
        let db = vlpds::partition::open_db(&store, vlsync_store::slots::ShardId(0), None).await.unwrap();
        let Ingest { secs, worst, slow, stalled, .. } = unpaced_ingest(&db, records).await;
        let [g, p, l, d] = counting.take();
        eprintln!(
            "ingest {name}: {records} records in {secs:.1} s ({:.0}/s), worst write {worst:?}, {slow} writes > 250 ms ({stalled:?} total); requests {g} GET {p} PUT {l} LIST {d} DELETE",
            records as f64 / secs
        );
        let m = db.manifest();
        eprintln!("{name}: closing with L0 {} and {} sorted runs", m.l0().len(), m.compacted().len());
        tokio::time::timeout(Duration::from_secs(60), db.close()).await.expect("close hung").unwrap();
    }
    vlpds::partition::set_compaction_polling(CompactionPolling::Adaptive);
}
