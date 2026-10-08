//! Memory and time of one big importRepo, by block order. One mode per
//! process (resident memory never shrinks back):
//!
//! ```text
//! IMPORT_BENCH_DIR=<dir> IMPORT_BENCH_N=1000000 IMPORT_BENCH_MODE=gen|stream|cid \
//!   cargo test --profile dev-release --features bench-jemalloc --test all \
//!   import_bench -- --ignored --nocapture
//! ```
//!
//! `gen` writes `<dir>/<n>-{stream,cid}.car`; the others import one. The
//! node's bucket is in memory, so what it holds is counted apart and left
//! out of the heap figures; its SST caches are pinned small.
//! `IMPORT_BENCH_TRACE=<secs>` prints the heap (and the write path's
//! gauges) every 250 ms, through `<secs>` after the import.
use crate::common::*;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use vlsync_atproto::cbor::key_cmp;

fn env(k: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| panic!("{k} unset"))
}

fn gen(dir: &str, n: usize) {
    let mut tree = vlsync_atproto::mst::Tree::new();
    let mut blocks: Vec<(Cid, Vec<u8>)> = Vec::with_capacity(n + n / 3);
    for i in 0..n {
        let (coll, mut m) = if i % 2 == 0 {
            (
                "app.bsky.feed.post",
                vec![
                    (
                        "text".to_string(),
                        Value::Text(format!(
                            "post number {i}: some ordinary text of a typical length, with a few words more {i}"
                        )),
                    ),
                    ("langs".to_string(), Value::Array(vec![Value::Text("en".into())])),
                ],
            )
        } else {
            (
                "app.bsky.feed.like",
                vec![(
                    "subject".to_string(),
                    Value::Map(vec![
                        (
                            "cid".to_string(),
                            Value::Text("bafyreie5737gdxlw5i64vzichcalba3z2v5n6icifvx5xytvske7mr3hpm".into()),
                        ),
                        (
                            "uri".to_string(),
                            Value::Text(format!("at://did:plc:ewvi7nxzyoun6zhxrhs64oiz/app.bsky.feed.post/3l{i:011}")),
                        ),
                    ]),
                )],
            )
        };
        m.push(("$type".to_string(), Value::Text(coll.into())));
        m.push(("createdAt".to_string(), Value::Text("2026-01-01T00:00:00.000Z".into())));
        m.sort_by(|a, b| key_cmp(&a.0, &b.0));
        let rec = Value::Map(m).to_cbor();
        let c = Cid::dag_cbor(&rec);
        tree.insert_no_proof(format!("{coll}/3l{i:011}").as_bytes(), c).unwrap();
        blocks.push((c, rec));
    }
    let data = tree.write_diff_blocks(&mut blocks).unwrap();
    drop(tree);
    let mut f = vec![
        ("did".to_string(), Value::Text("did:plc:bench".into())),
        ("rev".to_string(), Value::Text("3l3qo2vuowo2b".into())),
        ("data".to_string(), Value::Link(data)),
        ("prev".to_string(), Value::Null),
        ("version".to_string(), Value::Int(3)),
        ("sig".to_string(), Value::Bytes(vec![0; 64])),
    ];
    f.sort_by(|a, b| key_cmp(&a.0, &b.0));
    let commit = Value::Map(f).to_cbor();
    let root = Cid::dag_cbor(&commit);
    blocks.sort_by_key(|(c, _)| c.to_bytes());
    let mut cid = Vec::new();
    vlsync_atproto::car::write_header(&mut cid, &root);
    vlsync_atproto::car::write_block(&mut cid, &root, &commit);
    for (c, b) in &blocks {
        vlsync_atproto::car::write_block(&mut cid, c, b);
    }
    std::fs::write(format!("{dir}/{n}-cid.car"), &cid).unwrap();
    let map: std::collections::HashMap<Cid, Vec<u8>> = blocks.into_iter().collect();
    let stream = vlsync_atproto::car_order::write_car((root, &commit), data, &map).unwrap();
    std::fs::write(format!("{dir}/{n}-stream.car"), &stream).unwrap();
    println!("wrote {} and {} bytes", cid.len(), stream.len());
}

pub(crate) fn jemalloc() -> (u64, u64) {
    use tikv_jemalloc_ctl::{epoch, stats};
    epoch::advance().unwrap();
    (stats::allocated::read().unwrap() as u64, stats::resident::read().unwrap() as u64)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn import_bench() {
    let (dir, n, mode) =
        (env("IMPORT_BENCH_DIR"), env("IMPORT_BENCH_N").parse::<usize>().unwrap(), env("IMPORT_BENCH_MODE"));
    if mode == "gen" {
        return gen(&dir, n);
    }
    let store = Arc::new(Sized::default());
    let held = store.bytes.clone();
    let s = TestServer::spawn_with(move |c| {
        // flushes and compactions fill the SST caches with what they wrote,
        // whatever wrote it: pinned small so they don't hide the import's
        // own heap
        c.memory.block = Some(64 << 20);
        c.memory.meta = Some(16 << 20);
        c.max_import_bytes = 2 << 30;
        c.memory_store = Some(store);
    })
    .await;
    let a = s.create_account("bench").await;
    // held until the end: the request body's buffer doesn't leave the heap
    // while the import still runs
    let car = bytes::Bytes::from(std::fs::read(format!("{dir}/{n}-{mode}.car")).unwrap());
    let len = car.len();
    let (base_alloc, base_res) = jemalloc();
    let base_held = held.load(Ordering::Relaxed);
    let stop = Arc::new(AtomicBool::new(false));
    let (peak_heap, peak_res, peak_held) =
        (Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0)));
    let t = Instant::now();
    let sampler = {
        let (stop, ph, pr, pb, held) =
            (stop.clone(), peak_heap.clone(), peak_res.clone(), peak_held.clone(), held.clone());
        std::thread::spawn(move || {
            let trace = std::env::var("IMPORT_BENCH_TRACE").is_ok();
            let mut i = 0u64;
            while !stop.load(Ordering::Relaxed) {
                let (al, rs) = jemalloc();
                let bucket = (held.load(Ordering::Relaxed) - base_held).max(0) as u64;
                ph.fetch_max(al.saturating_sub(bucket), Ordering::Relaxed);
                pr.fetch_max(rs.saturating_sub(bucket), Ordering::Relaxed);
                pb.fetch_max(bucket, Ordering::Relaxed);
                i += 1;
                if trace && i.is_multiple_of(125) {
                    let mut g = String::new();
                    for mf in prometheus::gather() {
                        let n = mf.name();
                        if n.contains("compacted")
                            || n.contains("memtable")
                            || n.contains("unflushed")
                            || n.contains("live_bytes")
                            || n.contains("ring_bytes")
                        {
                            let v: f64 = mf.get_metric().iter().map(|m| m.get_gauge().get_value()).sum();
                            if v >= 1e6 {
                                g.push_str(&format!(" {n}={:.0}MB", v / 1e6));
                            }
                        }
                    }
                    eprintln!(
                        "t={:.1}s heap-bucket={} MB bucket={} MB{g}",
                        t.elapsed().as_secs_f64(),
                        (al.saturating_sub(bucket).saturating_sub(base_alloc)) >> 20,
                        bucket >> 20
                    );
                }
                std::thread::sleep(Duration::from_millis(2));
            }
        })
    };
    let url = format!("{}/xrpc/com.atproto.repo.importRepo", s.xrpc.base);
    let r = s
        .xrpc
        .http
        .post(url)
        .header("content-type", "application/vnd.ipld.car")
        .bearer_auth(&a.access)
        .body(car.clone())
        .send()
        .await
        .unwrap();
    let status = r.status();
    let text = r.text().await.unwrap_or_default();
    let took = t.elapsed();
    if std::env::var("IMPORT_BENCH_TRACE").is_ok() {
        let secs = std::env::var("IMPORT_BENCH_TRACE").ok().and_then(|s| s.parse().ok()).unwrap_or(8);
        tokio::time::sleep(Duration::from_secs(secs)).await;
        for mf in prometheus::gather() {
            for m in mf.get_metric() {
                let v = m.get_gauge().get_value();
                if v > 20e6 {
                    let labels: Vec<String> =
                        m.get_label().iter().map(|l| format!("{}={}", l.name(), l.value())).collect();
                    eprintln!("gauge {} {:?} = {:.0} MB", mf.name(), labels, v / 1e6);
                }
            }
        }
        eprintln!("caches {:?}", vlpds::partition::cache_stats());
    }
    stop.store(true, Ordering::Relaxed);
    sampler.join().unwrap();
    assert_eq!(status, 200, "{text}");
    drop(car);
    let path =
        if vlpds::metrics::IMPORT_REPO_PARSES.with_label_values(&["stream"]).get() > 0 { "stream" } else { "buffered" };
    let mb = |v: u64| v as f64 / (1 << 20) as f64;
    let ld = |p: &AtomicU64| p.load(Ordering::Relaxed);
    println!(
        "{n} records, {mode} order ({path} parse), CAR {:.0} MB: total {:.2}s; over baseline, the bucket's objects ({:.0} MB at most) left out: \
         peak heap {:.0} MB / resident {:.0} MB",
        mb(len as u64),
        took.as_secs_f64(),
        mb(ld(&peak_held)),
        mb(ld(&peak_heap).saturating_sub(base_alloc)),
        mb(ld(&peak_res).saturating_sub(base_res)),
    );
}

/// An in-memory bucket that counts the bytes it holds, so they can be told
/// apart from the rest of the heap.
#[derive(Debug, Default)]
pub(crate) struct Sized {
    inner: object_store::memory::InMemory,
    pub(crate) bytes: Arc<std::sync::atomic::AtomicI64>,
    sizes: Arc<parking_lot::Mutex<std::collections::HashMap<String, i64>>>,
}

impl std::fmt::Display for Sized {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Sized")
    }
}

#[async_trait::async_trait]
impl object_store::ObjectStore for Sized {
    async fn put_opts(
        &self,
        location: &object_store::path::Path,
        payload: object_store::PutPayload,
        opts: object_store::PutOptions,
    ) -> object_store::Result<object_store::PutResult> {
        let n = payload.content_length() as i64;
        let r = self.inner.put_opts(location, exact(payload), opts).await?;
        let old = self.sizes.lock().insert(location.to_string(), n).unwrap_or(0);
        self.bytes.fetch_add(n - old, Ordering::Relaxed);
        Ok(r)
    }
    async fn put_multipart_opts(
        &self,
        location: &object_store::path::Path,
        opts: object_store::PutMultipartOptions,
    ) -> object_store::Result<Box<dyn object_store::MultipartUpload>> {
        let inner = self.inner.put_multipart_opts(location, opts).await?;
        Ok(Box::new(SizedUpload {
            inner,
            path: location.to_string(),
            n: 0,
            sizes: self.sizes.clone(),
            bytes: self.bytes.clone(),
        }))
    }
    async fn get_opts(
        &self,
        location: &object_store::path::Path,
        options: object_store::GetOptions,
    ) -> object_store::Result<object_store::GetResult> {
        self.inner.get_opts(location, options).await
    }
    fn delete_stream(
        &self,
        locations: futures::stream::BoxStream<'static, object_store::Result<object_store::path::Path>>,
    ) -> futures::stream::BoxStream<'static, object_store::Result<object_store::path::Path>> {
        use futures::StreamExt;
        let (sizes, bytes) = (self.sizes.clone(), self.bytes.clone());
        self.inner
            .delete_stream(locations)
            .inspect(move |r| {
                if let Ok(p) = r {
                    if let Some(n) = sizes.lock().remove(p.as_ref()) {
                        bytes.fetch_sub(n, Ordering::Relaxed);
                    }
                }
            })
            .boxed()
    }
    fn list(
        &self,
        prefix: Option<&object_store::path::Path>,
    ) -> futures::stream::BoxStream<'static, object_store::Result<object_store::ObjectMeta>> {
        self.inner.list(prefix)
    }
    async fn list_with_delimiter(
        &self,
        prefix: Option<&object_store::path::Path>,
    ) -> object_store::Result<object_store::ListResult> {
        self.inner.list_with_delimiter(prefix).await
    }
    async fn copy_opts(
        &self,
        from: &object_store::path::Path,
        to: &object_store::path::Path,
        options: object_store::CopyOptions,
    ) -> object_store::Result<()> {
        self.inner.copy_opts(from, to, options).await?;
        let n = self.sizes.lock().get(from.as_ref()).copied().unwrap_or(0);
        let old = self.sizes.lock().insert(to.to_string(), n).unwrap_or(0);
        self.bytes.fetch_add(n - old, Ordering::Relaxed);
        Ok(())
    }
}

/// A multipart upload's bytes count once it completes (SlateDB writes big
/// SSTs this way).
#[derive(Debug)]
struct SizedUpload {
    inner: Box<dyn object_store::MultipartUpload>,
    path: String,
    n: i64,
    sizes: Arc<parking_lot::Mutex<std::collections::HashMap<String, i64>>>,
    bytes: Arc<std::sync::atomic::AtomicI64>,
}

#[async_trait::async_trait]
impl object_store::MultipartUpload for SizedUpload {
    fn put_part(&mut self, data: object_store::PutPayload) -> object_store::UploadPart {
        self.n += data.content_length() as i64;
        self.inner.put_part(exact(data))
    }
    async fn complete(&mut self) -> object_store::Result<object_store::PutResult> {
        let r = self.inner.complete().await?;
        let old = self.sizes.lock().insert(self.path.clone(), self.n).unwrap_or(0);
        self.bytes.fetch_add(self.n - old, Ordering::Relaxed);
        Ok(r)
    }
    async fn abort(&mut self) -> object_store::Result<()> {
        self.inner.abort().await
    }
}

/// The payload in one allocation of its size: an object kept as a slice of
/// a bigger buffer (a compressed segment in its compression bound) would
/// hold the whole buffer, which a real bucket wouldn't.
fn exact(p: object_store::PutPayload) -> object_store::PutPayload {
    let mut v = Vec::with_capacity(p.content_length());
    for c in p.iter() {
        v.extend_from_slice(c);
    }
    object_store::PutPayload::from(v)
}
