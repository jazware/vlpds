//! Counts object-store requests by billable operation and key component at
//! the bottom of the stack, so every request on the wire is counted once
//! (SlateDB retries and hedged PUTs included, disk-cache hits not): this is
//! what an S3/GCS/R2 bill counts.
//!
//! `client` is the connection pool (`log`, `state`, `ctl`). `result` is
//! `ok`, `not_found`, `precondition`, `timeout`, `error`, or `cancelled`
//! (dropped unanswered: a deadline, a lost hedge). `list` counts one request
//! per 1,000-key page; `delete_batch` one per 1,000 objects of a stream.
//!
//! `VLPDS_INJECT_{STATE,LOG,CTL}_MS` (bench only) add S3-like latency; see
//! `Latency`.

use async_trait::async_trait;
use futures::stream::BoxStream;
use futures::StreamExt;
use object_store::path::Path;
use object_store::{
    CopyOptions, GetOptions, GetResult, ListResult, MultipartUpload, ObjectMeta, ObjectStore, PutMode,
    PutMultipartOptions, PutOptions, PutPayload, PutResult, Result, UploadPart,
};
use std::sync::Arc;

pub fn component(prefix: &str, path: &str) -> &'static str {
    let rel = path.strip_prefix(prefix).and_then(|r| r.strip_prefix('/')).unwrap_or(path);
    let mut it = rel.split('/');
    match it.next().unwrap_or("") {
        "log" => "log_segment",
        "retain" => "retention_report",
        "nodes" => "ctl_lease",
        "assign" => "ctl_assign",
        "writers" => "ctl_writer",
        "cluster" => "ctl_version",
        "handle" | "email" => "account_index",
        "stats" => "ctl_stats",
        "blob" | "blob-gc" | "blob-tmp" => "blob",
        // vlrelay's quorum log: its manifest and leader record, and its
        // state's SlateDB at `qlog/state` (or a recovery's `qlog/state-e{n}`)
        "qlog" => match it.next().unwrap_or("") {
            "manifest" => "qlog_manifest",
            "leader" => "qlog_leader",
            s if s.starts_with("state") => state_component(it.next().unwrap_or("")),
            _ => "other",
        },
        "state" => {
            let _shard = it.next();
            state_component(it.next().unwrap_or(""))
        }
        _ => "other",
    }
}

fn state_component(dir: &str) -> &'static str {
    match dir {
        "manifest" => "state_manifest",
        "compacted" => "state_sst",
        "wal" => "state_wal",
        "compactions" => "state_compactions",
        // SlateDB's GC boundary files (`gc/manifest.boundary`, ...):
        // read on every latest-manifest/compactions read
        "gc" => "state_gc_boundary",
        _ => "state_other",
    }
}

#[derive(Debug)]
pub struct Counting {
    inner: Arc<dyn ObjectStore>,
    prefix: String,
    client: &'static str,
    latency: Option<Latency>,
    /// Objects and bytes by component (crate::store_stats).
    stats: Option<Arc<crate::store_stats::StoreStats>>,
}

/// Bench-only lognormal latency, `<read ms>,<write ms>[,<sigma>]`: emulates
/// S3 over a local MinIO, where call latency paces the timer-driven loops
/// (checkpoints, compaction) and so the op counts. Streamed LISTs and
/// DELETEs are not delayed.
#[derive(Debug, Clone, Copy)]
struct Latency {
    read_ms: f64,
    write_ms: f64,
    sigma: f64,
}

impl Latency {
    fn from_env(client: &str) -> Option<Latency> {
        let v = std::env::var(format!("VLPDS_INJECT_{}_MS", client.to_ascii_uppercase())).ok()?;
        let f: Vec<f64> = v.split(',').filter_map(|x| x.trim().parse().ok()).collect();
        (f.len() >= 2).then(|| Latency { read_ms: f[0], write_ms: f[1], sigma: f.get(2).copied().unwrap_or(0.5) })
    }
}

async fn sleep_lognormal(median_ms: f64, sigma: f64) {
    if median_ms <= 0.0 {
        return;
    }
    let u1: f64 = rand::random::<f64>().max(1e-12);
    let u2: f64 = rand::random();
    let z = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
    tokio::time::sleep(std::time::Duration::from_secs_f64(median_ms * (sigma * z).exp() / 1000.0)).await;
}

pub fn counted(inner: Arc<dyn ObjectStore>, prefix: &str, client: &'static str) -> Arc<dyn ObjectStore> {
    counted_with(inner, prefix, client, None)
}

pub fn counted_with(
    inner: Arc<dyn ObjectStore>,
    prefix: &str,
    client: &'static str,
    stats: Option<Arc<crate::store_stats::StoreStats>>,
) -> Arc<dyn ObjectStore> {
    Arc::new(Counting {
        inner,
        prefix: prefix.trim_end_matches('/').to_string(),
        client,
        latency: Latency::from_env(client),
        stats,
    })
}

fn count(op: &str, comp: &str, client: &str, result: &str) {
    crate::metrics::OBJ_REQUESTS.with_label_values(&[op, comp, client, result]).inc();
}

fn bytes(dir: &str, comp: &str, client: &str, n: u64) {
    if n > 0 {
        crate::metrics::OBJ_BYTES.with_label_values(&[dir, comp, client]).inc_by(n);
    }
}

fn result_label(e: &object_store::Error) -> &'static str {
    use object_store::Error as E;
    match e {
        E::NotFound { .. } => "not_found",
        E::Precondition { .. } | E::AlreadyExists { .. } | E::NotModified { .. } => "precondition",
        e if is_timeout(e) => "timeout",
        _ => "error",
    }
}

/// From the message chain. Not "timeout" alone: object_store's retry errors
/// print their `retry_timeout` setting whatever the cause.
pub fn is_timeout(e: &object_store::Error) -> bool {
    let mut cur: Option<&dyn std::error::Error> = Some(e);
    while let Some(x) = cur {
        if x.to_string().to_ascii_lowercase().contains("timed out") {
            return true;
        }
        cur = x.source();
    }
    false
}

/// Counted `cancelled` if dropped before `finish`.
struct Req {
    op: &'static str,
    comp: &'static str,
    client: &'static str,
    start: std::time::Instant,
    done: bool,
}

impl Req {
    fn new(op: &'static str, comp: &'static str, client: &'static str) -> Req {
        Req { op, comp, client, start: std::time::Instant::now(), done: false }
    }

    fn finish<T>(mut self, r: &Result<T>) {
        self.done = true;
        count(self.op, self.comp, self.client, r.as_ref().map_or_else(result_label, |_| "ok"));
        crate::metrics::OBJ_DURATION
            .with_label_values(&[self.op, self.comp])
            .observe(self.start.elapsed().as_secs_f64());
    }
}

impl Drop for Req {
    fn drop(&mut self) {
        if !self.done {
            count(self.op, self.comp, self.client, "cancelled");
        }
    }
}

impl Counting {
    async fn read_delay(&self) {
        if let Some(l) = self.latency {
            sleep_lognormal(l.read_ms, l.sigma).await;
        }
    }

    async fn write_delay(&self) {
        if let Some(l) = self.latency {
            sleep_lognormal(l.write_ms, l.sigma).await;
        }
    }

    fn comp(&self, p: &Path) -> &'static str {
        component(&self.prefix, p.as_ref())
    }

    /// Timed to the first page; one more request per 1,000 keys (the
    /// S3/GCS/R2 page size).
    fn count_list(
        &self,
        comp: &'static str,
        prefix: Option<&Path>,
        whole: bool,
        mut s: BoxStream<'static, Result<ObjectMeta>>,
    ) -> BoxStream<'static, Result<ObjectMeta>> {
        let client = self.client;
        let mut first = Some(Req::new("list", comp, client));
        let mut n = 0u64;
        let stats = self.stats.clone();
        let sizes = stats.as_ref().is_some_and(|st| st.sizes_from(prefix.map(|p| p.as_ref())));
        let mut observe = prefix.filter(|_| whole).map(|p| p.to_string());
        let mut seen_bytes = 0u64;
        futures::stream::poll_fn(move |cx| {
            let item = futures::ready!(s.poll_next_unpin(cx));
            match (&item, &stats) {
                (Some(Ok(m)), Some(st)) => {
                    seen_bytes += m.size;
                    if sizes {
                        st.listed(m.location.as_ref(), m.size);
                    }
                }
                (None, Some(st)) => {
                    if let Some(p) = observe.take() {
                        st.list_done(&p, n, seen_bytes);
                    }
                }
                _ => {}
            }
            match (&item, first.take()) {
                (Some(r), Some(req)) => req.finish(r),
                (None, Some(req)) => req.finish(&Ok(())),
                (Some(Err(e)), None) => count("list", comp, client, result_label(e)),
                _ => {}
            }
            if let Some(Ok(_)) = &item {
                n += 1;
                if n.is_multiple_of(1000) {
                    count("list", comp, client, "ok");
                }
            }
            std::task::Poll::Ready(item)
        })
        .boxed()
    }
}

impl std::fmt::Display for Counting {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Counting({})", self.inner)
    }
}

#[async_trait]
impl ObjectStore for Counting {
    async fn put_opts(&self, location: &Path, payload: PutPayload, opts: PutOptions) -> Result<PutResult> {
        let comp = self.comp(location);
        let op = match opts.mode {
            PutMode::Overwrite => "put",
            PutMode::Create => "put_create",
            PutMode::Update(_) => "put_cas",
        };
        let req = Req::new(op, comp, self.client);
        let size = payload.content_length() as u64;
        bytes("up", comp, self.client, size);
        let (kind, start) = (crate::store_stats::PutKind::from(&opts.mode), crate::store_stats::now_us());
        self.write_delay().await;
        let r = self.inner.put_opts(location, payload, opts).await;
        req.finish(&r);
        if let (Ok(_), Some(st)) = (&r, &self.stats) {
            st.put(location.as_ref(), comp, kind, size, start);
        }
        r
    }

    async fn put_multipart_opts(&self, location: &Path, opts: PutMultipartOptions) -> Result<Box<dyn MultipartUpload>> {
        let comp = self.comp(location);
        let req = Req::new("mpu_create", comp, self.client);
        self.write_delay().await;
        let r = self.inner.put_multipart_opts(location, opts).await;
        req.finish(&r);
        Ok(Box::new(CountingUpload {
            inner: r?,
            latency: self.latency,
            comp,
            client: self.client,
            stats: self.stats.clone(),
            path: location.to_string(),
            size: 0,
            start: crate::store_stats::now_us(),
        }))
    }

    async fn get_opts(&self, location: &Path, options: GetOptions) -> Result<GetResult> {
        let comp = self.comp(location);
        let op = if options.head {
            "head"
        } else if options.range.is_some() {
            "get_range"
        } else {
            "get"
        };
        let req = Req::new(op, comp, self.client);
        let head = options.head;
        self.read_delay().await;
        let r = self.inner.get_opts(location, options).await;
        req.finish(&r);
        let r = r?;
        if !head {
            bytes("down", comp, self.client, r.range.end - r.range.start);
        }
        // a read tells the object's size, so its later delete or overwrite is exact
        if let Some(st) = &self.stats {
            st.listed(location.as_ref(), r.meta.size);
        }
        Ok(r)
    }

    /// `delete_batch` is counted `ok` when sent: a bulk request's outcome is
    /// per object.
    fn delete_stream(&self, locations: BoxStream<'static, Result<Path>>) -> BoxStream<'static, Result<Path>> {
        let (prefix, client) = (self.prefix.clone(), self.client);
        let (stats, start) = (self.stats.clone(), crate::store_stats::now_us());
        // an error may not name its key: count it under the last one sent
        let last = Arc::new(parking_lot::Mutex::new("other"));
        let sent = last.clone();
        let mut n = 0u64;
        let locations = locations
            .inspect(move |p| {
                if let Ok(p) = p {
                    let comp = component(&prefix, p.as_ref());
                    *sent.lock() = comp;
                    if n.is_multiple_of(1000) {
                        count("delete_batch", comp, client, "ok");
                    }
                    n += 1;
                }
            })
            .boxed();
        let prefix = self.prefix.clone();
        self.inner
            .delete_stream(locations)
            .inspect(move |r| match r {
                Ok(p) => {
                    let comp = component(&prefix, p.as_ref());
                    count("delete", comp, client, "ok");
                    if let Some(st) = &stats {
                        st.deleted(p.as_ref(), comp, start);
                    }
                }
                Err(e) => count("delete", *last.lock(), client, result_label(e)),
            })
            .boxed()
    }

    fn list(&self, prefix: Option<&Path>) -> BoxStream<'static, Result<ObjectMeta>> {
        let comp = prefix.map_or("other", |p| self.comp(p));
        self.count_list(comp, prefix, true, self.inner.list(prefix))
    }

    fn list_with_offset(&self, prefix: Option<&Path>, offset: &Path) -> BoxStream<'static, Result<ObjectMeta>> {
        let comp = prefix.map_or("other", |p| self.comp(p));
        self.count_list(comp, prefix, false, self.inner.list_with_offset(prefix, offset))
    }

    async fn list_with_delimiter(&self, prefix: Option<&Path>) -> Result<ListResult> {
        let comp = prefix.map_or("other", |p| self.comp(p));
        let req = Req::new("list", comp, self.client);
        self.read_delay().await;
        let r = self.inner.list_with_delimiter(prefix).await;
        req.finish(&r);
        r
    }

    async fn copy_opts(&self, from: &Path, to: &Path, options: CopyOptions) -> Result<()> {
        let comp = self.comp(to);
        let req = Req::new("copy", comp, self.client);
        let start = crate::store_stats::now_us();
        self.write_delay().await;
        let r = self.inner.copy_opts(from, to, options).await;
        req.finish(&r);
        if let (Ok(()), Some(st)) = (&r, &self.stats) {
            st.copied(from.as_ref(), to.as_ref(), comp, start);
        }
        r
    }
}

#[derive(Debug)]
struct CountingUpload {
    inner: Box<dyn MultipartUpload>,
    latency: Option<Latency>,
    comp: &'static str,
    client: &'static str,
    stats: Option<Arc<crate::store_stats::StoreStats>>,
    path: String,
    size: u64,
    start: u64,
}

#[async_trait]
impl MultipartUpload for CountingUpload {
    fn put_part(&mut self, data: PutPayload) -> UploadPart {
        let req = Req::new("mpu_part", self.comp, self.client);
        bytes("up", self.comp, self.client, data.content_length() as u64);
        self.size += data.content_length() as u64;
        let part = self.inner.put_part(data);
        let latency = self.latency;
        Box::pin(async move {
            // a part is a PUT: a slow bucket holds each one, and the
            // writer's buffered parts with it
            if let Some(l) = latency {
                sleep_lognormal(l.write_ms, l.sigma).await;
            }
            let r = part.await;
            req.finish(&r);
            r
        })
    }

    async fn complete(&mut self) -> Result<PutResult> {
        let req = Req::new("mpu_complete", self.comp, self.client);
        let r = self.inner.complete().await;
        req.finish(&r);
        if let (Ok(_), Some(st)) = (&r, &self.stats) {
            st.put(&self.path, self.comp, crate::store_stats::PutKind::Overwrite, self.size, self.start);
        }
        r
    }

    async fn abort(&mut self) -> Result<()> {
        let req = Req::new("mpu_abort", self.comp, self.client);
        let r = self.inner.abort().await;
        req.finish(&r);
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use object_store::ObjectStoreExt;

    #[test]
    fn components() {
        assert_eq!(component("vlpds", "vlpds/log/ab/000000000001.seg"), "log_segment");
        assert_eq!(component("vlpds", "vlpds/state/003/manifest/00000000000000000001.manifest"), "state_manifest");
        assert_eq!(component("vlpds", "vlpds/state/003/compacted/01J.sst"), "state_sst");
        assert_eq!(component("a/b", "a/b/assign/007"), "ctl_assign");
        assert_eq!(component("vlpds", "vlpds/nodes/n1"), "ctl_lease");
        assert_eq!(component("vlpds", "vlpds/blob/did/cid"), "blob");
        assert_eq!(component("vlpds", "vlpds/state/005/gc/manifest.boundary"), "state_gc_boundary");
        assert_eq!(component("r", "r/qlog/manifest"), "qlog_manifest");
        assert_eq!(component("r", "r/qlog/leader"), "qlog_leader");
        assert_eq!(component("r", "r/qlog/state/compacted/01J.sst"), "state_sst");
        assert_eq!(component("r", "r/qlog/state-e7/manifest/00000000000000000001.manifest"), "state_manifest");
        assert_eq!(component("r", "r/log/qlog/000000000003.seg"), "log_segment");
    }

    fn n(op: &str, comp: &str, result: &str) -> u64 {
        crate::metrics::OBJ_REQUESTS.with_label_values(&[op, comp, "state", result]).get()
    }

    fn timed(op: &str, comp: &str) -> u64 {
        crate::metrics::OBJ_DURATION.with_label_values(&[op, comp]).get_sample_count()
    }

    #[tokio::test]
    async fn counts_ops() {
        let s = counted(Arc::new(object_store::memory::InMemory::new()), "objstats-test", "state");
        let p = Path::from("objstats-test/retain/x");
        let c = "retention_report";
        let (put0, get0, list0, del0, t0) = (
            n("put_create", c, "ok"),
            n("get_range", c, "ok"),
            n("list", c, "ok"),
            n("delete", c, "ok"),
            timed("get_range", c),
        );
        s.put_opts(&p, PutPayload::from_static(b"hello"), PutMode::Create.into()).await.unwrap();
        s.get_range(&p, 0..2).await.unwrap();
        let _: Vec<_> = s.list(Some(&Path::from("objstats-test/retain"))).collect().await;
        s.delete(&p).await.unwrap();
        assert_eq!(n("put_create", c, "ok") - put0, 1);
        assert_eq!(n("get_range", c, "ok") - get0, 1);
        assert_eq!(n("list", c, "ok") - list0, 1);
        assert_eq!(n("delete", c, "ok") - del0, 1);
        assert_eq!(timed("get_range", c) - t0, 1, "answered requests are timed");
    }

    #[tokio::test]
    async fn results_by_kind() {
        let s = counted(Arc::new(object_store::memory::InMemory::new()), "objstats-res", "state");
        let p = Path::from("objstats-res/assign/001");
        let c = "ctl_assign";
        let (nf0, pre0, empty0) =
            (n("get", c, "not_found"), n("put_create", c, "precondition"), n("list", "ctl_lease", "ok"));
        assert!(matches!(s.get(&p).await, Err(object_store::Error::NotFound { .. })));
        s.put_opts(&p, PutPayload::from_static(b"a"), PutMode::Create.into()).await.unwrap();
        assert!(s.put_opts(&p, PutPayload::from_static(b"b"), PutMode::Create.into()).await.is_err());
        let _: Vec<_> = s.list(Some(&Path::from("objstats-res/nodes"))).collect().await;
        assert_eq!(n("get", c, "not_found") - nf0, 1);
        assert_eq!(n("put_create", c, "precondition") - pre0, 1);
        assert_eq!(n("list", "ctl_lease", "ok") - empty0, 1);
    }

    #[tokio::test]
    async fn dropped_requests_count_as_cancelled() {
        let inner: Arc<dyn ObjectStore> = Arc::new(object_store::memory::InMemory::new());
        let slow = Counting {
            inner,
            prefix: "objstats-cancel".into(),
            client: "state",
            latency: Some(Latency { read_ms: 60_000.0, write_ms: 60_000.0, sigma: 0.0 }),
            stats: None,
        };
        let p = Path::from("objstats-cancel/writers/007");
        let (c0, t0) = (n("get", "ctl_writer", "cancelled"), timed("get", "ctl_writer"));
        assert!(tokio::time::timeout(std::time::Duration::from_millis(10), slow.get(&p)).await.is_err());
        assert_eq!(n("get", "ctl_writer", "cancelled") - c0, 1);
        assert_eq!(timed("get", "ctl_writer"), t0, "cancelled requests are not timed");
    }

    #[test]
    fn timeouts_from_the_message_chain() {
        let t =
            object_store::Error::Generic { store: "S3", source: "error sending request: operation timed out".into() };
        assert_eq!(result_label(&t), "timeout");
        let other = object_store::Error::Generic {
            store: "S3",
            source: "Error after 10 retries, retry_timeout: 180s, source: 503 SlowDown".into(),
        };
        assert_eq!(result_label(&other), "error");
    }
}
