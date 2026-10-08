//! Can this bucket host vlpds, and how fast is it from here?
//!
//!   vlpds-bucket-probe --s3-endpoint https://s3.us-east-1.amazonaws.com \
//!       --s3-bucket my-bucket [--prefix p] [--ops 200] [--concurrency 4] [--json out.json]
//!
//! Uses the node's client (`vlsync_store::store::Store::s3`: same HTTP pool, timeouts,
//! path-style addressing) and the node's `VLPDS_S3_*` env vars (credentials
//! also as `VLPDS_S3_{ACCESS,SECRET}_KEY_FILE`). Everything is
//! written under a fresh `vlpds-probe/<random>/` prefix (or `--prefix`, which
//! must be empty) and deleted at the end unless `--keep`.
//!
//! Correctness checks (any failure exits 1 with "UNSAFE: ..."):
//!   1. conditional create (`If-None-Match: *`): segment PUTs and log fencing
//!   2. compare-and-swap on ETag (`If-Match`): node leases and shard assignments
//!   3. N concurrent creates / CASes on one key: exactly one wins
//!   4. read/list-after-write, list order + offset, delete, multipart (complete + abort)
//!
//! Then latency (p50/p90/p99/max) for the request shapes the node issues.
//! Exit codes: 0 safe, 1 unsafe, 2 could not run (auth, network, non-empty prefix).

use clap::Parser;
use futures::{StreamExt, TryStreamExt};
use hdrhistogram::Histogram;
use object_store::path::Path;
use object_store::{ObjectStore, ObjectStoreExt, PutMode, PutOptions, PutPayload};
use parking_lot::Mutex;
use serde::Serialize;
use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use vlpds::cluster::if_match;
use vlsync_store::store::{S3Config, Store};

#[derive(Parser)]
#[command(
    name = "vlpds-bucket-probe",
    about = "Check whether an S3-compatible bucket can host vlpds and measure its latency"
)]
struct Args {
    #[arg(long, env = "VLPDS_S3_ENDPOINT", default_value = "http://localhost:9000")]
    s3_endpoint: String,
    #[arg(long, env = "VLPDS_S3_BUCKET", default_value = "vlpds")]
    s3_bucket: String,
    #[arg(long, env = "VLPDS_S3_ACCESS_KEY", default_value = "minioadmin", hide_env_values = true)]
    s3_access_key: String,
    /// File holding --s3-access-key (as the node's).
    #[arg(long, env = "VLPDS_S3_ACCESS_KEY_FILE", conflicts_with = "s3_access_key")]
    s3_access_key_file: Option<std::path::PathBuf>,
    #[arg(long, env = "VLPDS_S3_SECRET_KEY", default_value = "minioadmin", hide_env_values = true)]
    s3_secret_key: String,
    /// File holding --s3-secret-key (as the node's).
    #[arg(long, env = "VLPDS_S3_SECRET_KEY_FILE", conflicts_with = "s3_secret_key")]
    s3_secret_key_file: Option<std::path::PathBuf>,
    #[arg(long, env = "VLPDS_S3_REGION", default_value = "us-east-1")]
    s3_region: String,
    /// Key prefix to work under (must be empty). Default: vlpds-probe/<random>.
    #[arg(long)]
    prefix: Option<String>,
    /// Requests per latency measurement.
    #[arg(long, default_value_t = 200)]
    ops: usize,
    /// Requests in flight per latency measurement.
    #[arg(long, default_value_t = 4)]
    concurrency: usize,
    /// Concurrent writers in the one-winner races.
    #[arg(long, default_value_t = 16)]
    racers: usize,
    /// Keys raced (each by --racers writers), per race kind.
    #[arg(long, default_value_t = 4)]
    race_rounds: usize,
    /// Only run the correctness checks.
    #[arg(long)]
    skip_latency: bool,
    /// Write a JSON report to this path ("-" for stdout, replacing the table).
    #[arg(long)]
    json: Option<String>,
    /// Leave the probe's objects in the bucket.
    #[arg(long)]
    keep: bool,
}

#[derive(Serialize, Clone, Copy, PartialEq)]
#[serde(rename_all = "lowercase")]
enum Status {
    Pass,
    Warn,
    Fail,
}

#[derive(Serialize)]
struct Check {
    name: &'static str,
    relied_on_by: &'static str,
    status: Status,
    detail: String,
    ms: f64,
}

#[derive(Serialize)]
struct LatRow {
    op: &'static str,
    bytes: usize,
    n: u64,
    errors: u64,
    p50_ms: f64,
    p90_ms: f64,
    p99_ms: f64,
    max_ms: f64,
    ops_per_s: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    first_error: Option<String>,
}

#[derive(Serialize)]
struct Report {
    endpoint: String,
    bucket: String,
    region: String,
    prefix: String,
    ops: usize,
    concurrency: usize,
    checks: Vec<Check>,
    latency: Vec<LatRow>,
    notes: Vec<String>,
    safe: bool,
    verdict: String,
    cleanup: String,
}

/// Outcome of one check: Ok(detail) passes, Warn(detail) passes with a note.
enum Outcome {
    Ok(String),
    Warn(String),
    Fail(String),
}

fn kind(e: &object_store::Error) -> String {
    use object_store::Error::*;
    match e {
        AlreadyExists { .. } => "AlreadyExists".into(),
        Precondition { .. } => "Precondition".into(),
        NotFound { .. } => "NotFound".into(),
        NotModified { .. } => "NotModified".into(),
        NotSupported { .. } => "NotSupported".into(),
        NotImplemented { .. } => "NotImplemented".into(),
        other => {
            let s = other.to_string();
            let s = s.replace('\n', " ");
            if s.len() > 300 {
                format!("{}...", &s[..s.char_indices().nth(300).map(|(i, _)| i).unwrap_or(s.len())])
            } else {
                s
            }
        }
    }
}

fn is_conflict(e: &object_store::Error) -> bool {
    matches!(e, object_store::Error::AlreadyExists { .. } | object_store::Error::Precondition { .. })
}

fn opts(mode: PutMode) -> PutOptions {
    PutOptions { mode, ..Default::default() }
}

fn data(n: usize, seed: u8) -> Vec<u8> {
    (0..n).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed)).collect()
}

fn payload(n: usize, seed: u8) -> PutPayload {
    PutPayload::from(data(n, seed))
}

struct Probe {
    store: Arc<dyn ObjectStore>,
    root: String,
}

macro_rules! fail {
    ($($t:tt)*) => { return Outcome::Fail(format!($($t)*)) };
}

/// `?` for checks: a request error fails the check, naming the step.
macro_rules! tryf {
    ($e:expr, $step:expr) => {
        match $e {
            Ok(v) => v,
            Err(err) => return Outcome::Fail(format!("{}: unexpected error {}", $step, kind(&err))),
        }
    };
}

impl Probe {
    fn path(&self, rel: &str) -> Path {
        Path::from(format!("{}/{}", self.root, rel))
    }

    async fn get_bytes(&self, p: &Path) -> object_store::Result<(bytes::Bytes, Option<String>)> {
        let r = self.store.get(p).await?;
        let e = r.meta.e_tag.clone();
        Ok((r.bytes().await?, e))
    }

    /// Check 1: If-None-Match: * creates once; the second create is refused.
    async fn conditional_create(&self) -> Outcome {
        let p = self.path("checks/create/00000000000000000001.seg");
        let first = tryf!(
            self.store.put_opts(&p, PutPayload::from_static(b"first"), opts(PutMode::Create)).await,
            "first create"
        );
        match self.store.put_opts(&p, PutPayload::from_static(b"second"), opts(PutMode::Create)).await {
            Ok(_) => {
                let (b, _) = tryf!(self.get_bytes(&p).await, "GET after second create");
                fail!(
                    "second If-None-Match:* create of an existing key succeeded (object now {:?}): the store ignores conditional creates, so a zombie writer could overwrite a durable segment or a fence",
                    String::from_utf8_lossy(&b)
                )
            }
            Err(object_store::Error::AlreadyExists { .. }) => {}
            Err(e) => fail!("second create failed with {} instead of AlreadyExists", kind(&e)),
        }
        let (b, _) = tryf!(self.get_bytes(&p).await, "GET");
        if &b[..] != b"first" {
            fail!("object was changed by the refused create: {:?}", String::from_utf8_lossy(&b));
        }
        if first.e_tag.is_none() {
            return Outcome::Warn("create refused on an existing key; PUT returned no ETag".into());
        }
        Outcome::Ok("second create refused with AlreadyExists, original bytes intact".into())
    }

    /// Check 2: If-Match CAS on the ETag from a GET (and from the PUT
    /// response, as lease renewals use); stale and missing-key updates are refused.
    async fn compare_and_swap(&self) -> Outcome {
        let p = self.path("checks/cas/lease");
        let created =
            tryf!(self.store.put_opts(&p, PutPayload::from_static(b"v1"), opts(PutMode::Create)).await, "create");
        let (b, e1) = tryf!(self.get_bytes(&p).await, "GET v1");
        if &b[..] != b"v1" {
            fail!("read-after-create returned {:?}", String::from_utf8_lossy(&b));
        }
        if e1.is_none() {
            fail!("GET returned no ETag, so there is nothing to CAS on");
        }
        let mut notes = vec![];
        if created.e_tag.is_some() && created.e_tag != e1 {
            notes.push(format!("PUT ETag {:?} != GET ETag {:?}", created.e_tag, e1));
        }
        let put2 = match self.store.put_opts(&p, PutPayload::from_static(b"v2"), opts(if_match(e1.clone()))).await {
            Ok(r) => r,
            Err(object_store::Error::NotImplemented { .. } | object_store::Error::NotSupported { .. }) => {
                fail!("conditional update (If-Match) is not supported by this store/client")
            }
            Err(e) => fail!("CAS with the current ETag failed: {}", kind(&e)),
        };
        let (b, e2) = tryf!(self.get_bytes(&p).await, "GET v2");
        if &b[..] != b"v2" {
            fail!("read-after-overwrite returned {:?}, not v2 (stale read)", String::from_utf8_lossy(&b));
        }
        if e2 == e1 {
            fail!("ETag did not change on overwrite ({e1:?}): a stale CAS could not be detected");
        }
        match self.store.put_opts(&p, PutPayload::from_static(b"stale"), opts(if_match(e1.clone()))).await {
            Ok(_) => fail!("CAS with a stale ETag succeeded: two nodes could both hold a lease or an assignment"),
            Err(e) if is_conflict(&e) => {}
            Err(e) => fail!("CAS with a stale ETag failed with {} instead of Precondition", kind(&e)),
        }
        let (b, _) = tryf!(self.get_bytes(&p).await, "GET after stale CAS");
        if &b[..] != b"v2" {
            fail!("a refused stale CAS changed the object to {:?}", String::from_utf8_lossy(&b));
        }
        // renewals CAS on the ETag the previous PUT returned, without a GET
        match put2.e_tag {
            None => notes.push("PUT responses carry no ETag (renewals will need a GET)".into()),
            Some(et) => match self.store.put_opts(&p, PutPayload::from_static(b"v3"), opts(if_match(Some(et)))).await {
                Ok(_) => {}
                Err(e) => fail!(
                    "CAS with the ETag returned by the previous PUT failed ({}): lease renewals would fail",
                    kind(&e)
                ),
            },
        }
        let missing = self.path("checks/cas/missing");
        match self.store.put_opts(&missing, PutPayload::from_static(b"x"), opts(if_match(e1))).await {
            Ok(_) => fail!("CAS on a missing key created it"),
            Err(e) if is_conflict(&e) || matches!(e, object_store::Error::NotFound { .. }) => {}
            Err(e) => fail!("CAS on a missing key failed with {} instead of Precondition", kind(&e)),
        }
        let detail = "current-ETag CAS ok, stale-ETag CAS refused, PUT-response ETag reusable, missing-key CAS refused"
            .to_string();
        if notes.is_empty() {
            Outcome::Ok(detail)
        } else {
            Outcome::Warn(format!("{detail}; {}", notes.join("; ")))
        }
    }

    /// 3a/3b. N writers race a create (or a CAS from one ETag) on one key.
    async fn race(&self, racers: usize, rounds: usize, use_cas: bool) -> Outcome {
        let mut conflicts = 0;
        for round in 0..rounds {
            let p = self.path(&format!("checks/race-{}/{round}", if use_cas { "cas" } else { "create" }));
            let mode = if use_cas {
                tryf!(
                    self.store.put_opts(&p, PutPayload::from_static(b"base"), opts(PutMode::Create)).await,
                    "create base"
                );
                let (_, e) = tryf!(self.get_bytes(&p).await, "GET base");
                if_match(e)
            } else {
                PutMode::Create
            };
            let barrier = Arc::new(tokio::sync::Barrier::new(racers));
            let tasks: Vec<_> = (0..racers)
                .map(|i| {
                    let (store, p, mode, barrier) = (self.store.clone(), p.clone(), mode.clone(), barrier.clone());
                    tokio::spawn(async move {
                        barrier.wait().await;
                        store.put_opts(&p, PutPayload::from(format!("racer-{i}").into_bytes()), opts(mode)).await
                    })
                })
                .collect();
            let mut winners = vec![];
            let mut others = vec![];
            for (i, t) in tasks.into_iter().enumerate() {
                match t.await.expect("racer panicked") {
                    Ok(_) => winners.push(i),
                    Err(e) if is_conflict(&e) => conflicts += 1,
                    Err(e) => others.push(format!("racer {i}: {}", kind(&e))),
                }
            }
            if winners.len() != 1 {
                fail!("round {round}: {} of {racers} writers won ({winners:?}); exactly one must", winners.len());
            }
            if !others.is_empty() {
                fail!(
                    "round {round}: losers got non-conflict errors, so the outcome is ambiguous: {}",
                    others.join("; ")
                );
            }
            let (b, _) = tryf!(self.get_bytes(&p).await, "GET winner");
            let want = format!("racer-{}", winners[0]);
            if b[..] != *want.as_bytes() {
                fail!("round {round}: {want} won but the object holds {:?}", String::from_utf8_lossy(&b));
            }
        }
        Outcome::Ok(format!(
            "{rounds} keys x {racers} writers: one winner each, {conflicts} refused, final bytes = winner's"
        ))
    }

    /// 4a. read/list-after-write, LIST order and offset, delete.
    async fn list_delete(&self) -> Outcome {
        let n = 10;
        let dir = self.path("checks/list");
        let names: Vec<String> = (0..n).map(|i| format!("{i:020}.seg")).collect();
        let puts = futures::stream::iter(names.iter().enumerate())
            .map(|(i, name)| {
                let p = self.path(&format!("checks/list/{name}"));
                async move { self.store.put(&p, payload(100 + i, i as u8)).await }
            })
            .buffer_unordered(n)
            .try_collect::<Vec<_>>()
            .await;
        tryf!(puts, "PUT");
        let listed: Vec<_> = tryf!(self.store.list(Some(&dir)).try_collect::<Vec<_>>().await, "LIST");
        let got: Vec<String> = listed.iter().filter_map(|m| m.location.filename().map(str::to_string)).collect();
        let mut sorted = got.clone();
        sorted.sort();
        if sorted != names {
            fail!("LIST right after PUT returned {} of {n} objects (list-after-write is not consistent)", got.len());
        }
        for m in &listed {
            let i: usize = m.location.filename().unwrap().trim_end_matches(".seg").parse().unwrap_or(0);
            if m.size != 100 + i as u64 {
                fail!("LIST size for {} is {}, wrote {}", m.location, m.size, 100 + i);
            }
        }
        let mut notes = vec![];
        if got != names {
            notes.push("LIST is not in lexicographic order".to_string());
        }
        let off = self.path(&format!("checks/list/{}", names[4]));
        let after: Vec<String> =
            tryf!(self.store.list_with_offset(Some(&dir), &off).try_collect::<Vec<_>>().await, "LIST with offset")
                .iter()
                .filter_map(|m| m.location.filename().map(str::to_string))
                .collect();
        let mut after_sorted = after.clone();
        after_sorted.sort();
        if after_sorted != names[5..] {
            fail!("LIST with start-after {} returned {after:?}", names[4]);
        }
        let head = tryf!(self.store.head(&self.path(&format!("checks/list/{}", names[3]))).await, "HEAD");
        if head.size != 103 {
            fail!("HEAD size {} != 103", head.size);
        }
        for name in &names[..3] {
            tryf!(self.store.delete(&self.path(&format!("checks/list/{name}"))).await, "DELETE");
        }
        let left: Vec<String> = tryf!(self.store.list(Some(&dir)).try_collect::<Vec<_>>().await, "LIST after delete")
            .iter()
            .filter_map(|m| m.location.filename().map(str::to_string))
            .collect();
        if left.iter().any(|n| names[..3].contains(n)) || left.len() != n - 3 {
            fail!("LIST after deleting 3 objects returned {} objects (expected {})", left.len(), n - 3);
        }
        let gone = self.path(&format!("checks/list/{}", names[0]));
        match self.store.get(&gone).await {
            Err(object_store::Error::NotFound { .. }) => {}
            Ok(_) => fail!("GET of a deleted object succeeded"),
            Err(e) => fail!("GET of a deleted object failed with {} instead of NotFound", kind(&e)),
        }
        if let Err(e) = self.store.delete(&gone).await {
            notes.push(format!(
                "deleting a missing key errors ({}); retention retries assume idempotent deletes",
                kind(&e)
            ));
        }
        let detail =
            "PUT->LIST sees all 10 with sizes, start-after offset ok, HEAD ok, deletes visible to LIST and GET"
                .to_string();
        if notes.is_empty() {
            Outcome::Ok(detail)
        } else {
            Outcome::Warn(format!("{detail}; {}", notes.join("; ")))
        }
    }

    /// 4b. multipart: complete (two parts) and abort.
    async fn multipart(&self) -> Outcome {
        let part1 = 5 << 20;
        let p = self.path("checks/multipart/complete");
        let mut up = tryf!(self.store.put_multipart(&p).await, "create multipart upload");
        let a = up.put_part(payload(part1, 1));
        let b = up.put_part(payload(4096, 2));
        tryf!(futures::future::try_join(a, b).await, "upload part");
        tryf!(up.complete().await, "complete multipart upload");
        let meta = tryf!(self.store.head(&p).await, "HEAD completed upload");
        if meta.size != (part1 + 4096) as u64 {
            fail!("completed upload is {} bytes, wrote {}", meta.size, part1 + 4096);
        }
        let r = tryf!(
            self.store.get_range(&p, (part1 as u64 - 16)..(part1 as u64 + 16)).await,
            "range GET across the part boundary"
        );
        let want = [&data(part1, 1)[part1 - 16..], &data(4096, 2)[..16]].concat();
        if r[..] != want[..] {
            fail!("bytes across the part boundary differ from what was uploaded");
        }
        let q = self.path("checks/multipart/aborted");
        let mut up = tryf!(self.store.put_multipart(&q).await, "create multipart upload (abort)");
        tryf!(up.put_part(payload(part1, 3)).await, "upload part (abort)");
        tryf!(up.abort().await, "abort multipart upload");
        match self.store.head(&q).await {
            Err(object_store::Error::NotFound { .. }) => {}
            Ok(_) => fail!("an aborted multipart upload left an object behind"),
            Err(e) => fail!("HEAD after abort failed with {}", kind(&e)),
        }
        Outcome::Ok(
            "5 MiB + 4 KiB upload completed with correct size and boundary bytes; aborted upload left nothing".into(),
        )
    }

    /// Runs `ops` requests from `concurrency` workers; `f(worker, i)`.
    async fn measure<F, Fut>(&self, op: &'static str, bytes: usize, ops: usize, concurrency: usize, f: F) -> LatRow
    where
        F: Fn(usize, usize) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = object_store::Result<()>> + Send,
    {
        let f = Arc::new(f);
        let next = Arc::new(AtomicUsize::new(0));
        let hist = Arc::new(Mutex::new(Histogram::<u64>::new_with_bounds(1, 120_000_000, 3).unwrap()));
        let errors = Arc::new(Mutex::new((0u64, None::<String>)));
        let start = Instant::now();
        let workers: Vec<_> = (0..concurrency.max(1))
            .map(|w| {
                let (f, next, hist, errors) = (f.clone(), next.clone(), hist.clone(), errors.clone());
                tokio::spawn(async move {
                    loop {
                        let i = next.fetch_add(1, Ordering::Relaxed);
                        if i >= ops {
                            break;
                        }
                        let t = Instant::now();
                        match f(w, i).await {
                            Ok(()) => {
                                let us = t.elapsed().as_micros() as u64;
                                hist.lock().saturating_record(us.max(1));
                            }
                            Err(e) => {
                                let mut g = errors.lock();
                                g.0 += 1;
                                g.1.get_or_insert_with(|| kind(&e));
                            }
                        }
                    }
                })
            })
            .collect();
        for w in workers {
            w.await.expect("latency worker panicked");
        }
        let wall = start.elapsed().as_secs_f64();
        let h = hist.lock();
        let ms = |q: f64| if h.is_empty() { 0.0 } else { h.value_at_quantile(q) as f64 / 1000.0 };
        let (errs, first_error) = errors.lock().clone();
        LatRow {
            op,
            bytes,
            n: h.len(),
            errors: errs,
            p50_ms: ms(0.5),
            p90_ms: ms(0.9),
            p99_ms: ms(0.99),
            max_ms: if h.is_empty() { 0.0 } else { h.max() as f64 / 1000.0 },
            ops_per_s: h.len() as f64 / wall,
            first_error,
        }
    }

    async fn latency(&self, ops: usize, conc: usize, progress: bool) -> Vec<LatRow> {
        let mut rows = vec![];
        let small = 1024;
        let seg = 64 << 10;
        let big = 1 << 20;
        let s = self.store.clone();
        let root = self.root.clone();
        let p = move |rel: String| Path::from(format!("{root}/{rel}"));
        // fixtures + connection warmup
        let small_p = p("lat/small".into());
        let big_p = p("lat/big".into());
        let _ = s.put(&small_p, payload(small, 7)).await;
        let _ = s.put(&big_p, payload(big, 8)).await;
        futures::future::join_all((0..conc).map(|_| s.head(&small_p))).await;

        macro_rules! run {
            ($op:expr, $bytes:expr, $body:expr) => {{
                if progress {
                    eprintln!("  measuring {} ...", $op);
                }
                let row = self.measure($op, $bytes, ops, conc, $body).await;
                rows.push(row);
            }};
        }

        let (s1, p1) = (s.clone(), p.clone());
        let body = payload(big, 9);
        run!("put_1mib", big, move |_, i| {
            let (s, path, body) = (s1.clone(), p1(format!("lat/put1m/{i}")), body.clone());
            async move { s.put(&path, body).await.map(|_| ()) }
        });
        let (s1, p1) = (s.clone(), p.clone());
        let body = payload(seg, 10);
        run!("put_64kib", seg, move |_, i| {
            let (s, path, body) = (s1.clone(), p1(format!("lat/put64k/{i:08}")), body.clone());
            async move { s.put(&path, body).await.map(|_| ()) }
        });
        let (s1, p1) = (s.clone(), p.clone());
        let body = payload(seg, 11);
        run!("put_create_64kib", seg, move |_, i| {
            let (s, path, body) = (s1.clone(), p1(format!("lat/seg/{i:020}.seg")), body.clone());
            async move { s.put_opts(&path, body, opts(PutMode::Create)).await.map(|_| ()) }
        });
        // one lease object per worker, renewed by CAS on the last PUT's ETag
        let leases: Arc<Vec<Mutex<Option<Option<String>>>>> = Arc::new((0..conc).map(|_| Mutex::new(None)).collect());
        let (s1, p1) = (s.clone(), p.clone());
        run!("put_cas_small", 200, move |w, i| {
            let (s, path, leases) = (s1.clone(), p1(format!("lat/lease/{w}")), leases.clone());
            async move {
                let prev = leases[w].lock().clone();
                let mode = match prev {
                    None => PutMode::Create,
                    Some(e) => if_match(e),
                };
                let r = s.put_opts(&path, payload(200, i as u8), opts(mode)).await?;
                *leases[w].lock() = Some(r.e_tag);
                Ok(())
            }
        });
        let (s1, p1) = (s.clone(), small_p.clone());
        run!("get_1kib", small, move |_, _| {
            let (s, path) = (s1.clone(), p1.clone());
            async move { s.get(&path).await?.bytes().await.map(|_| ()) }
        });
        let (s1, p1) = (s.clone(), big_p.clone());
        run!("get_range_4kib", 4096, move |_, _| {
            let (s, path) = (s1.clone(), p1.clone());
            async move { s.get_range(&path, 0..4096).await.map(|_| ()) }
        });
        let (s1, p1) = (s.clone(), small_p.clone());
        run!("head", 0, move |_, _| {
            let (s, path) = (s1.clone(), p1.clone());
            async move { s.head(&path).await.map(|_| ()) }
        });
        let (s1, p1) = (s.clone(), p("lat/seg".into()));
        run!("list", 0, move |_, _| {
            let (s, path) = (s1.clone(), p1.clone());
            async move { s.list(Some(&path)).try_collect::<Vec<_>>().await.map(|_| ()) }
        });
        let (s1, p1) = (s.clone(), p.clone());
        run!("delete", 0, move |_, i| {
            let (s, path) = (s1.clone(), p1(format!("lat/put64k/{i:08}")));
            async move { s.delete(&path).await }
        });
        rows
    }

    /// Deletes everything under the root; returns how many objects remain.
    async fn cleanup(&self) -> object_store::Result<(usize, usize)> {
        let root = Path::from(self.root.clone());
        let all: Vec<_> = self.store.list(Some(&root)).try_collect().await?;
        let n = all.len();
        futures::stream::iter(all)
            .map(|m| async move { self.store.delete(&m.location).await })
            .buffer_unordered(32)
            .try_collect::<Vec<_>>()
            .await?;
        let left: Vec<_> = self.store.list(Some(&root)).try_collect().await?;
        Ok((n, left.len()))
    }
}

fn print_table(r: &Report) {
    println!(
        "vlpds-bucket-probe  endpoint={} bucket={} region={} prefix={}/",
        r.endpoint, r.bucket, r.region, r.prefix
    );
    println!();
    println!("Correctness");
    for c in &r.checks {
        let tag = match c.status {
            Status::Pass => "PASS",
            Status::Warn => "WARN",
            Status::Fail => "FAIL",
        };
        println!("  [{tag}] {:<22} {:>7.1} ms  {}", c.name, c.ms, c.detail);
        println!("         {:<22}             (vlpds: {})", "", c.relied_on_by);
    }
    if !r.latency.is_empty() {
        println!();
        println!("Latency ({} ops per row, {} in flight)", r.ops, r.concurrency);
        println!(
            "  {:<17} {:>8} {:>5} {:>4} {:>8} {:>8} {:>8} {:>8} {:>8}",
            "op", "bytes", "n", "err", "p50 ms", "p90 ms", "p99 ms", "max ms", "ops/s"
        );
        for l in &r.latency {
            println!(
                "  {:<17} {:>8} {:>5} {:>4} {:>8.1} {:>8.1} {:>8.1} {:>8.1} {:>8.1}",
                l.op, l.bytes, l.n, l.errors, l.p50_ms, l.p90_ms, l.p99_ms, l.max_ms, l.ops_per_s
            );
            if let Some(e) = &l.first_error {
                println!("    first error: {e}");
            }
        }
    }
    if !r.notes.is_empty() {
        println!();
        for n in &r.notes {
            println!("  note: {n}");
        }
    }
    println!();
    println!("cleanup: {}", r.cleanup);
    println!("{}", r.verdict);
}

async fn timed(name: &'static str, relied_on_by: &'static str, f: impl Future<Output = Outcome>) -> Check {
    let t = Instant::now();
    let o = tokio::time::timeout(Duration::from_secs(300), f)
        .await
        .unwrap_or_else(|_| Outcome::Fail("timed out after 300 s".into()));
    let ms = t.elapsed().as_secs_f64() * 1000.0;
    let (status, detail) = match o {
        Outcome::Ok(d) => (Status::Pass, d),
        Outcome::Warn(d) => (Status::Warn, d),
        Outcome::Fail(d) => (Status::Fail, d),
    };
    Check { name, relied_on_by, status, detail, ms }
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    std::process::exit(match run(args).await {
        Ok(true) => 0,
        Ok(false) => 1,
        Err(e) => {
            eprintln!("vlpds-bucket-probe: could not run: {e:#}");
            eprintln!("UNKNOWN: the probe could not run (exit 2)");
            2
        }
    });
}

async fn run(mut args: Args) -> anyhow::Result<bool> {
    if let Some(p) = &args.s3_access_key_file {
        args.s3_access_key = vlsync_store::secret_file::read("s3-access-key-file", p)?;
    }
    if let Some(p) = &args.s3_secret_key_file {
        args.s3_secret_key = vlsync_store::secret_file::read("s3-secret-key-file", p)?;
    }
    let cfg = S3Config {
        endpoint: args.s3_endpoint.clone(),
        bucket: args.s3_bucket.clone(),
        access_key: args.s3_access_key.clone(),
        secret_key: args.s3_secret_key.clone(),
        region: args.s3_region.clone(),
    };
    let root = match &args.prefix {
        Some(p) => p.trim_matches('/').to_string(),
        None => format!("vlpds-probe/{:032x}", rand::random::<u128>()),
    };
    anyhow::ensure!(!root.is_empty(), "--prefix must not be the bucket root");
    let store = Store::s3(&cfg, &root, None, 256)?;
    let probe = Probe { store: store.raw.clone(), root: root.clone() };
    let json_stdout = args.json.as_deref() == Some("-");
    let progress = !json_stdout;

    // reachability/auth, and never touch an existing prefix
    let existing: Vec<_> =
        probe.store.list(Some(&Path::from(root.clone()))).take(1).try_collect().await.map_err(|e| {
            anyhow::anyhow!("LIST {}/{root}/ failed (endpoint, credentials, bucket?): {}", args.s3_bucket, kind(&e))
        })?;
    if !existing.is_empty() {
        anyhow::bail!("prefix {root}/ is not empty; give an empty --prefix (the probe deletes everything under it)");
    }
    if progress {
        eprintln!("probing {} bucket {} under {root}/", args.s3_endpoint, args.s3_bucket);
    }

    let mut checks = vec![];
    checks.push(
        timed(
            "conditional_create",
            "segment PUTs, log fences, handle claims (If-None-Match: *)",
            probe.conditional_create(),
        )
        .await,
    );
    checks.push(
        timed(
            "compare_and_swap",
            "node leases, shard assignments, layout, writer ids (If-Match)",
            probe.compare_and_swap(),
        )
        .await,
    );
    checks.push(
        timed(
            "race_create",
            "fencing a zombie log: exactly one of fencer/zombie lands",
            probe.race(args.racers, args.race_rounds, false),
        )
        .await,
    );
    checks.push(
        timed(
            "race_cas",
            "lease/assignment takeovers: exactly one CAS from an ETag wins",
            probe.race(args.racers, args.race_rounds, true),
        )
        .await,
    );
    checks.push(
        timed("list_read_delete", "fence scan (LIST + offset), replay, retention deletes", probe.list_delete()).await,
    );
    checks.push(timed("multipart", "large SSTs and blobs (multipart upload)", probe.multipart()).await);

    let mut notes = vec![];
    let latency = if args.skip_latency {
        vec![]
    } else {
        let rows = probe.latency(args.ops, args.concurrency, progress).await;
        let get = |op: &str| rows.iter().find(|r| r.op == op);
        if let Some(seg) = get("put_create_64kib") {
            notes.push(format!(
                "an acked write waits for its segment PUT (and any earlier one still in flight): expect ack latency >= {:.1} ms p50 / {:.1} ms p99 from this host, plus up to one PUT of batching",
                seg.p50_ms, seg.p99_ms
            ));
        }
        if let Some(l) = get("put_cas_small") {
            notes.push(format!(
                "lease renewals are one CAS every TTL/5 (2 s at the default 10 s TTL); CAS max here {:.1} ms{}",
                l.max_ms,
                if l.max_ms > 2000.0 { " -- over a renewal interval: raise --lease-ttl" } else { "" }
            ));
        }
        for r in &rows {
            if r.errors > 0 {
                notes.push(format!(
                    "{}: {} of {} requests failed (first: {})",
                    r.op,
                    r.errors,
                    args.ops,
                    r.first_error.as_deref().unwrap_or("?")
                ));
            }
        }
        rows
    };

    let cleanup = if args.keep {
        format!("kept objects under {root}/ (--keep)")
    } else {
        match probe.cleanup().await {
            Ok((n, 0)) => format!("deleted {n} objects under {root}/"),
            Ok((n, left)) => format!("deleted {n} objects under {root}/ but LIST still shows {left}"),
            Err(e) => format!("FAILED to delete objects under {root}/: {}", kind(&e)),
        }
    };
    let fails: Vec<&Check> = checks.iter().filter(|c| c.status == Status::Fail).collect();
    let safe = fails.is_empty();
    let verdict = match fails.first() {
        None => "SAFE for vlpds".to_string(),
        Some(first) => {
            let mut reason: String = first.detail.chars().take(240).collect();
            if reason.len() < first.detail.len() {
                reason.push_str("...");
            }
            let others: Vec<&str> = fails[1..].iter().map(|c| c.name).collect();
            let also = if others.is_empty() { String::new() } else { format!(" (also failed: {})", others.join(", ")) };
            format!("UNSAFE: {}: {reason}{also}", first.name)
        }
    };
    let report = Report {
        endpoint: args.s3_endpoint,
        bucket: args.s3_bucket,
        region: args.s3_region,
        prefix: root,
        ops: args.ops,
        concurrency: args.concurrency,
        checks,
        latency,
        notes,
        safe,
        verdict,
        cleanup,
    };
    match args.json.as_deref() {
        Some("-") => println!("{}", serde_json::to_string_pretty(&report)?),
        Some(path) => {
            std::fs::write(path, serde_json::to_vec_pretty(&report)?)?;
            print_table(&report);
        }
        None => print_table(&report),
    }
    Ok(safe)
}
