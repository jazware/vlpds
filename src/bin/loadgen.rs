//! Open-loop load generator for vlpds.
//!
//!   loadgen setup  --accounts 20000 --records 500        # create + prepopulate, saves accounts.json
//!   loadgen run    --rate 20000 --duration 60 [--hot-rate 200] [--firehose]
//!
//! Requests are issued on a fixed schedule; latency is measured from the
//! scheduled send time, so server stalls show up as latency rather than as a
//! lower request rate (no coordinated omission).

use clap::{Parser, Subcommand};
use futures::StreamExt;
use hdrhistogram::Histogram;
use parking_lot::Mutex;
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[cfg(feature = "jemalloc")]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;
#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[derive(Parser)]
struct Args {
    #[arg(long, default_value = "http://127.0.0.1:2583")]
    host: String,
    #[arg(long, default_value = "accounts.json")]
    accounts_file: String,
    #[arg(long, default_value_t = 4)]
    threads: usize,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create accounts and prepopulate their repos.
    Setup {
        #[arg(long, default_value_t = 10000)]
        accounts: usize,
        #[arg(long, default_value_t = 500)]
        records: usize,
        #[arg(long, default_value_t = 512)]
        concurrency: usize,
        /// Handle prefix, so repeated setups don't collide.
        #[arg(long, default_value = "user")]
        prefix: String,
    },
    /// Run an open-loop write workload.
    Run {
        /// Fleet write rate (requests/s) spread uniformly over all accounts.
        #[arg(long, default_value_t = 1000.0)]
        rate: f64,
        /// Extra writes/s aimed at a single hot repo (account 0).
        #[arg(long, default_value_t = 0.0)]
        hot_rate: f64,
        #[arg(long, default_value_t = 30)]
        duration: u64,
        /// Use only the first N accounts (0 = all).
        #[arg(long, default_value_t = 0)]
        active: usize,
        /// Max in-flight requests before the generator counts drops.
        #[arg(long, default_value_t = 20000)]
        max_inflight: usize,
        /// Also consume the firehose and measure commit -> event lag.
        #[arg(long)]
        firehose: bool,
        /// Percent of writes that are updates / deletes (rest are creates).
        #[arg(long, default_value_t = 10)]
        update_pct: u32,
        #[arg(long, default_value_t = 10)]
        delete_pct: u32,
        /// Seconds excluded from the final histograms (connection ramp, cold caches).
        #[arg(long, default_value_t = 10)]
        warmup: u64,
        /// Write every acknowledged create (did -> rkeys) here, for `verify`.
        #[arg(long, default_value = "")]
        acked_out: String,
        /// Seconds between the progress lines on stderr.
        #[arg(long, default_value_t = 5)]
        report_secs: u64,
        #[command(flatten)]
        sim: Sim,
    },
    /// Closed-loop benchmark of individual XRPC methods (uses accounts from `setup`).
    Methods {
        /// Comma-separated method keys (default: all). See `method_keys()`.
        #[arg(long, default_value = "")]
        only: String,
        #[arg(long, default_value_t = 64)]
        concurrency: usize,
        #[arg(long, default_value_t = 10)]
        seconds: u64,
        /// Write results as JSON lines here.
        #[arg(long, default_value = "")]
        json_out: String,
    },
    /// Firehose fan-out: N subscribers measuring delivered events/s and lag.
    /// Clone a real repo (from a getRepo CAR) into fresh local account(s):
    /// same collections, rkeys and record bodies; blob refs re-pointed at small
    /// stand-in blobs uploaded locally. Appends the accounts to --accounts-file.
    CloneRepo {
        #[arg(long)]
        car: String,
        /// How many local copies to create.
        #[arg(long, default_value_t = 1)]
        copies: usize,
        #[arg(long, default_value_t = 8)]
        concurrency: usize,
        /// Directory of the source repo's blobs (files named by CID); real
        /// bytes keep their CIDs, missing ones get small stand-ins.
        #[arg(long, default_value = "")]
        blobs_dir: String,
    },
    /// Repo-size sweep: build one repo per size, then benchmark the read methods on it.
    Sweep {
        #[arg(long, default_value = "100,1000,10000,100000,1000000,10000000", value_delimiter = ',')]
        sizes: Vec<usize>,
        #[arg(long, default_value_t = 16)]
        concurrency: usize,
        #[arg(long, default_value_t = 10)]
        seconds: u64,
        /// Parallel applyWrites while populating a repo.
        #[arg(long, default_value_t = 16)]
        fill_concurrency: usize,
        #[arg(long, default_value = "")]
        json_out: String,
        /// Fixed handles (sw<size>.vlpds.test): a repo an earlier --reuse run
        /// filled is logged into and read as is instead of created and filled
        /// again (population snapshots for repeated bench runs).
        #[arg(long)]
        reuse: bool,
        /// Create and fill the repos, skip the read benchmarks.
        #[arg(long)]
        fill_only: bool,
    },
    Fanout {
        #[arg(long, default_value_t = 10)]
        subscribers: usize,
        #[arg(long, default_value_t = 30)]
        seconds: u64,
        /// Start from this cursor (backfill test); omit for live.
        #[arg(long)]
        cursor: Option<i64>,
        #[arg(long, default_value = "")]
        json_out: String,
    },
    /// Minimal AppView stand-in for proxy benchmarks: answers every request
    /// with a fixed JSON body of `body_bytes`.
    StubAppview {
        #[arg(long, default_value = "127.0.0.1:2700")]
        listen: String,
        #[arg(long, default_value_t = 2048)]
        body_bytes: usize,
        /// Label the body with this Content-Encoding (e.g. gzip) and send
        /// `body_bytes` opaque bytes, like an AppView's compressed response
        /// (the PDS passes it through without looking inside).
        #[arg(long, default_value = "")]
        content_encoding: String,
        /// Send this `atproto-repo-rev` (a TID), as a real AppView does on
        /// the methods with read-after-write; e.g. 7zzzzzzzzzzzz (after
        /// every repo's head: nothing to merge). Empty: no header.
        #[arg(long, default_value = "")]
        repo_rev: String,
    },
    /// Closed-loop proxied reads (app.bsky.* via the default AppView) from a
    /// window of `active` bulk accounts (self-minted access tokens).
    Proxy {
        #[arg(long, default_value_t = 50_000)]
        active: u64,
        #[arg(long, default_value_t = 256)]
        concurrency: usize,
        #[arg(long, default_value_t = 20)]
        seconds: u64,
        #[arg(long, default_value = "app.bsky.feed.getTimeline?limit=50")]
        path: String,
        /// HTTP/2 connections to spread requests over.
        #[arg(long, default_value_t = 64)]
        connections: usize,
        #[arg(long, default_value = "dev-secret-change-me")]
        jwt_secret: String,
        #[arg(long, default_value = "did:web:localhost")]
        service_did: String,
        /// Accept-Encoding sent with each request (none if empty).
        #[arg(long, default_value = "")]
        accept_encoding: String,
        #[arg(long, default_value = "")]
        json_out: String,
    },
    /// Check that every acknowledged create (from `run --acked-out`) exists.
    Verify {
        #[arg(long)]
        acked: String,
    },
    /// Bulk-create simulation accounts (deterministic DIDs) via the admin API.
    /// Run one per node with the same range: each asks its node which shards
    /// it serves (getClusterStatus) and sends it only those DIDs, with one
    /// record count per account. Idempotent: a resumed range skips accounts
    /// that exist. Fails if the node stops owning a DID it was sent (the
    /// layout moved): re-run.
    Bulk {
        #[arg(long, default_value_t = 0)]
        start: u64,
        #[arg(long)]
        count: u64,
        /// Max accounts per bulkCreate request.
        #[arg(long, default_value_t = 1000)]
        batch: u64,
        /// Max genesis records per bulkCreate request (one account always
        /// fits in a request).
        #[arg(long, default_value_t = 50_000)]
        max_request_records: u64,
        #[arg(long, default_value_t = 16)]
        concurrency: usize,
        #[arg(long, default_value = "dev-admin-token")]
        admin_token: String,
        /// Write {"watermark": i, ...} here every 2 s and at the end: every
        /// account below i is done (resume with --start i).
        #[arg(long, default_value = "")]
        progress_file: String,
        #[command(flatten)]
        dist: DistArgs,
    },
    /// Print what `bulk` would create for a population (records per repo
    /// from --dist), without a server: totals, quantiles, request count and a
    /// byte estimate. JSON to stdout.
    Dist {
        #[arg(long, default_value_t = 0)]
        start: u64,
        #[arg(long)]
        count: u64,
        #[arg(long, default_value_t = 1000)]
        batch: u64,
        #[arg(long, default_value_t = 50_000)]
        max_request_records: u64,
        /// State bytes per repo / per record for the estimate (SST bytes,
        /// zstd; bench/results/storage-2026-10-02).
        #[arg(long, default_value_t = 323.0)]
        bytes_per_repo: f64,
        #[arg(long, default_value_t = 154.0)]
        bytes_per_record: f64,
        #[command(flatten)]
        dist: DistArgs,
    },
}

/// Records per bulk repo. `fixed`: --records each. `real`: drawn from the
/// records-per-repo distribution of the real network (`vlpds::real_dist`), divided by
/// --dist-scale with stochastic rounding (keeps the mean exactly /scale and
/// the tail's shape; the body collapses toward 0/1 records), optionally
/// capped. Deterministic in (seed, index / group): consecutive groups of
/// --dist-group accounts share one draw (1 = every account its own; the
/// API takes a count per account, so groups no longer save requests). DIDs
/// are hashed, so a group's repos land on unrelated shards; the marginal
/// distribution per repo is unchanged.
#[derive(clap::Args, Clone)]
struct DistArgs {
    /// fixed | real
    #[arg(long, default_value = "fixed")]
    dist: String,
    /// Genesis records per account with --dist fixed.
    #[arg(long, default_value_t = 5)]
    records: u32,
    #[arg(long, default_value_t = 1.0)]
    dist_scale: f64,
    #[arg(long, default_value_t = 1)]
    dist_group: u64,
    #[arg(long, default_value_t = 1)]
    dist_seed: u64,
    /// Cap on records per repo after scaling (0 = none).
    #[arg(long, default_value_t = 0)]
    dist_cap: u32,
    /// Only the part of a draw above this many records is divided by
    /// --dist-scale (n <= knee stays exact: keeps the small-repo body; the
    /// tail above the knee keeps its shape, scaled).
    #[arg(long, default_value_t = 0)]
    dist_knee: u32,
}

/// Sliding active-set simulation over bulk-created accounts: writes go to a
/// window of `sim_active` repos out of `sim_total`, and the window advances by
/// `sim_churn` repos/s, so repos continuously go cold and new ones get loaded.
#[derive(clap::Args, Clone)]
struct Sim {
    #[arg(long, default_value_t = 0)]
    sim_total: u64,
    #[arg(long, default_value_t = 50000)]
    sim_active: u64,
    #[arg(long, default_value_t = 0.0)]
    sim_churn: f64,
    /// Index the active window starts at (it then advances by sim_churn/s),
    /// so successive runs can start on repos nothing has loaded yet.
    #[arg(long, default_value_t = 0)]
    sim_offset: u64,
    #[arg(long, default_value = "dev-secret-change-me")]
    jwt_secret: String,
    #[arg(long, default_value = "did:web:localhost")]
    service_did: String,
}

#[derive(Serialize, Deserialize, Clone)]
struct Acct {
    did: String,
    handle: String,
    token: String,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(args.threads).enable_all().build()?;
    rt.block_on(async move {
        match &args.cmd {
            Cmd::Setup { accounts, records, concurrency, prefix } => {
                setup(&args, *accounts, *records, *concurrency, prefix).await
            }
            Cmd::Run {
                rate,
                hot_rate,
                duration,
                active,
                max_inflight,
                firehose,
                update_pct,
                delete_pct,
                warmup,
                acked_out,
                report_secs,
                sim,
            } => {
                run(
                    &args,
                    *rate,
                    *hot_rate,
                    *duration,
                    *active,
                    *max_inflight,
                    *firehose,
                    *update_pct,
                    *delete_pct,
                    *warmup,
                    acked_out,
                    *report_secs,
                    sim.clone(),
                )
                .await
            }
            Cmd::Methods { only, concurrency, seconds, json_out } => {
                methods(&args, only, *concurrency, *seconds, json_out).await
            }
            Cmd::Fanout { subscribers, seconds, cursor, json_out } => {
                fanout(&args, *subscribers, *seconds, *cursor, json_out).await
            }
            Cmd::Verify { acked } => verify(&args, acked).await,
            Cmd::StubAppview { listen, body_bytes, content_encoding, repo_rev } => {
                stub_appview(listen, *body_bytes, content_encoding, repo_rev).await
            }
            Cmd::Proxy {
                active,
                concurrency,
                seconds,
                path,
                connections,
                jwt_secret,
                service_did,
                accept_encoding,
                json_out,
            } => {
                proxy_bench(
                    &args,
                    *active,
                    *concurrency,
                    *seconds,
                    path,
                    *connections,
                    jwt_secret,
                    service_did,
                    accept_encoding,
                    json_out,
                )
                .await
            }
            Cmd::CloneRepo { car, copies, concurrency, blobs_dir } => {
                clone_repo(&args, car, *copies, *concurrency, blobs_dir).await
            }
            Cmd::Sweep { sizes, concurrency, seconds, fill_concurrency, json_out, reuse, fill_only } => {
                sweep(&args, sizes, *concurrency, *seconds, *fill_concurrency, json_out, *reuse, *fill_only).await
            }
            Cmd::Bulk { start, count, batch, max_request_records, concurrency, admin_token, progress_file, dist } => {
                let d = Dist::new(dist)?;
                bulk(&args, *start, *count, &d, *batch, *max_request_records, *concurrency, admin_token, progress_file)
                    .await
            }
            Cmd::Dist { start, count, batch, max_request_records, bytes_per_repo, bytes_per_record, dist } => {
                let d = Dist::new(dist)?;
                dist_report(*start, *count, &d, *batch, *max_request_records, *bytes_per_repo, *bytes_per_record)
            }
        }
    })
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .http2_prior_knowledge()
        .http2_initial_stream_window_size(4 << 20)
        .http2_initial_connection_window_size(64 << 20)
        .http2_max_frame_size(256 << 10)
        .tcp_nodelay(true)
        .timeout(Duration::from_secs(60))
        .build()
        .unwrap()
}

/// Several HTTP/2 connections (one per client) so no single connection's
/// driver task is the bottleneck.
struct Clients(Vec<reqwest::Client>);

impl Clients {
    fn new(n: usize) -> Clients {
        Clients((0..n).map(|_| client()).collect())
    }
    fn pick(&self) -> &reqwest::Client {
        &self.0[rand::thread_rng().gen_range(0..self.0.len())]
    }
}

fn post_record(i: u64) -> serde_json::Value {
    json!({
        "$type": "app.bsky.feed.post",
        "text": format!("load test post {i} — the quick brown fox jumps over the lazy dog"),
        "createdAt": "2026-09-30T12:00:00.000Z",
        "langs": ["en"],
    })
}

async fn setup(args: &Args, n: usize, records: usize, concurrency: usize, prefix: &str) -> anyhow::Result<()> {
    let c = client();
    let started = Instant::now();
    let done = Arc::new(AtomicU64::new(0));
    let accts: Vec<Acct> = futures::stream::iter(0..n)
        .map(|i| {
            let c = c.clone();
            let host = args.host.clone();
            let done = done.clone();
            let handle = format!("{prefix}{i}.vlpds.test");
            async move {
                let r: serde_json::Value = c
                    .post(format!("{host}/xrpc/com.atproto.server.createAccount"))
                    .json(&json!({"handle": handle, "password": "hunter2", "email": format!("{}@example.com", handle.replace('.', "-"))}))
                    .send()
                    .await?
                    .json()
                    .await?;
                let did = r["did"].as_str().ok_or_else(|| anyhow::anyhow!("createAccount failed: {r}"))?.to_string();
                let token = r["accessJwt"].as_str().unwrap().to_string();
                let mut left = records;
                let mut k = 0u64;
                while left > 0 {
                    let n = left.min(200);
                    let writes: Vec<_> = (0..n)
                        .map(|_| {
                            k += 1;
                            json!({"$type": "com.atproto.repo.applyWrites#create", "collection": "app.bsky.feed.post", "value": post_record(k)})
                        })
                        .collect();
                    let resp = c
                        .post(format!("{host}/xrpc/com.atproto.repo.applyWrites"))
                        .bearer_auth(&token)
                        .json(&json!({"repo": did, "writes": writes}))
                        .send()
                        .await?;
                    anyhow::ensure!(resp.status().is_success(), "applyWrites failed: {}", resp.text().await?);
                    left -= n;
                }
                let d = done.fetch_add(1, Ordering::Relaxed) + 1;
                if d.is_multiple_of(1000) {
                    eprintln!("setup: {d} accounts ({:.0}/s)", d as f64 / started.elapsed().as_secs_f64());
                }
                anyhow::Ok(Acct { did, handle, token })
            }
        })
        .buffer_unordered(concurrency)
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .collect::<Result<_, _>>()?;
    std::fs::write(&args.accounts_file, serde_json::to_vec(&accts)?)?;
    let secs = started.elapsed().as_secs_f64();
    eprintln!(
        "setup done: {n} accounts, {} records in {secs:.1}s ({:.0} records/s)",
        n * records,
        (n * records) as f64 / secs
    );
    Ok(())
}

struct Run {
    lat: Mutex<Histogram<u64>>,
    window: Mutex<Histogram<u64>>,
    hot_lat: Mutex<Histogram<u64>>,
    ok: AtomicU64,
    err: AtomicU64,
    dropped: AtomicU64,
    inflight: AtomicU64,
    fh_events: AtomicU64,
    fh_lag: Mutex<Histogram<u64>>,
    first_err: Mutex<Option<String>>,
    /// Errors by [`err_kind`]: this report window's, and the run's.
    err_kinds: Mutex<(std::collections::BTreeMap<String, u64>, std::collections::BTreeMap<String, u64>)>,
    measure_from: std::sync::OnceLock<Instant>,
}

/// "503 ShardMoved", "timeout", ...: the status and XRPC error name of a
/// failed write, or the transport failure.
fn err_kind(e: &anyhow::Error) -> String {
    if let Some(r) = e.downcast_ref::<reqwest::Error>() {
        return if r.is_timeout() {
            "timeout"
        } else if r.is_connect() {
            "connect"
        } else {
            "transport"
        }
        .into();
    }
    let s = e.to_string();
    let mut it = s.splitn(2, ": ");
    let head = it.next().unwrap_or("");
    let status = head.split(' ').nth(1).unwrap_or("?");
    let v = it.next().and_then(|b| serde_json::from_str::<serde_json::Value>(b).ok()).unwrap_or_default();
    let msg = v["message"].as_str().unwrap_or("");
    let why = if msg.contains("did not answer") {
        ":deadline"
    } else if msg.contains("unreachable") {
        ":unreachable"
    } else {
        ""
    };
    format!("{status} {}{why}", v["error"].as_str().unwrap_or(""))
}

fn hist() -> Histogram<u64> {
    Histogram::new_with_bounds(1, 120_000_000, 3).unwrap()
}

#[allow(clippy::too_many_arguments)]
async fn run(
    args: &Args,
    rate: f64,
    hot_rate: f64,
    duration: u64,
    active: usize,
    max_inflight: usize,
    firehose: bool,
    update_pct: u32,
    delete_pct: u32,
    warmup: u64,
    acked_out: &str,
    report_secs: u64,
    sim: Sim,
) -> anyhow::Result<()> {
    let c = client();
    let mut accts: Vec<Acct> =
        if sim.sim_total > 0 { Vec::new() } else { serde_json::from_slice(&std::fs::read(&args.accounts_file)?)? };
    if active > 0 {
        accts.truncate(active);
    }
    accts = futures::stream::iter(accts)
        .map(|a| {
            let c = c.clone();
            let host = args.host.clone();
            async move {
                let r: serde_json::Value = c
                    .post(format!("{host}/xrpc/com.atproto.server.createSession"))
                    .json(&json!({"identifier": a.did, "password": "hunter2"}))
                    .send()
                    .await?
                    .json()
                    .await?;
                let token =
                    r["accessJwt"].as_str().ok_or_else(|| anyhow::anyhow!("createSession failed: {r}"))?.to_string();
                anyhow::Ok(Acct { token, ..a })
            }
        })
        .buffer_unordered(256)
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .collect::<Result<_, _>>()?;
    let accts = Arc::new(accts);
    // rkeys created during this run, per account, for updates/deletes
    let created: Arc<Vec<Mutex<Vec<String>>>> = Arc::new((0..accts.len()).map(|_| Mutex::new(Vec::new())).collect());
    let st = Arc::new(Run {
        lat: Mutex::new(hist()),
        window: Mutex::new(hist()),
        hot_lat: Mutex::new(hist()),
        ok: AtomicU64::new(0),
        err: AtomicU64::new(0),
        dropped: AtomicU64::new(0),
        inflight: AtomicU64::new(0),
        fh_events: AtomicU64::new(0),
        fh_lag: Mutex::new(hist()),
        first_err: Mutex::new(None),
        err_kinds: Mutex::new(Default::default()),
        measure_from: std::sync::OnceLock::new(),
    });

    if firehose {
        let st = st.clone();
        let url = format!("{}/xrpc/com.atproto.sync.subscribeRepos", args.host.replacen("http", "ws", 1));
        tokio::spawn(async move {
            if let Err(e) = consume_firehose(url, st).await {
                eprintln!("firehose consumer: {e}");
            }
        });
    }

    if sim.sim_total > 0 {
        eprintln!("sim: {} total repos, {} active window, churn {}/s", sim.sim_total, sim.sim_active, sim.sim_churn);
    }
    eprintln!(
        "run: {} accounts, fleet {rate}/s, hot {hot_rate}/s, {duration}s, mix create/update/delete = {}/{update_pct}/{delete_pct}",
        accts.len(),
        100 - update_pct - delete_pct
    );
    let start = Instant::now();
    let end = start + Duration::from_secs(warmup + duration);
    let measure_from = start + Duration::from_secs(warmup);
    st.measure_from.set(measure_from).ok();
    {
        let st = st.clone();
        tokio::spawn(async move {
            let mut last_ok = 0;
            let mut last_fh = 0;
            let every = report_secs.max(1) as f64;
            let mut tick = tokio::time::interval(Duration::from_secs_f64(every));
            tick.tick().await;
            loop {
                tick.tick().await;
                let ok = st.ok.load(Ordering::Relaxed);
                let fh = st.fh_events.load(Ordering::Relaxed);
                let (p50, p99, max) = {
                    let mut w = st.window.lock();
                    let r = (w.value_at_quantile(0.5), w.value_at_quantile(0.99), w.max());
                    w.reset();
                    r
                };
                let kinds: String = std::mem::take(&mut st.err_kinds.lock().0)
                    .into_iter()
                    .map(|(k, n)| format!(" [{k}]={n}"))
                    .collect();
                eprintln!(
                    "[{:>4.0}s] ok/s {:>7.0} err {} dropped {} inflight {} | p50 {:.1}ms p99 {:.1}ms max {:.0}ms | firehose ev/s {:.0}{}{kinds}",
                    start.elapsed().as_secs_f64(),
                    (ok - last_ok) as f64 / every,
                    st.err.load(Ordering::Relaxed),
                    st.dropped.load(Ordering::Relaxed),
                    st.inflight.load(Ordering::Relaxed),
                    p50 as f64 / 1000.0,
                    p99 as f64 / 1000.0,
                    max as f64 / 1000.0,
                    (fh - last_fh) as f64 / every,
                    if kinds.is_empty() { "" } else { " | errs" },
                );
                last_ok = ok;
                last_fh = fh;
            }
        });
    }

    let host: Arc<str> = args.host.clone().into();
    let clients = Arc::new(Clients::new(64));
    let jwt = Arc::new(vlpds::auth::Jwt::new(&sim.jwt_secret, &sim.service_did));
    let mut gens = Vec::new();
    for (r, hot) in [(rate, false), (hot_rate, true)] {
        if r <= 0.0 {
            continue;
        }
        let (accts, created, st, host, c) = (accts.clone(), created.clone(), st.clone(), host.clone(), clients.clone());
        let (sim, jwt) = (sim.clone(), jwt.clone());
        gens.push(tokio::spawn(async move {
            let interval = Duration::from_secs_f64(1.0 / r);
            let mut next = Instant::now();
            let mut i: u64 = 0;
            while next < end {
                let now = Instant::now();
                if next > now {
                    tokio::time::sleep_until(next.into()).await;
                }
                // issue everything due (catches up after scheduler hiccups)
                let now = Instant::now();
                while next <= now && next < end {
                    let scheduled = next;
                    next += interval;
                    i += 1;
                    if st.inflight.load(Ordering::Relaxed) as usize >= max_inflight {
                        st.dropped.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    let roll = rand::thread_rng().gen_range(0..100u32);
                    // sim mode: deterministic bulk DIDs in a sliding window, self-minted tokens
                    let sim_target = (sim.sim_total > 0).then(|| {
                        let idx = if hot {
                            0
                        } else {
                            let base = sim.sim_offset + (start.elapsed().as_secs_f64() * sim.sim_churn) as u64;
                            (base + rand::thread_rng().gen_range(0..sim.sim_active)) % sim.sim_total
                        };
                        let did = vlpds::state::bulk_did(idx);
                        let token = jwt.access(&did);
                        Acct { did, handle: String::new(), token }
                    });
                    let idx =
                        if hot || sim_target.is_some() { 0 } else { rand::thread_rng().gen_range(0..accts.len()) };
                    let (accts, created, st, host, c) =
                        (accts.clone(), created.clone(), st.clone(), host.clone(), c.clone());
                    st.inflight.fetch_add(1, Ordering::Relaxed);
                    tokio::spawn(async move {
                        let res = match &sim_target {
                            Some(a) => {
                                one_write(c.pick(), &host, a, &Mutex::new(Vec::new()), roll, update_pct, delete_pct, i)
                                    .await
                            }
                            None => {
                                one_write(c.pick(), &host, &accts[idx], &created[idx], roll, update_pct, delete_pct, i)
                                    .await
                            }
                        };
                        let us = scheduled.elapsed().as_micros() as u64;
                        st.inflight.fetch_sub(1, Ordering::Relaxed);
                        match res {
                            Ok(()) => {
                                let _ = st.window.lock().record(us);
                                if scheduled >= *st.measure_from.get().unwrap() {
                                    st.ok.fetch_add(1, Ordering::Relaxed);
                                    let _ = st.lat.lock().record(us);
                                    if hot {
                                        let _ = st.hot_lat.lock().record(us);
                                    }
                                }
                            }
                            Err(e) => {
                                st.err.fetch_add(1, Ordering::Relaxed);
                                let k = err_kind(&e);
                                {
                                    let mut ks = st.err_kinds.lock();
                                    *ks.0.entry(k.clone()).or_default() += 1;
                                    *ks.1.entry(k).or_default() += 1;
                                }
                                st.first_err.lock().get_or_insert_with(|| e.to_string());
                            }
                        }
                    });
                }
            }
        }));
    }
    for g in gens {
        g.await?;
    }
    let drain_deadline = Instant::now() + Duration::from_secs(30);
    while st.inflight.load(Ordering::Relaxed) > 0 && Instant::now() < drain_deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    let elapsed = duration as f64;
    let ok = st.ok.load(Ordering::Relaxed);
    let report = |name: &str, h: &Histogram<u64>| {
        if h.is_empty() {
            return;
        }
        let q = |p: f64| h.value_at_quantile(p) as f64 / 1000.0;
        println!(
            "{name:<10} n={:<9} p50={:>7.1}ms p90={:>7.1}ms p99={:>7.1}ms p99.9={:>7.1}ms max={:>7.1}ms",
            h.len(),
            q(0.5),
            q(0.9),
            q(0.99),
            q(0.999),
            h.max() as f64 / 1000.0
        );
    };
    println!("=== result ===");
    println!(
        "target {:.0}/s (fleet {rate} + hot {hot_rate}) | achieved {:.0}/s ok | errors {} | dropped {}",
        rate + hot_rate,
        ok as f64 / elapsed,
        st.err.load(Ordering::Relaxed),
        st.dropped.load(Ordering::Relaxed)
    );
    report("all", &st.lat.lock());
    report("hot-repo", &st.hot_lat.lock());
    if firehose {
        println!("firehose events received: {}", st.fh_events.load(Ordering::Relaxed));
        report("fh-lag", &st.fh_lag.lock());
    }
    if let Some(e) = st.first_err.lock().as_ref() {
        println!("first error: {e}");
    }
    for (k, n) in &st.err_kinds.lock().1 {
        println!("errors [{k}]: {n}");
    }
    if !acked_out.is_empty() {
        let m: std::collections::HashMap<&str, Vec<String>> =
            accts.iter().zip(created.iter()).map(|(a, c)| (a.did.as_str(), c.lock().clone())).collect();
        std::fs::write(acked_out, serde_json::to_vec(&m)?)?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn one_write(
    c: &reqwest::Client,
    host: &str,
    a: &Acct,
    created: &Mutex<Vec<String>>,
    roll: u32,
    update_pct: u32,
    delete_pct: u32,
    i: u64,
) -> anyhow::Result<()> {
    let existing = if roll < update_pct + delete_pct {
        let mut v = created.lock();
        if v.is_empty() {
            None
        } else if roll < update_pct {
            Some(v[rand::thread_rng().gen_range(0..v.len())].clone())
        } else {
            let j = rand::thread_rng().gen_range(0..v.len());
            Some(v.swap_remove(j))
        }
    } else {
        None
    };
    let (method, body) = match existing {
        Some(rkey) if roll < update_pct => (
            "putRecord",
            json!({"repo": a.did, "collection": "app.bsky.feed.post", "rkey": rkey, "record": post_record(i)}),
        ),
        Some(rkey) => ("deleteRecord", json!({"repo": a.did, "collection": "app.bsky.feed.post", "rkey": rkey})),
        None => ("createRecord", json!({"repo": a.did, "collection": "app.bsky.feed.post", "record": post_record(i)})),
    };
    let resp =
        c.post(format!("{host}/xrpc/com.atproto.repo.{method}")).bearer_auth(&a.token).json(&body).send().await?;
    let status = resp.status();
    let bytes = resp.bytes().await?;
    if !status.is_success() {
        anyhow::bail!("{method} {status}: {}", String::from_utf8_lossy(&bytes));
    }
    if method == "createRecord" {
        let v: serde_json::Value = serde_json::from_slice(&bytes)?;
        if let Some(rkey) = v["uri"].as_str().and_then(|u| u.rsplit('/').next()) {
            created.lock().push(rkey.to_string());
        }
    }
    Ok(())
}

async fn consume_firehose(url: String, st: Arc<Run>) -> anyhow::Result<()> {
    use tokio_tungstenite::tungstenite::Message;
    let (mut ws, _) = tokio_tungstenite::connect_async(&url).await?;
    while let Some(msg) = ws.next().await {
        let Message::Binary(b) = msg? else { continue };
        let Ok((_, hlen)) = vlsync_atproto::cbor::Value::decode_prefix(&b) else {
            continue;
        };
        let Ok(body) = vlsync_atproto::cbor::Value::decode(&b[hlen..]) else {
            continue;
        };
        st.fh_events.fetch_add(1, Ordering::Relaxed);
        if st.measure_from.get().is_none_or(|m| Instant::now() < *m) {
            continue;
        }
        if let Some(t) = body.get("time").and_then(|t| t.as_str()) {
            if let Ok(t) = chrono::DateTime::parse_from_rfc3339(t) {
                let lag = chrono::Utc::now().signed_duration_since(t).num_microseconds().unwrap_or(0).max(1);
                let _ = st.fh_lag.lock().record(lag as u64);
            }
        }
    }
    Ok(())
}

use vlpds::real_dist::REAL_DIST;

struct Dist {
    fixed: Option<u32>,
    /// cumulative repo counts per REAL_DIST bucket
    cum: Vec<u64>,
    scale: f64,
    group: u64,
    seed: u64,
    cap: u32,
    knee: u32,
}

fn splitmix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
}

fn unit(x: u64) -> f64 {
    (x >> 11) as f64 / (1u64 << 53) as f64
}

impl Dist {
    fn new(a: &DistArgs) -> anyhow::Result<Dist> {
        let fixed = match a.dist.as_str() {
            "fixed" => Some(a.records),
            "real" => None,
            d => anyhow::bail!("--dist {d}: want fixed or real"),
        };
        anyhow::ensure!(a.dist_scale >= 1.0, "--dist-scale must be >= 1");
        let mut acc = 0;
        let cum = REAL_DIST
            .iter()
            .map(|&(_, _, n)| {
                acc += n;
                acc
            })
            .collect();
        Ok(Dist {
            fixed,
            cum,
            scale: a.dist_scale,
            group: a.dist_group.max(1),
            seed: a.dist_seed,
            cap: a.dist_cap,
            knee: a.dist_knee,
        })
    }

    /// Unscaled draw for account `i` (same for its whole group).
    fn real(&self, i: u64) -> u32 {
        let g = i / self.group;
        let h1 = splitmix64(self.seed.wrapping_mul(0xA24B_AED4_963E_E407) ^ g);
        let h2 = splitmix64(h1);
        let total = *self.cum.last().unwrap();
        let r = ((unit(h1) * total as f64) as u64).min(total - 1);
        let b = self.cum.partition_point(|&c| c <= r);
        let (lo, hi, _) = REAL_DIST[b];
        lo + ((unit(h2) * (hi - lo + 1) as f64) as u32).min(hi - lo)
    }

    fn records(&self, i: u64) -> u32 {
        if let Some(n) = self.fixed {
            return n;
        }
        let n = self.real(i);
        if n <= self.knee {
            return if self.cap > 0 { n.min(self.cap) } else { n };
        }
        let x = (n - self.knee) as f64 / self.scale;
        let u = unit(splitmix64(splitmix64(self.seed ^ 0x5851_F42D_4C95_7F2D) ^ (i / self.group)));
        let mut v = self.knee + x.floor() as u32 + (u < x.fract()) as u32;
        if self.cap > 0 {
            v = v.min(self.cap);
        }
        v
    }
}

/// The slot ranges of the shards a node serves (its getClusterStatus), or
/// None outside a cluster (it serves every account).
async fn owned_slots(c: &reqwest::Client, host: &str, admin_token: &str) -> anyhow::Result<Option<Vec<(u32, u32)>>> {
    let v: serde_json::Value = c
        .get(format!("{host}/xrpc/vlpds.admin.getClusterStatus"))
        .basic_auth("admin", Some(admin_token))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let Some(shards) = v["layout"]["shards"].as_array() else { return Ok(None) };
    let owned: std::collections::HashSet<u64> =
        v["owned"].as_array().into_iter().flatten().filter_map(|x| x.as_u64()).collect();
    let mut r: Vec<(u32, u32)> = shards
        .iter()
        .filter(|s| s["id"].as_u64().is_some_and(|id| owned.contains(&id)))
        .map(|s| (s["lo"].as_u64().unwrap_or(0) as u32, s["hi"].as_u64().unwrap_or(0) as u32))
        .collect();
    r.sort_unstable();
    Ok(Some(r))
}

fn owns(slots: &[(u32, u32)], i: u64) -> bool {
    let s = vlsync_store::slots::slot_of(&vlpds::state::bulk_did(i)) as u32;
    let k = slots.partition_point(|r| r.1 <= s);
    k < slots.len() && slots[k].0 <= s
}

/// One bulkCreate request: the accounts of [lo, hi) this node creates
/// (`indices`; None = all of them) and their record counts.
struct BulkReq {
    lo: u64,
    hi: u64,
    indices: Option<Vec<u64>>,
    records: Vec<u32>,
}

/// bulkCreate requests for accounts start..start+count, in index order: at
/// most `batch` accounts and (one account aside) `max_records` genesis
/// records each, skipping accounts outside `owned` (slot ranges).
struct BulkPlan<'a> {
    d: &'a Dist,
    next: u64,
    end: u64,
    batch: u64,
    max_records: u64,
    owned: Option<&'a [(u32, u32)]>,
}

impl Iterator for BulkPlan<'_> {
    type Item = BulkReq;
    fn next(&mut self) -> Option<BulkReq> {
        if self.next >= self.end {
            return None;
        }
        let lo = self.next;
        let (mut idx, mut recs, mut total) = (Vec::new(), Vec::new(), 0u64);
        while self.next < self.end && (idx.len() as u64) < self.batch {
            let i = self.next;
            if self.owned.is_none_or(|o| owns(o, i)) {
                let r = self.d.records(i);
                if !idx.is_empty() && total + r as u64 > self.max_records {
                    break;
                }
                idx.push(i);
                recs.push(r);
                total += r as u64;
            }
            self.next += 1;
        }
        Some(BulkReq { lo, hi: self.next, indices: self.owned.is_some().then_some(idx), records: recs })
    }
}

#[allow(clippy::too_many_arguments)]
async fn bulk(
    args: &Args,
    start: u64,
    count: u64,
    d: &Dist,
    batch: u64,
    max_records: u64,
    concurrency: usize,
    admin_token: &str,
    progress_file: &str,
) -> anyhow::Result<()> {
    let c = client();
    let owned = owned_slots(&c, &args.host, admin_token).await?;
    if let Some(o) = &owned {
        let slots: u32 = o.iter().map(|r| r.1 - r.0).sum();
        eprintln!(
            "bulk: {} serves {} shards ({:.1}% of slots): sending only its DIDs",
            args.host,
            o.len(),
            slots as f64 / 655.36
        );
        anyhow::ensure!(!o.is_empty(), "{} serves no shards (cluster not converged?)", args.host);
    }
    let t = Instant::now();
    let done = Arc::new(AtomicU64::new(0));
    let recs = Arc::new(AtomicU64::new(0));
    let created = Arc::new(AtomicU64::new(0));
    let existing = Arc::new(AtomicU64::new(0));
    let reqs = Arc::new(AtomicU64::new(0));
    // completed ranges past the watermark (requests finish out of order)
    let wm = Arc::new(Mutex::new((start, std::collections::BTreeMap::<u64, u64>::new())));
    let write_progress = {
        let (done, recs, created, existing, reqs, wm) =
            (done.clone(), recs.clone(), created.clone(), existing.clone(), reqs.clone(), wm.clone());
        let path = progress_file.to_string();
        move |fin: bool| {
            let secs = t.elapsed().as_secs_f64();
            let (a, r, n) = (done.load(Ordering::Relaxed), recs.load(Ordering::Relaxed), reqs.load(Ordering::Relaxed));
            let v = json!({"start": start, "count": count, "watermark": wm.lock().0, "accounts": a, "records": r,
                "created": created.load(Ordering::Relaxed), "existing": existing.load(Ordering::Relaxed), "requests": n,
                "secs": secs, "accounts_s": a as f64 / secs, "records_s": r as f64 / secs, "done": fin});
            if !path.is_empty() {
                let tmp = format!("{path}.tmp");
                if std::fs::write(&tmp, v.to_string()).is_ok() {
                    let _ = std::fs::rename(&tmp, &path);
                }
            }
            v
        }
    };
    let reporter = {
        let wp = write_progress.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(2));
            tick.tick().await;
            let mut n = 0u64;
            loop {
                tick.tick().await;
                let v = wp(false);
                n += 1;
                if n.is_multiple_of(5) {
                    eprintln!(
                        "bulk: {}/{count} accounts, {} records ({:.0} accounts/s, {:.0} records/s)",
                        v["accounts"],
                        v["records"],
                        v["accounts_s"].as_f64().unwrap_or(0.0),
                        v["records_s"].as_f64().unwrap_or(0.0)
                    );
                }
            }
        })
    };
    let plan = BulkPlan {
        d,
        next: start,
        end: start + count,
        batch: batch.max(1),
        max_records: max_records.max(1),
        owned: owned.as_deref(),
    };
    let mut results = futures::stream::iter(plan)
        .map(|q| {
            let c = c.clone();
            let host = args.host.clone();
            let (done, recs, created, existing, reqs, wm) =
                (done.clone(), recs.clone(), created.clone(), existing.clone(), reqs.clone(), wm.clone());
            async move {
                let (lo, hi) = (q.lo, q.hi);
                if !q.records.is_empty() {
                    let body = match &q.indices {
                        Some(idx) => json!({"indices": idx, "records": q.records, "password": "hunter2"}),
                        None => json!({"start": lo, "count": hi - lo, "records": q.records, "password": "hunter2"}),
                    };
                    let resp = c
                        .post(format!("{host}/xrpc/vlpds.admin.bulkCreate"))
                        .bearer_auth(admin_token)
                        .json(&body)
                        .send()
                        .await?;
                    let status = resp.status();
                    let text = resp.text().await?;
                    let v: serde_json::Value = serde_json::from_str(&text).unwrap_or_else(|_| json!({"raw": text}));
                    anyhow::ensure!(
                        status.is_success() && v["failed"].as_u64() == Some(0),
                        "bulk {lo}..{hi} failed: {status} {v}"
                    );
                    anyhow::ensure!(
                        v["notOwned"].as_u64() == Some(0),
                        "bulk {lo}..{hi}: {host} no longer serves {} of its DIDs (layout moved): re-run",
                        v["notOwned"]
                    );
                    reqs.fetch_add(1, Ordering::Relaxed);
                    created.fetch_add(v["created"].as_u64().unwrap_or(0), Ordering::Relaxed);
                    existing.fetch_add(v["existing"].as_u64().unwrap_or(0), Ordering::Relaxed);
                    recs.fetch_add(v["records"].as_u64().unwrap_or(0), Ordering::Relaxed);
                }
                done.fetch_add(hi - lo, Ordering::Relaxed);
                let mut g = wm.lock();
                g.1.insert(lo, hi);
                loop {
                    let k = g.0;
                    let Some(e) = g.1.remove(&k) else { break };
                    g.0 = e;
                }
                Ok(())
            }
        })
        .buffer_unordered(concurrency);
    let mut first_err = None;
    while let Some(r) = results.next().await {
        if let Err(e) = r {
            first_err = Some(e);
            break;
        }
    }
    drop(results);
    reporter.abort();
    let v = write_progress(first_err.is_none());
    if let Some(e) = first_err {
        return Err(e);
    }
    eprintln!(
        "bulk done: {count} accounts ({} created here, {} existed) x {} dist, {} records here, {} requests in {:.1}s ({:.0} accounts/s, {:.0} records/s)",
        v["created"], v["existing"], d.fixed.map(|n| n.to_string()).unwrap_or_else(|| format!("real/{}", d.scale)),
        v["records"], v["requests"], t.elapsed().as_secs_f64(),
        v["accounts_s"].as_f64().unwrap_or(0.0), v["records_s"].as_f64().unwrap_or(0.0)
    );
    println!("{v}");
    Ok(())
}

fn dist_report(
    start: u64,
    count: u64,
    d: &Dist,
    batch: u64,
    max_records: u64,
    per_repo: f64,
    per_record: f64,
) -> anyhow::Result<()> {
    let t = Instant::now();
    let mut total = 0u64;
    let mut max = 0u32;
    let mut zero = 0u64;
    let mut h = Histogram::<u64>::new_with_bounds(1, 1 << 40, 3)?;
    // per group (the draw is per group): weight each draw by its accounts
    let mut i = start;
    let end = start + count;
    while i < end {
        let ge = ((i / d.group + 1) * d.group).min(end);
        let w = ge - i;
        // scaled values differ per group only (rounding is per group too)
        let r = d.records(i);
        total += r as u64 * w;
        max = max.max(r);
        if r == 0 {
            zero += w;
        }
        h.record_n(r as u64 + 1, w)?;
        i = ge;
    }
    // requests over all nodes (each sends only its own DIDs), as if one node
    let requests =
        BulkPlan { d, next: start, end, batch: batch.max(1), max_records: max_records.max(1), owned: None }.count();
    let q = |p: f64| h.value_at_quantile(p).saturating_sub(1);
    let bytes = per_repo * count as f64 + per_record * total as f64;
    println!(
        "{}",
        json!({
            "count": count, "records": total, "mean": total as f64 / count.max(1) as f64, "max": max,
            "zero_repos": zero, "requests": requests,
            "p50": q(0.5), "p90": q(0.9), "p99": q(0.99), "p999": q(0.999), "p9999": q(0.9999),
            "repos_ge_1k": count - h.count_between(1, 1000),
            "est_state_gb": bytes / 1e9, "secs": t.elapsed().as_secs_f64(),
            "dist": d.fixed.map(|n| format!("fixed/{n}")).unwrap_or_else(|| format!("real/{}", d.scale)),
            "group": d.group, "cap": d.cap, "knee": d.knee,
        })
    );
    Ok(())
}

fn method_keys() -> Vec<&'static str> {
    vec![
        "describeServer",
        "getRecord",
        "listRecords",
        "describeRepo",
        "getLatestCommit",
        "getRepoStatus",
        "sync.getRecord",
        "sync.getRepo",
        "listRepos",
        "createRecord",
        "putRecord",
        "deleteRecord",
        "applyWrites10",
        "applyWrites200",
        "uploadBlob64k",
        "uploadBlob1m",
        "getBlob64k",
        "createSession",
        "getSession",
        "refreshSession",
        "createAccount",
    ]
}

struct Ctx {
    host: String,
    accts: Vec<Acct>,
    /// a few existing record rkeys per account
    rkeys: Vec<Vec<String>>,
    blob64k: Vec<(String, String)>,
    refresh: Mutex<Vec<String>>,
    seq: AtomicU64,
}

async fn methods(args: &Args, only: &str, concurrency: usize, seconds: u64, json_out: &str) -> anyhow::Result<()> {
    let c = client();
    let mut accts: Vec<Acct> = serde_json::from_slice(&std::fs::read(&args.accounts_file)?)?;
    accts.truncate(2000);
    let sessions: Vec<(Acct, String)> = futures::stream::iter(accts)
        .map(|a| {
            let c = c.clone();
            let host = args.host.clone();
            async move {
                let r: serde_json::Value = c
                    .post(format!("{host}/xrpc/com.atproto.server.createSession"))
                    .json(&json!({"identifier": a.did, "password": "hunter2"}))
                    .send()
                    .await?
                    .json()
                    .await?;
                let token = r["accessJwt"].as_str().ok_or_else(|| anyhow::anyhow!("createSession: {r}"))?.to_string();
                let refresh = r["refreshJwt"].as_str().unwrap_or_default().to_string();
                anyhow::Ok((Acct { token, ..a }, refresh))
            }
        })
        .buffer_unordered(128)
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .collect::<Result<_, _>>()?;
    let refresh: Vec<String> = sessions.iter().map(|s| s.1.clone()).collect();
    let accts: Vec<Acct> = sessions.into_iter().map(|s| s.0).collect();
    let rkeys: Vec<Vec<String>> = futures::stream::iter(accts.iter().cloned())
        .map(|a| {
            let c = c.clone();
            let host = args.host.clone();
            async move {
                let r: serde_json::Value = c
                    .get(format!(
                        "{host}/xrpc/com.atproto.repo.listRecords?repo={}&collection=app.bsky.feed.post&limit=20",
                        a.did
                    ))
                    .send()
                    .await?
                    .json()
                    .await?;
                anyhow::Ok(
                    r["records"]
                        .as_array()
                        .map(|a| {
                            a.iter().filter_map(|r| r["uri"].as_str()?.rsplit('/').next().map(String::from)).collect()
                        })
                        .unwrap_or_default(),
                )
            }
        })
        // ordered: rkeys[i] must belong to accts[i]
        .buffered(128)
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .collect::<Result<_, _>>()?;
    let mut blob64k = Vec::new();
    for a in accts.iter().take(50) {
        let body: Vec<u8> = (0..65536).map(|_| rand::random::<u8>()).collect();
        let r: serde_json::Value = c
            .post(format!("{}/xrpc/com.atproto.repo.uploadBlob", args.host))
            .bearer_auth(&a.token)
            .header("content-type", "image/jpeg")
            .body(body)
            .send()
            .await?
            .json()
            .await?;
        if let Some(cid) = r["blob"]["ref"]["$link"].as_str() {
            blob64k.push((a.did.clone(), cid.to_string()));
        }
    }
    let ctx = Arc::new(Ctx {
        host: args.host.clone(),
        accts,
        rkeys,
        blob64k,
        refresh: Mutex::new(refresh),
        seq: AtomicU64::new(0),
    });
    let keys: Vec<&str> = if only.is_empty() { method_keys() } else { only.split(',').collect() };
    let mut out = String::new();
    println!(
        "{:<18} {:>10} {:>9} {:>9} {:>9} {:>9} {:>7}",
        "method", "ops/s", "p50 ms", "p90 ms", "p99 ms", "max ms", "errors"
    );
    for key in keys {
        let (n, errs, h, first_err) = bench_one(&ctx, &c, key, concurrency, seconds).await;
        let q = |p: f64| h.value_at_quantile(p) as f64 / 1000.0;
        let rate = n as f64 / seconds as f64;
        println!(
            "{key:<18} {rate:>10.0} {:>9.2} {:>9.2} {:>9.2} {:>9.1} {errs:>7}",
            q(0.5),
            q(0.9),
            q(0.99),
            h.max() as f64 / 1000.0
        );
        if let Some(e) = first_err {
            println!("  first error: {}", e.chars().take(200).collect::<String>());
        }
        out.push_str(
            &serde_json::to_string(&json!({
                "method": key, "concurrency": concurrency, "ops_per_s": rate, "errors": errs,
                "p50_ms": q(0.5), "p90_ms": q(0.9), "p99_ms": q(0.99), "p999_ms": q(0.999), "max_ms": h.max() as f64 / 1000.0,
            }))?,
        );
        out.push('\n');
    }
    if !json_out.is_empty() {
        std::fs::write(json_out, out)?;
    }
    Ok(())
}

async fn bench_one(
    ctx: &Arc<Ctx>,
    c: &reqwest::Client,
    key: &str,
    concurrency: usize,
    seconds: u64,
) -> (u64, u64, Histogram<u64>, Option<String>) {
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let hist = Arc::new(Mutex::new(hist()));
    let n = Arc::new(AtomicU64::new(0));
    let errs = Arc::new(AtomicU64::new(0));
    let first_err: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let mut tasks = Vec::new();
    for _ in 0..concurrency {
        let (ctx, c, hist, n, errs, first_err) =
            (ctx.clone(), c.clone(), hist.clone(), n.clone(), errs.clone(), first_err.clone());
        let key = key.to_string();
        tasks.push(tokio::spawn(async move {
            while Instant::now() < deadline {
                let t = Instant::now();
                match call(&ctx, &c, &key).await {
                    Ok(()) => {
                        n.fetch_add(1, Ordering::Relaxed);
                        let _ = hist.lock().record(t.elapsed().as_micros().max(1) as u64);
                    }
                    Err(e) => {
                        errs.fetch_add(1, Ordering::Relaxed);
                        first_err.lock().get_or_insert_with(|| e.to_string());
                    }
                }
            }
        }));
    }
    for t in tasks {
        let _ = t.await;
    }
    let h = hist.lock().clone();
    let fe = first_err.lock().clone();
    (n.load(Ordering::Relaxed), errs.load(Ordering::Relaxed), h, fe)
}

async fn call(ctx: &Ctx, c: &reqwest::Client, key: &str) -> anyhow::Result<()> {
    let i = rand::thread_rng().gen_range(0..ctx.accts.len());
    let a = &ctx.accts[i];
    let rkey = || {
        ctx.rkeys[i]
            .get(rand::thread_rng().gen_range(0..ctx.rkeys[i].len().max(1)))
            .cloned()
            .unwrap_or_else(|| "missing".into())
    };
    let h = &ctx.host;
    let n = ctx.seq.fetch_add(1, Ordering::Relaxed);
    let req = match key {
        "describeServer" => c.get(format!("{h}/xrpc/com.atproto.server.describeServer")),
        "getRecord" => c.get(format!("{h}/xrpc/com.atproto.repo.getRecord?repo={}&collection=app.bsky.feed.post&rkey={}", a.did, rkey())),
        "listRecords" => c.get(format!("{h}/xrpc/com.atproto.repo.listRecords?repo={}&collection=app.bsky.feed.post&limit=50", a.did)),
        "describeRepo" => c.get(format!("{h}/xrpc/com.atproto.repo.describeRepo?repo={}", a.did)),
        "getLatestCommit" => c.get(format!("{h}/xrpc/com.atproto.sync.getLatestCommit?did={}", a.did)),
        "getRepoStatus" => c.get(format!("{h}/xrpc/com.atproto.sync.getRepoStatus?did={}", a.did)),
        "sync.getRecord" => c.get(format!("{h}/xrpc/com.atproto.sync.getRecord?did={}&collection=app.bsky.feed.post&rkey={}", a.did, rkey())),
        "sync.getRepo" => c.get(format!("{h}/xrpc/com.atproto.sync.getRepo?did={}", a.did)),
        "listRepos" => c.get(format!("{h}/xrpc/com.atproto.sync.listRepos?limit=500")),
        "createRecord" => c
            .post(format!("{h}/xrpc/com.atproto.repo.createRecord"))
            .bearer_auth(&a.token)
            .json(&json!({"repo": a.did, "collection": "app.bsky.feed.post", "record": post_record(n)})),
        "putRecord" => c
            .post(format!("{h}/xrpc/com.atproto.repo.putRecord"))
            .bearer_auth(&a.token)
            .json(&json!({"repo": a.did, "collection": "app.bsky.actor.profile", "rkey": "self", "record": {"$type": "app.bsky.actor.profile", "displayName": format!("bench {n}")}})),
        "deleteRecord" => c
            .post(format!("{h}/xrpc/com.atproto.repo.deleteRecord"))
            .bearer_auth(&a.token)
            .json(&json!({"repo": a.did, "collection": "app.bsky.feed.like", "rkey": format!("bench{n}")})),
        "applyWrites10" | "applyWrites200" => {
            let k = if key == "applyWrites10" { 10 } else { 200 };
            let writes: Vec<_> = (0..k)
                .map(|j| json!({"$type": "com.atproto.repo.applyWrites#create", "collection": "app.bsky.feed.post", "value": post_record(n * 1000 + j)}))
                .collect();
            c.post(format!("{h}/xrpc/com.atproto.repo.applyWrites")).bearer_auth(&a.token).json(&json!({"repo": a.did, "writes": writes}))
        }
        "uploadBlob64k" | "uploadBlob1m" => {
            let size = if key == "uploadBlob64k" { 65536 } else { 1 << 20 };
            let mut body = vec![0u8; size];
            body[..8].copy_from_slice(&n.to_be_bytes());
            c.post(format!("{h}/xrpc/com.atproto.repo.uploadBlob")).bearer_auth(&a.token).header("content-type", "image/jpeg").body(body)
        }
        "getBlob64k" => {
            let (did, cid) = &ctx.blob64k[rand::thread_rng().gen_range(0..ctx.blob64k.len().max(1))];
            c.get(format!("{h}/xrpc/com.atproto.sync.getBlob?did={did}&cid={cid}"))
        }
        "createSession" => c.post(format!("{h}/xrpc/com.atproto.server.createSession")).json(&json!({"identifier": a.did, "password": "hunter2"})),
        "getSession" => c.get(format!("{h}/xrpc/com.atproto.server.getSession")).bearer_auth(&a.token),
        "refreshSession" => {
            let tok = ctx.refresh.lock().pop().ok_or_else(|| anyhow::anyhow!("out of refresh tokens"))?;
            let r = c.post(format!("{h}/xrpc/com.atproto.server.refreshSession")).bearer_auth(&tok).send().await?;
            anyhow::ensure!(r.status().is_success(), "refreshSession {}: {}", r.status(), r.text().await?);
            let v: serde_json::Value = r.json().await?;
            if let Some(t) = v["refreshJwt"].as_str() {
                ctx.refresh.lock().push(t.to_string());
            }
            return Ok(());
        }
        "createAccount" => c
            .post(format!("{h}/xrpc/com.atproto.server.createAccount"))
            .json(&{
                // first label <= 18 chars (reference handle limit)
                let handle = format!("m{}x{n}.vlpds.test", rand::random::<u16>());
                json!({"handle": handle, "password": "hunter2", "email": format!("{}@example.com", handle.replace('.', "-"))})
            }),
        other => anyhow::bail!("unknown method key {other}"),
    };
    let r = req.send().await?;
    let status = r.status();
    let body = r.bytes().await?;
    anyhow::ensure!(status.is_success(), "{key} {status}: {}", String::from_utf8_lossy(&body));
    Ok(())
}

async fn fanout(
    args: &Args,
    subscribers: usize,
    seconds: u64,
    cursor: Option<i64>,
    json_out: &str,
) -> anyhow::Result<()> {
    use tokio_tungstenite::tungstenite::Message;
    let mut url = format!("{}/xrpc/com.atproto.sync.subscribeRepos", args.host.replacen("http", "ws", 1));
    if let Some(c) = cursor {
        url.push_str(&format!("?cursor={c}"));
    }
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let mut tasks = Vec::new();
    for i in 0..subscribers {
        let url = url.clone();
        tasks.push(tokio::spawn(async move {
            let mut events = 0u64;
            let mut bytes = 0u64;
            let mut lag = hist();
            let mut last_seq = 0i64;
            let mut out_of_order = 0u64;
            let Ok((mut ws, _)) = tokio_tungstenite::connect_async(&url).await else {
                return (i, 0, 0, lag, 1);
            };
            while let Ok(Some(msg)) = tokio::time::timeout_at(deadline.into(), ws.next()).await {
                let Ok(Message::Binary(b)) = msg else {
                    continue;
                };
                events += 1;
                bytes += b.len() as u64;
                // decode a sample (every 64th) for lag + order checks; full decode is costly at 100k ev/s x N
                if events % 64 == 1 {
                    if let Ok((_, hl)) = vlsync_atproto::cbor::Value::decode_prefix(&b) {
                        if let Ok(body) = vlsync_atproto::cbor::Value::decode(&b[hl..]) {
                            if let Some(vlsync_atproto::cbor::Value::Int(seq)) = body.get("seq") {
                                if *seq <= last_seq {
                                    out_of_order += 1;
                                }
                                last_seq = *seq;
                            }
                            if let Some(t) = body
                                .get("time")
                                .and_then(|t| t.as_str())
                                .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
                            {
                                let l =
                                    chrono::Utc::now().signed_duration_since(t).num_microseconds().unwrap_or(0).max(1);
                                let _ = lag.record(l as u64);
                            }
                        }
                    }
                }
            }
            let _ = bytes;
            (i, events, bytes, lag, out_of_order)
        }));
    }
    let mut total = 0u64;
    let mut total_bytes = 0u64;
    let mut lag_all = hist();
    let mut per = Vec::new();
    let mut ooo = 0;
    for t in tasks {
        let (_, ev, by, lag, o) = t.await?;
        total += ev;
        total_bytes += by;
        ooo += o;
        per.push(ev);
        lag_all.add(&lag).ok();
    }
    let secs = seconds as f64;
    let min = per.iter().min().copied().unwrap_or(0) as f64 / secs;
    let max = per.iter().max().copied().unwrap_or(0) as f64 / secs;
    println!(
        "fanout subscribers={subscribers} cursor={cursor:?}: delivered {:.0} ev/s total ({:.1} MB/s), per-subscriber min {min:.0} max {max:.0} ev/s, lag p50 {:.1}ms p99 {:.1}ms max {:.1}ms, out-of-order {ooo}",
        total as f64 / secs,
        total_bytes as f64 / secs / 1e6,
        lag_all.value_at_quantile(0.5) as f64 / 1000.0,
        lag_all.value_at_quantile(0.99) as f64 / 1000.0,
        lag_all.max() as f64 / 1000.0
    );
    if !json_out.is_empty() {
        std::fs::write(
            json_out,
            serde_json::to_string(&json!({
                "subscribers": subscribers, "cursor": cursor, "events_per_s_total": total as f64 / secs,
                "mb_per_s_total": total_bytes as f64 / secs / 1e6, "per_sub_min": min, "per_sub_max": max,
                "lag_p50_ms": lag_all.value_at_quantile(0.5) as f64 / 1000.0, "lag_p99_ms": lag_all.value_at_quantile(0.99) as f64 / 1000.0,
                "lag_max_ms": lag_all.max() as f64 / 1000.0, "out_of_order": ooo,
            }))?,
        )?;
    }
    Ok(())
}

async fn verify(args: &Args, acked: &str) -> anyhow::Result<()> {
    let m: std::collections::HashMap<String, Vec<String>> = serde_json::from_slice(&std::fs::read(acked)?)?;
    let c = client();
    let total: usize = m.values().map(|v| v.len()).sum();
    let results: Vec<anyhow::Result<usize>> = futures::stream::iter(m)
        .map(|(did, rkeys)| {
            let c = c.clone();
            let host = args.host.clone();
            async move {
                let mut present = std::collections::HashSet::new();
                let mut cursor: Option<String> = None;
                loop {
                    let mut url = format!(
                        "{host}/xrpc/com.atproto.repo.listRecords?repo={did}&collection=app.bsky.feed.post&limit=100&reverse=true"
                    );
                    if let Some(cur) = &cursor {
                        url.push_str(&format!("&cursor={cur}"));
                    }
                    let v: serde_json::Value = c.get(&url).send().await?.json().await?;
                    let recs = v["records"].as_array().cloned().unwrap_or_default();
                    for r in &recs {
                        if let Some(k) = r["uri"].as_str().and_then(|u| u.rsplit('/').next()) {
                            present.insert(k.to_string());
                        }
                    }
                    match v["cursor"].as_str() {
                        Some(cur) if !recs.is_empty() => cursor = Some(cur.to_string()),
                        _ => break,
                    }
                }
                let missing = rkeys.iter().filter(|k| !present.contains(*k)).count();
                if missing > 0 {
                    eprintln!("{did}: {missing} acked records missing");
                }
                anyhow::Ok(missing)
            }
        })
        .buffer_unordered(64)
        .collect()
        .await;
    let (mut missing, mut errors) = (0, 0);
    for r in results {
        match r {
            Ok(m) => missing += m,
            Err(e) => {
                errors += 1;
                eprintln!("verify error: {e}");
            }
        }
    }
    println!("verify: {total} acked creates checked, {missing} missing, {errors} account errors");
    anyhow::ensure!(missing == 0 && errors == 0, "acknowledged writes lost");
    Ok(())
}

/// A sweep repo an earlier `sweep --reuse` filled: (did, its blobs' CIDs),
/// or None if `sw<size>.vlpds.test` doesn't exist.
async fn sweep_reuse(
    c: &reqwest::Client,
    h: &str,
    size: usize,
) -> anyhow::Result<Option<(String, Vec<(String, u64)>)>> {
    let r = c
        .post(format!("{h}/xrpc/com.atproto.server.createSession"))
        .json(&json!({"identifier": format!("sw{size}.vlpds.test"), "password": "hunter2"}))
        .send()
        .await?;
    if !r.status().is_success() {
        return Ok(None);
    }
    let v: serde_json::Value = r.json().await?;
    let did = v["did"].as_str().ok_or_else(|| anyhow::anyhow!("createSession: {v}"))?.to_string();
    let mut blobs = Vec::new();
    let mut cursor = String::new();
    loop {
        let mut u = format!("{h}/xrpc/com.atproto.sync.listBlobs?did={did}&limit=1000");
        if !cursor.is_empty() {
            u.push_str(&format!("&cursor={cursor}"));
        }
        let v: serde_json::Value = c.get(u).send().await?.json().await?;
        let page = v["cids"].as_array().cloned().unwrap_or_default();
        blobs.extend(page.iter().filter_map(|c| c.as_str()).map(|c| (c.to_string(), 0u64)));
        match v["cursor"].as_str() {
            Some(cur) if !page.is_empty() => cursor = cur.to_string(),
            _ => break,
        }
    }
    Ok(Some((did, blobs)))
}

#[allow(clippy::too_many_arguments)]
async fn sweep(
    args: &Args,
    sizes: &[usize],
    concurrency: usize,
    seconds: u64,
    fill_concurrency: usize,
    json_out: &str,
    reuse: bool,
    fill_only: bool,
) -> anyhow::Result<()> {
    let c = client();
    let h = args.host.clone();
    let mut out = String::new();
    for &size in sizes {
        // deterministic, time-ordered TID rkeys so reads can sample the whole repo
        const BASE_US: u64 = 1_600_000_000_000_000;
        let rkey_of = |i: usize| vlsync_atproto::tid::Tid::from_parts(BASE_US + i as u64 * 1000, 0).to_string();
        let reused = if reuse { sweep_reuse(&c, &h, size).await? } else { None };
        let (did, blobs, fill_secs) = if let Some((did, blobs)) = reused {
            eprintln!("== repo of {size} records reused ({did}, {} blobs)", blobs.len());
            (did, Arc::new(blobs), None)
        } else {
            let handle = if reuse {
                format!("sw{size}.vlpds.test")
            } else {
                format!("sw{size}x{}.vlpds.test", rand::random::<u16>())
            };
            let r: serde_json::Value = c
                .post(format!("{h}/xrpc/com.atproto.server.createAccount"))
                .json(&json!({"handle": handle, "password": "hunter2", "email": format!("{}@example.com", handle.replace('.', "-"))}))
                .send()
                .await?
                .json()
                .await?;
            let did = r["did"].as_str().ok_or_else(|| anyhow::anyhow!("createAccount: {r}"))?.to_string();
            let token = r["accessJwt"].as_str().unwrap().to_string();
            // one distinct blob per 100 records, so listBlobs pages over a
            // realistic blob index
            let nblobs = (size / 100).min(100_000);
            let t = Instant::now();
            let blobs: Vec<(String, u64)> = futures::stream::iter(0..nblobs)
                .map(|b| {
                    let (c, h, token) = (c.clone(), h.clone(), token.clone());
                    async move {
                        let body = format!("sweep blob {b} {}", rand::random::<u64>()).into_bytes();
                        let size = body.len() as u64;
                        let v: serde_json::Value = c
                            .post(format!("{h}/xrpc/com.atproto.repo.uploadBlob"))
                            .bearer_auth(&token)
                            .header("content-type", "image/jpeg")
                            .body(body)
                            .send()
                            .await?
                            .json()
                            .await?;
                        let cid = v["blob"]["ref"]["$link"]
                            .as_str()
                            .ok_or_else(|| anyhow::anyhow!("uploadBlob: {v}"))?
                            .to_string();
                        anyhow::Ok((cid, size))
                    }
                })
                .buffer_unordered(64)
                .collect::<Vec<_>>()
                .await
                .into_iter()
                .collect::<anyhow::Result<_>>()?;
            let blobs = Arc::new(blobs);
            if nblobs > 0 {
                eprintln!("  {nblobs} blobs uploaded in {:.1}s", t.elapsed().as_secs_f64());
            }
            let t = Instant::now();
            let filled = Arc::new(AtomicU64::new(0));
            let batches = size.div_ceil(200);
            {
                let pf = filled.clone();
                let progress = tokio::spawn(async move {
                    let t = Instant::now();
                    loop {
                        tokio::time::sleep(Duration::from_secs(10)).await;
                        let n = pf.load(Ordering::Relaxed);
                        eprintln!("  fill {size}: {n} records ({:.0}/s)", n as f64 / t.elapsed().as_secs_f64());
                    }
                });
                futures::stream::iter(0..batches)
                    .map(|b| {
                        let (c, h, did, token, filled, blobs) = (c.clone(), h.clone(), did.clone(), token.clone(), filled.clone(), blobs.clone());
                        async move {
                            let n = (size - b * 200).min(200);
                            let writes: Vec<_> = (0..n)
                                .map(|j| {
                                    let i = b * 200 + j;
                                    let mut v = post_record(i as u64);
                                    if i % 100 == 0 && i / 100 < blobs.len() {
                                        let (cid, sz) = &blobs[i / 100];
                                        v["embed"] = json!({"$type": "app.bsky.embed.images", "images": [{"alt": "", "image": {"$type": "blob", "ref": {"$link": cid}, "mimeType": "image/jpeg", "size": sz}}]});
                                    }
                                    json!({"$type": "com.atproto.repo.applyWrites#create", "collection": "app.bsky.feed.post", "rkey": rkey_of(i), "value": v})
                                })
                                .collect();
                            let body = json!({"repo": did, "writes": writes});
                            for attempt in 0..5 {
                                let resp = c
                                    .post(format!("{h}/xrpc/com.atproto.repo.applyWrites"))
                                    .bearer_auth(&token)
                                    .json(&body)
                                    .send()
                                    .await?;
                                if resp.status().is_success() {
                                    filled.fetch_add(n as u64, Ordering::Relaxed);
                                    return anyhow::Ok(());
                                }
                                if attempt == 4 {
                                    anyhow::bail!("fill failed: {}", resp.text().await?);
                                }
                                tokio::time::sleep(Duration::from_millis(200)).await;
                            }
                            Ok(())
                        }
                    })
                    .buffer_unordered(fill_concurrency)
                    .collect::<Vec<_>>()
                    .await
                    .into_iter()
                    .collect::<anyhow::Result<Vec<_>>>()?;
                progress.abort();
            }
            let fill_secs = t.elapsed().as_secs_f64();
            eprintln!("== repo of {size} records filled in {fill_secs:.1}s ({:.0} records/s)", size as f64 / fill_secs);
            (did, blobs, Some(fill_secs))
        };
        if fill_only {
            continue;
        }
        let rkeys: Vec<String> = (0..2000).map(|_| rkey_of(rand::thread_rng().gen_range(0..size))).collect();
        let mut cids = Vec::new();
        for rk in rkeys.iter().take(200) {
            let v: serde_json::Value = c
                .get(format!("{h}/xrpc/com.atproto.repo.getRecord?repo={did}&collection=app.bsky.feed.post&rkey={rk}"))
                .send()
                .await?
                .json()
                .await?;
            if let Some(cid) = v["cid"].as_str() {
                cids.push(cid.to_string());
            }
        }
        let rkeys = Arc::new(rkeys);
        let cids = Arc::new(cids);
        // listBlobs pages in CID order: a cursor from the middle of the set
        let mid_blob: Arc<str> = {
            let mut b: Vec<&str> = blobs.iter().map(|b| b.0.as_str()).collect();
            b.sort();
            b.get(b.len() / 2).copied().unwrap_or_default().into()
        };
        let methods = [
            "getRecord",
            "listRecords",
            "listRecordsDeep",
            "describeRepo",
            "getLatestCommit",
            "getRepoStatus",
            "sync.getRecord",
            "getBlocks10",
            "listBlobs",
            "listBlobsDeep",
        ];
        match fill_secs {
            Some(f) => println!("\n### repo size {size}  (fill {:.0} rec/s)", size as f64 / f),
            None => println!("\n### repo size {size}  (reused)"),
        }
        println!("{:<18} {:>10} {:>9} {:>9} {:>9} {:>7}", "method", "ops/s", "p50 ms", "p99 ms", "max ms", "errors");
        for m in methods {
            let deadline = Instant::now() + Duration::from_secs(seconds);
            let hist_all = Arc::new(Mutex::new(hist()));
            let (n, errs) = (Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0)));
            let first_err: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
            let mut tasks = Vec::new();
            for _ in 0..concurrency {
                let (c, h, did, rkeys, cids, mid_blob, hist_all, n, errs, first_err) = (
                    c.clone(),
                    h.clone(),
                    did.clone(),
                    rkeys.clone(),
                    cids.clone(),
                    mid_blob.clone(),
                    hist_all.clone(),
                    n.clone(),
                    errs.clone(),
                    first_err.clone(),
                );
                tasks.push(tokio::spawn(async move {
                    while Instant::now() < deadline {
                        let rk = rkeys.get(rand::thread_rng().gen_range(0..rkeys.len().max(1))).cloned().unwrap_or_default();
                        let url = match m {
                            "getRecord" => format!("{h}/xrpc/com.atproto.repo.getRecord?repo={did}&collection=app.bsky.feed.post&rkey={rk}"),
                            "listRecords" => format!("{h}/xrpc/com.atproto.repo.listRecords?repo={did}&collection=app.bsky.feed.post&limit=100"),
                            "listRecordsDeep" => format!("{h}/xrpc/com.atproto.repo.listRecords?repo={did}&collection=app.bsky.feed.post&limit=100&cursor={rk}"),
                            "describeRepo" => format!("{h}/xrpc/com.atproto.repo.describeRepo?repo={did}"),
                            "getLatestCommit" => format!("{h}/xrpc/com.atproto.sync.getLatestCommit?did={did}"),
                            "getRepoStatus" => format!("{h}/xrpc/com.atproto.sync.getRepoStatus?did={did}"),
                            "sync.getRecord" => format!("{h}/xrpc/com.atproto.sync.getRecord?did={did}&collection=app.bsky.feed.post&rkey={rk}"),
                            "getBlocks10" => {
                                let mut u = format!("{h}/xrpc/com.atproto.sync.getBlocks?did={did}");
                                for _ in 0..10 {
                                    if let Some(cid) = cids.get(rand::thread_rng().gen_range(0..cids.len().max(1))) {
                                        u.push_str(&format!("&cids={cid}"));
                                    }
                                }
                                u
                            }
                            "listBlobsDeep" => format!("{h}/xrpc/com.atproto.sync.listBlobs?did={did}&limit=500&cursor={mid_blob}"),
                            _ => format!("{h}/xrpc/com.atproto.sync.listBlobs?did={did}&limit=500"),
                        };
                        let t = Instant::now();
                        match c.get(&url).send().await {
                            Ok(r) if r.status().is_success() => {
                                let _ = r.bytes().await;
                                n.fetch_add(1, Ordering::Relaxed);
                                let _ = hist_all.lock().record(t.elapsed().as_micros().max(1) as u64);
                            }
                            Ok(r) => {
                                errs.fetch_add(1, Ordering::Relaxed);
                                let st = r.status();
                                let body = r.text().await.unwrap_or_default();
                                first_err.lock().get_or_insert_with(|| format!("{st} {body}"));
                            }
                            Err(e) => {
                                errs.fetch_add(1, Ordering::Relaxed);
                                first_err.lock().get_or_insert_with(|| e.to_string());
                            }
                        }
                    }
                }));
            }
            for t in tasks {
                let _ = t.await;
            }
            let hh = hist_all.lock().clone();
            let q = |p: f64| hh.value_at_quantile(p) as f64 / 1000.0;
            let rate = n.load(Ordering::Relaxed) as f64 / seconds as f64;
            let e = errs.load(Ordering::Relaxed);
            println!("{m:<18} {rate:>10.0} {:>9.2} {:>9.2} {:>9.1} {e:>7}", q(0.5), q(0.99), hh.max() as f64 / 1000.0);
            if let Some(fe) = first_err.lock().as_ref() {
                println!("  first error: {}", fe.chars().take(160).collect::<String>());
            }
            out.push_str(&serde_json::to_string(&json!({"size": size, "method": m, "concurrency": concurrency, "ops_per_s": rate,
                "p50_ms": q(0.5), "p90_ms": q(0.9), "p99_ms": q(0.99), "max_ms": hh.max() as f64 / 1000.0, "errors": e}))?);
            out.push('\n');
        }
        let runs = if size >= 1_000_000 { 2 } else { 5 };
        for i in 0..runs {
            let t = Instant::now();
            let mut bytes = 0usize;
            let mut resp = c.get(format!("{h}/xrpc/com.atproto.sync.getRepo?did={did}")).send().await?;
            let ttfb = t.elapsed().as_secs_f64();
            while let Some(chunk) = resp.chunk().await? {
                bytes += chunk.len();
            }
            let secs = t.elapsed().as_secs_f64();
            println!(
                "getRepo run {i}: {:.1} MB in {secs:.2}s ({:.0} MB/s), ttfb {:.0} ms",
                bytes as f64 / 1e6,
                bytes as f64 / 1e6 / secs,
                ttfb * 1000.0
            );
            out.push_str(&serde_json::to_string(&json!({"size": size, "method": "getRepo", "run": i, "bytes": bytes, "secs": secs, "ttfb_ms": ttfb * 1000.0}))?);
            out.push('\n');
        }
        out.push_str(&serde_json::to_string(&match fill_secs {
            Some(f) => json!({"size": size, "method": "_fill", "secs": f, "records_per_s": size as f64 / f}),
            None => json!({"size": size, "method": "_fill", "reused": true}),
        })?);
        out.push('\n');
        if !json_out.is_empty() {
            std::fs::write(json_out, &out)?;
        }
    }
    Ok(())
}

fn collect_blob_links(v: &serde_json::Value, out: &mut Vec<(String, String)>) {
    match v {
        serde_json::Value::Object(m) => {
            if m.get("$type").and_then(|t| t.as_str()) == Some("blob") {
                if let (Some(link), mime) = (
                    m.get("ref").and_then(|r| r.get("$link")).and_then(|l| l.as_str()),
                    m.get("mimeType").and_then(|t| t.as_str()),
                ) {
                    out.push((link.to_string(), mime.unwrap_or("application/octet-stream").to_string()));
                }
            }
            m.values().for_each(|c| collect_blob_links(c, out));
        }
        serde_json::Value::Array(a) => a.iter().for_each(|c| collect_blob_links(c, out)),
        _ => {}
    }
}

fn rewrite_blob_links(v: &mut serde_json::Value, map: &std::collections::HashMap<String, (String, u64)>) {
    match v {
        serde_json::Value::Object(m) => {
            if m.get("$type").and_then(|t| t.as_str()) == Some("blob") {
                let old = m.get("ref").and_then(|r| r.get("$link")).and_then(|l| l.as_str()).map(String::from);
                if let Some((new, size)) = old.and_then(|o| map.get(&o)) {
                    m.insert("ref".into(), json!({"$link": new}));
                    m.insert("size".into(), json!(size));
                }
            }
            m.values_mut().for_each(|c| rewrite_blob_links(c, map));
        }
        serde_json::Value::Array(a) => a.iter_mut().for_each(|c| rewrite_blob_links(c, map)),
        _ => {}
    }
}

async fn clone_repo(
    args: &Args,
    car_path: &str,
    copies: usize,
    concurrency: usize,
    blobs_dir: &str,
) -> anyhow::Result<()> {
    let data = std::fs::read(car_path)?;
    let (roots, blocks) = vlsync_atproto::car::read_car(&data)?;
    let map: std::collections::HashMap<vlsync_atproto::cid::Cid, Vec<u8>> =
        blocks.iter().map(|(c, b)| (*c, b.to_vec())).collect();
    let commit = vlsync_atproto::cbor::Value::decode(&map[&roots[0]])?;
    let Some(vlsync_atproto::cbor::Value::Link(data_root)) = commit.get("data") else {
        anyhow::bail!("no data root in commit")
    };
    let tree = vlsync_atproto::mst::Tree::load_from_blocks(&map, *data_root)?;
    let mut records: Vec<(String, String, serde_json::Value)> = Vec::new();
    let mut by_coll: std::collections::BTreeMap<String, (usize, usize)> = Default::default();
    let mut walk_err = None;
    tree.walk(&mut |k, cid| {
        let path = String::from_utf8_lossy(k).to_string();
        let Some((coll, rkey)) = path.split_once('/') else { return };
        match map.get(&cid).map(|b| vlsync_atproto::cbor::Value::decode(b)) {
            Some(Ok(v)) => {
                let e = by_coll.entry(coll.to_string()).or_default();
                e.0 += 1;
                e.1 += map[&cid].len();
                records.push((coll.to_string(), rkey.to_string(), v.to_json()));
            }
            Some(Err(e)) => walk_err = Some(format!("{path}: {e}")),
            None => walk_err = Some(format!("{path}: record block missing")),
        }
    });
    if let Some(e) = walk_err {
        eprintln!("warning: {e}");
    }
    let total_bytes: usize = by_coll.values().map(|v| v.1).sum();
    eprintln!(
        "source repo: {} records, {:.1} MB of record blocks, {} MST+record blocks",
        records.len(),
        total_bytes as f64 / 1e6,
        map.len()
    );
    for (c, (n, b)) in &by_coll {
        eprintln!("  {c:<40} {n:>7} records {:>8.1} KB", *b as f64 / 1e3);
    }
    let mut blob_links = Vec::new();
    for (_, _, v) in &records {
        collect_blob_links(v, &mut blob_links);
    }
    blob_links.sort();
    blob_links.dedup_by(|a, b| a.0 == b.0);
    eprintln!("  {} distinct blob refs (re-pointed at small stand-in blobs)", blob_links.len());

    let c = client();
    let h = args.host.clone();
    let mut accts: Vec<Acct> =
        std::fs::read(&args.accounts_file).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
    for copy in 0..copies {
        let t = Instant::now();
        let handle = format!("c{copy}x{}.vlpds.test", rand::random::<u32>());
        let r: serde_json::Value = c
            .post(format!("{h}/xrpc/com.atproto.server.createAccount"))
            .json(&json!({"handle": handle, "password": "hunter2", "email": format!("{}@example.com", handle.replace('.', "-"))}))
            .send()
            .await?
            .json()
            .await?;
        let did = r["did"].as_str().ok_or_else(|| anyhow::anyhow!("createAccount: {r}"))?.to_string();
        let token = r["accessJwt"].as_str().unwrap().to_string();
        let blob_map: std::collections::HashMap<String, (String, u64)> = futures::stream::iter(blob_links.clone())
            .map(|(old, mime)| {
                let (c, h, token) = (c.clone(), h.clone(), token.clone());
                async move {
                    let real =
                        (!blobs_dir.is_empty()).then(|| std::fs::read(format!("{blobs_dir}/{old}")).ok()).flatten();
                    let body = real.unwrap_or_else(|| format!("stand-in for {old}").into_bytes());
                    let size = body.len() as u64;
                    let v: serde_json::Value = c
                        .post(format!("{h}/xrpc/com.atproto.repo.uploadBlob"))
                        .bearer_auth(&token)
                        .header("content-type", mime)
                        .body(body)
                        .send()
                        .await?
                        .json()
                        .await?;
                    let new = v["blob"]["ref"]["$link"]
                        .as_str()
                        .ok_or_else(|| anyhow::anyhow!("uploadBlob: {v}"))?
                        .to_string();
                    anyhow::Ok((old, (new, size)))
                }
            })
            .buffer_unordered(16)
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .collect::<anyhow::Result<_>>()?;
        let kept = blob_map.iter().filter(|(o, (n, _))| o == &n).count();
        eprintln!("  blobs: {kept} uploaded with original bytes (same CID), {} stand-ins", blob_map.len() - kept);
        let mut recs = records.clone();
        for (_, _, v) in recs.iter_mut() {
            rewrite_blob_links(v, &blob_map);
        }
        // batch by count (<= 200 ops, the commit limit) and encoded size
        // (stay well under the server's JSON body limit)
        let mut batches: Vec<Vec<(String, String, serde_json::Value)>> = Vec::new();
        let (mut cur, mut cur_bytes) = (Vec::new(), 0usize);
        for rec in recs {
            let sz = rec.2.to_string().len() + 128;
            if !cur.is_empty() && (cur.len() == 200 || cur_bytes + sz > 48_000) {
                batches.push(std::mem::take(&mut cur));
                cur_bytes = 0;
            }
            cur_bytes += sz;
            cur.push(rec);
        }
        if !cur.is_empty() {
            batches.push(cur);
        }
        let failed = Arc::new(AtomicU64::new(0));
        let first_err: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        futures::stream::iter(batches)
            .map(|batch| {
                let (c, h, did, token, failed, first_err) = (c.clone(), h.clone(), did.clone(), token.clone(), failed.clone(), first_err.clone());
                async move {
                    let writes: Vec<_> = batch
                        .iter()
                        .map(|(coll, rkey, v)| json!({"$type": "com.atproto.repo.applyWrites#create", "collection": coll, "rkey": rkey, "value": v}))
                        .collect();
                    let resp = c
                        .post(format!("{h}/xrpc/com.atproto.repo.applyWrites"))
                        .bearer_auth(&token)
                        .json(&json!({"repo": did, "writes": writes, "validate": false}))
                        .send()
                        .await;
                    match resp {
                        Ok(r) if r.status().is_success() => {}
                        Ok(r) => {
                            failed.fetch_add(batch.len() as u64, Ordering::Relaxed);
                            let t = r.text().await.unwrap_or_default();
                            first_err.lock().get_or_insert(t);
                        }
                        Err(e) => {
                            failed.fetch_add(batch.len() as u64, Ordering::Relaxed);
                            first_err.lock().get_or_insert(e.to_string());
                        }
                    }
                }
            })
            .buffer_unordered(concurrency)
            .collect::<Vec<_>>()
            .await;
        let f = failed.load(Ordering::Relaxed);
        eprintln!(
            "copy {copy}: {did} ({handle}) {} records in {:.1}s, {f} failed{}",
            records.len() - f as usize,
            t.elapsed().as_secs_f64(),
            first_err
                .lock()
                .as_ref()
                .map(|e| format!(" (first error: {})", e.chars().take(200).collect::<String>()))
                .unwrap_or_default()
        );
        accts.push(Acct { did, handle, token });
    }
    std::fs::write(&args.accounts_file, serde_json::to_vec(&accts)?)?;
    Ok(())
}

async fn stub_appview(listen: &str, body_bytes: usize, content_encoding: &str, repo_rev: &str) -> anyhow::Result<()> {
    let body = if content_encoding.is_empty() {
        let pad = "x".repeat(body_bytes.saturating_sub(32));
        bytes::Bytes::from(format!("{{\"feed\":[],\"cursor\":\"{pad}\"}}"))
    } else {
        bytes::Bytes::from((0..body_bytes).map(|i| (i * 131 + 7) as u8).collect::<Vec<u8>>())
    };
    let ce = (!content_encoding.is_empty()).then(|| axum::http::HeaderValue::from_str(content_encoding)).transpose()?;
    let rev = (!repo_rev.is_empty()).then(|| axum::http::HeaderValue::from_str(repo_rev)).transpose()?;
    let app = axum::Router::new().fallback(move || {
        let (body, ce, rev) = (body.clone(), ce.clone(), rev.clone());
        async move {
            let mut r = axum::response::IntoResponse::into_response((
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                body,
            ));
            if let Some(ce) = ce {
                r.headers_mut().insert(axum::http::header::CONTENT_ENCODING, ce);
            }
            if let Some(rev) = rev {
                r.headers_mut().insert("atproto-repo-rev", rev);
            }
            r
        }
    });
    let l = tokio::net::TcpListener::bind(listen).await?;
    eprintln!("stub appview on {listen}, {body_bytes}-byte bodies");
    axum::serve(l, app).await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn proxy_bench(
    args: &Args,
    active: u64,
    concurrency: usize,
    seconds: u64,
    path: &str,
    connections: usize,
    jwt_secret: &str,
    service_did: &str,
    accept_encoding: &str,
    json_out: &str,
) -> anyhow::Result<()> {
    let t = Instant::now();
    let accept_encoding: Arc<str> = accept_encoding.into();
    let jwt = vlpds::auth::Jwt::new(jwt_secret, service_did);
    let tokens: Arc<Vec<(String, String)>> = Arc::new(
        (0..active)
            .map(|i| {
                let did = vlpds::state::bulk_did(i);
                let tok = format!("Bearer {}", jwt.access(&did));
                (did, tok)
            })
            .collect(),
    );
    eprintln!("minted {active} tokens in {:.1}s", t.elapsed().as_secs_f64());
    let clients = Arc::new(Clients::new(connections));
    let url: Arc<str> = format!("{}/xrpc/{path}", args.host).into();
    // warm: one pass over a sample so connections are up
    let run_for = |secs: u64, record: bool| {
        let (clients, tokens, url, ae) = (clients.clone(), tokens.clone(), url.clone(), accept_encoding.clone());
        async move {
            let deadline = Instant::now() + Duration::from_secs(secs);
            let tasks: Vec<_> = (0..concurrency)
                .map(|_| {
                    let (clients, tokens, url, ae) = (clients.clone(), tokens.clone(), url.clone(), ae.clone());
                    tokio::spawn(async move {
                        let mut h = hist();
                        let (mut ok, mut err, mut bytes) = (0u64, 0u64, 0u64);
                        let mut first_err = None;
                        while Instant::now() < deadline {
                            let (_, tok) = &tokens[rand::thread_rng().gen_range(0..tokens.len())];
                            let t = Instant::now();
                            let mut rb = clients.pick().get(&*url).header("authorization", tok);
                            if !ae.is_empty() {
                                rb = rb.header("accept-encoding", &*ae);
                            }
                            match rb.send().await {
                                Ok(r) if r.status().is_success() => match r.bytes().await {
                                    Ok(b) => {
                                        ok += 1;
                                        bytes += b.len() as u64;
                                        if record {
                                            let _ = h.record(t.elapsed().as_micros().max(1) as u64);
                                        }
                                    }
                                    Err(e) => {
                                        err += 1;
                                        first_err.get_or_insert(e.to_string());
                                    }
                                },
                                Ok(r) => {
                                    err += 1;
                                    let st = r.status();
                                    let b = r.text().await.unwrap_or_default();
                                    first_err
                                        .get_or_insert(format!("{st} {}", b.chars().take(160).collect::<String>()));
                                }
                                Err(e) => {
                                    err += 1;
                                    first_err.get_or_insert(e.to_string());
                                }
                            }
                        }
                        (h, ok, err, bytes, first_err)
                    })
                })
                .collect();
            let mut all = hist();
            let (mut ok, mut err, mut bytes, mut fe) = (0, 0, 0, None);
            for t in tasks {
                if let Ok((h, o, e, b, f)) = t.await {
                    all.add(&h).ok();
                    ok += o;
                    err += e;
                    bytes += b;
                    if fe.is_none() {
                        fe = f;
                    }
                }
            }
            (all, ok, err, bytes, fe)
        }
    };
    let _ = run_for(3, false).await;
    let (h, ok, err, bytes, fe) = run_for(seconds, true).await;
    let secs = seconds as f64;
    let q = |p: f64| h.value_at_quantile(p) as f64 / 1000.0;
    println!(
        "proxy active={active} concurrency={concurrency}: {:.0} req/s ok ({:.1} MB/s), errors {err}, p50 {:.2}ms p90 {:.2}ms p99 {:.2}ms p99.9 {:.2}ms max {:.1}ms",
        ok as f64 / secs,
        bytes as f64 / secs / 1e6,
        q(0.5),
        q(0.9),
        q(0.99),
        q(0.999),
        h.max() as f64 / 1000.0
    );
    if let Some(e) = &fe {
        println!("first error: {e}");
    }
    if !json_out.is_empty() {
        std::fs::write(
            json_out,
            serde_json::to_string(
                &json!({"active": active, "concurrency": concurrency, "connections": connections, "path": path,
                "req_per_s": ok as f64 / secs, "errors": err, "mb_per_s": bytes as f64 / secs / 1e6,
                "p50_ms": q(0.5), "p90_ms": q(0.9), "p99_ms": q(0.99), "p999_ms": q(0.999), "max_ms": h.max() as f64 / 1000.0, "first_error": fe}),
            )?,
        )?;
    }
    Ok(())
}
