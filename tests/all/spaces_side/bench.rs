//! In-process sync micro-bench for Spaces (results: bench/results/spaces-sync.md).
//!
//! ```text
//! systemd-run --user --scope -p MemoryMax=16G \
//!   cargo test --profile dev-release --features bench-jemalloc --test all \
//!   spaces_side::bench::spaces_microbench -- --ignored --nocapture --test-threads=1
//! ```
//!
//! (or `just spaces-microbench`). One node (three for `cluster`), `--spaces` on, log segment PUTs
//! delayed like S3 (`SPACES_BENCH_PUT_MS`, default 25 ms median, lognormal
//! sigma 0.3; below 5 ms a thread sleep, so 0.5 means 0.5). Sections, picked with
//! `SPACES_BENCH_ONLY=noop,delta,cred,conc,bucket,load,cluster` (default all):
//!
//! - `noop`: listRepoOps with `since` at the head, client p50/p99, the
//!   server's own histogram, and process CPU per request over a `_health`
//!   loop on the same client (the client's share cancels out).
//! - `delta`: listRepoOps of the last K ops (`SPACES_BENCH_DELTA`, default
//!   1,10,100).
//! - `cred`: the first use of each of `SPACES_BENCH_CREDS` (200) fresh
//!   credentials (a cache miss: the full chain verify) against one
//!   credential reused (a hit from C2 on).
//! - `conc`: `SPACES_BENCH_CONC` (1,4,16) concurrent writers on one
//!   account, public (a session token), public over OAuth (DPoP, as every
//!   space write is) and then space, and log segment PUTs per write.
//! - `bucket`: object-store requests by op and component while public
//!   writers run, without and then with concurrent space writes. The target
//!   is zero added PUTs per space write.
//! - `load`: public commit latency alone, then under a spaces load of
//!   `SPACES_BENCH_N` spaces x `_M` members x `_K` pollers each, plus
//!   `_SYNCERS` registered syncers per space that pull on every notify.
//! - `cluster`: write -> notify ack on a three-node cluster (the same PUT
//!   delay), each space's authority on one node and its members (at least
//!   two) on the others, so every notify crosses nodes and every syncer pull
//!   is forwarded: the server's write ack -> authority ack histogram and, at
//!   each syncer (at least one), write sent -> notified and notified ->
//!   pulled.
//!
//! Metrics are process-wide, so run it alone (`--test-threads=1`, no other
//! test filter). `SPACES_BENCH_SECS` sets each timed window (default 20).
//! Members (M > 0) need simplespace putMember and member writes (core C3);
//! syncers need registerNotify and fan-out (C3, C4). With C1 alone run
//! `SPACES_BENCH_M=0 SPACES_BENCH_SYNCERS=0`.

use super::cluster::Plc;
use crate::common::spaces::{xrpc_url, Holder, SpaceClient};
use crate::common::*;
use parking_lot::Mutex;
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn env_or<T: std::str::FromStr>(k: &str, d: T) -> T {
    std::env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(d)
}

struct Cfg {
    sections: Vec<String>,
    put_ms: f64,
    secs: f64,
    noop_reqs: usize,
    deltas: Vec<usize>,
    delta_reqs: usize,
    creds: usize,
    conc: Vec<usize>,
    spaces: usize,
    members: usize,
    pollers: usize,
    syncers: usize,
    poll_every: Duration,
    space_write_every: Duration,
    public_writers: usize,
}

impl Cfg {
    fn from_env() -> Cfg {
        let only = env_or("SPACES_BENCH_ONLY", "noop,delta,cred,conc,bucket,load,cluster".to_string());
        Cfg {
            sections: only.split(',').map(|s| s.trim().to_string()).collect(),
            put_ms: env_or("SPACES_BENCH_PUT_MS", 25.0),
            secs: env_or("SPACES_BENCH_SECS", 20.0),
            noop_reqs: env_or("SPACES_BENCH_REQS", 20_000),
            deltas: env_or("SPACES_BENCH_DELTA", "1,10,100".to_string())
                .split(',')
                .filter_map(|v| v.trim().parse().ok())
                .collect(),
            delta_reqs: env_or("SPACES_BENCH_DELTA_REQS", 2_000),
            creds: env_or("SPACES_BENCH_CREDS", 200),
            conc: env_or("SPACES_BENCH_CONC", "1,4,16".to_string())
                .split(',')
                .filter_map(|v| v.trim().parse().ok())
                .collect(),
            spaces: env_or("SPACES_BENCH_N", 20),
            members: env_or("SPACES_BENCH_M", 5),
            pollers: env_or("SPACES_BENCH_K", 3),
            syncers: env_or("SPACES_BENCH_SYNCERS", 1),
            poll_every: Duration::from_millis(env_or("SPACES_BENCH_POLL_MS", 1000)),
            space_write_every: Duration::from_millis(env_or("SPACES_BENCH_WRITE_MS", 500)),
            public_writers: env_or("SPACES_BENCH_PUBLIC", 16),
        }
    }

    /// Every section once, as small as still says something: the harness
    /// check, not a measurement.
    fn tiny() -> Cfg {
        Cfg {
            sections: ["noop", "delta", "cred", "conc", "bucket", "load"].map(String::from).to_vec(),
            put_ms: 2.0,
            secs: 1.0,
            noop_reqs: 50,
            deltas: vec![1, 5],
            delta_reqs: 10,
            creds: 4,
            conc: vec![2],
            spaces: 2,
            members: 0,
            pollers: 1,
            syncers: 0,
            poll_every: Duration::from_millis(100),
            space_write_every: Duration::from_millis(100),
            public_writers: 2,
        }
    }

    fn on(&self, section: &str) -> bool {
        self.sections.iter().any(|s| s == section)
    }
}

// ---------------------------------------------------------------- numbers

/// CLOCK_PROCESS_CPUTIME_ID, seconds: the server and the client share the
/// process, so callers difference it against a baseline loop.
fn process_cpu() -> f64 {
    #[repr(C)]
    struct Ts(i64, i64);
    unsafe extern "C" {
        fn clock_gettime(clk: i32, ts: *mut Ts) -> i32;
    }
    let clk = if cfg!(target_os = "macos") { 12 } else { 2 };
    let mut t = Ts(0, 0);
    unsafe { clock_gettime(clk, &mut t) };
    t.0 as f64 + t.1 as f64 * 1e-9
}

#[derive(Default, Clone)]
struct Lat(Vec<f64>);

impl Lat {
    fn push(&mut self, d: Duration) {
        self.0.push(d.as_secs_f64());
    }

    /// Nearest rank, in ms.
    fn q(&self, q: f64) -> f64 {
        if self.0.is_empty() {
            return f64::NAN;
        }
        let mut v = self.0.clone();
        v.sort_by(|a, b| a.total_cmp(b));
        v[((q * v.len() as f64).ceil() as usize).clamp(1, v.len()) - 1] * 1e3
    }

    fn line(&self) -> String {
        format!("n={} p50 {:.3} ms, p99 {:.3} ms, max {:.3} ms", self.0.len(), self.q(0.5), self.q(0.99), self.q(1.0))
    }
}

/// `name{labels} value` lines of a Prometheus exposition: the labels and
/// the value of every series of `name`.
fn series(text: &str, name: &str) -> Vec<(BTreeMap<String, String>, f64)> {
    let mut out = Vec::new();
    for l in text.lines() {
        let Some(rest) = l.strip_prefix(name) else { continue };
        let (labels, value) = match rest.as_bytes().first() {
            Some(b'{') => match rest.rfind('}') {
                Some(end) => (&rest[1..end], rest[end + 1..].trim()),
                None => continue,
            },
            Some(b' ') => ("", rest.trim()),
            _ => continue,
        };
        let Ok(v) = value.split(' ').next().unwrap_or("").parse::<f64>() else { continue };
        let mut m = BTreeMap::new();
        let mut s = labels;
        while let Some(eq) = s.find("=\"") {
            let k = s[..eq].trim_start_matches(',').trim().to_string();
            let after = &s[eq + 2..];
            let mut end = 0;
            let b = after.as_bytes();
            while end < b.len() && !(b[end] == b'"' && (end == 0 || b[end - 1] != b'\\')) {
                end += 1;
            }
            m.insert(k, after[..end].to_string());
            s = after.get(end + 1..).unwrap_or("");
        }
        out.push((m, v));
    }
    out
}

fn sum(text: &str, name: &str, filter: &[(&str, &str)]) -> f64 {
    series(text, name)
        .into_iter()
        .filter(|(m, _)| filter.iter().all(|(k, v)| m.get(*k).map(String::as_str) == Some(*v)))
        .map(|(_, v)| v)
        .sum()
}

/// A histogram's change between two scrapes: mean and an interpolated
/// quantile (ms), as Prometheus's histogram_quantile would give.
struct HistDelta {
    count: f64,
    sum: f64,
    buckets: Vec<(f64, f64)>,
}

impl HistDelta {
    fn new(before: &str, after: &str, name: &str, filter: &[(&str, &str)]) -> HistDelta {
        let le = |text: &str| {
            let mut m: BTreeMap<u64, (f64, f64)> = BTreeMap::new();
            for (labels, v) in series(text, &format!("{name}_bucket")) {
                if !filter.iter().all(|(k, val)| labels.get(*k).map(String::as_str) == Some(*val)) {
                    continue;
                }
                let Some(b) = labels.get("le") else { continue };
                let b = if b == "+Inf" { f64::INFINITY } else { b.parse().unwrap_or(f64::NAN) };
                m.entry(b.to_bits()).or_insert((b, 0.0)).1 += v;
            }
            m
        };
        let (b0, b1) = (le(before), le(after));
        let mut buckets: Vec<(f64, f64)> =
            b1.iter().map(|(k, (b, v))| (*b, v - b0.get(k).map_or(0.0, |x| x.1))).collect();
        buckets.sort_by(|a, b| a.0.total_cmp(&b.0));
        let d = |s: &str| sum(after, &format!("{name}{s}"), filter) - sum(before, &format!("{name}{s}"), filter);
        HistDelta { count: d("_count"), sum: d("_sum"), buckets }
    }

    fn mean_ms(&self) -> f64 {
        self.sum / self.count * 1e3
    }

    fn q_ms(&self, q: f64) -> f64 {
        let total = self.count;
        if total <= 0.0 {
            return f64::NAN;
        }
        let rank = q * total;
        let (mut lo, mut below) = (0.0, 0.0);
        for &(le, cum) in &self.buckets {
            if cum >= rank {
                if le.is_infinite() {
                    return lo * 1e3;
                }
                let inb = cum - below;
                let f = if inb > 0.0 { (rank - below) / inb } else { 1.0 };
                return (lo + (le - lo) * f) * 1e3;
            }
            (lo, below) = (le, cum);
        }
        f64::NAN
    }

    fn line(&self) -> String {
        format!(
            "n={} mean {:.3} ms, p50 {:.3} ms, p99 {:.3} ms (server histogram)",
            self.count,
            self.mean_ms(),
            self.q_ms(0.5),
            self.q_ms(0.99)
        )
    }
}

// ---------------------------------------------------------------- clients

/// A credential read with its headers signed once: the signature covers
/// only `authorization` and the audience, so it's the same for every
/// request and the client's own cost stays a plain GET.
#[derive(Clone)]
struct Reader {
    http: reqwest::Client,
    base: String,
    headers: reqwest::header::HeaderMap,
}

impl Reader {
    fn new(http: &reqwest::Client, base: &str, holder: &Holder, credential: &str, audience: &str) -> Reader {
        let mut headers = reqwest::header::HeaderMap::new();
        for (k, v) in holder.headers(&format!("Atproto-Space {credential}"), Some(audience)) {
            headers.insert(
                reqwest::header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                reqwest::header::HeaderValue::from_str(&v).unwrap(),
            );
        }
        Reader { http: http.clone(), base: base.to_string(), headers }
    }

    async fn get(&self, nsid: &str, query: &[(&str, &str)]) -> (u16, J, Duration) {
        let t = Instant::now();
        let r = self.http.get(xrpc_url(&self.base, nsid, query)).headers(self.headers.clone()).send().await.unwrap();
        let status = r.status().as_u16();
        let body = r.bytes().await.unwrap_or_default();
        (status, serde_json::from_slice(&body).unwrap_or(J::Null), t.elapsed())
    }

    async fn post(&self, nsid: &str, body: &J) -> (u16, J) {
        let r = self
            .http
            .post(xrpc_url(&self.base, nsid, &[]))
            .headers(self.headers.clone())
            .json(body)
            .send()
            .await
            .unwrap();
        let status = r.status().as_u16();
        let body = r.bytes().await.unwrap_or_default();
        (status, serde_json::from_slice(&body).unwrap_or(J::Null))
    }

    async fn list_repo_ops(&self, space: &str, repo: &str, since: Option<&str>, limit: usize) -> (u16, J, Duration) {
        let limit = limit.to_string();
        let mut q = vec![("space", space), ("repo", repo), ("limit", limit.as_str())];
        if let Some(s) = since {
            q.push(("since", s));
        }
        self.get("com.atproto.space.listRepoOps", &q).await
    }
}

fn http() -> reqwest::Client {
    reqwest::Client::builder().pool_max_idle_per_host(256).timeout(Duration::from_secs(60)).build().unwrap()
}

const SPACE_TYPE: &str = "com.example.bench.space";
const COLLECTION: &str = "com.example.bench.note";

fn note(i: usize) -> J {
    json!({"$type": COLLECTION, "text": format!("space note {i}, about as long as a short chat message"), "createdAt": now_iso()})
}

fn authority_scope() -> String {
    format!(
        "space:{SPACE_TYPE}?collection={COLLECTION}&action=read&action=create&action=update&action=delete\
         &manage=create&manage=update&manage=delete"
    )
}

fn member_scope() -> String {
    format!(
        "space:{SPACE_TYPE}?authority=*&collection={COLLECTION}&action=read&action=create&action=update&action=delete"
    )
}

/// One space: its authority (who also writes into it), its members, and a
/// credential the authority holds for reading every member's repo.
struct Fixture {
    authority: SpaceClient,
    members: Vec<SpaceClient>,
    space: String,
    credential: String,
}

impl Fixture {
    async fn new(s: &TestServer, members: usize) -> Fixture {
        Fixture::spread(&[s], members).await
    }

    /// The authority on `nodes[0]`, member i on `nodes[(i + 1) % n]` (an
    /// account lives on the node that created it).
    async fn spread(nodes: &[&TestServer], members: usize) -> Fixture {
        let s = nodes[0];
        let authority = SpaceClient::new(s, &unique_name("sba"), &authority_scope()).await;
        let skey = format!("b{}", unique_name("k").replace(['.', '-', '_'], ""));
        let space = authority.create_space(SPACE_TYPE, &skey).await;
        let mut ms = Vec::new();
        for i in 0..members {
            let m = SpaceClient::new(nodes[(i + 1) % nodes.len()], &unique_name("sbm"), &member_scope()).await;
            authority
                .post(
                    "com.atproto.simplespace.putMember",
                    json!({"space": space, "did": m.did, "read": true, "write": true}),
                )
                .await
                .ok();
            ms.push(m);
        }
        authority.create_record(&space, COLLECTION, None, note(0)).await.ok();
        for m in &ms {
            m.create_record(&space, COLLECTION, None, note(0)).await.ok();
        }
        let credential = authority.credential(&space).await;
        Fixture { authority, members: ms, space, credential }
    }

    fn writers(&self) -> impl Iterator<Item = &SpaceClient> {
        std::iter::once(&self.authority).chain(self.members.iter())
    }

    fn reader(&self, http: &reqwest::Client, repo: &str) -> Reader {
        Reader::new(http, &self.authority.srv.base, &self.authority.holder, &self.credential, repo)
    }

    async fn head_rev(&self, http: &reqwest::Client, repo: &str) -> String {
        let (st, j, _) = self
            .reader(http, repo)
            .get("com.atproto.space.getLatestCommit", &[("space", &self.space), ("repo", repo)])
            .await;
        assert_eq!(st, 200, "getLatestCommit: {j}");
        j["commit"]["rev"].as_str().unwrap().to_string()
    }
}

// ---------------------------------------------------------------- sections

struct Report(Vec<String>);

impl Report {
    fn say(&mut self, line: String) {
        println!("spaces-bench: {line}");
        self.0.push(line);
    }
}

/// Process CPU per request of `n` sequential calls of `f`, and their latency.
async fn cpu_loop<F, Fut>(n: usize, mut f: F) -> (f64, Lat)
where
    F: FnMut(usize) -> Fut,
    Fut: std::future::Future<Output = Duration>,
{
    let mut lat = Lat::default();
    let c0 = process_cpu();
    for i in 0..n {
        lat.push(f(i).await);
    }
    ((process_cpu() - c0) / n as f64 * 1e6, lat)
}

async fn bench_noop(s: &TestServer, fx: &Fixture, cfg: &Cfg, out: &mut Report) {
    let http = http();
    let repo = fx.authority.did.clone();
    let rd = fx.reader(&http, &repo);
    let head = fx.head_rev(&http, &repo).await;
    let health = format!("{}/xrpc/_health", s.url);
    for _ in 0..200 {
        let (st, j, _) = rd.list_repo_ops(&fx.space, &repo, Some(&head), 100).await;
        assert_eq!(st, 200, "{j}");
        assert_eq!(j["ops"].as_array().map(Vec::len), Some(0), "at the head: {j}");
        assert!(j["commit"]["sig"].is_string() || j["commit"]["sig"].is_object(), "a signed commit: {j}");
        http.get(&health).send().await.unwrap();
    }
    let n = cfg.noop_reqs;
    let (base_cpu, base_lat) = cpu_loop(n, |_| {
        let (http, health) = (http.clone(), health.clone());
        async move {
            let t = Instant::now();
            http.get(&health).send().await.unwrap().bytes().await.unwrap();
            t.elapsed()
        }
    })
    .await;
    let before = vlpds::metrics::render();
    let (cpu, lat) = cpu_loop(n, |_| {
        let (rd, space, repo, head) = (rd.clone(), fx.space.clone(), repo.clone(), head.clone());
        async move { rd.list_repo_ops(&space, &repo, Some(&head), 100).await.2 }
    })
    .await;
    let h =
        HistDelta::new(&before, &vlpds::metrics::render(), "vlpds_space_list_repo_ops_seconds", &[("path", "noop")]);
    out.say(format!("noop listRepoOps client: {}", lat.line()));
    out.say(format!("noop listRepoOps server: {}", h.line()));
    out.say(format!(
        "noop listRepoOps CPU: {cpu:.1} us/req process, {base_cpu:.1} us/req for _health on the same client ({}), \
         so ~{:.1} us/req above a trivial request",
        base_lat.line(),
        cpu - base_cpu
    ));
    // cold key: the author's signing key out of every cache before each poll
    let (_, cold) = cpu_loop(n.min(200), |_| {
        let (rd, space, repo, head, app) = (rd.clone(), fx.space.clone(), repo.clone(), head.clone(), s.app.clone());
        async move {
            app.forget_signing_key(&repo);
            rd.list_repo_ops(&space, &repo, Some(&head), 100).await.2
        }
    })
    .await;
    out.say(format!("noop listRepoOps client, cold signing key: {}", cold.line()));
}

async fn bench_delta(fx: &Fixture, cfg: &Cfg, out: &mut Report) {
    let http = http();
    let repo = fx.authority.did.clone();
    let rd = fx.reader(&http, &repo);
    for &k in &cfg.deltas {
        let since = fx.head_rev(&http, &repo).await;
        let mut left = k;
        while left > 0 {
            let n = left.min(200);
            let writes: Vec<J> = (0..n)
                .map(|i| json!({"$type": "com.atproto.space.applyWrites#create", "collection": COLLECTION, "value": note(i)}))
                .collect();
            fx.authority.apply_writes(&fx.space, json!(writes)).await.ok();
            left -= n;
        }
        let limit = (k + 1).min(1000);
        let (st, j, _) = rd.list_repo_ops(&fx.space, &repo, Some(&since), limit).await;
        assert_eq!(st, 200, "{j}");
        assert_eq!(j["ops"].as_array().map(Vec::len), Some(k.min(limit)), "K={k}: {j}");
        let before = vlpds::metrics::render();
        let (cpu, lat) = cpu_loop(cfg.delta_reqs, |_| {
            let (rd, space, repo, since) = (rd.clone(), fx.space.clone(), repo.clone(), since.clone());
            async move { rd.list_repo_ops(&space, &repo, Some(&since), limit).await.2 }
        })
        .await;
        let h = HistDelta::new(
            &before,
            &vlpds::metrics::render(),
            "vlpds_space_list_repo_ops_seconds",
            &[("path", "scan")],
        );
        out.say(format!("delta K={k}: client {}; server {}; {cpu:.1} us CPU/req (process)", lat.line(), h.line()));
    }
}

async fn bench_cred(fx: &Fixture, cfg: &Cfg, out: &mut Report) {
    let http = http();
    let repo = fx.authority.did.clone();
    let head = fx.head_rev(&http, &repo).await;
    let creds: Vec<String> = {
        let mut v = Vec::new();
        for _ in 0..cfg.creds {
            v.push(fx.authority.credential(&fx.space).await);
        }
        v
    };
    let readers: Vec<Reader> =
        creds.iter().map(|c| Reader::new(&http, &fx.authority.srv.base, &fx.authority.holder, c, &repo)).collect();
    let hot = fx.reader(&http, &repo);
    for _ in 0..50 {
        hot.list_repo_ops(&fx.space, &repo, Some(&head), 100).await;
    }
    let cache = |t: &str, r: &str| sum(t, "vlpds_space_credential_cache_total", &[("result", r)]);
    let m0 = vlpds::metrics::render();
    let (miss_cpu, miss) = cpu_loop(readers.len(), |i| {
        let (rd, space, repo, head) = (readers[i].clone(), fx.space.clone(), repo.clone(), head.clone());
        async move {
            let (st, j, d) = rd.list_repo_ops(&space, &repo, Some(&head), 100).await;
            assert_eq!(st, 200, "{j}");
            d
        }
    })
    .await;
    let m1 = vlpds::metrics::render();
    let (hit_cpu, hit) = cpu_loop(readers.len().max(1000), |_| {
        let (rd, space, repo, head) = (hot.clone(), fx.space.clone(), repo.clone(), head.clone());
        async move { rd.list_repo_ops(&space, &repo, Some(&head), 100).await.2 }
    })
    .await;
    let m2 = vlpds::metrics::render();
    out.say(format!("credential first use (miss): {}; {miss_cpu:.1} us CPU/req", miss.line()));
    out.say(format!("credential reused (hit): {}; {hit_cpu:.1} us CPU/req", hit.line()));
    out.say(format!(
        "credential cache counter over those: miss phase hit+{} miss+{}, hit phase hit+{} miss+{} (all 0: no cache before C2)",
        cache(&m1, "hit") - cache(&m0, "hit"),
        cache(&m1, "miss") - cache(&m0, "miss"),
        cache(&m2, "hit") - cache(&m1, "hit"),
        cache(&m2, "miss") - cache(&m1, "miss"),
    ));
}

/// Public writers posting back to back until `stop`; each commit's latency.
fn public_load(s: &TestServer, accts: &[TestAccount], stop: &Arc<AtomicBool>) -> Vec<tokio::task::JoinHandle<Lat>> {
    accts
        .iter()
        .map(|a| {
            let (xrpc, a, stop) = (s.xrpc.clone(), a.clone(), stop.clone());
            tokio::spawn(async move {
                let mut lat = Lat::default();
                let mut i = 0;
                while !stop.load(Ordering::Relaxed) {
                    let t = Instant::now();
                    let r = xrpc
                        .post(
                            "com.atproto.repo.createRecord",
                            &json!({"repo": a.did, "collection": "app.bsky.feed.post", "record": post_record(&format!("public {i}"))}),
                            &a.auth(),
                        )
                        .await;
                    assert_eq!(r.status, 200, "{}", r.text());
                    lat.push(t.elapsed());
                    i += 1;
                }
                lat
            })
        })
        .collect()
}

async fn join_lat(hs: Vec<tokio::task::JoinHandle<Lat>>) -> Lat {
    let mut all = Lat::default();
    for h in hs {
        all.0.extend(h.await.unwrap().0);
    }
    all
}

/// Space writers: each of `writers` creates a record every `every`
/// (jittered) until `stop`. Counts acked writes; notes when each repo last
/// sent one, for the syncers' notify latency.
fn space_writes(
    fixtures: &Arc<Vec<Fixture>>,
    every: Duration,
    stop: &Arc<AtomicBool>,
    sent: &Arc<Mutex<HashMap<String, Instant>>>,
    acked: &Arc<AtomicU64>,
) -> Vec<tokio::task::JoinHandle<()>> {
    let mut hs = Vec::new();
    for (fi, f) in fixtures.iter().enumerate() {
        for wi in 0..=f.members.len() {
            let (fixtures, stop, sent, acked) = (fixtures.clone(), stop.clone(), sent.clone(), acked.clone());
            hs.push(tokio::spawn(async move {
                let fx = &fixtures[fi];
                let w = fx.writers().nth(wi).unwrap();
                let mut i = 1;
                tokio::time::sleep(every.mul_f64(rand::random::<f64>())).await;
                while !stop.load(Ordering::Relaxed) {
                    sent.lock().insert(w.did.clone(), Instant::now());
                    let r = w.create_record(&fx.space, COLLECTION, None, note(i)).await;
                    assert_eq!(r.status, 200, "space write: {}", r.text());
                    acked.fetch_add(1, Ordering::Relaxed);
                    i += 1;
                    tokio::time::sleep(every.mul_f64(0.5 + rand::random::<f64>())).await;
                }
            }));
        }
    }
    hs
}

/// Pollers: K per space, each polling every repo of its space every
/// `every` from the rev it last saw.
fn pollers(
    fixtures: &Arc<Vec<Fixture>>,
    k: usize,
    every: Duration,
    stop: &Arc<AtomicBool>,
) -> Vec<tokio::task::JoinHandle<(Lat, Lat)>> {
    let http = http();
    let mut hs = Vec::new();
    for fi in 0..fixtures.len() {
        for _ in 0..k {
            let (fixtures, stop, http) = (fixtures.clone(), stop.clone(), http.clone());
            hs.push(tokio::spawn(async move {
                let fx = &fixtures[fi];
                let repos: Vec<(String, Reader)> =
                    fx.writers().map(|w| (w.did.clone(), fx.reader(&http, &w.did))).collect();
                let mut seen: HashMap<String, String> = HashMap::new();
                let (mut noop, mut delta) = (Lat::default(), Lat::default());
                tokio::time::sleep(every.mul_f64(rand::random::<f64>())).await;
                while !stop.load(Ordering::Relaxed) {
                    for (repo, rd) in &repos {
                        let since = seen.get(repo).cloned();
                        let (st, j, d) = rd.list_repo_ops(&fx.space, repo, since.as_deref(), 1000).await;
                        assert_eq!(st, 200, "poll: {j}");
                        let ops = j["ops"].as_array().map_or(0, Vec::len);
                        if ops == 0 {
                            noop.push(d)
                        } else {
                            delta.push(d)
                        }
                        if let Some(rev) = j["commit"]["rev"].as_str() {
                            seen.insert(repo.clone(), rev.to_string());
                        }
                    }
                    tokio::time::sleep(every).await;
                }
                (noop, delta)
            }));
        }
    }
    hs
}

/// A syncer on loopback (did:web): its notifyWrite handler hands each
/// notify to a puller that fetches the repo's ops since the rev it last
/// pulled, with the space authority's credential.
struct Syncer {
    did: String,
    notified: Arc<Mutex<Lat>>,
    pulled: Arc<Mutex<Lat>>,
    notifies: Arc<AtomicU64>,
}

impl Syncer {
    async fn spawn(fixtures: Arc<Vec<Fixture>>, sent: Arc<Mutex<HashMap<String, Instant>>>) -> Syncer {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let (did, base) = (format!("did:web:127.0.0.1%3A{}", addr.port()), format!("http://{addr}"));
        let key = vlsync_atproto::crypto::Keypair::generate();
        let doc = json!({
            "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"],
            "id": did,
            "verificationMethod": [{
                "id": format!("{did}#atproto"),
                "type": "Multikey",
                "controller": did,
                "publicKeyMultibase": key.did_key().strip_prefix("did:key:").unwrap(),
            }],
            "service": [{"id": "#atproto_space_syncer", "type": "AtprotoSpaceSyncer", "serviceEndpoint": base}],
        });
        let (notified, pulled, notifies) =
            (Arc::new(Mutex::new(Lat::default())), Arc::new(Mutex::new(Lat::default())), Arc::new(AtomicU64::new(0)));
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<(String, String, Instant)>();
        let (n2, c2) = (notified.clone(), notifies.clone());
        let router = axum::Router::new()
            .route("/.well-known/did.json", axum::routing::get(move || std::future::ready(axum::Json(doc.clone()))))
            .route(
                "/xrpc/com.atproto.space.notifyWrite",
                axum::routing::post(move |axum::Json(body): axum::Json<J>| {
                    let (tx, sent, n2, c2) = (tx.clone(), sent.clone(), n2.clone(), c2.clone());
                    async move {
                        let now = Instant::now();
                        c2.fetch_add(1, Ordering::Relaxed);
                        let repo = body["repo"].as_str().unwrap_or_default().to_string();
                        if let Some(t) = sent.lock().get(&repo) {
                            n2.lock().push(now.duration_since(*t));
                        }
                        let _ = tx.send((body["space"].as_str().unwrap_or_default().to_string(), repo, now));
                        axum::Json(json!({}))
                    }
                }),
            );
        tokio::spawn(async move { axum::serve(l, router).await.unwrap() });
        let p2 = pulled.clone();
        tokio::spawn(async move {
            let http = http();
            let mut seen: HashMap<(String, String), String> = HashMap::new();
            while let Some((space, repo, at)) = rx.recv().await {
                let Some(fx) = fixtures.iter().find(|f| f.space == space) else { continue };
                let key = (space.clone(), repo.clone());
                let (st, j, _) = fx
                    .reader(&http, &repo)
                    .list_repo_ops(&space, &repo, seen.get(&key).map(String::as_str), 1000)
                    .await;
                if st == 200 {
                    p2.lock().push(at.elapsed());
                    if let Some(rev) = j["commit"]["rev"].as_str() {
                        seen.insert(key, rev.to_string());
                    }
                }
            }
        });
        Syncer { did, notified, pulled, notifies }
    }

    async fn register(&self, fx: &Fixture) {
        let http = http();
        let rd = Reader::new(&http, &fx.authority.srv.base, &fx.authority.holder, &fx.credential, &fx.authority.did);
        let (st, j) = rd
            .post(
                "com.atproto.space.registerNotify",
                &json!({"space": fx.space, "service": format!("{}#atproto_space_syncer", self.did)}),
            )
            .await;
        assert_eq!(st, 200, "registerNotify: {j}");
    }
}

/// Object-store requests by (op, component) between two scrapes.
fn bucket_ops(before: &str, after: &str) -> BTreeMap<(String, String), f64> {
    let tally = |t: &str| {
        let mut m: BTreeMap<(String, String), f64> = BTreeMap::new();
        for (l, v) in series(t, "vlpds_object_store_requests_total") {
            *m.entry((l.get("op").cloned().unwrap_or_default(), l.get("component").cloned().unwrap_or_default()))
                .or_default() += v;
        }
        m
    };
    let (a, b) = (tally(before), tally(after));
    b.into_iter().map(|(k, v)| (k.clone(), v - a.get(&k).copied().unwrap_or(0.0))).filter(|(_, v)| *v > 0.0).collect()
}

fn puts(ops: &BTreeMap<(String, String), f64>) -> f64 {
    ops.iter().filter(|((op, _), _)| op.starts_with("put") || op.starts_with("mpu")).map(|(_, v)| v).sum()
}

async fn bench_bucket(
    s: &TestServer,
    fixtures: &Arc<Vec<Fixture>>,
    publics: &[TestAccount],
    cfg: &Cfg,
    out: &mut Report,
) {
    let window = Duration::from_secs_f64(cfg.secs);
    let stop = Arc::new(AtomicBool::new(false));
    let load = public_load(s, publics, &stop);
    tokio::time::sleep(Duration::from_millis(500)).await;

    let m0 = vlpds::metrics::render();
    let t0 = Instant::now();
    tokio::time::sleep(window).await;
    let (m1, w1) = (vlpds::metrics::render(), t0.elapsed().as_secs_f64());
    let commits1 = sum(&m1, "vlpds_commits_total", &[]) - sum(&m0, "vlpds_commits_total", &[]);

    let (sstop, sent, acked) = (Arc::new(AtomicBool::new(false)), Arc::default(), Arc::new(AtomicU64::new(0)));
    let writers = space_writes(fixtures, cfg.space_write_every, &sstop, &sent, &acked);
    tokio::time::sleep(Duration::from_millis(500)).await;
    let (m2, a2) = (vlpds::metrics::render(), acked.load(Ordering::Relaxed));
    let t2 = Instant::now();
    tokio::time::sleep(window).await;
    let (m3, w2, a3) = (vlpds::metrics::render(), t2.elapsed().as_secs_f64(), acked.load(Ordering::Relaxed));
    sstop.store(true, Ordering::Relaxed);
    for h in writers {
        h.await.unwrap();
    }
    stop.store(true, Ordering::Relaxed);
    join_lat(load).await;

    let (alone, with) = (bucket_ops(&m0, &m1), bucket_ops(&m2, &m3));
    let commits2 = sum(&m3, "vlpds_commits_total", &[]) - sum(&m2, "vlpds_commits_total", &[]);
    let space_writes = (a3 - a2) as f64;
    out.say(format!(
        "bucket: public alone {:.1} commits/s, {:.2} PUT/s; with space writes {:.1} commits/s + {:.1} space writes/s, {:.2} PUT/s",
        commits1 / w1,
        puts(&alone) / w1,
        commits2 / w2,
        space_writes / w2,
        puts(&with) / w2
    ));
    out.say(format!(
        "bucket: added PUTs per space write ~{:.4} (PUT/s difference over space writes/s; target 0)",
        (puts(&with) / w2 - puts(&alone) / w1) / (space_writes / w2).max(1e-9)
    ));
    // the rate difference moves with the public commit rate; PUTs per write
    // of either kind doesn't, and drops when space writes share segments
    out.say(format!(
        "bucket: PUTs per write {:.3} alone, {:.3} with space writes (public + space)",
        puts(&alone) / commits1.max(1.0),
        puts(&with) / (commits2 + space_writes).max(1.0)
    ));
    let keys: std::collections::BTreeSet<_> = alone.keys().chain(with.keys()).cloned().collect();
    for k in keys {
        out.say(format!(
            "bucket:   {:>12} {:<18} {:>8.2}/s alone {:>8.2}/s with spaces",
            k.0,
            k.1,
            alone.get(&k).copied().unwrap_or(0.0) / w1,
            with.get(&k).copied().unwrap_or(0.0) / w2
        ));
    }
}

/// `c` writers on one account back to back for `window`: each write's
/// latency and the log segment PUTs over the window.
async fn one_repo<F, Fut>(c: usize, window: Duration, f: F) -> (Lat, f64)
where
    F: Fn(usize) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let seg = |t: &str| sum(t, "vlpds_object_store_requests_total", &[("component", "log_segment")]);
    let m0 = vlpds::metrics::render();
    let end = Instant::now() + window;
    let lats = futures::future::join_all((0..c).map(|w| {
        let f = &f;
        async move {
            let mut lat = Lat::default();
            let mut i = 0;
            while Instant::now() < end {
                let t = Instant::now();
                f(w * 1_000_000 + i).await;
                lat.push(t.elapsed());
                i += 1;
            }
            lat
        }
    }))
    .await;
    let mut all = Lat::default();
    for l in lats {
        all.0.extend(l.0);
    }
    (all, seg(&vlpds::metrics::render()) - seg(&m0))
}

/// Concurrent writes to one repo, public and then space: a space write
/// should share segments with the others in flight as a public one does.
async fn bench_conc(s: &TestServer, fx: &Fixture, cfg: &Cfg, out: &mut Report) {
    let window = Duration::from_secs_f64(cfg.secs / 2.0);
    let a = s.create_account("sbc").await;
    let oc = SpaceClient::new(s, "sbo", "repo:app.bsky.feed.post?action=create").await;
    for &c in &cfg.conc {
        let (publat, pubsegs) = one_repo(c, window, |i| {
            let (xrpc, a) = (&s.xrpc, &a);
            async move {
                let body =
                    json!({"repo": a.did, "collection": "app.bsky.feed.post", "record": post_record(&format!("conc {i}"))});
                let r = xrpc.post("com.atproto.repo.createRecord", &body, &a.auth()).await;
                assert_eq!(r.status, 200, "{}", r.text());
            }
        })
        .await;
        // space writes are OAuth-only: the like-for-like public write
        let (olat, osegs) = one_repo(c, window, |i| {
            let oc = &oc;
            async move {
                let rec = post_record(&format!("conc {i}"));
                let body = json!({"repo": oc.did, "collection": "app.bsky.feed.post", "record": rec});
                let r = oc.post("com.atproto.repo.createRecord", body).await;
                assert_eq!(r.status, 200, "{}", r.json);
            }
        })
        .await;
        let (splat, spsegs) = one_repo(c, window, |i| async move {
            let r = fx.authority.create_record(&fx.space, COLLECTION, None, note(i)).await;
            assert_eq!(r.status, 200, "space write: {}", r.text());
        })
        .await;
        let n = |l: &Lat| l.0.len().max(1) as f64;
        out.say(format!(
            "one repo, {c} concurrent: public {:.3} PUTs/write, {}; public over OAuth {:.3} PUTs/write, {}; space {:.3} PUTs/write, {}",
            pubsegs / n(&publat),
            publat.line(),
            osegs / n(&olat),
            olat.line(),
            spsegs / n(&splat),
            splat.line()
        ));
    }
}

async fn bench_load(
    s: &TestServer,
    fixtures: &Arc<Vec<Fixture>>,
    publics: &[TestAccount],
    cfg: &Cfg,
    out: &mut Report,
) {
    let window = Duration::from_secs_f64(cfg.secs);
    let stop = Arc::new(AtomicBool::new(false));
    let load = public_load(s, publics, &stop);
    tokio::time::sleep(window).await;
    stop.store(true, Ordering::Relaxed);
    let alone = join_lat(load).await;

    let sent: Arc<Mutex<HashMap<String, Instant>>> = Arc::default();
    let mut syncers = Vec::new();
    for _ in 0..cfg.syncers {
        let sy = Syncer::spawn(fixtures.clone(), sent.clone()).await;
        for fx in fixtures.iter() {
            sy.register(fx).await;
        }
        syncers.push(sy);
    }
    let (sstop, acked) = (Arc::new(AtomicBool::new(false)), Arc::new(AtomicU64::new(0)));
    let writers = space_writes(fixtures, cfg.space_write_every, &sstop, &sent, &acked);
    let polls = pollers(fixtures, cfg.pollers, cfg.poll_every, &sstop);
    tokio::time::sleep(Duration::from_millis(500)).await;
    let m0 = vlpds::metrics::render();
    let stop = Arc::new(AtomicBool::new(false));
    let load = public_load(s, publics, &stop);
    tokio::time::sleep(window).await;
    stop.store(true, Ordering::Relaxed);
    let with = join_lat(load).await;
    let m1 = vlpds::metrics::render();
    sstop.store(true, Ordering::Relaxed);
    for h in writers {
        h.await.unwrap();
    }
    let (mut noop, mut delta) = (Lat::default(), Lat::default());
    for h in polls {
        let (n, d) = h.await.unwrap();
        noop.0.extend(n.0);
        delta.0.extend(d.0);
    }

    let members = fixtures.first().map_or(0, |f| f.members.len());
    out.say(format!(
        "load: {} spaces x {members} members x {} pollers (every {:?}), {} syncers/space, a space write every ~{:?} per writer",
        fixtures.len(),
        cfg.pollers,
        cfg.poll_every,
        cfg.syncers,
        cfg.space_write_every
    ));
    out.say(format!("load: public commits alone: {}", alone.line()));
    out.say(format!("load: public commits with spaces load: {}", with.line()));
    out.say(format!(
        "load: space writes acked {}, polls noop {}, polls delta {}",
        acked.load(Ordering::Relaxed),
        noop.line(),
        delta.line()
    ));
    let ack = HistDelta::new(&m0, &m1, "vlpds_space_notify_ack_seconds", &[]);
    out.say(format!("load: write ack -> authority notify ack: {}", ack.line()));
    for (i, sy) in syncers.iter().enumerate() {
        out.say(format!(
            "load: syncer {i}: {} notifies; write sent -> notified {}; notified -> pulled {}",
            sy.notifies.load(Ordering::Relaxed),
            sy.notified.lock().line(),
            sy.pulled.lock().line()
        ));
    }
    for (k, v) in notify_counts(&m0, &m1) {
        out.say(format!("load: notify {k}: +{v}"));
    }
}

async fn bench_cluster(cfg: &Cfg, out: &mut Report) {
    let (bucket, plc) = (Arc::new(object_store::memory::InMemory::new()), Plc::start().await);
    let put_ms = cfg.put_ms;
    let mut nodes = Vec::new();
    for i in 0..3 {
        let n = cluster_node(&format!("sbc-{i}"), bucket.clone(), 6, |c| {
            plc.apply(c);
            c.spaces = true;
            c.inject_latency = (put_ms > 0.0).then_some((put_ms, 0.3));
        })
        .await;
        nodes.push(n);
    }
    let refs: Vec<&TestServer> = nodes.iter().collect();
    balanced(&refs).await;
    let mut fixtures = Vec::new();
    for _ in 0..cfg.spaces {
        fixtures.push(Fixture::spread(&refs, cfg.members.max(2)).await);
    }
    let fixtures = Arc::new(fixtures);
    let sent: Arc<Mutex<HashMap<String, Instant>>> = Arc::default();
    let mut syncers = Vec::new();
    for _ in 0..cfg.syncers.max(1) {
        let sy = Syncer::spawn(fixtures.clone(), sent.clone()).await;
        for fx in fixtures.iter() {
            sy.register(fx).await;
        }
        syncers.push(sy);
    }
    let (stop, acked) = (Arc::new(AtomicBool::new(false)), Arc::new(AtomicU64::new(0)));
    let writers = space_writes(&fixtures, cfg.space_write_every, &stop, &sent, &acked);
    tokio::time::sleep(Duration::from_millis(500)).await;
    let (m0, a0) = (vlpds::metrics::render(), acked.load(Ordering::Relaxed));
    tokio::time::sleep(Duration::from_secs_f64(cfg.secs)).await;
    let (m1, a1) = (vlpds::metrics::render(), acked.load(Ordering::Relaxed));
    stop.store(true, Ordering::Relaxed);
    for h in writers {
        h.await.unwrap();
    }
    // the last writes' notifies and pulls land
    tokio::time::sleep(Duration::from_millis(500)).await;

    let members = fixtures.first().map_or(0, |f| f.members.len());
    out.say(format!(
        "cluster: 3 nodes, {} spaces x {members} members (authority on one node, members on the others), {} syncers/space, {} space writes in the window",
        fixtures.len(),
        syncers.len(),
        a1 - a0
    ));
    let ack = HistDelta::new(&m0, &m1, "vlpds_space_notify_ack_seconds", &[]);
    out.say(format!("cluster: write ack -> authority notify ack: {}", ack.line()));
    for (i, sy) in syncers.iter().enumerate() {
        out.say(format!(
            "cluster: syncer {i}: {} notifies; write sent -> notified {}; notified -> pulled {}",
            sy.notifies.load(Ordering::Relaxed),
            sy.notified.lock().line(),
            sy.pulled.lock().line()
        ));
    }
    for (k, v) in notify_counts(&m0, &m1) {
        out.say(format!("cluster: notify {k}: +{v}"));
    }
}

/// `vlpds_space_notify_total` by hop/result between two scrapes.
fn notify_counts(before: &str, after: &str) -> BTreeMap<String, f64> {
    let tally = |t: &str| {
        let mut m: BTreeMap<String, f64> = BTreeMap::new();
        for (l, v) in series(t, "vlpds_space_notify_total") {
            *m.entry(format!("{}/{}", l.get("hop").map_or("", |s| s), l.get("result").map_or("", |s| s)))
                .or_default() += v;
        }
        m
    };
    let (b, a) = (tally(before), tally(after));
    a.into_iter().map(|(k, v)| (k.clone(), v - b.get(&k).copied().unwrap_or(0.0))).collect()
}

async fn run(cfg: Cfg) -> Report {
    let mut out = Report(Vec::new());
    let put_ms = cfg.put_ms;
    let s = TestServer::spawn_with(move |c| {
        c.spaces = true;
        c.inject_latency = (put_ms > 0.0).then_some((put_ms, 0.3));
    })
    .await;
    let fx = Fixture::new(&s, 0).await;
    if cfg.on("noop") {
        bench_noop(&s, &fx, &cfg, &mut out).await;
    }
    if cfg.on("delta") {
        bench_delta(&fx, &cfg, &mut out).await;
    }
    if cfg.on("cred") {
        bench_cred(&fx, &cfg, &mut out).await;
    }
    if cfg.on("conc") {
        bench_conc(&s, &fx, &cfg, &mut out).await;
    }
    if cfg.on("bucket") || cfg.on("load") {
        let mut fixtures = Vec::new();
        for _ in 0..cfg.spaces {
            fixtures.push(Fixture::new(&s, cfg.members).await);
        }
        let fixtures = Arc::new(fixtures);
        let mut publics = Vec::new();
        for _ in 0..cfg.public_writers {
            publics.push(s.create_account("sbp").await);
        }
        if cfg.on("bucket") {
            bench_bucket(&s, &fixtures, &publics, &cfg, &mut out).await;
        }
        if cfg.on("load") {
            bench_load(&s, &fixtures, &publics, &cfg, &mut out).await;
        }
    }
    if cfg.on("cluster") {
        bench_cluster(&cfg, &mut out).await;
    }
    out
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "bench: run by hand, alone (see the module docs)"]
async fn spaces_microbench() {
    let out = run(Cfg::from_env()).await;
    println!("\n{}", out.0.join("\n"));
}

/// Every section at a tiny size: the harness runs end to end against the
/// space surface.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn spaces_microbench_smoke() {
    let out = run(Cfg::tiny()).await;
    for want in [
        "noop listRepoOps client",
        "delta K=5",
        "credential reused (hit)",
        "added PUTs per space write",
        "one repo, 2 concurrent",
        "with spaces load",
    ] {
        assert!(out.0.iter().any(|l| l.contains(want)), "no {want:?} in:\n{}", out.0.join("\n"));
    }
}

/// The cluster section at a tiny size: notifies cross nodes and reach the
/// syncer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn spaces_microbench_cluster_smoke() {
    let out = run(Cfg { sections: vec!["cluster".into()], ..Cfg::tiny() }).await;
    let text = out.0.join("\n");
    let line =
        |want: &str| out.0.iter().find(|l| l.contains(want)).unwrap_or_else(|| panic!("no {want:?} in:\n{text}"));
    assert!(!line("write ack -> authority notify ack").contains("n=0 "), "no notify acked:\n{text}");
    assert!(!line("syncer 0:").contains(" 0 notifies"), "the syncer heard nothing:\n{text}");
}

#[test]
fn exposition_and_histogram_math() {
    let a = "# HELP x y\nvlpds_t_total{op=\"put\",component=\"log_segment\"} 3\nvlpds_t_total{op=\"get\",component=\"state_sst\"} 5\n\
             vlpds_h_seconds_bucket{path=\"noop\",le=\"0.001\"} 10\nvlpds_h_seconds_bucket{path=\"noop\",le=\"0.002\"} 10\n\
             vlpds_h_seconds_bucket{path=\"noop\",le=\"+Inf\"} 10\nvlpds_h_seconds_sum{path=\"noop\"} 0.005\nvlpds_h_seconds_count{path=\"noop\"} 10\n";
    let b = "vlpds_t_total{op=\"put\",component=\"log_segment\"} 7\nvlpds_t_total{op=\"get\",component=\"state_sst\"} 5\n\
             vlpds_t_total{op=\"put_cas\",component=\"ctl_lease\"} 1\nvlpds_t_totalx 9\n\
             vlpds_h_seconds_bucket{path=\"noop\",le=\"0.001\"} 60\nvlpds_h_seconds_bucket{path=\"noop\",le=\"0.002\"} 110\n\
             vlpds_h_seconds_bucket{path=\"noop\",le=\"+Inf\"} 110\nvlpds_h_seconds_sum{path=\"noop\"} 0.105\nvlpds_h_seconds_count{path=\"noop\"} 110\n";
    assert_eq!(sum(b, "vlpds_t_total", &[]), 13.0);
    assert_eq!(sum(b, "vlpds_t_total", &[("op", "put")]), 7.0);
    let s = series("x{a=\"q\\\"uote\",b=\"2\"} 1.5", "x");
    assert_eq!((s[0].0["a"].as_str(), s[0].0["b"].as_str(), s[0].1), ("q\\\"uote", "2", 1.5));

    let ops =
        |t: &str| series(t, "vlpds_t_total").into_iter().map(|(l, v)| ((l["op"].clone(), l["component"].clone()), v));
    let mut before = String::new();
    for ((op, c), v) in ops(a) {
        before += &format!("vlpds_object_store_requests_total{{op=\"{op}\",component=\"{c}\"}} {v}\n");
    }
    let mut after = String::new();
    for ((op, c), v) in ops(b) {
        after += &format!("vlpds_object_store_requests_total{{op=\"{op}\",component=\"{c}\"}} {v}\n");
    }
    let d = bucket_ops(&before, &after);
    assert_eq!(d.len(), 2, "{d:?}");
    assert_eq!(puts(&d), 5.0);

    let h = HistDelta::new(a, b, "vlpds_h_seconds", &[("path", "noop")]);
    assert_eq!(h.count, 100.0);
    assert!((h.mean_ms() - 1.0).abs() < 1e-9);
    assert!((h.q_ms(0.5) - 1.0).abs() < 1e-9, "{}", h.q_ms(0.5));
    assert!((h.q_ms(0.99) - 1.98).abs() < 1e-9, "{}", h.q_ms(0.99));

    let mut l = Lat::default();
    for ms in 1..=100 {
        l.push(Duration::from_millis(ms));
    }
    for (q, ms) in [(0.5, 50.0), (0.99, 99.0), (1.0, 100.0)] {
        assert!((l.q(q) - ms).abs() < 1e-9, "q{q}: {}", l.q(q));
    }
}
