//! A node's key rates and latencies for the operator console
//! (`vlpds.admin.getNodeMetrics`). A sampler reads a dozen counters and three
//! histograms every [`EVERY`] and keeps [`KEPT`] samples in memory, so the
//! console gets each node's last few minutes in one call instead of scraping
//! `/metrics` on every node.

use crate::metrics;
use parking_lot::Mutex;
use prometheus::core::Collector;
use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::LazyLock;
use std::time::Duration;

pub const EVERY: Duration = Duration::from_secs(2);
/// Three minutes of 2 s intervals, plus the sample they start from.
pub const KEPT: usize = 91;

#[derive(Clone, Default)]
struct Sample {
    t_ms: u64,
    commits: u64,
    ops: u64,
    http: u64,
    http_5xx: u64,
    rate_limited: u64,
    firehose_events: u64,
    firehose_bytes: u64,
    repo_loads: u64,
    class_a: u64,
    class_b: u64,
    store_errors: u64,
    /// Class A and B requests by key component (objstats::component).
    store: BTreeMap<String, [u64; 2]>,
    cpu_s: f64,
    rss: i64,
    subscribers: i64,
    cached_repos: i64,
    mail_queue: i64,
    /// Cumulative counts per bucket (the last is the total count).
    commit: Vec<u64>,
    put: Vec<u64>,
    emit: Vec<u64>,
}

static SAMPLES: LazyLock<Mutex<VecDeque<Sample>>> = LazyLock::new(Default::default);
static STARTED: AtomicBool = AtomicBool::new(false);

/// Idempotent; needs a tokio runtime.
pub fn start() {
    if STARTED.swap(true, Ordering::AcqRel) {
        return;
    }
    tokio::spawn(async {
        let mut tick = tokio::time::interval(EVERY);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            let s = sample();
            let mut g = SAMPLES.lock();
            if g.len() >= KEPT {
                g.pop_front();
            }
            g.push_back(s);
        }
    });
}

fn buckets(h: &prometheus::Histogram) -> Vec<u64> {
    let mfs = h.collect();
    let Some(m) = mfs.first().and_then(|mf| mf.get_metric().first()) else { return Vec::new() };
    let h = m.get_histogram();
    let mut v: Vec<u64> = h.get_bucket().iter().map(|b| b.cumulative_count()).collect();
    v.push(h.get_sample_count());
    v
}

fn bounds(h: &prometheus::Histogram) -> Vec<f64> {
    let mfs = h.collect();
    let Some(m) = mfs.first().and_then(|mf| mf.get_metric().first()) else { return Vec::new() };
    m.get_histogram().get_bucket().iter().map(|b| b.upper_bound()).collect()
}

/// Sums a counter vec, split by `pick` on its label values.
fn sum_by<const N: usize>(v: &prometheus::IntCounterVec, pick: impl Fn(&[(&str, &str)]) -> Option<usize>) -> [u64; N] {
    let mut out = [0u64; N];
    for mf in v.collect() {
        for m in mf.get_metric() {
            let labels: Vec<(&str, &str)> = m.get_label().iter().map(|l| (l.name(), l.value())).collect();
            if let Some(i) = pick(&labels).filter(|i| *i < N) {
                out[i] += m.get_counter().get_value() as u64;
            }
        }
    }
    out
}

fn label<'a>(labels: &[(&str, &'a str)], name: &str) -> &'a str {
    labels.iter().find(|(n, _)| *n == name).map_or("", |(_, v)| v)
}

/// R2/S3 billing: reads are class B, deletes are free, the rest is class A.
fn store_class(op: &str) -> Option<usize> {
    match op {
        "get" | "get_range" | "head" => Some(1),
        "delete" | "delete_batch" => None,
        _ => Some(0),
    }
}

fn gauge_sum(v: &prometheus::IntGaugeVec) -> i64 {
    v.collect().iter().flat_map(|f| f.get_metric()).map(|m| m.get_gauge().get_value() as i64).sum()
}

fn sample() -> Sample {
    let s = &*crate::stats::STATS;
    let [http, http_5xx] =
        sum_by::<2>(&metrics::HTTP_REQUESTS, |l| Some(if label(l, "status").starts_with('5') { 1 } else { 0 }));
    let [class_a, class_b, store_errors] = sum_by::<3>(&vlsync_store::metrics::OBJ_REQUESTS, |l| {
        if matches!(label(l, "result"), "timeout" | "error") {
            return Some(2);
        }
        store_class(label(l, "op"))
    });
    let mut store: BTreeMap<String, [u64; 2]> = BTreeMap::new();
    for mf in vlsync_store::metrics::OBJ_REQUESTS.collect() {
        for m in mf.get_metric() {
            let labels: Vec<(&str, &str)> = m.get_label().iter().map(|l| (l.name(), l.value())).collect();
            if matches!(label(&labels, "result"), "timeout" | "error") {
                continue;
            }
            if let Some(i) = store_class(label(&labels, "op")) {
                store.entry(label(&labels, "component").to_string()).or_default()[i] +=
                    m.get_counter().get_value() as u64;
            }
        }
    }
    Sample {
        t_ms: vlatproto::tid::now_micros() / 1000,
        commits: s.commits.load(Ordering::Relaxed),
        ops: s.ops.load(Ordering::Relaxed),
        http: http + http_5xx,
        http_5xx,
        rate_limited: metrics::RATE_LIMITED.get(),
        firehose_events: vlsync_firehose::metrics::FIREHOSE_EVENTS.get(),
        firehose_bytes: vlsync_firehose::metrics::FIREHOSE_SENT_BYTES.get(),
        repo_loads: s.repo_loads.load(Ordering::Relaxed),
        class_a,
        class_b,
        store_errors,
        store,
        cpu_s: vlsync_store::metrics::cpu_seconds().unwrap_or(0.0),
        rss: vlsync_store::metrics::resident_bytes().map_or(0, |b| b as i64),
        subscribers: vlsync_firehose::metrics::FIREHOSE_SUBSCRIBERS.get(),
        cached_repos: gauge_sum(&metrics::CACHED_REPOS),
        mail_queue: crate::mail::MAIL_QUEUE.get(),
        commit: buckets(&metrics::COMMIT_LATENCY),
        put: buckets(&metrics::PUT_DURATION.with_label_values(&["node"])),
        emit: buckets(&vlsync_firehose::metrics::FIREHOSE_EMIT_DELAY),
    }
}

/// Prometheus's histogram_quantile over the counts between two samples, in
/// ms. None without observations.
fn quantile(q: f64, bounds: &[f64], a: &[u64], b: &[u64]) -> Option<f64> {
    if a.len() != b.len() || a.len() != bounds.len() + 1 {
        return None;
    }
    let total = b[bounds.len()].saturating_sub(a[bounds.len()]);
    if total == 0 {
        return None;
    }
    let rank = q * total as f64;
    let (mut prev_bound, mut prev_count) = (0.0, 0u64);
    for (i, ub) in bounds.iter().enumerate() {
        let c = b[i].saturating_sub(a[i]);
        if c as f64 >= rank {
            let in_bucket = c.saturating_sub(prev_count) as f64;
            let frac = if in_bucket > 0.0 { (rank - prev_count as f64) / in_bucket } else { 1.0 };
            return Some((prev_bound + (ub - prev_bound) * frac) * 1000.0);
        }
        (prev_bound, prev_count) = (*ub, c);
    }
    // past the last finite bucket: its bound is the best estimate
    bounds.last().map(|b| b * 1000.0)
}

#[derive(serde::Serialize, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Point {
    /// End of the interval, unix ms.
    pub t: u64,
    pub commits_per_sec: f64,
    pub ops_per_sec: f64,
    pub http_per_sec: f64,
    pub http_5xx_per_sec: f64,
    pub rate_limited_per_sec: f64,
    pub firehose_events_per_sec: f64,
    pub firehose_bytes_per_sec: f64,
    pub repo_loads_per_sec: f64,
    pub class_a_per_sec: f64,
    pub class_b_per_sec: f64,
    pub store_errors_per_sec: f64,
    /// CPU cores busy (1.0 = one core).
    pub cpu_cores: f64,
    pub rss_bytes: i64,
    pub subscribers: i64,
    pub cached_repos: i64,
    pub mail_queue: i64,
    pub commit_p50_ms: Option<f64>,
    pub commit_p99_ms: Option<f64>,
    pub put_p50_ms: Option<f64>,
    pub put_p99_ms: Option<f64>,
    pub emit_p99_ms: Option<f64>,
}

struct Bounds {
    commit: Vec<f64>,
    put: Vec<f64>,
    emit: Vec<f64>,
}

fn point(a: &Sample, b: &Sample, bd: &Bounds) -> Point {
    let secs = (b.t_ms.saturating_sub(a.t_ms) as f64 / 1000.0).max(0.001);
    let rate = |x: u64, y: u64| y.saturating_sub(x) as f64 / secs;
    Point {
        t: b.t_ms,
        commits_per_sec: rate(a.commits, b.commits),
        ops_per_sec: rate(a.ops, b.ops),
        http_per_sec: rate(a.http, b.http),
        http_5xx_per_sec: rate(a.http_5xx, b.http_5xx),
        rate_limited_per_sec: rate(a.rate_limited, b.rate_limited),
        firehose_events_per_sec: rate(a.firehose_events, b.firehose_events),
        firehose_bytes_per_sec: rate(a.firehose_bytes, b.firehose_bytes),
        repo_loads_per_sec: rate(a.repo_loads, b.repo_loads),
        class_a_per_sec: rate(a.class_a, b.class_a),
        class_b_per_sec: rate(a.class_b, b.class_b),
        store_errors_per_sec: rate(a.store_errors, b.store_errors),
        cpu_cores: ((b.cpu_s - a.cpu_s) / secs).max(0.0),
        rss_bytes: b.rss,
        subscribers: b.subscribers,
        cached_repos: b.cached_repos,
        mail_queue: b.mail_queue,
        commit_p50_ms: quantile(0.5, &bd.commit, &a.commit, &b.commit),
        commit_p99_ms: quantile(0.99, &bd.commit, &a.commit, &b.commit),
        put_p50_ms: quantile(0.5, &bd.put, &a.put, &b.put),
        put_p99_ms: quantile(0.99, &bd.put, &a.put, &b.put),
        emit_p99_ms: quantile(0.99, &bd.emit, &a.emit, &b.emit),
    }
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ComponentRate {
    pub component: String,
    pub class_a_per_sec: f64,
    pub class_b_per_sec: f64,
}

/// Class A and B rates by key component between two samples, busiest first.
fn components(a: &Sample, b: &Sample) -> Vec<ComponentRate> {
    let secs = (b.t_ms.saturating_sub(a.t_ms) as f64 / 1000.0).max(0.001);
    let mut out: Vec<ComponentRate> = b
        .store
        .iter()
        .map(|(c, [ca, cb])| {
            let [pa, pb] = a.store.get(c).copied().unwrap_or_default();
            ComponentRate {
                component: c.clone(),
                class_a_per_sec: ca.saturating_sub(pa) as f64 / secs,
                class_b_per_sec: cb.saturating_sub(pb) as f64 / secs,
            }
        })
        .filter(|r| r.class_a_per_sec + r.class_b_per_sec > 0.0)
        .collect();
    out.sort_by(|x, y| (y.class_a_per_sec + y.class_b_per_sec).total_cmp(&(x.class_a_per_sec + x.class_b_per_sec)));
    out
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    /// Oldest first, one per interval ending after `since`.
    pub series: Vec<Point>,
    /// Over the last [`SUMMARY_SAMPLES`] intervals (steadier than one point).
    pub latest: Option<Point>,
    /// Object-store requests by key component over every kept sample (up to
    /// 3 minutes: steadier than `latest` for slow pollers like leases).
    pub store_components: Vec<ComponentRate>,
    pub store_window_ms: u64,
    pub interval_ms: u64,
    pub cpu_limit_cores: f64,
    pub memory_limit_bytes: i64,
    pub started_at: u64,
}

/// Intervals `latest` covers: 10 s.
pub const SUMMARY_SAMPLES: usize = 5;

/// The points ending after `since_ms` (0: all kept). Starts the sampler.
pub fn report(since_ms: u64) -> Report {
    start();
    let bd = Bounds {
        commit: bounds(&metrics::COMMIT_LATENCY),
        put: bounds(&metrics::PUT_DURATION.with_label_values(&["node"])),
        emit: bounds(&vlsync_firehose::metrics::FIREHOSE_EMIT_DELAY),
    };
    let mut samples: Vec<Sample> = SAMPLES.lock().iter().cloned().collect();
    // a fresh sample, so a first call (or one between ticks) is current
    if samples.last().is_none_or(|s| s.t_ms + 250 < vlatproto::tid::now_micros() / 1000) {
        samples.push(sample());
    }
    let series = samples.windows(2).filter(|w| w[1].t_ms > since_ms).map(|w| point(&w[0], &w[1], &bd)).collect();
    let latest = (samples.len() >= 2).then(|| {
        let a = &samples[samples.len().saturating_sub(SUMMARY_SAMPLES + 1)];
        point(a, &samples[samples.len() - 1], &bd)
    });
    let (store_components, store_window_ms) = match (samples.first(), samples.last()) {
        (Some(a), Some(b)) if samples.len() >= 2 => (components(a, b), b.t_ms.saturating_sub(a.t_ms)),
        _ => (Vec::new(), 0),
    };
    vlsync_store::lifecycle::refresh_metrics();
    Report {
        series,
        latest,
        store_components,
        store_window_ms,
        interval_ms: EVERY.as_millis() as u64,
        cpu_limit_cores: std::thread::available_parallelism().map_or(0, |n| n.get()) as f64,
        memory_limit_bytes: metrics::MEMORY_LIMIT.get(),
        started_at: (vlsync_store::metrics::PROCESS_START.get() * 1000.0) as u64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quantiles_interpolate_within_buckets() {
        let bounds = [0.001, 0.002, 0.004];
        let a = [0, 0, 0, 0];
        // 10 in (0, 1 ms], 10 in (1, 2 ms]
        let b = [10, 20, 20, 20];
        assert_eq!(quantile(0.5, &bounds, &a, &b), Some(1.0));
        assert!((quantile(0.75, &bounds, &a, &b).unwrap() - 1.5).abs() < 1e-9);
        assert_eq!(quantile(0.5, &bounds, &b, &b), None, "no observations in between");
        // everything past the last bound
        assert_eq!(quantile(0.99, &bounds, &a, &[0, 0, 0, 5]), Some(4.0));
    }

    #[test]
    fn component_rates_busiest_first() {
        let at = |t_ms: u64, store: &[(&str, [u64; 2])]| Sample {
            t_ms,
            store: store.iter().map(|(c, v)| (c.to_string(), *v)).collect(),
            ..Default::default()
        };
        let a = at(0, &[("ctl_lease", [10, 10]), ("blob", [5, 0])]);
        let b = at(2000, &[("ctl_lease", [14, 12]), ("blob", [5, 0]), ("log_segment", [20, 2])]);
        let r = components(&a, &b);
        let names: Vec<&str> = r.iter().map(|c| c.component.as_str()).collect();
        assert_eq!(names, ["log_segment", "ctl_lease"], "idle components are left out");
        assert_eq!((r[0].class_a_per_sec, r[0].class_b_per_sec), (10.0, 1.0), "new since `a`: counted from 0");
        assert_eq!((r[1].class_a_per_sec, r[1].class_b_per_sec), (2.0, 1.0));
    }

    #[test]
    fn store_ops_bill_like_r2() {
        assert_eq!(store_class("get_range"), Some(1));
        assert_eq!(store_class("put_cas"), Some(0));
        assert_eq!(store_class("list"), Some(0));
        assert_eq!(store_class("delete_batch"), None);
    }
}
