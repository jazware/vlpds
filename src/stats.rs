//! Process-wide counters and latency histograms, logged periodically and
//! exposed at /metrics.

use hdrhistogram::Histogram;
use parking_lot::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::LazyLock;
use std::time::Duration;

pub struct Stats {
    pub commits: AtomicU64,
    pub ops: AtomicU64,
    pub write_requests: AtomicU64,
    pub write_errors: AtomicU64,
    pub entries_durable: AtomicU64,
    pub segments: AtomicU64,
    pub segment_bytes: AtomicU64,
    pub repo_loads: AtomicU64,
    pub hedges: AtomicU64,
    pub put_us: Mutex<Histogram<u64>>,
    pub commit_us: Mutex<Histogram<u64>>,
    pub request_us: Mutex<Histogram<u64>>,
    pub apply_us: Mutex<Histogram<u64>>,
    pub load_us: Mutex<Histogram<u64>>,
}

pub static STATS: LazyLock<Stats> = LazyLock::new(|| Stats {
    commits: AtomicU64::new(0),
    ops: AtomicU64::new(0),
    write_requests: AtomicU64::new(0),
    write_errors: AtomicU64::new(0),
    entries_durable: AtomicU64::new(0),
    segments: AtomicU64::new(0),
    segment_bytes: AtomicU64::new(0),
    repo_loads: AtomicU64::new(0),
    hedges: AtomicU64::new(0),
    put_us: Mutex::new(Histogram::new_with_bounds(1, 60_000_000, 2).unwrap()),
    commit_us: Mutex::new(Histogram::new_with_bounds(1, 60_000_000, 2).unwrap()),
    request_us: Mutex::new(Histogram::new_with_bounds(1, 60_000_000, 2).unwrap()),
    apply_us: Mutex::new(Histogram::new_with_bounds(1, 60_000_000, 2).unwrap()),
    load_us: Mutex::new(Histogram::new_with_bounds(1, 60_000_000, 2).unwrap()),
});

impl Stats {
    pub fn record_put(&self, d: Duration, bytes: usize) {
        self.segments.fetch_add(1, Ordering::Relaxed);
        self.segment_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
        let _ = self.put_us.lock().record(d.as_micros() as u64);
    }

    pub fn record_commit_latency(&self, d: Duration) {
        let _ = self.commit_us.lock().record(d.as_micros().max(1) as u64);
    }

    pub fn record_request(&self, d: Duration) {
        let _ = self.request_us.lock().record(d.as_micros().max(1) as u64);
    }
}

fn pct(h: &Mutex<Histogram<u64>>) -> (f64, f64, f64) {
    let mut h = h.lock();
    let r =
        (h.value_at_quantile(0.5) as f64 / 1000.0, h.value_at_quantile(0.99) as f64 / 1000.0, h.max() as f64 / 1000.0);
    h.reset();
    r
}

pub fn spawn_reporter(every: Duration) {
    tokio::spawn(async move {
        let s = &*STATS;
        let mut last = [0u64; 9];
        let mut tick = tokio::time::interval(every);
        tick.tick().await;
        loop {
            tick.tick().await;
            let cur = [
                s.write_requests.load(Ordering::Relaxed),
                s.commits.load(Ordering::Relaxed),
                s.ops.load(Ordering::Relaxed),
                s.segments.load(Ordering::Relaxed),
                s.segment_bytes.load(Ordering::Relaxed),
                vlsync_firehose::metrics::FIREHOSE_EVENTS.get(),
                s.write_errors.load(Ordering::Relaxed),
                s.repo_loads.load(Ordering::Relaxed),
                s.hedges.load(Ordering::Relaxed),
            ];
            let secs = every.as_secs_f64();
            let rate = |i: usize| (cur[i] - last[i]) as f64 / secs;
            let (put50, put99, putmax) = pct(&s.put_us);
            let (a50, a99, amax) = pct(&s.apply_us);
            let (l50, l99, _) = pct(&s.load_us);
            let (c50, c99, cmax) = pct(&s.commit_us);
            let (r50, r99, _) = pct(&s.request_us);
            tracing::info!(
                "req/s {:.0} commits/s {:.0} ops/s {:.0} errs/s {:.0} | segs/s {:.0} MB/s {:.1} | put p50 {:.1}ms p99 {:.1}ms max {:.0}ms hedges/s {:.1} | apply p50 {:.1}ms p99 {:.1}ms max {:.0}ms | commit p50 {:.1}ms p99 {:.1}ms max {:.0}ms | http p50 {:.1}ms p99 {:.1}ms | firehose ev/s {:.0} | loads/s {:.0} p50 {:.1}ms p99 {:.1}ms",
                rate(0), rate(1), rate(2), rate(6), rate(3), rate(4) / 1e6, put50, put99, putmax, rate(8), a50, a99, amax, c50, c99, cmax, r50, r99, rate(5), rate(7), l50, l99
            );
            last = cur;
        }
    });
}

/// A late 10 ms ticker means something is blocking runtime threads.
pub fn spawn_stall_detector() {
    tokio::spawn(async {
        let mut last = std::time::Instant::now();
        loop {
            tokio::time::sleep(Duration::from_millis(10)).await;
            let late = last.elapsed().saturating_sub(Duration::from_millis(10));
            // timer granularity is ~1 ms: count only what's beyond it
            if late > Duration::from_millis(2) {
                crate::metrics::RUNTIME_LATE.observe(late.as_secs_f64());
                crate::metrics::RUNTIME_LATE_TOTAL.inc_by(late.as_secs_f64());
            }
            if late > Duration::from_millis(100) {
                tracing::warn!(late_ms = late.as_millis() as u64, "tokio runtime stall");
            }
            last = std::time::Instant::now();
        }
    });
}
