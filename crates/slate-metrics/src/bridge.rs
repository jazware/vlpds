use crate::Inner;
use parking_lot::Mutex;
use prometheus::core::{Collector, Desc};
use prometheus::proto::MetricFamily;
use prometheus::{HistogramOpts, HistogramVec, IntCounterVec, IntGaugeVec, Opts, Registry};
use slatedb_common::metrics::{CounterFn, GaugeFn, HistogramFn, MetricsRecorder, UpDownCounterFn};
use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Weak};

pub(crate) const DB_LABEL: &str = "db";

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub(crate) enum Kind {
    Counter,
    Gauge,
    Hist,
}

/// One series: kind, SlateDB's dotted name, label values in the vec's key order.
type Key = (Kind, String, Vec<String>);

/// The Prometheus side: one vec per SlateDB name, created on first
/// registration (its label keys win; a later registration with other keys
/// gets a no-op handle), and a count of live handles per series so the
/// series goes when its last database does.
pub(crate) struct Bridge {
    registry: Registry,
    counters: Mutex<HashMap<String, Option<IntCounterVec>>>,
    gauges: Mutex<HashMap<String, Option<IntGaugeVec>>>,
    hists: Mutex<HashMap<String, Option<HistogramVec>>>,
    refs: Mutex<HashMap<Key, usize>>,
}

pub(crate) fn prom_name(name: &str) -> String {
    name.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }).collect()
}

fn help(description: &str, name: &str) -> String {
    if description.is_empty() {
        name.to_string()
    } else {
        description.to_string()
    }
}

fn vec<V: Clone + Collector + 'static>(
    registry: &Registry,
    map: &Mutex<HashMap<String, Option<V>>>,
    name: &str,
    keys: &[&str],
    make: impl FnOnce(&[&str]) -> prometheus::Result<V>,
) -> Option<V> {
    let mut m = map.lock();
    m.entry(name.to_string())
        .or_insert_with(|| {
            let v = make(keys).ok()?;
            match registry.register(Box::new(v.clone())) {
                Ok(()) => Some(v),
                Err(e) => {
                    tracing::warn!("{name} not exported: {e}");
                    None
                }
            }
        })
        .clone()
}

impl Bridge {
    pub(crate) fn new(registry: Registry) -> Bridge {
        Bridge {
            registry,
            counters: Default::default(),
            gauges: Default::default(),
            hists: Default::default(),
            refs: Default::default(),
        }
    }

    fn counter_vec(&self, name: &str, description: &str, keys: &[&str]) -> Option<IntCounterVec> {
        vec(&self.registry, &self.counters, name, keys, |keys| {
            IntCounterVec::new(Opts::new(prom_name(name) + "_total", help(description, name)), keys)
        })
    }

    fn gauge_vec(&self, name: &str, description: &str, keys: &[&str]) -> Option<IntGaugeVec> {
        vec(&self.registry, &self.gauges, name, keys, |keys| {
            IntGaugeVec::new(Opts::new(prom_name(name), help(description, name)), keys)
        })
    }

    fn hist_vec(&self, name: &str, description: &str, keys: &[&str], buckets: &[f64]) -> Option<HistogramVec> {
        vec(&self.registry, &self.hists, name, keys, |keys| {
            HistogramVec::new(
                HistogramOpts::new(prom_name(name), help(description, name)).buckets(buckets.to_vec()),
                keys,
            )
        })
    }

    /// Counts a handle on the series and returns its child, under the refs
    /// lock so a concurrent last release can't remove it in between.
    fn acquire<M>(
        &self,
        kind: Kind,
        name: &str,
        values: &[&str],
        get: impl FnOnce(&[&str]) -> Option<M>,
    ) -> Option<(M, Key)> {
        let key: Key = (kind, name.to_string(), values.iter().map(|v| v.to_string()).collect());
        let mut refs = self.refs.lock();
        let m = get(values)?;
        *refs.entry(key.clone()).or_insert(0) += 1;
        Some((m, key))
    }

    fn release(&self, key: &Key) {
        let mut refs = self.refs.lock();
        let Some(n) = refs.get_mut(key) else { return };
        *n -= 1;
        if *n > 0 {
            return;
        }
        refs.remove(key);
        let (kind, name, values) = key;
        let values: Vec<&str> = values.iter().map(String::as_str).collect();
        let _ = match kind {
            Kind::Counter => self.counters.lock().get(name).cloned().flatten().map(|v| v.remove_label_values(&values)),
            Kind::Gauge => self.gauges.lock().get(name).cloned().flatten().map(|v| v.remove_label_values(&values)),
            Kind::Hist => self.hists.lock().get(name).cloned().flatten().map(|v| v.remove_label_values(&values)),
        };
    }

    /// Every series of a SlateDB name (`db` given: only that database's),
    /// as (labels, value); histograms give their sample count.
    pub(crate) fn series(&self, kind: Kind, name: &str, db: Option<&str>) -> Vec<(Vec<(String, String)>, f64)> {
        let fams = match kind {
            Kind::Counter => self.counters.lock().get(name).cloned().flatten().map(|v| v.collect()),
            Kind::Gauge => self.gauges.lock().get(name).cloned().flatten().map(|v| v.collect()),
            Kind::Hist => self.hists.lock().get(name).cloned().flatten().map(|v| v.collect()),
        };
        let mut out = Vec::new();
        for m in fams.iter().flatten().flat_map(|f| f.get_metric()) {
            let labels: Vec<(String, String)> =
                m.get_label().iter().map(|l| (l.name().to_string(), l.value().to_string())).collect();
            if db.is_some_and(|db| !labels.iter().any(|(k, v)| k == DB_LABEL && v == db)) {
                continue;
            }
            let v = match kind {
                Kind::Counter => m.get_counter().get_value(),
                Kind::Gauge => m.get_gauge().get_value(),
                Kind::Hist => m.get_histogram().get_sample_count() as f64,
            };
            out.push((labels, v));
        }
        out
    }

    /// The sum over the matching series; None if the name has none.
    pub(crate) fn sum(&self, kind: Kind, name: &str, db: Option<&str>) -> Option<f64> {
        let s = self.series(kind, name, db);
        (!s.is_empty()).then(|| s.iter().map(|(_, v)| v).sum())
    }

    pub(crate) fn gauge_sum(&self, name: &str, db: Option<&str>) -> Option<i64> {
        self.sum(Kind::Gauge, name, db).map(|v| v as i64)
    }
}

/// Keeps the series alive while a SlateDB handle holds it.
struct Live {
    inner: Arc<Inner>,
    key: Key,
}

impl Drop for Live {
    fn drop(&mut self) {
        self.inner.bridge.release(&self.key);
    }
}

struct Noop;
impl CounterFn for Noop {
    fn increment(&self, _: u64) {}
}
impl GaugeFn for Noop {
    fn set(&self, _: i64) {}
}
impl UpDownCounterFn for Noop {
    fn increment(&self, _: i64) {}
}
impl HistogramFn for Noop {
    fn record(&self, _: f64) {}
}

struct Counter {
    c: prometheus::IntCounter,
    _live: Live,
}
impl CounterFn for Counter {
    fn increment(&self, v: u64) {
        self.c.inc_by(v);
    }
}

/// One handle's share of a gauge series. SlateDB can register the same
/// series twice under one database (a reopened handle before the old one
/// drops; a compactor next to its database), so each adds its delta and a
/// dropped one takes its share back out.
struct Share {
    g: prometheus::IntGauge,
    last: AtomicI64,
    _live: Live,
}
impl GaugeFn for Share {
    fn set(&self, v: i64) {
        self.g.add(v - self.last.swap(v, Ordering::Relaxed));
    }
}
impl UpDownCounterFn for Share {
    fn increment(&self, v: i64) {
        self.last.fetch_add(v, Ordering::Relaxed);
        self.g.add(v);
    }
}
impl Drop for Share {
    fn drop(&mut self) {
        self.g.sub(self.last.load(Ordering::Relaxed));
    }
}

struct Hist {
    h: prometheus::Histogram,
    _live: Live,
}
impl HistogramFn for Hist {
    fn record(&self, v: f64) {
        self.h.observe(v);
    }
}

/// Whether a SlateDB name gets the `db` label: what describes one
/// database's shape and health (memtable, L0 and runs, flushes, stalls,
/// cache, WAL, compaction). The rest stays node-wide, summed over every
/// database as before: per database, the object store's request counters
/// and latency histogram alone are ~500 series, and a vlpds node can hold
/// 64 shards.
pub(crate) fn per_db(name: &str) -> bool {
    const DB: [&str; 5] =
        ["slatedb.db.", "slatedb.db_cache.", "slatedb.compactor.", "slatedb.wal.", "slatedb.memtable_flush."];
    DB.iter().any(|p| name.starts_with(p)) && !name.starts_with("slatedb.db.sst_filter_")
}

/// A database's view of the bridge: `db` first (on [`per_db`] names), then SlateDB's labels
/// minus per-instance ids (the compactor worker's `worker_id` ULID, new
/// every start) so instances aggregate instead of minting series.
pub(crate) struct DbRecorder {
    pub(crate) inner: Arc<Inner>,
    pub(crate) db: String,
}

impl DbRecorder {
    fn labels<'a>(&'a self, name: &str, labels: &[(&'a str, &'a str)]) -> (Vec<&'a str>, Vec<&'a str>) {
        let kept = labels.iter().filter(|(k, _)| !k.ends_with("_id") && *k != DB_LABEL);
        let db = per_db(name).then_some((DB_LABEL, self.db.as_str()));
        let keys = db.iter().map(|(k, _)| *k).chain(kept.clone().map(|(k, _)| *k)).collect();
        let values = db.iter().map(|(_, v)| *v).chain(kept.map(|(_, v)| *v)).collect();
        (keys, values)
    }

    fn share(&self, name: &str, description: &str, labels: &[(&str, &str)]) -> Option<Share> {
        let b = &self.inner.bridge;
        let (keys, values) = self.labels(name, labels);
        let v = b.gauge_vec(name, description, &keys)?;
        let (g, key) = b.acquire(Kind::Gauge, name, &values, |vals| v.get_metric_with_label_values(vals).ok())?;
        Some(Share { g, last: AtomicI64::new(0), _live: Live { inner: self.inner.clone(), key } })
    }
}

impl MetricsRecorder for DbRecorder {
    fn register_counter(&self, name: &str, description: &str, labels: &[(&str, &str)]) -> Arc<dyn CounterFn> {
        let b = &self.inner.bridge;
        let (keys, values) = self.labels(name, labels);
        let c = b
            .counter_vec(name, description, &keys)
            .and_then(|v| b.acquire(Kind::Counter, name, &values, |vals| v.get_metric_with_label_values(vals).ok()));
        match c {
            Some((c, key)) => Arc::new(Counter { c, _live: Live { inner: self.inner.clone(), key } }),
            None => Arc::new(Noop),
        }
    }

    fn register_gauge(&self, name: &str, description: &str, labels: &[(&str, &str)]) -> Arc<dyn GaugeFn> {
        match self.share(name, description, labels) {
            Some(s) => Arc::new(s),
            None => Arc::new(Noop),
        }
    }

    fn register_up_down_counter(
        &self,
        name: &str,
        description: &str,
        labels: &[(&str, &str)],
    ) -> Arc<dyn UpDownCounterFn> {
        match self.share(name, description, labels) {
            Some(s) => Arc::new(s),
            None => Arc::new(Noop),
        }
    }

    fn register_histogram(
        &self,
        name: &str,
        description: &str,
        labels: &[(&str, &str)],
        boundaries: &[f64],
    ) -> Arc<dyn HistogramFn> {
        let b = &self.inner.bridge;
        let (keys, values) = self.labels(name, labels);
        let h = b
            .hist_vec(name, description, &keys, boundaries)
            .and_then(|v| b.acquire(Kind::Hist, name, &values, |vals| v.get_metric_with_label_values(vals).ok()));
        match h {
            Some((h, key)) => Arc::new(Hist { h, _live: Live { inner: self.inner.clone(), key } }),
            None => Arc::new(Noop),
        }
    }
}

/// `slatedb_lsm_*`, `slatedb_cache_entries` and `slatedb_cache_bytes`, read from each registered
/// database's in-memory manifest (and each shared cache) at scrape time.
pub(crate) struct LsmCollector {
    inner: Weak<Inner>,
    lock: Mutex<()>,
    ssts: IntGaugeVec,
    bytes: IntGaugeVec,
    runs: IntGaugeVec,
    largest_run: IntGaugeVec,
    checkpoints: IntGaugeVec,
    manifest: IntGaugeVec,
    cache_entries: IntGaugeVec,
    cache_bytes: IntGaugeVec,
}

impl LsmCollector {
    pub(crate) fn new(inner: Weak<Inner>) -> LsmCollector {
        let g = |name: &str, help: &str, keys: &[&str]| IntGaugeVec::new(Opts::new(name, help), keys).unwrap();
        LsmCollector {
            inner,
            lock: Mutex::new(()),
            ssts: g(
                "slatedb_lsm_ssts",
                "SSTs in the database's manifest, by tier (l0, compacted)",
                &[DB_LABEL, "tier"],
            ),
            bytes: g(
                "slatedb_lsm_sst_bytes",
                "Estimated bytes of the manifest's SSTs, by tier (l0, compacted)",
                &[DB_LABEL, "tier"],
            ),
            runs: g("slatedb_lsm_sorted_runs", "Sorted runs in the manifest", &[DB_LABEL]),
            largest_run: g(
                "slatedb_lsm_largest_run_bytes",
                "Estimated bytes of the manifest's largest sorted run",
                &[DB_LABEL],
            ),
            checkpoints: g(
                "slatedb_lsm_checkpoints",
                "Checkpoints in the manifest (each pins the SSTs it names)",
                &[DB_LABEL],
            ),
            manifest: g("slatedb_lsm_manifest_id", "The manifest version this handle last saw", &[DB_LABEL]),
            cache_entries: g("slatedb_cache_entries", "Entries in a shared SlateDB block/metadata cache", &["cache"]),
            cache_bytes: g(
                "slatedb_cache_bytes",
                "Bytes a shared SlateDB cache holds as it weighs entries, by part (block, meta; all for an unsplit cache)",
                &["cache", "part"],
            ),
        }
    }

    fn all(&self) -> [&IntGaugeVec; 8] {
        [
            &self.ssts,
            &self.bytes,
            &self.runs,
            &self.largest_run,
            &self.checkpoints,
            &self.manifest,
            &self.cache_entries,
            &self.cache_bytes,
        ]
    }
}

impl Collector for LsmCollector {
    fn desc(&self) -> Vec<&Desc> {
        self.all().into_iter().flat_map(|v| v.desc()).collect()
    }

    fn collect(&self) -> Vec<MetricFamily> {
        let Some(inner) = self.inner.upgrade() else { return Vec::new() };
        let _g = self.lock.lock();
        for v in self.all() {
            v.reset();
        }
        for (name, _, status) in inner.live_dbs() {
            let t = crate::shape::Totals::of(&status);
            let n = name.as_str();
            self.ssts.with_label_values(&[n, "l0"]).set(t.l0_ssts as i64);
            self.ssts.with_label_values(&[n, "compacted"]).set(t.compacted_ssts() as i64);
            self.bytes.with_label_values(&[n, "l0"]).set(t.l0_bytes as i64);
            self.bytes.with_label_values(&[n, "compacted"]).set(t.compacted_bytes() as i64);
            self.runs.with_label_values(&[n]).set(t.runs.len() as i64);
            self.largest_run.with_label_values(&[n]).set(t.runs.iter().map(|r| r.bytes).max().unwrap_or(0) as i64);
            self.checkpoints.with_label_values(&[n]).set(t.checkpoints as i64);
            self.manifest.with_label_values(&[n]).set(t.manifest_id as i64);
        }
        for (name, cache) in inner.caches.lock().iter() {
            self.cache_entries.with_label_values(&[name]).set(cache.entry_count() as i64);
            match cache.split_weighted_size() {
                Some((block, meta)) => {
                    self.cache_bytes.with_label_values(&[name.as_str(), "block"]).set(block as i64);
                    self.cache_bytes.with_label_values(&[name.as_str(), "meta"]).set(meta as i64);
                }
                None => self.cache_bytes.with_label_values(&[name.as_str(), "all"]).set(cache.weighted_size() as i64),
            }
        }
        self.all().into_iter().flat_map(|v| v.collect()).collect()
    }
}
