//! SlateDB's own metrics in Prometheus, a `db` label per database, plus
//! each open database's LSM shape (L0, sorted runs, bytes, memtable, cache,
//! compaction) for admin views.
//!
//! SlateDB reports through a [`MetricsRecorder`] given at build time, so a
//! database is wired in two steps: its builder takes [`recorder`], and the
//! built handle is passed to [`register`] (for the shape and the scrape-time
//! `slatedb_lsm_*` series, which also cover read-only `DbReader`s, whose
//! `slatedb_db_*` gauges SlateDB never sets).
//!
//! ```ignore
//! let db = slatedb::Db::builder(path, store)
//!     .with_metrics_recorder(slate_metrics::recorder("seeds"))
//!     .build()
//!     .await?;
//! slate_metrics::register("seeds", &db);
//! // GET /metrics: prometheus::gather() now has slatedb_db_*{db="seeds"}
//! let shapes: Vec<slate_metrics::DbShape> = slate_metrics::shapes();
//! ```
//!
//! The free functions use [`Exporter::global`] (Prometheus's default
//! registry); [`Exporter::new`] exports into another registry.
//!
//! Series names are SlateDB's dotted names with dots turned to underscores
//! (`slatedb.db.l0_sst_count` -> `slatedb_db_l0_sst_count`), counters with
//! `_total`. Only the families that describe one database get `db`
//! (`bridge::per_db`); object store calls, GC, filter counts and histograms
//! stay node-wide, summed. Labels ending in `_id` (the compactor's per-start worker ULID)
//! are dropped so a restart doesn't mint new series. A database's series are
//! removed when its last handle is dropped. Nothing polls: SlateDB pushes its
//! values, and the `slatedb_lsm_*` series and [`shapes`] read each
//! database's in-memory manifest when asked.

mod bridge;
mod shape;

pub use parking_lot::Mutex;
use prometheus::Registry;
pub use shape::{CacheAccess, CompactionShape, DbShape, RunShape, StallShape};
use slatedb::db_cache::DbCache;
use slatedb::{DbMetadataOps, DbStatus};
pub use slatedb_common::metrics::MetricsRecorder;
use std::sync::{Arc, LazyLock};
use tokio::sync::watch;

/// Exports SlateDB metrics into one Prometheus registry.
#[derive(Clone)]
pub struct Exporter {
    inner: Arc<Inner>,
}

struct Inner {
    bridge: bridge::Bridge,
    dbs: Mutex<Vec<Registered>>,
    caches: Mutex<Vec<(String, Arc<dyn DbCache>)>>,
}

struct Registered {
    name: String,
    role: &'static str,
    status: watch::Receiver<DbStatus>,
}

impl Registered {
    /// A dropped handle closes its status channel; a closed one sets the reason.
    fn live(&self) -> bool {
        self.status.has_changed().is_ok() && self.status.borrow().close_reason.is_none()
    }
}

static GLOBAL: LazyLock<Exporter> = LazyLock::new(|| Exporter::new(prometheus::default_registry()));

impl Exporter {
    /// The exporter into Prometheus's default registry (`prometheus::gather()`).
    pub fn global() -> &'static Exporter {
        &GLOBAL
    }

    /// One exporter per registry: a second one on the same registry can't
    /// register the same series names, and its handles record nothing.
    pub fn new(registry: &Registry) -> Exporter {
        let inner = Arc::new(Inner {
            bridge: bridge::Bridge::new(registry.clone()),
            dbs: Mutex::new(Vec::new()),
            caches: Mutex::new(Vec::new()),
        });
        let lsm = bridge::LsmCollector::new(Arc::downgrade(&inner));
        if let Err(e) = registry.register(Box::new(lsm)) {
            tracing::warn!("slatedb_lsm_* not registered: {e}");
        }
        Exporter { inner }
    }

    /// The recorder for a database's builders (`Db`, `DbReader`, a standalone
    /// compactor or worker): every series it registers carries `db=<db>`.
    pub fn recorder(&self, db: &str) -> Arc<dyn MetricsRecorder> {
        Arc::new(bridge::DbRecorder { inner: self.inner.clone(), db: db.to_string() })
    }

    /// Adds a built database to [`Self::shapes`] and the `slatedb_lsm_*`
    /// series until the handle is dropped or closed. Of several open handles
    /// under one name, the newest shows (one series per name); an older one
    /// shows again if the newer closes first.
    pub fn register<D: DbMetadataOps + ?Sized>(&self, db: &str, handle: &D) {
        self.register_status(db, "writer", handle.subscribe());
    }

    /// [`Self::register`] for a read-only handle (role `reader` in the shape).
    pub fn register_reader<D: DbMetadataOps + ?Sized>(&self, db: &str, handle: &D) {
        self.register_status(db, "reader", handle.subscribe());
    }

    fn register_status(&self, db: &str, role: &'static str, status: watch::Receiver<DbStatus>) {
        let mut dbs = self.inner.dbs.lock();
        dbs.retain(Registered::live);
        dbs.push(Registered { name: db.to_string(), role, status });
    }

    /// Exports `slatedb_cache_entries{cache=<name>}` for a cache several
    /// databases share (its hits and misses are per database already).
    pub fn register_cache(&self, name: &str, cache: Arc<dyn DbCache>) {
        let mut caches = self.inner.caches.lock();
        caches.retain(|(n, _)| n != name);
        caches.push((name.to_string(), cache));
    }

    /// Every registered, still-open database's shape, by name.
    pub fn shapes(&self) -> Vec<DbShape> {
        let mut out: Vec<DbShape> = self
            .inner
            .live_dbs()
            .into_iter()
            .map(|(name, role, status)| shape::of(&name, role, &status, &self.inner.bridge))
            .collect();
        out.sort_by(|a, b| a.db.cmp(&b.db));
        out
    }

    /// A SlateDB gauge (its dotted name) summed over every database; None
    /// if none registered it.
    pub fn gauge_sum(&self, name: &str) -> Option<i64> {
        self.inner.bridge.gauge_sum(name, None)
    }
}

impl Inner {
    /// Prunes closed databases and snapshots the rest's status (the watch
    /// lock isn't held past this).
    fn live_dbs(&self) -> Vec<(String, &'static str, DbStatus)> {
        let mut dbs = self.dbs.lock();
        dbs.retain(Registered::live);
        let mut out: Vec<(String, &'static str, DbStatus)> = Vec::new();
        for r in dbs.iter().rev() {
            if !out.iter().any(|(n, ..)| *n == r.name) {
                out.push((r.name.clone(), r.role, r.status.borrow().clone()));
            }
        }
        out
    }
}

/// [`Exporter::recorder`] on the global exporter.
pub fn recorder(db: &str) -> Arc<dyn MetricsRecorder> {
    Exporter::global().recorder(db)
}

/// [`Exporter::register`] on the global exporter.
pub fn register<D: DbMetadataOps + ?Sized>(db: &str, handle: &D) {
    Exporter::global().register(db, handle)
}

/// [`Exporter::register_reader`] on the global exporter.
pub fn register_reader<D: DbMetadataOps + ?Sized>(db: &str, handle: &D) {
    Exporter::global().register_reader(db, handle)
}

/// [`Exporter::register_cache`] on the global exporter.
pub fn register_cache(name: &str, cache: Arc<dyn DbCache>) {
    Exporter::global().register_cache(name, cache)
}

/// [`Exporter::shapes`] on the global exporter.
pub fn shapes() -> Vec<DbShape> {
    Exporter::global().shapes()
}

/// [`Exporter::gauge_sum`] on the global exporter.
pub fn gauge_sum(name: &str) -> Option<i64> {
    Exporter::global().gauge_sum(name)
}

#[cfg(test)]
mod tests;
