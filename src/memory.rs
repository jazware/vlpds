//! The node's memory budget and the cache sizes derived from it.
//!
//! The budget is the memory limit (the tightest cgroup `memory.max` on our
//! cgroup's path, else physical RAM) or `--memory-budget-mb`. Fixed costs
//! come off the top: a runtime baseline, the in-memory caches
//! (`--cache-budget-mb`), the MST node cache, the firehose rings and merge
//! queue, the backfill buffers, the export and import working sets, and a
//! headroom share for memtables, request bodies and allocator slack. The
//! rest is the cache pool.
//!
//! The pool goes first to the SST metadata cache, which must hold every
//! owned SST's filters and indexes (DESIGN.md "The metadata cache must hold
//! every owned SST's filter and index"), then evenly to the SST block cache
//! and the repo cache. The metadata target follows the owned SSTs (shards
//! acquired, released, split, compacted) as a background thread re-plans
//! every few seconds; growth applies at once, shrinking only once the lower
//! target has held for [`SHRINK_HOLD`], so a takeover and its hand-back
//! don't thrash the caches. A cache given an explicit size keeps it.
//!
//! The SST caches are process-wide (partition.rs), so the plan is too: the
//! first node built in a process sets it, and in-process test clusters
//! share it, their repo caches splitting its repo share.

use crate::partitions::PartitionTable;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock, Weak};
use std::time::{Duration, Instant};

const MIB: u64 = 1 << 20;

/// Heap and stacks of a node at rest: threads, runtimes, connection
/// buffers, the cluster's maps, allocator metadata.
pub const RUNTIME_BASELINE: u64 = 256 * MIB;
/// Memtables, request and response bodies in flight, fragmentation.
pub const HEADROOM_FRACTION: f64 = 0.15;
pub const MIN_HEADROOM: u64 = 512 * MIB;
/// Floor of an automatically sized block or repo cache.
pub const MIN_CACHE: u64 = 64 * MIB;
/// Floor of an automatically sized metadata cache.
pub const MIN_META: u64 = 16 * MIB;
/// Decoded / encoded size of SST filters and indexes until measured
/// (capacity test's records distribution).
pub const DEFAULT_META_DECODE_RATIO: f64 = 1.3;
const MAX_META_DECODE_RATIO: f64 = 2.0;
/// Compactions in flight hold their inputs' and outputs' metadata at once.
pub const COMPACTION_HEADROOM: f64 = 1.25;
/// A node inheriting a dead peer's shards: N / (N - 1), at most this.
pub const MAX_FAILOVER_FACTOR: f64 = 2.0;
/// The block cache's share of what the metadata cache leaves; the repo
/// cache gets the rest (the old defaults were 4 GiB each).
pub const BLOCK_SHARE: f64 = 0.5;
/// Before any SST is measured: the old default proportions (metadata a
/// quarter of a block cache as large as the repo cache).
const INITIAL_META_SHARE: f64 = 1.0 / 9.0;
const GROW_STEP: f64 = 1.05;
const SHRINK_STEP: f64 = 0.9;
pub const SHRINK_HOLD: Duration = Duration::from_secs(300);
const TICK: Duration = Duration::from_secs(5);
const FALLBACK_LIMIT: u64 = 4 << 30;

/// `--memory-budget-mb`: MiB, or a percentage of the memory limit.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum BudgetSpec {
    Bytes(u64),
    Fraction(f64),
}

impl std::str::FromStr for BudgetSpec {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> anyhow::Result<BudgetSpec> {
        let s = s.trim();
        if let Some(p) = s.strip_suffix('%') {
            let p: f64 =
                p.trim().parse().map_err(|_| anyhow::anyhow!("memory budget {s:?}: expected <MiB> or <percent>%"))?;
            anyhow::ensure!(p > 0.0 && p <= 100.0, "memory budget {s:?}: percent must be in (0, 100]");
            return Ok(BudgetSpec::Fraction(p / 100.0));
        }
        let mb: u64 = s.parse().map_err(|_| anyhow::anyhow!("memory budget {s:?}: expected <MiB> or <percent>%"))?;
        anyhow::ensure!(mb > 0, "memory budget must be positive");
        Ok(BudgetSpec::Bytes(mb * MIB))
    }
}

/// The operator's choices. None: automatic.
#[derive(Clone, Debug, Default)]
pub struct Settings {
    pub budget: Option<BudgetSpec>,
    pub block: Option<u64>,
    pub meta: Option<u64>,
    /// Some(0): bounded by entry count only.
    pub repo: Option<u64>,
}

/// The fixed costs' knobs, in bytes.
#[derive(Clone, Debug, Default)]
pub struct Fixed {
    /// None: [`crate::caches::DEFAULT_BUDGET_FRACTION`] of the budget.
    pub in_memory_caches: Option<u64>,
    pub mst_node_cache: u64,
    pub firehose_ring: u64,
    pub live_ring: u64,
    pub merge_queue: u64,
    pub backfill_cache: u64,
    /// Per backfilling subscriber.
    pub backfill_readahead: u64,
    pub max_backfills: u64,
    pub max_exports: u64,
    /// None: [`crate::xrpc::import_budget::budget_share`] of the budget.
    pub import_memory: Option<u64>,
    /// With `--spaces`: the room space getRepo exports reserve from
    /// ([`crate::space::export_budget_bytes`]).
    pub space_exports: u64,
}

#[derive(Clone, Debug)]
pub struct Plan {
    /// Detected (None: unreadable).
    pub limit: Option<u64>,
    pub budget: u64,
    /// Fixed costs, headroom last.
    pub parts: Vec<(&'static str, u64)>,
    pub pool: u64,
    pub block: Option<u64>,
    pub meta: Option<u64>,
    pub repo: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Split {
    pub meta: u64,
    pub block: u64,
    pub repo: u64,
    /// What the metadata cache should hold (decoded owned SST metadata with
    /// failover and compaction headroom), and how much of it doesn't fit.
    pub meta_want: u64,
    pub shortfall: u64,
}

pub fn headroom(budget: u64) -> u64 {
    ((budget as f64 * HEADROOM_FRACTION) as u64).max(MIN_HEADROOM)
}

fn mb(b: u64) -> u64 {
    b >> 20
}

/// Refuses a budget over the memory limit, and explicit sizes that leave
/// the automatic caches less than their floors.
pub fn plan(s: &Settings, f: &Fixed, limit: Option<u64>) -> anyhow::Result<Plan> {
    let base = limit.unwrap_or(FALLBACK_LIMIT);
    let budget = match s.budget {
        None => base,
        Some(BudgetSpec::Bytes(b)) => b,
        Some(BudgetSpec::Fraction(x)) => (base as f64 * x) as u64,
    };
    if let Some(l) = limit {
        anyhow::ensure!(
            budget <= l,
            "--memory-budget-mb {} MiB is over this node's memory limit ({} MiB: cgroup memory.max or RAM)",
            mb(budget),
            mb(l)
        );
    }
    let in_memory = f.in_memory_caches.unwrap_or((budget as f64 * crate::caches::DEFAULT_BUDGET_FRACTION) as u64);
    let mut parts = vec![
        ("runtime", RUNTIME_BASELINE),
        ("in_memory_caches", in_memory),
        ("mst_node_cache", f.mst_node_cache),
        ("firehose", f.firehose_ring + f.live_ring + f.merge_queue),
        ("backfill", f.backfill_cache + f.backfill_readahead * f.max_backfills),
        ("exports", crate::xrpc::export_memory_bytes(f.max_exports as usize)),
        ("import", f.import_memory.unwrap_or(crate::xrpc::import_budget::budget_share(budget))),
    ];
    if f.space_exports > 0 {
        parts.push(("space_exports", f.space_exports));
    }
    parts.push(("headroom", headroom(budget)));
    let fixed: u64 = parts.iter().map(|(_, b)| b).sum();
    let explicit = s.block.unwrap_or(0) + s.meta.unwrap_or(0) + s.repo.unwrap_or(0);
    let floors = [s.block.is_none(), s.repo.is_none()].iter().filter(|a| **a).count() as u64 * MIN_CACHE
        + if s.meta.is_none() { MIN_META } else { 0 };
    let need = fixed + explicit + floors;
    if need > budget {
        let list = parts.iter().map(|(k, b)| format!("{k} {}", mb(*b))).collect::<Vec<_>>().join(", ");
        anyhow::bail!(
            "memory: {} MiB needed but the budget is {} MiB (fixed: {list}; explicit caches {} MiB; automatic caches' floors {} MiB). \
             Lower the cache flags, ring and backfill sizes, or raise the memory limit / --memory-budget-mb",
            mb(need),
            mb(budget),
            mb(explicit),
            mb(floors)
        );
    }
    Ok(Plan { limit, budget, parts, pool: budget - fixed, block: s.block, meta: s.meta, repo: s.repo })
}

/// Decoded metadata of `encoded` bytes of owned SST filters and indexes,
/// with room to inherit a dead peer's share and for compactions in flight.
pub fn meta_want(encoded: u64, ratio: f64, nodes: usize) -> u64 {
    let failover = if nodes > 1 { (nodes as f64 / (nodes - 1) as f64).min(MAX_FAILOVER_FACTOR) } else { 1.0 };
    (encoded as f64 * ratio * failover * COMPACTION_HEADROOM) as u64
}

impl Plan {
    pub fn fixed(&self) -> u64 {
        self.parts.iter().map(|(_, b)| b).sum()
    }

    pub fn part(&self, name: &str) -> u64 {
        self.parts.iter().find(|(k, _)| *k == name).map_or(0, |(_, b)| *b)
    }

    fn initial_meta(&self) -> u64 {
        ((self.pool as f64 * INITIAL_META_SHARE) as u64).max(MIN_META)
    }

    pub fn split(&self, meta_want: u64) -> Split {
        let mut left = self.pool - self.block.unwrap_or(0) - self.repo.unwrap_or(0);
        let auto_rest = [self.block.is_none(), self.repo.is_none()].iter().filter(|a| **a).count() as u64;
        let meta = match self.meta {
            Some(m) => m,
            None => meta_want.max(MIN_META).min(left - auto_rest * MIN_CACHE),
        };
        left -= meta;
        let (block, repo) = match (self.block, self.repo) {
            (Some(b), Some(r)) => (b, r),
            (Some(b), None) => (b, left),
            (None, Some(r)) => (left, r),
            (None, None) => {
                let b = (left as f64 * BLOCK_SHARE) as u64;
                (b, left - b)
            }
        };
        Split { meta, block, repo, meta_want, shortfall: meta_want.saturating_sub(meta) }
    }

    pub fn to_json(&self) -> serde_json::Value {
        let s = self.split(self.initial_meta());
        let mut parts = serde_json::Map::new();
        for (k, b) in &self.parts {
            parts.insert((*k).into(), mb(*b).into());
        }
        serde_json::json!({
            "limit_mb": self.limit.map(mb),
            "budget_mb": mb(self.budget),
            "fixed_mb": parts,
            "pool_mb": mb(self.pool),
            "explicit_mb": {"block": self.block.map(mb), "meta": self.meta.map(mb), "repo": self.repo.map(mb)},
            "initial_mb": {"meta": mb(s.meta), "block": mb(s.block), "repo": mb(s.repo)},
            "imports": crate::xrpc::import_budget::plan_json(self.part("import")),
        })
    }
}

/// One re-plan's inputs.
#[derive(Clone, Copy, Debug, Default)]
pub struct Observation {
    /// Encoded filter + index bytes of the owned SSTs.
    pub encoded: u64,
    /// Live nodes in the cluster (this one included).
    pub nodes: usize,
    pub meta_cache_bytes: u64,
    /// The metadata cache's loads and evictions so far.
    pub meta_loads: u64,
    pub meta_evictions: u64,
}

/// The metadata target over time: the measured decode ratio and the
/// smoothing.
#[derive(Clone, Debug)]
pub struct Sizer {
    pub plan: Plan,
    /// The metadata target applied (before the pool's cap).
    meta: u64,
    want: u64,
    lower_since: Option<Instant>,
    ratio: f64,
    last: (u64, u64),
}

impl Sizer {
    pub fn new(plan: Plan) -> Sizer {
        let meta = plan.initial_meta();
        Sizer { plan, meta, want: 0, lower_since: None, ratio: DEFAULT_META_DECODE_RATIO, last: (u64::MAX, u64::MAX) }
    }

    /// The shortfall is against what the pool can give the metadata cache
    /// (not the smoothed size, which may trail a small growth).
    pub fn split(&self) -> Split {
        Split { meta_want: self.want, shortfall: self.plan.split(self.want).shortfall, ..self.plan.split(self.meta) }
    }

    pub fn ratio(&self) -> f64 {
        self.ratio
    }

    /// Decoded size of the owned metadata, at the measured ratio.
    pub fn need(&self, encoded: u64) -> u64 {
        (encoded as f64 * self.ratio) as u64
    }

    /// The cache's bytes over the owned encoded size, sampled only when the
    /// cache neither loaded nor evicted anything since the last
    /// observation (the owned set is resident), and never below 1 (some of
    /// it isn't loaded). Entries of shards just released inflate it until
    /// evicted, which errs toward a larger cache.
    fn measure(&mut self, o: &Observation) {
        let quiet = (o.meta_loads, o.meta_evictions) == self.last;
        self.last = (o.meta_loads, o.meta_evictions);
        if !quiet || o.encoded == 0 || o.meta_cache_bytes < o.encoded {
            return;
        }
        let sample = (o.meta_cache_bytes as f64 / o.encoded as f64).min(MAX_META_DECODE_RATIO);
        self.ratio = 0.8 * self.ratio + 0.2 * sample;
    }

    /// True when the split changed.
    pub fn observe(&mut self, o: &Observation, now: Instant) -> bool {
        self.measure(o);
        self.want = meta_want(o.encoded, self.ratio, o.nodes);
        if self.plan.meta.is_some() {
            return false;
        }
        let want = self.want.max(MIN_META);
        let was = self.plan.split(self.meta);
        if want as f64 > self.meta as f64 * GROW_STEP {
            self.meta = want;
            self.lower_since = None;
        } else if (want as f64) < self.meta as f64 * SHRINK_STEP {
            let since = *self.lower_since.get_or_insert(now);
            if now.duration_since(since) < SHRINK_HOLD {
                return false;
            }
            self.meta = want;
            self.lower_since = None;
        } else {
            self.lower_since = None;
        }
        self.plan.split(self.meta) != was
    }
}

// ---------------------------------------------------------------- limits

/// Physical RAM, or the cgroup limit when lower.
pub fn limit_bytes() -> Option<u64> {
    let cgroup = if cfg!(target_os = "linux") {
        let own = std::fs::read_to_string("/proc/self/cgroup")
            .ok()
            .and_then(|s| s.lines().find_map(|l| l.strip_prefix("0::").map(|p| p.trim().to_string())));
        cgroup_limit(Path::new("/sys/fs/cgroup"), own.as_deref())
    } else {
        None
    };
    match (sys::physical_memory(), cgroup) {
        (Some(p), Some(c)) => Some(p.min(c)),
        (p, c) => p.or(c),
    }
}

/// The tightest cgroup v2 `memory.max` from our cgroup (`own`, the path in
/// /proc/self/cgroup's `0::` line) up to the mount `root` (a container sees
/// its own cgroup as the root), else cgroup v1's
/// `memory/memory.limit_in_bytes`. "max", or v1's near-u64::MAX, is no limit.
pub fn cgroup_limit(root: &Path, own: Option<&str>) -> Option<u64> {
    let read = |p: PathBuf| std::fs::read_to_string(p).ok()?.trim().parse::<u64>().ok().filter(|v| *v < 1 << 60);
    let mut dir = PathBuf::from(own.unwrap_or("/").trim_start_matches('/'));
    let mut best: Option<u64> = None;
    loop {
        if let Some(v) = read(root.join(&dir).join("memory.max")) {
            best = Some(best.map_or(v, |b| b.min(v)));
        }
        if !dir.pop() {
            break;
        }
    }
    best.or_else(|| read(root.join("memory/memory.limit_in_bytes")))
}

#[cfg(target_os = "linux")]
mod sys {
    pub fn physical_memory() -> Option<u64> {
        let s = std::fs::read_to_string("/proc/meminfo").ok()?;
        let kb: u64 = s.lines().find_map(|l| l.strip_prefix("MemTotal:"))?.split_whitespace().next()?.parse().ok()?;
        Some(kb * 1024)
    }
}

#[cfg(target_os = "macos")]
mod sys {
    pub fn physical_memory() -> Option<u64> {
        extern "C" {
            fn sysctlbyname(
                name: *const std::ffi::c_char,
                old: *mut std::ffi::c_void,
                oldlen: *mut usize,
                new: *mut std::ffi::c_void,
                newlen: usize,
            ) -> i32;
        }
        let (mut v, mut len) = (0u64, std::mem::size_of::<u64>());
        let ok = unsafe {
            sysctlbyname(c"hw.memsize".as_ptr(), &mut v as *mut u64 as *mut _, &mut len, std::ptr::null_mut(), 0)
        } == 0;
        (ok && v > 0).then_some(v)
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod sys {
    pub fn physical_memory() -> Option<u64> {
        None
    }
}

// ---------------------------------------------------------------- runtime

/// Encoded (filter, index) bytes of every SST in `dbs`' manifests.
pub fn sst_meta_bytes<'a>(dbs: impl IntoIterator<Item = &'a slatedb::Db>) -> (u64, u64) {
    let (mut filter, mut index) = (0, 0);
    for db in dbs {
        let m = db.manifest();
        for h in
            m.l0().iter().map(|v| &v.sst).chain(m.compacted().iter().flat_map(|r| r.sst_views().iter().map(|v| &v.sst)))
        {
            filter += h.info.filter_len;
            index += h.info.index_len;
        }
    }
    (filter, index)
}

struct Node {
    table: Weak<PartitionTable>,
    cluster: Weak<crate::cluster::Cluster>,
    workers: Weak<crate::worker::WorkerSenders>,
}

struct Global {
    plan: Plan,
    sizer: parking_lot::Mutex<Sizer>,
    nodes: parking_lot::Mutex<Vec<Node>>,
    short: std::sync::atomic::AtomicBool,
}

static GLOBAL: OnceLock<Global> = OnceLock::new();

/// Sizes the SST caches from `plan` and starts re-planning. The first call
/// in a process wins; returns the plan in force.
pub fn init(plan: Plan) -> &'static Plan {
    let g = GLOBAL.get_or_init(|| {
        let sizer = Sizer::new(plan);
        let s = sizer.split();
        crate::partition::resize_caches(s.block, s.meta);
        tracing::info!(plan = %sizer.plan.to_json(), "memory budget");
        for (k, b) in &sizer.plan.parts {
            crate::metrics::MEMORY_BUDGET.with_label_values(&[k]).set(*b as i64);
        }
        crate::metrics::MEMORY_BUDGET.with_label_values(&["budget"]).set(sizer.plan.budget as i64);
        crate::metrics::MEMORY_BUDGET.with_label_values(&["pool"]).set(sizer.plan.pool as i64);
        std::thread::Builder::new()
            .name("vlpds-memory".into())
            .spawn(|| loop {
                std::thread::sleep(TICK);
                tick(GLOBAL.get().expect("set before the thread starts"));
            })
            .expect("spawning the memory sizer");
        Global {
            plan: sizer.plan.clone(),
            sizer: parking_lot::Mutex::new(sizer),
            nodes: Default::default(),
            short: Default::default(),
        }
    });
    &g.plan
}

/// The split in force (None before [`init`]).
pub fn current() -> Option<Split> {
    GLOBAL.get().map(|g| g.sizer.lock().split())
}

/// Re-plans with this node's owned shards, and sizes its repo cache.
pub fn register(table: &Arc<PartitionTable>, cluster: &Arc<crate::cluster::Cluster>, workers: &crate::worker::Workers) {
    let Some(g) = GLOBAL.get() else { return };
    {
        let mut nodes = g.nodes.lock();
        nodes.retain(|n| n.table.strong_count() > 0);
        nodes.push(Node {
            table: Arc::downgrade(table),
            cluster: Arc::downgrade(cluster),
            workers: Arc::downgrade(&workers.senders),
        });
    }
    tick(g);
    apply_repo(g, g.sizer.lock().split().repo);
}

fn apply_repo(g: &Global, total: u64) {
    let live: Vec<_> = g.nodes.lock().iter().filter_map(|n| n.workers.upgrade()).collect();
    let per = total / live.len().max(1) as u64;
    for w in live {
        w.set_cache_bytes(per as usize);
    }
    crate::metrics::REPO_CACHE_CAPACITY.set(total as i64);
}

fn tick(g: &Global) {
    let (tables, nodes) = {
        let mut list = g.nodes.lock();
        list.retain(|n| n.table.strong_count() > 0);
        let tables: Vec<_> = list.iter().filter_map(|n| n.table.upgrade()).collect();
        let nodes = list.iter().filter_map(|n| n.cluster.upgrade()).map(|c| c.peers().len()).max().unwrap_or(1);
        (tables, nodes)
    };
    let owned: Vec<_> = tables.iter().flat_map(|t| t.owned()).collect();
    let (filter, index) = sst_meta_bytes(owned.iter().map(|p| &*p.db));
    drop(owned);
    let st = crate::partition::cache_stats();
    let o = Observation {
        encoded: filter + index,
        nodes,
        meta_cache_bytes: st.meta_used,
        meta_loads: st.meta_loads,
        meta_evictions: st.meta_evictions,
    };
    let (changed, s, need, ratio) = {
        let mut sizer = g.sizer.lock();
        let changed = sizer.observe(&o, Instant::now());
        (changed, sizer.split(), sizer.need(o.encoded), sizer.ratio())
    };
    if changed {
        crate::partition::resize_caches(s.block, s.meta);
        apply_repo(g, s.repo);
        tracing::info!(
            meta_mb = mb(s.meta),
            block_mb = mb(s.block),
            repo_mb = mb(s.repo),
            owned_meta_mb = mb(need),
            nodes,
            "caches resized"
        );
    }
    use std::sync::atomic::Ordering::Relaxed;
    let was_short = g.short.swap(s.shortfall > 0, Relaxed);
    if s.shortfall > 0 && !was_short {
        tracing::error!(
            want_mb = mb(s.meta_want),
            meta_mb = mb(s.meta),
            short_mb = mb(s.shortfall),
            owned_meta_mb = mb(need),
            "the SST metadata cache can't hold the owned SSTs' filters and indexes with failover headroom: \
             point reads past it fetch whole filters from the store. Give the node more memory, or add nodes"
        );
    } else if s.shortfall == 0 && was_short {
        tracing::info!(meta_mb = mb(s.meta), "the SST metadata cache fits the owned SSTs' metadata again");
    }
    let st = crate::partition::cache_stats();
    let set = |c: &str, k: &str, v: u64| crate::metrics::MEMORY_CACHE.with_label_values(&[c, k]).set(v as i64);
    set("meta", "target", s.meta_want);
    set("meta", "capacity", st.meta_capacity);
    set("meta", "used", st.meta_used);
    set("block", "target", s.block);
    set("block", "capacity", st.block_capacity);
    set("block", "used", st.block_used);
    set("repo", "target", s.repo);
    set("repo", "capacity", s.repo);
    crate::metrics::SST_META_NEED.set(need as i64);
    crate::metrics::META_CACHE_SHORTFALL.set(s.shortfall as i64);
    crate::metrics::SST_META_DECODE_RATIO.set(ratio);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed() -> Fixed {
        Fixed {
            in_memory_caches: None,
            mst_node_cache: 256 * MIB,
            firehose_ring: 512 * MIB,
            live_ring: 128 * MIB,
            merge_queue: 256 * MIB,
            backfill_cache: 256 * MIB,
            backfill_readahead: 64 * MIB,
            max_backfills: 16,
            max_exports: 32,
            import_memory: None,
            space_exports: 0,
        }
    }

    const GIB: u64 = 1 << 30;

    #[test]
    fn budget_arithmetic() {
        let p = plan(&Settings::default(), &fixed(), Some(32 * GIB)).unwrap();
        assert_eq!(p.budget, 32 * GIB);
        assert_eq!(p.part("headroom"), (32.0 * GIB as f64 * HEADROOM_FRACTION) as u64);
        assert_eq!(p.part("in_memory_caches"), (32.0 * GIB as f64 * 0.10) as u64);
        assert_eq!(p.part("firehose"), 896 * MIB);
        assert_eq!(p.part("backfill"), (256 + 64 * 16) * MIB);
        // 32 exports: 8 MiB each + the full 512 MiB read-ahead pool
        assert_eq!(p.part("exports"), (32 * 8 + 512) * MIB);
        // imports: 1/16 of the budget, at most 1 GiB
        assert_eq!(p.part("import"), GIB);
        assert_eq!(p.pool + p.fixed(), p.budget);
        // the pool: metadata first, then block and repo evenly
        let s = p.split(GIB);
        assert_eq!((s.meta, s.shortfall), (GIB, 0));
        assert_eq!(s.block + s.repo + s.meta, p.pool);
        assert!(s.block.abs_diff(s.repo) <= 1);
        // a want over the pool: capped, the rest keeps its floors
        let s = p.split(p.pool * 2);
        assert_eq!((s.block, s.repo), (MIN_CACHE, MIN_CACHE));
        assert_eq!(s.shortfall, p.pool * 2 - s.meta);
        // small wants keep a floor
        assert_eq!(p.split(0).meta, MIN_META);

        // a budget given as a share of the limit, headroom floor on small ones
        let small = Settings { budget: Some("50%".parse().unwrap()), ..Default::default() };
        let tiny = Fixed {
            mst_node_cache: 64 * MIB,
            firehose_ring: 64 * MIB,
            live_ring: 32 * MIB,
            merge_queue: 32 * MIB,
            backfill_cache: 32 * MIB,
            backfill_readahead: 16 * MIB,
            max_backfills: 4,
            max_exports: 4,
            ..fixed()
        };
        let p = plan(&small, &tiny, Some(5 * GIB)).unwrap();
        assert_eq!(p.budget, 5 * GIB / 2);
        assert_eq!(p.part("headroom"), MIN_HEADROOM);
        assert_eq!(p.part("exports"), (4 * 8 + 64) * MIB);
        // imports: 1/16 of 2.5 GiB is under the 192 MiB floor
        assert_eq!(p.part("import"), 192 * MIB);
        // a tiny node still gets ~1 GB of caches
        assert!(p.pool > 768 * MIB && p.pool < 1280 * MIB, "{}", p.pool >> 20);

        // --spaces adds its exports' room; without it there's no such part
        assert_eq!(p.parts.iter().find(|(k, _)| *k == "space_exports"), None);
        let with = plan(&small, &Fixed { space_exports: 54 * MIB, ..tiny.clone() }, Some(5 * GIB)).unwrap();
        assert_eq!(with.part("space_exports"), 54 * MIB);
        assert_eq!(with.pool, p.pool - 54 * MIB);
        assert_eq!(with.parts.last().map(|(k, _)| *k), Some("headroom"));

        // explicit caches keep their sizes; the automatic one gets the rest
        let s = Settings { block: Some(GIB), meta: Some(512 * MIB), ..Default::default() };
        let p = plan(&s, &fixed(), Some(32 * GIB)).unwrap();
        let sp = p.split(10 * GIB);
        assert_eq!((sp.block, sp.meta, sp.repo), (GIB, 512 * MIB, p.pool - GIB - 512 * MIB));
        assert_eq!(sp.shortfall, 10 * GIB - 512 * MIB);
        assert!(
            "x%".parse::<BudgetSpec>().is_err()
                && "0".parse::<BudgetSpec>().is_err()
                && "150%".parse::<BudgetSpec>().is_err()
        );
        assert_eq!("2048".parse::<BudgetSpec>().unwrap(), BudgetSpec::Bytes(2 * GIB));
    }

    #[test]
    fn oversize_flags_are_refused() {
        // explicit caches over the budget
        let s = Settings { block: Some(30 * GIB), ..Default::default() };
        let e = plan(&s, &fixed(), Some(32 * GIB)).unwrap_err().to_string();
        assert!(e.contains("needed but the budget is 32768 MiB"), "{e}");
        // fixed costs alone over a small budget
        let s = Settings { budget: Some(BudgetSpec::Bytes(2 * GIB)), ..Default::default() };
        assert!(plan(&s, &fixed(), Some(32 * GIB)).is_err());
        // a budget over the limit
        let s = Settings { budget: Some(BudgetSpec::Bytes(64 * GIB)), ..Default::default() };
        let e = plan(&s, &fixed(), Some(32 * GIB)).unwrap_err().to_string();
        assert!(e.contains("over this node's memory limit"), "{e}");
        // the same flags fit a bigger node
        let s = Settings { block: Some(8 * GIB), meta: Some(2 * GIB), repo: Some(8 * GIB), ..Default::default() };
        assert!(plan(&s, &fixed(), Some(64 * GIB)).is_ok());
        assert!(plan(&s, &fixed(), Some(24 * GIB)).is_err());
    }

    #[test]
    fn failover_headroom() {
        assert_eq!(meta_want(1000, 1.0, 1), 1250);
        assert_eq!(meta_want(1000, 1.0, 2), 2500);
        assert_eq!(meta_want(1000, 1.0, 4), (1000.0 * 4.0 / 3.0 * 1.25) as u64);
        assert_eq!(meta_want(1000, 1.3, 100), (1000.0 * 1.3 * 100.0 / 99.0 * 1.25) as u64);
    }

    #[test]
    fn smoothing_grows_now_shrinks_after_hold() {
        let p = plan(&Settings::default(), &fixed(), Some(32 * GIB)).unwrap();
        let mut s = Sizer::new(p.clone());
        let t0 = Instant::now();
        let obs = |encoded| Observation { encoded, nodes: 1, ..Default::default() };
        let start = s.split().meta;
        // more than the start: applied at once
        assert!(s.observe(&obs(4 * GIB), t0));
        let big = s.split();
        assert_eq!(big.meta, meta_want(4 * GIB, DEFAULT_META_DECODE_RATIO, 1));
        assert!(big.meta > start && big.block < p.split(start).block);
        // a small wobble doesn't resize
        assert!(!s.observe(&obs(4 * GIB + GIB / 50), t0));
        // lower: held until SHRINK_HOLD passes
        assert!(!s.observe(&obs(GIB), t0));
        assert!(!s.observe(&obs(GIB), t0 + SHRINK_HOLD / 2));
        assert_eq!(s.split().meta, big.meta);
        assert!(s.observe(&obs(GIB), t0 + SHRINK_HOLD));
        assert_eq!(s.split().meta, meta_want(GIB, DEFAULT_META_DECODE_RATIO, 1));
        // a dip that recovers before the hold resets it
        assert!(!s.observe(&obs(GIB / 4), t0 + SHRINK_HOLD * 2));
        assert!(!s.observe(&obs(GIB), t0 + SHRINK_HOLD * 2 + SHRINK_HOLD / 2));
        assert!(!s.observe(&obs(GIB / 4), t0 + SHRINK_HOLD * 3));
        assert!(!s.observe(&obs(GIB / 4), t0 + SHRINK_HOLD * 3 + SHRINK_HOLD / 2));
        // explicit metadata size: never resized
        let mut fixed_meta =
            Sizer::new(plan(&Settings { meta: Some(GIB), ..Default::default() }, &fixed(), Some(32 * GIB)).unwrap());
        assert!(!fixed_meta.observe(&obs(8 * GIB), t0));
        assert_eq!(fixed_meta.split().meta, GIB);
        assert!(fixed_meta.split().shortfall > 0);
    }

    #[test]
    fn decode_ratio_is_measured_when_quiet() {
        let p = plan(&Settings::default(), &fixed(), Some(32 * GIB)).unwrap();
        let mut s = Sizer::new(p);
        let o = |bytes, loads| Observation {
            encoded: 1000,
            nodes: 1,
            meta_cache_bytes: bytes,
            meta_loads: loads,
            meta_evictions: 0,
        };
        s.observe(&o(1600, 1), Instant::now());
        assert_eq!(s.ratio(), DEFAULT_META_DECODE_RATIO, "the first observation has nothing to compare with");
        for _ in 0..50 {
            s.observe(&o(1600, 1), Instant::now());
        }
        assert!((s.ratio() - 1.6).abs() < 0.01, "{}", s.ratio());
        // loading (not all resident yet) or under 1x: no sample
        s.observe(&o(400, 2), Instant::now());
        s.observe(&o(400, 2), Instant::now());
        assert!((s.ratio() - 1.6).abs() < 0.01, "{}", s.ratio());
        // capped
        for _ in 0..50 {
            s.observe(&o(9000, 2), Instant::now());
        }
        assert!(s.ratio() <= MAX_META_DECODE_RATIO + 1e-9);
    }

    /// Owning more shards (SSTs in their manifests) grows the metadata
    /// target; releasing them shrinks it once the hold passes.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn owned_shards_drive_the_meta_target() {
        use vlsync_store::slots::ShardId;
        let store =
            vlsync_store::store::Store { prefix: "memory-sizer".into(), ..vlsync_store::store::Store::memory(None) };
        let mut dbs = Vec::new();
        for i in 0..3u32 {
            let db = crate::partition::open_db(&store, ShardId(i), None).await.unwrap();
            for k in 0..2000u32 {
                db.put(format!("k{i}-{k:06}").as_bytes(), [7u8; 64]).await.unwrap();
            }
            db.flush().await.unwrap();
            dbs.push(db);
        }
        let encoded = |n: usize| {
            let (f, i) = sst_meta_bytes(dbs[..n].iter());
            f + i
        };
        let (one, three) = (encoded(1), encoded(3));
        assert!(one > 0 && three > 2 * one, "{one} {three}");
        let p = plan(&Settings::default(), &fixed(), Some(32 * GIB)).unwrap();
        let mut s = Sizer::new(p);
        // these SSTs hold KBs of metadata: scaled up to production shards'
        // tens of MBs, so the target clears the floor
        const SCALE: u64 = 4096;
        let t0 = Instant::now();
        let obs = |encoded: u64| Observation { encoded: encoded * SCALE, nodes: 2, ..Default::default() };
        // a node that has owned one shard a while
        s.observe(&obs(one), t0);
        s.observe(&obs(one), t0 + SHRINK_HOLD);
        let small = s.split();
        assert_eq!(small.meta_want, meta_want(one * SCALE, DEFAULT_META_DECODE_RATIO, 2));
        assert_eq!(small.meta, small.meta_want.max(MIN_META));
        // acquire two more
        assert!(s.observe(&obs(three), t0 + SHRINK_HOLD * 2));
        let large = s.split();
        assert_eq!(large.meta_want, meta_want(three * SCALE, DEFAULT_META_DECODE_RATIO, 2));
        assert_eq!(large.meta, large.meta_want);
        assert!(large.meta > small.meta && large.block < small.block && large.repo < small.repo);
        // release them: shrinks after the hold
        assert!(!s.observe(&obs(one), t0 + SHRINK_HOLD * 3));
        assert_eq!(s.split().meta, large.meta);
        assert!(s.observe(&obs(one), t0 + SHRINK_HOLD * 4));
        assert_eq!(s.split(), small);
        for db in dbs {
            db.close().await.unwrap();
        }
    }

    #[test]
    fn cgroup_limit_from_a_fake_hierarchy() {
        let root = std::env::temp_dir().join(format!("vlpds-cgroup-{}-{}", std::process::id(), rand::random::<u32>()));
        let leaf = root.join("user.slice/bench.slice/node.scope");
        std::fs::create_dir_all(&leaf).unwrap();
        let w = |p: &Path, v: &str| std::fs::write(p.join("memory.max"), v).unwrap();
        w(&root, "max\n");
        w(&root.join("user.slice"), "max\n");
        w(&root.join("user.slice/bench.slice"), "8589934592\n");
        w(&leaf, "4294967296\n");
        let own = Some("/user.slice/bench.slice/node.scope");
        assert_eq!(cgroup_limit(&root, own), Some(4 << 30));
        // a parent tighter than the leaf wins
        w(&leaf, "17179869184\n");
        assert_eq!(cgroup_limit(&root, own), Some(8 << 30));
        // all "max": no limit; a container (own "/") reads the root
        w(&root.join("user.slice/bench.slice"), "max\n");
        w(&leaf, "max\n");
        assert_eq!(cgroup_limit(&root, own), None);
        w(&root, "2147483648\n");
        assert_eq!(cgroup_limit(&root, Some("/")), Some(2 << 30));
        // cgroup v1
        let v1 = root.join("v1");
        std::fs::create_dir_all(v1.join("memory")).unwrap();
        std::fs::write(v1.join("memory/memory.limit_in_bytes"), "1073741824\n").unwrap();
        assert_eq!(cgroup_limit(&v1, None), Some(1 << 30));
        std::fs::write(v1.join("memory/memory.limit_in_bytes"), "9223372036854771712\n").unwrap();
        assert_eq!(cgroup_limit(&v1, None), None);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn memory_is_detected() {
        let m = limit_bytes().expect("RAM size on linux/macos");
        assert!(m >= 256 << 20, "{m}");
    }
}
