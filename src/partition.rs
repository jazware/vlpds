//! A shard handle and its SlateDB: settings, shared caches, compaction,
//! and clones for split/merge. All shards on a node share its commit log
//! (nodelog.rs).

use crate::nodelog::NodeLog;
pub use crate::nodelog::{seq_floor, AckFn, LogEntry, Watermark};
use crate::slots::ShardId;
use crate::store::Store;
use slatedb::Db;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

pub struct Partition {
    pub id: ShardId,
    pub epoch: u64,
    pub db: Arc<Db>,
    /// Held (write) by the log finalizer across apply + ack; export readers
    /// take it (read) to pair a durable repo view with a SlateDB snapshot.
    pub apply_lock: Arc<tokio::sync::RwLock<()>>,
    /// The node log's intake.
    pub tx: mpsc::Sender<LogEntry>,
    pub wm: Arc<Watermark>,
    pub log: Arc<NodeLog>,
    pub recent: Arc<RecentRepos>,
}

pub const DEFAULT_RECENT_REPOS: usize = 2048;

/// The repos a shard committed to most recently, newest first. Persisted
/// with checkpoints (`nodelog::META_RECENT`) and preloaded by the shard's
/// next owner, so the first writes after a takeover or handback find their
/// repos warm. A hint: a stale entry costs one load.
pub struct RecentRepos {
    cap: usize,
    inner: parking_lot::Mutex<(lru::LruCache<Arc<str>, ()>, bool)>,
}

impl Default for RecentRepos {
    fn default() -> Self {
        RecentRepos::new(DEFAULT_RECENT_REPOS)
    }
}

impl RecentRepos {
    /// `cap` 0 = track nothing.
    pub fn new(cap: usize) -> RecentRepos {
        RecentRepos { cap, inner: parking_lot::Mutex::new((lru::LruCache::unbounded(), false)) }
    }

    pub fn cap(&self) -> usize {
        self.cap
    }

    pub fn touch(&self, did: &Arc<str>) {
        if self.cap == 0 {
            return;
        }
        let mut g = self.inner.lock();
        if g.0.put(did.clone(), ()).is_none() {
            g.1 = true;
            if g.0.len() > self.cap {
                g.0.pop_lru();
            }
        }
    }

    /// Adds a previous owner's list (newest first) behind what's here.
    pub fn seed(&self, dids: &[Arc<str>]) {
        let mut g = self.inner.lock();
        for d in dids {
            if g.0.len() >= self.cap {
                break;
            }
            if !g.0.contains(d) {
                g.0.push(d.clone(), ());
                g.0.demote(d);
            }
        }
    }

    /// Newest first.
    pub fn snapshot(&self) -> Vec<Arc<str>> {
        self.inner.lock().0.iter().map(|(d, _)| d.clone()).collect()
    }

    pub fn is_dirty(&self) -> bool {
        self.inner.lock().1
    }

    /// Newest first, if its members changed since the last call.
    pub fn take_dirty(&self) -> Option<bytes::Bytes> {
        let mut g = self.inner.lock();
        if !std::mem::take(&mut g.1) {
            return None;
        }
        let mut b = Vec::with_capacity(g.0.len() * 33);
        for (d, _) in g.0.iter() {
            b.extend_from_slice(d.as_bytes());
            b.push(b'\n');
        }
        Some(b.into())
    }

    pub fn decode(b: &[u8]) -> Vec<Arc<str>> {
        b.split(|&c| c == b'\n')
            .filter(|d| !d.is_empty())
            .filter_map(|d| std::str::from_utf8(d).ok())
            .map(Arc::from)
            .collect()
    }
}

/// One block/meta cache shared by every shard DB in the process: SlateDB's
/// default private caches per Db grow with the shard count. Sized by
/// src/memory.rs; these are the sizes they start at.
static BLOCK_CACHE_BYTES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(4 << 30);
static META_CACHE_BYTES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1 << 30);
/// 0: none.
static BLOCK_CACHE_PINNED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Tests and benches: a fixed block cache size, as `--block-cache-mb` (the
/// process's memory plan, made by the first node built, takes it).
pub fn set_block_cache_bytes(n: u64) {
    let n = n.max(MIN_BLOCK_CACHE_BYTES);
    BLOCK_CACHE_PINNED.store(n, std::sync::atomic::Ordering::Relaxed);
    resize_caches(n, META_CACHE_BYTES.load(std::sync::atomic::Ordering::Relaxed));
}

pub fn pinned_block_cache_bytes() -> Option<u64> {
    Some(BLOCK_CACHE_PINNED.load(std::sync::atomic::Ordering::Relaxed)).filter(|n| *n > 0)
}

const MIN_BLOCK_CACHE_BYTES: u64 = 16 << 20;
const MIN_META_CACHE_BYTES: u64 = 4 << 20;

/// Resizes the shared caches (or sets the sizes they will be created
/// with). A smaller size evicts down to it now.
pub fn resize_caches(block: u64, meta: u64) {
    use std::sync::atomic::Ordering::Relaxed;
    let block = block.max(MIN_BLOCK_CACHE_BYTES);
    let meta = meta.max(MIN_META_CACHE_BYTES);
    BLOCK_CACHE_BYTES.store(block, Relaxed);
    META_CACHE_BYTES.store(meta, Relaxed);
    if let Some(b) = BLOCK.get() {
        b.resize(block);
    }
    if let Some(m) = META.get() {
        m.0.set_capacity(meta as usize);
        crate::metrics::META_CACHE_CAPACITY.set(meta as i64);
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct CacheStats {
    pub block_capacity: u64,
    pub block_used: u64,
    pub meta_capacity: u64,
    pub meta_used: u64,
    pub meta_loads: u64,
    pub meta_evictions: u64,
}

/// The shared caches now (configured sizes before they exist).
pub fn cache_stats() -> CacheStats {
    use std::sync::atomic::Ordering::Relaxed;
    let mut s = CacheStats {
        block_capacity: BLOCK_CACHE_BYTES.load(Relaxed),
        meta_capacity: META_CACHE_BYTES.load(Relaxed),
        ..Default::default()
    };
    if let Some(b) = BLOCK.get() {
        (s.block_capacity, s.block_used) = (b.capacity(), b.0.usage() as u64);
    }
    if let Some(m) = META.get() {
        s.meta_capacity = m.capacity() as u64;
        s.meta_used = m.bytes() as u64;
        s.meta_loads = m.1.load(Relaxed);
        s.meta_evictions = m.0.evictions();
    }
    s
}

static CACHE_EPOCH: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Benchmarks: DBs opened from now on start cold, as after a restart.
pub fn bump_cache_epoch() {
    CACHE_EPOCH.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

static BLOCK: std::sync::OnceLock<Arc<BlockCache>> = std::sync::OnceLock::new();
static META: std::sync::OnceLock<Arc<MetaCache>> = std::sync::OnceLock::new();

fn shared_db_cache() -> Arc<dyn slatedb::db_cache::DbCache> {
    use slatedb::db_cache::SplitCache;
    static CACHE: std::sync::OnceLock<Arc<dyn slatedb::db_cache::DbCache>> = std::sync::OnceLock::new();
    CACHE
        .get_or_init(|| {
            let block: Arc<dyn slatedb::db_cache::DbCache> = BLOCK
                .get_or_init(|| Arc::new(BlockCache::new(BLOCK_CACHE_BYTES.load(std::sync::atomic::Ordering::Relaxed))))
                .clone();
            let meta: Arc<dyn slatedb::db_cache::DbCache> = shared_meta_cache().clone();
            Arc::new(SplitCache::new().with_block_cache(Some(block)).with_meta_cache(Some(meta)))
        })
        .clone()
}

fn shared_meta_cache() -> &'static Arc<MetaCache> {
    META.get_or_init(|| {
        let meta = Arc::new(MetaCache::new(META_CACHE_BYTES.load(std::sync::atomic::Ordering::Relaxed)));
        crate::metrics::META_CACHE_CAPACITY.set(meta.capacity() as i64);
        crate::metrics::on_render(|| {
            crate::metrics::META_CACHE_BYTES.set(shared_meta_cache().bytes() as i64);
            true
        });
        meta
    })
}

/// The shared SST block cache: Foyer, as SlateDB's `FoyerCache`, which
/// can't be resized. Foyer's `capacity()` keeps the size it was built
/// with, so the current one is kept here.
pub struct BlockCache(
    foyer::Cache<slatedb::db_cache::CachedKey, slatedb::db_cache::CachedEntry>,
    std::sync::atomic::AtomicU64,
);

impl BlockCache {
    pub fn new(bytes: u64) -> BlockCache {
        let shards = std::thread::available_parallelism().map_or(8, |n| n.get());
        BlockCache(
            foyer::CacheBuilder::new(bytes as usize)
                .with_weighter(|_, v: &slatedb::db_cache::CachedEntry| v.size())
                .with_shards(shards)
                .build(),
            std::sync::atomic::AtomicU64::new(bytes),
        )
    }

    pub fn capacity(&self) -> u64 {
        self.1.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn resize(&self, bytes: u64) {
        if self.1.swap(bytes, std::sync::atomic::Ordering::Relaxed) != bytes {
            if let Err(e) = self.0.resize(bytes as usize) {
                tracing::warn!("resizing the SST block cache to {} MiB failed: {e}", bytes >> 20);
            }
        }
    }

    /// Single-flight per key (Foyer's `get_or_fetch`).
    async fn fetch(
        &self,
        key: MetaKey,
        loader: slatedb::db_cache::CacheLoader,
    ) -> Result<slatedb::db_cache::CacheFetch, slatedb::Error> {
        use slatedb::db_cache::CacheFetch;
        let ran = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let r = ran.clone();
        let got = self.0.get_or_fetch(&key, move || {
            r.store(true, std::sync::atomic::Ordering::Relaxed);
            loader()
        });
        match got.await {
            Ok(e) if ran.load(std::sync::atomic::Ordering::Relaxed) => Ok(CacheFetch::miss(e.value().clone())),
            Ok(e) => Ok(CacheFetch::hit(e.value().clone())),
            Err(e) => Err(slatedb::Error::unavailable(format!("SST block cache load: {e}"))),
        }
    }
}

#[async_trait::async_trait]
impl slatedb::db_cache::DbCache for BlockCache {
    async fn get_block(&self, key: &MetaKey) -> Result<Option<MetaEntry>, slatedb::Error> {
        Ok(self.0.get(key).map(|e| e.value().clone()))
    }
    async fn get_index(&self, key: &MetaKey) -> Result<Option<MetaEntry>, slatedb::Error> {
        Ok(self.0.get(key).map(|e| e.value().clone()))
    }
    async fn get_filter(&self, key: &MetaKey) -> Result<Option<MetaEntry>, slatedb::Error> {
        Ok(self.0.get(key).map(|e| e.value().clone()))
    }
    async fn get_stats(&self, key: &MetaKey) -> Result<Option<MetaEntry>, slatedb::Error> {
        Ok(self.0.get(key).map(|e| e.value().clone()))
    }
    async fn insert(&self, key: MetaKey, value: MetaEntry) {
        self.0.insert(key, value);
    }
    async fn remove(&self, key: &MetaKey) {
        self.0.remove(key);
    }
    fn entry_count(&self) -> u64 {
        self.0.entries() as u64
    }
    async fn fetch_block(
        &self,
        key: MetaKey,
        loader: slatedb::db_cache::CacheLoader,
    ) -> Result<slatedb::db_cache::CacheFetch, slatedb::Error> {
        self.fetch(key, loader).await
    }
    async fn fetch_index(
        &self,
        key: MetaKey,
        loader: slatedb::db_cache::CacheLoader,
    ) -> Result<slatedb::db_cache::CacheFetch, slatedb::Error> {
        self.fetch(key, loader).await
    }
    async fn fetch_filter(
        &self,
        key: MetaKey,
        loader: slatedb::db_cache::CacheLoader,
    ) -> Result<slatedb::db_cache::CacheFetch, slatedb::Error> {
        self.fetch(key, loader).await
    }
    async fn fetch_stats(
        &self,
        key: MetaKey,
        loader: slatedb::db_cache::CacheLoader,
    ) -> Result<slatedb::db_cache::CacheFetch, slatedb::Error> {
        self.fetch(key, loader).await
    }
}

type MetaKey = slatedb::db_cache::CachedKey;
type MetaEntry = slatedb::db_cache::CachedEntry;

/// The shared SST metadata cache (filters, indexes, stats); see [`ClockCache`].
pub struct MetaCache(ClockCache<MetaKey, MetaEntry>, std::sync::atomic::AtomicU64);

impl Weigh for MetaEntry {
    fn weight(&self) -> usize {
        self.size()
    }
}

impl MetaCache {
    pub fn new(bytes: u64) -> MetaCache {
        MetaCache(ClockCache::new(bytes), Default::default())
    }

    pub fn capacity(&self) -> usize {
        self.0.capacity()
    }

    pub fn bytes(&self) -> usize {
        self.0.bytes()
    }

    async fn fetch(
        &self,
        key: MetaKey,
        loader: slatedb::db_cache::CacheLoader,
        kind: &'static str,
    ) -> Result<slatedb::db_cache::CacheFetch, slatedb::Error> {
        use slatedb::db_cache::CacheFetch;
        let (entry, how) = self.0.get_or_load(key, loader()).await?;
        Ok(match how {
            Lookup::Hit => CacheFetch::hit(entry),
            Lookup::Shared => {
                crate::metrics::META_CACHE_LOADS.with_label_values(&[kind, "shared"]).inc();
                CacheFetch::hit(entry)
            }
            Lookup::Loaded => {
                self.1.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                crate::metrics::META_CACHE_LOADS.with_label_values(&[kind, "fetched"]).inc();
                CacheFetch::miss(entry)
            }
        })
    }
}

#[async_trait::async_trait]
impl slatedb::db_cache::DbCache for MetaCache {
    async fn get_block(&self, key: &MetaKey) -> Result<Option<MetaEntry>, slatedb::Error> {
        Ok(self.0.get(key))
    }
    async fn get_index(&self, key: &MetaKey) -> Result<Option<MetaEntry>, slatedb::Error> {
        Ok(self.0.get(key))
    }
    async fn get_filter(&self, key: &MetaKey) -> Result<Option<MetaEntry>, slatedb::Error> {
        Ok(self.0.get(key))
    }
    async fn get_stats(&self, key: &MetaKey) -> Result<Option<MetaEntry>, slatedb::Error> {
        Ok(self.0.get(key))
    }
    async fn insert(&self, key: MetaKey, value: MetaEntry) {
        self.0.put(key, value);
    }
    async fn remove(&self, key: &MetaKey) {
        self.0.remove(key);
    }
    fn entry_count(&self) -> u64 {
        self.0.len() as u64
    }
    async fn fetch_index(
        &self,
        key: MetaKey,
        loader: slatedb::db_cache::CacheLoader,
    ) -> Result<slatedb::db_cache::CacheFetch, slatedb::Error> {
        self.fetch(key, loader, "index").await
    }
    async fn fetch_filter(
        &self,
        key: MetaKey,
        loader: slatedb::db_cache::CacheLoader,
    ) -> Result<slatedb::db_cache::CacheFetch, slatedb::Error> {
        self.fetch(key, loader, "filter").await
    }
    async fn fetch_stats(
        &self,
        key: MetaKey,
        loader: slatedb::db_cache::CacheLoader,
    ) -> Result<slatedb::db_cache::CacheFetch, slatedb::Error> {
        self.fetch(key, loader, "stats").await
    }
}

pub(crate) trait Weigh {
    fn weight(&self) -> usize;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Lookup {
    Hit,
    /// A concurrent caller loaded it while this one waited.
    Shared,
    Loaded,
}

/// Per key being loaded: the load's result, for the callers that waited on it.
type LoadLocks<K, V> = parking_lot::Mutex<std::collections::HashMap<K, Arc<tokio::sync::Mutex<Option<V>>>>>;

/// A byte-capped cache for large, read-mostly entries.
///
/// - Hits take a shard's shared lock and set one bit: Foyer takes its
///   shard's mutex on every hit, and every point read of a repo checks the
///   same few SSTs' filters, so threads serialized on those hot keys.
/// - Eviction is CLOCK with a persistent hand per shard that frees only
///   what an insert puts the cache over by. A new entry starts
///   unreferenced, so a one-off load goes before anything hit since the
///   hand last passed. The byte budget is cache-wide: a compacted SST's
///   filter is MBs, a per-shard budget of a few of them overflowed on hash
///   placement alone, and the overflow evicted hot filters.
/// - Loads are single-flight per key. A compacted SST's filter is MBs, and
///   every read of a cold SST waiting on the store otherwise fetched and
///   decoded its own copy: under uniform random keys that is every read of
///   the shard, and the duplicates grow with the store's latency.
pub(crate) struct ClockCache<K, V> {
    shards: Vec<parking_lot::RwLock<ClockShard<K, V>>>,
    loading: Vec<LoadLocks<K, V>>,
    capacity: std::sync::atomic::AtomicUsize,
    bytes: std::sync::atomic::AtomicUsize,
    evictions: std::sync::atomic::AtomicU64,
    hasher: std::hash::RandomState,
}

struct ClockShard<K, V> {
    index: std::collections::HashMap<K, usize>,
    slots: Vec<Option<ClockSlot<K, V>>>,
    free: Vec<usize>,
    hand: usize,
}

struct ClockSlot<K, V> {
    key: K,
    value: V,
    size: usize,
    /// CLOCK bit
    used: std::sync::atomic::AtomicBool,
}

impl<K, V> Default for ClockShard<K, V> {
    fn default() -> Self {
        ClockShard { index: Default::default(), slots: Vec::new(), free: Vec::new(), hand: 0 }
    }
}

impl<K: std::hash::Hash + Eq + Clone, V> ClockShard<K, V> {
    /// Evicts entries the hand finds unreferenced (clearing the bits of the
    /// rest) until it has freed `need` bytes, never `keep` (the entry just
    /// inserted). Returns the bytes freed.
    fn evict(&mut self, need: usize, keep: usize) -> usize {
        self.sweep(need, keep, true)
    }

    /// One turn of the hand taking only unreferenced entries, bits kept.
    fn evict_cold(&mut self, need: usize) -> usize {
        self.sweep(need, usize::MAX, false)
    }

    fn sweep(&mut self, need: usize, keep: usize, clear: bool) -> usize {
        use std::sync::atomic::Ordering::Relaxed;
        let n = self.slots.len();
        let (mut steps, mut freed) = (0, 0);
        let turns = if clear { 2 } else { 1 };
        while freed < need && steps < turns * n {
            let h = self.hand;
            self.hand = (h + 1) % n;
            steps += 1;
            if h == keep {
                continue;
            }
            match &self.slots[h] {
                None => continue,
                Some(s) if clear && s.used.swap(false, Relaxed) => continue,
                Some(s) if !clear && s.used.load(Relaxed) => continue,
                Some(_) => {}
            }
            let s = self.slots[h].take().expect("checked above");
            self.index.remove(&s.key);
            freed += s.size;
            self.free.push(h);
        }
        freed
    }

    fn remove(&mut self, key: &K) -> usize {
        let Some(i) = self.index.remove(key) else { return 0 };
        self.free.push(i);
        self.slots[i].take().expect("indexed slot").size
    }
}

const CLOCK_SHARDS: usize = 64;

impl<K: std::hash::Hash + Eq + Clone, V: Clone + Weigh> ClockCache<K, V> {
    pub fn new(bytes: u64) -> Self {
        ClockCache {
            shards: (0..CLOCK_SHARDS).map(|_| Default::default()).collect(),
            loading: (0..CLOCK_SHARDS).map(|_| Default::default()).collect(),
            capacity: std::sync::atomic::AtomicUsize::new(bytes as usize),
            bytes: Default::default(),
            evictions: Default::default(),
            hasher: Default::default(),
        }
    }

    pub fn capacity(&self) -> usize {
        self.capacity.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Lowering it evicts down to it now.
    pub fn set_capacity(&self, bytes: usize) {
        use std::sync::atomic::Ordering::Relaxed;
        self.capacity.store(bytes, Relaxed);
        let mut over = self.bytes().saturating_sub(bytes);
        // unreferenced entries in every shard before any referenced one
        for (cold, j) in (0..2 * CLOCK_SHARDS).map(|d| (d < CLOCK_SHARDS, d % CLOCK_SHARDS)) {
            if over == 0 {
                break;
            }
            let mut sh = self.shards[j].write();
            let freed = if cold { sh.evict_cold(over) } else { sh.evict(over, usize::MAX) };
            drop(sh);
            self.bytes.fetch_sub(freed, Relaxed);
            self.evictions.fetch_add((freed > 0) as u64, Relaxed);
            over = over.saturating_sub(freed);
        }
    }

    /// Inserts that went over the capacity, and shrinks that evicted.
    pub fn evictions(&self) -> u64 {
        self.evictions.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn bytes(&self) -> usize {
        self.bytes.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn len(&self) -> usize {
        self.shards.iter().map(|s| s.read().index.len()).sum()
    }

    fn shard_of(&self, key: &K) -> usize {
        use std::hash::BuildHasher;
        (self.hasher.hash_one(key) >> 32) as usize % CLOCK_SHARDS
    }

    pub fn get(&self, key: &K) -> Option<V> {
        use std::sync::atomic::Ordering::Relaxed;
        let s = self.shards[self.shard_of(key)].read();
        let slot = s.slots[*s.index.get(key)?].as_ref()?;
        // load first: a hot entry's bit is already set, and a store would
        // bounce its cache line between threads
        if !slot.used.load(Relaxed) {
            slot.used.store(true, Relaxed);
        }
        Some(slot.value.clone())
    }

    pub fn put(&self, key: K, value: V) {
        use std::sync::atomic::Ordering::Relaxed;
        let size = value.weight();
        let home = self.shard_of(&key);
        let mut guard = self.shards[home].write();
        let s = &mut *guard;
        let slot = ClockSlot { key: key.clone(), value, size, used: std::sync::atomic::AtomicBool::new(false) };
        let i = match s.index.get(&key) {
            Some(&i) => {
                let old = s.slots[i].replace(slot).expect("indexed slot");
                self.bytes.fetch_sub(old.size, Relaxed);
                i
            }
            None => {
                let i = match s.free.pop() {
                    Some(i) => {
                        s.slots[i] = Some(slot);
                        i
                    }
                    None => {
                        s.slots.push(Some(slot));
                        s.slots.len() - 1
                    }
                };
                s.index.insert(key, i);
                i
            }
        };
        let mut over = (self.bytes.fetch_add(size, Relaxed) + size).saturating_sub(self.capacity());
        if over == 0 {
            return;
        }
        self.evictions.fetch_add(1, Relaxed);
        let freed = s.evict(over, i);
        self.bytes.fetch_sub(freed, Relaxed);
        over = over.saturating_sub(freed);
        drop(guard);
        // a shard with too little to give: take the rest from the others
        for j in (1..CLOCK_SHARDS).map(|d| (home + d) % CLOCK_SHARDS) {
            if over == 0 {
                break;
            }
            let freed = self.shards[j].write().evict(over, usize::MAX);
            self.bytes.fetch_sub(freed, Relaxed);
            over = over.saturating_sub(freed);
        }
    }

    pub fn remove(&self, key: &K) {
        let freed = self.shards[self.shard_of(key)].write().remove(key);
        self.bytes.fetch_sub(freed, std::sync::atomic::Ordering::Relaxed);
    }

    /// `load` runs only if no concurrent caller is loading `key`; a failed
    /// load leaves the next waiter to try its own.
    pub async fn get_or_load<E>(
        &self,
        key: K,
        load: impl std::future::Future<Output = Result<V, E>>,
    ) -> Result<(V, Lookup), E> {
        if let Some(v) = self.get(&key) {
            return Ok((v, Lookup::Hit));
        }
        let gate = LoadGate::new(&self.loading[self.shard_of(&key)], &key);
        let mut done = gate.lock().await;
        // the leader's result even if the cache dropped it again already
        if let Some(v) = done.clone().or_else(|| self.get(&key)) {
            return Ok((v, Lookup::Shared));
        }
        let v = load.await?;
        *done = Some(v.clone());
        self.put(key, v.clone());
        Ok((v, Lookup::Loaded))
    }
}

/// A key's load lock, dropped from the map by its last holder (also when a
/// waiting caller is cancelled).
struct LoadGate<'a, K: std::hash::Hash + Eq, V> {
    map: &'a LoadLocks<K, V>,
    key: K,
    lock: Option<Arc<tokio::sync::Mutex<Option<V>>>>,
}

impl<'a, K: std::hash::Hash + Eq + Clone, V> LoadGate<'a, K, V> {
    fn new(map: &'a LoadLocks<K, V>, key: &K) -> Self {
        let lock = map.lock().entry(key.clone()).or_default().clone();
        LoadGate { map, key: key.clone(), lock: Some(lock) }
    }

    async fn lock(&self) -> tokio::sync::MutexGuard<'_, Option<V>> {
        self.lock.as_ref().expect("held until drop").lock().await
    }
}

impl<K: std::hash::Hash + Eq, V> Drop for LoadGate<'_, K, V> {
    fn drop(&mut self) {
        let mut m = self.map.lock();
        drop(self.lock.take());
        if m.get(&self.key).is_some_and(|l| Arc::strong_count(l) == 1) {
            m.remove(&self.key);
        }
    }
}

/// Each SST records its codec, so a DB written with another one stays
/// readable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SstCompression {
    None,
    Lz4,
    Zstd,
}

impl std::str::FromStr for SstCompression {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> anyhow::Result<Self> {
        Ok(match s {
            "none" | "off" => SstCompression::None,
            "lz4" => SstCompression::Lz4,
            "zstd" => SstCompression::Zstd,
            _ => anyhow::bail!("unknown SST compression {s:?} (none, lz4, zstd)"),
        })
    }
}

impl SstCompression {
    fn codec(self) -> Option<slatedb::config::CompressionCodec> {
        match self {
            SstCompression::None => None,
            SstCompression::Lz4 => Some(slatedb::config::CompressionCodec::Lz4),
            SstCompression::Zstd => Some(slatedb::config::CompressionCodec::Zstd),
        }
    }
}

static SST_COMPRESSION: parking_lot::RwLock<SstCompression> = parking_lot::RwLock::new(SstCompression::Zstd);

pub fn set_sst_compression(c: SstCompression) {
    *SST_COMPRESSION.write() = c;
}

/// SlateDB GC deletes an unreferenced SST once it is this old, counted from
/// its *creation*. It only guards SSTs written but not yet in a manifest,
/// so it doesn't protect reads: the compactor's checkpoint lifetime does.
static GC_MIN_AGE_SECS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(10 * 60);

pub fn set_gc_min_age(d: Duration) {
    GC_MIN_AGE_SECS.store(d.as_secs(), std::sync::atomic::Ordering::Relaxed);
}

/// Before each manifest update that replaces SSTs, the compactor writes a
/// checkpoint of the old manifest that lives this long, so GC keeps the
/// replaced SSTs for reads that started on it: a scan or snapshot (a big
/// getRepo to a slow client) must finish within it. It also bounds how long
/// replaced SSTs linger. Unit tests: 1 s, so forced detaches complete.
static CHECKPOINT_LIFETIME_SECS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(if cfg!(test) { 1 } else { 3600 });

pub fn set_checkpoint_lifetime(d: Duration) {
    CHECKPOINT_LIFETIME_SECS.store(d.as_secs().max(60), std::sync::atomic::Ordering::Relaxed);
}

/// Tests only: without the 60 s floor (a forced detach waits out the
/// compactor's checkpoints).
#[doc(hidden)]
pub fn set_checkpoint_lifetime_unchecked(d: Duration) {
    CHECKPOINT_LIFETIME_SECS.store(d.as_secs().max(1), std::sync::atomic::Ordering::Relaxed);
}

/// How often each shard DB's GC runs SlateDB's clone detach, which releases
/// a split/merge parent once no live manifest reads its SSTs (then
/// `reshard_gc` deletes the parent's dir). Each run reads the manifest.
static DETACH_INTERVAL_MS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(600_000);

pub fn set_detach_interval(d: Duration) {
    DETACH_INTERVAL_MS.store((d.as_millis() as u64).max(100), std::sync::atomic::Ordering::Relaxed);
}

fn checkpoint_lifetime() -> Duration {
    Duration::from_secs(CHECKPOINT_LIFETIME_SECS.load(std::sync::atomic::Ordering::Relaxed))
}

/// How often a shard DB re-reads its manifest (two GETs per poll per
/// shard). The node is the only writer of its shards' DBs, so reads never
/// wait on it: a poll only picks up the compactor's results, and every
/// flush's manifest CAS already reloads on a conflict. The one case that
/// waits on it, a writer whose view of L0 is full, is refreshed every
/// `FAST_POLL` instead (`spawn_deep_refresh`).
static MANIFEST_POLL_MS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(10_000);

pub fn set_manifest_poll_interval(d: Duration) {
    MANIFEST_POLL_MS.store((d.as_millis() as u64).max(100), std::sync::atomic::Ordering::Relaxed);
}

pub(crate) fn manifest_poll_interval() -> Duration {
    if cfg!(test) {
        return Duration::from_secs(1); // unit tests wait for compaction results
    }
    Duration::from_millis(MANIFEST_POLL_MS.load(std::sync::atomic::Ordering::Relaxed))
}

/// The compactor's and worker's poll interval while L0 is shallow. Nothing
/// waits on it then (shallow L0s cost only bloom-filtered read
/// amplification), and a deep L0 switches to `FAST_POLL`.
static SLOW_POLL_MS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(30_000);

pub fn set_compaction_poll_interval(d: Duration) {
    SLOW_POLL_MS.store((d.as_millis() as u64).max(100), std::sync::atomic::Ordering::Relaxed);
}

fn slow_poll() -> Duration {
    Duration::from_millis(SLOW_POLL_MS.load(std::sync::atomic::Ordering::Relaxed))
}

fn gc_options() -> slatedb::config::GarbageCollectorOptions {
    use slatedb::config::{GarbageCollectorDirectoryOptions, GarbageCollectorOptions};
    let min_age = Duration::from_secs(GC_MIN_AGE_SECS.load(std::sync::atomic::Ordering::Relaxed));
    let detach = Duration::from_millis(if cfg!(test) {
        500
    } else {
        DETACH_INTERVAL_MS.load(std::sync::atomic::Ordering::Relaxed)
    });
    GarbageCollectorOptions {
        compacted_options: Some(GarbageCollectorDirectoryOptions { min_age, ..Default::default() }),
        detach_options: Some(slatedb::config::GarbageCollectorScheduleOptions { interval: Some(detach) }),
        ..Default::default()
    }
}

/// One directory per shard under `dir`, each capped at `shard_bytes`.
#[derive(Clone, Debug)]
pub struct DiskCache {
    pub dir: std::path::PathBuf,
    pub shard_bytes: u64,
}

/// SlateDB's own per-DB default.
const DEFAULT_DISK_CACHE_SHARD_BYTES: u64 = 16 << 30;
/// A few of SlateDB's 4 MiB cache parts.
const MIN_DISK_CACHE_SHARD_BYTES: u64 = 64 << 20;

/// The node budget divided by every shard, not just those owned now, so
/// the caps sum to at most the budget even if this node ends up holding
/// every shard. An explicit `per_shard` wins.
pub fn disk_cache_shard_bytes(node_bytes: Option<u64>, per_shard: Option<u64>, shards: usize) -> u64 {
    let b = match (per_shard, node_bytes) {
        (Some(p), _) => p,
        (None, Some(n)) => n / shards.max(1) as u64,
        (None, None) => DEFAULT_DISK_CACHE_SHARD_BYTES,
    };
    b.max(MIN_DISK_CACHE_SHARD_BYTES)
}

#[derive(Clone, Debug)]
pub struct DiskCacheConfig {
    pub dir: std::path::PathBuf,
    pub node_bytes: Option<u64>,
    pub shard_bytes: Option<u64>,
}

impl DiskCacheConfig {
    pub fn for_shards(&self, shards: usize) -> DiskCache {
        DiskCache {
            dir: self.dir.clone(),
            shard_bytes: disk_cache_shard_bytes(self.node_bytes, self.shard_bytes, shards),
        }
    }
}

fn shard_settings(partition: ShardId, cache: Option<&DiskCache>) -> slatedb::Settings {
    // A whole repo lives in one shard, so one shard must absorb a bulk
    // import: L0 holds more than a slow compaction cycle's worth of ingest
    // (a full L0 stalls the finalizer, and so the whole node). L0s are
    // bloom-filtered, so the cost is read amplification only while
    // compaction lags. `max_unflushed_bytes` only binds on a shard whose
    // flushes are blocked, and then the finalizer stops feeding every shard:
    // no node-wide memtable budget needed. DESIGN.md §4 has the numbers.
    let mut settings = slatedb::Settings {
        wal_enabled: false,
        flush_interval: Some(Duration::from_millis(100)),
        l0_sst_size_bytes: 16 << 20,
        l0_max_ssts: 32,
        l0_max_ssts_per_key: 32,
        // room for the active memtable plus l0_flush_parallelism (4) uploads
        max_unflushed_bytes: 128 << 20,
        manifest_poll_interval: manifest_poll_interval(),
        compression_codec: SST_COMPRESSION.read().codec(),
        garbage_collector_options: Some(gc_options()),
        // started after the open (`spawn_compactor`)
        compactor_options: None,
        ..Default::default()
    };
    if let Some(c) = cache {
        let oc = &mut settings.object_store_cache_options;
        oc.root_folder = Some(c.dir.join(partition.key()));
        oc.max_cache_size_bytes = Some(c.shard_bytes as usize);
        oc.cache_on_flush = true;
        oc.cache_on_compaction = true;
    }
    settings
}

pub async fn open_db(store: &Store, partition: ShardId, cache: Option<&DiskCache>) -> anyhow::Result<Db> {
    let settings = shard_settings(partition, cache);
    let path = db_path(store, partition);
    let codec = settings.compression_codec;
    let id = cache_id(&path);
    let db = crate::metrics::with_slatedb_metrics(Db::builder(path.clone(), store.raw.clone()))
        .with_settings(settings)
        .with_db_cache(shared_db_cache(), id)
        .with_sst_block_size(SST_BLOCK_SIZE)
        .build()
        .await?;
    let raw = external_sst_redirect(&db, &path, store.raw.clone());
    spawn_compactor(&db, path, raw, codec, id);
    Ok(db)
}

/// What a shard's next owner warms, per shard: L0 SSTs (newest first) are
/// fetched whole up to this many bytes, and at most a quarter of the block
/// cache over the whole batch. Every point read and prefix scan touches
/// every L0, so the first cold repo loads would otherwise each fetch their
/// own block of each one.
const WARM_L0_BYTES: u64 = 64 << 20;
const WARM_CONCURRENCY: usize = 64;

/// Fetches the filters and index of every SST of `dbs` into the shared
/// meta cache, and their newest L0s whole into the block cache: one ranged
/// GET per SST component, in bulk, instead of the 10–65 random ones each
/// cold repo load of a freshly moved shard made. Best effort.
///
/// Metadata goes only into the meta cache's free room: warming a takeover's
/// shards into a full cache would push out the hot filters of the shards
/// this node already serves (inserts outpace the reads that re-mark them),
/// a larger loss than the moved shards' first misses, which load once each.
pub async fn warm<D: slatedb::DbCacheManagerOps + slatedb::DbMetadataOps + Send + Sync>(dbs: &[Arc<D>]) {
    use futures::StreamExt;
    use slatedb::CacheTarget;
    let started = std::time::Instant::now();
    let l0_budget = WARM_L0_BYTES.min(cache_stats().block_capacity / 4 / dbs.len().max(1) as u64);
    let meta = shared_meta_cache();
    let mut meta_room = meta.capacity().saturating_sub(meta.bytes()) as u64;
    let mut jobs = Vec::new();
    let mut skipped = 0;
    for db in dbs {
        let m = db.manifest();
        let mut l0_bytes = 0;
        let views = m
            .l0()
            .iter()
            .map(|v| (v, true))
            .chain(m.compacted().iter().flat_map(|r| r.sst_views().iter().map(|v| (v, false))));
        for (v, l0) in views {
            let need = v.sst.info.filter_len + v.sst.info.index_len;
            if need > meta_room {
                skipped += 1;
                continue;
            }
            meta_room -= need;
            if l0 {
                l0_bytes += v.estimate_size();
            }
            jobs.push((db.clone(), v.sst.id, l0 && l0_bytes <= l0_budget));
        }
    }
    let n = jobs.len();
    let failed = futures::stream::iter(jobs)
        .map(|(db, id, whole)| async move {
            let targets: &[CacheTarget] = if whole {
                &[CacheTarget::Filters, CacheTarget::Data((std::ops::Bound::Unbounded, std::ops::Bound::Unbounded))]
            } else {
                &[CacheTarget::Filters, CacheTarget::Index]
            };
            db.warm_sst(id, targets).await.is_err()
        })
        .buffer_unordered(WARM_CONCURRENCY)
        .filter(|f| std::future::ready(*f))
        .count()
        .await;
    crate::metrics::SHARD_WARM_SECONDS.observe(started.elapsed().as_secs_f64());
    crate::metrics::SHARD_WARM_SSTS.with_label_values(&["ok"]).inc_by((n - failed) as u64);
    crate::metrics::SHARD_WARM_SSTS.with_label_values(&["error"]).inc_by(failed as u64);
    tracing::info!(
        shards = dbs.len(),
        ssts = n,
        failed,
        skipped,
        elapsed_ms = started.elapsed().as_millis() as u64,
        "shards warmed"
    );
}

/// A read-only view of a shard another node still writes, sharing the
/// block cache with the `Db` this node opens for it later (same cache id):
/// what a handoff's recipient warms before the shard moves. No checkpoint
/// (the writer never waits on it), and nothing to replay (no WAL).
pub async fn open_reader(store: &Store, partition: ShardId) -> anyhow::Result<slatedb::DbReader> {
    let path = db_path(store, partition);
    let opts = slatedb::config::DbReaderOptions {
        skip_wal_replay: true,
        manifest_poll_interval: Duration::from_secs(3600),
        ..Default::default()
    };
    Ok(slatedb::DbReader::builder(path.clone(), store.raw.clone())
        .with_reader_mode(slatedb::DbReaderMode::FollowLatest)
        .with_options(opts)
        .with_db_cache(shared_db_cache(), cache_id(&path))
        .build()
        .await?)
}

/// Cache ids only need to be distinct per DB in this process (tests open
/// several prefixes with the same shard numbers).
fn cache_id(path: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::hash::DefaultHasher::new();
    path.hash(&mut h);
    CACHE_EPOCH.load(std::sync::atomic::Ordering::Relaxed).hash(&mut h);
    h.finish()
}

/// A cloned shard reads its ancestors' SSTs in place until compaction
/// rewrites them. The DB resolves them through its manifest, but a
/// standalone compactor and worker only know the DB's root, so they get a
/// store that redirects those SST paths. The set only shrinks after the
/// open.
fn external_sst_redirect(
    db: &Db,
    path: &str,
    raw: Arc<dyn object_store::ObjectStore>,
) -> Arc<dyn object_store::ObjectStore> {
    let m = db.manifest();
    let ext = m.external_dbs();
    if ext.is_empty() {
        return raw;
    }
    let mut map = std::collections::HashMap::new();
    for e in ext {
        let resolver = slatedb::PathResolver::new(path.to_string(), &m);
        for id in &e.sst_ids {
            let theirs = resolver.sst_path(id);
            let ours = object_store::path::Path::from(theirs.as_ref().replacen(e.path.as_str(), path, 1));
            map.insert(ours, theirs);
        }
    }
    Arc::new(Redirect { inner: raw, map })
}

#[derive(Debug)]
struct Redirect {
    inner: Arc<dyn object_store::ObjectStore>,
    map: std::collections::HashMap<object_store::path::Path, object_store::path::Path>,
}

impl std::fmt::Display for Redirect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Redirect({})", self.inner)
    }
}

#[async_trait::async_trait]
impl object_store::ObjectStore for Redirect {
    async fn put_opts(
        &self,
        location: &object_store::path::Path,
        payload: object_store::PutPayload,
        opts: object_store::PutOptions,
    ) -> object_store::Result<object_store::PutResult> {
        self.inner.put_opts(location, payload, opts).await
    }
    async fn put_multipart_opts(
        &self,
        location: &object_store::path::Path,
        opts: object_store::PutMultipartOptions,
    ) -> object_store::Result<Box<dyn object_store::MultipartUpload>> {
        self.inner.put_multipart_opts(location, opts).await
    }
    async fn get_opts(
        &self,
        location: &object_store::path::Path,
        options: object_store::GetOptions,
    ) -> object_store::Result<object_store::GetResult> {
        self.inner.get_opts(self.map.get(location).unwrap_or(location), options).await
    }
    fn delete_stream(
        &self,
        locations: futures::stream::BoxStream<'static, object_store::Result<object_store::path::Path>>,
    ) -> futures::stream::BoxStream<'static, object_store::Result<object_store::path::Path>> {
        self.inner.delete_stream(locations)
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
        self.inner.copy_opts(from, to, options).await
    }
}

pub fn db_path(store: &Store, id: ShardId) -> String {
    format!("{}/state/{}", store.prefix, id.key())
}

/// Creates shard `child`'s SlateDB as a clone of `sources` (shard id, slots
/// [lo, hi)), each projected to its slots. O(manifest): the child references
/// the sources' SSTs. The sources must be closed (all their state in SSTs).
/// Idempotent.
pub async fn clone_db(store: &Store, child: ShardId, sources: &[(ShardId, u32, u32)]) -> anyhow::Result<()> {
    anyhow::ensure!(!sources.is_empty(), "clone of shard {child} without sources");
    let srcs: Vec<(String, (bytes::Bytes, bytes::Bytes))> =
        sources.iter().map(|&(id, lo, hi)| (db_path(store, id), crate::state::slot_range_keys(lo, hi))).collect();
    clone_projected(store, db_path(store, child), &clone_checkpoint_name(child), &srcs).await
}

/// Slots [lo, hi) to the key range one family's rows of those slots span.
pub type FamilyRange = fn(u32, u32) -> (bytes::Bytes, bytes::Bytes);

/// [`clone_db`] for a DB that keeps slot-keyed rows under several key
/// families, each family's rows of a slot range one contiguous key range
/// (the first is usually [`crate::state::slot_range_keys`]). Keys outside
/// every family stay with the parent, as with `clone_db`. vlpds itself never
/// calls it: an embedder with more families (vlRelay) opts in.
///
/// SlateDB projects a clone source to one range and takes each source path
/// once, so each family past the first is cloned into a staging DB of its own
/// (O(manifest) too), and the child is the union of the sources and their
/// stages. The stages go once the child is initialized: the child names the
/// SSTs' owners, never a stage.
pub async fn clone_db_families(
    store: &Store,
    child: ShardId,
    sources: &[(ShardId, u32, u32)],
    families: &[FamilyRange],
) -> anyhow::Result<()> {
    anyhow::ensure!(!sources.is_empty(), "clone of shard {child} without sources");
    let Some((first, rest)) = families.split_first() else { anyhow::bail!("clone of shard {child} without families") };
    let path = db_path(store, child);
    let name = clone_checkpoint_name(child);
    let admin = slatedb::admin::AdminBuilder::new(path.clone(), store.raw.clone()).build();
    if !admin.read_manifest(None).await?.is_some_and(|m| m.initialized()) {
        let mut union = Vec::with_capacity(sources.len() * families.len());
        for &(id, lo, hi) in sources {
            union.push((db_path(store, id), first(lo, hi)));
            for (i, f) in rest.iter().enumerate() {
                let stage = stage_path(store, child, id, i + 1);
                clone_projected(store, stage.clone(), &name, &[(db_path(store, id), f(lo, hi))]).await?;
                union.push((stage, f(lo, hi)));
            }
        }
        clone_projected(store, path, &name, &union).await?;
    }
    for &(id, ..) in sources {
        for i in 1..families.len() {
            let s = stage_path(store, child, id, i);
            if let Err(e) = drop_stage(store, &s).await {
                tracing::debug!(stage = %s, "clone stage left behind: {e:#}");
            }
        }
    }
    Ok(())
}

fn stage_path(store: &Store, child: ShardId, src: ShardId, family: usize) -> String {
    // not a shard key, so reshard GC never takes it for a retired shard
    format!("{}.f{family}.{}", db_path(store, child), src.key())
}

/// Releases what a stage pinned in its source (the child pins those SSTs
/// with checkpoints of its own) and deletes it.
async fn drop_stage(store: &Store, stage: &str) -> anyhow::Result<()> {
    use futures::{StreamExt, TryStreamExt};
    let admin = slatedb::admin::AdminBuilder::new(stage.to_string(), store.raw.clone()).build();
    if let Some(m) = admin.read_manifest(None).await? {
        for x in m.external_dbs() {
            let Some(cp) = x.final_checkpoint_id else { continue };
            let src = slatedb::admin::AdminBuilder::new(x.path.clone(), store.raw.clone()).build();
            src.delete_checkpoint(cp).await?;
        }
    }
    let prefix = object_store::path::Path::from(stage);
    let objs: Vec<object_store::path::Path> =
        store.raw.list(Some(&prefix)).map_ok(|m| m.location).try_collect().await?;
    let mut deleted = store.raw.delete_stream(futures::stream::iter(objs.into_iter().map(Ok)).boxed());
    while let Some(r) = deleted.next().await {
        r?;
    }
    Ok(())
}

/// Creates the DB at `path` from `sources` (path, projected key range), each
/// read at a checkpoint named `name`. Idempotent.
async fn clone_projected(
    store: &Store,
    path: String,
    name: &str,
    sources: &[(String, (bytes::Bytes, bytes::Bytes))],
) -> anyhow::Result<()> {
    use std::ops::Bound;
    let admin = slatedb::admin::AdminBuilder::new(path, store.raw.clone()).build();
    // Our own retry check: SlateDB's wants every source named in the
    // clone's manifest, which a source with no SSTs of its own isn't.
    if admin.read_manifest(None).await?.is_some_and(|m| m.initialized()) {
        drop_clone_checkpoints(store, name, sources).await;
        return Ok(());
    }
    // Read each source at a checkpoint of our own, named for the child, and
    // drop it once the clone is initialized (the clone's final checkpoints
    // pin what it reads). SlateDB's own unnamed one could never be dropped
    // for a source the clone's manifest doesn't name, and would hold a
    // retired parent (reshard_gc keeps a dir while any checkpoint lives).
    let mut specs = Vec::with_capacity(sources.len());
    for (src_path, (a, b)) in sources {
        let src = slatedb::admin::AdminBuilder::new(src_path.clone(), store.raw.clone()).build();
        let now = chrono::Utc::now();
        let existing = src
            .list_checkpoints(Some(name))
            .await?
            .into_iter()
            .find(|c| c.expire_time.is_none_or(|t| t > now + chrono::Duration::minutes(5)));
        let cp = match existing {
            Some(c) => c.id,
            None => {
                src.create_detached_checkpoint(&slatedb::config::CheckpointOptions {
                    lifetime: Some(CLONE_CHECKPOINT_LIFETIME),
                    name: Some(name.to_string()),
                    ..Default::default()
                })
                .await?
                .id
            }
        };
        specs.push(
            slatedb::CloneSourceSpec::with_checkpoint(src_path.clone(), cp)
                .with_projection_range((Bound::Included(a.clone()), Bound::Excluded(b.clone()))),
        );
    }
    let mut specs = specs.into_iter();
    let mut b = admin.create_clone_builder_from_source(specs.next().expect("a source"));
    for s in specs {
        b = b.with_source(s);
    }
    b.build().await?;
    drop_clone_checkpoints(store, name, sources).await;
    Ok(())
}

/// If the clone never gets to drop them (a driver died mid-clone).
const CLONE_CHECKPOINT_LIFETIME: Duration = Duration::from_secs(3600);

fn clone_checkpoint_name(child: ShardId) -> String {
    format!("vlpds-clone-{}", child.key())
}

/// Best effort: they expire on their own.
async fn drop_clone_checkpoints(store: &Store, name: &str, sources: &[(String, (bytes::Bytes, bytes::Bytes))]) {
    for (path, _) in sources {
        let src = slatedb::admin::AdminBuilder::new(path.clone(), store.raw.clone()).build();
        let r = async {
            for c in src.list_checkpoints(Some(name)).await? {
                src.delete_checkpoint(c.id).await?;
            }
            anyhow::Ok(())
        };
        if let Err(e) = r.await {
            tracing::debug!(%path, name, "clone source checkpoint left to expire: {e:#}");
        }
    }
}

const SST_BLOCK_SIZE: slatedb::SstBlockSize = slatedb::SstBlockSize::Block16Kib;
/// Compacted SSTs roll at this size (SlateDB: 256 MiB). A point read that
/// misses an SST's filter or index in the meta cache fetches all of it,
/// and both grow with the SST: with the metadata working set over the
/// cache (uniform reads over a big node), smaller SSTs cut every miss's
/// GET by as much. A read still checks one SST per sorted run.
const MAX_SST_BYTES: usize = 64 << 20;

/// Runs a shard's compactor (coordinator + one worker) until the DB
/// closes. Started after the open instead of inside it: the embedded
/// compactor's startup (~12 sequential store calls) delayed serving after a
/// takeover or handback.
fn spawn_compactor(
    db: &Db,
    path: String,
    raw: Arc<dyn object_store::ObjectStore>,
    codec: Option<slatedb::config::CompressionCodec>,
    cache_id: u64,
) {
    spawn_deep_refresh(db);
    let mut status = db.subscribe();
    let watch = db.subscribe();
    tokio::spawn(async move {
        let polling = compaction_polling();
        let mut fast = polling == CompactionPolling::Fast;
        loop {
            let (compactor, worker) = match build_compactor(&path, &raw, codec, fast, cache_id).await {
                Ok(c) => c,
                Err(e) => {
                    tracing::error!(%path, "compaction worker failed to start: {e}");
                    return;
                }
            };
            // SlateDB marks the DB closed *before* its final memtable flush,
            // which waits for L0 room when L0 is full (a close under bulk
            // ingest). So keep compacting until every handle is dropped, at
            // most CLOSE_GRACE: stopping at the close mark deadlocks.
            let closed = async {
                while status.borrow_and_update().close_reason.is_none() {
                    if status.changed().await.is_err() {
                        return;
                    }
                }
                let gone = async { while status.changed().await.is_ok() {} };
                let _ = tokio::time::timeout(CLOSE_GRACE, gone).await;
            };
            let mut switch = false;
            tokio::select! {
                r = compactor.run() => if let Err(e) = r { tracing::warn!(%path, "compactor exited: {e}") },
                r = worker.run() => if let Err(e) = r { tracing::warn!(%path, "compaction worker exited: {e}") },
                _ = closed => {}
                _ = mode_change(&watch, fast), if polling == CompactionPolling::Adaptive => switch = true,
            }
            // a graceful stop hands claimed jobs back as Scheduled, so the
            // restarted worker picks them up again
            let _ = compactor.stop().await;
            let _ = worker.stop().await;
            if !switch {
                return;
            }
            fast = !fast;
            crate::metrics::COMPACTION_POLL_MODE.with_label_values(&[if fast { "fast" } else { "slow" }]).inc();
            tracing::debug!(%path, fast, "compaction polling switched");
        }
    });
}

/// While the writer's L0 runs deep, re-reads its manifest every
/// `FAST_POLL`: once its view of L0 is full no flush runs (whose CAS
/// conflicts would reload it), and only a refresh unblocks it. Holds a
/// handle until the DB is closed.
fn spawn_deep_refresh(db: &Db) {
    let db = db.clone();
    let mut status = db.subscribe();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(FAST_POLL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                r = status.changed() => if r.is_err() { return },
                _ = tick.tick() => {
                    if status.borrow().current_manifest.l0().len() >= DEEP_L0 {
                        let _ = db.refresh_manifest().await;
                    }
                }
            }
            if status.borrow().close_reason.is_some() {
                return;
            }
        }
    });
}

/// How long a closed shard's compactor keeps running for its final flush.
const CLOSE_GRACE: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompactionPolling {
    /// Cheapest idle, but an unpaced bulk ingest into one shard fills L0
    /// between cycles and backpressures.
    Slow,
    Fast,
    /// Slow while L0 is shallow, fast while it is deep.
    Adaptive,
}

impl std::str::FromStr for CompactionPolling {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> anyhow::Result<Self> {
        Ok(match s {
            "slow" => CompactionPolling::Slow,
            "fast" => CompactionPolling::Fast,
            "adaptive" => CompactionPolling::Adaptive,
            _ => anyhow::bail!("unknown compaction polling {s:?} (slow, fast, adaptive)"),
        })
    }
}

static COMPACTION_POLLING: parking_lot::RwLock<CompactionPolling> =
    parking_lot::RwLock::new(CompactionPolling::Adaptive);

pub fn set_compaction_polling(p: CompactionPolling) {
    *COMPACTION_POLLING.write() = p;
}

fn compaction_polling() -> CompactionPolling {
    *COMPACTION_POLLING.read()
}

const FAST_POLL: Duration = Duration::from_millis(500);
/// Adaptive: go fast at this many L0 SSTs (the writer is producing them
/// faster than slow cycles drain them), back to slow once L0 has stayed at
/// or below `CALM_L0` for `CALM_FOR`.
const DEEP_L0: usize = 8;
const CALM_L0: usize = 2;
const CALM_FOR: Duration = Duration::from_secs(15);

/// Resolves when an adaptive compactor in mode `fast` should switch. Holds
/// no DB handle, so the DB can drop.
async fn mode_change(status: &tokio::sync::watch::Receiver<slatedb::DbStatus>, fast: bool) {
    let mut calm_since = None;
    loop {
        tokio::time::sleep(Duration::from_millis(250)).await;
        let l0 = status.borrow().current_manifest.l0().len();
        if !fast {
            if l0 >= DEEP_L0 {
                return;
            }
            continue;
        }
        if l0 > CALM_L0 {
            calm_since = None;
        } else if calm_since.get_or_insert_with(std::time::Instant::now).elapsed() >= CALM_FOR {
            return;
        }
    }
}

async fn build_compactor(
    path: &str,
    raw: &Arc<dyn object_store::ObjectStore>,
    codec: Option<slatedb::config::CompressionCodec>,
    fast: bool,
    cache_id: u64,
) -> Result<(slatedb::compactor::Compactor, slatedb::CompactionWorker), slatedb::Error> {
    use slatedb::config::{CompactionWorkerOptions, CompactorOptions};
    let poll = if cfg!(test) {
        Duration::from_millis(100) // unit tests wait for compactions
    } else if fast {
        FAST_POLL
    } else {
        slow_poll()
    };
    let opts = CompactorOptions {
        worker: None,
        checkpoint_lifetime: checkpoint_lifetime(),
        poll_interval: poll,
        ..Default::default()
    };
    let worker_opts = CompactionWorkerOptions {
        compression_codec: codec,
        compactions_poll_interval: poll,
        max_sst_size: MAX_SST_BYTES,
        ..Default::default()
    };
    let compactor = slatedb::CompactorBuilder::new(path.to_string(), raw.clone()).with_options(opts);
    // the output's index and filters go straight into the DB's cache: every
    // read touching a new sorted run otherwise misses on them at once
    let worker = slatedb::CompactionWorkerBuilder::new(path.to_string(), raw.clone())
        .with_options(worker_opts)
        .with_sst_block_size(SST_BLOCK_SIZE)
        .with_db_cache(shared_db_cache(), cache_id);
    #[cfg(feature = "slatedb-metrics")]
    let (compactor, worker) = (
        compactor.with_metrics_recorder(crate::metrics::slatedb_recorder()),
        worker.with_metrics_recorder(crate::metrics::slatedb_recorder()),
    );
    Ok((compactor.build(), worker.build().await?))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Process CPU time (user + system), so contention on a busy machine
    /// inflates the wall times below but not these.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn cpu() -> Duration {
        #[repr(C)]
        struct Timeval {
            sec: i64,
            #[cfg(target_os = "macos")]
            usec: i32,
            #[cfg(target_os = "linux")]
            usec: i64,
        }
        #[repr(C)]
        struct Rusage {
            utime: Timeval,
            stime: Timeval,
            rest: [i64; 14],
        }
        extern "C" {
            fn getrusage(who: i32, usage: *mut Rusage) -> i32;
        }
        let mut r: Rusage = unsafe { std::mem::zeroed() };
        unsafe { getrusage(0, &mut r) };
        let t = |v: &Timeval| Duration::from_secs(v.sec as u64) + Duration::from_micros(v.usec as u64);
        t(&r.utime) + t(&r.stime)
    }

    /// SST bytes and read/write time per codec on real records: a repo CAR
    /// (`VLPDS_BENCH_CAR`, e.g. a getRepo export) written as `VLPDS_BENCH_COPIES`
    /// repos (default 4) of state rows (R/ value + c/ index key, as the worker
    /// writes them), flushed to L0 SSTs, then reopened cold and read back.
    /// `VLPDS_BENCH_CAR=~/repo.car cargo test --lib partition::tests::compression -- --ignored --nocapture`
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore]
    async fn compression() {
        use crate::cid::Cid;
        use std::collections::HashMap;
        let path = std::env::var("VLPDS_BENCH_CAR").expect("VLPDS_BENCH_CAR=path/to/repo.car");
        let copies: usize = std::env::var("VLPDS_BENCH_COPIES").ok().and_then(|v| v.parse().ok()).unwrap_or(4);
        let car = std::fs::read(path).unwrap();
        let (roots, blocks) = crate::car::read_car(&car).unwrap();
        let blocks: HashMap<Cid, Vec<u8>> = blocks.into_iter().map(|(c, b)| (c, b.to_vec())).collect();
        let commit = crate::cbor::Value::decode(&blocks[&roots[0]]).unwrap();
        let Some(crate::cbor::Value::Link(data)) = commit.get("data") else { panic!("no data in commit") };
        let tree = crate::mst::Tree::load_from_blocks(&blocks, *data).unwrap();
        let mut records = Vec::new();
        tree.walk(&mut |k, c| records.push((String::from_utf8(k.to_vec()).unwrap(), c)));
        let raw: usize = records.iter().map(|(_, c)| blocks[c].len()).sum();
        println!(
            "{} records x {copies} repos, {:.1} MiB of record bytes per repo",
            records.len(),
            raw as f64 / (1 << 20) as f64
        );
        for codec in [SstCompression::None, SstCompression::Lz4, SstCompression::Zstd] {
            set_sst_compression(codec);
            // two copies: one read by a scan, one by point gets, each cold
            let mut stores = Vec::new();
            let (mut write, mut sst, mut logical) = (Duration::ZERO, 0u64, 0usize);
            for half in ["scan", "get"] {
                let store = Store { prefix: format!("bench-{codec:?}-{half}"), ..Store::memory(None) };
                let db = open_db(&store, ShardId(0), None).await.unwrap();
                let t = cpu();
                logical = 0;
                for r in 0..copies {
                    let did = crate::state::bulk_did(r as u64);
                    for chunk in records.chunks(2000) {
                        let mut wb = slatedb::WriteBatch::new();
                        for (path, cid) in chunk {
                            let v = crate::state::record_value(cid, 1, &blocks[cid]);
                            let k = crate::state::record_key(&did, 0, path);
                            let ck = crate::state::record_cid_key(&did, 0, cid, path);
                            logical += k.len() + v.len() + ck.len();
                            wb.put(&k, &v);
                            wb.put(&ck, b"");
                        }
                        db.write(wb).await.unwrap();
                    }
                }
                db.close().await.unwrap();
                write = cpu() - t;
                sst = 0;
                let prefix = object_store::path::Path::from(format!("{}/state/0000000000", store.prefix));
                let mut list = store.raw.list(Some(&prefix));
                use futures::StreamExt;
                while let Some(m) = list.next().await {
                    let m = m.unwrap();
                    if m.location.as_ref().ends_with(".sst") {
                        sst += m.size;
                    }
                }
                stores.push(store);
            }
            let db = open_db(&stores[0], crate::slots::ShardId(0), None).await.unwrap();
            let t = cpu();
            let mut n = 0;
            let mut it = db.scan(b"R/".to_vec()..b"R0".to_vec()).await.unwrap();
            while let Some(_kv) = it.next().await.unwrap() {
                n += 1;
            }
            let scan = cpu() - t;
            drop(it);
            db.close().await.unwrap();
            let db = open_db(&stores[1], crate::slots::ShardId(0), None).await.unwrap();
            let step = (records.len() / 5000).max(1);
            let t = cpu();
            let mut gets = 0;
            for r in 0..copies {
                let did = crate::state::bulk_did(r as u64);
                for (path, _) in records.iter().skip(r).step_by(step * copies) {
                    assert!(db.get(crate::state::record_key(&did, 0, path)).await.unwrap().is_some());
                    gets += 1;
                }
            }
            let get = cpu() - t;
            db.close().await.unwrap();
            println!(
                "{codec:?}: SST {:.1} MiB ({:.2}x of {:.1} MiB of rows); CPU: write+flush {:.0} ms, cold scan of {n} rows {:.0} ms, {gets} cold gets {:.1} us/get",
                sst as f64 / (1 << 20) as f64,
                logical as f64 / sst as f64,
                logical as f64 / (1 << 20) as f64,
                write.as_secs_f64() * 1e3,
                scan.as_secs_f64() * 1e3,
                get.as_secs_f64() * 1e6 / gets as f64,
            );
        }
        set_sst_compression(SstCompression::Zstd);
    }

    /// The compactor started after the open compacts L0 into sorted runs
    /// that read back (in the DB's SST format), and stops with the DB.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn deferred_compactor_compacts() {
        let store = Store { prefix: "compact".into(), ..Store::memory(None) };
        let db = open_db(&store, ShardId(0), None).await.unwrap();
        for i in 0..8u32 {
            for j in 0..200u32 {
                db.put(format!("k{j:04}"), format!("value {i} {j} {}", "x".repeat(100))).await.unwrap();
            }
            db.flush_with_options(slatedb::config::FlushOptions { flush_type: slatedb::config::FlushType::MemTable })
                .await
                .unwrap();
        }
        let t = std::time::Instant::now();
        loop {
            let m = db.manifest();
            if m.l0().len() < 8 && !m.compacted().is_empty() {
                break;
            }
            assert!(t.elapsed() < Duration::from_secs(30), "no compaction: {} L0s", m.l0().len());
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        // the manifest update that replaced the L0s carries the compactor's
        // checkpoint of the old manifest, with our lifetime (what keeps the
        // replaced SSTs for in-flight reads, and nothing longer). Looked up in
        // the stored manifest history, not the writer's latest view: test
        // checkpoints live 1 s and the GC (detach ticks every 500 ms) drops
        // expired ones, so on a loaded machine it can be gone before the
        // writer's next manifest poll shows the compaction.
        let admin = slatedb::admin::AdminBuilder::new(db_path(&store, ShardId(0)), store.raw.clone()).build();
        let manifests = admin.list_manifests(..).await.unwrap();
        let cp = manifests
            .iter()
            .flat_map(|m| m.checkpoints().iter().filter_map(|c| Some(c.expire_time? - c.create_time)))
            .max()
            .expect("compactor checkpoint");
        assert_eq!(cp.num_seconds() as u64, checkpoint_lifetime().as_secs());
        db.close().await.unwrap();
        let db = open_db(&store, ShardId(0), None).await.unwrap();
        assert_eq!(
            db.get(b"k0123").await.unwrap().as_deref(),
            Some(format!("value 7 123 {}", "x".repeat(100)).as_bytes())
        );
        db.close().await.unwrap();
    }

    /// Counts GETs of SST objects.
    #[derive(Debug)]
    struct SstGets {
        inner: Arc<dyn object_store::ObjectStore>,
        n: std::sync::atomic::AtomicU64,
    }

    impl SstGets {
        fn take(&self) -> u64 {
            self.n.swap(0, std::sync::atomic::Ordering::Relaxed)
        }
    }

    impl std::fmt::Display for SstGets {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "SstGets")
        }
    }

    #[async_trait::async_trait]
    impl object_store::ObjectStore for SstGets {
        async fn put_opts(
            &self,
            l: &object_store::path::Path,
            p: object_store::PutPayload,
            o: object_store::PutOptions,
        ) -> object_store::Result<object_store::PutResult> {
            self.inner.put_opts(l, p, o).await
        }
        async fn put_multipart_opts(
            &self,
            l: &object_store::path::Path,
            o: object_store::PutMultipartOptions,
        ) -> object_store::Result<Box<dyn object_store::MultipartUpload>> {
            self.inner.put_multipart_opts(l, o).await
        }
        async fn get_opts(
            &self,
            l: &object_store::path::Path,
            o: object_store::GetOptions,
        ) -> object_store::Result<object_store::GetResult> {
            if l.as_ref().ends_with(".sst") {
                self.n.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                // a store round trip, so concurrent readers overlap
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            self.inner.get_opts(l, o).await
        }
        fn delete_stream(
            &self,
            l: futures::stream::BoxStream<'static, object_store::Result<object_store::path::Path>>,
        ) -> futures::stream::BoxStream<'static, object_store::Result<object_store::path::Path>> {
            self.inner.delete_stream(l)
        }
        fn list(
            &self,
            p: Option<&object_store::path::Path>,
        ) -> futures::stream::BoxStream<'static, object_store::Result<object_store::ObjectMeta>> {
            self.inner.list(p)
        }
        async fn list_with_delimiter(
            &self,
            p: Option<&object_store::path::Path>,
        ) -> object_store::Result<object_store::ListResult> {
            self.inner.list_with_delimiter(p).await
        }
        async fn copy_opts(
            &self,
            f: &object_store::path::Path,
            t: &object_store::path::Path,
            o: object_store::CopyOptions,
        ) -> object_store::Result<()> {
            self.inner.copy_opts(f, t, o).await
        }
    }

    /// A shard with `l0s` L0 SSTs of 200 keys each, closed: (store, counter).
    async fn shard_with_l0s(prefix: &str, l0s: u32) -> (Store, Arc<SstGets>) {
        let gets = Arc::new(SstGets { inner: Arc::new(object_store::memory::InMemory::new()), n: Default::default() });
        let store = Store { prefix: prefix.into(), raw: gets.clone(), ..Store::memory(None) };
        let db = open_db(&store, ShardId(0), None).await.unwrap();
        for i in 0..l0s {
            for j in 0..200u32 {
                db.put(format!("k{i:02}-{j:04}"), "v".repeat(64)).await.unwrap();
            }
            db.flush_with_options(slatedb::config::FlushOptions { flush_type: slatedb::config::FlushType::MemTable })
                .await
                .unwrap();
        }
        db.close().await.unwrap();
        (store, gets)
    }

    /// Concurrent cold reads of one shard share each SST's filter fetch
    /// (the meta cache is single-flight) instead of each fetching them all.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn cold_reads_fetch_each_filter_once() {
        let (store, gets) = shard_with_l0s("singleflight", 6).await;
        let db = Arc::new(open_db(&store, ShardId(0), None).await.unwrap());
        let m = db.manifest();
        let ssts = (m.l0().len() + m.compacted().iter().map(|r| r.sst_views().len()).sum::<usize>()) as u64;
        gets.take();
        // absent keys: each get reads every L0's filter and nothing else
        let reads: Vec<_> = (0..64)
            .map(|i| {
                let db = db.clone();
                tokio::spawn(async move { db.get(format!("absent-{i}")).await.unwrap() })
            })
            .collect();
        for r in reads {
            assert!(r.await.unwrap().is_none());
        }
        let n = gets.take();
        assert!(n <= 2 * ssts, "{n} SST GETs for 64 concurrent cold reads over {ssts} SSTs");
        db.close().await.unwrap();
    }

    /// After `warm`, reading every key of a reopened shard (all in L0s)
    /// needs no SST GET at all.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn warm_fetches_l0s_whole() {
        let (store, gets) = shard_with_l0s("warm", 3).await;
        let db = Arc::new(open_db(&store, ShardId(0), None).await.unwrap());
        gets.take();
        warm(std::slice::from_ref(&db)).await;
        let l0 = db.manifest().l0().len() as u64;
        let n = gets.take();
        assert!(n <= 3 * l0, "warm made {n} SST GETs for {l0} L0s");
        for i in 0..3u32 {
            for j in (0..200u32).step_by(7) {
                assert!(db.get(format!("k{i:02}-{j:04}")).await.unwrap().is_some());
            }
        }
        assert_eq!(gets.take(), 0, "reads after warm went to the store");
        db.close().await.unwrap();
    }

    /// A reader of a shard another handle writes shares its cache entries
    /// with the `Db` opened for it later: what a handoff recipient warms
    /// through it is a hit once it owns the shard.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn reader_warms_the_later_db() {
        let (store, gets) = shard_with_l0s("reader-warm", 3).await;
        let reader = Arc::new(open_reader(&store, ShardId(0)).await.unwrap());
        warm(std::slice::from_ref(&reader)).await;
        reader.close().await.unwrap();
        let db = open_db(&store, ShardId(0), None).await.unwrap();
        gets.take();
        for i in 0..3u32 {
            assert!(db.get(format!("k{i:02}-0100")).await.unwrap().is_some());
        }
        assert_eq!(gets.take(), 0, "the Db re-fetched what the reader warmed");
        db.close().await.unwrap();
    }

    /// Object-store calls (sequential round trips) a shard open makes: a
    /// fresh DB, then a reopen of one with data, on a store that takes 20 ms
    /// per call. `cargo test --lib partition::tests::open_calls -- --ignored --nocapture`
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore]
    async fn open_calls() {
        use object_store::throttle::{ThrottleConfig, ThrottledStore};
        let mem = Arc::new(object_store::memory::InMemory::new());
        let d = Duration::from_millis(20);
        let cfg = ThrottleConfig {
            wait_get_per_call: d,
            wait_put_per_call: d,
            wait_list_per_call: d,
            wait_delete_per_call: d,
            ..Default::default()
        };
        let store = Store { raw: Arc::new(ThrottledStore::new(mem, cfg)), ..Store::memory(None) };
        for round in ["fresh", "reopen"] {
            let t = std::time::Instant::now();
            let db = open_db(&store, ShardId(0), None).await.unwrap();
            let open = t.elapsed();
            db.put(b"k", b"v").await.unwrap();
            db.close().await.unwrap();
            println!(
                "{round}: open {:.0} ms (~{:.0} calls at 20 ms)",
                open.as_secs_f64() * 1e3,
                open.as_secs_f64() / 0.02
            );
        }
    }
}

#[cfg(test)]
mod clone_tests {
    use super::*;

    fn k(slot: u16, rest: &str) -> Vec<u8> {
        crate::state::slot_family(slot, rest.as_bytes())
    }

    async fn count(db: &Db) -> usize {
        let mut n = 0;
        let mut it = db.scan(..).await.unwrap();
        while it.next().await.unwrap().is_some() {
            n += 1;
        }
        n
    }

    /// A split is two projected clones of the parent, a merge one clone of
    /// two sources: each child sees exactly its slots (never the parent's
    /// shard-wide keys), writes and compacts on its own (its compactor reads
    /// inherited SSTs through the redirect), and clones again.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn split_and_merge_by_clone() {
        let store = Store { prefix: "clone".into(), ..Store::memory(None) };
        let db = open_db(&store, ShardId(0), None).await.unwrap();
        for s in [0u16, 100, 32767, 32768, 50000, 65535] {
            for i in 0..50 {
                db.put(k(s, &format!("h/did{i:03}")), format!("v{s}-{i}")).await.unwrap();
            }
        }
        db.put(crate::nodelog::META_APPLIED, b"m").await.unwrap();
        db.close().await.unwrap();
        clone_db(&store, ShardId(1), &[(ShardId(0), 0, 32768)]).await.unwrap();
        clone_db(&store, ShardId(1), &[(ShardId(0), 0, 32768)]).await.expect("a retried clone is a no-op");
        clone_db(&store, ShardId(2), &[(ShardId(0), 32768, 65536)]).await.unwrap();
        // an empty parent clones too
        open_db(&store, ShardId(9), None).await.unwrap().close().await.unwrap();
        clone_db(&store, ShardId(10), &[(ShardId(9), 0, 100)]).await.unwrap();
        let e = open_db(&store, ShardId(10), None).await.unwrap();
        assert_eq!(count(&e).await, 0);
        e.close().await.unwrap();

        let c1 = open_db(&store, ShardId(1), None).await.unwrap();
        let c2 = open_db(&store, ShardId(2), None).await.unwrap();
        assert!(c1.get(crate::nodelog::META_APPLIED).await.unwrap().is_none(), "shard-wide keys stay with the parent");
        assert!(c1.get(k(100, "h/did001")).await.unwrap().is_some());
        assert!(c1.get(k(50000, "h/did001")).await.unwrap().is_none());
        assert!(c2.get(k(50000, "h/did001")).await.unwrap().is_some());
        assert_eq!((count(&c1).await, count(&c2).await), (150, 150));
        for r in 0..10 {
            for i in 0..50 {
                c1.put(k(100, &format!("h/new{r}{i:03}")), "x").await.unwrap();
                c1.delete(k(0, &format!("h/did{i:03}"))).await.unwrap();
            }
            c1.flush_with_options(slatedb::config::FlushOptions { flush_type: slatedb::config::FlushType::MemTable })
                .await
                .unwrap();
        }
        let t = std::time::Instant::now();
        loop {
            let m = c1.manifest();
            if m.l0().len() < 4 && !m.compacted().is_empty() {
                break;
            }
            assert!(t.elapsed() < Duration::from_secs(30), "child never compacted: {} L0s", m.l0().len());
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(c1.get(k(0, "h/did001")).await.unwrap().is_none());
        assert!(c1.get(k(100, "h/did001")).await.unwrap().is_some());
        c1.close().await.unwrap();
        c2.close().await.unwrap();
        clone_db(&store, ShardId(3), &[(ShardId(1), 0, 32768), (ShardId(2), 32768, 65536)]).await.unwrap();
        let m = open_db(&store, ShardId(3), None).await.unwrap();
        assert_eq!(count(&m).await, 600 + 150);
        m.put(k(65535, "h/zz"), "z").await.unwrap();
        m.close().await.unwrap();
        let m = open_db(&store, ShardId(3), None).await.unwrap();
        assert!(m.get(k(65535, "h/zz")).await.unwrap().is_some());
        assert!(m.get(k(100, "h/new9001")).await.unwrap().is_some());
        m.close().await.unwrap();
    }

    fn tagged(tag: u8) -> impl Fn(u16, &str) -> Vec<u8> {
        move |slot, rest| [&[tag][..], &slot.to_be_bytes(), rest.as_bytes()].concat()
    }

    fn tag_range(tag: u8, lo: u32, hi: u32) -> (bytes::Bytes, bytes::Bytes) {
        let at = |s: u32| -> bytes::Bytes {
            if s >= crate::slots::SLOTS {
                bytes::Bytes::copy_from_slice(&[tag + 1])
            } else {
                bytes::Bytes::copy_from_slice(&[&[tag][..], &(s as u16).to_be_bytes()].concat())
            }
        };
        (at(lo), at(hi))
    }

    const FAMILIES: &[FamilyRange] =
        &[crate::state::slot_range_keys, |lo, hi| tag_range(0x02, lo, hi), |lo, hi| tag_range(0x03, lo, hi)];

    /// Every family's rows follow their slots through a split and a merge
    /// (an empty family included), shard-wide keys stay behind, and no stage
    /// or clone checkpoint outlives the clone.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn clone_with_families_splits_and_merges_every_family() {
        let store = Store { prefix: "fam".into(), ..Store::memory(None) };
        let (two, three) = (tagged(0x02), tagged(0x03));
        let db = open_db(&store, ShardId(0), None).await.unwrap();
        let slots = [0u16, 100, 32767, 32768, 50000, 65535];
        for s in slots {
            for i in 0..20 {
                db.put(k(s, &format!("d/{i:03}")), "r").await.unwrap();
                db.put(three(s, &format!("{i:03}")), "seed").await.unwrap();
            }
        }
        db.put(b"meta/applied/log-a", b"m").await.unwrap();
        db.close().await.unwrap();
        let fam = |c: u32, srcs: Vec<(ShardId, u32, u32)>| {
            let store = store.clone();
            async move { clone_db_families(&store, ShardId(c), &srcs, FAMILIES).await.unwrap() }
        };
        fam(1, vec![(ShardId(0), 0, 32768)]).await;
        fam(1, vec![(ShardId(0), 0, 32768)]).await;
        fam(2, vec![(ShardId(0), 32768, 65536)]).await;
        for (id, lo, hi) in [(1u32, 0u32, 32768u32), (2, 32768, 65536)] {
            let c = open_db(&store, ShardId(id), None).await.unwrap();
            assert!(c.get(b"meta/applied/log-a").await.unwrap().is_none());
            for s in slots {
                let mine = (lo..hi).contains(&(s as u32));
                assert_eq!(c.get(k(s, "d/001")).await.unwrap().is_some(), mine, "shard {id} slot {s}");
                assert_eq!(c.get(three(s, "001")).await.unwrap().is_some(), mine, "shard {id} slot {s}");
            }
            assert_eq!(count(&c).await, 3 * 20 * 2);
            c.put(two(lo as u16 + 1, "host"), "h").await.unwrap();
            c.close().await.unwrap();
        }
        fam(3, vec![(ShardId(1), 0, 32768), (ShardId(2), 32768, 65536)]).await;
        let m = open_db(&store, ShardId(3), None).await.unwrap();
        assert_eq!(count(&m).await, 6 * 20 * 2 + 2);
        assert!(m.get(two(1, "host")).await.unwrap().is_some());
        assert!(m.get(two(32769, "host")).await.unwrap().is_some());
        assert!(m.get(three(65535, "019")).await.unwrap().is_some());
        m.close().await.unwrap();
        let r = store.raw.list_with_delimiter(Some(&format!("{}/state", store.prefix).into())).await.unwrap();
        let dirs: Vec<String> = r.common_prefixes.iter().filter_map(|p| p.filename().map(str::to_string)).collect();
        assert_eq!(dirs.len(), 4, "stages left: {dirs:?}");
        for id in [0u32, 1, 2] {
            let admin = slatedb::admin::AdminBuilder::new(db_path(&store, ShardId(id)), store.raw.clone()).build();
            let cps = admin.list_checkpoints(None).await.unwrap();
            assert!(cps.iter().all(|c| c.expire_time.is_none() && c.name.is_none()), "shard {id}: {cps:?}");
        }
    }

    /// Regression: a families clone gives the child each parent L0 SST once
    /// per family (a view per projection, the stages' after the parent's).
    /// Once the child's compactor took some, SlateDB's L0 merge cut at the
    /// wrong copy of the compacted SST and the writer's next flush failed
    /// with `InvalidClockTick` (fixed upstream, #2134).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn family_child_flushes_through_compaction() {
        let three = tagged(0x03);
        let store = Store { prefix: "probe".into(), ..Store::memory(None) };
        let db = open_db(&store, ShardId(0), None).await.unwrap();
        for r in 0..12 {
            for i in 0..20 {
                db.put(k(10 + i, &format!("d/{r}")), "r").await.unwrap();
                db.put(three(10 + i, &format!("{r}")), "s").await.unwrap();
            }
            db.flush_with_options(slatedb::config::FlushOptions { flush_type: slatedb::config::FlushType::MemTable })
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        db.put(b"meta/applied/x", b"m").await.unwrap();
        db.close().await.unwrap();
        clone_db_families(&store, ShardId(1), &[(ShardId(0), 0, 32768)], FAMILIES).await.unwrap();
        let c = open_db(&store, ShardId(1), None).await.unwrap();
        for i in 0..80 {
            c.put(k(11, &format!("d/new{i}")), "x").await.unwrap();
            let r = c
                .flush_with_options(slatedb::config::FlushOptions { flush_type: slatedb::config::FlushType::MemTable })
                .await;
            if let Err(e) = r {
                panic!("flush {i}: {e} (L0s {})", c.manifest().l0().len());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        c.close().await.unwrap();
    }

    /// A merge whose sources have no SSTs of their own (split halves that
    /// took no writes) names neither in the clone's manifest, only their
    /// common ancestor: a retried clone still finds itself done (SlateDB's
    /// own retry check wanted every source named), and no source
    /// checkpoint is left behind, only the clones' final pins (which have
    /// no expiry and go when a clone detaches or is deleted).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn clone_retry_with_quiet_sources_leaves_only_pins() {
        let store = Store { prefix: "cq".into(), ..Store::memory(None) };
        let db = open_db(&store, ShardId(0), None).await.unwrap();
        for s in [10u16, 30000, 40000, 65000] {
            db.put(k(s, "h/x"), format!("v{s}")).await.unwrap();
        }
        db.close().await.unwrap();
        clone_db(&store, ShardId(1), &[(ShardId(0), 0, 32768)]).await.unwrap();
        clone_db(&store, ShardId(2), &[(ShardId(0), 32768, 65536)]).await.unwrap();
        let merge = [(ShardId(1), 0, 32768), (ShardId(2), 32768, 65536)];
        clone_db(&store, ShardId(3), &merge).await.unwrap();
        clone_db(&store, ShardId(3), &merge).await.expect("a retried merge of quiet sources is a no-op");
        clone_db(&store, ShardId(1), &[(ShardId(0), 0, 32768)]).await.expect("a retried split too");
        for id in [0u32, 1, 2] {
            let admin = slatedb::admin::AdminBuilder::new(db_path(&store, ShardId(id)), store.raw.clone()).build();
            let cps = admin.list_checkpoints(None).await.unwrap();
            assert!(cps.iter().all(|c| c.expire_time.is_none() && c.name.is_none()), "shard {id}: {cps:?}");
        }
        let m = open_db(&store, ShardId(3), None).await.unwrap();
        for s in [10u16, 30000, 40000, 65000] {
            assert_eq!(m.get(k(s, "h/x")).await.unwrap().as_deref(), Some(format!("v{s}").as_bytes()));
        }
        m.close().await.unwrap();
    }

    /// Flushes small L0s into `db` until its compactor has drained every L0
    /// SST it holds now (the inherited ones included).
    async fn compact_away_l0(db: &Db) {
        let before: Vec<_> = db.manifest().l0().iter().map(|v| v.sst.id).collect();
        let t = std::time::Instant::now();
        for i in 0.. {
            let m = db.manifest();
            if !m.l0().iter().any(|v| before.contains(&v.sst.id)) {
                return;
            }
            assert!(t.elapsed() < Duration::from_secs(60), "never compacted: {} L0s", m.l0().len());
            db.put(k(100, &format!("h/filler{i}")), "f").await.unwrap();
            db.flush_with_options(slatedb::config::FlushOptions { flush_type: slatedb::config::FlushType::MemTable })
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
            let _ = db.refresh_manifest().await;
        }
    }

    /// Regression (split_and_merge_under_write_load's lost acked write): a
    /// split's halves both inherit the parent's L0 SSTs as views with the
    /// parent's view ids, so merging them back gave the union one view id
    /// twice (once per half). SlateDB's compactor keys L0 views by id: it
    /// compacted one half's view and dropped both, losing every key of the
    /// other half that was still in those L0s.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn merging_a_splits_halves_keeps_their_shared_l0s() {
        let store = Store { prefix: "smc".into(), ..Store::memory(None) };
        let db = open_db(&store, ShardId(0), None).await.unwrap();
        let slots = [10u16, 20000, 32767, 32768, 40000, 65535];
        let mut wb = slatedb::WriteBatch::new();
        for s in slots {
            wb.put(k(s, "h/x"), format!("v{s}"));
        }
        db.write(wb).await.unwrap();
        db.close().await.unwrap(); // flushes them into one L0, spanning both halves
        clone_db(&store, ShardId(1), &[(ShardId(0), 0, 32768)]).await.unwrap();
        clone_db(&store, ShardId(2), &[(ShardId(0), 32768, 65536)]).await.unwrap();
        clone_db(&store, ShardId(3), &[(ShardId(1), 0, 32768), (ShardId(2), 32768, 65536)]).await.unwrap();
        let m = open_db(&store, ShardId(3), None).await.unwrap();
        let ids: Vec<_> = m.manifest().l0().iter().map(|v| v.id).collect();
        compact_away_l0(&m).await;
        let mut lost = Vec::new();
        for s in slots {
            if m.get(k(s, "h/x")).await.unwrap().is_none() {
                lost.push(s);
            }
        }
        assert!(lost.is_empty(), "keys of slots {lost:?} lost by the merged shard's compaction (L0 view ids {ids:?})");
        let unique: std::collections::HashSet<_> = ids.iter().collect();
        assert_eq!(unique.len(), ids.len(), "L0 view ids repeat in the merged shard: {ids:?}");
        m.close().await.unwrap();
    }

    /// Regression: a merge of halves that still hold more of their parent's
    /// L0s than one compaction takes (8) has each parent SST behind two views,
    /// and the oldest 8 start at the second half's copy of an SST the first
    /// half also holds. SlateDB used to cut the writer's L0 at the first view
    /// of the compacted SST, dropping uncompacted views from the compactor's
    /// manifest (the writer's next flush then failed with `InvalidClockTick`).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn merging_halves_that_share_many_l0s_keeps_them() {
        let store = Store { prefix: "sml".into(), ..Store::memory(None) };
        let db = open_db(&store, ShardId(0), None).await.unwrap();
        let slots = [10u16, 20000, 40000, 65535];
        for r in 0..12 {
            for s in slots {
                db.put(k(s, &format!("h/{r:02}")), format!("v{s}/{r}")).await.unwrap();
            }
            db.flush_with_options(slatedb::config::FlushOptions { flush_type: slatedb::config::FlushType::MemTable })
                .await
                .unwrap();
        }
        db.close().await.unwrap();
        clone_db(&store, ShardId(1), &[(ShardId(0), 0, 32768)]).await.unwrap();
        clone_db(&store, ShardId(2), &[(ShardId(0), 32768, 65536)]).await.unwrap();
        clone_db(&store, ShardId(3), &[(ShardId(1), 0, 32768), (ShardId(2), 32768, 65536)]).await.unwrap();
        let m = open_db(&store, ShardId(3), None).await.unwrap();
        assert!(m.manifest().l0().len() > 16, "L0s: {}", m.manifest().l0().len());
        compact_away_l0(&m).await;
        for r in 0..12 {
            for s in slots {
                let v = m.get(k(s, &format!("h/{r:02}"))).await.unwrap();
                assert_eq!(v.as_deref(), Some(format!("v{s}/{r}").as_bytes()), "slot {s} round {r}");
            }
        }
        m.close().await.unwrap();
    }

    /// Model check: random generations of split/merge clones with writes,
    /// flushes and compactions in between; every key ever written stays
    /// readable from the shard holding its slot. Timing-dependent (whether a
    /// shard compacted its inherited L0s before the next clone), so a seed
    /// sweep, not a CI test (it found the repeated-L0-view-id loss above):
    /// `for s in $(seq 1 20); do SEED=$s cargo test --lib generations_of_clones -- --ignored; done`
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore]
    async fn generations_of_clones_keep_every_key() {
        use rand::{Rng, SeedableRng};
        let seed: u64 = std::env::var("SEED").ok().and_then(|v| v.parse().ok()).unwrap_or(1);
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
        let store = Store { prefix: format!("gen{seed}"), ..Store::memory(None) };
        let mut model: std::collections::BTreeMap<Vec<u8>, (u16, String, ShardId, usize)> = Default::default();
        // (id, lo, hi, db)
        let mut shards: Vec<(ShardId, u32, u32, Db)> = Vec::new();
        for i in 0..4u32 {
            let lo = i * 16384;
            shards.push((ShardId(i), lo, lo + 16384, open_db(&store, ShardId(i), None).await.unwrap()));
        }
        let mut next_id = 4u32;
        let mut n = 0u64;
        let mut log: Vec<String> = Vec::new();
        for step in 0..40 {
            // writes into every shard, some flushes, sometimes enough L0s to compact
            for (sid, lo, hi, db) in &shards {
                let flushes = if rng.gen_bool(0.3) { 6 } else { rng.gen_range(0..3) };
                for _ in 0..=flushes {
                    for _ in 0..20 {
                        let slot = rng.gen_range(*lo..*hi) as u16;
                        let key = k(slot, &format!("h/{n:08}"));
                        db.put(&key, format!("v{n}")).await.unwrap();
                        model.insert(key, (slot, format!("v{n}"), *sid, step));
                        n += 1;
                    }
                    db.flush_with_options(slatedb::config::FlushOptions {
                        flush_type: slatedb::config::FlushType::MemTable,
                    })
                    .await
                    .unwrap();
                }
            }
            if rng.gen_bool(0.5) {
                tokio::time::sleep(Duration::from_millis(rng.gen_range(0..600))).await;
            }
            check(&shards, &model, &log, seed, step, "after writes").await;
            // an op
            let split = shards.len() < 3 || (shards.len() < 8 && rng.gen_bool(0.5));
            if split {
                let i = rng.gen_range(0..shards.len());
                let (id, lo, hi, db) = shards.remove(i);
                if hi - lo < 2 {
                    shards.insert(i, (id, lo, hi, db));
                    continue;
                }
                db.close().await.unwrap();
                let mid = (lo + hi) / 2;
                let (a, b) = (ShardId(next_id), ShardId(next_id + 1));
                next_id += 2;
                clone_db(&store, a, &[(id, lo, mid)]).await.unwrap();
                clone_db(&store, b, &[(id, mid, hi)]).await.unwrap();
                log.push(format!("step {step}: split {id} [{lo},{hi}) -> {a} [{lo},{mid}), {b} [{mid},{hi})"));
                shards.insert(i, (b, mid, hi, open_db(&store, b, None).await.unwrap()));
                shards.insert(i, (a, lo, mid, open_db(&store, a, None).await.unwrap()));
            } else {
                let i = rng.gen_range(0..shards.len() - 1);
                let (x, xlo, xhi, xdb) = shards.remove(i);
                let (y, ylo, yhi, ydb) = shards.remove(i);
                xdb.close().await.unwrap();
                ydb.close().await.unwrap();
                let m = ShardId(next_id);
                next_id += 1;
                clone_db(&store, m, &[(x, xlo, xhi), (y, ylo, yhi)]).await.unwrap();
                log.push(format!("step {step}: merge {x} [{xlo},{xhi}) + {y} [{ylo},{yhi}) -> {m}"));
                shards.insert(i, (m, xlo, yhi, open_db(&store, m, None).await.unwrap()));
            }
            check(&shards, &model, &log, seed, step, "after op").await;
        }
        for (_, _, _, db) in shards {
            db.close().await.unwrap();
        }
    }

    /// Every key of `model` reads back its value from the shard holding its slot.
    async fn check(
        shards: &[(ShardId, u32, u32, Db)],
        model: &std::collections::BTreeMap<Vec<u8>, (u16, String, ShardId, usize)>,
        log: &[String],
        seed: u64,
        step: usize,
        when: &str,
    ) {
        let mut missing = Vec::new();
        for (key, (slot, v, wid, wstep)) in model {
            let (id, _, _, db) =
                shards.iter().find(|(_, lo, hi, _)| (*slot as u32) >= *lo && (*slot as u32) < *hi).unwrap();
            match db.get(key).await.unwrap() {
                Some(got) if got.as_ref() == v.as_bytes() => {}
                other => missing.push((*id, *slot, v.clone(), other.is_some(), *wid, *wstep)),
            }
        }
        if !missing.is_empty() {
            for l in log {
                eprintln!("{l}");
            }
            for (id, _, _, db) in shards {
                let m = db.manifest();
                eprintln!(
                    "shard {id}: l0 {} srs {} ext {:?}",
                    m.l0().len(),
                    m.compacted().len(),
                    m.external_dbs().iter().map(|e| (e.path.clone(), e.sst_ids.len())).collect::<Vec<_>>()
                );
            }
            panic!("seed {seed} step {step} {when}: {} of {} keys missing, e.g. (shard, slot, v, present, written to, at step) {:?}", missing.len(), model.len(), &missing[..missing.len().min(8)]);
        }
    }

    /// FamilyScan walks one family across slots, skipping other families and
    /// empty slots, from any start key.
    #[tokio::test]
    async fn family_scan_skips_other_families() {
        let store = Store { prefix: "fam".into(), ..Store::memory(None) };
        let db = open_db(&store, ShardId(0), None).await.unwrap();
        for s in [3u16, 7, 9, 65535] {
            for f in ["C/x\0", "R/", "a/", "h/", "n/", "p/"] {
                db.put(k(s, &format!("{f}d{s}")), b"").await.unwrap();
            }
        }
        db.put(k(8, "R/only-records"), b"").await.unwrap();
        db.put(crate::nodelog::META_APPLIED, b"m").await.unwrap();
        let scan = |fam: &'static [u8], start: Option<Vec<u8>>| {
            let db = &db;
            async move {
                let mut it = crate::state::FamilyScan::new(db, fam, start, &Default::default()).await.unwrap();
                let mut out = Vec::new();
                while let Some(kv) = it.next().await.unwrap() {
                    out.push(String::from_utf8_lossy(crate::state::key_body(&kv.key)).into_owned());
                }
                out
            }
        };
        assert_eq!(scan(b"h/", None).await, vec!["h/d3", "h/d7", "h/d9", "h/d65535"]);
        assert_eq!(scan(b"a/", Some(k(7, "a/d7\0"))).await, vec!["a/d9", "a/d65535"]);
        assert_eq!(scan(b"p/", Some(k(9, "a/"))).await, vec!["p/d9", "p/d65535"]);
        assert_eq!(scan(b"C/x\0", None).await.len(), 4);
        assert!(scan(b"M/", None).await.is_empty());
        db.close().await.unwrap();
    }
}

#[cfg(test)]
mod disk_cache_tests {
    use super::*;

    #[test]
    fn node_budget_is_split_over_every_shard() {
        // unset: SlateDB's own default per shard
        assert_eq!(disk_cache_shard_bytes(None, None, 64), DEFAULT_DISK_CACHE_SHARD_BYTES);
        // 64 GiB over 64 shards = 1 GiB each, whatever this node owns
        assert_eq!(disk_cache_shard_bytes(Some(64 << 30), None, 64), 1 << 30);
        assert_eq!(disk_cache_shard_bytes(Some(64 << 30), None, 0), 64 << 30);
        // an explicit per-shard cap wins; tiny budgets get the floor
        assert_eq!(disk_cache_shard_bytes(Some(64 << 30), Some(3 << 30), 64), 3 << 30);
        assert_eq!(disk_cache_shard_bytes(Some(100 << 20), None, 64), MIN_DISK_CACHE_SHARD_BYTES);
    }

    #[test]
    fn cap_reaches_slatedb_settings() {
        let cfg = DiskCacheConfig { dir: "/var/cache/vlpds".into(), node_bytes: Some(32 << 30), shard_bytes: None };
        let s = shard_settings(ShardId(7), Some(&cfg.for_shards(16)));
        let oc = &s.object_store_cache_options;
        assert_eq!(oc.max_cache_size_bytes, Some(2 << 30));
        assert_eq!(oc.root_folder, Some(std::path::Path::new("/var/cache/vlpds").join(ShardId(7).key())));
        assert!(oc.cache_on_flush && oc.cache_on_compaction);
        assert!(shard_settings(ShardId(7), None).object_store_cache_options.root_folder.is_none());
    }
}

#[cfg(test)]
mod clock_cache_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Clone)]
    struct Kb(usize);
    impl Weigh for Kb {
        fn weight(&self) -> usize {
            self.0 << 10
        }
    }

    /// Keys that all land in one shard: its hand sees every entry.
    fn keys_in_one_shard(c: &ClockCache<u64, Kb>, n: usize) -> Vec<u64> {
        (0u64..).filter(|k| c.shard_of(k) == 0).take(n).collect()
    }

    fn cache_kb(kb: u64) -> ClockCache<u64, Kb> {
        ClockCache::new(kb << 10)
    }

    /// The budget is cache-wide: one shard may hold far more than
    /// capacity / CLOCK_SHARDS (a few MB-sized filters hashing together).
    #[test]
    fn budget_is_cache_wide() {
        let c = cache_kb(1000);
        let keys = keys_in_one_shard(&c, 3);
        for &k in &keys {
            c.put(k, Kb(300));
        }
        assert_eq!(c.len(), 3);
        c.put(keys[2] + 1_000_000, Kb(300)); // any shard: over by 200 KB
        assert_eq!(c.bytes(), 900 << 10);
    }

    /// An insert evicts only what it needs, not every entry that missed a
    /// hit since the previous insert.
    #[test]
    fn full_shard_of_hot_entries_loses_only_what_an_insert_needs() {
        let c = cache_kb(100);
        let keys = keys_in_one_shard(&c, 11);
        for &k in &keys[..10] {
            c.put(k, Kb(10));
            assert!(c.get(&k).is_some());
        }
        c.put(keys[10], Kb(10));
        assert_eq!(keys.iter().filter(|k| c.get(k).is_some()).count(), 10, "one evicted for one inserted");
        assert!(c.get(&keys[10]).is_some(), "the new entry stays");
    }

    /// Lowering the capacity evicts down to it at once (cold entries
    /// first); raising it lets the cache fill further.
    #[test]
    fn resize() {
        let c = cache_kb(1000);
        let keys: Vec<u64> = (0..100).collect();
        for &k in &keys {
            c.put(k, Kb(10));
        }
        for &k in &keys[..20] {
            assert!(c.get(&k).is_some());
        }
        let ev = c.evictions();
        c.set_capacity(300 << 10);
        assert_eq!((c.capacity(), c.bytes()), (300 << 10, 300 << 10));
        assert!(c.evictions() > ev);
        assert!(keys[..20].iter().all(|k| c.get(k).is_some()), "the hot entries stay");
        c.set_capacity(2000 << 10);
        for k in 100..200 {
            c.put(k, Kb(10));
        }
        assert_eq!(c.bytes(), 1300 << 10);
    }

    #[test]
    fn block_cache_resizes() {
        let c = BlockCache::new(64 << 20);
        c.resize(32 << 20);
        assert_eq!(c.capacity(), 32 << 20);
        c.resize(128 << 20);
        assert_eq!(c.capacity(), 128 << 20);
    }

    /// Entries hit since the hand passed outlive one-off loads.
    #[test]
    fn unreferenced_entries_go_first() {
        let c = cache_kb(100);
        let keys = keys_in_one_shard(&c, 13);
        for &k in &keys[..10] {
            c.put(k, Kb(10));
        }
        let hit_hot = || {
            for &k in &keys[..9] {
                assert!(c.get(&k).is_some());
            }
        };
        hit_hot();
        c.put(keys[10], Kb(10)); // evicts keys[9], the only cold one
        assert!(c.get(&keys[9]).is_none());
        // while the hot set keeps being read, a stream of one-off loads only
        // displaces itself
        for &k in &keys[11..] {
            hit_hot();
            c.put(k, Kb(10));
        }
        hit_hot();
        assert_eq!(c.bytes(), 100 << 10);
    }

    #[test]
    fn oversized_entry_stays_alone() {
        let c = cache_kb(100);
        let keys = keys_in_one_shard(&c, 3);
        c.put(keys[0], Kb(10));
        c.put(keys[1], Kb(10));
        c.put(keys[2], Kb(500));
        assert!(c.get(&keys[2]).is_some());
        assert_eq!(c.len(), 1);
        c.remove(&keys[2]);
        assert_eq!((c.len(), c.bytes()), (0, 0));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_misses_load_once() {
        let c = Arc::new(ClockCache::<u64, Kb>::new(64 << 20));
        let loads = Arc::new(AtomicUsize::new(0));
        let tasks: Vec<_> = (0..32)
            .map(|_| {
                let (c, loads) = (c.clone(), loads.clone());
                tokio::spawn(async move {
                    let load = async {
                        loads.fetch_add(1, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        Ok::<_, ()>(Kb(1))
                    };
                    c.get_or_load(7, load).await.unwrap().1
                })
            })
            .collect();
        let mut how = Vec::new();
        for t in tasks {
            how.push(t.await.unwrap());
        }
        assert_eq!(loads.load(Ordering::SeqCst), 1);
        assert_eq!(how.iter().filter(|h| **h == Lookup::Loaded).count(), 1);
        assert!(c.loading.iter().all(|m| m.lock().is_empty()));
    }

    #[tokio::test]
    async fn failed_or_cancelled_load_lets_the_next_caller_try() {
        let c = ClockCache::<u64, Kb>::new(64 << 20);
        assert!(c.get_or_load(1, async { Err::<Kb, _>("store down") }).await.is_err());
        let (_, how) = c.get_or_load(1, async { Ok::<_, ()>(Kb(1)) }).await.unwrap();
        assert_eq!(how, Lookup::Loaded);

        let stuck = c.get_or_load(2, std::future::pending::<Result<Kb, ()>>());
        assert!(tokio::time::timeout(Duration::from_millis(20), stuck).await.is_err());
        assert!(c.loading.iter().all(|m| m.lock().is_empty()), "a dropped load releases its key");
        let (_, how) = c.get_or_load(2, async { Ok::<_, ()>(Kb(1)) }).await.unwrap();
        assert_eq!(how, Lookup::Loaded);
    }
}
