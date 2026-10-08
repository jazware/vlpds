//! The SlateDB [`Source`]s a [`LazyTree`](crate::mst_lazy::LazyTree) loads
//! from (DESIGN.md "Partial MSTs"): interior nodes from `M/` by CID, leaves
//! rebuilt from `R/` range scans bounded by the separator keys above them.
//!
//! The sources are synchronous (the tree code is) and block on the runtime
//! with `Handle::block_on`, so they run on the blocking pool, never on a
//! runtime thread. The worker's own pass uses [`CachedOnly`], which fails
//! with `MstError::NotLoaded` instead of reading.

use crate::metrics;
use crate::mst_lazy::{Key, Source};
use crate::state;
use slatedb::DbReadOps;
use std::cell::{Cell, RefCell};
use std::sync::Arc;
use vlsync_atproto::cid::{Cid, CODEC_DAG_CBOR};
use vlsync_atproto::mst::{Entry, LeafEncoder, MstError, Node, MAX_DEPTH};

type Result<T> = std::result::Result<T, MstError>;

/// Loaded nodes shared by every lazy walk in the process. Nodes are
/// content-addressed, so an entry is right for any repo version that links
/// to it (no invalidation); each is shallow (children unloaded).
pub struct NodeCache {
    shards: Vec<parking_lot::Mutex<CacheShard>>,
    shard_bytes: std::sync::atomic::AtomicUsize,
}

/// The LRU and its approximate bytes.
type CacheShard = (lru::LruCache<Cid, Arc<Node>>, usize);

const NODE_CACHE_SHARDS: usize = 32;
pub const DEFAULT_NODE_CACHE_BYTES: usize = 256 << 20;

pub static NODE_CACHE: std::sync::LazyLock<NodeCache> = std::sync::LazyLock::new(|| NodeCache {
    shards: (0..NODE_CACHE_SHARDS).map(|_| parking_lot::Mutex::new((lru::LruCache::unbounded(), 0))).collect(),
    shard_bytes: std::sync::atomic::AtomicUsize::new(DEFAULT_NODE_CACHE_BYTES / NODE_CACHE_SHARDS),
});

impl NodeCache {
    /// 0 turns the cache off.
    pub fn set_bytes(&self, n: usize) {
        self.shard_bytes.store(n / NODE_CACHE_SHARDS, std::sync::atomic::Ordering::Relaxed);
    }

    fn shard(&self, c: &Cid) -> &parking_lot::Mutex<CacheShard> {
        &self.shards[c.digest[0] as usize % NODE_CACHE_SHARDS]
    }

    pub fn bytes(&self) -> usize {
        self.shards.iter().map(|s| s.lock().1).sum()
    }

    pub fn clear(&self) {
        for s in &self.shards {
            *s.lock() = (lru::LruCache::unbounded(), 0);
        }
    }

    pub fn get(&self, c: &Cid) -> Option<Arc<Node>> {
        self.shard(c).lock().0.get(c).cloned()
    }

    pub fn put(&self, n: &Arc<Node>) {
        let Some(c) = n.cid else { return };
        let cap = self.shard_bytes.load(std::sync::atomic::Ordering::Relaxed);
        let size = crate::mst_lazy::heap_bytes(n);
        if size > cap / 4 {
            return;
        }
        let mut g = self.shard(&c).lock();
        let (lru, bytes) = &mut *g;
        if let Some(old) = lru.put(c, n.clone()) {
            *bytes -= crate::mst_lazy::heap_bytes(&old);
        }
        *bytes += size;
        while *bytes > cap {
            let Some((_, old)) = lru.pop_lru() else { break };
            *bytes -= crate::mst_lazy::heap_bytes(&old);
        }
    }
}

/// Persisted nodes read ahead of a walk by one scan of the repo's `M/` range.
/// [`prefetch_tree`] keeps the height-1 nodes (~70% of `M/`) apart, to let
/// them go when the rest wouldn't fit.
#[derive(Default)]
pub struct Prefetched {
    upper: Arena,
    h1: Arena,
    h1_dropped: bool,
}

impl Prefetched {
    pub fn get(&self, cid: &Cid) -> Option<&[u8]> {
        self.upper.get(cid).or_else(|| self.h1.get(cid))
    }

    pub fn len(&self) -> usize {
        self.upper.index.len() + self.h1.index.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The blocks' own bytes.
    pub fn node_bytes(&self) -> usize {
        self.upper.node_bytes + self.h1.node_bytes
    }

    pub fn heap_bytes(&self) -> usize {
        self.upper.heap_bytes() + self.h1.heap_bytes()
    }

    /// The `persist_min` to walk the tree with: 2 once the height-1 nodes
    /// were let go (the walk rebuilds them from records instead of reading
    /// each).
    pub fn persist_min(&self) -> i32 {
        if self.h1_dropped {
            2
        } else {
            1
        }
    }
}

/// Blocks in digest order, each behind its digest and length in a few large
/// buffers, indexed by a sorted array: [`Arena::heap_bytes`] is all it holds
/// (no allocation per node), so a budget can be checked before each node.
#[derive(Default)]
struct Arena {
    chunks: Vec<Vec<u8>>,
    index: Vec<PrefetchEnt>,
    node_bytes: usize,
}

struct PrefetchEnt {
    /// The digest's first 8 bytes, big-endian: the index's sort key.
    prefix: u64,
    chunk: u32,
    off: u32,
}

const PREFETCH_CHUNK: usize = 1 << 20;
/// Digest, then the block's length (u32 LE).
const PREFETCH_HEAD: usize = 32 + 4;

impl Arena {
    fn heap_bytes(&self) -> usize {
        self.chunk_bytes() + self.index.capacity() * std::mem::size_of::<PrefetchEnt>()
    }

    fn chunk_bytes(&self) -> usize {
        self.chunks.iter().map(|c| c.capacity()).sum()
    }

    /// [`heap_bytes`](Self::heap_bytes) once a block of `len` bytes is added
    /// (an index that grows holds both arrays while it copies).
    fn heap_bytes_with(&self, len: usize) -> usize {
        let mut h = self.heap_bytes();
        if self.chunk_full(len) {
            h += self.next_chunk(len);
        }
        if self.index.len() == self.index.capacity() {
            h += self.index.capacity().max(4) * 2 * std::mem::size_of::<PrefetchEnt>();
        }
        h
    }

    fn chunk_full(&self, len: usize) -> bool {
        self.chunks.last().is_none_or(|c| c.capacity() - c.len() < PREFETCH_HEAD + len)
    }

    /// Chunks double from 4 KiB, so a small repo's read-ahead stays small.
    fn next_chunk(&self, len: usize) -> usize {
        self.chunk_bytes().clamp(4096, PREFETCH_CHUNK).max(PREFETCH_HEAD + len)
    }

    /// In ascending digest order.
    fn push(&mut self, digest: &[u8; 32], b: &[u8]) {
        if self.chunk_full(b.len()) {
            let n = self.next_chunk(b.len());
            self.chunks.push(Vec::with_capacity(n));
        }
        let chunk = self.chunks.len() - 1;
        let c = &mut self.chunks[chunk];
        let off = c.len() as u32;
        c.extend_from_slice(digest);
        c.extend_from_slice(&(b.len() as u32).to_le_bytes());
        c.extend_from_slice(b);
        self.index.push(PrefetchEnt { prefix: digest_prefix(digest), chunk: chunk as u32, off });
        self.node_bytes += b.len();
    }

    fn get(&self, cid: &Cid) -> Option<&[u8]> {
        if cid.codec != CODEC_DAG_CBOR || self.index.is_empty() {
            return None;
        }
        let p = digest_prefix(&cid.digest);
        let i = self.index.partition_point(|e| e.prefix < p);
        for e in self.index[i..].iter().take_while(|e| e.prefix == p) {
            let c = &self.chunks[e.chunk as usize][e.off as usize..];
            if c[..32] == cid.digest {
                let len = u32::from_le_bytes(c[32..PREFETCH_HEAD].try_into().expect("4 bytes")) as usize;
                return Some(&c[PREFETCH_HEAD..PREFETCH_HEAD + len]);
            }
        }
        None
    }
}

fn digest_prefix(d: &[u8; 32]) -> u64 {
    u64::from_be_bytes(d[..8].try_into().expect("8 bytes"))
}

fn store_err(e: impl std::fmt::Display) -> MstError {
    MstError::Store(e.to_string())
}

/// One repo in the live DB or a snapshot.
pub struct DbSource<'a, R: DbReadOps + Sync + ?Sized> {
    pub db: &'a R,
    pub did: &'a str,
    pub gen: u64,
    pub rt: &'a tokio::runtime::Handle,
    /// Misses read `db`.
    pub prefetched: Option<&'a Prefetched>,
    /// Node point reads + record scans.
    pub reads: Cell<u64>,
}

impl<'a, R: DbReadOps + Sync + ?Sized> DbSource<'a, R> {
    pub fn new(db: &'a R, did: &'a str, gen: u64, rt: &'a tokio::runtime::Handle) -> Self {
        DbSource { db, did, gen, rt, prefetched: None, reads: Cell::new(0) }
    }

    pub fn with_prefetched(mut self, p: Option<&'a Prefetched>) -> Self {
        self.prefetched = p;
        self
    }
}

/// The node cache alone: anything else fails with `NotLoaded` (the repo
/// worker's no-I/O pass).
pub struct CachedOnly;

impl Source for CachedOnly {
    fn cached(&self, cid: &Cid) -> Option<Arc<Node>> {
        NODE_CACHE.get(cid)
    }
    fn node(&self, _: &Cid) -> Result<Option<Arc<[u8]>>> {
        Err(MstError::NotLoaded)
    }
    fn records(&self, _: Option<&[u8]>, _: Option<&[u8]>, _: &mut Vec<(Key, Cid)>) -> Result<()> {
        Err(MstError::NotLoaded)
    }
}

/// Strictly between `lo` and `hi` (None = open).
fn record_range(did: &str, gen: u64, lo: Option<&[u8]>, hi: Option<&[u8]>) -> std::ops::Range<Vec<u8>> {
    let prefix = state::record_prefix(did, gen);
    let start = match lo {
        // the smallest key above `lo`
        Some(lo) => [&prefix[..], lo, b"\0"].concat(),
        None => prefix.clone(),
    };
    let end = match hi {
        Some(hi) => [&prefix[..], hi].concat(),
        None => vlsync_store::keys::prefix_end(&prefix),
    };
    start..end
}

fn record_entry(prefix_len: usize, kv: &slatedb::KeyValue) -> Result<(Key, Cid)> {
    let (cid, _) = state::decode_record_value(&kv.value).map_err(store_err)?;
    Ok((Arc::from(&kv.key[prefix_len..]), cid))
}

/// Scans `did`'s records strictly between `lo` and `hi`.
async fn scan_records<R: DbReadOps + Sync + ?Sized>(
    db: &R,
    did: &str,
    gen: u64,
    lo: Option<&[u8]>,
    hi: Option<&[u8]>,
    out: &mut Vec<(Key, Cid)>,
) -> Result<()> {
    let plen = state::record_prefix(did, gen).len();
    let mut it =
        vlsync_store::keys::BatchedScan::new(db.scan(record_range(did, gen, lo, hi)).await.map_err(store_err)?);
    while let Some(kv) = it.next().await.map_err(store_err)? {
        out.push(record_entry(plen, &kv)?);
    }
    Ok(())
}

/// For scans read to their end.
fn read_ahead_opts() -> slatedb::config::ScanOptions {
    slatedb::config::ScanOptions {
        read_ahead_bytes: 1 << 20,
        max_fetch_tasks: 2,
        cache_blocks: true,
        ..Default::default()
    }
}

impl<R: DbReadOps + Sync + ?Sized> Source for DbSource<'_, R> {
    fn cached(&self, cid: &Cid) -> Option<Arc<Node>> {
        NODE_CACHE.get(cid)
    }

    fn remember(&self, n: &Arc<Node>) {
        NODE_CACHE.put(n)
    }

    fn node(&self, cid: &Cid) -> Result<Option<Arc<[u8]>>> {
        if let Some(b) = self.prefetched.and_then(|p| p.get(cid)) {
            return Ok(Some(Arc::from(b)));
        }
        self.reads.set(self.reads.get() + 1);
        metrics::LAZY_MST_READS.with_label_values(&["node"]).inc();
        let v = self.rt.block_on(self.db.get(state::mst_node_key(self.did, self.gen, cid))).map_err(store_err)?;
        Ok(v.map(|b| Arc::from(&b[..])))
    }

    fn records(&self, lo: Option<&[u8]>, hi: Option<&[u8]>, out: &mut Vec<(Key, Cid)>) -> Result<()> {
        self.reads.set(self.reads.get() + 1);
        metrics::LAZY_MST_READS.with_label_values(&["leaf"]).inc();
        self.rt.block_on(scan_records(self.db, self.did, self.gen, lo, hi, out))
    }
}

/// Record ranges from one forward scan of the repo's `R/` range, for walks
/// that ask for them in key order (an export's or a full load's pre-order
/// walk).
pub struct ScanSource<'a, N: Source> {
    pub nodes: N,
    rt: &'a tokio::runtime::Handle,
    prefix_len: usize,
    iter: RefCell<vlsync_store::keys::BatchedScan>,
    /// The record read past the last range's end.
    peeked: RefCell<Option<(Key, Cid)>>,
    done: Cell<bool>,
}

impl<'a, N: Source> ScanSource<'a, N> {
    /// Blocking.
    pub fn open<R: DbReadOps + Sync + ?Sized>(
        db: &R,
        did: &str,
        gen: u64,
        nodes: N,
        rt: &'a tokio::runtime::Handle,
    ) -> Result<Self> {
        let prefix = state::record_prefix(did, gen);
        let iter = rt
            .block_on(db.scan_with_options(prefix.clone()..vlsync_store::keys::prefix_end(&prefix), &read_ahead_opts()))
            .map_err(store_err)?;
        Ok(ScanSource {
            nodes,
            rt,
            prefix_len: prefix.len(),
            iter: RefCell::new(vlsync_store::keys::BatchedScan::new(iter)),
            peeked: RefCell::new(None),
            done: Cell::new(false),
        })
    }

    fn next(&self) -> Result<Option<(Key, Cid)>> {
        if let Some(r) = self.peeked.borrow_mut().take() {
            return Ok(Some(r));
        }
        if self.done.get() {
            return Ok(None);
        }
        let mut it = self.iter.borrow_mut();
        let next = match it.next_buffered() {
            Some(kv) => Some(kv),
            None => self.rt.block_on(it.next()).map_err(store_err)?,
        };
        match next {
            Some(kv) => record_entry(self.prefix_len, &kv).map(Some),
            None => {
                self.done.set(true);
                Ok(None)
            }
        }
    }
}

impl<N: Source> Source for ScanSource<'_, N> {
    // an export or full load streams every node once: not worth caching
    fn node(&self, cid: &Cid) -> Result<Option<Arc<[u8]>>> {
        self.nodes.node(cid)
    }

    /// Records at or below `lo` are skipped (a range the caller had
    /// loaded); the first at or above `hi` stays for the next range.
    fn records(&self, lo: Option<&[u8]>, hi: Option<&[u8]>, out: &mut Vec<(Key, Cid)>) -> Result<()> {
        while let Some((k, c)) = self.next()? {
            if lo.is_some_and(|lo| &k[..] <= lo) {
                continue;
            }
            if hi.is_some_and(|hi| &k[..] >= hi) {
                *self.peeked.borrow_mut() = Some((k, c));
                break;
            }
            out.push((k, c));
        }
        Ok(())
    }
}

/// Records in key order, each with its block if the export carries it, the
/// bytes back to back in one buffer (no allocation per record).
#[derive(Default)]
pub struct Records {
    bytes: Vec<u8>,
    /// Where each record's key and block end (the next record starts there).
    recs: Vec<(u32, u32, Cid)>,
}

impl Records {
    pub fn with_capacity(n: usize) -> Self {
        Records { bytes: Vec::with_capacity(n * 32), recs: Vec::with_capacity(n) }
    }

    pub fn push(&mut self, key: &[u8], cid: Cid, block: Option<&[u8]>) {
        self.bytes.extend_from_slice(key);
        let key_end = self.bytes.len() as u32;
        self.bytes.extend_from_slice(block.unwrap_or_default());
        self.recs.push((key_end, self.bytes.len() as u32, cid));
    }

    pub fn len(&self) -> usize {
        self.recs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.recs.is_empty()
    }

    pub fn bytes(&self) -> usize {
        self.bytes.len()
    }

    /// A record block is never empty, so an empty one is none.
    fn get(&self, i: usize) -> (&[u8], &Cid, Option<&[u8]>) {
        let start = match i {
            0 => 0,
            _ => self.recs[i - 1].1 as usize,
        };
        let (key_end, end, cid) = &self.recs[i];
        let block = &self.bytes[*key_end as usize..*end as usize];
        (&self.bytes[start..*key_end as usize], cid, (!block.is_empty()).then_some(block))
    }
}

pub type RecordBatch = std::result::Result<Records, String>;

/// A repo's records in key order, from one forward `R/` scan by a producer
/// on the runtime (`export_repo`), so the scan runs ahead of the walk
/// instead of one `block_on` per record on the walking thread. The walk
/// reads keys for its leaves and takes record blocks in the same order a
/// little behind: only the batches between the two stay in memory.
pub struct FedSource<N: Source> {
    pub nodes: N,
    feed: RefCell<Feed>,
}

struct Feed {
    rx: tokio::sync::mpsc::Receiver<RecordBatch>,
    batches: std::collections::VecDeque<Records>,
    /// The first record of `batches[0]`, counted from the start of the scan.
    base: usize,
    /// The next record whose block to give.
    given: usize,
    /// The next record for a leaf; never behind `given`.
    read: usize,
    closed: bool,
}

impl Feed {
    /// Where record `i` is; None past the last. Blocking.
    fn at(&mut self, i: usize) -> Result<Option<(usize, usize)>> {
        loop {
            let mut off = i - self.base;
            for (b, batch) in self.batches.iter().enumerate() {
                if off < batch.len() {
                    return Ok(Some((b, off)));
                }
                off -= batch.len();
            }
            if self.closed {
                return Ok(None);
            }
            match self.rx.blocking_recv() {
                Some(Ok(b)) => self.batches.push_back(b),
                Some(Err(e)) => return Err(MstError::Store(e)),
                None => self.closed = true,
            }
        }
    }

    /// Records at or below `lo` are passed over (their blocks are still
    /// given); the first at or above `hi` stays for the next range.
    fn range(&mut self, lo: Option<&[u8]>, hi: Option<&[u8]>, mut f: impl FnMut(&[u8], &Cid)) -> Result<()> {
        while let Some((b, p)) = self.at(self.read)? {
            let (k, c, _) = self.batches[b].get(p);
            if hi.is_some_and(|hi| k >= hi) {
                break;
            }
            if lo.is_none_or(|lo| k > lo) {
                f(k, c);
            }
            self.read += 1;
        }
        Ok(())
    }

    fn give(&mut self, upto: Option<&[u8]>, f: &mut dyn FnMut(Cid, &[u8])) -> Result<()> {
        while let Some((b, p)) = self.at(self.given)? {
            let (k, c, block) = self.batches[b].get(p);
            if upto.is_some_and(|u| k > u) {
                break;
            }
            if let Some(block) = block {
                f(*c, block);
            }
            self.given += 1;
            self.read = self.read.max(self.given);
            if b == 0 && p + 1 == self.batches[0].len() {
                self.base += self.batches[0].len();
                self.batches.pop_front();
            }
        }
        Ok(())
    }
}

impl<N: Source> FedSource<N> {
    pub fn new(nodes: N, rx: tokio::sync::mpsc::Receiver<RecordBatch>) -> Self {
        let feed = Feed { rx, batches: Default::default(), base: 0, given: 0, read: 0, closed: false };
        FedSource { nodes, feed: RefCell::new(feed) }
    }
}

impl<N: Source> Source for FedSource<N> {
    fn node(&self, cid: &Cid) -> Result<Option<Arc<[u8]>>> {
        self.nodes.node(cid)
    }

    fn records(&self, lo: Option<&[u8]>, hi: Option<&[u8]>, out: &mut Vec<(Key, Cid)>) -> Result<()> {
        self.feed.borrow_mut().range(lo, hi, |k, c| out.push((Arc::from(k), *c)))
    }

    fn leaf_records(&self, lo: Option<&[u8]>, hi: Option<&[u8]>, enc: &mut LeafEncoder) -> Result<()> {
        enc.clear();
        self.feed.borrow_mut().range(lo, hi, |k, c| enc.push(k, c))
    }

    fn record_blocks(&self, upto: Option<&[u8]>, f: &mut dyn FnMut(Cid, &[u8])) -> Result<()> {
        self.feed.borrow_mut().give(upto, f)
    }
}

/// One scan of `did`'s `M/` range, up to `max_bytes` (0 = none), instead of
/// 7-11 dependent node reads. Also returns whether the range was read to its
/// end.
pub async fn prefetch<R: DbReadOps + Sync + ?Sized>(
    db: &R,
    did: &str,
    gen: u64,
    max_bytes: usize,
) -> anyhow::Result<(Prefetched, bool)> {
    if max_bytes == 0 {
        return Ok((Prefetched::default(), false));
    }
    scan_nodes(db, did, gen, &read_ahead_opts(), false, |b| b <= max_bytes).await
}

/// For a walk of the whole tree (an export): `did`'s `M/` range for as long
/// as `admit` takes the [`heap_bytes`](Prefetched::heap_bytes) the next node
/// would bring it to. When a node doesn't fit, the height-1 nodes are let go
/// and the scan goes on with the rest (walk with
/// [`Prefetched::persist_min`]); when those don't fit either, it stops there.
pub async fn prefetch_tree<R: DbReadOps + Sync + ?Sized>(
    db: &R,
    did: &str,
    gen: u64,
    opts: &slatedb::config::ScanOptions,
    admit: impl FnMut(usize) -> bool,
) -> anyhow::Result<Prefetched> {
    Ok(scan_nodes(db, did, gen, opts, true, admit).await?.0)
}

async fn scan_nodes<R: DbReadOps + Sync + ?Sized>(
    db: &R,
    did: &str,
    gen: u64,
    opts: &slatedb::config::ScanOptions,
    split: bool,
    mut admit: impl FnMut(usize) -> bool,
) -> anyhow::Result<(Prefetched, bool)> {
    let mut out = Prefetched::default();
    let prefix = state::mst_node_prefix(did, gen);
    let mut it = vlsync_store::keys::BatchedScan::new(
        db.scan_with_options(prefix.clone()..vlsync_store::keys::prefix_end(&prefix), opts).await?,
    );
    let mut complete = true;
    while let Some(kv) = it.next().await? {
        let Ok(digest) = <[u8; 32]>::try_from(&kv.key[prefix.len()..]) else { continue };
        let b = &kv.value[..];
        // a node misplaced by a bad first key only changes what is let go
        let h1 = split && vlsync_atproto::mst::first_key_height(b) == Some(1);
        if h1 && out.h1_dropped {
            continue;
        }
        let total = match h1 {
            true => out.h1.heap_bytes_with(b.len()) + out.upper.heap_bytes(),
            false => out.upper.heap_bytes_with(b.len()) + out.h1.heap_bytes(),
        };
        if !admit(total) {
            if !split || out.h1_dropped {
                complete = false;
                break;
            }
            out.h1 = Arena::default();
            out.h1_dropped = true;
            if h1 {
                continue;
            }
            if !admit(out.upper.heap_bytes_with(b.len())) {
                complete = false;
                break;
            }
        }
        match h1 {
            true => out.h1.push(&digest, b),
            false => out.upper.push(&digest, b),
        }
    }
    metrics::LAZY_MST_PREFETCH_BYTES.observe(out.node_bytes() as f64);
    Ok((out, complete))
}

/// `Tree::proof_blocks` of `key` on a lazy tree at `root`, without blocking
/// and without touching the tree: unloaded children are read from `db` (a
/// snapshot at the tree's version), each checked against its link.
pub async fn proof_blocks<R: DbReadOps + Sync + ?Sized>(
    root: &Arc<Node>,
    db: &R,
    did: &str,
    gen: u64,
    key: &[u8],
) -> Result<Vec<(Cid, Vec<u8>)>> {
    let mut out = Vec::new();
    walk_path(root, db, did, gen, key, &mut |n| {
        out.push((n.cid.ok_or(MstError::Invalid("unwritten node"))?, crate::mst_lazy::node_block(n)?));
        Ok(())
    })
    .await?;
    Ok(out)
}

/// The leaf, or the node holding `key`.
pub async fn path_end<R: DbReadOps + Sync + ?Sized>(
    root: &Arc<Node>,
    db: &R,
    did: &str,
    gen: u64,
    key: &[u8],
) -> Result<Arc<Node>> {
    walk_path(root, db, did, gen, key, &mut |_| Ok(())).await
}

async fn walk_path<R: DbReadOps + Sync + ?Sized>(
    root: &Arc<Node>,
    db: &R,
    did: &str,
    gen: u64,
    key: &[u8],
    visit: &mut (dyn FnMut(&Node) -> Result<()> + Send),
) -> Result<Arc<Node>> {
    let mut n = root.clone();
    let (mut lo, mut hi): (Option<Key>, Option<Key>) = (None, None);
    for _ in 0..=MAX_DEPTH {
        if n.stub {
            return Err(MstError::Partial);
        }
        visit(&n)?;
        let Some((i, clo, chi)) = crate::mst_lazy::proof_child(&n, key, &lo, &hi) else { return Ok(n) };
        let child = match &n.entries[i] {
            Entry::Child { node: Some(c), .. } => c.clone(),
            Entry::Child { node: None, cid: Some(c) } if n.height == 1 && NODE_CACHE.get(c).is_none() => {
                load_leaves(db, did, gen, &n, lo.as_deref(), hi.as_deref(), i).await?
            }
            Entry::Child { node: None, cid: Some(c) } => {
                load_child(db, did, gen, c, n.height - 1, clo.as_deref(), chi.as_deref()).await?
            }
            _ => return Err(MstError::Partial),
        };
        (n, lo, hi) = (child, clo, chi);
    }
    Err(MstError::Invalid("tree too deep"))
}

/// The leaf at entry `want` of the height-1 node `n`. One scan of `n`'s
/// record range rebuilds its unloaded siblings too (a range scan costs
/// mostly its setup), and those that match their links are cached for
/// nearby proofs and getBlocks.
async fn load_leaves<R: DbReadOps + Sync + ?Sized>(
    db: &R,
    did: &str,
    gen: u64,
    n: &Node,
    lo: Option<&[u8]>,
    hi: Option<&[u8]>,
    want: usize,
) -> Result<Arc<Node>> {
    metrics::LAZY_MST_READS.with_label_values(&["leaf"]).inc();
    let mut recs = Vec::new();
    scan_records(db, did, gen, lo, hi, &mut recs).await?;
    let mut pos = 0;
    let mut found = None;
    for (i, e) in n.entries.iter().enumerate() {
        match e {
            // the node's own keys are records too: skip them
            Entry::Value { key, .. } => {
                while pos < recs.len() && recs[pos].0[..] <= key[..] {
                    pos += 1;
                }
            }
            Entry::Child { node, cid: Some(c) } => {
                let end = match n.entries.get(i + 1) {
                    Some(Entry::Value { key, .. }) => {
                        recs[pos..].iter().position(|(k, _)| k[..] >= key[..]).map_or(recs.len(), |p| pos + p)
                    }
                    _ => recs.len(),
                };
                let group = &recs[pos..end];
                pos = end;
                if i == want {
                    let leaf = crate::mst_lazy::rebuilt_subtree(group, 0, c)?;
                    NODE_CACHE.put(&leaf);
                    found = Some(leaf);
                } else if node.is_none() && NODE_CACHE.get(c).is_none() {
                    if let Ok(leaf) = crate::mst_lazy::rebuilt_subtree(group, 0, c) {
                        NODE_CACHE.put(&leaf);
                    }
                }
            }
            Entry::Child { cid: None, .. } => {}
        }
    }
    found.ok_or(MstError::Partial)
}

/// Interior nodes from `M/`; a leaf (or a missing interior node) rebuilt
/// from its record range.
async fn load_child<R: DbReadOps + Sync + ?Sized>(
    db: &R,
    did: &str,
    gen: u64,
    cid: &Cid,
    height: i32,
    lo: Option<&[u8]>,
    hi: Option<&[u8]>,
) -> Result<Arc<Node>> {
    if let Some(n) = NODE_CACHE.get(cid).filter(|n| n.height == height) {
        return Ok(n);
    }
    let n = load_child_uncached(db, did, gen, cid, height, lo, hi).await?;
    NODE_CACHE.put(&n);
    Ok(n)
}

async fn load_child_uncached<R: DbReadOps + Sync + ?Sized>(
    db: &R,
    did: &str,
    gen: u64,
    cid: &Cid,
    height: i32,
    lo: Option<&[u8]>,
    hi: Option<&[u8]>,
) -> Result<Arc<Node>> {
    if height >= 1 {
        metrics::LAZY_MST_READS.with_label_values(&["node"]).inc();
        if let Some(b) = db.get(state::mst_node_key(did, gen, cid)).await.map_err(store_err)? {
            if let Some(n) = crate::mst_lazy::persisted_node(Arc::from(&b[..]), cid, Some(height))? {
                return Ok(n);
            }
        }
    }
    metrics::LAZY_MST_READS.with_label_values(&["leaf"]).inc();
    let mut recs = Vec::new();
    scan_records(db, did, gen, lo, hi, &mut recs).await?;
    crate::mst_lazy::rebuilt_subtree(&recs, height, cid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mst_lazy::{build_tree, export_blocks, persisted_nodes, MemStore};

    /// Nodes from `M/` in a DB (through the read-ahead), records from memory.
    struct Split<'a> {
        nodes: DbSource<'a, slatedb::Db>,
        recs: &'a MemStore,
    }

    impl Source for Split<'_> {
        fn node(&self, cid: &Cid) -> Result<Option<Arc<[u8]>>> {
            self.nodes.node(cid)
        }
        fn records(&self, lo: Option<&[u8]>, hi: Option<&[u8]>, out: &mut Vec<(Key, Cid)>) -> Result<()> {
            self.recs.records(lo, hi, out)
        }
    }

    /// Past its budget the read-ahead lets the height-1 nodes go and keeps
    /// the rest (the walk then rebuilds height-1 subtrees from records), or
    /// stops: every split exports the same blocks.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn prefetch_tree_splits_export_the_same_blocks() {
        let db = slatedb::Db::open("t", Arc::new(object_store::memory::InMemory::new())).await.unwrap();
        let did = "did:plc:prefetchtest";
        let recs: Vec<(Key, Cid)> = (0..20_000u64)
            .map(|i| (Arc::from(format!("app.x.y/{i:08}").as_bytes()), Cid::dag_cbor(&i.to_le_bytes())))
            .collect();
        let mut tree = build_tree(&recs).unwrap();
        let root = tree.root_cid().unwrap();
        let mut want = Vec::new();
        tree.walk_blocks(&mut |c, b| want.push((c, b.to_vec()))).unwrap();
        let nodes = persisted_nodes(&tree, 1);
        for (c, b) in &nodes {
            db.put(state::mst_node_key(did, 0, c), b).await.unwrap();
        }
        let h1 = nodes.values().filter(|b| vlsync_atproto::mst::first_key_height(b) == Some(1)).count();
        assert!(h1 > nodes.len() / 2, "{h1} of {} nodes at height 1", nodes.len());
        let mem = MemStore { records: recs.iter().cloned().collect(), ..Default::default() };
        let opts = read_ahead_opts();
        // the most it asked for (a growing index briefly holds two arrays)
        let mut peak = 0;
        let full = prefetch_tree(&db, did, 0, &opts, |b| {
            peak = peak.max(b);
            true
        })
        .await
        .unwrap();
        assert_eq!((full.len(), full.persist_min()), (nodes.len(), 1));
        let all = full.heap_bytes();
        let db = Arc::new(db);
        let mem = Arc::new(mem);
        for cap in [usize::MAX, peak, all / 2, all / 5, 1] {
            let pre = prefetch_tree(&*db, did, 0, &opts, |b| b <= cap).await.unwrap();
            assert!(pre.heap_bytes() <= cap, "cap {cap}: holds {}", pre.heap_bytes());
            let (persist_min, held) = (pre.persist_min(), pre.len());
            let (db, mem) = (db.clone(), mem.clone());
            let (got, reads) = tokio::task::spawn_blocking(move || {
                let rt = tokio::runtime::Handle::current();
                let src = Split { nodes: DbSource::new(&*db, did, 0, &rt).with_prefetched(Some(&pre)), recs: &mem };
                let mut got = Vec::new();
                export_blocks(root, pre.persist_min(), &src, &mut |c, b| got.push((c, b.to_vec()))).unwrap();
                (got, src.nodes.reads.get())
            })
            .await
            .unwrap();
            assert!(got == want, "cap {cap} (persist_min {persist_min}, {held} nodes held): blocks differ");
            if cap >= peak {
                assert_eq!((persist_min, reads), (1, 0), "cap {cap}");
            } else if cap == all / 2 {
                assert_eq!(
                    (persist_min, held, reads),
                    (2, nodes.len() - h1, 0),
                    "cap {cap}: every node above height 1 held"
                );
            } else {
                assert_eq!(persist_min, 2, "cap {cap}");
            }
        }
    }
}
