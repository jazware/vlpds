//! One commit log per node incarnation (`log_id`), shared by every shard the
//! node owns. Group commit across shards means segment size and PUT rate
//! scale with node throughput, not with shard count.
//!
//! workers ──LogEntry{shard}──► sequencer ──(K PUTs in flight)──► finalizer
//!                               assign seq, append  completions    per touched shard:
//!                               (shard, epoch)-     taken in       SlateDB batch + applied
//!                               tagged entries      ordinal order  marker, then acks,
//!                                                                  firehose, watermark
//!
//! Segments go to `log/{log_id}/{ordinal:012}.seg` with If-None-Match on dense
//! ordinals, up to `inflight` (K) PUTs at once. Ordinals are assigned at seal
//! time; the finalizer takes completed PUTs strictly in ordinal order, so acks,
//! apply, the live ring and the watermark only ever cover a gap-free prefix.
//! A crash can leave holes (n missing, n+1 present): the log's *durable
//! prefix* ends at its first missing ordinal, nothing past it was acked, and a
//! dead node's log is closed by a fence object at that first hole (see
//! `first_free` and cluster.rs), so a zombie's PUT there collides and it
//! fail-stops. Objects past the fence are garbage no reader ever reaches.
//! DESIGN.md "Pipelined segment PUTs" has the argument.

use crate::metrics;
use crate::stats::STATS;
use bytes::Bytes;
use object_store::path::Path;
use object_store::{ObjectStoreExt, PutMode, PutOptions, PutPayload};
use parking_lot::{Mutex, RwLock};
use slatedb::{Db, WriteBatch};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use vlatproto::events::Frame;
use vlsync_firehose::log::{check_header, segment_path, seq_floor, LogBatch, Watermark};
use vlsync_store::segment::{self, LogObject, Mutation, SegmentBuilder};
use vlsync_store::slots::ShardId;
use vlsync_store::store::Store;

pub type AckFn = Box<dyn FnOnce(Result<(), Arc<anyhow::Error>>) + Send>;

/// The error an entry is acked with when its shard isn't held here or is
/// closing: nothing of it is applied or replayed, so the write can be resent
/// to the shard's owner. Only ever for an entry no segment carries.
pub const NOT_HELD: &str = "partition not owned by this node (moved)";
/// An entry already in a durable segment whose shard is gone: a successor
/// may replay it, so it is not [`NOT_HELD`] (never resent).
pub const NOT_HELD_LOGGED: &str = "partition left this node after the write was logged: outcome unknown";
/// False once this node may no longer act as an owner (lease lapsed).
pub type LeaseCheck = Arc<dyn Fn() -> bool + Send + Sync>;

/// Per-shard applied marker: everything for this shard in `log_id` up to and
/// including `ordinal` is in the shard's SlateDB.
pub const META_APPLIED: &[u8] = b"meta/applied2";
/// The shard's recently written repos (`partition::RecentRepos`), newest
/// first, one DID per line: what its next owner preloads.
pub const META_RECENT: &[u8] = b"meta/recent";

pub struct LogEntry {
    pub shard: ShardId,
    pub frames: Vec<Frame>,
    pub muts: Vec<Mutation>,
    pub ack: Option<AckFn>,
    /// Per-repo in-flight counter, decremented once durable.
    pub pending: Option<Arc<AtomicU32>>,
    pub enqueued: Instant,
    /// The sequencer appends the slot's totals row (or delta row) to `muts`.
    pub totals: Option<crate::totals::Delta>,
}

pub const DEFAULT_LIVE_RING_BYTES: usize = 128 << 20;

/// This log's recent durable batches, for peers following it (remote.rs).
/// A batch is kept until every subscriber has read it, up to a byte budget
/// (each batch pins its whole segment, so a count bound would let one slow
/// follower pin GBs). A subscriber the budget evicts batches from is told it
/// lagged and catches up from S3 instead.
pub struct LiveRing {
    inner: Mutex<LiveInner>,
    max_bytes: AtomicUsize,
}

struct LiveInner {
    /// (batch, pinned bytes), consecutive ordinals
    buf: VecDeque<(Arc<LogBatch>, usize)>,
    bytes: usize,
    /// ordinal of the next batch to be pushed
    next: u64,
    /// subscriber id -> next ordinal it will read
    subs: HashMap<u64, u64>,
    next_id: u64,
}

impl LiveInner {
    /// Drops batches every subscriber has read, then the oldest while over
    /// budget (always keeping the newest).
    fn trim(&mut self, max: usize) {
        let min_next = self.subs.values().copied().min().unwrap_or(self.next);
        while let Some((b, n)) = self.buf.front() {
            if b.ordinal >= min_next && (self.bytes <= max || self.buf.len() == 1) {
                break;
            }
            self.bytes -= n;
            self.buf.pop_front();
        }
        metrics::LOG_LIVE_BYTES.set(self.bytes as i64);
    }
}

pub enum LiveRecv {
    Batch(Arc<LogBatch>),
    Empty,
    /// Batches this subscriber hadn't read were evicted: catch up from S3.
    Lagged,
}

pub struct LiveSub {
    ring: Arc<LiveRing>,
    id: u64,
    next: u64,
}

impl LiveRing {
    pub fn new(max_bytes: usize) -> Arc<LiveRing> {
        let inner = LiveInner { buf: VecDeque::new(), bytes: 0, next: 0, subs: HashMap::new(), next_id: 0 };
        Arc::new(LiveRing { inner: Mutex::new(inner), max_bytes: AtomicUsize::new(max_bytes) })
    }

    pub fn set_max_bytes(&self, n: usize) {
        self.max_bytes.store(n, Ordering::Relaxed);
    }

    pub fn bytes(&self) -> usize {
        self.inner.lock().bytes
    }

    /// Receives every batch pushed from now on (while it keeps up).
    pub fn subscribe(self: &Arc<Self>) -> LiveSub {
        let mut g = self.inner.lock();
        let (id, next) = (g.next_id, g.next);
        g.next_id += 1;
        g.subs.insert(id, next);
        LiveSub { ring: self.clone(), id, next }
    }

    fn push(&self, b: Arc<LogBatch>, bytes: usize) {
        let mut g = self.inner.lock();
        g.next = b.ordinal + 1;
        g.buf.push_back((b, bytes));
        g.bytes += bytes;
        g.trim(self.max_bytes.load(Ordering::Relaxed));
    }
}

impl LiveSub {
    pub fn try_recv(&mut self) -> LiveRecv {
        let mut g = self.ring.inner.lock();
        if self.next >= g.next {
            return LiveRecv::Empty;
        }
        let front = g.buf.front().map(|(b, _)| b.ordinal).unwrap_or(g.next);
        if self.next < front {
            return LiveRecv::Lagged;
        }
        let b = g.buf[(self.next - front) as usize].0.clone();
        self.next += 1;
        g.subs.insert(self.id, self.next);
        if front < self.next {
            g.trim(self.ring.max_bytes.load(Ordering::Relaxed));
        }
        LiveRecv::Batch(b)
    }
}

impl Drop for LiveSub {
    fn drop(&mut self) {
        let mut g = self.ring.inner.lock();
        g.subs.remove(&self.id);
        g.trim(self.ring.max_bytes.load(Ordering::Relaxed));
    }
}

pub const DEFAULT_LOG_INFLIGHT: usize = 4;

/// A shard this node applies into.
pub struct ShardSink {
    pub id: ShardId,
    pub epoch: u64,
    pub db: Arc<Db>,
    /// Held (write) across apply + ack of a segment; export readers take it
    /// (read) to pair a repo's durable view with a matching SlateDB snapshot.
    pub apply_lock: Arc<tokio::sync::RwLock<()>>,
    /// State mutations applied since the shard opened here (reshard policy).
    pub applied: AtomicU64,
    /// Shared with the shard's `Partition`; persisted by its checkpoints.
    pub recent: Arc<crate::partition::RecentRepos>,
    pub barrier: Barrier,
    /// Only the sequencer changes it, in log order.
    pub totals: Mutex<crate::totals::ShardTotals>,
}

/// A close barrier (`ShardSink::barrier_entry`) carries the sink's own token
/// as its `pending` counter, which no other entry holds. Once the sequencer
/// takes it, it refuses every later entry for the sink: one logged behind the
/// barrier lands past the span end the close publishes, where no successor
/// replays it, so acking it would lose it. (`put_private` sends from outside
/// the repo workers a close purges, so it could slip in after the barrier.)
#[derive(Default)]
pub struct Barrier {
    token: Arc<AtomicU32>,
    taken: std::sync::atomic::AtomicBool,
}

impl ShardSink {
    /// The entry that closes this shard on our log: once it is durable,
    /// every entry the log took for the shard is durable and applied, and
    /// the log takes no more for this sink.
    pub fn barrier_entry(&self, ack: AckFn) -> LogEntry {
        LogEntry {
            shard: self.id,
            frames: Vec::new(),
            muts: Vec::new(),
            ack: Some(ack),
            pending: Some(self.barrier.token.clone()),
            enqueued: Instant::now(),
            totals: None,
        }
    }

    pub fn barrier_taken(&self) -> bool {
        self.barrier.taken.load(Ordering::Acquire)
    }
}

pub struct ShardSinks {
    map: RwLock<HashMap<ShardId, Arc<ShardSink>>>,
    /// `NodeLog::durable_ordinal`
    durable: Arc<AtomicU64>,
    retain: Mutex<Retain>,
}

/// How long a closed shard still holds back this log's replay floor once
/// its close finished (its state flushed with the marker at its span end,
/// so nothing of this log is replayed for it; the grace is a margin). A
/// close in progress holds it however long it takes (`Retain::closing`):
/// one that fails fail-stops the node, and a successor replays from the
/// shard's durable marker.
const RETIRED_GRACE: Duration = Duration::from_secs(120);

/// What retention (retention.rs) may delete from this log, and what this
/// log's owner has certified (DESIGN.md "Log retention").
#[derive(Default)]
struct Retain {
    /// shard -> (replay floor, insert floor). The replay floor is the lowest
    /// ordinal of this log a crash replay of the shard could still need: the
    /// insert floor (the log's next ordinal when the sink was inserted:
    /// none of the shard's entries at this epoch are below it) until a
    /// checkpoint at or past the insert floor is durable, then its ordinal + 1.
    floors: HashMap<ShardId, (u64, u64)>,
    /// replay floors of shards whose close is in progress (sink removed,
    /// state not closed yet: `ShardSinks::retire`)
    closing: HashMap<ShardId, u64>,
    /// replay floors of recently closed shards (see RETIRED_GRACE)
    retired: Vec<(u64, Instant)>,
    /// shard -> highest epoch opened here. Opening replays and flushes every
    /// earlier span, so from then on the shard's durable state never replays
    /// a span from before that epoch.
    opened: std::collections::BTreeMap<ShardId, u64>,
}

impl Default for ShardSinks {
    fn default() -> Self {
        ShardSinks::new(Arc::new(AtomicU64::new(u64::MAX)))
    }
}

impl ShardSinks {
    pub fn new(durable: Arc<AtomicU64>) -> ShardSinks {
        ShardSinks { map: RwLock::default(), durable, retain: Mutex::default() }
    }
    pub fn get(&self, id: ShardId) -> Option<Arc<ShardSink>> {
        self.map.read().get(&id).cloned()
    }
    /// A shard opened (replayed and flushed) at `s.epoch`: it starts applying.
    pub fn insert(&self, s: Arc<ShardSink>) {
        let floor = self.durable.load(Ordering::Acquire).wrapping_add(1);
        {
            let mut r = self.retain.lock();
            r.floors.insert(s.id, (floor, floor));
            let e = r.opened.entry(s.id).or_default();
            *e = (*e).max(s.epoch);
        }
        self.map.write().insert(s.id, s);
    }
    /// The shard stops applying (its close barrier is durable). Its replay
    /// floor holds until `retire` (its state closed), however long that is.
    pub fn remove(&self, id: ShardId) -> Option<Arc<ShardSink>> {
        let mut r = self.retain.lock();
        if let Some((floor, _)) = r.floors.remove(&id) {
            let f = r.closing.entry(id).or_insert(floor);
            *f = (*f).min(floor);
        }
        drop(r);
        self.map.write().remove(&id)
    }

    /// The shard's close finished (state flushed and closed): its replay
    /// floor is held for RETIRED_GRACE more. A close that fails never
    /// retires: the floor stays until the node fail-stops.
    pub fn retire(&self, id: ShardId) {
        let mut r = self.retain.lock();
        if let Some(floor) = r.closing.remove(&id) {
            r.retired.push((floor, Instant::now()));
        }
    }
    pub fn all(&self) -> Vec<Arc<ShardSink>> {
        self.map.read().values().cloned().collect()
    }

    pub fn applied_entries(&self, id: ShardId) -> u64 {
        self.get(id).map_or(0, |s| s.applied.load(Ordering::Relaxed))
    }

    /// The ordinal a checkpoint marker for `shard` must reach (its insert
    /// floor): a marker below it is ambiguous (it can name the end of an
    /// earlier span of this log for the shard, and replay would start there).
    fn insert_floor(&self, shard: ShardId) -> Option<u64> {
        self.retain.lock().floors.get(&shard).map(|f| f.1)
    }

    fn checkpointed_at(&self, shard: ShardId, ordinal: u64) -> bool {
        self.retain.lock().floors.get(&shard).is_some_and(|f| ordinal >= f.1 && f.0 == ordinal + 1)
    }

    fn checkpointed(&self, shard: ShardId, ordinal: u64) {
        if let Some(f) = self.retain.lock().floors.get_mut(&shard) {
            if ordinal >= f.1 {
                f.0 = f.0.max(ordinal + 1);
            }
        }
    }

    /// Every ordinal of this log below this may be deleted as far as replay
    /// is concerned: no shard applying from it (or closing, or closed within
    /// RETIRED_GRACE) can need it after a crash. Never past the last durable
    /// segment, which is kept so fencing finds the end of the log.
    pub fn replay_floor(&self) -> u64 {
        let durable = self.durable.load(Ordering::Acquire);
        if durable == u64::MAX {
            return 0;
        }
        let mut r = self.retain.lock();
        r.retired.retain(|(_, at)| at.elapsed() < RETIRED_GRACE);
        r.floors
            .values()
            .map(|f| f.0)
            .chain(r.closing.values().copied())
            .chain(r.retired.iter().map(|f| f.0))
            .fold(durable, u64::min)
    }

    /// shard -> highest epoch this log's owner opened it at.
    pub fn opened(&self) -> std::collections::BTreeMap<ShardId, u64> {
        self.retain.lock().opened.clone()
    }
}

pub struct NodeLogConfig {
    pub log_id: String,
    pub writer: u8,
    pub max_segment_bytes: usize,
    pub hedge_after: Duration,
    pub lease_ok: Option<LeaseCheck>,
}

pub struct NodeLog {
    pub log_id: Arc<str>,
    pub tx: mpsc::Sender<LogEntry>,
    pub wm: Arc<Watermark>,
    pub live: Arc<LiveRing>,
    /// Last durable+applied ordinal (u64::MAX = none yet).
    pub durable_ordinal: Arc<AtomicU64>,
    pub sinks: Arc<ShardSinks>,
    /// Nothing more is streamed to peers: a graceful shutdown fenced this
    /// log, or an in-process test node "crashed" (`Node::halt`). Peers then
    /// drain the log from S3 to its fence.
    pub closed: std::sync::atomic::AtomicBool,
    pub feed: Arc<SegmentFeed>,
}

/// Segments the console's strata view shows: the last [`SegmentFeed::KEPT`]
/// this log sealed, each marked durable once finalized. Memory only, one
/// push per segment.
#[derive(Default)]
pub struct SegmentFeed {
    ring: Mutex<VecDeque<SegmentInfo>>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SegmentInfo {
    pub ordinal: u64,
    /// Sequenced entries: firehose events plus private-state writes.
    pub entries: u32,
    pub events: u32,
    /// Seqs as strings, like every seq the admin API returns (past 2^53).
    pub first_seq: String,
    pub last_seq: String,
    pub bytes: u64,
    /// Compressed size as stored; 0 until durable.
    pub stored_bytes: u64,
    pub sealed_at: u64,
    /// None while its PUT is in flight (or an earlier one is).
    pub durable_at: Option<u64>,
    pub put_ms: Option<f64>,
}

impl SegmentFeed {
    pub const KEPT: usize = 1024;

    fn sealed(&self, info: SegmentInfo) {
        let mut r = self.ring.lock();
        if r.len() >= Self::KEPT {
            r.pop_front();
        }
        r.push_back(info);
    }

    fn durable(&self, ordinal: u64, put_secs: f64, stored_bytes: usize) {
        let mut r = self.ring.lock();
        if let Some(s) = r.iter_mut().rev().find(|s| s.ordinal == ordinal) {
            s.durable_at = Some(vlatproto::tid::now_micros() / 1000);
            s.put_ms = Some(put_secs * 1000.0);
            s.stored_bytes = stored_bytes as u64;
        }
    }

    /// Oldest first, sealed at or after `since_ms`.
    pub fn since(&self, since_ms: u64) -> Vec<SegmentInfo> {
        self.ring.lock().iter().filter(|s| s.sealed_at >= since_ms).cloned().collect()
    }
}

pub fn encode_marker(log_id: &str, ordinal: u64) -> Vec<u8> {
    let mut b = Vec::with_capacity(10 + log_id.len());
    b.extend_from_slice(&(log_id.len() as u16).to_be_bytes());
    b.extend_from_slice(log_id.as_bytes());
    b.extend_from_slice(&ordinal.to_be_bytes());
    b
}

/// Decodes an applied marker. Anything but exactly `encode_marker`'s bytes
/// is an error, never "no marker" (which would replay every span).
pub fn decode_marker(b: &[u8]) -> anyhow::Result<(String, u64)> {
    let parsed = (|| {
        let n = u16::from_be_bytes(b.get(..2)?.try_into().ok()?) as usize;
        let id = String::from_utf8(b.get(2..2 + n)?.to_vec()).ok()?;
        let ord = u64::from_be_bytes(b.get(2 + n..10 + n)?.try_into().ok()?);
        (b.len() == 10 + n).then_some((id, ord))
    })();
    parsed.ok_or_else(|| {
        vlsync_store::version::format_error("applied_marker");
        anyhow::anyhow!("malformed applied marker ({} bytes)", b.len())
    })
}

impl NodeLog {
    /// Starts a fresh log (a node never reopens an old log: a restarted node
    /// gets a new log id; its previous log is fenced and replayed by owners).
    pub fn start(store: Store, cfg: NodeLogConfig, merger_tx: mpsc::UnboundedSender<LogBatch>) -> Arc<NodeLog> {
        Self::start_with_inflight(store, cfg, DEFAULT_LOG_INFLIGHT, merger_tx)
    }

    pub fn start_with_inflight(
        store: Store,
        cfg: NodeLogConfig,
        inflight: usize,
        merger_tx: mpsc::UnboundedSender<LogBatch>,
    ) -> Arc<NodeLog> {
        let wm = Arc::new(Watermark::new(cfg.writer, seq_floor(vlatproto::tid::now_micros())));
        let (tx, rx) = mpsc::channel(64 * 1024);
        let (fin_tx, fin_rx) = mpsc::channel(4);
        let live = LiveRing::new(DEFAULT_LIVE_RING_BYTES);
        let durable_ordinal = Arc::new(AtomicU64::new(u64::MAX));
        let sinks = Arc::new(ShardSinks::new(durable_ordinal.clone()));
        let feed = Arc::new(SegmentFeed::default());
        let log_id: Arc<str> = cfg.log_id.clone().into();
        let seq_cfg = SeqConfig {
            log_id: cfg.log_id.clone(),
            max_segment_bytes: cfg.max_segment_bytes,
            inflight: inflight.max(1),
            hedge_after: cfg.hedge_after,
        };
        // critical: a panic in either fail-stops the node (lifecycle.rs)
        tokio::spawn(vlsync_store::lifecycle::critical(
            "log_sequencer",
            run_sequencer(store, seq_cfg, cfg.lease_ok.clone(), wm.clone(), sinks.clone(), rx, fin_tx, feed.clone()),
        ));
        tokio::spawn(vlsync_store::lifecycle::critical(
            "log_finalizer",
            run_finalizer(
                log_id.clone(),
                sinks.clone(),
                wm.clone(),
                fin_rx,
                merger_tx,
                live.clone(),
                cfg.lease_ok,
                durable_ordinal.clone(),
                feed.clone(),
            ),
        ));
        Arc::new(NodeLog { log_id, tx, wm, live, durable_ordinal, sinks, closed: Default::default(), feed })
    }

    /// The ordinal the next segment will get (an owner records it as the start
    /// of its span when it takes a shard).
    pub fn next_ordinal(&self) -> u64 {
        self.durable_ordinal.load(Ordering::Acquire).wrapping_add(1)
    }

    /// Writes an applied marker for every shard and flushes their memtables,
    /// bounding how much of this log a successor must replay after a crash.
    /// One shard after another; `spawn_checkpoints` can spread them out.
    pub async fn checkpoint_all(&self) {
        let ord = self.durable_ordinal.load(Ordering::Acquire);
        if ord == u64::MAX {
            return;
        }
        // HA tests (bench/ha kill9-mid-checkpoint) key off this line.
        tracing::info!(ordinal = ord, shards = self.sinks.all().len(), "checkpoint start");
        for s in self.sinks.all() {
            self.checkpoint_shard(&s).await;
        }
    }

    /// Checkpoints one shard at the current durable ordinal: an applied
    /// marker, then a memtable flush (an L0 SST PUT plus a manifest update).
    pub async fn checkpoint_shard(&self, s: &ShardSink) {
        let ord = self.durable_ordinal.load(Ordering::Acquire);
        if ord == u64::MAX {
            return;
        }
        // Nothing of the shard is in this log before its insert floor; a
        // marker below it could also name the end of an earlier span of
        // this log for the shard (A -> B -> A), and replay would start
        // there (DESIGN.md "Log retention"). Its replay marker stands.
        if self.sinks.insert_floor(s.id).is_none_or(|f| ord < f) {
            return;
        }
        // Already checkpointed at this ordinal: every write into the shard
        // comes from a segment <= ord, so its marker and memtable are durable
        // as of ord, and another flush would only cost an L0 SST PUT and a
        // manifest CAS. A shard with no entries while the log moves is still
        // checkpointed, so a successor's replay stays short.
        if self.sinks.checkpointed_at(s.id, ord) && !s.recent.is_dirty() {
            return;
        }
        let t = Instant::now();
        // The lock keeps the markers monotonic with the finalizer's. It
        // covers no store call: `write` returns once the batch is in the
        // memtable (the WAL is off), and the flush runs after the guard is
        // dropped. The finalizer has applied every segment <= ord (it
        // updates durable_ordinal only after applying).
        let _g = s.apply_lock.write().await;
        let mut wb = WriteBatch::new();
        wb.put(META_APPLIED, encode_marker(&self.log_id, ord));
        if let Some(r) = s.recent.take_dirty() {
            wb.put(META_RECENT, r);
        }
        let written = s.db.write(wb).await.is_ok();
        drop(_g);
        let flushed =
            s.db.flush_with_options(slatedb::config::FlushOptions { flush_type: slatedb::config::FlushType::MemTable })
                .await;
        if written && flushed.is_ok() {
            self.sinks.checkpointed(s.id, ord);
        }
        crate::metrics::CHECKPOINT_SHARD.observe(t.elapsed().as_secs_f64());
    }

    /// Checkpoints every shard once per `every`. `stagger`: one shard every
    /// `every / shards`, so the flushes (SST encode on the runtime, two
    /// store PUTs each) don't arrive as one burst.
    pub fn spawn_checkpoints(self: &Arc<Self>, every: Duration, stagger: bool) {
        let log = Arc::downgrade(self);
        tokio::spawn(async move {
            loop {
                if !stagger {
                    tokio::time::sleep(every).await;
                    let Some(l) = log.upgrade() else { return };
                    l.checkpoint_all().await;
                    continue;
                }
                let Some(l) = log.upgrade() else { return };
                let mut shards = l.sinks.all();
                drop(l);
                shards.sort_by_key(|s| s.id);
                // bench/ha kill9-mid-checkpoint keys off "checkpoint start"
                tracing::info!(
                    shards = shards.len(),
                    every_ms = every.as_millis() as u64,
                    "checkpoint start (staggered pass)"
                );
                let gap = every / shards.len().max(1) as u32;
                if shards.is_empty() {
                    tokio::time::sleep(every).await;
                }
                for s in shards {
                    tokio::time::sleep(gap).await;
                    let Some(l) = log.upgrade() else { return };
                    // closed meanwhile (its close checkpointed it), or reopened
                    if l.sinks.get(s.id).is_some_and(|cur| Arc::ptr_eq(&cur, &s)) {
                        l.checkpoint_shard(&s).await;
                    }
                }
            }
        });
    }
}

struct Sealed {
    ordinal: u64,
    data: Bytes,
    frames: Vec<(i64, std::ops::Range<usize>)>,
    /// in log order per shard
    muts: BTreeMap<ShardId, Vec<Mutation>>,
    acks: Vec<PendingAck>,
    last_seq: i64,
    put_secs: f64,
    /// Size of the stored (compressed) object.
    stored_bytes: usize,
}

/// (shard, ack, pending counter, enqueued)
type PendingAck = (ShardId, Option<AckFn>, Option<Arc<AtomicU32>>, Instant);

struct Open {
    seg: SegmentBuilder,
    frames: Vec<(i64, std::ops::Range<usize>)>,
    muts: BTreeMap<ShardId, Vec<Mutation>>,
    acks: Vec<PendingAck>,
}

impl Open {
    fn new(log_id: &str) -> Open {
        Open { seg: SegmentBuilder::for_log(log_id), frames: Vec::new(), muts: BTreeMap::new(), acks: Vec::new() }
    }

    fn push(&mut self, wm: &Watermark, sinks: &ShardSinks, mut e: LogEntry) {
        // An entry for a shard we no longer hold (a repo load or cached repo
        // that outlived close()) matches no span, so no successor would
        // replay it: acking it would lose it.
        let reject = |e: LogEntry, why: &str| {
            tracing::warn!(shard = e.shard.0, "log entry for a shard this node {why}: rejected");
            if let Some(p) = e.pending {
                p.fetch_sub(1, Ordering::Release);
            }
            if let Some(ack) = e.ack {
                ack(Err(Arc::new(anyhow::anyhow!(NOT_HELD))));
            }
        };
        let Some(sink) = sinks.get(e.shard) else { return reject(e, "no longer holds") };
        if sink.barrier.taken.load(Ordering::Acquire) {
            return reject(e, "is closing");
        }
        if e.pending.as_ref().is_some_and(|p| Arc::ptr_eq(p, &sink.barrier.token)) {
            sink.barrier.taken.store(true, Ordering::Release);
            e.pending = None;
        }
        let epoch = sink.epoch;
        debug_assert!(
            e.frames.is_empty() || !e.muts.iter().any(|m| crate::state::is_space_key(&m.key)),
            "a log entry with space state carries a firehose frame"
        );
        if e.frames.is_empty() {
            // private-state write: an empty frame, skipped by the firehose
            e.frames.push(Frame { prefix: Vec::new(), suffix: Vec::new(), derived_muts: 0, derived_gen: 0 });
        }
        let n = e.frames.len();
        let seqs: Vec<i64> = (0..n).map(|_| wm.assign()).collect();
        if let Some(d) = e.totals.take() {
            sink.totals.lock().apply(&d, crate::totals::today(), seqs[n - 1], &mut e.muts);
        }
        for (i, f) in e.frames.iter().enumerate() {
            let seq = seqs[i];
            let (muts, derived): (&[Mutation], usize) = if i + 1 == n { (&e.muts, f.derived_muts) } else { (&[], 0) };
            let empty = f.prefix.is_empty() && f.suffix.is_empty();
            let range = self.seg.push_derived(
                seq,
                e.shard,
                epoch,
                |out| {
                    if !empty {
                        f.finish(seq, out)
                    }
                },
                muts,
                derived,
                f.derived_gen,
            );
            self.frames.push((seq, range));
        }
        self.muts.entry(e.shard).or_default().append(&mut e.muts);
        self.acks.push((e.shard, e.ack, e.pending, e.enqueued));
    }
}

struct SeqConfig {
    log_id: String,
    max_segment_bytes: usize,
    /// K
    inflight: usize,
    hedge_after: Duration,
}

/// Seals segments and keeps up to K PUTs in flight. Completions are taken in
/// ordinal order (a later segment that lands first waits for the earlier
/// ones), so the finalizer sees a gap-free ordinal sequence.
///
/// A segment is sealed when a slot is free and either nothing is in flight
/// (the K = 1 behavior: whatever queued during a PUT is the next segment),
/// it holds at least max_segment_bytes / K, or the newest PUT in flight has
/// stalled (taken over twice the recent PUT latency): then what queued
/// behind it goes out now and is acked when the stall ends, instead of
/// waiting for the stall *and* its own PUT. Extra concurrent PUTs therefore
/// only start under load or a stall, so the PUT rate at low load stays one
/// per PUT latency while the ceiling is K full segments per PUT latency.
#[allow(clippy::too_many_arguments)]
async fn run_sequencer(
    store: Store,
    cfg: SeqConfig,
    lease_ok: Option<LeaseCheck>,
    wm: Arc<Watermark>,
    sinks: Arc<ShardSinks>,
    mut rx: mpsc::Receiver<LogEntry>,
    fin_tx: mpsc::Sender<Sealed>,
    feed: Arc<SegmentFeed>,
) {
    use futures::stream::{FuturesOrdered, StreamExt};
    let SeqConfig { log_id, max_segment_bytes, inflight: k, hedge_after } = cfg;
    let concurrent_fill = (max_segment_bytes / k).max(1);
    let mut ordinal = 0u64;
    // every ordinal below this has been PUT: each sealed header's prefix_end
    let mut prefix_end = 0u64;
    let mut open = Open::new(&log_id);
    let mut inflight: FuturesOrdered<tokio::task::JoinHandle<Sealed>> = FuturesOrdered::new();
    // seal times of the PUTs in `inflight` (same order), and a moving
    // average of PUT latency: a PUT older than 2x that has stalled
    let mut started: std::collections::VecDeque<Instant> = Default::default();
    let mut put_avg = Duration::from_millis(10);
    let mut stalled = false;
    let mut closed = false;
    loop {
        let can_recv = !closed && open.seg.len() < max_segment_bytes;
        // timed from the newest PUT: one stall seals one segment, not one
        // per entry that queues while it lasts
        let stall_at = started.back().map(|t| *t + (put_avg * 2).clamp(Duration::from_millis(5), hedge_after));
        let watch_stall = k > 1 && !stalled && inflight.len() < k && !open.seg.is_empty() && stall_at.is_some();
        tokio::select! {
            biased;
            res = inflight.next(), if !inflight.is_empty() => match res {
                Some(Ok(sealed)) => {
                    started.pop_front();
                    stalled = false;
                    put_avg = (put_avg * 7 + Duration::from_secs_f64(sealed.put_secs)) / 8;
                    prefix_end = sealed.ordinal + 1;
                    if fin_tx.send(sealed).await.is_err() {
                        return;
                    }
                }
                // Nothing aborts upload tasks: a cancelled one means the
                // runtime is shutting down, and this task is about to be
                // dropped too. Its entries were never acked, so nothing
                // acknowledged is lost; a fail-stop would only turn a clean
                // exit into exit 2.
                Some(Err(e)) if e.is_cancelled() => return,
                Some(Err(e)) => {
                    tracing::error!(%log_id, "segment upload task failed: {e}; exiting");
                    vlsync_store::lifecycle::fail_stop(2, "segment_upload");
                }
                None => {}
            },
            e = rx.recv(), if can_recv => match e {
                Some(e) => {
                    open.push(&wm, &sinks, e);
                    while open.seg.len() < max_segment_bytes {
                        match rx.try_recv() {
                            Ok(e) => open.push(&wm, &sinks, e),
                            Err(_) => break,
                        }
                    }
                }
                None => closed = true,
            },
            _ = tokio::time::sleep_until(tokio::time::Instant::from_std(stall_at.unwrap_or_else(Instant::now))), if watch_stall => {
                stalled = true;
            }
        }
        metrics::SEQ_QUEUE.with_label_values(&["node"]).set((rx.max_capacity() - rx.capacity()) as i64);
        let want = if inflight.is_empty() || stalled { 1 } else { concurrent_fill };
        if inflight.len() < k && !open.seg.is_empty() && open.seg.len() >= want {
            if let Some(ok) = &lease_ok {
                if !ok() {
                    tracing::error!(%log_id, "node lease lapsed before segment PUT: fail-stop");
                    vlsync_store::lifecycle::fail_stop(5, "lease_lapsed");
                }
            }
            let o = std::mem::replace(&mut open, Open::new(&log_id));
            metrics::SEGMENT_ENTRIES.observe(o.frames.len() as f64);
            metrics::SEGMENT_EVENTS.observe(o.frames.iter().filter(|(_, r)| !r.is_empty()).count() as f64);
            metrics::COMMIT_STAGE
                .with_label_values(&["seal_wait"])
                .observe(o.acks.first().map_or(0.0, |a| a.3.elapsed().as_secs_f64()));
            if inflight.is_empty() {
                prefix_end = ordinal;
            }
            let last_seq = o.seg.last_seq;
            feed.sealed(SegmentInfo {
                ordinal,
                entries: o.frames.len() as u32,
                events: o.frames.iter().filter(|(_, r)| !r.is_empty()).count() as u32,
                first_seq: o.frames.first().map_or(last_seq, |f| f.0).to_string(),
                last_seq: last_seq.to_string(),
                bytes: o.seg.len() as u64,
                stored_bytes: 0,
                sealed_at: vlatproto::tid::now_micros() / 1000,
                durable_at: None,
                put_ms: None,
            });
            let data = o.seg.seal(&log_id, ordinal, prefix_end);
            let sealed = Sealed {
                ordinal,
                data: Bytes::from(data),
                frames: o.frames,
                muts: o.muts,
                acks: o.acks,
                last_seq,
                put_secs: 0.0,
                stored_bytes: 0,
            };
            ordinal += 1;
            if stalled {
                metrics::SEGMENT_STALL_SEALS.inc();
            }
            stalled = false;
            started.push_back(Instant::now());
            let (store, log_id) = (store.clone(), log_id.clone());
            inflight.push_back(tokio::spawn(async move {
                let mut sealed = sealed;
                // compressed off the runtime; the finalizer keeps slicing
                // frames out of the uncompressed `data`
                let raw = sealed.data.clone();
                let put = commit_pool()
                    .run(move || {
                        let t = Instant::now();
                        let z = segment::compress(&raw, segment::compression_level());
                        metrics::SEGMENT_COMPRESS.observe(t.elapsed().as_secs_f64());
                        match z {
                            Ok(Some(z)) => Bytes::from(z),
                            Ok(None) => raw,
                            Err(e) => {
                                tracing::error!("segment compression failed, storing it uncompressed: {e:#}");
                                raw
                            }
                        }
                    })
                    .await
                    .expect("segment compression task");
                sealed.stored_bytes = put.len();
                let t = Instant::now();
                upload(&store, &log_id, sealed.ordinal, put, hedge_after).await;
                sealed.put_secs = t.elapsed().as_secs_f64();
                sealed
            }));
        }
        if closed && inflight.is_empty() && open.seg.is_empty() {
            return;
        }
    }
}

/// A small fixed pool of threads for CPU work on the commit path (segment
/// compression), apart from tokio's blocking pool. That pool also runs
/// request-driven work (getRepo walks, cold loads, Argon2), and a compression
/// queued behind it would stall every write's ack. Nothing a request can
/// start runs here.
pub struct BlockingPool {
    tx: crossbeam_channel::Sender<Box<dyn FnOnce() + Send>>,
}

impl BlockingPool {
    pub fn new(name: &str, threads: usize) -> BlockingPool {
        let (tx, rx) = crossbeam_channel::unbounded::<Box<dyn FnOnce() + Send>>();
        for i in 0..threads.max(1) {
            let rx = rx.clone();
            std::thread::Builder::new()
                .name(format!("{name}-{i}"))
                .spawn(move || {
                    while let Ok(job) = rx.recv() {
                        // a panicking job fails its caller, not the pool
                        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(job));
                    }
                })
                .expect("spawning a pool thread");
        }
        BlockingPool { tx }
    }

    /// Runs `f` on the pool; Err if it panicked.
    pub async fn run<R: Send + 'static>(
        &self,
        f: impl FnOnce() -> R + Send + 'static,
    ) -> Result<R, tokio::sync::oneshot::error::RecvError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let job: Box<dyn FnOnce() + Send> = Box::new(move || {
            let _ = tx.send(f());
        });
        if self.tx.send(job).is_err() {
            unreachable!("pool threads never exit while the pool is alive");
        }
        rx.await
    }
}

/// A quarter of the cores, 2 to 8 threads: K PUTs in flight need at most K.
pub fn commit_pool() -> &'static BlockingPool {
    static POOL: std::sync::LazyLock<BlockingPool> = std::sync::LazyLock::new(|| {
        let cores = std::thread::available_parallelism().map_or(4, |n| n.get());
        BlockingPool::new("commit-pool", (cores / 4).clamp(2, 8))
    });
    &POOL
}

async fn put_once(store: &Store, path: &Path, data: Bytes) -> object_store::Result<()> {
    let _inflight = metrics::InflightGuard::new(&metrics::PUTS_INFLIGHT);
    store.inject_latency().await;
    let opts = PutOptions { mode: PutMode::Create, ..Default::default() };
    let r = store.raw.put_opts(path, PutPayload::from_bytes(data), opts).await.map(|_| ());
    metrics::PUT_ATTEMPTS
        .with_label_values(&[match &r {
            Ok(()) => "ok",
            Err(object_store::Error::AlreadyExists { .. }) => "already_exists",
            Err(_) => "error",
        }])
        .inc();
    r
}

/// PUTs a segment with If-None-Match until durable, hedging slow attempts.
/// A different object at our ordinal (another writer, or a fence) means this
/// log was closed out from under us: fail-stop.
async fn upload(store: &Store, log_id: &str, ordinal: u64, data: Bytes, hedge_after: Duration) {
    use futures::stream::{FuturesUnordered, StreamExt};
    let path = segment_path(store, log_id, ordinal);
    let t = Instant::now();
    let mut backoff = Duration::from_millis(20);
    // at most one hedge per ordinal: hedging every retry round of K segments
    // would multiply PUT load just when S3 is slow
    let mut hedged = false;
    loop {
        let mut attempts = FuturesUnordered::new();
        attempts.push(put_once(store, &path, data.clone()));
        let hedge = tokio::time::sleep(hedge_after);
        tokio::pin!(hedge);
        let result = loop {
            tokio::select! {
                Some(r) = attempts.next() => match r {
                    Ok(()) | Err(object_store::Error::AlreadyExists { .. }) => break r,
                    Err(e) if attempts.is_empty() => break Err(e),
                    Err(_) => continue,
                },
                _ = &mut hedge, if !hedged => {
                    hedged = true;
                    STATS.hedges.fetch_add(1, Ordering::Relaxed);
                    metrics::PUT_HEDGES.inc();
                    attempts.push(put_once(store, &path, data.clone()));
                }
            }
        };
        match result {
            Ok(()) => {
                STATS.record_put(t.elapsed(), data.len());
                return;
            }
            Err(object_store::Error::AlreadyExists { .. }) => match resolve_conflict(store, &path, &data).await {
                Conflict::Ours => {
                    STATS.record_put(t.elapsed(), data.len());
                    return;
                }
                Conflict::Fenced => {
                    tracing::error!(log_id, ordinal, "our log was fenced by a successor: fail-stop");
                    vlsync_store::lifecycle::fail_stop(3, "fenced");
                }
                Conflict::Other => {
                    tracing::error!(log_id, ordinal, "segment ordinal taken by another writer: fail-stop");
                    vlsync_store::lifecycle::fail_stop(3, "ordinal_taken");
                }
                Conflict::Missing => {
                    // S3 answers 409 (mapped to AlreadyExists) on conditional
                    // write conflicts too, e.g. our own hedge racing
                    tracing::warn!(log_id, ordinal, "segment PUT conflicted but no object is there; retrying");
                    tokio::time::sleep(jittered(backoff)).await;
                    backoff = (backoff * 2).min(Duration::from_secs(2));
                }
            },
            Err(e) => {
                tracing::warn!(log_id, ordinal, "segment PUT failed, retrying: {e}");
                tokio::time::sleep(jittered(backoff)).await;
                backoff = (backoff * 2).min(Duration::from_secs(2));
            }
        }
    }
}

/// K segments failing on the same S3 hiccup retry spread out, not in lockstep.
fn jittered(d: Duration) -> Duration {
    d.mul_f64(rand::Rng::gen_range(&mut rand::thread_rng(), 0.5..1.5))
}

#[derive(Debug, PartialEq)]
enum Conflict {
    /// A hedge or an earlier attempt won.
    Ours,
    Fenced,
    Other,
    Missing,
}

/// What occupies a segment path our conditional PUT conflicted on. Transient
/// GET errors are retried: only a confirmed fence or different bytes may make
/// the caller fail-stop.
async fn resolve_conflict(store: &Store, path: &Path, data: &Bytes) -> Conflict {
    let mut backoff = Duration::from_millis(20);
    loop {
        let got = match store.raw.get(path).await {
            Ok(r) => r.bytes().await,
            Err(e) => Err(e),
        };
        match got {
            Ok(b) if b == *data => return Conflict::Ours,
            Ok(b) => {
                return match segment::parse(b, false, None) {
                    Ok(LogObject::Fence { .. }) => Conflict::Fenced,
                    _ => Conflict::Other,
                };
            }
            Err(object_store::Error::NotFound { .. }) => return Conflict::Missing,
            Err(e) => {
                tracing::warn!(%path, "reading a conflicting segment failed, retrying: {e}");
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(2));
            }
        }
    }
}

/// Whether the runtime is shutting down: it cancels a task spawned then at
/// once, before it drops the tasks it holds.
async fn runtime_stopping() -> bool {
    tokio::spawn(async {}).await.is_err_and(|e| e.is_cancelled())
}

#[allow(clippy::too_many_arguments)]
async fn run_finalizer(
    log_id: Arc<str>,
    sinks: Arc<ShardSinks>,
    wm: Arc<Watermark>,
    mut rx: mpsc::Receiver<Sealed>,
    merger_tx: mpsc::UnboundedSender<LogBatch>,
    live: Arc<LiveRing>,
    lease_ok: Option<LeaseCheck>,
    durable_ordinal: Arc<AtomicU64>,
    feed: Arc<SegmentFeed>,
) {
    let mut expect = 0u64;
    while let Some(mut s) = rx.recv().await {
        // everything below (apply, live ring, merger, watermark, acks) must
        // cover a gap-free prefix of the log
        assert_eq!(s.ordinal, expect, "log {log_id}: finalizer got ordinal {} out of order", s.ordinal);
        expect += 1;
        let t_lock = Instant::now();
        // Take every touched shard's apply lock (id order) and hold it across
        // apply *and* ack, so export readers never see a SlateDB snapshot newer
        // than the repo views published by these acks.
        let mut guards = Vec::new();
        let mut targets = Vec::new();
        let mut unheld = Vec::new();
        for (shard, muts) in std::mem::take(&mut s.muts) {
            match sinks.get(shard) {
                Some(sink) => {
                    guards.push(sink.apply_lock.clone().write_owned().await);
                    targets.push((sink, muts));
                }
                None => {
                    // The sequencer took them while the sink was there, and
                    // a sink goes only once its barrier is durable, after
                    // which nothing is taken for it: unreachable. If it ever
                    // happens, they may lie past the span end the close
                    // published, where nobody replays them: never ack them.
                    tracing::error!(
                        shard = shard.0,
                        ordinal = s.ordinal,
                        "durable entries for a shard we no longer hold: not applied, acked as failed"
                    );
                    unheld.push(shard);
                }
            }
        }
        let t = Instant::now();
        metrics::COMMIT_STAGE.with_label_values(&["apply_lock"]).observe((t - t_lock).as_secs_f64());
        // concurrently: one shard stalled on memtable backpressure mustn't
        // serialize the rest
        let writes = targets.into_iter().map(|(sink, muts)| {
            let mut wb = WriteBatch::new();
            let n = muts.len();
            // moved in: `put` would copy every key and value
            for m in muts {
                match m.val {
                    Some(v) => wb.put_bytes(m.key, v),
                    None => wb.delete(&m.key),
                }
            }
            wb.put(META_APPLIED, encode_marker(&log_id, s.ordinal));
            sink.applied.fetch_add(n as u64, Ordering::Relaxed);
            async move { (sink.id, sink.db.write(wb).await) }
        });
        for (shard, r) in futures::future::join_all(writes).await {
            if let Err(e) = r {
                // A runtime shutting down drops SlateDB's tasks while this
                // one may still be mid-poll, and its write fails. Nothing
                // here was acked: a fail-stop would only turn a clean exit
                // into exit 4.
                if runtime_stopping().await {
                    return;
                }
                tracing::error!(shard = shard.0, "state apply failed: {e}; exiting");
                vlsync_store::lifecycle::fail_stop(4, "state_apply");
            }
        }
        let _ = STATS.apply_us.lock().record(t.elapsed().as_micros().max(1) as u64);
        metrics::APPLY_DURATION.observe(t.elapsed().as_secs_f64());
        metrics::COMMIT_STAGE.with_label_values(&["apply"]).observe(t.elapsed().as_secs_f64());
        let t_ack = Instant::now();
        let events: Vec<(i64, Bytes)> =
            s.frames.iter().filter(|(_, r)| !r.is_empty()).map(|(seq, r)| (*seq, s.data.slice(r.clone()))).collect();
        let batch = LogBatch { log_id: log_id.clone(), ordinal: s.ordinal, events };
        live.push(Arc::new(batch.clone()), s.data.len());
        let _ = merger_tx.send(batch);
        if let Some(ok) = &lease_ok {
            if !ok() {
                tracing::error!(%log_id, "node lease lapsed before ack: fail-stop");
                vlsync_store::lifecycle::fail_stop(5, "lease_lapsed");
            }
        }
        wm.set_durable(s.last_seq);
        durable_ordinal.store(s.ordinal, Ordering::Release);
        feed.durable(s.ordinal, s.put_secs, s.stored_bytes);
        metrics::SEGMENTS.with_label_values(&["node"]).inc();
        metrics::SEGMENT_BYTES.observe(s.data.len() as f64);
        metrics::SEGMENT_BYTES_TOTAL.inc_by(s.data.len() as u64);
        metrics::SEGMENT_STORED_BYTES_TOTAL.inc_by(s.stored_bytes as u64);
        metrics::PUT_DURATION.with_label_values(&["node"]).observe(s.put_secs);
        metrics::COMMIT_STAGE.with_label_values(&["put"]).observe(s.put_secs);
        let n = s.acks.len();
        for (shard, ack, pending, enq) in s.acks {
            STATS.record_commit_latency(enq.elapsed());
            metrics::COMMIT_LATENCY.observe(enq.elapsed().as_secs_f64());
            if let Some(p) = pending {
                p.fetch_sub(1, Ordering::Release);
            }
            if let Some(ack) = ack {
                if unheld.contains(&shard) {
                    ack(Err(Arc::new(anyhow::anyhow!(NOT_HELD_LOGGED))));
                } else {
                    ack(Ok(()));
                }
            }
        }
        drop(guards);
        metrics::COMMIT_STAGE.with_label_values(&["ack"]).observe(t_ack.elapsed().as_secs_f64());
        STATS.entries_durable.fetch_add(n as u64, Ordering::Relaxed);
    }
}

/// One ownership span of a shard in some node's log: entries for the shard in
/// `log_id` with ordinals in [start, end) belong to ownership `epoch`.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct Span {
    pub log_id: String,
    pub epoch: u64,
    pub start: u64,
    /// None = still open (current owner).
    pub end: Option<u64>,
}

/// The span an applied marker `(log, ord)` was written in: the *earliest* span
/// of `log` that covers it (start - 1 <= ord < end; start - 1 = nothing of the
/// span applied yet). A node can hold a shard twice in one log (A -> B -> A),
/// so the log id alone is ambiguous, and matching a later span would skip the
/// spans in between. On a boundary the earlier span wins: replaying more than
/// needed is safe (absolute puts/deletes, in log order), replaying less is not.
fn marker_span(history: &[Span], log: &str, ord: u64) -> Option<usize> {
    history.iter().position(|s| s.log_id == log && s.start <= ord.saturating_add(1) && s.end.is_none_or(|e| ord < e))
}

/// Brings a shard's SlateDB up to date from the log spans of its previous
/// owners (chronological), starting after its applied marker.
pub async fn replay_shard(store: &Store, shard: ShardId, db: &Db, history: &[Span]) -> anyhow::Result<u64> {
    replay_many(store, &[(shard, db, history)]).await
}

/// Replays many shards at once: each log segment is fetched once (16 in
/// flight, applied in order) and its entries dispatched to every shard whose
/// span covers it. Returns segments read.
pub async fn replay_many(store: &Store, shards: &[(ShardId, &Db, &[Span])]) -> anyhow::Result<u64> {
    use futures::StreamExt;
    // per shard: the spans still to apply, with the ordinal to start from,
    // and whether that is a resume point (the marker strictly inside it)
    let mut todo: Vec<Vec<(Span, u64, bool)>> = Vec::with_capacity(shards.len());
    for (shard, db, history) in shards {
        let marker = match db.get(META_APPLIED).await? {
            Some(b) => Some(decode_marker(&b).map_err(|e| e.context(format!("shard {shard}")))?),
            None => None,
        };
        // A marker always names a span of the history (spans leave it only
        // below `Assignment::applied_epoch`). One that names none means a
        // span the shard still needs was dropped: replaying from the oldest
        // one left would serve without that span's acked writes.
        let first = match &marker {
            Some((log, ord)) => marker_span(history, log, *ord).ok_or_else(|| {
                anyhow::anyhow!("shard {shard}: its applied marker ({log}, {ord}) names no span of its history {history:?}: a span it needs is missing; refusing to replay")
            })?,
            None => 0,
        };
        let mut v = Vec::new();
        for (i, span) in history.iter().enumerate().skip(first) {
            let (from, resume) = match &marker {
                Some((log, ord)) if i == first && &span.log_id == log => {
                    ((ord + 1).max(span.start), ord + 1 > span.start)
                }
                _ => (span.start, false),
            };
            if span.end.is_none_or(|e| from < e) {
                v.push((span.clone(), from, resume));
            }
        }
        todo.push(v);
    }
    let mut read = 0u64;
    let rounds = todo.iter().map(|v| v.len()).max().unwrap_or(0);
    for k in 0..rounds {
        // group this round's spans by log
        let mut by_log: std::collections::BTreeMap<String, Vec<(usize, Span, u64)>> = Default::default();
        let mut resumes: Vec<(String, u64, Span)> = Vec::new();
        for (i, v) in todo.iter().enumerate() {
            if let Some((span, from, resume)) = v.get(k) {
                by_log.entry(span.log_id.clone()).or_default().push((i, span.clone(), *from));
                if *resume {
                    resumes.push((span.log_id.clone(), *from, span.clone()));
                }
            }
        }
        for (log_id, members) in by_log {
            let mut lo = members.iter().map(|m| m.2).min().unwrap_or(0);
            // Retention may have pruned the log's head, which holds nothing
            // these spans still need (DESIGN.md "Log retention"), but never
            // past a resume point: the shard's next entries may be right
            // after its marker.
            let head = vlsync_firehose::backfill::first_ordinal(store, &log_id).await?;
            if let Some((_, from, span)) =
                resumes.iter().find(|(l, from, _)| *l == log_id && head.is_none_or(|h| h > *from))
            {
                anyhow::bail!("log {log_id} is pruned to {head:?}, past ordinal {from} where replay of {span:?} resumes after its applied marker");
            }
            match head {
                Some(first) => lo = lo.max(first),
                // nothing left: retention deleted a dead log's fence, which it
                // does only once no replay needs the log (an open span has
                // no fence yet)
                None if members.iter().all(|m| m.1.end.is_some()) => continue,
                None => {}
            }
            let hi = if members.iter().any(|m| m.1.end.is_none()) {
                u64::MAX
            } else {
                members.iter().filter_map(|m| m.1.end).max().unwrap_or(0)
            };
            let fetch = |ord: u64| {
                let (store, path) = (store.clone(), segment_path(store, &log_id, ord));
                async move {
                    match store.raw.get(&path).await {
                        // decompressed here, in parallel ahead of the apply loop
                        Ok(r) => {
                            let data = r.bytes().await?;
                            tokio::task::spawn_blocking(move || segment::decode(data)).await?.map(Some)
                        }
                        Err(object_store::Error::NotFound { .. }) => Ok(None),
                        Err(e) => Err(e.into()),
                    }
                }
            };
            let mut objs = futures::stream::iter(lo..hi).map(fetch).buffered(16);
            let mut ord = lo;
            // per member: the last ordinal read whose marker isn't written
            // yet (segments with none of its entries only move the marker,
            // written once at the end rather than per segment per shard)
            let mut marker_due: Vec<Option<u64>> = vec![None; members.len()];
            while let Some(obj) = objs.next().await {
                // The end of the log is only legitimate past every closed span:
                // a closed span's end is the fence ordinal.
                let seg = match obj? {
                    Some(data) => match crate::derived::parse(data, None)? {
                        LogObject::Segment(h, entries) => Some((h, entries)),
                        LogObject::Fence { .. } => None,
                    },
                    None => None,
                };
                let Some((h, entries)) = seg else {
                    if let Some((_, span, _)) =
                        members.iter().find(|(_, s, from)| ord >= *from && s.end.is_some_and(|e| ord < e))
                    {
                        anyhow::bail!("log {log_id} ends at ordinal {ord} inside closed span {span:?}");
                    }
                    break;
                };
                check_header(&h, &log_id, ord)?;
                read += 1;
                for (j, (i, span, from)) in members.iter().enumerate() {
                    if ord < *from || span.end.is_some_and(|e| ord >= e) {
                        continue;
                    }
                    let (shard, db, _) = &shards[*i];
                    let mut wb = WriteBatch::new();
                    let mut any = false;
                    for e in entries.iter() {
                        if e.shard != *shard || e.epoch != span.epoch {
                            continue;
                        }
                        any = true;
                        for m in &e.muts {
                            match &m.val {
                                Some(v) => wb.put(&m.key, v),
                                None => wb.delete(&m.key),
                            }
                        }
                    }
                    if !any {
                        marker_due[j] = Some(ord);
                        continue;
                    }
                    wb.put(META_APPLIED, encode_marker(&span.log_id, ord));
                    db.write(wb).await?;
                    marker_due[j] = None;
                }
                ord += 1;
            }
            for (j, due) in marker_due.into_iter().enumerate() {
                if let Some(o) = due {
                    let (i, span, _) = &members[j];
                    let mut wb = WriteBatch::new();
                    wb.put(META_APPLIED, encode_marker(&span.log_id, o));
                    shards[*i].1.write(wb).await?;
                }
            }
        }
    }
    Ok(read)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vlsync_firehose::log::{first_free, prefix_hole, read_head, Head};
    use vlsync_store::segment::SegmentBuilder;

    fn seg_bytes(log: &str, ord: u64, shard: ShardId, epoch: u64, key: &str) -> Vec<u8> {
        let mut b = SegmentBuilder::new();
        let m = Mutation { key: Bytes::from(key.to_string()), val: Some(Bytes::from_static(b"v")) };
        b.push(1000 + ord as i64, shard, epoch, |_| {}, &[m]);
        let mut obj = b.header(log, ord);
        obj.extend_from_slice(&b.body);
        obj
    }

    async fn put_seg(store: &Store, log: &str, ord: u64, shard: ShardId, epoch: u64, key: &str) {
        store
            .raw
            .put(&segment_path(store, log, ord), PutPayload::from(seg_bytes(log, ord, shard, epoch, key)))
            .await
            .unwrap();
    }

    fn span(log: &str, epoch: u64, start: u64, end: Option<u64>) -> Span {
        Span { log_id: log.into(), epoch, start, end }
    }

    /// A -> B -> A in one incarnation of A: the marker (A, 1) left by B's
    /// takeover replay must not match A's second span, or B's acked writes
    /// are skipped.
    #[tokio::test]
    async fn replay_aba_keeps_middle_span() {
        let store = Store::memory(None);
        let shard = ShardId(70_007);
        put_seg(&store, "A", 0, shard, 1, "a0").await;
        put_seg(&store, "A", 1, shard, 1, "a1").await;
        put_seg(&store, "B", 0, shard, 2, "b0").await;
        put_seg(&store, "B", 1, shard, 2, "b1").await;
        let db = crate::partition::open_db(&store, shard, None).await.unwrap();
        let mut wb = WriteBatch::new();
        wb.put(b"a0", b"v");
        wb.put(b"a1", b"v");
        wb.put(META_APPLIED, encode_marker("A", 1));
        db.write(wb).await.unwrap();
        let history = vec![span("A", 1, 0, Some(2)), span("B", 2, 0, Some(2)), span("A", 3, 2, None)];
        let n = replay_many(&store, &[(shard, &db, &history)]).await.unwrap();
        assert_eq!(n, 2);
        assert!(db.get(b"b0").await.unwrap().is_some());
        assert!(db.get(b"b1").await.unwrap().is_some());
        // marker inside A's second span: nothing before it is replayed
        put_seg(&store, "A", 2, shard, 3, "a2").await;
        put_seg(&store, "A", 3, shard, 3, "a3").await;
        let mut wb = WriteBatch::new();
        wb.put(META_APPLIED, encode_marker("A", 2));
        db.write(wb).await.unwrap();
        assert_eq!(replay_many(&store, &[(shard, &db, &history)]).await.unwrap(), 1);
        assert!(db.get(b"a3").await.unwrap().is_some());
    }

    /// A marker that doesn't decode is an error (the shard doesn't open),
    /// never "no marker": that would replay every span over newer state.
    #[tokio::test]
    async fn malformed_applied_marker_is_an_error() {
        assert_eq!(decode_marker(&encode_marker("A.1", 7)).unwrap(), ("A.1".to_string(), 7));
        let good = encode_marker("A", 1);
        let before = vlsync_store::metrics::FORMAT_ERRORS.with_label_values(&["applied_marker"]).get();
        let trailing = [good.as_slice(), b"x".as_slice()].concat();
        let bads: [&[u8]; 4] = [&good[..good.len() - 1], &trailing, b"", b"\x00\x09abc"];
        for bad in bads {
            assert!(decode_marker(bad).is_err(), "{bad:?}");
        }
        assert!(vlsync_store::metrics::FORMAT_ERRORS.with_label_values(&["applied_marker"]).get() >= before + 4);
        let store = Store::memory(None);
        let shard = ShardId(70_008);
        put_seg(&store, "A", 0, shard, 1, "a0").await;
        let db = crate::partition::open_db(&store, shard, None).await.unwrap();
        let mut wb = WriteBatch::new();
        wb.put(META_APPLIED, b"\x00\x05AB");
        db.write(wb).await.unwrap();
        let err = replay_many(&store, &[(shard, &db, &[span("A", 1, 0, None)])]).await.unwrap_err();
        assert!(format!("{err:#}").contains("malformed applied marker"), "{err:#}");
        assert!(db.get(b"a0").await.unwrap().is_none(), "nothing replayed");
    }

    #[test]
    fn marker_span_picks_the_covering_span() {
        let h = vec![span("A", 1, 0, Some(5)), span("B", 2, 0, Some(3)), span("A", 3, 9, None)];
        assert_eq!(marker_span(&h, "A", 2), Some(0));
        assert_eq!(marker_span(&h, "A", 4), Some(0));
        assert_eq!(marker_span(&h, "A", 8), Some(2)); // start - 1: nothing of it applied
        assert_eq!(marker_span(&h, "A", 20), Some(2));
        assert_eq!(marker_span(&h, "A", 6), None);
        assert_eq!(marker_span(&h, "B", 2), Some(1));
        assert_eq!(marker_span(&h, "C", 0), None);
        // back-to-back spans of one log: the earlier wins (replays more)
        let h = vec![span("A", 1, 0, Some(4)), span("A", 2, 4, None)];
        assert_eq!(marker_span(&h, "A", 3), Some(0));
    }

    #[tokio::test]
    async fn replay_rejects_holes_and_mislabeled_segments() {
        let store = Store::memory(None);
        let shard = ShardId(1);
        put_seg(&store, "A", 0, shard, 1, "a0").await;
        // ordinal 1 missing inside the closed span [0, 3)
        put_seg(&store, "A", 2, shard, 1, "a2").await;
        let db = crate::partition::open_db(&store, shard, None).await.unwrap();
        let history = vec![span("A", 1, 0, Some(3)), span("B", 2, 0, None)];
        let e = replay_many(&store, &[(shard, &db, &history)]).await.unwrap_err();
        assert!(e.to_string().contains("inside closed span"), "{e}");
        // a segment stored under the wrong ordinal
        let p = segment_path(&store, "A", 1);
        store.raw.put(&p, PutPayload::from(seg_bytes("A", 7, shard, 1, "a1"))).await.unwrap();
        let e = replay_many(&store, &[(shard, &db, &history)]).await.unwrap_err();
        assert!(e.to_string().contains("has header"), "{e}");
        // the end of an open span is fine (0 was applied before the errors)
        store.raw.put(&p, PutPayload::from(seg_bytes("A", 1, shard, 1, "a1"))).await.unwrap();
        assert_eq!(replay_many(&store, &[(shard, &db, &history)]).await.unwrap(), 2);
        assert!(db.get(b"a2").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn conflict_resolution() {
        let store = Store::memory(None);
        let path = segment_path(&store, "A", 0);
        let ours = Bytes::from(seg_bytes("A", 0, ShardId(1), 1, "k"));
        assert_eq!(resolve_conflict(&store, &path, &ours).await, Conflict::Missing);
        store.raw.put(&path, PutPayload::from_bytes(ours.clone())).await.unwrap();
        assert_eq!(resolve_conflict(&store, &path, &ours).await, Conflict::Ours);
        let other = Bytes::from(seg_bytes("A", 0, ShardId(1), 1, "other"));
        assert_eq!(resolve_conflict(&store, &path, &other).await, Conflict::Other);
        store.raw.put(&path, PutPayload::from_bytes(segment::fence_object("B"))).await.unwrap();
        assert_eq!(resolve_conflict(&store, &path, &ours).await, Conflict::Fenced);
    }

    /// In-memory object store whose segment PUTs can be delayed, or held
    /// forever (the node crashed before they landed), per ordinal.
    #[derive(Debug, Default)]
    struct FaultStore {
        inner: object_store::memory::InMemory,
        delays: Mutex<HashMap<u64, Duration>>,
        holds: Mutex<std::collections::HashSet<u64>>,
        /// Delay for every PUT that isn't a segment (SlateDB's SSTs and
        /// manifests).
        slow_state: Mutex<Option<Duration>>,
    }

    impl std::fmt::Display for FaultStore {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "FaultStore")
        }
    }

    #[async_trait::async_trait]
    impl object_store::ObjectStore for FaultStore {
        async fn put_opts(
            &self,
            location: &Path,
            payload: PutPayload,
            opts: PutOptions,
        ) -> object_store::Result<object_store::PutResult> {
            if let Some(ord) =
                location.filename().and_then(|f| f.strip_suffix(".seg")).and_then(|f| f.parse::<u64>().ok())
            {
                if self.holds.lock().contains(&ord) {
                    futures::future::pending::<()>().await;
                }
                let delay = self.delays.lock().get(&ord).copied();
                if let Some(d) = delay {
                    tokio::time::sleep(d).await;
                }
            } else {
                let delay = *self.slow_state.lock();
                if let Some(d) = delay {
                    tokio::time::sleep(d).await;
                }
            }
            self.inner.put_opts(location, payload, opts).await
        }
        async fn put_multipart_opts(
            &self,
            location: &Path,
            opts: object_store::PutMultipartOptions,
        ) -> object_store::Result<Box<dyn object_store::MultipartUpload>> {
            self.inner.put_multipart_opts(location, opts).await
        }
        async fn get_opts(
            &self,
            location: &Path,
            options: object_store::GetOptions,
        ) -> object_store::Result<object_store::GetResult> {
            self.inner.get_opts(location, options).await
        }
        fn delete_stream(
            &self,
            locations: futures::stream::BoxStream<'static, object_store::Result<Path>>,
        ) -> futures::stream::BoxStream<'static, object_store::Result<Path>> {
            self.inner.delete_stream(locations)
        }
        fn list(
            &self,
            prefix: Option<&Path>,
        ) -> futures::stream::BoxStream<'static, object_store::Result<object_store::ObjectMeta>> {
            self.inner.list(prefix)
        }
        async fn list_with_delimiter(&self, prefix: Option<&Path>) -> object_store::Result<object_store::ListResult> {
            self.inner.list_with_delimiter(prefix).await
        }
        async fn copy_opts(
            &self,
            from: &Path,
            to: &Path,
            options: object_store::CopyOptions,
        ) -> object_store::Result<()> {
            self.inner.copy_opts(from, to, options).await
        }
    }

    fn fault_store() -> (Arc<FaultStore>, Store) {
        let fs = Arc::new(FaultStore::default());
        (fs.clone(), Store { raw: fs, ..Store::memory(None) })
    }

    /// A log on `store` with K = `k`, owning `shard` (epoch 1) into a DB
    /// under its own prefix. Segments hold one entry each (`entry` makes
    /// entries bigger than max_segment_bytes).
    async fn test_log(
        store: &Store,
        k: usize,
        shard: ShardId,
        max_segment_bytes: usize,
    ) -> (Arc<NodeLog>, Arc<Db>, mpsc::UnboundedReceiver<LogBatch>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let cfg = NodeLogConfig {
            log_id: "L".into(),
            writer: 1,
            max_segment_bytes,
            hedge_after: Duration::from_secs(10),
            lease_ok: None,
        };
        let log = NodeLog::start_with_inflight(store.clone(), cfg, k, tx);
        let db = Arc::new(
            crate::partition::open_db(&Store { prefix: "apply".into(), ..store.clone() }, shard, None).await.unwrap(),
        );
        log.sinks.insert(Arc::new(ShardSink {
            id: shard,
            epoch: 1,
            db: db.clone(),
            apply_lock: Default::default(),
            applied: Default::default(),
            recent: Default::default(),
            barrier: Default::default(),
            totals: Default::default(),
        }));
        (log, db, rx)
    }

    fn entry(shard: ShardId, key: String, val_len: usize, ack: Option<AckFn>) -> LogEntry {
        LogEntry {
            shard,
            frames: vec![Frame {
                prefix: key.clone().into_bytes(),
                suffix: Vec::new(),
                derived_muts: 0,
                derived_gen: 0,
            }],
            muts: vec![Mutation { key: Bytes::from(key), val: Some(Bytes::from(vec![7u8; val_len])) }],
            ack,
            pending: None,
            enqueued: Instant::now(),
            totals: None,
        }
    }

    /// Sends `n` one-entry segments; returns the order acks arrived in.
    async fn send_n(log: &NodeLog, shard: ShardId, n: usize) -> Arc<Mutex<Vec<usize>>> {
        let acked = Arc::new(Mutex::new(Vec::new()));
        for i in 0..n {
            let a = acked.clone();
            let ack: AckFn = Box::new(move |r| {
                r.unwrap();
                a.lock().push(i);
            });
            log.tx.send(entry(shard, format!("k{i}"), 2000, Some(ack))).await.ok().unwrap();
            // let the sequencer seal it alone
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        acked
    }

    async fn exists(store: &Store, ord: u64) -> bool {
        matches!(read_head(store, "L", ord).await.unwrap(), Head::Segment(_))
    }

    /// Dropping the runtime while a segment PUT is in flight is not an
    /// upload failure. Shutdown cancels the PUT's task on one worker while
    /// another is still polling the sequencer, which then sees the PUT's
    /// JoinHandle fail.
    #[test]
    fn runtime_shutdown_mid_upload_is_not_a_fail_stop() {
        let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
        rt.block_on(async {
            let (fs, store) = fault_store();
            fs.holds.lock().insert(0);
            let shard = ShardId(9);
            let (log, _db, _rx) = test_log(&store, 1, shard, 1 << 20).await;
            log.tx.send(entry(shard, "k".into(), 10, None)).await.ok().unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
            // An entry for a shard the log doesn't hold is rejected inside
            // the sequencer's poll, so its ack holds the sequencer mid-poll
            // while the runtime shuts down around it.
            let (polling_tx, polling_rx) = tokio::sync::oneshot::channel();
            let ack: AckFn = Box::new(move |_| {
                let _ = polling_tx.send(());
                std::thread::sleep(Duration::from_millis(300));
            });
            log.tx.send(entry(ShardId(10), "x".into(), 10, Some(ack))).await.ok().unwrap();
            polling_rx.await.unwrap();
        });
        drop(rt);
    }

    /// A checkpoint on a slow state store doesn't hold the apply lock
    /// across its store calls: commits keep being applied and acked while
    /// its memtable flush waits on the store.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn slow_checkpoint_does_not_stall_the_finalizer() {
        let (fs, store) = fault_store();
        let shard = ShardId(5);
        let (log, _db, _merger) = test_log(&store, 2, shard, 1024).await;
        let acked = send_n(&log, shard, 1).await;
        let t = Instant::now();
        while acked.lock().is_empty() {
            assert!(t.elapsed() < Duration::from_secs(5), "first commit never acked");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        *fs.slow_state.lock() = Some(Duration::from_millis(1500));
        let l = log.clone();
        let s = log.sinks.get(shard).unwrap();
        let ckpt = tokio::spawn(async move { l.checkpoint_shard(&s).await });
        // the checkpoint is now in its (slow) flush
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!ckpt.is_finished());
        let t = Instant::now();
        let acked = send_n(&log, shard, 3).await;
        while acked.lock().len() < 3 {
            assert!(
                t.elapsed() < Duration::from_millis(1000),
                "commits stalled behind the checkpoint ({} acked)",
                acked.lock().len()
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(!ckpt.is_finished(), "the checkpoint was still flushing");
        *fs.slow_state.lock() = None;
        ckpt.await.unwrap();
    }

    /// K = 4 with segment 0 slow: 1..3 land first but are acked, applied,
    /// pushed to the live ring and the merger only after 0, in order.
    #[tokio::test]
    async fn out_of_order_completion_finalizes_in_order() {
        let (fs, store) = fault_store();
        fs.delays.lock().insert(0, Duration::from_millis(300));
        let (log, db, mut merger) = test_log(&store, 4, ShardId(3), 1024).await;
        let mut live = log.live.subscribe();
        let acked = send_n(&log, ShardId(3), 4).await;
        tokio::time::sleep(Duration::from_millis(80)).await;
        for o in 1..4 {
            assert!(exists(&store, o).await, "segment {o} landed");
        }
        assert!(!exists(&store, 0).await);
        assert!(acked.lock().is_empty(), "nothing acked before segment 0");
        assert_eq!(log.durable_ordinal.load(Ordering::Acquire), u64::MAX);
        assert!(matches!(live.try_recv(), LiveRecv::Empty));
        assert!(merger.try_recv().is_err());
        assert!(db.get(b"k1").await.unwrap().is_none(), "segment 1 not applied before 0");
        assert!(!log.wm.idle());
        // segments sealed while 0 was pending record it as the prefix end
        let Head::Segment(h) = read_head(&store, "L", 3).await.unwrap() else { panic!() };
        assert_eq!((h.prefix_end, prefix_hole(&store, &h, 0).await.unwrap()), (0, Some(0)));
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert_eq!(*acked.lock(), vec![0, 1, 2, 3]);
        assert_eq!(log.durable_ordinal.load(Ordering::Acquire), 3);
        assert!(log.wm.idle());
        for o in 0..4 {
            assert!(matches!(live.try_recv(), LiveRecv::Batch(b) if b.ordinal == o));
            assert_eq!(merger.try_recv().unwrap().ordinal, o);
        }
        assert_eq!(prefix_hole(&store, &h, 0).await.unwrap(), None, "segment 3 is in the gap-free prefix now");
        assert!(db.get(b"k3").await.unwrap().is_some());
        assert_eq!(first_free(&store, "L").await.unwrap(), (4, false));
    }

    /// A crash with K = 4 in flight leaves ordinal 1 missing and 2, 3
    /// present. Only 0 was acked; the fence goes at the hole, a zombie can't
    /// write it, and no reader gets past it.
    #[tokio::test]
    async fn crash_hole_is_fenced_and_never_read_past() {
        let (fs, store) = fault_store();
        fs.holds.lock().insert(1); // its PUT never lands: the node "crashed"
        let (log, _db, mut merger) = test_log(&store, 4, ShardId(3), 1024).await;
        let acked = send_n(&log, ShardId(3), 4).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(*acked.lock(), vec![0], "acks stop at the hole");
        assert_eq!(merger.try_recv().unwrap().ordinal, 0);
        assert!(merger.try_recv().is_err());
        assert!(exists(&store, 2).await && exists(&store, 3).await, "garbage past the hole");
        assert_eq!(log.durable_ordinal.load(Ordering::Acquire), 0);

        // the fencer's rule: the first non-segment ordinal
        assert_eq!(first_free(&store, "L").await.unwrap(), (1, false));
        let p = segment_path(&store, "L", 1);
        let create = PutOptions { mode: PutMode::Create, ..Default::default() };
        // (straight to the inner store: the faulty one holds every PUT at 1)
        use object_store::ObjectStore as _;
        fs.inner.put_opts(&p, PutPayload::from_bytes(segment::fence_object("B")), create.clone()).await.unwrap();
        // a zombie's PUT at the fence collides; a second fencer finds the same end
        let zombie = fs.inner.put_opts(&p, PutPayload::from_static(b"zombie"), create).await;
        assert!(matches!(zombie, Err(object_store::Error::AlreadyExists { .. })));
        assert_eq!(first_free(&store, "L").await.unwrap(), (1, true));

        // replay: the dead span ends at the fence; an open span stops at the hole
        let fresh = |name: &'static str| {
            let s = Store { prefix: name.into(), ..store.clone() };
            async move { crate::partition::open_db(&s, vlsync_store::slots::ShardId(3), None).await.unwrap() }
        };
        for (name, end) in [("r1", Some(1)), ("r2", None)] {
            let db = fresh(name).await;
            let history = vec![span("L", 1, 0, end)];
            assert_eq!(replay_many(&store, &[(ShardId(3), &db, &history)]).await.unwrap(), 1, "{name}");
            assert!(db.get(b"k0").await.unwrap().is_some());
            for k in ["k1", "k2", "k3"] {
                assert!(db.get(k.as_bytes()).await.unwrap().is_none(), "{name}: {k} replayed past the hole");
            }
        }
        // backfill and seek stop at the fence
        let (tx, mut rx) = mpsc::channel(64);
        vlsync_firehose::backfill::backfill(&store, 0, i64::MAX, &tx).await.unwrap();
        drop(tx);
        let mut n = 0;
        while rx.recv().await.is_some() {
            n += 1;
        }
        assert_eq!(n, 1, "only segment 0's event is served");
        assert_eq!(vlsync_firehose::backfill::seek(&store, "L", i64::MAX - 1).await.unwrap(), 1);
    }

    /// Single-log throughput, K = 1 vs K = 4, 25 ms (sigma 0.5) injected PUT
    /// latency, 256 KB segments of 1 KB entries.
    /// `cargo test --lib nodelog::tests::bench_inflight -- --ignored --nocapture`
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore]
    async fn bench_inflight() {
        const N: usize = 30_000;
        for k in [1, 2, 4] {
            let store = Store::memory(Some((25.0, 0.5)));
            let (log, _db, mut merger) = test_log(&store, k, ShardId(0), 256 << 10).await;
            tokio::spawn(async move { while merger.recv().await.is_some() {} });
            let done = Arc::new(AtomicUsize::new(0));
            let all = Arc::new(tokio::sync::Notify::new());
            let t = Instant::now();
            for i in 0..N {
                let (d, all) = (done.clone(), all.clone());
                let ack: AckFn = Box::new(move |r| {
                    r.unwrap();
                    if d.fetch_add(1, Ordering::AcqRel) + 1 == N {
                        all.notify_one();
                    }
                });
                log.tx.send(entry(ShardId(0), format!("k{i:08}"), 1000, Some(ack))).await.ok().unwrap();
            }
            all.notified().await;
            let secs = t.elapsed().as_secs_f64();
            let segs = log.durable_ordinal.load(Ordering::Acquire) + 1;
            println!(
                "K={k}: {N} entries in {secs:.2} s = {:.0}/s, {segs} segments ({:.1} segs/s)",
                N as f64 / secs,
                segs as f64 / secs
            );
        }
    }

    fn batch(ordinal: u64, n: usize) -> Arc<LogBatch> {
        Arc::new(LogBatch { log_id: "A".into(), ordinal, events: vec![(ordinal as i64, Bytes::from(vec![0u8; n]))] })
    }

    /// A write enqueued behind a shard's close barrier (`put_private` looked
    /// its Partition up before the close and sent after the barrier) must
    /// never be acked Ok: its segment lands past the span end the close
    /// publishes, where no successor replays it.
    #[tokio::test]
    async fn entry_behind_a_close_barrier_is_never_acked() {
        let (fs, store) = fault_store();
        let shard = ShardId(3);
        let (log, _db, _merger) = test_log(&store, 1, shard, 1 << 20).await;
        let sink = log.sinks.get(shard).unwrap();
        // an entry ahead of the barrier is taken and acked
        let (etx, erx) = tokio::sync::oneshot::channel();
        log.tx
            .send(entry(
                shard,
                "early".into(),
                10,
                Some(Box::new(move |r| {
                    let _ = etx.send(r.is_ok());
                })),
            ))
            .await
            .ok()
            .unwrap();
        let (btx, brx) = tokio::sync::oneshot::channel();
        log.tx
            .send(sink.barrier_entry(Box::new(move |r| {
                let _ = btx.send(r.is_ok());
            })))
            .await
            .ok()
            .unwrap();
        assert!(erx.await.unwrap() && brx.await.unwrap(), "the barrier is durable");
        assert!(sink.barrier_taken());
        // the late write; its segment (ordinal 1) is slow to land
        fs.delays.lock().insert(1, Duration::from_millis(300));
        let (tx, rx) = tokio::sync::oneshot::channel();
        log.tx
            .send(entry(
                shard,
                "late".into(),
                10,
                Some(Box::new(move |r| {
                    let _ = tx.send(r.is_ok());
                })),
            ))
            .await
            .ok()
            .unwrap();
        tokio::time::sleep(Duration::from_millis(30)).await;
        // the close completes: the sink goes, the span ends at the durable end
        log.sinks.remove(shard);
        assert_eq!(log.next_ordinal(), 1, "span end");
        assert!(!rx.await.unwrap(), "acked Ok past the span end: nobody replays it");
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert!(!exists(&store, 1).await, "never even logged");
    }

    /// A closed shard's replay floor is held while its close runs, however
    /// long (it was released RETIRED_GRACE after the sink went, even with
    /// the state not closed yet), then for RETIRED_GRACE after it finished.
    #[test]
    fn closing_shard_holds_its_replay_floor_until_retired() {
        let sinks = ShardSinks::new(Arc::new(AtomicU64::new(10)));
        sinks.retain.lock().floors.insert(ShardId(1), (4, 4));
        assert_eq!(sinks.replay_floor(), 4);
        sinks.remove(ShardId(1));
        assert_eq!(sinks.replay_floor(), 4, "closing");
        assert!(sinks.retain.lock().retired.is_empty(), "no grace clock runs before the close finishes");
        sinks.retire(ShardId(1));
        assert_eq!(sinks.replay_floor(), 4, "within the grace");
        sinks.retain.lock().retired[0].1 = Instant::now().checked_sub(RETIRED_GRACE + Duration::from_secs(1)).unwrap();
        assert_eq!(sinks.replay_floor(), 10, "released after it");
    }

    /// An applied marker naming no span of the history (one it needs was
    /// dropped) refuses to replay instead of starting at the oldest span
    /// left; so does a resume point retention pruned past.
    #[tokio::test]
    async fn replay_refuses_a_marker_outside_its_history() {
        let store = Store::memory(None);
        let shard = ShardId(70_009);
        for ord in 0..3 {
            put_seg(&store, "D", ord, shard, 1, &format!("d{ord}")).await;
        }
        put_seg(&store, "E", 0, shard, 3, "e0").await;
        let db = crate::partition::open_db(&store, shard, None).await.unwrap();
        let mut wb = WriteBatch::new();
        wb.put(META_APPLIED, encode_marker("C", 9));
        db.write(wb).await.unwrap();
        // C's span (which the marker names) is gone; D's is still needed
        let history = vec![span("D", 2, 0, Some(3)), span("E", 3, 0, Some(1))];
        let err = replay_many(&store, &[(shard, &db, &history)]).await.unwrap_err();
        assert!(format!("{err:#}").contains("names no span"), "{err:#}");
        assert!(db.get(b"e0").await.unwrap().is_none(), "nothing replayed");
        // marker inside D's span at 0; D pruned to 2: entry 1 is gone
        let mut wb = WriteBatch::new();
        wb.put(META_APPLIED, encode_marker("D", 0));
        db.write(wb).await.unwrap();
        store.raw.delete(&segment_path(&store, "D", 0)).await.unwrap();
        store.raw.delete(&segment_path(&store, "D", 1)).await.unwrap();
        let err = replay_many(&store, &[(shard, &db, &history)]).await.unwrap_err();
        assert!(format!("{err:#}").contains("resumes after its applied marker"), "{err:#}");
        // a head pruned only up to the resume point is fine
        put_seg(&store, "D", 1, shard, 2, "d1").await;
        assert_eq!(replay_many(&store, &[(shard, &db, &history)]).await.unwrap(), 3);
        assert!(db.get(b"d1").await.unwrap().is_some() && db.get(b"e0").await.unwrap().is_some());
    }

    #[test]
    fn live_ring_is_bounded_by_bytes() {
        let ring = LiveRing::new(1000);
        // no subscribers: nothing retained
        ring.push(batch(0, 400), 400);
        assert_eq!(ring.bytes(), 0);
        let mut fast = ring.subscribe();
        let mut slow = ring.subscribe();
        for o in 1..=2 {
            ring.push(batch(o, 400), 400);
            assert!(matches!(fast.try_recv(), LiveRecv::Batch(b) if b.ordinal == o));
        }
        assert!(matches!(fast.try_recv(), LiveRecv::Empty));
        assert_eq!(ring.bytes(), 800); // the slow one hasn't read them
        assert!(matches!(slow.try_recv(), LiveRecv::Batch(b) if b.ordinal == 1));
        assert_eq!(ring.bytes(), 400); // read by everyone: released
        for o in 3..=6 {
            ring.push(batch(o, 400), 400);
            assert!(matches!(fast.try_recv(), LiveRecv::Batch(b) if b.ordinal == o));
        }
        assert!(ring.bytes() <= 1000);
        assert!(matches!(slow.try_recv(), LiveRecv::Lagged));
        drop(slow);
        assert_eq!(ring.bytes(), 0);
    }
}
