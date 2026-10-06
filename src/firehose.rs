//! Firehose: merges durable node-log streams into one seq-ordered stream.
//!
//! Each log (this node's, each live peer's, and any dead node's log still
//! being drained from S3) delivers durable batches and a watermark W_l (every
//! event with seq <= W_l has been delivered). The merger emits events with
//! seq <= min_l W_l in seq order, so the merged order is total, stable and the
//! same on every node.
//!
//! The merged stream starts at a floor F (the clock at startup): every log
//! delivers its events with seq > F (followers catch up from S3, see
//! remote.rs), the merger drops anything <= F, and cursors at or below F are
//! backfilled from S3 (backfill.rs). A log followed later starts at the
//! merger's position at that moment, so nothing above it is skipped either,
//! and nothing at or below it is ever delivered: a joining node acks
//! nothing until every peer follows its log and its seqs pass every such
//! floor (`Cluster::try_join`).

use crate::backfill::{Reader, SegCache};
use crate::events;
use crate::metrics;
use crate::nodelog::{LogBatch, Watermark};
use crate::segment::{self, LogObject};
use crate::slots::SlotRange;
use crate::stats::STATS;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use parking_lot::RwLock;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, watch};

/// Where a log's watermark comes from: our own log, or a peer stream / S3
/// drain (the last watermark it reported).
#[derive(Clone)]
pub enum Source {
    Local(Arc<Watermark>),
    Remote(Arc<AtomicI64>),
}

impl Source {
    fn get(&self) -> i64 {
        match self {
            Source::Local(w) => w.get(),
            Source::Remote(a) => a.load(Ordering::Acquire),
        }
    }
}

/// Stream seqs other than the log keys, for vlRelay (opt-in through
/// [`Firehose::set_renumber`]; vlpds's own firehose sends the keys). Logs and
/// the merger stay in keys. Each emitted event gets the next seq of a dense
/// counter, spliced into its frame once per node, and cursors, the ring,
/// `last_emitted` and `ConnStats::last_seq` are in those seqs.
pub trait Renumber: Send + Sync + 'static {
    /// The seq of the merged stream's last event with key <= `key`. Asked
    /// once, for the start floor, after every log is durable up to it.
    fn anchor(&self, key: i64) -> futures::future::BoxFuture<'static, anyhow::Result<i64>>;
    /// Where to read the bucket from to serve the events after seq `after`:
    /// (key, seq of the last event with key <= it). The seq is <= `after`
    /// unless what's in between was pruned (then the caller sends
    /// OutdatedCursor and resumes from there).
    fn locate(&self, after: i64) -> futures::future::BoxFuture<'static, anyhow::Result<(i64, i64)>>;
    /// Writes `frame` with `seq` in place of the seq it carries.
    fn splice(&self, frame: &[u8], seq: i64, out: &mut Vec<u8>);
    /// The merger emitted `keys` as seqs `first`, `first + 1`, ..., and
    /// every event with key <= `bound` has been emitted.
    fn emitted(&self, keys: &[i64], first: i64, bound: i64);
}

/// Events emitted before they're in the bucket, read back from the
/// producer's own copy (vlRelay's quorum log: its commitlog holds every
/// committed entry above the last flush, which the bucket holds up to).
/// Opt-in through [`Firehose::set_local_tail`], counted streams only: the
/// backfill reads the bucket up to `floor()` and this above it.
pub trait LocalTail: Send + Sync + 'static {
    /// Every emitted event above this is readable here.
    fn floor(&self) -> i64;
    /// Events in (`after`, `until`], in order, about `max_bytes` of them (at
    /// least one if any); an error if `after` fell below the floor meanwhile.
    fn read(
        &self,
        after: i64,
        until: i64,
        max_bytes: usize,
    ) -> futures::future::BoxFuture<'_, anyhow::Result<Vec<(i64, Bytes)>>>;
}

pub struct MergedBatch {
    pub first: i64,
    pub last: i64,
    /// (seq, frame); each frame is a slice of `wire`
    pub events: Vec<(i64, Bytes)>,
    /// `wire.len()`
    pub bytes: usize,
    /// Wire bytes emitted through this batch since startup (subscriber lag
    /// is measured in these).
    pub end: u64,
    /// The events as consecutive binary websocket messages, written as-is
    /// to every subscriber. The frames are copied out of their segments, so
    /// the ring doesn't pin whole segment bodies.
    wire: Bytes,
    /// start of each event's message in `wire`
    offs: Vec<usize>,
    /// Computed by the first sharded subscriber to read the batch.
    slots: OnceLock<Vec<u16>>,
    /// Each event's log key when renumbered (empty: the seqs are the keys).
    keys: Vec<i64>,
    /// The [`FrameFilter`]'s verdicts and the generation they're for, from
    /// the first subscriber to read the batch under it. None inside: it
    /// skips none of these events.
    skips: parking_lot::Mutex<Option<(u64, Option<Arc<[bool]>>)>>,
}

impl MergedBatch {
    /// `events` in seq order; `emitted` = wire bytes emitted before it.
    fn new(events: Vec<(i64, Bytes)>, emitted: u64) -> MergedBatch {
        let mut buf = Vec::with_capacity(events.iter().map(|(_, f)| f.len() + 10).sum());
        let mut offs = Vec::with_capacity(events.len());
        let mut seqs = Vec::with_capacity(events.len());
        for (seq, f) in &events {
            offs.push(buf.len());
            push_message(&mut buf, OP_BINARY, f);
            seqs.push((*seq, buf.len() - f.len()));
        }
        Self::build(buf, offs, seqs, Vec::new(), emitted)
    }

    /// `events` in key order, as seqs `first`, `first + 1`, ...
    fn renumbered(events: Vec<(i64, Bytes)>, first: i64, r: &dyn Renumber, emitted: u64) -> MergedBatch {
        let mut buf = Vec::with_capacity(events.iter().map(|(_, f)| f.len() + 16).sum());
        let mut offs = Vec::with_capacity(events.len());
        let mut seqs = Vec::with_capacity(events.len());
        let mut keys = Vec::with_capacity(events.len());
        let mut frame = Vec::new();
        for (i, (key, f)) in events.iter().enumerate() {
            frame.clear();
            r.splice(f, first + i as i64, &mut frame);
            offs.push(buf.len());
            push_message(&mut buf, OP_BINARY, &frame);
            seqs.push((first + i as i64, buf.len() - frame.len()));
            keys.push(*key);
        }
        Self::build(buf, offs, seqs, keys, emitted)
    }

    /// `seqs`: each event's seq and where its payload starts in `buf`.
    fn build(buf: Vec<u8>, offs: Vec<usize>, seqs: Vec<(i64, usize)>, keys: Vec<i64>, emitted: u64) -> MergedBatch {
        let wire = Bytes::from(buf);
        let end = |j: usize| offs.get(j + 1).copied().unwrap_or(wire.len());
        let events: Vec<(i64, Bytes)> =
            seqs.iter().enumerate().map(|(j, (seq, at))| (*seq, wire.slice(*at..end(j)))).collect();
        MergedBatch {
            first: events[0].0,
            last: events[events.len() - 1].0,
            bytes: wire.len(),
            end: emitted + wire.len() as u64,
            events,
            wire,
            offs,
            slots: OnceLock::new(),
            keys,
            skips: parking_lot::Mutex::new(None),
        }
    }

    /// Event `i`'s log key (its seq unless renumbered).
    pub fn key(&self, i: usize) -> i64 {
        self.keys.get(i).copied().unwrap_or(self.events[i].0)
    }

    fn last_key(&self) -> i64 {
        self.key(self.events.len() - 1)
    }

    fn start(&self) -> u64 {
        self.end - self.bytes as u64
    }

    fn wire_from(&self, i: usize) -> Bytes {
        self.wire.slice(self.offs[i]..)
    }

    fn slots(&self) -> &[u16] {
        self.slots.get_or_init(|| self.events.iter().map(|(_, f)| event_slot(f)).collect())
    }

    /// Which events `filter` skips, computed once per filter generation
    /// (None: it skips none of them).
    fn skipped(&self, filter: &dyn FrameFilter) -> Option<Arc<[bool]>> {
        let g = filter.generation()?;
        let mut c = self.skips.lock();
        match &*c {
            Some((cg, v)) if *cg == g => v.clone(),
            _ => {
                let v: Vec<bool> = self.events.iter().map(|(_, f)| filter.skip(&frame_meta(f))).collect();
                let v: Option<Arc<[bool]>> = v.contains(&true).then(|| v.into());
                *c = Some((g, v.clone()));
                v
            }
        }
    }

    /// The messages of the events from index `i` on whose repo is in
    /// `range` (None: any) and that `skip` doesn't mark: one slice of `wire`
    /// per run of consecutive kept events. Returns the slices and the number
    /// of events.
    fn wire_runs(
        &self,
        i: usize,
        range: Option<&SlotRange>,
        skip: Option<&[bool]>,
    ) -> (Vec<std::io::IoSlice<'_>>, usize) {
        let slots = range.map(|r| (r, self.slots()));
        let keep = |j: usize| slots.is_none_or(|(r, s)| r.contains(s[j])) && skip.is_none_or(|s| !s[j]);
        let end = |j: usize| self.offs.get(j).copied().unwrap_or(self.wire.len());
        let len = self.events.len();
        let (mut runs, mut n, mut j) = (Vec::new(), 0, i);
        while j < len {
            if !keep(j) {
                j += 1;
                continue;
            }
            let a = j;
            while j < len && keep(j) {
                j += 1;
            }
            n += j - a;
            runs.push(std::io::IoSlice::new(&self.wire[self.offs[a]..end(j)]));
        }
        (runs, n)
    }
}

/// The hash slot of an event's repo (`repo` of a #commit, `did` of the
/// others), read straight from the frame's DAG-CBOR without decoding it. A
/// frame without one (none are produced) counts as slot 0, so a sharded
/// stream union still carries it exactly once.
pub fn event_slot(frame: &[u8]) -> u16 {
    frame_did(frame).map(crate::slots::slot_of_bytes).unwrap_or(0)
}

fn frame_did(f: &[u8]) -> Option<&[u8]> {
    let mut i = 0;
    cbor_skip(f, &mut i, 0)?; // header
    let (major, n) = cbor_head(f, &mut i)?;
    if major != 5 {
        return None;
    }
    for _ in 0..n {
        let key = cbor_text(f, &mut i)?;
        if key == b"repo" || key == b"did" {
            return cbor_text(f, &mut i);
        }
        cbor_skip(f, &mut i, 0)?;
    }
    None
}

/// A frame's event type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameKind {
    Commit,
    Sync,
    Identity,
    Account,
    /// `#info`, errors, anything else.
    Other,
}

/// What a [`FrameFilter`] sees of a frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameMeta<'a> {
    pub kind: FrameKind,
    /// `repo` of a #commit, `did` of a #sync, #identity or #account: the
    /// key each kind is checked and applied by, so a frame carrying both
    /// can't pass as the other DID. None for other kinds or a frame
    /// without it.
    pub did: Option<&'a [u8]>,
}

/// The type and DID of a frame, read straight from its DAG-CBOR without
/// decoding it.
pub fn frame_meta(f: &[u8]) -> FrameMeta<'_> {
    let mut meta = FrameMeta { kind: FrameKind::Other, did: None };
    let mut i = 0;
    let Some((5, n)) = cbor_head(f, &mut i) else { return meta };
    for _ in 0..n {
        let Some(key) = cbor_text(f, &mut i) else { return meta };
        if key == b"t" {
            meta.kind = match cbor_text(f, &mut i) {
                Some(b"#commit") => FrameKind::Commit,
                Some(b"#sync") => FrameKind::Sync,
                Some(b"#identity") => FrameKind::Identity,
                Some(b"#account") => FrameKind::Account,
                Some(_) => FrameKind::Other,
                None => return meta,
            };
        } else if cbor_skip(f, &mut i, 0).is_none() {
            return meta;
        }
    }
    let want: &[u8] = match meta.kind {
        FrameKind::Commit => b"repo",
        FrameKind::Sync | FrameKind::Identity | FrameKind::Account => b"did",
        FrameKind::Other => return meta,
    };
    let Some((5, n)) = cbor_head(f, &mut i) else { return meta };
    for _ in 0..n {
        let Some(key) = cbor_text(f, &mut i) else { return meta };
        if key == want {
            meta.did = cbor_text(f, &mut i);
            return meta;
        }
        if cbor_skip(f, &mut i, 0).is_none() {
            return meta;
        }
    }
    meta
}

/// Frames subscribeRepos leaves out, live and in cursor backfill (opt-in
/// through [`Firehose::set_filter`]; vlRelay's takedowns). A skipped frame
/// keeps its seq, so consumers see a gap rather than renumbered events.
pub trait FrameFilter: Send + Sync + 'static {
    /// None while it skips nothing: frames aren't even parsed. Otherwise a
    /// number that changes whenever `skip` may answer differently, since a
    /// ring batch's verdicts are computed once per generation and shared by
    /// all of its subscribers. Change it after the change `skip` sees.
    fn generation(&self) -> Option<u64>;
    fn skip(&self, frame: &FrameMeta<'_>) -> bool;
}

/// (major type, argument) of the item at `i`; definite lengths only (DAG-CBOR).
fn cbor_head(f: &[u8], i: &mut usize) -> Option<(u8, u64)> {
    let b = *f.get(*i)?;
    *i += 1;
    let n = match b & 0x1f {
        n @ 0..=23 => return Some((b >> 5, n as u64)),
        24 => 1,
        25 => 2,
        26 => 4,
        27 => 8,
        _ => return None,
    };
    let bytes = f.get(*i..*i + n)?;
    *i += n;
    Some((b >> 5, bytes.iter().fold(0u64, |a, x| a << 8 | *x as u64)))
}

fn cbor_text<'a>(f: &'a [u8], i: &mut usize) -> Option<&'a [u8]> {
    let (major, n) = cbor_head(f, i)?;
    if major != 3 {
        return None;
    }
    let s = f.get(*i..i.checked_add(usize::try_from(n).ok()?)?)?;
    *i += s.len();
    Some(s)
}

fn cbor_skip(f: &[u8], i: &mut usize, depth: u32) -> Option<()> {
    if depth > 64 {
        return None;
    }
    let (major, n) = cbor_head(f, i)?;
    match major {
        2 | 3 => {
            let end = i.checked_add(usize::try_from(n).ok()?)?;
            if end > f.len() {
                return None;
            }
            *i = end;
        }
        4 => {
            for _ in 0..n {
                cbor_skip(f, i, depth + 1)?;
            }
        }
        5 => {
            for _ in 0..n.checked_mul(2)? {
                cbor_skip(f, i, depth + 1)?;
            }
        }
        6 => cbor_skip(f, i, depth + 1)?,
        _ => {}
    }
    Some(())
}

#[derive(Clone)]
pub struct Options {
    /// Bytes of merged batches kept in memory for cursors and slow readers.
    pub ring_bytes: usize,
    /// A live subscriber further than this behind the stream head gets
    /// ConsumerTooSlow and is closed (it resumes from its cursor).
    pub max_lag_bytes: usize,
    /// Read-ahead per cursor backfill, across all logs.
    pub readahead_bytes: usize,
    pub backfill_cache_bytes: usize,
    /// More wait for a slot: read-ahead memory is at most this x
    /// `readahead_bytes`.
    pub max_backfills: usize,
    /// Per client IP (IPv6: per /64); 0 = no cap.
    pub max_per_ip: usize,
    /// A write outside the live path (backfill, info frames, pongs) that
    /// makes no progress for this long drops the subscriber.
    pub write_idle: Duration,
    /// None = the caller's runtime.
    pub runtime: Option<tokio::runtime::Handle>,
    /// Connections with their own `vlpds_firehose_subscriber_*` series; the
    /// rest share `conn="other"`.
    pub max_labelled: usize,
    /// None: seqs are log keys (time-based) and the stream starts at the
    /// clock. Some(f): seqs are a plain counter (vlRelay's quorum log) and
    /// the stream starts above `f`; a cursor past the head then gets the
    /// counted stream's grace instead of a comparison with the clock.
    pub start_floor: Option<i64>,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            ring_bytes: 64 << 20,
            max_lag_bytes: DEFAULT_MAX_LAG_BYTES,
            readahead_bytes: crate::backfill::DEFAULT_READAHEAD_BYTES,
            backfill_cache_bytes: crate::backfill::DEFAULT_CACHE_BYTES,
            max_backfills: DEFAULT_MAX_BACKFILLS,
            max_per_ip: DEFAULT_MAX_PER_IP,
            write_idle: DEFAULT_WRITE_IDLE,
            runtime: None,
            max_labelled: DEFAULT_MAX_LABELLED,
            start_floor: None,
        }
    }
}

pub const DEFAULT_MAX_BACKFILLS: usize = 16;
/// A relay may open one per `?shard=k/n` slice.
pub const DEFAULT_MAX_PER_IP: usize = 256;
pub const DEFAULT_WRITE_IDLE: Duration = Duration::from_secs(30);
pub const DEFAULT_MAX_LAG_BYTES: usize = 128 << 20;
/// Bounds the `/metrics` exposition if someone opens thousands of
/// connections.
pub const DEFAULT_MAX_LABELLED: usize = 1000;

/// The process-wide runtime for subscriber connections (subscribeRepos
/// fan-out, cursor backfills): their socket writes and frame copies stay off
/// the request runtime, so heavy fan-out can't stall writes. The first
/// caller's thread count wins.
pub fn runtime(threads: usize) -> tokio::runtime::Handle {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(threads.max(1))
            .thread_name("firehose")
            .enable_all()
            .build()
            .expect("firehose runtime")
    })
    .handle()
    .clone()
}

pub struct Firehose {
    /// Bytes emitted so far (the newest batch's `end`): subscribers wait on it.
    head: watch::Sender<u64>,
    ring: RwLock<VecDeque<Arc<MergedBatch>>>,
    ring_bytes: AtomicI64,
    max_ring_bytes: i64,
    pub last_emitted: AtomicI64,
    pub sources: RwLock<HashMap<Arc<str>, Source>>,
    /// The ring holds every event with seq > ring_floor (the start floor
    /// until the ring evicts). Older cursors are backfilled from S3.
    ring_floor: AtomicI64,
    /// `ring_floor` as a log key (the same unless renumbered). Both change
    /// under the ring's write lock.
    ring_floor_key: AtomicI64,
    renumber: OnceLock<Arc<dyn Renumber>>,
    filter: OnceLock<Arc<dyn FrameFilter>>,
    local_tail: OnceLock<Arc<dyn LocalTail>>,
    /// False while renumbered and not anchored yet: nothing is served.
    ready: watch::Sender<bool>,
    /// The merged stream's start floor F: events <= F are only served by the
    /// S3 backfill.
    start_floor: i64,
    /// Highest min watermark the merger has acted on: every event <= it (and
    /// > start_floor) of every followed log has been emitted.
    settled: AtomicI64,
    /// Set once the node log is known.
    pub store: RwLock<Option<crate::store::Store>>,
    max_queue_bytes: AtomicUsize,
    queued_bytes: AtomicUsize,
    /// Set (for good) when this node leaves the cluster: the merger emits
    /// nothing more (see `freeze`).
    frozen: AtomicBool,
    /// Set (for good) as the node drains: every subscriber, connected or
    /// connecting, gets a going-away close.
    closing: watch::Sender<bool>,
    runtime: tokio::runtime::Handle,
    max_lag_bytes: u64,
    readahead_bytes: usize,
    backfill_cache: Arc<SegCache>,
    backfill_slots: Arc<tokio::sync::Semaphore>,
    max_per_ip: usize,
    per_ip: parking_lot::Mutex<HashMap<std::net::IpAddr, usize>>,
    write_idle: Duration,
    /// `settled`, for backfills waiting on it.
    settled_tx: watch::Sender<i64>,
    /// Connected subscribers, for the operator's list. Locked on connect,
    /// disconnect and listing only: progress goes through each entry's
    /// atomics.
    subs: parking_lot::Mutex<HashMap<u64, Arc<SubscriberEntry>>>,
    gone: parking_lot::Mutex<VecDeque<GoneSubscriber>>,
    /// Connections with their own per-connection series, at most
    /// `max_labelled`.
    labelled: AtomicUsize,
    max_labelled: usize,
    /// Seqs are a counter, not time (`Options::start_floor`).
    counted: bool,
}

impl Firehose {
    pub fn new(opts: Options) -> Arc<Firehose> {
        let floor = opts.start_floor.unwrap_or_else(|| crate::nodelog::seq_floor(crate::tid::now_micros()));
        Arc::new(Firehose {
            head: watch::channel(0).0,
            ring: RwLock::new(VecDeque::new()),
            ring_bytes: AtomicI64::new(0),
            max_ring_bytes: opts.ring_bytes as i64,
            last_emitted: AtomicI64::new(0),
            sources: RwLock::new(HashMap::new()),
            ring_floor: AtomicI64::new(floor),
            ring_floor_key: AtomicI64::new(floor),
            renumber: OnceLock::new(),
            filter: OnceLock::new(),
            local_tail: OnceLock::new(),
            ready: watch::channel(true).0,
            start_floor: floor,
            settled: AtomicI64::new(i64::MIN),
            store: RwLock::new(None),
            max_queue_bytes: AtomicUsize::new(DEFAULT_MERGE_QUEUE_BYTES),
            queued_bytes: AtomicUsize::new(0),
            frozen: AtomicBool::new(false),
            closing: watch::channel(false).0,
            runtime: opts.runtime.unwrap_or_else(tokio::runtime::Handle::current),
            max_lag_bytes: opts.max_lag_bytes as u64,
            readahead_bytes: opts.readahead_bytes,
            backfill_cache: SegCache::new(opts.backfill_cache_bytes),
            backfill_slots: Arc::new(tokio::sync::Semaphore::new(opts.max_backfills.max(1))),
            max_per_ip: opts.max_per_ip,
            per_ip: Default::default(),
            write_idle: opts.write_idle,
            settled_tx: watch::channel(i64::MIN).0,
            subs: Default::default(),
            gone: Default::default(),
            labelled: AtomicUsize::new(0),
            max_labelled: opts.max_labelled,
            counted: opts.start_floor.is_some(),
        })
    }

    /// Changes whenever a batch is emitted (its value: bytes emitted so far).
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.head.subscribe()
    }

    pub fn min_watermark(&self) -> Option<i64> {
        self.sources.read().values().map(|s| s.get()).min()
    }

    /// Everything at or below this has been emitted (or is below the start
    /// floor): a log followed from now on only owes us its events above it.
    pub fn position(&self) -> i64 {
        self.start_floor.max(self.settled.load(Ordering::Acquire))
    }

    /// Registers a newly followed peer log: returns the floor its follower
    /// must deliver every event above, and its watermark (starting just
    /// below it). Taken under the sources lock, so no merger tick that
    /// ignored this log can settle past the floor afterwards.
    ///
    /// The watermark starts *below* the floor: at startup the S3 backfill
    /// serves events <= floor and waits for `settled` to reach the floor as
    /// proof that every log is durable up to it, which only the peer can
    /// vouch for (its first heartbeat, or a segment read back from S3).
    /// Otherwise a backfill could run while the peer still had segments in
    /// flight with seqs <= floor and skip them for good.
    pub fn add_remote(&self, log_id: &str) -> (i64, Arc<AtomicI64>) {
        let mut s = self.sources.write();
        let floor = self.position();
        let wm = Arc::new(AtomicI64::new(floor - 1));
        s.insert(log_id.into(), Source::Remote(wm.clone()));
        (floor, wm)
    }

    /// Adds (Some) or removes (None) a log's watermark source. Remove a log
    /// only after every one of its events has been handed to the merger.
    pub fn set_source(&self, log_id: &str, source: Option<Source>) {
        let mut s = self.sources.write();
        match source {
            Some(src) => {
                s.insert(log_id.into(), src);
            }
            None => {
                s.remove(log_id);
            }
        }
    }

    /// Stops the merger for good: called as a node leaves the cluster
    /// (graceful shutdown, before its lease is deleted). It no longer
    /// discovers joiners, and a node joining once our lease is gone neither
    /// counts nor greets us, so merging on could emit past a joiner's first
    /// events without them. Subscribers keep what was emitted; they resume
    /// elsewhere from their cursors when we close.
    pub fn freeze(&self) {
        self.frozen.store(true, Ordering::Release);
    }

    /// Closes every subscriber with 1001 (going away) at its next frame
    /// boundary: they reconnect and resume from their cursors.
    pub fn close_subscribers(&self) {
        self.closing.send_replace(true);
    }

    /// Backfills what the bucket doesn't hold yet from the producer (see
    /// [`LocalTail`]). Counted streams only.
    pub fn set_local_tail(&self, t: Arc<dyn LocalTail>) {
        assert!(self.counted, "a local tail needs a counted stream");
        let _ = self.local_tail.set(t);
    }

    /// Serves renumbered seqs (see [`Renumber`]). Set before `spawn_merger`.
    pub fn set_renumber(&self, r: Arc<dyn Renumber>) {
        if self.renumber.set(r).is_ok() {
            self.ready.send_replace(false);
        }
    }

    pub fn renumbered(&self) -> bool {
        self.renumber.get().is_some()
    }

    /// Leaves the frames `f` skips out of every subscriber's stream (see
    /// [`FrameFilter`]). Set once, before serving.
    pub fn set_filter(&self, f: Arc<dyn FrameFilter>) {
        let _ = self.filter.set(f);
    }

    /// (ring floor, its key), read together.
    fn ring_floors(&self) -> (i64, i64) {
        let _ring = self.ring.read();
        (self.ring_floor.load(Ordering::Acquire), self.ring_floor_key.load(Ordering::Acquire))
    }

    /// The log key of the event with seq `seq` if it's in the ring, else
    /// the ring floor's key if it's older (None: newer than the head).
    pub fn key_at(&self, seq: i64) -> Option<i64> {
        let ring = self.ring.read();
        let i = ring.partition_point(|b| b.last < seq);
        match ring.get(i) {
            Some(b) if b.first <= seq => {
                Some(b.key(b.events.partition_point(|(s, _)| *s < seq).min(b.events.len() - 1)))
            }
            Some(_) => Some(self.ring_floor_key.load(Ordering::Acquire)),
            None => None,
        }
    }

    /// Over this many queued bytes, logs are spilled (see `spawn_merger`).
    pub fn set_max_queue_bytes(&self, n: usize) {
        self.max_queue_bytes.store(n, Ordering::Relaxed);
    }

    pub fn queued_bytes(&self) -> usize {
        self.queued_bytes.load(Ordering::Relaxed)
    }

    /// Merges every followed log's batches by seq.
    ///
    /// While one log holds the min watermark back (a dead peer whose fence
    /// hasn't been drained yet), every other log queues here. Past the byte
    /// budget the merger *spills* a log instead of queueing it: it ignores
    /// that log's batches from then on and later reads them back from its S3
    /// segments, one chunk at a time as the watermark lets them out, until it
    /// meets the live stream again. Memory stays near the budget however long
    /// the stall lasts; the merged order is unchanged (events are durable in
    /// S3 before any producer hands them to us).
    pub fn spawn_merger(self: &Arc<Self>, mut rx: mpsc::UnboundedReceiver<LogBatch>) {
        let fh = self.clone();
        // critical: a panic here fail-stops the node (lifecycle.rs)
        tokio::spawn(crate::lifecycle::critical("firehose_merger", async move {
            let mut logs: HashMap<Arc<str>, LogQ> = HashMap::new();
            // Everything at or below this has been emitted (or is below the
            // start floor): later events at or below it are late.
            let mut emitted = fh.start_floor;
            let mut total = 0usize;
            let mut tick = tokio::time::interval(Duration::from_millis(2));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let mut behind = false;
            let mut pushed = 0u64;
            let renumber = fh.renumber.get().cloned();
            // the seq of the last event emitted, once anchored
            let mut seq: Option<i64> = None;
            let mut anchoring: Option<tokio::task::JoinHandle<anyhow::Result<i64>>> = None;
            let mut anchor_retry = tokio::time::Instant::now();
            loop {
                if !behind {
                    tick.tick().await;
                }
                behind = false;
                if fh.frozen.load(Ordering::Acquire) {
                    loop {
                        match rx.try_recv() {
                            Ok(_) => {}
                            Err(mpsc::error::TryRecvError::Empty) => break,
                            Err(mpsc::error::TryRecvError::Disconnected) => return,
                        }
                    }
                    continue;
                }
                // Read the watermark *before* draining: anything at or below it
                // was sent to us before the watermark was published. Settle it
                // under the sources lock (see add_remote): from here on the
                // merger owes exactly the events <= w of the logs it saw.
                let w = {
                    let s = fh.sources.read();
                    let Some(w) = s.values().map(|s| s.get()).min() else {
                        continue;
                    };
                    if fh.settled.fetch_max(w, Ordering::AcqRel) < w {
                        fh.settled_tx.send_if_modified(|v| std::mem::replace(v, w) < w);
                    }
                    w
                };
                let max = fh.max_queue_bytes.load(Ordering::Relaxed);
                let store = fh.store.read().clone();
                let mut late = 0usize;
                loop {
                    let b = match rx.try_recv() {
                        Ok(b) => b,
                        Err(mpsc::error::TryRecvError::Empty) => break,
                        Err(mpsc::error::TryRecvError::Disconnected) => return,
                    };
                    let lq = logs.entry(b.log_id.clone()).or_default();
                    match &lq.spill {
                        // already read back from S3, or will be
                        Some(sp) if b.ordinal != sp.next || sp.end || total >= max / 2 => continue,
                        Some(_) => {
                            // the read-back met the live stream: queue it again
                            tracing::info!(log_id = %b.log_id, ordinal = b.ordinal, "firehose merger: spilled log rejoined the live stream");
                            lq.spill = None;
                        }
                        None if total >= max && store.is_some() => {
                            tracing::warn!(log_id = %b.log_id, ordinal = b.ordinal, queued = total, "firehose merger: queue over budget, spilling log to S3 read-back");
                            metrics::FIREHOSE_SPILLS.inc();
                            lq.spill = Some(Spill { next: b.ordinal, loaded: lq.high, end: false, checked: None });
                            continue;
                        }
                        None => {}
                    }
                    total += lq.accept(b.events, emitted, fh.start_floor, &mut late);
                }
                let mut bound = w;
                if let Some(store) = &store {
                    let more;
                    (bound, more) = read_back(
                        store,
                        &mut logs,
                        w,
                        (max / 16).max(1),
                        emitted,
                        fh.start_floor,
                        &mut total,
                        &mut late,
                    )
                    .await;
                    behind |= more;
                }
                if late > 0 {
                    tracing::warn!(late, emitted, "firehose merger: dropped late events below the emitted watermark");
                }
                if let Some(r) = renumber.as_ref().filter(|_| seq.is_none()) {
                    if anchoring.is_none()
                        && fh.settled.load(Ordering::Acquire) >= fh.start_floor
                        && tokio::time::Instant::now() >= anchor_retry
                    {
                        anchoring = Some(tokio::spawn(r.anchor(fh.start_floor)));
                    }
                    if anchoring.as_ref().is_some_and(|j| j.is_finished()) {
                        match anchoring.take().expect("checked").await {
                            Ok(Ok(n)) => {
                                tracing::info!(key = fh.start_floor, seq = n, "firehose: stream seqs anchored");
                                seq = Some(n);
                                {
                                    let _ring = fh.ring.write();
                                    fh.ring_floor.store(n, Ordering::Release);
                                }
                                fh.last_emitted.store(n, Ordering::Release);
                                fh.ready.send_replace(true);
                            }
                            Ok(Err(e)) => tracing::warn!("firehose: anchoring stream seqs failed, retrying: {e:#}"),
                            Err(e) => tracing::warn!("firehose: anchoring stream seqs failed, retrying: {e}"),
                        }
                        anchor_retry = tokio::time::Instant::now() + Duration::from_millis(500);
                    }
                    // nothing leaves the queues until seqs can be numbered
                    if seq.is_none() {
                        bound = bound.min(fh.start_floor);
                    }
                }
                let mut out = Vec::new();
                for lq in logs.values_mut() {
                    while let Some((seq, f)) = lq.q.front() {
                        if *seq > bound {
                            break;
                        }
                        lq.bytes -= f.len();
                        total -= f.len();
                        out.push(lq.q.pop_front().unwrap());
                    }
                }
                emitted = emitted.max(bound);
                // forget logs that are gone and fully emitted
                {
                    let s = fh.sources.read();
                    logs.retain(|id, lq| {
                        !lq.q.is_empty() || s.contains_key(id) || lq.spill.as_ref().is_some_and(|sp| !sp.end)
                    });
                }
                fh.queued_bytes.store(total, Ordering::Relaxed);
                metrics::FIREHOSE_MERGE_QUEUE_BYTES.set(total as i64);
                if out.is_empty() {
                    if let (Some(r), Some(n)) = (&renumber, seq) {
                        r.emitted(&[], n + 1, emitted);
                    }
                    continue;
                }
                out.sort_unstable_by_key(|(s, _)| *s);
                let batch = match (&renumber, seq) {
                    (Some(r), Some(n)) => {
                        let b = MergedBatch::renumbered(out, n + 1, r.as_ref(), pushed);
                        seq = Some(b.last);
                        r.emitted(&b.keys, b.first, emitted);
                        b
                    }
                    _ => MergedBatch::new(out, pushed),
                };
                let batch = Arc::new(batch);
                pushed = batch.end;
                STATS.firehose_events.fetch_add(batch.events.len() as u64, Ordering::Relaxed);
                metrics::FIREHOSE_EVENTS.inc_by(batch.events.len() as u64);
                metrics::FIREHOSE_BATCH.observe(batch.events.len() as f64);
                if !fh.counted {
                    metrics::FIREHOSE_EMIT_DELAY
                        .observe(crate::tid::now_micros().saturating_sub((batch.key(0) >> 8) as u64) as f64 / 1e6);
                }
                fh.push(batch);
            }
        }));
    }

    fn push(&self, batch: Arc<MergedBatch>) {
        {
            let mut ring = self.ring.write();
            self.ring_bytes.fetch_add(batch.bytes as i64, Ordering::Relaxed);
            ring.push_back(batch.clone());
            while self.ring_bytes.load(Ordering::Relaxed) > self.max_ring_bytes && ring.len() > 1 {
                let old = ring.pop_front().unwrap();
                self.ring_floor.fetch_max(old.last, Ordering::AcqRel);
                self.ring_floor_key.fetch_max(old.last_key(), Ordering::AcqRel);
                self.ring_bytes.fetch_sub(old.bytes as i64, Ordering::Relaxed);
            }
        }
        metrics::FIREHOSE_RING_BYTES.set(self.ring_bytes.load(Ordering::Relaxed));
        self.last_emitted.store(batch.last, Ordering::Release);
        self.head.send_replace(batch.end);
    }

    /// Batches with events with seq > `after` currently in the ring, and
    /// whether the ring still reaches back to `after` (false = some were
    /// already dropped).
    pub fn from_ring(&self, after: i64) -> (Vec<Arc<MergedBatch>>, bool) {
        let ring = self.ring.read();
        // seqs are gappy: completeness is about what was evicted, not adjacency.
        let complete = after >= self.ring_floor.load(Ordering::Acquire);
        let i = ring.partition_point(|b| b.last <= after);
        (ring.range(i..).cloned().collect(), complete)
    }

    /// subscribeRepos: answers the websocket handshake and serves the
    /// connection on the firehose runtime (see [`runtime`]).
    ///
    /// The upgrade is done by hand rather than with axum's `WebSocket` so a
    /// subscriber owns its raw socket: every event goes out as the batch's
    /// pre-built websocket messages (`MergedBatch::wire`), one write per
    /// batch shared byte-for-byte by every subscriber, instead of a framing
    /// pass, a sink send and a flush per event per subscriber.
    ///
    /// `shard` (vlpds extension, `?shard=k/n`): only events whose repo hashes
    /// into that slice of the slot space. Same seqs, order and cursors as the
    /// full stream (a cursor from either works on the other); the union of
    /// the n streams is the full stream.
    ///
    /// `client` (the trusted-proxy-resolved client address): at most
    /// `Options::max_per_ip` connections per address (IPv6: per /64), 429
    /// past it. `relay`: the configured relay the client matched, if any.
    pub fn upgrade(
        self: &Arc<Self>,
        mut req: axum::extract::Request,
        cursor: Option<i64>,
        shard: Option<SlotRange>,
        client: Option<std::net::IpAddr>,
        relay: Option<String>,
    ) -> Response {
        let accept = match handshake(req.headers()) {
            Ok(a) => a,
            Err(e) => return e.into_response(),
        };
        let slot = match client.map(|ip| self.ip_slot(ip)) {
            Some(None) => {
                metrics::FIREHOSE_REJECTED.with_label_values(&["per_ip"]).inc();
                let body = serde_json::json!({"error": "RateLimitExceeded", "message": "too many subscribeRepos connections from this address"});
                return (StatusCode::TOO_MANY_REQUESTS, axum::Json(body)).into_response();
            }
            Some(Some(s)) => Some(s),
            None => None,
        };
        let id = NEXT_CONN.fetch_add(1, Ordering::Relaxed);
        let series = Series::new(self, id, client, relay.as_deref());
        let conn = Arc::new(ConnStats::default());
        let _ = conn.series.set((series.events.clone(), series.bytes.clone()));
        let entry = SubscriberEntry {
            id,
            labelled: series.labels.is_some(),
            ip: client,
            user_agent: user_agent(req.headers()),
            relay,
            connected_at_ms: now_ms(),
            cursor,
            shard: shard.map(|s| format!("{}/{}", s.k, s.n)),
            stats: conn.clone(),
        };
        let closed = ClosedOnDrop(conn);
        let on_upgrade = hyper::upgrade::on(&mut req);
        let fh = self.clone();
        self.runtime.spawn(async move {
            let (_slot, _series) = (slot, series);
            let listed = Listed::new(&fh, entry);
            let up = match on_upgrade.await {
                Ok(up) => up,
                Err(e) => return tracing::debug!("subscribeRepos upgrade failed: {e}"),
            };
            metrics::FIREHOSE_CONNECTIONS
                .with_label_values(&[if cursor.is_some() { "backfill" } else { "live" }])
                .inc();
            // a kick (or a runtime shutdown) drops `serve` unfinished
            let mut sub = Subscribed::new("kicked", Some(listed));
            let c = closed.0.clone();
            // dropping `serve` closes the socket wherever it was waiting
            tokio::select! {
                r = fh.serve(up, cursor, shard, c.clone()) => sub.reason = r,
                _ = c.kick.notified() => {}
            }
        });
        (
            StatusCode::SWITCHING_PROTOCOLS,
            [
                (header::CONNECTION, "upgrade".to_string()),
                (header::UPGRADE, "websocket".to_string()),
                (header::SEC_WEBSOCKET_ACCEPT, accept),
            ],
        )
            .into_response()
    }

    /// None = at the cap.
    fn ip_slot(self: &Arc<Self>, ip: std::net::IpAddr) -> Option<IpSlot> {
        if self.max_per_ip == 0 {
            return Some(IpSlot { fh: None, key: ip });
        }
        let key = ip_key(ip);
        let mut m = self.per_ip.lock();
        let n = m.entry(key).or_default();
        if *n >= self.max_per_ip {
            return None;
        }
        *n += 1;
        Some(IpSlot { fh: Some(self.clone()), key })
    }

    pub fn connections_from(&self, ip: std::net::IpAddr) -> usize {
        self.per_ip.lock().get(&ip_key(ip)).copied().unwrap_or(0)
    }

    /// Returns the disconnect reason.
    async fn serve(
        self: Arc<Self>,
        up: hyper::upgrade::Upgraded,
        cursor: Option<i64>,
        shard: Option<SlotRange>,
        conn: Arc<ConnStats>,
    ) -> &'static str {
        use hyper_util::rt::TokioIo;
        use tokio::net::TcpStream;
        // Move the socket onto this runtime's reactor (it was accepted on
        // the request runtime), so its readiness events are ours too.
        match hyper_util::server::conn::auto::upgrade::downcast::<TokioIo<TcpStream>>(up) {
            Ok(parts) => match parts.io.into_inner().into_std().and_then(TcpStream::from_std) {
                Ok(tcp) => {
                    let (r, w) = tcp.into_split();
                    self.serve_conn(std::io::Cursor::new(parts.read_buf).chain(r), w, cursor, shard, Some(conn)).await
                }
                Err(e) => {
                    tracing::debug!("subscribeRepos socket: {e}");
                    "client_gone"
                }
            },
            Err(up) => {
                tracing::debug!(
                    "subscribeRepos: upgraded connection isn't a plain TCP stream; serving it through hyper's IO"
                );
                let (r, w) = tokio::io::split(TokioIo::new(up));
                self.serve_conn(r, w, cursor, shard, Some(conn)).await
            }
        }
    }

    async fn serve_conn<R, W>(
        &self,
        r: R,
        w: W,
        cursor: Option<i64>,
        shard: Option<SlotRange>,
        conn: Option<Arc<ConnStats>>,
    ) -> &'static str
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin,
    {
        let (ctl_tx, ctl) = mpsc::channel(8);
        // the read half keeps the socket open until it's aborted, kicks included
        let _reader = AbortOnDrop(tokio::spawn(read_client(r, ctl_tx, self.closing.subscribe())));
        let mut out = Out { w, ctl, idle: self.write_idle, conn };
        match self.stream(&mut out, cursor, shard).await {
            Ok(()) => "shutdown",
            Err(reason) => reason,
        }
    }

    async fn stream<W: AsyncWrite + Unpin>(
        &self,
        out: &mut Out<W>,
        cursor: Option<i64>,
        shard: Option<SlotRange>,
    ) -> Result<(), &'static str> {
        let mut head = self.head.subscribe();
        let mut ready = self.ready.subscribe();
        while !*ready.borrow_and_update() {
            tokio::select! {
                r = ready.changed() => if r.is_err() { return Ok(()) },
                c = out.ctl.recv() => out.control(c).await?,
            }
        }
        let mut last = match cursor {
            Some(c) => c,
            // the ring holds everything above its floor
            None => self.last_emitted.load(Ordering::Acquire).max(self.ring_floor.load(Ordering::Acquire)),
        };
        out.sent(0, 0, last);
        if let Some(c) = cursor {
            // seqs are time-based: a cursor beyond both the stream head and the
            // current clock can't have been issued by us. Renumbered seqs
            // aren't: another node's stream may just be ahead of ours (an
            // edge trails the cores), so give ours a moment to get there.
            let future = if self.renumbered() || self.counted {
                let deadline = tokio::time::Instant::now() + FUTURE_CURSOR_GRACE;
                while c > self.last_emitted.load(Ordering::Acquire) && tokio::time::Instant::now() < deadline {
                    tokio::select! {
                        _ = head.changed() => {}
                        _ = tokio::time::sleep_until(deadline) => {}
                        c = out.ctl.recv() => out.control(c).await?,
                    }
                }
                c > self.last_emitted.load(Ordering::Acquire)
            } else {
                let now = crate::nodelog::seq_floor(crate::tid::now_micros()) | 0xff;
                c > self.last_emitted.load(Ordering::Acquire).max(now)
            };
            if future {
                out.finish(&events::error_frame("FutureCursor", "cursor in the future")).await;
                return Err("future_cursor");
            }
            // older than the ring: stream it from the S3 segments first
            self.catch_up(out, &mut last, shard).await?;
        }
        // Live. A subscriber more than `allowance` bytes behind the head is
        // dropped: the configured bound, or (a cursor replaying the ring)
        // what it started with, so it may catch up but not fall further back.
        let mut allowance = None;
        // stream offset up to which this subscriber got the ring's batches
        // (None: it came from S3 or hasn't been sent any yet)
        let mut sent_to: Option<u64> = None;
        loop {
            head.borrow_and_update();
            let (batches, complete) = self.from_ring(last);
            if !complete {
                // The ring is a memory budget, not the lag rule: it can drop
                // batches a subscriber within its allowance hasn't been sent
                // (a ring smaller than the allowance; or a backfill handing
                // over right at the ring floor as the next batch evicts it).
                // Those catch up from S3 again; only one past its allowance
                // is too slow.
                let lag = sent_to.map(|p| self.head.borrow().saturating_sub(p));
                let within = lag.is_none_or(|l| l <= allowance.unwrap_or(self.max_lag_bytes));
                if within && self.store.read().is_some() {
                    self.catch_up(out, &mut last, shard).await?;
                    sent_to = None;
                    continue;
                }
                out.finish(&events::error_frame("ConsumerTooSlow", "fell behind the in-memory window")).await;
                return Err("too_slow");
            }
            if batches.is_empty() {
                tokio::select! {
                    r = head.changed() => {
                        if r.is_err() {
                            return Ok(());
                        }
                    }
                    c = out.ctl.recv() => out.control(c).await?,
                }
                continue;
            }
            let allowance = *allowance
                .get_or_insert_with(|| self.max_lag_bytes.max(self.head.borrow().saturating_sub(batches[0].start())));
            for b in &batches {
                let i = b.events.partition_point(|(seq, _)| *seq <= last);
                if i == b.events.len() {
                    continue;
                }
                let skip = self.filter.get().and_then(|f| b.skipped(f.as_ref()));
                let (sent, bytes) = match (&shard, &skip) {
                    (None, None) => {
                        let wire = b.wire_from(i);
                        out.send_live(&mut [std::io::IoSlice::new(&wire)], &mut head, b.start(), allowance).await?;
                        (b.events.len() - i, wire.len())
                    }
                    // only the kept events: each run of them is one slice
                    // of the shared bytes, all written in one go
                    _ => {
                        let (mut runs, n) = b.wire_runs(i, shard.as_ref(), skip.as_deref());
                        let len = runs.iter().map(|r| r.len()).sum();
                        if n > 0 {
                            out.send_live(&mut runs, &mut head, b.start(), allowance).await?;
                        }
                        (n, len)
                    }
                };
                metrics::FIREHOSE_SENT.inc_by(sent as u64);
                out.sent(sent, bytes, b.last);
                out.sent_to(b.end);
                last = b.last;
                sent_to = Some(b.end);
                while let Ok(c) = out.ctl.try_recv() {
                    out.control(Some(c)).await?;
                }
            }
        }
    }

    /// Streams (`last`, ring floor] from the S3 segments until the ring
    /// reaches back to `last` (the floor moves while it backfills); history
    /// that's gone is skipped with an `OutdatedCursor` info.
    async fn catch_up<W: AsyncWrite + Unpin>(
        &self,
        out: &mut Out<W>,
        last: &mut i64,
        shard: Option<SlotRange>,
    ) -> Result<(), &'static str> {
        out.set_backfilling(true);
        let r = self.catch_up_from_bucket(out, last, shard).await;
        out.set_backfilling(false);
        r
    }

    async fn catch_up_from_bucket<W: AsyncWrite + Unpin>(
        &self,
        out: &mut Out<W>,
        last: &mut i64,
        shard: Option<SlotRange>,
    ) -> Result<(), &'static str> {
        loop {
            if !self.backfill_to_ring(out, last, shard).await? {
                out.send(&info_frame("OutdatedCursor", OUTDATED_CURSOR)).await?;
                *last = (*last).max(self.ring_floor.load(Ordering::Acquire));
            }
            if *last >= self.ring_floor.load(Ordering::Acquire) {
                return Ok(());
            }
        }
    }

    /// Sends the events in (`last`, ring floor] from S3, once every log is
    /// durable up to the floor. Ok(false) = there's no store (nothing older
    /// than the ring exists): the caller skips to the ring. A backfill that
    /// keeps failing disconnects the subscriber.
    async fn backfill_to_ring<W: AsyncWrite + Unpin>(
        &self,
        out: &mut Out<W>,
        last: &mut i64,
        shard: Option<SlotRange>,
    ) -> Result<bool, &'static str> {
        let tail = self.local_tail.get().cloned();
        let store = self.store.read().clone();
        if store.is_none() && tail.is_none() {
            return Ok(false);
        }
        let (mut overtaken, mut failures) = (0u32, 0u32);
        // a running-backfill slot, taken once there is something to read
        let mut slot: Option<BackfillSlot> = None;
        let renumber = self.renumber.get().cloned();
        loop {
            let (floor, floor_key) = self.ring_floors();
            if *last >= floor {
                return Ok(true);
            }
            // right after startup the start floor can be ahead of a peer's
            // watermark: its events <= F may not be in S3 yet. Wait for the
            // merger to settle past it, answering the client meanwhile (and
            // noticing it leave).
            if self.settled.load(Ordering::Acquire) < floor_key {
                let mut settled = self.settled_tx.subscribe();
                tokio::select! {
                    _ = async { settled.wait_for(|s| *s >= floor_key).await.is_ok() } => {}
                    c = out.ctl.recv() => out.control(c).await?,
                    // the floor moves as the ring evicts: look again
                    _ = tokio::time::sleep(Duration::from_secs(1)) => {}
                }
                continue;
            }
            if slot.is_none() {
                slot = Some(self.backfill_slot(out).await?);
                continue; // the floor moved while it waited
            }
            if let Some(t) = tail.as_ref().filter(|t| *last >= t.floor()) {
                match t.read(*last, floor_key, BACKFILL_CHANNEL * 4096).await {
                    Ok(evs) => {
                        let Some(&(top, _)) = evs.last() else {
                            // nothing between the cursor and the ring
                            *last = (*last).max(floor);
                            continue;
                        };
                        let filter = self.filter.get().filter(|f| f.generation().is_some());
                        let mut buf = Vec::new();
                        let mut n = 0;
                        for (_, f) in &evs {
                            if filter.is_some_and(|x| x.skip(&frame_meta(f))) {
                                continue;
                            }
                            push_message(&mut buf, OP_BINARY, f);
                            n += 1;
                        }
                        if n > 0 {
                            out.write(&buf).await?;
                            metrics::FIREHOSE_SENT.inc_by(n as u64);
                            metrics::FIREHOSE_BACKFILL_EVENTS.inc_by(n as u64);
                        }
                        *last = top;
                        out.sent(n, buf.len(), *last);
                        while let Ok(c) = out.ctl.try_recv() {
                            out.control(Some(c)).await?;
                        }
                        failures = 0;
                    }
                    Err(e) => {
                        failures += 1;
                        if failures >= BACKFILL_ATTEMPTS {
                            tracing::warn!(
                                after = *last,
                                "firehose backfill: the local tail failed, disconnecting: {e:#}"
                            );
                            out.close(1011).await;
                            return Err("backfill_failed");
                        }
                        tokio::time::sleep(Duration::from_millis(100) * failures).await;
                    }
                }
                continue;
            }
            let Some(store) = store.clone() else { return Ok(false) };
            let reader =
                Reader { store, cache: self.backfill_cache.clone(), readahead_bytes: self.readahead_bytes, shard };
            // the bucket up to where the local tail takes over
            let (floor, floor_key) = match &tail {
                Some(t) => (floor.min(t.floor()), floor_key.min(t.floor())),
                None => (floor, floor_key),
            };
            // Where to read from, in keys, and the seq of the last event at
            // or below it (renumbered: the next event read is `seq + 1`).
            let (from, mut seq) = match &renumber {
                None => {
                    // older than what log retention deleted: OutdatedCursor, then the
                    // oldest events left (retention.rs raises this before deleting)
                    match crate::retention::retained_floor(&reader.store).await {
                        Ok(pruned) if *last < pruned => {
                            out.send(&info_frame("OutdatedCursor", OUTDATED_CURSOR)).await?;
                            *last = pruned;
                            continue;
                        }
                        Ok(_) => {}
                        Err(e) => tracing::warn!("reading the retained floor failed: {e:#}"),
                    }
                    (*last, *last)
                }
                Some(r) => match r.locate(*last).await {
                    Ok((key, seq)) if seq > *last => {
                        out.send(&info_frame("OutdatedCursor", OUTDATED_CURSOR)).await?;
                        *last = seq;
                        if seq >= floor {
                            // what's left starts in the ring
                            continue;
                        }
                        (key, seq)
                    }
                    Ok(v) => v,
                    Err(e) => {
                        failures += 1;
                        if failures >= BACKFILL_ATTEMPTS {
                            tracing::warn!(
                                after = *last,
                                "firehose backfill: locating the cursor failed, disconnecting: {e:#}"
                            );
                            out.close(1011).await;
                            return Err("backfill_failed");
                        }
                        tracing::warn!(after = *last, "firehose backfill: locating the cursor failed, retrying: {e:#}");
                        tokio::time::sleep(Duration::from_millis(100) * failures).await;
                        continue;
                    }
                },
            };
            let (tx, mut rx) = mpsc::channel(BACKFILL_CHANNEL);
            let r = reader.clone();
            let mut job =
                AbortOnDrop(tokio::spawn(
                    async move { crate::backfill::backfill_with(&r, from, floor_key, &tx).await },
                ));
            let mut chunk = Vec::with_capacity(1024);
            let mut buf = Vec::new();
            let mut frame = Vec::new();
            while rx.recv_many(&mut chunk, 1024).await > 0 {
                buf.clear();
                let mut n = 0;
                let filter = self.filter.get().filter(|f| f.generation().is_some());
                let skip = |f: &[u8]| filter.is_some_and(|x| x.skip(&frame_meta(f)));
                for (key, f) in &chunk {
                    match &renumber {
                        None => {
                            seq = *key;
                            if skip(f) {
                                continue;
                            }
                            push_message(&mut buf, OP_BINARY, f);
                        }
                        Some(r) => {
                            seq += 1;
                            // the read started at a checkpoint before the cursor
                            if seq <= *last || skip(f) {
                                continue;
                            }
                            frame.clear();
                            r.splice(f, seq, &mut frame);
                            push_message(&mut buf, OP_BINARY, &frame);
                        }
                    }
                    n += 1;
                }
                chunk.clear();
                if n == 0 {
                    continue;
                }
                out.write(&buf).await?;
                metrics::FIREHOSE_SENT.inc_by(n as u64);
                metrics::FIREHOSE_BACKFILL_EVENTS.inc_by(n as u64);
                *last = seq;
                out.sent(n, buf.len(), *last);
                while let Ok(c) = out.ctl.try_recv() {
                    out.control(Some(c)).await?;
                }
            }
            let err = match (&mut job.0).await {
                Ok(Ok(_)) => {
                    if renumber.is_some() && seq != floor {
                        // the bucket and the merged stream disagree on how
                        // many events there are: a numbering bug
                        tracing::error!(
                            from,
                            floor_key,
                            read_to = seq,
                            floor,
                            "firehose backfill: stream seqs don't match the bucket"
                        );
                    }
                    *last = (*last).max(floor); // everything <= floor that exists was sent
                    (overtaken, failures) = (0, 0);
                    continue;
                }
                Ok(Err(e)) => e,
                Err(e) => anyhow::anyhow!("backfill task: {e}"),
            };
            if err.downcast_ref::<crate::backfill::Pruned>().is_some() && overtaken < MAX_PRUNED_RETRIES {
                // Retention deleted segments the reader was walking. All of
                // them are <= the retained floor (raised before deleting):
                // past `last`, the check above sends OutdatedCursor; at or
                // below it, nothing we owe was deleted (a log's head below
                // the cursor pruned under the seek, e.g. a dead log wholly
                // below it): read again from `last`. Each retry needs a new
                // delete, so this ends.
                overtaken += 1;
                metrics::FIREHOSE_BACKFILL_RETRIES.with_label_values(&["pruned"]).inc();
                tracing::debug!(from, floor, "firehose backfill overtaken by retention, retrying: {err:#}");
                continue;
            }
            // Anything else (an S3 error) is retried a few times, then the
            // subscriber is disconnected to resume from its cursor: skipping
            // to the ring would drop stored events behind an OutdatedCursor.
            failures += 1;
            if failures >= BACKFILL_ATTEMPTS {
                tracing::warn!(from, floor, "firehose backfill failed, disconnecting: {err:#}");
                out.close(1011).await;
                return Err("backfill_failed");
            }
            metrics::FIREHOSE_BACKFILL_RETRIES.with_label_values(&["error"]).inc();
            tracing::warn!(from, floor, "firehose backfill failed, retrying: {err:#}");
            tokio::time::sleep(Duration::from_millis(100) * failures).await;
        }
    }
}

/// One subscriber's progress, for [`Firehose::subscribers`]. Updated once
/// per batch written.
#[derive(Default)]
pub struct ConnStats {
    /// Events written to the subscriber.
    pub events: AtomicU64,
    /// Bytes of those events' messages.
    pub bytes: AtomicU64,
    /// Stream position: the newest seq passed (0 = none yet). A sharded
    /// subscriber passes events it isn't sent.
    pub last_seq: AtomicI64,
    /// Streaming from the bucket rather than the ring.
    pub backfilling: AtomicBool,
    /// The stream offset the subscriber was sent the ring up to (0: none
    /// since it last went live), for its lag in bytes.
    pub sent_to: AtomicU64,
    /// The connection ended (or never started), however it ended.
    pub closed: AtomicBool,
    kick: tokio::sync::Notify,
    /// Its `vlpds_firehose_subscriber_{events,bytes}_total` series, resolved
    /// at connect.
    series: OnceLock<(prometheus::IntCounter, prometheus::IntCounter)>,
}

impl ConnStats {
    /// Disconnects the subscriber at once, even an idle one.
    pub fn kick(&self) {
        // notify_one keeps a permit: a kick before the upgrade completes isn't lost
        self.kick.notify_one();
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }
}

struct ClosedOnDrop(Arc<ConnStats>);

impl Drop for ClosedOnDrop {
    fn drop(&mut self) {
        self.0.closed.store(true, Ordering::Relaxed);
    }
}

/// A served subscriber, counted out with its disconnect reason when its
/// serve future ends or is dropped.
struct Subscribed {
    reason: &'static str,
    listed: Option<Listed>,
}

impl Subscribed {
    fn new(reason: &'static str, listed: Option<Listed>) -> Subscribed {
        metrics::FIREHOSE_SUBSCRIBERS.inc();
        Subscribed { reason, listed }
    }
}

impl Drop for Subscribed {
    fn drop(&mut self) {
        metrics::FIREHOSE_SUBSCRIBERS.dec();
        metrics::FIREHOSE_DISCONNECTS.with_label_values(&[self.reason]).inc();
        if let Some(l) = &mut self.listed {
            l.reason = Some(self.reason);
        }
    }
}

/// Process-wide, so two firehoses in one process (tests, memory clusters)
/// never share a series.
static NEXT_CONN: AtomicU64 = AtomicU64::new(1);
const USER_AGENT_CHARS: usize = 120;
/// Disconnected subscribers kept for the operator's list.
const GONE_KEPT: usize = 50;
pub const OTHER: &str = "other";

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64)
}

fn user_agent(h: &HeaderMap) -> String {
    let ua = h.get(header::USER_AGENT).and_then(|v| v.to_str().ok()).unwrap_or("");
    ua.chars().take(USER_AGENT_CHARS).collect()
}

/// A connection's `vlpds_firehose_subscriber_*` series: its own
/// `{ip, conn, relay}` while fewer than `max_labelled` connections have one
/// (the earliest keep theirs, so a series never changes labels midway), else
/// the shared `other`. Its own series go when it does.
struct Series {
    fh: Arc<Firehose>,
    labels: Option<[String; 3]>,
    events: prometheus::IntCounter,
    bytes: prometheus::IntCounter,
}

impl Series {
    fn new(fh: &Arc<Firehose>, id: u64, ip: Option<std::net::IpAddr>, relay: Option<&str>) -> Series {
        let own = fh
            .labelled
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| (n < fh.max_labelled).then_some(n + 1))
            .is_ok();
        let labels = if own {
            [
                ip.map_or_else(|| "unknown".into(), |ip| ip_key(ip).to_string()),
                id.to_string(),
                relay.unwrap_or("").into(),
            ]
        } else {
            [OTHER.into(), OTHER.into(), String::new()]
        };
        let l = [labels[0].as_str(), labels[1].as_str(), labels[2].as_str()];
        Series {
            fh: fh.clone(),
            events: metrics::FIREHOSE_SUBSCRIBER_EVENTS.with_label_values(&l),
            bytes: metrics::FIREHOSE_SUBSCRIBER_BYTES.with_label_values(&l),
            labels: own.then_some(labels),
        }
    }
}

impl Drop for Series {
    fn drop(&mut self) {
        let Some(labels) = &self.labels else { return };
        let l = [labels[0].as_str(), labels[1].as_str(), labels[2].as_str()];
        let _ = metrics::FIREHOSE_SUBSCRIBER_EVENTS.remove_label_values(&l);
        let _ = metrics::FIREHOSE_SUBSCRIBER_BYTES.remove_label_values(&l);
        self.fh.labelled.fetch_sub(1, Ordering::AcqRel);
    }
}

/// A connected subscriber as the operator sees it.
struct SubscriberEntry {
    id: u64,
    labelled: bool,
    ip: Option<std::net::IpAddr>,
    user_agent: String,
    relay: Option<String>,
    connected_at_ms: u64,
    cursor: Option<i64>,
    shard: Option<String>,
    stats: Arc<ConnStats>,
}

struct GoneSubscriber {
    entry: Arc<SubscriberEntry>,
    at_ms: u64,
    reason: &'static str,
}

/// An entry in [`Firehose::subscribers`] while it's connected, then kept
/// among the recently gone with its reason if it was served.
struct Listed {
    fh: Arc<Firehose>,
    entry: Arc<SubscriberEntry>,
    reason: Option<&'static str>,
}

impl Listed {
    fn new(fh: &Arc<Firehose>, e: SubscriberEntry) -> Listed {
        let entry = Arc::new(e);
        fh.subs.lock().insert(entry.id, entry.clone());
        Listed { fh: fh.clone(), entry, reason: None }
    }
}

impl Drop for Listed {
    fn drop(&mut self) {
        self.fh.subs.lock().remove(&self.entry.id);
        if let Some(reason) = self.reason {
            let mut g = self.fh.gone.lock();
            if g.len() >= GONE_KEPT {
                g.pop_back();
            }
            g.push_front(GoneSubscriber { entry: self.entry.clone(), at_ms: now_ms(), reason });
        }
    }
}

/// One subscriber in `vlpds.admin.listFirehoseSubscribers`.
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SubscriberView {
    /// Its `conn` label, when `labelled` (else it counts under `other`).
    pub conn: String,
    pub labelled: bool,
    pub ip: Option<String>,
    /// The address's PTR name (filled in by the listing, from `ptr`'s cache).
    #[serde(default)]
    pub ptr: Option<String>,
    /// `ptr` resolves back to the address; an unverified name is anyone's
    /// claim.
    #[serde(default)]
    pub ptr_verified: bool,
    /// Its origin AS (from `asn`'s cache).
    #[serde(default)]
    pub asn: Option<u32>,
    #[serde(default)]
    pub as_name: Option<String>,
    #[serde(default)]
    pub as_country: Option<String>,
    pub user_agent: String,
    pub relay: Option<String>,
    pub connected_at: u64,
    /// Seqs as strings: they're past 2^53, where JSON numbers lose digits.
    pub cursor: Option<String>,
    pub shard: Option<String>,
    /// backfilling | live
    pub state: String,
    pub last_seq: String,
    pub events: u64,
    pub bytes: u64,
    /// Live only: bytes of the stream it hasn't been sent yet.
    pub lag_bytes: Option<u64>,
    /// Time-based seqs: how far its position trails the stream head.
    pub lag_ms: Option<u64>,
    /// Renumbered seqs: events between its position and the head.
    pub lag_events: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disconnected_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl Firehose {
    /// The connected subscribers (oldest first) and the recently gone ones
    /// (newest first).
    pub fn subscribers(&self) -> (Vec<SubscriberView>, Vec<SubscriberView>) {
        let head = *self.head.borrow();
        let emitted = self.last_emitted.load(Ordering::Acquire);
        let renumbered = self.renumbered();
        let view = |e: &SubscriberEntry| {
            let s = &e.stats;
            let backfilling = s.backfilling.load(Ordering::Relaxed);
            let last_seq = s.last_seq.load(Ordering::Relaxed);
            let sent_to = s.sent_to.load(Ordering::Relaxed);
            let behind = emitted.saturating_sub(last_seq).max(0) as u64;
            SubscriberView {
                conn: e.id.to_string(),
                labelled: e.labelled,
                ip: e.ip.map(|ip| ip.to_canonical().to_string()),
                ptr: None,
                ptr_verified: false,
                asn: None,
                as_name: None,
                as_country: None,
                user_agent: e.user_agent.clone(),
                relay: e.relay.clone(),
                connected_at: e.connected_at_ms,
                cursor: e.cursor.map(|c| c.to_string()),
                shard: e.shard.clone(),
                state: if backfilling { "backfilling" } else { "live" }.into(),
                last_seq: last_seq.to_string(),
                events: s.events.load(Ordering::Relaxed),
                bytes: s.bytes.load(Ordering::Relaxed),
                lag_bytes: (!backfilling && sent_to > 0).then(|| head.saturating_sub(sent_to)),
                lag_ms: (!renumbered && last_seq > 0).then_some((behind >> 8) / 1000),
                lag_events: (renumbered && last_seq > 0).then_some(behind),
                disconnected_at: None,
                reason: None,
            }
        };
        let mut live: Vec<SubscriberView> = Vec::new();
        let mut ids: Vec<(u64, SubscriberView)> = self.subs.lock().values().map(|e| (e.id, view(e))).collect();
        ids.sort_by_key(|(id, _)| *id);
        live.extend(ids.into_iter().map(|(_, v)| v));
        let gone = self
            .gone
            .lock()
            .iter()
            .map(|g| SubscriberView {
                disconnected_at: Some(g.at_ms),
                reason: Some(g.reason.to_string()),
                ..view(&g.entry)
            })
            .collect();
        (live, gone)
    }

    /// Disconnects connected subscriber `conn` (its [`SubscriberView::conn`])
    /// at once, even an idle one; false if it isn't connected.
    pub fn kick(&self, conn: u64) -> bool {
        let Some(e) = self.subs.lock().get(&conn).cloned() else { return false };
        e.stats.kick();
        true
    }
}

const BACKFILL_ATTEMPTS: u32 = 3;
/// How long a renumbered stream waits to reach a cursor past its head
/// before calling it FutureCursor.
const FUTURE_CURSOR_GRACE: Duration = Duration::from_secs(2);
/// Frames between a backfill reader and its subscriber's writer (they are
/// slices of segments the reader holds anyway).
const BACKFILL_CHANNEL: usize = 1024;

struct BackfillSlot(#[allow(dead_code)] tokio::sync::OwnedSemaphorePermit);

impl Drop for BackfillSlot {
    fn drop(&mut self) {
        metrics::FIREHOSE_BACKFILLS.with_label_values(&["running"]).dec();
    }
}

impl Firehose {
    /// Waits for a backfill slot, answering the client meanwhile.
    async fn backfill_slot<W: AsyncWrite + Unpin>(&self, out: &mut Out<W>) -> Result<BackfillSlot, &'static str> {
        let p = match self.backfill_slots.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                let waiting = metrics::FIREHOSE_BACKFILLS.with_label_values(&["waiting"]);
                waiting.inc();
                let acquire = self.backfill_slots.clone().acquire_owned();
                tokio::pin!(acquire);
                let r = loop {
                    tokio::select! {
                        p = &mut acquire => break Ok(p.expect("never closed")),
                        c = out.ctl.recv() => {
                            if let Err(e) = out.control(c).await {
                                break Err(e);
                            }
                        }
                    }
                };
                waiting.dec();
                r?
            }
        };
        metrics::FIREHOSE_BACKFILLS.with_label_values(&["running"]).inc();
        Ok(BackfillSlot(p))
    }
}

struct IpSlot {
    fh: Option<Arc<Firehose>>,
    key: std::net::IpAddr,
}

impl Drop for IpSlot {
    fn drop(&mut self) {
        let Some(fh) = &self.fh else { return };
        let mut m = fh.per_ip.lock();
        if let Some(n) = m.get_mut(&self.key) {
            *n -= 1;
            if *n == 0 {
                m.remove(&self.key);
            }
        }
    }
}

/// The IPv4 address, or the IPv6 /64 (one host's usual allocation).
fn ip_key(ip: std::net::IpAddr) -> std::net::IpAddr {
    match ip.to_canonical() {
        std::net::IpAddr::V6(v6) => {
            std::net::IpAddr::V6(std::net::Ipv6Addr::from(u128::from(v6) & !((1u128 << 64) - 1)))
        }
        v4 => v4,
    }
}

const MAX_PRUNED_RETRIES: u32 = 64;

const OUTDATED_CURSOR: &str = "cursor is older than the retained history; starting from the oldest available event";

pub const DEFAULT_MERGE_QUEUE_BYTES: usize = 256 << 20;

/// One log's events waiting in the merger.
#[derive(Default)]
struct LogQ {
    q: VecDeque<(i64, Bytes)>,
    bytes: usize,
    /// Highest seq accepted: drops duplicates (S3 catch-up overlapping a
    /// live stream).
    high: i64,
    spill: Option<Spill>,
}

/// A log the merger stopped queueing: its batches are read back from S3.
struct Spill {
    next: u64,
    /// every event of the log <= this is queued or emitted
    loaded: i64,
    /// read up to the log's fence
    end: bool,
    /// When `next` was last checked against the log's first ordinal.
    checked: Option<std::time::Instant>,
}

/// How often a spilled log's missing next segment is checked (one LIST) for
/// having been pruned.
const SPILL_PRUNE_CHECK: Duration = Duration::from_secs(1);

impl LogQ {
    /// Queues a log's events in seq order; returns the bytes added.
    fn accept(&mut self, events: Vec<(i64, Bytes)>, emitted: i64, start_floor: i64, late: &mut usize) -> usize {
        let mut added = 0;
        for (seq, frame) in events {
            if seq <= self.high {
                continue;
            }
            self.high = seq;
            // At or below what we already emitted: the start of a follower's
            // S3 catch-up (<= the start floor, backfill serves it), or a late
            // event (a log we weren't following yet, or a watermark that
            // overpromised), which live order can't take.
            if seq <= emitted {
                if seq > start_floor {
                    *late += 1;
                }
                continue;
            }
            added += frame.len();
            self.q.push_back((seq, frame));
        }
        self.bytes += added;
        added
    }
}

/// Reads spilled logs back from S3 up to `w`, a `chunk` of queued bytes at a
/// time. Returns the bound the merger may emit up to (what every spilled log
/// has loaded) and whether more is to be read once that is emitted.
#[allow(clippy::too_many_arguments)]
async fn read_back(
    store: &crate::store::Store,
    logs: &mut HashMap<Arc<str>, LogQ>,
    w: i64,
    chunk: usize,
    emitted: i64,
    start_floor: i64,
    total: &mut usize,
    late: &mut usize,
) -> (i64, bool) {
    let (mut bound, mut more) = (w, false);
    for (log_id, lq) in logs.iter_mut() {
        let Some(mut sp) = lq.spill.take() else { continue };
        let mut caught_up = sp.end || sp.loaded >= w;
        let mut failed = false;
        while !caught_up && lq.bytes < chunk {
            match crate::nodelog::read_object(store, log_id, sp.next).await {
                Ok(Some(LogObject::Segment(_, entries))) => {
                    metrics::FIREHOSE_SPILL_SEGMENTS.inc();
                    sp.next += 1;
                    if let Some(l) = entries.last().map(|e| e.seq) {
                        sp.loaded = sp.loaded.max(l);
                    }
                    *total += lq.accept(segment::events(entries), emitted, start_floor, late);
                    caught_up = sp.loaded >= w;
                }
                Ok(Some(LogObject::Fence { .. })) => {
                    sp.end = true;
                    caught_up = true;
                }
                // Not written: every event <= w of this log was PUT before w
                // was published, so all are loaded (w only covers the log's
                // gap-free prefix). Unless retention deleted it (the read-back
                // is a whole window behind): then it never appears, and live
                // batches only rejoin at `next`, so skip to the log's first
                // segment.
                Ok(None) => {
                    if sp.checked.is_none_or(|t| t.elapsed() >= SPILL_PRUNE_CHECK) {
                        sp.checked = Some(std::time::Instant::now());
                        match crate::backfill::first_ordinal(store, log_id).await {
                            Ok(Some(first)) if first > sp.next => {
                                tracing::warn!(%log_id, from = sp.next, to = first, "firehose merger: spilled log pruned ahead of its read-back; skipping");
                                sp.next = first;
                                continue;
                            }
                            Ok(_) => {}
                            Err(e) => tracing::warn!(%log_id, "firehose merger: listing a spilled log failed: {e:#}"),
                        }
                    }
                    caught_up = true;
                }
                Err(e) => {
                    tracing::warn!(%log_id, ordinal = sp.next, "firehose merger: reading back a spilled log failed: {e:#}");
                    failed = true;
                    break;
                }
            }
        }
        if !caught_up {
            bound = bound.min(sp.loaded);
            // errors wait for the next tick
            more |= !failed;
        }
        lq.spill = Some(sp);
    }
    (bound, more)
}

// ---- subscriber connections (a minimal RFC 6455 server) ----

const OP_BINARY: u8 = 0x2;
const OP_CLOSE: u8 = 0x8;
const OP_PING: u8 = 0x9;
const OP_PONG: u8 = 0xa;

/// How long a subscriber being dropped gets to take its final frames.
const FINAL_GRACE: Duration = Duration::from_secs(10);

/// subscribeRepos takes no client data messages; larger ones are refused.
const MAX_CLIENT_MESSAGE: u64 = 1 << 20;

/// Appends one unmasked, final websocket message (server to client).
fn push_message(out: &mut Vec<u8>, op: u8, payload: &[u8]) {
    out.push(0x80 | op);
    match payload.len() {
        n if n < 126 => out.push(n as u8),
        n if n <= u16::MAX as usize => {
            out.push(126);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        }
        n => {
            out.push(127);
            out.extend_from_slice(&(n as u64).to_be_bytes());
        }
    }
    out.extend_from_slice(payload);
}

/// Returns the Sec-WebSocket-Accept value.
fn handshake(h: &HeaderMap) -> Result<String, (StatusCode, &'static str)> {
    let has = |name: header::HeaderName, token: &str| {
        h.get_all(name)
            .iter()
            .any(|v| v.to_str().is_ok_and(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case(token))))
    };
    if !has(header::CONNECTION, "upgrade") || !has(header::UPGRADE, "websocket") {
        return Err((StatusCode::BAD_REQUEST, "expected a websocket upgrade"));
    }
    if h.get(header::SEC_WEBSOCKET_VERSION).is_none_or(|v| v != "13") {
        return Err((StatusCode::UPGRADE_REQUIRED, "Sec-WebSocket-Version must be 13"));
    }
    let key = h.get(header::SEC_WEBSOCKET_KEY).ok_or((StatusCode::BAD_REQUEST, "missing Sec-WebSocket-Key"))?;
    Ok(tokio_tungstenite::tungstenite::handshake::derive_accept_key(key.as_bytes()))
}

enum Ctl {
    Ping(Vec<u8>),
    Close,
    /// We are shutting down.
    GoingAway,
}

/// Ends on a close frame, EOF, a protocol error or `closing`; dropping
/// `ctl` tells the writer the client is gone.
async fn read_client<R: AsyncRead + Unpin>(mut r: R, ctl: mpsc::Sender<Ctl>, mut closing: watch::Receiver<bool>) {
    tokio::select! {
        res = read_frames(&mut r, &ctl) => if let Err(e) = res {
            tracing::trace!("subscriber read side ended: {e}");
        },
        true = async { closing.wait_for(|c| *c).await.is_ok() } => {
            let _ = ctl.send(Ctl::GoingAway).await;
        }
    }
}

async fn read_frames<R: AsyncRead + Unpin>(r: &mut R, ctl: &mpsc::Sender<Ctl>) -> std::io::Result<()> {
    loop {
        let mut h = [0u8; 2];
        r.read_exact(&mut h).await?;
        let op = h[0] & 0x0f;
        let len = match h[1] & 0x7f {
            126 => r.read_u16().await? as u64,
            127 => r.read_u64().await?,
            n => n as u64,
        };
        let mut mask = [0u8; 4];
        if h[1] & 0x80 != 0 {
            r.read_exact(&mut mask).await?;
        }
        if op & 0x8 != 0 {
            if len > 125 {
                return Err(std::io::ErrorKind::InvalidData.into());
            }
            let mut p = vec![0u8; len as usize];
            r.read_exact(&mut p).await?;
            for (i, b) in p.iter_mut().enumerate() {
                *b ^= mask[i % 4];
            }
            match op {
                OP_CLOSE => {
                    let _ = ctl.try_send(Ctl::Close);
                    return Ok(());
                }
                OP_PING => {
                    let _ = ctl.try_send(Ctl::Ping(p));
                }
                _ => {}
            }
        } else {
            if len > MAX_CLIENT_MESSAGE {
                return Err(std::io::ErrorKind::InvalidData.into());
            }
            tokio::io::copy(&mut (&mut *r).take(len), &mut tokio::io::sink()).await?;
        }
    }
}

struct Out<W> {
    w: W,
    ctl: mpsc::Receiver<Ctl>,
    /// Longest a write outside the live path may go without progress.
    idle: Duration,
    conn: Option<Arc<ConnStats>>,
}

impl<W: AsyncWrite + Unpin> Out<W> {
    fn sent(&self, events: usize, bytes: usize, last_seq: i64) {
        if let Some(c) = &self.conn {
            c.events.fetch_add(events as u64, Ordering::Relaxed);
            c.bytes.fetch_add(bytes as u64, Ordering::Relaxed);
            c.last_seq.store(last_seq, Ordering::Relaxed);
            if let Some((e, b)) = c.series.get() {
                e.inc_by(events as u64);
                b.inc_by(bytes as u64);
            }
        }
    }

    fn set_backfilling(&self, on: bool) {
        if let Some(c) = &self.conn {
            c.backfilling.store(on, Ordering::Relaxed);
            c.sent_to.store(0, Ordering::Relaxed);
        }
    }

    fn sent_to(&self, pos: u64) {
        if let Some(c) = &self.conn {
            c.sent_to.store(pos, Ordering::Relaxed);
        }
    }

    /// Writes `data`; a client that takes nothing for `idle` is dropped
    /// (the live path bounds lag instead, `send_live`).
    async fn write(&mut self, data: &[u8]) -> Result<(), &'static str> {
        let mut at = 0;
        while at < data.len() {
            match tokio::time::timeout(self.idle, self.w.write(&data[at..])).await {
                Ok(Ok(0)) | Ok(Err(_)) => return Err("client_gone"),
                Ok(Ok(n)) => at += n,
                Err(_) => return Err("write_stalled"),
            }
        }
        metrics::FIREHOSE_SENT_BYTES.inc_by(data.len() as u64);
        Ok(())
    }

    async fn send(&mut self, payload: &[u8]) -> Result<(), &'static str> {
        let mut m = Vec::with_capacity(payload.len() + 10);
        push_message(&mut m, OP_BINARY, payload);
        self.write(&m).await
    }

    /// Writes live data that starts at stream offset `pos`. While the write
    /// waits on the socket, every new batch re-checks the lag: past
    /// `allowance` bytes behind the head the subscriber is dropped with
    /// ConsumerTooSlow, so a stalled reader holds nothing but its place in
    /// the shared ring and can't slow anyone else.
    async fn send_live(
        &mut self,
        data: &mut [std::io::IoSlice<'_>],
        head: &mut watch::Receiver<u64>,
        pos: u64,
        allowance: u64,
    ) -> Result<(), &'static str> {
        let len: usize = data.iter().map(|d| d.len()).sum();
        let too_slow = {
            let mut write = std::pin::pin!(write_all_vectored(&mut self.w, data));
            loop {
                tokio::select! {
                    r = &mut write => {
                        r.map_err(|_| "client_gone")?;
                        break false;
                    }
                    r = head.changed() => {
                        if r.is_err() {
                            // the stream is shutting down: just finish
                            (&mut write).await.map_err(|_| "client_gone")?;
                            break false;
                        }
                        if head.borrow_and_update().saturating_sub(pos) <= allowance {
                            continue;
                        }
                        // finish the message in flight so the error frame
                        // can follow it
                        match tokio::time::timeout(FINAL_GRACE, &mut write).await {
                            Ok(Ok(())) => break true,
                            _ => return Err("too_slow"),
                        }
                    }
                }
            }
        };
        metrics::FIREHOSE_SENT_BYTES.inc_by(len as u64);
        if too_slow {
            self.finish(&events::error_frame(
                "ConsumerTooSlow",
                "fell too far behind the stream; reconnect with a cursor",
            ))
            .await;
            return Err("too_slow");
        }
        Ok(())
    }

    /// Best effort: a close frame with `code`, then the caller drops the
    /// connection.
    async fn close(&mut self, code: u16) {
        let mut m = Vec::with_capacity(4);
        push_message(&mut m, OP_CLOSE, &code.to_be_bytes());
        self.write_final(&m).await;
    }

    /// Best effort: a last message and a close frame, then the caller drops
    /// the connection.
    async fn finish(&mut self, payload: &[u8]) {
        let mut m = Vec::with_capacity(payload.len() + 12);
        push_message(&mut m, OP_BINARY, payload);
        push_message(&mut m, OP_CLOSE, &1000u16.to_be_bytes());
        self.write_final(&m).await;
    }

    async fn write_final(&mut self, m: &[u8]) {
        let _ = tokio::time::timeout(FINAL_GRACE, async {
            self.w.write_all(m).await?;
            self.w.shutdown().await
        })
        .await;
    }

    /// Answers the read side: a pong, or the close handshake (None = the
    /// client is gone).
    async fn control(&mut self, c: Option<Ctl>) -> Result<(), &'static str> {
        let mut m = Vec::new();
        match c {
            Some(Ctl::Ping(p)) => {
                push_message(&mut m, OP_PONG, &p);
                self.write(&m).await
            }
            Some(Ctl::Close) => {
                push_message(&mut m, OP_CLOSE, &1000u16.to_be_bytes());
                let _ = tokio::time::timeout(FINAL_GRACE, self.w.write_all(&m)).await;
                Err("client_closed")
            }
            Some(Ctl::GoingAway) => {
                self.close(1001).await;
                Err("shutdown")
            }
            None => Err("client_gone"),
        }
    }
}

/// Most slices per vectored write (IOV_MAX is 1024 on Linux and macOS).
const MAX_IOV: usize = 1024;

/// `write_all` over several slices: one writev per call where the socket
/// supports it (a single slice is a plain write).
async fn write_all_vectored<W: AsyncWrite + Unpin>(
    w: &mut W,
    mut bufs: &mut [std::io::IoSlice<'_>],
) -> std::io::Result<()> {
    std::io::IoSlice::advance_slices(&mut bufs, 0);
    while !bufs.is_empty() {
        let n = w.write_vectored(&bufs[..bufs.len().min(MAX_IOV)]).await?;
        if n == 0 {
            return Err(std::io::ErrorKind::WriteZero.into());
        }
        std::io::IoSlice::advance_slices(&mut bufs, n);
    }
    Ok(())
}

struct AbortOnDrop<T>(tokio::task::JoinHandle<T>);

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn info_frame(name: &str, message: &str) -> Vec<u8> {
    use crate::cbor::*;
    let mut out = Vec::new();
    write_map_head(&mut out, 2);
    write_text(&mut out, "t");
    write_text(&mut out, "#info");
    write_text(&mut out, "op");
    write_uint(&mut out, 1);
    write_map_head(&mut out, 2);
    write_text(&mut out, "name");
    write_text(&mut out, name);
    write_text(&mut out, "message");
    write_text(&mut out, message);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::segment::SegmentBuilder;
    use object_store::{ObjectStoreExt, PutPayload};

    /// A #commit, #sync, #identity or #account (by `kind % 4`) for `did`.
    fn kind_frame(kind: usize, did: &str, seq: i64) -> Bytes {
        let cid = crate::cid::Cid::dag_cbor(b"x");
        let f = match kind % 4 {
            0 => {
                let ops = [
                    events::RepoOp { action: "create", path: "app.bsky.feed.post/3k", cid: Some(cid), prev: None },
                    events::RepoOp { action: "update", path: "app.bsky.feed.like/3j", cid: Some(cid), prev: Some(cid) },
                ];
                events::commit_frame(&events::CommitFrame {
                    repo: did,
                    rev: "3kabc",
                    since: Some("3kabb"),
                    commit: cid,
                    prev_data: Some(cid),
                    blocks: &[7u8; 300],
                    ops: &ops,
                    time: "2026-01-01T00:00:00Z",
                })
            }
            1 => events::sync_frame(did, "3kabc", &[1, 2, 3], "t"),
            2 => events::identity_frame(did, "a.test", "t"),
            _ => events::account_frame(did, false, Some("takendown"), "t"),
        };
        let mut out = Vec::new();
        f.finish(seq, &mut out);
        Bytes::from(out)
    }

    /// event_slot finds the repo of every event kind (a #commit's `repo`
    /// sits after its ops), and wire_runs writes exactly the matching
    /// events' messages, one slice per run.
    #[test]
    fn event_slots_and_runs() {
        let dids: Vec<String> = (0..64).map(crate::state::bulk_did).collect();
        let frame = |i: usize| kind_frame(i, &dids[i], 1000 + i as i64);
        let evs: Vec<(i64, Bytes)> = (0..dids.len()).map(|i| (1000 + i as i64, frame(i))).collect();
        for (i, (_, f)) in evs.iter().enumerate() {
            assert_eq!(event_slot(f), crate::slots::slot_of(&dids[i]), "event {i}");
        }
        assert_eq!(event_slot(b"\xa0"), 0);
        assert_eq!(event_slot(&evs[0].1[..20]), 0);
        let batch = MergedBatch::new(evs.clone(), 0);
        for n in [1u32, 2, 5] {
            for k in 0..n {
                let range = SlotRange::new(k, n).unwrap();
                for from in [0, 17] {
                    let (runs, count) = batch.wire_runs(from, Some(&range), None);
                    let got: Vec<u8> = runs.iter().flat_map(|r| r.to_vec()).collect();
                    let want: Vec<(i64, Bytes)> =
                        evs[from..].iter().filter(|(_, f)| range.contains(event_slot(f))).cloned().collect();
                    let mut buf = Vec::new();
                    for (_, f) in &want {
                        push_message(&mut buf, OP_BINARY, f);
                    }
                    assert_eq!((got, count), (buf, want.len()), "{k}/{n} from {from}");
                    assert!(runs.len() <= count);
                }
            }
        }
    }

    /// Skips #commit and #sync frames of one DID while it's set.
    #[derive(Default)]
    struct SkipDid {
        did: parking_lot::Mutex<Option<String>>,
        generation: AtomicU64,
        calls: AtomicUsize,
    }

    impl SkipDid {
        fn set(&self, did: Option<&str>) {
            *self.did.lock() = did.map(String::from);
            self.generation.fetch_add(1, Ordering::AcqRel);
        }
    }

    impl FrameFilter for SkipDid {
        fn generation(&self) -> Option<u64> {
            self.did.lock().is_some().then(|| self.generation.load(Ordering::Acquire))
        }
        fn skip(&self, f: &FrameMeta<'_>) -> bool {
            self.calls.fetch_add(1, Ordering::Relaxed);
            matches!(f.kind, FrameKind::Commit | FrameKind::Sync)
                && f.did == self.did.lock().as_deref().map(str::as_bytes)
        }
    }

    /// frame_meta reads each kind's own DID key, even with the other one
    /// in the frame, and never panics on garbage.
    #[test]
    fn frame_meta_reads_the_kind_and_its_did() {
        use crate::cbor::*;
        let did = crate::state::bulk_did(1);
        for (k, kind) in
            [FrameKind::Commit, FrameKind::Sync, FrameKind::Identity, FrameKind::Account].into_iter().enumerate()
        {
            let f = kind_frame(k, &did, 7);
            assert_eq!(frame_meta(&f), FrameMeta { kind, did: Some(did.as_bytes()) });
        }
        // a #commit carrying a `did` (sorted first) is still its `repo`'s
        let mut f = Vec::new();
        write_map_head(&mut f, 2);
        write_text(&mut f, "t");
        write_text(&mut f, "#commit");
        write_text(&mut f, "op");
        write_uint(&mut f, 1);
        write_map_head(&mut f, 2);
        write_text(&mut f, "did");
        write_text(&mut f, "did:plc:other");
        write_text(&mut f, "repo");
        write_text(&mut f, "did:plc:real");
        assert_eq!(frame_meta(&f), FrameMeta { kind: FrameKind::Commit, did: Some(b"did:plc:real".as_slice()) });
        let info = info_frame("OutdatedCursor", "x");
        assert_eq!(frame_meta(&info), FrameMeta { kind: FrameKind::Other, did: None });
        let full = kind_frame(0, &did, 7);
        for n in 0..full.len() {
            let m = frame_meta(&full[..n]);
            assert!(m.did.is_none_or(|d| d == did.as_bytes()), "truncated at {n}");
        }
        assert_eq!(frame_meta(b"").kind, FrameKind::Other);
    }

    /// A batch asks the filter once per generation (every subscriber shares
    /// the verdicts), reports none skipped when nothing matches, and its
    /// runs leave out exactly the skipped events, with or without a shard.
    #[test]
    fn filtered_runs_skip_exactly_the_marked_events() {
        let dids: Vec<String> = (0..4).map(crate::state::bulk_did).collect();
        let evs: Vec<(i64, Bytes)> =
            (0..64).map(|i| (1000 + i as i64, kind_frame(i % 4, &dids[(i / 4) % 4], 1000 + i as i64))).collect();
        let batch = MergedBatch::new(evs.clone(), 0);
        let filter = SkipDid::default();
        assert!(batch.skipped(&filter).is_none());
        assert_eq!(filter.calls.load(Ordering::Relaxed), 0, "no generation: frames aren't parsed");
        filter.set(Some("did:plc:nobody"));
        assert!(batch.skipped(&filter).is_none());
        filter.set(Some(&dids[1]));
        let calls = filter.calls.load(Ordering::Relaxed);
        let skip = batch.skipped(&filter).expect("did 1's commits and syncs");
        assert!(Arc::ptr_eq(&skip, &batch.skipped(&filter).unwrap()));
        assert_eq!(filter.calls.load(Ordering::Relaxed), calls + evs.len(), "once per generation");
        let want_skip = |i: usize| (i / 4) % 4 == 1 && i % 4 < 2;
        assert_eq!(skip.iter().filter(|s| **s).count(), 8);
        assert!(skip.iter().enumerate().all(|(i, s)| *s == want_skip(i)));
        let range = SlotRange::new(1, 2).unwrap();
        for shard in [None, Some(&range)] {
            for from in [0, 5, 63] {
                let (runs, count) = batch.wire_runs(from, shard, Some(&skip));
                let got: Vec<u8> = runs.iter().flat_map(|r| r.to_vec()).collect();
                let mut want = Vec::new();
                let mut n = 0;
                for (i, (_, f)) in evs.iter().enumerate().skip(from) {
                    if !want_skip(i) && shard.is_none_or(|r| r.contains(event_slot(f))) {
                        push_message(&mut want, OP_BINARY, f);
                        n += 1;
                    }
                }
                assert_eq!((got, count), (want, n), "shard {shard:?} from {from}");
            }
        }
        filter.set(None);
        assert!(batch.skipped(&filter).is_none(), "lifted: everything again");
    }

    /// The filter's cost (ignored; --ignored --nocapture): the verdicts for
    /// a 2,000-event batch against a 10,000-DID set, once per batch, and
    /// the runs each of 16 subscribers then writes.
    #[test]
    #[ignore]
    fn frame_filter_cost() {
        struct Set(std::collections::HashSet<Vec<u8>>);
        impl FrameFilter for Set {
            fn generation(&self) -> Option<u64> {
                Some(1)
            }
            fn skip(&self, f: &FrameMeta<'_>) -> bool {
                matches!(f.kind, FrameKind::Commit | FrameKind::Sync) && f.did.is_some_and(|d| self.0.contains(d))
            }
        }
        // one taken-down DID in the batch: every subscriber writes runs
        let set = Set((10_000..20_000u64).chain([7]).map(|i| crate::state::bulk_did(i).into_bytes()).collect());
        let evs: Vec<(i64, Bytes)> =
            (0..2000u64).map(|i| (i as i64, kind_frame(0, &crate::state::bulk_did(i), i as i64))).collect();
        let rounds = 50;
        let (mut skip_t, mut runs_t) = (Duration::ZERO, Duration::ZERO);
        for _ in 0..rounds {
            let b = MergedBatch::new(evs.clone(), 0);
            let t = std::time::Instant::now();
            std::hint::black_box(b.skipped(&set));
            skip_t += t.elapsed();
            let t = std::time::Instant::now();
            for _ in 0..16 {
                let skip = b.skipped(&set);
                match skip {
                    None => std::hint::black_box(b.wire_from(0).len()),
                    Some(s) => std::hint::black_box(b.wire_runs(0, None, Some(&s)).1),
                };
            }
            runs_t += t.elapsed();
        }
        let per = |d: Duration| d.as_nanos() as f64 / (rounds * evs.len()) as f64;
        eprintln!(
            "filter verdicts: {:.0} ns/event once per batch; 16 subscribers' cached lookups: {:.1} ns/event total",
            per(skip_t),
            per(runs_t)
        );
    }

    /// Sharded fan-out cost per event (ignored; --ignored --nocapture):
    /// computing a batch's slots once, then each of 16 sharded subscribers
    /// picking its runs.
    #[test]
    #[ignore]
    fn sharded_filter_cost() {
        let cid = crate::cid::Cid::dag_cbor(b"x");
        let ops =
            [events::RepoOp { action: "create", path: "app.bsky.feed.post/3kabcdefghij2", cid: Some(cid), prev: None }];
        let evs: Vec<(i64, Bytes)> = (0..2000u64)
            .map(|i| {
                let did = crate::state::bulk_did(i);
                let f = events::commit_frame(&events::CommitFrame {
                    repo: &did,
                    rev: "3kabc",
                    since: Some("3kabb"),
                    commit: cid,
                    prev_data: Some(cid),
                    blocks: &[7u8; 1200],
                    ops: &ops,
                    time: "2026-01-01T00:00:00.000Z",
                });
                let mut out = Vec::new();
                f.finish(i as i64, &mut out);
                (i as i64, Bytes::from(out))
            })
            .collect();
        let rounds = 50;
        let (mut slots_t, mut runs_t) = (Duration::ZERO, Duration::ZERO);
        for _ in 0..rounds {
            let b = MergedBatch::new(evs.clone(), 0);
            let t = std::time::Instant::now();
            std::hint::black_box(b.slots());
            slots_t += t.elapsed();
            let t = std::time::Instant::now();
            for k in 0..16 {
                std::hint::black_box(b.wire_runs(0, Some(&SlotRange::new(k, 16).unwrap()), None));
            }
            runs_t += t.elapsed();
        }
        let per = |d: Duration| d.as_nanos() as f64 / (rounds * evs.len()) as f64;
        eprintln!(
            "slots: {:.0} ns/event once per batch; runs for 16 sharded subscribers: {:.0} ns/event total",
            per(slots_t),
            per(runs_t)
        );
    }

    /// The next emitted batches after `last` (advanced past them).
    async fn next_batches(fh: &Firehose, sub: &mut watch::Receiver<u64>, last: &mut i64) -> Vec<Arc<MergedBatch>> {
        loop {
            sub.borrow_and_update();
            let (b, _) = fh.from_ring(*last);
            if let Some(l) = b.last() {
                *last = l.last;
                return b;
            }
            tokio::time::timeout(Duration::from_secs(5), sub.changed()).await.expect("merged stream stalled").unwrap();
        }
    }

    async fn put_seg(store: &crate::store::Store, log: &str, ord: u64, seq: i64, frame_len: usize) -> LogBatch {
        put_frame(store, log, ord, seq, Bytes::from(vec![ord as u8; frame_len])).await
    }

    async fn put_frame(store: &crate::store::Store, log: &str, ord: u64, seq: i64, frame: Bytes) -> LogBatch {
        let mut b = SegmentBuilder::new();
        b.push(seq, crate::slots::ShardId(0), 1, |o| o.extend_from_slice(&frame), &[]);
        let mut obj = b.header(log, ord);
        obj.extend_from_slice(&b.body);
        store.raw.put(&crate::nodelog::segment_path(store, log, ord), PutPayload::from(obj)).await.unwrap();
        LogBatch { log_id: log.into(), ordinal: ord, events: vec![(seq, frame)] }
    }

    /// A spilled log whose next segment retention deleted (the read-back a
    /// whole window behind) skips to the log's first segment instead of
    /// waiting for it forever: its later events are emitted and its live
    /// batches rejoin.
    #[tokio::test]
    async fn spilled_log_skips_pruned_segments() {
        let store = crate::store::Store::memory(None);
        let fh = Firehose::new(Options::default());
        fh.set_max_queue_bytes(2000);
        *fh.store.write() = Some(store.clone());
        let (_, wa) = fh.add_remote("A");
        let (_, wb) = fh.add_remote("B");
        let (tx, rx) = mpsc::unbounded_channel();
        let mut sub = fh.subscribe();
        let mut last = i64::MIN;
        fh.spawn_merger(rx);
        let base = fh.position();
        let seq = |k: i64| base + k * 256 + 1;
        let n = 60u64;
        for k in 0..n {
            tx.send(put_seg(&store, "B", k, seq(k as i64), 200).await).unwrap();
            wb.store(seq(k as i64), Ordering::Release);
            if k % 8 == 0 {
                tokio::time::sleep(Duration::from_millis(3)).await;
            }
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
        // retention deletes B's oldest segments, past where its read-back is
        for k in 0..=40u64 {
            store.raw.delete(&crate::nodelog::segment_path(&store, "B", k)).await.unwrap();
        }
        wa.store(seq(n as i64 + 10), Ordering::Release);
        let mut got = Vec::new();
        while got.last() != Some(&seq(n as i64 - 1)) {
            for b in next_batches(&fh, &mut sub, &mut last).await {
                got.extend(b.events.iter().map(|(s, _)| *s));
            }
        }
        assert!(got.windows(2).all(|w| w[0] < w[1]), "in order");
        // and B's live stream is taken again
        tx.send(put_seg(&store, "B", n, seq(n as i64), 200).await).unwrap();
        wb.store(seq(n as i64), Ordering::Release);
        let b = next_batches(&fh, &mut sub, &mut last).await;
        assert_eq!(b[0].events[0].0, seq(n as i64));
    }

    /// Writes outside the live path give up on a client that takes nothing
    /// for `idle`.
    #[tokio::test]
    async fn stalled_writes_drop_the_subscriber() {
        let (w, _r) = tokio::io::duplex(64);
        let (_ctl_tx, ctl) = mpsc::channel(1);
        let mut out = Out { w, ctl, idle: Duration::from_millis(100), conn: None };
        let t = std::time::Instant::now();
        assert_eq!(out.write(&[0u8; 4096]).await, Err("write_stalled"));
        assert!(t.elapsed() < Duration::from_secs(2));
        // a reader that keeps taking bytes is fine, however slowly
        let (w, mut r) = tokio::io::duplex(64);
        let (_ctl_tx, ctl) = mpsc::channel(1);
        let mut out = Out { w, ctl, idle: Duration::from_millis(100), conn: None };
        let reader = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let mut n = 0;
            while n < 4096 {
                tokio::time::sleep(Duration::from_millis(10)).await;
                n += r.read(&mut buf).await.unwrap();
            }
        });
        assert_eq!(out.write(&[0u8; 4096]).await, Ok(()));
        reader.await.unwrap();
    }

    /// A tracked live subscriber's stats count the events and bytes it was
    /// sent and its position.
    #[tokio::test]
    async fn conn_stats_count_what_was_sent() {
        let store = crate::store::Store::memory(None);
        let fh = Firehose::new(Options::default());
        *fh.store.write() = Some(store.clone());
        let (_, wa) = fh.add_remote("A");
        let (tx, rx) = mpsc::unbounded_channel();
        fh.spawn_merger(rx);
        let base = fh.position();
        let seq = |k: i64| base + k * 256 + 1;
        let conn = Arc::new(ConnStats::default());
        let (w, _r) = tokio::io::duplex(1 << 16);
        let (_ctl_tx, ctl) = mpsc::channel(1);
        let mut out = Out { w, ctl, idle: Duration::from_secs(5), conn: Some(conn.clone()) };
        let fh2 = fh.clone();
        let streaming = AbortOnDrop(tokio::spawn(async move { fh2.stream(&mut out, None, None).await }));
        // a live subscriber starts at the head: let it get there first
        tokio::time::sleep(Duration::from_millis(20)).await;
        for k in 0..3 {
            tx.send(put_seg(&store, "A", k as u64, seq(k), 100).await).unwrap();
            wa.store(seq(k), Ordering::Release);
        }
        let t = std::time::Instant::now();
        while conn.events.load(Ordering::Relaxed) < 3 {
            assert!(t.elapsed() < Duration::from_secs(5), "events {}", conn.events.load(Ordering::Relaxed));
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(conn.events.load(Ordering::Relaxed), 3);
        // each message: the 100-byte frame plus a 2-byte websocket header
        assert_eq!(conn.bytes.load(Ordering::Relaxed), 3 * 102);
        assert_eq!(conn.last_seq.load(Ordering::Relaxed), seq(2));
        assert!(!conn.backfilling.load(Ordering::Relaxed));
        assert!(!streaming.0.is_finished());
    }

    /// The websocket messages' payloads, as a subscriber reads them, until
    /// `n` have come.
    async fn read_messages(r: &mut tokio::io::DuplexStream, n: usize) -> Vec<Bytes> {
        let (mut buf, mut out) = (Vec::new(), Vec::new());
        while out.len() < n {
            let mut tmp = [0u8; 8192];
            let k = tokio::time::timeout(Duration::from_secs(5), r.read(&mut tmp))
                .await
                .unwrap_or_else(|_| panic!("got {} of {n} messages", out.len()))
                .unwrap();
            assert!(k > 0, "closed after {} of {n} messages", out.len());
            buf.extend_from_slice(&tmp[..k]);
            loop {
                if buf.len() < 2 {
                    break;
                }
                let (len, at) = match buf[1] & 0x7f {
                    126 if buf.len() >= 4 => (u16::from_be_bytes([buf[2], buf[3]]) as usize, 4),
                    127 if buf.len() >= 10 => (u64::from_be_bytes(buf[2..10].try_into().unwrap()) as usize, 10),
                    126 | 127 => break,
                    n => (n as usize, 2),
                };
                if buf.len() < at + len {
                    break;
                }
                out.push(Bytes::copy_from_slice(&buf[at..at + len]));
                buf.drain(..at + len);
            }
        }
        out
    }

    /// A filtered subscriber from an old cursor gets every frame but the
    /// skipped ones, from the bucket and from the ring, with their seqs
    /// unchanged; once the filter lets a DID go, its frames come back.
    #[tokio::test]
    async fn filter_skips_frames_in_backfill_and_live() {
        let store = crate::store::Store::memory(None);
        // the ring keeps only the newest batch: the rest is backfilled
        let fh = Firehose::new(Options { ring_bytes: 1, ..Options::default() });
        *fh.store.write() = Some(store.clone());
        let filter = Arc::new(SkipDid::default());
        fh.set_filter(filter.clone());
        let (_, wa) = fh.add_remote("A");
        let (tx, rx) = mpsc::unbounded_channel();
        let mut sub = fh.subscribe();
        let mut last = i64::MIN;
        fh.spawn_merger(rx);
        let base = fh.position();
        let seq = |k: i64| base + k * 256 + 1;
        let dids: Vec<String> = (0..3).map(crate::state::bulk_did).collect();
        // commits and syncs from 3 DIDs, then DID 0's #account
        let mut frames: Vec<Bytes> = (0..12).map(|k| kind_frame(k % 2, &dids[k % 3], seq(k as i64))).collect();
        frames.push(kind_frame(3, &dids[0], seq(12)));
        for (k, f) in frames.iter().enumerate() {
            tx.send(put_frame(&store, "A", k as u64, seq(k as i64), f.clone()).await).unwrap();
            wa.store(seq(k as i64), Ordering::Release);
            next_batches(&fh, &mut sub, &mut last).await;
        }
        assert!(fh.ring_floor.load(Ordering::Acquire) >= seq(11), "older events are only in the bucket");
        let subscribe = |cursor: i64| {
            let (w, r) = tokio::io::duplex(1 << 20);
            let (ctl_tx, ctl) = mpsc::channel(1);
            let mut out = Out { w, ctl, idle: Duration::from_secs(5), conn: None };
            let fh = fh.clone();
            (AbortOnDrop(tokio::spawn(async move { fh.stream(&mut out, Some(cursor), None).await })), r, ctl_tx)
        };
        filter.set(Some(&dids[0]));
        let kept: Vec<Bytes> =
            frames.iter().enumerate().filter(|(k, _)| k % 3 != 0 || *k == 12).map(|(_, f)| f.clone()).collect();
        let (_s, mut r, _c) = subscribe(base);
        assert_eq!(read_messages(&mut r, kept.len()).await, kept);
        // live: a later commit of DID 0 is skipped, DID 1's isn't
        let later = [kind_frame(0, &dids[0], seq(13)), kind_frame(0, &dids[1], seq(14))];
        for (k, f) in later.iter().enumerate() {
            let k = 13 + k as i64;
            tx.send(put_frame(&store, "A", k as u64, seq(k), f.clone()).await).unwrap();
        }
        wa.store(seq(14), Ordering::Release);
        assert_eq!(read_messages(&mut r, 1).await, vec![later[1].clone()]);
        // lifted: the same cursor gets everything again
        filter.set(None);
        let all: Vec<Bytes> = frames.iter().chain(later.iter()).cloned().collect();
        let (_s, mut r, _c) = subscribe(base);
        assert_eq!(read_messages(&mut r, all.len()).await, all);
    }

    /// Ring replay fan-out with and without a filter (ignored; --ignored
    /// --nocapture): 16 subscribers replay the same 40,000 ~5 KB commits
    /// from the ring into in-memory pipes, with no filter, a filter with an
    /// empty set, and one whose set hits one DID in 1,000 (most batches
    /// write runs instead of one slice).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore]
    async fn frame_filter_fanout() {
        struct Set(std::collections::HashSet<Vec<u8>>);
        impl FrameFilter for Set {
            fn generation(&self) -> Option<u64> {
                (!self.0.is_empty()).then_some(1)
            }
            fn skip(&self, f: &FrameMeta<'_>) -> bool {
                matches!(f.kind, FrameKind::Commit | FrameKind::Sync) && f.did.is_some_and(|d| self.0.contains(d))
            }
        }
        let (n, subs, per_batch) = (40_000usize, 16usize, 500usize);
        let cid = crate::cid::Cid::dag_cbor(b"x");
        let ops = [events::RepoOp { action: "create", path: "app.bsky.feed.post/3k", cid: Some(cid), prev: None }];
        let blocks = vec![7u8; 5000];
        let frames: Vec<Bytes> = (0..n as u64)
            .map(|i| {
                let did = crate::state::bulk_did(i % 5000);
                let f = events::commit_frame(&events::CommitFrame {
                    repo: &did,
                    rev: "3kabc",
                    since: None,
                    commit: cid,
                    prev_data: None,
                    blocks: &blocks,
                    ops: &ops,
                    time: "2026-01-01T00:00:00.000Z",
                });
                let mut out = Vec::new();
                f.finish(i as i64, &mut out);
                Bytes::from(out)
            })
            .collect();
        let modes: [(&str, Option<Set>); 3] = [
            ("no filter", None),
            ("empty set", Some(Set(Default::default()))),
            (
                "1 DID in 1,000",
                Some(Set((0..5000u64).step_by(1000).map(|i| crate::state::bulk_did(i).into_bytes()).collect())),
            ),
        ];
        for (name, filter) in modes {
            let msg_len = |f: &Bytes| {
                let mut v = Vec::new();
                push_message(&mut v, OP_BINARY, &[]);
                v.len()
                    + if f.len() < 126 {
                        0
                    } else if f.len() <= 65535 {
                        2
                    } else {
                        8
                    }
                    + f.len()
            };
            let want: usize =
                frames.iter().filter(|f| filter.as_ref().is_none_or(|s| !s.skip(&frame_meta(f)))).map(msg_len).sum();
            let mut best = Duration::MAX;
            let filter = filter.map(Arc::new);
            for _ in 0..3 {
                let fh = Firehose::new(Options { ring_bytes: 1 << 30, ..Options::default() });
                // without one, a cursor gets an OutdatedCursor first
                *fh.store.write() = Some(crate::store::Store::memory(None));
                if let Some(f) = &filter {
                    fh.set_filter(f.clone());
                }
                let (_, wa) = fh.add_remote("A");
                let (tx, rx) = mpsc::unbounded_channel();
                let mut sub = fh.subscribe();
                let mut last = i64::MIN;
                fh.spawn_merger(rx);
                let base = fh.position();
                for (b, chunk) in frames.chunks(per_batch).enumerate() {
                    let events: Vec<(i64, Bytes)> = chunk
                        .iter()
                        .enumerate()
                        .map(|(j, f)| (base + ((b * per_batch + j) as i64 + 1) * 256, f.clone()))
                        .collect();
                    let top = events.last().unwrap().0;
                    tx.send(LogBatch { log_id: "A".into(), ordinal: b as u64, events }).unwrap();
                    wa.store(top, Ordering::Release);
                    next_batches(&fh, &mut sub, &mut last).await;
                }
                let t = std::time::Instant::now();
                let mut tasks = Vec::new();
                for _ in 0..subs {
                    let (w, mut r) = tokio::io::duplex(1 << 20);
                    let (ctl_tx, ctl) = mpsc::channel(1);
                    let fh = fh.clone();
                    let (conn, series) = tracked(&fh, "192.0.2.1", None);
                    let s = tokio::spawn(async move {
                        let mut out = Out { w, ctl, idle: Duration::from_secs(30), conn: Some(conn) };
                        let _ctl = (ctl_tx, series);
                        let _ = fh.stream(&mut out, Some(base), None).await;
                    });
                    tasks.push(tokio::spawn(async move {
                        let mut buf = vec![0u8; 1 << 20];
                        let mut got = 0;
                        while got < want {
                            got += r.read(&mut buf).await.unwrap();
                        }
                        s.abort();
                        got
                    }));
                }
                for t in tasks {
                    assert_eq!(t.await.unwrap(), want, "{name}");
                }
                best = best.min(t.elapsed());
            }
            let events = frames.len() as f64 * subs as f64;
            eprintln!(
                "{name:>15}: {:.2} GB/s out, {:.2}M events/s across {subs} subscribers (best of 3)",
                (want * subs) as f64 / best.as_secs_f64() / 1e9,
                events / best.as_secs_f64() / 1e6,
            );
        }
    }

    /// Backfills beyond `max_backfills` wait for a slot (answering their
    /// client meanwhile), and one whose client leaves stops waiting.
    #[tokio::test]
    async fn backfills_wait_for_a_slot() {
        let fh = Firehose::new(Options { max_backfills: 1, ..Options::default() });
        let out = || {
            let (w, _r) = tokio::io::duplex(1 << 16);
            let (tx, ctl) = mpsc::channel(1);
            (Out { w, ctl, idle: Duration::from_secs(5), conn: None }, tx, _r)
        };
        let (mut a, _a_tx, _ar) = out();
        let first = fh.backfill_slot(&mut a).await.unwrap();
        // the second waits; its client leaving ends the wait
        let (mut b, b_tx, _br) = out();
        let fh2 = fh.clone();
        let waiting = tokio::spawn(async move { fh2.backfill_slot(&mut b).await.map(|_| ()) });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!waiting.is_finished());
        drop(b_tx);
        assert_eq!(waiting.await.unwrap(), Err("client_gone"));
        // a third gets the slot once the first ends
        let (mut c, _c_tx, _cr) = out();
        let fh3 = fh.clone();
        let next = tokio::spawn(async move { fh3.backfill_slot(&mut c).await.is_ok() });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!next.is_finished());
        drop(first);
        assert!(tokio::time::timeout(Duration::from_secs(5), next).await.unwrap().unwrap());
    }

    /// At most `max_per_ip` subscriber connections per address (IPv6: per
    /// /64); a closed one frees its slot.
    #[test]
    fn subscribers_per_ip_are_capped() {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let _g = rt.enter();
        let fh = Firehose::new(Options { max_per_ip: 2, ..Options::default() });
        let v4: std::net::IpAddr = "192.0.2.7".parse().unwrap();
        let a = fh.ip_slot(v4).expect("first");
        let _b = fh.ip_slot(v4).expect("second");
        assert!(fh.ip_slot(v4).is_none(), "third from the same address");
        assert!(fh.ip_slot("192.0.2.8".parse().unwrap()).is_some(), "another address");
        drop(a);
        assert!(fh.ip_slot(v4).is_some(), "a closed connection frees its slot");
        let x: std::net::IpAddr = "2001:db8:1:2::1".parse().unwrap();
        let y: std::net::IpAddr = "2001:db8:1:2:ffff::9".parse().unwrap();
        let _x = fh.ip_slot(x).unwrap();
        let _y = fh.ip_slot(y).unwrap();
        assert!(fh.ip_slot("2001:db8:1:2::77".parse().unwrap()).is_none(), "same /64");
        assert!(fh.ip_slot("2001:db8:1:3::1".parse().unwrap()).is_some(), "another /64");
        assert_eq!(fh.connections_from(x), 2);
        let open = Firehose::new(Options { max_per_ip: 0, ..Options::default() });
        let all: Vec<_> = (0..10).map(|_| open.ip_slot(v4).unwrap()).collect();
        assert_eq!((all.len(), open.connections_from(v4)), (10, 0), "0 = no cap");
    }

    /// A connection's stats with its per-connection series, as `upgrade`
    /// makes them.
    fn tracked(fh: &Arc<Firehose>, ip: &str, relay: Option<&str>) -> (Arc<ConnStats>, Series) {
        let series = Series::new(fh, NEXT_CONN.fetch_add(1, Ordering::Relaxed), Some(ip.parse().unwrap()), relay);
        let conn = Arc::new(ConnStats::default());
        let _ = conn.series.set((series.events.clone(), series.bytes.clone()));
        (conn, series)
    }

    /// The subscriber series' label sets, as /metrics shows them.
    fn series_labels() -> Vec<(String, String, String)> {
        let mut out = Vec::new();
        for mf in prometheus::gather() {
            if mf.name() != "vlpds_firehose_subscriber_events_total" {
                continue;
            }
            for m in mf.get_metric() {
                let get = |n: &str| m.get_label().iter().find(|l| l.name() == n).unwrap().value().to_string();
                out.push((get("ip"), get("conn"), get("relay")));
            }
        }
        out
    }

    /// Each connection gets its own series (IPv6 by /64) until the cap, the
    /// rest share `other`, and a connection's series go when it does.
    #[test]
    fn subscriber_series_are_capped_and_removed() {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let _g = rt.enter();
        let fh = Firehose::new(Options { max_labelled: 2, ..Options::default() });
        let (a, sa) = tracked(&fh, "2001:db8:5:6:1:2:3:4", Some("relay.example.com"));
        let (_b, sb) = tracked(&fh, "198.51.100.9", None);
        let (c, sc) = tracked(&fh, "198.51.100.10", None);
        let (ida, idb) = (sa.labels.as_ref().unwrap()[1].clone(), sb.labels.as_ref().unwrap()[1].clone());
        assert!(sc.labels.is_none(), "past the cap");
        let out = |o: &Out<tokio::io::DuplexStream>, n| o.sent(n, n * 10, 1);
        let (w, _r) = tokio::io::duplex(64);
        let (_t, ctl) = mpsc::channel(1);
        let oa = Out { w, ctl, idle: Duration::from_secs(1), conn: Some(a) };
        out(&oa, 3);
        let (w, _r2) = tokio::io::duplex(64);
        let (_t2, ctl) = mpsc::channel(1);
        let oc = Out { w, ctl, idle: Duration::from_secs(1), conn: Some(c) };
        out(&oc, 4);
        let labels = series_labels();
        let mine = |id: &str| labels.iter().find(|l| l.1 == id).cloned();
        assert_eq!(
            mine(&ida),
            Some(("2001:db8:5:6::".to_string(), ida.clone(), "relay.example.com".to_string())),
            "IPv6 by /64, with the relay"
        );
        assert_eq!(mine(&idb), Some(("198.51.100.9".to_string(), idb.clone(), String::new())));
        let ev = |l: &[&str]| metrics::FIREHOSE_SUBSCRIBER_EVENTS.with_label_values(l).get();
        assert_eq!(ev(&["2001:db8:5:6::", &ida, "relay.example.com"]), 3);
        assert!(ev(&[OTHER, OTHER, ""]) >= 4, "the third counts under other");
        drop(sa);
        assert!(series_labels().iter().all(|l| l.1 != ida), "removed on disconnect");
        // its slot is free again
        let (_d, sd) = tracked(&fh, "198.51.100.11", None);
        assert!(sd.labels.is_some());
        drop((sb, sc, sd));
        assert!(series_labels().iter().all(|l| l.1 != idb));
    }

    /// The operator's list: an entry from connect to disconnect, its state
    /// following the stream, then among the recently gone with its reason.
    #[test]
    fn subscribers_are_listed_while_connected() {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let _g = rt.enter();
        let fh = Firehose::new(Options::default());
        let (conn, _series) = tracked(&fh, "192.0.2.44", None);
        let entry = SubscriberEntry {
            id: 7,
            labelled: true,
            ip: Some("192.0.2.44".parse().unwrap()),
            user_agent: "relay-test/1".into(),
            relay: None,
            connected_at_ms: now_ms(),
            cursor: Some(5),
            shard: Some("1/4".into()),
            stats: conn.clone(),
        };
        let sub = Subscribed::new("client_gone", Some(Listed::new(&fh, entry)));
        conn.backfilling.store(true, Ordering::Relaxed);
        let (live, gone) = fh.subscribers();
        assert_eq!((live.len(), gone.len()), (1, 0));
        let v = &live[0];
        assert_eq!(
            (v.conn.as_str(), v.ip.as_deref(), v.state.as_str(), v.cursor.as_deref(), v.shard.as_deref()),
            ("7", Some("192.0.2.44"), "backfilling", Some("5"), Some("1/4"))
        );
        assert_eq!(v.lag_bytes, None, "no byte lag while backfilling");
        conn.backfilling.store(false, Ordering::Relaxed);
        conn.events.store(12, Ordering::Relaxed);
        assert_eq!(fh.subscribers().0[0].state, "live");
        assert_eq!(fh.subscribers().0[0].events, 12);
        drop(sub);
        let (live, gone) = fh.subscribers();
        assert!(live.is_empty());
        assert_eq!((gone[0].conn.as_str(), gone[0].reason.as_deref()), ("7", Some("client_gone")));
        assert!(gone[0].disconnected_at.is_some());
    }

    #[tokio::test]
    async fn kick_reaches_a_listed_subscriber_only() {
        let fh = Firehose::new(Options::default());
        let (conn, _series) = tracked(&fh, "192.0.2.45", None);
        let entry = SubscriberEntry {
            id: 9,
            labelled: false,
            ip: None,
            user_agent: String::new(),
            relay: None,
            connected_at_ms: now_ms(),
            cursor: None,
            shard: None,
            stats: conn.clone(),
        };
        let listed = Listed::new(&fh, entry);
        assert!(!fh.kick(10), "unknown conn");
        assert!(fh.kick(9));
        tokio::time::timeout(Duration::from_secs(1), conn.kick.notified()).await.expect("kick delivered");
        drop(listed);
        assert!(!fh.kick(9), "gone");
    }

    /// A counted stream (`Options::start_floor`) starts above its floor
    /// rather than the clock: small seqs are emitted, in order, up to the
    /// watermark, and nothing at or below the floor is.
    #[tokio::test]
    async fn counted_stream_starts_at_its_floor() {
        let fh = Firehose::new(Options { start_floor: Some(100), ..Options::default() });
        assert_eq!(fh.position(), 100);
        let (floor, wm) = fh.add_remote("q");
        assert_eq!(floor, 100);
        let (tx, rx) = mpsc::unbounded_channel();
        let mut sub = fh.subscribe();
        let mut last = 100;
        fh.spawn_merger(rx);
        let ev = |s: i64| (s, Bytes::from(vec![s as u8; 8]));
        tx.send(LogBatch { log_id: "q".into(), ordinal: 0, events: (99..=103).map(ev).collect() }).unwrap();
        wm.store(102, Ordering::Release);
        let got: Vec<i64> = next_batches(&fh, &mut sub, &mut last)
            .await
            .iter()
            .flat_map(|b| b.events.iter().map(|(s, _)| *s))
            .collect();
        assert_eq!(got, vec![101, 102], "held at the watermark, nothing at or below the floor");
        wm.store(103, Ordering::Release);
        let got: Vec<i64> = next_batches(&fh, &mut sub, &mut last)
            .await
            .iter()
            .flat_map(|b| b.events.iter().map(|(s, _)| *s))
            .collect();
        assert_eq!(got, vec![103]);
        assert_eq!(fh.last_emitted.load(Ordering::Acquire), 103);
    }

    /// A stalled log holds the min watermark back while another keeps
    /// writing: the merger's queue stays near its budget (the busy log is
    /// read back from S3 later) and the merged stream is still complete and
    /// in order once the stall ends.
    #[tokio::test]
    async fn merger_queue_is_bounded_while_a_log_stalls() {
        let store = crate::store::Store::memory(None);
        let fh = Firehose::new(Options::default());
        fh.set_max_queue_bytes(2000);
        *fh.store.write() = Some(store.clone());
        let (_, wa) = fh.add_remote("A");
        let (_, wb) = fh.add_remote("B");
        let (tx, rx) = mpsc::unbounded_channel();
        let mut sub = fh.subscribe();
        let mut last = i64::MIN;
        fh.spawn_merger(rx);
        let base = fh.position();
        let seq = |k: i64| base + k * 256 + 1;
        let n = 60;
        for k in 0..n {
            tx.send(put_seg(&store, "B", k as u64, seq(2 * k + 1), 200).await).unwrap();
            wb.store(seq(2 * k + 1), Ordering::Release);
            if k % 8 == 0 {
                tokio::time::sleep(Duration::from_millis(3)).await;
            }
            assert!(fh.queued_bytes() <= 2000 + 200, "queued {}", fh.queued_bytes());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(fh.queued_bytes() <= 2000 + 200, "queued {}", fh.queued_bytes());
        // the stalled log delivers interleaved events, then catches up
        for k in 0..n {
            tx.send(put_seg(&store, "A", k as u64, seq(2 * k), 10).await).unwrap();
        }
        wa.store(seq(2 * n), Ordering::Release);
        let mut got = Vec::new();
        while got.len() < 2 * n as usize {
            for b in next_batches(&fh, &mut sub, &mut last).await {
                got.extend(b.events.iter().map(|(s, _)| *s));
            }
        }
        assert_eq!(got, (0..2 * n).map(seq).collect::<Vec<_>>());
        // B rejoins the live stream after the read-back
        tx.send(put_seg(&store, "B", n as u64, seq(2 * n + 1), 200).await).unwrap();
        wb.store(seq(2 * n + 1), Ordering::Release);
        wa.store(seq(2 * n + 1), Ordering::Release);
        let b = next_batches(&fh, &mut sub, &mut last).await;
        assert_eq!(b[0].events[0].0, seq(2 * n + 1));
    }
}
