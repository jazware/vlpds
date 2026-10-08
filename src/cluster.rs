//! Cluster control plane: node leases (`nodes/`), writer ids (`writers/`),
//! shard assignments and the layout (`assign/`), log fencing, and the
//! feature level (`cluster/version`). Every object moves by CAS. A single
//! node is a one-node cluster.
//!
//! Liveness never compares wall clocks across nodes: a peer is presumed dead
//! once its lease has not changed for TTL + skew of *our* monotonic time.
//! Safety rests on fencing and CAS, not clocks: DESIGN.md "HA", "Liveness"
//! and "Why safety needs no clocks".

use crate::nodelog::Span;
use object_store::path::Path;
use object_store::{ObjectStoreExt, PutMode, PutOptions, PutPayload, UpdateVersion};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use vlsync_store::slots::{Layout, Reshard, ShardId};
use vlsync_store::store::Store;
use vlsync_store::version::{self, ClusterVersion};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct NodeLease {
    pub node_id: String,
    pub log_id: String,
    pub addr: String,
    pub writer: u8,
    /// Informational (status pages): peers never compare it with their clocks.
    pub expires_ms: u64,
    /// Bumped on every write: peers judge liveness by seeing the lease change.
    pub renewals: u64,
    /// Ordinals only grow, so a peer handing us a shard starts our span
    /// here: a lower bound on our first entry for it.
    pub next_ordinal: u64,
    /// Set by a graceful shutdown before it hands its shards out: peers stop
    /// counting it toward fair shares.
    pub draining: bool,
    /// Every live peer follows this incarnation's log from below its first
    /// seq (`Cluster::try_join`); only then may it hold shards.
    pub joined: bool,
    /// Peer log -> our follower's floor (it delivers every event above it).
    /// A joiner reads its own log here as this node's confirmation.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub follows: BTreeMap<String, i64>,
    /// This node's merged firehose never settles past this seq (send time +
    /// TTL) unless a later renewal lands. A joiner that ignores this node as
    /// dead makes its own seqs pass it.
    pub wm_cap: i64,
    pub rev: String,
    pub min_level: u32,
    pub max_level: u32,
    /// 0 = not read yet.
    pub seen_level: u32,
    /// How long this node's oldest log append had waited to be durable at
    /// the renewal, on its own clock (`ShardHost::pending_age`): peers judge
    /// a slow log without comparing clocks. Absent unless the host says.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_age_ms: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
#[serde(default)]
pub struct Assignment {
    pub owner: Option<String>,
    pub log_id: Option<String>,
    pub addr: Option<String>,
    pub epoch: u64,
    /// Every seq a previous owner assigned for this shard is <= this. A new
    /// owner's seqs start above it, so a repo's commits keep their firehose
    /// order across a handoff whatever the wall clocks say.
    pub seq_floor: i64,
    /// Chronological; the last may be open.
    pub history: Vec<Span>,
    /// The reshard op id this shard was closed for: never acquired again,
    /// and its DB holds every entry of every span in `history`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frozen: Option<u64>,
    /// Every span of an epoch below this is in the shard's durable state,
    /// and its applied marker names a span of this epoch or later (a clean
    /// `release`, or a checkpoint inside the owner's span: `trim_owned`).
    /// Only spans below it ever leave `history`. 0 = nothing is dropped.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub applied_epoch: u64,
    /// Fields of a newer feature level, kept across our CAS writes.
    #[serde(default, flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

fn is_zero(v: &u64) -> bool {
    *v == 0
}

/// A history longer than this drops its spans below `applied_epoch`.
const TRIM_SPANS: usize = 8;

/// Spans no successful open has replayed are never dropped (they hold acked
/// writes), so an acquire that would exceed this takes nothing, loudly:
/// only a crash loop that never once opens the shard cleanly gets here.
const MAX_SPANS: usize = 1024;

fn trim_history(history: &mut Vec<Span>, applied: u64, keep: usize) {
    if history.len() > keep {
        history.retain(|sp| sp.epoch >= applied);
    }
}

/// A shard handed straight to a peer: the releaser closed it, CASed its
/// assignment to name the peer, and POSTs this to the peer's
/// /internal/v1/cluster/nudge, so the peer adopts it without a control-plane
/// read. If the nudge is lost, the peer's next step finds the assignment.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Handoff {
    pub shard: ShardId,
    pub assignment: Assignment,
    pub etag: Option<String>,
}

#[derive(Clone, Debug)]
pub struct ClusterConfig {
    pub node_id: String,
    pub addr: String,
    /// Used only if this prefix has no layout yet.
    pub shards: u32,
    pub ttl: Duration,
    pub renew_every: Duration,
    pub skew: Duration,
    /// Tests only: simulates clock skew in the `expires_ms` we publish.
    pub clock_offset_ms: i64,
    /// The build's window; tests pose as other builds.
    pub levels: version::Window,
    /// Where the lease is renewed. None: the caller's runtime and `store`.
    pub lease_plane: Option<LeasePlane>,
    /// How long startup keeps retrying control-plane reads and its first
    /// step that fail or time out, before the node gives up.
    pub startup_deadline: Duration,
}

/// A runtime and an object-store client for lease renewal alone. A node
/// whose request runtime is saturated (a consumer reconnect storm, a
/// backfill burst) or whose bucket connections are all busy would otherwise
/// renew late, lapse and fail-stop. The store must point at the same bucket
/// and prefix; its own client means its own connections, driven on
/// `runtime`.
#[derive(Clone)]
pub struct LeasePlane {
    pub runtime: tokio::runtime::Handle,
    pub store: Store,
}

impl std::fmt::Debug for LeasePlane {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LeasePlane").finish_non_exhaustive()
    }
}

impl LeasePlane {
    /// One worker thread of its own: renewals are a PUT every fifth of the
    /// TTL and the watchdog a timer.
    pub fn new(store: Store) -> LeasePlane {
        static RT: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();
        let rt = RT.get_or_init(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .thread_name("lease")
                .enable_all()
                .build()
                .expect("lease runtime")
        });
        LeasePlane { runtime: rt.handle().clone(), store }
    }
}

impl Default for ClusterConfig {
    fn default() -> Self {
        ClusterConfig {
            node_id: format!("node-{}", hex::encode(rand::random::<[u8; 4]>())),
            addr: "http://127.0.0.1:2583".into(),
            shards: 64,
            ttl: Duration::from_secs(10),
            renew_every: Duration::from_secs(2),
            skew: Duration::from_secs(2),
            clock_offset_ms: 0,
            levels: version::Window::BUILD,
            lease_plane: None,
            startup_deadline: STARTUP_DEADLINE,
        }
    }
}

/// The least time from one answered write of our lease to the next one's
/// send: R2 takes about one write a second to one key. Never more than
/// `renew_every`, so a short test TTL keeps its cadence.
const LEASE_KEY_GAP: Duration = Duration::from_secs(1);

fn lease_key_gap(renew_every: Duration) -> Duration {
    LEASE_KEY_GAP.min(renew_every)
}

/// [`ClusterConfig::startup_deadline`]'s default. A store that answers late
/// for a few seconds at boot (one R2 GET took over 3 s) otherwise kills a
/// node that would have served a moment later.
pub const STARTUP_DEADLINE: Duration = Duration::from_secs(60);

/// Startup's first retry waits about this long; later ones double, capped
/// at `renew_every`.
const STARTUP_BACKOFF_FLOOR: Duration = Duration::from_millis(200);

/// Exponential backoff with equal jitter: attempt `n` (from 0) waits
/// between half and all of `min(cap, floor * 2^n)`, `unit` (in [0, 1))
/// picking where.
pub(crate) fn jittered_backoff(attempt: u32, floor: Duration, cap: Duration, unit: f64) -> Duration {
    let full = floor.saturating_mul(1u32 << attempt.min(16)).min(cap);
    full / 2 + full.mul_f64(unit.clamp(0.0, 1.0) / 2.0)
}

/// Startup retries a store error that may pass (a 5xx past object_store's
/// retries, a transport error, a deadline), never a refusal or an answer.
fn transient(e: &object_store::Error) -> bool {
    matches!(e, object_store::Error::Generic { .. })
}

/// What the cluster asks the node to do with shards.
#[async_trait::async_trait]
pub trait ShardHost: Send + Sync + 'static {
    /// Start of our span when we take a shard.
    fn next_ordinal(&self) -> u64;
    /// End (exclusive) of our span when we release.
    fn durable_end(&self) -> u64;
    /// Every seq this node has assigned so far is <= this.
    fn seq_high(&self) -> i64 {
        0
    }
    /// Returns once every seq this node assigns from now on exceeds `seq`.
    async fn wait_seq_floor(&self, _seq: i64) {}
    /// Replays each shard's `history` and starts serving it. Batched so a
    /// takeover reads a dead log once for all shards.
    async fn open_many(&self, shards: Vec<(ShardId, u64, Vec<Span>)>) -> Vec<(ShardId, anyhow::Result<()>)>;
    /// Stops writes, drains (one barrier segment for all), checkpoints,
    /// closes. A shard may be released only if its close succeeded:
    /// otherwise entries of it may still be in flight.
    async fn close_many(&self, shards: Vec<ShardId>) -> Vec<(ShardId, anyhow::Result<()>)>;
    /// Waits until nothing is queued or in flight on our log. False if it
    /// did not quiesce in time.
    async fn quiesce(&self) -> bool {
        true
    }
    /// Whether a checkpoint of `shard` inside its current span on our log
    /// is durable (its state then holds every earlier span).
    fn checkpointed(&self, _shard: ShardId) -> bool {
        false
    }
    /// Must stop acking immediately.
    fn lost(&self);
    fn on_membership(&self) {}
    /// POSTs /internal/v1/cluster/nudge to each `(addr, handoffs)`. Best
    /// effort: a missed nudge costs a step interval.
    async fn nudge(&self, _nudges: Vec<(String, Vec<Handoff>)>) {}
    /// Before we hand `(addr, shards)` over: each recipient warms its caches
    /// from their state while we still serve them. Returns once every
    /// recipient answered or ran out of time.
    async fn prewarm(&self, _plan: Vec<(String, Vec<ShardId>)>) {}
    fn on_layout(&self, _layout: Arc<Layout>) {}
    /// Creates `op`'s children from its frozen parents (in `layout`).
    /// Idempotent.
    async fn clone_shards(&self, _layout: &Layout, _op: &Reshard) -> anyhow::Result<()> {
        Ok(())
    }
    /// (shard, approximate state bytes, log entries applied so far).
    fn shard_stats(&self) -> Vec<(ShardId, u64, u64)> {
        Vec::new()
    }
    /// Joiner: asks each of `peers` to follow our log now. Per peer, its
    /// follower's floor, or None if it didn't confirm (`Cluster::try_join`).
    /// A host without a firehose has nothing to lose: every peer confirms.
    async fn greet(&self, peers: Vec<NodeLease>) -> Vec<Option<i64>> {
        peers.iter().map(|_| Some(i64::MIN)).collect()
    }
    /// Published in our lease (`NodeLease::follows`).
    fn follow_floors(&self) -> BTreeMap<String, i64> {
        BTreeMap::new()
    }
    /// Graceful shutdown is about to delete our (fenced) lease: a joiner
    /// from now on won't greet us and our steps have stopped, so our merged
    /// firehose must emit nothing more, and our log streams end (peers
    /// drain it from S3 to the fence).
    fn leaving(&self) {}
    /// Whether a TCP connect to a peer's `addr` is refused: the process
    /// holding that lease is gone.
    async fn refused(&self, _addr: &str) -> bool {
        false
    }
    /// Joiner with live peers: false holds the join (a host that knows its
    /// peers can't reach it yet would take shards only to give them up).
    fn may_join(&self) -> bool {
        true
    }
    /// Published in our lease as `pending_age_ms`. None: not published.
    fn pending_age(&self) -> Option<Duration> {
        None
    }
}

/// What we last saw of a peer's lease, timed on our monotonic clock.
struct Seen {
    etag: Option<String>,
    lease: NodeLease,
    changed_at: Instant,
    /// Of this incarnation (log_id).
    first_seen: Instant,
}

/// Re-read every assignment, not only those whose ETag changed, every this
/// many steps: a safety net.
const FULL_RESYNC_STEPS: u64 = 150;

/// A lone, settled node LISTs `assign/` only every this many steps: nothing
/// but its own writes can change it while no other lease exists. A divisor
/// of FULL_RESYNC_STEPS, so full resyncs still happen on schedule.
const LONE_ASSIGN_EVERY: u64 = 25;

/// Under `assign/` so the per-step LIST covers it.
pub(crate) const LAYOUT: &str = "assign/layout";

/// An object with the ETag it was read at.
pub(crate) type Versioned<T> = (T, Option<String>);

/// When the split policy last planned, and per shard the applied-entry
/// count last seen (and when).
pub(crate) type PolicyState = (Option<Instant>, HashMap<ShardId, (u64, Instant)>);

pub struct Cluster {
    pub cfg: ClusterConfig,
    pub log_id: String,
    pub writer: u8,
    pub(crate) store: Store,
    lease_etag: RwLock<Option<String>>,
    lease: RwLock<NodeLease>,
    /// Our lease expiry on our own (unoffset) wall clock: the watermark cap.
    expires_local_ms: AtomicU64,
    valid_until: RwLock<Instant>,
    /// shard -> (owner node, addr)
    table: RwLock<BTreeMap<ShardId, (String, String)>>,
    owned: RwLock<HashSet<ShardId>>,
    peers: RwLock<HashMap<String, NodeLease>>,
    seen: RwLock<HashMap<String, Seen>>,
    /// Every shard id with an assignment object, retired ones included.
    pub(crate) assigns: RwLock<BTreeMap<ShardId, Versioned<Assignment>>>,
    pub(crate) layout: RwLock<(Arc<Layout>, Option<String>)>,
    /// Handbacks prefer shards opened longer ago.
    opened_at: RwLock<HashMap<ShardId, Instant>>,
    pub(crate) policy: RwLock<crate::reshard::Policy>,
    pub(crate) policy_state: parking_lot::Mutex<PolicyState>,
    steps: AtomicU64,
    requests: AtomicU64,
    lists: AtomicU64,
    /// log_id -> (fence ordinal, last seq in it).
    fenced: RwLock<HashMap<String, (u64, i64)>>,
    joined_at: Instant,
    /// Set by shutdown; with `step_lock`, a step can't re-acquire shards
    /// while (or after) shutdown releases them.
    stopping: AtomicBool,
    step_lock: tokio::sync::Mutex<()>,
    /// Shutdown is about to delete our lease: the renew loop and watchdog
    /// stop (they keep running through the shutdown drain itself).
    gone: AtomicBool,
    /// Held across each renewal so shutdown can't delete the lease under one.
    renew_lock: tokio::sync::Mutex<()>,
    /// The last write of our lease: when it was answered, whether it landed,
    /// and the `joined` / `draining` it carried.
    last_lease_write: parking_lot::Mutex<Option<(Instant, bool, bool, bool)>>,
    /// With a lease plane every renewal runs there: callers elsewhere ask
    /// its loop (`renew_now`) and wait for a renewal that started after
    /// they asked (`renew_started`, then `renew_done` carrying its number).
    renew_now: tokio::sync::Notify,
    renew_started: AtomicU64,
    renew_done: tokio::sync::watch::Sender<u64>,
    on_plane: AtomicBool,
    /// Tests: this in-process node "crashed" (`halt`). Its store calls hang;
    /// it must never fail-stop the shared test process.
    halted: AtomicBool,
    /// Set once `join` is done: startup keeps the store's own timeouts and
    /// retries instead of `call_deadline`.
    bounded: AtomicBool,
    nudged: tokio::sync::Notify,
    /// Not adopted yet.
    handed: parking_lot::Mutex<Vec<Handoff>>,
    /// No live peer as of the last step (or greeting).
    alone: AtomicBool,
    joined: AtomicBool,
    /// Hello answers: peer log id -> its follower's floor of our log.
    confirmed: parking_lot::Mutex<HashMap<String, i64>>,
    /// Our previous incarnation's published `wm_cap`: our seqs pass it
    /// before we join.
    join_floor: std::sync::atomic::AtomicI64,
    /// The step loop runs. Joining waits for it when we have peers: the
    /// inline first step at startup must not open shards before the node
    /// serves.
    spawned: AtomicBool,
    /// Highest epoch of each shard this incarnation has opened. An
    /// assignment naming us at an epoch we already opened (a failed release
    /// CAS) must not be adopted again: its history minus our span would
    /// replay older owners' writes over ours.
    opened: RwLock<HashMap<ShardId, u64>>,
    /// Epoch each shard last opened *successfully* at. Releasing a shard we
    /// never served at its epoch drops our span (nothing of it was logged).
    served: RwLock<HashMap<ShardId, u64>>,
    /// Tests: skip every step (renewals go on).
    hold_steps: AtomicBool,
    /// Tests: answer every greeting "not following".
    ignore_hellos: AtomicBool,
    /// As last read, and when (re-read once per TTL).
    version: RwLock<Option<(ClusterVersion, Instant)>>,
    /// `nodes/` held only our lease as of the last step.
    lone: AtomicBool,
    /// The last step finished alone with nothing in motion: every shard
    /// ours, no split/merge, nothing handed or unreleased.
    settled: AtomicBool,
    /// A peer contacted us since the last step began: the next step lists
    /// whatever `lone` says.
    contact: AtomicBool,
    /// When the last `LIST nodes/` started, and lone steps that reused its
    /// view since.
    nodes_listed: parking_lot::Mutex<(Option<Instant>, u32)>,
    /// Tests: list every step even when alone (a unit-test host's greetings
    /// never reach its peers' `learn_peer`).
    pub(crate) list_every_step: AtomicBool,
    /// `TRIM_SPANS` unless the host set its own (`set_trim_spans`).
    trim_spans: std::sync::atomic::AtomicUsize,
    /// `set_revalidate`: a lapsed lease is renewed (if our log is unfenced)
    /// instead of fail-stopping.
    revalidate: AtomicBool,
}

#[derive(Debug)]
pub enum FinalizeError {
    Invalid(String),
    /// (node id, rev, min level, max level) of live nodes that can't run it.
    Incompatible {
        level: u32,
        nodes: Vec<(String, String, u32, u32)>,
    },
    /// Retry.
    Store(anyhow::Error),
}

impl std::fmt::Display for FinalizeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FinalizeError::Invalid(m) => write!(f, "{m}"),
            FinalizeError::Incompatible { level, nodes } => {
                let list: Vec<String> =
                    nodes.iter().map(|(n, rev, min, max)| format!("{n} (rev {rev}, levels {min}..={max})")).collect();
                write!(f, "nodes that can't run level {level}: {}", list.join(", "))
            }
            FinalizeError::Store(e) => write!(f, "{e:#}"),
        }
    }
}

impl From<anyhow::Error> for FinalizeError {
    fn from(e: anyhow::Error) -> Self {
        FinalizeError::Store(e)
    }
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

/// Waits (up to `max`) until every seq this node assigns exceeds `floor`.
/// False if our clock is still behind it.
pub(crate) async fn wait_clock_past(floor: i64, max: Duration) -> bool {
    let deadline = Instant::now() + max;
    loop {
        let now = vlsync_atproto::tid::now_micros();
        if vlsync_firehose::log::seq_floor(now) > floor {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        let ahead_us = ((floor >> 8) as u64).saturating_sub(now);
        tokio::time::sleep(Duration::from_micros(ahead_us.clamp(1_000, 50_000))).await;
    }
}

pub(crate) fn is_conflict(e: &object_store::Error) -> bool {
    matches!(e, object_store::Error::Precondition { .. } | object_store::Error::AlreadyExists { .. })
}

/// A CAS on the version read with `e_tag`.
pub fn if_match(e_tag: Option<String>) -> PutMode {
    PutMode::Update(UpdateVersion { e_tag, version: None })
}

/// A CAS on our node lease failed because the object isn't the one we
/// read: changed, or deleted (S3 answers an If-Match PUT of a missing key
/// 404, the in-memory store a precondition failure).
fn lease_moved(e: &object_store::Error) -> bool {
    is_conflict(e) || matches!(e, object_store::Error::NotFound { .. })
}

/// How often `join` re-reads its node lease after it changed under the
/// join's CAS before giving up.
const JOIN_LEASE_RETRIES: u32 = 5;

enum Recreate {
    Done,
    /// The object is our own renewal: it landed, but its answer was lost
    /// (a connection reset after the store applied it) and the client's
    /// retry of the same If-Match failed. Its ETag is ours now.
    Landed,
    /// Our lease is someone else's now, or our log is fenced: fail-stop.
    Lost,
    /// The next renewal tries again.
    Retry,
}

impl Cluster {
    /// Checks the cluster's feature level, claims a writer id and creates
    /// our node lease. A node whose levels can't run the cluster's refuses
    /// (`version::refuse`) before it touches anything else, or right after
    /// its lease write (then deleting it).
    pub async fn join(cfg: ClusterConfig, store: Store) -> anyhow::Result<Arc<Cluster>> {
        Self::join_inner(cfg, store, None).await
    }

    /// Tests run `before_lease` (a race) between the first level check and
    /// the lease write.
    async fn join_inner(
        cfg: ClusterConfig,
        store: Store,
        before_lease: Option<std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>>,
    ) -> anyhow::Result<Arc<Cluster>> {
        let log_id = format!("{}.{}", cfg.node_id, vlsync_atproto::tid::now_micros());
        let mut c = Cluster {
            log_id: log_id.clone(),
            writer: 0,
            store,
            lease_etag: RwLock::new(None),
            lease: RwLock::new(NodeLease {
                node_id: cfg.node_id.clone(),
                log_id,
                addr: cfg.addr.clone(),
                writer: 0,
                expires_ms: 0,
                renewals: 0,
                next_ordinal: 0,
                draining: false,
                joined: false,
                follows: BTreeMap::new(),
                wm_cap: 0,
                rev: crate::build::rev().to_string(),
                min_level: cfg.levels.min,
                max_level: cfg.levels.max,
                seen_level: 0,
                pending_age_ms: None,
            }),
            expires_local_ms: AtomicU64::new(0),
            valid_until: RwLock::new(Instant::now()),
            table: RwLock::new(BTreeMap::new()),
            owned: RwLock::new(HashSet::new()),
            peers: RwLock::new(HashMap::new()),
            seen: RwLock::new(HashMap::new()),
            assigns: RwLock::new(BTreeMap::new()),
            layout: RwLock::new((Arc::new(Layout::uniform(cfg.shards)), None)),
            opened_at: RwLock::new(HashMap::new()),
            policy: RwLock::new(Default::default()),
            policy_state: parking_lot::Mutex::new((None, HashMap::new())),
            steps: AtomicU64::new(0),
            requests: AtomicU64::new(0),
            lists: AtomicU64::new(0),
            fenced: RwLock::new(HashMap::new()),
            joined_at: Instant::now(),
            stopping: AtomicBool::new(false),
            step_lock: tokio::sync::Mutex::new(()),
            gone: AtomicBool::new(false),
            renew_lock: tokio::sync::Mutex::new(()),
            last_lease_write: parking_lot::Mutex::new(None),
            renew_now: tokio::sync::Notify::new(),
            renew_started: AtomicU64::new(0),
            renew_done: tokio::sync::watch::channel(0).0,
            on_plane: AtomicBool::new(false),
            halted: AtomicBool::new(false),
            bounded: AtomicBool::new(false),
            nudged: tokio::sync::Notify::new(),
            handed: parking_lot::Mutex::new(Vec::new()),
            opened: RwLock::new(HashMap::new()),
            served: RwLock::new(HashMap::new()),
            joined: AtomicBool::new(false),
            confirmed: parking_lot::Mutex::new(HashMap::new()),
            join_floor: std::sync::atomic::AtomicI64::new(0),
            spawned: AtomicBool::new(false),
            alone: AtomicBool::new(false),
            hold_steps: AtomicBool::new(false),
            ignore_hellos: AtomicBool::new(false),
            version: RwLock::new(None),
            lone: AtomicBool::new(false),
            settled: AtomicBool::new(false),
            contact: AtomicBool::new(false),
            nodes_listed: parking_lot::Mutex::new((None, 0)),
            list_every_step: AtomicBool::new(false),
            trim_spans: std::sync::atomic::AtomicUsize::new(TRIM_SPANS),
            revalidate: AtomicBool::new(false),
            cfg,
        };
        let v = c.ensure_version().await?;
        if let Err(why) = c.cfg.levels.check(&v) {
            return Err(version::refuse(&c.cfg.node_id, &why));
        }
        c.observed_version(v);
        if let Some(f) = before_lease {
            f.await;
        }
        // The lease we read can vanish before our CAS lands: a peer that
        // presumed our previous incarnation dead fenced its log and deletes
        // the lease once its shards moved. Then read it again.
        let mut vanished = 0;
        let mut mode = c.read_own_lease().await?;
        loop {
            let (writer, claim_etag) = c.claim_writer().await?;
            c.writer = writer;
            c.lease.write().writer = writer;
            if let Err(e) = c.write_lease(mode).await {
                if !e.downcast_ref::<object_store::Error>().is_some_and(lease_moved) || vanished == JOIN_LEASE_RETRIES {
                    return Err(e);
                }
                vanished += 1;
                tracing::warn!(attempt = vanished, "our node lease changed under the join (a peer deleted our previous incarnation's): reading it again: {e:#}");
                crate::metrics::LEASE_EVENTS.with_label_values(&["join_lease_moved"]).inc();
                mode = c.read_own_lease().await?;
                continue;
            }
            mode = if_match(c.lease_etag.read().clone());
            // A claim is taken over only while its holder has no lease:
            // rewriting it now changes its ETag, so a joiner that read it
            // before our lease existed fails its CAS instead of sharing our id.
            let wpath = c.path(&format!("writers/{writer:03}"));
            let confirmed = serde_json::json!({"node_id": c.cfg.node_id, "log_id": c.log_id, "confirmed": true});
            match c.put_json(&wpath, &confirmed, if_match(claim_etag)).await {
                Ok(_) => break,
                Err(e) if is_conflict(&e) => {
                    tracing::warn!(writer, "writer id taken over before our lease existed; claiming another");
                }
                Err(e) => return Err(e.into()),
            }
        }
        // A raise that listed the leases before ours landed wrote its target
        // first, so we see it here (store writes are linearizable).
        let v = match c.read_version().await? {
            Some((v, _)) => v,
            None => anyhow::bail!("{} vanished", version::OBJECT),
        };
        if let Err(why) = c.cfg.levels.check(&v) {
            c.delete(&format!("nodes/{}", c.cfg.node_id)).await;
            return Err(version::refuse(&c.cfg.node_id, &why));
        }
        c.observed_version(v);
        c.ensure_layout().await?;
        c.bounded.store(true, Ordering::Release);
        let c = Arc::new(c);
        let (weak, node_id) = (Arc::downgrade(&c), c.cfg.node_id.clone());
        vlsync_store::metrics::on_render(move || match weak.upgrade() {
            Some(c) => {
                crate::metrics::LEASE_VALIDITY.with_label_values(&[node_id.as_str()]).set(c.lease_validity_secs());
                true
            }
            None => {
                let _ = crate::metrics::LEASE_VALIDITY.remove_label_values(&[node_id.as_str()]);
                false
            }
        });
        Ok(c)
    }

    /// How to write our lease over `nodes/{our id}`. Another incarnation's
    /// is fenced first: if it still runs, its next PUT collides and it
    /// fail-stops; everything it acked is before the fence and replayed.
    async fn read_own_lease(&self) -> anyhow::Result<PutMode> {
        let path = self.path(&format!("nodes/{}", self.cfg.node_id));
        let Some((l, etag)) = self.get_json::<NodeLease>(&path).await? else {
            return Ok(PutMode::Create);
        };
        if l.log_id != self.log_id {
            self.fence_as(&l.log_id, Some("restart")).await?;
            // its merged firehose (if it still runs) settles no further
            self.join_floor.fetch_max(l.wm_cap, Ordering::AcqRel);
        }
        let mut ours = self.lease.write();
        ours.renewals = ours.renewals.max(l.renewals);
        Ok(if_match(etag))
    }

    /// Negative: lapsed that long ago.
    pub fn lease_validity_secs(&self) -> f64 {
        let (until, now) = (*self.valid_until.read(), Instant::now());
        if until >= now {
            (until - now).as_secs_f64()
        } else {
            -(now - until).as_secs_f64()
        }
    }

    /// Creates the uniform layout if this prefix has none (a racing
    /// creator's wins).
    async fn ensure_layout(&self) -> anyhow::Result<()> {
        let path = self.path(LAYOUT);
        let (l, etag) = loop {
            if let Some((l, etag)) = self.get_json::<Layout>(&path).await? {
                l.validate()?;
                if l.shards.len() != self.cfg.shards as usize && l.version == 1 {
                    tracing::warn!(
                        configured = self.cfg.shards,
                        layout = l.shards.len(),
                        "--shards differs from this prefix's layout: the layout wins"
                    );
                }
                break (l, etag);
            }
            let l = Layout::uniform(self.cfg.shards);
            match self.put_json(&path, &l, PutMode::Create).await {
                Ok(etag) => {
                    tracing::info!(shards = self.cfg.shards, "created the shard layout (v1, uniform)");
                    break (l, etag);
                }
                Err(e) if is_conflict(&e) => continue,
                Err(e) => return Err(e.into()),
            }
        };
        crate::metrics::LAYOUT_SHARDS.set(l.shards.len() as i64);
        crate::metrics::LAYOUT_VERSION.set(l.version as i64);
        *self.layout.write() = (Arc::new(l), etag);
        Ok(())
    }

    /// An unreadable object is an error (counted as a format error), never
    /// "absent".
    pub async fn read_version(&self) -> anyhow::Result<Option<Versioned<ClusterVersion>>> {
        self.get_json::<ClusterVersion>(&self.path(version::OBJECT)).await.map_err(|e| {
            if e.downcast_ref::<serde_json::Error>().is_some() {
                version::format_error("cluster_version");
            }
            e.context(format!("reading {}", version::OBJECT))
        })
    }

    /// Creates `cluster/version` at this build's max level if this prefix
    /// has none. A racing creator's wins.
    async fn ensure_version(&self) -> anyhow::Result<ClusterVersion> {
        loop {
            if let Some((v, _)) = self.read_version().await? {
                return Ok(v);
            }
            let level = self.cfg.levels.max;
            let v = ClusterVersion::new(level, &self.cfg.node_id);
            match self.put_json(&self.path(version::OBJECT), &v, PutMode::Create).await {
                Ok(_) => {
                    tracing::info!(level, "created {}", version::OBJECT);
                    return Ok(v);
                }
                Err(e) if is_conflict(&e) => continue,
                Err(e) => return Err(e.into()),
            }
        }
    }

    fn observed_version(&self, v: ClusterVersion) {
        self.lease.write().seen_level = v.active;
        version::set_active(v.active);
        *self.version.write() = Some((v, Instant::now()));
    }

    pub fn cluster_version(&self) -> Option<ClusterVersion> {
        self.version.read().as_ref().map(|(v, _)| v.clone())
    }

    /// As of its last write, plus flags set since.
    pub fn own_lease(&self) -> NodeLease {
        self.lease.read().clone()
    }

    /// `node_id`'s lease as the bucket has it now.
    pub async fn read_lease(&self, node_id: &str) -> anyhow::Result<Option<NodeLease>> {
        Ok(self.get_json::<NodeLease>(&self.path(&format!("nodes/{node_id}"))).await?.map(|(l, _)| l))
    }

    /// Whether `lease` expired by its own clock, read against ours with
    /// the configured skew as margin.
    pub fn lease_expired(&self, lease: &NodeLease) -> bool {
        lease.expires_ms + (self.cfg.skew.as_millis() as u64) < self.wall_ms()
    }

    /// Once per TTL. An active level outside our window (an operator forced
    /// it) is a fail-stop; a `target` past it is not (a raise lists our lease
    /// and aborts).
    async fn observe_version(&self) -> anyhow::Result<()> {
        let due = self.version.read().as_ref().is_none_or(|(_, at)| at.elapsed() >= self.cfg.ttl);
        if !due || self.halted() {
            return Ok(());
        }
        let Some((v, _)) = self.read_version().await? else {
            tracing::error!("{} is missing: keeping level {}", version::OBJECT, version::active());
            return Ok(());
        };
        if !self.cfg.levels.contains(v.active) {
            let why = format!(
                "cluster level {} is outside this build's levels {}..={}",
                v.active, self.cfg.levels.min, self.cfg.levels.max
            );
            return Err(version::refuse(&self.cfg.node_id, &why));
        }
        self.observed_version(v);
        Ok(())
    }

    /// (1) CAS `target = level`; (2) list every lease *after* that write and
    /// require each live one to run `level`; (3) CAS `active = level`. A node
    /// whose lease landed after (2)'s listing sees the target in `join` and
    /// refuses. Raising a persistent level can't be undone.
    pub async fn finalize_level(&self, level: u32, by: &str) -> Result<ClusterVersion, FinalizeError> {
        let path = self.path(version::OBJECT);
        let Some((cur, etag)) = self.read_version().await? else {
            return Err(FinalizeError::Invalid(format!("{} is missing", version::OBJECT)));
        };
        if level == cur.active {
            // A leftover target (a finalize that died between its steps)
            // keeps nodes that can't run it from starting. A raise still in
            // flight then fails its last CAS (retry).
            if let Some(t) = cur.target {
                self.clear_target(t).await?;
                tracing::warn!(target = t, active = level, by, "cleared a pending feature level raise");
                return Ok(ClusterVersion { target: None, ..cur });
            }
            return Ok(cur);
        }
        if level < cur.active {
            return Err(FinalizeError::Invalid(format!(
                "level {level} is below the active level {}: levels are never lowered",
                cur.active
            )));
        }
        if !self.cfg.levels.contains(level) {
            return Err(FinalizeError::Invalid(format!(
                "this node runs levels {}..={}, not {level}",
                self.cfg.levels.min, self.cfg.levels.max
            )));
        }
        let mut next = cur.clone();
        next.target = Some(level);
        let etag = match self.put_json(&path, &next, if_match(etag)).await {
            Ok(e) => e,
            Err(e) if is_conflict(&e) => {
                return Err(FinalizeError::Store(anyhow::anyhow!("{} changed concurrently: retry", version::OBJECT)))
            }
            Err(e) => return Err(FinalizeError::Store(e.into())),
        };
        tracing::info!(level, by, "feature level raise: target written");
        let offenders = match self.leases_unable(level).await {
            Ok(o) => o,
            Err(e) => {
                let _ = self.clear_target(level).await;
                return Err(FinalizeError::Store(e));
            }
        };
        if !offenders.is_empty() {
            if let Err(e) = self.clear_target(level).await {
                tracing::warn!(level, "clearing the raise target failed (the next finalize clears it): {e:#}");
            }
            tracing::warn!(level, ?offenders, "feature level raise aborted: nodes can't run it");
            return Err(FinalizeError::Incompatible { level, nodes: offenders });
        }
        next.active = level;
        next.target = None;
        next.history.push(version::Change::new(level, by));
        match self.put_json(&path, &next, if_match(etag)).await {
            Ok(_) => {}
            Err(e) if is_conflict(&e) => {
                // someone else finished (or cleared) it meanwhile
                return match self.read_version().await? {
                    Some((v, _)) if v.active == level => {
                        self.observed_version(v.clone());
                        Ok(v)
                    }
                    _ => Err(FinalizeError::Store(anyhow::anyhow!(
                        "{} changed during the raise: retry",
                        version::OBJECT
                    ))),
                };
            }
            Err(e) => return Err(FinalizeError::Store(e.into())),
        }
        tracing::warn!(
            level,
            by,
            "cluster feature level raised (finalized): rollback to older builds is no longer possible"
        );
        self.observed_version(next.clone());
        Ok(next)
    }

    async fn clear_target(&self, level: u32) -> anyhow::Result<()> {
        let path = self.path(version::OBJECT);
        for _ in 0..5 {
            let Some((mut v, etag)) = self.read_version().await? else { return Ok(()) };
            if v.target != Some(level) {
                return Ok(());
            }
            v.target = None;
            match self.put_json(&path, &v, if_match(etag)).await {
                Ok(_) => return Ok(()),
                Err(e) if is_conflict(&e) => continue,
                Err(e) => return Err(e.into()),
            }
        }
        anyhow::bail!("{} kept changing", version::OBJECT)
    }

    /// (node id, rev, min level, max level) of leases that can't run
    /// `level`. Only a lease whose log we fenced is ignored; an unreadable
    /// one counts as unable.
    async fn leases_unable(&self, level: u32) -> anyhow::Result<Vec<(String, String, u32, u32)>> {
        let mut out = Vec::new();
        for (id, _) in self.list("nodes").await? {
            let got = self.get_json::<serde_json::Value>(&self.path(&format!("nodes/{id}"))).await?;
            let Some((v, _)) = got else { continue };
            match serde_json::from_value::<NodeLease>(v) {
                Ok(l) if self.fenced.read().contains_key(&l.log_id) => {}
                Ok(l) if (l.min_level..=l.max_level).contains(&level) => {}
                Ok(l) => out.push((id, l.rev, l.min_level, l.max_level)),
                Err(_) => out.push((id, "?".into(), 0, 0)),
            }
        }
        Ok(out)
    }

    /// Only past levels that put no new bytes in the bucket, never while a
    /// raise is in progress, and only if every live node can run `level`
    /// (one whose `MIN_LEVEL` is above it would fail-stop).
    pub async fn lower_level(&self, level: u32, by: &str) -> Result<ClusterVersion, FinalizeError> {
        self.lower_level_with(version::LEVELS, level, by).await
    }

    /// Tests pose as builds with wire-only levels.
    pub(crate) async fn lower_level_with(
        &self,
        table: &[version::Level],
        level: u32,
        by: &str,
    ) -> Result<ClusterVersion, FinalizeError> {
        let path = self.path(version::OBJECT);
        let Some((cur, etag)) = self.read_version().await? else {
            return Err(FinalizeError::Invalid(format!("{} is missing", version::OBJECT)));
        };
        if level == cur.active {
            return Ok(cur);
        }
        if let Some(t) = cur.target {
            return Err(FinalizeError::Invalid(format!(
                "a raise to level {t} is in progress (clear it with `cluster finalize --level {}`)",
                cur.active
            )));
        }
        version::check_lower(table, cur.active, level).map_err(FinalizeError::Invalid)?;
        let offenders = self.leases_unable(level).await?;
        if !offenders.is_empty() {
            return Err(FinalizeError::Incompatible { level, nodes: offenders });
        }
        let mut next = cur.clone();
        next.active = level;
        next.history.push(version::Change::new(level, by));
        match self.put_json(&path, &next, if_match(etag)).await {
            Ok(_) => {}
            Err(e) if is_conflict(&e) => {
                return Err(FinalizeError::Store(anyhow::anyhow!("{} changed concurrently: retry", version::OBJECT)))
            }
            Err(e) => return Err(FinalizeError::Store(e.into())),
        }
        tracing::warn!(from = cur.active, level, by, "cluster feature level lowered");
        self.observed_version(next.clone());
        Ok(next)
    }

    pub fn set_reshard_policy(&self, p: crate::reshard::Policy) {
        *self.policy.write() = p;
    }

    /// Histories longer than `n` spans drop the spans a checkpoint made
    /// redundant (`ShardHost::checkpointed`). A host whose opens pay per
    /// span (a relay replays each earlier owner's log) wants 1.
    pub fn set_trim_spans(&self, n: usize) {
        self.trim_spans.store(n.max(1), Ordering::Release);
    }

    fn trim_at(&self) -> usize {
        self.trim_spans.load(Ordering::Acquire)
    }

    /// Opt-in for a host whose log holds (rather than fails) while the
    /// lease is lapsed: a node that wakes from a pause with its lease lapsed
    /// renews it by CAS on its own lease and goes on if its log is still
    /// unfenced, instead of fail-stopping. Safety still rests on the fence:
    /// a peer that presumed us dead fenced our log before taking anything,
    /// so we see the fence and fail-stop, and a fence landing after our
    /// check fails our next segment PUT. The watchdog then fail-stops only
    /// past `revalidate_window`.
    pub fn set_revalidate(&self, on: bool) {
        self.revalidate.store(on, Ordering::Release);
    }

    /// How long past its validity a lapsed lease may still be revalidated.
    /// Peers presume us dead 2 x skew after it; a TTL more is when the
    /// slowest of them has surely fenced us.
    fn revalidate_window(&self) -> Duration {
        self.cfg.skew * 2 + self.cfg.ttl
    }

    /// Our lapsed lease: renew it by CAS and check our log isn't fenced.
    /// The lease counts as valid again only once the check passed. False
    /// means fail-stop.
    async fn try_revalidate(&self, host: &Arc<dyn ShardHost>) -> bool {
        let etag = self.lease_etag.read().clone();
        let renewed = match self.write_lease_ungranted(if_match(etag)).await {
            Ok(v) => v,
            Err(e) => {
                let moved = e.downcast_ref::<object_store::Error>().is_some_and(lease_moved);
                if !moved {
                    // still lapsed (no validity from a failed write): the
                    // next renewal retries, the watchdog bounds it
                    tracing::warn!("revalidating our lapsed node lease failed (will retry): {e:#}");
                    return true;
                }
                // our previous attempt may have landed with its answer lost
                return match self.recreate_vanished_lease().await {
                    Recreate::Lost => {
                        tracing::error!("lapsed node lease was rewritten under us: fail-stop ({e:#})");
                        false
                    }
                    Recreate::Landed => {
                        crate::metrics::LEASE_EVENTS.with_label_values(&["renewal_landed"]).inc();
                        tracing::warn!("a revalidation of our lapsed lease landed with its answer lost: adopted it, still lapsed ({e:#})");
                        true
                    }
                    // recreated only after its own fence check
                    Recreate::Done | Recreate::Retry => true,
                };
            }
        };
        match self.bounded_any("fence-scan", self.own_log_fenced(host)).await {
            Ok(false) => {
                *self.valid_until.write() = renewed;
                crate::metrics::LEASE_EVENTS.with_label_values(&["revalidated"]).inc();
                tracing::warn!("node lease had lapsed (a pause?) but our log is unfenced: renewed it and carry on");
                true
            }
            Ok(true) => {
                tracing::error!("node lease lapsed and our log is fenced: fail-stop");
                false
            }
            Err(e) => {
                tracing::warn!("checking our log for a fence after revalidating (will retry): {e:#}");
                true
            }
        }
    }

    /// A peer's fence goes at our log's first hole, which is at or past
    /// `durable_end` and at most `next_ordinal`: a few GETs, where the scan
    /// LISTs the whole log (3 s and more on a slow bucket path).
    async fn own_log_fenced(&self, host: &Arc<dyn ShardHost>) -> anyhow::Result<bool> {
        let (from, to) = (host.durable_end(), host.next_ordinal());
        if to < from || to - from > 64 {
            self.count("list");
            return Ok(vlsync_firehose::log::first_free(&self.store, &self.log_id).await?.1);
        }
        let heads = futures::future::try_join_all((from..=to).map(|o| {
            self.count("get");
            vlsync_firehose::log::read_head(&self.store, &self.log_id, o)
        }))
        .await?;
        Ok(heads.iter().any(|h| matches!(h, vlsync_firehose::log::Head::Fence)))
    }

    pub fn layout(&self) -> Arc<Layout> {
        self.layout.read().0.clone()
    }

    pub(crate) fn path(&self, rel: &str) -> Path {
        Path::from(format!("{}/{}", self.store.prefix, rel))
    }

    fn count(&self, op: &str) {
        self.requests.fetch_add(1, Ordering::Relaxed);
        if op == "list" {
            self.lists.fetch_add(1, Ordering::Relaxed);
        }
        crate::metrics::CLUSTER_STORE_REQUESTS.with_label_values(&[op]).inc();
    }

    pub fn store_requests(&self) -> u64 {
        self.requests.load(Ordering::Relaxed)
    }

    pub fn store_lists(&self) -> u64 {
        self.lists.load(Ordering::Relaxed)
    }

    fn wall_ms(&self) -> u64 {
        (now_ms() as i64 + self.cfg.clock_offset_ms).max(0) as u64
    }

    /// min(TTL, 5 s) per control-plane call: a request the store stalls on
    /// fails the step (retried next tick) instead of stalling every takeover
    /// behind it. Renewals never time out: a cancelled CAS that lands anyway
    /// would leave us an ETag we never learned.
    fn call_deadline(&self) -> Option<Duration> {
        self.bounded.load(Ordering::Acquire).then(|| self.cfg.ttl.min(Duration::from_secs(5)))
    }

    async fn with_deadline<T, E>(
        &self,
        op: &str,
        f: impl std::future::Future<Output = Result<T, E>>,
        timed_out: impl FnOnce(String) -> E,
    ) -> Result<T, E> {
        let Some(d) = self.call_deadline() else { return f.await };
        match tokio::time::timeout(d, f).await {
            Ok(r) => r,
            Err(_) => {
                crate::metrics::CLUSTER_STORE_TIMEOUTS.with_label_values(&[op]).inc();
                Err(timed_out(format!("control-plane {op} timed out after {d:?}")))
            }
        }
    }

    async fn bounded_any<T>(
        &self,
        op: &str,
        f: impl std::future::Future<Output = anyhow::Result<T>>,
    ) -> anyhow::Result<T> {
        self.with_deadline(op, f, |m| anyhow::anyhow!(m)).await
    }

    pub(crate) async fn bounded<T>(
        &self,
        op: &str,
        f: impl std::future::Future<Output = Result<T, object_store::Error>>,
    ) -> Result<T, object_store::Error> {
        self.with_deadline(op, f, |m| object_store::Error::Generic { store: "cluster", source: m.into() }).await
    }

    /// Before our lease is written, a transient error is retried with
    /// backoff until `startup_deadline`: there is no lease yet to lapse.
    pub(crate) async fn get_json<T: for<'de> Deserialize<'de>>(
        &self,
        path: &Path,
    ) -> anyhow::Result<Option<(T, Option<String>)>> {
        let started = Instant::now();
        let mut attempt = 0;
        loop {
            self.count("get");
            let got = self
                .bounded("get", async {
                    let r = self.store.raw.get(path).await?;
                    let etag = r.meta.e_tag.clone();
                    Ok((r.bytes().await?, etag))
                })
                .await;
            match got {
                Ok((b, etag)) => return Ok(Some((serde_json::from_slice(&b)?, etag))),
                Err(object_store::Error::NotFound { .. }) => return Ok(None),
                Err(e) if transient(&e) && self.expires_local_ms.load(Ordering::Acquire) == 0 => {
                    let wait = jittered_backoff(attempt, STARTUP_BACKOFF_FLOOR, self.cfg.renew_every, rand::random());
                    if started.elapsed() + wait >= self.cfg.startup_deadline {
                        return Err(anyhow::Error::from(e)
                            .context(format!("reading {path} at startup, retried for {:?}", started.elapsed())));
                    }
                    attempt += 1;
                    tracing::warn!(
                        %path,
                        attempt,
                        retry_in_ms = wait.as_millis() as u64,
                        "control-plane read failed at startup (retrying): {e:#}"
                    );
                    tokio::time::sleep(wait).await;
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    pub(crate) async fn put_json<T: Serialize>(
        &self,
        path: &Path,
        v: &T,
        mode: PutMode,
    ) -> Result<Option<String>, object_store::Error> {
        self.bounded("put", self.put_json_unbounded(path, v, mode)).await
    }

    async fn put_json_unbounded<T: Serialize>(
        &self,
        path: &Path,
        v: &T,
        mode: PutMode,
    ) -> Result<Option<String>, object_store::Error> {
        self.count("put");
        Self::put_json_on(&self.store, path, v, mode).await
    }

    /// Renewals: never cancelled.
    async fn put_json_on<T: Serialize>(
        store: &Store,
        path: &Path,
        v: &T,
        mode: PutMode,
    ) -> Result<Option<String>, object_store::Error> {
        let body = PutPayload::from(serde_json::to_vec(v).unwrap());
        store.raw.put_opts(path, body, PutOptions { mode, ..Default::default() }).await.map(|r| r.e_tag)
    }

    /// (file name, ETag) of every object under `rel`.
    async fn list(&self, rel: &str) -> anyhow::Result<Vec<(String, Option<String>)>> {
        use futures::StreamExt;
        self.count("list");
        let listed = self
            .bounded("list", async {
                let mut out = Vec::new();
                let mut list = self.store.raw.list(Some(&self.path(rel)));
                while let Some(m) = list.next().await {
                    let m = m?;
                    if let Some(name) = m.location.filename() {
                        out.push((name.to_string(), m.e_tag.clone()));
                    }
                }
                Ok(out)
            })
            .await?;
        Ok(listed)
    }

    async fn delete(&self, rel: &str) {
        self.count("delete");
        let _ = self.bounded("delete", self.store.raw.delete(&self.path(rel))).await;
    }

    /// Returns the id and the claim's ETag. A claim is free when unclaimed,
    /// ours, or its holder has no node lease at all (`join` confirms ours).
    /// A holder with a lease is never judged dead here: that takes
    /// observation over time, and there are 256 ids to choose from.
    async fn claim_writer(&self) -> anyhow::Result<(u8, Option<String>)> {
        let start = (crate::state::did_hash(&self.cfg.node_id) % 256) as u16;
        let claim = serde_json::json!({"node_id": self.cfg.node_id, "log_id": self.log_id, "confirmed": false});
        for i in 0..256u16 {
            let w = ((start + i) % 256) as u8;
            let path = self.path(&format!("writers/{w:03}"));
            let mode = match self.get_json::<serde_json::Value>(&path).await? {
                None => PutMode::Create,
                Some((v, etag)) => {
                    let holder = v["node_id"].as_str().unwrap_or_default().to_string();
                    if holder != self.cfg.node_id
                        && self.get_json::<NodeLease>(&self.path(&format!("nodes/{holder}"))).await?.is_some()
                    {
                        continue;
                    }
                    if_match(etag)
                }
            };
            match self.put_json(&path, &claim, mode).await {
                Ok(etag) => return Ok((w, etag)),
                Err(e) if is_conflict(&e) => continue,
                Err(e) => return Err(e.into()),
            }
        }
        anyhow::bail!("no free writer id (256 nodes with leases?)")
    }

    async fn write_lease(&self, mode: PutMode) -> anyhow::Result<()> {
        let valid_until = self.write_lease_ungranted(mode).await?;
        *self.valid_until.write() = valid_until;
        Ok(())
    }

    /// [`Cluster::write_lease`] without granting the validity it earns,
    /// which it returns: a revalidation grants it only once our log is
    /// known unfenced, or the log could PUT and ack in between.
    async fn write_lease_ungranted(&self, mode: PutMode) -> anyhow::Result<Instant> {
        let sent = Instant::now();
        let mut l = self.lease.read().clone();
        l.expires_ms = self.wall_ms() + self.cfg.ttl.as_millis() as u64;
        l.renewals += 1;
        // our watermark cap once this lands (published as `wm_cap`): from
        // the send time, so the cap never exceeds what peers read
        let expires_local_ms = now_ms() + self.cfg.ttl.as_millis() as u64;
        l.wm_cap = vlsync_firehose::log::seq_floor(expires_local_ms * 1000);
        let store = self.cfg.lease_plane.as_ref().map_or(&self.store, |p| &p.store);
        let put = Self::put_json_on(store, &self.path(&format!("nodes/{}", self.cfg.node_id)), &l, mode).await;
        *self.last_lease_write.lock() = Some((Instant::now(), put.is_ok(), l.joined, l.draining));
        self.count("put");
        crate::metrics::LEASE_RENEW_SECONDS.observe(sent.elapsed().as_secs_f64());
        let etag = put?;
        *self.lease_etag.write() = etag;
        {
            // only what this write changed: a flag set meanwhile (`joined`,
            // `draining`) must survive until the next write carries it
            let mut cur = self.lease.write();
            cur.renewals = l.renewals;
            cur.expires_ms = l.expires_ms;
            cur.wm_cap = l.wm_cap;
        }
        self.expires_local_ms.store(expires_local_ms, Ordering::Release);
        Ok(sent + self.cfg.ttl - self.cfg.skew)
    }

    /// True while we may acknowledge writes and PUT segments.
    pub fn lease_valid(&self) -> bool {
        // a halted test node's segment PUTs hang instead of fail-stopping
        // the shared test process
        self.halted.load(Ordering::Acquire) || Instant::now() < *self.valid_until.read()
    }

    /// Tests only: stops this node's control plane as if its process died.
    /// The caller makes its object-store calls hang, so nothing it still has
    /// in flight lands.
    pub fn halt(&self) {
        self.halted.store(true, Ordering::Release);
        self.gone.store(true, Ordering::Release);
        self.stopping.store(true, Ordering::Release);
    }

    /// Tests only: while set, steps do nothing (the lease is still renewed).
    pub fn test_hold_steps(&self, on: bool) {
        self.hold_steps.store(on, Ordering::Release);
        if !on {
            self.nudged.notify_one();
        }
    }

    /// Tests only: while set, greetings are answered "not following".
    pub fn test_ignore_hellos(&self, on: bool) {
        self.ignore_hellos.store(on, Ordering::Release);
    }

    pub fn halted(&self) -> bool {
        self.halted.load(Ordering::Acquire)
    }

    /// Shutting down (or halted): never takes a shard again.
    pub fn stopping(&self) -> bool {
        self.stopping.load(Ordering::Acquire)
    }

    /// On our own wall clock (caps our announced watermark).
    pub fn lease_expiry_us(&self) -> u64 {
        self.expires_local_ms.load(Ordering::Acquire) * 1000
    }

    pub fn alone(&self) -> bool {
        self.alone.load(Ordering::Acquire)
    }

    pub fn is_owner(&self, shard: ShardId) -> bool {
        self.owned.read().contains(&shard)
    }

    pub fn owned(&self) -> Vec<ShardId> {
        let mut v: Vec<ShardId> = self.owned.read().iter().copied().collect();
        v.sort();
        v
    }

    /// (node_id, addr)
    pub fn owner_of(&self, shard: ShardId) -> Option<(String, String)> {
        self.table.read().get(&shard).cloned()
    }

    /// Whether we own the shard holding slot 0: the one node that runs
    /// cluster-wide singleton work (dead-log retention, reshard dir GC).
    pub fn leads_slot0(&self) -> bool {
        self.owner_of(self.layout().shard_of_slot(0)).is_some_and(|(o, _)| o == self.cfg.node_id)
    }

    pub fn assignment(&self, shard: ShardId) -> Option<Assignment> {
        self.assigns.read().get(&shard).map(|(a, _)| a.clone())
    }

    pub fn peers(&self) -> Vec<NodeLease> {
        self.peers.read().values().cloned().collect()
    }

    pub fn fenced_logs(&self) -> HashMap<String, u64> {
        self.fenced.read().iter().map(|(k, (o, _))| (k.clone(), *o)).collect()
    }

    /// Closes a log: writes a fence object at its first ordinal that isn't
    /// a segment (a crash with K PUTs in flight can leave never-acked
    /// segments past a hole: the fence cuts them off). Returns that ordinal
    /// (the log's final end) and the last seq before it.
    pub async fn fence(&self, log_id: &str) -> anyhow::Result<(u64, i64)> {
        self.fence_as(log_id, None).await
    }

    /// `takeover`: the log of an incarnation that ended without fencing it
    /// (a dead peer's, or our previous one's); counts
    /// `vlpds_peer_takeovers_total{reason}` once cluster-wide (a fence is a
    /// create-only PUT).
    async fn fence_as(&self, log_id: &str, takeover: Option<&str>) -> anyhow::Result<(u64, i64)> {
        if let Some(f) = self.fenced.read().get(log_id) {
            return Ok(*f);
        }
        loop {
            // An existing fence is the log's end: every fencer must agree on
            // it, so never stack another one after it.
            self.count("list");
            let (next, fenced) =
                self.bounded_any("fence-scan", vlsync_firehose::log::first_free(&self.store, log_id)).await?;
            if !fenced {
                let path = vlsync_firehose::log::segment_path(&self.store, log_id, next);
                self.count("put");
                // a fence PUT that times out and lands later is found by the
                // next attempt's scan (or collides with it: conflict path)
                let put = self.store.raw.put_opts(
                    &path,
                    PutPayload::from_bytes(vlsync_store::segment::fence_object(&self.cfg.node_id)),
                    PutOptions { mode: PutMode::Create, ..Default::default() },
                );
                match self.bounded("fence", put).await {
                    Ok(_) => {
                        if let Some(reason) = takeover {
                            crate::metrics::PEER_TAKEOVERS.with_label_values(&[reason]).inc();
                        }
                    }
                    Err(e) if is_conflict(&e) => {
                        // a zombie got a segment in, or another node fenced first
                        self.count("get");
                        let b = self.bounded("get", async { self.store.raw.get(&path).await?.bytes().await }).await?;
                        if !matches!(
                            vlsync_store::segment::parse(b, false, None)?,
                            vlsync_store::segment::LogObject::Fence { .. }
                        ) {
                            continue; // re-scan: the log grew
                        }
                    }
                    Err(e) => return Err(e.into()),
                }
            }
            let seq = self.last_seq_before(log_id, next).await?;
            self.fenced.write().insert(log_id.to_string(), (next, seq));
            tracing::info!(log_id, fence_ordinal = next, last_seq = seq, "fenced dead node's log");
            return Ok((next, seq));
        }
    }

    /// 0 for an empty log. Everything below a fence is a segment, so this
    /// reads one header.
    async fn last_seq_before(&self, log_id: &str, end: u64) -> anyhow::Result<i64> {
        let mut ord = end;
        while ord > 0 {
            ord -= 1;
            self.count("get");
            match self.bounded_any("get", vlsync_firehose::log::read_head(&self.store, log_id, ord)).await? {
                vlsync_firehose::log::Head::Segment(h) => return Ok(h.last_seq),
                // below a fence only retention removes segments, and only
                // ones past its window: their seqs are long behind any clock
                vlsync_firehose::log::Head::Missing => break,
                vlsync_firehose::log::Head::Fence => {}
            }
        }
        Ok(0)
    }

    pub fn spawn(self: &Arc<Self>, host: Arc<dyn ShardHost>) {
        self.spawned.store(true, Ordering::Release);
        // Renewals get their own loop: a step makes O(shards) store calls,
        // and one slow step must not let the lease lapse.
        let spawn = |f: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>| match &self.cfg.lease_plane {
            Some(p) => drop(p.runtime.spawn(f)),
            None => drop(tokio::spawn(f)),
        };
        let me = self.clone();
        let h = host.clone();
        self.on_plane.store(self.cfg.lease_plane.is_some(), Ordering::Release);
        spawn(Box::pin(async move {
            let mut tick = tokio::time::interval(me.cfg.renew_every);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = tick.tick() => {}
                    _ = me.renew_now.notified() => {}
                }
                // keeps renewing through a graceful shutdown's drain
                if me.gone.load(Ordering::Acquire) {
                    me.on_plane.store(false, Ordering::Release);
                    me.renew_done.send_replace(u64::MAX);
                    return;
                }
                let n = me.renew_started.fetch_add(1, Ordering::AcqRel) + 1;
                me.renew_here(&h).await;
                me.renew_done.send_replace(n);
            }
        }));
        // Watchdog: a node whose store calls hang never reaches the
        // validity checks before a PUT or ack, and would hold requests open
        // as a zombie. Peers presume us dead no earlier than 2 x skew after
        // our validity ends: by then we can never ack again, so fail-stop.
        let me = self.clone();
        let h = host.clone();
        spawn(Box::pin(async move {
            let mut tick = tokio::time::interval(me.cfg.renew_every / 2);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                if me.gone.load(Ordering::Acquire) {
                    return;
                }
                let lapsed_for = Instant::now().saturating_duration_since(*me.valid_until.read());
                let limit =
                    if me.revalidate.load(Ordering::Acquire) { me.revalidate_window() } else { me.cfg.skew * 2 };
                if lapsed_for > limit {
                    tracing::error!(
                        lapsed_ms = lapsed_for.as_millis() as u64,
                        "node lease lapsed past takeover: fail-stop"
                    );
                    h.lost();
                    return;
                }
            }
        }));
        let me = self.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(me.cfg.renew_every);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = tick.tick() => {}
                    _ = me.nudged.notified() => {
                        crate::metrics::CLUSTER_NUDGES.with_label_values(&["received"]).inc();
                    }
                }
                if let Err(e) = me.adopt_handed(&host).await {
                    tracing::warn!("adopting handed shards failed: {e:#}");
                }
                if let Err(e) = me.step_inner(&host, false).await {
                    tracing::warn!("cluster step failed: {e:#}");
                }
            }
        });
    }

    /// A peer handed us shards or released some: adopt and step now
    /// (coalesced).
    pub fn nudge(&self, handoffs: Vec<Handoff>) {
        self.contact.store(true, Ordering::Release);
        self.handed.lock().extend(handoffs);
        self.nudged.notify_one();
    }

    /// `a` names this incarnation at an epoch it hasn't opened yet.
    fn handed_to_us(&self, shard: ShardId, a: &Assignment) -> bool {
        self.names_us(a) && !self.is_owner(shard) && self.opened.read().get(&shard).is_none_or(|&e| e < a.epoch)
    }

    async fn adopt_handed(&self, host: &Arc<dyn ShardHost>) -> anyhow::Result<()> {
        if self.handed.lock().is_empty() {
            return Ok(());
        }
        let _step = self.step_lock.lock().await;
        let handed = std::mem::take(&mut *self.handed.lock());
        // not joined yet (or without a lease): the step adopts them later
        if self.stopping.load(Ordering::Acquire) || !self.lease_valid() || !self.joined.load(Ordering::Acquire) {
            return Ok(());
        }
        let mut adopt = Vec::new();
        let layout = self.layout();
        for h in handed {
            if !layout.contains(h.shard) || !self.handed_to_us(h.shard, &h.assignment) {
                continue;
            }
            self.assigns.write().insert(h.shard, (h.assignment.clone(), h.etag));
            adopt.push((h.shard, h.assignment));
        }
        self.adopt(host, adopt).await
    }

    /// Starts serving shards whose assignment already names us: replays the
    /// history before our own span.
    async fn adopt(&self, host: &Arc<dyn ShardHost>, shards: Vec<(ShardId, Assignment)>) -> anyhow::Result<()> {
        if shards.is_empty() {
            return Ok(());
        }
        let mut floor = 0i64;
        let mut open = Vec::with_capacity(shards.len());
        for (s, a) in shards {
            self.owned.write().insert(s);
            floor = floor.max(a.seq_floor);
            let mut history = a.history;
            history.pop(); // our own, open span
            open.push((s, a.epoch, history));
        }
        tracing::info!(shards = ?open.iter().map(|a| a.0).collect::<Vec<_>>(), owned = self.owned().len(), "adopting shards handed to us");
        host.wait_seq_floor(floor).await;
        self.open_acquired(host, open).await
    }

    /// One that fails to open is released (nothing was logged for it).
    async fn open_acquired(
        &self,
        host: &Arc<dyn ShardHost>,
        shards: Vec<(ShardId, u64, Vec<Span>)>,
    ) -> anyhow::Result<()> {
        {
            let mut opened = self.opened.write();
            let (mut at, now) = (self.opened_at.write(), Instant::now());
            for (s, epoch, _) in &shards {
                opened.insert(*s, *epoch);
                at.insert(*s, now);
            }
        }
        for (s, res) in host.open_many(shards).await {
            match res {
                Ok(()) => {
                    if let Some(&e) = self.opened.read().get(&s) {
                        self.served.write().insert(s, e);
                    }
                    self.table.write().insert(s, (self.cfg.node_id.clone(), self.cfg.addr.clone()));
                }
                Err(e) => {
                    tracing::error!(shard = s.0, "open failed: {e:#}; releasing");
                    self.owned.write().remove(&s);
                    self.release(s, host.next_ordinal(), host.seq_high(), None, None).await?;
                }
            }
        }
        Ok(())
    }

    /// Before it takes any shard, a new incarnation needs every peer's
    /// merged firehose to follow its log from below its first seq: a peer
    /// that starts following late starts at its merger's position and can
    /// never deliver the log's events below it in order. So every live peer
    /// must confirm it follows our log (a hello answer, or our log in its
    /// lease's `follows`), and our seqs must pass every confirmed floor (and
    /// the `wm_cap` of each peer we ignore as dead) before we join.
    ///
    /// No timer ends this: a live peer that never confirms keeps us out
    /// until it confirms or we presume it dead. Peers learn `joined` from our
    /// lease at their next step; nudging them all instead made every peer
    /// release at the same instant.
    async fn try_join(&self, host: &Arc<dyn ShardHost>, live: &[NodeLease], dead: &[NodeLease]) -> bool {
        let peers: Vec<&NodeLease> = live.iter().filter(|l| l.node_id != self.cfg.node_id).collect();
        if !peers.is_empty() && !self.spawned.load(Ordering::Acquire) {
            return false;
        }
        if !peers.is_empty() && !host.may_join() {
            tracing::info!("not joining yet: the host holds the join");
            return false;
        }
        let confirmed =
            |l: &NodeLease, c: &HashMap<String, i64>| l.follows.get(&self.log_id).or_else(|| c.get(&l.log_id)).copied();
        let mut floor = self.join_floor.load(Ordering::Acquire);
        let mut pending = Vec::new();
        {
            let c = self.confirmed.lock();
            for l in &peers {
                match confirmed(l, &c) {
                    Some(f) => floor = floor.max(f),
                    None => pending.push((*l).clone()),
                }
            }
        }
        if !pending.is_empty() {
            let answers = host.greet(pending.clone()).await;
            let mut c = self.confirmed.lock();
            let mut missing = Vec::new();
            for (l, a) in pending.iter().zip(answers.into_iter().chain(std::iter::repeat(None))) {
                match a {
                    Some(f) => {
                        c.insert(l.log_id.clone(), f);
                        floor = floor.max(f);
                    }
                    None => missing.push(l.node_id.clone()),
                }
            }
            if !missing.is_empty() {
                tracing::info!(
                    ?missing,
                    after_ms = self.joined_at.elapsed().as_millis() as u64,
                    "not joining yet: peers not following our log"
                );
                return false;
            }
        }
        {
            let c = self.confirmed.lock();
            for d in dead.iter().filter(|d| d.node_id != self.cfg.node_id) {
                floor = floor.max(confirmed(d, &c).unwrap_or(d.wm_cap));
            }
        }
        if !wait_clock_past(floor, self.cfg.renew_every).await {
            tracing::warn!(floor, "not joining yet: our clock is behind a peer's merged firehose");
            return false;
        }
        self.joined.store(true, Ordering::Release);
        self.lease.write().joined = true;
        tracing::info!(
            after_ms = self.joined_at.elapsed().as_millis() as u64,
            peers = peers.len(),
            "every peer follows our log: joined"
        );
        self.renew(host).await;
        true
    }

    pub fn joined(&self) -> bool {
        self.joined.load(Ordering::Acquire)
    }

    /// A joiner greeted us: learn its lease now and follow its log. Returns
    /// our follower's floor for its log, or None if it has no lease, we
    /// presume it dead, or we don't follow it yet (a step racing us replaced
    /// our peer list: it asks again).
    pub async fn learn_peer(&self, host: &Arc<dyn ShardHost>, node_id: &str) -> anyhow::Result<Option<i64>> {
        if node_id == self.cfg.node_id || self.ignore_hellos.load(Ordering::Acquire) {
            return Ok(None);
        }
        self.contact.store(true, Ordering::Release);
        let Some((lease, etag)) = self.get_json::<NodeLease>(&self.path(&format!("nodes/{node_id}"))).await? else {
            return Ok(None);
        };
        if lease.draining || self.fenced.read().contains_key(&lease.log_id) {
            return Ok(None);
        }
        let log_id = lease.log_id.clone();
        {
            let now = Instant::now();
            let mut seen = self.seen.write();
            let same = seen.get(node_id).filter(|s| s.lease.log_id == lease.log_id);
            let first_seen = same.map_or(now, |s| s.first_seen);
            seen.insert(node_id.to_string(), Seen { etag, lease: lease.clone(), changed_at: now, first_seen });
        }
        self.peers.write().insert(node_id.to_string(), lease);
        self.alone.store(false, Ordering::Release);
        host.on_membership();
        Ok(host.follow_floors().get(&log_id).copied())
    }

    /// Renews now. On a lease plane the plane's loop does it: a renewal
    /// sent from a starved runtime (a step's keepalive during a heavy shard
    /// open) would hold the renew lock across a late answer and starve the
    /// plane's own renewals too.
    async fn renew(&self, host: &Arc<dyn ShardHost>) {
        if !self.on_plane.load(Ordering::Acquire) {
            return self.renew_here(host).await;
        }
        let mut done = self.renew_done.subscribe();
        let asked = self.renew_started.load(Ordering::Acquire);
        self.renew_now.notify_one();
        let _ = tokio::time::timeout(self.cfg.ttl, done.wait_for(|n| *n > asked)).await;
    }

    /// A conflict means someone else rewrote our lease: fail-stop.
    async fn renew_here(&self, host: &Arc<dyn ShardHost>) {
        let _g = self.renew_lock.lock().await;
        if self.gone.load(Ordering::Acquire) {
            return;
        }
        // At most one write to our lease key per gap (R2 throttles a key
        // past about one a second). A renewal right after a write that
        // landed and carried the same flags would only push validity a few
        // hundred ms further: skipped, and the next tick renews. One that
        // must publish a flag, or follows a failed write, waits out the gap.
        // Both only while the validity left covers the next tick with room
        // to spare: a slow write earns validity from its send, so one that
        // landed late (or failed late) is renewed at once, 429 or not.
        let gap = lease_key_gap(self.cfg.renew_every);
        let last = *self.last_lease_write.lock();
        if let Some((at, landed, joined, draining)) = last {
            let since = at.elapsed();
            let left = self.valid_until.read().saturating_duration_since(Instant::now());
            if since < gap && left > self.cfg.renew_every + gap + self.cfg.skew {
                let same = {
                    let l = self.lease.read();
                    l.joined == joined && l.draining == draining
                };
                if landed && same {
                    return;
                }
                tokio::time::sleep(gap - since).await;
                if self.gone.load(Ordering::Acquire) {
                    return;
                }
            }
        }
        // Never resurrect a lapsed lease: peers may have fenced our log, and
        // a renewal landing now would make them count us live again and
        // release shards they just took.
        if !self.lease_valid() {
            let lapsed_for = Instant::now().saturating_duration_since(*self.valid_until.read());
            if self.revalidate.load(Ordering::Acquire) && lapsed_for <= self.revalidate_window() {
                if !self.try_revalidate(host).await {
                    crate::metrics::LEASE_RENEW_ERRORS.with_label_values(&["lapsed"]).inc();
                    host.lost();
                }
                return;
            }
            crate::metrics::LEASE_RENEW_ERRORS.with_label_values(&["lapsed"]).inc();
            tracing::error!("node lease lapsed before renewal: fail-stop");
            host.lost();
            return;
        }
        {
            let mut l = self.lease.write();
            l.next_ordinal = host.next_ordinal();
            l.pending_age_ms = host.pending_age().map(|a| a.as_millis() as u64);
            l.follows = host.follow_floors();
        }
        let etag = self.lease_etag.read().clone();
        if let Err(e) = self.write_lease(if_match(etag)).await {
            let moved = e.downcast_ref::<object_store::Error>().is_some_and(lease_moved);
            let recreated = if moved { self.recreate_vanished_lease().await } else { Recreate::Retry };
            match (moved, recreated) {
                (true, Recreate::Done) => {}
                (true, Recreate::Landed) => {
                    crate::metrics::LEASE_EVENTS.with_label_values(&["renewal_landed"]).inc();
                    tracing::warn!("node lease renewal landed but its answer was lost: adopted it ({e:#})");
                }
                (true, Recreate::Lost) => {
                    crate::metrics::LEASE_RENEW_ERRORS.with_label_values(&["conflict"]).inc();
                    tracing::error!("node lease lost (CAS conflict): {e:#}");
                    host.lost();
                }
                _ => {
                    let kind =
                        if e.downcast_ref::<object_store::Error>().is_some_and(vlsync_store::objstats::is_timeout) {
                            "timeout"
                        } else {
                            "error"
                        };
                    crate::metrics::LEASE_RENEW_ERRORS.with_label_values(&[kind]).inc();
                    tracing::warn!("node lease renew error (will retry): {e:#}");
                }
            }
        }
    }

    /// A renewal CAS failed: if our lease is simply gone and our log isn't
    /// fenced, recreate it. A peer deletes a lease only once it fenced that
    /// incarnation's log, so a lease missing over our unfenced log was our
    /// previous incarnation's as the peer saw it: our join's CAS landed
    /// before its delete.
    async fn recreate_vanished_lease(&self) -> Recreate {
        let path = self.path(&format!("nodes/{}", self.cfg.node_id));
        match self.get_json::<serde_json::Value>(&path).await {
            Ok(None) => {}
            // validity isn't extended: when the write was sent is unknown,
            // and the next renewal (a fifth of the TTL away) does it
            Ok(Some((l, etag))) => {
                let mut cur = self.lease.write();
                return match serde_json::from_value::<NodeLease>(l) {
                    Ok(l) if l.log_id == cur.log_id && l.renewals > cur.renewals => {
                        cur.renewals = l.renewals;
                        *self.lease_etag.write() = etag;
                        Recreate::Landed
                    }
                    _ => Recreate::Lost,
                };
            }
            Err(e) => {
                tracing::warn!("reading our node lease after a failed renewal: {e:#}");
                return Recreate::Retry;
            }
        }
        self.count("list");
        match self.bounded_any("fence-scan", vlsync_firehose::log::first_free(&self.store, &self.log_id)).await {
            Ok((_, false)) => {}
            Ok((_, true)) => return Recreate::Lost,
            Err(e) => {
                tracing::warn!("checking our log for a fence: {e:#}");
                return Recreate::Retry;
            }
        }
        match self.write_lease(PutMode::Create).await {
            Ok(()) => {
                crate::metrics::LEASE_EVENTS.with_label_values(&["lease_recreated"]).inc();
                tracing::warn!("our node lease vanished (a peer deleted our previous incarnation's after we took it over): recreated");
                Recreate::Done
            }
            Err(e) if e.downcast_ref::<object_store::Error>().is_some_and(is_conflict) => Recreate::Lost,
            Err(e) => {
                tracing::warn!("recreating our vanished node lease: {e:#}");
                Recreate::Retry
            }
        }
    }

    /// (live, dead) node leases. A lease is fetched only when its ETag
    /// changed. A peer is dead once its lease has gone unchanged for TTL +
    /// skew of our monotonic time, or once we fenced its log (a renewal it
    /// sent before lapsing may still land).
    ///
    /// A peer that missed a renewal is probed with a TCP connect: refused
    /// means that incarnation is gone, so we presume it dead now. Presuming
    /// early is safe (the takeover fences its log first); any other probe
    /// result leaves the TTL rule in charge.
    async fn read_nodes(&self, host: &Arc<dyn ShardHost>) -> anyhow::Result<(Vec<NodeLease>, Vec<NodeLease>)> {
        use futures::StreamExt;
        // judge staleness as of before the LIST: a slow LIST can't make a
        // lease look older than it is
        let t0 = Instant::now();
        let listed = self.list("nodes").await?;
        let stale: Vec<String> = {
            let seen = self.seen.read();
            listed
                .iter()
                .filter(|(id, etag)| {
                    *id != self.cfg.node_id && (etag.is_none() || seen.get(id).is_none_or(|s| s.etag != *etag))
                })
                .map(|(id, _)| id.clone())
                .collect()
        };
        let fetched: Vec<(String, Option<Versioned<NodeLease>>)> = futures::stream::iter(stale)
            .map(|id| async move {
                let r = self.get_json::<NodeLease>(&self.path(&format!("nodes/{id}"))).await;
                r.map(|v| (id, v))
            })
            .buffered(16)
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .collect::<anyhow::Result<_>>()?;
        let now = Instant::now();
        let late = self.cfg.renew_every + self.cfg.renew_every / 2;
        let (mut live, mut dead, mut suspects) = (vec![self.lease.read().clone()], Vec::new(), Vec::new());
        {
            let mut seen = self.seen.write();
            for (id, got) in fetched {
                match got {
                    None => {
                        seen.remove(&id);
                    }
                    Some((lease, etag)) => {
                        let same = seen.get(&id).filter(|s| s.lease.log_id == lease.log_id);
                        let first_seen = same.map_or(now, |s| s.first_seen);
                        let changed_at =
                            same.filter(|s| s.lease.renewals == lease.renewals).map_or(now, |s| s.changed_at);
                        seen.insert(id, Seen { etag, lease, changed_at, first_seen });
                    }
                }
            }
            let names: HashSet<&String> = listed.iter().map(|(id, _)| id).collect();
            seen.retain(|id, _| names.contains(id));
            let fenced = self.fenced.read();
            for s in seen.values() {
                let quiet = t0.saturating_duration_since(s.changed_at);
                if fenced.contains_key(&s.lease.log_id) || quiet > self.cfg.ttl + self.cfg.skew {
                    dead.push(s.lease.clone());
                } else if quiet > late && !s.lease.draining {
                    suspects.push(s.lease.clone());
                } else {
                    live.push(s.lease.clone());
                }
            }
        }
        let probed: Vec<(NodeLease, bool)> = futures::future::join_all(suspects.into_iter().map(|l| async move {
            let gone = host.refused(&l.addr).await;
            (l, gone)
        }))
        .await;
        for (l, gone) in probed {
            if gone {
                tracing::warn!(node = %l.node_id, log_id = %l.log_id, addr = %l.addr, "peer missed a renewal and refuses connections: presumed dead");
                crate::metrics::LEASE_EVENTS.with_label_values(&["peer_refused"]).inc();
                dead.push(l);
            } else {
                live.push(l);
            }
        }
        Ok((live, dead))
    }

    /// One LIST of `assign/`, then a GET for each object whose ETag changed
    /// (every one if `full`).
    async fn read_assignments(&self, host: &Arc<dyn ShardHost>, full: bool) -> anyhow::Result<()> {
        use futures::StreamExt;
        let mut listed: BTreeMap<ShardId, Option<String>> = BTreeMap::new();
        let mut layout_etag = None;
        for (name, etag) in self.list("assign").await? {
            if name == "layout" {
                layout_etag = Some(etag);
            } else if let Some(s) = ShardId::from_key(&name) {
                listed.insert(s, etag);
            }
        }
        // the layout first: routing must never run behind the assignments
        if let Some(etag) = layout_etag {
            let stale = full || etag.is_none() || self.layout.read().1 != etag;
            if stale {
                self.refresh_layout(host).await?;
            }
        }
        let stale: Vec<ShardId> = {
            let cache = self.assigns.read();
            listed
                .iter()
                .filter(|(s, e)| match (e, cache.get(s)) {
                    (Some(e), Some((_, Some(ce)))) => full || e != ce,
                    _ => true,
                })
                .map(|(s, _)| *s)
                .collect()
        };
        let fetched: Vec<(ShardId, Option<Versioned<Assignment>>)> = futures::stream::iter(stale)
            .map(|s| async move {
                self.get_json::<Assignment>(&self.path(&format!("assign/{}", s.key()))).await.map(|a| (s, a))
            })
            .buffered(32)
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .collect::<anyhow::Result<_>>()?;
        let mut cache = self.assigns.write();
        cache.retain(|s, _| listed.contains_key(s));
        for (s, a) in fetched {
            match a {
                Some(a) => cache.insert(s, a),
                None => cache.remove(&s),
            };
        }
        Ok(())
    }

    pub(crate) async fn refresh_layout(&self, host: &Arc<dyn ShardHost>) -> anyhow::Result<Arc<Layout>> {
        let Some((l, etag)) = self.get_json::<Layout>(&self.path(LAYOUT)).await? else {
            anyhow::bail!("shard layout missing");
        };
        l.validate()?;
        Ok(self.install_layout(host, l, etag))
    }

    /// Unless ours is newer.
    pub(crate) fn install_layout(&self, host: &Arc<dyn ShardHost>, l: Layout, etag: Option<String>) -> Arc<Layout> {
        let mut cur = self.layout.write();
        if l.version < cur.0.version {
            return cur.0.clone();
        }
        if l.next_id < cur.0.next_id {
            // every layout write derives from the current one, so the id
            // allocator only grows; one that went back would reuse ids
            tracing::error!(
                version = l.version,
                next_id = l.next_id.0,
                ours = cur.0.next_id.0,
                "shard layout's id allocator went backwards: ignored"
            );
            return cur.0.clone();
        }
        let changed = l.version > cur.0.version;
        if changed {
            tracing::info!(version = l.version, shards = l.shards.len(), "installed shard layout");
            crate::metrics::LAYOUT_VERSION.set(l.version as i64);
            crate::metrics::LAYOUT_SHARDS.set(l.shards.len() as i64);
        }
        let l = Arc::new(l);
        *cur = (l.clone(), etag);
        drop(cur);
        host.on_layout(l.clone());
        l
    }

    /// Runs `fut` while renewing our lease every renew interval (when no
    /// renew loop runs yet: the inline first step at startup, tests).
    /// Renewals are never cancelled mid-flight: a dropped CAS PUT could land
    /// with an ETag we never learn, and our next renew would lose the lease.
    async fn with_keepalive<T>(&self, host: &Arc<dyn ShardHost>, fut: impl std::future::Future<Output = T>) -> T {
        let done = tokio::sync::Notify::new();
        let work = async {
            let r = fut.await;
            done.notify_one();
            r
        };
        let keepalive = async {
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(self.cfg.renew_every) => {}
                    _ = done.notified() => return,
                }
                self.renew(host).await;
            }
        };
        let (r, ()) = tokio::join!(work, keepalive);
        r
    }

    /// One control-plane round, renewing first.
    pub async fn step(&self, host: &Arc<dyn ShardHost>) -> anyhow::Result<()> {
        self.step_inner(host, true).await
    }

    /// The node's first step, before it serves, retried with backoff until
    /// `startup_deadline`. The step loop retries a failed step next tick
    /// anyway; a store slow at boot must not kill a node that never got
    /// that far. Each attempt keeps the per-call deadline and renews first,
    /// and no wait exceeds `renew_every`, so our lease never lapses between
    /// attempts.
    pub async fn first_step(&self, host: &Arc<dyn ShardHost>) -> anyhow::Result<()> {
        let started = Instant::now();
        let mut attempt = 0;
        loop {
            let e = match self.step(host).await {
                Ok(()) => return Ok(()),
                Err(e) if e.is::<version::Refused>() => return Err(e),
                Err(e) => e,
            };
            let wait = jittered_backoff(attempt, STARTUP_BACKOFF_FLOOR, self.cfg.renew_every, rand::random());
            if started.elapsed() + wait >= self.cfg.startup_deadline {
                return Err(e.context(format!("first cluster step, retried for {:?}", started.elapsed())));
            }
            attempt += 1;
            tracing::warn!(
                attempt,
                retry_in_ms = wait.as_millis() as u64,
                "first cluster step failed at startup (retrying): {e:#}"
            );
            tokio::time::sleep(wait).await;
        }
    }

    async fn step_inner(&self, host: &Arc<dyn ShardHost>, renew: bool) -> anyhow::Result<()> {
        let _step = self.step_lock.lock().await;
        if self.stopping.load(Ordering::Acquire) || self.hold_steps.load(Ordering::Acquire) {
            return Ok(());
        }
        if !renew {
            return self.step_body(host).await;
        }
        self.renew(host).await;
        // a lone node's first step opens its whole share, which can outlive
        // the lease
        self.with_keepalive(host, self.step_body(host)).await
    }

    async fn step_body(&self, host: &Arc<dyn ShardHost>) -> anyhow::Result<()> {
        self.observe_version().await?;
        // A lone node lists less (DESIGN.md "Lone-node control plane"): while
        // `nodes/` holds only our lease, `assign/` changes only by our own
        // writes, and a joiner greets us before it may write anything there.
        let step = self.steps.fetch_add(1, Ordering::Relaxed);
        let contact = self.contact.swap(false, Ordering::AcqRel);
        let was_lone = self.lone.load(Ordering::Acquire) && !contact && !self.list_every_step.load(Ordering::Acquire);
        let was_settled = self.settled.swap(false, Ordering::AcqRel);
        let (live, dead) = self.membership(host, was_lone).await?;
        let lone = live.len() == 1 && dead.is_empty();
        self.lone.store(lone, Ordering::Release);
        let live_ids: HashSet<String> = live.iter().map(|l| l.node_id.clone()).collect();
        let dead_logs: HashMap<String, String> = dead.iter().map(|l| (l.node_id.clone(), l.log_id.clone())).collect();
        // Listed every LONE_ASSIGN_EVERY steps anyway (an out-of-band edit of
        // the bucket).
        if lone && was_lone && was_settled && !step.is_multiple_of(LONE_ASSIGN_EVERY) {
            crate::metrics::CLUSTER_LONE_SKIPS.with_label_values(&["assign"]).inc();
        } else {
            self.read_assignments(host, step.is_multiple_of(FULL_RESYNC_STEPS)).await?;
        }
        let layout = self.layout();
        self.route(&live_ids);
        host.on_membership();
        // A shard we hold was reassigned under us: a peer presumed us dead
        // and fenced our log. Fail-stop now rather than serve stale reads
        // until our next segment PUT collides.
        let assigns = self.assigns.read().clone();
        if let Some(s) = self.owned().into_iter().find(|s| assigns.get(s).is_none_or(|(a, _)| !self.names_us(a))) {
            tracing::error!(shard = s.0, "a shard we hold was reassigned: fail-stop");
            host.lost();
            return Ok(());
        }
        let fair = layout.shards.len().div_ceil(live.iter().filter(|l| !l.draining).count().max(1));
        if !self.joined.load(Ordering::Acquire) && !self.try_join(host, &live, &dead).await {
            return Ok(());
        }
        // e.g. a zombie that woke after its peers fenced it
        if !self.lease_valid() {
            return Ok(());
        }
        // handoffs whose nudge we missed
        let handed: Vec<(ShardId, Assignment)> = layout
            .ids()
            .into_iter()
            .filter_map(|s| assigns.get(&s).filter(|(a, _)| self.handed_to_us(s, a)).map(|(a, _)| (s, a.clone())))
            .collect();
        self.adopt(host, handed).await?;
        self.retry_unreleased(host, &layout, &assigns).await;
        let owned = self.owned();
        if owned.len() < fair {
            self.acquire(host, layout.ids(), fair - owned.len(), &live_ids, &dead_logs, fair, live.len()).await?;
        } else if !self.hand_back_extras(host, &layout, &owned, fair, live.len()).await {
            return Ok(());
        }
        self.trim_owned(host).await;
        if let Err(e) = self.reshard_step(host, &live_ids).await {
            tracing::warn!("reshard step failed (retried next step): {e:#}");
        }
        // dead nodes whose shards have all moved can be forgotten
        for d in &dead {
            if !assigns.values().any(|(a, _)| a.owner.as_deref() == Some(&d.node_id))
                && self.fenced.read().contains_key(&d.log_id)
            {
                self.forget_dead(d).await?;
            }
        }
        // an early return above leaves this false
        let layout = self.layout();
        let settled = lone
            && layout.op.is_none()
            && self.handed.lock().is_empty()
            && layout.ids().iter().all(|s| self.is_owner(*s));
        self.settled.store(settled, Ordering::Release);
        Ok(())
    }

    /// (live, dead) leases. A lone node reuses its view, but still lists
    /// `nodes/` at least once per TTL, so a joiner whose greeting never
    /// arrives is seen anyway.
    async fn membership(
        &self,
        host: &Arc<dyn ShardHost>,
        was_lone: bool,
    ) -> anyhow::Result<(Vec<NodeLease>, Vec<NodeLease>)> {
        let skip = was_lone && self.joined() && {
            let (at, reused) = *self.nodes_listed.lock();
            let per_ttl = (self.cfg.ttl.as_nanos() / self.cfg.renew_every.as_nanos().max(1)).max(1) as u32;
            at.is_some_and(|t| reused + 1 < per_ttl && t.elapsed() + self.cfg.renew_every / 2 < self.cfg.ttl)
        };
        if skip {
            self.nodes_listed.lock().1 += 1;
            crate::metrics::CLUSTER_LONE_SKIPS.with_label_values(&["nodes"]).inc();
            // `peers` is left alone: a greeting racing this step may have
            // added a joiner, which the next step (contact) lists
            return Ok((vec![self.lease.read().clone()], Vec::new()));
        }
        // a failed LIST leaves us not lone: the next step lists again
        self.lone.store(false, Ordering::Release);
        let started = Instant::now();
        let (live, dead) = self.read_nodes(host).await?;
        *self.nodes_listed.lock() = (Some(started), 0);
        let mut peers = self.peers.write();
        *peers =
            live.iter().filter(|l| l.node_id != self.cfg.node_id).map(|l| (l.node_id.clone(), l.clone())).collect();
        self.alone.store(peers.is_empty(), Ordering::Release);
        Ok((live, dead))
    }

    fn names_us(&self, a: &Assignment) -> bool {
        a.owner.as_deref() == Some(&self.cfg.node_id) && a.log_id.as_deref() == Some(&self.log_id)
    }

    /// Our releases that may not have landed (a CAS that failed or timed out
    /// after the close): an assignment still naming us at an epoch we
    /// opened, for a shard we no longer hold. Nobody else would ever take it
    /// (we look alive), and nothing of it was logged since its close, so our
    /// span may end now.
    async fn retry_unreleased(
        &self,
        host: &Arc<dyn ShardHost>,
        layout: &Layout,
        assigns: &BTreeMap<ShardId, Versioned<Assignment>>,
    ) {
        let unreleased: Vec<ShardId> = layout
            .ids()
            .into_iter()
            .filter(|s| {
                !self.is_owner(*s)
                    && assigns.get(s).is_some_and(|(a, _)| {
                        self.names_us(a) && self.opened.read().get(s).is_some_and(|&e| e >= a.epoch)
                    })
            })
            .collect();
        for s in unreleased {
            let frozen = layout.op.as_ref().filter(|o| o.parents.contains(&s)).map(|o| o.id);
            tracing::warn!(shard = s.0, "retrying the release of a shard we closed");
            if let Err(e) = self.release(s, host.durable_end(), host.seq_high(), None, frozen).await {
                tracing::warn!(shard = s.0, "release retry failed: {e:#}");
            }
        }
    }

    /// Hands our shards past an even split straight to the joined peers
    /// short of their share. Parents of a reshard stay (they are about to
    /// freeze), and shards we opened most recently go last (a split's
    /// children). False if we fail-stopped.
    async fn hand_back_extras(
        &self,
        host: &Arc<dyn ShardHost>,
        layout: &Layout,
        owned: &[ShardId],
        fair: usize,
        live: usize,
    ) -> bool {
        let settled = self.settled_peers();
        let keep = layout.shards.len().div_ceil(settled.len() + 1);
        if owned.len() <= keep {
            return true;
        }
        tracing::info!(owned = owned.len(), keep, live, "handing back extra shards");
        let busy: HashSet<ShardId> = layout.op.iter().flat_map(|o| o.parents.clone()).collect();
        let mut cands: Vec<ShardId> = owned.iter().copied().filter(|s| !busy.contains(s)).collect();
        let at = self.opened_at.read().clone();
        cands.sort_by_key(|s| (at.get(s).copied(), std::cmp::Reverse(*s)));
        let extras: Vec<ShardId> = cands.into_iter().take(owned.len() - keep).collect();
        let to = self.short_of(&settled, fair);
        self.close_and_release(host, extras, to, None).await
    }

    /// Deletes a dead incarnation's lease unless the node restarted since
    /// (re-read first: the read that judged it dead may be a step old). The
    /// store has no conditional delete; a restart landing between this GET
    /// and the DELETE recreates its lease at its next renewal.
    async fn forget_dead(&self, d: &NodeLease) -> anyhow::Result<()> {
        let rel = format!("nodes/{}", d.node_id);
        match self.get_json::<serde_json::Value>(&self.path(&rel)).await? {
            Some((l, _)) if l["log_id"].as_str() == Some(d.log_id.as_str()) => self.delete(&rel).await,
            _ => {}
        }
        Ok(())
    }

    fn route(&self, live_ids: &HashSet<String>) {
        let layout = self.layout();
        let assigns = self.assigns.read();
        let mut t = self.table.write();
        t.clear();
        for s in layout.ids() {
            if let Some((a, _)) = assigns.get(&s) {
                if let Some(o) = a.owner.clone().filter(|o| live_ids.contains(o)) {
                    t.insert(s, (o, a.addr.clone().unwrap_or_default()));
                }
            }
        }
    }

    /// Takes up to `want` of `candidates` that are free or orphaned (fencing
    /// an orphan's log first so its span end is final) and opens them.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn acquire(
        &self,
        host: &Arc<dyn ShardHost>,
        candidates: Vec<ShardId>,
        want: usize,
        live_ids: &HashSet<String>,
        dead_logs: &HashMap<String, String>,
        fair: usize,
        live: usize,
    ) -> anyhow::Result<()> {
        use futures::StreamExt;
        let mut picked = Vec::new();
        let mut fresh: Option<Arc<Layout>> = None;
        let mut leases: HashMap<String, Option<String>> = HashMap::new();
        for s in candidates {
            if picked.len() == want {
                break;
            }
            if self.is_owner(s) {
                continue;
            }
            let cached = self.assigns.read().get(&s).cloned();
            let (cur, etag) = match cached {
                None => {
                    // No record: never taken yet, or retired and deleted by
                    // reshard_gc. Only a fresh layout tells them apart: a
                    // step that stalled on an old layout must never recreate
                    // a retired shard over nothing.
                    if fresh.is_none() {
                        fresh = Some(self.refresh_layout(host).await?);
                    }
                    if !fresh.as_ref().is_some_and(|l| l.contains(s)) {
                        continue;
                    }
                    (Assignment::default(), None)
                }
                Some((a, e)) => (a, e),
            };
            if cur.frozen.is_some() {
                continue;
            }
            let mut history = cur.history.clone();
            let mut seq_floor = cur.seq_floor;
            let stale_self =
                cur.owner.as_deref() == Some(&self.cfg.node_id) && cur.log_id.as_deref() != Some(&self.log_id);
            let mut restarted = stale_self;
            if let Some(o) = cur.owner.as_deref().filter(|o| live_ids.contains(*o) && !stale_self) {
                // unless the assignment names an earlier incarnation of it
                // (a fast same-id restart reclaims only its fair share, and
                // nobody else would ever take the rest)
                if !self.superseded(o, cur.log_id.as_deref(), &mut leases).await? {
                    continue; // healthy owner
                }
                restarted = true;
            }
            if let Some(o) = &cur.owner {
                let Some(log) = cur.log_id.clone().or_else(|| dead_logs.get(o).cloned()) else { continue };
                let (end, last_seq) = self.fence_as(&log, Some(if restarted { "restart" } else { "peer" })).await?;
                seq_floor = seq_floor.max(last_seq);
                if let Some(last) = history.last_mut() {
                    if last.end.is_none() {
                        last.end = Some(end);
                    }
                }
            }
            let epoch = cur.epoch + 1;
            let mut next = history.clone();
            next.push(Span { log_id: self.log_id.clone(), epoch, start: host.next_ordinal(), end: None });
            // never drop a span to make room: an unreplayed one holds acked writes
            trim_history(&mut next, cur.applied_epoch, self.trim_at());
            if next.len() > MAX_SPANS {
                tracing::error!(shard = s.0, spans = next.len(), applied_epoch = cur.applied_epoch, "shard history at its cap with no clean open to trim it: not taking it (spans are never dropped unreplayed)");
                crate::metrics::LEASE_EVENTS.with_label_values(&["history_full"]).inc();
                continue;
            }
            let newa = Assignment {
                owner: Some(self.cfg.node_id.clone()),
                log_id: Some(self.log_id.clone()),
                addr: Some(self.cfg.addr.clone()),
                epoch,
                seq_floor,
                history: next,
                frozen: None,
                applied_epoch: cur.applied_epoch,
                extra: cur.extra.clone(),
            };
            let mode = match etag {
                None => PutMode::Create,
                e => if_match(e),
            };
            picked.push((s, newa, mode, history));
        }
        let cas: Vec<_> = futures::stream::iter(picked)
            .map(|(s, newa, mode, history)| async move {
                let r = self.put_json(&self.path(&format!("assign/{}", s.key())), &newa, mode).await;
                (s, newa, history, r)
            })
            .buffer_unordered(32)
            .collect()
            .await;
        let (mut acquired, mut floor, mut failed) = (Vec::new(), 0i64, None);
        for (s, newa, history, r) in cas {
            match r {
                Ok(e) => {
                    floor = floor.max(newa.seq_floor);
                    acquired.push((s, newa.epoch, history));
                    self.assigns.write().insert(s, (newa, e));
                    self.owned.write().insert(s);
                }
                Err(e) if is_conflict(&e) => {
                    // re-read it next step
                    if let Some((_, etag)) = self.assigns.write().get_mut(&s) {
                        *etag = None;
                    }
                }
                Err(e) => failed = Some(e),
            }
        }
        acquired.sort_by_key(|a| a.0);
        if !acquired.is_empty() {
            tracing::info!(shards = ?acquired.iter().map(|a| a.0).collect::<Vec<_>>(), owned = self.owned().len(), fair, live, "acquired shards");
            host.wait_seq_floor(floor).await;
        }
        self.open_acquired(host, acquired).await?;
        if let Some(e) = failed {
            return Err(e.into());
        }
        Ok(())
    }

    /// The peers that may take shards.
    fn settled_peers(&self) -> Vec<NodeLease> {
        self.peers.read().values().filter(|l| !l.draining && l.joined).cloned().collect()
    }

    /// `peers` owning fewer than `share` shards, each with how many it is short.
    fn short_of(&self, peers: &[NodeLease], share: usize) -> Vec<(NodeLease, usize)> {
        let mut count: HashMap<&str, usize> = HashMap::new();
        let assigns = self.assigns.read();
        for (a, _) in assigns.values() {
            if let Some(o) = a.owner.as_deref() {
                *count.entry(o).or_default() += 1;
            }
        }
        peers
            .iter()
            .filter_map(|l| {
                let have = count.get(l.node_id.as_str()).copied().unwrap_or(0);
                (have < share).then(|| (l.clone(), share - have))
            })
            .collect()
    }

    /// Closes `shards` together and releases each one whose close
    /// succeeded: handed to a peer in `to` while it is short, else unowned.
    /// Then nudges every peer (recipients adopt; the rest fix their routing).
    /// A failed close may leave entries in flight past the span end we would
    /// publish, so it is never released: we fail-stop instead, and a
    /// successor fences our log and replays it. False if we fail-stopped.
    /// `frozen`: release them frozen for that reshard op (`to` empty).
    pub(crate) async fn close_and_release(
        &self,
        host: &Arc<dyn ShardHost>,
        shards: Vec<ShardId>,
        mut to: Vec<(NodeLease, usize)>,
        frozen: Option<u64>,
    ) -> bool {
        use futures::StreamExt;
        if shards.is_empty() {
            return true;
        }
        let n = shards.len();
        let started = Instant::now();
        // round-robin over the peers still short, so each gets a fair slice
        let mut dest: HashMap<ShardId, NodeLease> = HashMap::new();
        let mut i = 0;
        for &s in &shards {
            for _ in 0..to.len() {
                let k = i % to.len();
                i += 1;
                if to[k].1 > 0 {
                    to[k].1 -= 1;
                    dest.insert(s, to[k].0.clone());
                    break;
                }
            }
        }
        if !dest.is_empty() {
            let mut plan: HashMap<String, Vec<ShardId>> = HashMap::new();
            for (s, l) in &dest {
                plan.entry(l.addr.clone()).or_default().push(*s);
            }
            host.prewarm(plan.into_iter().collect()).await;
            tracing::info!(
                shards = dest.len(),
                elapsed_ms = started.elapsed().as_millis() as u64,
                "recipients prewarmed"
            );
        }
        let closed = host.close_many(shards).await;
        if frozen.is_some() && crate::reshard::crash_at(&self.cfg.node_id, "closed") {
            return false;
        }
        let (end, floor) = (host.durable_end(), host.seq_high());
        let mut ok = true;
        let mut done = Vec::new();
        for (s, r) in closed {
            match r {
                Ok(()) => {
                    self.owned.write().remove(&s);
                    done.push(s);
                }
                Err(e) => {
                    tracing::error!(shard = s.0, "close failed: {e:#}");
                    ok = false;
                }
            }
        }
        let plan: Vec<(ShardId, Option<NodeLease>)> = done.into_iter().map(|s| (s, dest.remove(&s))).collect();
        let released: Vec<(Option<NodeLease>, anyhow::Result<Option<Handoff>>)> = futures::stream::iter(plan)
            .map(|(s, dest)| async move {
                let r = self.release(s, end, floor, dest.as_ref(), frozen).await;
                (dest, r)
            })
            .buffer_unordered(32)
            .collect()
            .await;
        // a stale route forwards to us, and we no longer own the shard
        let mut nudges: HashMap<String, Vec<Handoff>> =
            self.peers.read().values().map(|l| (l.addr.clone(), Vec::new())).collect();
        for (dest, r) in released {
            match r {
                Ok(Some(h)) => nudges.entry(dest.map(|l| l.addr).unwrap_or_default()).or_default().push(h),
                Ok(None) => {}
                // the assignment still names us with an open span: whoever
                // takes the shard once our lease lapses fences and replays
                Err(e) => tracing::warn!("release failed: {e:#}"),
            }
        }
        let handed: usize = nudges.values().map(|v| v.len()).sum();
        tracing::info!(
            shards = n,
            handed,
            elapsed_ms = started.elapsed().as_millis() as u64,
            "closed and released shards"
        );
        let nudges: Vec<(String, Vec<Handoff>)> = nudges.into_iter().filter(|(a, _)| !a.is_empty()).collect();
        crate::metrics::CLUSTER_NUDGES.with_label_values(&["sent"]).inc_by(nudges.len() as u64);
        host.nudge(nudges).await;
        if !ok {
            tracing::error!("a shard failed to close cleanly: fail-stop (a successor fences and replays our log)");
            host.lost();
        }
        ok
    }

    /// Closes our span at `end` (exclusive): unowned, or handed to `to` (the
    /// next epoch, with an open span for it). CAS against the cached
    /// assignment; re-read once on a conflict. Returns the handoff for `to`.
    async fn release(
        &self,
        shard: ShardId,
        end: u64,
        seq_floor: i64,
        to: Option<&NodeLease>,
        frozen: Option<u64>,
    ) -> anyhow::Result<Option<Handoff>> {
        let path = self.path(&format!("assign/{}", shard.key()));
        let mut cur = self.assigns.read().get(&shard).cloned().filter(|(_, e)| e.is_some());
        for attempt in 0..2 {
            let (mut a, etag) = match cur.take() {
                Some(c) => c,
                None => match self.get_json::<Assignment>(&path).await? {
                    Some(c) => c,
                    None => return Ok(None),
                },
            };
            if a.owner.as_deref() != Some(&self.cfg.node_id) {
                return Ok(None);
            }
            // Served at this epoch (and closed): its state holds every span
            // up to ours. Never served (a failed open, a handoff passed on
            // unopened): nothing of it is in our log, so our span goes.
            let served = a.log_id.as_deref() == Some(&self.log_id) && self.served.read().get(&shard) == Some(&a.epoch);
            if a.history.last().is_some_and(|l| l.log_id == self.log_id && l.end.is_none()) {
                if served || frozen.is_some() {
                    a.history.last_mut().unwrap().end = Some(end);
                } else {
                    a.history.pop();
                }
            }
            if served && frozen.is_none() {
                a.applied_epoch = a.applied_epoch.max(a.epoch);
            }
            a.seq_floor = a.seq_floor.max(seq_floor);
            if frozen.is_some() {
                a.frozen = frozen;
            }
            match to {
                None => {
                    a.owner = None;
                    a.addr = None;
                    a.log_id = None;
                }
                Some(l) => {
                    // Its span starts at the ordinal its lease published (a
                    // lower bound), and never inside an earlier span of the
                    // same log: replay markers must map to one span.
                    let start = a
                        .history
                        .iter()
                        .filter(|sp| sp.log_id == l.log_id)
                        .filter_map(|sp| sp.end)
                        .fold(l.next_ordinal, u64::max);
                    a.epoch += 1;
                    a.owner = Some(l.node_id.clone());
                    a.addr = Some(l.addr.clone());
                    a.log_id = Some(l.log_id.clone());
                    a.history.push(Span { log_id: l.log_id.clone(), epoch: a.epoch, start, end: None });
                }
            }
            if frozen.is_none() {
                trim_history(&mut a.history, a.applied_epoch, self.trim_at());
            }
            match self.put_json(&path, &a, if_match(etag)).await {
                Ok(e) => {
                    self.assigns.write().insert(shard, (a.clone(), e.clone()));
                    match to {
                        Some(l) => self.table.write().insert(shard, (l.node_id.clone(), l.addr.clone())),
                        None => self.table.write().remove(&shard),
                    };
                    return Ok(to.map(|_| Handoff { shard, assignment: a, etag: e }));
                }
                Err(e) if is_conflict(&e) && attempt == 0 => continue, // stale cache: re-read
                Err(e) => return Err(e.into()),
            }
        }
        unreachable!("second attempt returns")
    }

    /// Whether an assignment naming live owner `o` with `log` names an
    /// earlier incarnation of it. Our listing of `o`'s lease may predate the
    /// assignment, so the lease is re-read: an incarnation writes its lease
    /// before any assignment, so a lease read after the assignment that
    /// still names another log names a later one. `leases` caches re-reads.
    async fn superseded(
        &self,
        o: &str,
        log: Option<&str>,
        leases: &mut HashMap<String, Option<String>>,
    ) -> anyhow::Result<bool> {
        let Some(log) = log else { return Ok(false) };
        let listed = self.peers.read().get(o).map(|l| l.log_id.clone());
        if listed.is_none_or(|l| l == log) {
            return Ok(false);
        }
        if !leases.contains_key(o) {
            let fresh = self.get_json::<NodeLease>(&self.path(&format!("nodes/{o}"))).await?.map(|(l, _)| l.log_id);
            leases.insert(o.to_string(), fresh);
        }
        let fresh = leases[o].as_deref();
        if fresh.is_some_and(|f| f != log) {
            tracing::warn!(
                owner = o,
                stale_log = log,
                live_log = fresh,
                "shard still names an earlier incarnation of its live owner: taking it over"
            );
            return Ok(true);
        }
        Ok(false)
    }

    /// Trims our histories past `trim_at` (a crash loop, many takeovers)
    /// that a durable checkpoint inside our own span made redundant. Best
    /// effort.
    async fn trim_owned(&self, host: &Arc<dyn ShardHost>) {
        let cands: Vec<(ShardId, Assignment, Option<String>)> = {
            let assigns = self.assigns.read();
            let served = self.served.read();
            self.owned()
                .into_iter()
                .filter_map(|s| {
                    let (a, e) = assigns.get(&s)?;
                    let ours = self.names_us(a) && served.get(&s) == Some(&a.epoch);
                    (ours
                        && e.is_some()
                        && a.frozen.is_none()
                        && a.history.len() > self.trim_at()
                        && a.history.iter().any(|sp| sp.epoch < a.epoch))
                    .then(|| (s, a.clone(), e.clone()))
                })
                .filter(|(s, ..)| host.checkpointed(*s))
                .collect()
        };
        for (s, mut a, etag) in cands {
            a.applied_epoch = a.applied_epoch.max(a.epoch);
            trim_history(&mut a.history, a.applied_epoch, self.trim_at());
            let path = self.path(&format!("assign/{}", s.key()));
            match self.put_json(&path, &a, if_match(etag)).await {
                Ok(e) => {
                    tracing::info!(
                        shard = s.0,
                        spans = a.history.len(),
                        "trimmed a shard's history to our span (checkpointed in it)"
                    );
                    self.assigns.write().insert(s, (a, e));
                }
                Err(e) => {
                    // a conflict: re-read next step (and fail-stop if moved)
                    if let Some((_, etag)) = self.assigns.write().get_mut(&s) {
                        *etag = None;
                    }
                    tracing::warn!(shard = s.0, "trimming a shard's history failed: {e}");
                }
            }
        }
    }

    /// Writes our lease as draining ahead of `shutdown`, for a node with
    /// its own work to hand over first: peers stop handing it shards, and
    /// its own steps stop taking them.
    pub async fn announce_drain(&self, host: &Arc<dyn ShardHost>) {
        self.lease.write().draining = true;
        self.renew(host).await;
    }

    /// Closes and releases every shard, fences our log, drops our lease.
    /// Err if our log could not be fenced: our lease is then left in place
    /// (renewals stopped) and the caller must exit nonzero, so peers presume
    /// us dead and fence it. Deleting the lease over an unfenced log would
    /// leave nobody to fence it, and peers following it would wait forever.
    pub async fn shutdown(&self, host: &Arc<dyn ShardHost>) -> anyhow::Result<()> {
        // a step would re-acquire the shards we are releasing
        self.stopping.store(true, Ordering::Release);
        let _step = self.step_lock.lock().await;
        // Announce the drain first, or a peer stepping meanwhile hands shards
        // back to us, which we'd never adopt. Without peers nobody reads it,
        // and the write would wait out the lease key's gap (up to ~1 s).
        // A joiner we haven't listed yet owns nothing, so it hands us
        // nothing, and its step takes our shards once our lease is gone.
        self.lease.write().draining = true;
        if !self.peers.read().is_empty() {
            self.renew(host).await;
        }
        let settled = self.settled_peers();
        let to = self.short_of(&settled, self.layout().shards.len().div_ceil(settled.len().max(1)));
        // plus any a peer handed us before it saw the drain (never opened:
        // they are just handed on)
        let mut shards = self.owned();
        let pending = std::mem::take(&mut *self.handed.lock());
        let layout = self.layout();
        for h in pending {
            if layout.contains(h.shard) && self.handed_to_us(h.shard, &h.assignment) {
                self.assigns.write().insert(h.shard, (h.assignment, h.etag));
            }
        }
        let assigns = self.assigns.read().clone();
        shards.extend(
            assigns.iter().filter(|(s, (a, _))| layout.contains(**s) && self.handed_to_us(**s, a)).map(|(s, _)| *s),
        );
        if !self.close_and_release(host, shards, to, None).await {
            return Ok(()); // fail-stopped (host.lost)
        }
        // a fence below an in-flight segment would cut entries out of a span
        if !host.quiesce().await {
            tracing::error!("our log did not quiesce: fail-stop without fencing it (peers will)");
            host.lost();
            return Ok(());
        }
        // Peers following our log drop its firehose source only at a fence;
        // without one every peer's merged firehose stalls at our watermark.
        if let Err(e) = self.fence_own_log(host).await {
            {
                let _r = self.renew_lock.lock().await;
                self.gone.store(true, Ordering::Release);
            }
            crate::metrics::LEASE_EVENTS.with_label_values(&["shutdown_fence_failed"]).inc();
            return Err(e.context("fencing our log on shutdown"));
        }
        {
            // stop renewing (waiting out a renewal in flight) before the delete
            let _r = self.renew_lock.lock().await;
            self.gone.store(true, Ordering::Release);
        }
        host.leaving();
        self.delete(&format!("nodes/{}", self.cfg.node_id)).await;
        // peers' next step takes whatever we didn't hand them: run it now
        self.nudge_all(host, false).await;
        Ok(())
    }

    /// Nudges every peer (and, with `me`, ourselves) to step now.
    pub(crate) async fn nudge_all(&self, host: &Arc<dyn ShardHost>, me: bool) {
        let nudges: Vec<(String, Vec<Handoff>)> = self.peers().into_iter().map(|l| (l.addr, Vec::new())).collect();
        crate::metrics::CLUSTER_NUDGES.with_label_values(&["sent"]).inc_by(nudges.len() as u64);
        if me {
            self.nudge(Vec::new());
        }
        host.nudge(nudges).await;
    }

    /// Ok(true): our log is fenced at `end` (by us, or a peer before us).
    /// Ok(false): a segment holds `end`.
    async fn fence_own_at(&self, end: u64, last_seq: i64) -> anyhow::Result<bool> {
        let path = vlsync_firehose::log::segment_path(&self.store, &self.log_id, end);
        self.count("put");
        let put = self.store.raw.put_opts(
            &path,
            PutPayload::from_bytes(vlsync_store::segment::fence_object(&self.cfg.node_id)),
            PutOptions { mode: PutMode::Create, ..Default::default() },
        );
        match self.bounded("fence", put).await {
            Ok(_) => {}
            Err(e) if is_conflict(&e) => {
                self.count("get");
                let b = self.bounded("get", async { self.store.raw.get(&path).await?.bytes().await }).await?;
                if !matches!(
                    vlsync_store::segment::parse(b, false, None)?,
                    vlsync_store::segment::LogObject::Fence { .. }
                ) {
                    return Ok(false);
                }
            }
            Err(e) => return Err(e.into()),
        }
        self.fenced.write().insert(self.log_id.clone(), (end, last_seq));
        tracing::info!(log_id = %self.log_id, fence_ordinal = end, "fenced our log at its end");
        Ok(true)
    }

    /// A TTL, at most 30 s (inside a supervisor's stop timeout).
    fn shutdown_fence_budget(&self) -> Duration {
        self.cfg.ttl.min(Duration::from_secs(30))
    }

    /// Retries with backoff for `shutdown_fence_budget`. A fence PUT that
    /// timed out but landed is found by the next attempt's scan.
    async fn fence_own_log(&self, host: &Arc<dyn ShardHost>) -> anyhow::Result<()> {
        let deadline = Instant::now() + self.shutdown_fence_budget();
        let mut backoff = Duration::from_millis(200);
        let mut attempt = 1u32;
        // Quiesced, our log's end is known: fence there without the scan,
        // whose LIST of a long-lived log outlasted the whole budget under
        // load. Anything else at that ordinal falls back to the scan.
        match self.fence_own_at(host.durable_end(), host.seq_high()).await {
            Ok(true) => return Ok(()),
            Ok(false) => {}
            Err(e) => tracing::warn!("fencing our log at its end failed (scanning it instead): {e:#}"),
        }
        loop {
            let e = match self.fence(&self.log_id).await {
                Ok(_) => return Ok(()),
                Err(e) => e,
            };
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                tracing::error!(attempts = attempt, "fencing our log on shutdown failed: giving up: {e:#}");
                return Err(e);
            }
            tracing::warn!(
                attempt,
                retry_in_ms = backoff.min(left).as_millis() as u64,
                "fencing our log on shutdown failed (retrying): {e:#}"
            );
            tokio::time::sleep(backoff.min(left)).await;
            backoff = (backoff * 2).min(Duration::from_secs(5));
            attempt += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;
    use std::sync::atomic::AtomicI64;

    #[derive(Default)]
    struct Host {
        opened: Mutex<Vec<(ShardId, u64, Vec<Span>)>>,
        closed: Mutex<Vec<Vec<ShardId>>>,
        ord: AtomicU64,
        seq: AtomicI64,
        floors: Mutex<Vec<i64>>,
        lost: AtomicU64,
        fail_close: Mutex<HashSet<ShardId>>,
        /// shards whose opens fail (a replay error, say)
        fail_open: Mutex<HashSet<ShardId>>,
        /// every shard checkpointed inside its span (`ShardHost::checkpointed`)
        checkpointed: std::sync::atomic::AtomicBool,
        nudged: Mutex<Vec<(String, Vec<Handoff>)>>,
        /// (addr, shards, closes done before it)
        prewarmed: Mutex<Vec<(String, Vec<ShardId>, usize)>>,
        /// peers answer our greetings "not following"
        unheard: std::sync::atomic::AtomicBool,
        /// peer logs our "firehose" follows (published in our lease)
        follows: Mutex<BTreeMap<String, i64>>,
        /// `ShardHost::may_join` answers false
        hold_join: std::sync::atomic::AtomicBool,
    }

    #[async_trait::async_trait]
    impl ShardHost for Host {
        fn next_ordinal(&self) -> u64 {
            self.ord.load(Ordering::SeqCst)
        }
        fn durable_end(&self) -> u64 {
            self.ord.load(Ordering::SeqCst)
        }
        fn seq_high(&self) -> i64 {
            self.seq.load(Ordering::SeqCst)
        }
        async fn wait_seq_floor(&self, seq: i64) {
            self.floors.lock().push(seq);
        }
        async fn open_many(&self, v: Vec<(ShardId, u64, Vec<Span>)>) -> Vec<(ShardId, anyhow::Result<()>)> {
            let fail = self.fail_open.lock().clone();
            v.into_iter()
                .map(|(s, e, h)| {
                    if fail.contains(&s) {
                        return (s, Err(anyhow::anyhow!("replay failed")));
                    }
                    self.opened.lock().push((s, e, h));
                    (s, Ok(()))
                })
                .collect()
        }
        async fn close_many(&self, v: Vec<ShardId>) -> Vec<(ShardId, anyhow::Result<()>)> {
            self.closed.lock().push(v.clone());
            let fail = self.fail_close.lock().clone();
            v.into_iter()
                .map(|s| (s, if fail.contains(&s) { Err(anyhow::anyhow!("barrier timed out")) } else { Ok(()) }))
                .collect()
        }
        fn checkpointed(&self, _shard: ShardId) -> bool {
            self.checkpointed.load(Ordering::SeqCst)
        }
        fn lost(&self) {
            self.lost.fetch_add(1, Ordering::SeqCst);
        }
        async fn nudge(&self, nudges: Vec<(String, Vec<Handoff>)>) {
            self.nudged.lock().extend(nudges);
        }
        async fn prewarm(&self, plan: Vec<(String, Vec<ShardId>)>) {
            let closes = self.closed.lock().len();
            self.prewarmed.lock().extend(plan.into_iter().map(|(a, s)| (a, s, closes)));
        }
        async fn greet(&self, peers: Vec<NodeLease>) -> Vec<Option<i64>> {
            let ok = !self.unheard.load(Ordering::SeqCst);
            peers.iter().map(|_| ok.then_some(i64::MIN)).collect()
        }
        fn follow_floors(&self) -> BTreeMap<String, i64> {
            self.follows.lock().clone()
        }
        fn may_join(&self) -> bool {
            !self.hold_join.load(Ordering::SeqCst)
        }
    }

    /// vlrelay's chaos `consumers` scenario: a node whose runtime was
    /// saturated renewed late, lapsed and fail-stopped. On a lease plane the
    /// renewals go on while the caller's only thread is stuck.
    #[test]
    fn a_starved_runtime_keeps_its_lease_on_the_lease_plane() {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            let store = Store::memory(None);
            let plane = LeasePlane::new(store.clone());
            let c = join(ClusterConfig { lease_plane: Some(plane), ..cfg("a") }, store).await.unwrap();
            let h = Arc::new(Host::default());
            c.spawn(h.clone());
            tokio::time::sleep(Duration::from_millis(200)).await;
            std::thread::sleep(Duration::from_millis(1800));
            assert!(c.lease_valid(), "renewals stopped with the caller's runtime");
            assert_eq!(h.lost.load(Ordering::SeqCst), 0);
        });
    }

    /// Joins as a node whose step loop runs (`spawn`): it greets peers, so
    /// its steps can join with live peers around (`try_join`). The mock
    /// host's greetings never reach a peer's `learn_peer`, so these nodes
    /// list everything every step (`lone_join` doesn't).
    async fn join(cfg: ClusterConfig, store: Store) -> anyhow::Result<Arc<Cluster>> {
        let c = lone_join(cfg, store).await?;
        c.list_every_step.store(true, Ordering::Release);
        Ok(c)
    }

    /// [`join`] with the lone-node listing savings on, as in production.
    async fn lone_join(cfg: ClusterConfig, store: Store) -> anyhow::Result<Arc<Cluster>> {
        let c = Cluster::join(cfg, store).await?;
        c.spawned.store(true, Ordering::Release);
        Ok(c)
    }

    fn cfg(id: &str) -> ClusterConfig {
        ClusterConfig {
            node_id: id.into(),
            addr: format!("http://{id}"),
            shards: 8,
            ttl: Duration::from_millis(600),
            renew_every: Duration::from_millis(100),
            skew: Duration::from_millis(100),
            clock_offset_ms: 0,
            levels: version::Window::BUILD,
            lease_plane: None,
            startup_deadline: STARTUP_DEADLINE,
        }
    }

    fn skewed(id: &str, offset_ms: i64) -> ClusterConfig {
        ClusterConfig { clock_offset_ms: offset_ms, ..cfg(id) }
    }

    fn host() -> (Arc<Host>, Arc<dyn ShardHost>) {
        let h = Arc::new(Host::default());
        let d: Arc<dyn ShardHost> = h.clone();
        (h, d)
    }

    /// A real segment holding one entry at `seq` (fence/replay parse it).
    fn segment(log_id: &str, ord: u64, seq: i64) -> PutPayload {
        let mut b = vlsync_store::segment::SegmentBuilder::new();
        b.push(seq, vlsync_store::slots::ShardId(0), 1, |_| {}, &[]);
        let mut data = b.header(log_id, ord);
        data.extend_from_slice(&b.body);
        PutPayload::from(data)
    }

    /// Renewals are timed, validity is exported, a lost CAS is counted, and
    /// a restart that fences its previous (unfenced) incarnation counts a
    /// takeover. Counters are process-wide: checked for growth.
    #[tokio::test]
    async fn lease_metrics() {
        let m = &crate::metrics::LEASE_RENEW_ERRORS;
        let store = Store::memory(None);
        let (h, hd) = host();
        let id = format!("lease-metrics-{}", vlsync_atproto::tid::now_micros());
        let restarts0 = crate::metrics::PEER_TAKEOVERS.with_label_values(&["restart"]).get();
        let a = join(cfg(&id), store.clone()).await.unwrap();
        let (timed0, conflicts0) =
            (crate::metrics::LEASE_RENEW_SECONDS.get_sample_count(), m.with_label_values(&["conflict"]).get());
        tokio::time::sleep(a.cfg.renew_every).await; // past the lease-write gap
        a.renew(&hd).await;
        assert!(crate::metrics::LEASE_RENEW_SECONDS.get_sample_count() > timed0);
        let v = a.lease_validity_secs();
        assert!(v > 0.0 && v <= 0.5, "TTL - skew = 500 ms after the send: {v}");
        crate::metrics::render();
        assert!(crate::metrics::LEASE_VALIDITY.with_label_values(&[id.as_str()]).get() > 0.0, "exported at render");
        // someone else rewrites our lease: the next renewal loses its CAS
        store.raw.put(&a.path(&format!("nodes/{id}")), PutPayload::from_static(b"{}")).await.unwrap();
        tokio::time::sleep(a.cfg.renew_every).await; // past the lease-write gap
        a.renew(&hd).await;
        assert_eq!(h.lost.load(Ordering::SeqCst), 1);
        assert!(m.with_label_values(&["conflict"]).get() > conflicts0);
        // a restart with the same id (its predecessor never fenced its log)
        store.raw.delete(&a.path(&format!("nodes/{id}"))).await.unwrap();
        let lease = NodeLease {
            node_id: id.clone(),
            log_id: a.log_id.clone(),
            addr: String::new(),
            writer: 0,
            expires_ms: 0,
            renewals: 1,
            next_ordinal: 0,
            draining: false,
            joined: true,
            follows: BTreeMap::new(),
            wm_cap: 0,
            rev: String::new(),
            min_level: 1,
            max_level: 1,
            seen_level: 1,
            pending_age_ms: None,
        };
        a.put_json(&a.path(&format!("nodes/{id}")), &lease, PutMode::Overwrite).await.unwrap();
        let b = join(cfg(&id), store.clone()).await.unwrap();
        assert!(b.fenced_logs().contains_key(&a.log_id));
        assert!(crate::metrics::PEER_TAKEOVERS.with_label_values(&["restart"]).get() > restarts0);
    }

    /// With K PUTs in flight a crash leaves holes: 0..=2 durable, 3 never
    /// landed, 4 and 5 (sealed while 3 was in flight) did. The fence goes at
    /// the hole, every fencer agrees on it, and the garbage stays cut off.
    #[tokio::test]
    async fn fence_lands_at_the_first_hole() {
        let store = Store::memory(None);
        let log = "dead.1";
        for ord in 0..3 {
            store
                .raw
                .put(&vlsync_firehose::log::segment_path(&store, log, ord), segment(log, ord, 100 + ord as i64))
                .await
                .unwrap();
        }
        for ord in 4..6u64 {
            let mut b = vlsync_store::segment::SegmentBuilder::new();
            b.push(200 + ord as i64, vlsync_store::slots::ShardId(0), 1, |_| {}, &[]);
            let mut data = b.sealed_header(log, ord, 3);
            data.extend_from_slice(&b.body);
            store.raw.put(&vlsync_firehose::log::segment_path(&store, log, ord), PutPayload::from(data)).await.unwrap();
        }
        let a = join(cfg("a"), store.clone()).await.unwrap();
        assert_eq!(a.fence(log).await.unwrap(), (3, 102), "fence at the hole; last seq from the durable prefix");
        let b = join(cfg("b"), store.clone()).await.unwrap();
        assert_eq!(b.fence(log).await.unwrap(), (3, 102), "a second fencer finds the same end instead of stacking one");
        let r = store
            .raw
            .put_opts(
                &vlsync_firehose::log::segment_path(&store, log, 3),
                segment(log, 3, 103),
                PutOptions { mode: PutMode::Create, ..Default::default() },
            )
            .await;
        assert!(r.is_err(), "the zombie's in-flight segment collides with the fence");
    }

    #[tokio::test]
    async fn assignment_handoff_fencing() {
        let store = Store::memory(None);
        let a = join(cfg("a"), store.clone()).await.unwrap();
        let (ha, ha_dyn) = host();
        a.step(&ha_dyn).await.unwrap();
        assert_eq!(a.owned().len(), 8);
        ha.ord.store(5, Ordering::SeqCst); // a wrote 5 segments
        ha.seq.store(1000, Ordering::SeqCst);

        let b = join(cfg("b"), store.clone()).await.unwrap();
        assert_ne!(a.writer, b.writer, "writer ids unique among live nodes");
        let (hb, hb_dyn) = host();
        b.step(&hb_dyn).await.unwrap();
        assert!(b.joined(), "a confirmed it follows b's log");
        assert!(b.owned().is_empty(), "every shard has a live owner");
        a.step(&ha_dyn).await.unwrap(); // a sees b joined: releases 4
        assert_eq!(ha.closed.lock().len(), 1, "the 4 extras are closed in one batch (one barrier segment)");
        let nudged = ha.nudged.lock().clone();
        assert_eq!(nudged.len(), 1, "one nudge, to the node short of its share");
        assert_eq!((nudged[0].0.as_str(), nudged[0].1.len()), ("http://b", 4), "carrying the 4 handoffs");
        for h in &nudged[0].1 {
            let a = &h.assignment;
            assert_eq!(
                (a.owner.as_deref(), a.log_id.as_deref(), a.epoch),
                (Some("b"), Some(b.log_id.as_str()), 2),
                "handed straight to b"
            );
            assert_eq!(a.history.len(), 2);
            assert_eq!(
                a.history[1],
                Span { log_id: b.log_id.clone(), epoch: 2, start: 0, end: None },
                "b's span opens at b's published ordinal"
            );
        }
        // b adopts them from the nudge, with no control-plane read
        let before = b.store_requests();
        b.nudge(nudged[0].1.clone());
        b.adopt_handed(&hb_dyn).await.unwrap();
        assert_eq!(b.store_requests(), before, "adopting a handoff reads nothing");
        assert_eq!((a.owned().len(), b.owned().len()), (4, 4));
        for (_, epoch, hist) in hb.opened.lock().iter() {
            assert_eq!(*epoch, 2);
            assert_eq!(hist.len(), 1);
            assert_eq!((hist[0].log_id.as_str(), hist[0].start, hist[0].end), (a.log_id.as_str(), 0, Some(5)));
        }
        assert_eq!(*hb.floors.lock(), vec![1000], "the releaser's seqs bound the new owner's");

        // a dies with a segment in flight; b fences a's log and takes over
        store
            .raw
            .put(&vlsync_firehose::log::segment_path(&store, &a.log_id, 7), segment(&a.log_id, 7, 5000))
            .await
            .unwrap();
        // b keeps renewing (as its renew loop would) while a's lease goes
        // stale; it must not take a's shards before ttl + skew of b's time
        for _ in 0..5 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            b.step(&hb_dyn).await.unwrap();
        }
        assert_eq!(b.owned().len(), 4, "a presumed alive for ttl + skew after its lease last changed");
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(!a.lease_valid(), "a must stop acking after ttl - skew");
        b.step(&hb_dyn).await.unwrap();
        assert_eq!(b.owned().len(), 8, "b takes over all shards");
        let fence = *b.fenced_logs().get(&a.log_id).unwrap();
        assert_eq!(fence, 8, "fence lands after the highest existing segment");
        let last = hb.opened.lock().last().cloned().unwrap();
        assert_eq!(last.2.last().unwrap().end, Some(8), "dead span ends at the fence");
        assert_eq!(*hb.floors.lock().last().unwrap(), 5000, "a dead log's last seq bounds the new owner's");
        // a zombie write at the fence ordinal now collides
        let r = store
            .raw
            .put_opts(
                &vlsync_firehose::log::segment_path(&store, &a.log_id, 8),
                PutPayload::from_static(b"zombie"),
                PutOptions { mode: PutMode::Create, ..Default::default() },
            )
            .await;
        assert!(r.is_err(), "zombie append must fail");
        // and a stepping again (it has no valid lease) fail-stops: its
        // shards were reassigned under it
        a.step(&ha_dyn).await.unwrap();
        assert!(ha.lost.load(Ordering::SeqCst) > 0, "a zombie whose shards moved fail-stops");
    }

    /// A handoff whose nudge never arrived is adopted by the joiner's next
    /// step; a shard still naming us at an epoch we already opened (our
    /// release CAS failed) is never adopted again.
    #[tokio::test]
    async fn missed_nudge_is_adopted_by_the_next_step_once() {
        let store = Store::memory(None);
        let a = join(cfg("a"), store.clone()).await.unwrap();
        let (ha, ha_dyn) = host();
        a.step(&ha_dyn).await.unwrap();
        ha.ord.store(3, Ordering::SeqCst);
        let b = join(cfg("b"), store.clone()).await.unwrap();
        let (hb, hb_dyn) = host();
        hb.ord.store(7, Ordering::SeqCst);
        b.step(&hb_dyn).await.unwrap(); // renews: publishes ordinal 7
        a.step(&ha_dyn).await.unwrap();
        tokio::time::sleep(Duration::from_millis(250)).await;
        a.step(&ha_dyn).await.unwrap(); // hands 4 to b; the nudge is dropped
        assert_eq!(ha.nudged.lock()[0].1.len(), 4);
        // b was asked to warm exactly those, before a closed them
        let mut handed: Vec<ShardId> = ha.nudged.lock()[0].1.iter().map(|h| h.shard).collect();
        handed.sort();
        let pw = ha.prewarmed.lock().clone();
        assert_eq!(pw.len(), 1, "{pw:?}");
        let mut warmed = pw[0].1.clone();
        warmed.sort();
        assert_eq!((pw[0].0.as_str(), warmed, pw[0].2), (b.cfg.addr.as_str(), handed, 0));
        b.step(&hb_dyn).await.unwrap();
        assert_eq!(b.owned(), [4, 5, 6, 7].map(ShardId).to_vec());
        for (_, epoch, hist) in hb.opened.lock().iter() {
            assert_eq!((*epoch, hist.len(), hist[0].end), (2, 1, Some(3)), "replays a's closed span only");
        }
        // b's release of 7 "fails" (the assignment still names b): b must not
        // re-adopt it with a's span as its history (which would drop b's own
        // span); it retries the release and takes it back the normal way,
        // replaying its own closed span too
        b.owned.write().remove(&ShardId(7));
        b.step(&hb_dyn).await.unwrap();
        let opened = hb.opened.lock().clone();
        assert_eq!(opened.len(), 5);
        let (s, epoch, hist) = opened.last().unwrap();
        assert_eq!((*s, *epoch, hist.len()), (ShardId(7), 3, 2), "{hist:?}");
        assert_eq!(
            (hist[1].log_id.as_str(), hist[1].epoch, hist[1].end.is_some()),
            (b.log_id.as_str(), 2, true),
            "b's span closed and replayed"
        );
    }

    /// No timer lets a joiner in: while a live peer doesn't confirm it
    /// follows the joiner's log, the joiner takes nothing and nobody hands
    /// it anything, however long that takes (a peer following late would
    /// skip whatever it acked meanwhile). A confirmation through the peer's
    /// lease (`follows`) counts like a hello answer.
    #[tokio::test]
    async fn joiner_waits_for_every_peer_to_follow_its_log() {
        let store = Store::memory(None);
        let a = join(cfg("a"), store.clone()).await.unwrap();
        let (ha, ha_dyn) = host();
        a.step(&ha_dyn).await.unwrap();
        assert_eq!(a.owned().len(), 8);
        let b = join(cfg("b"), store.clone()).await.unwrap();
        let (hb, hb_dyn) = host();
        hb.unheard.store(true, Ordering::SeqCst);
        for _ in 0..5 {
            b.step(&hb_dyn).await.unwrap();
            a.step(&ha_dyn).await.unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(!b.joined());
        assert!(b.owned().is_empty() && ha.closed.lock().is_empty(), "no handback to a node that hasn't joined");
        // a's lease names b's log among those it follows: that's a's confirmation
        ha.follows.lock().insert(b.log_id.clone(), 42);
        a.renew(&ha_dyn).await;
        b.step(&hb_dyn).await.unwrap();
        assert!(b.joined(), "confirmed through a's lease");
        a.step(&ha_dyn).await.unwrap();
        assert_eq!(ha.closed.lock().len(), 1, "a hands b its share at once");
    }

    /// A host that holds its join (`may_join`) stays out while it has peers.
    #[tokio::test]
    async fn joiner_waits_while_its_host_holds_the_join() {
        let store = Store::memory(None);
        let a = join(cfg("a"), store.clone()).await.unwrap();
        let (_ha, ha_dyn) = host();
        a.step(&ha_dyn).await.unwrap();
        let b = join(cfg("b"), store.clone()).await.unwrap();
        let (hb, hb_dyn) = host();
        hb.hold_join.store(true, Ordering::SeqCst);
        for _ in 0..3 {
            b.step(&hb_dyn).await.unwrap();
            a.step(&ha_dyn).await.unwrap();
        }
        assert!(!b.joined() && b.owned().is_empty());
        hb.hold_join.store(false, Ordering::SeqCst);
        b.step(&hb_dyn).await.unwrap();
        assert!(b.joined());
    }

    /// A joiner's seqs must pass every floor before it joins: here its
    /// previous incarnation's published watermark cap, as a clock behind it.
    #[tokio::test]
    async fn joiner_waits_until_its_seqs_pass_the_floors() {
        let store = Store::memory(None);
        let id = format!("floors-{}", vlsync_atproto::tid::now_micros());
        let a = join(cfg(&id), store.clone()).await.unwrap();
        // a's previous incarnation's merger may have settled up to 300 ms
        // ahead of our clock
        let cap = vlsync_firehose::log::seq_floor(vlsync_atproto::tid::now_micros() + 300_000);
        let mut lease = a.lease.read().clone();
        lease.wm_cap = cap;
        a.put_json(&a.path(&format!("nodes/{id}")), &lease, PutMode::Overwrite).await.unwrap();
        let b = join(cfg(&id), store.clone()).await.unwrap();
        let (_hb, hb_dyn) = host();
        b.step(&hb_dyn).await.unwrap();
        assert!(!b.joined() && b.owned().is_empty(), "our clock is behind the floor: not joined");
        tokio::time::sleep(Duration::from_millis(300)).await;
        b.step(&hb_dyn).await.unwrap();
        assert!(b.joined() && b.owned().len() == 8);
        assert!(vlsync_firehose::log::seq_floor(vlsync_atproto::tid::now_micros()) > cap);
    }

    /// A shard whose close failed (its barrier never became durable) is
    /// never released: entries of it may still be in flight past the span
    /// end we'd publish. The node fail-stops; a successor fences and replays.
    #[tokio::test]
    async fn failed_close_is_not_released() {
        let store = Store::memory(None);
        let a = join(cfg("a"), store.clone()).await.unwrap();
        let (ha, ha_dyn) = host();
        a.step(&ha_dyn).await.unwrap();
        let b = join(cfg("b"), store.clone()).await.unwrap();
        let (_hb, hb_dyn) = host();
        b.step(&hb_dyn).await.unwrap(); // b joins
        ha.fail_close.lock().insert(ShardId(7)); // a releases 7..4 (highest first)
        a.step(&ha_dyn).await.unwrap();
        assert_eq!(ha.lost.load(Ordering::SeqCst), 1, "fail-stop on a failed close");
        assert_eq!(a.owned(), [0, 1, 2, 3, 7].map(ShardId).to_vec());
        let get = |s: ShardId| {
            let store = store.clone();
            async move {
                let r = store.raw.get(&Path::from(format!("{}/assign/{}", store.prefix, s.key()))).await.unwrap();
                serde_json::from_slice::<Assignment>(&r.bytes().await.unwrap()).unwrap()
            }
        };
        let s7 = get(ShardId(7)).await;
        assert_eq!(s7.owner.as_deref(), Some("a"), "not released");
        assert_eq!(s7.history.last().unwrap().end, None, "span left open: a successor ends it at the fence");
        assert_eq!(get(ShardId(6)).await.owner.as_deref(), Some("b"), "the closed ones are handed to b");
    }

    async fn read_assign(store: &Store, s: ShardId) -> Assignment {
        let r = store.raw.get(&Path::from(format!("{}/assign/{}", store.prefix, s.key()))).await.unwrap();
        serde_json::from_slice::<Assignment>(&r.bytes().await.unwrap()).unwrap()
    }

    async fn all_assigns(store: &Store) -> BTreeMap<ShardId, Assignment> {
        let mut out = BTreeMap::new();
        for i in 0..8 {
            out.insert(ShardId(i), read_assign(store, ShardId(i)).await);
        }
        out
    }

    /// A node that took every shard, wrote `segs` segments, then died.
    async fn dead_owner(store: &Store, segs: u64) -> Arc<Cluster> {
        let d = join(cfg("d"), store.clone()).await.unwrap();
        let (_hd, hd) = host();
        d.step(&hd).await.unwrap();
        assert_eq!(d.owned().len(), 8);
        for ord in 0..segs {
            store
                .raw
                .put(
                    &vlsync_firehose::log::segment_path(store, &d.log_id, ord),
                    segment(&d.log_id, ord, 100 + ord as i64),
                )
                .await
                .unwrap();
        }
        d.halt();
        d
    }

    /// Opens that keep failing (a replay error, say) must never push a dead
    /// owner's span out of a shard's history: its acked tail would be
    /// neither replayed nor protected from retention (`needed_by`).
    #[tokio::test]
    async fn failing_opens_never_drop_a_dead_span() {
        let store = Store::memory(None);
        let d = dead_owner(&store, 3).await;
        let a = join(cfg("a"), store.clone()).await.unwrap();
        let (ha, ha_dyn) = host();
        ha.fail_open.lock().insert(ShardId(0));
        let t = Instant::now();
        while a.owned().len() < 7 {
            a.step(&ha_dyn).await.unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
            assert!(t.elapsed() < Duration::from_secs(3), "never took over");
        }
        for _ in 0..24 {
            a.step(&ha_dyn).await.unwrap();
        }
        assert!(!a.owned().contains(&ShardId(0)));
        let s0 = read_assign(&store, ShardId(0)).await;
        assert!(s0.epoch > 20, "24 failed open cycles: {}", s0.epoch);
        assert!(s0.history.iter().any(|sp| sp.log_id == d.log_id && sp.end == Some(3)), "{:?}", s0.history);
        assert!(s0.history.len() <= 2, "a failed open leaves no span behind: {:?}", s0.history);
        let assigns = all_assigns(&store).await;
        assert_eq!(
            crate::retention::needed_by(&d.log_id, &assigns, &HashMap::new()),
            Some(ShardId(0)),
            "retention keeps the dead log"
        );
        // the open finally succeeds: it replays the dead span
        ha.fail_open.lock().clear();
        a.step(&ha_dyn).await.unwrap();
        assert!(a.owned().contains(&ShardId(0)));
        let (_, _, hist) = ha.opened.lock().iter().rev().find(|o| o.0 == ShardId(0)).cloned().unwrap();
        assert!(hist.iter().any(|sp| sp.log_id == d.log_id && sp.end == Some(3)), "{hist:?}");
        assert_eq!(ha.lost.load(Ordering::SeqCst), 0);
    }

    /// A crash loop of same-id restarts (each incarnation reclaims every
    /// shard and dies before closing any cleanly) keeps every span: the
    /// first dead owner's included, however many incarnations pile up.
    #[tokio::test]
    async fn crash_looping_restarts_keep_every_span() {
        let store = Store::memory(None);
        let d = dead_owner(&store, 3).await;
        for i in 0..20 {
            let b = join(cfg("b"), store.clone()).await.unwrap();
            let (hb, hb_dyn) = host();
            // (each waits out its predecessor's published wm_cap to join)
            let t = Instant::now();
            while b.owned().len() < 8 {
                b.step(&hb_dyn).await.unwrap();
                if b.owned().len() < 8 {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                assert!(t.elapsed() < Duration::from_secs(3), "incarnation {i} never took over");
            }
            let (_, _, hist) = hb.opened.lock().iter().find(|o| o.0 == ShardId(0)).cloned().unwrap();
            assert!(hist.iter().any(|sp| sp.log_id == d.log_id && sp.end == Some(3)), "incarnation {i}: {hist:?}");
            b.halt();
        }
        let s0 = read_assign(&store, ShardId(0)).await;
        assert_eq!(s0.history.len(), 21, "{:?}", s0.history);
        let assigns = all_assigns(&store).await;
        assert!(crate::retention::needed_by(&d.log_id, &assigns, &HashMap::new()).is_some());
        // an incarnation that serves and checkpoints inside its own span
        // trims the history down to that span
        let b = join(cfg("b"), store.clone()).await.unwrap();
        let (hb, hb_dyn) = host();
        let t = Instant::now();
        while b.owned().len() < 8 {
            b.step(&hb_dyn).await.unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
            assert!(t.elapsed() < Duration::from_secs(3), "never took over");
        }
        b.step(&hb_dyn).await.unwrap();
        assert_eq!(read_assign(&store, ShardId(0)).await.history.len(), 22, "not checkpointed yet: nothing dropped");
        hb.checkpointed.store(true, Ordering::SeqCst);
        b.step(&hb_dyn).await.unwrap();
        let s0 = read_assign(&store, ShardId(0)).await;
        assert_eq!((s0.history.len(), s0.applied_epoch), (1, s0.epoch), "{s0:?}");
        assert_eq!(s0.history[0].log_id, b.log_id);
        assert_eq!(
            crate::retention::needed_by(&d.log_id, &all_assigns(&store).await, &HashMap::new()),
            None,
            "the dead log is no longer needed"
        );
    }

    /// A pause that lapsed our lease (as `set_revalidate` hosts see it):
    /// unfenced, the next renewal takes the lease back; fenced, it
    /// fail-stops; without the opt-in it fail-stops as before.
    #[tokio::test]
    async fn lapsed_lease_is_revalidated_only_while_unfenced() {
        let store = Store::memory(None);
        let a = join(cfg("a"), store.clone()).await.unwrap();
        let (ha, ha_dyn) = host();
        a.step(&ha_dyn).await.unwrap();
        a.set_revalidate(true);
        let lapse = |c: &Cluster| *c.valid_until.write() = Instant::now() - c.cfg.skew;
        lapse(&a);
        assert!(!a.lease_valid());
        let renewals = a.own_lease().renewals;
        a.renew(&ha_dyn).await;
        assert!(a.lease_valid(), "revalidated");
        assert!(a.own_lease().renewals > renewals);
        assert_eq!(ha.lost.load(Ordering::SeqCst), 0);

        // a peer presumed us dead and fenced our log
        lapse(&a);
        let b = join(cfg("b"), store.clone()).await.unwrap();
        b.fence(&a.log_id).await.unwrap();
        a.renew(&ha_dyn).await;
        assert_eq!(ha.lost.load(Ordering::SeqCst), 1, "fenced: fail-stop");

        // past the window, or without the opt-in: fail-stop as before
        let c = join(cfg("c"), store.clone()).await.unwrap();
        let (hc, hc_dyn) = host();
        c.set_revalidate(true);
        *c.valid_until.write() = Instant::now() - c.revalidate_window() - Duration::from_millis(10);
        c.renew(&hc_dyn).await;
        assert_eq!(hc.lost.load(Ordering::SeqCst), 1, "past the window");
        let d = join(cfg("d"), store.clone()).await.unwrap();
        let (hd, hd_dyn) = host();
        lapse(&d);
        d.renew(&hd_dyn).await;
        assert_eq!(hd.lost.load(Ordering::SeqCst), 1, "no opt-in");
    }

    /// A revalidation's CAS grants no validity before the fence check, and
    /// one that landed with its answer lost is adopted on the next try
    /// instead of read as our lease rewritten under us.
    #[tokio::test]
    async fn revalidation_grants_nothing_early_and_survives_a_lost_answer() {
        let store = Store::memory(None);
        let a = join(cfg("a"), store.clone()).await.unwrap();
        let (ha, ha_dyn) = host();
        a.step(&ha_dyn).await.unwrap();
        a.set_revalidate(true);
        let lapse = |c: &Cluster| *c.valid_until.write() = Instant::now() - c.cfg.skew;
        lapse(&a);
        let etag = a.lease_etag.read().clone();
        a.write_lease_ungranted(if_match(etag)).await.unwrap();
        assert!(!a.lease_valid(), "the CAS alone grants nothing");

        // our CAS landed, its answer didn't: the bucket is a renewal ahead
        let mut landed = a.own_lease();
        landed.renewals += 1;
        let path = a.path("nodes/a");
        Cluster::put_json_on(&store, &path, &landed, PutMode::Overwrite).await.unwrap();
        a.renew(&ha_dyn).await;
        assert_eq!(ha.lost.load(Ordering::SeqCst), 0, "a lost answer is no rewrite");
        assert!(!a.lease_valid(), "still lapsed until a revalidation passes");
        a.renew(&ha_dyn).await;
        assert!(a.lease_valid(), "revalidated");
        assert_eq!(ha.lost.load(Ordering::SeqCst), 0);
    }

    /// With `set_trim_spans(1)` one checkpointed takeover is enough: the
    /// dead owner's span leaves the history as soon as ours is checkpointed.
    #[tokio::test]
    async fn trim_spans_one_trims_after_a_single_takeover() {
        let store = Store::memory(None);
        let d = dead_owner(&store, 3).await;
        let b = join(cfg("b"), store.clone()).await.unwrap();
        b.set_trim_spans(1);
        let (hb, hb_dyn) = host();
        let t = Instant::now();
        while b.owned().len() < 8 {
            b.step(&hb_dyn).await.unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
            assert!(t.elapsed() < Duration::from_secs(3), "never took over");
        }
        b.step(&hb_dyn).await.unwrap();
        assert_eq!(read_assign(&store, ShardId(0)).await.history.len(), 2, "not checkpointed yet: nothing dropped");
        hb.checkpointed.store(true, Ordering::SeqCst);
        b.step(&hb_dyn).await.unwrap();
        let s0 = read_assign(&store, ShardId(0)).await;
        assert_eq!((s0.history.len(), s0.applied_epoch), (1, s0.epoch), "{s0:?}");
        assert_eq!(s0.history[0].log_id, b.log_id);
        assert!(s0.history.iter().all(|sp| sp.log_id != d.log_id));
    }

    /// A same-id restart before peers presumed the old incarnation dead: b1
    /// held all 8, a joined (fair share 4), b1 died before handing any back,
    /// b2 came up. b2 reclaims its share of b1's shards; the rest name owner
    /// "b" (live) with b1's log, and a must take them (fencing b1's log)
    /// instead of skipping them as healthy: nobody served them.
    #[tokio::test]
    async fn fast_same_id_restart_strands_no_shard() {
        let store = Store::memory(None);
        let b1 = join(cfg("b"), store.clone()).await.unwrap();
        let (_hb1, hb1) = host();
        b1.step(&hb1).await.unwrap();
        assert_eq!(b1.owned().len(), 8);
        let a = join(cfg("a"), store.clone()).await.unwrap();
        let (ha, ha_dyn) = host();
        a.step(&ha_dyn).await.unwrap();
        assert!(a.joined() && a.owned().is_empty());
        b1.halt();
        let b2 = join(cfg("b"), store.clone()).await.unwrap();
        let (hb2, hb2_dyn) = host();
        let t = Instant::now();
        loop {
            b2.step(&hb2_dyn).await.unwrap();
            a.step(&ha_dyn).await.unwrap();
            let assigns = all_assigns(&store).await;
            let served = assigns
                .values()
                .filter(|x| {
                    x.log_id.as_deref() == Some(a.log_id.as_str()) || x.log_id.as_deref() == Some(b2.log_id.as_str())
                })
                .count();
            if served == 8 && a.owned().len() + b2.owned().len() == 8 {
                break;
            }
            assert!(
                t.elapsed() < Duration::from_secs(3),
                "stranded: a {:?}, b2 {:?}, {assigns:?}",
                a.owned(),
                b2.owned()
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(a.fenced_logs().contains_key(&b1.log_id) || b2.fenced_logs().contains_key(&b1.log_id));
        assert_eq!(ha.lost.load(Ordering::SeqCst) + hb2.lost.load(Ordering::SeqCst), 0);
    }

    /// Wall clocks minutes apart: liveness doesn't care (O3). With the old
    /// rule (peer live while its expires_ms > my now - skew) `slow` looked
    /// dead to `fast` immediately and was fenced over and over.
    #[tokio::test]
    async fn skewed_clocks_stay_live() {
        let store = Store::memory(None);
        let slow = join(skewed("slow", -120_000), store.clone()).await.unwrap();
        let fast = join(skewed("fast", 120_000), store.clone()).await.unwrap();
        let (hs, hs_dyn) = host();
        let (hf, hf_dyn) = host();
        for _ in 0..25 {
            slow.step(&hs_dyn).await.unwrap();
            fast.step(&hf_dyn).await.unwrap();
            tokio::time::sleep(Duration::from_millis(80)).await;
        }
        assert_eq!((slow.owned().len(), fast.owned().len()), (4, 4));
        assert!(slow.fenced_logs().is_empty() && fast.fenced_logs().is_empty(), "nobody was fenced");
        assert_eq!((slow.peers().len(), fast.peers().len()), (1, 1));
        assert_eq!(hs.lost.load(Ordering::SeqCst) + hf.lost.load(Ordering::SeqCst), 0);
    }

    /// A dead node whose clock ran an hour ahead (its expires_ms is far in
    /// the future) is still taken over after ttl + skew of the observer's
    /// time, and a lease first seen gets a full ttl from first sight.
    #[tokio::test]
    async fn dead_peer_with_future_clock_is_taken_over() {
        let store = Store::memory(None);
        let a = join(skewed("a", 3_600_000), store.clone()).await.unwrap();
        let (_ha, ha_dyn) = host();
        a.step(&ha_dyn).await.unwrap();
        assert_eq!(a.owned().len(), 8);
        // a dies now; c joins later and has never seen a's lease change
        tokio::time::sleep(Duration::from_millis(500)).await;
        let c = join(cfg("c"), store.clone()).await.unwrap();
        let (hc, hc_dyn) = host();
        let first_seen = Instant::now();
        while c.owned().len() < 8 {
            c.step(&hc_dyn).await.unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
            assert!(first_seen.elapsed() < Duration::from_secs(3), "never took over");
        }
        assert!(
            first_seen.elapsed() >= Duration::from_millis(700),
            "full ttl + skew from first sight: {:?}",
            first_seen.elapsed()
        );
        assert!(c.fenced_logs().contains_key(&a.log_id));
        assert_eq!(hc.lost.load(Ordering::SeqCst), 0);
    }

    /// An in-memory store that stalls chosen calls (as MinIO did in bench/ha
    /// ret3): the next call of `op` ("get", "put", "list") on a path
    /// containing a substring waits 30 s first. "vanish": the next GET is
    /// answered, then the object deleted. "conflict": the next PUT fails
    /// its precondition. "fail": the next PUT fails (a store error),
    /// "getfail" the next GET. "slowfail": the next PUT fails after
    /// SLOW_FAIL (a write the store throttled until object_store gave up).
    /// "slowland": the next PUT lands after SLOW_LAND (throttled, then let
    /// through).
    /// `puts` logs every PUT: (key, sent, answered).
    #[derive(Debug, Default)]
    struct Stalls {
        inner: object_store::memory::InMemory,
        armed: Mutex<Vec<(&'static str, String)>>,
        stalled: AtomicU64,
        puts: Mutex<Vec<(String, Instant, Instant)>>,
    }

    const SLOW_FAIL: Duration = Duration::from_millis(1500);
    const SLOW_LAND: Duration = Duration::from_millis(3300);

    struct PutLog<'a>(&'a Stalls, String, Instant);

    impl Drop for PutLog<'_> {
        fn drop(&mut self) {
            self.0.puts.lock().push((std::mem::take(&mut self.1), self.2, Instant::now()));
        }
    }

    impl std::fmt::Display for Stalls {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "Stalls")
        }
    }

    impl Stalls {
        fn arm(&self, op: &'static str, path: &str) {
            self.armed.lock().push((op, path.to_string()));
        }
        fn take(&self, op: &str, path: &str) -> bool {
            let mut a = self.armed.lock();
            let Some(i) = a.iter().position(|(o, p)| *o == op && path.contains(p.as_str())) else { return false };
            a.remove(i);
            self.stalled.fetch_add(1, Ordering::SeqCst);
            true
        }
    }

    const STALL: Duration = Duration::from_secs(30);

    #[async_trait::async_trait]
    impl object_store::ObjectStore for Stalls {
        async fn put_opts(
            &self,
            location: &Path,
            payload: PutPayload,
            opts: PutOptions,
        ) -> object_store::Result<object_store::PutResult> {
            let _log = PutLog(self, location.to_string(), Instant::now());
            if self.take("slowfail", location.as_ref()) {
                tokio::time::sleep(SLOW_FAIL).await;
                return Err(object_store::Error::Generic { store: "Stalls", source: "429 Too Many Requests".into() });
            }
            if self.take("slowland", location.as_ref()) {
                tokio::time::sleep(SLOW_LAND).await;
            }
            if self.take("put", location.as_ref()) {
                tokio::time::sleep(STALL).await;
            }
            if self.take("conflict", location.as_ref()) {
                return Err(object_store::Error::Precondition {
                    path: location.to_string(),
                    source: "armed conflict".into(),
                });
            }
            if self.take("fail", location.as_ref()) {
                return Err(object_store::Error::Generic { store: "Stalls", source: "armed failure".into() });
            }
            if self.take("landed", location.as_ref()) {
                // applied, answer lost, and the client's retry of the same
                // conditional request refused
                self.inner.put_opts(location, payload, opts).await?;
                return Err(object_store::Error::Precondition {
                    path: location.to_string(),
                    source: "armed: landed, retry refused".into(),
                });
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
            if self.take("get", location.as_ref()) {
                tokio::time::sleep(STALL).await;
            }
            if self.take("getfail", location.as_ref()) {
                return Err(object_store::Error::Generic { store: "Stalls", source: "armed failure".into() });
            }
            if self.take("vanish", location.as_ref()) {
                // answered, then deleted (a peer's delete right after our read)
                let r = self.inner.get_opts(location, options).await;
                self.inner.delete(location).await?;
                return r;
            }
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
            use futures::StreamExt;
            let inner = self.inner.list(prefix);
            if self.take("list", prefix.map_or("", |p| p.as_ref())) {
                return futures::stream::once(async move {
                    tokio::time::sleep(STALL).await;
                    inner
                })
                .flatten()
                .boxed();
            }
            inner
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

    /// A takeover isn't held up by object-store calls that stall (bench/ha
    /// ret3: 36 s instead of ~4): each step call has a deadline of
    /// min(TTL, 5 s), the step fails and the next one retries.
    #[tokio::test]
    async fn stalled_store_calls_do_not_stall_takeover() {
        let stalls = Arc::new(Stalls::default());
        let store = Store { raw: stalls.clone(), ..Store::memory(None) };
        let a = join(cfg("a"), store.clone()).await.unwrap();
        let (_ha, ha_dyn) = host();
        a.step(&ha_dyn).await.unwrap();
        assert_eq!(a.owned().len(), 8);
        // a dies now (no more renewals); b's takeover path stalls: a LIST
        // of the assignments, the GET of a's lease, the LIST and a header
        // read of a's log (fencing it), and an assignment CAS
        let died = Instant::now();
        let b = join(cfg("b"), store.clone()).await.unwrap();
        stalls.arm("list", "assign");
        stalls.arm("get", "nodes/a");
        stalls.arm("list", &format!("log/{}", a.log_id));
        stalls.arm("put", "assign/0000000003");
        let (hb, hb_dyn) = host();
        while b.owned().len() < 8 {
            let _ = b.step(&hb_dyn).await; // a stalled call fails the step
            assert!(
                died.elapsed() < Duration::from_secs(10),
                "takeover stalled: {:?} owned after {:?}",
                b.owned(),
                died.elapsed()
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        // ttl + skew (700 ms) + at most a step, plus one deadline (600 ms)
        // per stalled call on the way
        let took = died.elapsed();
        assert!(took < Duration::from_millis(700 + 4 * 600 + 800), "takeover took {took:?}");
        assert!(stalls.stalled.load(Ordering::SeqCst) >= 3, "the stalls were hit");
        assert!(b.fenced_logs().contains_key(&a.log_id));
        assert_eq!(hb.lost.load(Ordering::SeqCst), 0);
    }

    /// A renewal that lands but whose answer is lost (a reset after the
    /// store applied it; seen under the vlrelay chaos harness's bucket
    /// resets, where every core fail-stopped within a second) comes back as
    /// a conflict on the client's retry. The lease is still ours: adopt it.
    #[tokio::test]
    async fn a_renewal_whose_answer_was_lost_is_adopted() {
        let stalls = Arc::new(Stalls::default());
        let store = Store { raw: stalls.clone(), ..Store::memory(None) };
        let a = join(cfg("a"), store.clone()).await.unwrap();
        let (ha, ha_dyn) = host();
        a.step(&ha_dyn).await.unwrap();
        stalls.arm("landed", "nodes/a");
        tokio::time::sleep(a.cfg.renew_every).await; // past the lease-write gap
        a.renew(&ha_dyn).await;
        assert_eq!(stalls.stalled.load(Ordering::SeqCst), 1, "the armed renewal ran");
        assert_eq!(ha.lost.load(Ordering::SeqCst), 0, "a landed renewal is no lost lease");
        tokio::time::sleep(a.cfg.renew_every).await; // past the lease-write gap
        a.renew(&ha_dyn).await;
        assert_eq!(ha.lost.load(Ordering::SeqCst), 0, "the next renewal CASes on the adopted ETag");
        assert!(a.lease_valid());

        // a lease someone else rewrote is still a conflict
        let mut l = a.lease.read().clone();
        l.log_id = "someone-else".into();
        a.put_json_unbounded(&a.path("nodes/a"), &l, PutMode::Overwrite).await.unwrap();
        tokio::time::sleep(a.cfg.renew_every).await; // past the lease-write gap
        a.renew(&ha_dyn).await;
        assert_eq!(ha.lost.load(Ordering::SeqCst), 1);
    }

    /// A same-id restart whose previous incarnation's lease vanishes between
    /// the join's read and its CAS (a peer that presumed the old process
    /// dead fenced its log and deleted the lease): the join creates the
    /// lease fresh instead of failing with "precondition failure: not found".
    #[tokio::test]
    async fn restart_survives_its_old_lease_vanishing_mid_join() {
        let stalls = Arc::new(Stalls::default());
        let store = Store { raw: stalls.clone(), ..Store::memory(None) };
        let old = join(cfg("r"), store.clone()).await.unwrap();
        let (_ho, ho) = host();
        old.step(&ho).await.unwrap();
        assert_eq!(old.owned().len(), 8);
        let moved0 = crate::metrics::LEASE_EVENTS.with_label_values(&["join_lease_moved"]).get();
        // the old process is gone; the restart's read of its lease is the
        // last anyone sees of it
        stalls.arm("vanish", "nodes/r");
        let new = join(cfg("r"), store.clone()).await.expect("join creates the vanished lease");
        assert_eq!(stalls.stalled.load(Ordering::SeqCst), 1, "the lease vanished after the join read it");
        assert!(crate::metrics::LEASE_EVENTS.with_label_values(&["join_lease_moved"]).get() > moved0);
        // same safety as a plain restart: the old log is fenced first
        assert!(new.fenced_logs().contains_key(&old.log_id));
        let (lease, _) = new.get_json::<NodeLease>(&new.path("nodes/r")).await.unwrap().expect("our lease");
        assert_eq!((lease.log_id.as_str(), lease.writer), (new.log_id.as_str(), new.writer));
        let (claim, _) =
            new.get_json::<serde_json::Value>(&new.path(&format!("writers/{:03}", new.writer))).await.unwrap().unwrap();
        assert_eq!((claim["log_id"].as_str(), claim["confirmed"].as_bool()), (Some(new.log_id.as_str()), Some(true)));
        // it renews, and takes its previous incarnation's shards back (once
        // its seqs pass the old one's published watermark cap)
        let (hn, hn_dyn) = host();
        let t = Instant::now();
        while new.owned().len() < 8 {
            assert!(t.elapsed() < Duration::from_secs(3), "never took its shards back");
            new.step(&hn_dyn).await.unwrap();
        }
        assert_eq!(hn.lost.load(Ordering::SeqCst), 0);
        // a lease that keeps changing under the join: bounded retries
        for _ in 0..=JOIN_LEASE_RETRIES {
            stalls.arm("conflict", "nodes/r");
        }
        let err = join(cfg("r"), store.clone()).await.err().expect("bounded retries");
        assert!(format!("{err:#}").contains("precondition"), "{err:#}");
        assert_eq!(stalls.armed.lock().len(), 0, "every retry re-read and CASed again");
    }

    /// The lease deleted *after* the restart's CAS over the old one landed
    /// (the peer's delete was in flight): the next renewal finds it gone
    /// over an unfenced log and recreates it. Gone over a fenced log (we
    /// were presumed dead), or rewritten by someone else, it is lost.
    #[tokio::test]
    async fn renewal_recreates_a_lease_deleted_over_an_unfenced_log() {
        let store = Store::memory(None);
        let (h, hd) = host();
        let a = join(cfg("rv"), store.clone()).await.unwrap();
        let path = a.path("nodes/rv");
        store.raw.delete(&path).await.unwrap();
        tokio::time::sleep(a.cfg.renew_every).await; // past the lease-write gap
        a.renew(&hd).await;
        assert_eq!(h.lost.load(Ordering::SeqCst), 0);
        let (l, _) = a.get_json::<NodeLease>(&path).await.unwrap().expect("recreated");
        assert_eq!(l.log_id, a.log_id);
        tokio::time::sleep(a.cfg.renew_every).await; // past the lease-write gap
        a.renew(&hd).await; // and renews from there
        assert_eq!(h.lost.load(Ordering::SeqCst), 0);
        // presumed dead: a peer fenced our log, then deleted the lease
        let p = join(cfg("rv-peer"), store.clone()).await.unwrap();
        p.fence(&a.log_id).await.unwrap();
        store.raw.delete(&path).await.unwrap();
        tokio::time::sleep(a.cfg.renew_every).await; // past the lease-write gap
        a.renew(&hd).await;
        assert_eq!(h.lost.load(Ordering::SeqCst), 1);
        assert!(a.get_json::<NodeLease>(&path).await.unwrap().is_none(), "not resurrected");
    }

    /// A peer forgets a dead incarnation's lease only if it is still that
    /// incarnation's: the node may have restarted under the same id since
    /// the peer judged it dead.
    #[tokio::test]
    async fn dead_lease_is_not_deleted_once_its_node_restarted() {
        let store = Store::memory(None);
        let old = join(cfg("fd"), store.clone()).await.unwrap();
        let dead = old.own_lease();
        let new = join(cfg("fd"), store.clone()).await.unwrap();
        let p = join(cfg("fd-peer"), store.clone()).await.unwrap();
        p.forget_dead(&dead).await.unwrap();
        let (l, _) =
            p.get_json::<NodeLease>(&p.path("nodes/fd")).await.unwrap().expect("the restarted node's lease stays");
        assert_eq!(l.log_id, new.log_id);
        p.forget_dead(&new.own_lease()).await.unwrap();
        assert!(p.get_json::<NodeLease>(&p.path("nodes/fd")).await.unwrap().is_none());
    }

    /// Steady state reads only what changed: one LIST of leases, one of
    /// assignments, and a GET per peer renewal (O5).
    #[tokio::test]
    async fn steady_state_reads_are_cheap() {
        let store = Store::memory(None);
        let mut c = cfg("a");
        c.shards = 256;
        let a = join(c.clone(), store.clone()).await.unwrap();
        let b = join(ClusterConfig { node_id: "b".into(), ..c }, store.clone()).await.unwrap();
        let ((_, ha), (_, hb)) = (host(), host());
        for _ in 0..10 {
            a.step(&ha).await.unwrap();
            b.step(&hb).await.unwrap();
            tokio::time::sleep(Duration::from_millis(60)).await;
        }
        assert_eq!((a.owned().len(), b.owned().len()), (128, 128));
        // 10 more rounds (none a full resync), each node renewing in its step
        let before = a.store_requests();
        for _ in 0..10 {
            a.step(&ha).await.unwrap();
            b.step(&hb).await.unwrap();
        }
        let per_step = (a.store_requests() - before) as f64 / 10.0;
        // renew PUT + 2 LISTs + 1 GET (b's renewed lease), plus one GET of
        // cluster/version per TTL
        assert!(per_step <= 4.1, "{per_step} requests per step at 256 shards");
    }

    // ---- lone-node control plane (DESIGN.md "Lone-node control plane") ----

    /// Whether every shard has exactly one owner among `nodes`, and its
    /// stored assignment names that node's current incarnation.
    async fn one_owner_each(store: &Store, nodes: &[&Arc<Cluster>]) {
        let layout = nodes[0].layout();
        for s in layout.ids() {
            let holders: Vec<&str> = nodes.iter().filter(|n| n.is_owner(s)).map(|n| n.cfg.node_id.as_str()).collect();
            assert!(holders.len() <= 1, "shard {} held by {holders:?}", s.0);
            if let [h] = holders.as_slice() {
                let r = store.raw.get(&Path::from(format!("{}/assign/{}", store.prefix, s.key()))).await.unwrap();
                let a: Assignment = serde_json::from_slice(&r.bytes().await.unwrap()).unwrap();
                let n = nodes.iter().find(|n| n.cfg.node_id == *h).unwrap();
                assert_eq!(
                    (a.owner.as_deref(), a.log_id.as_deref()),
                    (Some(*h), Some(n.log_id.as_str())),
                    "shard {}",
                    s.0
                );
            }
        }
    }

    /// A lone, settled node lists `nodes/` once per TTL (every TTL/renew
    /// steps) and `assign/` every LONE_ASSIGN_EVERY steps, instead of both
    /// every step.
    #[tokio::test]
    async fn lone_node_lists_less() {
        let store = Store::memory(None);
        let a = lone_join(cfg("a"), store.clone()).await.unwrap();
        let (ha, ha_dyn) = host();
        a.step(&ha_dyn).await.unwrap();
        assert_eq!(a.owned().len(), 8);
        let before = a.store_lists();
        for _ in 0..50 {
            a.step(&ha_dyn).await.unwrap();
        }
        let lists = a.store_lists() - before;
        // nodes/: every 6th step (TTL 600 ms / renew 100 ms) = 8-9; assign/:
        // the 25th and 50th step = 2
        assert!((9..=12).contains(&lists), "{lists} LISTs in 50 lone steps");
        assert_eq!(a.owned().len(), 8);
        assert_eq!(ha.lost.load(Ordering::SeqCst), 0);
        // listing everything every step costs 2 per step
        a.list_every_step.store(true, Ordering::Release);
        let before = a.store_lists();
        for _ in 0..10 {
            a.step(&ha_dyn).await.unwrap();
        }
        assert_eq!(a.store_lists() - before, 20);
    }

    /// Time, not just steps, bounds the gap between `LIST nodes/`: steps
    /// further apart than TTL/renew intervals list every time.
    #[tokio::test]
    async fn lone_node_lists_nodes_at_least_once_per_ttl() {
        let store = Store::memory(None);
        let a = lone_join(cfg("a"), store.clone()).await.unwrap();
        let (_ha, ha_dyn) = host();
        a.step(&ha_dyn).await.unwrap();
        a.step(&ha_dyn).await.unwrap(); // reuses the lone view
        let before = a.store_lists();
        tokio::time::sleep(Duration::from_millis(560)).await; // > TTL - renew/2 since the listing
        a.step(&ha_dyn).await.unwrap();
        assert_eq!(a.store_lists() - before, 1, "nodes/ listed (assign/ skipped)");
    }

    /// A hello (`learn_peer`) or a nudge ends the reduced listing at once:
    /// the next step lists both, the joiner joins, and the lone node hands
    /// it its share.
    #[tokio::test]
    async fn lone_node_resumes_listing_on_contact() {
        let store = Store::memory(None);
        let a = lone_join(cfg("a"), store.clone()).await.unwrap();
        let (ha, ha_dyn) = host();
        a.step(&ha_dyn).await.unwrap();
        a.step(&ha_dyn).await.unwrap();
        let b = lone_join(cfg("b"), store.clone()).await.unwrap();
        let (hb, hb_dyn) = host();
        // b greets a (its hello reaches a's learn_peer)
        a.learn_peer(&ha_dyn, "b").await.unwrap();
        let before = a.store_lists();
        a.step(&ha_dyn).await.unwrap();
        assert_eq!(a.store_lists() - before, 2, "nodes/ and assign/ listed right after the hello");
        assert_eq!(a.peers().len(), 1);
        b.step(&hb_dyn).await.unwrap(); // b joins (the mock peers confirm)
        assert!(b.joined());
        a.step(&ha_dyn).await.unwrap(); // a hands b its share
        b.step(&hb_dyn).await.unwrap(); // b adopts what a handed it
        assert_eq!((a.owned().len(), b.owned().len()), (4, 4));
        one_owner_each(&store, &[&a, &b]).await;
        assert_eq!(ha.lost.load(Ordering::SeqCst) + hb.lost.load(Ordering::SeqCst), 0);
        // a nudge (a peer released shards, or a split was planned) also
        // counts as contact
        let store = Store::memory(None);
        let c = lone_join(cfg("c"), store.clone()).await.unwrap();
        let (_hc, hc_dyn) = host();
        c.step(&hc_dyn).await.unwrap();
        c.step(&hc_dyn).await.unwrap();
        let before = c.store_lists();
        c.step(&hc_dyn).await.unwrap();
        assert_eq!(c.store_lists() - before, 0, "lone and settled: nothing listed");
        c.nudge(Vec::new());
        c.step(&hc_dyn).await.unwrap();
        assert_eq!(c.store_lists() - before, 2, "nudged: both listed");
    }

    /// A joiner whose greeting never reaches the lone node (lost hello) is
    /// still seen within the listing bound, followed, and handed its share;
    /// meanwhile no shard ever has two holders and the joiner takes nothing
    /// before it is followed (HA invariants).
    #[tokio::test]
    async fn joiner_with_a_lost_hello_is_adopted_within_a_ttl() {
        let store = Store::memory(None);
        let a = lone_join(cfg("a"), store.clone()).await.unwrap();
        let (ha, ha_dyn) = host();
        a.test_ignore_hellos(true);
        a.step(&ha_dyn).await.unwrap();
        a.step(&ha_dyn).await.unwrap(); // settled: reduced listing from here
                                        // b's lease appears right after a's last `LIST nodes/` (the worst
                                        // case); its greeting is lost, and its peers confirm only through
                                        // their leases (`follows`)
        let b = lone_join(cfg("b"), store.clone()).await.unwrap();
        let (hb, hb_dyn) = host();
        hb.unheard.store(true, Ordering::SeqCst);
        let t0 = Instant::now();
        let (mut seen, mut joined) = (None, None);
        while a.owned().len() != 4 || b.owned().len() != 4 {
            assert!(
                t0.elapsed() < Duration::from_secs(3),
                "b never got its share: a {:?} b {:?}",
                a.owned(),
                b.owned()
            );
            a.step(&ha_dyn).await.unwrap();
            if seen.is_none() && !a.peers().is_empty() {
                seen = Some(t0.elapsed());
                // a's merged firehose now follows b's log (as on_membership
                // would): published in a's next renewal
                ha.follows.lock().insert(b.log_id.clone(), 0);
            }
            b.step(&hb_dyn).await.unwrap();
            if joined.is_none() && b.joined() {
                joined = Some(t0.elapsed());
                assert!(seen.is_some(), "b joined before a followed its log");
            }
            if !b.joined() {
                assert!(b.owned().is_empty(), "b took shards before joining");
            }
            one_owner_each(&store, &[&a, &b]).await;
            tokio::time::sleep(a.cfg.renew_every).await;
        }
        let seen = seen.unwrap();
        eprintln!(
            "lost hello: a saw b after {seen:?}, b joined after {joined:?}, shares settled after {:?}",
            t0.elapsed()
        );
        // a step lists nodes/ at most TTL/renew steps apart (+ the steps' own time)
        assert!(seen <= a.cfg.ttl + a.cfg.renew_every * 2, "a saw b after {seen:?}");
        assert!(t0.elapsed() <= a.cfg.ttl + a.cfg.renew_every * 8, "b got its share after {:?}", t0.elapsed());
        assert_eq!(ha.lost.load(Ordering::SeqCst) + hb.lost.load(Ordering::SeqCst), 0);
        assert!(a.fenced_logs().is_empty() && b.fenced_logs().is_empty(), "nobody was presumed dead");
    }

    /// An out-of-band edit of `assign/` (an admin tool writing the bucket)
    /// is seen within LONE_ASSIGN_EVERY steps: here a shard reassigned
    /// under the lone node, which fail-stops.
    #[tokio::test]
    async fn lone_node_sees_out_of_band_assign_edits_within_its_resync() {
        let store = Store::memory(None);
        let a = lone_join(cfg("a"), store.clone()).await.unwrap();
        let (ha, ha_dyn) = host();
        a.step(&ha_dyn).await.unwrap();
        let path = a.path(&format!("assign/{}", ShardId(3).key()));
        let (mut s3, _) = a.get_json::<Assignment>(&path).await.unwrap().unwrap();
        s3.owner = Some("elsewhere".into());
        a.put_json(&path, &s3, PutMode::Overwrite).await.unwrap();
        let mut steps = 0;
        while ha.lost.load(Ordering::SeqCst) == 0 {
            a.step(&ha_dyn).await.unwrap();
            steps += 1;
            assert!(steps <= LONE_ASSIGN_EVERY, "not seen within {LONE_ASSIGN_EVERY} steps");
        }
        assert!(steps > 1, "seen at once: the lone listing savings were off");
    }

    /// Graceful shutdown retries a failing fence of our own log; one that
    /// lands in time completes the shutdown normally.
    #[tokio::test]
    async fn shutdown_retries_the_fence_of_our_log() {
        let stalls = Arc::new(Stalls::default());
        let store = Store { raw: stalls.clone(), ..Store::memory(None) };
        let a = lone_join(cfg("a"), store.clone()).await.unwrap();
        let (_ha, ha_dyn) = host();
        a.step(&ha_dyn).await.unwrap();
        for _ in 0..2 {
            stalls.arm("fail", &format!("log/{}/", a.log_id));
        }
        a.shutdown(&ha_dyn).await.unwrap();
        assert_eq!(stalls.stalled.load(Ordering::SeqCst), 2, "two failed fence PUTs, then one that landed");
        assert!(vlsync_firehose::log::first_free(&store, &a.log_id).await.unwrap().1, "our log is fenced");
        assert!(a.get_json::<NodeLease>(&a.path("nodes/a")).await.unwrap().is_none(), "lease dropped");
    }

    /// Quiesced, shutdown fences our log at its known end without a LIST.
    #[tokio::test]
    async fn shutdown_fences_our_log_at_its_end_without_a_scan() {
        let store = Store::memory(None);
        let a = lone_join(cfg("a"), store.clone()).await.unwrap();
        let (ha, ha_dyn) = host();
        a.step(&ha_dyn).await.unwrap();
        for ord in 0..3 {
            store
                .raw
                .put(
                    &vlsync_firehose::log::segment_path(&store, &a.log_id, ord),
                    segment(&a.log_id, ord, 100 + ord as i64),
                )
                .await
                .unwrap();
        }
        ha.ord.store(3, Ordering::SeqCst);
        let lists = a.store_lists();
        a.shutdown(&ha_dyn).await.unwrap();
        assert_eq!(a.store_lists(), lists, "no fence scan");
        assert_eq!(vlsync_firehose::log::first_free(&store, &a.log_id).await.unwrap(), (3, true));
    }

    /// A fence that keeps failing: shutdown gives up after its budget and
    /// returns Err (the caller exits nonzero), keeping our lease so the log
    /// still gets fenced: by our restart (same node id) or by a peer once
    /// the lease goes quiet.
    #[tokio::test]
    async fn shutdown_that_cannot_fence_keeps_the_lease_and_fails() {
        let stalls = Arc::new(Stalls::default());
        let store = Store { raw: stalls.clone(), ..Store::memory(None) };
        let a = lone_join(cfg("a"), store.clone()).await.unwrap();
        let (ha, ha_dyn) = host();
        a.step(&ha_dyn).await.unwrap();
        for _ in 0..100 {
            stalls.arm("fail", &format!("log/{}/", a.log_id));
        }
        let t0 = Instant::now();
        let e = a.shutdown(&ha_dyn).await.unwrap_err();
        assert!(format!("{e:#}").contains("fencing our log on shutdown"), "{e:#}");
        let took = t0.elapsed();
        assert!(
            took >= a.shutdown_fence_budget() && took < a.shutdown_fence_budget() + Duration::from_secs(2),
            "{took:?}"
        );
        assert!(stalls.stalled.load(Ordering::SeqCst) >= 3, "retried with backoff");
        assert_eq!(ha.lost.load(Ordering::SeqCst), 0, "no fail-stop from the cluster: the caller exits");
        assert!(!vlsync_firehose::log::first_free(&store, &a.log_id).await.unwrap().1, "not fenced");
        let (lease, _) = a.get_json::<NodeLease>(&a.path("nodes/a")).await.unwrap().expect("lease kept");
        assert_eq!(lease.log_id, a.log_id);
        // renewals stopped: the lease goes quiet, so peers presume us dead
        let renewals = lease.renewals;
        tokio::time::sleep(a.cfg.renew_every * 3).await;
        a.renew(&ha_dyn).await;
        assert_eq!(a.get_json::<NodeLease>(&a.path("nodes/a")).await.unwrap().unwrap().0.renewals, renewals);
        // the supervisor restarts us: the new incarnation fences the old log
        stalls.armed.lock().clear();
        let a2 = lone_join(cfg("a"), store.clone()).await.unwrap();
        assert!(a2.fenced_logs().contains_key(&a.log_id));
        assert!(vlsync_firehose::log::first_free(&store, &a.log_id).await.unwrap().1);
        // or, without a restart, a peer takes over once the lease is quiet
        // (covered by dead_peer_with_future_clock_is_taken_over)
    }

    // ---- feature levels (version.rs, DESIGN.md "Rolling upgrades") ----

    /// Exit-7 refusals as (node id, why), recorded instead of exiting.
    fn refusals() -> &'static Mutex<Vec<(String, String)>> {
        static R: std::sync::OnceLock<Mutex<Vec<(String, String)>>> = std::sync::OnceLock::new();
        let r = R.get_or_init(|| Mutex::new(Vec::new()));
        static HOOK: std::sync::Once = std::sync::Once::new();
        HOOK.call_once(|| {
            version::set_refuse_hook(Some(Arc::new(|node: &str, why: &str| {
                refusals().lock().push((node.into(), why.into()))
            })))
        });
        r
    }

    fn refused(node: &str) -> Vec<String> {
        refusals().lock().iter().filter(|(n, _)| n == node).map(|(_, w)| w.clone()).collect()
    }

    /// `cfg(id)` posing as a build running levels `min..=max`.
    fn levels(id: &str, min: u32, max: u32) -> ClusterConfig {
        ClusterConfig { levels: version::Window { min, max }, ..cfg(id) }
    }

    async fn put_version(store: &Store, active: u32, target: Option<u32>) {
        let v = ClusterVersion { target, ..ClusterVersion::new(active, "test") };
        store
            .raw
            .put(
                &Path::from(format!("{}/{}", store.prefix, version::OBJECT)),
                PutPayload::from(serde_json::to_vec(&v).unwrap()),
            )
            .await
            .unwrap();
    }

    async fn objects(store: &Store, rel: &str) -> Vec<String> {
        use futures::StreamExt;
        store
            .raw
            .list(Some(&Path::from(format!("{}/{rel}", store.prefix))))
            .map(|m| m.unwrap().location.to_string())
            .collect()
            .await
    }

    /// A fresh prefix starts at the first node's max level. Leases advertise
    /// the node's window and the level it read.
    #[tokio::test]
    async fn version_object_is_created_at_join() {
        let store = Store::memory(None);
        let a = join(levels("va", 1, 2), store.clone()).await.unwrap();
        assert_eq!(a.cluster_version().unwrap().active, 2);
        let l = a.own_lease();
        assert_eq!((l.min_level, l.max_level, l.seen_level, l.rev.is_empty()), (1, 2, 2, false));
    }

    /// A node whose build can't run the cluster's level refuses (exit 7)
    /// before it reads or writes anything: no lease, no writer claim, no
    /// fence of its previous incarnation's log.
    #[tokio::test]
    async fn incompatible_node_is_refused() {
        refusals();
        let store = Store::memory(None);
        put_version(&store, 2, None).await;
        let id = format!("old-{}", vlsync_atproto::tid::now_micros());
        let err = join(levels(&id, 1, 1), store.clone()).await.err().expect("refused");
        assert!(format!("{err:#}").contains(version::EXIT_REASON), "{err:#}");
        assert_eq!(refused(&id).len(), 1, "fail-stop 7 hook ran once");
        assert!(refused(&id)[0].contains("outside"), "{:?}", refused(&id));
        assert!(
            objects(&store, "nodes").await.is_empty()
                && objects(&store, "writers").await.is_empty()
                && objects(&store, "assign").await.is_empty()
        );
        // a build that can no longer read the active level, and one that is
        // older than a raise in progress, are refused too
        let id2 = format!("new-{}", vlsync_atproto::tid::now_micros());
        assert!(join(levels(&id2, 3, 4), store.clone()).await.is_err());
        assert_eq!(refused(&id2).len(), 1);
        put_version(&store, 1, Some(2)).await;
        let id3 = format!("mid-{}", vlsync_atproto::tid::now_micros());
        assert!(join(levels(&id3, 1, 1), store.clone()).await.is_err());
        assert!(refused(&id3)[0].contains("raising"), "{:?}", refused(&id3));
        // one that can run it joins
        assert!(join(levels(&format!("ok-{}", vlsync_atproto::tid::now_micros()), 1, 2), store.clone()).await.is_ok());
    }

    /// An operator forced the active level past a running node's window: its
    /// next observation (once per TTL) fail-stops it.
    #[tokio::test]
    async fn running_node_seeing_a_level_past_it_fail_stops() {
        refusals();
        let store = Store::memory(None);
        let id = format!("run-{}", vlsync_atproto::tid::now_micros());
        let a = join(levels(&id, 1, 1), store.clone()).await.unwrap();
        let (_, ha) = host();
        a.step(&ha).await.unwrap();
        // a raise in progress isn't a reason to stop (the raise aborts on our lease)
        put_version(&store, 1, Some(2)).await;
        tokio::time::sleep(a.cfg.ttl).await;
        a.step(&ha).await.unwrap();
        assert!(refused(&id).is_empty());
        put_version(&store, 2, None).await;
        tokio::time::sleep(a.cfg.ttl).await;
        assert!(a.step(&ha).await.is_err());
        assert_eq!(refused(&id).len(), 1);
    }

    /// The raise protocol: refused while a live node's build can't run the
    /// level (target cleared, nothing changed), done once that node is gone;
    /// then the old build can't rejoin, and levels never go down.
    #[tokio::test]
    async fn finalize_raises_only_when_every_live_node_can() {
        refusals();
        let store = Store::memory(None);
        let old_id = format!("fin-old-{}", vlsync_atproto::tid::now_micros());
        let old = join(levels(&old_id, 1, 1), store.clone()).await.unwrap();
        let new = join(levels("fin-new", 1, 2), store.clone()).await.unwrap();
        assert_eq!(new.cluster_version().unwrap().active, 1, "created by the level-1 build");
        match new.finalize_level(2, "op").await {
            Err(FinalizeError::Incompatible { level: 2, nodes }) => {
                assert_eq!(nodes.iter().map(|n| n.0.as_str()).collect::<Vec<_>>(), [old_id.as_str()])
            }
            r => panic!("{r:?}"),
        }
        let (v, _) = new.read_version().await.unwrap().unwrap();
        assert_eq!((v.active, v.target, v.history.len()), (1, None, 1), "aborted raise leaves no target");
        assert!(matches!(new.finalize_level(3, "op").await, Err(FinalizeError::Invalid(_))), "past this node's build");
        // the old node stops (its lease goes)
        let (_, ho) = host();
        old.shutdown(&ho).await.unwrap();
        let v = new.finalize_level(2, "op").await.unwrap();
        assert_eq!(
            (v.active, v.target, v.history.last().unwrap().level, v.history.last().unwrap().by.as_str()),
            (2, None, 2, "op")
        );
        assert_eq!(new.finalize_level(2, "op").await.unwrap().active, 2, "idempotent");
        // a finalize that died after its target: nodes that can't run the
        // target refuse until a finalize at the active level clears it
        put_version(&store, 2, Some(3)).await;
        let stuck = format!("fin-stuck-{}", vlsync_atproto::tid::now_micros());
        assert!(join(levels(&stuck, 1, 2), store.clone()).await.is_err());
        assert_eq!(new.finalize_level(2, "op").await.unwrap().target, None);
        assert_eq!(new.read_version().await.unwrap().unwrap().0.target, None);
        assert!(join(levels(&stuck, 1, 2), store.clone()).await.is_ok());
        assert!(matches!(new.finalize_level(1, "op").await, Err(FinalizeError::Invalid(_))), "never lowered");
        // the old build can't come back
        assert!(join(levels(&old_id, 1, 1), store.clone()).await.is_err());
        assert_eq!(refused(&old_id).len(), 1);
        version::set_active(1);
    }

    /// A lease of a dead node whose log we fenced doesn't block a raise.
    #[tokio::test]
    async fn finalize_ignores_fenced_dead_leases() {
        let store = Store::memory(None);
        let old = join(levels("fen-old", 1, 1), store.clone()).await.unwrap();
        let new = join(levels("fen-new", 1, 2), store.clone()).await.unwrap();
        assert!(new.finalize_level(2, "op").await.is_err());
        new.fence(&old.log_id).await.unwrap();
        assert_eq!(new.finalize_level(2, "op").await.unwrap().active, 2);
        version::set_active(1);
    }

    /// `cluster lower`: only past wire-only levels, never during a raise,
    /// only when every live node can run the lower level; this build's own
    /// table (level 1 persistent, and the test level) lowers nothing.
    #[tokio::test]
    async fn lower_only_wire_levels_every_node_can_run() {
        let l =
            |level, persistent| version::Level { level, name: "x", description: "", persistent, segment_magic: None };
        let table = [l(1, true), l(2, false), l(3, false)];
        let store = Store::memory(None);
        put_version(&store, 3, None).await;
        let a = join(levels("low-a", 1, 3), store.clone()).await.unwrap();
        let b = join(levels("low-b", 2, 3), store.clone()).await.unwrap();
        match a.lower_level_with(&table, 1, "op").await {
            Err(FinalizeError::Incompatible { level: 1, nodes }) => {
                assert_eq!(nodes.iter().map(|n| (n.0.as_str(), n.2)).collect::<Vec<_>>(), [("low-b", 2)])
            }
            r => panic!("{r:?}"),
        }
        let v = a.lower_level_with(&table, 2, "op").await.unwrap();
        assert_eq!((v.active, v.history.last().unwrap().level, v.history.len()), (2, 2, 2));
        assert_eq!(b.lower_level_with(&table, 2, "op").await.unwrap().active, 2, "already there");
        assert!(
            matches!(a.lower_level_with(&table, 3, "op").await, Err(FinalizeError::Invalid(_))),
            "lowering never raises"
        );
        assert!(
            matches!(a.lower_level(1, "op").await, Err(FinalizeError::Invalid(m)) if m.contains("unknown") || m.contains("persistent"))
        );
        let persistent = [l(1, true), l(2, true)];
        assert!(
            matches!(a.lower_level_with(&persistent, 1, "op").await, Err(FinalizeError::Invalid(m)) if m.contains("persistent"))
        );
        put_version(&store, 2, Some(3)).await;
        assert!(
            matches!(a.lower_level_with(&table, 1, "op").await, Err(FinalizeError::Invalid(m)) if m.contains("in progress"))
        );
        version::set_active(1);
    }

    /// The race the target exists for: an old-range node reads the level
    /// before the raise and writes its lease after the raise listed the
    /// leases. It re-reads the object once its lease exists and refuses
    /// (deleting its lease). Either the raise aborts or the node exits 7,
    /// in every interleaving.
    #[tokio::test]
    async fn finalize_races_a_joining_old_node() {
        refusals();
        // deterministic: the whole raise runs between the joiner's first
        // check and its lease write
        let store = Store::memory(None);
        put_version(&store, 1, None).await;
        let new = join(levels("race-new", 1, 2), store.clone()).await.unwrap();
        let old_id = format!("race-old-{}", vlsync_atproto::tid::now_micros());
        let n = new.clone();
        let raise = Box::pin(async move {
            assert_eq!(n.finalize_level(2, "op").await.unwrap().active, 2, "the joiner had no lease yet");
        });
        let r = Cluster::join_inner(levels(&old_id, 1, 1), store.clone(), Some(raise)).await;
        assert!(r.is_err(), "refused after its lease write");
        assert_eq!(refused(&old_id).len(), 1);
        assert!(!objects(&store, "nodes").await.iter().any(|o| o.ends_with(&old_id)), "its lease is deleted");
        // the other order: the lease lands first, so the raise aborts
        let store = Store::memory(None);
        put_version(&store, 1, None).await;
        let new = join(levels("race-new2", 1, 2), store.clone()).await.unwrap();
        let _old = join(levels("race-old2", 1, 1), store.clone()).await.unwrap();
        assert!(matches!(new.finalize_level(2, "op").await, Err(FinalizeError::Incompatible { .. })));
        assert_eq!(new.read_version().await.unwrap().unwrap().0.active, 1);
        // concurrently, with jitter: never both
        for i in 0..20u64 {
            let store = Store::memory(None);
            put_version(&store, 1, None).await;
            let new = join(levels(&format!("racer-new-{i}"), 1, 2), store.clone()).await.unwrap();
            let old_id = format!("racer-old-{i}-{}", vlsync_atproto::tid::now_micros());
            let (n, s, oid) = (new.clone(), store.clone(), old_id.clone());
            let raise = tokio::spawn(async move {
                tokio::time::sleep(Duration::from_micros(rand::random::<u64>() % 3000)).await;
                n.finalize_level(2, "op").await
            });
            let joiner = tokio::spawn(async move {
                tokio::time::sleep(Duration::from_micros(rand::random::<u64>() % 3000)).await;
                Cluster::join(levels(&oid, 1, 1), s).await
            });
            let (raised, joined) = (raise.await.unwrap(), joiner.await.unwrap());
            assert!(!(raised.is_ok() && joined.is_ok()), "round {i}: a level-1-only node runs at level 2");
            if joined.is_ok() {
                assert!(matches!(raised, Err(FinalizeError::Incompatible { .. })), "round {i}: {raised:?}");
            }
            if raised.is_ok() {
                assert!(
                    !objects(&store, "nodes").await.iter().any(|o| o.ends_with(&old_id)),
                    "round {i}: no lease left"
                );
            }
        }
        version::set_active(1);
    }

    /// An older node's read-modify-CAS of an assignment keeps the fields a
    /// newer level added (acquire and release both rewrite it).
    #[tokio::test]
    async fn old_node_round_trips_unknown_assignment_fields() {
        let store = Store::memory(None);
        let mut c = cfg("rt");
        c.shards = 2;
        let a = join(c, store.clone()).await.unwrap();
        let path = a.path(&format!("assign/{}", ShardId(0).key()));
        let raw = serde_json::json!({"owner": null, "log_id": null, "addr": null, "epoch": 3, "seq_floor": 0, "history": [], "placement": {"zone": "b"}});
        store.raw.put(&path, PutPayload::from(serde_json::to_vec(&raw).unwrap())).await.unwrap();
        let (_, ha) = host();
        a.step(&ha).await.unwrap();
        assert!(a.is_owner(ShardId(0)));
        let got: serde_json::Value =
            serde_json::from_slice(&store.raw.get(&path).await.unwrap().bytes().await.unwrap()).unwrap();
        assert_eq!(
            (got["epoch"].as_u64(), &got["placement"]),
            (Some(4), &serde_json::json!({"zone": "b"})),
            "acquired: {got}"
        );
        a.release(ShardId(0), 1, 0, None, None).await.unwrap();
        let got: serde_json::Value =
            serde_json::from_slice(&store.raw.get(&path).await.unwrap().bytes().await.unwrap()).unwrap();
        assert_eq!(
            (&got["owner"], &got["placement"]),
            (&serde_json::Value::Null, &serde_json::json!({"zone": "b"})),
            "released: {got}"
        );
    }

    #[test]
    fn startup_backoff_doubles_with_jitter_under_its_cap() {
        let (floor, cap) = (Duration::from_millis(200), Duration::from_secs(2));
        let lo: Vec<u128> = (0..6).map(|n| jittered_backoff(n, floor, cap, 0.0).as_millis()).collect();
        let hi: Vec<u128> = (0..6).map(|n| jittered_backoff(n, floor, cap, 0.999_999).as_millis()).collect();
        assert_eq!(lo, [100, 200, 400, 800, 1000, 1000]);
        assert_eq!(hi, [199, 399, 799, 1599, 1999, 1999]);
        assert_eq!(jittered_backoff(40, floor, cap, 0.5), Duration::from_millis(1500));
        // a cap under the floor (a short test TTL) wins
        assert_eq!(jittered_backoff(0, floor, Duration::from_millis(100), 0.0), Duration::from_millis(50));
    }

    /// R2 at cluster start: one control-plane GET took over 3 s against a
    /// 3 s TTL and the node exited instead of retrying. A read that fails
    /// before our lease exists and a first step whose LIST outlives the
    /// call deadline are retried, and the node comes up with its shards.
    #[tokio::test]
    async fn startup_retries_failing_and_slow_control_plane_reads() {
        let stalls = Arc::new(Stalls::default());
        let store = Store { raw: stalls.clone(), ..Store::memory(None) };
        stalls.arm("getfail", "cluster/version");
        stalls.arm("getfail", "cluster/version");
        let c = lone_join(cfg("a"), store).await.unwrap();
        assert_eq!(stalls.stalled.load(Ordering::SeqCst), 2, "both failing reads retried");
        stalls.arm("list", "nodes");
        stalls.arm("list", "nodes");
        let (h, d) = host();
        let t = Instant::now();
        c.first_step(&d).await.unwrap();
        assert_eq!(stalls.stalled.load(Ordering::SeqCst), 4);
        assert!(t.elapsed() >= c.cfg.ttl * 2, "each stalled LIST waited out the call deadline: {:?}", t.elapsed());
        assert_eq!(c.owned().len(), 8);
        assert!(c.lease_valid());
        assert_eq!(h.lost.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn startup_gives_up_at_its_deadline() {
        let stalls = Arc::new(Stalls::default());
        let store = Store { raw: stalls.clone(), ..Store::memory(None) };
        let short = || ClusterConfig { startup_deadline: Duration::from_millis(1500), ..cfg("a") };
        for _ in 0..100 {
            stalls.arm("getfail", "cluster/version");
        }
        let t = Instant::now();
        let e = lone_join(short(), store.clone()).await.err().expect("join gives up");
        assert!(t.elapsed() < Duration::from_secs(3), "{:?}", t.elapsed());
        assert!(format!("{e:#}").contains("at startup"), "{e:#}");
        stalls.armed.lock().clear();

        let c = lone_join(short(), store).await.unwrap();
        for _ in 0..100 {
            stalls.arm("list", "nodes");
        }
        let (_h, d) = host();
        let t = Instant::now();
        let e = c.first_step(&d).await.unwrap_err();
        assert!(t.elapsed() < Duration::from_secs(3), "{:?}", t.elapsed());
        assert!(format!("{e:#}").contains("timed out after"), "{e:#}");
    }

    /// Startup's retries end with startup. Afterwards a control-plane call
    /// fails at its deadline (min(TTL, 5 s)) or on its first error, and a
    /// renewal stalled past the lease's validity still fail-stops the node.
    #[tokio::test]
    async fn after_startup_calls_keep_their_deadline_and_renewals_fail_stop() {
        let stalls = Arc::new(Stalls::default());
        let store = Store { raw: stalls.clone(), ..Store::memory(None) };
        let c = lone_join(cfg("a"), store).await.unwrap();
        let (_h, d) = host();
        c.first_step(&d).await.unwrap();
        assert_eq!(c.call_deadline(), Some(c.cfg.ttl));

        stalls.arm("get", "nodes/b");
        let t = Instant::now();
        let e = c.read_lease("b").await.unwrap_err();
        assert!(format!("{e:#}").contains("timed out after 600ms"), "{e:#}");
        assert!(t.elapsed() < c.cfg.ttl * 2, "{:?}", t.elapsed());
        stalls.arm("getfail", "nodes/b");
        let gets = c.store_requests();
        assert!(c.read_lease("b").await.is_err());
        assert_eq!(c.store_requests(), gets + 1, "no retry once our lease exists");

        let stalls = Arc::new(Stalls::default());
        let store = Store { raw: stalls.clone(), ..Store::memory(None) };
        let c = lone_join(cfg("r"), store).await.unwrap();
        let (h, d) = host();
        c.first_step(&d).await.unwrap();
        assert!(c.lease_valid());
        stalls.arm("put", "nodes/r");
        c.spawn(d);
        tokio::time::sleep(c.cfg.ttl + c.cfg.skew * 3 + Duration::from_millis(300)).await;
        assert!(h.lost.load(Ordering::SeqCst) >= 1, "a stalled renewal must still fail-stop");
    }

    /// Sends to our lease key from the renew loop, as (when, urgent): a tick
    /// every `renew_every` (a missed one fires when polled, the next a
    /// period later), `rtt` per attempt, and write number `bad` throttled
    /// `retries` times (object_store's shortest waits, the floor, between)
    /// before it lands. `renew_here` within the gap of the last answer
    /// skips (after a landed write) or waits, unless the validity left is
    /// short: then it sends at once (urgent). The bool: a tick found the
    /// lease lapsed.
    fn lease_sends(ttl_s: u64, rtt: Duration, bad: usize, retries: u32) -> (Vec<(Duration, bool)>, bool) {
        let ttl = Duration::from_secs(ttl_s);
        let (renew_every, skew) = (ttl / 5, ttl / 5);
        let gap = lease_key_gap(renew_every);
        let floor = vlsync_store::throttle::CTL_WRITE_FLOOR.min(renew_every);
        let (mut sends, mut tick, mut now) = (Vec::new(), Duration::ZERO, Duration::ZERO);
        let (mut valid_until, mut last_end, mut writes) = (ttl - skew, None::<Duration>, 0);
        for _ in 0..40 {
            now = now.max(tick);
            tick = now + renew_every;
            if now >= valid_until {
                return (sends, true);
            }
            let left = valid_until - now;
            let mut urgent = false;
            if last_end.is_some_and(|e| now - e < gap) {
                if left > renew_every + gap + skew {
                    continue;
                }
                urgent = true;
            }
            let sent = now;
            let tries = if writes == bad { retries + 1 } else { 1 };
            for t in 0..tries {
                sends.push((now, urgent && t == 0));
                now += rtt;
                if t + 1 < tries {
                    now += floor;
                }
            }
            writes += 1;
            if now < sent + ttl - skew {
                valid_until = sent + ttl - skew;
            }
            last_end = Some(now);
        }
        (sends, false)
    }

    /// R2 takes about one write a second to one key. Renewals go every TTL/5
    /// (0.5/s at the default 10 s TTL, 1/s at 5 s), a throttled one retries
    /// at least min(1 s, renew_every) apart, and the next renewal keeps
    /// that gap unless the slow one left too little validity: then it goes
    /// at once, since a lapse would fail-stop the node.
    #[test]
    fn lease_renewals_stay_under_one_write_a_second_per_key() {
        let rtt = Duration::from_millis(200);
        for ttl_s in [3u64, 5, 10, 60] {
            let renew_every = Duration::from_secs(ttl_s) / 5;
            let gap = lease_key_gap(renew_every);
            let (calm, lapsed) = lease_sends(ttl_s, rtt, usize::MAX, 0);
            assert!(!lapsed);
            let calm_gap = calm.windows(2).map(|w| w[1].0 - w[0].0).min().unwrap();
            assert_eq!(calm_gap, renew_every, "TTL {ttl_s} s: calm cadence");
            for retries in 0..=6 {
                let (sends, lapsed) = lease_sends(ttl_s, rtt, 3, retries);
                let slow = (rtt + gap) * retries + rtt;
                let ceiling = Duration::from_secs(ttl_s) * 4 / 5;
                if slow < ceiling - renew_every {
                    assert!(!lapsed, "TTL {ttl_s} s, {retries} retries: lapsed");
                }
                for w in sends.windows(2).filter(|w| !w[1].1) {
                    assert!(w[1].0 - w[0].0 >= gap, "TTL {ttl_s} s, {retries} retries: {:?} apart", w[1].0 - w[0].0);
                }
                if ttl_s == 10 && retries <= 2 {
                    assert!(sends.iter().all(|s| !s.1), "TTL 10 s, {retries} retries: an urgent renewal");
                }
            }
        }
        assert_eq!(lease_key_gap(Duration::from_secs(2)), Duration::from_secs(1));
        assert_eq!(lease_key_gap(Duration::from_millis(100)), Duration::from_millis(100));
    }

    /// The renew loop itself: a renewal the store held past its tick and
    /// then failed is followed by the next one no sooner than the gap.
    #[tokio::test]
    async fn a_slow_failed_renewal_is_not_followed_at_once() {
        let stalls = Arc::new(Stalls::default());
        let store = Store { raw: stalls.clone(), ..Store::memory(None) };
        let c = ClusterConfig {
            ttl: Duration::from_secs(8),
            renew_every: Duration::from_secs(1),
            skew: Duration::from_secs(1),
            ..cfg("r")
        };
        let c = lone_join(c, store).await.unwrap();
        let (h, d) = host();
        c.first_step(&d).await.unwrap();
        stalls.arm("slowfail", "nodes/r");
        c.hold_steps.store(true, Ordering::Release);
        c.spawn(d);
        tokio::time::sleep(Duration::from_secs(4)).await;
        let puts: Vec<(Instant, Instant)> =
            stalls.puts.lock().iter().filter(|(k, _, _)| k.ends_with("nodes/r")).map(|&(_, s, e)| (s, e)).collect();
        let slow = puts.iter().position(|(s, e)| *e - *s >= SLOW_FAIL).expect("the throttled renewal");
        let next = puts.get(slow + 1).expect("a renewal after it");
        let after = next.0 - puts[slow].1;
        assert!(after >= Duration::from_millis(950), "renewed {after:?} after the failed one");
        assert!(c.lease_valid());
        assert_eq!(h.lost.load(Ordering::SeqCst), 0);
    }

    /// The join's lease write, the first step's renewal and the renewal
    /// that publishes `joined` used to land within a few ms on one key (a
    /// likely cause of R2's 429 at a restart). Now no two writes to it are
    /// under the gap apart, a renewal that only refreshes is skipped, and
    /// `joined` still gets published.
    #[tokio::test]
    async fn startup_lease_writes_are_a_gap_apart() {
        let stalls = Arc::new(Stalls::default());
        let store = Store { raw: stalls.clone(), ..Store::memory(None) };
        let c = ClusterConfig {
            ttl: Duration::from_secs(6),
            renew_every: Duration::from_secs(1),
            skew: Duration::from_secs(1),
            ..cfg("s")
        };
        let c = lone_join(c, store.clone()).await.unwrap();
        let (h, d) = host();
        c.first_step(&d).await.unwrap();
        assert!(c.joined() && c.owned().len() == 8);
        c.spawn(d);
        tokio::time::sleep(Duration::from_millis(3500)).await;
        let puts: Vec<(Instant, Instant)> =
            stalls.puts.lock().iter().filter(|(k, _, _)| k.ends_with("nodes/s")).map(|&(_, s, e)| (s, e)).collect();
        assert!(puts.len() >= 3, "{} lease writes", puts.len());
        for w in puts.windows(2) {
            let apart = w[1].0 - w[0].1;
            assert!(apart >= Duration::from_millis(990), "lease writes {apart:?} apart");
        }
        assert!(c.read_lease("s").await.unwrap().unwrap().joined, "joined published");
        assert!(c.lease_valid());
        assert_eq!(h.lost.load(Ordering::SeqCst), 0);
    }

    /// A renewal the store throttled for most of the validity it earns
    /// (TTL 10 s scaled by half: sent at S, landed at S + 3.3 s, valid to
    /// S + 4 s). The missed tick that fires as it lands must renew at once:
    /// skipping it, or waiting out the gap, left the next tick to find the
    /// lease lapsed and fail-stop.
    #[tokio::test]
    async fn a_renewal_landing_late_in_its_validity_is_renewed_at_once() {
        let stalls = Arc::new(Stalls::default());
        let store = Store { raw: stalls.clone(), ..Store::memory(None) };
        let c = ClusterConfig {
            ttl: Duration::from_secs(5),
            renew_every: Duration::from_secs(1),
            skew: Duration::from_secs(1),
            ..cfg("late")
        };
        let c = lone_join(c, store).await.unwrap();
        let (h, d) = host();
        c.first_step(&d).await.unwrap();
        tokio::time::sleep(Duration::from_millis(1100)).await;
        stalls.arm("slowland", "nodes/late");
        c.hold_steps.store(true, Ordering::Release);
        c.spawn(d);
        tokio::time::sleep(Duration::from_secs(6)).await;
        assert_eq!(h.lost.load(Ordering::SeqCst), 0, "fail-stopped after a slow renewal that landed");
        assert!(c.lease_valid());
        let puts: Vec<(Instant, Instant)> =
            stalls.puts.lock().iter().filter(|(k, _, _)| k.ends_with("nodes/late")).map(|&(_, s, e)| (s, e)).collect();
        let slow = puts.iter().position(|(s, e)| *e - *s >= SLOW_LAND).expect("the slow renewal");
        let next = puts.get(slow + 1).expect("a renewal after it");
        assert!(next.0 - puts[slow].1 < Duration::from_millis(200), "renewed {:?} after it", next.0 - puts[slow].1);
    }
}
