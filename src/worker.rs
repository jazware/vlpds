//! Repo workers. Each repo is owned by one worker thread (hash of DID), which
//! keeps the loaded paths of its MST in memory (DESIGN.md "Partial MSTs"),
//! coalesces queued writes into commits, signs them and hands them to the
//! node log without waiting for durability (acks come back in log order).

use crate::car;
use crate::chan::{Receiver, Sender};
use crate::cid::Cid;
use crate::crypto::Keypair;
use crate::events::{self, RepoOp};
use crate::metrics;
use crate::mst::Tree;
use crate::mst_lazy::{LazyTree, Source};
use crate::mst_store::{DbSource, ScanSource};
use crate::partition::{LogEntry, Partition};
use crate::secrets::Secrets;
use crate::segment::Mutation;
use crate::state::{self, Head};
use crate::stats::STATS;
use crate::tid::{self, Tid};
use bytes::Bytes;
use prometheus::IntCounter;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};
use tokio::sync::oneshot;

/// Spec limits for a single commit.
pub const MAX_COMMIT_OPS: usize = 200;
pub const MAX_COMMIT_RECORD_BYTES: usize = 1_000_000;
pub const REPO_EXISTS: &str = "repo already exists";

#[derive(Debug, Clone)]
pub enum WriteError {
    RepoNotFound,
    /// The account status (deactivated, takendown, deleted).
    RepoInactive(String),
    InvalidSwap(String),
    Invalid(String),
    Internal(String),
    /// The shard is moving between owners. Raised only before the request
    /// started, so the entry node may resend it.
    Unavailable(String),
    /// Signing key couldn't be unwrapped; nothing was applied.
    KeyUnavailable(String),
    /// The commit signature failed verification twice (suspected hardware
    /// fault, src/crypto.rs); nothing was applied or emitted.
    SignatureFault(String),
}

pub enum Write {
    /// `prune_backlinks`: the repo's earlier records of the collection with
    /// the same subject are deleted in the same commit (the reference's
    /// `getBacklinkConflicts`).
    Create {
        collection: String,
        rkey: String,
        cid: Cid,
        bytes: Bytes,
        blobs: Vec<Cid>,
        prune_backlinks: bool,
    },
    /// putRecord / applyWrites#update (`must_exist`). `swap`: Some(None) =
    /// must not exist.
    Update {
        collection: String,
        rkey: String,
        cid: Cid,
        bytes: Bytes,
        blobs: Vec<Cid>,
        swap: Option<Option<Cid>>,
        must_exist: bool,
    },
    Delete {
        collection: String,
        rkey: String,
        swap: Option<Option<Cid>>,
    },
}

impl Write {
    fn parts(&self) -> (&str, &str) {
        match self {
            Write::Create { collection, rkey, .. }
            | Write::Update { collection, rkey, .. }
            | Write::Delete { collection, rkey, .. } => (collection, rkey),
        }
    }

    fn path(&self) -> String {
        let (c, r) = self.parts();
        let mut p = String::with_capacity(c.len() + 1 + r.len());
        p.push_str(c);
        p.push('/');
        p.push_str(r);
        p
    }
}

#[derive(Debug, Clone)]
pub enum WriteOutcome {
    Create { path: String, cid: Cid },
    Update { path: String, cid: Cid },
    Delete,
}

#[derive(Debug, Clone)]
pub struct CommitAck {
    pub commit: Cid,
    pub rev: Tid,
    pub results: Vec<WriteOutcome>,
}

pub type WriteReply = oneshot::Sender<Result<CommitAck, WriteError>>;

pub struct WriteReq {
    pub did: Arc<str>,
    pub writes: Vec<Write>,
    pub swap_commit: Option<Cid>,
    pub reply: WriteReply,
    /// None = always applied once queued.
    pub claim: Option<Arc<Claim>>,
    /// Admission permit, released when the request is consumed rather than
    /// when the handler goes away (in `claim` when there is one).
    pub permit: Option<tokio::sync::OwnedSemaphorePermit>,
}

/// Decides a queued write's fate: its worker taking it into a commit, or its
/// handler abandoning it (a forwarded write answered 503 `RepoLoading`, which
/// the forwarding node retries). Exactly one wins, so an abandoned write is
/// never applied and a taken one is always answered.
#[derive(Default)]
pub struct Claim {
    state: std::sync::atomic::AtomicU8,
    /// The write's admission permit: freed when the write is abandoned, not
    /// when its queued copy is dropped after the repo's load. Every resend
    /// queues another copy, and abandoned copies holding permits through a
    /// takeover's multi-second loads filled the cap (`Overloaded`).
    permit: parking_lot::Mutex<Option<tokio::sync::OwnedSemaphorePermit>>,
}

impl Claim {
    const PENDING: u8 = 0;
    const TAKEN: u8 = 1;
    const ABANDONED: u8 = 2;

    pub fn holding(permit: tokio::sync::OwnedSemaphorePermit) -> Claim {
        Claim { state: Default::default(), permit: parking_lot::Mutex::new(Some(permit)) }
    }

    /// The worker starts the write: false if it was abandoned.
    pub fn take(&self) -> bool {
        self.state.compare_exchange(Self::PENDING, Self::TAKEN, Ordering::AcqRel, Ordering::Acquire).is_ok()
    }

    /// False if the worker took it already.
    pub fn abandon(&self) -> bool {
        let won =
            self.state.compare_exchange(Self::PENDING, Self::ABANDONED, Ordering::AcqRel, Ordering::Acquire).is_ok();
        if won {
            self.permit.lock().take();
        }
        won
    }
}

pub struct CreateRepoReq {
    pub did: Arc<str>,
    pub handle: String,
    pub key: Arc<Keypair>,
    pub account_json: Bytes,
    /// Genesis records (path, cid, bytes).
    pub records: Vec<(String, Cid, Bytes)>,
    pub reply: oneshot::Sender<Result<Head, WriteError>>,
}

/// Account-level changes, ordered with the repo's commits by its worker.
pub struct AccountReq {
    pub did: Arc<str>,
    pub op: AccountOp,
    pub reply: oneshot::Sender<Result<Head, WriteError>>,
}

/// A read-modify-write of the account on the worker's current copy, so
/// concurrent changes compose instead of overwriting each other with stale
/// snapshots; preconditions belong inside it. `Ok(false)` = nothing to do.
pub type AccountMutation = Box<dyn FnOnce(&mut state::Account) -> Result<bool, WriteError> + Send>;

/// Checked against the account as the op applies: Err refuses the op.
pub type AccountCheck = Box<dyn FnOnce(&state::Account) -> Result<(), WriteError> + Send>;

pub enum AccountOp {
    /// A changed handle moves the handle index. `account_event` emits
    /// #account with the account's status (None = active).
    Update {
        mutate: AccountMutation,
        identity_event: bool,
        account_event: bool,
    },
    /// importRepo / reset: new commit and #sync (none while deactivated:
    /// activation emits it). Records are (path, cid, bytes, blob refs).
    /// `swap_commit`: refused unless the head is still this commit (admin
    /// rebuildRepo, which read the records from a snapshot); `stale_keys`
    /// are what that snapshot found stale, deleted in the same batch.
    /// `tree`: the MST of `records` built off the worker thread (hashing a
    /// big repo's tree would stall every repo of the worker); None = the
    /// worker builds it.
    ReplaceRepo {
        records: Vec<(String, Cid, Bytes, Vec<Cid>)>,
        swap_commit: Option<Cid>,
        stale_keys: Vec<Bytes>,
        tree: Option<Tree>,
    },
    /// `only_if`: refused unless the account still passes it (the
    /// scheduled-deletion sweep, racing a reactivation).
    Delete {
        only_if: Option<AccountCheck>,
    },
    /// Emits #account, #identity and #sync of the current commit, as the
    /// reference's sequenceAccountActivation.
    Activate {
        mutate: AccountMutation,
    },
    SigningKey(KeyStep),
    /// importRepo staged under a new generation (`crate::import`, DESIGN.md
    /// "Staged imports").
    Import(ImportStep),
    /// Replaces `S/` with stats counted from a snapshot whose head was at
    /// `at_rev` (admin recountRepo); refused if the head moved since.
    SetStats {
        stats: state::RepoStats,
        at_rev: u64,
    },
}

/// The steps of a staged import, each its own log entry. Every step but
/// `Begin` names the import by its driver's nonce (and the shard epoch it
/// began in), so a driver whose import was aborted, or whose shard moved,
/// can't touch the repo again.
pub enum ImportStep {
    /// Reserves a generation and the rev of the import's commit (`G/`).
    /// Refused as an import is (inactive account, key rotating or
    /// unavailable) and while another driver's import is staged here; one
    /// whose driver is gone is moved to the garbage first.
    Begin { nonce: u64, ticket: oneshot::Sender<ImportTicket> },
    /// Rows of the staged generation, no frame.
    Rows { nonce: u64, epoch: u64, muts: Vec<Mutation> },
    /// Makes the staged generation the repo's in one entry: a commit over
    /// `root` (its block; None: the empty tree) at the reserved rev, the
    /// account's generation, `S/`, the collection index changes, the old
    /// generation to the garbage, and #sync unless deactivated.
    Commit {
        nonce: u64,
        epoch: u64,
        root: Option<Bytes>,
        stats: state::RepoStats,
        colls_add: Vec<String>,
        colls_del: Vec<String>,
    },
    /// The staged generation becomes garbage. A no-op for another nonce.
    Abort { nonce: u64 },
    /// Deletes of a garbage generation's rows.
    Sweep { gen: u64, muts: Vec<Mutation> },
    /// A garbage generation's rows are gone: forget it.
    Swept { gen: u64 },
}

#[derive(Clone, Copy, Debug)]
pub struct ImportTicket {
    pub gen: u64,
    /// What the account's generation was: the commit sends it to the garbage.
    pub old_gen: u64,
    pub rev: Tid,
    pub epoch: u64,
    /// A staged import this Begin sent to the garbage (its driver gone, or
    /// this driver starting over).
    pub stale: Option<u64>,
}

/// The repo side of a signing-key rotation (DESIGN.md "Signing-key
/// rotation"): `Begin` before the DID document names the new key, then
/// `Finish` (or `Abort` if it never will).
pub enum KeyStep {
    /// Records the pending key. Until `Finish` or `Abort`, writes and
    /// imports are refused (retryable), so no commit is signed with the old
    /// key once the DID document may list the new one. The same key already
    /// pending is a no-op; another one is refused.
    Begin(state::PendingSigningKey),
    /// A no-op unless `pubkey` is the pending key.
    Abort { pubkey: String },
    /// Makes the pending `key` the signing key and re-signs the head with
    /// it (the reference's empty rotate-keys commit): #identity, then #sync
    /// unless the account is inactive. A no-op once `key` is the current
    /// key (a repeated `Finish`).
    Finish { key: Arc<Keypair> },
    /// Re-signs the head with the current `key`, as `Finish` does
    /// (publishIdentity syncPlc). Refused while a rotation is pending.
    Resign { key: Arc<Keypair> },
}

enum KeyOutcome {
    Noop,
    Refused(WriteError),
    /// A re-sign carries its read-after-write entry, applied at the ack.
    Written(Option<crate::recent_writes::Commit>),
}

pub enum Queued {
    Write(WriteReq),
    Account(AccountReq),
    Snapshot(SnapshotReq),
    Space(crate::space::repo::SpaceReq),
}

impl Queued {
    fn did(&self) -> &Arc<str> {
        match self {
            Queued::Write(r) => &r.did,
            Queued::Account(r) => &r.did,
            Queued::Snapshot(r) => &r.did,
            Queued::Space(r) => &r.did,
        }
    }
    fn fail(self, e: WriteError) {
        match self {
            Queued::Write(r) => _ = r.reply.send(Err(e)),
            Queued::Account(r) => _ = r.reply.send(Err(e)),
            Queued::Snapshot(r) => _ = r.reply.send(Err(e)),
            Queued::Space(r) => _ = r.reply.send(Err(e.into())),
        }
    }
}

pub enum WorkerMsg {
    Write(WriteReq),
    Account(AccountReq),
    Snapshot(SnapshotReq),
    /// A space write or space host op (`crate::space::repo`).
    Space(crate::space::repo::SpaceReq),
    CreateRepo(CreateRepoReq),
    /// Forget cached repos of a partition this node no longer owns; replies
    /// once no repo state referencing it remains in this worker.
    DropPartition(crate::slots::ShardId, oneshot::Sender<()>),
    /// Boxed: a RepoState is ~900 bytes, and every message is that size otherwise.
    Loaded {
        did: Arc<str>,
        res: Box<anyhow::Result<Option<RepoState>>>,
    },
    /// Sent when the last [`Workers`] handle drops: each worker holds a
    /// sender to its own channel, so the channel alone never disconnects.
    Shutdown,
    /// Load a recently written repo ahead of its first request; `done` gets
    /// whether the load was started and cached.
    Preload {
        did: Arc<str>,
        done: oneshot::Sender<bool>,
    },
    CacheInfo {
        did: Arc<str>,
        reply: oneshot::Sender<Option<CachedRepo>>,
    },
    /// Result of `Worker::start_fetch`: the tree to continue with (None:
    /// unchanged), and the blob refs and backlinks if it read them.
    Fetched {
        did: Arc<str>,
        res: Result<Box<FetchedState>, crate::mst::MstError>,
    },
    /// A new [`CacheLimits::bytes`] (src/memory.rs resizes the repo cache).
    SetCacheBytes(usize),
    /// Result of `Worker::start_space_fetch`.
    SpaceFetched {
        did: Arc<str>,
        res: Box<anyhow::Result<crate::space::repo::Fetched>>,
    },
}

pub type BlobRefs = HashMap<String, Vec<Cid>>;

pub type FetchedState = (Option<LazyTree>, Option<BlobRefs>, Option<crate::backlinks::Fetched>);

#[derive(Clone, Debug)]
pub struct CachedRepo {
    pub loaded_nodes: usize,
    pub charge: usize,
    pub blob_refs_loaded: bool,
}

/// The repo as of its latest *durable* commit: what exports and proofs serve.
/// Published by the commit's ack (after the state apply), so it never shows a
/// commit that could still be lost.
pub struct DurableView {
    pub head: Head,
    /// The generation the head's rows are under (`state::Gen`).
    pub gen: u64,
    /// Only partly loaded: readers load the rest into a private copy from a
    /// SlateDB snapshot taken with the view (`App::repo_view`).
    pub tree: Tree,
    /// Shared with the worker, which advances it per commit.
    pub nodes: crate::mst::SharedNodeIndex,
}

pub type ViewCell = Arc<parking_lot::RwLock<Arc<DurableView>>>;

pub struct SnapshotReq {
    pub did: Arc<str>,
    pub reply: oneshot::Sender<Result<ViewCell, WriteError>>,
    /// Admission permit, held while queued.
    pub permit: Option<tokio::sync::OwnedSemaphorePermit>,
}

pub struct RepoState {
    pub did: Arc<str>,
    pub partition: Arc<Partition>,
    pub mst: LazyTree,
    pub head: Head,
    /// None if the key service was down at load: reads are served, writes
    /// refused with `KeyUnavailable`.
    pub key: Option<Arc<Keypair>>,
    pub pending: Arc<AtomicU32>,
    pub account: state::Account,
    /// Loaded on first need (an update or delete, which must drop the old
    /// record's refs; a create with blobs, which counts their other refs;
    /// an account delete / import). Until then it holds only paths created
    /// since the open, whose refs may not be durable yet, so the load keeps
    /// them over what it reads.
    pub blob_refs: BlobRefs,
    pub blob_refs_loaded: bool,
    /// Paths referencing each blob of `blob_refs`, once it is loaded (every
    /// change to the refs runs with them loaded).
    pub blob_cids: HashMap<Cid, u32>,
    /// The counts at the in-memory head; `S/{did}` holds them at the
    /// durable one.
    pub stats: state::RepoStats,
    pub view: ViewCell,
    pub nodes: crate::mst::SharedNodeIndex,
    /// Approximate heap charged to the worker's cache ([`repo_bytes`]).
    pub charge: usize,
    /// Re-walked only where the tree changed (`Worker::settle`).
    pub heap: crate::mst_lazy::HeapMemo,
    /// Backlink index entries of commits in flight, and those read for the
    /// requests about to run.
    pub backlinks: crate::backlinks::Cache,
    /// Paths are being loaded off the worker thread; requests wait in
    /// `Worker::loading`.
    pub fetching: bool,
    /// Rebuilt from its records on open: its interior nodes are written to
    /// `M/` once it is cached.
    pub backfill: bool,
    /// `S/` was missing on open: `stats` were counted from scratch and are
    /// written once it is cached.
    pub backfill_stats: bool,
    /// Log entries in flight that wrote MST state, oldest first: (applied,
    /// the nodes written; None = the whole tree). Paths are unloaded only
    /// outside these sets while commits are in flight.
    pub inflight: std::collections::VecDeque<(Arc<std::sync::atomic::AtomicBool>, Option<HashSet<Cid>>)>,
    /// `G/{did}` at the in-memory head: a staged import, generations to sweep.
    pub imports: state::ImportState,
    /// The spaces the account writes to or governs, as loaded so far.
    /// Allocated by the repo's first space request, so a repo that never
    /// touches a space carries no space state.
    pub spaces: Option<Box<crate::space::repo::SpaceStates>>,
}

impl RepoState {
    pub fn spaces_mut(&mut self) -> &mut crate::space::repo::SpaceStates {
        self.spaces.get_or_insert_with(Default::default)
    }

    pub fn gen(&self) -> u64 {
        self.account.repo_gen
    }

    fn durable_view(&self) -> Arc<DurableView> {
        Arc::new(DurableView {
            head: self.head.clone(),
            gen: self.gen(),
            tree: self.mst.tree.clone(),
            nodes: self.nodes.clone(),
        })
    }
}

/// Drops a replaced durable view on the `view-drop` thread when this is its
/// last reference: freeing the old tree's path is costly, and the caller is
/// the log finalizer, which applies and acks every segment in order. The
/// thread collects every 5 ms because a wake-up per view costs more than
/// the free.
fn retire_view(v: Arc<DurableView>) {
    static RETIRED: parking_lot::Mutex<Vec<Arc<DurableView>>> = parking_lot::const_mutex(Vec::new());
    static DROPPER: LazyLock<bool> = LazyLock::new(|| {
        let run = || loop {
            std::thread::sleep(Duration::from_millis(5));
            let views = std::mem::take(&mut *RETIRED.lock());
            drop(views);
        };
        std::thread::Builder::new().name("view-drop".into()).spawn(run).is_ok()
    });
    // a reader still holding it frees it on its own drop
    if Arc::strong_count(&v) == 1 && *DROPPER {
        RETIRED.lock().push(v);
    }
}

/// Per-repo overhead outside the tree (account, key, head, views, maps).
const REPO_BASE_BYTES: usize = 2048;

fn spaces_bytes(st: &RepoState) -> usize {
    st.spaces.as_ref().map_or(0, |s| std::mem::size_of::<crate::space::repo::SpaceStates>() + s.heap_bytes())
}

/// Approximate heap of a cached repo: what the cache budget counts.
pub fn repo_bytes(st: &RepoState) -> usize {
    REPO_BASE_BYTES + st.mst.heap_bytes() + st.blob_refs.len() * 96 + st.backlinks.heap_bytes() + spaces_bytes(st)
}

/// A repo charged more than this is unloaded as soon as nothing of it is in
/// flight, whatever the budget: a fully loaded tree (an import, a rebuild)
/// mustn't be walked for its charge every commit.
const LAZY_REPO_MAX_BYTES: usize = 1 << 20;

/// Repo cache limits, per worker.
#[derive(Clone, Copy, Debug)]
pub struct CacheLimits {
    pub entries: usize,
    /// Over it, idle repos drop back to their root, then the least recently
    /// used are evicted. 0 = unbounded.
    pub bytes: usize,
    /// Cold open: read up to this much of the repo's `M/` range with one
    /// scan (0 = point reads only).
    pub prefetch_bytes: usize,
    /// Tests: unload every idle repo's paths after each pass.
    pub unload_idle: bool,
}

/// Covers the whole `M/` range of most active repos; larger windows cost a
/// big repo more round trips than its path's point reads (DESIGN.md
/// "Partial MSTs").
pub const DEFAULT_PREFETCH_BYTES: usize = 1 << 20;

impl From<usize> for CacheLimits {
    fn from(entries: usize) -> CacheLimits {
        CacheLimits { entries, bytes: 0, prefetch_bytes: DEFAULT_PREFETCH_BYTES, unload_idle: false }
    }
}

fn new_view(head: &Head, gen: u64, mst: &LazyTree, nodes: &crate::mst::SharedNodeIndex) -> ViewCell {
    Arc::new(parking_lot::RwLock::new(Arc::new(DurableView {
        head: head.clone(),
        gen,
        tree: mst.tree.clone(),
        nodes: nodes.clone(),
    })))
}

#[derive(Clone)]
pub struct Workers {
    pub senders: Arc<WorkerSenders>,
    /// This node's share of `LAZY_MST_FALLBACKS` (tests running side by side
    /// in one process all bump the global one).
    pub lazy_fallbacks: Arc<AtomicU64>,
}

/// Dropping the last handle stops the threads.
pub struct WorkerSenders(Vec<Sender<WorkerMsg>>);

impl std::ops::Deref for WorkerSenders {
    type Target = Vec<Sender<WorkerMsg>>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl WorkerSenders {
    /// Splits `total` evenly between the workers; each evicts down to its
    /// share on its next pass.
    pub fn set_cache_bytes(&self, total: usize) {
        for tx in &self.0 {
            let _ = tx.send(WorkerMsg::SetCacheBytes(total / self.0.len().max(1)));
        }
    }
}

impl Drop for WorkerSenders {
    fn drop(&mut self) {
        for tx in &self.0 {
            let _ = tx.send(WorkerMsg::Shutdown);
        }
    }
}

impl Workers {
    pub fn route(&self, did: &str) -> &Sender<WorkerMsg> {
        let h = state::did_hash(did);
        &self.senders[((h >> 32) % self.senders.len() as u64) as usize]
    }
}

pub type PartitionLookup = Arc<dyn Fn(&str) -> Option<Arc<Partition>> + Send + Sync>;

pub fn spawn(
    n: usize,
    limits: impl Into<CacheLimits>,
    partitions: PartitionLookup,
    rt: tokio::runtime::Handle,
) -> Workers {
    spawn_with_secrets(n, limits, partitions, rt, Secrets::dev())
}

/// [`spawn`] with the node's keyring (signing keys are unwrapped on load).
pub fn spawn_with_secrets(
    n: usize,
    limits: impl Into<CacheLimits>,
    partitions: PartitionLookup,
    rt: tokio::runtime::Handle,
    secrets: Arc<Secrets>,
) -> Workers {
    let limits = limits.into();
    let mut senders = Vec::with_capacity(n);
    let mut receivers = Vec::with_capacity(n);
    for _ in 0..n {
        let (tx, rx) = crate::chan::unbounded();
        senders.push(tx);
        receivers.push(rx);
    }
    let lazy_fallbacks = Arc::new(AtomicU64::new(0));
    for (i, rx) in receivers.into_iter().enumerate() {
        let me = senders[i].clone();
        let partitions = partitions.clone();
        let rt = rt.clone();
        let secrets = secrets.clone();
        let fallbacks = lazy_fallbacks.clone();
        std::thread::Builder::new()
            .name(format!("repo-worker-{i}"))
            .spawn(move || {
                crate::lifecycle::mark_critical_thread("repo_worker");
                Worker::new(i, me, partitions, rt, limits, secrets, fallbacks).run(rx)
            })
            .unwrap();
    }
    Workers { senders: Arc::new(WorkerSenders(senders)), lazy_fallbacks }
}

struct Worker {
    label: String,
    me: Sender<WorkerMsg>,
    partitions: PartitionLookup,
    rt: tokio::runtime::Handle,
    cache: lru::LruCache<Arc<str>, RepoState>,
    limits: CacheLimits,
    /// Sum of the cached repos' charges.
    bytes: usize,
    loading: HashMap<Arc<str>, Vec<Queued>>,
    /// Preloads in flight (their `loading` entry starts empty).
    preloads: HashMap<Arc<str>, oneshot::Sender<bool>>,
    /// Repos whose commit failed while earlier commits were still in flight:
    /// held out of the cache (their requests buffer in `loading`) until those
    /// commits are durable, then reloaded. Reloading any sooner would build
    /// the next commit on a durable head that lacks them: a fork.
    draining: HashMap<Arc<str>, RepoState>,
    clock_id: u64,
    stop: bool,
    /// Repos charged over [`LAZY_REPO_MAX_BYTES`]: unloaded once idle.
    big: HashSet<Arc<str>>,
    secrets: Arc<Secrets>,
    fallbacks: Arc<AtomicU64>,
}

impl Worker {
    fn new(
        idx: usize,
        me: Sender<WorkerMsg>,
        partitions: PartitionLookup,
        rt: tokio::runtime::Handle,
        limits: CacheLimits,
        secrets: Arc<Secrets>,
        fallbacks: Arc<AtomicU64>,
    ) -> Worker {
        Worker {
            secrets,
            fallbacks,
            label: idx.to_string(),
            me,
            partitions,
            rt,
            cache: lru::LruCache::unbounded(),
            limits,
            bytes: 0,
            loading: HashMap::new(),
            preloads: HashMap::new(),
            draining: HashMap::new(),
            clock_id: rand::random::<u64>() & 0x3ff,
            stop: false,
            big: HashSet::new(),
        }
    }

    fn run(mut self, rx: Receiver<WorkerMsg>) {
        let mut msgs = Vec::with_capacity(8192);
        loop {
            let timeout = (!self.draining.is_empty()).then(|| Duration::from_millis(5));
            match rx.recv_batch(&mut msgs, 8192, timeout) {
                Ok(()) => {}
                Err(crate::chan::RecvError::Timeout) => {
                    self.release_drained();
                    continue;
                }
                Err(crate::chan::RecvError::Disconnected) => break,
            }
            metrics::WORKER_BATCH.observe(msgs.len() as f64);
            metrics::WORKER_QUEUE.with_label_values(&[&self.label]).set(rx.len() as i64);
            let mut order: Vec<Arc<str>> = Vec::new();
            let mut groups: HashMap<Arc<str>, Vec<Queued>> = HashMap::new();
            for m in msgs.drain(..) {
                let queued = match m {
                    WorkerMsg::Write(req) => Some(Queued::Write(req)),
                    WorkerMsg::Account(req) => Some(Queued::Account(req)),
                    WorkerMsg::Snapshot(req) => Some(Queued::Snapshot(req)),
                    WorkerMsg::Space(req) => Some(Queued::Space(req)),
                    other => {
                        self.handle_control(other, &mut order, &mut groups);
                        None
                    }
                };
                if let Some(q) = queued {
                    let did = q.did().clone();
                    if let Some(buf) = self.loading.get_mut(&did) {
                        CACHE_LOADING.inc();
                        buf.push(q);
                    } else if self.cache.contains(&did) {
                        CACHE_HIT.inc();
                        let g = groups.entry(did.clone()).or_insert_with(|| {
                            order.push(did.clone());
                            Vec::new()
                        });
                        g.push(q);
                    } else {
                        CACHE_MISS.inc();
                        self.start_load(q);
                    }
                }
            }
            for did in order {
                let reqs = groups.remove(&did).unwrap_or_default();
                if reqs.is_empty() {
                    continue;
                }
                let Some(st) = self.cache.get_mut(&did) else {
                    // dropped by a DropPartition in this same batch: a load
                    // answers "not owned" (retryable) or serves a new owner
                    self.requeue(&did, reqs);
                    continue;
                };
                // space state (heads, prev CIDs) is read off this thread too
                let reqs = match space_needs(st, reqs) {
                    Ok(reqs) => reqs,
                    Err((reqs, need)) => {
                        self.start_space_fetch(did, reqs, *need);
                        continue;
                    }
                };
                // paths the repo hasn't loaded are loaded on the blocking
                // pool first, never on this thread
                let reqs = match lazy_needs(st, reqs) {
                    Ok(reqs) => reqs,
                    Err((reqs, Some(need))) => {
                        self.start_fetch(did, reqs, *need);
                        continue;
                    }
                    Err((reqs, None)) => {
                        tracing::error!(%did, "lazy MST walk failed, evicting repo");
                        self.reload(did, reqs);
                        continue;
                    }
                };
                let wrote = reqs.iter().any(|q| matches!(q, Queued::Write(_)));
                let had_key = st.key.is_some();
                let res = process(st, reqs, self.clock_id, &self.rt);
                if let Some(ss) = &mut st.spaces {
                    ss.clear_fetched();
                }
                let leftover = match res {
                    Ok(l) => l,
                    Err(e) => {
                        // in-memory state can't be trusted: reload from durable
                        // state once nothing is in flight
                        tracing::error!(%did, "commit failed, evicting repo: {e:#}");
                        self.discard(did);
                        continue;
                    }
                };
                if !leftover.is_empty() {
                    self.reload(did, leftover);
                    continue;
                }
                // without its signing key writes are refused: reload, which
                // unwraps it again
                if st.key.is_none() && (wrote || had_key) {
                    self.discard(did);
                    continue;
                }
                if wrote {
                    st.partition.recent.touch(&did);
                }
                self.settle(&did);
            }
            self.release_drained();
            self.evict();
            metrics::CACHED_REPOS.with_label_values(&[&self.label]).set(self.cache.len() as i64);
            metrics::REPO_CACHE_BYTES.with_label_values(&[&self.label]).set(self.bytes as i64);
            if self.stop {
                break;
            }
        }
    }

    fn handle_control(&mut self, m: WorkerMsg, order: &mut Vec<Arc<str>>, groups: &mut HashMap<Arc<str>, Vec<Queued>>) {
        match m {
            WorkerMsg::Write(_) | WorkerMsg::Account(_) | WorkerMsg::Snapshot(_) | WorkerMsg::Space(_) => {
                unreachable!()
            }
            WorkerMsg::SpaceFetched { did, res } => self.space_fetched(did, *res, order, groups),
            WorkerMsg::Loaded { did, res } => self.loaded(did, *res, order, groups),
            WorkerMsg::Fetched { did, res } => self.fetched(did, res, order, groups),
            WorkerMsg::CreateRepo(req) => self.create_repo(req),
            WorkerMsg::Shutdown => self.stop = true,
            WorkerMsg::SetCacheBytes(n) => {
                self.limits.bytes = n;
                self.evict();
            }
            WorkerMsg::CacheInfo { did, reply } => {
                let _ = reply.send(self.cache.peek(&did).map(|st| CachedRepo {
                    loaded_nodes: st.mst.loaded_nodes(),
                    charge: st.charge,
                    blob_refs_loaded: st.blob_refs_loaded,
                }));
            }
            WorkerMsg::Preload { did, done } => {
                if self.cache.contains(&did) || self.loading.contains_key(&did) || self.draining.contains_key(&did) {
                    metrics::REPO_PRELOADS.with_label_values(&["cached"]).inc();
                    let _ = done.send(false);
                } else {
                    self.loading.insert(did.clone(), Vec::new());
                    self.preloads.insert(did.clone(), done);
                    self.spawn_load(did, None, true);
                }
            }
            WorkerMsg::DropPartition(p, done) => {
                let drop: Vec<Arc<str>> =
                    self.cache.iter().filter(|(_, st)| st.partition.id == p).map(|(d, _)| d.clone()).collect();
                for d in drop {
                    self.cache_pop(&d);
                }
                // the shard is unrouted (and its close barrier settles the
                // in-flight commits): buffered requests go through a load,
                // which fails over as "not owned"
                let drained: Vec<Arc<str>> =
                    self.draining.iter().filter(|(_, st)| st.partition.id == p).map(|(d, _)| d.clone()).collect();
                for d in drained {
                    self.draining.remove(&d);
                    self.reload_buffered(&d);
                }
                let _ = done.send(());
            }
        }
    }

    fn loaded(
        &mut self,
        did: Arc<str>,
        res: anyhow::Result<Option<RepoState>>,
        order: &mut Vec<Arc<str>>,
        groups: &mut HashMap<Arc<str>, Vec<Queued>>,
    ) {
        let buffered = self.loading.remove(&did).unwrap_or_default();
        // The shard closed (and maybe reopened) while the load was in flight:
        // the state belongs to an ownership that ended and must never be
        // cached, or commits built on it chain past whatever the shard saw
        // since. close() purges the cache after unrouting the shard, so
        // checking here closes the window.
        let current =
            matches!(&res, Ok(Some(st)) if (self.partitions)(&did).is_some_and(|p| Arc::ptr_eq(&p, &st.partition)));
        if let Some(done) = self.preloads.remove(&did) {
            let outcome = match &res {
                _ if current => "loaded",
                Ok(Some(_)) => "stale",
                Ok(None) => "not_found",
                Err(_) => "error",
            };
            metrics::REPO_PRELOADS.with_label_values(&[outcome]).inc();
            let _ = done.send(current);
        }
        match res {
            Ok(Some(_)) if !current => {
                metrics::REPO_LOADS.with_label_values(&["stale"]).inc();
                self.requeue(&did, buffered);
            }
            Ok(Some(mut st)) => {
                STATS.repo_loads.fetch_add(1, Ordering::Relaxed);
                metrics::REPO_LOADS.with_label_values(&["ok"]).inc();
                if st.backfill || st.backfill_stats {
                    backfill_nodes(&mut st);
                }
                self.cache_put(did.clone(), st);
                self.settle(&did);
                order.push(did.clone());
                groups.insert(did, buffered);
            }
            Ok(None) => {
                metrics::REPO_LOADS.with_label_values(&["not_found"]).inc();
                for r in buffered {
                    r.fail(WriteError::RepoNotFound);
                }
            }
            Err(e) => {
                tracing::error!(%did, "repo load failed: {e:#}");
                metrics::REPO_LOADS.with_label_values(&["error"]).inc();
                let msg = format!("repo load failed: {e}");
                // a shard closed under the load: nothing was applied, so the
                // entry node may resend
                let gone = msg.contains("not owned") || msg.contains("db is closed");
                for r in buffered {
                    r.fail(if gone { WriteError::Unavailable(msg.clone()) } else { WriteError::Internal(msg.clone()) });
                }
            }
        }
    }

    fn fetched(
        &mut self,
        did: Arc<str>,
        res: Result<Box<FetchedState>, crate::mst::MstError>,
        order: &mut Vec<Arc<str>>,
        groups: &mut HashMap<Arc<str>, Vec<Queued>>,
    ) {
        let buffered = self.loading.remove(&did).unwrap_or_default();
        match (self.cache.peek_mut(&did), res) {
            (Some(st), Ok(fetched)) if st.fetching => {
                metrics::LAZY_MST_FETCHES.with_label_values(&["ok"]).inc();
                st.fetching = false;
                let (mst, blobs, bl) = *fetched;
                if let Some(mst) = mst {
                    st.mst = mst;
                }
                if let Some(b) = blobs {
                    install_blob_refs(st, b);
                }
                if let Some(bl) = bl {
                    st.backlinks.install(bl);
                }
                order.push(did.clone());
                groups.insert(did, buffered);
            }
            // failed (a node or rebuilt leaf didn't match its link, or the
            // store failed), or dropped meanwhile: reload, which falls back
            // to a rebuild from the records
            (cached, res) => {
                if let Err(e) = &res {
                    tracing::error!(%did, "lazy MST fetch failed, evicting repo: {e}");
                    metrics::LAZY_MST_FETCHES.with_label_values(&["error"]).inc();
                }
                if let Some(st) = cached {
                    st.fetching = false;
                }
                self.reload(did, buffered);
            }
        }
    }

    /// Drops a repo's in-memory state; it reloads from durable state on the
    /// next write, but only once its in-flight commits are durable.
    fn discard(&mut self, did: Arc<str>) {
        let Some(st) = self.cache_pop(&did) else { return };
        if st.pending.load(Ordering::Acquire) > 0 {
            self.loading.entry(did.clone()).or_default();
            self.draining.insert(did, st);
        }
    }

    /// Discards the repo and reloads it for `reqs` once nothing of it is in
    /// flight.
    fn reload(&mut self, did: Arc<str>, reqs: Vec<Queued>) {
        self.loading.insert(did.clone(), reqs);
        self.discard(did.clone());
        if !self.draining.contains_key(&did) {
            self.reload_buffered(&did);
        }
    }

    /// Reloads drained repos (see `draining`) whose commits are all durable.
    fn release_drained(&mut self) {
        let done: Vec<Arc<str>> = self
            .draining
            .iter()
            .filter(|(_, st)| st.pending.load(Ordering::Acquire) == 0)
            .map(|(d, _)| d.clone())
            .collect();
        for did in done {
            self.draining.remove(&did);
            self.reload_buffered(&did);
        }
    }

    fn reload_buffered(&mut self, did: &Arc<str>) {
        let reqs = self.loading.remove(did).unwrap_or_default();
        self.requeue(did, reqs);
    }

    /// Queues `reqs` behind a load of `did`, starting one if none is running.
    fn requeue(&mut self, did: &Arc<str>, reqs: Vec<Queued>) {
        let mut reqs = reqs.into_iter();
        let Some(first) = reqs.next() else { return };
        match self.loading.get_mut(did) {
            Some(buf) => buf.push(first),
            None => self.start_load(first),
        }
        if let Some(buf) = self.loading.get_mut(did) {
            buf.extend(reqs);
        }
    }

    fn start_load(&mut self, req: Queued) {
        let did = req.did().clone();
        let need = Some(Need::of(std::slice::from_ref(&req)));
        self.loading.insert(did.clone(), vec![req]);
        self.spawn_load(did, need, false);
    }

    /// Loads `did` (and what `need` visits) in the background; its `loading`
    /// entry is set. The result comes back as [`WorkerMsg::Loaded`].
    /// A preload also reads the repo's security controls into the block
    /// cache: its first request reads them before anything else.
    fn spawn_load(&mut self, did: Arc<str>, need: Option<Need>, preload: bool) {
        let opts = LoadOpts { prefetch_bytes: self.limits.prefetch_bytes, need, secrets: Some(self.secrets.clone()) };
        metrics::LOADING_REPOS.inc();
        let (me, fallbacks) = (self.me.clone(), self.fallbacks.clone());
        let Some(partition) = (self.partitions)(&did) else {
            let _ = me.send(WorkerMsg::Loaded {
                did,
                res: Box::new(Err(anyhow::anyhow!("partition not owned by this node"))),
            });
            return;
        };
        let db = preload.then(|| partition.db.clone());
        self.rt.spawn(async move {
            let t = Instant::now();
            // a shard closed under the load moved: retryable like "not owned"
            let res = load_repo_with(partition, did.clone(), opts).await.map_err(|e| {
                let closed = e.chain().any(|c| {
                    c.downcast_ref::<slatedb::Error>()
                        .is_some_and(|s| matches!(s.kind(), slatedb::ErrorKind::Closed(_)))
                });
                if closed {
                    e.context("partition not owned by this node (closed while loading)")
                } else {
                    e
                }
            });
            if res.as_ref().is_ok_and(|st| st.as_ref().is_some_and(|st| st.backfill)) {
                fallbacks.fetch_add(1, Ordering::Relaxed);
            }
            let _ = STATS.load_us.lock().record(t.elapsed().as_micros().max(1) as u64);
            metrics::REPO_LOAD_DURATION.observe(t.elapsed().as_secs_f64());
            metrics::LOADING_REPOS.dec();
            let found = matches!(res, Ok(Some(_)));
            let _ = me.send(WorkerMsg::Loaded { did: did.clone(), res: Box::new(res) });
            if let Some(db) = db.filter(|_| found) {
                let _ = warm_security(&*db, &did).await;
            }
        });
    }

    fn cache_put(&mut self, did: Arc<str>, st: RepoState) {
        self.bytes += st.charge;
        if let Some(old) = self.cache.put(did, st) {
            self.bytes -= old.charge;
        }
    }

    fn cache_pop(&mut self, did: &Arc<str>) -> Option<RepoState> {
        let st = self.cache.pop(did)?;
        self.bytes -= st.charge;
        Some(st)
    }

    /// Re-charges a cached repo after its loaded paths changed.
    fn settle(&mut self, did: &Arc<str>) {
        if self.big.contains(did) {
            return; // charged as loaded until it is unloaded (`evict`)
        }
        let Some(st) = self.cache.peek_mut(did) else { return };
        let charge = REPO_BASE_BYTES
            + st.heap.heap_bytes(&st.mst.tree.root)
            + st.blob_refs.len() * 96
            + st.backlinks.heap_bytes()
            + spaces_bytes(st);
        debug_assert_eq!(charge, repo_bytes(st));
        if charge > LAZY_REPO_MAX_BYTES {
            self.big.insert(did.clone());
        }
        self.bytes = self.bytes + charge - st.charge;
        st.charge = charge;
    }

    /// Unloads paths, then evicts least recently used repos while over the
    /// entry or byte budget. Repos with commits in flight (durable state lags
    /// memory) or a fetch running are skipped.
    fn evict(&mut self) {
        self.unload_paths();
        let over = |n: usize, b: usize, l: &CacheLimits| n > l.entries || (l.bytes > 0 && b > l.bytes);
        let (mut n, mut b) = (self.cache.len(), self.bytes);
        if !over(n, b, &self.limits) {
            return;
        }
        let mut victims = Vec::new();
        for (scanned, (did, st)) in self.cache.iter().rev().enumerate() {
            if !over(n, b, &self.limits) || scanned > 1024 {
                break;
            }
            if st.fetching || st.pending.load(Ordering::Acquire) > 0 {
                continue;
            }
            n -= 1;
            b -= st.charge;
            victims.push(did.clone());
        }
        for did in victims {
            self.cache_pop(&did);
            metrics::REPO_EVICTIONS.inc();
        }
    }

    /// Loads what `reqs` visit on the blocking pool, so the worker thread
    /// never waits on the store. The requests wait in `loading` meanwhile,
    /// so the tree doesn't change; the loaded copy replaces it on
    /// [`WorkerMsg::Fetched`].
    fn start_fetch(&mut self, did: Arc<str>, reqs: Vec<Queued>, need: Need) {
        let Some(st) = self.cache.peek_mut(&did) else {
            self.loading.insert(did.clone(), reqs);
            self.reload_buffered(&did);
            return;
        };
        st.fetching = true;
        let mut mst = (!need.tree_loaded).then(|| st.mst.clone());
        let (db, gen) = (st.partition.db.clone(), st.gen());
        let (rt, me, d) = (self.rt.clone(), self.me.clone(), did.clone());
        self.loading.insert(did, reqs);
        self.rt.spawn_blocking(move || {
            let store_err = |e: anyhow::Error| crate::mst::MstError::Store(e.to_string());
            let res = mst.as_mut().map_or(Ok(()), |m| need.load(m, &*db, &d, gen, &rt)).and_then(|_| {
                let blobs = match need.blobs {
                    true => Some(rt.block_on(load_blob_refs(&*db, &d, gen)).map_err(store_err)?),
                    false => None,
                };
                let bl = rt.block_on(need.load_backlinks(&*db, &d, gen)).map_err(store_err)?;
                Ok(Box::new((mst, blobs, bl)))
            });
            let _ = me.send(WorkerMsg::Fetched { did: d, res });
        });
    }

    /// Reads what a repo's space requests need ([`crate::space::repo::fetch`])
    /// off this thread, as [`Self::start_fetch`] loads MST paths; the result
    /// comes back as [`WorkerMsg::SpaceFetched`].
    fn start_space_fetch(&mut self, did: Arc<str>, reqs: Vec<Queued>, need: crate::space::repo::SpaceNeed) {
        let Some(st) = self.cache.peek_mut(&did) else {
            self.loading.insert(did.clone(), reqs);
            self.reload_buffered(&did);
            return;
        };
        st.fetching = true;
        let db = st.partition.db.clone();
        let (me, d) = (self.me.clone(), did.clone());
        self.loading.insert(did, reqs);
        self.rt.spawn(async move {
            let res = crate::space::repo::fetch(&db, &d, need).await;
            let _ = me.send(WorkerMsg::SpaceFetched { did: d, res: Box::new(res) });
        });
    }

    fn space_fetched(
        &mut self,
        did: Arc<str>,
        res: anyhow::Result<crate::space::repo::Fetched>,
        order: &mut Vec<Arc<str>>,
        groups: &mut HashMap<Arc<str>, Vec<Queued>>,
    ) {
        let buffered = self.loading.remove(&did).unwrap_or_default();
        let Some(st) = self.cache.peek_mut(&did).filter(|st| st.fetching) else {
            self.reload(did, buffered);
            return;
        };
        st.fetching = false;
        let buffered = match res {
            Ok(f) => {
                crate::space::repo::install(st.spaces_mut(), f);
                buffered
            }
            // only the space requests fail; the rest go on
            Err(e) => {
                tracing::error!(%did, "space state fetch failed: {e:#}");
                let msg = format!("space state fetch failed: {e}");
                let closed = msg.contains("not owned") || msg.contains("db is closed") || msg.contains("Closed");
                let (space, rest): (Vec<Queued>, Vec<Queued>) =
                    buffered.into_iter().partition(|q| matches!(q, Queued::Space(_)));
                for q in space {
                    q.fail(if closed {
                        WriteError::Unavailable(msg.clone())
                    } else {
                        WriteError::Internal(msg.clone())
                    });
                }
                rest
            }
        };
        order.push(did.clone());
        groups.insert(did, buffered);
    }

    /// Drops the loaded paths of repos over [`LAZY_REPO_MAX_BYTES`], then of
    /// the least recently used while over the byte budget. Only repos with
    /// nothing in flight: their loaded nodes are then all durable, so any can
    /// be read back, and a commit's persistence diff only needs the nodes
    /// its own walks loaded.
    fn unload_paths(&mut self) {
        let idle = |st: &RepoState| {
            st.pending.load(Ordering::Acquire) == 0 && !st.fetching && st.view.read().head.rev == st.head.rev
        };
        let big: Vec<Arc<str>> = self.big.iter().cloned().collect();
        for did in big {
            let Some(st) = self.cache.peek_mut(&did) else {
                self.big.remove(&did);
                continue;
            };
            let was = st.charge;
            if idle(st) {
                unload_repo(st);
            } else if !st.fetching && !unload_settled(st) {
                continue; // a whole-tree entry in flight: wait for it
            }
            self.bytes = self.bytes - was + st.charge;
            if st.charge <= LAZY_REPO_MAX_BYTES {
                self.big.remove(&did);
            }
        }
        let all = self.limits.unload_idle;
        if !all && (self.limits.bytes == 0 || self.bytes <= self.limits.bytes) {
            return;
        }
        let mut b = self.bytes;
        let mut freed = 0;
        for (scanned, (_, st)) in self.cache.iter_mut().rev().enumerate() {
            if !all && (b <= self.limits.bytes || scanned > 4096) {
                break;
            }
            if !idle(st) || st.mst.loaded_nodes() <= 1 {
                continue;
            }
            let was = st.charge;
            unload_repo(st);
            b -= was - st.charge.min(was);
            freed += was - st.charge.min(was);
        }
        self.bytes -= freed;
    }

    fn create_repo(&mut self, req: CreateRepoReq) {
        let (partition, tree, head, account, imports) = match self.check_create(&req) {
            Ok(v) => v,
            Err(e) => {
                let _ = req.reply.send(Err(e));
                return;
            }
        };
        let record_bytes = req.records.iter().map(|(_, _, b)| b.len() as u64).sum();
        let stats = match crate::repo_stats::of_tree(&tree, record_bytes, 0) {
            Ok(s) => s,
            Err(e) => {
                let _ = req.reply.send(Err(WriteError::Internal(e.to_string())));
                return;
            }
        };
        let did = req.did.clone();
        let time = events::now_rfc3339();
        // an account created inactive (migration in) is announced only when
        // activated (reference createAccount: no events when deactivated)
        let frames = if account.status.is_some() {
            Vec::new()
        } else {
            vec![
                events::identity_frame(&did, &req.handle, &time),
                events::account_frame(&did, true, None, &time),
                sync_frame(&did, &head, &time),
            ]
        };
        let mut muts = Vec::with_capacity(3 + req.records.len());
        let gen = account.repo_gen;
        let mut colls = HashSet::new();
        for (path, cid, bytes) in &req.records {
            muts.push(put(state::record_key(&did, gen, path), state::record_value(cid, head.rev.0, bytes)));
            muts.push(put(state::record_cid_key(&did, gen, cid, path), Bytes::new()));
            if colls.insert(collection_of(path)) {
                muts.push(put(state::collection_key(collection_of(path), &did), Bytes::new()));
            }
        }
        replace_nodes_mutations(&did, gen, HashMap::new(), &tree, &mut muts);
        muts.push(put(state::repo_stats_key(&did), stats.encode()));
        // a new repo's whole tree is in flight until this applies
        let applied = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut backlinks = crate::backlinks::Cache::default();
        index_backlinks(
            &did,
            gen,
            req.records.iter().map(|(p, _, b)| (p.as_str(), &b[..])),
            &mut backlinks,
            &Some(applied.clone()),
            &mut muts,
        );
        let account_json = match gen {
            0 => req.account_json.clone(),
            _ => match account_mutation(&did, &account) {
                Ok(m) => m.val.expect("a put"),
                Err(e) => {
                    let _ = req.reply.send(Err(WriteError::Internal(e.to_string())));
                    return;
                }
            },
        };
        muts.extend([
            put(state::account_key(&did), account_json),
            put(state::handle_key(&did, &req.handle), Bytes::from(did.to_string())),
            put(state::head_key(&did), head.encode()),
        ]);
        let pending = Arc::new(AtomicU32::new(1));
        let (reply, acked_head, ack_did, a2) = (req.reply, head.clone(), did.clone(), applied.clone());
        let entry = LogEntry {
            shard: partition.id,
            frames,
            muts,
            ack: Some(Box::new(move |r| {
                a2.store(true, Ordering::Release);
                if r.is_ok() {
                    crate::recent_writes::invalidate(&ack_did);
                }
                let _ = reply.send(r.map(|_| acked_head).map_err(|e| WriteError::Internal(e.to_string())));
            })),
            pending: Some(pending.clone()),
            enqueued: Instant::now(),
            totals: crate::totals::Delta::account(
                &did,
                Default::default(),
                crate::totals::Counted::of(&account, &head),
            ),
        };
        let nodes = crate::mst::SharedNodeIndex::default();
        let mst = LazyTree::loaded(tree, 1);
        let view = new_view(&head, gen, &mst, &nodes);
        let st = RepoState {
            did: did.clone(),
            partition: partition.clone(),
            mst,
            head,
            key: Some(req.key),
            pending,
            account,
            blob_refs: HashMap::new(),
            // a new repo: no refs anywhere yet
            blob_refs_loaded: true,
            blob_cids: HashMap::new(),
            stats,
            view,
            nodes,
            charge: 0,
            heap: Default::default(),
            backlinks,
            fetching: false,
            backfill: false,
            backfill_stats: false,
            inflight: [(applied, None)].into(),
            imports,
            spaces: Default::default(),
        };
        self.cache_put(did.clone(), st);
        if partition.tx.blocking_send(entry).is_err() {
            tracing::error!("partition sequencer gone");
        }
        self.settle(&did);
    }

    /// Everything a CreateRepo needs before it writes: the partition, the
    /// genesis tree, the signed head and the account.
    fn check_create(
        &mut self,
        req: &CreateRepoReq,
    ) -> Result<(Arc<Partition>, Tree, Head, state::Account, state::ImportState), WriteError> {
        // a deleted repo's cached state doesn't block its DID coming back
        // (migration in), once nothing of it is in flight
        if self.cache.peek(&req.did).is_some_and(|st| {
            st.account.status.as_deref() == Some("deleted") && st.pending.load(Ordering::Acquire) == 0
        }) {
            self.cache_pop(&req.did);
        }
        if self.cache.contains(&req.did) || self.loading.contains_key(&req.did) {
            return Err(WriteError::Invalid(REPO_EXISTS.into()));
        }
        let partition = (self.partitions)(&req.did)
            .ok_or_else(|| WriteError::Unavailable("partition not owned by this node".into()))?;
        // Not cached is not "doesn't exist": a repo created and then evicted
        // is only in durable state, and two createAccounts for one DID can
        // both pass the handler's check. Not cached also means nothing of it
        // is in flight, so durable state is current.
        let (hv, gv) = match self.rt.block_on(async {
            tokio::try_join!(partition.db.get(state::head_key(&req.did)), partition.db.get(state::import_key(&req.did)))
        }) {
            Ok(v) => v,
            Err(e) => return Err(WriteError::Unavailable(format!("repo existence check failed: {e}"))),
        };
        if hv.is_some() {
            return Err(WriteError::Invalid(REPO_EXISTS.into()));
        }
        // a DID coming back while an earlier incarnation's generations
        // await their sweep starts above them
        let imports = match gv {
            Some(v) => state::ImportState::decode(&v).map_err(|e| WriteError::Internal(e.to_string()))?,
            None => state::ImportState::default(),
        };
        let mut tree = Tree::new();
        for (path, cid, _) in &req.records {
            tree.insert_no_proof(path.as_bytes(), *cid).map_err(|e| WriteError::Invalid(e.to_string()))?;
        }
        let data = tree.root_cid().map_err(|e| WriteError::Internal(e.to_string()))?;
        let rev = tid::next_rev(None, self.clock_id);
        let (commit, commit_block) =
            sign_commit(&req.did, &rev.to_string(), &data, &req.key).map_err(|e| signature_fault(&e))?;
        let mut account: state::Account = serde_json::from_slice(&req.account_json)
            .map_err(|e| WriteError::Internal(format!("bad account json: {e}")))?;
        account.repo_gen = imports.next_gen(None);
        Ok((partition, tree, Head { commit, data, rev, commit_block }, account, imports))
    }
}

/// What a repo's queued requests visit: the keys they write (paths and
/// neighbours), `coll/` probes for the collection index, or everything (an
/// account delete or import).
#[derive(Clone, Debug, Default)]
pub struct Need {
    keys: Vec<Vec<u8>>,
    probes: Vec<Vec<u8>>,
    all: bool,
    /// An update or delete drops the old record's blob refs; a write adding
    /// refs counts the blobs' other references.
    blobs: bool,
    /// Backlink index values a write changes, the paths whose old link an
    /// update or delete removes, or the whole index.
    bl_links: Vec<Vec<u8>>,
    bl_paths: Vec<String>,
    bl_all: bool,
    /// Links of `prune_backlinks` creates: a conflict deletes, which needs
    /// the blob refs.
    bl_prune: Vec<Vec<u8>>,
    /// A fetch for backlinks alone.
    tree_loaded: bool,
}

impl Need {
    fn of(reqs: &[Queued]) -> Need {
        let mut n = Need::default();
        for q in reqs {
            match q {
                Queued::Write(r) => {
                    for w in &r.writes {
                        // a create with blobs: whether another record holds
                        // them already (expectedBlobs counts distinct ones)
                        n.blobs |= match w {
                            Write::Create { blobs, .. } => !blobs.is_empty(),
                            _ => true,
                        };
                        n.backlinks(w);
                        let p = w.path();
                        let coll = collection_of(&p).as_bytes();
                        if !n.probes.iter().any(|q| q.strip_suffix(b"/") == Some(coll)) {
                            n.probes.push([coll, b"/"].concat());
                        }
                        n.keys.push(p.into_bytes());
                    }
                }
                Queued::Account(AccountReq {
                    op: AccountOp::ReplaceRepo { .. } | AccountOp::Delete { .. }, ..
                }) => {
                    n.all = true;
                    n.blobs = true;
                    n.bl_all = true;
                }
                Queued::Account(_) | Queued::Snapshot(_) | Queued::Space(_) => {}
            }
        }
        n
    }

    fn is_empty(&self) -> bool {
        self.keys.is_empty() && self.probes.is_empty() && !self.all && !self.blobs && !self.backlinks_needed()
    }

    fn backlinks(&mut self, w: &Write) {
        let (coll, rkey, record) = match w {
            Write::Create { collection, rkey, bytes, .. } => (collection, rkey, Some(bytes)),
            Write::Update { collection, rkey, bytes, .. } => (collection, rkey, Some(bytes)),
            Write::Delete { collection, rkey, .. } => (collection, rkey, None),
        };
        if !crate::backlinks::linked(coll) {
            return;
        }
        if let Some(l) = record.and_then(|b| crate::backlinks::link(coll, b)) {
            if matches!(w, Write::Create { prune_backlinks: true, .. }) {
                self.bl_prune.push(l.clone());
            }
            self.bl_links.push(l);
        }
        if !matches!(w, Write::Create { .. }) {
            self.bl_paths.push(format!("{coll}/{rkey}"));
        }
    }

    fn backlinks_needed(&self) -> bool {
        !self.bl_links.is_empty() || !self.bl_paths.is_empty() || self.bl_all
    }

    fn skip_cached_backlinks(&mut self, c: &crate::backlinks::Cache) {
        self.bl_all &= !c.all;
        self.bl_links.retain(|l| !c.vals.contains_key(&l[..]));
        let mut more = Vec::new();
        self.bl_paths.retain(|p| match c.paths.get(p.as_str()) {
            Some((Some(l), _)) => {
                if !c.vals.contains_key(l) {
                    more.push(l.to_vec());
                }
                false
            }
            Some((None, _)) => false,
            None => true,
        });
        self.bl_links.extend(more);
    }

    async fn load_backlinks<R: slatedb::DbReadOps + Sync + ?Sized>(
        &self,
        db: &R,
        did: &str,
        gen: u64,
    ) -> anyhow::Result<Option<crate::backlinks::Fetched>> {
        if !self.backlinks_needed() {
            return Ok(None);
        }
        crate::backlinks::fetch(db, did, gen, &self.bl_links, &self.bl_paths, self.bl_all).await.map(Some)
    }

    /// Blocking: the blocking pool only. A persisted node found missing is
    /// an error too: the repo is then reopened, which rebuilds the tree and
    /// backfills `M/`.
    fn load<R: slatedb::DbReadOps + Sync + ?Sized>(
        &self,
        mst: &mut LazyTree,
        db: &R,
        did: &str,
        gen: u64,
        rt: &tokio::runtime::Handle,
    ) -> Result<(), crate::mst::MstError> {
        let fallbacks = mst.stats.fallbacks;
        if self.all && !mst.fully_loaded() {
            // one forward scan of the records serves every unloaded leaf
            let scan = ScanSource::open(db, did, gen, DbSource::new(db, did, gen, rt), rt)?;
            mst.load_all(&scan)?;
        }
        let keys: Vec<&[u8]> = self.keys.iter().map(|k| &k[..]).collect();
        let probes: Vec<&[u8]> = self.probes.iter().map(|k| &k[..]).collect();
        mst.fetch(&keys, &probes, &DbSource::new(db, did, gen, rt))?;
        match mst.stats.fallbacks > fallbacks {
            true => Err(crate::mst::MstError::Invalid("persisted MST nodes missing")),
            false => Ok(()),
        }
    }
}

/// Requests to run later, and what to load first (None: the walk failed
/// and the repo must be reloaded).
type Deferred = (Vec<Queued>, Option<Box<Need>>);

/// `Ok` if a repo's space requests run on the space state it holds; else
/// what to read first.
fn space_needs(
    st: &mut RepoState,
    reqs: Vec<Queued>,
) -> Result<Vec<Queued>, (Vec<Queued>, Box<crate::space::repo::SpaceNeed>)> {
    if !reqs.iter().any(|q| matches!(q, Queued::Space(_))) {
        return Ok(reqs);
    }
    let ss = st.spaces_mut();
    ss.prune();
    let mut need = crate::space::repo::SpaceNeed::default();
    for q in &reqs {
        if let Queued::Space(r) = q {
            need.add(ss, r);
        }
    }
    match need.is_empty() {
        true => Ok(reqs),
        false => Err((reqs, Box::new(need))),
    }
}

/// `Ok` if a repo's `reqs` run on its loaded paths alone.
fn lazy_needs(st: &mut RepoState, reqs: Vec<Queued>) -> Result<Vec<Queued>, Deferred> {
    let mut need = Need::of(&reqs);
    need.blobs &= !st.blob_refs_loaded;
    need.skip_cached_backlinks(&st.backlinks);
    // a create's conflicts are deleted (their blob refs dropped)
    let bl = &st.backlinks.vals;
    need.blobs |=
        !st.blob_refs_loaded && need.bl_prune.iter().any(|l| bl.get(&l[..]).is_some_and(|(v, _)| !v.is_empty()));
    if need.is_empty() {
        return Ok(reqs);
    }
    if need.blobs || (need.all && !st.mst.fully_loaded()) {
        return Err((reqs, Some(Box::new(need))));
    }
    let keys: Vec<&[u8]> = need.keys.iter().map(|k| &k[..]).collect();
    let probes: Vec<&[u8]> = need.probes.iter().map(|k| &k[..]).collect();
    match st.mst.fetch(&keys, &probes, &crate::mst_store::CachedOnly) {
        // backlink index entries to read first (off this thread too)
        Ok(()) if need.backlinks_needed() => {
            need.tree_loaded = true;
            Err((reqs, Some(Box::new(need))))
        }
        Ok(()) => Ok(reqs),
        Err(crate::mst::MstError::NotLoaded) => Err((reqs, Some(Box::new(need)))),
        Err(e) => {
            tracing::error!(did = %st.did, "lazy MST walk failed: {e}");
            Err((reqs, None))
        }
    }
}

/// Drops the loaded paths of a repo with commits in flight, except the
/// nodes those commits wrote (not applied yet). False if one of them
/// replaces the whole tree.
fn unload_settled(st: &mut RepoState) -> bool {
    pop_applied(st);
    let mut keep = HashSet::new();
    for (_, nodes) in &st.inflight {
        match nodes {
            Some(n) => keep.extend(n.iter().copied()),
            None => return false,
        }
    }
    st.mst.unload_except(&keep);
    st.heap = Default::default();
    metrics::LAZY_MST_UNLOADS.inc();
    st.charge = repo_bytes(st);
    true
}

fn pop_applied(st: &mut RepoState) {
    while st.inflight.front().is_some_and(|(done, _)| done.load(Ordering::Acquire)) {
        st.inflight.pop_front();
    }
}

/// Marks a repo's log entry that writes MST state as in flight; `done` is
/// set once it is applied.
fn track_inflight(
    st: &mut RepoState,
    nodes: Option<HashSet<Cid>>,
    done: Arc<std::sync::atomic::AtomicBool>,
) -> Arc<std::sync::atomic::AtomicBool> {
    pop_applied(st);
    st.inflight.push_back((done.clone(), nodes));
    done
}

/// Drops the loaded paths of a repo with nothing in flight and republishes
/// its durable view (same head) without them.
fn unload_repo(st: &mut RepoState) {
    st.inflight.clear();
    st.mst.unload(0);
    st.heap = Default::default();
    // durable now: read again when next needed
    st.blob_refs = HashMap::new();
    st.blob_refs_loaded = false;
    st.blob_cids = HashMap::new();
    st.backlinks.prune();
    *st.view.write() = st.durable_view();
    metrics::LAZY_MST_UNLOADS.inc();
    st.charge = repo_bytes(st);
}

/// Logs the interior nodes of a repo rebuilt from its records on open (its
/// `M/` nodes were missing or wrong), and stats counted on open (`S/`
/// missing), so the next open reads them.
fn backfill_nodes(st: &mut RepoState) {
    let mut muts = Vec::new();
    if std::mem::take(&mut st.backfill) {
        replace_nodes_mutations(&st.did, st.gen(), HashMap::new(), &st.mst.tree, &mut muts);
    }
    if std::mem::take(&mut st.backfill_stats) {
        muts.push(put(state::repo_stats_key(&st.did), st.stats.encode()));
    }
    if muts.is_empty() {
        return;
    }
    let applied = track_inflight(st, None, Default::default());
    let ack: crate::partition::AckFn = Box::new(move |_| applied.store(true, Ordering::Release));
    let entry = LogEntry {
        shard: st.partition.id,
        frames: Vec::new(),
        muts,
        ack: Some(ack),
        pending: Some(st.pending.clone()),
        enqueued: Instant::now(),
        totals: None,
    };
    if let Err(e) = send_entry(st, entry) {
        tracing::warn!(did = %st.did, "MST node backfill not logged: {e}");
    }
}

#[derive(Clone, Debug, Default)]
pub struct LoadOpts {
    pub prefetch_bytes: usize,
    /// What to load besides the root (the first request's paths).
    pub need: Option<Need>,
    /// None: the dev keyring.
    pub secrets: Option<Arc<Secrets>>,
}

const PRELOAD_CONCURRENCY: usize = 32;

/// Warms freshly opened shards in the background so first writes don't pay
/// the cold load: the recently written repos the previous owner persisted
/// with its last checkpoint, newest first and interleaved across shards.
/// Each shard's set is seeded with what it read, so it carries over to the
/// next owner. A shard closed meanwhile just fails its loads.
pub fn spawn_preload(
    workers: &Workers,
    shards: Vec<(crate::slots::ShardId, Arc<slatedb::Db>, Arc<crate::partition::RecentRepos>)>,
) {
    use futures::StreamExt;
    let senders = Arc::downgrade(&workers.senders);
    tokio::spawn(async move {
        let t = Instant::now();
        // every shard's set at once: one at a time, a takeover's reads queue
        // behind the request-driven cold loads they are meant to spare
        let recent: Vec<Vec<Arc<str>>> = futures::stream::iter(shards)
            .map(|(shard, db, set)| async move {
                if set.cap() == 0 {
                    return Vec::new();
                }
                match db.get(crate::nodelog::META_RECENT).await {
                    Ok(Some(b)) => {
                        let recent = crate::partition::RecentRepos::decode(&b);
                        set.seed(&recent);
                        recent
                    }
                    Ok(None) => Vec::new(),
                    Err(e) => {
                        tracing::warn!(shard = shard.0, "recent repos read failed: {e:#}");
                        Vec::new()
                    }
                }
            })
            .buffer_unordered(64)
            .filter(|v| std::future::ready(!v.is_empty()))
            .collect()
            .await;
        // newest first, round-robin over the shards
        let mut order = Vec::with_capacity(recent.iter().map(Vec::len).sum());
        for k in 0..recent.iter().map(Vec::len).max().unwrap_or(0) {
            order.extend(recent.iter().filter_map(|v| v.get(k).cloned()));
        }
        let n = order.len();
        let loaded = futures::stream::iter(order)
            .map(|did| {
                let senders = senders.clone();
                async move {
                    let rx = {
                        let senders = senders.upgrade()?;
                        let (tx, rx) = oneshot::channel();
                        let w = Workers { senders, lazy_fallbacks: Default::default() };
                        w.route(&did).send(WorkerMsg::Preload { did, done: tx }).ok()?;
                        rx
                    };
                    rx.await.ok()
                }
            })
            .buffer_unordered(PRELOAD_CONCURRENCY)
            .filter(|r| std::future::ready(*r == Some(true)))
            .count()
            .await;
        if n > 0 {
            tracing::info!(
                recent = n,
                recent_loaded = loaded,
                elapsed_ms = t.elapsed().as_millis() as u64,
                "repos preloaded"
            );
        }
    });
}

/// The signed commit block, verified before anything can sequence it
/// (src/crypto.rs). Err: the signature failed twice (suspected hardware
/// fault): nothing may be emitted for this commit.
pub fn sign_commit(
    did: &str,
    rev: &str,
    data: &Cid,
    key: &Keypair,
) -> Result<(Cid, Bytes), crate::crypto::SignatureFault> {
    let unsigned = events::encode_commit(did, rev, data, None);
    let sig = key.sign_verified(crate::crypto::Purpose::Commit, &unsigned)?;
    let signed = events::encode_commit(did, rev, data, Some(&sig));
    Ok((Cid::dag_cbor(&signed), Bytes::from(signed)))
}

fn signature_fault(e: &crate::crypto::SignatureFault) -> WriteError {
    WriteError::SignatureFault(e.to_string())
}

/// Reads what a cold load of `did` reads (head, account, the `M/`
/// read-ahead), only for their blocks to land in the block cache.
pub async fn warm_repo<R: slatedb::DbReadOps + Sync + ?Sized>(db: &R, did: &str) -> anyhow::Result<()> {
    db.get(state::head_key(did)).await?;
    let gen = match db.get(state::account_key(did)).await? {
        Some(v) => serde_json::from_slice::<state::Account>(&v)?.repo_gen,
        None => return Ok(()),
    };
    crate::mst_store::prefetch(db, did, gen, DEFAULT_PREFETCH_BYTES).await?;
    warm_security(db, did).await
}

/// Reads the account's security controls (`sec/` private rows), which
/// every authenticated request on its owner reads first, into the block
/// cache.
pub async fn warm_security<R: slatedb::DbReadOps + Sync + ?Sized>(db: &R, did: &str) -> anyhow::Result<()> {
    let lo = [state::private_prefix(did), crate::xrpc::SEC.as_bytes().to_vec()].concat();
    let hi = state::prefix_end(&lo);
    let opts = slatedb::config::ScanOptions { cache_blocks: true, ..Default::default() };
    let mut it = db.scan_with_options(lo..hi, &opts).await?;
    while it.next().await?.is_some() {}
    Ok(())
}

/// Opens a repo cold: its root, nothing else.
pub async fn load_repo(partition: Arc<Partition>, did: Arc<str>) -> anyhow::Result<Option<RepoState>> {
    load_repo_with(partition, did, LoadOpts { prefetch_bytes: DEFAULT_PREFETCH_BYTES, need: None, secrets: None }).await
}

async fn load_repo_with(partition: Arc<Partition>, did: Arc<str>, opts: LoadOpts) -> anyhow::Result<Option<RepoState>> {
    let db = &partition.db;
    let Some(hv) = db.get(state::head_key(&did)).await? else {
        return load_husk(partition.clone(), did).await;
    };
    let head = Head::decode(&hv)?;
    let av = db.get(state::account_key(&did)).await?.ok_or_else(|| anyhow::anyhow!("head without account"))?;
    let acct: state::Account = serde_json::from_slice(&av)?;
    let gen = acct.repo_gen;
    let (sv, gv) = tokio::try_join!(db.get(state::repo_stats_key(&did)), db.get(state::import_key(&did)))?;
    let imports = gv.map(|v| state::ImportState::decode(&v)).transpose()?.unwrap_or_default();
    // with the key service down the repo still loads for reads; writes get
    // a 503 and the next one reloads (retries the unwrap)
    let secrets = opts.secrets.clone().unwrap_or_else(Secrets::dev);
    let key = match secrets.account_signing_key(&acct).await {
        // the (possibly long-cached) scalar must still derive the account's
        // public key; if not, treat the key as unavailable
        Ok(k) if !k.matches_public(&acct.signing_pubkey) => {
            crate::crypto::record_fault(crate::crypto::Purpose::KeyLoad);
            secrets.forget(&did);
            None
        }
        Ok(k) => Some(k),
        Err(e) if e.retryable() => None,
        Err(e) => return Err(anyhow::anyhow!("signing key of {did}: {e}")),
    };
    // most cold writes are creates without blobs: no refs to read
    let read_refs = async {
        match opts.need.as_ref().is_some_and(|n| n.blobs) {
            true => load_blob_refs(&**db, &did, gen).await.map(Some),
            false => Ok(None),
        }
    };
    let ((mst, backfill), blob_refs) = tokio::try_join!(open_lazy(&partition, &did, gen, &head, &opts), read_refs)?;
    let stats = sv.map(|v| state::RepoStats::decode(&v)).transpose()?;
    let (stats, backfill_stats) = match stats {
        Some(s) if s.bytes.is_some() => (s, false),
        Some(_) => {
            // a row from before repo bytes were counted
            metrics::LAZY_MST_FALLBACKS.with_label_values(&["stats_without_bytes"]).inc();
            (crate::repo_stats::walk(&**db, &did, gen).await?, true)
        }
        None => {
            tracing::warn!(%did, "repo stats missing: counting the repo");
            metrics::LAZY_MST_FALLBACKS.with_label_values(&["missing_stats"]).inc();
            (crate::repo_stats::walk(&**db, &did, gen).await?, true)
        }
    };
    let backlinks = match opts.need.as_ref() {
        Some(n) => n.load_backlinks(&**db, &did, gen).await?,
        None => None,
    };
    let mut st = finish_load(partition.clone(), did, mst, head, key, acct)?;
    st.imports = imports;
    st.stats = stats;
    st.backfill_stats = backfill_stats;
    if let Some(b) = blob_refs {
        install_blob_refs(&mut st, b);
    }
    if let Some(b) = backlinks {
        st.backlinks.install(b);
    }
    st.backfill = backfill;
    Ok(Some(st))
}

/// Opens a repo's MST lazily: its `M/` range read ahead with one scan, the
/// root, and the paths `opts.need` visits. A root that isn't persisted (a
/// small repo's leaf root, or missing nodes) or a node that doesn't match its
/// link rebuilds the whole tree from the records (nothing is in flight
/// during a cold open, so `R/` is at the head); the bool tells the caller to
/// backfill `M/`.
async fn open_lazy(
    partition: &Arc<Partition>,
    did: &Arc<str>,
    gen: u64,
    head: &Head,
    opts: &LoadOpts,
) -> anyhow::Result<(LazyTree, bool)> {
    let _permit = LOAD_PERMITS.acquire().await?;
    let (pre, _) = crate::mst_store::prefetch(&*partition.db, did, gen, opts.prefetch_bytes).await?;
    let (db, did, root, need) = (partition.db.clone(), did.clone(), head.data, opts.need.clone().unwrap_or_default());
    let rt = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || -> anyhow::Result<(LazyTree, bool)> {
        let src = DbSource::new(&*db, &did, gen, &rt).with_prefetched(Some(&pre));
        let opened = LazyTree::open(root, 1, &src).and_then(|mut t| {
            need.load(&mut t, &*db, &did, gen, &rt)?;
            Ok(t)
        });
        let err = match opened {
            Ok(t) if t.stats.node_reads == 0 && t.tree.root.height >= 1 => "missing",
            Ok(t) => return Ok((t, false)),
            Err(crate::mst::MstError::Store(e)) => anyhow::bail!("lazy MST open: {e}"),
            Err(crate::mst::MstError::Invalid("persisted MST nodes missing")) => "missing_node",
            Err(e) => {
                tracing::warn!(%did, "lazy MST open failed ({e}): rebuilding from records");
                "invalid"
            }
        };
        metrics::LAZY_MST_FALLBACKS.with_label_values(&[err]).inc();
        let mut recs = Vec::new();
        src.records(None, None, &mut recs)?;
        let mut t = LazyTree::loaded(crate::mst_lazy::build_tree(&recs)?, 1);
        let r = t.tree.root_cid()?;
        anyhow::ensure!(r == root, "MST rebuilt from records {r} != head data {root}");
        Ok((t, true))
    })
    .await?
}

/// A DID without a repo whose earlier generations still await their sweep
/// (`G/`): loaded as a deleted repo, so the sweep's ops run on its worker,
/// ordered with a createAccount bringing the DID back.
async fn load_husk(partition: Arc<Partition>, did: Arc<str>) -> anyhow::Result<Option<RepoState>> {
    let Some(gv) = partition.db.get(state::import_key(&did)).await? else {
        return Ok(None);
    };
    let imports = state::ImportState::decode(&gv)?;
    let tree = Tree::new();
    let mut tree_c = tree.clone();
    let data = tree_c.root_cid()?;
    let head = Head { commit: data, data, rev: Tid(0), commit_block: Bytes::new() };
    let account = state::Account { did: did.to_string(), status: Some("deleted".into()), ..Default::default() };
    let mut st = finish_load(partition, did, LazyTree::loaded(tree, 1), head, None, account)?;
    st.imports = imports;
    st.blob_refs_loaded = true;
    st.backlinks.all = true;
    Ok(Some(st))
}

async fn load_blob_refs<R: slatedb::DbReadOps + Sync + ?Sized>(
    db: &R,
    did: &str,
    gen: u64,
) -> anyhow::Result<BlobRefs> {
    let prefix = state::blob_ref_prefix(did, gen);
    let mut iter = db.scan(prefix.clone()..state::prefix_end(&prefix)).await?;
    let mut out = BlobRefs::new();
    while let Some(kv) = iter.next().await? {
        let rest = std::str::from_utf8(&kv.key[prefix.len()..])?;
        let (cid, path) = rest.split_once('\0').ok_or_else(|| anyhow::anyhow!("bad blob ref key"))?;
        out.entry(path.to_string()).or_default().push(Cid::parse(cid)?);
    }
    Ok(out)
}

/// Paths written since the open keep their refs (which may not be durable
/// yet); every other path's durable refs are current, since only creates ran
/// without the map.
fn install_blob_refs(st: &mut RepoState, loaded: BlobRefs) {
    for (path, blobs) in loaded {
        st.blob_refs.entry(path).or_insert(blobs);
    }
    st.blob_refs_loaded = true;
    st.blob_cids.clear();
    for b in st.blob_refs.values().flatten() {
        *st.blob_cids.entry(*b).or_default() += 1;
    }
}

pub fn collection_of(path: &str) -> &str {
    path.split_once('/').map(|(c, _)| c).unwrap_or(path)
}

/// Bounds cold loads so a takeover doesn't stampede the object store.
static LOAD_PERMITS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(256);

fn finish_load(
    partition: Arc<Partition>,
    did: Arc<str>,
    mut mst: LazyTree,
    head: Head,
    key: Option<Arc<Keypair>>,
    account: state::Account,
) -> anyhow::Result<RepoState> {
    let root = mst.tree.root_cid()?;
    anyhow::ensure!(root == head.data, "rebuilt MST root {root} != head data {}", head.data);
    let nodes = crate::mst::SharedNodeIndex::default();
    let view = new_view(&head, account.repo_gen, &mst, &nodes);
    Ok(RepoState {
        did,
        partition,
        mst,
        head,
        key,
        pending: Arc::new(AtomicU32::new(0)),
        account,
        blob_refs: HashMap::new(),
        blob_refs_loaded: false,
        blob_cids: HashMap::new(),
        stats: Default::default(),
        view,
        nodes,
        charge: 0,
        heap: Default::default(),
        backlinks: Default::default(),
        fetching: false,
        backfill: false,
        backfill_stats: false,
        inflight: Default::default(),
        imports: Default::default(),
        spaces: Default::default(),
    })
}

// `with_label_values` hashes and locks on every call: resolve hot counters once.
static CACHE_HIT: LazyLock<IntCounter> = LazyLock::new(|| metrics::REPO_CACHE.with_label_values(&["hit"]));
static CACHE_MISS: LazyLock<IntCounter> = LazyLock::new(|| metrics::REPO_CACHE.with_label_values(&["miss"]));
static CACHE_LOADING: LazyLock<IntCounter> = LazyLock::new(|| metrics::REPO_CACHE.with_label_values(&["loading"]));
static OPS_CREATE: LazyLock<IntCounter> = LazyLock::new(|| metrics::OPS.with_label_values(&["create"]));
static OPS_UPDATE: LazyLock<IntCounter> = LazyLock::new(|| metrics::OPS.with_label_values(&["update"]));
static OPS_DELETE: LazyLock<IntCounter> = LazyLock::new(|| metrics::OPS.with_label_values(&["delete"]));

/// One commit's worth of coalesced writes.
#[derive(Default)]
struct Batch {
    /// Net change per path: (value before the batch, value after).
    ops: BTreeMap<String, (Option<Cid>, Option<Cid>)>,
    records: HashMap<Cid, Bytes>,
    record_bytes: usize,
    /// Blob refs of each path's latest value.
    blobs: HashMap<String, Vec<Cid>>,
    waiters: Vec<(WriteReply, Vec<WriteOutcome>)>,
    /// Whether each written collection had records before the batch.
    colls: BTreeMap<String, bool>,
    /// Set once the commit is applied; tags the backlink cache entries it
    /// writes.
    applied: Arc<std::sync::atomic::AtomicBool>,
    /// Backlink index values the batch changes, as they were before it.
    bl_init: BTreeMap<Box<[u8]>, crate::backlinks::Rkeys>,
    /// Link of each linked-collection path's latest value.
    links: HashMap<String, Option<Box<[u8]>>>,
}

impl Batch {
    fn is_empty(&self) -> bool {
        self.waiters.is_empty()
    }
}

fn valid_path_part(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 512
        && s != "."
        && s != ".."
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b".-_:~".contains(&b))
}

/// Coalesces a repo's queued requests into as few commits as possible.
fn process(
    st: &mut RepoState,
    reqs: Vec<Queued>,
    clock_id: u64,
    rt: &tokio::runtime::Handle,
) -> anyhow::Result<Leftover> {
    // `lazy_needs` loaded the paths before; the source reads only if an op
    // still finds one missing, on the worker thread (metered)
    let (part, did) = (st.partition.clone(), st.did.clone());
    let db_src = DbSource::new(&*part.db, &did, st.gen(), rt);
    let r = process_with(st, reqs, clock_id, &db_src);
    if db_src.reads.get() > 0 {
        metrics::LAZY_MST_FETCHES.with_label_values(&["inline"]).inc_by(db_src.reads.get());
    }
    r
}

fn key_unavailable(did: &str) -> WriteError {
    WriteError::KeyUnavailable(format!("signing key of {did} is unavailable (key service unreachable); retry"))
}

fn key_rotating(did: &str) -> WriteError {
    WriteError::KeyUnavailable(format!("signing key of {did} is being rotated; retry"))
}

/// An import's driver is staging the repo on this node. Its commit takes
/// the rev reserved at its start, so no other commit may come first; a
/// staged import whose driver is gone holds nothing up (it can no longer
/// commit, and the sweeper moves it to the garbage).
fn importing(st: &RepoState) -> bool {
    st.imports.staging.is_some_and(|s| crate::xrpc::staged_import::driving(&st.did, s.nonce))
}

fn import_in_progress() -> WriteError {
    WriteError::Invalid("a repo import is in progress; retry once it is done".into())
}

fn import_interrupted() -> WriteError {
    WriteError::Unavailable("the repo import was interrupted (its shard moved, or the account was deleted); nothing was imported: retry the import".into())
}

/// Every key under `gen` of the repo's generation families.
fn under_gen(did: &str, gen: u64, muts: &[Mutation]) -> bool {
    let prefixes: Vec<Vec<u8>> = state::GEN_FAMILIES.iter().map(|f| state::gen_prefix(f, did, gen)).collect();
    muts.iter().all(|m| prefixes.iter().any(|p| m.key.starts_with(p)))
}

/// An [`ImportStep`]: its entry's mutations and frames (`Ok(true)`), a
/// no-op (`Ok(false)`) or a refusal; a refused step changed nothing.
fn import_step(
    st: &mut RepoState,
    step: ImportStep,
    clock_id: u64,
    time: &str,
    frames: &mut Vec<events::Frame>,
    muts: &mut Vec<Mutation>,
) -> Result<bool, WriteError> {
    let epoch_ok = |st: &RepoState, nonce: u64, epoch: u64| {
        st.imports.staging.is_some_and(|s| s.nonce == nonce) && st.partition.epoch == epoch
    };
    match step {
        ImportStep::Begin { nonce, ticket } => {
            if let Some(status) = st.account.status.as_ref().filter(|s| *s != "deactivated") {
                return Err(if status == "deleted" {
                    WriteError::RepoNotFound
                } else {
                    WriteError::RepoInactive(status.clone())
                });
            }
            if st.account.pending_signing_key.is_some() {
                return Err(key_rotating(&st.did));
            }
            if st.key.is_none() {
                return Err(key_unavailable(&st.did));
            }
            let stale = st.imports.staging.map(|s| s.gen);
            if let Some(s) = st.imports.staging {
                if s.nonce != nonce && crate::xrpc::staged_import::driving(&st.did, s.nonce) {
                    return Err(import_in_progress());
                }
                st.imports.staging = None;
                st.imports.garbage.push(s.gen);
            }
            let gen = st.imports.next_gen(Some(st.gen()));
            let rev = tid::next_rev(Some(st.head.rev), clock_id);
            st.imports.staging = Some(state::Staging { gen, nonce, rev: rev.0 });
            muts.push(st.imports.mutation(&st.did));
            let _ = ticket.send(ImportTicket { gen, old_gen: st.gen(), rev, epoch: st.partition.epoch, stale });
            Ok(true)
        }
        ImportStep::Rows { nonce, epoch, muts: rows } => {
            if !epoch_ok(st, nonce, epoch) {
                return Err(import_interrupted());
            }
            let gen = st.imports.staging.map(|s| s.gen).unwrap_or_default();
            if !under_gen(&st.did, gen, &rows) {
                return Err(WriteError::Internal("staged import rows outside their generation".into()));
            }
            *muts = rows;
            Ok(true)
        }
        ImportStep::Commit { nonce, epoch, root, stats, colls_add, colls_del } => {
            if !epoch_ok(st, nonce, epoch) {
                return Err(import_interrupted());
            }
            if let Some(status) = st.account.status.as_ref().filter(|s| *s != "deactivated") {
                return Err(WriteError::RepoInactive(status.clone()));
            }
            if st.account.pending_signing_key.is_some() {
                return Err(key_rotating(&st.did));
            }
            let Some(key) = st.key.clone() else { return Err(key_unavailable(&st.did)) };
            let staged = st.imports.staging.expect("checked");
            let rev = Tid(staged.rev);
            if rev <= st.head.rev {
                return Err(import_interrupted());
            }
            let mut tree = Tree::new();
            if let Some(b) = root {
                let cid = Cid::dag_cbor(&b);
                match crate::mst_lazy::persisted_node(Arc::from(&b[..]), &cid, None) {
                    Ok(Some(n)) => tree.root = n,
                    Ok(None) => {}
                    Err(e) => return Err(WriteError::Internal(format!("staged import root: {e}"))),
                }
            }
            let data = tree.root_cid().map_err(|e| WriteError::Internal(e.to_string()))?;
            let (commit, commit_block) =
                sign_commit(&st.did, &rev.to_string(), &data, &key).map_err(|e| signature_fault(&e))?;
            let old_gen = st.gen();
            let mut account = st.account.clone();
            account.repo_gen = staged.gen;
            muts.push(account_mutation(&st.did, &account).map_err(|e| WriteError::Internal(e.to_string()))?);
            st.account = account;
            st.imports.staging = None;
            st.imports.garbage.push(old_gen);
            muts.push(st.imports.mutation(&st.did));
            for c in &colls_del {
                muts.push(del(state::collection_key(c, &st.did)));
            }
            for c in &colls_add {
                muts.push(put(state::collection_key(c, &st.did), Bytes::new()));
            }
            st.stats = stats;
            muts.push(put(state::repo_stats_key(&st.did), st.stats.encode()));
            st.head = Head { commit, data, rev, commit_block };
            muts.push(put(state::head_key(&st.did), st.head.encode()));
            // a deactivated account (mid-migration) is announced with #sync
            // when activated (reference importRepo sequences nothing)
            if st.account.status.is_none() {
                frames.push(sync_frame(&st.did, &st.head, time));
            }
            // nothing of the old generation is in memory any more
            st.mst = LazyTree::loaded(tree, 1);
            st.heap = Default::default();
            st.blob_refs = HashMap::new();
            st.blob_refs_loaded = false;
            st.blob_cids = HashMap::new();
            st.backlinks = Default::default();
            st.nodes = Default::default();
            st.inflight.clear();
            Ok(true)
        }
        ImportStep::Abort { nonce } => {
            let Some(s) = st.imports.staging.filter(|s| s.nonce == nonce) else { return Ok(false) };
            st.imports.staging = None;
            st.imports.garbage.push(s.gen);
            muts.push(st.imports.mutation(&st.did));
            Ok(true)
        }
        ImportStep::Sweep { gen, muts: dels } => {
            if !st.imports.garbage.contains(&gen) || gen == st.gen() && st.account.status.as_deref() != Some("deleted")
            {
                return Err(import_interrupted());
            }
            if !under_gen(&st.did, gen, &dels) || dels.iter().any(|m| m.val.is_some()) {
                return Err(WriteError::Internal("sweep outside its generation".into()));
            }
            *muts = dels;
            Ok(true)
        }
        ImportStep::Swept { gen } => {
            let n = st.imports.garbage.len();
            st.imports.garbage.retain(|g| *g != gen);
            if st.imports.garbage.len() == n {
                return Ok(false);
            }
            muts.push(st.imports.mutation(&st.did));
            Ok(true)
        }
    }
}

/// The requests left unprocessed: those after an import's commit, which
/// moved the repo to another generation (the loaded paths, the source's keys
/// and the needs computed for them were the old one's). The repo reloads
/// before they run.
pub(crate) type Leftover = Vec<Queued>;

fn process_with(st: &mut RepoState, reqs: Vec<Queued>, clock_id: u64, src: &dyn Source) -> anyhow::Result<Leftover> {
    let mut rest = reqs.into_iter();
    let r = process_reqs(st, &mut rest, clock_id, src);
    // after a signature fault the requests not reached yet weren't applied
    // either: answer them retryably rather than dropping them
    if let Err(e) = &r {
        if let Some(f) = e.downcast_ref::<crate::crypto::SignatureFault>() {
            for q in rest {
                q.fail(signature_fault(f));
            }
            return r.map(|_| Vec::new());
        }
    }
    r.map(|_| rest.collect())
}

/// Commits `batch`, if it holds anything, and starts a new one.
fn flush_pending(st: &mut RepoState, batch: &mut Batch, clock_id: u64, src: &dyn Source) -> anyhow::Result<()> {
    if batch.is_empty() {
        return Ok(());
    }
    flush(st, std::mem::take(batch), clock_id, src)
}

fn process_reqs(
    st: &mut RepoState,
    reqs: &mut std::vec::IntoIter<Queued>,
    clock_id: u64,
    src: &dyn Source,
) -> anyhow::Result<()> {
    let mut batch = Batch::default();
    for q in reqs {
        let mut req = match q {
            // abandoned by its handler (answered "not started"): drop it
            Queued::Write(r) if r.claim.as_ref().is_some_and(|c| !c.take()) => {
                metrics::WRITES_ABANDONED.inc();
                continue;
            }
            Queued::Write(r) => r,
            Queued::Snapshot(r) => {
                // a deleted repo's view keeps its old head over an empty
                // tree: there is no repo to read
                let deleted = st.account.status.as_deref() == Some("deleted");
                let _ = r.reply.send(if deleted { Err(WriteError::RepoNotFound) } else { Ok(st.view.clone()) });
                continue;
            }
            Queued::Space(r) => {
                process_space(st, r, clock_id)?;
                continue;
            }
            Queued::Account(a) => {
                flush_pending(st, &mut batch, clock_id, src)?;
                let gen = st.gen();
                apply_account(st, a, clock_id, src)?;
                if st.gen() != gen {
                    break;
                }
                continue;
            }
        };
        if let Some(status) = &st.account.status {
            let _ = req.reply.send(Err(WriteError::RepoInactive(status.clone())));
            continue;
        }
        if st.account.pending_signing_key.is_some() {
            let _ = req.reply.send(Err(key_rotating(&st.did)));
            continue;
        }
        if importing(st) {
            let _ = req.reply.send(Err(import_in_progress()));
            continue;
        }
        if st.key.is_none() {
            let _ = req.reply.send(Err(key_unavailable(&st.did)));
            continue;
        }
        if req.writes.len() > MAX_COMMIT_OPS {
            let _ = req.reply.send(Err(WriteError::Invalid(format!("too many writes (max {MAX_COMMIT_OPS})"))));
            continue;
        }
        if let Some(sc) = req.swap_commit {
            // swapCommit must be evaluated against a real commit boundary
            flush_pending(st, &mut batch, clock_id, src)?;
            if sc != st.head.commit {
                let _ = req.reply.send(Err(WriteError::InvalidSwap(format!("commit was at {}", st.head.commit))));
                continue;
            }
        }
        if req.writes.iter().any(|w| matches!(w, Write::Create { prune_backlinks: true, .. })) {
            let deletes = backlink_conflicts(st, &req.writes)?;
            req.writes.splice(0..0, deletes);
        }
        let paths: Vec<String> = req.writes.iter().map(Write::path).collect();
        let new_paths = paths.iter().filter(|p| !batch.ops.contains_key(*p)).collect::<HashSet<_>>().len();
        let incoming_bytes: usize = req
            .writes
            .iter()
            .map(|w| match w {
                Write::Create { bytes, .. } | Write::Update { bytes, .. } => bytes.len(),
                _ => 0,
            })
            .sum();
        if batch.ops.len() + new_paths > MAX_COMMIT_OPS || batch.record_bytes + incoming_bytes > MAX_COMMIT_RECORD_BYTES
        {
            flush_pending(st, &mut batch, clock_id, src)?;
        }
        if let Err(e) = validate(st, &req.writes, &paths, src) {
            let _ = req.reply.send(Err(e));
            continue;
        }
        let mut outcomes = Vec::with_capacity(req.writes.len());
        for (w, path) in req.writes.into_iter().zip(paths) {
            if !batch.colls.contains_key(collection_of(&path)) {
                let coll = collection_of(&path);
                let had = st.mst.has_prefix(format!("{coll}/").as_bytes(), src)?;
                batch.colls.insert(coll.to_string(), had);
            }
            match w {
                Write::Create { cid, bytes, blobs, .. } | Write::Update { cid, bytes, blobs, .. } => {
                    let prev = st.mst.insert(path.as_bytes(), cid, src)?;
                    if crate::backlinks::linked(collection_of(&path)) {
                        let link = crate::backlinks::link(collection_of(&path), &bytes);
                        apply_backlink(st, &mut batch, &path, prev.is_some(), link)?;
                    }
                    batch.ops.entry(path.clone()).or_insert((prev, None)).1 = Some(cid);
                    batch.blobs.insert(path.clone(), blobs);
                    batch.record_bytes += bytes.len();
                    batch.records.insert(cid, bytes);
                    outcomes.push(if prev.is_some() {
                        WriteOutcome::Update { path, cid }
                    } else {
                        WriteOutcome::Create { path, cid }
                    });
                }
                Write::Delete { .. } => {
                    let prev = st.mst.remove(path.as_bytes(), src)?;
                    if prev.is_some() {
                        if crate::backlinks::linked(collection_of(&path)) {
                            apply_backlink(st, &mut batch, &path, true, None)?;
                        }
                        batch.blobs.remove(&path);
                        batch.ops.entry(path).or_insert((prev, None)).1 = None;
                    }
                    outcomes.push(WriteOutcome::Delete);
                }
            }
        }
        batch.waiters.push((req.reply, outcomes));
    }
    flush_pending(st, &mut batch, clock_id, src)?;
    // what durable state holds again is read from it next time
    st.backlinks.prune();
    Ok(())
}

/// A space request ([`crate::space::repo`]): its own private log entry
/// (no frame), acked like a commit. The account's status is checked here,
/// in order with its takedowns and deactivations.
fn process_space(st: &mut RepoState, r: crate::space::repo::SpaceReq, clock_id: u64) -> anyhow::Result<()> {
    use crate::space::repo::{self as sr, SpaceAck, SpaceError, SpaceOp};
    let sr::SpaceReq { did, uri, sid, op, spaces, reply, permit } = r;
    drop(permit);
    let status = st.account.status.clone();
    if status.as_deref() == Some("deleted") {
        let _ = reply.send(Err(WriteError::RepoNotFound.into()));
        return Ok(());
    }
    let (muts, on_ack): (Vec<Mutation>, Box<dyn FnOnce() -> SpaceAck + Send>) = match op {
        SpaceOp::Write { writes } => {
            if let Some(s) = status {
                let _ = reply.send(Err(WriteError::RepoInactive(s).into()));
                return Ok(());
            }
            if spaces.import_nonce(&did, sid).is_some() {
                let m = "an import of this space repo is in progress; retry once it is done";
                let _ = reply.send(Err(WriteError::Invalid(m.into()).into()));
                return Ok(());
            }
            let applied = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let delivered = spaces.outbox.take_delivered(&did);
            let max = spaces.limits.max_records;
            let mut b = match sr::write(st.spaces_mut(), &did, sid, &uri, writes, clock_id, &applied, delivered, max) {
                Err(e) => {
                    // fetched again (and its rows looked for) next time
                    if matches!(e, SpaceError::Unswept(_)) {
                        st.spaces_mut().repos.remove(&sid);
                    }
                    let _ = reply.send(Err(e));
                    return Ok(());
                }
                Ok(Err(results)) => return space_noop(st, reply, SpaceAck::Write { rev: None, results }),
                Ok(Ok(b)) => b,
            };
            b.head.shard = st.partition.id;
            b.head.epoch = st.partition.epoch;
            let (head, notify, rev, results) = (Arc::new(b.head), b.notify, b.rev, b.results);
            let fanout = b.sequenced.map(|seq| crate::space::fanout::Job {
                authority: did.clone(),
                uri: uri.clone(),
                sid,
                writer: did.to_string(),
                repo_rev: rev,
                hash: head.hash.digest(),
                seq,
                epoch: st.partition.epoch,
            });
            let (sp, d) = (spaces.clone(), did.clone());
            let ack = move || {
                sp.heads.publish(&d, &sid, head);
                if let Some(n) = notify {
                    sp.outbox.enqueue(&d, sid, &n.uri, n.repo_rev, n.hash, true);
                }
                if let Some(job) = fanout {
                    sp.fanout.notify(job);
                }
                applied.store(true, Ordering::Release);
                SpaceAck::Write { rev: Some(rev), results }
            };
            (b.muts, Box::new(ack))
        }
        SpaceOp::RecordWriter { writer, repo_rev, hash, managing_app, same_rev } => {
            let r = sr::record_writer(
                st.spaces_mut(),
                &did,
                sid,
                &uri,
                &writer,
                repo_rev,
                hash,
                managing_app,
                same_rev,
                clock_id,
            );
            match r {
                Err(e) => {
                    let _ = reply.send(Err(e));
                    return Ok(());
                }
                Ok(None) => return space_noop(st, reply, SpaceAck::Writer(None)),
                Ok(Some((muts, seq))) => {
                    let job = crate::space::fanout::Job {
                        authority: did.clone(),
                        uri: uri.clone(),
                        sid,
                        writer,
                        repo_rev,
                        hash,
                        seq,
                        epoch: st.partition.epoch,
                    };
                    let sp = spaces.clone();
                    let ack = move || {
                        sp.fanout.notify(job);
                        SpaceAck::Writer(Some(seq))
                    };
                    (muts, Box::new(ack))
                }
            }
        }
        SpaceOp::ImportBegin { .. } | SpaceOp::ImportCommit { .. } if status.is_some() => {
            let _ = reply.send(Err(WriteError::RepoInactive(status.unwrap_or_default()).into()));
            return Ok(());
        }
        // the caller ends the claim if this fails
        SpaceOp::ImportBegin { nonce, rev } => {
            if !spaces.begin_import(&did, sid, nonce) {
                let m = "an import of this space repo is in progress";
                let _ = reply.send(Err(WriteError::Invalid(m.into()).into()));
                return Ok(());
            }
            match sr::import_begin(st.spaces_mut(), &did, sid, &uri, rev) {
                Err(e) => {
                    spaces.end_import(&did, sid, nonce);
                    let _ = reply.send(Err(e));
                    return Ok(());
                }
                Ok(None) => return space_noop(st, reply, SpaceAck::Host),
                Ok(Some(m)) => {
                    let (sp, d) = (spaces.clone(), did.clone());
                    let ack = move || {
                        sp.forget_space(&d, &sid);
                        SpaceAck::Host
                    };
                    (m, Box::new(ack))
                }
            }
        }
        SpaceOp::ImportCommit { nonce, rev, hash, records } => {
            if spaces.import_nonce(&did, sid) != Some(nonce) {
                let _ = reply.send(Err(SpaceError::Write(WriteError::Internal("space import not claimed".into()))));
                return Ok(());
            }
            let b = match sr::import_commit(st.spaces_mut(), &did, sid, &uri, rev, *hash, records, clock_id) {
                Ok(b) => b,
                Err(e) => {
                    let _ = reply.send(Err(e));
                    return Ok(());
                }
            };
            let mut head = b.head;
            (head.shard, head.epoch) = (st.partition.id, st.partition.epoch);
            let (head, notify) = (Arc::new(head), b.notify);
            let fanout = b.sequenced.map(|seq| crate::space::fanout::Job {
                authority: did.clone(),
                uri: uri.clone(),
                sid,
                writer: did.to_string(),
                repo_rev: rev,
                hash: head.hash.digest(),
                seq,
                epoch: st.partition.epoch,
            });
            let (sp, d) = (spaces.clone(), did.clone());
            let ack = move || {
                sp.heads.publish(&d, &sid, head);
                if let Some(n) = notify {
                    sp.outbox.enqueue(&d, sid, &n.uri, n.repo_rev, n.hash, true);
                }
                if let Some(job) = fanout {
                    sp.fanout.notify(job);
                }
                SpaceAck::Write { rev: Some(rev), results: Vec::new() }
            };
            (b.muts, Box::new(ack))
        }
        // the space host's management ops are the authority's own: refused
        // while its account is inactive
        SpaceOp::CreateSpace { .. }
        | SpaceOp::UpdateSpace { .. }
        | SpaceOp::PutMember { .. }
        | SpaceOp::RemoveMember { .. }
        | SpaceOp::DeleteSpace { .. }
            if status.is_some() =>
        {
            let _ = reply.send(Err(WriteError::RepoInactive(status.unwrap_or_default()).into()));
            return Ok(());
        }
        op => {
            let ss = st.spaces_mut();
            let r = match op {
                SpaceOp::CreateSpace { row } => {
                    sr::create_space(ss, &did, sid, row, clock_id).map(|m| (m, SpaceAck::Created))
                }
                SpaceOp::UpdateSpace { read_policy, write_policy, app_access } => {
                    sr::update_space(ss, &did, sid, read_policy, write_policy, app_access)
                        .map(|m| (m.into_iter().collect(), SpaceAck::Host))
                }
                SpaceOp::PutMember { member, access } => {
                    sr::set_member(ss, &did, sid, &member, Some(access)).map(|m| (vec![m], SpaceAck::Host))
                }
                SpaceOp::RemoveMember { member } => {
                    sr::set_member(ss, &did, sid, &member, None).map(|m| (vec![m], SpaceAck::Host))
                }
                SpaceOp::RegisterNotify { service, row } => {
                    sr::set_registration(ss, &did, sid, &service, Some(row), None)
                        .map(|m| (m.into_iter().collect(), SpaceAck::Host))
                }
                SpaceOp::UnregisterNotify { service, expired_by } => {
                    sr::set_registration(ss, &did, sid, &service, None, expired_by)
                        .map(|m| (m.into_iter().collect(), SpaceAck::Host))
                }
                SpaceOp::DeleteSpace { deleted_at } => match sr::delete_space(ss, &did, sid, &uri, deleted_at) {
                    Ok(Some(m)) => Ok((m, SpaceAck::Deleted { already: false })),
                    Ok(None) => Ok((Vec::new(), SpaceAck::Deleted { already: true })),
                    Err(e) => Err(e),
                },
                SpaceOp::Write { .. }
                | SpaceOp::RecordWriter { .. }
                | SpaceOp::ImportBegin { .. }
                | SpaceOp::ImportCommit { .. } => unreachable!("matched above"),
            };
            match r {
                Err(e) => {
                    let _ = reply.send(Err(e));
                    return Ok(());
                }
                Ok((muts, ack)) if muts.is_empty() => return space_noop(st, reply, ack),
                Ok((muts, SpaceAck::Deleted { already })) => {
                    let (sp, d) = (spaces.clone(), did.clone());
                    let ack = move || {
                        sp.forget_space(&d, &sid);
                        SpaceAck::Deleted { already }
                    };
                    (muts, Box::new(ack))
                }
                Ok((muts, ack)) => (muts, Box::new(move || ack)),
            }
        }
    };
    let entry = LogEntry {
        shard: st.partition.id,
        frames: Vec::new(),
        muts,
        ack: Some(Box::new(move |r| {
            let _ = reply.send(match r {
                Ok(()) => Ok(on_ack()),
                // refused by the log, nothing applied: the entry node resends
                Err(e) if e.to_string() == crate::nodelog::NOT_HELD => {
                    Err(SpaceError::Write(WriteError::Unavailable(e.to_string())))
                }
                Err(e) => Err(SpaceError::Write(WriteError::Internal(e.to_string()))),
            });
        })),
        pending: Some(st.pending.clone()),
        enqueued: Instant::now(),
        totals: None,
    };
    send_entry(st, entry)
}

/// Answers a space request that wrote nothing: at once with nothing in
/// flight, else after the repo's earlier entries, so a caller never learns
/// of state that isn't durable yet.
fn space_noop(
    st: &RepoState,
    reply: oneshot::Sender<Result<crate::space::repo::SpaceAck, crate::space::repo::SpaceError>>,
    ack: crate::space::repo::SpaceAck,
) -> anyhow::Result<()> {
    if st.pending.load(Ordering::Acquire) == 0 {
        let _ = reply.send(Ok(ack));
        return Ok(());
    }
    let entry = LogEntry {
        shard: st.partition.id,
        frames: Vec::new(),
        muts: Vec::new(),
        ack: Some(Box::new(move |r| {
            let _ = reply.send(r.map(|_| ack).map_err(|e| WriteError::Internal(e.to_string()).into()));
        })),
        pending: Some(st.pending.clone()),
        enqueued: Instant::now(),
        totals: None,
    };
    send_entry(st, entry)
}

/// Deletes of the records a `prune_backlinks` create among `writes`
/// conflicts with (same collection and subject). At most
/// `MAX_COMMIT_OPS - writes.len()`, oldest rkeys first, so the commit stays
/// within its op limit: the rest stay indexed and a later create for the
/// same subject prunes them.
fn backlink_conflicts(st: &mut RepoState, writes: &[Write]) -> anyhow::Result<Vec<Write>> {
    let mut deletes = Vec::new();
    let room = MAX_COMMIT_OPS.saturating_sub(writes.len());
    for w in writes {
        let Write::Create { collection, bytes, prune_backlinks: true, .. } = w else { continue };
        let Some(link) = crate::backlinks::link(collection, bytes) else { continue };
        let bl = &mut st.backlinks;
        let (rkeys, tag) =
            bl.vals.get(&link[..]).ok_or_else(|| anyhow::anyhow!("backlink index value of {} not loaded", st.did))?;
        for r in rkeys.iter().take(room - deletes.len()) {
            // the deleted record's link is this one
            bl.paths
                .entry(format!("{collection}/{r}").into())
                .or_insert_with(|| (Some(link.clone().into()), tag.clone()));
            deletes.push(Write::Delete { collection: collection.clone(), rkey: r.to_string(), swap: None });
        }
    }
    Ok(deletes)
}

/// Moves the record at `path` from its old link (`existed`: it held a
/// record) to `new` in the backlink cache, recording in `batch` the values
/// it changes.
fn apply_backlink(
    st: &mut RepoState,
    batch: &mut Batch,
    path: &str,
    existed: bool,
    new: Option<Vec<u8>>,
) -> anyhow::Result<()> {
    let bl = &mut st.backlinks;
    let did = &st.did;
    let old = match existed {
        true => bl.paths.get(path).ok_or_else(|| anyhow::anyhow!("backlink of {did} {path} not loaded"))?.0.clone(),
        false => None,
    };
    let new: Option<Box<[u8]>> = new.map(Into::into);
    let rkey = path.split_once('/').map_or(path, |(_, r)| r);
    let tag = Some(batch.applied.clone());
    fn value<'v>(
        vals: &'v mut HashMap<Box<[u8]>, (crate::backlinks::Rkeys, crate::backlinks::Tag)>,
        init: &mut BTreeMap<Box<[u8]>, crate::backlinks::Rkeys>,
        l: &[u8],
        tag: &crate::backlinks::Tag,
    ) -> anyhow::Result<&'v mut crate::backlinks::Rkeys> {
        let (v, t) = vals.get_mut(l).ok_or_else(|| anyhow::anyhow!("backlink index value not loaded"))?;
        init.entry(l.into()).or_insert_with(|| v.clone());
        *t = tag.clone();
        Ok(v)
    }
    if let Some(o) = old.as_ref().filter(|o| Some(*o) != new.as_ref()) {
        value(&mut bl.vals, &mut batch.bl_init, o, &tag)
            .map_err(|e| e.context(format!("{did} {path}")))?
            .retain(|r| &**r != rkey);
    }
    // the new link's value is visited even when unchanged: the commit's
    // derived put of it may need a stored one after it (flush)
    if let Some(n) = &new {
        let v = value(&mut bl.vals, &mut batch.bl_init, n, &tag).map_err(|e| e.context(format!("{did} {path}")))?;
        if let Err(i) = v.binary_search_by(|r| (**r).cmp(rkey)) {
            v.insert(i, rkey.into());
        }
    }
    batch.links.insert(path.to_string(), new.clone());
    bl.paths.insert(path.into(), (new, tag));
    Ok(())
}

/// Checks a request against the current tree (including earlier writes in
/// the batch) without mutating anything, so applyWrites stays atomic.
fn validate(st: &mut RepoState, writes: &[Write], paths: &[String], src: &dyn Source) -> Result<(), WriteError> {
    let mut overlay: HashMap<&str, Option<Cid>> = HashMap::new();
    for (w, path) in writes.iter().zip(paths) {
        let (coll, rkey) = w.parts();
        if !valid_path_part(coll) || !coll.contains('.') || !valid_path_part(rkey) {
            return Err(WriteError::Invalid(format!("invalid record path {coll}/{rkey}")));
        }
        let cur = match overlay.get(path.as_str()) {
            Some(v) => *v,
            None => st.mst.get(path.as_bytes(), src).map_err(|e| WriteError::Internal(e.to_string()))?,
        };
        let check_swap = |swap: &Option<Option<Cid>>| -> Result<(), WriteError> {
            match swap {
                Some(expected) if *expected != cur => Err(WriteError::InvalidSwap(format!(
                    "record was at {}",
                    cur.map(|c| c.to_string()).unwrap_or_else(|| "null".into())
                ))),
                _ => Ok(()),
            }
        };
        let new = match w {
            Write::Create { cid, .. } => {
                if cur.is_some() {
                    return Err(WriteError::Invalid(format!("record already exists: {path}")));
                }
                Some(*cid)
            }
            Write::Update { cid, swap, must_exist, .. } => {
                check_swap(swap)?;
                if *must_exist && cur.is_none() {
                    return Err(WriteError::Invalid(format!("Could not find a record with key: {path}")));
                }
                Some(*cid)
            }
            Write::Delete { swap, .. } => {
                check_swap(swap)?;
                None
            }
        };
        overlay.insert(path.as_str(), new);
    }
    Ok(())
}

/// Builds, signs and enqueues one commit for the batch.
fn flush(st: &mut RepoState, batch: Batch, clock_id: u64, src: &dyn Source) -> anyhow::Result<()> {
    let build_start = Instant::now();
    let gen = st.gen();
    let mut mst_blocks = Vec::with_capacity(16);
    let prev_data = st.head.data;
    let before = crate::totals::RepoKey::of(&st.account, &st.head);
    let mut coll_muts = Vec::new();
    for (coll, had) in &batch.colls {
        // only deletes from a collection that had records need the probe
        let put = batch.ops.iter().any(|(path, (_, new))| new.is_some() && collection_of(path) == coll);
        let has = put || (*had && st.mst.has_prefix(format!("{coll}/").as_bytes(), src)?);
        if has != *had {
            coll_muts.push(Mutation { key: state::collection_key(coll, &st.did).into(), val: has.then(Bytes::new) });
        }
    }
    // once getBlocks has asked for node blocks, report where written leaves
    // sit (interior nodes come from `M/`)
    let mut node_refs = st.nodes.lock().wanted.then(Vec::new);
    let (data, mut persist) = st.mst.write_diff_blocks_with_refs(&mut mst_blocks, node_refs.as_mut())?;
    // a batch that nets to no change leaves no dirty nodes, but the commit's
    // CAR must still carry the root node so it can be loaded and verified
    if !mst_blocks.iter().any(|(c, _)| *c == data) {
        let root = st.mst.tree.root_block()?;
        // replay derives a put of it from the CAR (an interior root)
        if st.mst.tree.root.height >= st.mst.persist_min() && !st.mst.tree.root.entries.is_empty() {
            persist.puts.push(root.clone());
        }
        mst_blocks.push(root);
    }
    let rev = tid::next_rev(Some(st.head.rev), clock_id);
    let rev_s = rev.to_string();
    let since_rev = st.head.rev;
    let since_s = since_rev.to_string();
    let key = st.key.as_deref().ok_or_else(|| anyhow::anyhow!("signing key unavailable"))?;
    let (commit, commit_block) = match sign_commit(&st.did, &rev_s, &data, key) {
        Ok(c) => c,
        Err(e) => {
            // the tree already holds the batch: the caller evicts the repo
            for (reply, _) in batch.waiters {
                let _ = reply.send(Err(signature_fault(&e)));
            }
            return Err(e.into());
        }
    };

    let stats_before = st.stats;
    st.stats.nodes = st.stats.nodes.saturating_add_signed(persist.node_delta);
    let (mut created_bytes, mut deleted) = (0u64, 0u64);
    let mut ops = Vec::with_capacity(batch.ops.len());
    let mut muts = Vec::with_capacity(batch.ops.len() + 1);
    // exact up to the varints: header ~60, each block varint + 36-byte CID
    let mut car_bytes = Vec::with_capacity(
        96 + commit_block.len()
            + mst_blocks.iter().map(|(_, b)| b.len() + 40).sum::<usize>()
            + batch.record_bytes
            + batch.records.len() * 40,
    );
    car::write_header(&mut car_bytes, &commit);
    car::write_block(&mut car_bytes, &commit, &commit_block);
    for (c, b) in &mst_blocks {
        car::write_block(&mut car_bytes, c, b);
    }
    // `muts` gets what replay rebuilds from the #commit frame
    // (segment::derive_commit_muts), `extra` the rest; the segment stores
    // only `extra`
    let mut extra = Vec::new();
    let mut derived_bl: HashMap<&[u8], &str> = HashMap::new();
    let mut written: HashSet<Cid> = HashSet::new();
    // what read-after-write needs (crate::recent_writes), applied at the ack
    let mut recent = Some(Vec::new());
    for (path, (prev, new)) in &batch.ops {
        if prev == new {
            continue;
        }
        match recent.as_mut() {
            Some(r) if r.len() < crate::recent_writes::MAX_RECS => {
                let bytes = new
                    .filter(|_| crate::recent_writes::keeps_bytes(path))
                    .map(|c| Bytes::copy_from_slice(&batch.records[&c]));
                r.push((Arc::<str>::from(path.as_str()), new.map(|c| (c, bytes))));
            }
            _ => recent = None,
        }
        let action = match (prev, new) {
            (None, Some(c)) => {
                st.stats.records += 1;
                created_bytes += batch.records[c].len() as u64;
                "create"
            }
            (Some(_), Some(_)) => "update",
            _ => {
                st.stats.records = st.stats.records.saturating_sub(1);
                deleted += 1;
                "delete"
            }
        };
        ops.push(RepoOp { action, path, cid: *new, prev: *prev });
        index_mutations(st, rev.0, path, prev.is_some(), new.is_some(), batch.blobs.get(path.as_str()), &mut extra)?;
        let key = Bytes::from(state::record_key(&st.did, gen, path));
        if let Some(p) = prev {
            muts.push(Mutation { key: state::record_cid_key(&st.did, gen, p, path).into(), val: None });
        }
        if let Some(c) = new {
            muts.push(Mutation { key: state::record_cid_key(&st.did, gen, c, path).into(), val: Some(Bytes::new()) });
        }
        match new {
            Some(c) => {
                let bytes = &batch.records[c];
                if written.insert(*c) {
                    car::write_block(&mut car_bytes, c, bytes);
                }
                muts.push(Mutation { key, val: Some(state::record_value(c, rev.0, bytes)) });
            }
            None => muts.push(Mutation { key, val: None }),
        }
        // the record's backlink, as if its subject had no other record
        // (replay derives it); `bl_init` below stores what differs
        if let (Some(_), Some(Some(l))) = (new, batch.links.get(path.as_str())) {
            let rkey = path.split_once('/').map_or(path.as_str(), |(_, r)| r);
            muts.push(Mutation {
                key: state::backlink_key(&st.did, gen, l).into(),
                val: Some(Bytes::copy_from_slice(rkey.as_bytes())),
            });
            derived_bl.insert(&l[..], rkey);
        }
    }
    // backlink index values the derived puts above don't leave as they are now
    for (l, before) in &batch.bl_init {
        let now = st
            .backlinks
            .vals
            .get(l)
            .map(|(v, _)| v)
            .ok_or_else(|| anyhow::anyhow!("backlink index value left the cache"))?;
        let as_derived = match derived_bl.get(&l[..]) {
            Some(r) => now.len() == 1 && &*now[0] == *r,
            None => now == before,
        };
        if !as_derived {
            extra.push(Mutation {
                key: state::backlink_key(&st.did, gen, l).into(),
                val: (!now.is_empty()).then(|| crate::backlinks::encode(now)),
            });
        }
    }
    let head = Head { commit, data, rev, commit_block };
    muts.push(Mutation { key: state::head_key(&st.did).into(), val: Some(head.encode()) });
    // `M/` holds exactly the interior nodes of the tree at `h/`: put the
    // commit's (derived from its CAR at replay), delete the replaced ones
    for (c, b) in std::mem::take(&mut persist.puts) {
        // exact-size: the memtable keeps the value's allocation, and encode
        // buffers are sized generously
        muts.push(Mutation {
            key: state::mst_node_key(&st.did, gen, &c).into(),
            val: Some(Bytes::from(b.into_boxed_slice())),
        });
    }
    for c in &persist.deletes {
        extra.push(Mutation { key: state::mst_node_key(&st.did, gen, c).into(), val: None });
    }
    extra.append(&mut coll_muts);
    // a commit that leaves the counts alone (updates) leaves the bytes too:
    // `S/` is written only when the counts change
    if st.stats.counts() != stats_before.counts() {
        if let Some(b) = st.stats.bytes.as_mut() {
            b.commit(&stats_before, created_bytes, deleted, persist.added_bytes, persist.gone);
        }
    }
    if st.stats != stats_before {
        extra.push(put(state::repo_stats_key(&st.did), st.stats.encode()));
    }
    let derived = muts.len();
    muts.append(&mut extra);

    let time = events::now_rfc3339();
    let mut frame = events::commit_frame(&events::CommitFrame {
        repo: &st.did,
        rev: &rev_s,
        since: Some(&since_s),
        commit,
        prev_data: Some(prev_data),
        blocks: &car_bytes,
        ops: &ops,
        time: &time,
    });
    frame.derived_muts = derived;
    frame.derived_gen = gen;
    #[cfg(debug_assertions)]
    {
        let mut f = Vec::new();
        frame.finish(0, &mut f);
        let d = crate::segment::derive_commit_muts_n(&f, derived, gen).expect("derive commit muts");
        assert!(
            d.len() == derived && d.iter().zip(&muts).all(|(a, b)| a.key == b.key && a.val == b.val),
            "muts derived from the #commit frame differ from the commit's"
        );
    }
    STATS.commits.fetch_add(1, Ordering::Relaxed);
    STATS.ops.fetch_add(ops.len() as u64, Ordering::Relaxed);
    metrics::COMMITS.inc();
    for op in &ops {
        match op.action {
            "create" => OPS_CREATE.inc(),
            "update" => OPS_UPDATE.inc(),
            _ => OPS_DELETE.inc(),
        }
        metrics::record_written(op.path, op.action);
    }
    metrics::COMMIT_OPS.observe(ops.len() as f64);
    metrics::COMMIT_REQUESTS.observe(batch.waiters.len() as f64);
    metrics::COMMIT_BLOCKS_BYTES.observe(car_bytes.len() as f64);
    metrics::COMMIT_BUILD.observe(build_start.elapsed().as_secs_f64());
    if let Some(refs) = node_refs {
        st.nodes.lock().commit(st.head.rev.0, head.rev.0, refs);
    }
    st.head = head;
    let applied = track_inflight(st, Some(mst_blocks.iter().map(|(c, _)| *c).collect()), batch.applied.clone());

    let waiters = batch.waiters;
    let (view, snap) = (st.view.clone(), st.durable_view());
    let recent = crate::recent_writes::Commit {
        did: st.did.clone(),
        part: (st.partition.id, st.partition.epoch),
        since: since_rev.0,
        rev: rev.0,
        prev_nonempty: prev_data != *crate::recent_writes::EMPTY_ROOT,
        ops: recent,
    };
    let entry = LogEntry {
        shard: st.partition.id,
        frames: vec![frame],
        muts,
        ack: Some(Box::new(move |r| {
            if r.is_ok() {
                let old = std::mem::replace(&mut *view.write(), snap);
                retire_view(old);
                // before the replies: the writer's next read sees it
                recent.apply();
            }
            applied.store(true, Ordering::Release);
            for (reply, results) in waiters {
                let _ = reply.send(match &r {
                    Ok(()) => Ok(CommitAck { commit, rev, results }),
                    Err(e) => Err(WriteError::Internal(e.to_string())),
                });
            }
        })),
        pending: Some(st.pending.clone()),
        enqueued: Instant::now(),
        totals: crate::totals::Delta::new(&st.did, before, crate::totals::RepoKey::of(&st.account, &st.head)),
    };
    send_entry(st, entry)
}

/// Counts the entry as in flight for the repo and hands it to the node log.
fn send_entry(st: &RepoState, entry: LogEntry) -> anyhow::Result<()> {
    st.pending.fetch_add(1, Ordering::AcqRel);
    st.partition.tx.blocking_send(entry).map_err(|e| {
        // never logged: it must not hold the repo out of reloads (see `draining`)
        if let Some(p) = &e.0.pending {
            p.fetch_sub(1, Ordering::AcqRel);
        }
        anyhow::anyhow!("partition sequencer gone")
    })
}

/// Blob-ref index mutations for one net op. `existed`: the path held a
/// record before, whose refs are known only once the repo's are loaded.
fn index_mutations(
    st: &mut RepoState,
    rev: u64,
    path: &str,
    existed: bool,
    exists: bool,
    new_blobs: Option<&Vec<Cid>>,
    muts: &mut Vec<Mutation>,
) -> anyhow::Result<()> {
    anyhow::ensure!(!existed || st.blob_refs_loaded, "blob refs of {} not loaded for a write to {path}", st.did);
    anyhow::ensure!(
        st.blob_refs_loaded || new_blobs.is_none_or(|b| b.is_empty()),
        "blob refs of {} not loaded for a write adding refs to {path}",
        st.did
    );
    let gen = st.gen();
    let old = st.blob_refs.remove(path).unwrap_or_default();
    let mut new: Vec<Cid> = if exists { new_blobs.cloned().unwrap_or_default() } else { Vec::new() };
    new.sort();
    new.dedup();
    for b in old.iter().filter(|b| !new.contains(b)) {
        muts.push(del(state::blob_ref_key(&st.did, gen, b, path)));
        if let Some(n) = st.blob_cids.get_mut(b) {
            *n -= 1;
            if *n == 0 {
                st.blob_cids.remove(b);
                st.stats.blobs = st.stats.blobs.saturating_sub(1);
            }
        }
    }
    for b in new.iter().filter(|b| !old.contains(b)) {
        let n = st.blob_cids.entry(*b).or_default();
        *n += 1;
        if *n == 1 {
            st.stats.blobs += 1;
        }
    }
    // rewrite every current ref with the record's rev, so listBlobs `since`
    // sees blobs kept across an update too
    for b in new.iter() {
        muts.push(put(state::blob_ref_key(&st.did, gen, b, path), Bytes::copy_from_slice(&rev.to_be_bytes())));
    }
    if !new.is_empty() {
        st.blob_refs.insert(path.to_string(), new);
    }
    Ok(())
}

/// Acks an account op that wrote nothing: at once with nothing in flight,
/// else through an empty log entry, so the ack follows the repo's earlier
/// entries in log order and a caller can rely on those being durable.
fn ack_noop(st: &RepoState, reply: oneshot::Sender<Result<Head, WriteError>>) -> anyhow::Result<()> {
    if st.pending.load(Ordering::Acquire) == 0 {
        let _ = reply.send(Ok(st.head.clone()));
        return Ok(());
    }
    let entry = LogEntry {
        shard: st.partition.id,
        frames: Vec::new(),
        muts: Vec::new(),
        ack: Some(head_ack(reply, st.head.clone())),
        pending: Some(st.pending.clone()),
        enqueued: Instant::now(),
        totals: None,
    };
    send_entry(st, entry)
}

fn head_ack(reply: oneshot::Sender<Result<Head, WriteError>>, head: Head) -> crate::partition::AckFn {
    Box::new(move |r| {
        let _ = reply.send(r.map(|_| head).map_err(|e| WriteError::Internal(e.to_string())));
    })
}

/// Mutations deleting every record (and its index entries) in the repo.
/// Loads the rest of its tree if the fetch before the op didn't, and
/// returns its persisted (interior) nodes, whose `M/` keys the caller
/// deletes or keeps.
fn clear_repo_mutations(
    st: &mut RepoState,
    muts: &mut Vec<Mutation>,
    src: &dyn Source,
) -> anyhow::Result<HashMap<Cid, Arc<[u8]>>> {
    if !st.mst.fully_loaded() {
        st.mst.load_all(src)?;
    }
    anyhow::ensure!(st.blob_refs_loaded, "blob refs of {} not loaded to clear them", st.did);
    let (did, gen) = (st.did.clone(), st.gen());
    let mut colls = std::collections::BTreeSet::new();
    st.mst.tree.walk(&mut |k, cid| {
        if let Ok(path) = std::str::from_utf8(k) {
            muts.push(del(state::record_key(&did, gen, path)));
            muts.push(del(state::record_cid_key(&did, gen, &cid, path)));
            if !colls.contains(collection_of(path)) {
                colls.insert(collection_of(path).to_string());
            }
        }
    });
    for coll in &colls {
        muts.push(del(state::collection_key(coll, &did)));
    }
    for (path, blobs) in &st.blob_refs {
        for b in blobs {
            muts.push(del(state::blob_ref_key(&did, gen, b, path)));
        }
    }
    st.blob_refs.clear();
    st.blob_cids.clear();
    st.stats = state::RepoStats::default();
    Ok(crate::mst_lazy::persisted_nodes(&st.mst.tree, st.mst.persist_min()))
}

/// Mutations deleting the repo's whole backlink index; the cache says so
/// until `done` (the clearing entry) is applied.
fn clear_backlinks(
    st: &mut RepoState,
    muts: &mut Vec<Mutation>,
    done: &Arc<std::sync::atomic::AtomicBool>,
) -> anyhow::Result<()> {
    anyhow::ensure!(st.backlinks.all, "backlink index of {} not loaded to clear it", st.did);
    let gen = st.gen();
    for (l, (v, t)) in st.backlinks.vals.iter_mut() {
        if !v.is_empty() {
            muts.push(del(state::backlink_key(&st.did, gen, l)));
            v.clear();
            *t = Some(done.clone());
        }
    }
    st.backlinks.paths.clear();
    Ok(())
}

/// The backlink index of a whole repo's `records` (path, bytes): its puts,
/// and the cache entries (tagged `tag`: durable state may not have them).
fn index_backlinks<'a>(
    did: &str,
    gen: u64,
    records: impl Iterator<Item = (&'a str, &'a [u8])>,
    cache: &mut crate::backlinks::Cache,
    tag: &crate::backlinks::Tag,
    muts: &mut Vec<Mutation>,
) {
    let mut vals: BTreeMap<Vec<u8>, crate::backlinks::Rkeys> = BTreeMap::new();
    for (path, bytes) in records {
        let coll = collection_of(path);
        if !crate::backlinks::linked(coll) {
            continue;
        }
        let link = crate::backlinks::link(coll, bytes);
        if let Some(l) = &link {
            vals.entry(l.clone()).or_default().push(path[coll.len() + 1..].into());
        }
        cache.paths.insert(path.into(), (link.map(Into::into), tag.clone()));
    }
    for (l, mut rkeys) in vals {
        rkeys.sort();
        muts.push(put(state::backlink_key(did, gen, &l), crate::backlinks::encode(&rkeys)));
        cache.vals.insert(l.into(), (rkeys, tag.clone()));
    }
}

/// `M/` mutations replacing a repo's persisted nodes `old` by those of the
/// fully loaded `tree`.
fn replace_nodes_mutations(did: &str, gen: u64, old: HashMap<Cid, Arc<[u8]>>, tree: &Tree, muts: &mut Vec<Mutation>) {
    let new = crate::mst_lazy::persisted_nodes(tree, 1);
    for c in old.keys().filter(|c| !new.contains_key(c)) {
        muts.push(del(state::mst_node_key(did, gen, c)));
    }
    for (c, b) in new {
        muts.push(put(state::mst_node_key(did, gen, &c), Bytes::copy_from_slice(&b)));
    }
}

/// Runs `mutate` on a copy of the current account: None = nothing changed.
fn mutate_account(st: &RepoState, mutate: AccountMutation) -> Result<Option<state::Account>, WriteError> {
    if st.account.status.as_deref() == Some("deleted") {
        return Err(WriteError::RepoNotFound);
    }
    let mut next = st.account.clone();
    Ok(mutate(&mut next)?.then_some(next))
}

fn account_mutation(did: &str, account: &state::Account) -> anyhow::Result<Mutation> {
    Ok(put(state::account_key(did), Bytes::from(serde_json::to_vec(account)?)))
}

/// `D/{did}` as the account says. A deletion leaves the row: the sweep
/// finds the deletion's leftovers through it.
fn delete_after_mutation(did: &str, account: &state::Account) -> Mutation {
    match account.extra.get("deleteAfter").and_then(|v| v.as_str()) {
        Some(t) => put(state::delete_after_key(did), Bytes::copy_from_slice(t.as_bytes())),
        None => del(state::delete_after_key(did)),
    }
}

fn apply_account(st: &mut RepoState, req: AccountReq, clock_id: u64, src: &dyn Source) -> anyhow::Result<()> {
    let time = events::now_rfc3339();
    let mut frames = Vec::new();
    let mut muts = Vec::new();
    let before = crate::totals::Counted::of(&st.account, &st.head);
    let whole_tree = matches!(req.op, AccountOp::ReplaceRepo { .. } | AccountOp::Delete { .. });
    let new_repo = whole_tree || matches!(req.op, AccountOp::Import(ImportStep::Commit { .. }));
    let gen = st.gen();
    // a re-signed head (KeyStep::Finish) extends read-after-write's log at the ack
    let mut resigned: Option<crate::recent_writes::Commit> = None;
    // tags the backlink cache entries a whole-tree op writes
    let done: Arc<std::sync::atomic::AtomicBool> = Default::default();
    let refuse = |reply: oneshot::Sender<Result<Head, WriteError>>, e: WriteError| {
        let _ = reply.send(Err(e));
        Ok(())
    };
    // a staged import's commit takes the rev it reserved: nothing else may
    // sign a commit first
    if matches!(
        req.op,
        AccountOp::ReplaceRepo { .. } | AccountOp::SigningKey(KeyStep::Begin(_) | KeyStep::Finish { .. })
    ) && importing(st)
    {
        return refuse(req.reply, import_in_progress());
    }
    match req.op {
        AccountOp::Import(step) => match import_step(st, step, clock_id, &time, &mut frames, &mut muts) {
            Ok(true) => {}
            Ok(false) => return ack_noop(st, req.reply),
            Err(e) => return refuse(req.reply, e),
        },
        AccountOp::Update { mutate, identity_event, account_event } => {
            let account = match mutate_account(st, mutate) {
                Ok(Some(a)) => a,
                Ok(None) => return ack_noop(st, req.reply),
                Err(e) => return refuse(req.reply, e),
            };
            if account.handle != st.account.handle {
                muts.push(del(state::handle_key(&st.did, &st.account.handle)));
                muts.push(put(state::handle_key(&st.did, &account.handle), Bytes::from(st.did.to_string())));
            }
            muts.push(account_mutation(&st.did, &account)?);
            if identity_event {
                frames.push(events::identity_frame(&st.did, &account.handle, &time));
            }
            if account_event {
                frames.push(events::account_frame(&st.did, account.status.is_none(), account.status.as_deref(), &time));
            }
            // admin.updateAccountSigningKey: the row holds only the wrapped
            // key, so drop ours and the worker reloads the repo, finding the
            // new key in the keyring's cache. A rewrap under a new KEK keeps
            // the key.
            if account.signing_pubkey != st.account.signing_pubkey {
                st.key = None;
            }
            st.account = account;
        }
        AccountOp::Activate { mutate } => {
            let account = match mutate_account(st, mutate) {
                Ok(Some(a)) => a,
                Ok(None) => return ack_noop(st, req.reply),
                Err(e) => return refuse(req.reply, e),
            };
            muts.push(account_mutation(&st.did, &account)?);
            frames.push(events::account_frame(&st.did, account.status.is_none(), account.status.as_deref(), &time));
            frames.push(events::identity_frame(&st.did, &account.handle, &time));
            frames.push(sync_frame(&st.did, &st.head, &time));
            st.account = account;
        }
        AccountOp::ReplaceRepo { records, swap_commit, stale_keys, tree: prebuilt } => {
            if let Some(swap) = swap_commit.filter(|c| *c != st.head.commit) {
                return refuse(
                    req.reply,
                    WriteError::InvalidSwap(format!("head commit is {}, not {swap}", st.head.commit)),
                );
            }
            // first: a stale key the replace writes again ends up written
            muts.extend(stale_keys.into_iter().map(|key| Mutation { key, val: None }));
            // deactivated accounts may import (the migration flow); others may not
            if let Some(status) = st.account.status.as_ref().filter(|s| *s != "deactivated") {
                return refuse(req.reply, WriteError::RepoInactive(status.clone()));
            }
            if st.account.pending_signing_key.is_some() {
                return refuse(req.reply, key_rotating(&st.did));
            }
            let Some(key) = st.key.clone() else { return refuse(req.reply, key_unavailable(&st.did)) };
            let old_nodes = clear_repo_mutations(st, &mut muts, src)?;
            clear_backlinks(st, &mut muts, &done)?;
            let rev = tid::next_rev(Some(st.head.rev), clock_id);
            let build = prebuilt.is_none();
            let mut tree = prebuilt.unwrap_or_default();
            let mut colls = HashSet::new();
            for (path, cid, bytes, blobs) in &records {
                if colls.insert(collection_of(path)) {
                    muts.push(put(state::collection_key(collection_of(path), &st.did), Bytes::new()));
                }
                if build {
                    tree.insert_no_proof(path.as_bytes(), *cid)?;
                }
                muts.push(put(state::record_key(&st.did, gen, path), state::record_value(cid, rev.0, bytes)));
                muts.push(put(state::record_cid_key(&st.did, gen, cid, path), Bytes::new()));
                index_mutations(st, rev.0, path, false, true, Some(blobs), &mut muts)?;
            }
            // after the clear's deletes: a link kept is written again
            index_backlinks(
                &st.did,
                gen,
                records.iter().map(|(p, _, b, _)| (p.as_str(), &b[..])),
                &mut st.backlinks,
                &Some(done.clone()),
                &mut muts,
            );
            let data = tree.root_cid()?;
            let record_bytes = records.iter().map(|(_, _, b, _)| b.len() as u64).sum();
            let counted = crate::repo_stats::of_tree(&tree, record_bytes, 0)?;
            replace_nodes_mutations(&st.did, gen, old_nodes, &tree, &mut muts);
            let (commit, commit_block) = match sign_commit(&st.did, &rev.to_string(), &data, &key) {
                Ok(c) => c,
                Err(e) => {
                    // nothing sequenced; evict (the import's reads loaded the tree)
                    let _ = req.reply.send(Err(signature_fault(&e)));
                    return Err(e.into());
                }
            };
            st.stats = state::RepoStats { blobs: st.stats.blobs, ..counted };

            muts.push(put(state::repo_stats_key(&st.did), st.stats.encode()));
            st.mst = LazyTree::loaded(tree, 1);
            st.head = Head { commit, data, rev, commit_block };
            // a deactivated account (mid-migration) is announced with #sync
            // when activated (reference importRepo sequences nothing)
            if st.account.status.is_none() {
                frames.push(sync_frame(&st.did, &st.head, &time));
            }
            muts.push(put(state::head_key(&st.did), st.head.encode()));
        }
        AccountOp::SetStats { stats, at_rev } => {
            if st.head.rev.0 != at_rev {
                let e = format!("head rev is {}, not the one counted at; run it again", st.head.rev);
                return refuse(req.reply, WriteError::InvalidSwap(e));
            }
            st.stats = stats;
            muts.push(put(state::repo_stats_key(&st.did), st.stats.encode()));
        }
        AccountOp::Delete { only_if } => {
            if let Some(Err(e)) = only_if.map(|check| check(&st.account)) {
                return refuse(req.reply, e);
            }

            let old_nodes = clear_repo_mutations(st, &mut muts, src)?;
            clear_backlinks(st, &mut muts, &done)?;
            for c in old_nodes.keys() {
                muts.push(del(state::mst_node_key(&st.did, gen, c)));
            }
            st.mst = LazyTree::loaded(Tree::new(), 1);
            muts.push(del(state::head_key(&st.did)));
            muts.push(del(state::account_key(&st.did)));
            muts.push(del(state::handle_key(&st.did, &st.account.handle)));
            muts.push(del(state::repo_stats_key(&st.did)));
            // a staged import's rows are left to the sweeper
            if let Some(s) = st.imports.staging.take() {
                st.imports.garbage.push(s.gen);
                muts.push(st.imports.mutation(&st.did));
            }
            frames.push(events::account_frame(&st.did, false, Some("deleted"), &time));
            st.account.status = Some("deleted".into());
        }
        AccountOp::SigningKey(step) => match key_step(st, step, clock_id, &time, &mut frames, &mut muts)? {
            KeyOutcome::Noop => return ack_noop(st, req.reply),
            KeyOutcome::Refused(e) => return refuse(req.reply, e),
            KeyOutcome::Written(c) => resigned = c,
        },
    }
    let account_key = state::account_key(&st.did);
    if muts.iter().any(|m| m.key == account_key && m.val.is_some()) {
        muts.push(delete_after_mutation(&st.did, &st.account));
    }
    let applied = whole_tree.then(|| track_inflight(st, None, done));
    let inner = head_ack(req.reply, st.head.clone());
    let (view, snap) = (st.view.clone(), st.durable_view());
    let did = st.did.clone();
    let entry = LogEntry {
        shard: st.partition.id,
        frames,
        muts,
        ack: Some(Box::new(move |r| {
            if r.is_ok() {
                *view.write() = snap;
                if let Some(c) = resigned {
                    c.apply();
                }
            }
            if let Some(a) = applied {
                a.store(true, Ordering::Release);
            }
            // acks follow the state apply: drop cached copies of the
            // account (status, signing key)
            crate::xrpc::proxy::account_changed(&did);
            if new_repo {
                crate::recent_writes::invalidate(&did);
            }
            inner(r)
        })),
        pending: Some(st.pending.clone()),
        enqueued: Instant::now(),
        totals: crate::totals::Delta::account(&st.did, before, crate::totals::Counted::of(&st.account, &st.head)),
    };
    send_entry(st, entry)
}

/// Applies a [`KeyStep`] to the repo.
fn key_step(
    st: &mut RepoState,
    step: KeyStep,
    clock_id: u64,
    time: &str,
    frames: &mut Vec<events::Frame>,
    muts: &mut Vec<Mutation>,
) -> anyhow::Result<KeyOutcome> {
    if st.account.status.as_deref() == Some("deleted") {
        return Ok(KeyOutcome::Refused(WriteError::RepoNotFound));
    }
    let mut account = st.account.clone();
    let mut resigned = None;
    let finish = matches!(step, KeyStep::Finish { .. });
    match step {
        KeyStep::Begin(p) => {
            match &account.pending_signing_key {
                Some(cur) if *cur == p => return Ok(KeyOutcome::Noop),
                Some(_) => {
                    return Ok(KeyOutcome::Refused(WriteError::Invalid(
                        "a signing key rotation is already in progress".into(),
                    )))
                }
                None if p.pubkey == account.signing_pubkey => {
                    return Ok(KeyOutcome::Refused(WriteError::Invalid(
                        "that is already the account's signing key".into(),
                    )))
                }
                None => {}
            }
            account.pending_signing_key = Some(p);
        }
        KeyStep::Abort { pubkey } => {
            if account.pending_signing_key.as_ref().is_none_or(|p| p.pubkey != pubkey) {
                return Ok(KeyOutcome::Noop);
            }
            account.pending_signing_key = None;
        }
        KeyStep::Finish { key } | KeyStep::Resign { key } => {
            let pubkey = key.public_multibase();
            match (account.pending_signing_key.take(), finish) {
                (Some(p), true) if p.pubkey == pubkey => {
                    account.wrapped_signing_key = p.wrapped;
                    account.signing_pubkey = p.pubkey;
                }
                // finished already
                (None, true) if account.signing_pubkey == pubkey => return Ok(KeyOutcome::Noop),
                (None, false) if account.signing_pubkey == pubkey => {}
                (Some(_), _) => {
                    return Ok(KeyOutcome::Refused(WriteError::Invalid("a signing key rotation is in progress".into())))
                }
                (None, _) => {
                    return Ok(KeyOutcome::Refused(WriteError::Invalid(
                        "not the account's signing key or its pending one".into(),
                    )))
                }
            }
            // the empty commit: same data root, new rev, signed with the new key
            let rev = tid::next_rev(Some(st.head.rev), clock_id);
            let (commit, commit_block) = match sign_commit(&st.did, &rev.to_string(), &st.head.data, &key) {
                Ok(c) => c,
                Err(e) => return Ok(KeyOutcome::Refused(signature_fault(&e))),
            };
            let since = st.head.rev;
            let head = Head { commit, data: st.head.data, rev, commit_block };
            muts.push(put(state::head_key(&st.did), head.encode()));
            frames.push(events::identity_frame(&st.did, &account.handle, time));
            if account.status.is_none() {
                frames.push(sync_frame(&st.did, &head, time));
            }
            {
                // no MST node changed: the node index just moves to the new rev
                let mut nodes = st.nodes.lock();
                if nodes.wanted {
                    nodes.commit(since.0, rev.0, Vec::new());
                }
            }
            resigned = Some(crate::recent_writes::Commit {
                did: st.did.clone(),
                part: (st.partition.id, st.partition.epoch),
                since: since.0,
                rev: rev.0,
                prev_nonempty: st.head.data != *crate::recent_writes::EMPTY_ROOT,
                ops: Some(Vec::new()),
            });
            st.head = head;
            st.key = Some(key);
        }
    }
    muts.push(account_mutation(&st.did, &account)?);
    st.account = account;
    Ok(KeyOutcome::Written(resigned))
}

fn put(key: impl Into<Bytes>, val: Bytes) -> Mutation {
    Mutation { key: key.into(), val: Some(val) }
}

fn del(key: impl Into<Bytes>) -> Mutation {
    Mutation { key: key.into(), val: None }
}

/// The #sync frame of `head`: its commit block as a one-block CAR.
fn sync_frame(did: &str, head: &Head, time: &str) -> events::Frame {
    let mut car_bytes = Vec::with_capacity(head.commit_block.len() + 64);
    car::write_header(&mut car_bytes, &head.commit);
    car::write_block(&mut car_bytes, &head.commit, &head.commit_block);
    events::sync_frame(did, &head.rev.to_string(), &car_bytes, time)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nodelog::{NodeLog, NodeLogConfig};

    #[test]
    fn an_abandoned_claim_frees_its_permit_at_once() {
        let sem = Arc::new(tokio::sync::Semaphore::new(1));
        let c = Claim::holding(sem.clone().try_acquire_owned().unwrap());
        assert!(c.abandon());
        assert_eq!(sem.available_permits(), 1, "freed while the queued copy still holds the claim");
        let c = Claim::holding(sem.clone().try_acquire_owned().unwrap());
        assert!(c.take());
        assert!(!c.abandon());
        assert_eq!(sem.available_permits(), 0, "a taken write keeps it until consumed");
        drop(c);
        assert_eq!(sem.available_permits(), 1);
    }

    fn settle(e: LogEntry) {
        if let Some(p) = e.pending {
            p.fetch_sub(1, Ordering::AcqRel);
        }
        if let Some(ack) = e.ack {
            ack(Ok(()));
        }
    }

    fn write(did: &Arc<str>, rkey: &str) -> (WorkerMsg, oneshot::Receiver<Result<CommitAck, WriteError>>) {
        let bytes = Bytes::from(format!("record {rkey}"));
        let (reply, rx) = oneshot::channel();
        let w = Write::Create {
            collection: "app.test.thing".into(),
            rkey: rkey.into(),
            cid: Cid::dag_cbor(&bytes),
            bytes,
            blobs: Vec::new(),
            prune_backlinks: false,
        };
        (
            WorkerMsg::Write(WriteReq {
                did: did.clone(),
                writes: vec![w],
                swap_commit: None,
                reply,
                claim: None,
                permit: None,
            }),
            rx,
        )
    }

    /// A commit that fails while an earlier one is still in flight must not
    /// reload the repo before that one is durable: the reload would build on
    /// a durable head without it (a fork).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn failed_commit_waits_for_inflight_before_reload() {
        // the "sequencer" is this test: it decides when entries become durable
        let (part, mut rx) = test_partition().await;
        let p2 = part.clone();
        let workers = spawn(1, 100, Arc::new(move |_: &str| Some(p2.clone())), tokio::runtime::Handle::current());
        drop(part);
        let w = workers.senders[0].clone();
        let did: Arc<str> = "did:plc:test".into();
        let key = Arc::new(Keypair::generate());
        let account = serde_json::json!({
            "did": &*did, "handle": "t.test", "wrapped_signing_key": Secrets::dev().wrap_signing_key(&did, &key).await.unwrap().0, "signing_pubkey": key.public_multibase(),
            "password_hash": "", "created_at": "2026-01-01T00:00:00Z",
        });
        let (reply, created) = oneshot::channel();
        w.send(WorkerMsg::CreateRepo(CreateRepoReq {
            did: did.clone(),
            handle: "t.test".into(),
            key,
            account_json: Bytes::from(serde_json::to_vec(&account).unwrap()),
            records: Vec::new(),
            reply,
        }))
        .unwrap();
        settle(rx.recv().await.unwrap());
        created.await.unwrap().unwrap();
        // commit 1: in flight, not durable yet
        let (m, first) = write(&did, "a");
        w.send(m).unwrap();
        let inflight = rx.recv().await.unwrap();
        // commit 2 fails (the log intake is gone)
        drop(rx);
        let (m, second) = write(&did, "b");
        w.send(m).unwrap();
        assert!(second.await.is_err());
        // a later write must wait for commit 1 instead of reloading now
        let (m, mut third) = write(&did, "c");
        w.send(m).unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(third.try_recv().is_err(), "repo reloaded with a commit in flight");
        settle(inflight);
        first.await.unwrap().unwrap();
        // now it reloads (from a state that never got the commits applied here)
        let r = tokio::time::timeout(Duration::from_secs(5), third).await.unwrap().unwrap();
        assert!(r.is_err());
    }

    /// A write its handler abandoned before the worker took it (a forwarded
    /// write answered RepoLoading) is never applied; one with a live claim is.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn abandoned_writes_are_not_applied() {
        let (part, mut rx) = test_partition().await;
        let p2 = part.clone();
        let workers = spawn(1, 100, Arc::new(move |_: &str| Some(p2.clone())), tokio::runtime::Handle::current());
        let w = workers.senders[0].clone();
        let did: Arc<str> = "did:plc:claims".into();
        let key = Arc::new(Keypair::generate());
        let account = serde_json::json!({
            "did": &*did, "handle": "t.test", "wrapped_signing_key": Secrets::dev().wrap_signing_key(&did, &key).await.unwrap().0, "signing_pubkey": key.public_multibase(),
            "password_hash": "", "created_at": "2026-01-01T00:00:00Z",
        });
        let (reply, created) = oneshot::channel();
        w.send(WorkerMsg::CreateRepo(CreateRepoReq {
            did: did.clone(),
            handle: "t.test".into(),
            key,
            account_json: Bytes::from(serde_json::to_vec(&account).unwrap()),
            records: Vec::new(),
            reply,
        }))
        .unwrap();
        settle(rx.recv().await.unwrap());
        created.await.unwrap().unwrap();
        let with_claim = |rkey: &str, abandoned: bool| {
            let (m, r) = write(&did, rkey);
            let WorkerMsg::Write(mut req) = m else { unreachable!() };
            let c = Arc::new(Claim::default());
            if abandoned {
                assert!(c.abandon());
            }
            req.claim = Some(c.clone());
            (WorkerMsg::Write(req), r, c)
        };
        let (m1, r1, _) = with_claim("a", true);
        let (m2, r2, c2) = with_claim("b", false);
        w.send(m1).unwrap();
        w.send(m2).unwrap();
        settle(rx.recv().await.unwrap());
        assert!(r1.await.is_err(), "abandoned write answered");
        let ack = r2.await.unwrap().unwrap();
        assert!(
            matches!(&ack.results[..], [WriteOutcome::Create { path, .. }] if path == "app.test.thing/b"),
            "{:?}",
            ack.results
        );
        assert!(!c2.abandon(), "taken by the worker");
        let (reply, info) = oneshot::channel();
        w.send(WorkerMsg::CacheInfo { did: did.clone(), reply }).unwrap();
        assert!(info.await.unwrap().unwrap().loaded_nodes >= 1);
        assert!(
            part.recent.take_dirty().is_some_and(|b| b.as_ref() == b"did:plc:claims\n"),
            "written repo tracked as recent"
        );
    }

    /// Blob refs are loaded on a repo's first update, delete or create with
    /// blobs, not on open: a cold open for a create without blobs skips
    /// them; the paths it created (still in flight, so not in the scanned
    /// `b/`) survive the load. A create with blobs counts their other refs
    /// (`RepoStats::blobs`), and a delete right after drops its in-flight
    /// ref.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn blob_refs_load_on_first_need() {
        // the sequencer is this test: it applies entries when it chooses
        let (part, mut rx) = test_partition().await;
        let db = part.db.clone();
        let apply = |e: LogEntry| {
            let db = db.clone();
            async move { apply(&db, e).await }
        };
        let did: Arc<str> = "did:plc:blobrefs".into();
        let op = |w: Write| {
            let (reply, rx) = oneshot::channel();
            (
                WorkerMsg::Write(WriteReq {
                    did: did.clone(),
                    writes: vec![w],
                    swap_commit: None,
                    reply,
                    claim: None,
                    permit: None,
                }),
                rx,
            )
        };
        let blob = |i: u8| Cid::dag_cbor(&[i]);
        let rec = |rkey: &str, blobs: Vec<Cid>, update: bool| {
            let bytes = Bytes::from(format!("record {rkey} {blobs:?}"));
            let (collection, rkey, cid) = ("app.test.thing".to_string(), rkey.to_string(), Cid::dag_cbor(&bytes));
            match update {
                false => Write::Create { collection, rkey, cid, bytes, blobs, prune_backlinks: false },
                true => Write::Update { collection, rkey, cid, bytes, blobs, swap: None, must_exist: true },
            }
        };
        let route: PartitionLookup = {
            let p = part.clone();
            Arc::new(move |_: &str| Some(p.clone()))
        };
        {
            let workers = spawn(1, 100, route.clone(), tokio::runtime::Handle::current());
            let w = workers.senders[0].clone();
            let key = Arc::new(Keypair::generate());
            let account = serde_json::json!({
                "did": &*did, "handle": "t.test", "wrapped_signing_key": Secrets::dev().wrap_signing_key(&did, &key).await.unwrap().0, "signing_pubkey": key.public_multibase(),
                "password_hash": "", "created_at": "2026-01-01T00:00:00Z",
            });
            let (reply, created) = oneshot::channel();
            w.send(WorkerMsg::CreateRepo(CreateRepoReq {
                did: did.clone(),
                handle: "t.test".into(),
                key,
                account_json: Bytes::from(serde_json::to_vec(&account).unwrap()),
                records: Vec::new(),
                reply,
            }))
            .unwrap();
            apply(rx.recv().await.unwrap()).await;
            created.await.unwrap().unwrap();
            let (m, r) = op(rec("p1", vec![blob(1)], false));
            w.send(m).unwrap();
            apply(rx.recv().await.unwrap()).await;
            r.await.unwrap().unwrap();
        }
        // a fresh worker: the repo opens cold
        let workers = spawn(1, 100, route, tokio::runtime::Handle::current());
        let w = workers.senders[0].clone();
        let cached = || {
            let (reply, info) = oneshot::channel();
            w.send(WorkerMsg::CacheInfo { did: did.clone(), reply }).unwrap();
            info
        };
        let (m, plain) = op(rec("p0", Vec::new(), false));
        w.send(m).unwrap();
        let e_plain = rx.recv().await.unwrap();
        assert!(
            !cached().await.unwrap().unwrap().blob_refs_loaded,
            "a create without blobs opened the repo with its blob refs"
        );
        let (m, created) = op(rec("p2", vec![blob(2), blob(1)], false));
        w.send(m).unwrap();
        let e_create = rx.recv().await.unwrap(); // in flight: its b/ row isn't applied
        assert!(cached().await.unwrap().unwrap().blob_refs_loaded, "a create with blobs ran without the refs");
        let stats = |e: &LogEntry| {
            e.muts
                .iter()
                .find(|m| m.key[..] == state::repo_stats_key(&did)[..])
                .map(|m| state::RepoStats::decode(m.val.as_ref().unwrap()).unwrap())
        };
        // blob(1) was p1's already
        assert_eq!(stats(&e_create).map(|s| (s.records, s.blobs)), Some((3, 2)));
        let has = |e: &LogEntry, b: u8, path: &str, put: bool| {
            e.muts
                .iter()
                .any(|m| m.key[..] == state::blob_ref_key(&did, 0, &blob(b), path)[..] && m.val.is_some() == put)
        };
        let (m, deleted) = op(Write::Delete { collection: "app.test.thing".into(), rkey: "p2".into(), swap: None });
        w.send(m).unwrap();
        let e_delete = rx.recv().await.unwrap();
        assert!(has(&e_delete, 2, "app.test.thing/p2", false), "the in-flight create's ref isn't dropped");
        assert!(cached().await.unwrap().unwrap().blob_refs_loaded);
        let (m, updated) = op(rec("p1", vec![blob(3)], true));
        w.send(m).unwrap();
        let e_update = rx.recv().await.unwrap();
        assert!(
            has(&e_update, 1, "app.test.thing/p1", false) && has(&e_update, 3, "app.test.thing/p1", true),
            "the durable ref isn't replaced"
        );
        assert_eq!(stats(&e_delete).map(|s| (s.records, s.blobs)), Some((2, 1)));
        // p1's blob(1) replaced: blob(3) only
        assert_eq!(stats(&e_update).map(|s| (s.records, s.blobs)), None, "unchanged counts aren't written");
        for e in [e_plain, e_create, e_delete, e_update] {
            apply(e).await;
        }
        for r in [plain, created, deleted, updated] {
            r.await.unwrap().unwrap();
        }
        let prefix = state::blob_ref_prefix(&did, 0);
        let mut it = db.scan(prefix.clone()..state::prefix_end(&prefix)).await.unwrap();
        let mut left = Vec::new();
        while let Some(kv) = it.next().await.unwrap() {
            left.push(kv.key.to_vec());
        }
        assert_eq!(left, vec![state::blob_ref_key(&did, 0, &blob(3), "app.test.thing/p1")]);
    }

    /// The path cache: over the byte budget, idle repos drop back to their
    /// root, least recently used first; if the roots alone are still over
    /// it, the least recently used repos are evicted. A repo charged over
    /// [`LAZY_REPO_MAX_BYTES`] drops its paths as soon as it is idle,
    /// whatever the budget.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn path_cache_unloads_then_evicts_by_bytes() {
        let (part, _rx) = test_partition().await;
        // a fully loaded repo (as after an import or a rebuild)
        let repo = |name: &str, records: u32| {
            let did: Arc<str> = format!("did:plc:{name}").into();
            let key = Keypair::generate();
            let mut tree = Tree::new();
            for i in 0..records {
                tree.insert_no_proof(format!("c.x/{i:05}").as_bytes(), Cid::dag_cbor(&i.to_be_bytes())).unwrap();
            }
            let root = tree.root_cid().unwrap();
            let head = Head { commit: root, data: root, rev: Tid(1), commit_block: Bytes::new() };
            let acct: state::Account = serde_json::from_value(serde_json::json!({
                "did": &*did, "handle": "t.test", "wrapped_signing_key": "", "signing_pubkey": key.public_multibase(), "password_hash": "", "created_at": "",
            }))
            .unwrap();
            (
                did.clone(),
                finish_load(part.clone(), did, LazyTree::loaded(tree, 1), head, Some(Arc::new(key)), acct).unwrap(),
            )
        };
        // a repo's charge fully loaded, and with its root only
        let charges = |records: u32| {
            let (_, mut st) = repo("probe", records);
            let full = repo_bytes(&st);
            st.mst.unload(0);
            (full, repo_bytes(&st))
        };
        let (full, root) = charges(400);
        assert!(full > 3 * root, "{full} vs {root}");
        let limits = CacheLimits { entries: 100, bytes: full + root + root / 2, ..CacheLimits::from(0) };
        let (me, _me_rx) = crate::chan::unbounded();
        let mut w = Worker::new(
            0,
            me,
            Arc::new(|_: &str| None),
            tokio::runtime::Handle::current(),
            limits,
            Secrets::dev(),
            Default::default(),
        );
        let put = |w: &mut Worker, (did, st): (Arc<str>, RepoState)| {
            w.cache_put(did.clone(), st);
            w.settle(&did);
            w.evict();
            did
        };
        let loaded = |w: &Worker, did: &Arc<str>| w.cache.peek(did).map(|st| st.mst.loaded_nodes());
        // the second loaded repo puts the worker over: the older one unloads
        let a = put(&mut w, repo("a", 400));
        let b = put(&mut w, repo("b", 400));
        assert_eq!(loaded(&w, &a), Some(1));
        assert!(loaded(&w, &b).unwrap() > 1);
        assert_eq!(w.bytes, full + root);
        // a third: b unloads, then c itself
        let c = put(&mut w, repo("c", 400));
        assert_eq!((loaded(&w, &b), loaded(&w, &c)), (Some(1), Some(1)));
        assert_eq!((w.cache.len(), w.bytes), (3, 3 * root));
        // roots alone over the budget: the least recently used is evicted
        w.limits.bytes = 2 * root + root / 2;
        w.evict();
        assert!(!w.cache.contains(&a) && w.cache.contains(&b) && w.cache.contains(&c));
        assert_eq!(w.bytes, 2 * root);
        // an unbounded cache still unloads a repo over 1 MiB once idle
        w.limits.bytes = 0;
        let (big_full, big_root) = charges(8_000);
        assert!(big_full > LAZY_REPO_MAX_BYTES, "{big_full}");
        let big = put(&mut w, repo("big", 8_000));
        assert_eq!(loaded(&w, &big), Some(1));
        assert!(!w.big.contains(&big));
        assert_eq!(w.bytes, 2 * root + big_root);
    }

    /// Dropping the last `Workers` handle ends the threads (each holds a
    /// sender to its own channel, so disconnection alone never would).
    #[tokio::test]
    async fn workers_exit_when_dropped() {
        let workers = spawn(2, 10, Arc::new(|_: &str| None), tokio::runtime::Handle::current());
        let probes: Vec<_> = workers.senders.iter().cloned().collect();
        drop(workers);
        let deadline = Instant::now() + Duration::from_secs(5);
        // a worker's receiver is dropped when its thread returns
        while probes.iter().any(|p| p.send(WorkerMsg::Shutdown).is_ok()) {
            assert!(Instant::now() < deadline, "repo workers still running");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// Thread CPU seconds (CLOCK_THREAD_CPUTIME_ID).
    fn thread_cpu() -> f64 {
        #[repr(C)]
        struct Ts(i64, i64);
        unsafe extern "C" {
            fn clock_gettime(clk: i32, ts: *mut Ts) -> i32;
        }
        let clk = if cfg!(target_os = "macos") { 16 } else { 3 };
        let mut t = Ts(0, 0);
        unsafe { clock_gettime(clk, &mut t) };
        t.0 as f64 + t.1 as f64 * 1e-9
    }

    /// A partition whose "sequencer" is the test (`rx`).
    async fn test_partition() -> (Arc<Partition>, tokio::sync::mpsc::Receiver<LogEntry>) {
        let store = crate::store::Store::memory(None);
        let db = Arc::new(crate::partition::open_db(&store, crate::slots::ShardId(0), None).await.unwrap());
        let (merger_tx, _merger_rx) = tokio::sync::mpsc::unbounded_channel();
        let log = NodeLog::start(
            store.clone(),
            NodeLogConfig {
                log_id: "t".into(),
                writer: 1,
                max_segment_bytes: 1 << 20,
                hedge_after: Duration::from_secs(1),
                lease_ok: None,
            },
            merger_tx,
        );
        let (tx, rx) = tokio::sync::mpsc::channel::<LogEntry>(16);
        (
            Arc::new(Partition {
                id: crate::slots::ShardId(0),
                epoch: 1,
                db,
                apply_lock: Default::default(),
                tx,
                wm: log.wm.clone(),
                log: log.clone(),
                recent: Default::default(),
            }),
            rx,
        )
    }

    async fn apply(db: &Arc<slatedb::Db>, e: LogEntry) {
        let mut wb = slatedb::WriteBatch::new();
        for m in &e.muts {
            match &m.val {
                Some(v) => wb.put(&m.key, v),
                None => wb.delete(&m.key),
            }
        }
        if !e.muts.is_empty() {
            db.write(wb).await.unwrap();
        }
        settle(e);
    }

    async fn create_req(did: &Arc<str>) -> (WorkerMsg, oneshot::Receiver<Result<Head, WriteError>>) {
        let key = Arc::new(Keypair::generate());
        let account = serde_json::json!({
            "did": &**did, "handle": "t.test", "wrapped_signing_key": Secrets::dev().wrap_signing_key(did, &key).await.unwrap().0, "signing_pubkey": key.public_multibase(),
            "password_hash": "", "created_at": "2026-01-01T00:00:00Z",
        });
        let (reply, rx) = oneshot::channel();
        let req = CreateRepoReq {
            did: did.clone(),
            handle: "t.test".into(),
            key,
            account_json: Bytes::from(serde_json::to_vec(&account).unwrap()),
            records: Vec::new(),
            reply,
        };
        (WorkerMsg::CreateRepo(req), rx)
    }

    /// A repo that is only in durable state (created, then evicted: here a
    /// fresh worker) can't be created again over.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn create_repo_refuses_a_durable_repo() {
        let (part, mut rx) = test_partition().await;
        let db = part.db.clone();
        let p2 = part.clone();
        let route: PartitionLookup = Arc::new(move |_: &str| Some(p2.clone()));
        let did: Arc<str> = "did:plc:createtwice".into();
        {
            let workers = spawn(1, 100, route.clone(), tokio::runtime::Handle::current());
            let (m, created) = create_req(&did).await;
            workers.senders[0].send(m).unwrap();
            apply(&db, rx.recv().await.unwrap()).await;
            created.await.unwrap().unwrap();
        }
        let workers = spawn(1, 100, route, tokio::runtime::Handle::current());
        let (m, again) = create_req(&did).await;
        workers.senders[0].send(m).unwrap();
        let r = tokio::time::timeout(Duration::from_secs(5), again).await.unwrap().unwrap();
        assert!(matches!(&r, Err(WriteError::Invalid(m)) if m == REPO_EXISTS), "{:?}", r.map(|h| h.rev));
        assert!(rx.try_recv().is_err(), "nothing logged");
    }

    /// A no-op account op is acked after the repo's earlier entries, not
    /// before them; and a deleted repo has no snapshot.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn noop_account_ops_ack_in_log_order() {
        let (part, mut rx) = test_partition().await;
        let db = part.db.clone();
        let p2 = part.clone();
        let workers = spawn(1, 100, Arc::new(move |_: &str| Some(p2.clone())), tokio::runtime::Handle::current());
        let w = workers.senders[0].clone();
        let did: Arc<str> = "did:plc:noopack".into();
        let (m, created) = create_req(&did).await;
        w.send(m).unwrap();
        apply(&db, rx.recv().await.unwrap()).await;
        created.await.unwrap().unwrap();
        let account = |mutate: AccountMutation| {
            let (reply, r) = oneshot::channel();
            (
                WorkerMsg::Account(AccountReq {
                    did: did.clone(),
                    op: AccountOp::Update { mutate, identity_event: false, account_event: false },
                    reply,
                }),
                r,
            )
        };
        // nothing in flight: acked at once, nothing logged
        let (m, mut r) = account(Box::new(|_| Ok(false)));
        w.send(m).unwrap();
        tokio::time::timeout(Duration::from_secs(5), &mut r).await.unwrap().unwrap().unwrap();
        // behind an in-flight commit: waits for it
        let (m, first) = write(&did, "a");
        w.send(m).unwrap();
        let inflight = rx.recv().await.unwrap();
        let (m, mut noop) = account(Box::new(|_| Ok(false)));
        w.send(m).unwrap();
        let empty = rx.recv().await.unwrap();
        assert!(empty.muts.is_empty() && empty.frames.is_empty(), "an empty entry carries the ack");
        assert!(noop.try_recv().is_err(), "acked before the earlier commit");
        apply(&db, inflight).await;
        first.await.unwrap().unwrap();
        apply(&db, empty).await;
        noop.await.unwrap().unwrap();
        // deleted: no snapshot of the old head over an empty tree
        let (reply, deleted) = oneshot::channel();
        w.send(WorkerMsg::Account(AccountReq { did: did.clone(), op: AccountOp::Delete { only_if: None }, reply }))
            .unwrap();
        apply(&db, rx.recv().await.unwrap()).await;
        deleted.await.unwrap().unwrap();
        let (reply, snap) = oneshot::channel();
        w.send(WorkerMsg::Snapshot(SnapshotReq { did: did.clone(), reply, permit: None })).unwrap();
        assert!(matches!(snap.await.unwrap(), Err(WriteError::RepoNotFound)));
    }

    /// CPU per commit of the worker's commit path plus its ack, one
    /// createRecord per commit on a loaded tree, with the state and segment
    /// bytes per commit. Measurement only:
    /// `cargo test --release --lib bench_commit_cpu -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn bench_commit_cpu() {
        let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
        let (part, mut rx) = rt.block_on(async {
            let store = crate::store::Store::memory(None);
            let db = Arc::new(crate::partition::open_db(&store, crate::slots::ShardId(0), None).await.unwrap());
            let (merger_tx, _merger_rx) = tokio::sync::mpsc::unbounded_channel();
            let log = NodeLog::start(
                store.clone(),
                NodeLogConfig {
                    log_id: "t".into(),
                    writer: 1,
                    max_segment_bytes: 1 << 20,
                    hedge_after: Duration::from_secs(1),
                    lease_ok: None,
                },
                merger_tx,
            );
            std::mem::forget(_merger_rx);
            let (tx, rx) = tokio::sync::mpsc::channel::<LogEntry>(1 << 16);
            (
                Arc::new(Partition {
                    id: crate::slots::ShardId(0),
                    epoch: 1,
                    db,
                    apply_lock: Default::default(),
                    tx,
                    wm: log.wm.clone(),
                    log: log.clone(),
                    recent: Default::default(),
                }),
                rx,
            )
        });
        let tid = |i: u64| Tid::from_parts(1_700_000_000_000_000 + i * 1_000_003, i % 1024).to_string();
        // likes and follows: createRecord's backlink check (one index
        // read per create, done inline here) and the index's `bl/` puts
        for (kind, records) in [("post", 20u64), ("post", 5000), ("like", 5000), ("follow", 5000)] {
            let did: Arc<str> = format!("did:plc:bench{kind}{records}").into();
            let key = Keypair::generate();
            let mut tree = Tree::new();
            for i in 0..records {
                tree.insert_no_proof(
                    format!("app.bsky.feed.post/{}", tid(i)).as_bytes(),
                    Cid::dag_cbor(&i.to_be_bytes()),
                )
                .unwrap();
            }
            let root = tree.root_cid().unwrap();
            let head = Head { commit: root, data: root, rev: Tid(1), commit_block: Bytes::new() };
            let acct: state::Account = serde_json::from_value(serde_json::json!({
                "did": &*did, "handle": "t.test", "wrapped_signing_key": "", "signing_pubkey": key.public_multibase(), "password_hash": "", "created_at": "",
            }))
            .unwrap();
            let mut st =
                finish_load(part.clone(), did.clone(), LazyTree::loaded(tree, 1), head, Some(Arc::new(key)), acct)
                    .unwrap();
            let mut next = records;
            let (mut state_bytes, mut seg_bytes, mut commits) = (0usize, 0usize, 0usize);
            let mut one = |st: &mut RepoState| {
                let rkey = tid(next);
                next += 1;
                let (collection, bytes) = match kind {
                    "post" => ("app.bsky.feed.post", Bytes::from(format!("{{\"$type\":\"app.bsky.feed.post\",\"text\":\"post {rkey} {}\",\"createdAt\":\"2026-10-01T00:00:00.000Z\"}}", "x".repeat(120)))),
                    _ => {
                        let coll = if kind == "like" { "app.bsky.feed.like" } else { "app.bsky.graph.follow" };
                        let subject = match kind {
                            "like" => serde_json::json!({"uri": format!("at://did:plc:{next:024}/app.bsky.feed.post/{rkey}"), "cid": Cid::dag_cbor(rkey.as_bytes()).to_string()}),
                            _ => serde_json::json!(format!("did:plc:{next:024}")),
                        };
                        let v = serde_json::json!({"$type": coll, "subject": subject, "createdAt": "2026-10-01T00:00:00.000Z"});
                        (coll, Bytes::from(crate::cbor::Value::from_json(&v).unwrap().to_cbor()))
                    }
                };
                let (reply, _rx) = oneshot::channel();
                let w = Write::Create {
                    collection: collection.into(),
                    rkey,
                    cid: Cid::dag_cbor(&bytes),
                    bytes,
                    blobs: Vec::new(),
                    prune_backlinks: kind != "post",
                };
                let reqs = vec![Queued::Write(WriteReq {
                    did: did.clone(),
                    writes: vec![w],
                    swap_commit: None,
                    reply,
                    claim: None,
                    permit: None,
                })];
                let reqs = match lazy_needs(st, reqs) {
                    Ok(reqs) => reqs,
                    // the backlink read a fetch does off the worker thread
                    Err((reqs, Some(need))) => {
                        if let Some(f) = rt.block_on(need.load_backlinks(&*st.partition.db, &st.did, st.gen())).unwrap()
                        {
                            st.backlinks.install(f);
                        }
                        let Ok(reqs) = lazy_needs(st, reqs) else { panic!("paths not loaded") };
                        reqs
                    }
                    Err(_) => panic!("paths not loaded"),
                };
                process(st, reqs, 7, rt.handle()).unwrap();
                while let Ok(e) = rx.try_recv() {
                    commits += 1;
                    state_bytes +=
                        e.muts.iter().map(|m| m.key.len() + m.val.as_ref().map_or(0, |v| v.len())).sum::<usize>();
                    let derived = e.frames.first().map_or(0, |f| f.derived_muts);
                    seg_bytes += e.frames.iter().map(|f| f.len_hint()).sum::<usize>()
                        + e.muts[derived..]
                            .iter()
                            .map(|m| 6 + m.key.len() + m.val.as_ref().map_or(0, |v| v.len()))
                            .sum::<usize>();
                    settle(e);
                }
            };
            for _ in 0..2000 {
                one(&mut st);
            }
            let mut best = f64::MAX;
            // BENCH_ROUNDS: more rounds, e.g. to attach a sampler
            let rounds = std::env::var("BENCH_ROUNDS").ok().and_then(|v| v.parse().ok()).unwrap_or(7);
            for _ in 0..rounds {
                let n = 3000;
                let t = thread_cpu();
                for _ in 0..n {
                    one(&mut st);
                }
                best = best.min((thread_cpu() - t) / n as f64 * 1e6);
            }
            println!(
                "bench_commit_cpu {kind} records={records}: {best:.2} us/commit (thread CPU, best of {rounds}); {} state B/commit, {} segment B/commit",
                state_bytes / commits.max(1),
                seg_bytes / commits.max(1)
            );
        }
    }
}
