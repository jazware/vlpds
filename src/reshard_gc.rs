//! Retired-state GC for online split/merge (DESIGN.md "Retired state GC").
//! A split or merge leaves its parents' state dirs behind: the children are
//! SlateDB clones reading the parents' SSTs in place until compaction
//! rewrites them, which size-tiered compaction may never do for a quiet
//! child's bottom run. So:
//!
//! - **Forced detach** (every node, for the shards it holds): a shard still
//!   reading inherited SSTs `detach_after` after we opened it gets one
//!   rewriting compaction; SlateDB's own detach GC then releases the parents.
//! - **Dir GC** (the owner of slot 0's shard): a state dir out of the layout
//!   is deleted once no checkpoint is left in its manifest, no manifest
//!   lists its SSTs, and its manifest is older than `grace`; then its
//!   `assign/` record goes.
//! - Optionally (`full_every`), a full compaction of every held shard.

use crate::cluster::Assignment;
use crate::metrics;
use futures::StreamExt;
use object_store::path::Path;
use object_store::ObjectStoreExt;
use parking_lot::Mutex;
use slatedb::compactor::{Compaction, CompactionSpec, CompactionStatus, SourceId};
use slatedb::{Db, VersionedManifest};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use vlsync_store::slots::{Layout, ShardId};
use vlsync_store::store::Store;

#[derive(Clone, Debug)]
pub struct Config {
    pub interval: Duration,
    /// None = no dir or assign/ GC.
    pub grace: Option<Duration>,
    /// Dirs deleted per pass at most (and 4x that many checked).
    pub max_dirs: usize,
    /// None = no forced detach.
    pub detach_after: Option<Duration>,
    /// Forced compactions in flight per node.
    pub max_inflight: usize,
    pub full_every: Option<Duration>,
}

pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(60);
const DEFAULT_GRACE: Duration = Duration::from_secs(3600);
const DEFAULT_DETACH_AFTER: Duration = Duration::from_secs(300);
/// A dir pass LISTs at least this often even while the skip rule says
/// nothing can be there: a safety net (see `ReshardGc::dir_pass`).
pub const FULL_PASS_EVERY: Duration = Duration::from_secs(3600);

impl Default for Config {
    fn default() -> Self {
        Config {
            interval: DEFAULT_INTERVAL,
            grace: Some(DEFAULT_GRACE),
            max_dirs: 8,
            detach_after: Some(DEFAULT_DETACH_AFTER),
            max_inflight: 1,
            full_every: None,
        }
    }
}

/// Test hook: true = stop at this named point, as a crash would.
pub type PhaseHook = Box<dyn Fn(&str) -> bool + Send + Sync>;

pub struct Hooks {
    /// Whether this node runs dir GC.
    pub leader: Box<dyn Fn() -> bool + Send + Sync>,
    /// Checked before each delete.
    pub lease_ok: Box<dyn Fn() -> bool + Send + Sync>,
    pub owned: Box<dyn Fn() -> Vec<(ShardId, Arc<Db>)> + Send + Sync>,
    /// Asked at "deleted-dir" (a dir is gone, its assignment not yet).
    pub crash_at: Option<PhaseHook>,
}

/// Why a retired dir is kept (`vlpds_reshard_gc_retired_dirs` states).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Held {
    /// A live checkpoint in its manifest: a clone (child, grandchild) that
    /// still reads its SSTs, a reader, or a named backup.
    Checkpoint,
    /// Its manifest changed within the grace.
    Grace,
    /// Some manifest lists its SSTs although it holds no checkpoint (a
    /// broken invariant: never deleted).
    Referenced,
    /// No manifest (and no delete in progress), or an assignment with an owner.
    Other,
}

impl Held {
    fn label(self) -> &'static str {
        match self {
            Held::Checkpoint => "checkpoint",
            Held::Grace => "grace",
            Held::Referenced => "referenced",
            Held::Other => "other",
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct Pass {
    /// Dirs of shards out of the layout.
    pub retired: usize,
    pub deleted_dirs: usize,
    pub deleted_objects: usize,
    pub deleted_assigns: usize,
    pub held: HashMap<Held, usize>,
    pub op_pending: bool,
    /// The layout is the one an earlier pass found nothing to do under.
    pub skipped: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Detach,
    Full,
}

impl Kind {
    fn label(self) -> &'static str {
        match self {
            Kind::Detach => "detach",
            Kind::Full => "full",
        }
    }
}

#[derive(Default)]
struct State {
    inflight: HashMap<ShardId, (Compaction, Kind, Instant)>,
    /// When we first saw each shard open here.
    seen: HashMap<ShardId, Instant>,
    last_full: HashMap<ShardId, Instant>,
    /// Dir GC resumes checking after this id (round robin).
    cursor: Option<ShardId>,
    /// The layout of the last full dir pass, if it found nothing out of the
    /// layout, and when that pass started.
    idle: Option<(Layout, Instant)>,
}

pub struct ReshardGc {
    store: Store,
    cfg: Config,
    hooks: Hooks,
    st: Mutex<State>,
}

/// Abandon our wait on a submitted compaction after this (SlateDB may have
/// trimmed it from its compactions file; a still-needed detach resubmits).
const INFLIGHT_TIMEOUT: Duration = Duration::from_secs(3600);

impl ReshardGc {
    pub fn new(store: Store, cfg: Config, hooks: Hooks) -> Arc<ReshardGc> {
        Arc::new(ReshardGc { store, cfg, hooks, st: Mutex::default() })
    }

    pub fn spawn(self: &Arc<Self>) {
        metrics::init_reshard_gc_counters();
        let me = self.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(me.cfg.interval);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            tick.tick().await; // the first tick is immediate: skip it
            loop {
                tick.tick().await;
                if let Err(e) = me.compaction_pass().await {
                    tracing::warn!("forced compaction pass failed: {e:#}");
                }
                if !(me.hooks.leader)() {
                    // what we learned may be stale by the time we lead again
                    me.st.lock().idle = None;
                    continue;
                }
                match me.dir_pass().await {
                    Ok(p) if p.skipped => metrics::RESHARD_GC_SKIPPED.inc(),
                    Ok(p) => {
                        metrics::RESHARD_GC_PASSES.with_label_values(&["ok"]).inc();
                        if p.deleted_dirs + p.deleted_assigns > 0 {
                            tracing::info!(
                                dirs = p.deleted_dirs,
                                objects = p.deleted_objects,
                                assigns = p.deleted_assigns,
                                retired = p.retired,
                                "reshard GC pass"
                            );
                        }
                    }
                    Err(e) => {
                        metrics::RESHARD_GC_PASSES.with_label_values(&["error"]).inc();
                        tracing::warn!("reshard GC pass failed: {e:#}");
                    }
                }
            }
        });
    }

    fn admin(&self, id: ShardId) -> slatedb::admin::Admin {
        slatedb::admin::AdminBuilder::new(crate::partition::db_path(&self.store, id), self.store.raw.clone()).build()
    }

    /// Follows the compactions we submitted, and submits one for each held
    /// shard due a forced detach or a full compaction.
    pub async fn compaction_pass(&self) -> anyhow::Result<()> {
        let owned = (self.hooks.owned)();
        let now = Instant::now();
        let ids: HashSet<ShardId> = owned.iter().map(|(id, _)| *id).collect();
        let inflight: Vec<(ShardId, Compaction, Kind, Instant)> = {
            let mut st = self.st.lock();
            st.seen.retain(|id, _| ids.contains(id));
            st.last_full.retain(|id, _| ids.contains(id));
            // a shard that moved away: its new owner takes over
            st.inflight.retain(|id, _| ids.contains(id));
            for id in &ids {
                st.seen.entry(*id).or_insert(now);
            }
            st.inflight.iter().map(|(id, (c, k, t))| (*id, c.clone(), *k, *t)).collect()
        };
        for (id, c, kind, at) in inflight {
            let status = self.admin(id).read_compaction(c.id(), None).await?.map(|c| c.status());
            let done = match status {
                Some(CompactionStatus::Completed) | None => Some("completed"),
                Some(CompactionStatus::Failed) => Some("failed"),
                _ if now.duration_since(at) > INFLIGHT_TIMEOUT => Some("failed"),
                _ => None,
            };
            if let Some(r) = done {
                metrics::FORCED_COMPACTIONS.with_label_values(&[kind.label(), r]).inc();
                if r == "failed" {
                    tracing::info!(
                        shard = id.0,
                        kind = kind.label(),
                        "forced compaction failed (conflicted with another; retried)"
                    );
                }
                self.st.lock().inflight.remove(&id);
            }
        }
        let mut inherited = 0i64;
        for (id, db) in owned {
            let m = db.manifest();
            let ext = has_inherited(&m);
            inherited += ext as i64;
            let (busy, seen, due_full) = {
                let st = self.st.lock();
                let busy = st.inflight.contains_key(&id) || st.inflight.len() >= self.cfg.max_inflight.max(1);
                let seen = st.seen.get(&id).copied().unwrap_or(now);
                let due_full = self
                    .cfg
                    .full_every
                    .is_some_and(|every| now.duration_since(st.last_full.get(&id).copied().unwrap_or(seen)) >= every);
                (busy, seen, due_full)
            };
            // a deep L0 means compaction is busy (and would refuse ours)
            if busy || m.l0().len() >= 8 {
                continue;
            }
            let kind = if ext && self.cfg.detach_after.is_some_and(|d| now.duration_since(seen) >= d) {
                Kind::Detach
            } else if due_full {
                Kind::Full
            } else {
                continue;
            };
            let admin = self.admin(id);
            // Never next to an active compaction: SlateDB promotes a submitted
            // spec without checking it against claimed jobs, and the worker
            // panics on two jobs for one destination (fixed in the fork on
            // vlpds-0.17-submit-dest-guard; this narrows the race until then).
            if admin.read_compactions(None).await?.is_some_and(|cs| cs.recent_compactions().any(|c| c.active())) {
                continue;
            }
            // the stored manifest: the compactor validates against it, and the
            // writer's view lags its results
            let Some(latest) = admin.read_manifest(None).await? else { continue };
            let Some(spec) = rewrite_spec(&latest, kind == Kind::Full) else { continue };
            match admin.submit_compaction(spec).await {
                Ok(c) => {
                    tracing::info!(shard = id.0, kind = kind.label(), spec = %c.spec(), "submitted forced compaction");
                    metrics::FORCED_COMPACTIONS.with_label_values(&[kind.label(), "submitted"]).inc();
                    let mut st = self.st.lock();
                    if kind == Kind::Full {
                        st.last_full.insert(id, now);
                    }
                    st.inflight.insert(id, (c, kind, now));
                }
                // e.g. no compactions file yet (the compactor just started)
                Err(e) => tracing::debug!(shard = id.0, "forced compaction not submitted: {e}"),
            }
        }
        metrics::SHARDS_INHERITED.set(inherited);
        Ok(())
    }

    async fn get_json<T: serde::de::DeserializeOwned>(&self, path: &Path) -> anyhow::Result<Option<T>> {
        match self.store.raw.get(path).await {
            Ok(r) => Ok(Some(serde_json::from_slice(&r.bytes().await?)?)),
            Err(object_store::Error::NotFound { .. }) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    async fn read_assignment(&self, id: ShardId) -> anyhow::Result<Option<Assignment>> {
        self.get_json(&assign_path(&self.store, id)).await
    }

    async fn state_dirs(&self) -> anyhow::Result<BTreeSet<ShardId>> {
        let r = self.store.raw.list_with_delimiter(Some(&Path::from(format!("{}/state", self.store.prefix)))).await?;
        Ok(r.common_prefixes.iter().filter_map(|p| p.filename().and_then(ShardId::from_key)).collect())
    }

    async fn assign_records(&self) -> anyhow::Result<BTreeSet<ShardId>> {
        let r = self.store.raw.list_with_delimiter(Some(&Path::from(format!("{}/assign", self.store.prefix)))).await?;
        Ok(r.objects.iter().filter_map(|m| m.location.filename().and_then(ShardId::from_key)).collect())
    }

    /// Retired state dirs, then orphaned assignments.
    ///
    /// Skipped after the layout GET when the layout equals that of a full
    /// pass at most [`FULL_PASS_EVERY`] ago that found nothing out of the
    /// layout: things out of the layout only appear through a layout change
    /// (an op's children, or a shard leaving the layout). A pass with
    /// anything left, a pending op, an error or a lost leadership forgets
    /// what it learned. A skip never deletes; it only defers work, by at
    /// most FULL_PASS_EVERY for anything the rule doesn't foresee (e.g. a
    /// stale former owner rewriting a deleted shard's record).
    pub async fn dir_pass(&self) -> anyhow::Result<Pass> {
        let mut pass = Pass::default();
        let Some(grace) = self.cfg.grace else { return Ok(pass) };
        // An owner's in-memory manifest that still lists a parent's SSTs is
        // replaced only at its next manifest poll.
        let grace = if cfg!(test) { grace } else { grace.max(crate::partition::manifest_poll_interval() * 3) };
        let layout =
            self.get_json::<Layout>(&Path::from(format!("{}/{}", self.store.prefix, crate::cluster::LAYOUT))).await;
        let started = Instant::now();
        {
            let mut st = self.st.lock();
            if let (Ok(Some(l)), Some((seen, at))) = (&layout, &st.idle) {
                if l == seen && at.elapsed() < FULL_PASS_EVERY {
                    pass.skipped = true;
                    return Ok(pass);
                }
            }
            st.idle = None;
        }
        let Some(layout) = layout? else { return Ok(pass) };
        if layout.op.is_some() {
            // it may still clone from its parents or write its children's
            // assignments
            pass.op_pending = true;
            return Ok(pass);
        }
        let live: HashSet<ShardId> = layout.ids().into_iter().collect();
        let dirs = self.state_dirs().await?;
        // ids at or past next_id were never handed out: not ours to touch
        let retired: Vec<ShardId> = dirs.iter().copied().filter(|s| !live.contains(s) && *s < layout.next_id).collect();
        pass.retired = retired.len();
        metrics::RESHARD_GC_RETIRED.with_label_values(&["total"]).set(retired.len() as i64);
        // round robin, so held dirs don't starve the rest
        let start = self.st.lock().cursor;
        let mut order: Vec<ShardId> = retired.iter().copied().filter(|s| start.is_none_or(|c| *s > c)).collect();
        order.extend(retired.iter().copied().filter(|s| start.is_some_and(|c| *s <= c)));
        order.truncate(self.cfg.max_dirs.max(1) * 4);
        let mut deletable = Vec::new();
        for &x in &order {
            self.st.lock().cursor = Some(x);
            match self.check_dir(x, grace).await? {
                Ok(()) => deletable.push(x),
                Err(h) => *pass.held.entry(h).or_default() += 1,
            }
        }
        if !deletable.is_empty() {
            // defense in depth: no manifest in the bucket (live shards and
            // other retired dirs alike) may list a deletable dir's SSTs
            let referenced = self.referenced(&dirs, &deletable).await?;
            deletable.retain(|x| {
                let r = referenced.contains(x);
                if r {
                    tracing::error!(
                        shard = x.0,
                        "retired state dir holds no checkpoint but a manifest lists its SSTs: kept"
                    );
                    *pass.held.entry(Held::Referenced).or_default() += 1;
                }
                !r
            });
        }
        for (state, n) in [("deletable", deletable.len())].into_iter().chain(
            [Held::Checkpoint, Held::Grace, Held::Referenced, Held::Other]
                .map(|h| (h.label(), pass.held.get(&h).copied().unwrap_or(0))),
        ) {
            metrics::RESHARD_GC_RETIRED.with_label_values(&[state]).set(n as i64);
        }
        for x in deletable.into_iter().take(self.cfg.max_dirs.max(1)) {
            anyhow::ensure!((self.hooks.lease_ok)(), "node lease not valid: no deletes");
            let gone = self.admin(x).delete_db(true).await?;
            pass.deleted_dirs += 1;
            pass.deleted_objects += gone.len();
            metrics::RESHARD_GC_DELETED.with_label_values(&["state_dirs"]).inc();
            metrics::RESHARD_GC_DELETED.with_label_values(&["state_objects"]).inc_by(gone.len() as u64);
            tracing::info!(shard = x.0, objects = gone.len(), "deleted retired shard state");
            if self.hooks.crash_at.as_ref().is_some_and(|h| h("deleted-dir")) {
                return Ok(pass);
            }
            if self.delete_assignment(x).await? {
                pass.deleted_assigns += 1;
            }
        }
        // assignments whose dir is gone (a pass that stopped between the
        // two deletes, an op aborted before its clone)
        let dirs = self.state_dirs().await?;
        let orphans: Vec<ShardId> = self
            .assign_records()
            .await?
            .into_iter()
            .filter(|s| !live.contains(s) && *s < layout.next_id && !dirs.contains(s))
            .collect();
        metrics::RESHARD_GC_ORPHAN_ASSIGNS.set(orphans.len() as i64);
        let idle = pass.retired == 0 && orphans.is_empty();
        for x in orphans.into_iter().take(self.cfg.max_dirs.max(1) * 4) {
            anyhow::ensure!((self.hooks.lease_ok)(), "node lease not valid: no deletes");
            if self.delete_assignment(x).await? {
                pass.deleted_assigns += 1;
            }
        }
        if idle {
            self.st.lock().idle = Some((layout, started));
        }
        Ok(pass)
    }

    /// Ok: retired dir `x` may go.
    async fn check_dir(&self, x: ShardId, grace: Duration) -> anyhow::Result<Result<(), Held>> {
        if self.read_assignment(x).await?.is_some_and(|a| a.owner.is_some()) {
            tracing::warn!(shard = x.0, "a shard out of the layout has an owner: its state is kept");
            return Ok(Err(Held::Other));
        }
        let dir = crate::partition::db_path(&self.store, x);
        let Some(m) = self.admin(x).read_manifest(None).await? else {
            // a delete that stopped half-way finishes
            return Ok(match self.store.raw.head(&Path::from(format!("{dir}/.deleting"))).await {
                Ok(_) => Ok(()),
                Err(object_store::Error::NotFound { .. }) => Err(Held::Other),
                Err(e) => return Err(e.into()),
            });
        };
        let now = chrono::Utc::now();
        if m.checkpoints().iter().any(|c| c.expire_time.is_none_or(|t| t > now)) {
            return Ok(Err(Held::Checkpoint));
        }
        // the newest manifest's age: every checkpoint add/delete rewrites it
        let newest = self
            .store
            .raw
            .list(Some(&Path::from(format!("{dir}/manifest"))))
            .filter_map(|m| async move { m.ok().map(|m| m.last_modified) })
            .fold(None, |a: Option<chrono::DateTime<chrono::Utc>>, t| async move { Some(a.map_or(t, |a| a.max(t))) })
            .await;
        if newest.is_some_and(|t| {
            t > now - chrono::Duration::from_std(grace).unwrap_or_else(|_| chrono::Duration::weeks(5200))
        }) {
            return Ok(Err(Held::Grace));
        }
        Ok(Ok(()))
    }

    /// Which of `xs` some other manifest under `state/` lists with SSTs it
    /// still reads.
    async fn referenced(&self, dirs: &BTreeSet<ShardId>, xs: &[ShardId]) -> anyhow::Result<HashSet<ShardId>> {
        let paths: HashMap<String, ShardId> =
            xs.iter().map(|x| (crate::partition::db_path(&self.store, *x), *x)).collect();
        let lists: Vec<anyhow::Result<Vec<String>>> = futures::stream::iter(dirs.iter().copied())
            .map(|d| async move {
                let Some(m) = self.admin(d).read_manifest(None).await? else { return Ok(Vec::new()) };
                Ok(m.external_dbs().iter().filter(|e| !e.sst_ids.is_empty()).map(|e| e.path.clone()).collect())
            })
            .buffer_unordered(16)
            .collect()
            .await;
        let mut out = HashSet::new();
        for l in lists {
            for p in l? {
                if let Some(x) = paths.get(p.trim_start_matches('/')).or_else(|| paths.get(&p)) {
                    out.insert(*x);
                }
            }
        }
        Ok(out)
    }

    /// Unless it names an owner. True if it was there.
    async fn delete_assignment(&self, x: ShardId) -> anyhow::Result<bool> {
        match self.read_assignment(x).await? {
            None => Ok(false),
            Some(a) if a.owner.is_some() => {
                tracing::warn!(shard = x.0, "a shard out of the layout has an owner: its assignment is kept");
                Ok(false)
            }
            Some(_) => {
                match self.store.raw.delete(&assign_path(&self.store, x)).await {
                    Ok(()) | Err(object_store::Error::NotFound { .. }) => {}
                    Err(e) => return Err(e.into()),
                }
                metrics::RESHARD_GC_DELETED.with_label_values(&["assign_records"]).inc();
                tracing::info!(shard = x.0, "deleted retired shard's assignment");
                Ok(true)
            }
        }
    }
}

fn assign_path(store: &Store, id: ShardId) -> Path {
    Path::from(format!("{}/assign/{}", store.prefix, id.key()))
}

pub fn has_inherited(m: &VersionedManifest) -> bool {
    m.external_dbs().iter().any(|e| !e.sst_ids.is_empty())
}

/// The compaction that stops a shard reading inherited SSTs: its tree from
/// the newest source holding one down to the oldest sorted run (`full`:
/// every source). A suffix of the tree is always a valid compaction: it
/// keeps recency order, and the output is the bottom run (where tombstones
/// are dropped). None: nothing to do.
fn rewrite_spec(m: &VersionedManifest, full: bool) -> Option<CompactionSpec> {
    let inherited: Vec<_> = m.external_dbs().iter().flat_map(|e| e.sst_ids.iter()).collect();
    // logical order: L0 newest -> oldest, then sorted runs highest id -> 0
    let mut sources: Vec<(SourceId, bool)> =
        m.l0().iter().map(|v| (SourceId::SstView(v.id), inherited.contains(&&v.sst.id))).collect();
    sources.extend(
        m.compacted()
            .iter()
            .map(|sr| (SourceId::SortedRun(sr.id), sr.sst_views().iter().any(|v| inherited.contains(&&v.sst.id)))),
    );
    let first = if full { (!sources.is_empty()).then_some(0)? } else { sources.iter().position(|(_, ext)| *ext)? };
    let srcs: Vec<SourceId> = sources[first..].iter().map(|(s, _)| *s).collect();
    // into the lowest sorted run among them; with none (L0 only, so no
    // sorted run exists at all) a new run 0
    let dest =
        srcs.iter().filter_map(|s| if let SourceId::SortedRun(id) = s { Some(*id) } else { None }).min().unwrap_or(0);
    Some(CompactionSpec::new(srcs, dest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::partition::{clone_db, open_db};

    type OwnedDbs = Arc<Mutex<Vec<(ShardId, Arc<Db>)>>>;

    fn k(slot: u16, rest: &str) -> Vec<u8> {
        vlsync_store::keys::slot_family(slot, rest.as_bytes())
    }

    async fn put_json<T: serde::Serialize>(store: &Store, rel: &str, v: &T) {
        store
            .raw
            .put(&Path::from(format!("{}/{rel}", store.prefix)), serde_json::to_vec(v).unwrap().into())
            .await
            .unwrap();
    }

    fn layout(shards: &[(u32, u32, u32)], next_id: u32, op: Option<vlsync_store::slots::Reshard>) -> Layout {
        let mut l = Layout::uniform(1);
        l.version = 2;
        l.shards =
            shards.iter().map(|&(id, lo, hi)| vlsync_store::slots::ShardRange { id: ShardId(id), lo, hi }).collect();
        l.next_id = ShardId(next_id);
        l.op_seq = 1;
        l.op = op;
        l
    }

    fn gc(
        store: &Store,
        owned: OwnedDbs,
        grace: Duration,
        crash: Option<Arc<std::sync::atomic::AtomicBool>>,
    ) -> Arc<ReshardGc> {
        let cfg = Config {
            interval: Duration::from_secs(3600),
            grace: Some(grace),
            max_dirs: 8,
            detach_after: Some(Duration::ZERO),
            max_inflight: 4,
            full_every: None,
        };
        let hooks = Hooks {
            leader: Box::new(|| true),
            lease_ok: Box::new(|| true),
            owned: Box::new(move || owned.lock().clone()),
            crash_at: crash.map(|c| {
                Box::new(move |p: &str| p == "deleted-dir" && c.swap(false, std::sync::atomic::Ordering::SeqCst))
                    as PhaseHook
            }),
        };
        ReshardGc::new(store.clone(), cfg, hooks)
    }

    async fn dirs(store: &Store) -> Vec<u32> {
        let r = store.raw.list_with_delimiter(Some(&Path::from(format!("{}/state", store.prefix)))).await.unwrap();
        r.common_prefixes.iter().filter_map(|p| p.filename().and_then(ShardId::from_key)).map(|s| s.0).collect()
    }

    async fn assigns(store: &Store) -> Vec<u32> {
        let r = store.raw.list_with_delimiter(Some(&Path::from(format!("{}/assign", store.prefix)))).await.unwrap();
        r.objects.iter().filter_map(|m| m.location.filename().and_then(ShardId::from_key)).map(|s| s.0).collect()
    }

    /// A closed parent with `n` keys spread over its slots (flushed into
    /// one L0 at close: its children inherit it as L0 views).
    async fn parent(store: &Store, id: ShardId, n: usize) -> Vec<(Vec<u8>, String)> {
        let db = open_db(store, id, None).await.unwrap();
        let mut keys = Vec::new();
        for i in 0..n {
            let slot = ((i * 7919) % 65536) as u16;
            let key = k(slot, &format!("h/p{i:05}"));
            db.put(&key, format!("v{i}")).await.unwrap();
            keys.push((key, format!("v{i}")));
        }
        db.close().await.unwrap();
        keys
    }

    async fn wait_for(what: &str, secs: u64, mut f: impl AsyncFnMut() -> bool) {
        let t = Instant::now();
        while !f().await {
            assert!(t.elapsed() < Duration::from_secs(secs), "timed out waiting for {what}");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    async fn check_keys(db: &Db, keys: &[(Vec<u8>, String)], lo: u32, hi: u32) {
        for (key, v) in keys {
            let slot = u16::from_be_bytes([key[1], key[2]]) as u32;
            if slot < lo || slot >= hi {
                continue;
            }
            let got = db.get(key).await.unwrap();
            assert_eq!(got.as_deref(), Some(v.as_bytes()), "key of slot {slot} lost");
        }
    }

    /// The spec is a suffix of the tree starting at the newest source with
    /// an inherited SST, merged into the lowest sorted run.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn rewrite_spec_is_a_suffix() {
        let store = Store { prefix: "gcspec".into(), ..Store::memory(None) };
        parent(&store, ShardId(0), 200).await;
        clone_db(&store, ShardId(1), &[(ShardId(0), 0, 32768)]).await.unwrap();
        let c = open_db(&store, ShardId(1), None).await.unwrap();
        let m = c.manifest();
        assert!(has_inherited(&m));
        let spec = rewrite_spec(&m, false).expect("inherited SSTs to rewrite");
        assert_eq!(spec.sources().len(), m.l0().len() + m.compacted().len(), "{spec}");
        // a write of its own on top: still the inherited suffix only
        c.put(k(5, "h/own"), "x").await.unwrap();
        c.flush_with_options(slatedb::config::FlushOptions { flush_type: slatedb::config::FlushType::MemTable })
            .await
            .unwrap();
        let m = c.manifest();
        let spec2 = rewrite_spec(&m, false).unwrap();
        assert_eq!(
            spec2.sources().len(),
            m.l0().len() + m.compacted().len() - 1,
            "the newest (own) L0 is left out: {spec2}"
        );
        assert_eq!(rewrite_spec(&m, true).unwrap().sources().len(), m.l0().len() + m.compacted().len());
        c.close().await.unwrap();
    }

    /// The whole lifecycle on one store: a split of shard 0 into 1 and 2,
    /// child 2 never written (a quiet child keeps its inherited run
    /// forever under size-tiered compaction), then a merge of 1 and 2 into
    /// 3. GC refuses while the op is pending and while any clone holds a
    /// checkpoint; forced compactions detach every child (the quiet one
    /// included) with every key intact; then the retired dirs and their
    /// assignments go, transitively (3 read 0's SSTs through 1 and 2).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn forced_detach_then_retired_dirs_go() {
        let store = Store { prefix: "gclife".into(), ..Store::memory(None) };
        let keys = parent(&store, ShardId(0), 400).await;
        put_json(&store, "assign/0000000000", &Assignment { frozen: Some(1), ..Default::default() }).await;
        // the op is still pending: nothing is touched
        let op = vlsync_store::slots::Reshard {
            id: 1,
            parents: vec![ShardId(0)],
            children: vec![],
            driver: "n".into(),
            extra: Default::default(),
        };
        put_json(&store, "assign/layout", &layout(&[(0, 0, 65536)], 3, Some(op))).await;
        clone_db(&store, ShardId(1), &[(ShardId(0), 0, 32768)]).await.unwrap();
        clone_db(&store, ShardId(2), &[(ShardId(0), 32768, 65536)]).await.unwrap();
        let owned = Arc::new(Mutex::new(Vec::new()));
        let g = gc(&store, owned.clone(), Duration::ZERO, None);
        assert!(g.dir_pass().await.unwrap().op_pending);
        // flipped: 0 is retired, but both children pin it
        put_json(&store, "assign/layout", &layout(&[(1, 0, 32768), (2, 32768, 65536)], 3, None)).await;
        put_json(&store, "assign/0000000001", &Assignment::default()).await;
        put_json(&store, "assign/0000000002", &Assignment::default()).await;
        let p = g.dir_pass().await.unwrap();
        assert_eq!((p.retired, p.deleted_dirs, p.held.get(&Held::Checkpoint)), (1, 0, Some(&1)), "{p:?}");
        let c1 = Arc::new(open_db(&store, ShardId(1), None).await.unwrap());
        let c2 = Arc::new(open_db(&store, ShardId(2), None).await.unwrap());
        // child 1 takes writes; child 2 never does
        for i in 0..50 {
            c1.put(k(100, &format!("h/c1-{i}")), "w").await.unwrap();
        }
        *owned.lock() = vec![(ShardId(1), c1.clone()), (ShardId(2), c2.clone())];
        wait_for("both children detached", 60, async || {
            g.compaction_pass().await.unwrap();
            let _ = c1.refresh_manifest().await;
            let _ = c2.refresh_manifest().await;
            c1.manifest().external_dbs().is_empty() && c2.manifest().external_dbs().is_empty()
        })
        .await;
        check_keys(&c1, &keys, 0, 32768).await;
        check_keys(&c2, &keys, 32768, 65536).await;
        // nothing pins 0 now: it goes, with its assignment
        let p = g.dir_pass().await.unwrap();
        assert_eq!((p.deleted_dirs, p.deleted_assigns), (1, 1), "{p:?}");
        assert_eq!(dirs(&store).await, vec![1, 2]);
        assert_eq!(assigns(&store).await, vec![1, 2]);
        check_keys(&c1, &keys, 0, 32768).await;
        check_keys(&c2, &keys, 32768, 65536).await;

        // merge 1 + 2 -> 3 before they compact again: 3 reads their SSTs
        c1.close().await.unwrap();
        c2.close().await.unwrap();
        clone_db(&store, ShardId(3), &[(ShardId(1), 0, 32768), (ShardId(2), 32768, 65536)]).await.unwrap();
        put_json(&store, "assign/layout", &layout(&[(3, 0, 65536)], 4, None)).await;
        put_json(&store, "assign/0000000003", &Assignment::default()).await;
        let p = g.dir_pass().await.unwrap();
        assert_eq!((p.retired, p.deleted_dirs, p.held.get(&Held::Checkpoint)), (2, 0, Some(&2)), "{p:?}");
        let m = Arc::new(open_db(&store, ShardId(3), None).await.unwrap());
        *owned.lock() = vec![(ShardId(3), m.clone())];
        wait_for("the merged shard detached", 60, async || {
            g.compaction_pass().await.unwrap();
            let _ = m.refresh_manifest().await;
            m.manifest().external_dbs().is_empty()
        })
        .await;
        let p = g.dir_pass().await.unwrap();
        assert_eq!((p.deleted_dirs, p.deleted_assigns), (2, 2), "{p:?}");
        assert_eq!(dirs(&store).await, vec![3]);
        assert_eq!(assigns(&store).await, vec![3]);
        check_keys(&m, &keys, 0, 65536).await;
        for i in 0..50 {
            assert!(m.get(k(100, &format!("h/c1-{i}"))).await.unwrap().is_some());
        }
        m.close().await.unwrap();
        // and it reopens from its own SSTs alone
        let m = open_db(&store, ShardId(3), None).await.unwrap();
        check_keys(&m, &keys, 0, 65536).await;
        m.close().await.unwrap();
    }

    /// A reader's (or a backup's) checkpoint in a retired dir holds it;
    /// so does the grace; an aborted op's half-made clone (never in any
    /// layout) goes and releases its parent's checkpoint with it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn checkpoints_grace_and_aborted_clones() {
        let store = Store { prefix: "gchold".into(), ..Store::memory(None) };
        let keys = parent(&store, ShardId(0), 100).await;
        parent(&store, ShardId(5), 10).await;
        // shard 0 stays live; an aborted split of it left clone 7
        clone_db(&store, ShardId(7), &[(ShardId(0), 0, 100)]).await.unwrap();
        put_json(&store, "assign/0000000007", &Assignment::default()).await;
        // shard 5 retired (out of the layout), held by a named checkpoint
        put_json(&store, "assign/layout", &layout(&[(0, 0, 65536)], 8, None)).await;
        let admin5 =
            slatedb::admin::AdminBuilder::new(crate::partition::db_path(&store, ShardId(5)), store.raw.clone()).build();
        let cp = admin5
            .create_detached_checkpoint(&slatedb::config::CheckpointOptions {
                lifetime: Some(Duration::from_secs(3600)),
                name: Some("backup".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        let g = gc(&store, Arc::new(Mutex::new(Vec::new())), Duration::from_secs(3600), None);
        // within the grace: everything kept
        let p = g.dir_pass().await.unwrap();
        assert_eq!((p.retired, p.deleted_dirs), (2, 0), "{p:?}");
        assert_eq!((p.held.get(&Held::Checkpoint), p.held.get(&Held::Grace)), (Some(&1), Some(&1)), "{p:?}");
        let admin0 =
            slatedb::admin::AdminBuilder::new(crate::partition::db_path(&store, ShardId(0)), store.raw.clone()).build();
        assert_eq!(
            admin0.list_checkpoints(None).await.unwrap().iter().filter(|c| c.expire_time.is_none()).count(),
            1,
            "clone 7 pins 0"
        );
        // past the grace: the aborted clone goes (and unpins 0); 5 stays
        let g = gc(&store, Arc::new(Mutex::new(Vec::new())), Duration::ZERO, None);
        let p = g.dir_pass().await.unwrap();
        assert_eq!((p.deleted_dirs, p.deleted_assigns, p.held.get(&Held::Checkpoint)), (1, 1, Some(&1)), "{p:?}");
        assert_eq!(dirs(&store).await, vec![0, 5]);
        assert!(
            admin0.list_checkpoints(None).await.unwrap().iter().all(|c| c.expire_time.is_some()),
            "0's pin went with the clone"
        );
        // the backup's checkpoint expires (deleted here): 5 goes too
        admin5.delete_checkpoint(cp.id).await.unwrap();
        let p = g.dir_pass().await.unwrap();
        assert_eq!(p.deleted_dirs, 1, "{p:?}");
        assert_eq!(dirs(&store).await, vec![0]);
        // the live shard is intact
        let db = open_db(&store, ShardId(0), None).await.unwrap();
        check_keys(&db, &keys, 0, 65536).await;
        db.close().await.unwrap();
    }

    /// Crashes: between a dir's delete and its assignment's (the next pass
    /// deletes the orphaned assignment), and in the middle of a dir's
    /// delete (SlateDB's `.deleting` marker: the next pass finishes it even
    /// with the manifest gone).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn crash_mid_gc_resumes() {
        let store = Store { prefix: "gccrash".into(), ..Store::memory(None) };
        parent(&store, ShardId(0), 50).await;
        parent(&store, ShardId(1), 50).await;
        let keys = parent(&store, ShardId(2), 50).await;
        for id in ["0000000000", "0000000001"] {
            put_json(&store, &format!("assign/{id}"), &Assignment { frozen: Some(1), ..Default::default() }).await;
        }
        put_json(&store, "assign/layout", &layout(&[(2, 0, 65536)], 3, None)).await;
        let crash = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let g = gc(&store, Arc::new(Mutex::new(Vec::new())), Duration::ZERO, Some(crash.clone()));
        let p = g.dir_pass().await.unwrap();
        assert_eq!((p.deleted_dirs, p.deleted_assigns), (1, 0), "stopped after the first dir: {p:?}");
        assert_eq!(dirs(&store).await, vec![1, 2]);
        assert_eq!(assigns(&store).await, vec![0, 1], "0's assignment outlived its dir");
        // a delete of 1 that died half-way: marker written, manifests gone
        let dir1 = crate::partition::db_path(&store, ShardId(1));
        store.raw.put(&Path::from(format!("{dir1}/.deleting")), bytes::Bytes::new().into()).await.unwrap();
        let manifests: Vec<Path> = store
            .raw
            .list(Some(&Path::from(format!("{dir1}/manifest"))))
            .filter_map(|m| async move { m.ok().map(|m| m.location) })
            .collect()
            .await;
        for m in manifests {
            store.raw.delete(&m).await.unwrap();
        }
        let p = g.dir_pass().await.unwrap();
        assert_eq!((p.deleted_dirs, p.deleted_assigns), (1, 2), "{p:?}");
        assert_eq!(dirs(&store).await, vec![2]);
        assert!(assigns(&store).await.is_empty());
        let left: Vec<Path> = store
            .raw
            .list(Some(&Path::from(dir1)))
            .filter_map(|m| async move { m.ok().map(|m| m.location) })
            .collect()
            .await;
        assert!(left.is_empty(), "{left:?}");
        let db = open_db(&store, ShardId(2), None).await.unwrap();
        check_keys(&db, &keys, 0, 65536).await;
        db.close().await.unwrap();
        // nothing else to do, and a dir with neither manifest nor marker is left alone
        store
            .raw
            .put(
                &Path::from(format!("{}/state/0000000001/stray", store.prefix)),
                bytes::Bytes::from_static(b"x").into(),
            )
            .await
            .unwrap();
        let p = g.dir_pass().await.unwrap();
        assert_eq!((p.deleted_dirs, p.held.get(&Held::Other)), (0, Some(&1)), "{p:?}");
    }

    /// Counts LISTs and GETs on top of another store.
    #[derive(Debug)]
    struct Counting {
        inner: Arc<dyn object_store::ObjectStore>,
        lists: std::sync::atomic::AtomicU64,
        gets: std::sync::atomic::AtomicU64,
    }

    impl std::fmt::Display for Counting {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "Counting")
        }
    }

    impl Counting {
        /// (LISTs, GETs) since the last call.
        fn take(&self) -> (u64, u64) {
            use std::sync::atomic::Ordering::Relaxed;
            (self.lists.swap(0, Relaxed), self.gets.swap(0, Relaxed))
        }

        /// Waits until nothing has touched the store for 200 ms, then resets the
        /// counts: a closed SlateDB can still have requests in flight on a slow
        /// machine, and they'd be counted against the next pass.
        async fn settle(&self) {
            loop {
                self.take();
                tokio::time::sleep(Duration::from_millis(200)).await;
                if self.take() == (0, 0) {
                    return;
                }
            }
        }
    }

    #[async_trait::async_trait]
    impl object_store::ObjectStore for Counting {
        async fn put_opts(
            &self,
            location: &Path,
            payload: object_store::PutPayload,
            opts: object_store::PutOptions,
        ) -> object_store::Result<object_store::PutResult> {
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
            self.gets.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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
            self.lists.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.inner.list(prefix)
        }
        async fn list_with_delimiter(&self, prefix: Option<&Path>) -> object_store::Result<object_store::ListResult> {
            self.lists.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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

    fn counting_store(prefix: &str) -> (Store, Arc<Counting>) {
        let c =
            Arc::new(Counting { inner: Store::memory(None).raw, lists: Default::default(), gets: Default::default() });
        (Store { prefix: prefix.into(), raw: c.clone(), ..Store::memory(None) }, c)
    }

    /// Idle passes skip their LISTs (one layout GET each); a layout change
    /// runs a full pass at once, and FULL_PASS_EVERY after the last full
    /// pass one runs anyway and finds what appeared without a layout
    /// change.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn idle_dir_passes_skip() {
        let (store, n) = counting_store("gcidle");
        parent(&store, ShardId(0), 10).await;
        put_json(&store, "assign/0000000000", &Assignment::default()).await;
        // id 1 was handed out (an aborted op's child, long gone)
        put_json(&store, "assign/layout", &layout(&[(0, 0, 65536)], 2, None)).await;
        let g = gc(&store, Arc::new(Mutex::new(Vec::new())), Duration::ZERO, None);
        n.settle().await;
        let p = g.dir_pass().await.unwrap();
        assert!(!p.skipped && p.retired == 0, "{p:?}");
        assert_eq!(n.take(), (3, 1), "a full pass: LIST state/ twice, LIST assign/, the layout GET");
        for _ in 0..3 {
            assert!(g.dir_pass().await.unwrap().skipped);
            assert_eq!(n.take(), (0, 1), "a skipped pass: the layout GET only");
        }
        // any layout change (here only its version): a full pass at once
        let mut l = layout(&[(0, 0, 65536)], 2, None);
        l.version = 3;
        put_json(&store, "assign/layout", &l).await;
        assert!(!g.dir_pass().await.unwrap().skipped);
        assert_eq!(n.take().0, 3);
        assert!(g.dir_pass().await.unwrap().skipped);
        // something out of the layout appears without a layout change (a
        // stale former owner rewriting a deleted shard's record): skipped
        // passes leave it, the hourly full pass deletes it
        put_json(&store, "assign/0000000001", &Assignment::default()).await;
        let p = g.dir_pass().await.unwrap();
        assert!(p.skipped && p.deleted_assigns == 0, "{p:?}");
        assert_eq!(assigns(&store).await, vec![0, 1]);
        {
            let mut st = g.st.lock();
            let at = &mut st.idle.as_mut().expect("idle").1;
            *at = at.checked_sub(FULL_PASS_EVERY).unwrap();
        }
        let p = g.dir_pass().await.unwrap();
        assert_eq!((p.skipped, p.deleted_assigns), (false, 1), "{p:?}");
        assert_eq!(assigns(&store).await, vec![0]);
        // that pass found something: the next one is full too, then idle
        assert!(!g.dir_pass().await.unwrap().skipped);
        assert!(g.dir_pass().await.unwrap().skipped);
        // an unreadable layout (gone here) forgets it all
        store.raw.delete(&Path::from("gcidle/assign/layout")).await.unwrap();
        assert!(!g.dir_pass().await.unwrap().skipped);
        put_json(&store, "assign/layout", &l).await;
        n.take();
        assert!(!g.dir_pass().await.unwrap().skipped);
        assert_eq!(n.take().0, 3);
    }

    /// A split (op pending, then flipped) runs full passes at once, and a
    /// retired parent held by the grace keeps every pass full until it is
    /// deleted; only then do passes skip again.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn reshard_and_grace_keep_passes_running() {
        let (store, n) = counting_store("gcgrace");
        parent(&store, ShardId(0), 10).await;
        put_json(&store, "assign/0000000000", &Assignment::default()).await;
        put_json(&store, "assign/layout", &layout(&[(0, 0, 65536)], 1, None)).await;
        let g = gc(&store, Arc::new(Mutex::new(Vec::new())), Duration::from_secs(3), None);
        assert!(!g.dir_pass().await.unwrap().skipped);
        assert!(g.dir_pass().await.unwrap().skipped);
        // the split is planned: nothing touched, nothing skipped
        let op = vlsync_store::slots::Reshard {
            id: 1,
            parents: vec![ShardId(0)],
            children: vec![],
            driver: "n".into(),
            extra: Default::default(),
        };
        put_json(&store, "assign/layout", &layout(&[(0, 0, 65536)], 2, Some(op))).await;
        let p = g.dir_pass().await.unwrap();
        assert!(p.op_pending && !p.skipped, "{p:?}");
        assert!(g.st.lock().idle.is_none());
        // the parent's last writes (its manifest changes now), the child, the flip
        put_json(&store, "assign/0000000000", &Assignment { frozen: Some(1), ..Default::default() }).await;
        parent(&store, ShardId(0), 10).await;
        parent(&store, ShardId(1), 10).await;
        put_json(&store, "assign/0000000001", &Assignment::default()).await;
        put_json(&store, "assign/layout", &layout(&[(1, 0, 65536)], 2, None)).await;
        n.take();
        for _ in 0..2 {
            let p = g.dir_pass().await.unwrap();
            assert_eq!(
                (p.skipped, p.retired, p.deleted_dirs, p.held.get(&Held::Grace)),
                (false, 1, 0, Some(&1)),
                "{p:?}"
            );
            assert!(n.take().0 >= 3, "a full pass");
        }
        wait_for("the parent deleted", 20, async || {
            let p = g.dir_pass().await.unwrap();
            assert!(!p.skipped, "{p:?}");
            p.deleted_dirs == 1
        })
        .await;
        assert_eq!(dirs(&store).await, vec![1]);
        assert_eq!(assigns(&store).await, vec![1]);
        let p = g.dir_pass().await.unwrap();
        assert!(!p.skipped && p.retired == 0, "the deleting pass found a retired dir: the next is full: {p:?}");
        assert!(g.dir_pass().await.unwrap().skipped);
    }

    /// A forced detach whose owner dies before the compaction ran (the DB
    /// dropped mid-way, a new owner opens it and a new GC instance takes
    /// over): the child still detaches and keeps every key.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn crash_during_forced_detach() {
        let store = Store { prefix: "gcdet".into(), ..Store::memory(None) };
        let keys = parent(&store, ShardId(0), 300).await;
        clone_db(&store, ShardId(1), &[(ShardId(0), 0, 65536)]).await.unwrap();
        let c = Arc::new(open_db(&store, ShardId(1), None).await.unwrap());
        let owned = Arc::new(Mutex::new(vec![(ShardId(1), c.clone())]));
        let g = gc(&store, owned.clone(), Duration::ZERO, None);
        // submitted, then the node "dies": the DB goes without a clean close
        wait_for("a submitted detach", 20, async || {
            g.compaction_pass().await.unwrap();
            !g.st.lock().inflight.is_empty()
        })
        .await;
        owned.lock().clear();
        drop(c);
        let c = Arc::new(open_db(&store, ShardId(1), None).await.unwrap());
        *owned.lock() = vec![(ShardId(1), c.clone())];
        let g2 = gc(&store, owned.clone(), Duration::ZERO, None);
        wait_for("detached after the crash", 60, async || {
            g2.compaction_pass().await.unwrap();
            let _ = c.refresh_manifest().await;
            c.manifest().external_dbs().is_empty()
        })
        .await;
        check_keys(&c, &keys, 0, 65536).await;
        c.close().await.unwrap();
    }
}
