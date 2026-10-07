//! Objects and bytes in the bucket by key component (objstats::component),
//! for `vlpds.admin.getStorageStats` (docs/operations/admin-console.md,
//! "Storage stats"), kept without listing the bucket.
//!
//! Every PUT, copy and DELETE this node makes goes through objstats'
//! `Counting`, which tells [`StoreStats`] what changed. A PUT knows its
//! size. A DELETE doesn't, so each node keeps the sizes of the keys it has
//! seen (its own PUTs, and every object in the LISTs its background jobs run
//! anyway: retention lists the segments it deletes, SlateDB's GC the SSTs,
//! the blob sweep the blobs), bounded to [`SIZES_KEPT`] keys. A change it
//! has to guess is counted `uncertain`: a DELETE of a key it hasn't seen
//! (its size is taken as the component's mean), an overwrite it can't tell
//! from a create. A component with no uncertain change since the seed is
//! exact.
//!
//! Each node folds its changes into one control-plane object,
//! `stats/storage`, every [`FLUSH_EVERY`] and when it shuts down: a GET and
//! a conditional PUT, never on a request or commit path. The totals are the
//! seed (what the last backfill listed) plus every node's folded changes
//! plus what live nodes hold unfolded. A node that crashes loses up to one
//! interval of changes; its next start marks the totals inexact.
//!
//! The backfill (`vlpds.admin.backfillStorageStats`) lists the prefix once,
//! in key order, rate-limited and capped, saving its place so it can stop
//! and resume. Changes made while it runs can land on either side of the
//! listing, so every node keeps them aside (a "window") with their path and
//! time. At the end each one is checked against the page that listed its
//! key: one made before that page was read is already in the listing and
//! is dropped, one made after is kept, and one made while the page was in
//! flight (or by a node that missed the start) is kept as uncertain.

use crate::store::Store;
use object_store::path::Path;
use object_store::{ObjectStore, ObjectStoreExt, PutMode, PutOptions, PutPayload, UpdateVersion};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::time::Duration;

pub const FLUSH_EVERY: Duration = Duration::from_secs(300);
/// Keys whose size a node remembers: two generations of half this, ~16
/// bytes a key.
pub const SIZES_KEPT: usize = 262_144;
/// Window changes a node keeps per backfill; past this they are kept as
/// uncertain.
pub const WINDOW_KEPT: usize = 200_000;
/// A page's read time is known to the listing node's clock: changes this
/// close to it on another node's clock are uncertain.
const SKEW_US: u64 = 250_000;
/// A runner that hasn't saved its place for this long can be taken over.
const RUNNER_STALE_MS: u64 = 120_000;
const SAVE_EVERY_PAGES: u64 = 20;
const SAVE_EVERY: Duration = Duration::from_secs(15);
pub const DEFAULT_PAGES_PER_SECOND: f64 = 2.0;
pub const MAX_PAGES_PER_SECOND: f64 = 50.0;
/// A slower runner would go longer than [`RUNNER_STALE_MS`] between saves.
pub const MIN_PAGES_PER_SECOND: f64 = 0.1;
pub const MAX_REQUESTS: u64 = 1_000_000;
/// S3, GCS and R2 list 1,000 keys a request.
pub const PAGE: u64 = 1000;

const DOC: &str = "stats/storage";
const BACKFILL_DOC: &str = "stats/backfill";

/// Components that overwrite their own keys: an overwrite of a key the node
/// hasn't seen is more likely a replace than a create.
fn overwrites_in_place(comp: &str) -> bool {
    comp.starts_with("ctl_") || matches!(comp, "retention_report" | "state_gc_boundary" | "state_other" | "other")
}

pub fn now_us() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_micros() as u64)
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64)
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counts {
    #[serde(default)]
    pub objects: i64,
    #[serde(default)]
    pub bytes: i64,
    /// Changes whose effect was guessed.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub uncertain: u64,
}

fn is_zero(n: &u64) -> bool {
    *n == 0
}

impl Counts {
    pub fn add(&mut self, o: &Counts) {
        self.objects += o.objects;
        self.bytes += o.bytes;
        self.uncertain += o.uncertain;
    }

    fn sub(&mut self, o: &Counts) {
        self.objects -= o.objects;
        self.bytes -= o.bytes;
        self.uncertain = self.uncertain.saturating_sub(o.uncertain);
    }

    fn is_empty(&self) -> bool {
        *self == Counts::default()
    }

    /// What a change of unknown standing counts as.
    fn uncertain(mut self) -> Counts {
        self.uncertain = self.uncertain.max(1);
        self
    }
}

pub type Comps = BTreeMap<String, Counts>;

pub fn add_all(into: &mut Comps, from: &Comps) {
    for (k, v) in from {
        into.entry(k.clone()).or_default().add(v);
    }
    into.retain(|_, v| !v.is_empty());
}

fn sub_all(into: &mut Comps, from: &Comps) {
    for (k, v) in from {
        into.entry(k.clone()).or_default().sub(v);
    }
    into.retain(|_, v| !v.is_empty());
}

/// Every count of `c` made uncertain.
fn all_uncertain(c: &Comps) -> Comps {
    c.iter().map(|(k, v)| (k.clone(), v.uncertain())).collect()
}

fn key_hash(path: &str) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    path.hash(&mut h);
    h.finish()
}

#[derive(Default)]
struct Sizes {
    cur: HashMap<u64, u64>,
    old: HashMap<u64, u64>,
}

impl Sizes {
    fn get(&self, k: u64) -> Option<u64> {
        self.cur.get(&k).or_else(|| self.old.get(&k)).copied()
    }

    fn insert(&mut self, k: u64, size: u64) {
        self.old.remove(&k);
        self.cur.insert(k, size);
        if self.cur.len() >= SIZES_KEPT / 2 {
            self.old = std::mem::take(&mut self.cur);
        }
    }

    fn remove(&mut self, k: u64) -> Option<u64> {
        let a = self.cur.remove(&k);
        let b = self.old.remove(&k);
        a.or(b)
    }
}

#[derive(Clone, Debug)]
struct WindowOp {
    path: Box<str>,
    comp: &'static str,
    d: Counts,
    /// Unix µs: the change landed between the two.
    start: u64,
    end: u64,
}

#[derive(Default)]
struct Window {
    epoch: u64,
    ops: Vec<WindowOp>,
    /// Past [`WINDOW_KEPT`]: kept as uncertain.
    overflow: Comps,
    /// Changes from before the window not yet folded: the listing has
    /// them, so a finished backfill drops them; until then they fold as
    /// usual.
    pre: Comps,
}

#[derive(Default)]
struct Inner {
    /// Changes not yet folded into the object.
    pending: Comps,
    window: Option<Window>,
    /// Component means (bytes per object) from the last totals read.
    means: HashMap<String, i64>,
    observed: Observed,
    /// The first fold of this process is done.
    folded: bool,
}

/// One per node, shared by its object-store clients.
pub struct StoreStats {
    prefix: String,
    node_id: Mutex<String>,
    inner: Mutex<Inner>,
    sizes: Mutex<Sizes>,
    ctl: Mutex<Option<Store>>,
    flush_lock: tokio::sync::Mutex<()>,
    running: Mutex<Option<tokio::task::AbortHandle>>,
}

impl std::fmt::Debug for StoreStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoreStats").field("prefix", &self.prefix).finish()
    }
}

/// What kind of PUT it was.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PutKind {
    /// `PutMode::Create`: the key was new.
    Create,
    /// `PutMode::Update`: the key existed.
    Replace,
    /// `PutMode::Overwrite`: either.
    Overwrite,
}

impl From<&PutMode> for PutKind {
    fn from(m: &PutMode) -> PutKind {
        match m {
            PutMode::Create => PutKind::Create,
            PutMode::Update(_) => PutKind::Replace,
            PutMode::Overwrite => PutKind::Overwrite,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Seed {
    /// Unix ms the backfill finished.
    pub at: u64,
    pub components: Comps,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeMark {
    pub flushed_at: u64,
    /// Set while the node runs; cleared by its last fold on shutdown. Found
    /// set by the node's next start: it crashed, and lost what it hadn't
    /// folded.
    pub open: bool,
}

/// `stats/storage`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatsDoc {
    #[serde(default)]
    pub seed: Option<Seed>,
    /// Changes folded since the seed.
    #[serde(default)]
    pub deltas: Comps,
    /// Changes folded while a backfill ran by nodes that didn't know: kept,
    /// uncertain, and carried into `deltas` by the next seed.
    #[serde(default)]
    pub late: Comps,
    #[serde(default)]
    pub nodes: BTreeMap<String, NodeMark>,
    /// The latest backfill's.
    #[serde(default)]
    pub epoch: u64,
    #[serde(default)]
    pub window_active: bool,
    /// A node crashed since the seed: its unfolded changes are gone.
    #[serde(default)]
    pub lost: bool,
}

impl StatsDoc {
    pub fn folded(&self) -> Comps {
        let mut t = self.seed.as_ref().map(|s| s.components.clone()).unwrap_or_default();
        add_all(&mut t, &self.deltas);
        add_all(&mut t, &self.late);
        t
    }
}

/// One page of a backfill's listing: requested at `s`, answered at `r`
/// (unix µs on the listing node), ending at key `last` (None: the end).
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Page {
    pub s: u64,
    pub r: u64,
    pub last: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackfillDoc {
    pub epoch: u64,
    /// running | capped | done | failed
    pub phase: String,
    pub runner: String,
    pub heartbeat_at: u64,
    pub started_at: u64,
    #[serde(default)]
    pub finished_at: Option<u64>,
    /// The last key listed: a resume lists after it.
    #[serde(default)]
    pub cursor: Option<String>,
    pub requests: u64,
    pub keys: u64,
    pub bytes: u64,
    /// This call's budget of LIST requests.
    pub max_requests: u64,
    pub pages_per_second: f64,
    #[serde(default)]
    pub partial: Comps,
    #[serde(default)]
    pub timeline: Vec<Page>,
    #[serde(default)]
    pub error: Option<String>,
}

impl BackfillDoc {
    /// Without the timeline and per-component counts, for the API.
    pub fn summary(&self) -> serde_json::Value {
        serde_json::json!({
            "epoch": self.epoch,
            "phase": self.phase,
            "runner": self.runner,
            "heartbeatAt": self.heartbeat_at,
            "startedAt": self.started_at,
            "finishedAt": self.finished_at,
            "cursor": self.cursor,
            "requests": self.requests,
            "keys": self.keys,
            "bytes": self.bytes,
            "maxRequests": self.max_requests,
            "pagesPerSecond": self.pages_per_second,
            "error": self.error,
        })
    }
}

/// Where a window change falls against the listing.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Side {
    /// Made before its key's page was read: the listing has it.
    Before,
    After,
    Unsure,
}

/// `timeline` in listing order; the key's page is the first whose `last`
/// is at or past it (None: the end).
pub fn side(timeline: &[Page], path: &str, start: u64, end: u64, skew: u64) -> Side {
    let i = timeline.partition_point(|p| p.last.as_deref().is_some_and(|l| l < path));
    let Some(p) = timeline.get(i) else {
        // past every page read: a listing that stopped early never read it
        return Side::After;
    };
    if end + skew < p.s {
        Side::Before
    } else if start > p.r + skew {
        Side::After
    } else {
        Side::Unsure
    }
}

fn classify(timeline: &[Page], w: Window, skew: u64) -> Comps {
    let mut out = w.overflow;
    for op in w.ops {
        let d = match side(timeline, &op.path, op.start, op.end, skew) {
            Side::Before => continue,
            Side::After => op.d,
            Side::Unsure => op.d.uncertain(),
        };
        out.entry(op.comp.to_string()).or_default().add(&d);
    }
    out.retain(|_, v| !v.is_empty());
    out
}

async fn read_json<T: serde::de::DeserializeOwned + Default>(
    store: &Store,
    rel: &str,
) -> anyhow::Result<(T, Option<UpdateVersion>)> {
    let p = Path::from(format!("{}/{rel}", store.prefix));
    match store.raw.get(&p).await {
        Ok(r) => {
            let v = UpdateVersion { e_tag: r.meta.e_tag.clone(), version: r.meta.version.clone() };
            let b = r.bytes().await?;
            Ok((serde_json::from_slice(&b)?, Some(v)))
        }
        Err(object_store::Error::NotFound { .. }) => Ok((T::default(), None)),
        Err(e) => Err(e.into()),
    }
}

/// Ok(false): the object changed since `ver` was read.
async fn write_json<T: Serialize>(store: &Store, rel: &str, v: &T, ver: Option<UpdateVersion>) -> anyhow::Result<bool> {
    let p = Path::from(format!("{}/{rel}", store.prefix));
    let mode = match ver {
        Some(v) => PutMode::Update(v),
        None => PutMode::Create,
    };
    let opts = PutOptions { mode, ..Default::default() };
    match store.raw.put_opts(&p, PutPayload::from(serde_json::to_vec(v)?), opts).await {
        Ok(_) => Ok(true),
        Err(e) if crate::cluster::is_conflict(&e) || matches!(e, object_store::Error::NotFound { .. }) => Ok(false),
        Err(e) => Err(e.into()),
    }
}

const CAS_ROUNDS: usize = 8;

impl StoreStats {
    pub fn new(prefix: &str) -> Arc<StoreStats> {
        Arc::new(StoreStats {
            prefix: prefix.trim_end_matches('/').to_string(),
            node_id: Mutex::new("single".into()),
            inner: Default::default(),
            sizes: Default::default(),
            ctl: Mutex::new(None),
            flush_lock: Default::default(),
            running: Mutex::new(None),
        })
    }

    /// Where it folds its changes, and as which node.
    pub fn attach(&self, ctl: Store, node_id: &str) {
        *self.ctl.lock() = Some(ctl);
        *self.node_id.lock() = node_id.to_string();
    }

    pub fn node_id(&self) -> String {
        self.node_id.lock().clone()
    }

    fn ctl(&self) -> anyhow::Result<Store> {
        self.ctl.lock().clone().ok_or_else(|| anyhow::anyhow!("storage stats: no control-plane store attached"))
    }

    fn mean(&self, comp: &str) -> i64 {
        self.inner.lock().means.get(comp).copied().unwrap_or(0)
    }

    fn record(&self, path: &str, comp: &'static str, d: Counts, start: u64) {
        if d.is_empty() {
            return;
        }
        let mut i = self.inner.lock();
        match i.window.as_mut() {
            Some(w) if w.ops.len() < WINDOW_KEPT => {
                w.ops.push(WindowOp { path: path.into(), comp, d, start, end: now_us() });
            }
            Some(w) => w.overflow.entry(comp.to_string()).or_default().add(&d.uncertain()),
            None => i.pending.entry(comp.to_string()).or_default().add(&d),
        }
    }

    pub fn put(&self, path: &str, comp: &'static str, kind: PutKind, size: u64, start: u64) {
        let k = key_hash(path);
        let old = self.sizes.lock().get(k);
        let size_i = size as i64;
        let d = match (kind, old) {
            (PutKind::Create, _) => Counts { objects: 1, bytes: size_i, uncertain: 0 },
            (_, Some(o)) => Counts { objects: 0, bytes: size_i - o as i64, uncertain: 0 },
            (PutKind::Replace, None) => Counts { objects: 0, bytes: 0, uncertain: 1 },
            (PutKind::Overwrite, None) if overwrites_in_place(comp) => Counts { objects: 0, bytes: 0, uncertain: 1 },
            (PutKind::Overwrite, None) => Counts { objects: 1, bytes: size_i, uncertain: 0 },
        };
        self.sizes.lock().insert(k, size);
        self.record(path, comp, d, start);
    }

    pub fn copied(&self, from: &str, to: &str, comp: &'static str, start: u64) {
        let (src, old) = {
            let s = self.sizes.lock();
            (s.get(key_hash(from)), s.get(key_hash(to)))
        };
        let size = src.map(|s| s as i64);
        let d = match (old, size) {
            (Some(o), Some(s)) => Counts { objects: 0, bytes: s - o as i64, uncertain: 0 },
            (Some(_), None) => Counts { objects: 0, bytes: 0, uncertain: 1 },
            (None, Some(s)) => Counts { objects: 1, bytes: s, uncertain: 0 },
            (None, None) => Counts { objects: 1, bytes: self.mean(comp), uncertain: 1 },
        };
        if let Some(s) = src {
            self.sizes.lock().insert(key_hash(to), s);
        }
        self.record(to, comp, d, start);
    }

    pub fn deleted(&self, path: &str, comp: &'static str, start: u64) {
        let d = match self.sizes.lock().remove(key_hash(path)) {
            Some(s) => Counts { objects: -1, bytes: -(s as i64), uncertain: 0 },
            None => Counts { objects: -1, bytes: -self.mean(comp), uncertain: 1 },
        };
        self.record(path, comp, d, start);
    }

    pub fn listed(&self, path: &str, size: u64) {
        self.sizes.lock().insert(key_hash(path), size);
    }

    /// A LIST of `prefix` read to its end.
    pub fn list_done(&self, prefix: &str, objects: u64, bytes: u64) {
        let mut i = self.inner.lock();
        if i.observed.len() >= 4096 && !i.observed.contains_key(prefix) {
            return;
        }
        i.observed.insert(prefix.to_string(), (objects, bytes, now_ms()));
    }

    /// Whether listings of `prefix` should feed the size map: the
    /// backfill's own listing of everything would only churn it.
    pub fn sizes_from(&self, prefix: Option<&str>) -> bool {
        prefix.is_some_and(|p| p.trim_end_matches('/') != self.prefix)
    }

    pub fn observed(&self) -> (u64, u64, usize) {
        observed_total(&self.observed_map())
    }

    pub fn observed_map(&self) -> Observed {
        self.inner.lock().observed.clone()
    }

    /// This node's part of getStorageStats.
    pub fn local(&self) -> serde_json::Value {
        let i = self.inner.lock();
        let (window_ops, window_epoch) = i.window.as_ref().map_or((0, None), |w| (w.ops.len(), Some(w.epoch)));
        let mut pending = i.pending.clone();
        if let Some(w) = &i.window {
            add_all(&mut pending, &w.pre);
        }
        serde_json::json!({
            "pending": pending,
            "windowEpoch": window_epoch,
            "windowChanges": window_ops,
            "observed": i.observed,
        })
    }

    /// Folds this node's changes into `stats/storage`. `closing`: the
    /// node's last fold (shutdown), which also gives up an open window.
    pub async fn flush(&self, closing: bool) -> anyhow::Result<()> {
        self.fold(closing, None).await
    }

    /// `entering`: the backfill whose window this node is about to open;
    /// what it holds is from before it.
    async fn fold(&self, closing: bool, entering: Option<u64>) -> anyhow::Result<()> {
        let ctl = self.ctl()?;
        let _g = self.flush_lock.lock().await;
        if closing {
            let mut i = self.inner.lock();
            if let Some(w) = i.window.as_mut() {
                for op in w.ops.drain(..) {
                    w.overflow.entry(op.comp.to_string()).or_default().add(&op.d.uncertain());
                }
            }
        }
        let me = self.node_id();
        for _ in 0..CAS_ROUNDS {
            let (mut doc, ver): (StatsDoc, _) = read_json(&ctl, DOC).await?;
            let mine = self.inner.lock().window.as_ref().map(|w| w.epoch);
            if let Some(e) = mine {
                if !doc.window_active || doc.epoch != e {
                    // the backfill ended (or another began) without us hearing
                    self.end_window(e).await?;
                    continue;
                }
            }
            let (pending, overflow, pre, folded) = {
                let i = self.inner.lock();
                let w = i.window.as_ref();
                (
                    i.pending.clone(),
                    w.map(|w| w.overflow.clone()).unwrap_or_default(),
                    w.map(|w| w.pre.clone()).unwrap_or_default(),
                    i.folded,
                )
            };
            if !folded && doc.nodes.get(&me).is_some_and(|n| n.open) {
                doc.lost = true;
            }
            let unaware = doc.window_active && mine.is_none() && entering != Some(doc.epoch);
            match unaware {
                // ours are from before or during the listing: can't tell which
                true => add_all(&mut doc.late, &all_uncertain(&pending)),
                false => add_all(&mut doc.deltas, &pending),
            }
            add_all(&mut doc.deltas, &pre);
            add_all(&mut doc.late, &overflow);
            doc.nodes.insert(me.clone(), NodeMark { flushed_at: now_ms(), open: !closing });
            if !write_json(&ctl, DOC, &doc, ver).await? {
                continue;
            }
            let mut i = self.inner.lock();
            sub_all(&mut i.pending, &pending);
            if let Some(w) = i.window.as_mut() {
                sub_all(&mut w.overflow, &overflow);
                sub_all(&mut w.pre, &pre);
            }
            if unaware && !closing {
                // what came in during the fold is from the window, unsorted
                let during = all_uncertain(&std::mem::take(&mut i.pending));
                i.window = Some(Window { epoch: doc.epoch, overflow: during, ..Default::default() });
            }
            i.folded = true;
            i.means = means(&doc.folded());
            return Ok(());
        }
        anyhow::bail!("storage stats: {DOC} kept changing under the fold")
    }

    /// Changes from here on are kept aside until the backfill `epoch` ends.
    /// What came before is folded first: the listing has it.
    pub async fn begin_window(&self, epoch: u64) -> anyhow::Result<()> {
        if self.inner.lock().window.as_ref().is_some_and(|w| w.epoch == epoch) {
            return Ok(());
        }
        let r = self.fold(false, Some(epoch)).await;
        let mut i = self.inner.lock();
        if i.window.as_ref().is_none_or(|w| w.epoch != epoch) {
            let mut pre = std::mem::take(&mut i.pending);
            if let Some(w) = i.window.take() {
                // a backfill that was overtaken: none of its window is sorted
                for op in &w.ops {
                    pre.entry(op.comp.to_string()).or_default().add(&op.d.uncertain());
                }
                add_all(&mut pre, &w.overflow);
                add_all(&mut pre, &w.pre);
            }
            i.window = Some(Window { epoch, pre, ..Default::default() });
        }
        r
    }

    /// Sorts the window of backfill `epoch` against its listing into this
    /// node's changes. A backfill that didn't finish (or was replaced)
    /// leaves every change kept, as uncertain.
    pub async fn end_window(&self, epoch: u64) -> anyhow::Result<()> {
        if self.inner.lock().window.as_ref().is_none_or(|w| w.epoch != epoch) {
            return Ok(());
        }
        let (doc, _): (BackfillDoc, _) = read_json(&self.ctl()?, BACKFILL_DOC).await?;
        let mut i = self.inner.lock();
        let Some(w) = i.window.take_if(|w| w.epoch == epoch) else { return Ok(()) };
        let kept = if doc.epoch == epoch && doc.phase == "done" {
            classify(&doc.timeline, w, if doc.runner == self.node_id() { 0 } else { SKEW_US })
        } else {
            let mut k = w.overflow;
            add_all(&mut k, &w.pre);
            for op in w.ops {
                k.entry(op.comp.to_string()).or_default().add(&op.d.uncertain());
            }
            k
        };
        add_all(&mut i.pending, &kept);
        Ok(())
    }

    /// Folds every [`FLUSH_EVERY`] while `self` lives.
    pub fn start(self: &Arc<Self>) {
        let weak = Arc::downgrade(self);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + FLUSH_EVERY, FLUSH_EVERY);
            loop {
                tick.tick().await;
                let Some(s) = weak.upgrade() else { return };
                if let Err(e) = s.flush(false).await {
                    tracing::warn!("storage stats: folding this node's changes: {e:#}");
                }
            }
        });
    }

    pub async fn read_doc(&self) -> anyhow::Result<StatsDoc> {
        Ok(read_json::<StatsDoc>(&self.ctl()?, DOC).await?.0)
    }

    pub async fn read_backfill(&self) -> anyhow::Result<Option<BackfillDoc>> {
        let (d, v): (BackfillDoc, _) = read_json(&self.ctl()?, BACKFILL_DOC).await?;
        Ok(v.map(|_| d))
    }

    pub fn note_means(&self, totals: &Comps) {
        self.inner.lock().means = means(totals);
    }

    pub fn backfill_running_here(&self) -> bool {
        self.running.lock().as_ref().is_some_and(|h| !h.is_finished())
    }
}

/// prefix -> (objects, bytes, unix ms) of the latest complete LIST of it.
pub type Observed = BTreeMap<String, (u64, u64, u64)>;

/// What the observed LISTs add up to, counting a prefix only when no
/// observed prefix contains it: (objects, bytes, prefixes counted).
pub fn observed_total(m: &Observed) -> (u64, u64, usize) {
    let (mut objects, mut bytes, mut n) = (0, 0, 0);
    for (k, (o, b, _)) in m {
        let nested = m.keys().any(|p| p != k && k.starts_with(&format!("{}/", p.trim_end_matches('/'))));
        if !nested {
            objects += o;
            bytes += b;
            n += 1;
        }
    }
    (objects, bytes, n)
}

/// Merges another node's observations: the later LIST of a prefix wins.
pub fn merge_observed(into: &mut Observed, from: &Observed) {
    for (k, v) in from {
        if into.get(k).is_none_or(|o| o.2 < v.2) {
            into.insert(k.clone(), *v);
        }
    }
}

fn means(t: &Comps) -> HashMap<String, i64> {
    t.iter().filter(|(_, c)| c.objects > 0).map(|(k, c)| (k.clone(), c.bytes.max(0) / c.objects)).collect()
}

// ------------------------------------------------------------------ backfill

#[derive(Clone, Debug)]
pub struct BackfillOpts {
    pub max_requests: u64,
    pub pages_per_second: f64,
    /// Start over instead of resuming a stopped run.
    pub restart: bool,
}

/// Tells every node a window began (`"begin"`) or ended (`"end"`); returns
/// the nodes that didn't hear it.
pub type Broadcast = Arc<dyn Fn(u64, &'static str) -> futures::future::BoxFuture<'static, Vec<String>> + Send + Sync>;

/// A run whose runner saved its place lately.
pub fn runner_alive(d: &BackfillDoc) -> bool {
    d.phase == "running" && now_ms().saturating_sub(d.heartbeat_at) < RUNNER_STALE_MS
}

#[derive(Debug)]
pub enum StartError {
    /// Another node runs one.
    Busy(String),
    Store(anyhow::Error),
}

impl From<anyhow::Error> for StartError {
    fn from(e: anyhow::Error) -> Self {
        StartError::Store(e)
    }
}

/// Claims the backfill (a new run, or resuming a stopped one) and runs it in
/// the background on `listing` (a counted client of the same bucket). The
/// doc as claimed.
pub async fn start_backfill(
    stats: &Arc<StoreStats>,
    listing: Store,
    opts: BackfillOpts,
    broadcast: Broadcast,
) -> Result<BackfillDoc, StartError> {
    let ctl = stats.ctl()?;
    let me = stats.node_id();
    let now = now_ms();
    let doc = 'claim: {
        for _ in 0..CAS_ROUNDS {
            let (prev, ver): (BackfillDoc, _) = read_json(&ctl, BACKFILL_DOC).await?;
            if ver.is_some()
                && prev.phase == "running"
                && now.saturating_sub(prev.heartbeat_at) < RUNNER_STALE_MS
                && (prev.runner != me || stats.backfill_running_here())
            {
                return Err(StartError::Busy(prev.runner));
            }
            let (sdoc, _): (StatsDoc, _) = read_json(&ctl, DOC).await?;
            let resume = ver.is_some() && !opts.restart && prev.phase != "done" && sdoc.epoch == prev.epoch;
            let doc = BackfillDoc {
                epoch: if resume { prev.epoch } else { sdoc.epoch.max(prev.epoch) + 1 },
                phase: "running".into(),
                runner: me.clone(),
                heartbeat_at: now,
                started_at: if resume { prev.started_at } else { now },
                finished_at: None,
                cursor: if resume { prev.cursor.clone() } else { None },
                requests: if resume { prev.requests } else { 0 },
                keys: if resume { prev.keys } else { 0 },
                bytes: if resume { prev.bytes } else { 0 },
                max_requests: opts.max_requests,
                pages_per_second: opts.pages_per_second,
                partial: if resume { prev.partial.clone() } else { Comps::new() },
                timeline: if resume { prev.timeline.clone() } else { Vec::new() },
                error: None,
            };
            if write_json(&ctl, BACKFILL_DOC, &doc, ver).await? {
                break 'claim doc;
            }
        }
        return Err(StartError::Store(anyhow::anyhow!("{BACKFILL_DOC} kept changing under the claim")));
    };
    // the window opens before the first page is read
    for _ in 0..CAS_ROUNDS {
        let (mut sdoc, ver): (StatsDoc, _) = read_json(&ctl, DOC).await?;
        if sdoc.window_active && sdoc.epoch == doc.epoch {
            break;
        }
        sdoc.epoch = doc.epoch;
        sdoc.window_active = true;
        if write_json(&ctl, DOC, &sdoc, ver).await? {
            break;
        }
    }
    stats.begin_window(doc.epoch).await?;
    let missed = broadcast(doc.epoch, "begin").await;
    if !missed.is_empty() {
        tracing::warn!(?missed, "storage backfill: nodes that didn't hear it begin keep their changes as uncertain");
    }
    let (s, d) = (stats.clone(), doc.clone());
    let task = tokio::spawn(async move {
        let epoch = d.epoch;
        match run(&s, &listing, d).await {
            Ok(true) => {
                let missed = broadcast(epoch, "end").await;
                if !missed.is_empty() {
                    tracing::warn!(?missed, "storage backfill: nodes sort their window at their next fold");
                }
            }
            Ok(false) => {}
            Err(e) => tracing::warn!("storage backfill: {e:#}"),
        }
    });
    *stats.running.lock() = Some(task.abort_handle());
    Ok(doc)
}

/// Ok(true): done and seeded; Ok(false): stopped at its budget (resumable).
async fn run(stats: &Arc<StoreStats>, listing: &Store, mut doc: BackfillDoc) -> anyhow::Result<bool> {
    use futures::StreamExt;
    let ctl = stats.ctl()?;
    let root = Path::from(listing.prefix.clone());
    // some stores read everything when the stream is made, not when polled
    let mut opened = Some(now_us());
    let mut stream = match &doc.cursor {
        Some(c) => listing.raw.list_with_offset(Some(&root), &Path::from(c.as_str())),
        None => listing.raw.list(Some(&root)),
    };
    let pps = doc.pages_per_second.clamp(MIN_PAGES_PER_SECOND, MAX_PAGES_PER_SECOND);
    let gap = Duration::from_secs_f64(1.0 / pps);
    let mut next_page = tokio::time::Instant::now();
    let (mut spent, mut since_save, mut saved_at) = (0u64, 0u64, tokio::time::Instant::now());
    let mut ver = read_json::<BackfillDoc>(&ctl, BACKFILL_DOC).await?.1;
    let save = |doc: &BackfillDoc, ver: Option<UpdateVersion>| {
        let ctl = ctl.clone();
        let doc = doc.clone();
        async move {
            if !write_json(&ctl, BACKFILL_DOC, &doc, ver).await? {
                anyhow::bail!("another node took the backfill over");
            }
            Ok::<_, anyhow::Error>(read_json::<BackfillDoc>(&ctl, BACKFILL_DOC).await?.1)
        }
    };
    loop {
        if spent >= doc.max_requests {
            doc.phase = "capped".into();
            doc.heartbeat_at = now_ms();
            save(&doc, ver).await?;
            tracing::info!(requests = doc.requests, keys = doc.keys, "storage backfill: stopped at its request budget");
            return Ok(false);
        }
        tokio::time::sleep_until(next_page).await;
        next_page = tokio::time::Instant::now() + gap;
        let s = opened.take().unwrap_or_else(now_us);
        let (mut n, mut r, mut last) = (0u64, 0u64, None::<String>);
        while n < PAGE {
            match stream.next().await {
                Some(Ok(meta)) => {
                    if n == 0 {
                        r = now_us();
                    }
                    n += 1;
                    let loc = meta.location.to_string();
                    let comp = crate::objstats::component(&listing.prefix, &loc);
                    let c = doc.partial.entry(comp.to_string()).or_default();
                    c.objects += 1;
                    c.bytes += meta.size as i64;
                    doc.keys += 1;
                    doc.bytes += meta.size;
                    last = Some(loc);
                }
                Some(Err(e)) => {
                    doc.error = Some(e.to_string());
                    doc.phase = "failed".into();
                    let _ = save(&doc, ver).await;
                    return Err(e.into());
                }
                None => break,
            }
        }
        if n == 0 {
            r = now_us();
        }
        spent += 1;
        doc.requests += 1;
        let end = n < PAGE;
        if let Some(l) = &last {
            doc.cursor = Some(l.clone());
        }
        doc.timeline.push(Page { s, r, last: if end { None } else { last } });
        doc.heartbeat_at = now_ms();
        since_save += 1;
        if end {
            break;
        }
        if since_save >= SAVE_EVERY_PAGES || saved_at.elapsed() >= SAVE_EVERY {
            ver = save(&doc, ver).await?;
            since_save = 0;
            saved_at = tokio::time::Instant::now();
        }
    }
    doc.phase = "done".into();
    doc.finished_at = Some(now_ms());
    save(&doc, ver).await?;
    for _ in 0..CAS_ROUNDS {
        let (mut sdoc, v): (StatsDoc, _) = read_json(&ctl, DOC).await?;
        if sdoc.epoch != doc.epoch {
            anyhow::bail!("a newer backfill (epoch {}) replaced this one", sdoc.epoch);
        }
        sdoc.seed = Some(Seed { at: doc.finished_at.unwrap_or_default(), components: doc.partial.clone() });
        sdoc.deltas = std::mem::take(&mut sdoc.late);
        sdoc.window_active = false;
        sdoc.lost = false;
        if write_json(&ctl, DOC, &sdoc, v).await? {
            stats.note_means(&sdoc.folded());
            stats.end_window(doc.epoch).await?;
            tracing::info!(
                requests = doc.requests,
                keys = doc.keys,
                bytes = doc.bytes,
                "storage backfill: done; counters seeded"
            );
            return Ok(true);
        }
    }
    anyhow::bail!("{DOC} kept changing under the seed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use object_store::ObjectStoreExt;

    fn memstore(prefix: &str, stats: &Arc<StoreStats>) -> Store {
        let raw: Arc<dyn ObjectStore> = Arc::new(object_store::memory::InMemory::new());
        Store {
            raw: crate::objstats::counted_with(raw, prefix, "state", Some(stats.clone())),
            prefix: prefix.into(),
            latency: None,
        }
    }

    fn node(prefix: &str, id: &str, raw: &Arc<dyn ObjectStore>) -> (Arc<StoreStats>, Store) {
        let s = StoreStats::new(prefix);
        let store = Store {
            raw: crate::objstats::counted_with(raw.clone(), prefix, "state", Some(s.clone())),
            prefix: prefix.into(),
            latency: None,
        };
        s.attach(store.clone(), id);
        (s, store)
    }

    fn pending(s: &StoreStats, comp: &str) -> Counts {
        s.inner.lock().pending.get(comp).copied().unwrap_or_default()
    }

    async fn put(store: &Store, rel: &str, n: usize, mode: PutMode) -> object_store::Result<()> {
        let p = Path::from(format!("{}/{rel}", store.prefix));
        store
            .raw
            .put_opts(&p, PutPayload::from(vec![7u8; n]), PutOptions { mode, ..Default::default() })
            .await
            .map(|_| ())
    }

    async fn del(store: &Store, rel: &str) {
        store.raw.delete(&Path::from(format!("{}/{rel}", store.prefix))).await.unwrap();
    }

    #[tokio::test]
    async fn puts_overwrites_and_deletes() {
        let s = StoreStats::new("t");
        let store = memstore("t", &s);
        put(&store, "log/A/1.seg", 100, PutMode::Create).await.unwrap();
        put(&store, "log/A/2.seg", 50, PutMode::Overwrite).await.unwrap();
        assert!(put(&store, "log/A/1.seg", 9, PutMode::Create).await.is_err(), "a failed create counts nothing");
        assert_eq!(pending(&s, "log_segment"), Counts { objects: 2, bytes: 150, uncertain: 0 });
        // an overwrite of a key it wrote is a replace
        put(&store, "log/A/2.seg", 70, PutMode::Overwrite).await.unwrap();
        assert_eq!(pending(&s, "log_segment"), Counts { objects: 2, bytes: 170, uncertain: 0 });
        del(&store, "log/A/1.seg").await;
        assert_eq!(pending(&s, "log_segment"), Counts { objects: 1, bytes: 70, uncertain: 0 });
        // a control row overwritten in place, first seen: a replace, size unknown
        put(&store, "nodes/n1", 30, PutMode::Overwrite).await.unwrap();
        assert_eq!(pending(&s, "ctl_lease"), Counts { objects: 0, bytes: 0, uncertain: 1 });
        put(&store, "nodes/n1", 40, PutMode::Overwrite).await.unwrap();
        assert_eq!(pending(&s, "ctl_lease"), Counts { objects: 0, bytes: 10, uncertain: 1 });
        // a delete of a key it never saw takes the component's mean, uncertain
        s.note_means(&Comps::from([("blob".into(), Counts { objects: 4, bytes: 400, uncertain: 0 })]));
        let other: Arc<dyn ObjectStore> = Arc::new(object_store::memory::InMemory::new());
        let p = Path::from("t/blob/did/x");
        other.put(&p, PutPayload::from_static(b"hi")).await.unwrap();
        let raw = crate::objstats::counted_with(other, "t", "state", Some(s.clone()));
        raw.delete(&p).await.unwrap();
        assert_eq!(pending(&s, "blob"), Counts { objects: -1, bytes: -100, uncertain: 1 });
        // a listing teaches it sizes, so the delete after it is exact
        let q = Path::from("t/blob/did/y");
        raw.put(&q, PutPayload::from(vec![0u8; 33])).await.unwrap();
        let s2 = StoreStats::new("t");
        let raw2 = crate::objstats::counted_with(raw.clone(), "t", "state", Some(s2.clone()));
        let _: Vec<_> = futures::StreamExt::collect(raw2.list(Some(&Path::from("t/blob")))).await;
        assert_eq!(s2.observed(), (1, 33, 1));
        raw2.delete(&q).await.unwrap();
        assert_eq!(pending(&s2, "blob"), Counts { objects: -1, bytes: -33, uncertain: 0 });
    }

    #[tokio::test]
    async fn copies_and_multipart() {
        let s = StoreStats::new("t");
        let store = memstore("t", &s);
        let tmp = Path::from("t/blob-tmp/u1");
        let mut up = store.raw.put_multipart(&tmp).await.unwrap();
        up.put_part(PutPayload::from(vec![1u8; 10])).await.unwrap();
        up.put_part(PutPayload::from(vec![1u8; 5])).await.unwrap();
        up.complete().await.unwrap();
        let dest = Path::from("t/blob/did/c");
        store.raw.copy(&tmp, &dest).await.unwrap();
        store.raw.delete(&tmp).await.unwrap();
        assert_eq!(pending(&s, "blob"), Counts { objects: 1, bytes: 15, uncertain: 0 });
        let total = s.inner.lock().pending.values().fold(Counts::default(), |mut a, c| {
            a.add(c);
            a
        });
        assert_eq!((total.objects, total.bytes, total.uncertain), (1, 15, 0));
    }

    #[tokio::test]
    async fn folds_merge_across_nodes_and_survive_restart() {
        let raw: Arc<dyn ObjectStore> = Arc::new(object_store::memory::InMemory::new());
        let (a, sa) = node("t", "a", &raw);
        let (b, sb) = node("t", "b", &raw);
        put(&sa, "log/A/1.seg", 100, PutMode::Create).await.unwrap();
        put(&sb, "log/B/1.seg", 10, PutMode::Create).await.unwrap();
        put(&sb, "log/B/2.seg", 10, PutMode::Create).await.unwrap();
        a.flush(false).await.unwrap();
        b.flush(true).await.unwrap();
        // node b is gone for good: its folded changes stay
        drop(b);
        let doc = a.read_doc().await.unwrap();
        let log = doc.folded()["log_segment"];
        assert_eq!((log.objects, log.bytes), (3, 120));
        assert!(doc.nodes["a"].open && !doc.nodes["b"].open);
        assert!(!doc.lost);
        // a restart of a crashed node marks the totals inexact
        let (a2, _) = node("t", "a", &raw);
        a2.flush(false).await.unwrap();
        assert!(a2.read_doc().await.unwrap().lost);
        // what was folded isn't folded again
        a.flush(false).await.unwrap();
        assert_eq!(a.read_doc().await.unwrap().folded()["log_segment"].objects, 3);
    }

    #[test]
    fn window_sides() {
        let tl = vec![
            Page { s: 1_000, r: 1_100, last: Some("p/b".into()) },
            Page { s: 5_000, r: 5_100, last: Some("p/m".into()) },
            Page { s: 9_000, r: 9_100, last: None },
        ];
        assert_eq!(side(&tl, "p/a", 100, 200, 250), Side::Before);
        assert_eq!(side(&tl, "p/a", 2_000, 2_010, 250), Side::After);
        assert_eq!(side(&tl, "p/a", 1_050, 1_060, 250), Side::Unsure);
        // the second page read p/c..p/m at 5 s
        assert_eq!(side(&tl, "p/c", 2_000, 2_010, 250), Side::Before);
        assert_eq!(side(&tl, "p/m", 6_000, 6_010, 250), Side::After);
        assert_eq!(side(&tl, "p/z", 8_000, 8_010, 250), Side::Before);
        assert_eq!(side(&tl, "p/z", 9_500, 9_510, 250), Side::After);
        // a listing that stopped before reaching it
        assert_eq!(side(&tl[..1], "p/z", 100, 200, 250), Side::After);
    }

    fn opts(max_requests: u64) -> BackfillOpts {
        BackfillOpts { max_requests, pages_per_second: MAX_PAGES_PER_SECOND, restart: false }
    }

    fn quiet() -> Broadcast {
        Arc::new(|_, _| Box::pin(async { Vec::new() }))
    }

    async fn wait_phase(s: &Arc<StoreStats>, phase: &str) -> BackfillDoc {
        for _ in 0..500 {
            if let Some(d) = s.read_backfill().await.unwrap() {
                if d.phase == phase && !s.backfill_running_here() {
                    return d;
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("backfill never reached {phase}");
    }

    /// Objects nothing counted (written around the counters), listed once:
    /// a capped run stops at its budget and resumes where it stopped, and
    /// the seed equals what's there.
    #[tokio::test]
    async fn backfill_caps_resumes_and_seeds() {
        let raw: Arc<dyn ObjectStore> = Arc::new(object_store::memory::InMemory::new());
        for i in 0..3_500u32 {
            raw.put(&Path::from(format!("t/blob/did/{i:05}")), PutPayload::from(vec![0u8; 3])).await.unwrap();
        }
        for i in 0..400u32 {
            raw.put(&Path::from(format!("t/log/A/{i:05}.seg")), PutPayload::from(vec![0u8; 10])).await.unwrap();
        }
        let (a, sa) = node("t", "a", &raw);
        let d = start_backfill(&a, sa.clone(), opts(2), quiet()).await.unwrap();
        assert_eq!(d.phase, "running");
        let capped = wait_phase(&a, "capped").await;
        assert_eq!((capped.requests, capped.keys), (2, 2_000));
        assert!(start_backfill(&a, sa.clone(), opts(1), quiet()).await.is_ok());
        let capped = wait_phase(&a, "capped").await;
        assert_eq!((capped.requests, capped.keys), (3, 3_000), "resumed after its cursor");
        // a write during the run, after the listing passed its key: kept
        tokio::time::sleep(Duration::from_micros(2 * SKEW_US)).await;
        put(&sa, "blob/did/00001x", 5, PutMode::Create).await.unwrap();
        start_backfill(&a, sa.clone(), opts(10), quiet()).await.unwrap();
        let done = wait_phase(&a, "done").await;
        assert_eq!(done.requests, 4, "{done:?}");
        let doc = a.read_doc().await.unwrap();
        let seed = doc.seed.as_ref().unwrap();
        assert_eq!(seed.components["blob"], Counts { objects: 3_500, bytes: 10_500, uncertain: 0 });
        assert_eq!(seed.components["log_segment"], Counts { objects: 400, bytes: 4_000, uncertain: 0 });
        assert!(!doc.window_active);
        a.flush(false).await.unwrap();
        let t = a.read_doc().await.unwrap().folded();
        assert_eq!(t["blob"].objects, 3_501, "the write after the listing passed it is kept: {t:?}");
        assert_eq!(t["blob"].uncertain, 0);
    }

    /// A write before the listing reaches its key is in the listing, and
    /// isn't counted twice.
    #[tokio::test]
    async fn window_drops_what_the_listing_has() {
        let raw: Arc<dyn ObjectStore> = Arc::new(object_store::memory::InMemory::new());
        for i in 0..1_500u32 {
            raw.put(&Path::from(format!("t/blob/did/{i:05}")), PutPayload::from(vec![0u8; 3])).await.unwrap();
        }
        let (a, sa) = node("t", "a", &raw);
        start_backfill(&a, sa.clone(), opts(1), quiet()).await.unwrap();
        wait_phase(&a, "capped").await;
        // ahead of the cursor: the resumed listing reads it
        tokio::time::sleep(Duration::from_micros(2 * SKEW_US)).await;
        put(&sa, "blob/did/99999", 4, PutMode::Create).await.unwrap();
        tokio::time::sleep(Duration::from_micros(2 * SKEW_US)).await;
        start_backfill(&a, sa.clone(), opts(5), quiet()).await.unwrap();
        wait_phase(&a, "done").await;
        a.flush(false).await.unwrap();
        let t = a.read_doc().await.unwrap().folded();
        assert_eq!(t["blob"], Counts { objects: 1_501, bytes: 4_504, uncertain: 0 }, "{t:?}");
    }

    /// One run at a time.
    #[tokio::test]
    async fn one_runner() {
        let raw: Arc<dyn ObjectStore> = Arc::new(object_store::memory::InMemory::new());
        for i in 0..3_000u32 {
            raw.put(&Path::from(format!("t/blob/did/{i:05}")), PutPayload::from(vec![0u8; 1])).await.unwrap();
        }
        let (a, sa) = node("t", "a", &raw);
        let (b, sb) = node("t", "b", &raw);
        let slow = BackfillOpts { max_requests: 10, pages_per_second: 2.0, restart: false };
        start_backfill(&a, sa, slow.clone(), quiet()).await.unwrap();
        match start_backfill(&b, sb, slow, quiet()).await {
            Err(StartError::Busy(r)) => assert_eq!(r, "a"),
            other => panic!("{:?}", other.map(|d| d.phase)),
        }
    }

    /// Pages are spaced by the rate.
    #[tokio::test]
    async fn rate_limited() {
        let raw: Arc<dyn ObjectStore> = Arc::new(object_store::memory::InMemory::new());
        for i in 0..3_500u32 {
            raw.put(&Path::from(format!("t/blob/did/{i:05}")), PutPayload::from(vec![0u8; 1])).await.unwrap();
        }
        let (a, sa) = node("t", "a", &raw);
        let started = std::time::Instant::now();
        start_backfill(&a, sa, BackfillOpts { max_requests: 10, pages_per_second: 10.0, restart: false }, quiet())
            .await
            .unwrap();
        let d = wait_phase(&a, "done").await;
        assert_eq!(d.requests, 4);
        assert!(started.elapsed() >= Duration::from_millis(300), "{:?}", started.elapsed());
        let gaps: Vec<u64> = d.timeline.windows(2).map(|w| w[1].s - w[0].s).collect();
        assert!(gaps.iter().all(|g| *g >= 95_000), "{gaps:?}");
    }
}
