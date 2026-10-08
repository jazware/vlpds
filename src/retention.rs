//! Log segment retention (DESIGN.md "Log retention").
//!
//! Node logs are both the WAL and the firehose history, so without this they
//! grow forever. A segment is deleted once
//!
//! - no replay can need it: below its log's *replay floor* (live log: every
//!   shard applying from it has a durable checkpoint past it; dead log: every
//!   shard with a span in it has been opened by a later owner, which replayed
//!   and flushed that span), and
//! - it is older than the firehose backfill window (`--log-retention`,
//!   default 72 h); a cursor older than what was deleted gets
//!   `OutdatedCursor` and continues from the oldest event left.
//!
//! One node deletes from a given log: its owner while it lives, and for dead
//! (fenced) logs the owner of the lowest-numbered shard. Deletes are
//! idempotent, so two nodes briefly both believing they lead is harmless.
//! Each pass deletes at most `max_deletes` objects, oldest first.
//!
//! Every node publishes `retain/{log_id}`: the shards its log's owner opened
//! (with epochs: permanent facts, so a stale copy is merely conservative) and
//! the highest seq it deleted (the retained floor is the max over reports).
//! A dead log keeps its fence object for `fence_retention` (default 7 days)
//! after it was written: it is what makes a zombie of that incarnation
//! fail-stop, whatever the zombie's clock says, so it goes only once no
//! zombie can plausibly still be running (DESIGN.md "Log retention",
//! "Fences").

use crate::cluster::Assignment;
use crate::metrics;
use crate::nodelog::NodeLog;
use futures::StreamExt;
use object_store::path::Path;
use object_store::{ObjectStoreExt, PutPayload};
use parking_lot::Mutex;
use vlsync_firehose::log::{read_json_dir, read_reports, report_path, Report};
use vlsync_store::slots::ShardId;
use vlsync_store::store::Store;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

pub const DEFAULT_WINDOW: Duration = Duration::from_secs(72 * 3600);
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(60);
pub const DEFAULT_MAX_DELETES: usize = 10_000;
pub const DEFAULT_FENCE_RETENTION: Duration = Duration::from_secs(7 * 86400);
/// A pass LISTs a log (or `log/`) at least this often even when what it
/// learned says nothing can be due yet: a safety net for anything the
/// skip rules don't foresee (see `Retention::pass`).
pub const RELIST_EVERY: Duration = Duration::from_secs(3600);

#[derive(Clone, Debug)]
pub struct Config {
    /// Firehose backfill window: segments younger than this are kept.
    pub window: Duration,
    pub interval: Duration,
    /// Per pass, all logs together.
    pub max_deletes: usize,
    /// A dead log pruned to its fence loses the fence (and so disappears
    /// from `log/`) once the fence is this old. None = fences stay forever.
    pub fence_retention: Option<Duration>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            window: DEFAULT_WINDOW,
            interval: DEFAULT_INTERVAL,
            max_deletes: DEFAULT_MAX_DELETES,
            fence_retention: Some(DEFAULT_FENCE_RETENTION),
        }
    }
}

/// What retention needs from the cluster.
pub struct Membership {
    /// Log ids of live nodes (ours included).
    pub live_logs: Box<dyn Fn() -> HashSet<String> + Send + Sync>,
    /// Whether this node prunes dead logs (owns the lowest-numbered shard).
    pub leader: Box<dyn Fn() -> bool + Send + Sync>,
}

/// Dead logs left after a pass over all of them (the dead-log gauges).
#[derive(Debug, Default, Clone, Copy, PartialEq)]
struct DeadLogs {
    unfenced: i64,
    needed: i64,
    pruning: i64,
    /// pruned down to their fence
    fenced: i64,
    /// objects below their logs' ends (fence or durable prefix)
    segments: u64,
}

impl DeadLogs {
    fn export(&self) {
        for (state, n) in
            [("unfenced", self.unfenced), ("needed", self.needed), ("pruning", self.pruning), ("fenced", self.fenced)]
        {
            metrics::RETENTION_DEAD_LOGS.with_label_values(&[state]).set(n);
        }
        metrics::RETENTION_DEAD_SEGMENTS.set(self.segments as i64);
    }
}

/// Objects and bytes one pass deleted.
#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub struct Pass {
    pub objects: usize,
    pub bytes: u64,
}

pub struct Retention {
    store: Store,
    log: Arc<NodeLog>,
    cfg: Config,
    members: Membership,
    state: Mutex<State>,
    /// The feature level active when our log started.
    log_level: u32,
}

#[derive(Default)]
struct State {
    pruned_seq: i64,
    written: Option<Report>,
    /// dead logs found fenced: log -> fence ordinal (permanent)
    fenced: HashMap<String, u64>,
    /// dead logs pruned down to their fence (and report deleted); their
    /// fence goes after `fence_retention`
    retired: HashSet<String>,
    /// dead logs left after the last full pass over them (leader only)
    dead: Option<DeadLogs>,
    /// What the last LIST of our own log says about the next one, and when.
    own_next: Option<(Due, std::time::Instant)>,
    /// What the last full dead-log scan says about the next one: the live
    /// logs it saw, when (if ever) a retired log's fence comes due, and
    /// when it ran. None: nothing is known (the next pass scans).
    dead_next: Option<DeadNext>,
}

/// See `State::dead_next`.
type DeadNext = (HashSet<String>, Option<chrono::DateTime<chrono::Utc>>, std::time::Instant);

/// When a log's next LIST can find something to delete (`Retention::prune`
/// stops at the first segment it may not delete; nothing behind it goes
/// before it does).
#[derive(Clone, Copy, Debug, PartialEq)]
enum Due {
    /// Not before this (the first segment left, or any segment written
    /// after the LIST, turns older than the window then).
    At(chrono::DateTime<chrono::Utc>),
    /// The first segment left is old enough but at or past the replay
    /// floor, which was this: nothing is due until the floor moves.
    Floor(u64),
    /// The pass stopped at its delete budget: due now.
    Now,
}

fn ordinal_of(p: &Path) -> Option<u64> {
    p.filename().and_then(|f| f.strip_suffix(".seg")).and_then(|f| f.parse().ok())
}

impl Retention {
    pub fn new(store: Store, log: Arc<NodeLog>, cfg: Config, members: Membership) -> Arc<Retention> {
        Arc::new(Retention {
            store,
            log,
            cfg,
            members,
            state: Mutex::default(),
            log_level: vlsync_store::version::active(),
        })
    }

    pub fn spawn(self: &Arc<Self>) {
        metrics::init_retention_counters();
        let me = self.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(me.cfg.interval);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            tick.tick().await; // the first tick is immediate: skip it
            loop {
                tick.tick().await;
                let started = std::time::Instant::now();
                let r = me.pass().await;
                metrics::RETENTION_PASS_SECONDS.observe(started.elapsed().as_secs_f64());
                match r {
                    Ok(p) => {
                        metrics::RETENTION_TICKS.with_label_values(&["ok"]).inc();
                        if p.objects > 0 {
                            tracing::info!(objects = p.objects, bytes = p.bytes, "log retention pass");
                        }
                    }
                    Err(e) => {
                        metrics::RETENTION_TICKS.with_label_values(&["error"]).inc();
                        tracing::warn!("log retention pass failed: {e:#}");
                    }
                }
            }
        });
    }

    /// One pass: our own log, our report, then (as leader) dead logs.
    ///
    /// Each LIST is skipped when the previous one showed nothing can be due
    /// yet (at most RELIST_EVERY apart), so an idle node's passes cost no
    /// requests:
    /// - Our log: only we delete from it, and only a prefix, so the segment
    ///   the last LIST stopped at is still the first. Nothing is due before
    ///   it turns older than the window or, if the replay floor held it,
    ///   before the floor moves.
    /// - Dead logs: the last full scan found none, or only retired ones
    ///   whose fences aren't due yet, and the live log set hasn't changed.
    ///   A log dies as a live one (the set changes). One never seen live (a
    ///   joiner that died before we listed it) waits for RELIST_EVERY; it
    ///   has nothing to prune before someone fences it anyway.
    pub async fn pass(&self) -> anyhow::Result<Pass> {
        let now = chrono::Utc::now();
        let cutoff = now - chrono::Duration::from_std(self.cfg.window)?;
        let mut budget = self.cfg.max_deletes;
        let mut pass = Pass::default();
        let floor = self.log.sinks.replay_floor();
        let durable = self.log.durable_ordinal.load(std::sync::atomic::Ordering::Acquire);
        if durable != u64::MAX {
            metrics::RETENTION_REPLAY_HOLD.set(durable.saturating_sub(floor) as i64);
        }
        let own_next = self.state.lock().own_next;
        let own_due = match own_next {
            Some((_, at)) if at.elapsed() >= RELIST_EVERY => true,
            Some((Due::At(t), _)) => now >= t,
            Some((Due::Floor(f), _)) => floor != f,
            Some((Due::Now, _)) | None => true,
        };
        if own_due {
            let listed = std::time::Instant::now();
            let (n, due) = self.prune(&self.log.log_id, floor, cutoff, &mut budget, "own").await?;
            self.state.lock().own_next = Some((due, listed));
            pass.objects += n.objects;
            pass.bytes += n.bytes;
        } else {
            metrics::RETENTION_LISTS_SKIPPED.with_label_values(&["own"]).inc();
        }
        self.publish().await?;
        if !(self.members.leader)() {
            // another node prunes (and reports) dead logs
            self.state.lock().dead_next = None;
            DeadLogs::default().export();
        } else if budget > 0 {
            let live = (self.members.live_logs)();
            let skip = self.state.lock().dead_next.as_ref().is_some_and(|(seen, until, at)| {
                *seen == live && at.elapsed() < RELIST_EVERY && until.is_none_or(|t| now < t)
            });
            if skip {
                metrics::RETENTION_LISTS_SKIPPED.with_label_values(&["dead"]).inc();
            } else {
                let n = self.prune_dead(live, cutoff, &mut budget).await?;
                pass.objects += n.objects;
                pass.bytes += n.bytes;
            }
        }
        Ok(pass)
    }

    async fn publish(&self) -> anyhow::Result<()> {
        let rep = Report::new(self.log.sinks.opened(), self.state.lock().pruned_seq, self.log_level);
        if self.state.lock().written.as_ref() == Some(&rep) {
            return Ok(());
        }
        let body = PutPayload::from(serde_json::to_vec(&rep)?);
        self.store.raw.put(&report_path(&self.store, &self.log.log_id), body).await?;
        metrics::RETENTION_PRUNED_SEQ.set(rep.pruned_seq);
        self.state.lock().written = Some(rep);
        Ok(())
    }

    /// Raises our published floor to `seq` (before deleting anything at or
    /// below it, so a reader that checked the floor first never misses data
    /// silently).
    async fn raise_floor(&self, seq: i64) -> anyhow::Result<()> {
        {
            let mut st = self.state.lock();
            if seq <= st.pruned_seq {
                return Ok(());
            }
            st.pruned_seq = seq;
        }
        self.publish().await
    }

    /// Deletes `log_id`'s oldest segments: ordinals below `limit` last
    /// modified before `cutoff`, at most `budget` of them.
    /// Also returns when the next LIST of the log can find something (see
    /// `Due`; this assumes nobody else deletes from the log meanwhile).
    async fn prune(
        &self,
        log_id: &str,
        limit: u64,
        cutoff: chrono::DateTime<chrono::Utc>,
        budget: &mut usize,
        kind: &str,
    ) -> anyhow::Result<(Pass, Due)> {
        let prefix = Path::from(format!("{}/log/{}", self.store.prefix, log_id));
        let window = chrono::Duration::from_std(self.cfg.window)?;
        let mut doomed: Vec<(u64, Path, u64)> = Vec::new();
        // the log ran out: a segment written from now on is younger
        let mut due = Due::At(chrono::Utc::now() + window);
        {
            // listings are in key order and ordinals zero-padded: oldest first
            let mut list = self.store.raw.list(Some(&prefix));
            while let Some(m) = list.next().await {
                let m = m?;
                let Some(ord) = ordinal_of(&m.location) else { continue };
                if m.last_modified >= cutoff {
                    due = Due::At(m.last_modified + window);
                    break;
                }
                if ord >= limit {
                    due = Due::Floor(limit);
                    break;
                }
                if doomed.len() >= *budget {
                    due = Due::Now;
                    break;
                }
                doomed.push((ord, m.location, m.size));
            }
        }
        let Some((last, ..)) = doomed.last() else { return Ok((Pass::default(), due)) };
        // Below a replay floor (or a fence) every object is a segment. One
        // already gone was deleted by another node, which raised its own
        // floor first.
        if let vlsync_firehose::log::Head::Segment(h) =
            vlsync_firehose::log::read_head(&self.store, log_id, *last).await?
        {
            self.raise_floor(h.last_seq).await?;
        }
        let pass = self.delete(doomed.into_iter().map(|(_, p, n)| (p, n)).collect(), budget, kind).await?;
        Ok((pass, due))
    }

    async fn delete(&self, objs: Vec<(Path, u64)>, budget: &mut usize, kind: &str) -> anyhow::Result<Pass> {
        let sizes: HashMap<Path, u64> = objs.iter().cloned().collect();
        let paths = futures::stream::iter(objs.into_iter().map(|(p, _)| Ok(p))).boxed();
        let mut pass = Pass::default();
        let mut deleted = self.store.raw.delete_stream(paths);
        while let Some(r) = deleted.next().await {
            match r {
                Ok(p) => {
                    pass.objects += 1;
                    pass.bytes += sizes.get(&p).copied().unwrap_or(0);
                }
                Err(object_store::Error::NotFound { .. }) => {}
                Err(e) => return Err(e.into()),
            }
        }
        *budget = budget.saturating_sub(pass.objects);
        metrics::RETENTION_DELETED_OBJECTS.with_label_values(&[kind]).inc_by(pass.objects as u64);
        metrics::RETENTION_DELETED_BYTES.with_label_values(&[kind]).inc_by(pass.bytes);
        Ok(pass)
    }

    /// Dead logs (no live node writes them): once fenced and fully applied by
    /// their shards' successors, deletes their segments past the window,
    /// then the garbage past the fence and their report. The fence stays.
    async fn prune_dead(
        &self,
        live: HashSet<String>,
        cutoff: chrono::DateTime<chrono::Utc>,
        budget: &mut usize,
    ) -> anyhow::Result<Pass> {
        let scanned = std::time::Instant::now();
        self.state.lock().dead_next = None;
        let logs = vlsync_firehose::backfill::list_logs(&self.store).await?;
        let dead: Vec<String> = logs.into_iter().filter(|l| !live.contains(l) && *l != *self.log.log_id).collect();
        let mut pass = Pass::default();
        let mut known: Option<Known> = None;
        let mut stats = DeadLogs::default();
        // the next scan may be skipped if only retired logs whose fences
        // aren't due are left (`quiet`), until the earliest fence comes due
        let (mut quiet, mut until) = (true, None::<chrono::DateTime<chrono::Utc>>);
        // objects left below `end` in log `x` (one LIST page)
        let held = |x: String, end: u64| async move {
            anyhow::Ok(
                end.saturating_sub(vlsync_firehose::backfill::first_ordinal(&self.store, &x).await?.unwrap_or(end)),
            )
        };
        for x in dead {
            if *budget == 0 {
                // stopped early: the gauges keep the last full count
                return Ok(pass);
            }
            if self.state.lock().retired.contains(&x) {
                match self.delete_fence(&x, &mut known, budget).await? {
                    FenceDue::Deleted => pass.objects += 1,
                    FenceDue::At(t) => {
                        stats.fenced += 1;
                        until = Some(until.map_or(t, |u| u.min(t)));
                    }
                    FenceDue::Never => stats.fenced += 1,
                    FenceDue::Held => {
                        stats.fenced += 1;
                        quiet = false;
                    }
                }
                continue;
            }
            // anything else may change by the next pass (fenced, opened by
            // a successor, pruned, retired)
            quiet = false;
            let cached = self.state.lock().fenced.get(&x).copied();
            let fence = match cached {
                Some(f) => f,
                None => match vlsync_firehose::log::first_free(&self.store, &x).await? {
                    // not fenced: its owner may be alive but unseen (joining),
                    // or dead with its shards not taken yet
                    (end, false) => {
                        stats.unfenced += 1;
                        stats.segments += held(x.clone(), end).await?;
                        continue;
                    }
                    (f, true) => {
                        self.state.lock().fenced.insert(x.clone(), f);
                        f
                    }
                },
            };
            let (assigns, reports) = load_known(&self.store, &mut known).await?;
            if let Some(s) = needed_by(&x, assigns, reports) {
                tracing::debug!(log = %x, shard = s.0, "dead log still needed for replay");
                stats.needed += 1;
                stats.segments += held(x.clone(), fence).await?;
                continue;
            }
            let (n, _) = self.prune(&x, fence, cutoff, budget, "dead").await?;
            pass.objects += n.objects;
            pass.bytes += n.bytes;
            // everything below the fence gone: retire it
            let first = vlsync_firehose::backfill::first_ordinal(&self.store, &x).await?;
            if first == Some(fence) {
                let n = self.retire(&x, fence, cutoff, budget).await?;
                pass.objects += n.objects;
                pass.bytes += n.bytes;
                if self.state.lock().retired.contains(&x) {
                    stats.fenced += 1;
                }
            } else {
                stats.pruning += 1;
                stats.segments += fence.saturating_sub(first.unwrap_or(fence));
            }
        }
        stats.export();
        let mut st = self.state.lock();
        st.dead = Some(stats);
        if quiet {
            st.dead_next = Some((live, until, scanned));
        }
        Ok(pass)
    }

    /// A dead log pruned down to its fence: deletes the garbage past the
    /// fence (segments a crash left in flight, never read) and its report,
    /// folding the report's floor into ours first.
    async fn retire(
        &self,
        x: &str,
        fence: u64,
        cutoff: chrono::DateTime<chrono::Utc>,
        budget: &mut usize,
    ) -> anyhow::Result<Pass> {
        let prefix = Path::from(format!("{}/log/{}", self.store.prefix, x));
        let mut garbage = Vec::new();
        let mut list = self.store.raw.list(Some(&prefix));
        while let Some(m) = list.next().await {
            let m = m?;
            if ordinal_of(&m.location).is_some_and(|o| o > fence) {
                if m.last_modified >= cutoff {
                    return Ok(Pass::default());
                }
                garbage.push((m.location, m.size));
            }
        }
        drop(list);
        let pass = self.delete(garbage, budget, "dead").await?;
        match self.store.raw.get(&report_path(&self.store, x)).await {
            Ok(r) => {
                let rep: Report = serde_json::from_slice(&r.bytes().await?)?;
                self.raise_floor(rep.pruned_seq).await?;
                self.store.raw.delete(&report_path(&self.store, x)).await?;
            }
            Err(object_store::Error::NotFound { .. }) => {}
            Err(e) => return Err(e.into()),
        }
        tracing::info!(log = x, fence, "dead log retired (pruned to its fence)");
        self.state.lock().retired.insert(x.to_string());
        Ok(pass)
    }

    /// A retired dead log's fence, once older than `fence_retention`: the
    /// log is then gone from `log/` entirely. Only if the fence is all that
    /// is left, no shard's replay can still read the log (`needed_by`,
    /// re-checked on fresh assignments), and no assignment names the log as
    /// its owner's (an orphan whose successor has yet to fence it: it must
    /// find this fence, not an empty log).
    async fn delete_fence(&self, x: &str, known: &mut Option<Known>, budget: &mut usize) -> anyhow::Result<FenceDue> {
        let Some(keep) = self.cfg.fence_retention else { return Ok(FenceDue::Never) };
        let Some(fence) = self.state.lock().fenced.get(x).copied() else { return Ok(FenceDue::Held) };
        let prefix = Path::from(format!("{}/log/{}", self.store.prefix, x));
        let objs: Vec<object_store::ObjectMeta> =
            self.store.raw.list(Some(&prefix)).collect::<Vec<_>>().await.into_iter().collect::<Result<_, _>>()?;
        let keep = chrono::Duration::from_std(keep)?;
        let cutoff = chrono::Utc::now() - keep;
        let [only] = objs.as_slice() else { return Ok(FenceDue::Held) };
        if ordinal_of(&only.location) != Some(fence) {
            return Ok(FenceDue::Held);
        }
        if only.last_modified >= cutoff {
            return Ok(FenceDue::At(only.last_modified + keep));
        }
        let (assigns, reports) = load_known(&self.store, known).await?;
        if needed_by(x, assigns, reports).is_some() || assigns.values().any(|a| a.log_id.as_deref() == Some(x)) {
            return Ok(FenceDue::Held);
        }
        match self.store.raw.delete(&only.location).await {
            Ok(()) | Err(object_store::Error::NotFound { .. }) => {}
            Err(e) => return Err(e.into()),
        }
        *budget = budget.saturating_sub(1);
        metrics::RETENTION_DELETED_OBJECTS.with_label_values(&["fence"]).inc();
        tracing::info!(log = x, fence, "dead log's fence deleted (past --fence-retention)");
        let mut st = self.state.lock();
        st.retired.remove(x);
        st.fenced.remove(x);
        Ok(FenceDue::Deleted)
    }
}

/// What `Retention::delete_fence` did with a retired log's fence.
enum FenceDue {
    Deleted,
    /// Kept: it turns older than `--fence-retention` then.
    At(chrono::DateTime<chrono::Utc>),
    /// Kept forever (`--fence-retention off`).
    Never,
    /// Kept for a reason that may change any time (an assignment names
    /// the log, objects besides the fence).
    Held,
}

/// Assignments (by shard id, retired shards' included) and every log's
/// report, read once per pass when first needed.
type Known = (BTreeMap<ShardId, Assignment>, HashMap<String, Report>);

async fn load_known<'k>(store: &Store, known: &'k mut Option<Known>) -> anyhow::Result<&'k Known> {
    if known.is_none() {
        let assigns = read_json_dir(store, "assign", ShardId::from_key, 32).await?.into_iter().collect();
        *known = Some((assigns, read_reports(store).await?));
    }
    Ok(known.as_ref().unwrap())
}

/// A shard whose replay may still read dead log `x`: its history has a span
/// in `x`, and no later owner (higher epoch) has reported opening it. An
/// open replays and flushes every earlier span, and durable markers only
/// move forward, so once that is reported `x` is never read for the shard.
/// A frozen shard (a split or merge parent) never replays again: its last
/// owner closed it with every span applied and flushed, so it needs nothing.
pub(crate) fn needed_by(
    x: &str,
    assigns: &BTreeMap<ShardId, Assignment>,
    reports: &HashMap<String, Report>,
) -> Option<ShardId> {
    for (&s, a) in assigns {
        if a.frozen.is_some() {
            continue;
        }
        let Some(last) = a.history.iter().filter(|sp| sp.log_id == x).map(|sp| sp.epoch).max() else { continue };
        if !reports.values().any(|r| r.opened.get(&s).is_some_and(|&e| e > last)) {
            return Some(s);
        }
    }
    None
}

/// Parses a duration like `72h`, `30m`, `90s`, `3d` or `500ms` (a bare
/// number is seconds).
pub fn parse_duration(s: &str) -> anyhow::Result<Duration> {
    let s = s.trim();
    let split = s.find(|c: char| !c.is_ascii_digit() && c != '.').unwrap_or(s.len());
    let (num, unit) = s.split_at(split);
    let v: f64 = num.parse().map_err(|_| anyhow::anyhow!("bad duration {s:?}"))?;
    let secs = match unit {
        "" | "s" => v,
        "ms" => v / 1000.0,
        "m" => v * 60.0,
        "h" => v * 3600.0,
        "d" => v * 86400.0,
        _ => anyhow::bail!("bad duration unit in {s:?} (ms, s, m, h, d)"),
    };
    anyhow::ensure!(secs.is_finite() && secs >= 0.0, "bad duration {s:?}");
    // from_secs_f64 panics past Duration::MAX (a flag of 10^23 days)
    Duration::try_from_secs_f64(secs).map_err(|_| anyhow::anyhow!("duration {s:?} out of range"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nodelog;
    use crate::nodelog::{NodeLogConfig, ShardSink, Span};
    use bytes::Bytes;
    use vlsync_firehose::log::{retained_floor, segment_path};
    use vlsync_store::segment::{fence_object, Mutation, SegmentBuilder};

    #[test]
    fn durations() {
        assert_eq!(parse_duration("72h").unwrap(), Duration::from_secs(72 * 3600));
        assert_eq!(parse_duration("90").unwrap(), Duration::from_secs(90));
        assert_eq!(parse_duration("1.5m").unwrap(), Duration::from_secs(90));
        assert_eq!(parse_duration("250ms").unwrap(), Duration::from_millis(250));
        assert_eq!(parse_duration("3d").unwrap(), Duration::from_secs(3 * 86400));
        assert!(parse_duration("3w").is_err() && parse_duration("h").is_err());
        // past Duration::MAX: an error, not a panic
        assert!(parse_duration("99999999999999999999999d").is_err());
    }

    /// A one-entry segment sealed with `prefix_end`.
    async fn put_seg(store: &Store, log: &str, ord: u64, prefix_end: u64, shard: ShardId, epoch: u64, seq: i64) {
        let mut b = SegmentBuilder::new();
        let m = Mutation { key: Bytes::from(format!("{log}/{ord}")), val: Some(Bytes::from_static(b"v")) };
        b.push(seq, shard, epoch, |o| o.extend_from_slice(b"frame"), &[m]);
        let mut obj = b.sealed_header(log, ord, prefix_end);
        obj.extend_from_slice(&b.body);
        store.raw.put(&segment_path(store, log, ord), PutPayload::from(obj)).await.unwrap();
    }

    async fn ordinals(store: &Store, log: &str) -> Vec<u64> {
        let prefix = Path::from(format!("{}/log/{log}", store.prefix));
        store.raw.list(Some(&prefix)).filter_map(|m| async move { ordinal_of(&m.unwrap().location) }).collect().await
    }

    fn members(live: &[&str], leader: bool) -> Membership {
        let live: HashSet<String> = live.iter().map(|s| s.to_string()).collect();
        Membership { live_logs: Box::new(move || live.clone()), leader: Box::new(move || leader) }
    }

    fn cfg(window: Duration) -> Config {
        Config { window, interval: Duration::from_secs(3600), max_deletes: 1000, fence_retention: None }
    }

    async fn put_assign(store: &Store, shard: ShardId, history: Vec<Span>) {
        let a = Assignment { epoch: history.last().map_or(0, |s| s.epoch), history, ..Default::default() };
        store
            .raw
            .put(
                &Path::from(format!("{}/assign/{}", store.prefix, shard.key())),
                PutPayload::from(serde_json::to_vec(&a).unwrap()),
            )
            .await
            .unwrap();
    }

    /// Our own log: nothing young, nothing a crash replay could need, and
    /// never the last durable segment; the floor is published first.
    #[tokio::test]
    async fn own_log_respects_window_and_replay_floor() {
        let store = Store::memory(None);
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let ncfg = NodeLogConfig {
            log_id: "L".into(),
            writer: 1,
            max_segment_bytes: 1 << 20,
            hedge_after: Duration::from_secs(10),
            lease_ok: None,
        };
        let log = NodeLog::start_with_inflight(store.clone(), ncfg, 1, tx);
        let db = Arc::new(
            crate::partition::open_db(&Store { prefix: "st".into(), ..store.clone() }, ShardId(3), None).await.unwrap(),
        );
        log.sinks.insert(Arc::new(ShardSink {
            id: ShardId(3),
            epoch: 7,
            db,
            apply_lock: Default::default(),
            applied: Default::default(),
            recent: Default::default(),
            barrier: Default::default(),
            totals: Default::default(),
        }));
        let send = |i: usize| {
            let log = log.clone();
            async move {
                let (atx, arx) = tokio::sync::oneshot::channel();
                let e = nodelog::LogEntry {
                    shard: ShardId(3),
                    frames: vec![vlatproto::events::Frame {
                        prefix: format!("e{i}").into_bytes(),
                        suffix: Vec::new(),
                        derived_muts: 0,
                        derived_gen: 0,
                    }],
                    muts: vec![Mutation { key: Bytes::from(format!("k{i}")), val: Some(Bytes::from_static(b"v")) }],
                    ack: Some(Box::new(move |r| {
                        let _ = atx.send(r.is_ok());
                    })),
                    pending: None,
                    enqueued: std::time::Instant::now(),
                    totals: None,
                };
                log.tx.send(e).await.ok().unwrap();
                assert!(arx.await.unwrap());
            }
        };
        for i in 0..6 {
            send(i).await;
        }
        assert_eq!(ordinals(&store, "L").await, (0..6).collect::<Vec<_>>());
        let r = Retention::new(store.clone(), log.clone(), cfg(Duration::ZERO), members(&["L"], true));
        // no checkpoint yet: the shard's insert floor (0) holds everything
        assert_eq!(r.pass().await.unwrap(), Pass::default());
        let held = r.state.lock().own_next.unwrap();
        assert_eq!(held.0, Due::Floor(0), "the first segment is old but held by the floor");
        assert_eq!(r.pass().await.unwrap(), Pass::default());
        assert_eq!(r.state.lock().own_next.unwrap().1, held.1, "floor unmoved: the LIST was skipped");
        log.checkpoint_all().await; // marker (L, 5) durable: replay starts at 6
        let p = r.pass().await.unwrap();
        assert_eq!(p.objects, 5, "everything but the last durable segment");
        assert_eq!(ordinals(&store, "L").await, vec![5]);
        assert!(p.bytes > 0);
        // the floor went out before the deletes, and fencing still finds the end
        let floor = retained_floor(&store).await.unwrap();
        let vlsync_firehose::log::Head::Segment(h5) = vlsync_firehose::log::read_head(&store, "L", 5).await.unwrap()
        else {
            panic!()
        };
        assert!(floor > 0 && floor < h5.first_seq, "floor {floor} = last seq of segment 4");
        assert_eq!(vlsync_firehose::log::first_free(&store, "L").await.unwrap(), (6, false));
        assert_eq!(r.state.lock().written.as_ref().unwrap().opened.get(&ShardId(3)), Some(&7));
        // the window holds young segments regardless
        send(6).await;
        send(7).await;
        log.checkpoint_all().await;
        let r2 = Retention::new(store.clone(), log.clone(), cfg(Duration::from_secs(3600)), members(&["L"], true));
        assert_eq!(r2.pass().await.unwrap(), Pass::default());
        // a closed shard holds the floor for a grace period
        log.sinks.remove(ShardId(3));
        assert_eq!(log.sinks.replay_floor(), 7);
    }

    /// A checkpoint below the insert floor would be ambiguous (it can name
    /// the end of an earlier span of this log): it is skipped.
    #[tokio::test]
    async fn checkpoint_skips_markers_below_the_insert_floor() {
        let store = Store::memory(None);
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let ncfg = NodeLogConfig {
            log_id: "L".into(),
            writer: 1,
            max_segment_bytes: 1 << 20,
            hedge_after: Duration::from_secs(10),
            lease_ok: None,
        };
        let log = NodeLog::start_with_inflight(store.clone(), ncfg, 1, tx);
        log.durable_ordinal.store(4, std::sync::atomic::Ordering::Release); // as if 0..=4 were durable
        let db = Arc::new(
            crate::partition::open_db(&Store { prefix: "st".into(), ..store.clone() }, ShardId(1), None).await.unwrap(),
        );
        log.sinks.insert(Arc::new(ShardSink {
            id: ShardId(1),
            epoch: 2,
            db: db.clone(),
            apply_lock: Default::default(),
            applied: Default::default(),
            recent: Default::default(),
            barrier: Default::default(),
            totals: Default::default(),
        }));
        log.checkpoint_all().await;
        assert!(db.get(nodelog::META_APPLIED).await.unwrap().is_none(), "no marker at 4 < insert floor 5");
        assert_eq!(log.sinks.replay_floor(), 4, "capped at the last durable segment");
        log.durable_ordinal.store(5, std::sync::atomic::Ordering::Release);
        log.checkpoint_all().await;
        assert_eq!(
            nodelog::decode_marker(&db.get(nodelog::META_APPLIED).await.unwrap().unwrap()).unwrap(),
            ("L".into(), 5)
        );
        assert_eq!(log.sinks.replay_floor(), 5);
    }

    /// A dead log: kept while unfenced or while a shard with a span in it has
    /// no later opener; then pruned to its fence (garbage past the fence and
    /// its report deleted, its floor folded into ours); and replay over the
    /// pruned head reads nothing it doesn't need.
    #[tokio::test]
    async fn dead_log_pruned_after_successors_open() {
        let store = Store::memory(None);
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let ncfg = NodeLogConfig {
            log_id: "B".into(),
            writer: 2,
            max_segment_bytes: 1 << 20,
            hedge_after: Duration::from_secs(10),
            lease_ok: None,
        };
        let log = NodeLog::start_with_inflight(store.clone(), ncfg, 1, tx);
        // dead log D: shard 0 (epoch 1) in 0..4, a crash hole at 4, garbage at 5
        for ord in 0..4 {
            put_seg(&store, "D", ord, ord, ShardId(0), 1, 100 + ord as i64).await;
        }
        put_seg(&store, "D", 5, 4, ShardId(0), 1, 105).await; // sealed while 4 was in flight
        let rep = Report { opened: [(ShardId(0), 1)].into(), pruned_seq: 42, ..Default::default() };
        store.raw.put(&report_path(&store, "D"), PutPayload::from(serde_json::to_vec(&rep).unwrap())).await.unwrap();
        put_assign(
            &store,
            ShardId(0),
            vec![
                Span { log_id: "D".into(), epoch: 1, start: 0, end: Some(4) },
                Span { log_id: "B".into(), epoch: 2, start: 0, end: None },
            ],
        )
        .await;
        let r = Retention::new(store.clone(), log.clone(), cfg(Duration::ZERO), members(&["B"], true));
        let dead = |r: &Retention| r.state.lock().dead.unwrap();
        assert_eq!(r.pass().await.unwrap(), Pass::default(), "not fenced: left alone");
        assert_eq!(
            dead(&r),
            DeadLogs { unfenced: 1, segments: 4, ..Default::default() },
            "its durable prefix 0..4 is held"
        );
        store.raw.put(&segment_path(&store, "D", 4), PutPayload::from_bytes(fence_object("B"))).await.unwrap();
        assert_eq!(r.pass().await.unwrap(), Pass::default(), "fenced, but B hasn't opened shard 0 yet");
        assert_eq!(dead(&r), DeadLogs { needed: 1, segments: 4, ..Default::default() });
        assert_eq!(ordinals(&store, "D").await, vec![0, 1, 2, 3, 4, 5]);
        // not the leader: never touches dead logs
        let db = Arc::new(
            crate::partition::open_db(&Store { prefix: "st".into(), ..store.clone() }, ShardId(0), None).await.unwrap(),
        );
        log.sinks.insert(Arc::new(ShardSink {
            id: ShardId(0),
            epoch: 2,
            db: db.clone(),
            apply_lock: Default::default(),
            applied: Default::default(),
            recent: Default::default(),
            barrier: Default::default(),
            totals: Default::default(),
        }));
        let follower = Retention::new(store.clone(), log.clone(), cfg(Duration::ZERO), members(&["B"], false));
        assert_eq!(follower.pass().await.unwrap(), Pass::default());
        let p = r.pass().await.unwrap();
        assert_eq!(p.objects, 5, "segments 0..4 and the garbage at 5");
        assert_eq!(dead(&r), DeadLogs { fenced: 1, ..Default::default() }, "retired: only the fence held");
        assert_eq!(ordinals(&store, "D").await, vec![4], "the fence stays");
        assert!(!read_reports(&store).await.unwrap().contains_key("D"), "its report is gone");
        assert!(retained_floor(&store).await.unwrap() >= 103, "the deleted seqs are covered");
        assert!(r.state.lock().pruned_seq >= 103);
        // a fence-only log still fences at the same place, and a replay of
        // its (applied) span reads nothing and doesn't fail
        assert_eq!(vlsync_firehose::log::first_free(&store, "D").await.unwrap(), (4, true));
        let history = vec![Span { log_id: "D".into(), epoch: 1, start: 0, end: Some(4) }];
        assert_eq!(nodelog::replay_shard(&store, ShardId(0), &db, &history).await.unwrap(), 0);
        assert_eq!(r.pass().await.unwrap(), Pass::default(), "retired");
        // past --fence-retention the fence goes too, unless an assignment
        // still names D as its owner's log (a successor must find the fence)
        let gc = Retention::new(
            store.clone(),
            log.clone(),
            Config { fence_retention: Some(Duration::ZERO), ..cfg(Duration::ZERO) },
            members(&["B"], true),
        );
        put_assign(&store, ShardId(1), vec![Span { log_id: "D".into(), epoch: 1, start: 0, end: None }]).await;
        let orphan = Assignment {
            owner: Some("d".into()),
            log_id: Some("D".into()),
            epoch: 1,
            history: vec![Span { log_id: "D".into(), epoch: 1, start: 0, end: None }],
            ..Default::default()
        };
        store
            .raw
            .put(
                &Path::from(format!("{}/assign/{}", store.prefix, ShardId(1).key())),
                PutPayload::from(serde_json::to_vec(&orphan).unwrap()),
            )
            .await
            .unwrap();
        gc.pass().await.unwrap();
        assert_eq!(ordinals(&store, "D").await, vec![4], "an orphan names D: the fence stays");
        store.raw.delete(&Path::from(format!("{}/assign/{}", store.prefix, ShardId(1).key()))).await.unwrap();
        let p = (gc.pass().await.unwrap().objects, gc.pass().await.unwrap().objects);
        assert_eq!(p, (0, 1), "retired again, then the fence");
        assert!(ordinals(&store, "D").await.is_empty());
        assert!(!vlsync_firehose::backfill::list_logs(&store).await.unwrap().contains(&"D".to_string()), "D left log/");
        assert_eq!(dead(&gc), DeadLogs::default());
        // a replay of a span in the vanished log reads nothing and doesn't fail
        assert_eq!(nodelog::replay_shard(&store, ShardId(0), &db, &history).await.unwrap(), 0);
    }

    /// Live logs as a test changes them.
    fn dyn_members(live: Arc<Mutex<HashSet<String>>>) -> Membership {
        Membership { live_logs: Box::new(move || live.lock().clone()), leader: Box::new(|| true) }
    }

    /// An idle node's passes skip both LISTs: its log's first segment is
    /// inside the window (nothing is due before it turns old), and the
    /// last dead-log scan found no dead log with the live set unchanged.
    /// A change of the live set (a node died) rescans at once.
    #[tokio::test]
    async fn idle_passes_skip_lists_until_something_can_be_due() {
        let store = Store::memory(None);
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let ncfg = NodeLogConfig {
            log_id: "L".into(),
            writer: 1,
            max_segment_bytes: 1 << 20,
            hedge_after: Duration::from_secs(10),
            lease_ok: None,
        };
        let log = NodeLog::start_with_inflight(store.clone(), ncfg, 1, tx);
        put_seg(&store, "L", 0, 0, ShardId(0), 1, 10).await;
        // a live peer's log: not dead, nothing to scan
        put_seg(&store, "P", 0, 0, ShardId(1), 1, 20).await;
        let live = Arc::new(Mutex::new(HashSet::from(["L".to_string(), "P".to_string()])));
        let r = Retention::new(store.clone(), log.clone(), cfg(Duration::from_secs(3600)), dyn_members(live.clone()));
        assert_eq!(r.pass().await.unwrap(), Pass::default());
        let (own, dead) = {
            let st = r.state.lock();
            (st.own_next.unwrap(), st.dead_next.clone().unwrap())
        };
        assert!(matches!(own.0, Due::At(t) if t > chrono::Utc::now() + chrono::Duration::minutes(59)), "{own:?}");
        assert_eq!((dead.1, &dead.0), (None, &*live.lock()), "no dead log: nothing due until the live set changes");
        for _ in 0..3 {
            assert_eq!(r.pass().await.unwrap(), Pass::default());
            let st = r.state.lock();
            assert_eq!(
                (st.own_next.unwrap().1, st.dead_next.as_ref().unwrap().2),
                (own.1, dead.2),
                "both LISTs skipped"
            );
        }
        // P dies: the next pass scans and finds it (unfenced)
        live.lock().remove("P");
        r.pass().await.unwrap();
        assert_eq!(r.state.lock().dead.unwrap().unfenced, 1);
        assert!(r.state.lock().dead_next.is_none(), "an unfenced dead log may change any time: scanned every pass");
        r.pass().await.unwrap();
        assert!(r.state.lock().dead_next.is_none());
        assert_eq!(r.state.lock().own_next.unwrap().1, own.1, "our own log still skipped");
    }

    /// Retired dead logs whose fences aren't due don't make passes rescan:
    /// the next scan is due when the earliest fence turns older than
    /// --fence-retention.
    #[tokio::test]
    async fn retired_logs_wait_for_their_fences() {
        let store = Store::memory(None);
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let ncfg = NodeLogConfig {
            log_id: "B".into(),
            writer: 2,
            max_segment_bytes: 1 << 20,
            hedge_after: Duration::from_secs(10),
            lease_ok: None,
        };
        let log = NodeLog::start_with_inflight(store.clone(), ncfg, 1, tx);
        // dead log D: one segment, fenced at 1, no shard needs it
        put_seg(&store, "D", 0, 0, ShardId(0), 1, 100).await;
        store.raw.put(&segment_path(&store, "D", 1), PutPayload::from_bytes(fence_object("B"))).await.unwrap();
        let keep = Duration::from_secs(3600);
        let r = Retention::new(
            store.clone(),
            log.clone(),
            Config { fence_retention: Some(keep), ..cfg(Duration::ZERO) },
            members(&["B"], true),
        );
        assert_eq!(r.pass().await.unwrap().objects, 1, "D pruned to its fence");
        assert!(r.state.lock().retired.contains("D"));
        // the pass that retired it doesn't know the fence's age yet
        r.pass().await.unwrap();
        let (_, until, at) = r.state.lock().dead_next.clone().expect("only a retired log left");
        let until = until.expect("its fence comes due");
        assert!(
            until > chrono::Utc::now() + chrono::Duration::minutes(59)
                && until <= chrono::Utc::now() + chrono::Duration::minutes(61),
            "{until}"
        );
        r.pass().await.unwrap();
        assert_eq!(r.state.lock().dead_next.as_ref().unwrap().2, at, "skipped");
        assert_eq!(ordinals(&store, "D").await, vec![1]);
    }

    #[test]
    fn needed_by_requires_a_later_opener() {
        let sp = |log: &str, epoch| Span { log_id: log.into(), epoch, start: 0, end: None };
        let a = |h: Vec<Span>| Assignment { history: h, ..Default::default() };
        let mut assigns: BTreeMap<ShardId, Assignment> = [
            (ShardId(0), a(vec![sp("X", 1), sp("Y", 2)])),
            (ShardId(1), a(vec![sp("Y", 3)])),
            (ShardId(3), a(vec![sp("X", 4), sp("Z", 5), sp("X", 6)])),
        ]
        .into();
        // a frozen split parent whose last span is in X never needs X again
        assigns.insert(ShardId(9), Assignment { frozen: Some(1), ..a(vec![sp("X", 2)]) });
        let mut reports = HashMap::new();
        reports
            .insert("Y".to_string(), Report { opened: [(ShardId(0), 2)].into(), pruned_seq: 0, ..Default::default() });
        assert_eq!(needed_by("X", &assigns, &reports), Some(ShardId(3)), "X holds shard 3's last span");
        reports
            .insert("Z".to_string(), Report { opened: [(ShardId(3), 5)].into(), pruned_seq: 0, ..Default::default() });
        assert_eq!(needed_by("X", &assigns, &reports), Some(ShardId(3)), "Z opened it before X's second span");
        reports
            .insert("W".to_string(), Report { opened: [(ShardId(3), 7)].into(), pruned_seq: 0, ..Default::default() });
        assert_eq!(needed_by("X", &assigns, &reports), None);
        assert_eq!(needed_by("Q", &assigns, &HashMap::new()), None);
    }
}
