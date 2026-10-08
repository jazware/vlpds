//! The notifyWrite outbox (repo-host side). A space write logs an `sP` row
//! with its rev and hash in the write's own entry, so the notify survives
//! a crash or takeover after the ack; this is the in-memory side that
//! sends it.
//!
//! One row per (repo, space), single-flight: writes acked while a send is
//! in flight only move the row's rev, and the next send carries the newest
//! one as soon as the first returns. Retries back off from 1 min, doubling
//! to 1 h with 50-100% jitter, until 24 h after the rev was written; a
//! permanent refusal drops the row. Retry state lives here only, never in
//! the bucket. A delivered row's `sP` delete rides the author's next space
//! write (see `take_delivered`), so delivery costs no extra PUT; a row left
//! behind is resent once by the next owner, which the authority ignores as
//! not newer (the send works out the hash the repo serves at that rev, so
//! a resend matches what the authority has even across a takedown).
//!
//! Bounded: at most [`MAX_ROWS`] rows are held (a row past that stays in
//! the bucket, and the owned shards' `sP` rows are scanned again once the
//! outbox has drained to half) and [`MAX_SENDS`] sends are in flight.
//!
//! Isolation: an authority that answers slowly or not at all must not hold
//! up anyone else's notifies, and any account can write into a space whose
//! authority it runs. So an authority has at most [`DEST_SENDS`] sends in
//! flight, and one whose last send failed (retryable) draws only on a
//! shared [`SLOW_SENDS`]. Rows wait in a ready queue and a timer heap, so
//! the write path's enqueue and the sender's pass cost O(log n) per row,
//! never a scan of the outbox.

use crate::state::SpaceId;
use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap, HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};
use vlatproto::tid::Tid;

pub const RETRY_BASE: Duration = Duration::from_secs(60);
pub const RETRY_MAX: Duration = Duration::from_secs(3600);
pub const DEADLINE: Duration = Duration::from_secs(24 * 3600);
pub const MAX_ROWS: usize = 1 << 18;
pub const MAX_SENDS: usize = 256;
/// Sends in flight to one authority.
pub const DEST_SENDS: usize = 8;
/// Sends in flight, all told, to authorities whose last send failed.
pub const SLOW_SENDS: usize = 32;
/// Delivered revs whose `sP` deletes wait for their author's next write.
const MAX_DELIVERED: usize = 1 << 16;

/// What a send came to.
#[derive(Debug)]
pub enum Outcome {
    Delivered,
    /// Refused for good (a 4xx the reference doesn't retry): dropped.
    Refused(String),
    Retry(String),
    /// The writer's account is inactive: tried again later, not counted.
    Wait,
    /// No longer this node's to send (the shard moved, the account is gone).
    Gone,
}

type Key = (Arc<str>, SpaceId);

struct Row {
    uri: Arc<str>,
    /// The space's authority: whom the send goes to.
    dest: Arc<str>,
    repo_rev: Tid,
    hash: [u8; 32],
    in_flight: bool,
    /// Due, with an entry in a ready or parked queue: a newer write needn't
    /// queue it again.
    queued: bool,
    attempts: u32,
    /// Bumped whenever the row is scheduled again: queue entries naming an
    /// older one are stale.
    gen: u64,
    /// When the write this row first held was acked (or the row was found
    /// on open): the outbox age gauge.
    since: Instant,
    /// Its entry in `State::oldest`.
    id: u64,
    /// When the write of `repo_rev` was acked (None: found on open).
    acked: Option<Instant>,
    /// Held for an inactive writer: left out of the age gauge, which would
    /// otherwise page for as long as an account stays deactivated.
    waiting: bool,
    /// Sent again once the send in flight returns, at the same rev.
    again: bool,
    /// When its current rev was owed (enqueued, renotified, or found on
    /// open): [`DEADLINE`] counts from here, as the reference's `expiresAt`
    /// does, not from the rev's time, so an old rev (imported, a writer
    /// back from deactivation, a takedown's renotify) gets its retries too.
    owed: Instant,
}

#[derive(Default)]
struct Dest {
    rows: usize,
    in_flight: usize,
    /// Its last send failed and may be retried.
    failing: bool,
    /// Due rows held back by its cap.
    parked: VecDeque<(Key, u64)>,
}

#[derive(Default)]
struct State {
    rows: BTreeMap<Key, Row>,
    ready: VecDeque<(Key, u64)>,
    timers: BinaryHeap<Reverse<(Instant, u64, Key)>>,
    /// (since, id) of every row not waiting.
    oldest: BTreeSet<(Instant, u64)>,
    dests: HashMap<Arc<str>, Dest>,
    /// Due rows held back by [`SLOW_SENDS`].
    slow_parked: VecDeque<(Key, u64)>,
    slow_in_flight: usize,
    in_flight: usize,
    next_id: u64,
    next_gen: u64,
}

impl State {
    /// Queues `key` to send at `at` (now or later), superseding its older
    /// queue entries.
    fn schedule(&mut self, key: &Key, at: Instant, now: Instant) {
        self.next_gen += 1;
        let gen = self.next_gen;
        let Some(r) = self.rows.get_mut(key) else { return };
        r.gen = gen;
        r.queued = at <= now;
        if at <= now {
            self.ready.push_back((key.clone(), gen));
        } else {
            self.timers.push(Reverse((at, gen, key.clone())));
        }
    }

    fn set_waiting(&mut self, key: &Key, waiting: bool) {
        let Some(r) = self.rows.get_mut(key) else { return };
        if r.waiting != waiting {
            r.waiting = waiting;
            match waiting {
                true => self.oldest.remove(&(r.since, r.id)),
                false => self.oldest.insert((r.since, r.id)),
            };
        }
    }

    fn remove(&mut self, key: &Key) -> Option<Row> {
        let r = self.rows.remove(key)?;
        self.oldest.remove(&(r.since, r.id));
        if let Some(d) = self.dests.get_mut(&r.dest) {
            d.rows -= 1;
            if d.rows == 0 && d.in_flight == 0 {
                self.dests.remove(&r.dest);
            }
        }
        Some(r)
    }

    fn live(&self, (key, gen): &(Key, u64)) -> bool {
        self.rows.get(key).is_some_and(|r| r.gen == *gen && !r.in_flight)
    }
}

/// A send to make: the row as it was when taken.
pub struct Pending {
    pub did: Arc<str>,
    pub sid: SpaceId,
    pub uri: Arc<str>,
    pub repo_rev: Tid,
    pub hash: [u8; 32],
    dest: Arc<str>,
    slow: bool,
}

pub struct Outbox {
    state: parking_lot::Mutex<State>,
    /// Delivered revs whose `sP` rows are still in the bucket, by author.
    delivered: parking_lot::Mutex<HashMap<Arc<str>, Vec<(SpaceId, Tid)>>>,
    wake: tokio::sync::Notify,
    started: AtomicBool,
    /// A row was left in the bucket for want of room.
    overflowed: AtomicBool,
    max_rows: usize,
    retry_base_ms: std::sync::atomic::AtomicU64,
}

impl Default for Outbox {
    fn default() -> Outbox {
        Outbox::new(MAX_ROWS)
    }
}

/// A space URI's authority.
fn authority(uri: &str) -> &str {
    uri.strip_prefix("at://").and_then(|r| r.split('/').next()).unwrap_or(uri)
}

impl Outbox {
    pub fn new(max_rows: usize) -> Outbox {
        Outbox {
            state: Default::default(),
            delivered: Default::default(),
            wake: Default::default(),
            started: AtomicBool::new(false),
            overflowed: AtomicBool::new(false),
            max_rows,
            retry_base_ms: (RETRY_BASE.as_millis() as u64).into(),
        }
    }

    #[doc(hidden)]
    pub fn set_retry_base(&self, base: Duration) {
        self.retry_base_ms.store(base.as_millis() as u64, Ordering::Relaxed);
    }

    /// A write of (did, space) at `repo_rev` is durable; `acked`: it was
    /// just acked (not a row found on open). Runs in the node log's ack, so
    /// it does O(log n) work under the lock and never waits on a send.
    pub fn enqueue(&self, did: &str, sid: SpaceId, uri: &str, repo_rev: Tid, hash: [u8; 32], acked: bool) {
        self.put(did, sid, uri, repo_rev, hash, acked, false);
    }

    /// Sends (did, space)'s notify at `repo_rev` again, delivered or not:
    /// a record takedown or its reversal changed the hash the repo serves
    /// at that rev (the send works out which). Not logged, so a crash
    /// before it goes leaves the change to syncers' polls.
    pub fn renotify(&self, did: &str, sid: SpaceId, uri: &str, repo_rev: Tid, hash: [u8; 32]) {
        self.put(did, sid, uri, repo_rev, hash, false, true);
    }

    #[allow(clippy::too_many_arguments)]
    fn put(&self, did: &str, sid: SpaceId, uri: &str, repo_rev: Tid, hash: [u8; 32], acked: bool, again: bool) {
        let now = Instant::now();
        {
            let mut d = self.delivered.lock();
            if let Some(v) = d.get_mut(did) {
                v.retain(|(s, _)| *s != sid);
                if v.is_empty() {
                    d.remove(did);
                }
            }
        }
        let key: Key = (did.into(), sid);
        let mut guard = self.state.lock();
        let st = &mut *guard;
        let full = st.rows.len() >= self.max_rows;
        match st.rows.get_mut(&key) {
            Some(r) if r.repo_rev > repo_rev || (r.repo_rev == repo_rev && !again) => return,
            Some(r) if r.repo_rev == repo_rev => {
                r.attempts = 0;
                r.owed = now;
                r.again |= r.in_flight;
                let idle = !r.in_flight && !r.queued;
                st.set_waiting(&key, false);
                if idle {
                    st.schedule(&key, now, now);
                }
            }
            Some(r) => {
                r.repo_rev = repo_rev;
                r.hash = hash;
                r.attempts = 0;
                r.owed = now;
                r.acked = acked.then_some(now);
                let idle = !r.in_flight && !r.queued;
                st.set_waiting(&key, false);
                // one in flight is resent at once when it returns
                if idle {
                    st.schedule(&key, now, now);
                }
            }
            None if full => {
                self.overflowed.store(true, Ordering::Release);
                crate::metrics::space_outbox_overflow();
                return;
            }
            None => {
                st.next_id += 1;
                let id = st.next_id;
                let dest: Arc<str> = authority(uri).into();
                st.dests.entry(dest.clone()).or_default().rows += 1;
                let row = Row {
                    uri: uri.into(),
                    dest,
                    repo_rev,
                    hash,
                    in_flight: false,
                    queued: false,
                    attempts: 0,
                    gen: 0,
                    since: now,
                    id,
                    acked: acked.then_some(now),
                    waiting: false,
                    again: false,
                    owed: now,
                };
                st.rows.insert(key.clone(), row);
                st.oldest.insert((now, id));
                st.schedule(&key, now, now);
            }
        }
        drop(guard);
        self.wake.notify_one();
    }

    /// Delivered revs of `did`'s spaces whose `sP` rows the caller (the
    /// author's worker, which orders every `sP` write of the author) may
    /// delete, if it has written nothing newer.
    pub fn take_delivered(&self, did: &str) -> Vec<(SpaceId, Tid)> {
        let mut d = self.delivered.lock();
        if d.is_empty() {
            return Vec::new();
        }
        d.remove(did).unwrap_or_default()
    }

    fn did_range(did: &str) -> std::ops::RangeInclusive<Key> {
        let d: Arc<str> = did.into();
        (d.clone(), [0; 16])..=(d, [0xff; 16])
    }

    /// `did`'s account is active again: its waiting rows send now.
    pub fn resume(&self, did: &str) {
        let now = Instant::now();
        let mut st = self.state.lock();
        let keys: Vec<Key> = st
            .rows
            .range(Self::did_range(did))
            .filter(|(_, r)| !r.in_flight && !r.queued)
            .map(|(k, _)| k.clone())
            .collect();
        for k in &keys {
            st.set_waiting(k, false);
            st.schedule(k, now, now);
        }
        drop(st);
        if !keys.is_empty() {
            self.wake.notify_one();
        }
    }

    /// `did`'s account is gone with its rows.
    pub fn drop_did(&self, did: &str) {
        let mut st = self.state.lock();
        let keys: Vec<Key> = st.rows.range(Self::did_range(did)).map(|(k, _)| k.clone()).collect();
        for k in keys {
            st.remove(&k);
        }
        drop(st);
        self.delivered.lock().remove(did);
    }

    pub fn len(&self) -> usize {
        self.state.lock().rows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn retry_base(&self) -> Duration {
        Duration::from_millis(self.retry_base_ms.load(Ordering::Relaxed))
    }

    /// Whether the rows left in the bucket should be scanned for again:
    /// some were, and there's room for them now.
    fn take_overflow(&self) -> bool {
        self.overflowed.load(Ordering::Acquire)
            && self.state.lock().rows.len() <= self.max_rows / 2
            && self.overflowed.swap(false, Ordering::AcqRel)
    }

    /// Rows due now (as many as may be in flight), marked in flight, and
    /// when the next timer is due.
    fn due(&self, now: Instant) -> (Vec<Pending>, Option<Instant>) {
        let mut guard = self.state.lock();
        let st = &mut *guard;
        while let Some(Reverse((at, _, _))) = st.timers.peek() {
            if *at > now {
                break;
            }
            let Some(Reverse((_, gen, key))) = st.timers.pop() else { break };
            if st.live(&(key.clone(), gen)) {
                st.rows.get_mut(&key).expect("live").queued = true;
                st.ready.push_back((key, gen));
            }
        }
        let mut out = Vec::new();
        while st.in_flight < MAX_SENDS {
            let Some(e) = st.ready.pop_front() else { break };
            if !st.live(&e) {
                continue;
            }
            let dest = st.rows[&e.0].dest.clone();
            let slow_full = st.slow_in_flight >= SLOW_SENDS;
            let d = st.dests.entry(dest.clone()).or_default();
            if d.in_flight >= DEST_SENDS {
                d.parked.push_back(e);
                continue;
            }
            let slow = d.failing;
            if slow && slow_full {
                st.slow_parked.push_back(e);
                continue;
            }
            d.in_flight += 1;
            st.in_flight += 1;
            st.slow_in_flight += slow as usize;
            let r = st.rows.get_mut(&e.0).expect("live");
            r.in_flight = true;
            r.queued = false;
            out.push(Pending {
                did: e.0 .0.clone(),
                sid: e.0 .1,
                uri: r.uri.clone(),
                repo_rev: r.repo_rev,
                hash: r.hash,
                dest,
                slow,
            });
        }
        let next = st.timers.peek().map(|Reverse((at, _, _))| *at);
        let oldest = st.oldest.first().map(|(since, _)| *since);
        crate::metrics::space_outbox_gauges(st.rows.len(), oldest.map_or(0.0, |s| now.duration_since(s).as_secs_f64()));
        (out, next)
    }

    fn finish(&self, s: &Pending, outcome: &Outcome) {
        let key: Key = (s.did.clone(), s.sid);
        let now = Instant::now();
        let mut guard = self.state.lock();
        let st = &mut *guard;
        st.in_flight -= 1;
        if s.slow {
            st.slow_in_flight -= 1;
            if let Some(e) = st.slow_parked.pop_front() {
                st.ready.push_front(e);
            }
        }
        if let Some(d) = st.dests.get_mut(&s.dest) {
            d.in_flight -= 1;
            match outcome {
                Outcome::Retry(_) => d.failing = true,
                Outcome::Delivered | Outcome::Refused(_) => d.failing = false,
                Outcome::Wait | Outcome::Gone => {}
            }
            if let Some(e) = d.parked.pop_front() {
                st.ready.push_front(e);
            }
            if d.rows == 0 && d.in_flight == 0 {
                st.dests.remove(&s.dest);
            }
        }
        // its account went (drop_did) while it was in flight
        let Some(r) = st.rows.get_mut(&key) else {
            drop(guard);
            self.wake.notify_one();
            return;
        };
        r.in_flight = false;
        let newer = r.repo_rev > s.repo_rev || std::mem::take(&mut r.again);
        let expired = now.saturating_duration_since(r.owed) > DEADLINE;
        let (result, drop_row) = match outcome {
            Outcome::Delivered => {
                if let Some(t) = r.acked.filter(|_| !newer) {
                    crate::metrics::space_notify_ack(now.duration_since(t));
                }
                ("ok", !newer)
            }
            Outcome::Refused(_) => ("refused", !newer),
            Outcome::Gone => ("gone", true),
            Outcome::Retry(_) if expired => ("expired", true),
            Outcome::Retry(_) => ("retry", false),
            Outcome::Wait => ("wait", false),
        };
        crate::metrics::space_notify("out", result);
        let mut at = now;
        if newer {
            r.attempts = 0;
        } else if !drop_row {
            if !matches!(outcome, Outcome::Wait) {
                r.attempts += 1;
            }
            at = now + backoff(self.retry_base(), r.attempts.max(1));
        }
        st.set_waiting(&key, matches!(outcome, Outcome::Wait) && !newer);
        let removed = match drop_row {
            true => st.remove(&key),
            false => {
                st.schedule(&key, at, now);
                None
            }
        };
        drop(guard);
        if let (Some(r), false) = (&removed, matches!(outcome, Outcome::Gone)) {
            let mut d = self.delivered.lock();
            if d.len() >= MAX_DELIVERED && !d.contains_key(&key.0) {
                // its `sP` row is resent once by a later owner instead
                if let Some(k) = d.keys().next().cloned() {
                    d.remove(&k);
                }
            }
            d.entry(key.0.clone()).or_default().push((key.1, r.repo_rev));
        }
        self.wake.notify_one();
        if let Outcome::Refused(why) | Outcome::Retry(why) = outcome {
            tracing::info!(space = %hex::encode(s.sid), rev = %s.repo_rev, "space notifyWrite {result}: {why}");
        }
    }

    /// Starts the sender (once). `app` is held weakly: the sender ends
    /// with the server.
    pub fn start(self: &Arc<Self>, app: Weak<crate::xrpc::App>) {
        if self.started.swap(true, Ordering::AcqRel) {
            return;
        }
        let me = self.clone();
        tokio::spawn(async move {
            loop {
                let (sends, next) = me.due(Instant::now());
                for s in sends {
                    let Some(app) = app.upgrade() else { return };
                    let me = me.clone();
                    tokio::spawn(async move {
                        let outcome = crate::xrpc::space::deliver(&app, &s).await;
                        me.finish(&s, &outcome);
                    });
                }
                if me.take_overflow() {
                    let Some(app) = app.upgrade() else { return };
                    if let Some(sp) = app.spaces.clone() {
                        let shards = app.partitions.owned().into_iter().map(|p| (p.id, p.db.clone())).collect();
                        sp.spawn_outbox_rescan(Arc::downgrade(&app.partitions), shards, true);
                    }
                }
                if app.strong_count() == 0 {
                    return;
                }
                // the gauges stay fresh while rows wait
                let wait = next.map_or(Duration::from_secs(1), |n| n.saturating_duration_since(Instant::now()));
                let _ = tokio::time::timeout(wait.min(Duration::from_secs(1)), me.wake.notified()).await;
            }
        });
    }
}

/// `base` (1 min) doubling to 1 h, then 50-100% of that.
pub fn backoff(base: Duration, attempts: u32) -> Duration {
    let base = base.saturating_mul(1 << attempts.saturating_sub(1).min(6)).min(RETRY_MAX);
    base.mul_f64(0.5 + rand::random::<f64>() / 2.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn send(o: &Outbox) -> Vec<Pending> {
        o.due(Instant::now()).0
    }

    fn oldest(o: &Outbox) -> Option<Instant> {
        o.state.lock().oldest.first().map(|(since, _)| *since)
    }

    fn uri(authority: usize) -> String {
        format!("at://did:web:a{authority}.example/space/t.t/k")
    }

    #[test]
    fn single_flight_coalesces() {
        let o = Outbox::default();
        let sid = [1; 16];
        o.enqueue("did:a", sid, "at://s", Tid(1), [0; 32], true);
        let s1 = send(&o);
        assert_eq!(s1.len(), 1);
        // in flight: newer writes only move the row
        o.enqueue("did:a", sid, "at://s", Tid(2), [0; 32], true);
        o.enqueue("did:a", sid, "at://s", Tid(3), [0; 32], true);
        assert!(send(&o).is_empty());
        o.finish(&s1[0], &Outcome::Delivered);
        let s2 = send(&o);
        assert_eq!(s2.iter().map(|s| s.repo_rev).collect::<Vec<_>>(), vec![Tid(3)]);
        assert!(o.take_delivered("did:a").is_empty(), "the newer rev is still owed");
        o.finish(&s2[0], &Outcome::Delivered);
        assert!(o.is_empty());
        assert_eq!(o.take_delivered("did:a"), vec![(sid, Tid(3))]);
        // an older rev never replaces a newer one
        o.enqueue("did:a", sid, "at://s", Tid(5), [0; 32], false);
        o.enqueue("did:a", sid, "at://s", Tid(4), [0; 32], false);
        assert_eq!(send(&o)[0].repo_rev, Tid(5));
    }

    /// A renotify sends a delivered rev again, and one in flight once more
    /// after it returns; it never replaces a newer rev.
    #[test]
    fn renotify_resends_the_same_rev() {
        let o = Outbox::default();
        let sid = [1; 16];
        o.enqueue("did:a", sid, "at://s", Tid(3), [0; 32], true);
        let s = send(&o);
        o.finish(&s[0], &Outcome::Delivered);
        assert!(o.is_empty());
        o.renotify("did:a", sid, "at://s", Tid(3), [0; 32]);
        let s = send(&o);
        assert_eq!(s.iter().map(|s| s.repo_rev).collect::<Vec<_>>(), vec![Tid(3)]);
        o.renotify("did:a", sid, "at://s", Tid(3), [0; 32]);
        assert!(send(&o).is_empty(), "single flight");
        o.finish(&s[0], &Outcome::Delivered);
        let s = send(&o);
        assert_eq!(s.len(), 1, "sent again after the one in flight");
        o.finish(&s[0], &Outcome::Delivered);
        assert!(o.is_empty());
        o.enqueue("did:a", sid, "at://s", Tid(4), [0; 32], true);
        o.renotify("did:a", sid, "at://s", Tid(3), [0; 32]);
        assert_eq!(send(&o)[0].repo_rev, Tid(4));
    }

    #[test]
    fn bounded() {
        let o = Outbox::new(2);
        for i in 0..3u8 {
            o.enqueue("did:a", [i; 16], "at://s", Tid(1), [0; 32], true);
        }
        assert_eq!(o.len(), 2);
        assert!(!o.take_overflow(), "no room yet");
        let s = send(&o);
        for p in &s {
            o.finish(p, &Outcome::Delivered);
        }
        assert!(o.take_overflow(), "drained: rescan");
        assert!(!o.take_overflow(), "once");
        // sends in flight are capped
        let o = Outbox::default();
        for i in 0..(MAX_SENDS + 10) {
            let mut sid = [0; 16];
            sid[..8].copy_from_slice(&(i as u64).to_be_bytes());
            o.enqueue("did:a", sid, &uri(i), Tid(1), [0; 32], true);
        }
        let first = send(&o);
        assert_eq!(first.len(), MAX_SENDS);
        assert!(send(&o).is_empty());
        o.finish(&first[0], &Outcome::Delivered);
        assert_eq!(send(&o).len(), 1);
        // a newer write to a row waiting its turn doesn't queue it twice
        let o = Outbox::default();
        for i in 0..DEST_SENDS + 1 {
            o.enqueue("did:a", [i as u8; 16], &uri(0), Tid(1), [0; 32], true);
        }
        let first = send(&o);
        for rev in 2..100 {
            o.enqueue("did:a", [DEST_SENDS as u8; 16], &uri(0), Tid(rev), [0; 32], true);
        }
        let st = o.state.lock();
        assert_eq!(st.ready.len() + st.dests.values().map(|d| d.parked.len()).sum::<usize>(), 1);
        drop(st);
        o.finish(&first[0], &Outcome::Delivered);
        assert_eq!(send(&o).iter().map(|p| p.repo_rev).collect::<Vec<_>>(), [Tid(99)]);
    }

    /// One authority gets at most DEST_SENDS at once; once its sends fail,
    /// it shares SLOW_SENDS with every other failing one, so a tarpit (or
    /// many) leaves the rest of the budget to everyone else.
    #[test]
    fn a_failing_authority_holds_up_no_one_else() {
        let o = Outbox::default();
        let now = || vlatproto::tid::Tid::from_parts(vlatproto::tid::now_micros(), 0);
        let sid = |i: usize| {
            let mut s = [0; 16];
            s[..8].copy_from_slice(&(i as u64).to_be_bytes());
            s
        };
        for i in 0..100 {
            o.enqueue("did:w", sid(i), &uri(0), now(), [0; 32], true);
        }
        let first = send(&o);
        assert_eq!(first.len(), DEST_SENDS);
        assert!(send(&o).is_empty(), "the rest wait for its sends, not the global budget");
        // it fails: its rows back off, and once due again draw on the slow pool
        o.set_retry_base(Duration::ZERO);
        for p in &first {
            o.finish(p, &Outcome::Retry("timeout".into()));
        }
        // a hundred tarpits, each failing
        for t in 1..=100 {
            for i in 0..DEST_SENDS {
                o.enqueue("did:w", sid(t * 1000 + i), &uri(t), now(), [0; 32], true);
            }
            for p in send(&o) {
                o.finish(&p, &Outcome::Retry("timeout".into()));
            }
        }
        let slow = send(&o);
        assert_eq!(slow.len(), SLOW_SENDS, "failing authorities share one small pool");
        // a healthy authority still sends at once
        o.enqueue("did:x", sid(1), &uri(500), now(), [0; 32], true);
        let fresh = send(&o);
        assert_eq!(fresh.iter().map(|p| &*p.did).collect::<Vec<_>>(), ["did:x"]);
        // a success makes an authority healthy again
        o.finish(&slow[0], &Outcome::Delivered);
        let st = o.state.lock();
        assert_eq!(st.slow_in_flight, SLOW_SENDS - 1);
    }

    #[test]
    fn retries_back_off() {
        let o = Outbox::default();
        let sid = [1; 16];
        o.enqueue(
            "did:a",
            sid,
            "at://s",
            vlatproto::tid::Tid::from_parts(vlatproto::tid::now_micros(), 0),
            [0; 32],
            true,
        );
        let s = send(&o);
        o.finish(&s[0], &Outcome::Retry("503".into()));
        assert!(send(&o).is_empty(), "backed off");
        assert_eq!(o.len(), 1);
        // a newer write sends at once
        o.enqueue(
            "did:a",
            sid,
            "at://s",
            vlatproto::tid::Tid::from_parts(vlatproto::tid::now_micros() + 1, 0),
            [0; 32],
            true,
        );
        let s = send(&o);
        assert_eq!(s.len(), 1);
        o.finish(&s[0], &Outcome::Refused("400".into()));
        assert!(o.is_empty());
        // an old rev (imported, renotified after a takedown) gets its
        // retries: the deadline counts from when it was owed
        o.set_retry_base(Duration::ZERO);
        o.enqueue("did:b", sid, "at://s", Tid::from_parts(1_000_000, 0), [0; 32], false);
        let s = send(&o);
        o.finish(&s[0], &Outcome::Retry("503".into()));
        assert_eq!(o.len(), 1, "one 5xx doesn't drop an old rev");
        // past the deadline a retryable failure drops the row
        let past = Instant::now().checked_sub(DEADLINE + Duration::from_secs(1)).unwrap();
        o.state.lock().rows.values_mut().for_each(|r| r.owed = past);
        let s = send(&o);
        o.finish(&s[0], &Outcome::Retry("503".into()));
        assert!(o.is_empty());
        o.set_retry_base(RETRY_BASE);
        for a in 1..10 {
            let d = backoff(RETRY_BASE, a);
            assert!(d >= RETRY_BASE / 2 && d <= RETRY_MAX, "{a}: {d:?}");
        }
        assert!(backoff(RETRY_BASE, 1) <= RETRY_BASE);
    }

    #[test]
    fn waiting_rows_leave_the_age_gauge() {
        let o = Outbox::default();
        let sid = [3; 16];
        o.enqueue("did:w", sid, "at://s", Tid::from_parts(vlatproto::tid::now_micros(), 0), [0; 32], true);
        let s = send(&o);
        assert!(oldest(&o).is_some());
        o.finish(&s[0], &Outcome::Wait);
        assert!(oldest(&o).is_none(), "an inactive writer's row isn't a backlog");
        assert_eq!(o.len(), 1);
        o.resume("did:w");
        assert!(oldest(&o).is_some());
        assert_eq!(send(&o).len(), 1, "resumed: due at once");
    }

    #[test]
    fn delivered_is_bounded_and_dropped_rows_settle() {
        let o = Outbox::default();
        for i in 0..MAX_DELIVERED + 10 {
            let did = format!("did:d{i}");
            o.enqueue(&did, [0; 16], "at://s", Tid(1), [0; 32], true);
            let p = send(&o);
            o.finish(&p[0], &Outcome::Delivered);
        }
        assert!(o.delivered.lock().len() <= MAX_DELIVERED);
        // an account dropped while its send is in flight
        o.enqueue("did:gone", [0; 16], &uri(9), Tid(1), [0; 32], true);
        let p = send(&o);
        o.drop_did("did:gone");
        o.finish(&p[0], &Outcome::Delivered);
        let st = o.state.lock();
        assert_eq!((st.in_flight, st.rows.len()), (0, 0));
        assert!(st.dests.is_empty());
    }
}
