//! Per-repo log of recent record writes, for read-after-write on proxied
//! AppView reads (DESIGN.md "Read-after-write").
//!
//! The reference PDS answers "which of the requester's records were written
//! after the AppView's `atproto-repo-rev`?" with an indexed SQL query; vlpds
//! has no rev index, so the owner node keeps, per recently seen repo, the
//! records above `base` (oldest first, bounded) and the repo's `head` rev.
//! A rev at or above `head` (nearly every request) is answered with no
//! store read; one at or above `base` from the entry; anything else reads
//! the store and [`fill`]s the entry. A lagging AppView's answer is kept for
//! its rev until the repo changes ([`fill_lagging`]), since it polls with the
//! same rev. Entries are valid only in the partition epoch they were made in,
//! and loads that raced a change are not cached (per-shard generations).

use bytes::Bytes;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};
use vlatproto::cid::Cid;

/// Records kept per repo above `base`.
pub const MAX_RECS: usize = 32;
pub const MAX_BYTES: usize = 64 << 10;
/// Records the reference returns per request.
pub const LIMIT: usize = 10;
/// A full shard first drops entries idle this long.
const IDLE: Duration = Duration::from_secs(600);
const SHARDS: usize = 64;

pub const POST: &str = "app.bsky.feed.post";
pub const PROFILE_PATH: &str = "app.bsky.actor.profile/self";

#[derive(Clone, Debug)]
pub struct Rec {
    pub path: Arc<str>,
    pub rev: u64,
    pub cid: Cid,
    /// Posts and the profile only: the records munging reads.
    pub bytes: Option<Bytes>,
}

pub fn keeps_bytes(path: &str) -> bool {
    path == PROFILE_PATH || crate::worker::collection_of(path) == POST
}

/// (partition id, ownership epoch) an entry was made in.
pub type Part = (vlsync_store::slots::ShardId, u64);

struct Entry {
    part: Part,
    head: u64,
    base: u64,
    /// The reference's sanity check: an AppView rev older than *every*
    /// local record (e.g. after a migration) gets no munging.
    old_exists: bool,
    /// ascending rev
    recs: Vec<Rec>,
    bytes: usize,
    touched: Instant,
    /// the answer for one rev below `base` (`fill_lagging`), while `head`
    /// is unchanged
    lagging: Option<(u64, Vec<Rec>)>,
}

impl Entry {
    fn new(part: Part, head: u64, base: u64, old_exists: bool) -> Entry {
        Entry { part, head, base, old_exists, recs: Vec::new(), bytes: 0, touched: Instant::now(), lagging: None }
    }

    fn remove(&mut self, path: &str) {
        if let Some(i) = self.recs.iter().position(|r| &*r.path == path) {
            let r = self.recs.remove(i);
            self.bytes -= r.bytes.as_ref().map_or(0, |b| b.len());
        }
    }

    fn push(&mut self, r: Rec) {
        self.remove(&r.path);
        self.bytes += r.bytes.as_ref().map_or(0, |b| b.len());
        // commits arrive in rev order: appending keeps `recs` sorted
        let at = self.recs.partition_point(|x| x.rev <= r.rev);
        self.recs.insert(at, r);
    }

    /// Drops the oldest revs (whole commits) until within bounds.
    fn trim(&mut self) {
        while self.recs.len() > MAX_RECS || self.bytes > MAX_BYTES {
            let rev = self.recs[0].rev;
            let n = self.recs.partition_point(|r| r.rev <= rev);
            for r in self.recs.drain(..n) {
                self.bytes -= r.bytes.as_ref().map_or(0, |b| b.len());
            }
            self.base = self.base.max(rev);
            self.old_exists = true;
        }
    }
}

#[derive(Debug)]
pub enum Since {
    /// No records after it, or the sanity check failed.
    Nothing,
    /// The oldest [`LIMIT`] records after it.
    Records(Vec<Rec>),
    /// Not known here: read the store.
    Unknown,
}

struct Log {
    shards: Vec<Mutex<HashMap<Box<str>, Entry>>>,
    gens: Vec<AtomicU64>,
}

impl crate::caches::Len for Log {
    fn len(&self) -> usize {
        self.shards.iter().map(|s| s.lock().len()).sum()
    }
}

static LOG: LazyLock<Arc<Log>> = LazyLock::new(|| {
    use crate::caches::{track, Cache};
    track(
        Cache::RecentWrites,
        Arc::new(Log {
            shards: (0..SHARDS).map(|_| Mutex::new(HashMap::new())).collect(),
            gens: (0..SHARDS).map(|_| AtomicU64::new(0)).collect(),
        }),
    )
});

fn shard(did: &str) -> usize {
    use std::hash::{Hash, Hasher};
    let mut h = std::hash::DefaultHasher::new();
    did.hash(&mut h);
    (h.finish() as usize) % SHARDS
}

/// Drops idle entries from a full shard, else all of it.
fn make_room(m: &mut HashMap<Box<str>, Entry>) {
    let cap = crate::caches::cap(crate::caches::Cache::RecentWrites).div_ceil(SHARDS).max(1);
    if m.len() >= cap {
        m.retain(|_, e| e.touched.elapsed() < IDLE);
        if m.len() >= cap {
            m.clear();
        }
    }
}

/// The oldest [`LIMIT`] of `recs` (ascending) above `since`, or nothing when
/// no record is at or below it (`old` = records at or below the entry's base).
fn answer(recs: &[Rec], since: u64, old: bool) -> Since {
    let start = recs.partition_point(|r| r.rev <= since);
    if start == recs.len() || !(old || start > 0) {
        return Since::Nothing;
    }
    Since::Records(recs[start..].iter().take(LIMIT).cloned().collect())
}

pub fn lookup(did: &str, part: Part, since: u64) -> Since {
    let i = shard(did);
    let mut m = LOG.shards[i].lock();
    let Some(e) = m.get_mut(did) else { return Since::Unknown };
    if e.part != part {
        m.remove(did);
        return Since::Unknown;
    }
    e.touched = Instant::now();
    if since >= e.head {
        return Since::Nothing;
    }
    if since < e.base {
        return match &e.lagging {
            Some((s, r)) if *s == since && r.is_empty() => Since::Nothing,
            Some((s, r)) if *s == since => Since::Records(r.clone()),
            _ => Since::Unknown,
        };
    }
    answer(&e.recs, since, e.old_exists)
}

/// Taken before reading what will be passed to [`fill`].
pub fn generation(did: &str) -> u64 {
    LOG.gens[shard(did)].load(Ordering::SeqCst)
}

pub struct Read {
    /// At least the head's rev when the read began.
    pub head: u64,
    pub base: u64,
    pub old_exists: bool,
    /// Every record above `base`, ascending.
    pub recs: Vec<Rec>,
}

/// Caches `read` unless the repo changed since `gen` was taken; returns the
/// answer for `since`.
pub fn fill(did: &str, part: Part, gen: u64, read: Read, since: u64) -> Since {
    let Read { head, base, old_exists, recs } = read;
    let out = if since >= head { Since::Nothing } else { answer(&recs, since, old_exists) };
    let i = shard(did);
    let mut m = LOG.shards[i].lock();
    if LOG.gens[i].load(Ordering::SeqCst) != gen {
        return out;
    }
    let mut e = Entry::new(part, head, base, old_exists);
    for r in recs {
        e.push(r);
    }
    e.trim();
    if !m.contains_key(did) {
        make_room(&mut m);
    }
    m.insert(did.into(), e);
    out
}

/// Keeps `answer` for `since` (read when more than [`MAX_RECS`] records
/// were above it) until the repo changes. An entry for the same head keeps
/// its records; otherwise it restarts at `head`.
pub fn fill_lagging(did: &str, part: Part, gen: u64, head: u64, since: u64, answer: Vec<Rec>) {
    let i = shard(did);
    let mut m = LOG.shards[i].lock();
    if LOG.gens[i].load(Ordering::SeqCst) != gen {
        return;
    }
    if !m.contains_key(did) {
        make_room(&mut m);
    }
    let e = m
        .entry(did.into())
        .and_modify(|e| {
            if e.part != part || e.head != head {
                *e = Entry::new(part, head, head, true);
            }
        })
        .or_insert_with(|| Entry::new(part, head, head, true));
    e.touched = Instant::now();
    e.lagging = Some((since, answer));
}

/// For changes other than commits (import, delete, creation).
pub fn invalidate(did: &str) {
    let i = shard(did);
    let mut m = LOG.shards[i].lock();
    LOG.gens[i].fetch_add(1, Ordering::SeqCst);
    m.remove(did);
}

/// One commit's record changes, applied to the log at its durable ack.
pub struct Commit {
    pub did: Arc<str>,
    pub part: Part,
    pub since: u64,
    pub rev: u64,
    pub prev_nonempty: bool,
    /// None: too many to keep (the entry restarts above this commit).
    pub ops: Option<Vec<Op>>,
}

/// A commit's net change to a path: the new CID and kept bytes, or None
/// (deleted).
pub type Op = (Arc<str>, Option<(Cid, Option<Bytes>)>);

impl Commit {
    /// At the commit's durable ack. An entry that missed a commit restarts
    /// at this one's `since`.
    pub fn apply(self) {
        let i = shard(&self.did);
        let mut m = LOG.shards[i].lock();
        LOG.gens[i].fetch_add(1, Ordering::SeqCst);
        let fresh = match m.get(&*self.did) {
            Some(e) if e.part == self.part && e.head >= self.rev => return, // already read
            Some(e) => !(e.part == self.part && e.head == self.since),
            None => true,
        };
        if fresh && !m.contains_key(&*self.did) {
            make_room(&mut m);
        }
        let e = match m.entry(self.did.as_ref().into()) {
            std::collections::hash_map::Entry::Occupied(o) => {
                let e = o.into_mut();
                if fresh {
                    *e = Entry::new(self.part, self.since, self.since, self.prev_nonempty);
                }
                e
            }
            std::collections::hash_map::Entry::Vacant(v) => {
                v.insert(Entry::new(self.part, self.since, self.since, self.prev_nonempty))
            }
        };
        e.head = self.rev;
        e.touched = Instant::now();
        e.lagging = None;
        match self.ops {
            Some(ops) => {
                for (path, new) in ops {
                    match new {
                        Some((cid, bytes)) => e.push(Rec { path, rev: self.rev, cid, bytes }),
                        None => e.remove(&path),
                    }
                }
                e.trim();
            }
            None => {
                *e = Entry::new(self.part, self.rev, self.rev, true);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cid(n: u8) -> Cid {
        vlatproto::cid::Cid::dag_cbor(&[n])
    }

    fn commit(did: &str, since: u64, rev: u64, ops: Vec<(&str, bool)>) -> Commit {
        Commit {
            did: did.into(),
            part: (vlsync_store::slots::ShardId(1), 1),
            since,
            rev,
            prev_nonempty: true,
            ops: Some(
                ops.into_iter()
                    .map(|(p, put)| {
                        (Arc::from(p), put.then(|| (cid(rev as u8), keeps_bytes(p).then(|| Bytes::from_static(b"x")))))
                    })
                    .collect(),
            ),
        }
    }

    fn paths(s: Since) -> Vec<String> {
        match s {
            Since::Records(r) => r.iter().map(|r| r.path.to_string()).collect(),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn commits_extend_and_answer() {
        let did = "did:plc:rwtest1";
        invalidate(did);
        assert!(matches!(lookup(did, (vlsync_store::slots::ShardId(1), 1), 5), Since::Unknown));
        commit(did, 10, 20, vec![("app.bsky.feed.post/a", true)]).apply();
        commit(did, 20, 30, vec![("app.bsky.feed.like/b", true), ("app.bsky.feed.post/a", false)]).apply();
        assert!(matches!(lookup(did, (vlsync_store::slots::ShardId(1), 1), 30), Since::Nothing));
        assert_eq!(paths(lookup(did, (vlsync_store::slots::ShardId(1), 1), 10)), vec!["app.bsky.feed.like/b"]);
        assert!(matches!(lookup(did, (vlsync_store::slots::ShardId(1), 1), 9), Since::Unknown), "below base");
        assert!(matches!(lookup(did, (vlsync_store::slots::ShardId(2), 1), 30), Since::Unknown), "other epoch");
        // the wrong-epoch lookup dropped it; a commit that doesn't follow restarts it
        commit(did, 40, 50, vec![("app.bsky.feed.post/c", true)]).apply();
        assert_eq!(paths(lookup(did, (vlsync_store::slots::ShardId(1), 1), 40)), vec!["app.bsky.feed.post/c"]);
        assert!(matches!(lookup(did, (vlsync_store::slots::ShardId(1), 1), 30), Since::Unknown));
    }

    #[test]
    fn bounded_and_sanity_checked() {
        let did = "did:plc:rwtest2";
        invalidate(did);
        let mut c = commit(did, 1, 2, vec![("app.bsky.feed.post/0", true)]);
        c.prev_nonempty = false;
        c.apply();
        // no record at or below the AppView's rev: nothing (reference sanity check)
        assert!(matches!(lookup(did, (vlsync_store::slots::ShardId(1), 1), 1), Since::Nothing));
        for i in 2..60u64 {
            commit(did, i, i + 1, vec![(&format!("app.bsky.feed.post/{i}"), true)]).apply();
        }
        assert!(matches!(lookup(did, (vlsync_store::slots::ShardId(1), 1), 2), Since::Unknown), "trimmed below");
        let r = paths(lookup(did, (vlsync_store::slots::ShardId(1), 1), 40));
        assert_eq!(r.len(), LIMIT);
        assert_eq!(r[0], "app.bsky.feed.post/40");
        // a filled entry raced by a commit is not cached
        invalidate(did);
        let g = generation(did);
        commit(did, 70, 71, vec![]).apply();
        fill(
            did,
            (vlsync_store::slots::ShardId(1), 1),
            g,
            Read { head: 60, base: 60, old_exists: true, recs: vec![] },
            60,
        );
        assert!(matches!(lookup(did, (vlsync_store::slots::ShardId(1), 1), 70), Since::Nothing));
        assert!(matches!(lookup(did, (vlsync_store::slots::ShardId(1), 1), 69), Since::Unknown));
    }

    /// The answer for a rev with too many records above it is kept until
    /// the next commit (a lagging AppView polls with the same rev).
    #[test]
    fn lagging_answer_kept_until_the_repo_changes() {
        let did = "did:plc:rwtest3";
        let part = (vlsync_store::slots::ShardId(1), 1);
        invalidate(did);
        let rec = |p: &str, rev| Rec { path: p.into(), rev, cid: cid(rev as u8), bytes: None };
        let g = generation(did);
        fill_lagging(did, part, g, 100, 5, vec![rec("app.bsky.feed.like/a", 6)]);
        assert_eq!(paths(lookup(did, part, 5)), vec!["app.bsky.feed.like/a"]);
        assert!(matches!(lookup(did, part, 4), Since::Unknown), "only that rev");
        assert!(matches!(lookup(did, part, 100), Since::Nothing));
        fill_lagging(did, part, generation(did), 100, 7, vec![]);
        assert!(matches!(lookup(did, part, 7), Since::Nothing), "an empty answer (sanity check) is kept too");
        // a commit drops it
        commit(did, 100, 110, vec![("app.bsky.feed.post/b", true)]).apply();
        assert!(matches!(lookup(did, part, 7), Since::Unknown));
        assert_eq!(paths(lookup(did, part, 100)), vec!["app.bsky.feed.post/b"]);
        // a stale generation caches nothing
        let g = generation(did);
        commit(did, 110, 120, vec![]).apply();
        fill_lagging(did, part, g, 110, 9, vec![rec("x/y", 10)]);
        assert!(matches!(lookup(did, part, 9), Since::Unknown));
    }
}
