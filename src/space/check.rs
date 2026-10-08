//! check-space (`vlpds.admin.checkSpace`, `vlpds admin check-space`): one
//! account's repo in one space against its own rows, as check-repo does for
//! a public repo. The set hash and count are recomputed from `sR` and
//! compared with `sH`; the oplog (`sO`) is replayed onto `sR`; the outbox
//! row (`sP`) and, when the account is the space's authority, the host's
//! writer rows (`sW`, `sQ`) are checked against the head. listSpaces's
//! index rows (`sL`) must be there exactly when the head is and when a live
//! space row (`sS`) is.
//!
//! [`check`] is pure: it takes decoded rows, so the fuzz and crash
//! harnesses can feed it whatever a snapshot held.

use super::commit::element;
use super::lthash::LtHash;
use anyhow::Context;
use bytes::Bytes;
use serde_json::{json, Value as J};
use std::collections::{BTreeMap, HashMap};
use vlatproto::cid::Cid;
use vlatproto::tid::Tid;

/// Problems listed per check (counts are exact).
const LIST_MAX: usize = 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Create,
    Update,
    Delete,
}

/// `sH`.
#[derive(Clone, Debug)]
pub struct Head {
    pub uri: String,
    pub rev: Tid,
    pub hash: LtHash,
    pub records: u64,
    /// Unix microseconds of the first write.
    pub created: u64,
}

/// An `sR` row whose value decoded.
#[derive(Clone, Debug)]
pub struct Record {
    /// `{collection}/{rkey}`.
    pub path: String,
    pub cid: Cid,
    pub rev: Tid,
    /// The record bytes hash to `cid`.
    pub hashes: bool,
}

/// An `sO` row.
#[derive(Clone, Debug)]
pub struct Op {
    pub rev: Tid,
    pub idx: u16,
    pub action: Action,
    pub collection: String,
    pub rkey: String,
    pub cid: Option<Cid>,
    pub prev: Option<Cid>,
}

impl Op {
    fn path(&self) -> String {
        format!("{}/{}", self.collection, self.rkey)
    }
}

/// `sP`.
#[derive(Clone, Debug)]
pub struct Outbox {
    pub uri: String,
    pub repo_rev: Tid,
    pub hash: [u8; 32],
}

/// An `sW` row.
#[derive(Clone, Debug)]
pub struct Writer {
    pub did: String,
    pub repo_rev: Tid,
    pub hash: [u8; 32],
    pub space_rev: Tid,
}

/// The space host's rows, when the account is the space's authority.
#[derive(Clone, Debug, Default)]
pub struct Host {
    /// `sS` holds a live space, or none (the defaults): not a tombstone.
    pub live: bool,
    pub writers: Vec<Writer>,
    /// `sQ`: (spaceRev, the spaceRev before it, writer DID).
    pub seq: Vec<(Tid, Option<Tid>, String)>,
}

/// The account's `sL` rows for the space.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Listed {
    pub repo: bool,
    pub governs: bool,
}

/// One snapshot's rows of (account, space), in key order.
#[derive(Clone, Debug, Default)]
pub struct Rows {
    pub head: Option<Head>,
    pub records: Vec<Record>,
    /// Paths of `sR` rows that don't decode.
    pub bad_records: Vec<String>,
    pub ops: Vec<Op>,
    /// `{rev}/{idx}` (or the key, hex) of `sO` rows that don't decode.
    pub bad_ops: Vec<String>,
    pub outbox: Option<Outbox>,
    pub host: Option<Host>,
    /// The account governs the space and its `sS` row is live.
    pub governs: bool,
    pub listed: Listed,
}

impl Rows {
    pub fn is_empty(&self) -> bool {
        self.head.is_none()
            && self.records.is_empty()
            && self.bad_records.is_empty()
            && self.ops.is_empty()
            && self.bad_ops.is_empty()
            && self.outbox.is_none()
            && self.host.is_none()
            && self.listed == Listed::default()
    }
}

/// The rows of `did`'s repo in `uri` (and, when `did` is its authority, the
/// space host's) from `db`, a snapshot taken under the apply lock.
pub async fn load<R: slatedb::DbReadOps + Sync + ?Sized>(db: &R, did: &str, uri: &str) -> anyhow::Result<Rows> {
    use super::rows;
    use crate::state;
    let sid = state::space_id(uri);
    let mut out = Rows::default();
    if let Some(v) = db.get(state::space_head_key(did, &sid)).await? {
        let h = rows::HeadRow::decode(&v).context("the head (sH) doesn't decode")?;
        out.head = Some(Head { uri: h.uri, rev: h.rev, hash: h.hash, records: h.records, created: h.created });
    }
    let rp = state::space_prefix(state::SPACE_RECORD_FAMILY, did, &sid);
    for (k, v) in scan(db, &rp).await? {
        let path = String::from_utf8_lossy(&k[rp.len()..]).into_owned();
        match state::record_value_parts(&v) {
            Ok((cid, bytes)) => out.records.push(Record {
                path,
                cid,
                rev: Tid(state::record_value_rev(&v)),
                hashes: Cid::dag_cbor(bytes) == cid,
            }),
            Err(_) => out.bad_records.push(path),
        }
    }
    let op = state::space_prefix(state::SPACE_OPLOG_FAMILY, did, &sid);
    for (k, v) in scan(db, &op).await? {
        let pos = rows::oplog_position(&k).filter(|_| k.len() == op.len() + 10);
        match (pos, rows::OpRow::decode(&v)) {
            (Some((rev, idx)), Ok(o)) => out.ops.push(Op {
                rev,
                idx,
                action: match o.action {
                    rows::OpAction::Create => Action::Create,
                    rows::OpAction::Update => Action::Update,
                    rows::OpAction::Delete => Action::Delete,
                },
                collection: o.collection,
                rkey: o.rkey,
                cid: o.cid,
                prev: o.prev,
            }),
            (Some((rev, idx)), Err(_)) => out.bad_ops.push(format!("{rev}/{idx}")),
            (None, _) => out.bad_ops.push(hex::encode(&k[op.len()..])),
        }
    }
    if let Some(v) = db.get(state::space_outbox_key(did, &sid)).await? {
        let o = rows::OutboxRow::decode(&v).context("the outbox row (sP) doesn't decode")?;
        out.outbox = Some(Outbox { uri: o.uri, repo_rev: o.repo_rev, hash: o.hash });
    }
    if authority(uri) == Some(did) {
        let space = match db.get(state::space_key(did, &sid)).await? {
            Some(v) => Some(rows::SpaceRow::decode(&v).context("the space row (sS) doesn't decode")?),
            None => None,
        };
        let wp = state::space_prefix(state::SPACE_WRITER_FAMILY, did, &sid);
        let mut writers = Vec::new();
        for (k, v) in scan(db, &wp).await? {
            let w = rows::WriterRow::decode(&v).context("a writer row (sW) doesn't decode")?;
            let did = String::from_utf8_lossy(&k[wp.len()..]).into_owned();
            writers.push(Writer { did, repo_rev: w.repo_rev, hash: w.hash, space_rev: w.space_rev });
        }
        let qp = state::space_prefix(state::SPACE_SEQ_FAMILY, did, &sid);
        let mut seq = Vec::new();
        for (k, v) in scan(db, &qp).await? {
            let rev = rows::seq_rev(&k).filter(|_| k.len() == qp.len() + 8).context("a bad listRepos (sQ) key")?;
            let q = rows::SeqRow::decode(&v).context("a listRepos row (sQ) doesn't decode")?;
            seq.push((rev, q.prev, q.writer));
        }
        out.governs = space.as_ref().is_some_and(|s| s.live() && s.uri == uri);
        if space.is_some() || !writers.is_empty() || !seq.is_empty() {
            // no sS row: governed with the defaults (ensureSpace), not deleted
            let live = space.as_ref().is_none_or(|s| s.live() && s.uri == uri);
            out.host = Some(Host { live, writers, seq });
        }
    }
    let listed = |why| db.get(state::space_list_key(did, uri, why));
    out.listed = Listed {
        repo: listed(state::SpaceListed::Repo).await?.is_some(),
        governs: listed(state::SpaceListed::Governs).await?.is_some(),
    };
    Ok(out)
}

async fn scan<R: slatedb::DbReadOps + Sync + ?Sized>(db: &R, prefix: &[u8]) -> anyhow::Result<Vec<(Bytes, Bytes)>> {
    let mut it = db.scan(prefix.to_vec()..vlsync_store::keys::prefix_end(prefix)).await?;
    let mut out = Vec::new();
    while let Some(kv) = it.next().await? {
        out.push((kv.key, kv.value));
    }
    Ok(out)
}

fn sample<T: ToString>(v: impl IntoIterator<Item = T>) -> Vec<String> {
    v.into_iter().take(LIST_MAX).map(|x| x.to_string()).collect()
}

/// The authority DID of a space URI (`at://{authority}/space/...`).
pub fn authority(uri: &str) -> Option<&str> {
    uri.strip_prefix("at://")?.split('/').next().filter(|a| !a.is_empty())
}

fn count(problems: &mut Vec<String>, n: usize, what: &str) {
    if n > 0 {
        problems.push(format!("{n} {what}"));
    }
}

fn split_path(path: &str) -> (&str, &str) {
    path.split_once('/').unwrap_or((path, ""))
}

/// The report of [`Rows`] for `did`'s repo in `uri` at `now_us`: the
/// checkRepo shape (`ok`, `problems` and per-check sections).
///
/// A repo created within `retention` (None: never pruned) has never had an
/// op pruned, so its oplog must replay from empty to exactly its records.
/// An imported repo (`created` 0) never had the ops before its import.
pub fn check(did: &str, uri: &str, rows: &Rows, now_us: u64, retention: Option<std::time::Duration>) -> J {
    let mut problems: Vec<String> = Vec::new();
    let head = rows.head.as_ref();
    let head_rev = head.map(|h| h.rev);

    // records against the head
    let by_path: HashMap<&str, &Record> = rows.records.iter().map(|r| (r.path.as_str(), r)).collect();
    let mut set = LtHash::default();
    for r in &rows.records {
        let (c, k) = split_path(&r.path);
        set.add(&element(c, k, &r.cid.to_string()));
    }
    let unhashed: Vec<&str> = rows.records.iter().filter(|r| !r.hashes).map(|r| r.path.as_str()).collect();
    let newer: Vec<&str> =
        rows.records.iter().filter(|r| head_rev.is_none_or(|h| r.rev > h)).map(|r| r.path.as_str()).collect();
    let stored = rows.records.len() + rows.bad_records.len();
    let mut hash_ok = None;
    match head {
        Some(h) => {
            if h.uri != uri {
                problems.push(format!("the head (sH) is {}'s: a space id collision", h.uri));
            }
            let ok = set.state() == h.hash.state();
            if !ok {
                problems.push(format!(
                    "records hash to {}, the head says {}",
                    hex::encode(set.digest()),
                    hex::encode(h.hash.digest())
                ));
            }
            hash_ok = Some(ok);
            if h.records != stored as u64 {
                problems.push(format!("the head counts {} record(s), sR holds {stored}", h.records));
            }
        }
        None if stored > 0 || !rows.ops.is_empty() || !rows.bad_ops.is_empty() => {
            problems
                .push(format!("no head (sH) for {stored} record(s) and {} op(s)", rows.ops.len() + rows.bad_ops.len()));
        }
        None => {}
    }
    count(&mut problems, rows.bad_records.len(), "record row(s) (sR) don't decode");
    count(&mut problems, unhashed.len(), "record(s) don't hash to their CID");
    if head.is_some() {
        count(&mut problems, newer.len(), "record(s) written at a rev after the head's");
    }

    // the oplog, replayed onto the records
    let expect_complete = head.is_some_and(|h| {
        h.created != 0 && retention.is_none_or(|r| u128::from(now_us.saturating_sub(h.created)) < r.as_micros())
    });
    let mut revs: BTreeMap<Tid, Vec<u16>> = BTreeMap::new();
    let (mut malformed, mut prev_wrong) = (Vec::new(), Vec::new());
    let mut replay: BTreeMap<String, (Option<Cid>, Tid)> = BTreeMap::new();
    for op in &rows.ops {
        revs.entry(op.rev).or_default().push(op.idx);
        let pos = format!("{}/{}", op.rev, op.idx);
        let shape_ok = match op.action {
            Action::Create => op.cid.is_some() && op.prev.is_none(),
            Action::Update => op.cid.is_some() && op.prev.is_some(),
            Action::Delete => op.cid.is_none() && op.prev.is_some(),
        };
        if !shape_ok {
            malformed.push(pos.clone());
        }
        let path = op.path();
        let prev_ok = match replay.get(&path) {
            Some((cid, _)) => op.prev == *cid,
            // the first retained op of a path; with nothing pruned, a create
            None => !expect_complete || op.prev.is_none(),
        };
        if !prev_ok {
            prev_wrong.push(pos);
        }
        replay.insert(path, (op.cid, op.rev));
    }
    let gaps: Vec<String> = revs
        .iter()
        .filter(|(_, idx)| idx.iter().enumerate().any(|(i, x)| usize::from(*x) != i))
        .map(|(rev, _)| rev.to_string())
        .collect();
    let ops_after_head = rows.ops.iter().filter(|o| head_rev.is_none_or(|h| o.rev > h)).count();
    let (oldest, newest) = (revs.keys().next().copied(), revs.keys().next_back().copied());
    if let (Some(n), Some(h)) = (newest, head_rev) {
        if n != h {
            problems.push(format!("the newest op is at rev {n}, the head at {h}"));
        }
    }
    let mut disagree: Vec<String> = replay
        .iter()
        .filter(|(path, (cid, rev))| match (cid, by_path.get(path.as_str())) {
            (Some(c), Some(r)) => r.cid != *c || r.rev != *rev,
            (Some(_), None) => !rows.bad_records.contains(path),
            (None, Some(_)) => true,
            (None, None) => false,
        })
        .map(|(p, _)| p.clone())
        .collect();
    let unlogged: Vec<&str> = rows
        .records
        .iter()
        .filter(|r| !replay.contains_key(&r.path))
        .filter(|r| expect_complete || oldest.is_some_and(|o| r.rev >= o))
        .map(|r| r.path.as_str())
        .collect();
    disagree.sort();
    count(&mut problems, rows.bad_ops.len(), "oplog row(s) (sO) don't decode");
    count(&mut problems, malformed.len(), "op(s) whose action doesn't fit their cid/prev");
    count(&mut problems, gaps.len(), "rev(s) whose ops aren't numbered from 0 without gaps");
    if head.is_some() {
        count(&mut problems, ops_after_head, "op(s) at a rev after the head's");
    }
    count(&mut problems, prev_wrong.len(), "op(s) whose prev isn't the path's CID before them");
    count(&mut problems, disagree.len(), "path(s) where the oplog replays to something sR doesn't hold");
    count(&mut problems, unlogged.len(), "record(s) written inside the oplog's window with no op");

    // the outbox row
    let auth = authority(uri);
    let digest = head.map(|h| h.hash.digest());
    let outbox = rows.outbox.as_ref().map(|o| {
        if o.uri != uri {
            problems.push(format!("the outbox row (sP) is {}'s: a space id collision", o.uri));
        }
        if auth == Some(did) {
            problems.push("an outbox row (sP) for a space the account governs (its writes need no notify)".into());
        }
        match head_rev {
            None => problems.push("an outbox row (sP) with no head".into()),
            Some(h) if o.repo_rev > h => {
                problems.push(format!("the outbox row is at rev {}, the head at {h}", o.repo_rev))
            }
            Some(h) if o.repo_rev == h && Some(o.hash) != digest => {
                problems.push("the outbox row is at the head's rev with another hash".into())
            }
            Some(_) => {}
        }
        json!({"repoRev": o.repo_rev.to_string(), "hash": hex::encode(o.hash)})
    });

    // listSpaces's index
    match (head.is_some(), rows.listed.repo) {
        (true, false) => problems.push("the head (sH) has no listSpaces row (sL)".into()),
        (false, true) => problems.push("a listSpaces row (sL) for a repo with no head".into()),
        _ => {}
    }
    match (rows.governs, rows.listed.governs) {
        (true, false) => problems.push("the live space row (sS) has no listSpaces row (sL)".into()),
        (false, true) => problems.push("a listSpaces row (sL) for a space that isn't live here".into()),
        _ => {}
    }

    // the space host's rows, when the account governs the space
    let host = rows.host.as_ref().map(|h| {
        let seq: HashMap<Tid, &str> = h.seq.iter().map(|(t, _, w)| (*t, w.as_str())).collect();
        let writers: HashMap<&str, &Writer> = h.writers.iter().map(|w| (w.did.as_str(), w)).collect();
        let unsequenced = h.writers.iter().filter(|w| seq.get(&w.space_rev) != Some(&w.did.as_str())).count();
        let stale_seq =
            h.seq.iter().filter(|(t, _, w)| writers.get(w.as_str()).is_none_or(|x| x.space_rev != *t)).count();
        // the spaceRev before a row's is at least the row before it in sQ
        // (rows between them are writers that wrote again) and below its own
        let bad_prev = h
            .seq
            .iter()
            .enumerate()
            .filter(|(i, (t, p, _))| {
                let floor = i.checked_sub(1).map(|j| h.seq[j].0);
                p.is_some_and(|p| p >= *t) || floor.is_some_and(|f| p.is_none_or(|p| p < f))
            })
            .count();
        count(&mut problems, unsequenced, "writer row(s) (sW) without their listRepos row (sQ)");
        count(&mut problems, stale_seq, "listRepos row(s) (sQ) that aren't their writer's latest");
        count(&mut problems, bad_prev, "listRepos row(s) (sQ) whose prevSpaceRev is out of order");
        if !h.live && !(h.writers.is_empty() && h.seq.is_empty()) {
            problems.push(format!(
                "a deleted space keeps {} writer and {} listRepos row(s)",
                h.writers.len(),
                h.seq.len()
            ));
        }
        let own = writers.get(did).copied();
        if let (Some(w), Some(hd)) = (own, head) {
            if w.repo_rev != hd.rev || Some(w.hash) != digest {
                problems.push(format!(
                    "the space host has the account's own repo at rev {}, the head is at {}",
                    w.repo_rev, hd.rev
                ));
            }
        }
        json!({
            "live": h.live,
            "writers": h.writers.len(),
            "seq": h.seq.len(),
            "maxSpaceRev": h.seq.iter().map(|(t, ..)| *t).max().map(|t| t.to_string()),
            "unsequenced": unsequenced,
            "staleSeq": stale_seq,
        })
    });

    json!({
        "did": did,
        "space": uri,
        "ok": problems.is_empty(),
        "problems": problems,
        "head": head.map(|h| json!({
            "rev": h.rev.to_string(),
            "records": h.records,
            "hash": hex::encode(h.hash.digest()),
            "created": h.created,
        })),
        "records": {
            "count": stored,
            "badCount": rows.bad_records.len(),
            "bad": sample(&rows.bad_records),
            "unhashed": sample(&unhashed),
            "newerThanHead": sample(&newer),
            "rehash": hex::encode(set.digest()),
            "matchesHead": hash_ok,
        },
        "oplog": {
            "ops": rows.ops.len() + rows.bad_ops.len(),
            "revs": revs.len(),
            "oldestRev": oldest.map(|t| t.to_string()),
            "newestRev": newest.map(|t| t.to_string()),
            "complete": expect_complete,
            "bad": sample(&rows.bad_ops),
            "malformed": sample(&malformed),
            "gaps": sample(&gaps),
            "prevWrong": sample(&prev_wrong),
            "disagree": sample(&disagree),
            "unlogged": sample(&unlogged),
        },
        "outbox": outbox,
        "host": host,
        "listed": {"repo": rows.listed.repo, "governs": rows.listed.governs},
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const RET: Option<std::time::Duration> = Some(crate::space::retention::DEFAULT_RETENTION);

    const DID: &str = "did:plc:writer";
    const URI: &str = "at://did:plc:auth/space/com.example.group/x";
    const NOW: u64 = 1_800_000_000_000_000;

    /// Rows as a correct writer leaves them after `batches`, each one rev of
    /// (path, Some(record bytes) | None for a delete).
    fn written(batches: &[&[(&str, Option<&[u8]>)]]) -> Rows {
        let mut rows = Rows::default();
        let mut set = LtHash::default();
        let mut live: BTreeMap<String, (Cid, Tid)> = BTreeMap::new();
        let mut rev = Tid::from_parts(NOW - 1_000_000, 1);
        for batch in batches {
            rev = Tid(rev.0 + (1 << 10));
            for (idx, (path, bytes)) in batch.iter().enumerate() {
                let (c, k) = split_path(path);
                let prev = live.get(*path).map(|x| x.0);
                if let Some(p) = prev {
                    set.remove(&element(c, k, &p.to_string()));
                }
                let cid = bytes.map(Cid::dag_cbor);
                let action = match (prev, cid) {
                    (None, _) => Action::Create,
                    (Some(_), Some(_)) => Action::Update,
                    (Some(_), None) => Action::Delete,
                };
                match cid {
                    Some(n) => {
                        set.add(&element(c, k, &n.to_string()));
                        live.insert(path.to_string(), (n, rev));
                    }
                    None => {
                        live.remove(*path);
                    }
                }
                rows.ops.push(Op { rev, idx: idx as u16, action, collection: c.into(), rkey: k.into(), cid, prev });
            }
        }
        rows.records =
            live.iter().map(|(p, (cid, rev))| Record { path: p.clone(), cid: *cid, rev: *rev, hashes: true }).collect();
        rows.head =
            Some(Head { uri: URI.into(), rev, hash: set, records: live.len() as u64, created: NOW - 1_000_000 });
        rows.listed.repo = true;
        rows
    }

    fn healthy() -> Rows {
        written(&[
            &[("a.b.c/1", Some(b"\xa1aa\x01")), ("a.b.c/2", Some(b"\xa1aa\x02"))],
            &[("a.b.c/1", Some(b"\xa1aa\x03")), ("a.b.c/1", Some(b"\xa1aa\x04")), ("a.b.c/3", Some(b"\xa1aa\x05"))],
            &[("a.b.c/2", None), ("a.b.c/4", Some(b"\xa1aa\x06")), ("a.b.c/4", None)],
        ])
    }

    fn problems(r: &J) -> Vec<String> {
        r["problems"].as_array().unwrap().iter().map(|p| p.as_str().unwrap().to_string()).collect()
    }

    #[track_caller]
    fn assert_problem(rows: &Rows, now: u64, needle: &str) {
        let r = check(DID, URI, rows, now, RET);
        assert_eq!(r["ok"], json!(false), "{r}");
        assert!(problems(&r).iter().any(|p| p.contains(needle)), "no problem with {needle:?}: {r}");
    }

    #[test]
    fn healthy_rows_are_ok() {
        let rows = healthy();
        let r = check(DID, URI, &rows, NOW, RET);
        assert_eq!(r["ok"], json!(true), "{r}");
        assert_eq!(r["records"]["count"], json!(2));
        assert_eq!(r["oplog"]["ops"], json!(8));
        assert_eq!(r["oplog"]["revs"], json!(3));
        assert_eq!(r["oplog"]["complete"], json!(true));
        assert_eq!(r["records"]["matchesHead"], json!(true));
        assert!(check(DID, URI, &Rows::default(), NOW, RET)["ok"] == json!(true));
    }

    #[test]
    fn record_damage_is_reported() {
        let mut rows = healthy();
        rows.records.pop();
        assert_problem(&rows, NOW, "records hash to");
        assert_problem(&rows, NOW, "the head counts 2 record(s), sR holds 1");
        assert_problem(&rows, NOW, "oplog replays to something sR doesn't hold");

        let mut rows = healthy();
        rows.records[0].hashes = false;
        assert_problem(&rows, NOW, "1 record(s) don't hash to their CID");

        let mut rows = healthy();
        rows.records[0].rev = Tid(rows.head.as_ref().unwrap().rev.0 + 1);
        assert_problem(&rows, NOW, "written at a rev after the head's");

        let mut rows = healthy();
        rows.head.as_mut().unwrap().uri = "at://did:plc:other/space/com.example.group/y".into();
        assert_problem(&rows, NOW, "space id collision");

        let mut rows = healthy();
        rows.head = None;
        assert_problem(&rows, NOW, "no head (sH)");

        let mut rows = healthy();
        rows.bad_records.push("a.b.c/9".into());
        assert_problem(&rows, NOW, "1 record row(s) (sR) don't decode");
    }

    #[test]
    fn oplog_damage_is_reported() {
        let mut rows = healthy();
        rows.ops.remove(2); // a.b.c/1's first update
        assert_problem(&rows, NOW, "1 rev(s) whose ops aren't numbered from 0");
        assert_problem(&rows, NOW, "1 op(s) whose prev isn't the path's CID");

        let mut rows = healthy();
        rows.ops.remove(4); // a.b.c/3's create, the last op of its rev
        assert_problem(&rows, NOW, "1 record(s) written inside the oplog's window with no op");

        let mut rows = healthy();
        rows.ops[3].prev = None; // an update without its prev
        assert_problem(&rows, NOW, "action doesn't fit");
        assert_problem(&rows, NOW, "prev isn't the path's CID");

        let mut rows = healthy();
        rows.ops[3].prev = Some(Cid::dag_cbor(b"\xa0"));
        assert_problem(&rows, NOW, "1 op(s) whose prev isn't the path's CID");

        let mut rows = healthy();
        let last = rows.ops.len() - 1;
        rows.ops[last].cid = Some(Cid::dag_cbor(b"\xa0"));
        rows.ops[last].action = Action::Update;
        assert_problem(&rows, NOW, "oplog replays to something sR doesn't hold");

        let mut rows = healthy();
        let h = rows.head.as_mut().unwrap();
        h.rev = Tid(h.rev.0 + (1 << 10));
        assert_problem(&rows, NOW, "the newest op is at rev");

        let mut rows = healthy();
        rows.bad_ops.push("x/0".into());
        assert_problem(&rows, NOW, "1 oplog row(s) (sO) don't decode");
    }

    /// Past retention the oldest ops may be gone: the window still has to
    /// replay onto sR, but a path's first retained op needn't be a create.
    #[test]
    fn a_pruned_oplog_checks_its_window() {
        let mut rows = healthy();
        let first_rev = rows.ops[0].rev;
        rows.ops.retain(|o| o.rev != first_rev);
        assert_problem(&rows, NOW, "2 op(s) whose prev isn't the path's CID");
        let later = NOW + RET.unwrap().as_micros() as u64;
        let r = check(DID, URI, &rows, later, RET);
        assert_eq!(r["ok"], json!(true), "{r}");
        assert_eq!(r["oplog"]["complete"], json!(false));

        // a record inside the window must still have its op
        rows.ops.retain(|o| o.path() != "a.b.c/3");
        assert_problem(&rows, later, "1 record(s) written inside the oplog's window with no op");
    }

    #[test]
    fn outbox_and_host_rows() {
        let mut rows = healthy();
        let h = rows.head.clone().unwrap();
        rows.outbox = Some(Outbox { uri: URI.into(), repo_rev: h.rev, hash: h.hash.digest() });
        assert_eq!(check(DID, URI, &rows, NOW, RET)["ok"], json!(true));
        rows.outbox.as_mut().unwrap().hash = [0; 32];
        assert_problem(&rows, NOW, "at the head's rev with another hash");
        rows.outbox.as_mut().unwrap().repo_rev = Tid(h.rev.0 - (1 << 10));
        assert_eq!(check(DID, URI, &rows, NOW, RET)["ok"], json!(true), "an older rev still owed");
        rows.outbox.as_mut().unwrap().repo_rev = Tid(h.rev.0 + 1);
        assert_problem(&rows, NOW, "the outbox row is at rev");
        let own = "at://did:plc:writer/space/com.example.group/x";
        let mut self_rows = rows.clone();
        self_rows.head.as_mut().unwrap().uri = own.into();
        self_rows.outbox = Some(Outbox { uri: own.into(), repo_rev: h.rev, hash: h.hash.digest() });
        let r = check(DID, own, &self_rows, NOW, RET);
        assert!(problems(&r).iter().any(|p| p.contains("governs")), "{r}");

        // the authority's view of its own repo, and listRepos rows
        let mut rows = healthy();
        rows.head.as_mut().unwrap().uri = own.into();
        let s1 = Tid::from_parts(NOW, 2);
        let s2 = Tid::from_parts(NOW + 1, 2);
        let me = Writer { did: DID.into(), repo_rev: h.rev, hash: h.hash.digest(), space_rev: s2 };
        let other = Writer { did: "did:plc:other".into(), repo_rev: s1, hash: [1; 32], space_rev: s1 };
        rows.host = Some(Host {
            live: true,
            writers: vec![me, other.clone()],
            seq: vec![(s1, None, other.did.clone()), (s2, Some(s1), DID.into())],
        });
        let r = check(DID, own, &rows, NOW, RET);
        assert_eq!(r["ok"], json!(true), "{r}");
        assert_eq!(r["host"]["maxSpaceRev"], json!(s2.to_string()));
        let mut stale = rows.clone();
        stale.host.as_mut().unwrap().seq.insert(0, (Tid(s1.0 - 1), None, other.did.clone()));
        assert_problem(&stale, NOW, "1 listRepos row(s) (sQ) that aren't their writer's latest");
        let mut unseq = rows.clone();
        unseq.host.as_mut().unwrap().seq.remove(0);
        let mut forked = rows.clone();
        forked.host.as_mut().unwrap().seq[1].1 = Some(Tid(s1.0 - 1));
        assert_problem(&forked, NOW, "1 listRepos row(s) (sQ) whose prevSpaceRev is out of order");
        assert_problem(&unseq, NOW, "1 writer row(s) (sW) without their listRepos row");
        let mut behind = rows.clone();
        behind.host.as_mut().unwrap().writers[0].repo_rev = Tid(h.rev.0 - 1);
        assert_problem(&behind, NOW, "the space host has the account's own repo at rev");
        let mut deleted = rows.clone();
        deleted.host.as_mut().unwrap().live = false;
        assert_problem(&deleted, NOW, "a deleted space keeps 2 writer");
    }

    #[test]
    fn list_index_rows() {
        let mut unlisted = healthy();
        unlisted.listed.repo = false;
        assert_problem(&unlisted, NOW, "the head (sH) has no listSpaces row (sL)");
        let mut headless = Rows::default();
        headless.listed.repo = true;
        assert!(!headless.is_empty());
        assert_problem(&headless, NOW, "a listSpaces row (sL) for a repo with no head");
        let mut governs = healthy();
        governs.governs = true;
        assert_problem(&governs, NOW, "the live space row (sS) has no listSpaces row (sL)");
        governs.listed.governs = true;
        assert_eq!(check(DID, URI, &governs, NOW, RET)["ok"], json!(true));
        governs.governs = false;
        assert_problem(&governs, NOW, "a listSpaces row (sL) for a space that isn't live here");
    }

    #[test]
    fn authorities() {
        assert_eq!(authority(URI), Some("did:plc:auth"));
        assert_eq!(authority("at:///space/x/y"), None);
        assert_eq!(authority("did:plc:x"), None);
    }
}
