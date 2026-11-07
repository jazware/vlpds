//! Space writes on the repo worker (`crate::worker`): the per-repo state a
//! worker keeps for the spaces an account writes to (`SpaceHead`) and
//! governs (`HostHead`), what a request needs read first, and the log
//! mutations of each op. Everything here runs on the worker thread except
//! [`fetch`], which the worker runs on the runtime.
//!
//! Prev CIDs: a write needs the CID each path held before it. Paths written
//! by entries not yet applied are in the head's `overlay`; anything else is
//! read from `sR` off the worker thread into `fetched`. The overlay is only
//! pruned (applied entries dropped) while `fetched` is empty, so a value
//! read before an entry applied is never used once that entry's overlay is
//! gone.
//!
//! Blob refs: each path's held state carries the blobs its record names, so
//! a write's `sb`/`sc` deletes come from the same read as its prev CID.

use super::heads::DurableSpaceHead;
use super::lthash::LtHash;
use super::publish;
use super::rows::{HeadRow, MemberRow, NotifyRow, OpAction, OpRow, OutboxRow, Policy, SeqRow, SpaceRow, WriterRow};
use crate::state::{self, SpaceId, SpaceListed};
use crate::worker::WriteError;
use bytes::Bytes;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use vlatproto::cid::Cid;
use vlatproto::tid::{self, Tid};
use vlsync_store::segment::Mutation;

pub const MAX_WRITES: usize = 200;

#[derive(Clone, Debug)]
pub enum SpaceWrite {
    Create {
        collection: String,
        rkey: String,
        cid: Cid,
        bytes: Bytes,
        blobs: Vec<Cid>,
    },
    /// applyWrites#update (`must_exist`), or putRecord, which is a create
    /// or an update by what the path holds: `put` names the scope each would
    /// lack (None: granted).
    Update {
        collection: String,
        rkey: String,
        cid: Cid,
        bytes: Bytes,
        blobs: Vec<Cid>,
        must_exist: bool,
        put: Option<PutScopes>,
    },
    /// deleteRecord of a missing record is a no-op (`must_exist` false).
    Delete {
        collection: String,
        rkey: String,
        must_exist: bool,
    },
}

#[derive(Clone, Debug, Default)]
pub struct PutScopes {
    pub create: Option<String>,
    pub update: Option<String>,
}

impl SpaceWrite {
    fn parts(&self) -> (&str, &str) {
        match self {
            SpaceWrite::Create { collection, rkey, .. }
            | SpaceWrite::Update { collection, rkey, .. }
            | SpaceWrite::Delete { collection, rkey, .. } => (collection, rkey),
        }
    }

    pub fn path(&self) -> String {
        let (c, r) = self.parts();
        format!("{c}/{r}")
    }
}

pub enum SpaceOp {
    /// A write to the worker's account's repo in the space.
    Write {
        writes: Vec<SpaceWrite>,
    },
    /// The space host records a writer's newer state (notifyWrite), the
    /// worker's account being the authority. `managing_app`: the managing
    /// app's verdict, asked by the caller when the write policy names one.
    RecordWriter {
        writer: String,
        repo_rev: Tid,
        hash: [u8; 32],
        managing_app: Option<bool>,
        same_rev: SameRev,
    },
    /// space.createSpace by the worker's account.
    CreateSpace {
        row: SpaceRow,
    },
    /// space.importSpaceMeta: the space's row put in over whatever is held,
    /// once its member list, writer states and sequence are in `sM`, `sW`
    /// and `sQ`; the host state cached here is read again from them.
    ImportSpaceMeta {
        row: SpaceRow,
        max_space_rev: Option<Tid>,
    },
    /// space.updateSpace: the policy replaced wholesale.
    UpdateSpace {
        policy: Policy,
    },
    /// memberspace.putMember: both flags replaced. One without write also
    /// leaves the writer set.
    PutMember {
        member: String,
        access: MemberRow,
    },
    /// memberspace.removeMember, which also drops the writer.
    RemoveMember {
        member: String,
    },
    /// space.removeWriter: out of listRepos until it writes again.
    RemoveWriter {
        writer: String,
    },
    /// space.deleteSpace: the space becomes a tombstone and the
    /// authority's own repo in it goes from reads at once. Its other rows
    /// are swept by the caller after the ack (`delete_space_rows`).
    DeleteSpace {
        deleted_at: String,
    },
    RegisterNotify {
        service: String,
        row: NotifyRow,
    },
    UnregisterNotify {
        service: String,
        /// The expired-registration prune: deletes it only if it expired by
        /// then, so a renewal that landed meanwhile is never undone.
        expired_by: Option<u64>,
    },
    /// space.importRepo: claims the space for an import (`nonce`); the
    /// account's writes there wait it out. With `replace`, a repo there has
    /// its head taken away, so what's staged is never served until the
    /// commit; without, only a repo with no head is claimed: to clear rows
    /// left under it.
    ImportBegin {
        nonce: u64,
        replace: bool,
    },
    /// The imported records are durable in `sR`: the head goes in at a new
    /// rev after `prev` (the archive's and the replaced repo's), with an
    /// empty oplog.
    ImportCommit {
        nonce: u64,
        prev: Option<Tid>,
        hash: Box<LtHash>,
        records: u64,
    },
    /// clearRecords' claim (as an import's): the account's writes there wait
    /// it out, and its ack follows every earlier entry, so what is stored
    /// then is the whole repo.
    Claim {
        nonce: u64,
    },
    /// clearRecords under its claim: `deletes` (every record outside the
    /// kept collections, their blob refs, the whole oplog) and the head at
    /// a new rev after `prev`, over what's kept, in one entry.
    Clear {
        nonce: u64,
        prev: Tid,
        deletes: Vec<Mutation>,
        hash: Box<LtHash>,
        records: u64,
    },
}

impl SpaceOp {
    /// A host op that publishes, to run again once the rows a stopped
    /// import or sweep left under the authority's repo are cleared.
    pub fn host_retry(&self) -> Option<SpaceOp> {
        Some(match self {
            SpaceOp::CreateSpace { row } => SpaceOp::CreateSpace { row: row.clone() },
            SpaceOp::UpdateSpace { policy } => SpaceOp::UpdateSpace { policy: policy.clone() },
            SpaceOp::PutMember { member, access } => SpaceOp::PutMember { member: member.clone(), access: *access },
            SpaceOp::RemoveMember { member } => SpaceOp::RemoveMember { member: member.clone() },
            _ => return None,
        })
    }
}

pub struct SpaceReq {
    pub did: Arc<str>,
    pub uri: Arc<str>,
    pub sid: SpaceId,
    pub op: SpaceOp,
    pub spaces: Arc<super::Spaces>,
    pub reply: tokio::sync::oneshot::Sender<Result<SpaceAck, SpaceError>>,
    /// Admission permit, held while queued.
    pub permit: Option<tokio::sync::OwnedSemaphorePermit>,
}

#[derive(Debug, Clone)]
pub enum SpaceOutcome {
    Create {
        path: String,
        cid: Cid,
    },
    Update {
        path: String,
        cid: Cid,
    },
    Delete,
    /// A delete of a record that wasn't there.
    Noop,
}

#[derive(Debug, Clone, Copy)]
pub struct Sequenced {
    pub space_rev: Tid,
    pub prev: Option<Tid>,
}

#[derive(Debug, Clone)]
pub enum SpaceAck {
    /// `rev`: None if nothing was written.
    Write {
        rev: Option<Tid>,
        results: Vec<SpaceOutcome>,
    },
    /// None: not newer than what the host has.
    Writer(Option<Sequenced>),
    Created,
    /// A space host op other than createSpace and deleteSpace.
    Host,
    /// `already`: the space was a tombstone before.
    Deleted {
        already: bool,
    },
}

#[derive(Debug, Clone)]
pub enum SpaceError {
    Write(WriteError),
    RecordNotFound(String),
    RecordAlreadyExists(String),
    ScopeMissing(String),
    SpaceNotFound,
    SpaceDeleted,
    SpaceAlreadyExists,
    /// A memberspace method on a space under another policy.
    PolicyMismatch,
    NotAuthorized(String),
    /// A notify at the repoRev held for the writer with another hash, under
    /// [`SameRev::Verify`]: nothing was written.
    SameRev,
    /// The repo has no head but rows of it remain (an import or a sweep
    /// stopped part way): they're cleared before the write, handed back.
    Unswept(Vec<SpaceWrite>),
}

impl From<WriteError> for SpaceError {
    fn from(e: WriteError) -> SpaceError {
        SpaceError::Write(e)
    }
}

/// A notify at the repoRev the authority holds for the writer, with
/// another hash: a record takedown or its reversal, or a writer making
/// every syncer refetch the whole repo for nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SameRev {
    /// Sequenced again: this cluster's own outbox computed the hash, or the
    /// caller checked it at the writer's host.
    Sequence,
    /// Refused with [`SpaceError::SameRev`] so the caller checks it first.
    Verify,
}

fn internal(m: impl Into<String>) -> SpaceError {
    SpaceError::Write(WriteError::Internal(m.into()))
}

/// A record a path holds: its CID and the distinct blobs it names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathRec {
    pub cid: Cid,
    pub blobs: Vec<Cid>,
}

impl PathRec {
    /// From an `sR` value.
    pub fn from_value(v: &[u8]) -> anyhow::Result<PathRec> {
        let (cid, bytes) = state::record_value_parts(v)?;
        let mut blobs = Vec::new();
        vlatproto::cbor::blob_refs(&vlatproto::cbor::Value::decode(bytes)?, &mut blobs);
        Ok(PathRec { cid, blobs })
    }

    fn heap_bytes(&self) -> usize {
        self.blobs.len() * std::mem::size_of::<Cid>()
    }
}

/// One account's repo in one space, as the worker builds on it: the head
/// after every entry it sent, applied or not.
pub struct SpaceHead {
    pub uri: Arc<str>,
    pub rev: Option<Tid>,
    pub hash: LtHash,
    pub records: u64,
    pub created: u64,
    /// path -> record (None: deleted) written by an entry, and whether that
    /// entry has applied.
    overlay: HashMap<String, (Option<PathRec>, Arc<AtomicBool>)>,
    /// Read from `sR` for the requests about to run.
    fetched: HashMap<String, Option<PathRec>>,
    /// No head, yet rows under it: see [`SpaceError::Unswept`].
    unswept: bool,
}

impl SpaceHead {
    fn new(uri: Arc<str>, row: Option<HeadRow>) -> SpaceHead {
        let (rev, hash, records, created) = match row {
            Some(r) => (Some(r.rev), r.hash, r.records, r.created),
            None => (None, LtHash::default(), 0, 0),
        };
        SpaceHead { uri, rev, hash, records, created, overlay: HashMap::new(), fetched: HashMap::new(), unswept: false }
    }

    fn known(&self, path: &str) -> Option<&Option<PathRec>> {
        self.overlay.get(path).map(|(c, _)| c).or_else(|| self.fetched.get(path))
    }

    fn heap_bytes(&self) -> usize {
        let blobs = |r: &Option<PathRec>| r.as_ref().map_or(0, PathRec::heap_bytes);
        std::mem::size_of::<Self>()
            + self.uri.len()
            + (self.overlay.len() + self.fetched.len()) * 128
            + self.overlay.values().map(|(r, _)| blobs(r)).sum::<usize>()
            + self.fetched.values().map(blobs).sum::<usize>()
    }
}

/// A space the worker's account governs.
pub struct HostHead {
    pub uri: Arc<str>,
    pub space: Option<SpaceRow>,
    /// The newest `sQ` spaceRev.
    pub max_space_rev: Option<Tid>,
    /// `sW` rows read so far (None: absent).
    pub writers: HashMap<String, Option<WriterRow>>,
    pub members: HashMap<String, Option<MemberRow>>,
    /// `members` holds the whole list, as read for an updateSpace.
    pub members_complete: bool,
    /// `sN` expiries read so far, by service (None: absent).
    pub registrations: HashMap<String, Option<u64>>,
}

impl HostHead {
    fn live(&self) -> Option<&SpaceRow> {
        self.space.as_ref().filter(|s| s.live())
    }

    fn heap_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            + self.uri.len()
            + 256
            + (self.writers.len() + self.members.len() + self.registrations.len()) * 128
    }
}

#[derive(Default)]
pub struct SpaceStates {
    pub repos: HashMap<SpaceId, SpaceHead>,
    pub hosts: HashMap<SpaceId, HostHead>,
}

impl SpaceStates {
    pub fn heap_bytes(&self) -> usize {
        self.repos.values().map(SpaceHead::heap_bytes).sum::<usize>()
            + self.hosts.values().map(HostHead::heap_bytes).sum::<usize>()
    }

    /// Drops overlay entries whose entries have applied, unless values read
    /// for the next requests are pending use.
    pub fn prune(&mut self) {
        for h in self.repos.values_mut() {
            if h.fetched.is_empty() {
                h.overlay.retain(|_, (_, applied)| !applied.load(Ordering::Acquire));
            }
        }
    }

    /// After the requests that needed them ran.
    pub fn clear_fetched(&mut self) {
        for h in self.repos.values_mut() {
            h.fetched.clear();
        }
    }
}

/// What a worker must read before running a repo's space requests.
#[derive(Default, Debug)]
pub struct SpaceNeed {
    heads: Vec<(SpaceId, Arc<str>)>,
    paths: Vec<(SpaceId, String)>,
    hosts: Vec<(SpaceId, Arc<str>)>,
    writers: Vec<(SpaceId, String)>,
    members: Vec<(SpaceId, String)>,
    /// The whole member list and the published member records.
    member_lists: Vec<SpaceId>,
    registrations: Vec<(SpaceId, String)>,
}

impl SpaceNeed {
    pub fn is_empty(&self) -> bool {
        self.heads.is_empty()
            && self.paths.is_empty()
            && self.hosts.is_empty()
            && self.writers.is_empty()
            && self.members.is_empty()
            && self.member_lists.is_empty()
            && self.registrations.is_empty()
    }

    fn head(&mut self, st: &SpaceStates, sid: SpaceId, uri: &Arc<str>) {
        if !st.repos.contains_key(&sid) && !self.heads.iter().any(|(s, _)| *s == sid) {
            self.heads.push((sid, uri.clone()));
        }
    }

    fn host(&mut self, st: &SpaceStates, sid: SpaceId, uri: &Arc<str>) {
        if !st.hosts.contains_key(&sid) && !self.hosts.iter().any(|(s, _)| *s == sid) {
            self.hosts.push((sid, uri.clone()));
        }
    }

    fn writer(&mut self, st: &SpaceStates, sid: SpaceId, did: &str) {
        if !st.hosts.get(&sid).is_some_and(|h| h.writers.contains_key(did)) {
            self.writers.push((sid, did.to_string()));
        }
    }

    fn registration(&mut self, st: &SpaceStates, sid: SpaceId, service: &str) {
        if !st.hosts.get(&sid).is_some_and(|h| h.registrations.contains_key(service)) {
            self.registrations.push((sid, service.to_string()));
        }
    }

    fn member(&mut self, st: &SpaceStates, sid: SpaceId, did: &str) {
        if !st.hosts.get(&sid).is_some_and(|h| h.members.contains_key(did)) {
            self.members.push((sid, did.to_string()));
        }
    }

    fn path(&mut self, st: &SpaceStates, sid: SpaceId, path: String) {
        if !st.repos.get(&sid).is_some_and(|h| h.known(&path).is_some()) && !self.paths.contains(&(sid, path.clone())) {
            self.paths.push((sid, path));
        }
    }

    /// A host op that may publish: the authority's repo and its writer state.
    fn publisher(&mut self, st: &SpaceStates, sid: SpaceId, uri: &Arc<str>, did: &str) {
        self.host(st, sid, uri);
        self.head(st, sid, uri);
        self.writer(st, sid, did);
    }

    /// Adds what `req` needs that `st` doesn't hold.
    pub fn add(&mut self, st: &SpaceStates, req: &SpaceReq) {
        let (sid, uri, did) = (req.sid, &req.uri, &*req.did);
        match &req.op {
            SpaceOp::Write { writes } => {
                self.head(st, sid, uri);
                for w in writes {
                    self.path(st, sid, w.path());
                }
                if authority(uri) == Some(did) {
                    self.host(st, sid, uri);
                    self.writer(st, sid, did);
                }
            }
            SpaceOp::RecordWriter { writer, .. } => {
                self.host(st, sid, uri);
                self.writer(st, sid, writer);
                self.member(st, sid, writer);
            }
            SpaceOp::CreateSpace { .. } => {
                self.publisher(st, sid, uri, did);
                self.path(st, sid, publish::policy_path());
            }
            // the whole member list (a migration wipes it, publishMembers
            // puts its records out or withdraws them), then each member's
            // record path
            SpaceOp::UpdateSpace { .. } => {
                self.publisher(st, sid, uri, did);
                self.path(st, sid, publish::policy_path());
                match st.hosts.get(&sid).filter(|h| h.members_complete) {
                    Some(h) => {
                        for m in h.members.iter().filter(|(_, row)| row.is_some()).map(|(m, _)| m) {
                            self.path(st, sid, publish::member_path(m));
                        }
                    }
                    None if !self.member_lists.contains(&sid) => self.member_lists.push(sid),
                    None => {}
                }
            }
            SpaceOp::PutMember { member, .. } | SpaceOp::RemoveMember { member } => {
                self.publisher(st, sid, uri, did);
                self.writer(st, sid, member);
                self.path(st, sid, publish::member_path(member));
            }
            SpaceOp::RemoveWriter { writer } => {
                self.host(st, sid, uri);
                self.writer(st, sid, writer);
            }
            SpaceOp::DeleteSpace { .. } => {
                self.host(st, sid, uri);
                self.head(st, sid, uri);
            }
            SpaceOp::ImportSpaceMeta { .. } => self.host(st, sid, uri),
            SpaceOp::ImportBegin { .. } | SpaceOp::Claim { .. } => self.head(st, sid, uri),
            SpaceOp::ImportCommit { .. } | SpaceOp::Clear { .. } => {
                self.head(st, sid, uri);
                if authority(uri) == Some(did) {
                    self.host(st, sid, uri);
                    self.writer(st, sid, did);
                }
            }
            SpaceOp::UnregisterNotify { service, expired_by: Some(_) } => {
                self.host(st, sid, uri);
                self.registration(st, sid, service);
            }
            SpaceOp::RegisterNotify { .. } | SpaceOp::UnregisterNotify { .. } => self.host(st, sid, uri),
        }
    }
}

fn authority(uri: &str) -> Option<&str> {
    uri.strip_prefix("at://")?.split('/').next()
}

#[derive(Default)]
pub struct Fetched {
    heads: Vec<(SpaceId, Arc<str>, Option<HeadRow>)>,
    /// Heads not found that have rows under them.
    unswept: Vec<SpaceId>,
    paths: Vec<(SpaceId, String, Option<PathRec>)>,
    hosts: Vec<(SpaceId, Arc<str>, Option<SpaceRow>, Option<Tid>)>,
    writers: Vec<(SpaceId, String, Option<WriterRow>)>,
    members: Vec<(SpaceId, String, Option<MemberRow>)>,
    /// A space's whole `sM` list and the published member records.
    member_lists: Vec<(SpaceId, Vec<(String, MemberRow)>, Vec<(String, PathRec)>)>,
    registrations: Vec<(SpaceId, String, Option<u64>)>,
}

/// Reads what `need` names. A head or space row naming another URI than
/// requested (a space id collision) is an error.
pub async fn fetch(db: &slatedb::Db, did: &str, need: SpaceNeed) -> anyhow::Result<Fetched> {
    let get = |k: Vec<u8>| db.get(k);
    let mut f = Fetched::default();
    for (sid, uri) in need.heads {
        let row = get(state::space_head_key(did, &sid)).await?.map(|v| HeadRow::decode(&v)).transpose()?;
        if let Some(r) = &row {
            anyhow::ensure!(*r.uri == *uri, "space id collision: {} and {uri}", r.uri);
        }
        // only a repo's first write (or import) gets here without a head
        if row.is_none() {
            for fam in [state::SPACE_RECORD_FAMILY, state::SPACE_BLOB_FAMILY, state::SPACE_OPLOG_FAMILY] {
                let prefix = state::space_prefix(fam, did, &sid);
                if db.scan(prefix.clone()..vlsync_store::keys::prefix_end(&prefix)).await?.next().await?.is_some() {
                    f.unswept.push(sid);
                    break;
                }
            }
        }
        f.heads.push((sid, uri, row));
    }
    let paths = futures::future::try_join_all(need.paths.into_iter().map(|(sid, path)| async move {
        let v = db.get(state::space_record_key(did, &sid, &path)).await?;
        let rec = v.map(|v| PathRec::from_value(&v)).transpose()?;
        anyhow::Ok((sid, path, rec))
    }))
    .await?;
    f.paths = paths;
    for (sid, uri) in need.hosts {
        let row = get(state::space_key(did, &sid)).await?.map(|v| SpaceRow::decode(&v)).transpose()?;
        if let Some(r) = &row {
            anyhow::ensure!(*r.uri == *uri, "space id collision: {} and {uri}", r.uri);
        }
        let prefix = state::space_prefix(state::SPACE_SEQ_FAMILY, did, &sid);
        let opts = slatedb::config::ScanOptions::default().with_order(slatedb::IterationOrder::Descending);
        let mut it = db.scan_with_options(prefix.clone()..vlsync_store::keys::prefix_end(&prefix), &opts).await?;
        let max = it.next().await?.and_then(|kv| super::rows::seq_rev(&kv.key));
        f.hosts.push((sid, uri, row, max));
    }
    for (sid, w) in need.writers {
        let row = get(state::space_writer_key(did, &sid, &w)).await?.map(|v| WriterRow::decode(&v)).transpose()?;
        f.writers.push((sid, w, row));
    }
    for (sid, m) in need.members {
        let row = get(state::space_member_key(did, &sid, &m)).await?.map(|v| MemberRow::decode(&v)).transpose()?;
        f.members.push((sid, m, row));
    }
    for sid in need.member_lists {
        let prefix = state::space_prefix(state::SPACE_MEMBER_FAMILY, did, &sid);
        let mut it = db.scan(prefix.clone()..vlsync_store::keys::prefix_end(&prefix)).await?;
        let mut members = Vec::new();
        while let Some(kv) = it.next().await? {
            members.push((std::str::from_utf8(&kv.key[prefix.len()..])?.to_string(), MemberRow::decode(&kv.value)?));
        }
        let rec = state::space_prefix(state::SPACE_RECORD_FAMILY, did, &sid);
        let prefix = [&rec[..], publish::MEMBER_COLLECTION.as_bytes(), b"/"].concat();
        let mut it = db.scan(prefix.clone()..vlsync_store::keys::prefix_end(&prefix)).await?;
        let mut records = Vec::new();
        while let Some(kv) = it.next().await? {
            records.push((std::str::from_utf8(&kv.key[rec.len()..])?.to_string(), PathRec::from_value(&kv.value)?));
        }
        f.member_lists.push((sid, members, records));
    }
    for (sid, service) in need.registrations {
        let row =
            get(state::space_notify_key(did, &sid, &service)).await?.map(|v| NotifyRow::decode(&v)).transpose()?;
        f.registrations.push((sid, service, row.map(|r| r.expires)));
    }
    Ok(f)
}

/// Installs fetched state; what is already held is newer and kept.
pub fn install(st: &mut SpaceStates, f: Fetched) {
    for (sid, uri, row) in f.heads {
        st.repos.entry(sid).or_insert_with(|| SpaceHead::new(uri, row));
    }
    for sid in f.unswept {
        if let Some(h) = st.repos.get_mut(&sid).filter(|h| h.rev.is_none()) {
            h.unswept = true;
        }
    }
    for (sid, path, rec) in f.paths {
        if let Some(h) = st.repos.get_mut(&sid) {
            h.fetched.insert(path, rec);
        }
    }
    for (sid, uri, space, max) in f.hosts {
        st.hosts.entry(sid).or_insert_with(|| HostHead {
            uri,
            space,
            max_space_rev: max,
            writers: HashMap::new(),
            members: HashMap::new(),
            members_complete: false,
            registrations: HashMap::new(),
        });
    }
    for (sid, w, row) in f.writers {
        if let Some(h) = st.hosts.get_mut(&sid) {
            h.writers.entry(w).or_insert(row);
        }
    }
    for (sid, m, row) in f.members {
        if let Some(h) = st.hosts.get_mut(&sid) {
            h.members.entry(m).or_insert(row);
        }
    }
    for (sid, members, records) in f.member_lists {
        if let Some(h) = st.hosts.get_mut(&sid) {
            for (m, row) in members {
                h.members.entry(m).or_insert(Some(row));
            }
            h.members_complete = true;
        }
        // a member with no record here holds none (the overlay has any
        // written since)
        if let Some(h) = st.repos.get_mut(&sid) {
            let listed = st.hosts.get(&sid).map(|h| h.members.keys().cloned().collect::<Vec<_>>()).unwrap_or_default();
            for m in listed {
                h.fetched.entry(publish::member_path(&m)).or_insert(None);
            }
            for (path, rec) in records {
                h.fetched.insert(path, Some(rec));
            }
        }
    }
    for (sid, service, expires) in f.registrations {
        if let Some(h) = st.hosts.get_mut(&sid) {
            h.registrations.entry(service).or_insert(expires);
        }
    }
}

fn put(key: Vec<u8>, val: Bytes) -> Mutation {
    Mutation { key: key.into(), val: Some(val) }
}

fn del(key: Vec<u8>) -> Mutation {
    Mutation { key: key.into(), val: None }
}

/// A write's entry: its mutations, the head readers get once it is acked,
/// and the outbox row to send then (None when the author is the authority).
pub struct BuiltWrite {
    pub muts: Vec<Mutation>,
    pub rev: Tid,
    pub head: DurableSpaceHead,
    pub notify: Option<OutboxRow>,
    /// The author is the authority: its writer state moved in this entry.
    pub sequenced: Option<Sequenced>,
    pub results: Vec<SpaceOutcome>,
}

/// Validates `writes` against the repo as the worker holds it and builds
/// their entry, updating the held state as if it were sent (`applied` is
/// set once it applies). Ok(Err(results)): nothing to write.
#[allow(clippy::too_many_arguments)]
pub fn write(
    st: &mut SpaceStates,
    did: &str,
    sid: SpaceId,
    uri: &Arc<str>,
    writes: Vec<SpaceWrite>,
    clock_id: u64,
    applied: &Arc<AtomicBool>,
    delivered: Vec<(SpaceId, Tid)>,
    max_records: u64,
) -> Result<Result<BuiltWrite, Vec<SpaceOutcome>>, SpaceError> {
    if writes.len() > MAX_WRITES {
        return Err(SpaceError::Write(WriteError::Invalid(format!("Too many writes. Max: {MAX_WRITES}"))));
    }
    build_write(st, did, sid, uri, writes, clock_id, applied, delivered, max_records)
}

#[allow(clippy::too_many_arguments)]
fn build_write(
    st: &mut SpaceStates,
    did: &str,
    sid: SpaceId,
    uri: &Arc<str>,
    writes: Vec<SpaceWrite>,
    clock_id: u64,
    applied: &Arc<AtomicBool>,
    delivered: Vec<(SpaceId, Tid)>,
    max_records: u64,
) -> Result<Result<BuiltWrite, Vec<SpaceOutcome>>, SpaceError> {
    // the authority's own repo lives only as long as its space (reference
    // `ensureRepo`); another account's repo needs no space here
    let own = authority(uri) == Some(did);
    if own && !st.hosts.get(&sid).and_then(|h| h.space.as_ref()).is_some_and(|s| s.live()) {
        return Err(SpaceError::SpaceNotFound);
    }
    let head = st.repos.get_mut(&sid).ok_or_else(|| internal("space head not loaded"))?;
    if *head.uri != **uri {
        return Err(internal(format!("space id collision: {} and {uri}", head.uri)));
    }
    if head.rev.is_none() && head.unswept {
        return Err(SpaceError::Unswept(writes));
    }
    let mut batch: HashMap<String, Option<PathRec>> = HashMap::new();
    // the blobs each path named before the batch
    let mut before: HashMap<String, Vec<Cid>> = HashMap::new();
    let mut ops: Vec<(OpRow, Option<Bytes>)> = Vec::with_capacity(writes.len());
    let mut results = Vec::with_capacity(writes.len());
    for w in writes {
        let path = w.path();
        let prev = match batch.get(&path) {
            Some(c) => c.clone(),
            None => {
                let p = head.known(&path).ok_or_else(|| internal(format!("space record {path} not loaded")))?.clone();
                before.entry(path.clone()).or_insert_with(|| p.as_ref().map(|r| r.blobs.clone()).unwrap_or_default());
                p
            }
        };
        let (action, new, bytes) = match w {
            SpaceWrite::Create { cid, bytes, blobs, .. } => {
                if prev.is_some() {
                    return Err(SpaceError::RecordAlreadyExists(format!("Record already exists: {path}")));
                }
                (OpAction::Create, Some(PathRec { cid, blobs }), Some(bytes))
            }
            SpaceWrite::Update { cid, bytes, blobs, must_exist, put, .. } => {
                if prev.is_none() && must_exist {
                    return Err(SpaceError::RecordNotFound(format!("Record not found: {path}")));
                }
                let missing = put.and_then(|p| if prev.is_some() { p.update } else { p.create });
                if let Some(scope) = missing {
                    return Err(SpaceError::ScopeMissing(scope));
                }
                let action = if prev.is_some() { OpAction::Update } else { OpAction::Create };
                (action, Some(PathRec { cid, blobs }), Some(bytes))
            }
            SpaceWrite::Delete { must_exist, .. } => {
                if prev.is_none() {
                    if must_exist {
                        return Err(SpaceError::RecordNotFound(format!("Record not found: {path}")));
                    }
                    results.push(SpaceOutcome::Noop);
                    continue;
                }
                (OpAction::Delete, None, None)
            }
        };
        let (cid, prev) = (new.as_ref().map(|r| r.cid), prev.map(|r| r.cid));
        results.push(match (action, cid) {
            (OpAction::Create, Some(cid)) => SpaceOutcome::Create { path: path.clone(), cid },
            (OpAction::Update, Some(cid)) => SpaceOutcome::Update { path: path.clone(), cid },
            _ => SpaceOutcome::Delete,
        });
        batch.insert(path.clone(), new);
        let (collection, rkey) = path.split_once('/').map(|(c, r)| (c.to_string(), r.to_string())).unwrap_or_default();
        ops.push((OpRow { action, collection, rkey, cid, prev }, bytes));
    }
    if ops.is_empty() {
        return Ok(Err(results));
    }
    let added = ops.iter().map(|(o, _)| o.cid.is_some() as i64 - o.prev.is_some() as i64).sum::<i64>();
    // a write that doesn't grow the repo is let through over the cap (a
    // lowered flag), so it can be trimmed
    if added > 0 && head.records.saturating_add(added as u64) > max_records {
        return Err(SpaceError::Write(WriteError::Invalid(format!(
            "Space repo record limit reached: at most {max_records} records"
        ))));
    }
    let rev = tid::next_rev(head.rev, clock_id);
    let mut muts = Vec::with_capacity(2 * ops.len() + 6);
    for (idx, (op, bytes)) in ops.iter().enumerate() {
        let path = format!("{}/{}", op.collection, op.rkey);
        if let Some(p) = op.prev {
            head.hash.remove(&super::commit::element(&op.collection, &op.rkey, &p.to_string()));
            head.records = head.records.saturating_sub(1);
        }
        match (op.cid, bytes) {
            (Some(c), Some(b)) => {
                head.hash.add(&super::commit::element(&op.collection, &op.rkey, &c.to_string()));
                head.records += 1;
                muts.push(put(state::space_record_key(did, &sid, &path), state::record_value(&c, rev.0, b)));
            }
            _ => muts.push(del(state::space_record_key(did, &sid, &path))),
        }
        muts.push(put(state::space_oplog_key(did, &sid, rev.0, idx as u16), op.encode()));
    }
    blob_ref_mutations(did, sid, rev, &batch, &before, &mut muts);
    if head.rev.is_none() {
        head.created = tid::now_micros();
        muts.push(put(state::space_list_key(did, uri, SpaceListed::Repo), Bytes::new()));
    }
    head.rev = Some(rev);
    for (path, rec) in batch {
        head.overlay.insert(path, (rec, applied.clone()));
    }
    let row =
        HeadRow { uri: uri.to_string(), rev, hash: head.hash.clone(), records: head.records, created: head.created };
    muts.push(put(state::space_head_key(did, &sid), row.encode()));
    let digest = head.hash.digest();
    let durable = DurableSpaceHead {
        uri: uri.clone(),
        rev,
        hash: head.hash.clone(),
        records: head.records,
        created: head.created,
        shard: vlsync_store::slots::ShardId(0),
        epoch: 0,
    };
    // A delivered rev's row goes only while its space's head is held and
    // still at that rev: this worker orders every `sP` write of the account,
    // and an unheld head may have a newer write whose ack (and outbox
    // enqueue) hasn't run yet. A row left behind costs one resend, which
    // the authority ignores as not newer.
    for (s, d) in delivered {
        if s != sid && st.repos.get(&s).is_some_and(|h| h.rev == Some(d)) {
            muts.push(del(state::space_outbox_key(did, &s)));
        }
    }
    let (notify, sequenced) = if own {
        (None, record_self(st, did, sid, rev, digest, clock_id, &mut muts)?)
    } else {
        let o = OutboxRow { uri: uri.to_string(), repo_rev: rev, hash: digest };
        muts.push(put(state::space_outbox_key(did, &sid), o.encode()));
        (Some(o), None)
    };
    Ok(Ok(BuiltWrite { muts, rev, head: durable, notify, sequenced, results }))
}

/// The `sb`/`sc` rows of a batch's net change per path: refs the record no
/// longer names go, and every ref it names is (re)written with the batch's
/// rev, so listBlobs `since` sees a blob kept across an update, as `b/`.
fn blob_ref_mutations(
    did: &str,
    sid: SpaceId,
    rev: Tid,
    batch: &HashMap<String, Option<PathRec>>,
    before: &HashMap<String, Vec<Cid>>,
    muts: &mut Vec<Mutation>,
) {
    for (path, rec) in batch {
        let new = rec.as_ref().map_or(&[][..], |r| &r.blobs[..]);
        for b in before.get(path).into_iter().flatten().filter(|b| !new.contains(b)) {
            muts.push(del(state::space_blob_key(did, &sid, b, path)));
            muts.push(del(state::space_blob_cid_key(did, b, &sid, path)));
        }
        for b in new {
            muts.push(put(state::space_blob_key(did, &sid, b, path), Bytes::copy_from_slice(&rev.0.to_be_bytes())));
            muts.push(put(state::space_blob_cid_key(did, b, &sid, path), Bytes::new()));
        }
    }
}

/// The author is the authority: the space host's writer state moves in the
/// write's own entry, as notifyWrite would move it. A space never created
/// (or deleted) records nothing, as the reference's notify of it fails.
fn record_self(
    st: &mut SpaceStates,
    did: &str,
    sid: SpaceId,
    rev: Tid,
    hash: [u8; 32],
    clock_id: u64,
    muts: &mut Vec<Mutation>,
) -> Result<Option<Sequenced>, SpaceError> {
    let host = st.hosts.get_mut(&sid).ok_or_else(|| internal("space host state not loaded"))?;
    if host.live().is_none() {
        return Ok(None);
    }
    sequence(host, did, sid, did, rev, hash, clock_id, muts)
}

#[allow(clippy::too_many_arguments)]
fn sequence(
    host: &mut HostHead,
    authority: &str,
    sid: SpaceId,
    writer: &str,
    repo_rev: Tid,
    hash: [u8; 32],
    clock_id: u64,
    muts: &mut Vec<Mutation>,
) -> Result<Option<Sequenced>, SpaceError> {
    let old = *host.writers.get(writer).ok_or_else(|| internal("space writer state not loaded"))?;
    // the same rev with another hash is sequenced again: a record takedown
    // or its reversal changes the hash a repo serves without a new rev
    if old.is_some_and(|o| o.repo_rev > repo_rev || (o.repo_rev == repo_rev && o.hash == hash)) {
        return Ok(None);
    }
    let prev = host.max_space_rev;
    let space_rev = tid::next_rev(prev, clock_id);
    if let Some(o) = old {
        muts.push(del(state::space_seq_key(authority, &sid, o.space_rev.0)));
    }
    let seq = SeqRow { prev, writer: writer.to_string() };
    muts.push(put(state::space_seq_key(authority, &sid, space_rev.0), seq.encode()));
    let row = WriterRow { repo_rev, hash, space_rev };
    muts.push(put(state::space_writer_key(authority, &sid, writer), row.encode()));
    host.writers.insert(writer.to_string(), Some(row));
    host.max_space_rev = Some(space_rev);
    Ok(Some(Sequenced { space_rev, prev }))
}

/// notifyWrite at the authority. Ok(None): not newer (nothing to write).
#[allow(clippy::too_many_arguments)]
pub fn record_writer(
    st: &mut SpaceStates,
    authority: &str,
    sid: SpaceId,
    uri: &str,
    writer: &str,
    repo_rev: Tid,
    hash: [u8; 32],
    managing_app: Option<bool>,
    same_rev: SameRev,
    clock_id: u64,
) -> Result<Option<(Vec<Mutation>, Sequenced)>, SpaceError> {
    let host = st.hosts.get_mut(&sid).ok_or_else(|| internal("space host state not loaded"))?;
    let space = host.live().filter(|s| s.uri == uri).ok_or(SpaceError::SpaceNotFound)?;
    let allowed = writer == authority
        || match &space.policy {
            Policy::Personal => false,
            Policy::Member { public_write: true, .. } => true,
            Policy::Member { .. } => match host.members.get(writer) {
                Some(m) => m.is_some_and(|m| m.write),
                None => return Err(internal("space member not loaded")),
            },
            Policy::Managed { .. } => managing_app == Some(true),
        };
    if !allowed {
        return Err(SpaceError::NotAuthorized("notifyWrite writer is not authorized".into()));
    }
    if same_rev == SameRev::Verify
        && host.writers.get(writer).copied().flatten().is_some_and(|o| o.repo_rev == repo_rev && o.hash != hash)
    {
        return Err(SpaceError::SameRev);
    }
    let mut muts = Vec::with_capacity(3);
    Ok(sequence(host, authority, sid, writer, repo_rev, hash, clock_id, &mut muts)?.map(|s| (muts, s)))
}

fn importable(head: &SpaceHead, uri: &str, replace: bool) -> Result<(), SpaceError> {
    if *head.uri != *uri {
        return Err(internal(format!("space id collision: {} and {uri}", head.uri)));
    }
    match (head.rev, replace) {
        (Some(_), false) => Err(SpaceError::Write(WriteError::Invalid("this account has a repo in the space".into()))),
        _ => Ok(()),
    }
}

/// importRepo's claim. Some(the head's delete) when a repo is there: it's
/// replaced, its rows swept under the claim before the new ones stage.
pub fn import_begin(
    st: &mut SpaceStates,
    did: &str,
    sid: SpaceId,
    uri: &str,
    replace: bool,
) -> Result<Option<Vec<Mutation>>, SpaceError> {
    let head = st.repos.get_mut(&sid).ok_or_else(|| internal("space head not loaded"))?;
    importable(head, uri, replace)?;
    if head.rev.is_none() {
        // what's staged lands under it: the next op reads it again (and
        // looks for leftovers), whether the import commits or stops. With no
        // rev, nothing of the repo is in flight.
        st.repos.remove(&sid);
        return Ok(None);
    }
    // its rows are still there, and the head's delete is in flight: the
    // import sweeps them, and a write after a failed import clears what's
    // left before it lands
    let mut empty = SpaceHead::new(head.uri.clone(), None);
    empty.unswept = true;
    *head = empty;
    Ok(Some(vec![del(state::space_head_key(did, &sid)), del(state::space_list_key(did, uri, SpaceListed::Repo))]))
}

/// importRepo's head: the `sH` row at a new rev after `prev`, and the
/// notify the authority is owed (or, the account being the authority, its
/// writer state), as a write's entry has.
#[allow(clippy::too_many_arguments)]
pub fn import_commit(
    st: &mut SpaceStates,
    did: &str,
    sid: SpaceId,
    uri: &Arc<str>,
    prev: Option<Tid>,
    hash: LtHash,
    records: u64,
    clock_id: u64,
) -> Result<BuiltWrite, SpaceError> {
    importable(st.repos.get(&sid).ok_or_else(|| internal("space head not loaded"))?, uri, true)?;
    new_head(st, did, sid, uri, tid::next_rev(prev, clock_id), hash, records, 0, Vec::new(), clock_id)
}

/// clearRecords' entry: the head over what's kept at a new rev after
/// `prev`, which must still be the head's (the claim held writes off), and
/// the deletes. An emptied repo's oplog begins at empty again; one that
/// keeps published records doesn't.
#[allow(clippy::too_many_arguments)]
pub fn clear_commit(
    st: &mut SpaceStates,
    did: &str,
    sid: SpaceId,
    uri: &Arc<str>,
    prev: Tid,
    deletes: Vec<Mutation>,
    hash: LtHash,
    records: u64,
    clock_id: u64,
) -> Result<BuiltWrite, SpaceError> {
    let head = st.repos.get(&sid).ok_or_else(|| internal("space head not loaded"))?;
    if *head.uri != **uri {
        return Err(internal(format!("space id collision: {} and {uri}", head.uri)));
    }
    if head.rev != Some(prev) {
        return Err(SpaceError::Write(WriteError::Unavailable("the space repo changed under its clear; retry".into())));
    }
    let created = if records == 0 { tid::now_micros() } else { 0 };
    new_head(st, did, sid, uri, tid::next_rev(Some(prev), clock_id), hash, records, created, deletes, clock_id)
}

#[allow(clippy::too_many_arguments)]
fn new_head(
    st: &mut SpaceStates,
    did: &str,
    sid: SpaceId,
    uri: &Arc<str>,
    rev: Tid,
    hash: LtHash,
    records: u64,
    created: u64,
    mut muts: Vec<Mutation>,
    clock_id: u64,
) -> Result<BuiltWrite, SpaceError> {
    let mut head = SpaceHead::new(uri.clone(), None);
    (head.rev, head.hash, head.records, head.created) = (Some(rev), hash.clone(), records, created);
    st.repos.insert(sid, head);
    let row = HeadRow { uri: uri.to_string(), rev, hash: hash.clone(), records, created };
    muts.push(put(state::space_head_key(did, &sid), row.encode()));
    muts.push(put(state::space_list_key(did, uri, SpaceListed::Repo), Bytes::new()));
    let digest = hash.digest();
    let (notify, sequenced) = if authority(uri) == Some(did) {
        (None, record_self(st, did, sid, rev, digest, clock_id, &mut muts)?)
    } else {
        let o = OutboxRow { uri: uri.to_string(), repo_rev: rev, hash: digest };
        muts.push(put(state::space_outbox_key(did, &sid), o.encode()));
        (Some(o), None)
    };
    let head = DurableSpaceHead {
        uri: uri.clone(),
        rev,
        hash,
        records,
        created,
        shard: vlsync_store::slots::ShardId(0),
        epoch: 0,
    };
    Ok(BuiltWrite { muts, rev, head, notify, sequenced, results: Vec::new() })
}

/// A host op's entry: its config mutations, then the write that brings
/// the authority's published records in line (None: they already are).
pub struct HostBuilt {
    pub muts: Vec<Mutation>,
    pub published: Option<BuiltWrite>,
}

impl HostBuilt {
    fn config(muts: Vec<Mutation>) -> HostBuilt {
        HostBuilt { muts, published: None }
    }
}

/// What `path` in the authority's repo should hold: `want` (None: no
/// record). An unchanged record is left alone.
fn publish_write(head: &SpaceHead, path: &str, want: Option<(Cid, Bytes)>) -> Result<Option<SpaceWrite>, SpaceError> {
    let held = head.known(path).ok_or_else(|| internal(format!("published record {path} not loaded")))?;
    let (collection, rkey) = path.split_once('/').expect("published paths have a collection");
    let (collection, rkey) = (collection.to_string(), rkey.to_string());
    Ok(match (want, held) {
        (Some((cid, _)), Some(r)) if r.cid == cid => None,
        (Some((cid, bytes)), _) => {
            Some(SpaceWrite::Update { collection, rkey, cid, bytes, blobs: Vec::new(), must_exist: false, put: None })
        }
        (None, Some(_)) => Some(SpaceWrite::Delete { collection, rkey, must_exist: true }),
        (None, None) => None,
    })
}

/// Appends the published writes to `built`, as the authority's write: one
/// entry for the config and the records that mirror it.
#[allow(clippy::too_many_arguments)]
fn with_published(
    st: &mut SpaceStates,
    authority: &str,
    sid: SpaceId,
    uri: &Arc<str>,
    mut built: HostBuilt,
    writes: Vec<SpaceWrite>,
    clock_id: u64,
    applied: &Arc<AtomicBool>,
    max_records: u64,
) -> Result<HostBuilt, SpaceError> {
    if writes.is_empty() {
        return Ok(built);
    }
    if let Ok(b) = build_write(st, authority, sid, uri, writes, clock_id, applied, Vec::new(), max_records)? {
        built.published = Some(b);
    }
    Ok(built)
}

/// The authority's repo in the space, which a published record goes into.
fn own_head<'a>(st: &'a SpaceStates, sid: SpaceId, uri: &str) -> Result<&'a SpaceHead, SpaceError> {
    let head = st.repos.get(&sid).ok_or_else(|| internal("space head not loaded"))?;
    if *head.uri != *uri {
        return Err(internal(format!("space id collision: {} and {uri}", head.uri)));
    }
    if head.rev.is_none() && head.unswept {
        return Err(SpaceError::Unswept(Vec::new()));
    }
    Ok(head)
}

/// space.createSpace: refused while a live space has the URI. Over a
/// tombstone it starts fresh (the caller swept the old rows first). Writes
/// the authority made before creating it are sequenced now, as the
/// reference's retried notify of them would be once the space exists. A
/// policy that publishes itself goes out in the same entry.
#[allow(clippy::too_many_arguments)]
pub fn create_space(
    st: &mut SpaceStates,
    authority: &str,
    sid: SpaceId,
    uri: &Arc<str>,
    row: SpaceRow,
    clock_id: u64,
    applied: &Arc<AtomicBool>,
    max_records: u64,
) -> Result<HostBuilt, SpaceError> {
    let head = own_head(st, sid, uri)?;
    let own = head.rev.map(|rev| (rev, head.hash.digest()));
    let publish = match row.policy.publishes_policy() {
        true => publish_write(head, &publish::policy_path(), Some(publish::policy_record(&row.policy)))?,
        false => None,
    };
    let host = st.hosts.get_mut(&sid).ok_or_else(|| internal("space host state not loaded"))?;
    if host.live().is_some() {
        return Err(SpaceError::SpaceAlreadyExists);
    }
    if host.space.is_some() {
        host.members.clear();
        host.members_complete = true;
        host.writers.clear();
        host.writers.insert(authority.to_string(), None);
        host.max_space_rev = None;
    }
    let mut muts = vec![
        put(state::space_key(authority, &sid), row.encode()),
        put(state::space_list_key(authority, &row.uri, SpaceListed::Governs), Bytes::new()),
    ];
    host.space = Some(row);
    // a publishing write sequences the repo itself
    if let (Some((rev, hash)), None) = (own, &publish) {
        sequence(host, authority, sid, authority, rev, hash, clock_id, &mut muts)?;
    }
    let writes = publish.into_iter().collect();
    with_published(st, authority, sid, uri, HostBuilt::config(muts), writes, clock_id, applied, max_records)
}

fn live_host(st: &mut SpaceStates, sid: SpaceId) -> Result<&mut HostHead, SpaceError> {
    let host = st.hosts.get_mut(&sid).ok_or_else(|| internal("space host state not loaded"))?;
    match host.live() {
        Some(_) => Ok(host),
        None => Err(SpaceError::SpaceNotFound),
    }
}

/// Reference `updateSpace`: the policy replaced wholesale. Another `$type`
/// migrates the space, and the old policy's state goes with it (a
/// memberspace's list: migrating back doesn't restore it). The published
/// policy, and the member records when what's published of the list
/// changes, follow in the same entry. The writer set stays as it is.
#[allow(clippy::too_many_arguments)]
pub fn update_space(
    st: &mut SpaceStates,
    authority: &str,
    sid: SpaceId,
    uri: &Arc<str>,
    next: Policy,
    clock_id: u64,
    applied: &Arc<AtomicBool>,
    max_records: u64,
) -> Result<HostBuilt, SpaceError> {
    let host = live_host(st, sid)?;
    if !host.members_complete {
        return Err(internal("space member list not loaded"));
    }
    let current = host.space.clone().expect("live");
    let members: Vec<(String, MemberRow)> =
        host.members.iter().filter_map(|(d, m)| m.map(|m| (d.clone(), m))).collect();
    let head = own_head(st, sid, uri)?;
    let policy = next.publishes_policy().then(|| publish::policy_record(&next));
    let mut writes: Vec<SpaceWrite> = publish_write(head, &publish::policy_path(), policy)?.into_iter().collect();
    if current.policy.publishes_members() != next.publishes_members() {
        let mut sorted = members.clone();
        sorted.sort_by(|a, b| a.0.cmp(&b.0));
        for (did, access) in sorted {
            let want = next.publishes_members().then(|| publish::member_record(access));
            writes.extend(publish_write(head, &publish::member_path(&did), want)?);
        }
    }
    let host = st.hosts.get_mut(&sid).expect("live");
    let mut muts = Vec::with_capacity(1 + members.len());
    if current.policy.type_name() != next.type_name() {
        for (did, _) in &members {
            muts.push(del(state::space_member_key(authority, &sid, did)));
        }
        host.members.clear();
    }
    let row = SpaceRow { policy: next, ..current };
    muts.push(put(state::space_key(authority, &sid), row.encode()));
    host.space = Some(row);
    with_published(st, authority, sid, uri, HostBuilt::config(muts), writes, clock_id, applied, max_records)
}

/// A writer's `sW` row and its `sQ` entry go. The chain stays whole: a
/// later forward may name a gone spaceRev as its prev, as one does when a
/// writer writes again.
fn drop_writer(
    host: &mut HostHead,
    authority: &str,
    sid: SpaceId,
    writer: &str,
    muts: &mut Vec<Mutation>,
) -> Result<(), SpaceError> {
    match host.writers.get(writer) {
        None => return Err(internal("space writer state not loaded")),
        Some(None) => {}
        Some(Some(w)) => {
            muts.push(del(state::space_seq_key(authority, &sid, w.space_rev.0)));
            muts.push(del(state::space_writer_key(authority, &sid, writer)));
            host.writers.insert(writer.to_string(), None);
        }
    }
    Ok(())
}

/// memberspace.putMember (`access` Some: both flags replaced) and
/// removeMember (None). Revoking write (removal does) also takes the
/// member out of the writer set; a published list follows.
#[allow(clippy::too_many_arguments)]
pub fn set_member(
    st: &mut SpaceStates,
    authority: &str,
    sid: SpaceId,
    uri: &Arc<str>,
    member: &str,
    access: Option<MemberRow>,
    clock_id: u64,
    applied: &Arc<AtomicBool>,
    max_records: u64,
) -> Result<HostBuilt, SpaceError> {
    let host = live_host(st, sid)?;
    let policy = host.space.as_ref().expect("live").policy.clone();
    if !policy.is_memberspace() {
        return Err(SpaceError::PolicyMismatch);
    }
    let key = state::space_member_key(authority, &sid, member);
    let mut muts = vec![match access {
        Some(a) => put(key, a.encode()),
        None => del(key),
    }];
    if !access.is_some_and(|a| a.write) {
        drop_writer(host, authority, sid, member, &mut muts)?;
    }
    host.members.insert(member.to_string(), access);
    let writes = match policy.publishes_members() {
        true => {
            let want = access.map(publish::member_record);
            publish_write(own_head(st, sid, uri)?, &publish::member_path(member), want)?.into_iter().collect()
        }
        false => Vec::new(),
    };
    with_published(st, authority, sid, uri, HostBuilt::config(muts), writes, clock_id, applied, max_records)
}

/// space.removeWriter. Idempotent: Ok(empty) if it isn't one.
/// importSpaceMeta's row, live, and the host state reset to what the
/// import wrote: members and writers are read again as they're needed.
pub fn import_space_meta(
    st: &mut SpaceStates,
    authority: &str,
    sid: SpaceId,
    row: SpaceRow,
    max_space_rev: Option<Tid>,
) -> Result<Vec<Mutation>, SpaceError> {
    let host = st.hosts.get_mut(&sid).ok_or_else(|| internal("space host state not loaded"))?;
    host.members.clear();
    host.members_complete = false;
    host.writers.clear();
    host.max_space_rev = max_space_rev;
    let muts = vec![
        put(state::space_key(authority, &sid), row.encode()),
        put(state::space_list_key(authority, &row.uri, SpaceListed::Governs), Bytes::new()),
    ];
    host.space = Some(row);
    Ok(muts)
}

pub fn remove_writer(
    st: &mut SpaceStates,
    authority: &str,
    sid: SpaceId,
    writer: &str,
) -> Result<Vec<Mutation>, SpaceError> {
    let host = live_host(st, sid)?;
    let mut muts = Vec::new();
    drop_writer(host, authority, sid, writer, &mut muts)?;
    Ok(muts)
}

/// registerNotify (`row` Some) and unregisterNotify. With `expired_by`,
/// a registration that is gone or expires after it is left alone (no
/// mutation).
pub fn set_registration(
    st: &mut SpaceStates,
    authority: &str,
    sid: SpaceId,
    service: &str,
    row: Option<NotifyRow>,
    expired_by: Option<u64>,
) -> Result<Option<Mutation>, SpaceError> {
    let host = live_host(st, sid)?;
    if let Some(t) = expired_by {
        match host.registrations.get(service) {
            Some(Some(expires)) if *expires <= t => {}
            Some(_) => return Ok(None),
            None => return Err(internal("space registration not loaded")),
        }
    }
    host.registrations.insert(service.to_string(), row.as_ref().map(|r| r.expires));
    let key = state::space_notify_key(authority, &sid, service);
    Ok(Some(match row {
        Some(r) => put(key, r.encode()),
        None => del(key),
    }))
}

/// space.deleteSpace: Ok(None) if it already was a tombstone. A
/// space the authority only wrote to (never created) is deleted too, as
/// the reference's `ensureSpace` row is.
pub fn delete_space(
    st: &mut SpaceStates,
    authority: &str,
    sid: SpaceId,
    uri: &str,
    deleted_at: String,
) -> Result<Option<Vec<Mutation>>, SpaceError> {
    let wrote = st.repos.get(&sid).is_some_and(|h| h.rev.is_some());
    let host = st.hosts.get_mut(&sid).ok_or_else(|| internal("space host state not loaded"))?;
    let mut row = match &host.space {
        Some(s) if !s.live() => return Ok(None),
        Some(s) => s.clone(),
        None if wrote => SpaceRow::defaults(uri, &deleted_at),
        None => return Err(SpaceError::SpaceNotFound),
    };
    row.deleted_at = Some(deleted_at);
    let muts = vec![
        put(state::space_key(authority, &sid), row.encode()),
        del(state::space_head_key(authority, &sid)),
        del(state::space_list_key(authority, uri, SpaceListed::Governs)),
        del(state::space_list_key(authority, uri, SpaceListed::Repo)),
    ];
    host.space = Some(row);
    host.members.clear();
    host.members_complete = true;
    host.writers.clear();
    host.max_space_rev = None;
    st.repos.remove(&sid);
    Ok(Some(muts))
}

#[cfg(test)]
mod tests {
    use super::*;

    const URI: &str = "at://did:plc:auth/space/com.example.group/x";

    /// createSpace, the authority's repo there unwritten unless held.
    fn cs(st: &mut SpaceStates, auth: &str, sid: SpaceId, row: SpaceRow) -> Result<HostBuilt, SpaceError> {
        let uri: Arc<str> = row.uri.as_str().into();
        st.repos.entry(sid).or_insert_with(|| SpaceHead::new(uri.clone(), None));
        create_space(st, auth, sid, &uri, row, 1, &Arc::new(AtomicBool::new(false)), u64::MAX)
    }

    fn states_with(paths: &[(&str, Option<Cid>)]) -> (SpaceStates, SpaceId, Arc<str>) {
        let uri: Arc<str> = URI.into();
        let sid = state::space_id(URI);
        let mut st = SpaceStates::default();
        let mut f = Fetched::default();
        f.heads.push((sid, uri.clone(), None));
        for (p, c) in paths {
            f.paths.push((sid, p.to_string(), c.map(|cid| PathRec { cid, blobs: Vec::new() })));
        }
        install(&mut st, f);
        (st, sid, uri)
    }

    fn create(rkey: &str, n: u8) -> SpaceWrite {
        let bytes = Bytes::from(vec![0xa1, 0x61, 0x61, n]);
        SpaceWrite::Create {
            collection: "com.example.post".into(),
            rkey: rkey.into(),
            cid: Cid::dag_cbor(&bytes),
            bytes,
            blobs: Vec::new(),
        }
    }

    fn update(rkey: &str, n: u8, must_exist: bool) -> SpaceWrite {
        let bytes = Bytes::from(vec![0xa1, 0x61, 0x61, n]);
        SpaceWrite::Update {
            collection: "com.example.post".into(),
            rkey: rkey.into(),
            cid: Cid::dag_cbor(&bytes),
            bytes,
            blobs: Vec::new(),
            must_exist,
            put: None,
        }
    }

    fn go(st: &mut SpaceStates, sid: SpaceId, uri: &Arc<str>, w: Vec<SpaceWrite>) -> Result<BuiltWrite, SpaceError> {
        let applied = Arc::new(AtomicBool::new(false));
        write(st, "did:plc:writer", sid, uri, w, 1, &applied, Vec::new(), u64::MAX)
            .map(|r| r.expect("something written"))
    }

    #[test]
    fn batch_validation() {
        let (mut st, sid, uri) = states_with(&[("com.example.post/a", None), ("com.example.post/b", None)]);
        // a create then an update of it in one batch: one rev, two ops
        let b = go(&mut st, sid, &uri, vec![create("a", 1), update("a", 2, true)]).unwrap();
        assert_eq!(b.head.records, 1);
        assert!(b.notify.is_some(), "another authority is notified");
        // a duplicate create in one batch, and an update of a missing record
        let e = go(&mut st, sid, &uri, vec![create("b", 1), create("b", 2)]).err().unwrap();
        assert!(matches!(e, SpaceError::RecordAlreadyExists(_)), "{e:?}");
        let e = go(&mut st, sid, &uri, vec![update("b", 1, true)]).err().unwrap();
        assert!(matches!(e, SpaceError::RecordNotFound(_)), "{e:?}");
        // a refused batch changed nothing
        assert_eq!(st.repos[&sid].records, 1);
        assert_eq!(st.repos[&sid].rev, Some(b.rev));
        // a path never read is an error, not a guess
        let e = go(&mut st, sid, &uri, vec![create("c", 1)]).err().unwrap();
        assert!(matches!(e, SpaceError::Write(WriteError::Internal(_))), "{e:?}");
        // deleteRecord of a missing record writes nothing
        let applied = Arc::new(AtomicBool::new(false));
        let w = vec![SpaceWrite::Delete { collection: "com.example.post".into(), rkey: "b".into(), must_exist: false }];
        assert!(write(&mut st, "did:plc:writer", sid, &uri, w, 1, &applied, Vec::new(), u64::MAX).unwrap().is_err());
        // the head's hash is the set's
        let mut want = LtHash::default();
        let c = Cid::dag_cbor(&[0xa1, 0x61, 0x61, 2]);
        want.add(&super::super::commit::element("com.example.post", "a", &c.to_string()));
        assert_eq!(st.repos[&sid].hash, want);
    }

    #[test]
    fn record_cap() {
        let paths: Vec<(String, Option<Cid>)> =
            ["a", "b", "c"].iter().map(|r| (format!("com.example.post/{r}"), None)).collect();
        let refs: Vec<(&str, Option<Cid>)> = paths.iter().map(|(p, c)| (p.as_str(), *c)).collect();
        let (mut st, sid, uri) = states_with(&refs);
        let applied = Arc::new(AtomicBool::new(false));
        let w = |st: &mut SpaceStates, ws: Vec<SpaceWrite>, cap: u64| {
            write(st, "did:plc:writer", sid, &uri, ws, 1, &applied, Vec::new(), cap).map(|r| r.is_ok())
        };
        assert!(w(&mut st, vec![create("a", 1), create("b", 1)], 2).unwrap());
        let e = w(&mut st, vec![create("c", 1)], 2).err().unwrap();
        assert!(matches!(e, SpaceError::Write(WriteError::Invalid(_))), "{e:?}");
        // a batch that nets out at the cap, an update, and a delete are fine
        let del =
            |r: &str| SpaceWrite::Delete { collection: "com.example.post".into(), rkey: r.into(), must_exist: true };
        assert!(w(&mut st, vec![del("a"), create("c", 1)], 2).unwrap());
        assert!(w(&mut st, vec![update("b", 2, true)], 1).unwrap(), "over a lowered cap, no growth");
        assert!(w(&mut st, vec![del("b")], 1).unwrap());
        assert_eq!(st.repos[&sid].records, 1);
    }

    /// `sb`/`sc` rows follow each path's net change: a ref a record stops
    /// naming goes, the ones it names are rewritten with the new rev, and a
    /// path created and deleted in one batch leaves none.
    #[test]
    fn blob_refs_follow_the_batch() {
        let blob = |i: u8| Cid::raw(&[i]);
        let with = |w: SpaceWrite, blobs: Vec<Cid>| match w {
            SpaceWrite::Create { collection, rkey, cid, bytes, .. } => {
                SpaceWrite::Create { collection, rkey, cid, bytes, blobs }
            }
            SpaceWrite::Update { collection, rkey, cid, bytes, must_exist, put, .. } => {
                SpaceWrite::Update { collection, rkey, cid, bytes, blobs, must_exist, put }
            }
            d => d,
        };
        let del =
            |r: &str| SpaceWrite::Delete { collection: "com.example.post".into(), rkey: r.into(), must_exist: true };
        let (mut st, sid, uri) = states_with(&[("com.example.post/a", None), ("com.example.post/t", None)]);
        // `o` was written before and names blob 9, as read from `sR`
        let mut f = Fetched::default();
        let old = PathRec { cid: Cid::dag_cbor(b"old"), blobs: vec![blob(9)] };
        f.paths.push((sid, "com.example.post/o".into(), Some(old)));
        install(&mut st, f);
        let did = "did:plc:writer";
        let refs = |b: &BuiltWrite| {
            let mut v: Vec<(Vec<u8>, bool)> = b
                .muts
                .iter()
                .filter(|m| {
                    let body = vlsync_store::keys::key_body(&m.key);
                    body.starts_with(state::SPACE_BLOB_FAMILY) || body.starts_with(state::SPACE_BLOB_CID_FAMILY)
                })
                .map(|m| (m.key.to_vec(), m.val.is_some()))
                .collect();
            v.sort();
            v
        };
        let row = |b: u8, path: &str, put: bool| {
            let mut v = vec![
                (state::space_blob_key(did, &sid, &blob(b), path), put),
                (state::space_blob_cid_key(did, &blob(b), &sid, path), put),
            ];
            v.sort();
            v
        };
        let b = go(&mut st, sid, &uri, vec![with(create("a", 1), vec![blob(1), blob(2)])]).unwrap();
        let mut want = [row(1, "com.example.post/a", true), row(2, "com.example.post/a", true)].concat();
        want.sort();
        assert_eq!(refs(&b), want);
        let sb = b.muts.iter().find(|m| m.key[..] == state::space_blob_key(did, &sid, &blob(1), "com.example.post/a"));
        assert_eq!(sb.unwrap().val.as_deref(), Some(&b.rev.0.to_be_bytes()[..]));
        // from the overlay: 1 goes, 2 is rewritten, 3 comes
        let b = go(&mut st, sid, &uri, vec![with(update("a", 2, true), vec![blob(2), blob(3)])]).unwrap();
        let mut want = [
            row(1, "com.example.post/a", false),
            row(2, "com.example.post/a", true),
            row(3, "com.example.post/a", true),
        ]
        .concat();
        want.sort();
        assert_eq!(refs(&b), want);
        // from `sR`: deleting `o` drops its ref
        let b = go(&mut st, sid, &uri, vec![del("o")]).unwrap();
        assert_eq!(refs(&b), row(9, "com.example.post/o", false));
        // created and deleted in one batch: no rows at all
        let b = go(&mut st, sid, &uri, vec![with(create("t", 1), vec![blob(4)]), del("t")]).unwrap();
        assert_eq!(refs(&b), Vec::new());
        // the overlay remembers the update's blobs for the next write
        let b = go(&mut st, sid, &uri, vec![del("a")]).unwrap();
        let mut want = [row(2, "com.example.post/a", false), row(3, "com.example.post/a", false)].concat();
        want.sort();
        assert_eq!(refs(&b), want);
    }

    #[test]
    fn path_rec_reads_blob_refs_from_the_stored_value() {
        let blob = Cid::raw(b"img");
        let rec = serde_json::json!({"$type": "com.example.post", "img": {"$type": "blob", "ref": {"$link": blob.to_string()}, "mimeType": "image/png", "size": 3}});
        let v = vlatproto::cbor::Value::from_json(&rec).unwrap();
        let mut bytes = Vec::new();
        v.encode(&mut bytes);
        let cid = Cid::dag_cbor(&bytes);
        let r = PathRec::from_value(&state::record_value(&cid, 7, &bytes)).unwrap();
        assert_eq!(r, PathRec { cid, blobs: vec![blob] });
    }

    /// A value read from `sR` before an entry applied is never used once
    /// that entry's overlay is gone: the overlay outlives every fetch.
    #[test]
    fn overlay_survives_a_fetch_racing_an_apply() {
        let (mut st, sid, uri) = states_with(&[("com.example.post/a", None)]);
        let applied = Arc::new(AtomicBool::new(false));
        let b = write(&mut st, "did:plc:writer", sid, &uri, vec![create("a", 1)], 1, &applied, Vec::new(), u64::MAX)
            .unwrap()
            .ok()
            .unwrap();
        st.clear_fetched();
        // the next request needs another path: a fetch starts while the
        // create is in flight, and reads `a` from before it applied
        let mut stale = Fetched::default();
        stale.paths.push((sid, "com.example.post/a".into(), None));
        stale.paths.push((sid, "com.example.post/z".into(), None));
        // the entry applies before the fetch result is used
        applied.store(true, Ordering::Release);
        install(&mut st, stale);
        st.prune();
        // the overlay still answers for `a`: a create of it is refused
        let e = go(&mut st, sid, &uri, vec![create("a", 2)]).err().unwrap();
        assert!(matches!(e, SpaceError::RecordAlreadyExists(_)), "{e:?}");
        st.clear_fetched();
        // with nothing pending use, the applied entry is pruned
        st.prune();
        assert!(st.repos[&sid].known("com.example.post/a").is_none());
        assert_eq!(st.repos[&sid].rev, Some(b.rev));
    }

    #[test]
    fn host_sequencing() {
        let uri: Arc<str> = URI.into();
        let sid = state::space_id(URI);
        let mut st = SpaceStates::default();
        let mut f = Fetched::default();
        f.hosts.push((sid, uri.clone(), None, None));
        f.writers.push((sid, "did:plc:w".into(), None));
        f.members.push((sid, "did:plc:w".into(), Some(MemberRow { read: true, write: true })));
        f.writers.push((sid, "did:plc:x".into(), None));
        f.members.push((sid, "did:plc:x".into(), None));
        install(&mut st, f);
        let e =
            record_writer(&mut st, "did:plc:auth", sid, URI, "did:plc:w", Tid(10), [1; 32], None, SameRev::Sequence, 1)
                .err()
                .unwrap();
        assert!(matches!(e, SpaceError::SpaceNotFound));
        cs(&mut st, "did:plc:auth", sid, SpaceRow::defaults(URI, "t")).unwrap();
        assert!(matches!(
            cs(&mut st, "did:plc:auth", sid, SpaceRow::defaults(URI, "t")),
            Err(SpaceError::SpaceAlreadyExists)
        ));
        let (muts, s1) =
            record_writer(&mut st, "did:plc:auth", sid, URI, "did:plc:w", Tid(10), [1; 32], None, SameRev::Sequence, 1)
                .unwrap()
                .unwrap();
        assert_eq!(muts.len(), 2);
        assert!(s1.prev.is_none());
        // not newer: nothing
        assert!(record_writer(
            &mut st,
            "did:plc:auth",
            sid,
            URI,
            "did:plc:w",
            Tid(10),
            [1; 32],
            None,
            SameRev::Sequence,
            1
        )
        .unwrap()
        .is_none());
        let (muts, s2) =
            record_writer(&mut st, "did:plc:auth", sid, URI, "did:plc:w", Tid(11), [1; 32], None, SameRev::Sequence, 1)
                .unwrap()
                .unwrap();
        assert_eq!(muts.len(), 3, "the old sQ entry goes");
        assert!(s2.space_rev > s1.space_rev);
        assert_eq!(s2.prev, Some(s1.space_rev));
        // the same rev with another hash (a takedown's adjusted view): again
        let (_, s3) =
            record_writer(&mut st, "did:plc:auth", sid, URI, "did:plc:w", Tid(11), [2; 32], None, SameRev::Sequence, 1)
                .unwrap()
                .unwrap();
        assert_eq!(s3.prev, Some(s2.space_rev));
        assert!(record_writer(
            &mut st,
            "did:plc:auth",
            sid,
            URI,
            "did:plc:w",
            Tid(11),
            [2; 32],
            None,
            SameRev::Sequence,
            1
        )
        .unwrap()
        .is_none());
        // a remote host's: handed back to be checked, nothing written
        let verify = |st: &mut SpaceStates, hash| {
            record_writer(st, "did:plc:auth", sid, URI, "did:plc:w", Tid(11), hash, None, SameRev::Verify, 1)
        };
        assert!(matches!(verify(&mut st, [9; 32]), Err(SpaceError::SameRev)));
        assert!(verify(&mut st, [2; 32]).unwrap().is_none(), "the hash held is a no-op");
        let (_, s4) =
            record_writer(&mut st, "did:plc:auth", sid, URI, "did:plc:w", Tid(12), [9; 32], None, SameRev::Verify, 1)
                .unwrap()
                .unwrap();
        assert_eq!(s4.prev, Some(s3.space_rev), "a newer rev needs no check");
        assert!(record_writer(
            &mut st,
            "did:plc:auth",
            sid,
            URI,
            "did:plc:w",
            Tid(10),
            [3; 32],
            None,
            SameRev::Sequence,
            1
        )
        .unwrap()
        .is_none());
        // not a member
        let e =
            record_writer(&mut st, "did:plc:auth", sid, URI, "did:plc:x", Tid(10), [1; 32], None, SameRev::Sequence, 1)
                .err()
                .unwrap();
        assert!(matches!(e, SpaceError::NotAuthorized(_)));
    }

    /// Members, writers and the sequence of a deleted space never carry
    /// over into its re-creation, and the authority can't write to it in
    /// between.
    #[test]
    fn unswept_rows_and_import_claims() {
        let did = "did:plc:writer";
        // a head fetched with rows under it refuses a write, handing it back
        let uri: Arc<str> = URI.into();
        let sid = state::space_id(URI);
        let mut st = SpaceStates::default();
        let mut f = Fetched::default();
        f.heads.push((sid, uri.clone(), None));
        f.paths.push((sid, "com.example.post/a".into(), None));
        f.unswept.push(sid);
        install(&mut st, f);
        match go(&mut st, sid, &uri, vec![create("a", 1)]) {
            Err(SpaceError::Unswept(w)) => assert_eq!(w.len(), 1),
            r => panic!("{:?}", r.err()),
        }
        // a headless repo is claimed and read again afterwards
        assert!(import_begin(&mut st, did, sid, URI, false).unwrap().is_none());
        assert!(!st.repos.contains_key(&sid));

        let (mut st, sid, uri) = states_with(&[("com.example.post/a", None)]);
        go(&mut st, sid, &uri, vec![create("a", 1)]).unwrap();
        let invalid =
            |r: Result<Option<Vec<Mutation>>, SpaceError>| matches!(r, Err(SpaceError::Write(WriteError::Invalid(_))));
        let del = SpaceWrite::Delete { collection: "com.example.post".into(), rkey: "a".into(), must_exist: true };
        go(&mut st, sid, &uri, vec![del]).unwrap();
        assert!(invalid(import_begin(&mut st, did, sid, URI, false)), "a sweep never takes a head");
        // an empty repo's head goes, and what's held is headless and unswept
        let m = import_begin(&mut st, did, sid, URI, true).unwrap().unwrap();
        let keys: Vec<_> = m.iter().map(|m| (m.key.to_vec(), m.val.clone())).collect();
        let list = state::space_list_key(did, URI, SpaceListed::Repo);
        assert_eq!(keys, [(state::space_head_key(did, &sid), None), (list, None)]);
        assert!(st.repos[&sid].rev.is_none() && st.repos[&sid].unswept);
        // a repo with records is replaced the same way
        let (mut st, sid, uri) = states_with(&[("com.example.post/a", None)]);
        go(&mut st, sid, &uri, vec![create("a", 1)]).unwrap();
        let m = import_begin(&mut st, did, sid, URI, true).unwrap().unwrap();
        let keys: Vec<_> = m.iter().map(|m| (m.key.to_vec(), m.val.clone())).collect();
        let list = state::space_list_key(did, URI, SpaceListed::Repo);
        assert_eq!(keys, [(state::space_head_key(did, &sid), None), (list, None)]);
        assert!(st.repos[&sid].rev.is_none() && st.repos[&sid].unswept && st.repos[&sid].records == 0);
    }

    #[test]
    fn delete_and_recreate() {
        let auth = "did:plc:auth";
        let uri: Arc<str> = URI.into();
        let sid = state::space_id(URI);
        let mut st = SpaceStates::default();
        let mut f = Fetched::default();
        f.hosts.push((sid, uri.clone(), None, None));
        f.heads.push((sid, uri.clone(), None));
        f.writers.push((sid, auth.into(), None));
        f.writers.push((sid, "did:plc:w".into(), None));
        f.members.push((sid, "did:plc:w".into(), None));
        install(&mut st, f);
        assert!(matches!(delete_space(&mut st, auth, sid, URI, "t".into()), Err(SpaceError::SpaceNotFound)));
        let applied = Arc::new(AtomicBool::new(false));
        let sm =
            |st: &mut SpaceStates, access| set_member(st, auth, sid, &uri, "did:plc:w", access, 1, &applied, u64::MAX);
        assert!(matches!(sm(&mut st, None), Err(SpaceError::SpaceNotFound)));
        cs(&mut st, auth, sid, SpaceRow::defaults(URI, "t")).unwrap();
        sm(&mut st, Some(MemberRow { read: true, write: true })).unwrap();
        record_writer(&mut st, auth, sid, URI, "did:plc:w", Tid(10), [1; 32], None, SameRev::Sequence, 1)
            .unwrap()
            .unwrap();
        let up = |st: &mut SpaceStates, p| update_space(st, auth, sid, &uri, p, 1, &applied, u64::MAX);
        assert!(
            matches!(up(&mut st, Policy::Personal), Err(SpaceError::Write(WriteError::Internal(_)))),
            "the list unread"
        );
        st.hosts.get_mut(&sid).unwrap().members_complete = true;
        st.repos.get_mut(&sid).unwrap().fetched.insert(publish::policy_path(), None);
        let public = Policy::Member {
            public_read: true,
            public_write: false,
            allowed_apps: None,
            publish_policy: false,
            publish_members: false,
        };
        let b = up(&mut st, public.clone()).unwrap();
        assert!(b.published.is_none());
        assert_eq!(SpaceRow::decode(b.muts[0].val.as_ref().unwrap()).unwrap().policy, public);
        let muts = delete_space(&mut st, auth, sid, URI, "t2".into()).unwrap().unwrap();
        let keys: Vec<_> = muts[1..].iter().map(|m| (m.key.to_vec(), m.val.is_none())).collect();
        let list = |why| state::space_list_key(auth, URI, why);
        assert_eq!(
            keys,
            [
                (state::space_head_key(auth, &sid), true),
                (list(SpaceListed::Governs), true),
                (list(SpaceListed::Repo), true)
            ]
        );
        assert!(!SpaceRow::decode(muts[0].val.as_ref().unwrap()).unwrap().live());
        assert!(delete_space(&mut st, auth, sid, URI, "t3".into()).unwrap().is_none(), "already a tombstone");
        let e = record_writer(&mut st, auth, sid, URI, "did:plc:w", Tid(11), [1; 32], None, SameRev::Sequence, 1)
            .err()
            .unwrap();
        assert!(matches!(e, SpaceError::SpaceNotFound));
        // the authority's own writes wait for a live space
        let mut f = Fetched::default();
        f.heads.push((sid, uri.clone(), None));
        f.paths.push((sid, "com.example.post/a".into(), None));
        install(&mut st, f);
        let applied = Arc::new(AtomicBool::new(false));
        let e = write(&mut st, auth, sid, &uri, vec![create("a", 1)], 1, &applied, Vec::new(), u64::MAX).err().unwrap();
        assert!(matches!(e, SpaceError::SpaceNotFound));
        cs(&mut st, auth, sid, SpaceRow::defaults(URI, "t4")).unwrap();
        let host = &st.hosts[&sid];
        assert!(host.members.is_empty() && host.max_space_rev.is_none());
        assert_eq!(host.writers.get(auth), Some(&None));
        // a member must be loaded afresh: nothing is assumed
        let e = record_writer(&mut st, auth, sid, URI, "did:plc:w", Tid(12), [1; 32], None, SameRev::Sequence, 1)
            .err()
            .unwrap();
        assert!(matches!(e, SpaceError::Write(WriteError::Internal(_))), "{e:?}");
    }

    /// The authority's own repo needs its space (reference "refuses an
    /// authority write to its own deleted space", and `ensureRepo`): a
    /// write before createSpace is SpaceNotFound.
    #[test]
    fn own_writes_need_a_live_space() {
        let auth = "did:plc:auth";
        let uri: Arc<str> = URI.into();
        let sid = state::space_id(URI);
        let mut st = SpaceStates::default();
        let mut f = Fetched::default();
        f.hosts.push((sid, uri.clone(), None, None));
        f.heads.push((sid, uri.clone(), None));
        f.paths.push((sid, "com.example.post/a".into(), None));
        f.writers.push((sid, auth.into(), None));
        install(&mut st, f);
        let applied = Arc::new(AtomicBool::new(false));
        let e = write(&mut st, auth, sid, &uri, vec![create("a", 1)], 1, &applied, Vec::new(), u64::MAX).err().unwrap();
        assert!(matches!(e, SpaceError::SpaceNotFound), "{e:?}");
        let muts = cs(&mut st, auth, sid, SpaceRow::defaults(URI, "t")).unwrap().muts;
        assert_eq!(muts[1].key.to_vec(), state::space_list_key(auth, URI, SpaceListed::Governs));
        let b = write(&mut st, auth, sid, &uri, vec![create("a", 1)], 1, &applied, Vec::new(), u64::MAX)
            .unwrap()
            .ok()
            .unwrap();
        assert!(b.sequenced.is_some(), "an own write in a live space is sequenced in its entry");
    }

    fn record_keys(m: &[Mutation], did: &str, sid: SpaceId) -> Vec<(String, bool)> {
        let prefix = state::space_prefix(state::SPACE_RECORD_FAMILY, did, &sid);
        m.iter()
            .filter(|m| m.key.starts_with(&prefix))
            .map(|m| (String::from_utf8(m.key[prefix.len()..].to_vec()).unwrap(), m.val.is_some()))
            .collect()
    }

    /// A publishing policy's records go out in its host op's entry, follow
    /// the member list, and are withdrawn with it; the writer set loses a
    /// member whose write is revoked.
    #[test]
    fn published_records_follow_the_config() {
        let auth = "did:plc:auth";
        let (w, x) = ("did:plc:w", "did:web:localhost%3A2583");
        let uri: Arc<str> = URI.into();
        let sid = state::space_id(URI);
        let mut st = SpaceStates::default();
        let mut f = Fetched::default();
        f.hosts.push((sid, uri.clone(), None, None));
        f.heads.push((sid, uri.clone(), None));
        f.writers.push((sid, auth.into(), None));
        f.writers.push((sid, x.into(), None));
        f.writers.push((sid, w.into(), Some(WriterRow { repo_rev: Tid(5), hash: [5; 32], space_rev: Tid(6) })));
        for p in [publish::policy_path(), publish::member_path(w), publish::member_path(x)] {
            f.paths.push((sid, p, None));
        }
        f.member_lists.push((sid, Vec::new(), Vec::new()));
        install(&mut st, f);
        let applied = Arc::new(AtomicBool::new(false));
        let publishing = Policy::Member {
            public_read: false,
            public_write: false,
            allowed_apps: None,
            publish_policy: true,
            publish_members: true,
        };
        let mut row = SpaceRow::defaults(URI, "t");
        row.policy = publishing.clone();
        let b = create_space(&mut st, auth, sid, &uri, row, 1, &applied, u64::MAX).unwrap();
        let p = b.published.expect("the policy is published");
        assert_eq!(record_keys(&p.muts, auth, sid), [(publish::policy_path(), true)]);
        assert!(p.sequenced.is_some() && p.notify.is_none(), "the authority's own write, sequenced in the entry");
        assert_eq!(p.head.records, 1);

        let sm =
            |st: &mut SpaceStates, m: &str, access| set_member(st, auth, sid, &uri, m, access, 1, &applied, u64::MAX);
        let b = sm(&mut st, w, Some(MemberRow { read: true, write: true })).unwrap();
        assert_eq!(record_keys(&b.published.unwrap().muts, auth, sid), [(publish::member_path(w), true)]);
        // the same access again changes nothing published
        assert!(sm(&mut st, w, Some(MemberRow { read: true, write: true })).unwrap().published.is_none());
        let b = sm(&mut st, x, Some(MemberRow { read: true, write: false })).unwrap();
        assert_eq!(
            record_keys(&b.published.unwrap().muts, auth, sid),
            [("com.atproto.memberspace.member/did:web:localhost:2583".into(), true)]
        );
        // revoking write drops the writer (its sW and sQ rows)
        let b = sm(&mut st, w, Some(MemberRow { read: true, write: false })).unwrap();
        let wk = state::space_writer_key(auth, &sid, w);
        assert!(b.muts.iter().any(|m| m.key.to_vec() == wk && m.val.is_none()));
        assert!(b.muts.iter().any(|m| m.key.to_vec() == state::space_seq_key(auth, &sid, 6) && m.val.is_none()));
        assert_eq!(st.hosts[&sid].writers[w], None);
        assert!(remove_writer(&mut st, auth, sid, w).unwrap().is_empty(), "idempotent");

        // a migration wipes the list and withdraws everything published
        let b = update_space(&mut st, auth, sid, &uri, Policy::Personal, 1, &applied, u64::MAX).unwrap();
        let mk = |m: &str| state::space_member_key(auth, &sid, m);
        for m in [w, x] {
            assert!(b.muts.iter().any(|mu| mu.key.to_vec() == mk(m) && mu.val.is_none()), "{m}'s row");
        }
        let mut withdrawn = record_keys(&b.published.as_ref().unwrap().muts, auth, sid);
        withdrawn.sort();
        let mut want =
            vec![(publish::policy_path(), false), (publish::member_path(w), false), (publish::member_path(x), false)];
        want.sort();
        assert_eq!(withdrawn, want);
        assert_eq!(b.published.unwrap().head.records, 0);
        assert!(st.hosts[&sid].members.is_empty());
        assert!(matches!(sm(&mut st, w, None), Err(SpaceError::PolicyMismatch)));
    }

    #[test]
    fn clear_replaces_the_head() {
        let did = "did:plc:writer";
        let (mut st, sid, uri) = states_with(&[("com.example.post/a", None)]);
        let b = go(&mut st, sid, &uri, vec![create("a", 1)]).unwrap();
        let del = vec![Mutation { key: state::space_record_key(did, &sid, "com.example.post/a").into(), val: None }];
        let e = clear_commit(&mut st, did, sid, &uri, Tid(1), del.clone(), LtHash::default(), 0, 1).err().unwrap();
        assert!(matches!(e, SpaceError::Write(WriteError::Unavailable(_))), "a stale prev: {e:?}");
        let c = clear_commit(&mut st, did, sid, &uri, b.rev, del, LtHash::default(), 0, 1).unwrap();
        assert!(c.rev > b.rev && c.head.records == 0 && c.head.created != 0);
        assert_eq!(c.head.hash.digest(), LtHash::default().digest());
        assert!(c.notify.is_some_and(|n| n.repo_rev == c.rev), "the authority is told");
        assert_eq!(c.muts[0].key.to_vec(), state::space_record_key(did, &sid, "com.example.post/a"));
        assert_eq!(st.repos[&sid].rev, Some(c.rev));
    }

    /// An updateSpace reads the member list once: what it needs is all
    /// held after one fetch (the worker fetches until it needs nothing).
    #[test]
    fn update_space_needs_settle() {
        let auth = "did:plc:auth";
        let uri: Arc<str> = URI.into();
        let sid = state::space_id(URI);
        let (tx, _rx) = tokio::sync::oneshot::channel();
        let req = SpaceReq {
            did: auth.into(),
            uri: uri.clone(),
            sid,
            op: SpaceOp::UpdateSpace { policy: Policy::Personal },
            spaces: Arc::new(super::super::Spaces::default()),
            reply: tx,
            permit: None,
        };
        let mut st = SpaceStates::default();
        let mut need = SpaceNeed::default();
        need.add(&st, &req);
        assert_eq!(need.member_lists, [sid]);
        let mut f = Fetched::default();
        f.hosts.push((sid, uri.clone(), Some(SpaceRow::defaults(URI, "t")), None));
        f.heads.push((sid, uri.clone(), None));
        f.writers.push((sid, auth.into(), None));
        f.paths.push((sid, publish::policy_path(), None));
        let members = vec![("did:plc:m".to_string(), MemberRow { read: true, write: true })];
        f.member_lists.push((sid, members, Vec::new()));
        install(&mut st, f);
        let mut need = SpaceNeed::default();
        need.add(&st, &req);
        assert!(need.is_empty(), "{need:?}");
        // the next batch reads only the member records it no longer holds
        st.clear_fetched();
        let mut need = SpaceNeed::default();
        need.add(&st, &req);
        assert!(need.member_lists.is_empty() && need.paths.contains(&(sid, publish::member_path("did:plc:m"))));
    }
}
