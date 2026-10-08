//! Materialized-state key layout (one SlateDB per shard).
//!
//! Every per-account key is slot-major: `0x01 ‖ slot (u16 BE) ‖ family ‖ rest`,
//! where the slot is that of the key's routing key (`slots::slot_of`). A
//! shard's slot range is then one contiguous key range, so a shard splits or
//! merges by cloning its SlateDB with a projection range (DESIGN.md "Online
//! shard split/merge"). Shard-wide keys (`meta/...`) are plain ASCII and sort
//! outside every slot range.
//!
//! h/{did}                 -> head: commit cid | data cid | rev u64 | signed commit block
//! a/{did}                 -> account JSON (signing key wrapped: src/secrets.rs)
//! n/{handle}              -> did (slot of the account's DID)
//! R/{did}\0{gen}{coll}/{rkey}  -> record cid | rev | record bytes
//! c/{did}\0{gen}{cid8}{path}   -> empty (record CID index for getBlocks)
//! C/{coll}\0{did}         -> empty (collection index; slot of the DID)
//! b/{did}\0{gen}{cid}\0{path}  -> rev (blob references)
//! p/{routing}\0{name}     -> private per-account state (slot of the routing key)
//! M/{did}\0{gen}{cid digest}   -> MST node block, height >= 1 (DESIGN.md "Partial MSTs")
//! bl/{did}\0{gen}{code}{subject} -> rkeys linking `subject` (crate::backlinks, DESIGN.md "Backlinks")
//! T/                      -> the slot's account totals (crate::totals; keyed by slot alone)
//! S/{did}                 -> repo counts (`RepoStats`: checkAccountStatus)
//! G/{did}                 -> `ImportState`: a staged import, generations left to sweep
//! D/{did}                 -> the account's `deleteAfter` (crate::xrpc::scheduled_deletion)
//! L/{did}\0{factor}       -> locked until, u64 BE secs: the lockout index (crate::xrpc::mfa)
//!
//! `{gen}` is the repo's generation (`Account::repo_gen`, LEB128): importRepo
//! stages the new repo under a fresh one and moves the account to it in one
//! entry (DESIGN.md "Staged imports").
//!
//! Spaces (`--spaces`; values in `crate::space::rows`). `{sid}` is the first
//! 16 bytes of sha256(space URI); the URI itself is in `sH`/`sS`/`sP` and
//! checked by every reader. Repo-host rows are in the author's slot:
//!
//! sH/{did}\0{sid}                   -> space repo head: URI, rev, LtHash state, count, created
//! sR/{did}\0{sid}{coll}/{rkey}      -> record cid | rev | record bytes (as `R/`)
//! sO/{did}\0{sid}{rev u64}{idx u16} -> oplog op: action, coll, rkey, cid?, prev?
//! sP/{did}\0{sid}                   -> notifyWrite outbox: URI, repoRev, hash
//! sb/{did}\0{sid}{cid}\0{path}       -> rev (space blob refs: space.listBlobs/getBlob)
//! sc/{did}\0{cid}\0{sid}{path}       -> empty (the same refs by CID: blob GC)
//!
//! Space-host rows are in the authority's slot:
//!
//! sS/{auth}\0{sid}                  -> the space (JSON: URI, policies, created, deleted)
//! sM/{auth}\0{sid}{member}          -> member access
//! sW/{auth}\0{sid}{writer}          -> writer state: repoRev, hash, spaceRev
//! sQ/{auth}\0{sid}{spaceRev u64}    -> writer DID (listRepos order; latest state per writer only)
//! sN/{auth}\0{sid}{service}         -> notify registration: endpoint, expiry

use bytes::{BufMut, Bytes};
use sha2::{Digest, Sha256};
use vlatproto::cid::{Cid, CID_BYTES_LEN};
use vlatproto::tid::Tid;
use vlsync_store::keys::{key_body, key_slot, slot_family, slot_prefix, Gen, SLOT_PREFIX_LEN, SLOT_TAG};

/// Remembers the last DID per thread: a commit builds ~10 keys of one
/// repo, and the slot is a SHA-256 of the DID.
fn slot_cached(routing: &str) -> u16 {
    thread_local! {
        static LAST: std::cell::RefCell<(String, u16)> = const { std::cell::RefCell::new((String::new(), 0)) };
    }
    LAST.with(|c| {
        let mut c = c.borrow_mut();
        if c.0.is_empty() || c.0 != routing {
            c.1 = vlsync_store::slots::slot_of(routing);
            c.0.clear();
            c.0.push_str(routing);
        }
        c.1
    })
}

fn keyed(routing: &str, fam: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let len = SLOT_PREFIX_LEN + fam.len() + parts.iter().map(|p| p.len()).sum::<usize>();
    let mut k = Vec::with_capacity(len);
    k.extend_from_slice(&slot_prefix(slot_cached(routing)));
    k.extend_from_slice(fam);
    for p in parts {
        k.extend_from_slice(p);
    }
    k
}

pub fn head_key(did: &str) -> Vec<u8> {
    keyed(did, b"h/", &[did.as_bytes()])
}

pub fn account_key(did: &str) -> Vec<u8> {
    keyed(did, b"a/", &[did.as_bytes()])
}

/// In `did`'s slot.
pub fn handle_key(did: &str, handle: &str) -> Vec<u8> {
    keyed(did, b"n/", &[handle.as_bytes()])
}

/// Written in the same batch as every head change that changes the counts.
pub fn repo_stats_key(did: &str) -> Vec<u8> {
    keyed(did, b"S/", &[did.as_bytes()])
}

/// Present while the account has a `deleteAfter`, written in the same
/// batch as the account row, so the deletion sweep finds the scheduled
/// accounts with one family scan instead of reading every account.
pub fn delete_after_key(did: &str) -> Vec<u8> {
    keyed(did, DELETE_AFTER_FAMILY, &[did.as_bytes()])
}

pub const DELETE_AFTER_FAMILY: &[u8] = b"D/";

pub const HEAD_FAMILY: &[u8] = b"h/";
pub const ACCOUNT_FAMILY: &[u8] = b"a/";
pub const PRIVATE_FAMILY: &[u8] = b"p/";

pub fn collection_key(collection: &str, did: &str) -> Vec<u8> {
    keyed(did, b"C/", &[collection.as_bytes(), b"\0", did.as_bytes()])
}

/// For [`FamilyScan`].
pub fn collection_family(collection: &str) -> Vec<u8> {
    [b"C/", collection.as_bytes(), b"\0"].concat()
}

pub fn blob_ref_key(did: &str, gen: u64, blob: &vlatproto::cid::Cid, path: &str) -> Vec<u8> {
    keyed(
        did,
        BLOB_REF_FAMILY,
        &[did.as_bytes(), b"\0", &Gen(gen).bytes(), blob.to_string().as_bytes(), b"\0", path.as_bytes()],
    )
}

pub fn blob_ref_prefix(did: &str, gen: u64) -> Vec<u8> {
    gen_prefix(BLOB_REF_FAMILY, did, gen)
}

pub const LOCKOUT_FAMILY: &[u8] = b"L/";

pub fn lockout_key(did: &str, factor: &str) -> Vec<u8> {
    keyed(did, LOCKOUT_FAMILY, &[did.as_bytes(), b"\0", factor.as_bytes()])
}

pub fn private_key(did: &str, name: &str) -> Vec<u8> {
    keyed(did, b"p/", &[did.as_bytes(), b"\0", name.as_bytes()])
}

pub fn private_prefix(did: &str) -> Vec<u8> {
    keyed(did, b"p/", &[did.as_bytes(), b"\0"])
}

/// Keyed by the CID's digest alone: every node is dag-cbor sha-256.
/// Written and deleted in the commit's state batch, so `M/{did}` holds
/// exactly the interior nodes of the tree at `h/{did}`'s data root.
pub fn mst_node_key(did: &str, gen: u64, cid: &Cid) -> Vec<u8> {
    keyed(did, MST_NODE_FAMILY, &[did.as_bytes(), b"\0", &Gen(gen).bytes(), &cid.digest])
}

pub fn mst_node_prefix(did: &str, gen: u64) -> Vec<u8> {
    gen_prefix(MST_NODE_FAMILY, did, gen)
}

pub const MST_NODE_FAMILY: &[u8] = b"M/";

pub fn backlink_key(did: &str, gen: u64, link: &[u8]) -> Vec<u8> {
    keyed(did, BACKLINK_FAMILY, &[did.as_bytes(), b"\0", &Gen(gen).bytes(), link])
}

pub fn backlink_prefix(did: &str, gen: u64) -> Vec<u8> {
    gen_prefix(BACKLINK_FAMILY, did, gen)
}

pub fn record_prefix(did: &str, gen: u64) -> Vec<u8> {
    gen_prefix(RECORD_FAMILY, did, gen)
}

pub fn record_key(did: &str, gen: u64, path: &str) -> Vec<u8> {
    keyed(did, RECORD_FAMILY, &[did.as_bytes(), b"\0", &Gen(gen).bytes(), path.as_bytes()])
}

/// Bytes of a record CID's digest in its index key: enough to make
/// collisions rare (a lookup checks the record's CID anyway), short enough
/// to keep the extra key per record small.
const RECORD_CID_KEY_BYTES: usize = 8;

/// The same CID can sit at several paths (one key each), so lookups scan
/// [`record_cid_prefix`].
pub fn record_cid_key(did: &str, gen: u64, cid: &Cid, path: &str) -> Vec<u8> {
    [&record_cid_prefix(did, gen, cid)[..], path.as_bytes()].concat()
}

pub fn record_cid_prefix(did: &str, gen: u64, cid: &Cid) -> Vec<u8> {
    keyed(did, RECORD_CID_FAMILY, &[did.as_bytes(), b"\0", &Gen(gen).bytes(), &cid.digest[..RECORD_CID_KEY_BYTES]])
}

pub const RECORD_FAMILY: &[u8] = b"R/";
pub const RECORD_CID_FAMILY: &[u8] = b"c/";
pub const BLOB_REF_FAMILY: &[u8] = b"b/";
pub const BACKLINK_FAMILY: &[u8] = b"bl/";

/// The families whose keys carry the repo's generation: a generation's rows
/// are exactly these prefixes ([`gen_prefix`]).
pub const GEN_FAMILIES: [&[u8]; 5] =
    [RECORD_FAMILY, RECORD_CID_FAMILY, BLOB_REF_FAMILY, BACKLINK_FAMILY, MST_NODE_FAMILY];

pub const SPACE_HEAD_FAMILY: &[u8] = b"sH/";
pub const SPACE_RECORD_FAMILY: &[u8] = b"sR/";
pub const SPACE_OPLOG_FAMILY: &[u8] = b"sO/";
pub const SPACE_OUTBOX_FAMILY: &[u8] = b"sP/";
pub const SPACE_FAMILY: &[u8] = b"sS/";
pub const SPACE_MEMBER_FAMILY: &[u8] = b"sM/";
pub const SPACE_WRITER_FAMILY: &[u8] = b"sW/";
pub const SPACE_SEQ_FAMILY: &[u8] = b"sQ/";
pub const SPACE_NOTIFY_FAMILY: &[u8] = b"sN/";
pub const SPACE_BLOB_FAMILY: &[u8] = b"sb/";
pub const SPACE_BLOB_CID_FAMILY: &[u8] = b"sc/";
pub const SPACE_LIST_FAMILY: &[u8] = b"sL/";

/// Every Spaces family: rows that must never reach a firehose frame.
pub const SPACE_FAMILIES: [&[u8]; 12] = [
    SPACE_HEAD_FAMILY,
    SPACE_RECORD_FAMILY,
    SPACE_OPLOG_FAMILY,
    SPACE_OUTBOX_FAMILY,
    SPACE_FAMILY,
    SPACE_MEMBER_FAMILY,
    SPACE_WRITER_FAMILY,
    SPACE_SEQ_FAMILY,
    SPACE_NOTIFY_FAMILY,
    SPACE_BLOB_FAMILY,
    SPACE_BLOB_CID_FAMILY,
    SPACE_LIST_FAMILY,
];

/// Why an account is listed under a space URI in `sL/`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpaceListed {
    /// It holds a repo there (an `sH` row).
    Repo,
    /// It governs the space and it's live (an `sS` row that isn't a tombstone).
    Governs,
}

impl SpaceListed {
    fn byte(self) -> u8 {
        match self {
            SpaceListed::Repo => b'h',
            SpaceListed::Governs => b's',
        }
    }
}

/// `sL/{did}\0{uri}\0{h|s}`: listSpaces's index, in URI order. URIs hold
/// no NUL, so a key's URI ends at the first one and the order is the URIs'.
pub fn space_list_key(did: &str, uri: &str, why: SpaceListed) -> Vec<u8> {
    keyed(did, SPACE_LIST_FAMILY, &[did.as_bytes(), b"\0", uri.as_bytes(), b"\0", &[why.byte()]])
}

/// The URI of an `sL/` key under `prefix` ([`space_did_prefix`]).
pub fn space_list_uri<'a>(key: &'a [u8], prefix: &[u8]) -> Option<&'a str> {
    let rest = key.strip_prefix(prefix)?;
    let end = rest.iter().position(|b| *b == 0)?;
    std::str::from_utf8(&rest[..end]).ok()
}

pub const SPACE_ID_LEN: usize = 16;
pub type SpaceId = [u8; SPACE_ID_LEN];

/// How logs name a space: its id, so log readers don't see the space's
/// name or who is in it.
pub fn space_log_id(uri: &str) -> String {
    hex::encode(space_id(uri))
}

pub fn space_id(uri: &str) -> SpaceId {
    Sha256::digest(uri.as_bytes())[..SPACE_ID_LEN].try_into().unwrap()
}

pub fn is_space_key(key: &[u8]) -> bool {
    key_slot(key).is_some() && SPACE_FAMILIES.iter().any(|f| key_body(key).starts_with(f))
}

/// `fam ‖ did ‖ \0`: all of one account's rows of a Spaces family.
pub fn space_did_prefix(fam: &[u8], did: &str) -> Vec<u8> {
    keyed(did, fam, &[did.as_bytes(), b"\0"])
}

/// `fam ‖ did ‖ \0 ‖ sid`: one (account, space)'s rows of a family.
pub fn space_prefix(fam: &[u8], did: &str, sid: &SpaceId) -> Vec<u8> {
    keyed(did, fam, &[did.as_bytes(), b"\0", sid])
}

pub fn space_head_key(did: &str, sid: &SpaceId) -> Vec<u8> {
    space_prefix(SPACE_HEAD_FAMILY, did, sid)
}

pub fn space_record_key(did: &str, sid: &SpaceId, path: &str) -> Vec<u8> {
    keyed(did, SPACE_RECORD_FAMILY, &[did.as_bytes(), b"\0", sid, path.as_bytes()])
}

pub fn space_oplog_key(did: &str, sid: &SpaceId, rev: u64, idx: u16) -> Vec<u8> {
    keyed(did, SPACE_OPLOG_FAMILY, &[did.as_bytes(), b"\0", sid, &rev.to_be_bytes(), &idx.to_be_bytes()])
}

pub fn space_outbox_key(did: &str, sid: &SpaceId) -> Vec<u8> {
    space_prefix(SPACE_OUTBOX_FAMILY, did, sid)
}

pub fn space_key(authority: &str, sid: &SpaceId) -> Vec<u8> {
    space_prefix(SPACE_FAMILY, authority, sid)
}

pub fn space_member_key(authority: &str, sid: &SpaceId, member: &str) -> Vec<u8> {
    keyed(authority, SPACE_MEMBER_FAMILY, &[authority.as_bytes(), b"\0", sid, member.as_bytes()])
}

pub fn space_writer_key(authority: &str, sid: &SpaceId, writer: &str) -> Vec<u8> {
    keyed(authority, SPACE_WRITER_FAMILY, &[authority.as_bytes(), b"\0", sid, writer.as_bytes()])
}

pub fn space_seq_key(authority: &str, sid: &SpaceId, space_rev: u64) -> Vec<u8> {
    keyed(authority, SPACE_SEQ_FAMILY, &[authority.as_bytes(), b"\0", sid, &space_rev.to_be_bytes()])
}

pub fn space_notify_key(authority: &str, sid: &SpaceId, service: &str) -> Vec<u8> {
    keyed(authority, SPACE_NOTIFY_FAMILY, &[authority.as_bytes(), b"\0", sid, service.as_bytes()])
}

/// The CID is in its string form, as in `b/`, so listBlobs pages in the
/// reference's (string) CID order.
pub fn space_blob_key(did: &str, sid: &SpaceId, blob: &Cid, path: &str) -> Vec<u8> {
    [&space_blob_prefix(did, sid, blob)[..], path.as_bytes()].concat()
}

/// `sb/{did}\0{sid}{cid}\0`: the paths in one space naming one blob.
pub fn space_blob_prefix(did: &str, sid: &SpaceId, blob: &Cid) -> Vec<u8> {
    keyed(did, SPACE_BLOB_FAMILY, &[did.as_bytes(), b"\0", sid, blob.to_string().as_bytes(), b"\0"])
}

pub fn space_blob_cid_key(did: &str, blob: &Cid, sid: &SpaceId, path: &str) -> Vec<u8> {
    [&space_blob_cid_prefix(did, &blob.to_string())[..], sid, path.as_bytes()].concat()
}

/// `sc/{did}\0`: every space ref of the account's blobs, in CID order.
pub fn space_blob_cid_did_prefix(did: &str) -> Vec<u8> {
    keyed(did, SPACE_BLOB_CID_FAMILY, &[did.as_bytes(), b"\0"])
}

/// `sc/{did}\0{cid}\0`: every space ref of one blob of the account.
pub fn space_blob_cid_prefix(did: &str, blob: &str) -> Vec<u8> {
    keyed(did, SPACE_BLOB_CID_FAMILY, &[did.as_bytes(), b"\0", blob.as_bytes(), b"\0"])
}

/// `fam ‖ did ‖ \0 ‖ gen`: one generation's rows of a [`GEN_FAMILIES`] family.
pub fn gen_prefix(fam: &[u8], did: &str, gen: u64) -> Vec<u8> {
    keyed(did, fam, &[did.as_bytes(), b"\0", &Gen(gen).bytes()])
}

/// Present while an import is staged or a generation awaits its sweep, so
/// the sweeper finds them with one family scan (`crate::import`).
pub fn import_key(did: &str) -> Vec<u8> {
    keyed(did, IMPORT_FAMILY, &[did.as_bytes()])
}

pub const IMPORT_FAMILY: &[u8] = b"G/";

/// An import being staged: its generation, its driver's nonce, and the rev
/// its records carry and its commit will have.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Staging {
    pub gen: u64,
    pub nonce: u64,
    pub rev: u64,
}

/// `G/{did}`, absent when nothing is staged or left to sweep.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ImportState {
    pub staging: Option<Staging>,
    /// Generations no account points at whose rows may remain.
    pub garbage: Vec<u64>,
}

impl ImportState {
    pub fn is_empty(&self) -> bool {
        self.staging.is_none() && self.garbage.is_empty()
    }

    /// A generation no row can be under: above the current one and every
    /// one staged or left to sweep (a swept one may be handed out again).
    pub fn next_gen(&self, current: Option<u64>) -> u64 {
        let top = self.garbage.iter().copied().chain(self.staging.map(|s| s.gen)).chain(current).max();
        top.map_or(0, |g| g + 1)
    }

    pub fn encode(&self) -> Bytes {
        let mut b = Vec::with_capacity(1 + 24 + 4 + 8 * self.garbage.len());
        match &self.staging {
            Some(s) => {
                b.put_u8(1);
                b.put_u64(s.gen);
                b.put_u64(s.nonce);
                b.put_u64(s.rev);
            }
            None => b.put_u8(0),
        }
        b.put_u32(self.garbage.len() as u32);
        for g in &self.garbage {
            b.put_u64(*g);
        }
        b.into()
    }

    pub fn decode(b: &[u8]) -> anyhow::Result<ImportState> {
        let u64_at = |i: usize| -> anyhow::Result<u64> {
            Ok(u64::from_be_bytes(b.get(i..i + 8).ok_or_else(|| anyhow::anyhow!("short import state"))?.try_into()?))
        };
        let (staging, mut at) = match b.first() {
            Some(0) => (None, 1),
            Some(1) => (Some(Staging { gen: u64_at(1)?, nonce: u64_at(9)?, rev: u64_at(17)? }), 25),
            _ => anyhow::bail!("bad import state"),
        };
        let n = u32::from_be_bytes(b.get(at..at + 4).ok_or_else(|| anyhow::anyhow!("short import state"))?.try_into()?)
            as usize;
        at += 4;
        anyhow::ensure!(b.len() == at + 8 * n, "import state of {} bytes", b.len());
        let garbage = (0..n).map(|i| u64_at(at + 8 * i)).collect::<anyhow::Result<_>>()?;
        Ok(ImportState { staging, garbage })
    }

    /// The row's mutation: a delete once empty.
    pub fn mutation(&self, did: &str) -> vlsync_store::segment::Mutation {
        vlsync_store::segment::Mutation { key: import_key(did).into(), val: (!self.is_empty()).then(|| self.encode()) }
    }
}

/// The keys of one family (or a narrower prefix such as
/// [`collection_family`]) across slots, in (slot, key) order. Slot-major
/// keys interleave families, so the scan seeks from the end of one slot's
/// run to the next slot's: an empty slot costs nothing (the seek lands on
/// the next key that exists). A shard's DB holds only its own slots (a
/// projection hides the rest), so no slot bounds are needed.
pub struct FamilyScan {
    iter: slatedb::DbIterator,
    fam: Vec<u8>,
}

impl FamilyScan {
    /// `start` is a full slot-major key, inclusive; None starts at slot 0.
    pub async fn new<R: slatedb::DbReadOps + ?Sized>(
        db: &R,
        fam: &[u8],
        start: Option<Vec<u8>>,
        opts: &slatedb::config::ScanOptions,
    ) -> Result<FamilyScan, slatedb::Error> {
        let lo = start.unwrap_or_else(|| slot_family(0, fam));
        let hi = vec![SLOT_TAG + 1];
        let iter = db.scan_with_options(lo..hi, opts).await?;
        Ok(FamilyScan { iter, fam: fam.to_vec() })
    }

    pub async fn next(&mut self) -> Result<Option<slatedb::KeyValue>, slatedb::Error> {
        loop {
            let Some(kv) = self.iter.next().await? else { return Ok(None) };
            let Some(slot) = key_slot(&kv.key) else { return Ok(None) };
            let body = key_body(&kv.key);
            if body.starts_with(&self.fam) {
                return Ok(Some(kv));
            }
            // this slot's run of the family is ahead (body < fam) or done
            let target = if body < self.fam.as_slice() {
                slot_family(slot, &self.fam)
            } else if slot == u16::MAX {
                return Ok(None);
            } else {
                slot_family(slot + 1, &self.fam)
            };
            self.iter.seek(target).await?;
        }
    }
}

/// (slot, DID) order key of a slot-major `family ‖ did` key (h/, a/, L/).
pub fn slot_did(key: &[u8], fam_len: usize) -> (&[u8], &[u8]) {
    (key.get(1..SLOT_PREFIX_LEN).unwrap_or_default(), key.get(SLOT_PREFIX_LEN + fam_len..).unwrap_or_default())
}

#[derive(Clone, Debug)]
pub struct Head {
    pub commit: Cid,
    pub data: Cid,
    pub rev: Tid,
    pub commit_block: Bytes,
}

impl Head {
    pub fn encode(&self) -> Bytes {
        let mut b = Vec::with_capacity(2 * CID_BYTES_LEN + 8 + self.commit_block.len());
        b.put_slice(&self.commit.to_bytes());
        b.put_slice(&self.data.to_bytes());
        b.put_u64(self.rev.0);
        b.put_slice(&self.commit_block);
        b.into()
    }

    pub fn decode(b: &Bytes) -> anyhow::Result<Head> {
        anyhow::ensure!(b.len() >= 2 * CID_BYTES_LEN + 8, "short head");
        Ok(Head {
            commit: Cid::from_bytes(&b[..CID_BYTES_LEN])?,
            data: Cid::from_bytes(&b[CID_BYTES_LEN..2 * CID_BYTES_LEN])?,
            rev: Tid(u64::from_be_bytes(b[2 * CID_BYTES_LEN..2 * CID_BYTES_LEN + 8].try_into()?)),
            commit_block: b.slice(2 * CID_BYTES_LEN + 8..),
        })
    }
}

/// What checkAccountStatus reports about a repo's contents, maintained by
/// the repo worker with each commit (`S/{did}`) instead of walked per call
/// (`crate::repo_stats::walk` checks it).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RepoStats {
    /// `R/` rows.
    pub records: u64,
    /// MST nodes with entries, leaves included (the empty tree's root isn't one).
    pub nodes: u64,
    /// Distinct blob CIDs the records reference (`b/`).
    pub blobs: u64,
    /// None in a row written before bytes were counted: the repo's next
    /// load counts them (`crate::repo_stats::walk`).
    pub bytes: Option<RepoBytes>,
}

/// A repo's size as the console shows it: its record blocks plus its MST
/// node blocks (leaves included), what a getRepo CAR holds less the commit
/// and the CAR framing. Not the bytes the repo's rows take in the bucket
/// (keys, indexes, compression). A full count is exact; a commit keeps it
/// without reading what it replaces, so between counts it is close, not
/// exact (see `RepoBytes::commit`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RepoBytes {
    pub records: u64,
    pub nodes: u64,
}

impl RepoBytes {
    pub fn total(&self) -> u64 {
        self.records + self.nodes
    }

    /// A commit's change, from what the commit has in hand. A created
    /// record adds its size. An updated record is taken to be the size it
    /// was (the old block isn't read), and a deleted one the repo's mean
    /// record size. Nodes the commit wrote add their size; each one it
    /// replaced takes the repo's mean node size. Only for commits that
    /// change the counts: one that only updates records changes nothing. `before` is the counts
    /// before the commit; `created` the created records' bytes, `deleted`
    /// how many it deleted; `written` the bytes of the nodes it added and
    /// `gone` how many it lost.
    pub fn commit(&mut self, before: &RepoStats, created: u64, deleted: u64, written: u64, gone: u64) {
        let mean = |total: u64, n: u64| total.checked_div(n).unwrap_or(0);
        let rec_mean = mean(self.records, before.records);
        let node_mean = mean(self.nodes, before.nodes);
        self.records = (self.records + created).saturating_sub(deleted * rec_mean);
        self.nodes = (self.nodes + written).saturating_sub(gone * node_mean);
    }
}

impl RepoStats {
    pub const LEN: usize = 40;
    /// A row written before bytes were counted.
    const LEN_COUNTS: usize = 24;

    pub fn encode(&self) -> Bytes {
        let mut b = Vec::with_capacity(Self::LEN);
        b.put_u64(self.records);
        b.put_u64(self.nodes);
        b.put_u64(self.blobs);
        if let Some(by) = self.bytes {
            b.put_u64(by.records);
            b.put_u64(by.nodes);
        }
        b.into()
    }

    pub fn decode(b: &[u8]) -> anyhow::Result<RepoStats> {
        anyhow::ensure!(b.len() == Self::LEN || b.len() == Self::LEN_COUNTS, "repo stats of {} bytes", b.len());
        let at = |i: usize| u64::from_be_bytes(b[i * 8..i * 8 + 8].try_into().unwrap());
        let bytes = (b.len() == Self::LEN).then(|| RepoBytes { records: at(3), nodes: at(4) });
        Ok(RepoStats { records: at(0), nodes: at(1), blobs: at(2), bytes })
    }

    /// The counts without the bytes, which only a full count gets exact.
    pub fn counts(&self) -> (u64, u64, u64) {
        (self.records, self.nodes, self.blobs)
    }

    /// The reference's `repoBlocks`: the commit, the nodes, a block per record.
    pub fn repo_blocks(&self) -> u64 {
        1 + self.nodes + self.records
    }
}

/// cid | rev of the commit that last wrote it (getRepo/listBlobs `since`) | bytes.
pub fn record_value(cid: &Cid, rev: u64, bytes: &[u8]) -> Bytes {
    let mut b = Vec::with_capacity(CID_BYTES_LEN + 8 + bytes.len());
    b.put_slice(&cid.to_bytes());
    b.put_u64(rev);
    b.put_slice(bytes);
    b.into()
}

pub fn decode_record_value(v: &Bytes) -> anyhow::Result<(Cid, Bytes)> {
    anyhow::ensure!(v.len() >= CID_BYTES_LEN + 8, "short record value");
    Ok((Cid::from_bytes(&v[..CID_BYTES_LEN])?, v.slice(CID_BYTES_LEN + 8..)))
}

pub fn record_value_parts(v: &[u8]) -> anyhow::Result<(Cid, &[u8])> {
    anyhow::ensure!(v.len() >= CID_BYTES_LEN + 8, "short record value");
    Ok((Cid::from_bytes(&v[..CID_BYTES_LEN])?, &v[CID_BYTES_LEN + 8..]))
}

pub fn record_value_rev(v: &[u8]) -> u64 {
    v.get(CID_BYTES_LEN..CID_BYTES_LEN + 8).map(|b| u64::from_be_bytes(b.try_into().unwrap())).unwrap_or(0)
}

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct Account {
    pub did: String,
    pub handle: String,
    /// Wrapped under the KEK (`secrets::Purpose::SigningKey`, bound to this
    /// DID): rows reach the log and SSTs as-is. Unwrap through
    /// `Secrets::account_signing_key` (cached).
    pub wrapped_signing_key: String,
    /// Multibase multikey, so readers that only need the public half never unwrap.
    pub signing_pubkey: String,
    pub password_hash: String,
    pub created_at: String,
    /// None = active; otherwise "deactivated" | "takendown" | "suspended" | "deleted".
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub email_confirmed: bool,
    /// The generation the repo's rows are keyed under ([`Gen`]); an import
    /// moves it. Written only by the repo's worker, with the head.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub repo_gen: u64,
    /// Recorded before the DID document changes and cleared when the repo is
    /// re-signed with it or the rotation is abandoned; repo writes are
    /// refused meanwhile (DESIGN.md "Signing-key rotation").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_signing_key: Option<PendingSigningKey>,
    #[serde(default, flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

fn is_zero(v: &u64) -> bool {
    *v == 0
}

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PendingSigningKey {
    pub wrapped: String,
    pub pubkey: String,
}

/// As many Argon2 runs at once as there are pooled block buffers: each takes
/// ~20 ms of a core and 19 MiB, so more at once only adds memory and
/// blocking-pool threads.
static ARGON2_PERMITS: std::sync::LazyLock<tokio::sync::Semaphore> =
    std::sync::LazyLock::new(|| tokio::sync::Semaphore::new(*ARGON2_POOL_MAX));

pub const ARGON2_MAX_WAIT: std::time::Duration = std::time::Duration::from_secs(2);

/// Answer 503.
#[derive(Debug, thiserror::Error)]
#[error("password hashing is saturated; retry shortly")]
pub struct Argon2Busy;

async fn argon2_permit(wait: Option<std::time::Duration>) -> Result<tokio::sync::SemaphorePermit<'static>, Argon2Busy> {
    let acquire = ARGON2_PERMITS.acquire();
    let p = match wait {
        None => acquire.await,
        Some(w) => tokio::time::timeout(w, acquire).await.map_err(|_| Argon2Busy)?,
    };
    Ok(p.expect("the Argon2 semaphore is never closed"))
}

/// Saturates the pool until the guard drops (tests/argon2_shed.rs).
#[doc(hidden)]
pub async fn hold_all_argon2_permits() -> tokio::sync::SemaphorePermit<'static> {
    ARGON2_PERMITS.acquire_many(*ARGON2_POOL_MAX as u32).await.expect("the Argon2 semaphore is never closed")
}

/// Argon2id PHC string, OWASP baseline parameters. Waits for a permit.
pub async fn hash_password(password: &str) -> String {
    let _p = argon2_permit(None).await.expect("unbounded wait");
    let pw = password.to_string();
    tokio::task::spawn_blocking(move || hash_password_blocking(&pw)).await.expect("argon2 task")
}

/// Sheds ([`Argon2Busy`]) after [`ARGON2_MAX_WAIT`].
pub async fn try_hash_password(password: &str) -> Result<String, Argon2Busy> {
    let _p = argon2_permit(Some(ARGON2_MAX_WAIT)).await?;
    let pw = password.to_string();
    Ok(tokio::task::spawn_blocking(move || hash_password_blocking(&pw)).await.expect("argon2 task"))
}

pub fn hash_password_blocking(password: &str) -> String {
    use argon2::password_hash::{rand_core::OsRng, PasswordHasher, SaltString};
    let salt = SaltString::generate(&mut OsRng);
    PooledArgon2
        .hash_password_customized(
            password.as_bytes(),
            Some(argon2::Algorithm::Argon2id.ident()),
            Some(0x13),
            argon2_params(),
            &salt,
        )
        .expect("argon2 hash")
        .to_string()
}

/// Sheds ([`Argon2Busy`]) after [`ARGON2_MAX_WAIT`].
pub async fn try_verify_password_hash(phc: &str, password: &str) -> Result<bool, Argon2Busy> {
    let _p = argon2_permit(Some(ARGON2_MAX_WAIT)).await?;
    Ok(verify_blocking(phc, password).await)
}

async fn verify_blocking(phc: &str, password: &str) -> bool {
    let (phc, pw) = (phc.to_string(), password.to_string());
    tokio::task::spawn_blocking(move || {
        use argon2::password_hash::{PasswordHash, PasswordVerifier};
        PasswordHash::new(&phc).is_ok_and(|h| PooledArgon2.verify_password(pw.as_bytes(), &h).is_ok())
    })
    .await
    .unwrap_or(false)
}

fn argon2_params() -> argon2::Params {
    argon2::Params::new(19 * 1024, 2, 1, None).expect("argon2 params")
}

/// Argon2 with its 19 MiB of block memory reused across hashes: a fresh
/// allocation per hash is a new mapping (page faults, zeroing) and an unmap,
/// which takes the process's mmap lock on Linux. Same PHC strings as
/// `argon2::Argon2` (`PasswordVerifier` is the blanket impl over this).
struct PooledArgon2;

/// One per core, at most 16 (~300 MiB): hashing is CPU-bound.
static ARGON2_MEMORY: parking_lot::Mutex<Vec<Vec<argon2::Block>>> = parking_lot::Mutex::new(Vec::new());
static ARGON2_POOL_MAX: std::sync::LazyLock<usize> =
    std::sync::LazyLock::new(|| std::thread::available_parallelism().map_or(8, |n| n.get()).min(16));

impl argon2::password_hash::PasswordHasher for PooledArgon2 {
    type Params = argon2::Params;

    fn hash_password_customized<'a>(
        &self,
        password: &[u8],
        alg_id: Option<argon2::password_hash::Ident<'a>>,
        version: Option<argon2::password_hash::Decimal>,
        params: argon2::Params,
        salt: impl Into<argon2::password_hash::Salt<'a>>,
    ) -> argon2::password_hash::Result<argon2::password_hash::PasswordHash<'a>> {
        let algorithm = alg_id.map(argon2::Algorithm::try_from).transpose()?.unwrap_or_default();
        let version = version.map(argon2::Version::try_from).transpose()?.unwrap_or_default();
        let salt = salt.into();
        let mut salt_arr = [0u8; 64];
        let salt_bytes = salt.decode_b64(&mut salt_arr)?;
        let ctx = argon2::Argon2::new(algorithm, version, params.clone());
        let blocks = params.block_count();
        let output = argon2::password_hash::Output::init_with(
            params.output_len().unwrap_or(argon2::Params::DEFAULT_OUTPUT_LEN),
            |out| {
                let mut mem = ARGON2_MEMORY.lock().pop().unwrap_or_default();
                if mem.len() < blocks {
                    // every block is written before it is read
                    mem.resize(blocks, argon2::Block::default());
                }
                let r = ctx.hash_password_into_with_memory(password, salt_bytes, out, &mut mem[..blocks]);
                let mut pool = ARGON2_MEMORY.lock();
                if pool.len() < *ARGON2_POOL_MAX {
                    pool.push(mem);
                }
                Ok(r?)
            },
        )?;
        Ok(argon2::password_hash::PasswordHash {
            algorithm: algorithm.ident(),
            version: Some(version.into()),
            params: argon2::password_hash::ParamsString::try_from(&params)?,
            salt: Some(salt),
            hash: Some(output),
        })
    }
}

/// Stable across processes and nodes: partition assignment must agree everywhere.
pub fn did_hash(did: &str) -> u64 {
    u64::from_be_bytes(Sha256::digest(did.as_bytes())[..8].try_into().unwrap())
}

/// Deterministic, so load generators can address bulk account `i` without a lookup.
pub fn bulk_did(i: u64) -> String {
    let h = Sha256::digest(format!("vlpds-bulk:{i}").as_bytes());
    format!("did:plc:{}", &vlatproto::cid::base32_encode(&h)[..24])
}

pub fn bulk_handle(i: u64) -> String {
    format!("b{i}.bulk.vlpds.test")
}

#[cfg(test)]
mod tests {
    use super::*;
    use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};

    #[test]
    fn pooled_argon2_matches_argon2() {
        let stock = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, argon2_params());
        for (i, pw) in ["hunter2", "", "correct horse battery staple"].iter().enumerate() {
            let salt = SaltString::encode_b64(&[i as u8 + 1; 16]).unwrap();
            let a = stock.hash_password(pw.as_bytes(), &salt).unwrap().to_string();
            let b = PooledArgon2
                .hash_password_customized(
                    pw.as_bytes(),
                    Some(argon2::Algorithm::Argon2id.ident()),
                    Some(0x13),
                    argon2_params(),
                    &salt,
                )
                .unwrap()
                .to_string();
            assert_eq!(a, b);
            let mine = hash_password_blocking(pw);
            assert!(stock.verify_password(pw.as_bytes(), &PasswordHash::new(&mine).unwrap()).is_ok());
            assert!(PooledArgon2.verify_password(pw.as_bytes(), &PasswordHash::new(&a).unwrap()).is_ok());
            assert!(PooledArgon2.verify_password(b"wrong", &PasswordHash::new(&a).unwrap()).is_err());
        }
        // a hash with other parameters (e.g. made before a cost change) still verifies
        let small = argon2::Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::new(4096, 3, 1, None).unwrap(),
        );
        let salt = SaltString::encode_b64(&[9; 16]).unwrap();
        let h = small.hash_password(b"pw", &salt).unwrap().to_string();
        assert!(PooledArgon2.verify_password(b"pw", &PasswordHash::new(&h).unwrap()).is_ok());
    }

    #[tokio::test]
    async fn argon2_concurrency_is_bounded() {
        let held = ARGON2_PERMITS.acquire_many(*ARGON2_POOL_MAX as u32).await.unwrap();
        assert!(argon2_permit(Some(std::time::Duration::from_millis(20))).await.is_err());
        let phc = hash_password_blocking("pw");
        let waiting = tokio::spawn(async move {
            let _p = argon2_permit(None).await.unwrap();
            verify_blocking(&phc, "pw").await
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(!waiting.is_finished(), "verified without a permit");
        drop(held);
        assert!(waiting.await.unwrap());
    }
}
