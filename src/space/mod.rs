//! AT Protocol Spaces (permissioned data), tracking the reference's alpha
//! (bluesky-social/atproto PR #5187; pinned commit in
//! testdata/spaces-alpha/SOURCE). This holds the protocol primitives only:
//! pure, no I/O, each checked against vectors from the reference.
//!
//! - [`lthash`]: the space repo's homomorphic set hash.
//! - [`commit`]: the deniable commit (ctx, MAC, signature).
//! - [`httpsig`]: the RFC 9421 subset requests carry with a delegation
//!   token or a space credential.
//! - [`token`]: delegation tokens, space credentials, client attestations.
//!
//! Serving is behind `--spaces` (`Config::spaces`), off by default; with it
//! on, a Spaces NSID without a handler answers 501 rather than reaching the
//! `atproto-proxy` fallback. The serving side:
//!
//! - [`rows`]: the values of the `s*` state families (keys in `crate::state`).
//! - [`repo`]: space writes and space host ops on the repo worker.
//! - [`heads`]: durable space repo heads for reads.
//! - [`outbox`]: delivery of notifyWrite to space authorities.
//! - [`host`]: the space host role (simplespace policies, notifyWrite).
//! - [`fanout`]: forwarding of sequenced writes to registered services.
//! - [`car`]: getRepo's streamed export.
//! - [`retention`]: pruning of oplogs past the retention window.
//! - [`attestation`]: client attestations for `appAccess` allow lists.
//! - [`revocations`]: revoked credentials.
//! - [`credcache`]: verified credentials, until they expire.

pub mod attestation;
pub mod car;
pub mod check;
pub mod commit;
pub mod credcache;
pub mod fanout;
pub mod heads;
pub mod host;
pub mod httpsig;
pub mod lthash;
pub mod outbox;
pub mod repo;
pub mod retention;
pub mod revocations;
pub mod rows;
mod sfv;
pub mod token;

use std::sync::Arc;

/// `--space-repo-max-records`: a 100k-record repo's index block is ~6 MB.
pub const DEFAULT_MAX_RECORDS: u64 = 100_000;

/// A space getRepo's pass 1 per record: its path (most are well under 64
/// bytes), end offset and CID, with room for the vectors' growth.
pub const EXPORT_RECORD_BYTES: u64 = 128;
/// Full-size space exports the memory plan holds room for at once. A
/// smaller export takes room in proportion, so only a pile-up of the
/// biggest repos waits for it.
pub const EXPORTS_PLANNED: u64 = 4;
const EXPORT_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

/// What a space getRepo of `records` records holds: pass 1 and the chunk
/// being filled.
pub fn export_bytes(records: u64) -> u64 {
    records * EXPORT_RECORD_BYTES + crate::xrpc::EXPORT_CHUNK as u64
}

/// The memory plan's room for space exports (`memory.rs` "space_exports").
pub fn export_budget_bytes(max_records: u64) -> u64 {
    EXPORTS_PLANNED * export_bytes(max_records)
}

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Records an account's repo in one space may hold.
    pub max_records: u64,
    /// How long oplog rows are kept (None: forever).
    pub oplog_retention: Option<std::time::Duration>,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits { max_records: DEFAULT_MAX_RECORDS, oplog_retention: Some(retention::DEFAULT_RETENTION) }
    }
}

/// A node's Spaces state (`App::spaces`, `Node::spaces`), with `--spaces`.
pub struct Spaces {
    pub heads: heads::Heads,
    pub outbox: Arc<outbox::Outbox>,
    pub fanout: Arc<fanout::Fanout>,
    pub revocations: revocations::Revocations,
    pub credentials: credcache::CredCache,
    pub limits: Limits,
    /// notifyWrites received from the cluster's other nodes' outboxes.
    pub peer_notifies: std::sync::atomic::AtomicU64,
    /// Account and takedown-set reads from SlateDB on this node: the caches
    /// a no-op listRepoOps poll answers from, so tests can assert that
    /// polls read nothing.
    #[doc(hidden)]
    pub cache_fills: std::sync::atomic::AtomicU64,
    /// (account, space) -> the importRepo staging it on this node. Not
    /// with the worker's state, which can be evicted mid-import.
    imports: parking_lot::Mutex<std::collections::HashMap<(String, crate::state::SpaceId), u64>>,
    /// importRepo calls running on this node, per account, from before the
    /// body is read ([`Spaces::import_slot`]).
    importing: parking_lot::Mutex<std::collections::HashMap<String, usize>>,
    /// (live spaces per authority account, live notify registrations per
    /// authority account); tests lower them.
    account_caps: parking_lot::Mutex<(usize, usize)>,
    /// registerNotify's count-and-write, per space (striped).
    registering: [tokio::sync::Mutex<()>; 64],
    /// Authorities whose shard's owner (another node) said the cluster
    /// doesn't host them, and when: their notifies go out over HTTP without
    /// asking it again on every send.
    not_hosted: parking_lot::Mutex<std::collections::HashMap<String, std::time::Instant>>,
    /// (writer, space) -> when its same-rev notifies were checked, within
    /// [`SAME_REV_WINDOW`].
    same_rev: parking_lot::Mutex<std::collections::HashMap<(String, crate::state::SpaceId), Vec<std::time::Instant>>>,
    /// [`export_budget_bytes`] in KiB, which space exports reserve from.
    exports: Arc<tokio::sync::Semaphore>,
    export_kib: u32,
}

/// Live spaces one account governs. Each fans out to its own registrations,
/// so their number bounds what one account's writes send.
pub const MAX_SPACES_PER_ACCOUNT: usize = 1000;

/// importRepo calls one account runs at once on a node: a move brings its
/// spaces in one after another.
pub const IMPORTS_PER_ACCOUNT: usize = 2;
/// importRepo calls a node runs at once. Each also reserves its working set
/// from the import budget; this bounds the PLC and DID lookups besides.
pub const IMPORTS_RUNNING: usize = 8;

/// An importRepo's slot ([`Spaces::import_slot`]), given back on drop.
pub struct ImportSlot<'a> {
    sp: &'a Spaces,
    did: String,
}

impl Drop for ImportSlot<'_> {
    fn drop(&mut self) {
        let mut m = self.sp.importing.lock();
        if let Some(n) = m.get_mut(&self.did) {
            *n -= 1;
            if *n == 0 {
                m.remove(&self.did);
            }
        }
    }
}

/// An authority that moves into the cluster within this is still told
/// over HTTP (its DID document then names this cluster), which works, just
/// with one more hop.
const NOT_HOSTED_TTL: std::time::Duration = std::time::Duration::from_secs(300);
const NOT_HOSTED_MAX: usize = 4096;

/// Same-rev notifies (a record takedown or its reversal at the writer's
/// host) checked per (writer, space) and window: real ones are a moderator's
/// actions, a handful a day.
pub const SAME_REV_PER_WINDOW: usize = 3;
pub const SAME_REV_WINDOW: std::time::Duration = std::time::Duration::from_secs(600);
/// ~200 B each. Full of live budgets, a new pair is refused rather than any
/// budget forgotten: refusing costs a real one a poll's delay.
const SAME_REV_MAX: usize = 16_384;

const RESCAN_RETRY: std::time::Duration = std::time::Duration::from_secs(1);
const RESCAN_RETRY_MAX: std::time::Duration = std::time::Duration::from_secs(60);

fn now_secs() -> i64 {
    vlatproto::tid::now_micros() as i64 / 1_000_000
}

impl Spaces {
    pub fn new(limits: Limits) -> Spaces {
        let export_kib = export_budget_bytes(limits.max_records).div_ceil(1024).min(u32::MAX as u64) as u32;
        Spaces {
            exports: Arc::new(tokio::sync::Semaphore::new(export_kib as usize)),
            export_kib,
            limits,
            peer_notifies: Default::default(),
            cache_fills: Default::default(),
            imports: Default::default(),
            importing: Default::default(),
            account_caps: parking_lot::Mutex::new((MAX_SPACES_PER_ACCOUNT, host::MAX_REGISTRATIONS_PER_AUTHORITY)),
            registering: std::array::from_fn(|_| Default::default()),
            not_hosted: Default::default(),
            same_rev: Default::default(),
            heads: heads::Heads::new(heads::DEFAULT_HEADS_BYTES),
            outbox: Default::default(),
            fanout: Arc::new(fanout::Fanout::new(fanout::QUEUE, fanout::RETRY_BASE)),
            revocations: Default::default(),
            credentials: credcache::CredCache::new(credcache::DEFAULT_ENTRIES),
        }
    }

    /// One of the node's `node_cap` importRepo slots (at most
    /// [`IMPORTS_RUNNING`]), and one of `did`'s [`IMPORTS_PER_ACCOUNT`];
    /// Err(true) when the account's are taken, Err(false) when the node's
    /// are.
    pub fn import_slot(&self, did: &str, node_cap: usize) -> Result<ImportSlot<'_>, bool> {
        let mut m = self.importing.lock();
        if m.get(did).is_some_and(|n| *n >= IMPORTS_PER_ACCOUNT) {
            return Err(true);
        }
        if m.values().sum::<usize>() >= node_cap.clamp(1, IMPORTS_RUNNING) {
            return Err(false);
        }
        *m.entry(did.to_string()).or_default() += 1;
        Ok(ImportSlot { sp: self, did: did.to_string() })
    }

    /// Tests: the importRepo slots `did` holds now.
    #[doc(hidden)]
    pub fn imports_running(&self, did: &str) -> usize {
        self.importing.lock().get(did).copied().unwrap_or(0)
    }

    /// (live spaces per authority account, live notify registrations per
    /// authority account).
    pub fn account_caps(&self) -> (usize, usize) {
        *self.account_caps.lock()
    }

    #[doc(hidden)]
    pub fn set_account_caps(&self, spaces: usize, registrations: usize) {
        *self.account_caps.lock() = (spaces, registrations);
    }

    /// Room for `bytes` of a space export, waited for up to 10 s.
    pub async fn reserve_export(&self, bytes: u64) -> Option<tokio::sync::OwnedSemaphorePermit> {
        let kib = bytes.div_ceil(1024).clamp(1, self.export_kib as u64) as u32;
        let wait = self.exports.clone().acquire_many_owned(kib);
        tokio::time::timeout(EXPORT_WAIT, wait).await.ok()?.ok()
    }

    /// Tests: KiB of the export room free now.
    pub fn export_room_free(&self) -> (usize, usize) {
        (self.exports.available_permits(), self.export_kib as usize)
    }

    /// Whether a peer said lately that the cluster doesn't host `authority`.
    pub fn known_not_hosted(&self, authority: &str) -> bool {
        self.not_hosted.lock().get(authority).is_some_and(|at| at.elapsed() < NOT_HOSTED_TTL)
    }

    pub fn mark_not_hosted(&self, authority: &str) {
        let mut m = self.not_hosted.lock();
        if m.len() >= NOT_HOSTED_MAX && !m.contains_key(authority) {
            m.retain(|_, at| at.elapsed() < NOT_HOSTED_TTL);
            if m.len() >= NOT_HOSTED_MAX {
                m.clear();
            }
        }
        m.insert(authority.to_string(), std::time::Instant::now());
    }

    /// Takes one of `writer`'s same-rev checks in `sid`: false once
    /// [`SAME_REV_PER_WINDOW`] were taken in the last [`SAME_REV_WINDOW`].
    pub fn same_rev_budget(&self, writer: &str, sid: crate::state::SpaceId) -> bool {
        let now = std::time::Instant::now();
        let live = |at: &std::time::Instant| now.duration_since(*at) < SAME_REV_WINDOW;
        let mut m = self.same_rev.lock();
        let key = (writer.to_string(), sid);
        if m.len() >= SAME_REV_MAX && !m.contains_key(&key) {
            m.retain(|_, ats| ats.iter().any(live));
            if m.len() >= SAME_REV_MAX {
                return false;
            }
        }
        let ats = m.entry(key).or_default();
        ats.retain(live);
        if ats.len() >= SAME_REV_PER_WINDOW {
            return false;
        }
        ats.push(now);
        true
    }

    /// Re-reads the revocations object; cached credentials it newly
    /// revokes are dropped.
    pub async fn refresh_revocations(&self, store: &vlsync_store::store::Store) -> anyhow::Result<()> {
        let added = self.revocations.refresh(store, now_secs()).await?;
        self.credentials.invalidate(&added);
        Ok(())
    }

    /// Revokes `jtis` of `space` cluster-wide (durable on Ok(Ok); peers
    /// learn of it by a nudge or their next re-read), on the stake of `aud`,
    /// an account here. One that can't be stored blocks the space in the
    /// object, or here alone when it wasn't written (Err((refused, false)):
    /// peers need telling). On Err (the store failed, or CAS ran out) the
    /// space is blocked here too, and the caller tells the peers.
    /// Ok(Ok(true)): the object was written.
    pub async fn revoke(
        &self,
        store: &vlsync_store::store::Store,
        space: &str,
        aud: &str,
        jtis: &[String],
        local_authority: bool,
    ) -> anyhow::Result<Result<bool, (revocations::Refused, bool)>> {
        let now = now_secs();
        let r = match self.revocations.revoke(store, space, aud, jtis, local_authority, now).await {
            Ok(r) => r,
            Err(e) => {
                self.revocations.block(space, local_authority, now);
                return Err(e);
            }
        };
        self.credentials.invalidate(&r.added);
        match r.refused {
            None => Ok(Ok(r.wrote)),
            Some(refused) => {
                if !r.wrote {
                    self.revocations.block(space, local_authority, now);
                }
                Ok(Err((refused, r.wrote)))
            }
        }
    }

    /// Loads the revocations (credential reads answer 503 until a load
    /// succeeds), then keeps them fresh in the background: every
    /// [`revocations::REFRESH_EVERY`], or at once when woken by a peer.
    pub async fn start_revocations(self: &Arc<Self>, store: vlsync_store::store::Store) {
        if self.revocations.started.swap(true, std::sync::atomic::Ordering::AcqRel) {
            return;
        }
        let mut ok = match self.refresh_revocations(&store).await {
            Ok(()) => true,
            Err(e) => {
                tracing::warn!("space revocations unreadable (credential reads wait for them): {e:#}");
                false
            }
        };
        let weak = Arc::downgrade(self);
        tokio::spawn(async move {
            loop {
                let wait = if ok { revocations::REFRESH_EVERY } else { revocations::RETRY_EVERY };
                let Some(wake) = weak.upgrade().map(|me| me.revocations.wake.clone()) else { return };
                let _ = tokio::time::timeout(wait, wake.notified()).await;
                let Some(me) = weak.upgrade() else { return };
                ok = match me.refresh_revocations(&store).await {
                    Ok(()) => true,
                    Err(e) => {
                        tracing::warn!("space revocations re-read failed (retrying): {e:#}");
                        false
                    }
                };
            }
        });
    }

    pub async fn registering(&self, sid: &crate::state::SpaceId) -> tokio::sync::MutexGuard<'_, ()> {
        self.registering[sid[0] as usize % self.registering.len()].lock().await
    }

    /// Claims (did, sid) for import `nonce`; false if another holds it.
    pub fn begin_import(&self, did: &str, sid: crate::state::SpaceId, nonce: u64) -> bool {
        let mut m = self.imports.lock();
        match m.entry((did.to_string(), sid)) {
            std::collections::hash_map::Entry::Occupied(_) => false,
            std::collections::hash_map::Entry::Vacant(v) => {
                v.insert(nonce);
                true
            }
        }
    }

    pub fn import_nonce(&self, did: &str, sid: crate::state::SpaceId) -> Option<u64> {
        self.imports.lock().get(&(did.to_string(), sid)).copied()
    }

    pub fn end_import(&self, did: &str, sid: crate::state::SpaceId, nonce: u64) {
        let mut m = self.imports.lock();
        if m.get(&(did.to_string(), sid)) == Some(&nonce) {
            m.remove(&(did.to_string(), sid));
        }
    }

    /// A space `did` governed is deleted: its own repo there is gone.
    pub fn forget_space(&self, did: &str, sid: &crate::state::SpaceId) {
        self.heads.drop_space(did, sid);
    }

    /// An account deleted: nothing of it is served or sent any more.
    pub fn forget_account(&self, did: &str) {
        self.heads.drop_did(did);
        self.outbox.drop_did(did);
    }

    /// Enqueues the `sP` rows of shards just opened (a start, a takeover, a
    /// handback, a split's children; with `overflow`, the owned shards
    /// again for rows the full outbox left behind): notifies this node now
    /// owes. In the background, each shard retried with backoff until it
    /// scans or isn't this node's any more, since nothing else would ever
    /// send its rows; a row found twice is enqueued once.
    pub fn spawn_outbox_rescan(
        self: Arc<Self>,
        table: std::sync::Weak<crate::partitions::PartitionTable>,
        shards: Vec<(vlsync_store::slots::ShardId, Arc<slatedb::Db>)>,
        overflow: bool,
    ) {
        if shards.is_empty() {
            return;
        }
        // the lease epoch, while `db` is still the shard's
        let owned = move |shard: vlsync_store::slots::ShardId, db: &Arc<slatedb::Db>| {
            table.upgrade().and_then(|t| t.get(shard)).filter(|p| Arc::ptr_eq(&p.db, db)).map(|p| p.epoch)
        };
        tokio::spawn(async move {
            for (shard, db) in shards {
                let mut wait = RESCAN_RETRY;
                loop {
                    let r = self.rescan_outbox(&db).await;
                    let r = match r {
                        Ok(n) if overflow => Ok((n, 0)),
                        Ok(n) => match owned(shard, &db) {
                            Some(epoch) => self.catch_up_registrations(&db, epoch).await.map(|c| (n, c)),
                            None => Ok((n, 0)),
                        },
                        Err(e) => Err(e),
                    };
                    match r {
                        Ok((n, c)) => {
                            if n > 0 {
                                tracing::info!(shard = shard.0, rows = n, "space notify outbox resumed");
                            }
                            if c > 0 {
                                tracing::info!(shard = shard.0, spaces = c, "space syncers sent a catch-up notify");
                            }
                            break;
                        }
                        Err(e) if owned(shard, &db).is_some() => {
                            tracing::warn!(shard = shard.0, "space notify outbox rescan failed (retrying): {e:#}");
                            tokio::time::sleep(wait).await;
                            wait = (wait * 2).min(RESCAN_RETRY_MAX);
                        }
                        Err(e) => {
                            tracing::info!(shard = shard.0, "space notify outbox rescan stopped (shard gone): {e:#}");
                            break;
                        }
                    }
                }
            }
        });
    }

    /// Fan-out lanes live in memory, so a forward queued on the shard's
    /// last owner may be gone. Each space of the shard with a live
    /// registration gets one forward of its newest sequenced writer, naming
    /// the spaceRev sequenced just before it (`sQ` keeps it: the row that
    /// held it may be gone, and the row before isn't always it): a syncer
    /// that's current ignores it, one that missed something sees the gap
    /// and pulls listRepos. Once per shard open, nothing in steady state.
    async fn catch_up_registrations(&self, db: &slatedb::Db, epoch: u64) -> anyhow::Result<usize> {
        use crate::state::{self, SpaceId};
        let opts = slatedb::config::ScanOptions::default();
        let mut scan = state::FamilyScan::new(db, state::SPACE_NOTIFY_FAMILY, None, &opts).await?;
        let now = vlatproto::tid::now_micros();
        let mut spaces: Vec<(String, SpaceId)> = Vec::new();
        while let Some(kv) = scan.next().await? {
            let Some((did, sid)) = rows::did_sid_head(&kv.key) else { continue };
            if rows::NotifyRow::decode(&kv.value)?.expires <= now {
                continue;
            }
            if spaces.last().is_none_or(|(d, s)| d != did || *s != sid) {
                spaces.push((did.to_string(), sid));
            }
        }
        drop(scan);
        let mut sent = 0;
        for (authority, sid) in spaces {
            let Some(v) = db.get(state::space_key(&authority, &sid)).await? else { continue };
            let space = rows::SpaceRow::decode(&v)?;
            if !space.live() {
                continue;
            }
            let prefix = state::space_prefix(state::SPACE_SEQ_FAMILY, &authority, &sid);
            let desc = slatedb::config::ScanOptions::default().with_order(slatedb::IterationOrder::Descending);
            let mut it = db.scan_with_options(prefix.clone()..vlsync_store::keys::prefix_end(&prefix), &desc).await?;
            let Some(last) = it.next().await? else { continue };
            let Some(space_rev) = rows::seq_rev(&last.key) else { continue };
            let rows::SeqRow { prev, writer } = rows::SeqRow::decode(&last.value)?;
            let Some(w) = db.get(state::space_writer_key(&authority, &sid, &writer)).await? else { continue };
            let w = rows::WriterRow::decode(&w)?;
            self.fanout.notify(fanout::Job {
                authority: authority.into(),
                uri: space.uri.as_str().into(),
                sid,
                writer,
                repo_rev: w.repo_rev,
                hash: w.hash,
                seq: repo::Sequenced { space_rev, prev },
                epoch,
            });
            sent += 1;
        }
        Ok(sent)
    }

    /// A row that doesn't decode is skipped (and logged), not the shard.
    async fn rescan_outbox(&self, db: &slatedb::Db) -> anyhow::Result<usize> {
        let opts = slatedb::config::ScanOptions::default();
        let mut scan = crate::state::FamilyScan::new(db, crate::state::SPACE_OUTBOX_FAMILY, None, &opts).await?;
        let (mut n, mut bad) = (0, 0);
        while let Some(kv) = scan.next().await? {
            let Some((did, sid)) = rows::did_sid(&kv.key) else { continue };
            match rows::OutboxRow::decode(&kv.value) {
                Ok(row) if crate::state::space_id(&row.uri) == sid => {
                    self.outbox.enqueue(did, sid, &row.uri, row.repo_rev, row.hash, false);
                    n += 1;
                }
                _ => bad += 1,
            }
        }
        if bad > 0 {
            tracing::warn!(bad, "space notify outbox rows skipped: undecodable or naming another space");
        }
        Ok(n)
    }
}

impl Default for Spaces {
    fn default() -> Self {
        Spaces::new(Limits::default())
    }
}

/// The XRPC methods of the Spaces lexicons. NSID authorities are
/// case-insensitive, as the proxy's method lists match them.
pub fn is_space_nsid(nsid: &str) -> bool {
    ["com.atproto.space.", "com.atproto.simplespace."]
        .iter()
        .any(|p| nsid.get(..p.len()).is_some_and(|h| h.eq_ignore_ascii_case(p)))
}

/// A did:key's JWT `alg` (@atproto/crypto `parseDidKey`): ES256K for
/// secp256k1, ES256 for P-256.
pub fn did_key_alg(did_key: &str) -> Option<&'static str> {
    let raw = bs58::decode(did_key.strip_prefix("did:key:z")?).into_vec().ok()?;
    match raw.as_slice() {
        [0xe7, 0x01, ..] => Some("ES256K"),
        [0x80, 0x24, ..] => Some("ES256"),
        _ => None,
    }
}

/// A compact (r‖s, 64-byte) ECDSA signature over sha256(msg) by `did_key`;
/// DER is refused. High-S only with `allow_high_s` (@atproto/crypto
/// `allowMalleableSig`). Err: not a usable did:key or signature encoding.
fn verify_did_key(did_key: &str, msg: &[u8], sig: &[u8], allow_high_s: bool) -> Result<bool, String> {
    if sig.len() != 64 {
        return Err("signature must be 64 bytes".into());
    }
    let multibase = did_key.strip_prefix("did:key:").ok_or("not a did:key")?;
    // libsecp256k1 also parses hybrid (0x06/0x07) points; the reference doesn't
    let raw = bs58::decode(multibase.strip_prefix('z').ok_or("unsupported multibase")?)
        .into_vec()
        .map_err(|e| e.to_string())?;
    let key = raw.get(2..).unwrap_or_default();
    if !matches!((key.len(), key.first()), (33, Some(2 | 3)) | (65, Some(4))) {
        return Err("unsupported public key encoding".into());
    }
    if allow_high_s {
        crate::oauth::lexicon::verify_sig_malleable(multibase, msg, sig)
    } else {
        crate::oauth::lexicon::verify_sig(multibase, msg, sig)
    }
}

#[cfg(test)]
pub(crate) mod vectors {
    use std::sync::LazyLock;

    pub static VECTORS: LazyLock<serde_json::Value> = LazyLock::new(|| {
        serde_json::from_str(include_str!("../../testdata/spaces-alpha/vectors.json")).expect("vectors.json")
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A revoke the store can't take (here an unreadable object) blocks the
    /// space here rather than leaving its credentials readable.
    #[tokio::test]
    async fn a_failed_revoke_blocks_the_space() {
        let store = vlsync_store::store::Store {
            raw: Arc::new(object_store::memory::InMemory::new()),
            prefix: "t".into(),
            latency: None,
        };
        let bad = object_store::PutPayload::from(b"not json".to_vec());
        store.raw.put_opts(&revocations::path(&store), bad, Default::default()).await.unwrap();
        let sp = Spaces::new(Limits::default());
        let space = "at://did:web:a.example/space/t.t/k";
        assert!(sp.revoke(&store, space, "did:aud", &["j".into()], false).await.is_err());
        assert!(sp.revocations.is_blocked(space, now_secs()));
        assert!(!sp.revocations.is_blocked("at://did:web:a.example/space/t.t/other", now_secs()));
    }

    /// Two importRepo slots per account and eight per node, given back on
    /// drop.
    #[test]
    fn import_slots_cap_accounts_and_the_node() {
        let sp = Spaces::new(Limits::default());
        let a1 = sp.import_slot("did:a", 8).unwrap();
        let _a2 = sp.import_slot("did:a", 8).unwrap();
        assert!(matches!(sp.import_slot("did:a", 8), Err(true)));
        drop(a1);
        let a3 = sp.import_slot("did:a", 8).unwrap();
        let others: Vec<_> = (0..6).map(|i| sp.import_slot(&format!("did:o{i}"), 8).unwrap()).collect();
        assert!(matches!(sp.import_slot("did:new", 8), Err(false)));
        drop(a3);
        let _n = sp.import_slot("did:new", 8).unwrap();
        drop(others);
        assert_eq!(sp.importing.lock().len(), 2);
        // a smaller node cap (a small import budget)
        assert!(matches!(sp.import_slot("did:x", 2), Err(false)));
        assert!(sp.import_slot("did:x", 3).is_ok());
    }

    #[test]
    fn space_nsids() {
        for yes in ["com.atproto.space.getRecord", "com.atproto.simplespace.createSpace", "COM.ATPROTO.Space.x"] {
            assert!(is_space_nsid(yes), "{yes}");
        }
        for no in ["com.atproto.repo.getRecord", "com.atproto.spaces.x", "com.atproto.space", "app.bsky.space.x", ""] {
            assert!(!is_space_nsid(no), "{no}");
        }
    }

    #[test]
    fn same_rev_budget_per_writer_and_space() {
        let sp = Spaces::new(Limits::default());
        let (a, b) = (crate::state::space_id("at://a"), crate::state::space_id("at://b"));
        for _ in 0..SAME_REV_PER_WINDOW {
            assert!(sp.same_rev_budget("did:plc:w", a));
        }
        assert!(!sp.same_rev_budget("did:plc:w", a));
        assert!(sp.same_rev_budget("did:plc:w", b), "another space has its own");
        assert!(sp.same_rev_budget("did:plc:x", a), "another writer has its own");
        let old = std::time::Instant::now() - SAME_REV_WINDOW;
        sp.same_rev.lock().get_mut(&("did:plc:w".to_string(), a)).unwrap().iter_mut().for_each(|t| *t = old);
        assert!(sp.same_rev_budget("did:plc:w", a), "the window passed");
        // full of live budgets: a new pair is refused, none forgotten
        let mut m = sp.same_rev.lock();
        let now = std::time::Instant::now();
        for i in m.len()..SAME_REV_MAX {
            m.insert((format!("did:plc:{i}"), a), vec![now]);
        }
        drop(m);
        assert!(!sp.same_rev_budget("did:plc:new", a));
        assert!(sp.same_rev_budget("did:plc:x", a), "a pair held keeps its budget");
        assert_eq!(sp.same_rev.lock().len(), SAME_REV_MAX);
    }

    #[test]
    fn did_key_algs() {
        let k256 = vlatproto::crypto::Keypair::generate().did_key();
        assert_eq!(did_key_alg(&k256), Some("ES256K"));
        let p256 = vectors::VECTORS["httpsig"][0]["keyDid"].as_str().unwrap();
        assert_eq!(did_key_alg(p256), Some("ES256"));
        assert_eq!(did_key_alg("did:key:zQ3"), None);
        assert_eq!(did_key_alg("did:plc:abc"), None);
        assert!(verify_did_key("did:plc:abc", b"x", &[0; 64], false).is_err());
        assert!(verify_did_key(&k256, b"x", &[0; 70], false).is_err());
        // a hybrid-encoded point (0x06/0x07 prefix) of a real key
        let key = vlatproto::crypto::Keypair::generate();
        let sig = key.sign(b"x");
        let pk = secp256k1::PublicKey::from_slice(&key.public_key_sec1()).unwrap().serialize_uncompressed();
        let mut hybrid = vec![0xe7, 0x01, 6 | (pk[64] & 1)];
        hybrid.extend_from_slice(&pk[1..]);
        let hybrid = format!("did:key:z{}", bs58::encode(hybrid).into_string());
        assert!(
            crate::oauth::lexicon::verify_sig(hybrid.strip_prefix("did:key:").unwrap(), b"x", &sig).is_ok_and(|v| v)
        );
        assert!(verify_did_key(&hybrid, b"x", &sig, false).is_err());
        assert_eq!(verify_did_key(&key.did_key(), b"x", &sig, false), Ok(true));
    }
}
