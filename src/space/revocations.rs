//! Revoked space credentials, by (space, jti), until a time past which the
//! credential has expired anyway (the reference keeps them 3610 s: the
//! longest lifetime plus skew at both ends). Every credential check
//! consults this set.
//!
//! Cluster-wide, since a credential can read any repo hosted here: one
//! control object, `{prefix}/spaces/revocations.json`, appended with CAS on
//! its ETag and pruned at `until` as it is rewritten. It is written only
//! when something is revoked. Every node loads it before it serves a
//! credential, re-reads it every [`REFRESH_EVERY`] (a conditional GET),
//! and when the node that revoked nudges it.
//!
//! Only revocations with a stake here are stored (the caller drops the
//! rest: no credential for such a space reads anything here), each capped
//! per authority, space and audience account. One that can't be stored
//! blocks its space instead, in the object too, so the block outlives a
//! restart and reaches every node. Blocks never fail open, and escalate so
//! that a party can only hurt spaces it's behind: past [`BLOCKS_PER_AUTHORITY`]
//! spaces (or [`MAX_BLOCKED`] in all) an authority's blocks collapse into
//! one for the authority, and past [`MAX_BLOCKED_AUTHORITIES`] of those,
//! credentials of every remote authority are refused, never a local one's.
//!
//! A block lasts [`KEEP_SECS`] from when it's made (an authority's, from
//! the latest of the blocks it collapsed). That's safe: it stands for
//! revocations of credentials that existed when it was made, and each of
//! those has expired by then. A credential issued after the block isn't
//! one it stands for, so letting it through once the block ends is right.

use object_store::{GetOptions, ObjectStore, PutMode, PutOptions, PutPayload};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use vlsync_store::store::Store;

/// `SPACE_CREDENTIAL_MAX_AGE_SEC + 2 * CLOCK_SKEW_SEC` (reference
/// addRevokedSpaceCredentials).
pub const KEEP_SECS: i64 = super::token::CREDENTIAL_MAX_AGE_SECS + 2 * super::token::CLOCK_SKEW_SECS;
/// Peers are nudged on every revocation, so this only bounds staleness
/// after a lost nudge.
pub const REFRESH_EVERY: Duration = Duration::from_secs(300);
/// Until the first load succeeds (credential reads answer 503 meanwhile),
/// and after a failed re-read.
pub const RETRY_EVERY: Duration = Duration::from_secs(5);
/// Past this since the last good read (a re-read failing, a nudge lost and
/// the next re-read failing too), the set may lack a revocation: credential
/// reads answer 503 until a read succeeds.
pub const STALE_AFTER: Duration = Duration::from_secs(REFRESH_EVERY.as_secs() + 60);
const CALL_DEADLINE: Duration = Duration::from_secs(5);
const CAS_RETRIES: usize = 16;
/// The reference's jtis are 32 hex characters; a credential with a longer
/// one is refused, so every credential accepted here can be revoked.
pub const MAX_JTI_LEN: usize = 128;
/// Live entries in all. The object is read whole by every node, so it
/// stays small (~7 MB here).
pub const HARD_CAP: usize = 50_000;
/// Live entries of one authority's spaces.
pub const PER_AUTHORITY: usize = 2_000;
/// Live entries of one space.
pub const PER_SPACE: usize = 1_000;
/// Live entries one account here gave the stake for: one account and many
/// authorities can't fill the object.
pub const PER_AUD: usize = 5_000;
/// Spaces blocked at once; past this, a new one's authority is blocked.
pub const MAX_BLOCKED: usize = 10_000;
/// Spaces of one authority blocked at once; past this, the authority is.
pub const BLOCKS_PER_AUTHORITY: usize = 100;
/// Authorities blocked at once; past this, every remote authority's
/// credentials are refused (a local authority is always blocked alone).
pub const MAX_BLOCKED_AUTHORITIES: usize = 1_000;
/// Revokes waiting on this node's writes: past this they're refused at
/// once (the space blocked) rather than queued behind a flood.
pub const MAX_QUEUED: usize = 8;

/// The control object.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Doc {
    pub revoked: Vec<Entry>,
    // The new fields are left out while unset, so an object without them
    // is written as level 1 wrote it.
    /// Spaces whose revocation couldn't be stored.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blocked: Vec<Block>,
    /// Authorities with too many blocked spaces (`space` is the authority).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blocked_authorities: Vec<Block>,
    /// Every remote authority, once `blocked_authorities` is full (Unix
    /// seconds).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub remote_blocked_until: i64,
    /// Bumped by every write: a node never installs an older object over a
    /// newer one, whichever read finishes last.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub gen: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Entry {
    pub space: String,
    pub jti: String,
    /// Unix seconds.
    pub until: i64,
    /// The account here that gave the stake ([`PER_AUD`]).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub aud: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Block {
    pub space: String,
    /// Unix seconds.
    pub until: i64,
}

impl Doc {
    pub fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("serializable")
    }

    pub fn decode(b: &[u8]) -> anyhow::Result<Doc> {
        Ok(serde_json::from_slice(b)?)
    }

    /// Whether anything was past `until`.
    fn prune(&mut self, now: i64) -> bool {
        let n = (self.revoked.len(), self.blocked.len(), self.blocked_authorities.len(), self.remote_blocked_until);
        self.revoked.retain(|e| e.until > now);
        self.blocked.retain(|b| b.until > now);
        self.blocked_authorities.retain(|b| b.until > now);
        if self.remote_blocked_until <= now {
            self.remote_blocked_until = 0;
        }
        n != (self.revoked.len(), self.blocked.len(), self.blocked_authorities.len(), self.remote_blocked_until)
    }

    fn blocks(&self) -> Blocks {
        Blocks {
            spaces: self.blocked.iter().map(|b| (b.space.clone(), b.until)).collect(),
            authorities: self.blocked_authorities.iter().map(|b| (b.space.clone(), b.until)).collect(),
            remote_until: self.remote_blocked_until,
        }
    }

    fn set_blocks(&mut self, b: Blocks) {
        let list = |m: HashMap<String, i64>| {
            let mut v: Vec<Block> = m.into_iter().map(|(space, until)| Block { space, until }).collect();
            v.sort_by(|a, b| a.space.cmp(&b.space));
            v
        };
        self.blocked = list(b.spaces);
        self.blocked_authorities = list(b.authorities);
        self.remote_blocked_until = b.remote_until;
    }

    /// Each (space, jti) not held yet (one already held outlives every
    /// credential it can name).
    fn new_entries(&self, space: &str, aud: &str, jtis: &[String], until: i64) -> Vec<Entry> {
        let held: std::collections::HashSet<&str> =
            self.revoked.iter().filter(|e| e.space == space).map(|e| e.jti.as_str()).collect();
        jtis.iter()
            .filter(|j| !held.contains(j.as_str()))
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .map(|j| Entry { space: space.into(), jti: j.clone(), until, aud: aud.into() })
            .collect()
    }

    fn count(&self, f: impl Fn(&Entry) -> bool) -> usize {
        self.revoked.iter().filter(|e| f(e)).count()
    }
}

/// [`BLOCKS_PER_AUTHORITY`], [`MAX_BLOCKED`], [`MAX_BLOCKED_AUTHORITIES`];
/// tests lower them.
#[derive(Clone, Copy, Debug)]
pub struct BlockCaps {
    pub per_authority: usize,
    pub spaces: usize,
    pub authorities: usize,
}

impl Default for BlockCaps {
    fn default() -> BlockCaps {
        BlockCaps { per_authority: BLOCKS_PER_AUTHORITY, spaces: MAX_BLOCKED, authorities: MAX_BLOCKED_AUTHORITIES }
    }
}

/// Blocked spaces, authorities, and remote authorities as a whole, each
/// until a time (Unix seconds).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Blocks {
    pub spaces: HashMap<String, i64>,
    pub authorities: HashMap<String, i64>,
    pub remote_until: i64,
}

/// Whether a space's credentials are refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Blocked {
    No,
    Yes,
    /// Only if its authority isn't hosted here.
    IfRemote,
}

impl Blocks {
    fn check(&self, space: &str, now: i64) -> Blocked {
        let live = |u: Option<&i64>| u.is_some_and(|u| *u > now);
        let authority = authority_of(space).unwrap_or_default();
        if live(self.spaces.get(space)) || live(self.authorities.get(authority)) {
            Blocked::Yes
        } else if self.remote_until > now {
            Blocked::IfRemote
        } else {
            Blocked::No
        }
    }

    fn prune(&mut self, now: i64) {
        self.spaces.retain(|_, u| *u > now);
        self.authorities.retain(|_, u| *u > now);
    }

    /// Blocks `space` until `until`, escalating to its authority past the
    /// caps, and past those to every remote authority unless
    /// `local_authority`.
    fn block(&mut self, space: &str, until: i64, local_authority: bool, caps: BlockCaps) {
        let authority = authority_of(space).unwrap_or(space).to_string();
        if let Some(u) = self.authorities.get_mut(&authority) {
            *u = (*u).max(until);
            return;
        }
        if let Some(u) = self.spaces.get_mut(space) {
            *u = (*u).max(until);
            return;
        }
        let of_authority = self.spaces.keys().filter(|s| authority_of(s) == Some(&authority)).count();
        if of_authority < caps.per_authority && self.spaces.len() < caps.spaces {
            self.spaces.insert(space.to_string(), until);
            return;
        }
        let mut u = until;
        self.spaces.retain(|s, v| match authority_of(s) == Some(&authority) {
            true => {
                u = u.max(*v);
                false
            }
            false => true,
        });
        if local_authority || self.authorities.len() < caps.authorities {
            self.authorities.insert(authority, u);
        } else {
            self.remote_until = self.remote_until.max(u);
        }
    }
}

fn is_zero<T: Default + PartialEq>(n: &T) -> bool {
    *n == T::default()
}

/// A space URI's authority.
pub fn authority_of(space: &str) -> Option<&str> {
    space.strip_prefix("at://")?.split('/').next()
}

/// A jti a revocation may name: 1 to [`MAX_JTI_LEN`] printable ASCII
/// characters.
pub fn valid_jti(jti: &str) -> bool {
    (1..=MAX_JTI_LEN).contains(&jti.len()) && jti.bytes().all(|b| b.is_ascii_graphic())
}

/// Why a revocation wasn't stored. Either way the space is refused on this
/// node and its peers until it would have expired ([`Revocations::block`]).
#[derive(Debug, PartialEq, Eq)]
pub enum Refused {
    /// The authority has [`PER_AUTHORITY`] live entries.
    Authority,
    /// The space has [`PER_SPACE`].
    Space,
    /// The audience account gave the stake for [`PER_AUD`].
    Aud,
    /// The object has [`HARD_CAP`].
    Full,
    /// [`MAX_QUEUED`] revokes were waiting on this node.
    Busy,
}

impl Refused {
    pub fn as_str(&self) -> &'static str {
        match self {
            Refused::Authority => "authority",
            Refused::Space => "space",
            Refused::Aud => "aud",
            Refused::Full => "full",
            Refused::Busy => "busy",
        }
    }
}

#[derive(Debug, Default)]
pub struct Revoked {
    /// Refused, the space blocked instead (in the object when `wrote`).
    pub refused: Option<Refused>,
    /// Revocations new to this node.
    pub added: Vec<(String, String)>,
    /// The object was written (peers have something to re-read).
    pub wrote: bool,
}

pub fn path(store: &Store) -> object_store::path::Path {
    object_store::path::Path::from(format!("{}/spaces/revocations.json", store.prefix))
}

async fn bounded<T>(f: impl std::future::Future<Output = object_store::Result<T>>) -> object_store::Result<T> {
    match tokio::time::timeout(CALL_DEADLINE, f).await {
        Ok(r) => r,
        Err(_) => Err(object_store::Error::Generic { store: "revocations", source: "call timed out".into() }),
    }
}

/// (doc, etag); None when there is no object. With `etag`, NotModified if
/// the object is still that one.
async fn fetch(store: &Store, etag: Option<String>) -> object_store::Result<Option<(Doc, Option<String>)>> {
    let got = bounded(async {
        let r = store.raw.get_opts(&path(store), GetOptions { if_none_match: etag, ..Default::default() }).await?;
        let e = r.meta.e_tag.clone();
        Ok((r.bytes().await?, e))
    })
    .await;
    match got {
        Ok((b, e)) => {
            let doc = Doc::decode(&b)
                .map_err(|err| object_store::Error::Generic { store: "revocations", source: err.into() })?;
            Ok(Some((doc, e)))
        }
        Err(object_store::Error::NotFound { .. }) => Ok(None),
        Err(e) => Err(e),
    }
}

/// [`HARD_CAP`], [`PER_AUTHORITY`], [`PER_SPACE`] and [`PER_AUD`]; tests
/// lower them.
struct Caps {
    hard: std::sync::atomic::AtomicUsize,
    authority: std::sync::atomic::AtomicUsize,
    space: std::sync::atomic::AtomicUsize,
    aud: std::sync::atomic::AtomicUsize,
}

impl Default for Caps {
    fn default() -> Caps {
        Caps { hard: HARD_CAP.into(), authority: PER_AUTHORITY.into(), space: PER_SPACE.into(), aud: PER_AUD.into() }
    }
}

/// What a node enforces, from the object and its own blocks.
#[derive(Default)]
struct Installed {
    /// space -> jti -> until (Unix seconds).
    set: HashMap<String, HashMap<String, i64>>,
    blocked: Blocks,
    gen: u64,
}

#[derive(Default)]
pub struct Revocations {
    st: parking_lot::RwLock<Installed>,
    /// Of the object installed last.
    etag: parking_lot::Mutex<Option<String>>,
    loaded: AtomicBool,
    /// When a read of the object last succeeded (unix µs).
    last_ok: std::sync::atomic::AtomicU64,
    /// Blocks made here alone (a peer's nudge, or a revoke refused before
    /// it could write). Fails closed, escalating as the object's do.
    local_blocked: parking_lot::RwLock<Blocks>,
    caps: Caps,
    block_caps: parking_lot::Mutex<BlockCaps>,
    /// Appends on this node, one at a time (fewer CAS conflicts). Re-reads
    /// take their own lock, so a queue of appends never holds them up past
    /// [`STALE_AFTER`]; `Installed::gen` orders what either installs.
    writes: tokio::sync::Mutex<()>,
    reads: tokio::sync::Mutex<()>,
    queued: std::sync::atomic::AtomicUsize,
    pub(super) wake: std::sync::Arc<tokio::sync::Notify>,
    pub(super) started: AtomicBool,
}

impl Revocations {
    pub fn is_revoked(&self, space: &str, jti: &str, now: i64) -> bool {
        let g = self.st.read();
        if g.set.is_empty() {
            return false;
        }
        g.set.get(space).and_then(|j| j.get(jti)).is_some_and(|until| *until > now)
    }

    /// The live revocations of `space`: (jti, until).
    pub fn of_space(&self, space: &str, now: i64) -> Vec<(String, i64)> {
        let g = self.st.read();
        let mut out: Vec<(String, i64)> =
            g.set.get(space).into_iter().flatten().filter(|(_, u)| **u > now).map(|(j, u)| (j.clone(), *u)).collect();
        out.sort();
        out
    }

    /// Whether the control object has been read since this node started.
    pub fn loaded(&self) -> bool {
        self.loaded.load(Ordering::Acquire)
    }

    /// Loaded, and read within [`STALE_AFTER`].
    pub fn fresh(&self) -> bool {
        let age = vlatproto::tid::now_micros().saturating_sub(self.last_ok.load(Ordering::Acquire));
        self.loaded() && age < STALE_AFTER.as_micros() as u64
    }

    #[doc(hidden)]
    pub fn set_caps(&self, hard: usize, authority: usize, space: usize, aud: usize) {
        self.caps.hard.store(hard, Ordering::Relaxed);
        self.caps.authority.store(authority, Ordering::Relaxed);
        self.caps.space.store(space, Ordering::Relaxed);
        self.caps.aud.store(aud, Ordering::Relaxed);
    }

    /// Makes the last good read `by` older, as a run of failed re-reads would.
    #[doc(hidden)]
    pub fn age_last_read(&self, by: Duration) {
        self.last_ok.fetch_sub(by.as_micros() as u64, Ordering::AcqRel);
    }

    fn read_ok(&self) {
        self.last_ok.store(vlatproto::tid::now_micros(), Ordering::Release);
    }

    /// Whether `space`'s credentials are refused here.
    pub fn blocked(&self, space: &str, now: i64) -> Blocked {
        let local = self.local_blocked.read().check(space, now);
        let object = self.st.read().blocked.check(space, now);
        match (local, object) {
            (Blocked::Yes, _) | (_, Blocked::Yes) => Blocked::Yes,
            (Blocked::IfRemote, _) | (_, Blocked::IfRemote) => Blocked::IfRemote,
            _ => Blocked::No,
        }
    }

    /// Blocked outright (not only if remote).
    pub fn is_blocked(&self, space: &str, now: i64) -> bool {
        self.blocked(space, now) == Blocked::Yes
    }

    /// Whether every remote authority's credentials are refused now: the
    /// blocks are saturated (`VlpdsSpaceRevocationsSaturated`).
    pub fn saturated(&self, now: i64) -> bool {
        self.local_blocked.read().remote_until > now || self.st.read().blocked.remote_until > now
    }

    /// (spaces, authorities) blocked now, here and in the object.
    pub fn blocks(&self, now: i64) -> (usize, usize) {
        let (l, g) = (self.local_blocked.read(), self.st.read());
        let n = |a: &HashMap<String, i64>, b: &HashMap<String, i64>| {
            a.iter()
                .chain(b.iter())
                .filter(|(_, u)| **u > now)
                .map(|(k, _)| k)
                .collect::<std::collections::HashSet<_>>()
                .len()
        };
        (n(&l.spaces, &g.blocked.spaces), n(&l.authorities, &g.blocked.authorities))
    }

    #[doc(hidden)]
    pub fn set_block_caps(&self, caps: BlockCaps) {
        *self.block_caps.lock() = caps;
    }

    fn saturation_metric(&self, now: i64) {
        let (spaces, authorities) = self.blocks(now);
        crate::metrics::space_revocation_blocks(self.saturated(now), spaces, authorities);
    }

    /// Refuses `space`'s credentials here for as long as a revocation of it
    /// would have lasted, escalating as the object's blocks do.
    pub fn block(&self, space: &str, local_authority: bool, now: i64) {
        let caps = *self.block_caps.lock();
        let mut g = self.local_blocked.write();
        g.prune(now);
        g.block(space, now + KEEP_SECS, local_authority, caps);
        drop(g);
        self.saturation_metric(now);
    }

    pub fn len(&self) -> usize {
        self.st.read().set.values().map(HashMap::len).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Asks the background re-read to run now.
    pub fn wake(&self) {
        self.wake.notify_one();
    }

    /// Replaces the set with `doc`'s live entries, unless a newer object is
    /// installed already; returns those that are new to this node.
    fn install(&self, doc: &Doc, etag: Option<String>, now: i64) -> Vec<(String, String)> {
        let mut next: HashMap<String, HashMap<String, i64>> = HashMap::new();
        for e in doc.revoked.iter().filter(|e| e.until > now) {
            let u = next.entry(e.space.clone()).or_default().entry(e.jti.clone()).or_insert(e.until);
            *u = (*u).max(e.until);
        }
        let mut blocked = doc.blocks();
        blocked.prune(now);
        let mut g = self.st.write();
        if self.loaded() && doc.gen < g.gen {
            drop(g);
            self.read_ok();
            return Vec::new();
        }
        let added = next
            .iter()
            .flat_map(|(s, js)| js.keys().map(move |j| (s, j)))
            .filter(|(s, j)| !g.set.get(*s).is_some_and(|m| m.contains_key(*j)))
            .map(|(s, j)| (s.clone(), j.clone()))
            .collect();
        *g = Installed { set: next, blocked, gen: doc.gen };
        let n = g.set.values().map(HashMap::len).sum::<usize>();
        drop(g);
        self.saturation_metric(now);
        *self.etag.lock() = etag;
        self.read_ok();
        self.loaded.store(true, Ordering::Release);
        crate::metrics::space_revocations(n);
        added
    }

    /// Re-reads the object (conditional on the last ETag). Returns the
    /// revocations new to this node.
    pub async fn refresh(&self, store: &Store, now: i64) -> anyhow::Result<Vec<(String, String)>> {
        let _reads = self.reads.lock().await;
        let seen = if self.loaded() { self.etag.lock().clone() } else { None };
        match fetch(store, seen).await {
            Ok(Some((doc, etag))) => Ok(self.install(&doc, etag, now)),
            Ok(None) => Ok(self.install(&Doc::default(), None, now)),
            Err(object_store::Error::NotModified { .. }) => {
                // entries past `until` leave even when nothing was written
                let mut g = self.st.write();
                g.set.retain(|_, js| {
                    js.retain(|_, until| *until > now);
                    !js.is_empty()
                });
                g.blocked.prune(now);
                drop(g);
                self.saturation_metric(now);
                self.read_ok();
                crate::metrics::space_revocations(self.len());
                Ok(Vec::new())
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Appends `jtis` of `space` to the object (CAS), pruning expired
    /// entries as it goes, and installs the result here. `aud`: the account
    /// here whose stake let it in; `local_authority`: the space's authority
    /// is hosted here (its blocks never escalate to every remote one). Durable when this returns Ok with no
    /// `refused`; a refused one blocks the space in the object instead
    /// (`wrote`) or, with the object unwritable, Err (the caller blocks it
    /// here).
    pub async fn revoke(
        &self,
        store: &Store,
        space: &str,
        aud: &str,
        jtis: &[String],
        local_authority: bool,
        now: i64,
    ) -> anyhow::Result<Revoked> {
        struct Queued<'a>(&'a std::sync::atomic::AtomicUsize);
        impl Drop for Queued<'_> {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::AcqRel);
            }
        }
        let _q = Queued(&self.queued);
        if self.queued.fetch_add(1, Ordering::AcqRel) >= MAX_QUEUED {
            return Ok(Revoked { refused: Some(Refused::Busy), ..Default::default() });
        }
        let _writes = self.writes.lock().await;
        let until = now + KEEP_SECS;
        let authority = authority_of(space).unwrap_or_default();
        let cap = |c: &std::sync::atomic::AtomicUsize| c.load(Ordering::Relaxed);
        for _ in 0..CAS_RETRIES {
            let (mut doc, etag) = fetch(store, None).await?.unwrap_or_default();
            let pruned = doc.prune(now);
            let new = doc.new_entries(space, aud, jtis, until);
            let refused = if new.is_empty() {
                if !pruned {
                    return Ok(Revoked { added: self.install(&doc, etag, now), ..Default::default() });
                }
                None
            } else {
                let k = new.len();
                if doc.count(|e| authority_of(&e.space) == Some(authority)) + k > cap(&self.caps.authority) {
                    Some(Refused::Authority)
                } else if doc.count(|e| e.space == space) + k > cap(&self.caps.space) {
                    Some(Refused::Space)
                } else if doc.count(|e| e.aud == aud) + k > cap(&self.caps.aud) {
                    Some(Refused::Aud)
                } else if doc.revoked.len() + k > cap(&self.caps.hard) {
                    Some(Refused::Full)
                } else {
                    None
                }
            };
            match refused {
                Some(_) => {
                    let mut b = doc.blocks();
                    b.block(space, until, local_authority, *self.block_caps.lock());
                    doc.set_blocks(b);
                }
                None => doc.revoked.extend(new),
            }
            doc.gen += 1;
            let mode = match &etag {
                Some(e) => crate::cluster::if_match(Some(e.clone())),
                None => PutMode::Create,
            };
            let opts = PutOptions { mode, ..Default::default() };
            match bounded(store.raw.put_opts(&path(store), PutPayload::from(doc.encode()), opts)).await {
                Ok(r) => return Ok(Revoked { added: self.install(&doc, r.e_tag, now), wrote: true, refused }),
                // another node appended first (S3 answers an If-Match PUT
                // of a key deleted meanwhile 404)
                Err(
                    object_store::Error::Precondition { .. }
                    | object_store::Error::AlreadyExists { .. }
                    | object_store::Error::NotFound { .. },
                ) => continue,
                Err(e) => return Err(e.into()),
            }
        }
        anyhow::bail!("revocations: too much contention, try again")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn store() -> Store {
        Store { raw: Arc::new(object_store::memory::InMemory::new()), prefix: "t".into(), latency: None }
    }

    async fn revoke(r: &Revocations, s: &Store, space: &str, aud: &str, jtis: &[String], now: i64) -> Revoked {
        r.revoke(s, space, aud, jtis, false, now).await.unwrap()
    }

    #[tokio::test]
    async fn append_reload_and_prune() {
        let s = store();
        let (a, b) = (Revocations::default(), Revocations::default());
        assert!(!a.loaded() && !a.fresh());
        assert!(a.refresh(&s, 0).await.unwrap().is_empty());
        assert!(a.loaded() && a.fresh());
        let r = revoke(&a, &s, "sp", "did:aud", &["1".into(), "2".into()], 100).await;
        assert_eq!((r.added.len(), r.wrote, r.refused), (2, true, None));
        assert!(a.is_revoked("sp", "1", 100));
        assert!(!a.is_revoked("other", "1", 100), "scoped to its space");
        assert_eq!(a.of_space("sp", 100), [("1".to_string(), 100 + KEEP_SECS), ("2".to_string(), 100 + KEEP_SECS)]);
        // idempotent: nothing new, no write
        let r = revoke(&a, &s, "sp", "did:aud", &["1".into()], 100).await;
        assert!(r.added.is_empty() && !r.wrote);
        // another node: a concurrent append isn't lost
        revoke(&b, &s, "sp", "did:aud", &["3".into()], 100).await;
        let added = a.refresh(&s, 100).await.unwrap();
        assert_eq!(added, vec![("sp".to_string(), "3".to_string())]);
        assert_eq!(a.len(), 3);
        // unchanged object: a conditional re-read
        assert!(a.refresh(&s, 100).await.unwrap().is_empty());
        // past `until`: gone from the set, and pruned at the next append
        let later = 100 + KEEP_SECS;
        assert!(!a.is_revoked("sp", "1", later));
        a.refresh(&s, later).await.unwrap();
        assert!(a.is_empty());
        revoke(&a, &s, "sp", "did:aud", &["4".into()], later).await;
        let (doc, _) = fetch(&s, None).await.unwrap().unwrap();
        assert_eq!(doc.revoked.iter().map(|e| e.jti.as_str()).collect::<Vec<_>>(), ["4"]);
    }

    /// An object written before this version (no gen, no blocks, no aud)
    /// still reads.
    #[test]
    fn older_objects_decode() {
        let d = Doc::decode(br#"{"revoked":[{"space":"s","jti":"j","until":5}]}"#).unwrap();
        assert_eq!((d.gen, d.blocked.len(), d.revoked[0].aud.as_str()), (0, 0, ""));
    }

    #[test]
    fn valid_jtis() {
        assert!(valid_jti(&new_jti_like()));
        assert!(valid_jti(&"a".repeat(MAX_JTI_LEN)));
        for bad in ["", "a b", "\u{e9}", "a\n"] {
            assert!(!valid_jti(bad), "{bad:?}");
        }
        assert!(!valid_jti(&"a".repeat(MAX_JTI_LEN + 1)));
    }

    fn new_jti_like() -> String {
        crate::space::token::new_jti()
    }

    fn jtis(from: usize, n: usize) -> Vec<String> {
        (from..from + n).map(|i| format!("{i:032x}")).collect()
    }

    fn space(a: usize, k: usize) -> String {
        format!("at://did:web:a{a}.example/space/t.t/k{k}")
    }

    /// The object stays small whoever notifies: caps per authority, space
    /// and audience account, and in all. A refusal stores a block of the
    /// space instead, which every node reads, before and after a restart.
    #[tokio::test]
    async fn bounded_and_blocked_in_the_object() {
        let s = store();
        let r = Revocations::default();
        r.set_caps(400, 200, 100, 300);
        // one space, past its cap
        revoke(&r, &s, &space(0, 0), "did:x", &jtis(0, 100), 1).await;
        let x = revoke(&r, &s, &space(0, 0), "did:y", &jtis(100, 1), 1).await;
        assert_eq!((x.refused, x.wrote), (Some(Refused::Space), true));
        assert!(r.is_blocked(&space(0, 0), 1) && !r.is_blocked(&space(0, 1), 1));
        // one authority, past its cap
        revoke(&r, &s, &space(0, 1), "did:y", &jtis(0, 100), 1).await;
        let x = revoke(&r, &s, &space(0, 2), "did:z", &jtis(0, 1), 1).await;
        assert_eq!(x.refused, Some(Refused::Authority));
        // one audience account, past its cap (x has 100, y 100)
        for a in 1..=2 {
            revoke(&r, &s, &space(a, 0), "did:x", &jtis(0, 100), 1).await;
        }
        let x = revoke(&r, &s, &space(3, 0), "did:x", &jtis(0, 1), 1).await;
        assert_eq!(x.refused, Some(Refused::Aud));
        // in all
        let x = revoke(&r, &s, &space(4, 0), "did:w", &jtis(0, 100), 1).await;
        assert_eq!(x.refused, Some(Refused::Full), "{}", r.len());
        assert_eq!(r.len(), 400);
        let (doc, _) = fetch(&s, None).await.unwrap().unwrap();
        assert_eq!(doc.revoked.len(), 400);
        assert_eq!(doc.blocked.len(), 4);
        // already held: no cap applies, nothing is written
        let held = revoke(&r, &s, &space(1, 0), "did:x", &jtis(0, 1), 1).await;
        assert!(!held.wrote && held.refused.is_none());
        // another node (or this one restarted) reads the blocks
        let fresh = Revocations::default();
        fresh.refresh(&s, 1).await.unwrap();
        for b in [space(0, 0), space(0, 2), space(3, 0), space(4, 0)] {
            assert!(fresh.is_blocked(&b, 1), "{b}");
            assert!(!fresh.is_blocked(&b, 1 + KEEP_SECS), "{b}");
        }
        assert!(!fresh.is_blocked(&space(1, 0), 1));
        // past `until` the room comes back
        let x = revoke(&r, &s, &space(4, 0), "did:w", &jtis(0, 1), 1 + KEEP_SECS).await;
        assert_eq!(x.refused, None);
    }

    fn auth_space(a: &str, k: usize) -> String {
        format!("at://{a}/space/t.t/k{k}")
    }

    /// A refused revocation blocks its space; past the per-authority cap the
    /// authority (its space blocks collapsed into one); past the authority
    /// cap every remote authority, but a local authority is still blocked
    /// alone. Never fails open, and never globally for a remote party.
    #[test]
    fn blocks_escalate_space_authority_remote() {
        let caps = BlockCaps { per_authority: 3, spaces: 100, authorities: 2 };
        let mut b = Blocks::default();
        for k in 0..3 {
            b.block(&auth_space("did:web:a", k), 100 + k as i64, false, caps);
        }
        assert_eq!((b.spaces.len(), b.authorities.len()), (3, 0));
        assert_eq!(b.check(&auth_space("did:web:a", 0), 0), Blocked::Yes);
        assert_eq!(b.check(&auth_space("did:web:a", 7), 0), Blocked::No);
        // the 4th: the authority, from the latest of its blocks
        b.block(&auth_space("did:web:a", 3), 50, false, caps);
        assert_eq!((b.spaces.len(), b.authorities.get("did:web:a").copied()), (0, Some(102)));
        assert_eq!(b.check(&auth_space("did:web:a", 7), 0), Blocked::Yes);
        assert_eq!(b.check(&auth_space("did:web:b", 0), 0), Blocked::No, "only its own spaces");
        // a second authority fills the authority cap
        for k in 0..4 {
            b.block(&auth_space("did:web:b", k), 100, false, caps);
        }
        assert_eq!(b.authorities.len(), 2);
        // a third remote one: every remote authority, not local ones
        for k in 0..4 {
            b.block(&auth_space("did:web:c", k), 100, false, caps);
        }
        assert_eq!(b.remote_until, 100);
        assert_eq!(b.check(&auth_space("did:web:z", 0), 0), Blocked::IfRemote);
        assert!(b.spaces.keys().all(|s| authority_of(s) != Some("did:web:c")), "collapsed");
        // a local authority past the caps is blocked alone
        for k in 0..4 {
            b.block(&auth_space("did:plc:local", k), 100, true, caps);
        }
        assert_eq!(b.authorities.get("did:plc:local"), Some(&100));
        // the space cap in all escalates too
        let caps = BlockCaps { per_authority: 100, spaces: 2, authorities: 10 };
        let mut b = Blocks::default();
        b.block(&auth_space("did:web:a", 0), 100, false, caps);
        b.block(&auth_space("did:web:b", 0), 100, false, caps);
        b.block(&auth_space("did:web:b", 1), 100, false, caps);
        assert!(b.authorities.contains_key("did:web:b") && b.spaces.len() == 1);
    }

    /// The object's blocks escalate the same way, survive a restart, and
    /// expire [`KEEP_SECS`] after they were made.
    #[tokio::test]
    async fn object_blocks_escalate_and_expire() {
        let s = store();
        let r = Revocations::default();
        r.set_caps(1, 100, 100, 100);
        r.set_block_caps(BlockCaps { per_authority: 2, spaces: 100, authorities: 1 });
        revoke(&r, &s, &auth_space("did:web:x", 99), "did:aud", &["held".into()], 0).await;
        for k in 0..3 {
            let x = revoke(&r, &s, &auth_space("did:web:a", k), "did:aud", &["j".into()], k as i64).await;
            assert_eq!((x.refused, x.wrote), (Some(Refused::Full), true));
        }
        let (doc, _) = fetch(&s, None).await.unwrap().unwrap();
        assert_eq!((doc.blocked.len(), doc.blocked_authorities.len()), (0, 1));
        assert_eq!(doc.blocked_authorities[0].until, 2 + KEEP_SECS);
        // another remote authority past the authority cap: remote ones
        for k in 0..3 {
            revoke(&r, &s, &auth_space("did:web:b", k), "did:aud", &["j".into()], 2).await;
        }
        // a local one past it is blocked alone
        for k in 0..3 {
            r.revoke(&s, &auth_space("did:plc:local", k), "did:aud", &["j".into()], true, 2).await.unwrap();
        }
        let fresh = Revocations::default();
        fresh.refresh(&s, 2).await.unwrap();
        assert!(fresh.is_blocked(&auth_space("did:web:a", 9), 2));
        assert!(fresh.is_blocked(&auth_space("did:plc:local", 9), 2));
        assert_eq!(fresh.blocked(&auth_space("did:web:zz", 0), 2), Blocked::IfRemote);
        assert!(fresh.saturated(2));
        // a credential issued before the block stays refused until it
        // could have expired, then the block goes
        assert!(fresh.is_blocked(&auth_space("did:web:a", 0), 2 + KEEP_SECS - 1));
        assert!(!fresh.is_blocked(&auth_space("did:web:a", 0), 2 + KEEP_SECS));
        assert!(!fresh.saturated(2 + KEEP_SECS));
        fresh.refresh(&s, 2 + KEEP_SECS).await.unwrap();
        assert_eq!(fresh.blocks(2 + KEEP_SECS), (0, 0));
        // pruned from the object at the next write
        revoke(&r, &s, &auth_space("did:web:y", 0), "did:aud2", &["k".into()], 3 + KEEP_SECS).await;
        let (doc, _) = fetch(&s, None).await.unwrap().unwrap();
        assert_eq!((doc.blocked.len(), doc.blocked_authorities.len(), doc.remote_blocked_until), (0, 0, 0));
    }

    /// Blocks made here alone escalate the same way.
    #[test]
    fn local_blocks_escalate() {
        let r = Revocations::default();
        r.set_block_caps(BlockCaps { per_authority: 1, spaces: 100, authorities: 1 });
        r.block(&auth_space("did:web:a", 0), false, 10);
        r.block(&auth_space("did:web:a", 1), false, 10);
        assert!(r.is_blocked(&auth_space("did:web:a", 5), 10));
        r.block(&auth_space("did:web:b", 0), false, 10);
        r.block(&auth_space("did:web:b", 1), false, 10);
        assert_eq!(r.blocked(&auth_space("did:web:q", 0), 10), Blocked::IfRemote);
        assert!(!r.is_blocked(&auth_space("did:web:q", 0), 10));
    }

    /// Appends queued behind a slow one don't hold the re-read up (it has
    /// its own lock), and past [`MAX_QUEUED`] they're refused at once.
    #[tokio::test]
    async fn a_queue_of_appends_never_starves_the_reread() {
        let s = store();
        let r = Arc::new(Revocations::default());
        r.refresh(&s, 0).await.unwrap();
        let slow = r.writes.lock().await;
        let waiting: Vec<_> = (0..MAX_QUEUED)
            .map(|i| {
                let (r, s) = (r.clone(), s.clone());
                tokio::spawn(async move { r.revoke(&s, &space(i, 0), "did:a", &jtis(0, 1), false, 0).await.unwrap() })
            })
            .collect();
        while r.queued.load(Ordering::Acquire) < MAX_QUEUED {
            tokio::task::yield_now().await;
        }
        let t = std::time::Instant::now();
        let busy = r.revoke(&s, &space(99, 0), "did:a", &jtis(0, 1), false, 0).await.unwrap();
        assert_eq!(busy.refused, Some(Refused::Busy));
        r.age_last_read(STALE_AFTER);
        assert!(!r.fresh());
        tokio::time::timeout(Duration::from_secs(1), r.refresh(&s, 0)).await.expect("re-read not starved").unwrap();
        assert!(r.fresh() && t.elapsed() < Duration::from_secs(1));
        drop(slow);
        for w in waiting {
            assert_eq!(w.await.unwrap().refused, None);
        }
        assert_eq!(r.len(), MAX_QUEUED);
    }

    /// A slow re-read that read an older object doesn't install it over a
    /// newer one an append installed meanwhile.
    #[tokio::test]
    async fn an_older_object_never_replaces_a_newer_one() {
        let s = store();
        let r = Revocations::default();
        revoke(&r, &s, "sp", "did:a", &["1".into()], 0).await;
        let (old, e) = fetch(&s, None).await.unwrap().unwrap();
        revoke(&r, &s, "sp", "did:a", &["2".into()], 0).await;
        r.install(&old, e, 0);
        assert!(r.is_revoked("sp", "2", 0));
    }

    #[tokio::test]
    async fn stale_after_a_failed_read() {
        let s = store();
        let r = Revocations::default();
        r.refresh(&s, 0).await.unwrap();
        assert!(r.fresh());
        r.age_last_read(STALE_AFTER);
        assert!(r.loaded() && !r.fresh(), "a set not read for too long is refused");
        r.refresh(&s, 0).await.unwrap();
        assert!(r.fresh(), "a conditional re-read counts");
    }
}
