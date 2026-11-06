//! `vlpds.space.importRepo` (`--spaces`; DESIGN.md "Spaces", Q8): an
//! account moving in brings its repo in a space as the STAR archive its old
//! host's space.getRepo serves. There's no upstream import yet; this
//! follows the plan's proposal and changes when the upstream contract
//! settles.
//!
//! It takes a `space:` grant like every space write (OAuth, or a scoped app
//! password), so an account moving in imports once it's active here, after
//! its DID points here. The archive's commit
//! must name the account and the space; a commit carries no signature, so
//! what's checked is that the records are the repo it describes: they
//! stream in (paths in order, each record's CID computed from its bytes)
//! and are staged in bounded frameless entries, folded into a set hash
//! that must be the commit's `data` at the end. A final entry on the repo's
//! worker then switches the head in at the commit's rev. The oplog stays
//! empty (the spec lets a host drop ops: a syncer falls back to getRepo),
//! and the authority is owed a notify like any write.
//!
//! An import over a repo that's there replaces it, as the public importRepo
//! does: the claim's entry takes the old head away, the old rows are swept
//! in bounded batches, and the new head goes in at the end. The worker
//! refuses the account's writes to the space, and other imports of it,
//! while it imports (`Spaces::begin_import`). An import stopped part way
//! (or whose records don't match its commit) leaves staged rows no head
//! names, which no read serves; they're cleared, and the next import of
//! the space deletes any left first.
//!
//! What a body can cost is bounded before any of it is read: the grant,
//! the account's rate limit and slots, and a reservation from the import
//! budget are taken first, and every frame is capped from its length.

use super::repo::check_path;
use super::space::{spaces, submit_space, Space};
use super::*;
use crate::oauth::scopes::SpaceAccess;
use crate::space::repo::{SpaceAck, SpaceError, SpaceOp};
use crate::space::star;
use vlatproto::tid::Tid;

pub fn routes() -> Router<Arc<App>> {
    Router::new().route("/xrpc/vlpds.space.importRepo", post(import_repo))
}

/// Rows per staged entry, or fewer at [`BATCH_BYTES`].
const BATCH_ROWS: usize = 1000;
const BATCH_BYTES: usize = 4 << 20;
/// The metadata, a commit (~200 bytes) with its `$type`.
const MAX_META: usize = 4 << 10;
/// A record path: an NSID and a record key.
const MAX_PATH: usize = 1 << 10;
/// What an import holds besides its frames: tasks, the reader, the claim.
const FIXED: u64 = 256 << 10;

/// What an import of a `declared`-byte body (None: unknown) holds at most:
/// a record twice (the reader's buffer and its copy), and a staged batch
/// with its rows' keys while the next one fills. Every frame is capped
/// before it's buffered, and a body declared smaller caps them more.
fn working_set(declared: Option<u64>) -> u64 {
    let body = declared.unwrap_or(u64::MAX);
    let record = (star::MAX_RECORD_SIZE as u64).min(body);
    let batch = (BATCH_BYTES as u64).min(body) + BATCH_ROWS as u64 * 400;
    FIXED + 2 * record + 2 * batch
}

fn bad(error: &str, m: impl Into<String>) -> XrpcError {
    XrpcError::bad(error, m)
}

fn invalid(m: impl Into<String>) -> XrpcError {
    bad("InvalidRequest", m)
}

/// A STAR archive read frame by frame as the body arrives.
struct StarReader {
    body: super::import_stream::TimedBody,
    buf: Vec<u8>,
    pos: usize,
    total: usize,
    max: usize,
    eof: bool,
}

impl StarReader {
    fn new(body: super::import_stream::TimedBody, max: usize) -> StarReader {
        StarReader { body, buf: Vec::new(), pos: 0, total: 0, max, eof: false }
    }

    /// Whether `n` unread bytes are buffered, reading more as needed.
    async fn fill(&mut self, n: usize) -> XResult<bool> {
        while self.buf.len() - self.pos < n {
            if self.eof {
                return Ok(false);
            }
            if self.pos > 0 && self.pos * 2 >= self.buf.len() {
                self.buf.drain(..self.pos);
                self.pos = 0;
            }
            match self.body.next().await {
                Some(Ok(chunk)) => {
                    self.total += chunk.len();
                    if self.total > self.max {
                        return Err(super::import_stream::too_large(self.max));
                    }
                    self.buf.extend_from_slice(&chunk);
                }
                Some(Err(e)) => return Err(e),
                None => self.eof = true,
            }
        }
        Ok(true)
    }

    async fn magic(&mut self) -> XResult<()> {
        if !self.fill(star::MAGIC.len()).await? || self.buf[self.pos..self.pos + 4] != star::MAGIC {
            return Err(invalid("invalid STAR archive: invalid magic bytes"));
        }
        self.pos += star::MAGIC.len();
        Ok(())
    }

    /// The next length-prefixed frame, None at the end (which only a pair
    /// boundary may be). One longer than `max` is refused from its length,
    /// before any of it is buffered.
    async fn frame(&mut self, max: usize, what: &str) -> XResult<Option<Vec<u8>>> {
        if !self.fill(1).await? {
            return Ok(None);
        }
        let (len, n) = loop {
            match star::read_varint(&self.buf[self.pos..]) {
                Ok(Some(v)) => break v,
                Ok(None) => {}
                Err(e) => return Err(invalid(format!("invalid STAR archive: {e}"))),
            }
            let have = self.buf.len() - self.pos;
            if !self.fill(have + 1).await? {
                return Err(invalid("invalid STAR archive: unexpected end of archive"));
            }
        };
        if len > max as u64 {
            return Err(invalid(format!("invalid STAR archive: the {what} is over {max} bytes")));
        }
        self.pos += n;
        if !self.fill(len as usize).await? {
            return Err(invalid("invalid STAR archive: unexpected end of archive"));
        }
        let out = self.buf[self.pos..self.pos + len as usize].to_vec();
        self.pos += len as usize;
        Ok(Some(out))
    }
}

/// A record's blob refs, once its size and encoding are checked.
fn record_blobs(path: &str, bytes: &[u8]) -> XResult<Vec<Cid>> {
    if bytes.len() > star::MAX_RECORD_SIZE {
        return Err(invalid(format!("record at '{path}' too large ({} bytes)", bytes.len())));
    }
    vlatproto::cbor::scan_blob_refs(bytes).map_err(|_| invalid(format!("Could not parse record at '{path}'")))
}

/// An authority hears of an import as of any write and refuses a
/// non-writer then, but by that time the repo is in; when this cluster
/// hosts the authority, it's refused up front. Run at the owner of the
/// authority's shard (a shard nobody holds right now is refused for a
/// retry, never skipped).
async fn authority_check(app: &App, space: &Space, did: &str, rev: Tid) -> XResult<()> {
    app.partition(&space.authority)?;
    // (no row: the authority moved in without its spaces, which aren't
    // migrated; its own repos come first)
    if super::server::account_if_exists(app, &space.authority).await?.is_none() {
        return Ok(());
    }
    let Some(row) = super::simplespace::space_row_opt(app, space).await? else {
        return Ok(());
    };
    if !row.live() {
        return Err(super::simplespace::space_not_found());
    }
    // a repo from before the space was (re)created belongs to an
    // incarnation that was deleted: importing it would bring that back
    if rev.micros() + CREATED_SLACK_MICROS < created_micros(&row.created_at)? {
        return Err(invalid("the imported commit predates the space (it was deleted and made again since)"));
    }
    if !super::simplespace::authorize_user(app, space, &row, did, "write", None).await? {
        return Err(bad("NotAuthorized", "Not a member allowed to write in this space"));
    }
    Ok(())
}

#[derive(Deserialize)]
pub(super) struct CheckQ {
    space: String,
    did: String,
    rev: String,
}

/// [`authority_check`] for an import on another node of the cluster.
pub(super) async fn internal_import_check(
    State(app): AppState,
    headers: HeaderMap,
    Query(q): Query<CheckQ>,
) -> XResult<Json<J>> {
    super::internal::check(&app, &headers)?;
    let space = Space::parse(&q.space)?;
    let rev = Tid::parse(&q.rev).ok_or_else(|| invalid("rev must be a TID"))?;
    authority_check(&app, &space, &q.did, rev).await?;
    Ok(Json(json!({})))
}

/// How far a repo's rev may be before its space's `createdAt`: the
/// writer's clock and the authority's needn't agree.
const CREATED_SLACK_MICROS: u64 = 120_000_000;

/// A space row's `createdAt`, in Unix microseconds.
fn created_micros(at: &str) -> XResult<u64> {
    chrono::DateTime::parse_from_rfc3339(at)
        .ok()
        .and_then(|t| u64::try_from(t.timestamp_micros()).ok())
        .ok_or_else(|| XrpcError::internal("bad space createdAt"))
}

#[derive(Deserialize)]
struct ImportQ {
    space: String,
}

/// Releases the import's claim however it ends.
struct Claim<'a> {
    sp: &'a crate::space::Spaces,
    did: &'a str,
    sid: crate::state::SpaceId,
    nonce: u64,
}

impl Drop for Claim<'_> {
    fn drop(&mut self) {
        self.sp.end_import(self.did, self.sid, self.nonce);
    }
}

async fn import_repo(
    State(app): AppState,
    Auth(creds): Auth,
    Query(q): Query<ImportQ>,
    headers: HeaderMap,
    body: Body,
) -> XResult<Json<J>> {
    let r = import(&app, &creds, &q, &headers, body).await;
    crate::metrics::space_import(match &r {
        Ok(_) => "ok",
        Err(e) if e.status.is_server_error() => "error",
        Err(_) => "refused",
    });
    r
}

async fn import(app: &Arc<App>, creds: &Credentials, q: &ImportQ, headers: &HeaderMap, body: Body) -> XResult<Json<J>> {
    let sp = spaces(app)?;
    let space = Space::parse(&q.space)?;
    let did = creds.user_did()?.to_string();
    // Everything before the body is read: a grant that writes in the space
    // (OAuth, as every space write: need_space refuses anything else), the
    // account's budget and slot, and the import's memory. Which
    // collections it writes is checked as its records come in.
    creds.need_space(&space.target(), SpaceAccess::WriteAny("create"))?;
    let max = app.config.max_import_bytes;
    let declared =
        headers.get(header::CONTENT_LENGTH).and_then(|v| v.to_str().ok()).and_then(|v| v.parse::<u64>().ok());
    if declared.is_some_and(|n| n > max as u64) {
        return Err(super::import_stream::too_large(max));
    }
    crate::ratelimit::check(&[&crate::ratelimit::SPACE_IMPORT], &did, 1)?;
    if let Some(st) = app.account(&did).await?.status {
        return Err(inactive_account_error(&st));
    }
    // no more at once than the budget holds at their largest (what a
    // chunked body reserves): past that they're refused at once, and the
    // ones let in never wait on each other for room
    let node_cap = app.imports.holds(working_set(None)) as usize;
    let _slot = sp.import_slot(&did, node_cap).map_err(|account| match account {
        true => invalid("too many space imports in progress for this account; retry once one is done"),
        false => XrpcError::unavailable("Overloaded", "too many space imports in progress; retry shortly"),
    })?;
    let _room = app.imports.admit_working_set(working_set(declared)).await?;
    // (the worker checks again)
    let held = super::space::load_head(sp, &*app.partition(&did)?, &did, &space).await?;
    let body = super::import_stream::TimedBody::new(body, app.config.import_body_idle, app.config.import_body_deadline);
    let mut star = StarReader::new(body, max);
    star.magic().await?;
    let meta =
        star.frame(MAX_META, "metadata").await?.ok_or_else(|| invalid("invalid STAR archive: missing metadata"))?;
    let commit = star::parse_meta(&meta).map_err(|e| invalid(format!("invalid STAR archive: {e}")))?;
    if commit.ver != crate::space::commit::COMMIT_VERSION {
        return Err(invalid(format!("unsupported commit version {}", commit.ver)));
    }
    if commit.repo != did || commit.space != space.uri {
        return Err(invalid("the archive's commit is another repo's"));
    }
    if commit.data.len() != 32 {
        return Err(invalid("commit.data must be 32 bytes"));
    }
    let rev = Tid::parse(&commit.rev).ok_or_else(|| invalid("commit.rev must be a TID"))?;
    match app.remote_owner(&space.authority) {
        Some(owner) => {
            let q = [("space", space.uri.as_str()), ("did", did.as_str()), ("rev", commit.rev.as_str())];
            super::internal::owner_get(app, &owner, "/internal/v1/space/importCheck", &q).await?;
        }
        None => authority_check(app, &space, &did, rev).await?,
    }
    // every later write's rev follows it, and an authority refuses a
    // notify this far ahead (FutureRev), so the account would go unheard
    if rev.micros() > vlatproto::tid::now_micros() + super::space::FUTURE_REV.as_micros() as u64 {
        return Err(bad("FutureRev", "The commit's rev is in the future"));
    }
    // an equal rev is let through here only to be checked for the same
    // content below
    if held.as_ref().is_some_and(|h| rev < h.rev) {
        return Err(invalid("the imported commit's rev must be newer than the repo's in the space"));
    }
    let limits = Limits { max_records: sp.limits.max_records, creds, space: &space };
    if let Some(h) = held.filter(|h| h.rev == rev) {
        // a retried import of the repo as it stands: the set hash covers
        // every (path, CID), so an equal digest and count is the same records
        if h.hash.digest()[..] != commit.data[..] {
            return Err(invalid("the imported commit's rev must be newer than the repo's in the space"));
        }
        let (records, set) = stage(None, &did, &space, &mut star, commit, rev, &limits).await?;
        if records != h.records || set.state() != h.hash.state() {
            return Err(invalid("the imported commit's rev must be newer than the repo's in the space"));
        }
        return Ok(Json(json!({"rev": rev.to_string(), "records": records})));
    }

    let nonce = rand::random::<u64>();
    let _claim = Claim { sp, did: &did, sid: space.sid, nonce };
    submit_space(app, &did, &space, SpaceOp::ImportBegin { nonce, rev: Some(rev) }).await?;
    let p = app.partition(&did)?;
    clear_unheaded(&p, &did, &space).await?;
    let staged = stage(Some(&p), &did, &space, &mut star, commit, rev, &limits).await;
    let (records, set) = match staged {
        Ok(n) => n,
        Err(e) => {
            // rows staged with no head over them are never served, but
            // they'd hold blobs and slow the repo's first write (which
            // clears them) until then
            if let Err(c) = clear_unheaded(&p, &did, &space).await {
                tracing::warn!(space = hex::encode(space.sid), "a failed import's rows not cleared: {}", c.message);
            }
            return Err(e);
        }
    };
    let op = SpaceOp::ImportCommit { nonce, rev, hash: Box::new(set), records };
    match submit_space(app, &did, &space, op).await? {
        SpaceAck::Write { .. } => {}
        _ => return Err(XrpcError::internal("unexpected space ack")),
    }
    Ok(Json(json!({"rev": rev.to_string(), "records": records})))
}

/// What an import may hold: the record cap, and the grant's collections.
struct Limits<'a> {
    max_records: u64,
    creds: &'a Credentials,
    space: &'a Space,
}

/// Writes the archive's records (and their blob refs) as rows with no head
/// over them yet, checking each ([`star::Archive::push`]) and, at the end,
/// that they're the repo the commit describes; Ok((the record count, their
/// set)). With no partition it only checks them.
#[allow(clippy::too_many_arguments)]
async fn stage(
    p: Option<&crate::partition::Partition>,
    did: &str,
    space: &Space,
    star: &mut StarReader,
    commit: crate::space::commit::Commit,
    rev: Tid,
    limits: &Limits<'_>,
) -> XResult<(u64, crate::space::lthash::LtHash)> {
    let mut archive = star::Archive::new(commit);
    let mut collections: std::collections::BTreeSet<String> = Default::default();
    let mut muts = Vec::new();
    let mut bytes = 0;
    while let Some(key) = star.frame(MAX_PATH, "record path").await? {
        let b = star
            .frame(star::MAX_RECORD_SIZE, "record")
            .await?
            .ok_or_else(|| invalid("invalid STAR archive: missing value for key"))?;
        let (path, cid) = archive.push(&key, &b).map_err(|e| invalid(format!("invalid STAR archive: {e}")))?;
        let (collection, rkey) = path.split_once('/').unwrap_or_default();
        check_path(collection, Some(rkey))?;
        if !collections.contains(collection) {
            limits.creds.need_space(&limits.space.target(), SpaceAccess::Write("create", collection))?;
            collections.insert(collection.to_string());
        }
        if archive.records > limits.max_records {
            return Err(invalid(format!("Space repo record limit reached: at most {} records", limits.max_records)));
        }
        let blobs = record_blobs(&path, &b)?;
        let Some(p) = p else { continue };
        for blob in &blobs {
            let r = Bytes::copy_from_slice(&rev.0.to_be_bytes());
            muts.push(put(state::space_blob_key(did, &space.sid, blob, &path), r));
            muts.push(put(state::space_blob_cid_key(did, blob, &space.sid, &path), Bytes::new()));
        }
        muts.push(put(state::space_record_key(did, &space.sid, &path), state::record_value(&cid, rev.0, &b)));
        bytes += b.len();
        if muts.len() >= BATCH_ROWS || bytes >= BATCH_BYTES {
            write_private_local(p, std::mem::take(&mut muts)).await?;
            bytes = 0;
        }
    }
    archive.finish().map_err(|_| bad("DigestMismatch", "The archive's records are not the commit's"))?;
    if let Some(p) = p.filter(|_| !muts.is_empty()) {
        write_private_local(p, muts).await?;
    }
    Ok((archive.records, archive.set))
}

fn put(key: Vec<u8>, val: Bytes) -> vlsync_store::segment::Mutation {
    vlsync_store::segment::Mutation { key: key.into(), val: Some(val) }
}

/// Clears the rows of `did`'s headless repo in the space under an import's
/// claim (so no import stages meanwhile). A head that turned up meanwhile
/// leaves them be: they're its own.
pub(super) async fn sweep_unheaded(app: &App, did: &str, space: &Space) -> XResult<()> {
    let sp = spaces(app)?;
    let nonce = rand::random::<u64>();
    let _claim = Claim { sp, did, sid: space.sid, nonce };
    let op = SpaceOp::ImportBegin { nonce, rev: None };
    match super::space::submit_space_once(app, did, space, op).await? {
        Ok(_) => clear_unheaded(&*app.partition(did)?, did, space).await,
        Err(SpaceError::Write(WriteError::Invalid(_))) => Ok(()),
        Err(e) => Err(super::space::space_error(e)),
    }
}

/// Rows of the account's repo in the space with no head over them (an
/// earlier import stopped part way, or a deleted repo's sweep did): gone
/// before this import stages its own.
async fn clear_unheaded(p: &crate::partition::Partition, did: &str, space: &Space) -> XResult<()> {
    for fam in [state::SPACE_BLOB_FAMILY, state::SPACE_RECORD_FAMILY, state::SPACE_OPLOG_FAMILY] {
        let prefix = state::space_prefix(fam, did, &space.sid);
        loop {
            let mut iter =
                p.db.scan(prefix.clone()..vlsync_store::keys::prefix_end(&prefix))
                    .await
                    .map_err(XrpcError::from_err)?;
            let rows = iter.next_batch(BATCH_ROWS).await.map_err(XrpcError::from_err)?;
            if rows.is_empty() {
                break;
            }
            let mut muts = Vec::with_capacity(rows.len() * 2);
            for kv in rows {
                if fam == state::SPACE_BLOB_FAMILY {
                    let (cid, path) = crate::space::rows::blob_ref_parts(&kv.key[prefix.len()..])
                        .ok_or_else(|| XrpcError::internal("bad space blob ref key"))?;
                    let cid = Cid::parse(cid).map_err(XrpcError::from_err)?;
                    let key = state::space_blob_cid_key(did, &cid, &space.sid, path);
                    muts.push(vlsync_store::segment::Mutation { key: key.into(), val: None });
                }
                muts.push(vlsync_store::segment::Mutation { key: kv.key, val: None });
            }
            write_private_local(p, muts).await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A small declared body reserves little; an undeclared one stays
    /// within one import's largest reservation.
    #[test]
    fn working_set_follows_the_caps() {
        assert!(working_set(Some(10 << 10)) < 2 << 20, "{}", working_set(Some(10 << 10)));
        let full = working_set(None);
        assert!(full <= super::super::import_budget::MAX_WORKING_SET, "{full}");
        assert!(full >= 2 * star::MAX_RECORD_SIZE as u64);
    }
}
