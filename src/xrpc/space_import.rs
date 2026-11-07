//! `com.atproto.space.importRepo` (`--spaces`): an account moving in
//! brings its repo in a space as the STAR archive its old host's
//! space.getRepo serves. The archive carries no MAC: it's the account's own
//! data, uploaded with its own grant, so its records are checked against
//! the commit's `data` and the commit must name the account, nothing more.
//!
//! It's OAuth-only like every space write, so an account moving in imports
//! once it's active here, after its DID points here. The records stream in
//! as the body arrives, each checked canonical and in path order, staged in
//! bounded frameless entries with no head over them; once the set hash
//! they fold to is the commit's, a final entry on the repo's worker puts
//! the head in at a new rev (after the archive's and any held here). The
//! oplog starts empty (a syncer reading from an older `since` gets the
//! commit and no ops), and the authority is owed a notify like any write.
//!
//! An import over a repo that's there replaces it: the claim's entry takes
//! the old head away, the old rows are swept in bounded batches, and the
//! new head goes in at the end. The worker refuses the account's writes to
//! the space, and other imports of it, while it imports
//! (`Spaces::begin_import`). An import stopped part way leaves staged rows
//! no head names, which no read serves; the next import of the space
//! deletes them first.
//!
//! What a body can cost is bounded before any of it is read: the grant,
//! the account's rate limit and slots, and a reservation from the import
//! budget are taken first, and every frame is capped from its length.

use super::repo::check_path;
use super::space::{spaces, submit_space, Space};
use super::*;
use crate::oauth::scopes::SpaceAccess;
use crate::space::commit;
use crate::space::lthash::LtHash;
use crate::space::repo::{SpaceAck, SpaceError, SpaceOp};
use crate::space::star;
use vlatproto::tid::Tid;

pub fn routes() -> Router<Arc<App>> {
    Router::new().route("/xrpc/com.atproto.space.importRepo", post(import_repo))
}

/// Rows per staged entry, or fewer at [`BATCH_BYTES`].
const BATCH_ROWS: usize = 1000;
const BATCH_BYTES: usize = 4 << 20;
/// What an import holds besides its records: tasks, the reader, the claim.
const FIXED: u64 = 256 << 10;

/// What an import of a `declared`-byte body (None: unknown) holds at most:
/// a record twice (the reader's buffer and its copy) and a staged batch
/// with its rows' keys while the next one fills. Every frame is capped
/// before it's buffered, and a body declared smaller caps them more.
fn working_set(declared: Option<u64>) -> u64 {
    let body = declared.unwrap_or(u64::MAX);
    let record = ((star::LIMITS.value + star::LIMITS.key) as u64).min(body);
    let batch = (BATCH_BYTES as u64).min(body) + BATCH_ROWS as u64 * 400;
    FIXED + 3 * record + 2 * batch + (KEEP_IN_MEMORY as u64).min(body)
}

fn invalid(m: impl Into<String>) -> XrpcError {
    XrpcError::bad("InvalidRequest", m)
}

/// A STAR archive read item by item as the body arrives.
/// Where a [`StarBody`] reads: the request body (kept for a second pass,
/// in memory up to [`KEEP_IN_MEMORY`], then in a temporary file), or that
/// copy.
enum Source {
    Body { body: super::import_stream::TimedBody, kept: Kept },
    Mem(Vec<u8>),
    File { file: tokio::fs::File, _unlink: Unlink },
}

/// The body as read so far.
enum Kept {
    Mem(Vec<u8>),
    File(tokio::fs::File, Unlink),
}

/// A body past this is kept on disk for the second pass.
const KEEP_IN_MEMORY: usize = 8 << 20;
const REPLAY_CHUNK: usize = 1 << 20;

/// Deletes the temporary file however the import ends.
struct Unlink(std::path::PathBuf);

impl Drop for Unlink {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

impl Kept {
    async fn push(&mut self, chunk: &[u8]) -> XResult<()> {
        use tokio::io::AsyncWriteExt;
        if let Kept::Mem(v) = self {
            if v.len() + chunk.len() <= KEEP_IN_MEMORY {
                v.extend_from_slice(chunk);
                return Ok(());
            }
            let path = std::env::temp_dir().join(format!("vlpds-space-import-{:016x}.star", rand::random::<u64>()));
            let unlink = Unlink(path.clone());
            let mut f = tokio::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&path)
                .await
                .map_err(|_| XrpcError::internal("could not buffer the import body"))?;
            f.write_all(v).await.map_err(|_| XrpcError::internal("could not buffer the import body"))?;
            *self = Kept::File(f, unlink);
        }
        if let Kept::File(f, _) = self {
            f.write_all(chunk).await.map_err(|_| XrpcError::internal("could not buffer the import body"))?;
        }
        Ok(())
    }
}

struct StarBody {
    src: Source,
    reader: star::Reader,
    buf: Vec<u8>,
    pos: usize,
    total: usize,
    max: usize,
    eof: bool,
}

impl StarBody {
    fn new(body: super::import_stream::TimedBody, max: usize) -> StarBody {
        StarBody::over(Source::Body { body, kept: Kept::Mem(Vec::new()) }, max)
    }

    fn over(src: Source, max: usize) -> StarBody {
        StarBody { src, reader: star::Reader::new(star::LIMITS), buf: Vec::new(), pos: 0, total: 0, max, eof: false }
    }

    /// A reader over the body this one read whole, from its start.
    async fn replay(self) -> XResult<StarBody> {
        use tokio::io::AsyncSeekExt;
        let Source::Body { kept, .. } = self.src else { return Err(XrpcError::internal("not a request body")) };
        let src = match kept {
            Kept::Mem(v) => Source::Mem(v),
            Kept::File(mut f, unlink) => {
                f.seek(std::io::SeekFrom::Start(0)).await.map_err(XrpcError::from_err)?;
                Source::File { file: f, _unlink: unlink }
            }
        };
        Ok(StarBody::over(src, self.max))
    }

    /// The next item, None once the archive has ended cleanly.
    async fn next(&mut self) -> XResult<Option<star::Item>> {
        loop {
            let bad = |e: star::StarError| invalid(format!("Invalid STAR: {e}"));
            if let Some((item, n)) = self.reader.step(&self.buf[self.pos..], self.eof).map_err(bad)? {
                self.pos += n;
                if item == star::Item::End {
                    // whatever follows the end byte is refused
                    while !self.eof {
                        self.read().await?;
                    }
                    self.reader.step(&self.buf[self.pos..], true).map_err(bad)?;
                    return Ok(None);
                }
                return Ok(Some(item));
            }
            if self.eof {
                return Ok(None);
            }
            self.read().await?;
        }
    }

    async fn read(&mut self) -> XResult<()> {
        if self.pos > 0 && self.pos * 2 >= self.buf.len() {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
        let chunk = match &mut self.src {
            Source::Body { body, kept } => match body.next().await {
                Some(Ok(chunk)) => {
                    if self.total + chunk.len() > self.max {
                        return Err(super::import_stream::too_large(self.max));
                    }
                    kept.push(&chunk).await?;
                    chunk.to_vec()
                }
                Some(Err(e)) => return Err(e),
                None => Vec::new(),
            },
            Source::Mem(v) => std::mem::take(v),
            Source::File { file, .. } => {
                use tokio::io::AsyncReadExt;
                let mut c = vec![0; REPLAY_CHUNK];
                let n = file.read(&mut c).await.map_err(XrpcError::from_err)?;
                c.truncate(n);
                c
            }
        };
        if chunk.is_empty() {
            self.eof = true;
        }
        self.total += chunk.len();
        self.buf.extend_from_slice(&chunk);
        Ok(())
    }
}

/// A record's blob refs, once its encoding is checked canonical: it's
/// stored as is, so another encoding of it would match neither its CID nor
/// the commit.
fn record_blobs(path: &str, bytes: &[u8]) -> XResult<Vec<Cid>> {
    let v =
        vlatproto::cbor::Value::decode(bytes).map_err(|_| invalid(format!("Could not parse record at '{path}'")))?;
    let mut again = Vec::with_capacity(bytes.len());
    v.encode(&mut again);
    if again != bytes {
        return Err(invalid(format!("Invalid STAR: record is not canonical DRISL at {path}")));
    }
    vlatproto::cbor::scan_blob_refs(bytes).map_err(|_| invalid(format!("Could not parse record at '{path}'")))
}

/// Releases the import's claim however it ends.
pub(super) struct Claim<'a> {
    pub(super) sp: &'a crate::space::Spaces,
    pub(super) did: &'a str,
    pub(super) sid: crate::state::SpaceId,
    pub(super) nonce: u64,
}

impl Drop for Claim<'_> {
    fn drop(&mut self) {
        self.sp.end_import(self.did, self.sid, self.nonce);
    }
}

async fn import_repo(State(app): AppState, Auth(creds): Auth, headers: HeaderMap, body: Body) -> XResult<StatusCode> {
    let r = import(&app, &creds, &headers, body).await;
    crate::metrics::space_import(match &r {
        Ok(_) => "ok",
        Err(e) if e.status.is_server_error() => "error",
        Err(_) => "refused",
    });
    r.map(|_| StatusCode::OK)
}

async fn import(app: &Arc<App>, creds: &Credentials, headers: &HeaderMap, body: Body) -> XResult<()> {
    let sp = spaces(app)?;
    let did = creds.user_did()?.to_string();
    // Everything before the body is read: an OAuth grant that writes in
    // some space (need_space refuses anything else), the account's budget
    // and slot, and the import's memory. The archive names the space, and
    // which collections it writes are checked as its records arrive.
    creds.need_any_space_write()?;
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
    let body = super::import_stream::TimedBody::new(body, app.config.import_body_idle, app.config.import_body_deadline);
    let mut star = StarBody::new(body, max);
    let meta = match star.next().await? {
        Some(star::Item::Meta(m)) => m,
        _ => return Err(invalid("Invalid STAR: missing metadata")),
    };
    let c = star::parse_repo_meta(&meta).map_err(|e| invalid(format!("Invalid STAR: {e}")))?;
    if c.repo != did {
        return Err(invalid("Repo does not match the authenticated account"));
    }
    let space = Space::parse(&c.space)?;
    creds.need_space(&space.target(), SpaceAccess::WriteAny("create"))?;
    // the authority's own repo comes after its space (importSpaceMeta)
    if space.authority == did && !super::space_policy::live_space(app, &space).await.is_ok() {
        return Err(super::space_policy::space_not_found());
    }
    let floor = Tid::parse(&c.rev);
    // the repo's new rev comes after this one: past the authorities'
    // FutureRev window, every notify of it would be refused
    if floor.is_some_and(|r| r.micros() > vlatproto::tid::now_micros() + super::space::FUTURE_REV.as_micros() as u64) {
        return Err(XrpcError::bad("FutureRev", "The archive's rev is in the future"));
    }
    // (the worker checks again)
    let held = super::space::load_head(sp, &*app.partition(&did)?, &did, &space).await?;
    let prev = held.as_ref().map(|h| h.rev).max(floor);

    // the whole archive is checked before anything of the repo here is
    // touched, so a refused import leaves it as it was
    let (set, _) = stage(None, creds, &did, &space, &mut star, sp.limits.max_records).await?;
    if !commit::matches(&set, &c) {
        return Err(invalid("Invalid STAR: the records do not match the commit's data"));
    }
    let mut star = star.replay().await?;
    if !matches!(star.next().await?, Some(star::Item::Meta(_))) {
        return Err(XrpcError::internal("the kept import body changed"));
    }

    let nonce = rand::random::<u64>();
    let _claim = Claim { sp, did: &did, sid: space.sid, nonce };
    submit_space(app, &did, &space, SpaceOp::ImportBegin { nonce, replace: true }).await?;
    let p = app.partition(&did)?;
    clear_unheaded(&p, &did, &space).await?;
    let staged = stage(Some(&p), creds, &did, &space, &mut star, sp.limits.max_records).await;
    let (set, records) = match staged.and_then(|(again, n)| match again.digest() == set.digest() {
        true => Ok((again, n)),
        false => Err(XrpcError::internal("the kept import body changed")),
    }) {
        Ok(v) => v,
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
    let op = SpaceOp::ImportCommit { nonce, prev, hash: Box::new(set), records };
    match submit_space(app, &did, &space, op).await? {
        SpaceAck::Write { .. } => Ok(()),
        _ => Err(XrpcError::internal("unexpected space ack")),
    }
}

/// Writes the archive's records (and their blob refs) as rows with no head
/// over them yet, at rev 0 until the head names theirs; Ok(the set they
/// fold to, the record count). With no partition it only checks them.
async fn stage(
    p: Option<&crate::partition::Partition>,
    creds: &Credentials,
    did: &str,
    space: &Space,
    star: &mut StarBody,
    max_records: u64,
) -> XResult<(LtHash, u64)> {
    let mut set = LtHash::default();
    let (mut records, mut bytes) = (0u64, 0usize);
    let mut muts = Vec::new();
    let mut prev: Option<Vec<u8>> = None;
    let mut granted: std::collections::BTreeSet<String> = Default::default();
    while let Some(item) = star.next().await? {
        let star::Item::Pair { key, value } = item else { return Err(invalid("Invalid STAR: a second metadata")) };
        if prev.as_ref().is_some_and(|p| key <= *p) {
            return Err(invalid("Invalid STAR: duplicate or out-of-order key"));
        }
        let path = std::str::from_utf8(&key).map_err(|_| invalid("Invalid STAR: a record path is not UTF-8"))?;
        let (collection, rkey) = path.split_once('/').ok_or_else(|| invalid(format!("invalid record path {path}")))?;
        check_path(collection, Some(rkey))?;
        if !granted.contains(collection) {
            creds.need_space(&space.target(), SpaceAccess::Write("create", collection))?;
            granted.insert(collection.to_string());
        }
        records += 1;
        if records > max_records {
            return Err(invalid(format!("Space repo record limit reached: at most {max_records} records")));
        }
        let blobs = record_blobs(path, &value)?;
        let cid = Cid::dag_cbor(&value);
        set.add(&commit::element(collection, rkey, &cid.to_string()));
        let Some(p) = p else {
            prev = Some(key);
            continue;
        };
        for blob in &blobs {
            muts.push(put(
                state::space_blob_key(did, &space.sid, blob, path),
                Bytes::copy_from_slice(&0u64.to_be_bytes()),
            ));
            muts.push(put(state::space_blob_cid_key(did, blob, &space.sid, path), Bytes::new()));
        }
        muts.push(put(state::space_record_key(did, &space.sid, path), state::record_value(&cid, 0, &value)));
        bytes += value.len();
        if muts.len() >= BATCH_ROWS || bytes >= BATCH_BYTES {
            write_private_local(p, std::mem::take(&mut muts)).await?;
            bytes = 0;
        }
        prev = Some(key);
    }
    if let Some(p) = p.filter(|_| !muts.is_empty()) {
        write_private_local(p, muts).await?;
    }
    Ok((set, records))
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
    let op = SpaceOp::ImportBegin { nonce, replace: false };
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
    }

    #[test]
    fn records_must_be_canonical() {
        let mut b = Vec::new();
        vlatproto::cbor::write_map_head(&mut b, 1);
        vlatproto::cbor::write_text(&mut b, "a");
        vlatproto::cbor::write_int(&mut b, 1);
        assert!(record_blobs("a.b.c/x", &b).is_ok());
        // the same map with a non-minimal integer, and with its keys out of
        // canonical order: refused whether the decoder or the re-encoding
        // catches it
        let mut nc = Vec::new();
        vlatproto::cbor::write_map_head(&mut nc, 1);
        vlatproto::cbor::write_text(&mut nc, "a");
        nc.extend_from_slice(&[0x18, 0x01]);
        assert!(record_blobs("a.b.c/x", &nc).is_err());
        let mut unsorted = Vec::new();
        vlatproto::cbor::write_map_head(&mut unsorted, 2);
        for k in ["bb", "a"] {
            vlatproto::cbor::write_text(&mut unsorted, k);
            vlatproto::cbor::write_int(&mut unsorted, 1);
        }
        assert!(record_blobs("a.b.c/x", &unsorted).is_err());
    }
}
