//! Blob endpoints and the unreferenced-blob GC (DESIGN.md "6. Blobs").
//! `{prefix}/blob/{did}/{cid}` holds the bytes, MIME type as its
//! Content-Type attribute; large uploads go through a multipart upload to
//! `blob-tmp/` since the CID is only known at the end.

use super::sync::assert_available;
use super::*;
use futures::StreamExt;
use object_store::{Attribute, Attributes, ObjectStore, PutMultipartOptions, WriteMultipart};
use sha2::{Digest, Sha256};
use std::time::Duration;

pub fn routes() -> Router<Arc<App>> {
    Router::new()
        .route("/xrpc/com.atproto.repo.uploadBlob", post(upload_blob))
        .route("/xrpc/com.atproto.repo.listMissingBlobs", get(list_missing_blobs))
        .route("/xrpc/com.atproto.sync.getBlob", get(get_blob))
        .route("/xrpc/com.atproto.sync.listBlobs", get(list_blobs))
}

/// S3's minimum part is 5 MiB. Smaller bodies are one PUT to the final key.
const PART_SIZE: usize = 8 << 20;
const PART_CONCURRENCY: usize = 4;
const TMP_GRACE: Duration = Duration::from_secs(24 * 3600);

pub(super) fn blob_path(app: &App, did: &str, cid: impl std::fmt::Display) -> object_store::path::Path {
    object_store::path::Path::from(format!("{}/blob/{}/{}", app.store.prefix, did, cid))
}

/// Private row names `blob/{cid}`: the blobs the account stores, what
/// checkAccountStatus counts as `importedBlobs` (DESIGN.md
/// "checkAccountStatus counts"). Written after the upload's PUT, deleted
/// before the GC's delete, so a failed step leaves the object (which the
/// next upload or sweep repeats) rather than a row without one.
pub(super) const STORED: &str = "blob/";

pub(super) fn stored(did: &str, cid: &str, present: bool) -> vlsync_store::segment::Mutation {
    super::server::pmut(did, &format!("{STORED}{cid}"), present.then(Vec::new))
}

/// `importedBlobs`: the account's stored-blob rows in `db`.
pub(super) async fn count_stored<R: slatedb::DbReadOps + ?Sized>(db: &R, did: &str) -> anyhow::Result<u64> {
    let lo = state::private_key(did, STORED);
    let opts = slatedb::config::ScanOptions { read_ahead_bytes: 1 << 20, max_fetch_tasks: 2, ..Default::default() };
    let mut iter = db.scan_with_options(lo.clone()..vlsync_store::keys::prefix_end(&lo), &opts).await?;
    let mut n = 0;
    while iter.next().await?.is_some() {
        n += 1;
    }
    Ok(n)
}

fn too_large(max: u64) -> XrpcError {
    XrpcError {
        status: StatusCode::PAYLOAD_TOO_LARGE,
        error: "PayloadTooLarge".into(),
        message: format!("request entity too large (max {max} bytes)"),
    }
}

fn blob_json(cid: &Cid, mime: &str, size: u64) -> J {
    json!({"blob": {"$type": "blob", "ref": {"$link": cid.to_string()}, "mimeType": mime, "size": size}})
}

async fn upload_blob(State(app): AppState, Auth(creds): Auth, headers: HeaderMap, body: Body) -> XResult<Json<J>> {
    let did = creds.user_did()?.to_string();
    let mime = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .unwrap_or("application/octet-stream")
        .to_string();
    creds.need_blob(&mime)?;
    // Deactivated accounts may upload (migration). Unlike the reference this
    // applies to user service JWTs too: one issued before a takedown would
    // otherwise still upload for up to an hour.
    let acct = app.account(&did).await?;
    if super::server::is_takendown_account(&acct) {
        return Err(super::takedown_error());
    }
    // An account moving in uploads every blob its imported repo references;
    // those don't count against the per-IP daily budget or the global per-IP
    // limit (checked below, once the CID is known), so a big account can
    // arrive in one sitting at full speed.
    let moving_in = acct.status.as_deref() == Some("deactivated");
    if !moving_in {
        crate::ratelimit::check_ip(&[&crate::ratelimit::UPLOAD_BLOB], 1)?;
    }
    let max = app.config.max_blob_size;
    let declared =
        headers.get(header::CONTENT_LENGTH).and_then(|v| v.to_str().ok()).and_then(|v| v.parse::<u64>().ok());
    if declared.is_some_and(|n| n > max) {
        return Err(too_large(max));
    }
    super::blob_quota::precheck(&app, &did, declared, moving_in).await?;
    let mut attrs = Attributes::new();
    attrs.insert(Attribute::ContentType, mime.clone().into());

    let mut up =
        Upload { app: &app, did: &did, attrs, mime, head: Vec::new(), buf: Vec::new(), buffered: 0, multipart: None };
    let (cid, size) = match up.receive(body, max).await {
        Ok(v) => v,
        Err(e) => {
            up.abort().await;
            return Err(e);
        }
    };
    if declared.is_some_and(|n| n != size) {
        tracing::debug!(%did, declared = ?declared, size, "uploadBlob: content-length mismatch");
    }
    let c = cid.to_string();
    let checks = async {
        // before the bytes land under blob/: a taken-down blob stays in
        // quarantine (and is purged) however often it is re-uploaded
        if super::admin::is_blob_takendown(&app, &did, &c).await? {
            return Err(XrpcError::bad("InvalidRequest", "Blob has been takendown, cannot re-upload"));
        }
        // blobs of the repo moving in: no daily count, no byte refusal
        // (they still count toward the bytes)
        let imported = moving_in && referenced(&*app.partition(&did)?, &did, &c).await.map_err(XrpcError::from_err)?;
        if moving_in && !imported {
            crate::ratelimit::check_ip(&[&crate::ratelimit::UPLOAD_BLOB], 1)?;
        }
        if imported {
            crate::ratelimit::refund_global_ip();
        }
        Ok(super::blob_quota::Exempt { daily: imported, bytes: imported })
    };
    let exempt = match checks.await {
        Ok(x) => x,
        Err(e) => {
            up.abort().await;
            return Err(e);
        }
    };
    if let Err(e) = super::blob_quota::commit(&app, &did, &c, size, exempt, up.commit(cid)).await {
        up.abort().await;
        return Err(e);
    }
    crate::metrics::BLOB_UPLOADS.with_label_values(&[crate::metrics::blob_kind(&up.mime)]).inc();
    crate::metrics::BLOB_UPLOAD_BYTES.inc_by(size);
    Ok(Json(blob_json(&cid, &up.mime, size)))
}

struct Upload<'a> {
    app: &'a App,
    did: &'a str,
    attrs: Attributes,
    /// Client-declared type until the first bytes are sniffed.
    mime: String,
    head: Vec<u8>,
    /// Held until we know whether a multipart upload is needed.
    buf: Vec<Bytes>,
    buffered: usize,
    multipart: Option<(WriteMultipart, object_store::path::Path)>,
}

impl Upload<'_> {
    /// Reads and hashes the body: held in memory, or in a multipart upload to
    /// `blob-tmp/` once large. Nothing is under `blob/` until [`Self::commit`].
    async fn receive(&mut self, body: Body, max: u64) -> XResult<(Cid, u64)> {
        let mut stream = body.into_data_stream();
        let mut hasher = Sha256::new();
        let mut size: u64 = 0;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| XrpcError::bad("InvalidRequest", format!("error reading body: {e}")))?;
            size += chunk.len() as u64;
            if size > max {
                return Err(too_large(max));
            }
            hasher.update(&chunk);
            if self.head.len() < SNIFF_BYTES {
                let n = (SNIFF_BYTES - self.head.len()).min(chunk.len());
                self.head.extend_from_slice(&chunk[..n]);
            }
            match &mut self.multipart {
                Some((w, _)) => {
                    w.wait_for_capacity(PART_CONCURRENCY).await.map_err(XrpcError::from_err)?;
                    w.put(chunk);
                }
                None => {
                    self.buffered += chunk.len();
                    self.buf.push(chunk);
                    if self.buffered >= PART_SIZE {
                        self.start_multipart().await?;
                    }
                }
            }
        }
        let cid = Cid { codec: vlatproto::cid::CODEC_RAW, digest: hasher.finalize().into() };
        Ok((cid, size))
    }

    /// Drops a pending multipart upload (the in-memory body needs nothing).
    async fn abort(&mut self) {
        if let Some((w, tmp)) = self.multipart.take() {
            let _ = w.abort().await;
            let _ = self.app.store.raw.delete(&tmp).await;
        }
    }

    /// Stores the received bytes at `blob/{did}/{cid}`.
    async fn commit(&mut self, cid: Cid) -> XResult<()> {
        let dest = blob_path(self.app, self.did, cid);
        let store = &self.app.store.raw;
        match self.multipart.take() {
            None => {
                self.sniff();
                let payload: PutPayload = std::mem::take(&mut self.buf).into_iter().collect();
                let opts = PutOptions { attributes: self.attrs.clone(), ..Default::default() };
                store.put_opts(&dest, payload, opts).await.map_err(XrpcError::from_err)?;
            }
            Some((w, tmp)) => {
                if let Err(e) = w.finish().await {
                    let _ = store.delete(&tmp).await;
                    return Err(XrpcError::from_err(e));
                }
                // the copy restarts a re-uploaded blob's GC grace period
                let copied = store.copy(&tmp, &dest).await;
                let _ = store.delete(&tmp).await;
                copied.map_err(XrpcError::from_err)?;
            }
        }
        Ok(())
    }

    /// As the reference (file-type), a recognized signature overrides the
    /// client's Content-Type.
    fn sniff(&mut self) {
        if let Some(m) = sniff_mime(&self.head) {
            self.mime = m.to_string();
        }
        self.attrs.insert(Attribute::ContentType, self.mime.clone().into());
    }

    async fn start_multipart(&mut self) -> XResult<()> {
        self.sniff();
        let tmp = object_store::path::Path::from(format!(
            "{}/blob-tmp/{}/{}",
            self.app.store.prefix,
            self.did,
            hex::encode(rand::random::<[u8; 16]>())
        ));
        let opts = PutMultipartOptions { attributes: self.attrs.clone(), ..Default::default() };
        let upload = self.app.store.raw.put_multipart_opts(&tmp, opts).await.map_err(XrpcError::from_err)?;
        let mut w = WriteMultipart::new_with_chunk_size(upload, PART_SIZE);
        for b in self.buf.drain(..) {
            w.put(b);
        }
        self.buffered = 0;
        self.multipart = Some((w, tmp));
        Ok(())
    }
}

const SNIFF_BYTES: usize = 64;

/// The common subset of what the reference's `file-type` detects for media.
fn sniff_mime(b: &[u8]) -> Option<&'static str> {
    let at = |off: usize, sig: &[u8]| b.len() >= off + sig.len() && &b[off..off + sig.len()] == sig;
    if at(0, b"\x89PNG\r\n\x1a\n") {
        return Some("image/png");
    }
    if at(0, &[0xff, 0xd8, 0xff]) {
        return Some("image/jpeg");
    }
    if at(0, b"GIF87a") || at(0, b"GIF89a") {
        return Some("image/gif");
    }
    if at(0, b"RIFF") && at(8, b"WEBP") {
        return Some("image/webp");
    }
    if at(0, &[0x1a, 0x45, 0xdf, 0xa3]) {
        return Some("video/webm");
    }
    if at(0, b"%PDF-") {
        return Some("application/pdf");
    }
    if at(4, b"ftyp") {
        let brand = b.get(8..12)?;
        return Some(match brand {
            b"avif" | b"avis" => "image/avif",
            b"heic" | b"heix" | b"heim" | b"heis" => "image/heic",
            b"mif1" | b"msf1" => "image/heif",
            b"qt  " => "video/quicktime",
            b"M4A " | b"M4B " => "audio/mp4",
            b"3gp4" | b"3gp5" | b"3gp6" | b"3gs7" => "video/3gpp",
            _ => "video/mp4",
        });
    }
    None
}

pub(super) fn stored_mime(attrs: &Attributes) -> String {
    attrs
        .get(&Attribute::ContentType)
        .map(|v| v.as_ref().to_string())
        .unwrap_or_else(|| "application/octet-stream".into())
}

#[derive(Deserialize)]
struct BlobQ {
    did: String,
    cid: String,
}

async fn get_blob(State(app): AppState, MaybeAuth(creds): MaybeAuth, Query(q): Query<BlobQ>) -> XResult<Response> {
    let cid = Cid::parse(&q.cid).map_err(|_| XrpcError::bad("InvalidRequest", "Invalid cid"))?;
    assert_available(&app, &q.did, creds.as_ref()).await?;
    let is_admin = matches!(creds, Some(Credentials::Admin { .. }));
    if !is_admin && super::admin::is_blob_takendown(&app, &q.did, &cid.to_string()).await? {
        return Err(XrpcError::bad("BlobNotFound", "Blob not found"));
    }
    // Spaces: the reference rule (`hasRecordsForBlob`). Serving an upload
    // before a public record names it would serve one a space record names.
    // Space refs outlive the flag (the blob GC keeps their blobs), so a blob
    // only space records name stays private with it off too.
    let cid_s = cid.to_string();
    if app.config.spaces && !publicly_referenced(&app, &q.did, &cid_s).await? {
        return Err(XrpcError::bad("BlobNotFound", "Blob not found"));
    }
    // an account no space record names a blob of reads nothing more; a
    // public ref settles it: only a blob none names pays for the sc/ scan
    if !app.config.spaces
        && app.space_blob_accounts.has_refs(&app, &q.did).await?
        && !publicly_referenced(&app, &q.did, &cid_s).await?
        && space_referenced(&app, &q.did, &cid_s).await?
    {
        return Err(XrpcError::bad("BlobNotFound", "Blob not found"));
    }
    let r = match app.store.raw.get(&blob_path(&app, &q.did, cid)).await {
        Ok(r) => r,
        // the operator reviewing a taken-down blob reads its quarantined copy
        Err(object_store::Error::NotFound { .. }) if is_admin => {
            match app.store.raw.get(&super::moderation::quarantine_path(&app, &q.did, cid)).await {
                Ok(r) => r,
                Err(object_store::Error::NotFound { .. }) => {
                    return Err(XrpcError::bad("BlobNotFound", "Blob not found"))
                }
                Err(e) => return Err(XrpcError::from_err(e)),
            }
        }
        Err(object_store::Error::NotFound { .. }) => return Err(XrpcError::bad("BlobNotFound", "Blob not found")),
        Err(e) => return Err(XrpcError::from_err(e)),
    };
    Ok(blob_response(r, &cid))
}

/// A stored blob's bytes, streamed, with the reference's headers.
pub(super) fn blob_response(r: object_store::GetResult, cid: &Cid) -> Response {
    let mime = stored_mime(&r.attributes);
    let size = r.meta.size;
    let mut resp = Body::from_stream(r.into_stream()).into_response();
    let h = resp.headers_mut();
    let hv = |s: String| {
        header::HeaderValue::from_str(&s).unwrap_or(header::HeaderValue::from_static("application/octet-stream"))
    };
    h.insert(header::CONTENT_TYPE, hv(mime));
    h.insert(header::CONTENT_LENGTH, header::HeaderValue::from(size));
    // the reference PDS's hardening headers
    h.insert(header::X_CONTENT_TYPE_OPTIONS, header::HeaderValue::from_static("nosniff"));
    h.insert(header::CONTENT_DISPOSITION, hv(format!("attachment; filename=\"{cid}\"")));
    h.insert(header::CONTENT_SECURITY_POLICY, header::HeaderValue::from_static("default-src 'none'; sandbox"));
    resp
}

/// Named by a record of `did`'s public repo. The generation is re-read
/// after a miss, as [`referenced`] does.
async fn publicly_referenced(app: &App, did: &str, cid: &str) -> XResult<bool> {
    let p = app.partition(did)?;
    let mut gen = app.repo_gen(did).await?;
    loop {
        let prefix = [state::blob_ref_prefix(did, gen).as_slice(), cid.as_bytes(), b"\0"].concat();
        let mut iter =
            p.db.scan(prefix.clone()..vlsync_store::keys::prefix_end(&prefix)).await.map_err(XrpcError::from_err)?;
        if iter.next().await.map_err(XrpcError::from_err)?.is_some() {
            return Ok(true);
        }
        let now = app.repo_gen(did).await?;
        if now == gen {
            return Ok(false);
        }
        gen = now;
    }
}

/// Which accounts have space blob refs (`sc/` rows), for sync.getBlob with
/// `--spaces` off, where the common answer (none) lets it skip every ref
/// read. Only consulted with the flag off, when this node writes no space
/// rows: a shard's rows written elsewhere arrive with a new partition,
/// which the entries are keyed by, so each is computed once per partition
/// and never goes stale.
pub struct SpaceBlobAccounts {
    inner: parking_lot::Mutex<lru::LruCache<Box<str>, (PartitionKey, bool)>>,
}

/// A partition's identity on this node: its shard, epoch and open DB.
type PartitionKey = (vlsync_store::slots::ShardId, u64, usize);

/// Accounts held; a miss costs one prefix scan.
const SPACE_BLOB_ACCOUNTS: usize = 16 * 1024;

impl Default for SpaceBlobAccounts {
    fn default() -> Self {
        let cap = std::num::NonZeroUsize::new(SPACE_BLOB_ACCOUNTS).expect("non-zero");
        SpaceBlobAccounts { inner: parking_lot::Mutex::new(lru::LruCache::new(cap)) }
    }
}

impl SpaceBlobAccounts {
    /// Whether `did` has an `sc/` row.
    pub async fn has_refs(&self, app: &App, did: &str) -> XResult<bool> {
        let p = app.partition(did)?;
        let key = (p.id, p.epoch, Arc::as_ptr(&p.db) as usize);
        if let Some(has) = self.cached(did, key) {
            return Ok(has);
        }
        let prefix = state::space_blob_cid_did_prefix(did);
        let mut iter =
            p.db.scan(prefix.clone()..vlsync_store::keys::prefix_end(&prefix)).await.map_err(XrpcError::from_err)?;
        let has = iter.next().await.map_err(XrpcError::from_err)?.is_some();
        self.inner.lock().put(did.into(), (key, has));
        Ok(has)
    }

    fn cached(&self, did: &str, key: PartitionKey) -> Option<bool> {
        self.inner.lock().get(did).filter(|(k, _)| *k == key).map(|(_, has)| *has)
    }

    /// The held answer for `did`, if any (tests).
    pub fn peek(&self, did: &str) -> Option<bool> {
        self.inner.lock().peek(did).map(|(_, has)| *has)
    }
}

/// Whether a space record of `did` names `cid` (an `sc/` row).
async fn space_referenced(app: &App, did: &str, cid: &str) -> XResult<bool> {
    let p = app.partition(did)?;
    let prefix = state::space_blob_cid_prefix(did, cid);
    let mut iter =
        p.db.scan(prefix.clone()..vlsync_store::keys::prefix_end(&prefix)).await.map_err(XrpcError::from_err)?;
    Ok(iter.next().await.map_err(XrpcError::from_err)?.is_some())
}

/// Distinct (cid, one referencing record path) of `did`, in CID order after
/// `cursor`; with `since`, only refs from records written after that rev.
async fn referenced_blobs(
    app: &App,
    did: &str,
    cursor: Option<&str>,
    limit: usize,
    since: Option<u64>,
) -> XResult<Vec<(String, String)>> {
    // the generation moved under the scan (an import committed): its rows
    // may be part swept, so the scan is redone at the new one
    let mut gen = app.repo_gen(did).await?;
    loop {
        let out = referenced_blobs_at(app, did, gen, cursor, limit, since).await?;
        let now = app.repo_gen(did).await?;
        if now == gen {
            return Ok(out);
        }
        gen = now;
    }
}

async fn referenced_blobs_at(
    app: &App,
    did: &str,
    gen: u64,
    cursor: Option<&str>,
    limit: usize,
    since: Option<u64>,
) -> XResult<Vec<(String, String)>> {
    let p = app.partition(did)?;
    let prefix = state::blob_ref_prefix(did, gen);
    let lo = match cursor {
        // skip every key of the cursor cid: b/{did}\0{cursor}\0...
        Some(c) => vlsync_store::keys::prefix_end(&[prefix.as_slice(), c.as_bytes(), b"\0"].concat()),
        None => prefix.clone(),
    };
    let mut iter = p.db.scan(lo..vlsync_store::keys::prefix_end(&prefix)).await.map_err(XrpcError::from_err)?;
    let mut out: Vec<(String, String)> = Vec::new();
    while let Some(kv) = iter.next().await.map_err(XrpcError::from_err)? {
        let rest = String::from_utf8_lossy(&kv.key[prefix.len()..]).into_owned();
        let Some((cid, path)) = rest.split_once('\0') else {
            continue;
        };
        if out.last().is_some_and(|(c, _)| c == cid) {
            continue;
        }
        // ref values carry the rev of the record that references the blob
        if let Some(s) = since {
            let rev = kv.value.get(..8).map(|b| u64::from_be_bytes(b.try_into().unwrap())).unwrap_or(0);
            if rev <= s {
                continue;
            }
        }
        if out.len() == limit {
            break;
        }
        out.push((cid.to_string(), path.to_string()));
    }
    Ok(out)
}

#[derive(Deserialize)]
struct ListBlobsQ {
    did: String,
    since: Option<String>,
    limit: Option<i64>,
    cursor: Option<String>,
}

async fn list_blobs(
    State(app): AppState,
    MaybeAuth(creds): MaybeAuth,
    Query(q): Query<ListBlobsQ>,
) -> XResult<Json<J>> {
    let since = match q.since.as_deref() {
        Some(s) => Some(
            vlatproto::tid::Tid::parse(s).ok_or_else(|| XrpcError::bad("InvalidRequest", "since must be a TID"))?.0,
        ),
        None => None,
    };
    let limit = super::extract::limit_param(q.limit, 500, 1, 1000)?;
    assert_available(&app, &q.did, creds.as_ref()).await?;
    let blobs = referenced_blobs(&app, &q.did, q.cursor.as_deref(), limit, since).await?;
    let cids: Vec<&str> = blobs.iter().map(|(c, _)| c.as_str()).collect();
    let mut out = json!({"cids": cids});
    if let Some(last) = cids.last() {
        out["cursor"] = json!(last);
    }
    Ok(Json(out))
}

#[derive(Deserialize)]
struct MissingQ {
    limit: Option<usize>,
    cursor: Option<String>,
}

/// Public refs, and with `--spaces` the account's space records' refs
/// (`sc/`, imported ones included), merged in CID order: a blob a space
/// record names has to come over in a move as much as a public one does.
async fn list_missing_blobs(State(app): AppState, Auth(creds): Auth, Query(q): Query<MissingQ>) -> XResult<Json<J>> {
    const PAGE: usize = 256;
    let did = creds.user_did()?.to_string();
    let limit = q.limit.unwrap_or(500).clamp(1, 1000);
    let mut cursor = q.cursor.clone();
    let mut missing: Vec<J> = Vec::new();
    // a taken-down blob can't be re-uploaded: not the user's to fix
    let takedowns = super::server::ctl(&app, &did).await?;
    let mut space_uris = std::collections::HashMap::new();
    'outer: loop {
        let public = referenced_blobs(&app, &did, cursor.as_deref(), PAGE, None).await?;
        let spaced = match app.config.spaces {
            true => space_referenced_blobs(&app, &did, cursor.as_deref(), PAGE, &mut space_uris).await?,
            false => Vec::new(),
        };
        // past the last CID of a full page, that list hasn't been read yet
        let bound = [&public, &spaced]
            .iter()
            .filter(|l| l.len() == PAGE)
            .filter_map(|l| l.last())
            .map(|(c, _)| c)
            .min()
            .cloned();
        let mut page: std::collections::BTreeMap<String, String> = spaced.into_iter().collect();
        for (cid, path) in public {
            page.insert(cid, format!("at://{did}/{path}"));
        }
        if let Some(b) = &bound {
            page.retain(|c, _| c <= b);
        }
        if page.is_empty() {
            break;
        }
        cursor = page.keys().next_back().cloned();
        page.retain(|cid, _| !takedowns.has_takedown(&format!("blob/{cid}")));
        let checks: Vec<_> = page
            .keys()
            .map(|cid| {
                let path = blob_path(&app, &did, cid);
                let store = app.store.raw.clone();
                async move {
                    match store.head(&path).await {
                        Ok(_) => Ok(false),
                        Err(object_store::Error::NotFound { .. }) => Ok(true),
                        Err(e) => Err(XrpcError::from_err(e)),
                    }
                }
            })
            .collect();
        let results: Vec<XResult<bool>> = futures::stream::iter(checks).buffered(32).collect().await;
        for ((cid, uri), r) in page.iter().zip(results) {
            if r? {
                missing.push(json!({"cid": cid, "recordUri": uri}));
                if missing.len() == limit {
                    break 'outer;
                }
            }
        }
        if bound.is_none() {
            break;
        }
    }
    let mut out = json!({"blobs": missing});
    if let Some(last) = missing.last() {
        out["cursor"] = last["cid"].clone();
    }
    Ok(Json(out))
}

/// Distinct (cid, the URI of one space record naming it) of `did`'s space
/// refs after `cursor`, in CID order. `uris` caches each space's URI (its
/// `sH` row). A ref whose space has no head (an import that stopped) is
/// skipped, as it's never served.
async fn space_referenced_blobs(
    app: &App,
    did: &str,
    cursor: Option<&str>,
    limit: usize,
    uris: &mut std::collections::HashMap<state::SpaceId, Option<String>>,
) -> XResult<Vec<(String, String)>> {
    let p = app.partition(did)?;
    let prefix = state::space_blob_cid_did_prefix(did);
    let lo = match cursor {
        Some(c) => vlsync_store::keys::prefix_end(&[prefix.as_slice(), c.as_bytes(), b"\0"].concat()),
        None => prefix.clone(),
    };
    let mut iter = p.db.scan(lo..vlsync_store::keys::prefix_end(&prefix)).await.map_err(XrpcError::from_err)?;
    let mut out: Vec<(String, String)> = Vec::new();
    while let Some(kv) = iter.next().await.map_err(XrpcError::from_err)? {
        let rest = &kv.key[prefix.len()..];
        let Some(nul) = rest.iter().position(|b| *b == 0) else { continue };
        let (Ok(cid), tail) = (std::str::from_utf8(&rest[..nul]), &rest[nul + 1..]) else { continue };
        if out.last().is_some_and(|(c, _)| c == cid) || tail.len() < state::SPACE_ID_LEN {
            continue;
        }
        let (sid, path) = tail.split_at(state::SPACE_ID_LEN);
        let sid: state::SpaceId = sid.try_into().unwrap();
        let uri = match uris.get(&sid) {
            Some(u) => u.clone(),
            None => {
                let head = p.db.get(state::space_head_key(did, &sid)).await.map_err(XrpcError::from_err)?;
                let u = head.and_then(|h| crate::space::rows::HeadRow::decode(&h).ok()).map(|h| h.uri);
                uris.insert(sid, u.clone());
                u
            }
        };
        let Some(uri) = uri else { continue };
        if out.len() == limit {
            break;
        }
        out.push((cid.to_string(), format!("{uri}/{did}/{}", String::from_utf8_lossy(path))));
    }
    Ok(out)
}

/// Only DIDs whose partition this node owns are swept.
pub fn spawn_blob_gc(app: Arc<App>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let grace = app.config.blob_gc_grace;
        let every = (grace / 4).clamp(Duration::from_secs(10), Duration::from_secs(3600));
        let mut tick = tokio::time::interval(every);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            match sweep_blobs(&app, grace).await {
                Ok((scanned, deleted)) if deleted > 0 => {
                    tracing::info!(scanned, deleted, "blob gc")
                }
                Ok(_) => {}
                Err(e) => tracing::warn!("blob gc: {e:#}"),
            }
            match super::moderation::sweep_quarantine(&app, app.config.blob_quarantine).await {
                Ok(n) if n > 0 => tracing::info!(purged = n, "taken-down blobs purged from quarantine"),
                Ok(_) => {}
                Err(e) => tracing::warn!("blob quarantine sweep: {e:#}"),
            }
        }
    })
}

/// Longer than a write that checked the blob (repo.rs `check_blobs`)
/// usually takes to apply its reference; one still in flight past it holds
/// the blob ([`HeldBlobs`]).
const QUARANTINE_SETTLE: Duration = Duration::from_secs(60);

/// (did, cid) -> writes in flight on this node that checked the blob. A
/// quarantined blob held here isn't purged however long its write takes to
/// apply (a cold repo load, a store brownout). Writes run on the repo's
/// owner, the node whose GC sweeps its blobs.
static IN_FLIGHT: std::sync::LazyLock<parking_lot::Mutex<std::collections::HashMap<(String, Cid), usize>>> =
    std::sync::LazyLock::new(Default::default);

/// Holds a write's checked blobs in [`IN_FLIGHT`] until dropped.
pub struct HeldBlobs {
    keys: Vec<(String, Cid)>,
}

impl HeldBlobs {
    pub fn hold(did: &str, cids: impl IntoIterator<Item = Cid>) -> HeldBlobs {
        let keys: Vec<(String, Cid)> = cids.into_iter().map(|c| (did.to_string(), c)).collect();
        let mut m = IN_FLIGHT.lock();
        for k in &keys {
            *m.entry(k.clone()).or_default() += 1;
        }
        HeldBlobs { keys }
    }
}

impl Drop for HeldBlobs {
    fn drop(&mut self) {
        let mut m = IN_FLIGHT.lock();
        for k in &self.keys {
            if let Some(n) = m.get_mut(k) {
                *n -= 1;
                if *n == 0 {
                    m.remove(k);
                }
            }
        }
    }
}

fn held(did: &str, cid: &Cid) -> bool {
    IN_FLIGHT.lock().contains_key(&(did.to_string(), *cid))
}

fn quarantine_path(app: &App, did: &str, cid: &str) -> object_store::path::Path {
    object_store::path::Path::from(format!("{}/blob-gc/{}/{}", app.store.prefix, did, cid))
}

/// Referenced by the repo, by an import staged into it, or by a record of
/// the account in a space (`sc/`, whatever `--spaces` is now, so turning
/// it off never collects a space's blobs). The generation is re-read after
/// a miss, as `App::record_value` does: an import's commit may have moved
/// it, and the generation it left be swept since.
async fn referenced(p: &Partition, did: &str, cid: &str) -> anyhow::Result<bool> {
    let sc = state::space_blob_cid_prefix(did, cid);
    if p.db.scan(sc.clone()..vlsync_store::keys::prefix_end(&sc)).await?.next().await?.is_some() {
        return Ok(true);
    }
    let gens = || async {
        let (a, g) = tokio::try_join!(p.db.get(state::account_key(did)), p.db.get(state::import_key(did)))?;
        let current = a.map(|a| serde_json::from_slice::<state::Account>(&a)).transpose()?.map_or(0, |a| a.repo_gen);
        let staged = g.map(|g| state::ImportState::decode(&g)).transpose()?.and_then(|s| s.staging).map(|s| s.gen);
        anyhow::Ok((current, staged))
    };
    let mut at = gens().await?;
    loop {
        for g in std::iter::once(at.0).chain(at.1) {
            let prefix = [state::blob_ref_prefix(did, g).as_slice(), cid.as_bytes(), b"\0"].concat();
            let mut iter = p.db.scan(prefix.clone()..vlsync_store::keys::prefix_end(&prefix)).await?;
            if iter.next().await?.is_some() {
                return Ok(true);
            }
        }
        let now = gens().await?;
        if now.0 == at.0 {
            return Ok(false);
        }
        at = now;
    }
}

/// (did, cid) of a `.../{did}/{cid}` object path.
pub(super) fn did_cid(path: &object_store::path::Path) -> Option<(String, String)> {
    let parts: Vec<String> = path.parts().map(|p| super::sync::pct_decode(p.as_ref(), false)).collect();
    let n = parts.len();
    (n >= 2).then(|| (parts[n - 2].clone(), parts[n - 1].clone()))
}

/// Returns (blobs scanned, objects deleted).
pub async fn sweep_blobs(app: &App, grace: Duration) -> anyhow::Result<(usize, usize)> {
    sweep_blobs_settle(app, grace, grace.min(QUARANTINE_SETTLE)).await
}

/// A blob moved to quarantine counts as deleted (it is no longer served).
///
/// The race: a write checks that its blob exists (`check_blobs`) and is
/// applied a little later; a sweep that read "no reference" in between would
/// delete the blob under it. So an unreferenced blob older than `grace` is
/// first moved to `blob-gc/` (writes referencing it then fail their check),
/// and only after `settle` are its references checked again: one that
/// appeared moves it back, a write still in flight ([`HeldBlobs`]) defers
/// it, otherwise it is deleted.
///
/// Orphaned multipart uploads can't be listed through object_store: DESIGN.md
/// "6. Blobs" has the bucket lifecycle rule that aborts them.
pub async fn sweep_blobs_settle(app: &App, grace: Duration, settle: Duration) -> anyhow::Result<(usize, usize)> {
    let now = chrono::Utc::now();
    let cutoff = now - chrono::Duration::from_std(grace)?;
    let store = app.store.raw.clone();
    let (mut scanned, mut deleted) = (0usize, 0usize);

    let blob_root = object_store::path::Path::from(format!("{}/blob", app.store.prefix));
    let mut list = store.list(Some(&blob_root));
    while let Some(meta) = list.next().await {
        let meta = meta?;
        scanned += 1;
        if meta.last_modified > cutoff {
            continue;
        }
        let Some((did, cid)) = did_cid(&meta.location) else { continue };
        let Ok(p) = app.partition(&did) else { continue };
        if referenced(&p, &did, &cid).await? {
            continue;
        }
        // the copy's last-modified time starts the settle period
        if let Err(e) = store.copy(&meta.location, &quarantine_path(app, &did, &cid)).await {
            if !matches!(e, object_store::Error::NotFound { .. }) {
                tracing::warn!(path = %meta.location, "blob gc quarantine: {e}");
            }
            continue;
        }
        if let Err(e) = super::blob_quota::drop_stored(app, &did, &cid, meta.size).await {
            tracing::warn!(path = %meta.location, "blob gc: dropping the stored row: {}", e.message);
            continue;
        }
        match store.delete(&meta.location).await {
            Ok(()) | Err(object_store::Error::NotFound { .. }) => deleted += 1,
            Err(e) => tracing::warn!(path = %meta.location, "blob gc delete: {e}"),
        }
    }

    let settled = now - chrono::Duration::from_std(settle)?;
    let gc_root = object_store::path::Path::from(format!("{}/blob-gc", app.store.prefix));
    let mut list = store.list(Some(&gc_root));
    let (mut restored, mut purged) = (0usize, 0usize);
    while let Some(meta) = list.next().await {
        let meta = meta?;
        if meta.last_modified > settled {
            continue;
        }
        let Some((did, cid)) = did_cid(&meta.location) else { continue };
        let Ok(p) = app.partition(&did) else { continue };
        if referenced(&p, &did, &cid).await? {
            // a write that checked the blob before the move: put it back
            let Ok(c) = Cid::parse(&cid) else { continue };
            if let Err(e) = super::blob_quota::restore_stored(app, &did, &cid, meta.size).await {
                tracing::warn!(path = %meta.location, "blob gc restore: {}", e.message);
                continue;
            }
            // taken down meanwhile: its bytes belong in the takedown's quarantine
            let dest = match super::admin::is_blob_takendown(app, &did, &cid).await {
                Ok(true) => super::moderation::quarantine_path(app, &did, c),
                Ok(false) => blob_path(app, &did, c),
                Err(e) => {
                    tracing::warn!(path = %meta.location, "blob gc restore: {}", e.message);
                    continue;
                }
            };
            if let Err(e) = store.copy(&meta.location, &dest).await {
                tracing::warn!(path = %meta.location, "blob gc restore: {e}");
                continue;
            }
            restored += 1;
            tracing::warn!(%did, %cid, "blob gc: a reference appeared during quarantine; restored");
        } else if Cid::parse(&cid).is_ok_and(|c| held(&did, &c)) {
            // a write that checked it hasn't applied yet: decide next pass
            continue;
        } else {
            purged += 1;
        }
        if let Err(e) = store.delete(&meta.location).await {
            tracing::warn!(path = %meta.location, "blob gc purge: {e}");
        }
    }
    if restored + purged > 0 {
        tracing::debug!(restored, purged, "blob gc quarantine");
    }

    let tmp_cutoff = now - chrono::Duration::from_std(TMP_GRACE.max(grace))?;
    let tmp_root = object_store::path::Path::from(format!("{}/blob-tmp", app.store.prefix));
    let mut list = store.list(Some(&tmp_root));
    while let Some(meta) = list.next().await {
        let meta = meta?;
        if meta.last_modified <= tmp_cutoff && store.delete(&meta.location).await.is_ok() {
            deleted += 1;
        }
    }
    Ok((scanned, deleted))
}
