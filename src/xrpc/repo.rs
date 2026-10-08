use super::extract::RecordBody;
use super::*;
use vlatproto::cbor::{JsonValue, RecordRefs};

pub fn routes() -> Router<Arc<App>> {
    Router::new()
        .route("/xrpc/com.atproto.repo.createRecord", post(create_record))
        .route("/xrpc/com.atproto.repo.putRecord", post(put_record))
        .route("/xrpc/com.atproto.repo.deleteRecord", post(delete_record))
        .route("/xrpc/com.atproto.repo.applyWrites", post(apply_writes))
        .route("/xrpc/com.atproto.repo.getRecord", get(get_record))
        .route("/xrpc/com.atproto.repo.listRecords", get(list_records))
        .route("/xrpc/com.atproto.repo.describeRepo", get(describe_repo))
        .route("/xrpc/com.atproto.repo.importRepo", post(import_repo))
}

/// Largest importRepo body. A streamed import holds a few batches whatever
/// its size; the buffered fallback holds the whole body, within the import
/// budget (`import_budget`).
pub const DEFAULT_MAX_IMPORT_BYTES: usize = 1 << 30;

/// The reference sets no limit; our own writes refuse a record over 1 MB,
/// so this leaves room for records made elsewhere while bounding what one
/// record costs every later read.
const MAX_IMPORT_RECORD_BYTES: usize = 2 << 20;

pub(super) fn check_path(collection: &str, rkey: Option<&str>) -> XResult<()> {
    if !vlatproto::syntax::valid_nsid(collection) {
        return Err(XrpcError::bad("InvalidRequest", format!("Invalid collection: {collection} is not a valid NSID")));
    }
    if let Some(r) = rkey.filter(|r| !vlatproto::syntax::valid_rkey(r)) {
        return Err(XrpcError::bad("InvalidRequest", format!("Invalid record key: {r}")));
    }
    Ok(())
}

/// Reference prepareCreate/prepareUpdate; deletes are not checked.
pub(super) fn check_rkey_slur(rkey: Option<&str>) -> XResult<()> {
    if rkey.is_some_and(crate::handle_policy::has_explicit_slur) {
        return Err(XrpcError::bad("InvalidRequest", "Unacceptable slur in record key"));
    }
    Ok(())
}

fn parse_cid_opt(v: &Option<String>) -> XResult<Option<Cid>> {
    v.as_deref()
        .map(|s| Cid::parse(s).map_err(|_| XrpcError::bad("InvalidRequest", format!("bad cid {s}"))))
        .transpose()
}

/// An encoded record: (cid, DAG-CBOR bytes, blob refs, validation status,
/// declared blob refs).
const CREATE: &str = "com.atproto.repo.applyWrites#create";
const UPDATE: &str = "com.atproto.repo.applyWrites#update";
const DELETE: &str = "com.atproto.repo.applyWrites#delete";

pub(super) type Encoded = (Cid, Bytes, Vec<Cid>, crate::lexicon::ValidationStatus, Vec<BlobDecl>);

/// A blob ref as the record declares it: (cid, mimeType, size).
pub(super) type BlobDecl = (Cid, Option<String>, Option<i64>);

/// Reference prepareWrite: a missing `$type` defaults to the collection.
/// `resolved` is the dynamically resolved lexicon of `collection`, if any.
pub(super) fn encode_record(
    v: &mut JsonValue,
    collection: &str,
    rkey: &str,
    validate: Option<bool>,
    resolved: Option<&crate::lexicon::Lexicons>,
) -> XResult<Encoded> {
    if !matches!(v, JsonValue::Object(_)) {
        return Err(XrpcError::bad("InvalidRequest", "record must be an object"));
    }
    match v.get("$type") {
        None => v.insert("$type", JsonValue::Str(collection.to_string().into())),
        Some(JsonValue::Str(t)) if t == collection => {}
        Some(t) => {
            return Err(XrpcError::bad(
                "InvalidRequest",
                format!("Invalid $type: expected {collection}, got {}", t.to_json()),
            ))
        }
    }
    let mut bytes = Vec::with_capacity(512);
    let mut refs = RecordRefs::default();
    v.encode_record(&mut bytes, &mut refs).map_err(|e| XrpcError::bad("InvalidRequest", e.to_string()))?;
    let status = crate::lexicon::validate_record(collection, rkey, &*v, validate, resolved)
        .map_err(|e| XrpcError::bad("InvalidRequest", e))?;
    if let Some(c) = refs.legacy {
        return Err(XrpcError::bad("InvalidRequest", format!("Legacy blobs are not allowed ({c})")));
    }
    if bytes.len() > 1_000_000 {
        return Err(XrpcError::bad("InvalidRequest", "record too large"));
    }
    let blobs = refs.cids();
    Ok((Cid::dag_cbor(&bytes), Bytes::from(bytes), blobs, status, refs.blobs))
}

pub(super) fn with_status(mut out: J, status: crate::lexicon::ValidationStatus) -> J {
    if let Some(st) = status {
        out["validationStatus"] = json!(st);
    }
    out
}

/// Serde's wording, for fields read from the body tree.
pub(super) fn field_err(m: String) -> XrpcError {
    XrpcError::bad("InvalidRequest", format!("Invalid JSON body: {m}"))
}

pub(super) fn opt_str(v: &JsonValue, k: &str) -> XResult<Option<String>> {
    match v.get(k) {
        None | Some(JsonValue::Null) => Ok(None),
        Some(JsonValue::Str(s)) => Ok(Some(s.to_string())),
        Some(_) => Err(field_err(format!("invalid type for `{k}`, expected a string"))),
    }
}

pub(super) fn req_str(v: &JsonValue, k: &str) -> XResult<String> {
    opt_str(v, k)?.ok_or_else(|| field_err(format!("missing field `{k}`")))
}

pub(super) fn opt_bool(v: &JsonValue, k: &str) -> XResult<Option<bool>> {
    match v.get(k) {
        None | Some(JsonValue::Null) => Ok(None),
        Some(JsonValue::Bool(b)) => Ok(Some(*b)),
        Some(_) => Err(field_err(format!("invalid type for `{k}`, expected a boolean"))),
    }
}

pub(super) fn take<'a>(v: &mut JsonValue<'a>, k: &str) -> XResult<JsonValue<'a>> {
    v.get_mut(k).map(|x| std::mem::replace(x, JsonValue::Null)).ok_or_else(|| field_err(format!("missing field `{k}`")))
}

/// Reference processWriteBlobs + verifyBlob: declared mimeType and size must
/// match the stored blob, so lexicon `accept`/`maxSize` checks hold for the
/// real bytes. One HEAD per distinct blob (a 1 MB record can declare ~9k
/// refs). Keep the returned guard until the write has applied or failed; it
/// is taken before the checks, so a quarantine that races them is covered.
pub(super) async fn check_blobs(app: &App, did: &str, decls: &[BlobDecl]) -> XResult<super::blobs::HeldBlobs> {
    let mut seen = std::collections::HashSet::with_capacity(decls.len());
    let decls: Vec<&BlobDecl> = decls.iter().filter(|d| seen.insert(*d)).collect();
    let mut cids: Vec<Cid> = Vec::with_capacity(decls.len());
    let mut distinct = std::collections::HashSet::with_capacity(decls.len());
    cids.extend(decls.iter().map(|d| d.0).filter(|c| distinct.insert(*c)));
    let held = super::blobs::HeldBlobs::hold(did, cids.iter().copied());
    let mut stored: std::collections::HashMap<Cid, (String, u64)> =
        std::collections::HashMap::with_capacity(cids.len());
    for cid in &cids {
        let missing = || XrpcError::bad("BlobNotFound", format!("Could not find blob: {cid}"));
        if super::admin::is_blob_takendown(app, did, &cid.to_string()).await? {
            return Err(missing());
        }
        let opts = object_store::GetOptions { head: true, ..Default::default() };
        let found = match app.store.raw.get_opts(&super::blobs::blob_path(app, did, cid), opts).await {
            Ok(r) => r,
            Err(object_store::Error::NotFound { .. }) => return Err(missing()),
            Err(e) => return Err(XrpcError::from_err(e)),
        };
        stored.insert(*cid, (super::blobs::stored_mime(&found.attributes), found.meta.size));
    }
    for (cid, mime, size) in decls {
        let (stored_mime, stored_size) = &stored[cid];
        if mime.as_deref() != Some(stored_mime.as_str()) {
            return Err(XrpcError::bad(
                "InvalidMimeType",
                format!(
                    "Referenced Mimetype does not match stored blob. Expected: {stored_mime}, Got: {}",
                    mime.as_deref().unwrap_or("undefined")
                ),
            ));
        }
        if *size != i64::try_from(*stored_size).ok() {
            return Err(XrpcError::bad(
                "InvalidSize",
                format!(
                    "Referenced Size does not match stored blob. Expected: {stored_size}, Got: {}",
                    size.map_or("undefined".to_string(), |n| n.to_string())
                ),
            ));
        }
    }
    Ok(held)
}

async fn submit(app: &Arc<App>, did: Arc<str>, writes: Vec<Write>, swap_commit: Option<Cid>) -> XResult<CommitAck> {
    // held by the queued message, so a handler that goes away doesn't free
    // its slot while its write still sits queued
    let Ok(permit) = app.write_permits.clone().try_acquire_owned() else {
        STATS.write_errors.fetch_add(1, Ordering::Relaxed);
        metrics::WRITES_SHED.inc();
        return Err(XrpcError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            error: "Overloaded".into(),
            message: "too many writes in flight; retry with backoff".into(),
        });
    };
    let start = Instant::now();
    STATS.write_requests.fetch_add(1, Ordering::Relaxed);
    let (tx, mut rx) = oneshot::channel();
    let did_kick = did.clone();
    // A forwarding peer fails this at its time-to-first-byte deadline: if the
    // write can't start soon (cold repo load), give it up unapplied and say
    // so; the peer resends it (crate::forward, "RepoLoading").
    let start_wait = app.config.forwarded_write_start.filter(|_| crate::forward::is_forwarded());
    let (claim, permit) = match start_wait {
        Some(_) => (Some(Arc::new(crate::worker::Claim::holding(permit))), None),
        None => (None, Some(permit)),
    };
    app.workers
        .route(&did)
        .send(WorkerMsg::Write(WriteReq { did, writes, swap_commit, reply: tx, claim: claim.clone(), permit }))
        .map_err(XrpcError::from_err)?;
    let r = match (start_wait, &claim) {
        (Some(wait), Some(c)) => match tokio::time::timeout(wait, &mut rx).await {
            Ok(r) => r,
            Err(_) if c.abandon() => {
                metrics::WRITE_ERRORS.with_label_values(&["not_started"]).inc();
                return Err(XrpcError {
                    status: StatusCode::SERVICE_UNAVAILABLE,
                    error: crate::forward::REPO_LOADING.into(),
                    message: format!(
                        "write not started within {} ms (repo loading); not applied, retry",
                        wait.as_millis()
                    ),
                });
            }
            Err(_) => rx.await,
        },
        _ => rx.await,
    }
    .map_err(|_| XrpcError::internal("worker dropped request"))?;
    STATS.record_request(start.elapsed());
    r.map_err(|e| {
        STATS.write_errors.fetch_add(1, Ordering::Relaxed);
        let kind = match &e {
            WriteError::RepoNotFound => "repo_not_found",
            WriteError::RepoInactive(_) => "repo_inactive",
            WriteError::InvalidSwap(_) => "invalid_swap",
            WriteError::Invalid(_) => "invalid",
            WriteError::Internal(_) => "internal",
            WriteError::Unavailable(_) => "unavailable",
            WriteError::KeyUnavailable(_) => {
                super::key_rotation::kick(app, &did_kick);
                "key_unavailable"
            }
            WriteError::SignatureFault(_) => "signature_fault",
        };
        metrics::WRITE_ERRORS.with_label_values(&[kind]).inc();
        e.into()
    })
}

fn commit_json(ack: &CommitAck) -> J {
    json!({"cid": ack.commit.to_string(), "rev": ack.rev.to_string()})
}

fn uri(did: &str, path: &str) -> String {
    format!("at://{did}/{path}")
}

struct CreateRecordIn<'a> {
    repo: String,
    collection: String,
    rkey: Option<String>,
    record: JsonValue<'a>,
    swap_commit: Option<String>,
    validate: Option<bool>,
}

impl<'a> CreateRecordIn<'a> {
    fn from_tree(mut v: JsonValue<'a>) -> XResult<Self> {
        Ok(CreateRecordIn {
            repo: req_str(&v, "repo")?,
            collection: req_str(&v, "collection")?,
            rkey: opt_str(&v, "rkey")?,
            swap_commit: opt_str(&v, "swapCommit")?,
            validate: opt_bool(&v, "validate")?,
            record: take(&mut v, "record")?,
        })
    }
}

async fn create_record(State(app): AppState, Auth(creds): Auth, body: RecordBody) -> XResult<Json<J>> {
    let mut inp = CreateRecordIn::from_tree(body.parse()?)?;
    crate::ratelimit::check_repo_write(creds.did(), crate::ratelimit::CREATE_POINTS)?;
    let did = authed_repo(&app, &creds, &inp.repo).await?;
    creds.need_repo(&inp.collection, "create")?;
    check_path(&inp.collection, inp.rkey.as_deref())?;
    check_rkey_slur(inp.rkey.as_deref())?;
    let rkey = inp.rkey.unwrap_or_else(|| app.tids.next().to_string());
    let schema = crate::lexicon::resolve_record_schema(&app, &inp.collection, inp.validate).await;
    let (cid, bytes, blobs, status, decls) =
        encode_record(&mut inp.record, &inp.collection, &rkey, inp.validate, schema.as_deref())?;
    let _held = check_blobs(&app, &did, &decls).await?;
    let swap = parse_cid_opt(&inp.swap_commit)?;
    let path = format!("{}/{}", inp.collection, rkey);
    let ack = submit(
        &app,
        did.clone(),
        vec![Write::Create {
            collection: inp.collection,
            rkey,
            cid,
            bytes,
            blobs,
            // the reference's createRecord: unless `validate` is false, the
            // repo's earlier like/repost/follow/block of the subject goes
            prune_backlinks: inp.validate != Some(false),
        }],
        swap,
    )
    .await?;
    Ok(Json(with_status(
        json!({
            "uri": uri(&did, &path),
            "cid": cid.to_string(),
            "commit": commit_json(&ack),
        }),
        status,
    )))
}

struct PutRecordIn<'a> {
    repo: String,
    collection: String,
    rkey: String,
    record: JsonValue<'a>,
    /// Some(None): an explicit null.
    swap_record: Option<Option<String>>,
    swap_commit: Option<String>,
    validate: Option<bool>,
}

impl<'a> PutRecordIn<'a> {
    fn from_tree(mut v: JsonValue<'a>) -> XResult<Self> {
        Ok(PutRecordIn {
            repo: req_str(&v, "repo")?,
            collection: req_str(&v, "collection")?,
            rkey: req_str(&v, "rkey")?,
            swap_record: match v.get("swapRecord") {
                None => None,
                Some(_) => Some(opt_str(&v, "swapRecord")?),
            },
            swap_commit: opt_str(&v, "swapCommit")?,
            validate: opt_bool(&v, "validate")?,
            record: take(&mut v, "record")?,
        })
    }
}

fn parse_swap_record(v: &Option<Option<String>>) -> XResult<Option<Option<Cid>>> {
    match v {
        None => Ok(None),
        Some(None) => Ok(Some(None)),
        Some(Some(s)) => Ok(Some(Some(Cid::parse(s).map_err(|_| XrpcError::bad("InvalidRequest", "bad swapRecord"))?))),
    }
}

async fn put_record(State(app): AppState, Auth(creds): Auth, body: RecordBody) -> XResult<Json<J>> {
    let mut inp = PutRecordIn::from_tree(body.parse()?)?;
    crate::ratelimit::check_repo_write(creds.did(), crate::ratelimit::UPDATE_POINTS)?;
    let did = authed_repo(&app, &creds, &inp.repo).await?;
    creds.need_repo(&inp.collection, "create")?;
    creds.need_repo(&inp.collection, "update")?;
    check_path(&inp.collection, Some(&inp.rkey))?;
    check_rkey_slur(Some(&inp.rkey))?;
    let schema = crate::lexicon::resolve_record_schema(&app, &inp.collection, inp.validate).await;
    let (cid, bytes, blobs, status, decls) =
        encode_record(&mut inp.record, &inp.collection, &inp.rkey, inp.validate, schema.as_deref())?;
    let swap = parse_cid_opt(&inp.swap_commit)?;
    let swap_record = parse_swap_record(&inp.swap_record)?;
    let path = format!("{}/{}", inp.collection, inp.rkey);
    // Writing the record it already holds is a no-op with no `commit` field
    // and no swap checks (reference putRecord).
    if let Some(cur) = app.record_value(&did, None, &path).await? {
        let (cur, _) = state::decode_record_value(&cur).map_err(XrpcError::from_err)?;
        if cur == cid {
            app.ensure_active(&did).await?;
            return Ok(Json(with_status(json!({"uri": uri(&did, &path), "cid": cid.to_string()}), status)));
        }
    }
    let _held = check_blobs(&app, &did, &decls).await?;
    let w = Write::Update {
        collection: inp.collection,
        rkey: inp.rkey,
        cid,
        bytes,
        blobs,
        swap: swap_record,
        must_exist: false,
    };
    let ack = submit(&app, did.clone(), vec![w], swap).await?;
    Ok(Json(with_status(
        json!({
            "uri": uri(&did, &path),
            "cid": cid.to_string(),
            "commit": commit_json(&ack),
        }),
        status,
    )))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeleteRecordIn {
    repo: String,
    collection: String,
    rkey: String,
    swap_record: Option<String>,
    swap_commit: Option<String>,
}

async fn delete_record(State(app): AppState, Auth(creds): Auth, Json(inp): Json<DeleteRecordIn>) -> XResult<Json<J>> {
    crate::ratelimit::check_repo_write(creds.did(), crate::ratelimit::DELETE_POINTS)?;
    let did = authed_repo(&app, &creds, &inp.repo).await?;
    creds.need_repo(&inp.collection, "delete")?;
    check_path(&inp.collection, Some(&inp.rkey))?;
    let swap = parse_cid_opt(&inp.swap_commit)?;
    let swap_record = parse_cid_opt(&inp.swap_record)?.map(Some);
    // A no-op, as in the reference: the worker would otherwise emit an empty
    // commit whose CAR lacks the unchanged MST root, which relays reject.
    let path = format!("{}/{}", inp.collection, inp.rkey);
    if app.record_value(&did, None, &path).await?.is_none() {
        app.ensure_active(&did).await?;
        return Ok(Json(json!({})));
    }
    let w = Write::Delete { collection: inp.collection, rkey: inp.rkey, swap: swap_record };
    let ack = submit(&app, did, vec![w], swap).await?;
    Ok(Json(json!({"commit": commit_json(&ack)})))
}

struct ApplyWritesIn<'a> {
    repo: String,
    writes: Vec<JsonValue<'a>>,
    swap_commit: Option<String>,
    validate: Option<bool>,
}

impl<'a> ApplyWritesIn<'a> {
    fn from_tree(mut v: JsonValue<'a>) -> XResult<Self> {
        Ok(ApplyWritesIn {
            repo: req_str(&v, "repo")?,
            swap_commit: opt_str(&v, "swapCommit")?,
            validate: opt_bool(&v, "validate")?,
            writes: match take(&mut v, "writes")? {
                JsonValue::Array(a) => a,
                _ => return Err(field_err("invalid type for `writes`, expected a sequence".into())),
            },
        })
    }
}

async fn apply_writes(State(app): AppState, Auth(creds): Auth, body: RecordBody) -> XResult<Json<J>> {
    let mut inp = ApplyWritesIn::from_tree(body.parse()?)?;
    {
        use crate::ratelimit::*;
        let points = inp
            .writes
            .iter()
            .map(|w| match w.get("$type").and_then(|t| t.as_str()) {
                Some(CREATE) => CREATE_POINTS,
                Some(UPDATE) => UPDATE_POINTS,
                _ => DELETE_POINTS,
            })
            .sum();
        check_repo_write(creds.did(), points)?;
    }
    let did = authed_repo(&app, &creds, &inp.repo).await?;
    let swap = parse_cid_opt(&inp.swap_commit)?;
    if inp.writes.len() > crate::worker::MAX_COMMIT_OPS {
        return Err(XrpcError::bad(
            "InvalidRequest",
            format!("Too many writes. Max: {}", crate::worker::MAX_COMMIT_OPS),
        ));
    }
    let mut writes = Vec::with_capacity(inp.writes.len());
    let mut statuses = Vec::with_capacity(inp.writes.len());
    let mut decls = Vec::new();
    let mut schemas: std::collections::HashMap<String, Option<Arc<crate::lexicon::Lexicons>>> = Default::default();
    for w in inp.writes.iter_mut() {
        let t = w.get("$type").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let collection = w.get("collection").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let rkey = w.get("rkey").and_then(|v| v.as_str()).map(String::from);
        let action = match t.as_str() {
            CREATE => "create",
            UPDATE => "update",
            _ => "delete",
        };
        creds.need_repo(&collection, action)?;
        check_path(&collection, rkey.as_deref())?;
        if action != "delete" {
            check_rkey_slur(rkey.as_deref())?;
        }
        if action != "delete" && !schemas.contains_key(&collection) {
            let s = crate::lexicon::resolve_record_schema(&app, &collection, inp.validate).await;
            schemas.insert(collection.clone(), s);
        }
        let schema = schemas.get(&collection).cloned().flatten();
        let mut value = w.get_mut("value").map(|x| std::mem::replace(x, JsonValue::Null)).unwrap_or(JsonValue::Null);
        let rkey = match t.as_str() {
            CREATE => rkey.unwrap_or_else(|| app.tids.next().to_string()),
            UPDATE | DELETE => {
                rkey.ok_or_else(|| XrpcError::bad("InvalidRequest", format!("{action} requires rkey")))?
            }
            _ => return Err(XrpcError::bad("InvalidRequest", format!("unknown write type {t}"))),
        };
        if t == DELETE {
            statuses.push(None);
            writes.push(Write::Delete { collection, rkey, swap: None });
            continue;
        }
        let (cid, bytes, blobs, status, d) =
            encode_record(&mut value, &collection, &rkey, inp.validate, schema.as_deref())?;
        statuses.push(status);
        decls.extend(d);
        writes.push(if t == CREATE {
            // the reference prunes duplicate backlinks in createRecord only
            Write::Create { collection, rkey, cid, bytes, blobs, prune_backlinks: false }
        } else {
            Write::Update { collection, rkey, cid, bytes, blobs, swap: None, must_exist: true }
        });
    }
    let _held = check_blobs(&app, &did, &decls).await?;
    let ack = submit(&app, did.clone(), writes, swap).await?;
    let results: Vec<J> = ack
        .results
        .iter()
        .zip(statuses)
        .map(|(r, status)| match r {
            WriteOutcome::Create { path, cid } => with_status(json!({"$type": "com.atproto.repo.applyWrites#createResult", "uri": uri(&did, path), "cid": cid.to_string()}), status),
            WriteOutcome::Update { path, cid } => with_status(json!({"$type": "com.atproto.repo.applyWrites#updateResult", "uri": uri(&did, path), "cid": cid.to_string()}), status),
            WriteOutcome::Delete => json!({"$type": "com.atproto.repo.applyWrites#deleteResult"}),
        })
        .collect();
    Ok(Json(json!({"commit": commit_json(&ack), "results": results})))
}

#[derive(Deserialize)]
struct GetRecordQ {
    repo: String,
    collection: String,
    rkey: String,
    cid: Option<String>,
}

/// Records of repos not hosted here are piped through to the AppView, as in
/// the reference. A DID owned by another node was already forwarded there.
async fn get_record(
    State(app): AppState,
    MaybeAuth(creds): MaybeAuth,
    headers: HeaderMap,
    req_uri: axum::http::Uri,
    Query(q): Query<GetRecordQ>,
) -> XResult<Response> {
    check_path(&q.collection, Some(&q.rkey))?;
    let not_hosted = |e: &XrpcError| e.error == "RepoNotFound" || e.error == "AccountNotFound";
    let local = match app.resolve_repo(&q.repo).await {
        Ok(did) => match app.account(&did).await {
            Ok(_) => Some(did),
            Err(e) if not_hosted(&e) => None,
            Err(e) => return Err(e),
        },
        Err(e) if not_hosted(&e) => None,
        Err(e) => return Err(e),
    };
    let Some(did) = local else {
        if app.config.appview.is_none() {
            return Err(XrpcError::bad("InvalidRequest", "Could not locate record"));
        }
        return super::proxy::pipethrough_unauthed(&app, &headers, &req_uri, "com.atproto.repo.getRecord").await;
    };
    let acct = super::sync::assert_available(&app, &did, creds.as_ref()).await?;
    let path = format!("{}/{}", q.collection, q.rkey);
    let not_found = || XrpcError::bad("RecordNotFound", format!("Could not locate record: at://{did}/{path}"));
    let v = app.record_value(&did, Some(acct.repo_gen), &path).await?.ok_or_else(not_found)?;
    let (cid, bytes) = state::decode_record_value(&v).map_err(XrpcError::from_err)?;
    if super::admin::is_record_takendown(&app, &did, &path).await?
        || q.cid.as_ref().is_some_and(|want| *want != cid.to_string())
    {
        return Err(not_found());
    }
    let mut out = Vec::with_capacity(bytes.len() * 2 + 128);
    write_record_json(&mut out, &uri(&did, &path), &cid, &bytes)?;
    Ok(json_bytes(out))
}

/// Appends `{"uri","cid","value"}`, transcoding DAG-CBOR straight to JSON.
fn write_record_json(out: &mut Vec<u8>, uri: &str, cid: &Cid, bytes: &[u8]) -> XResult<()> {
    out.extend_from_slice(b"{\"uri\":");
    serde_json::to_writer(&mut *out, uri).map_err(XrpcError::from_err)?;
    out.extend_from_slice(b",\"cid\":\"");
    cid.write_string(out);
    out.extend_from_slice(b"\",\"value\":");
    vlatproto::cbor::write_json(bytes, out).map_err(XrpcError::from_err)?;
    out.push(b'}');
    Ok(())
}

pub(super) fn json_bytes(body: Vec<u8>) -> Response {
    ([(axum::http::header::CONTENT_TYPE, "application/json")], body).into_response()
}

#[derive(Deserialize)]
struct ListRecordsQ {
    repo: String,
    collection: String,
    limit: Option<i64>,
    cursor: Option<String>,
    reverse: Option<bool>,
}

async fn list_records(
    State(app): AppState,
    MaybeAuth(creds): MaybeAuth,
    Query(q): Query<ListRecordsQ>,
) -> XResult<Response> {
    check_path(&q.collection, None)?;
    // reference listRecords: any unavailable repo is "Could not find repo"
    let not_found = |e: XrpcError| {
        if e.status == StatusCode::BAD_REQUEST && e.error.starts_with("Repo") {
            XrpcError::bad("InvalidRequest", format!("Could not find repo: {}", q.repo))
        } else {
            e
        }
    };
    let did = app.resolve_repo(&q.repo).await.map_err(not_found)?;
    let acct = super::sync::assert_available(&app, &did, creds.as_ref()).await.map_err(not_found)?;
    let limit = match q.limit {
        None => 50,
        Some(n @ 1..=100) => n as usize,
        Some(n) => return Err(XrpcError::bad("InvalidRequest", format!("limit must be between 1 and 100, got {n}"))),
    };
    // redone at the new generation if an import moved it under the scan
    // (the old one may be part swept)
    let mut gen = acct.repo_gen;
    loop {
        let out = list_records_at(&app, &did, gen, &q, limit).await?;
        let now = app.repo_gen(&did).await?;
        if now == gen {
            return Ok(json_bytes(out));
        }
        gen = now;
    }
}

async fn list_records_at(app: &App, did: &str, gen: u64, q: &ListRecordsQ, limit: usize) -> XResult<Vec<u8>> {
    let p = app.partition(did)?;
    let prefix = state::record_key(did, gen, &format!("{}/", q.collection));
    let end = vlsync_store::keys::prefix_end(&prefix);
    // newest first (descending rkey) unless reverse
    let ascending = q.reverse.unwrap_or(false);
    let (lo, hi) = match (&q.cursor, ascending) {
        (Some(c), true) => ([&prefix[..], c.as_bytes(), &[0]].concat(), end),
        (Some(c), false) => (prefix.clone(), [&prefix[..], c.as_bytes()].concat()),
        (None, _) => (prefix.clone(), end),
    };
    let order = if ascending { slatedb::IterationOrder::Ascending } else { slatedb::IterationOrder::Descending };
    let opts = slatedb::config::ScanOptions::default().with_order(order);
    let takedowns = super::server::ctl(app, did).await?;
    let mut iter = p.db.scan_with_options(lo..hi, &opts).await.map_err(XrpcError::from_err)?;
    let mut out = Vec::with_capacity(limit * 512);
    out.extend_from_slice(b"{\"records\":[");
    let mut n = 0;
    let mut last_rkey = None;
    while n < limit {
        let rows = iter.next_batch(limit - n).await.map_err(XrpcError::from_err)?;
        if rows.is_empty() {
            break;
        }
        for kv in rows {
            let rkey = String::from_utf8_lossy(&kv.key[prefix.len()..]).to_string();
            let rec_uri = uri(did, &format!("{}/{}", q.collection, rkey));
            if takedowns.has_takedown(&format!("rec/{}/{rkey}", q.collection)) {
                last_rkey = Some(rkey);
                continue;
            }
            let (cid, bytes) = state::decode_record_value(&kv.value).map_err(XrpcError::from_err)?;
            if n > 0 {
                out.push(b',');
            }
            write_record_json(&mut out, &rec_uri, &cid, &bytes)?;
            n += 1;
            last_rkey = Some(rkey);
        }
    }
    out.push(b']');
    if let (true, Some(c)) = (n == limit, &last_rkey) {
        out.extend_from_slice(b",\"cursor\":");
        serde_json::to_writer(&mut out, c).map_err(XrpcError::from_err)?;
    }
    out.push(b'}');
    Ok(out)
}

#[derive(Deserialize)]
struct RepoQ {
    repo: String,
}

/// One seek per collection over its contiguous key range, at the
/// account's generation (redone if an import moved it meanwhile).
async fn list_collections(app: &App, did: &str, mut gen: u64) -> XResult<Vec<String>> {
    loop {
        let out = list_collections_at(app, did, gen).await?;
        let now = app.repo_gen(did).await?;
        if now == gen {
            return Ok(out);
        }
        gen = now;
    }
}

async fn list_collections_at(app: &App, did: &str, gen: u64) -> XResult<Vec<String>> {
    let p = app.partition(did)?;
    let prefix = state::record_prefix(did, gen);
    let end = vlsync_store::keys::prefix_end(&prefix);
    let mut lo = prefix.clone();
    let mut out = Vec::new();
    loop {
        let mut iter = p.db.scan(lo..end.clone()).await.map_err(XrpcError::from_err)?;
        let Some(kv) = iter.next().await.map_err(XrpcError::from_err)? else {
            break;
        };
        let path = String::from_utf8_lossy(&kv.key[prefix.len()..]).into_owned();
        let coll = crate::worker::collection_of(&path).to_string();
        lo = vlsync_store::keys::prefix_end(&state::record_key(did, gen, &format!("{coll}/")));
        out.push(coll);
    }
    Ok(out)
}

async fn describe_repo(State(app): AppState, Query(q): Query<RepoQ>) -> XResult<Json<J>> {
    let did = app.resolve_repo(&q.repo).await?;
    let acct = super::sync::assert_available(&app, &did, None).await?;
    let did_doc = super::identity::account_did_doc(&app, &acct)
        .await
        .map_err(|e| XrpcError::bad("InvalidRequest", format!("Could not resolve DID: {e}")))?;
    let handle_is_correct = app.resolve_handle(&acct.handle).await?.as_deref() == Some(acct.did.as_str());
    Ok(Json(json!({
        "handle": if handle_is_correct { acct.handle.as_str() } else { "handle.invalid" },
        "did": acct.did,
        "didDoc": did_doc,
        "collections": list_collections(&app, &did, acct.repo_gen).await?,
        "handleIsCorrect": handle_is_correct,
    })))
}

/// Staged under a new repo generation (`staged_import`), then a new commit
/// signed with our key, and `#sync` unless the account is deactivated
/// (migration in: activation announces it). Like the reference, neither the
/// imported commit's signature nor its `did` is checked: only its contents
/// are used.
async fn import_repo(State(app): AppState, Auth(creds): Auth, headers: HeaderMap, body: Body) -> XResult<StatusCode> {
    let did = creds.user_did()?.to_string();
    creds.need_account("repo", "manage")?;
    if super::server::is_takendown_account(&app.account(&did).await?) {
        return Err(super::takedown_error());
    }
    super::staged_import::import(&app, &did, body, &headers).await?;
    Ok(StatusCode::OK)
}

pub type ImportedRecord = (String, Cid, Bytes, Vec<Cid>);

/// An imported record's blob refs, once its size and encoding are checked.
pub(super) fn imported_record_blobs(path: &str, bytes: &[u8]) -> XResult<Vec<Cid>> {
    if bytes.len() > MAX_IMPORT_RECORD_BYTES {
        return Err(XrpcError::bad("InvalidRequest", format!("record at '{path}' too large ({} bytes)", bytes.len())));
    }
    let v = Value::decode(bytes)
        .map_err(|_| XrpcError::bad("InvalidRequest", format!("Could not parse record at '{path}'")))?;
    let mut blobs = Vec::new();
    blob_refs(&v, &mut blobs);
    Ok(blobs)
}

/// The import of a CAR in any block order. Record bytes are sliced from
/// `body`, not copied.
pub fn parse_import(body: &Bytes) -> XResult<(Vec<ImportedRecord>, vlatproto::mst::Tree)> {
    let bad = |m: String| XrpcError::bad("InvalidRequest", m);
    let (roots, blocks) = car::read_car(body).map_err(|e| bad(format!("invalid CAR: {e}")))?;
    if roots.len() != 1 {
        return Err(bad("expected one root".into()));
    }
    if roots[0].codec != vlatproto::cid::CODEC_DAG_CBOR {
        return Err(bad("commit CID is not dag-cbor".into()));
    }
    let mut map: std::collections::HashMap<Cid, &[u8]> = std::collections::HashMap::with_capacity(blocks.len());
    for (c, b) in blocks {
        if !car::block_matches(&c, b) {
            return Err(bad(format!("block does not match its cid: {c}")));
        }
        map.insert(c, b);
    }
    let commit_bytes = map.get(&roots[0]).ok_or_else(|| bad("missing commit block".into()))?;
    let commit = Value::decode(commit_bytes).map_err(|e| bad(format!("invalid commit: {e}")))?;
    match commit.get("version") {
        Some(Value::Int(2 | 3)) => {}
        _ => return Err(bad("unsupported commit version".into())),
    }
    let Some(Value::Link(data)) = commit.get("data") else {
        return Err(bad("commit has no data root".into()));
    };
    let tree =
        vlatproto::mst::Tree::load_from_blocks(&map, *data).map_err(|e| bad(format!("could not load MST: {e}")))?;
    let mut entries: Vec<(String, Cid)> = Vec::new();
    let mut key_err = None;
    tree.walk(&mut |k, c| match std::str::from_utf8(k) {
        Ok(p) => entries.push((p.to_string(), c)),
        Err(_) => key_err = Some(String::from_utf8_lossy(k).into_owned()),
    });
    if let Some(k) = key_err {
        return Err(bad(format!("invalid record path {k}")));
    }
    drop(tree);
    // walk() skips subtrees missing from the CAR: rebuilding from the walked
    // entries reproduces `data` only if the tree was complete. The rebuilt
    // tree is the one the worker writes.
    let mut check = vlatproto::mst::Tree::new();
    for (path, cid) in &entries {
        check.insert_no_proof(path.as_bytes(), *cid).map_err(|e| bad(format!("invalid record path {path}: {e}")))?;
    }
    if check.root_cid().map_err(XrpcError::from_err)? != *data {
        return Err(bad("CAR does not contain the complete MST".into()));
    }
    let mut out = Vec::with_capacity(entries.len());
    for (path, cid) in entries {
        if !vlatproto::syntax::valid_record_path(&path) {
            return Err(bad(format!("invalid record path {path}")));
        }
        // the root check holds for any leaf CID; records are dag-cbor only
        if cid.codec != vlatproto::cid::CODEC_DAG_CBOR {
            return Err(bad(format!("record CID at {path} is not dag-cbor: {cid}")));
        }
        let bytes = *map.get(&cid).ok_or_else(|| bad(format!("missing record block {cid} at {path}")))?;
        let blobs = imported_record_blobs(&path, bytes)?;
        out.push((path, cid, body.slice_ref(bytes), blobs));
    }
    Ok((out, check))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `serde_json::Value`-based record path, kept as an oracle.
    mod legacy {
        use super::super::*;

        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        pub struct CreateRecordIn {
            pub collection: String,
            pub rkey: Option<String>,
            pub record: J,
            pub validate: Option<bool>,
        }

        fn blob_decls(v: &Value, out: &mut Vec<BlobDecl>) {
            match v {
                Value::Map(m) => {
                    if v.get("$type").and_then(|t| t.as_str()) == Some("blob") {
                        if let Some(Value::Link(c)) = v.get("ref") {
                            let mime = v.get("mimeType").and_then(|m| m.as_str()).map(String::from);
                            let size = match v.get("size") {
                                Some(Value::Int(n)) => Some(*n),
                                _ => None,
                            };
                            out.push((*c, mime, size));
                        }
                    }
                    for (_, child) in m {
                        blob_decls(child, out);
                    }
                }
                Value::Array(a) => a.iter().for_each(|c| blob_decls(c, out)),
                _ => {}
            }
        }

        fn legacy_blob(v: &Value) -> Option<String> {
            match v {
                Value::Map(m) => {
                    if v.get("$type").is_none() {
                        if let (Some(Value::Text(c)), Some(Value::Text(_))) = (v.get("cid"), v.get("mimeType")) {
                            if Cid::parse(c).is_ok() {
                                return Some(c.clone());
                            }
                        }
                    }
                    m.iter().find_map(|(_, c)| legacy_blob(c))
                }
                Value::Array(a) => a.iter().find_map(legacy_blob),
                _ => None,
            }
        }

        pub fn encode_record(v: &J, collection: &str, rkey: &str, validate: Option<bool>) -> XResult<Encoded> {
            let J::Object(o) = v else {
                return Err(XrpcError::bad("InvalidRequest", "record must be an object"));
            };
            let defaulted;
            let v = match o.get("$type") {
                None => {
                    let mut o = o.clone();
                    o.insert("$type".into(), J::String(collection.into()));
                    defaulted = J::Object(o);
                    &defaulted
                }
                Some(J::String(t)) if t == collection => v,
                Some(t) => {
                    return Err(XrpcError::bad(
                        "InvalidRequest",
                        format!("Invalid $type: expected {collection}, got {t}"),
                    ))
                }
            };
            let val = Value::from_json(v).map_err(|e| XrpcError::bad("InvalidRequest", e.to_string()))?;
            let status = crate::lexicon::validate_record(collection, rkey, &val, validate, None)
                .map_err(|e| XrpcError::bad("InvalidRequest", e))?;
            if let Some(c) = legacy_blob(&val) {
                return Err(XrpcError::bad("InvalidRequest", format!("Legacy blobs are not allowed ({c})")));
            }
            let bytes = val.to_cbor();
            if bytes.len() > 1_000_000 {
                return Err(XrpcError::bad("InvalidRequest", "record too large"));
            }
            let mut blobs = Vec::new();
            blob_refs(&val, &mut blobs);
            let mut decls = Vec::new();
            blob_decls(&val, &mut decls);
            Ok((Cid::dag_cbor(&bytes), Bytes::from(bytes), blobs, status, decls))
        }

        /// createRecord body -> encoded record, the old way.
        pub fn create(body: &[u8]) -> XResult<Encoded> {
            let nsid = "com.atproto.repo.createRecord";
            let v: J = serde_json::from_slice(body)
                .map_err(|e| XrpcError::bad("InvalidRequest", format!("Invalid JSON body: {e}")))?;
            crate::lexicon::validate_input(nsid, &v).map_err(|e| XrpcError::bad("InvalidRequest", e))?;
            let inp: CreateRecordIn = serde_json::from_value(v)
                .map_err(|e| XrpcError::bad("InvalidRequest", format!("Invalid JSON body: {e}")))?;
            let rkey = inp.rkey.unwrap_or_else(|| "3jui7kd54zh2y".into());
            encode_record(&inp.record, &inp.collection, &rkey, inp.validate)
        }
    }

    /// createRecord body -> encoded record, as the handler does it.
    fn create(body: &RecordBody) -> XResult<Encoded> {
        let mut inp = CreateRecordIn::from_tree(body.parse()?)?;
        let rkey = inp.rkey.take().unwrap_or_else(|| "3jui7kd54zh2y".into());
        encode_record(&mut inp.record, &inp.collection, &rkey, inp.validate, None)
    }

    fn same(a: &XResult<Encoded>, b: &XResult<Encoded>) -> bool {
        match (a, b) {
            (Ok(a), Ok(b)) => a == b,
            (Err(a), Err(b)) => (a.status, &a.error, &a.message) == (b.status, &b.error, &b.message),
            _ => false,
        }
    }

    fn show(r: &XResult<Encoded>) -> String {
        match r {
            Ok(e) => format!("ok {} {:?} {:?}", e.0, e.3, e.4),
            Err(e) => format!("{} {}: {}", e.status, e.error, e.message),
        }
    }

    const POST: &str = r#"{"$type":"app.bsky.feed.post","text":"Check out this thing @alice.bsky.social wrote about merkle search trees https://example.com/mst — really neat","createdAt":"2026-10-01T12:34:56.789Z","langs":["en"],"facets":[{"index":{"byteStart":15,"byteEnd":34},"features":[{"$type":"app.bsky.richtext.facet#mention","did":"did:plc:ewvi7nxzyoun6zhxrhs64oiz"}]},{"index":{"byteStart":75,"byteEnd":99},"features":[{"$type":"app.bsky.richtext.facet#link","uri":"https://example.com/mst"}]}],"reply":{"root":{"uri":"at://did:plc:ewvi7nxzyoun6zhxrhs64oiz/app.bsky.feed.post/3l3qo2vuowo2b","cid":"bafyreie5737gdxlw5i64vzichcalba3z2v5n6icifvx5xytvske7mr3hpm"},"parent":{"uri":"at://did:plc:ewvi7nxzyoun6zhxrhs64oiz/app.bsky.feed.post/3l3qo2vuowo2b","cid":"bafyreie5737gdxlw5i64vzichcalba3z2v5n6icifvx5xytvske7mr3hpm"}},"embed":{"$type":"app.bsky.embed.images","images":[{"alt":"a diagram of a tree","image":{"$type":"blob","ref":{"$link":"bafkreie5737gdxlw5i64vzichcalba3z2v5n6icifvx5xytvske7mr3hpm"},"mimeType":"image/jpeg","size":123456},"aspectRatio":{"width":1200,"height":800}}]}}"#;
    const LIKE: &str = r#"{"$type":"app.bsky.feed.like","subject":{"uri":"at://did:plc:ewvi7nxzyoun6zhxrhs64oiz/app.bsky.feed.post/3l3qo2vuowo2b","cid":"bafyreie5737gdxlw5i64vzichcalba3z2v5n6icifvx5xytvske7mr3hpm"},"createdAt":"2026-10-01T12:34:56.789Z"}"#;

    fn body(collection: &str, record: &str, extra: &str) -> Vec<u8> {
        format!(r#"{{"repo":"did:plc:ewvi7nxzyoun6zhxrhs64oiz","collection":"{collection}"{extra},"record":{record}}}"#)
            .into_bytes()
    }

    /// The handler path against the oracle: same CID, bytes, blob refs,
    /// declarations and validation status, or the same error.
    #[test]
    fn record_path_matches_legacy() {
        let post_no_type = POST.replacen(r#""$type":"app.bsky.feed.post","#, "", 1);
        let cases: Vec<(&str, String, &str)> = vec![
            ("app.bsky.feed.post", POST.into(), ""),
            ("app.bsky.feed.like", LIKE.into(), ""),
            ("app.bsky.feed.post", post_no_type.clone(), ""),
            ("app.bsky.feed.like", POST.into(), ""),
            ("app.bsky.feed.post", post_no_type.replace("2026-10-01T12:34:56.789Z", "yesterday"), ""),
            ("app.bsky.feed.post", POST.replace("image/jpeg", "text/html"), ""),
            ("app.bsky.feed.post", POST.replace("123456", "123456.0"), ""),
            ("app.bsky.feed.post", POST.replace("123456", "1.5"), ""),
            ("app.bsky.feed.post", POST.replace(r#""langs":["en"]"#, r#""langs":["en"],"langs":[5]"#), ""),
            ("app.bsky.feed.post", POST.replace(r#""langs":["en"]"#, r#""langs":[5],"langs":["en"]"#), ""),
            ("app.bsky.feed.post", POST.replace(r#""alt":"a diagram of a tree""#, r#""alt":"x","legacy":{"cid":"bafyreie5737gdxlw5i64vzichcalba3z2v5n6icifvx5xytvske7mr3hpm","mimeType":"image/png"}"#), ""),
            ("app.bsky.feed.post", POST.replace("bafkreie5737", "bafkreiX5737"), ""),
            ("app.bsky.feed.post", POST.into(), r#","validate":false"#),
            ("app.bsky.feed.post", POST.into(), r#","validate":true"#),
            ("com.example.thing", r#"{"a":1.0,"b":{"$bytes":"AQID"},"c":{"$link":"bafyreie5737gdxlw5i64vzichcalba3z2v5n6icifvx5xytvske7mr3hpm"}}"#.into(), ""),
            ("com.example.thing", r#"{"a":1.0}"#.into(), r#","validate":true"#),
            ("com.example.thing", r#"{"$type":5}"#.into(), ""),
            ("com.example.thing", r#"{"$type":"com.example.other"}"#.into(), ""),
            ("com.example.thing", r#""text""#.into(), ""),
            ("com.example.thing", r#"[]"#.into(), ""),
            ("com.example.thing", r#"{"x":{"$link":"bad","y":1}}"#.into(), ""),
            ("com.example.thing", r#"{"x":9223372036854775808}"#.into(), ""),
            ("com.example.thing", r#"{"x":{"$type":"blob","ref":{"$link":"bafkreie5737gdxlw5i64vzichcalba3z2v5n6icifvx5xytvske7mr3hpm"},"mimeType":"a/b","size":18446744073709551615}}"#.into(), ""),
            ("com.example.thing", r#"{"z":1.5,"a":{"$link":"bad"}}"#.into(), ""),
            ("com.example.thing", format!(r#"{{"big":"{}"}}"#, "x".repeat(1_000_001)), ""),
        ];
        for (coll, rec, extra) in &cases {
            let b = body(coll, rec, extra);
            let old = legacy::create(&b);
            let new = create(&RecordBody::new("com.atproto.repo.createRecord", b.clone()));
            assert!(
                same(&old, &new),
                "{coll} {extra} {}:\n old {}\n new {}",
                &rec[..rec.len().min(200)],
                show(&old),
                show(&new)
            );
        }
        // input-level failures read the same too
        for b in [
            &br#"{"repo":1,"collection":"a.b.c","record":{}}"#[..],
            br#"{"repo":"did:plc:abc","record":{}}"#,
            br#"{"repo":"did:plc:abc","collection":"a.b.c","record":{},"validate":"yes"}"#,
            br#"{"repo":"did:plc:abc","collection":"a.b.c","record":{"#,
            br#"[]"#,
        ] {
            let old = legacy::create(b);
            let new = create(&RecordBody::new("com.atproto.repo.createRecord", b.to_vec()));
            assert!(same(&old, &new), "{}:\n old {}\n new {}", String::from_utf8_lossy(b), show(&old), show(&new));
        }
    }

    /// `cargo test --profile dev-release --lib xrpc::repo::tests::bench_record_path -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn bench_record_path() {
        let n = 300_000u32;
        let run = |name: &str, f: &dyn Fn() -> usize| {
            let mut sink = 0;
            for _ in 0..n / 10 {
                sink += f();
            }
            let t = Instant::now();
            for _ in 0..n {
                sink += f();
            }
            let us = t.elapsed().as_secs_f64() * 1e6 / n as f64;
            println!("{name:44} {us:6.2} us/op ({})", sink % 7);
        };
        for (name, coll, rec) in [("post", "app.bsky.feed.post", POST), ("like", "app.bsky.feed.like", LIKE)] {
            let b = body(coll, rec, "");
            let rb = RecordBody::new("com.atproto.repo.createRecord", b.clone());
            assert!(same(&legacy::create(&b), &create(&rb)));
            run(&format!("{name} createRecord body -> record: old"), &|| legacy::create(&b).ok().unwrap().1.len());
            run(&format!("{name} createRecord body -> record: new"), &|| create(&rb).ok().unwrap().1.len());
            run(&format!("{name}   parse body tree"), &|| rb.parse().ok().unwrap().get("record").is_some() as usize);
            run(&format!("{name}   parse + input lexicon"), &|| {
                CreateRecordIn::from_tree(rb.parse().ok().unwrap()).ok().unwrap().repo.len()
            });
            let mut rec = CreateRecordIn::from_tree(rb.parse().ok().unwrap()).ok().unwrap().record;
            let mut out = Vec::new();
            rec.encode_record(&mut out, &mut Default::default()).unwrap();
            run(&format!("{name}   encode only"), &|| {
                let mut r = rec.clone();
                let mut out = Vec::with_capacity(512);
                r.encode_record(&mut out, &mut Default::default()).unwrap();
                out.len()
            });
            run(&format!("{name}   clone only"), &|| matches!(rec.clone(), JsonValue::Object(_)) as usize);
            run(&format!("{name}   record lexicon only"), &|| {
                crate::lexicon::validate_record(coll, "3jui7kd54zh2y", &rec, None, None).unwrap().unwrap().len()
            });
            run(&format!("{name}   sha256 cid only"), &|| Cid::dag_cbor(&out).digest[0] as usize);
        }
    }
}
