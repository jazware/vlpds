//! `com.atproto.space.*` (`--spaces`; src/space, DESIGN.md "Spaces"): space
//! record writes through the author's repo worker, reads of space repos by
//! their owner (OAuth) or a space credential, the credential exchange, and
//! the notifyWrite outbox's sends.

use super::authn::{verify_delegation, SpaceAuth};
use super::extract::RecordBody;
use super::repo::{
    check_path, check_rkey_slur, encode_record, json_bytes, opt_bool, opt_str, req_str, take, with_status,
};
use super::*;
use crate::cbor::JsonValue;
use crate::oauth::scopes::{SpaceAccess, SpaceTarget};
use crate::space::heads::DurableSpaceHead;
use crate::space::lthash::LtHash;
use crate::space::outbox::{Outcome, Pending};
use crate::space::repo::{
    PutScopes, SameRev, SpaceAck, SpaceError, SpaceOp, SpaceOutcome, SpaceReq, SpaceWrite, MAX_WRITES,
};
use crate::space::revocations;
use crate::space::rows::{HeadRow, OpRow};
use crate::space::token::{self, TokenType};
use crate::space::Spaces;
use crate::state::SpaceId;
use crate::tid::Tid;
use base64::Engine;

pub fn routes() -> Router<Arc<App>> {
    Router::new()
        .route("/xrpc/com.atproto.space.createRecord", post(create_record))
        .route("/xrpc/com.atproto.space.putRecord", post(put_record))
        .route("/xrpc/com.atproto.space.deleteRecord", post(delete_record))
        .route("/xrpc/com.atproto.space.applyWrites", post(apply_writes))
        .route("/xrpc/com.atproto.space.getRecord", get(get_record))
        .route("/xrpc/com.atproto.space.listRecords", get(list_records))
        .route("/xrpc/com.atproto.space.getBlob", get(get_blob))
        .route("/xrpc/com.atproto.space.listBlobs", get(list_blobs))
        .route("/xrpc/com.atproto.space.getLatestCommit", get(get_latest_commit))
        .route("/xrpc/com.atproto.space.listRepoOps", get(list_repo_ops))
        .route("/xrpc/com.atproto.space.getDelegationToken", get(get_delegation_token))
        .route("/xrpc/com.atproto.space.getSpaceCredential", post(get_space_credential))
        .route("/xrpc/com.atproto.space.listSpaces", get(list_spaces))
        .route("/xrpc/com.atproto.space.notifyCredentialRevoked", post(notify_credential_revoked))
        .route("/xrpc/com.atproto.space.getRepo", get(get_repo))
        .route("/xrpc/com.atproto.space.notifyWrite", post(notify_write))
        .route("/xrpc/com.atproto.space.listRepos", get(list_repos))
        .route("/xrpc/com.atproto.space.registerNotify", post(register_notify))
        .route("/xrpc/com.atproto.space.unregisterNotify", post(unregister_notify))
}

pub fn internal_routes() -> Router<Arc<App>> {
    Router::new()
        .route("/internal/v1/space/revocations/reload", post(internal_reload_revocations))
        .route("/internal/v1/space/notify", post(internal_notify))
        .route("/internal/v1/space/holdsRepo", get(internal_holds_repo))
        .route("/internal/v1/space/importCheck", get(super::space_import::internal_import_check))
}

pub(super) fn spaces(app: &App) -> XResult<&Arc<Spaces>> {
    app.spaces.as_ref().ok_or_else(|| XrpcError {
        status: StatusCode::NOT_IMPLEMENTED,
        error: "MethodNotImplemented".into(),
        message: "Method Not Implemented".into(),
    })
}

/// A `space-ref` parameter, canonical.
pub(super) struct Space {
    pub uri: String,
    pub authority: String,
    pub space_type: String,
    pub skey: String,
    pub sid: SpaceId,
}

impl Space {
    pub fn parse(s: &str) -> XResult<Space> {
        let u = super::syntax::parse_space_uri(s)
            .filter(|u| u.record.is_none())
            .ok_or_else(|| XrpcError::bad("InvalidRequest", format!("Not a space uri: {s}")))?;
        let uri = format!("at://{}/space/{}/{}", u.authority, u.space_type, u.skey);
        Ok(Space {
            sid: state::space_id(&uri),
            authority: u.authority.into(),
            space_type: u.space_type.into(),
            skey: u.skey.into(),
            uri,
        })
    }

    pub fn target(&self) -> SpaceTarget<'_> {
        SpaceTarget { space_type: &self.space_type, authority: &self.authority, skey: &self.skey }
    }

    fn record_uri(&self, author: &str, path: &str) -> String {
        format!("{}/{author}/{path}", self.uri)
    }
}

pub(super) fn space_error(e: SpaceError) -> XrpcError {
    match e {
        SpaceError::Write(w) => w.into(),
        SpaceError::RecordNotFound(m) => XrpcError::bad("RecordNotFound", m),
        SpaceError::RecordAlreadyExists(m) => XrpcError::bad("RecordAlreadyExists", m),
        SpaceError::ScopeMissing(scope) => super::authn::scope_refused("oauth", &scope),
        SpaceError::SpaceNotFound => XrpcError::bad("SpaceNotFound", "Space not found"),
        SpaceError::SpaceDeleted => XrpcError::bad("SpaceDeleted", "Space has been deleted"),
        SpaceError::SpaceAlreadyExists => XrpcError::bad("SpaceAlreadyExists", "Space already exists"),
        SpaceError::NotAuthorized(m) => forbidden(m),
        SpaceError::Unswept(_) => XrpcError::unavailable("Unavailable", "the space repo is being cleared; retry"),
        SpaceError::SameRev => XrpcError::internal("an unchecked same-rev notify"),
    }
}

fn forbidden(m: impl Into<String>) -> XrpcError {
    XrpcError { status: StatusCode::FORBIDDEN, error: "Forbidden".into(), message: m.into() }
}

/// Queues `op` on `did`'s repo worker, which orders it with the account's
/// commits and status changes, and waits for its ack (durable, applied). A
/// first write over rows an import or a sweep left behind clears them and
/// runs again.
pub(super) async fn submit_space(app: &App, did: &str, space: &Space, op: SpaceOp) -> XResult<SpaceAck> {
    let ack = match submit_space_once(app, did, space, op).await? {
        Err(SpaceError::Unswept(writes)) => {
            super::space_import::sweep_unheaded(app, did, space).await?;
            submit_space_once(app, did, space, SpaceOp::Write { writes }).await?.map_err(space_error)
        }
        r => r.map_err(space_error),
    }?;
    // the authority's own write sequenced its whole set: with records of it
    // taken down, what it serves (and so listRepos) is the set without them
    if matches!(ack, SpaceAck::Write { rev: Some(_), .. })
        && did == space.authority
        && !hidden_paths(app, did, &space.sid).await.map_err(after_applied)?.is_empty()
    {
        push_served_hash(app, did, space.sid).await.map_err(after_applied)?;
    }
    Ok(ack)
}

/// A failure once the write is applied: neither a refusal nor a "nothing
/// done" answer (ShardMoved, which the entry node resends), but a 500 whose
/// outcome the client must treat as unknown.
fn after_applied(e: XrpcError) -> XrpcError {
    XrpcError::internal(format!("the write was applied, then failed: {}", e.message))
}

pub(super) async fn submit_space_once(
    app: &App,
    did: &str,
    space: &Space,
    op: SpaceOp,
) -> XResult<Result<SpaceAck, SpaceError>> {
    let sp = spaces(app)?.clone();
    let Ok(permit) = app.write_permits.clone().try_acquire_owned() else {
        metrics::WRITES_SHED.inc();
        return Err(XrpcError::unavailable("Overloaded", "too many writes in flight; retry with backoff"));
    };
    let (tx, rx) = oneshot::channel();
    let req = SpaceReq {
        did: did.into(),
        uri: space.uri.as_str().into(),
        sid: space.sid,
        op,
        spaces: sp,
        reply: tx,
        permit: Some(permit),
    };
    app.workers.route(did).send(WorkerMsg::Space(req)).map_err(XrpcError::from_err)?;
    rx.await.map_err(|_| XrpcError::internal("worker dropped request"))
}

/// Reference: `repo` must be the caller (ForbiddenError).
fn writer(creds: &Credentials, repo: &str) -> XResult<String> {
    let did = creds.user_did()?;
    if did != repo {
        return Err(forbidden("repo must match authenticated user"));
    }
    Ok(did.to_string())
}

struct Prepared {
    collection: String,
    rkey: String,
    cid: Cid,
    bytes: Bytes,
    blobs: Vec<Cid>,
    decls: Vec<super::repo::BlobDecl>,
    status: crate::lexicon::ValidationStatus,
}

/// Reference prepareCreate/prepareUpdate of a space record. Its blobs are
/// checked as a repo write's are (`check_blobs`), by the caller.
async fn prepare(
    app: &Arc<App>,
    collection: String,
    rkey: String,
    mut record: JsonValue<'_>,
    validate: Option<bool>,
) -> XResult<Prepared> {
    check_path(&collection, Some(&rkey))?;
    check_rkey_slur(Some(&rkey))?;
    let schema = crate::lexicon::resolve_record_schema(app, &collection, validate).await;
    let (cid, bytes, blobs, status, decls) =
        encode_record(&mut record, &collection, &rkey, validate, schema.as_deref())?;
    Ok(Prepared { collection, rkey, cid, bytes, blobs, decls, status })
}

fn write_result(op: &str, r: &XResult<impl Sized>) {
    let result = match r {
        Ok(_) => "ok",
        Err(e) if e.status.is_server_error() => "error",
        Err(_) => "refused",
    };
    metrics::space_write(op, result);
}

async fn create_record(State(app): AppState, Auth(creds): Auth, body: RecordBody) -> XResult<Json<J>> {
    let r = create_record_inner(&app, &creds, body).await;
    write_result("createRecord", &r);
    r
}

async fn create_record_inner(app: &Arc<App>, creds: &Credentials, body: RecordBody) -> XResult<Json<J>> {
    spaces(app)?;
    let mut v = body.parse()?;
    let space = Space::parse(&req_str(&v, "space")?)?;
    let (repo, collection) = (req_str(&v, "repo")?, req_str(&v, "collection")?);
    let (rkey, validate) = (opt_str(&v, "rkey")?, opt_bool(&v, "validate")?);
    let record = take(&mut v, "record")?;
    crate::ratelimit::check_repo_write(creds.did(), crate::ratelimit::CREATE_POINTS)?;
    let did = writer(creds, &repo)?;
    creds.need_space(&space.target(), SpaceAccess::Write("create", &collection))?;
    check_path(&collection, rkey.as_deref())?;
    let rkey = rkey.unwrap_or_else(|| app.tids.next().to_string());
    let p = prepare(app, collection, rkey, record, validate).await?;
    let _held = super::repo::check_blobs(app, &did, &p.decls).await?;
    let path = format!("{}/{}", p.collection, p.rkey);
    let w = SpaceWrite::Create { collection: p.collection, rkey: p.rkey, cid: p.cid, bytes: p.bytes, blobs: p.blobs };
    submit_space(app, &did, &space, SpaceOp::Write { writes: vec![w] }).await?;
    Ok(Json(with_status(json!({"uri": space.record_uri(&did, &path), "cid": p.cid.to_string()}), p.status)))
}

async fn put_record(State(app): AppState, Auth(creds): Auth, body: RecordBody) -> XResult<Json<J>> {
    let r = put_record_inner(&app, &creds, body).await;
    write_result("putRecord", &r);
    r
}

async fn put_record_inner(app: &Arc<App>, creds: &Credentials, body: RecordBody) -> XResult<Json<J>> {
    spaces(app)?;
    let mut v = body.parse()?;
    let space = Space::parse(&req_str(&v, "space")?)?;
    let (repo, collection, rkey) = (req_str(&v, "repo")?, req_str(&v, "collection")?, req_str(&v, "rkey")?);
    let validate = opt_bool(&v, "validate")?;
    let record = take(&mut v, "record")?;
    crate::ratelimit::check_repo_write(creds.did(), crate::ratelimit::UPDATE_POINTS)?;
    let did = writer(creds, &repo)?;
    // a create or an update by what the path holds: the worker asks for the
    // scope of the one it turns out to be (reference putRecord)
    let t = space.target();
    let missing = |action| {
        let a = SpaceAccess::Write(action, &collection);
        (!creds.allows_space(&t, a)).then(|| crate::oauth::scopes::SpacePermission::needed_for(&t, a))
    };
    let put = PutScopes { create: missing("create"), update: missing("update") };
    if put.create.is_some() && put.update.is_some() {
        // neither would do: the refusal names the create scope, as for a new record
        creds.need_space(&t, SpaceAccess::Write("create", &collection))?;
    }
    let p = prepare(app, collection, rkey, record, validate).await?;
    let _held = super::repo::check_blobs(app, &did, &p.decls).await?;
    let path = format!("{}/{}", p.collection, p.rkey);
    let w = SpaceWrite::Update {
        collection: p.collection,
        rkey: p.rkey,
        cid: p.cid,
        bytes: p.bytes,
        blobs: p.blobs,
        must_exist: false,
        put: Some(put).filter(|p| p.create.is_some() || p.update.is_some()),
    };
    submit_space(app, &did, &space, SpaceOp::Write { writes: vec![w] }).await?;
    Ok(Json(with_status(json!({"uri": space.record_uri(&did, &path), "cid": p.cid.to_string()}), p.status)))
}

#[derive(Deserialize)]
struct DeleteRecordIn {
    space: String,
    repo: String,
    collection: String,
    rkey: String,
}

async fn delete_record(State(app): AppState, Auth(creds): Auth, Json(inp): Json<DeleteRecordIn>) -> XResult<Json<J>> {
    let r = delete_record_inner(&app, &creds, inp).await;
    write_result("deleteRecord", &r);
    r
}

async fn delete_record_inner(app: &App, creds: &Credentials, inp: DeleteRecordIn) -> XResult<Json<J>> {
    spaces(app)?;
    let space = Space::parse(&inp.space)?;
    crate::ratelimit::check_repo_write(creds.did(), crate::ratelimit::DELETE_POINTS)?;
    let did = writer(creds, &inp.repo)?;
    creds.need_space(&space.target(), SpaceAccess::Write("delete", &inp.collection))?;
    check_path(&inp.collection, Some(&inp.rkey))?;
    // idempotent, as com.atproto.repo.deleteRecord is
    let w = SpaceWrite::Delete { collection: inp.collection, rkey: inp.rkey, must_exist: false };
    submit_space(app, &did, &space, SpaceOp::Write { writes: vec![w] }).await?;
    Ok(Json(json!({})))
}

const CREATE: &str = "com.atproto.space.applyWrites#create";
const UPDATE: &str = "com.atproto.space.applyWrites#update";
const DELETE: &str = "com.atproto.space.applyWrites#delete";

async fn apply_writes(State(app): AppState, Auth(creds): Auth, body: RecordBody) -> XResult<Json<J>> {
    let r = apply_writes_inner(&app, &creds, body).await;
    write_result("applyWrites", &r);
    r
}

async fn apply_writes_inner(app: &Arc<App>, creds: &Credentials, body: RecordBody) -> XResult<Json<J>> {
    spaces(app)?;
    let mut v = body.parse()?;
    let space = Space::parse(&req_str(&v, "space")?)?;
    let repo = req_str(&v, "repo")?;
    let validate = opt_bool(&v, "validate")?;
    let mut writes = match take(&mut v, "writes")? {
        JsonValue::Array(a) => a,
        _ => return Err(super::repo::field_err("invalid type for `writes`, expected a sequence".into())),
    };
    {
        use crate::ratelimit::*;
        let points = writes
            .iter()
            .map(|w| match w.get("$type").and_then(|t| t.as_str()) {
                Some(CREATE) => CREATE_POINTS,
                Some(UPDATE) => UPDATE_POINTS,
                _ => DELETE_POINTS,
            })
            .sum();
        check_repo_write(creds.did(), points)?;
    }
    let did = writer(creds, &repo)?;
    if writes.len() > MAX_WRITES {
        return Err(XrpcError::bad("InvalidRequest", format!("Too many writes. Max: {MAX_WRITES}")));
    }
    let mut ops = Vec::with_capacity(writes.len());
    let mut statuses = Vec::with_capacity(writes.len());
    let mut decls = Vec::new();
    for w in writes.iter_mut() {
        let t = w.get("$type").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let collection = w.get("collection").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let rkey = w.get("rkey").and_then(|v| v.as_str()).map(String::from);
        let action = match t.as_str() {
            CREATE => "create",
            UPDATE => "update",
            DELETE => "delete",
            _ => return Err(XrpcError::bad("InvalidRequest", format!("Action not supported: {t}"))),
        };
        creds.need_space(&space.target(), SpaceAccess::Write(action, &collection))?;
        check_path(&collection, rkey.as_deref())?;
        if action == "delete" {
            let rkey = rkey.ok_or_else(|| XrpcError::bad("InvalidRequest", "delete requires rkey"))?;
            statuses.push(None);
            ops.push(SpaceWrite::Delete { collection, rkey, must_exist: true });
            continue;
        }
        let rkey = match (action, rkey) {
            ("create", r) => r.unwrap_or_else(|| app.tids.next().to_string()),
            (_, Some(r)) => r,
            (_, None) => return Err(XrpcError::bad("InvalidRequest", "update requires rkey")),
        };
        let value = w.get_mut("value").map(|x| std::mem::replace(x, JsonValue::Null)).unwrap_or(JsonValue::Null);
        let p = prepare(app, collection, rkey, value, validate).await?;
        statuses.push(p.status);
        decls.extend(p.decls);
        ops.push(match action {
            "create" => SpaceWrite::Create {
                collection: p.collection,
                rkey: p.rkey,
                cid: p.cid,
                bytes: p.bytes,
                blobs: p.blobs,
            },
            _ => SpaceWrite::Update {
                collection: p.collection,
                rkey: p.rkey,
                cid: p.cid,
                bytes: p.bytes,
                blobs: p.blobs,
                must_exist: true,
                put: None,
            },
        });
    }
    let _held = super::repo::check_blobs(app, &did, &decls).await?;
    let results = match submit_space(app, &did, &space, SpaceOp::Write { writes: ops }).await? {
        SpaceAck::Write { results, .. } => results,
        _ => return Err(XrpcError::internal("unexpected space ack")),
    };
    let results: Vec<J> = results
        .iter()
        .zip(statuses)
        .map(|(r, status)| match r {
            SpaceOutcome::Create { path, cid } => with_status(
                json!({"$type": "com.atproto.space.applyWrites#createResult", "uri": space.record_uri(&did, path), "cid": cid.to_string()}),
                status,
            ),
            SpaceOutcome::Update { path, cid } => with_status(
                json!({"$type": "com.atproto.space.applyWrites#updateResult", "uri": space.record_uri(&did, path), "cid": cid.to_string()}),
                status,
            ),
            SpaceOutcome::Delete | SpaceOutcome::Noop => json!({"$type": "com.atproto.space.applyWrites#deleteResult"}),
        })
        .collect();
    Ok(Json(json!({"results": results})))
}

/// Reference `assertSpaceRead`: a credential reads any member's repo it is
/// addressed to (the audience) in its own space; an account reads its own
/// repo with `read_self`. Whether a repo exists in a space the caller can't
/// read is none of its business: RepoNotFound either way. Ok(true): a
/// self-read.
pub(super) fn assert_space_read(creds: &Credentials, space: &Space, repo: &str) -> XResult<bool> {
    match creds {
        Credentials::SpaceCredential { audience, space: s, .. } => {
            assert_credential_space(audience, s, space, repo)?;
            Ok(false)
        }
        c => {
            if c.did() != Some(repo) {
                return Err(XrpcError::bad("RepoNotFound", format!("Could not find repo for DID: {repo}")));
            }
            c.need_space(&space.target(), SpaceAccess::ReadSelf)?;
            Ok(true)
        }
    }
}

/// A space takedown closes the space to credential readers on its host
/// too: credentials minted before it would otherwise read on for up to
/// 300 s. The account's own reads of its repo stay open.
async fn assert_space_open(app: &App, space: &Space, self_read: bool) -> XResult<()> {
    if !self_read && space_takendown(app, space).await? {
        return Err(super::simplespace::space_not_found());
    }
    Ok(())
}

/// Reference `assertCredentialSpace`: the request's audience is the repo
/// read (the authority for host methods), and the credential is this
/// space's. The audience header is signed but names no method or URL, so
/// these checks are what bind a signature to this request.
pub(super) fn assert_credential_space(audience: &str, cred_space: &str, space: &Space, target: &str) -> XResult<()> {
    if audience != target {
        metrics::space_credential_check("audience");
        return Err(XrpcError {
            status: StatusCode::UNAUTHORIZED,
            error: "BadSpaceAudience".into(),
            message: "space audience does not match the request".into(),
        });
    }
    if cred_space != space.uri {
        metrics::space_credential_check("space");
        return Err(XrpcError::bad("InvalidCredential", "Credential is not scoped to this space"));
    }
    metrics::space_credential_check("ok");
    Ok(())
}

/// A space record's takedown, beside the account's `rec/` ones
/// (`sec/td/space/{sid}/{collection}/{rkey}`). The space's id rather than
/// its URI keeps the name short; the record's author is the account.
pub(super) fn takedown_name(sid: &SpaceId, path: &str) -> String {
    format!("space/{}/{path}", hex::encode(sid))
}

/// A space's own takedown (a vlpds extension), on its authority's account
/// beside its records' (`sec/td/space/{sid}`): no credentials, no
/// listRepos or registrations, and writers' notifies dropped.
pub(super) fn space_takedown_name(sid: &SpaceId) -> String {
    format!("space/{}", hex::encode(sid))
}

pub(super) async fn space_takendown(app: &App, space: &Space) -> XResult<bool> {
    space_sid_takendown(app, &space.authority, &space.sid).await
}

pub(crate) async fn space_sid_takendown(app: &App, authority: &str, sid: &SpaceId) -> XResult<bool> {
    Ok(super::server::ctl(app, authority).await?.has_takedown(&space_takedown_name(sid)))
}

/// The repo's records taken down in this space, by path. Record takedowns
/// are a vlpds extension (the reference has none for space records): the
/// sync views leave these records out of the index, the blocks and the
/// ops, and sign a commit over the set without them, so what's served
/// still verifies and a syncer that held one sees its digest mismatch and
/// refetches. A reversal flips it back the same way.
pub(super) async fn hidden_paths(app: &App, repo: &str, sid: &SpaceId) -> XResult<Vec<String>> {
    let ctl = super::server::ctl(app, repo).await?;
    Ok(ctl.takedowns_under(&takedown_name(sid, "")))
}

/// The hash `repo` serves in `space` at `rev` when records of it there are
/// taken down: its set less those, which is what its authority should hold.
/// None: nothing is hidden, or the head is past `rev` (a newer notify
/// follows).
async fn served_digest(app: &App, repo: &str, space: &Space, rev: Tid) -> XResult<Option<[u8; 32]>> {
    let hidden = hidden_paths(app, repo, &space.sid).await?;
    if hidden.is_empty() {
        return Ok(None);
    }
    let p = app.partition(repo)?;
    let snap = p.db.snapshot().map_err(XrpcError::from_err)?;
    let Some(v) = snap.get(state::space_head_key(repo, &space.sid)).await.map_err(XrpcError::from_err)? else {
        return Ok(None);
    };
    let row = HeadRow::decode(&v).map_err(XrpcError::from_err)?;
    if row.rev != rev {
        return Ok(None);
    }
    Ok(Some(served_set(&snap, repo, &space.sid, &row.hash, &hidden).await?.digest()))
}

/// A record takedown or its reversal in `sid` changed what `repo` serves
/// there at its current rev, so its authority (and through it the space's
/// syncers) hears the new hash at the same rev: from the outbox, or at
/// once when the repo is the authority's own. Best effort: syncers polling
/// see it anyway.
async fn push_served_hash(app: &App, repo: &str, sid: SpaceId) -> XResult<()> {
    let sp = spaces(app)?;
    let p = app.partition(repo)?;
    let Some(v) = p.db.get(state::space_head_key(repo, &sid)).await.map_err(XrpcError::from_err)? else {
        return Ok(());
    };
    let row = HeadRow::decode(&v).map_err(XrpcError::from_err)?;
    let space = Space::parse(&row.uri)?;
    if space.authority != repo {
        sp.outbox.renotify(repo, sid, &row.uri, row.rev, row.hash.digest());
        return Ok(());
    }
    let hash = served_digest(app, repo, &space, row.rev).await?.unwrap_or_else(|| row.hash.digest());
    let op = SpaceOp::RecordWriter {
        writer: repo.to_string(),
        repo_rev: row.rev,
        hash,
        managing_app: None,
        same_rev: SameRev::Sequence,
    };
    submit_space_once(app, repo, &space, op).await?.map(|_| ()).map_err(space_error)
}

/// After `muts` were written to `did`'s private state here (its shard's
/// owner): a space record takedown or reversal among them is pushed.
pub(super) async fn sec_written(app: &App, did: &str, muts: &[crate::segment::Mutation]) {
    if app.spaces.is_none() || app.remote_owner(did).is_some() {
        return;
    }
    let prefix = state::private_key(did, &format!("{}space/", super::server::TAKEDOWN));
    let mut sids: Vec<SpaceId> = Vec::new();
    for m in muts {
        let Some(rest) = m.key.strip_prefix(prefix.as_slice()) else { continue };
        // a record's (`{sid}/{path}`), not the space's own (`{sid}`)
        let Some((hex_sid, path)) = std::str::from_utf8(rest).ok().and_then(|r| r.split_once('/')) else { continue };
        let Some(sid) = hex::decode(hex_sid).ok().and_then(|b| SpaceId::try_from(b).ok()) else { continue };
        if !path.is_empty() && !sids.contains(&sid) {
            sids.push(sid);
        }
    }
    for sid in sids {
        if let Err(e) = push_served_hash(app, did, sid).await {
            tracing::info!(%did, space = %hex::encode(sid), "space takedown push failed: {}", e.message);
        }
    }
}

/// `set` less the hidden records as `snap` holds them.
async fn served_set(
    snap: &slatedb::DbSnapshot,
    repo: &str,
    sid: &SpaceId,
    set: &LtHash,
    hidden: &[String],
) -> XResult<LtHash> {
    let mut set = set.clone();
    for path in hidden {
        let Some(v) = snap.get(state::space_record_key(repo, sid, path)).await.map_err(XrpcError::from_err)? else {
            continue;
        };
        let (cid, _) = state::record_value_parts(&v).map_err(XrpcError::from_err)?;
        let (collection, rkey) = path.split_once('/').ok_or_else(|| XrpcError::internal("malformed takedown path"))?;
        set.remove(&crate::space::commit::element(collection, rkey, &cid.to_string()));
    }
    Ok(set)
}

/// The head and the set to sign for it, read from one snapshot when some
/// record is hidden (a write between the two reads would remove the wrong
/// element); from the heads map otherwise.
async fn served_head(
    app: &App,
    sp: &Spaces,
    p: &crate::partition::Partition,
    repo: &str,
    space: &Space,
) -> XResult<Option<(Arc<DurableSpaceHead>, Option<LtHash>)>> {
    let hidden = hidden_paths(app, repo, &space.sid).await?;
    if hidden.is_empty() {
        return Ok(load_head(sp, p, repo, space).await?.map(|h| (h, None)));
    }
    let snap = p.db.snapshot().map_err(XrpcError::from_err)?;
    let Some(v) = snap.get(state::space_head_key(repo, &space.sid)).await.map_err(XrpcError::from_err)? else {
        return Ok(None);
    };
    let head = head_of(HeadRow::decode(&v).map_err(XrpcError::from_err)?, space, p)?;
    let set = served_set(&snap, repo, &space.sid, &head.hash, &hidden).await?;
    Ok(Some((Arc::new(head), Some(set))))
}

fn auth_label(creds: &Credentials) -> &'static str {
    match creds {
        Credentials::SpaceCredential { .. } => "credential",
        _ => "oauth",
    }
}

/// Reference `assertRepoAvailability`, from the account cache (a hot
/// repo's reads read no state): only its owner reads an inactive repo.
/// Returns the account's signing key, which signs commits per read.
async fn available(app: &App, repo: &str, self_read: bool) -> XResult<Arc<Keypair>> {
    let not_found = || XrpcError::bad("RepoNotFound", format!("Could not find repo for DID: {repo}"));
    let (key, status) = match super::proxy::account_key_status(app, repo).await {
        Ok(a) => a,
        Err(e) if e.error == "AccountNotFound" => return Err(not_found()),
        Err(e) => return Err(e),
    };
    match status.as_deref() {
        Some("deleted") => Err(not_found()),
        None => Ok(key),
        Some(_) if self_read => Ok(key),
        Some("takendown") => Err(XrpcError::bad("RepoTakendown", format!("Repo has been takendown: {repo}"))),
        Some("deactivated") => Err(XrpcError::bad("RepoDeactivated", format!("Repo has been deactivated: {repo}"))),
        Some(st) => Err(XrpcError::bad(&inactive_error(st), format!("Repo is {st}: {repo}"))),
    }
}

fn head_of(row: HeadRow, space: &Space, p: &crate::partition::Partition) -> XResult<DurableSpaceHead> {
    if row.uri != space.uri {
        return Err(XrpcError::internal(format!("space id collision: {} and {}", row.uri, space.uri)));
    }
    Ok(DurableSpaceHead {
        uri: row.uri.into(),
        rev: row.rev,
        hash: row.hash,
        records: row.records,
        created: row.created,
        shard: p.id,
        epoch: p.epoch,
    })
}

/// `repo`'s durable head in `space`: from the heads map, else read once.
/// None: the account never wrote there.
pub(super) async fn load_head(
    sp: &Spaces,
    p: &crate::partition::Partition,
    repo: &str,
    space: &Space,
) -> XResult<Option<Arc<DurableSpaceHead>>> {
    if let Some(h) = sp.heads.get(repo, &space.sid, p.id, p.epoch) {
        if *h.uri != *space.uri {
            return Err(XrpcError::internal(format!("space id collision: {} and {}", h.uri, space.uri)));
        }
        return Ok(Some(h));
    }
    sp.heads.note_load();
    let Some(v) = p.db.get(state::space_head_key(repo, &space.sid)).await.map_err(XrpcError::from_err)? else {
        return Ok(None);
    };
    let h = Arc::new(head_of(HeadRow::decode(&v).map_err(XrpcError::from_err)?, space, p)?);
    sp.heads.publish(repo, &space.sid, h.clone());
    Ok(Some(h))
}

fn b64(b: &[u8]) -> J {
    json!({"$bytes": base64::engine::general_purpose::STANDARD_NO_PAD.encode(b)})
}

/// `buildSignedCommit`: a fresh ikm per response, signed by the author,
/// over `set` (the head's unless records are hidden).
fn signed_commit(
    key: &Keypair,
    space: &Space,
    author: &str,
    head: &DurableSpaceHead,
    set: Option<&LtHash>,
) -> XResult<J> {
    let rev = head.rev.to_string();
    let ctx = crate::space::commit::CommitCtx { space: &space.uri, author, rev: &rev };
    let t = Instant::now();
    let c = crate::space::commit::sign(set.unwrap_or(&head.hash), &ctx, rand::random(), |b| {
        Ok::<_, std::convert::Infallible>(key.sign(b))
    })
    .map_err(|_| XrpcError::internal("space commit context too long"))?;
    metrics::space_sign(t.elapsed());
    Ok(
        json!({"ver": c.ver, "hash": b64(&c.hash), "ikm": b64(&c.ikm), "sig": b64(&c.sig), "mac": b64(&c.mac), "rev": c.rev}),
    )
}

#[derive(Deserialize)]
struct RecordQ {
    space: String,
    repo: String,
    collection: String,
    rkey: String,
}

async fn get_record(State(app): AppState, SpaceAuth(creds): SpaceAuth, Query(q): Query<RecordQ>) -> XResult<Response> {
    let sp = spaces(&app)?;
    let space = Space::parse(&q.space)?;
    let self_read = assert_space_read(&creds, &space, &q.repo)?;
    assert_space_open(&app, &space, self_read).await?;
    check_path(&q.collection, Some(&q.rkey))?;
    available(&app, &q.repo, self_read).await?;
    metrics::space_read("getRecord", auth_label(&creds));
    let p = app.partition(&q.repo)?;
    let path = format!("{}/{}", q.collection, q.rkey);
    let uri = space.record_uri(&q.repo, &path);
    let not_found = || XrpcError::bad("RecordNotFound", format!("Could not locate record: {uri}"));
    // the head names the space: a space id shared with another fails here
    if load_head(sp, &p, &q.repo, &space).await?.is_none() {
        return Err(not_found());
    }
    if super::server::ctl(&app, &q.repo).await?.has_takedown(&takedown_name(&space.sid, &path)) {
        return Err(not_found());
    }
    let key = state::space_record_key(&q.repo, &space.sid, &path);
    let v = p.db.get(key).await.map_err(XrpcError::from_err)?.ok_or_else(not_found)?;
    let (cid, bytes) = state::record_value_parts(&v).map_err(XrpcError::from_err)?;
    let mut out = Vec::with_capacity(bytes.len() * 2 + 256);
    out.extend_from_slice(b"{\"uri\":");
    serde_json::to_writer(&mut out, &uri).map_err(XrpcError::from_err)?;
    out.extend_from_slice(b",\"cid\":\"");
    cid.write_string(&mut out);
    out.extend_from_slice(b"\",\"value\":");
    crate::cbor::write_json(bytes, &mut out).map_err(XrpcError::from_err)?;
    out.push(b'}');
    Ok(json_bytes(out))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListRecordsQ {
    space: String,
    repo: String,
    collection: Option<String>,
    limit: Option<i64>,
    cursor: Option<String>,
    reverse: Option<bool>,
    exclude_values: Option<bool>,
}

/// Values a page of listRecords or listRepoOps holds before it ends early
/// with a cursor (records run to 1 MB each); rows are read this many at a
/// time.
const PAGE_BYTES: usize = 4 << 20;
const PAGE_BATCH: usize = 32;

/// Newest path first unless `reverse`, as the reference orders by URI; the
/// cursor is the last record's URI.
async fn list_records(
    State(app): AppState,
    SpaceAuth(creds): SpaceAuth,
    Query(q): Query<ListRecordsQ>,
) -> XResult<Response> {
    let sp = spaces(&app)?;
    let space = Space::parse(&q.space)?;
    let self_read = assert_space_read(&creds, &space, &q.repo)?;
    assert_space_open(&app, &space, self_read).await?;
    if let Some(c) = &q.collection {
        check_path(c, None)?;
    }
    let limit = super::extract::limit_param(q.limit, 50, 1, 1000)?;
    available(&app, &q.repo, self_read).await?;
    metrics::space_read("listRecords", auth_label(&creds));
    let p = app.partition(&q.repo)?;
    let mut out = Vec::with_capacity(limit * 256);
    out.extend_from_slice(b"{\"records\":[");
    if load_head(sp, &p, &q.repo, &space).await?.is_none() {
        out.extend_from_slice(b"]}");
        return Ok(json_bytes(out));
    }
    let base = state::space_prefix(state::SPACE_RECORD_FAMILY, &q.repo, &space.sid);
    let prefix = match &q.collection {
        Some(c) => [&base[..], c.as_bytes(), b"/"].concat(),
        None => base.clone(),
    };
    let end = state::prefix_end(&prefix);
    let ascending = q.reverse.unwrap_or(false);
    let after = q.cursor.as_deref().and_then(|c| c.strip_prefix(&space.record_uri(&q.repo, "")));
    let (lo, hi) = match (after, ascending) {
        (Some(c), true) => ([&base[..], c.as_bytes(), &[0]].concat().max(prefix.clone()), end),
        (Some(c), false) => (prefix.clone(), [&base[..], c.as_bytes()].concat().min(end)),
        (None, _) => (prefix.clone(), end),
    };
    if lo >= hi {
        out.extend_from_slice(b"]}");
        return Ok(json_bytes(out));
    }
    let order = if ascending { slatedb::IterationOrder::Ascending } else { slatedb::IterationOrder::Descending };
    let opts = slatedb::config::ScanOptions::default().with_order(order);
    let takedowns = super::server::ctl(&app, &q.repo).await?;
    let mut iter = p.db.scan_with_options(lo..hi, &opts).await.map_err(XrpcError::from_err)?;
    let (mut n, mut last, mut full) = (0, None, false);
    while n < limit && !full {
        let rows = iter.next_batch((limit - n).min(PAGE_BATCH)).await.map_err(XrpcError::from_err)?;
        if rows.is_empty() {
            break;
        }
        for kv in rows {
            if out.len() >= PAGE_BYTES {
                full = true;
                break;
            }
            let path = std::str::from_utf8(&kv.key[base.len()..]).map_err(XrpcError::from_err)?;
            if takedowns.has_takedown(&takedown_name(&space.sid, path)) {
                last = Some(path.to_string());
                continue;
            }
            let (collection, rkey) = path.split_once('/').unwrap_or((path, ""));
            let (cid, bytes) = state::record_value_parts(&kv.value).map_err(XrpcError::from_err)?;
            if n > 0 {
                out.push(b',');
            }
            out.extend_from_slice(b"{\"collection\":");
            serde_json::to_writer(&mut out, collection).map_err(XrpcError::from_err)?;
            out.extend_from_slice(b",\"rkey\":");
            serde_json::to_writer(&mut out, rkey).map_err(XrpcError::from_err)?;
            out.extend_from_slice(b",\"cid\":\"");
            cid.write_string(&mut out);
            out.push(b'"');
            if !q.exclude_values.unwrap_or(false) {
                out.extend_from_slice(b",\"value\":");
                crate::cbor::write_json(bytes, &mut out).map_err(XrpcError::from_err)?;
            }
            out.push(b'}');
            n += 1;
            last = Some(path.to_string());
        }
    }
    out.push(b']');
    if let (true, Some(path)) = (n == limit || full, last) {
        out.extend_from_slice(b",\"cursor\":");
        serde_json::to_writer(&mut out, &space.record_uri(&q.repo, &path)).map_err(XrpcError::from_err)?;
    }
    out.push(b'}');
    Ok(json_bytes(out))
}

#[derive(Deserialize)]
struct BlobQ {
    space: String,
    repo: String,
    cid: String,
}

/// Reference space.getBlob: only a blob a record of this repo in this space
/// names (`sb`), so a credential for one space reads none of another's, nor
/// an upload no record names; whether such a blob exists isn't revealed.
async fn get_blob(State(app): AppState, SpaceAuth(creds): SpaceAuth, Query(q): Query<BlobQ>) -> XResult<Response> {
    let sp = spaces(&app)?;
    let space = Space::parse(&q.space)?;
    let self_read = assert_space_read(&creds, &space, &q.repo)?;
    assert_space_open(&app, &space, self_read).await?;
    let cid = Cid::parse(&q.cid).map_err(|_| XrpcError::bad("InvalidRequest", "Invalid cid"))?;
    available(&app, &q.repo, self_read).await?;
    metrics::space_read("getBlob", auth_label(&creds));
    let not_found = || XrpcError::bad("BlobNotFound", "Blob not found");
    let p = app.partition(&q.repo)?;
    // the head names the space: a space id shared with another fails here
    if load_head(sp, &p, &q.repo, &space).await?.is_none() {
        return Err(not_found());
    }
    // named by some record that isn't taken down
    let hidden = hidden_paths(&app, &q.repo, &space.sid).await?;
    let prefix = state::space_blob_prefix(&q.repo, &space.sid, &cid);
    let mut iter = p.db.scan(prefix.clone()..state::prefix_end(&prefix)).await.map_err(XrpcError::from_err)?;
    let mut named = false;
    while let Some(kv) = iter.next().await.map_err(XrpcError::from_err)? {
        let path = std::str::from_utf8(&kv.key[prefix.len()..]).map_err(XrpcError::from_err)?;
        if !hidden.iter().any(|h| h == path) {
            named = true;
            break;
        }
    }
    if !named {
        return Err(not_found());
    }
    if super::admin::is_blob_takendown(&app, &q.repo, &q.cid).await? {
        return Err(not_found());
    }
    match app.store.raw.get(&super::blobs::blob_path(&app, &q.repo, cid)).await {
        Ok(r) => Ok(super::blobs::blob_response(r, &cid)),
        Err(object_store::Error::NotFound { .. }) => Err(not_found()),
        Err(e) => Err(XrpcError::from_err(e)),
    }
}

#[derive(Deserialize)]
struct ListBlobsQ {
    space: String,
    repo: String,
    since: Option<String>,
    limit: Option<i64>,
    cursor: Option<String>,
}

/// Reference space.listBlobs: the distinct blobs this repo's records in
/// this space name, in CID order; with `since`, those named by a record
/// written after that rev. Only a full page has a cursor.
async fn list_blobs(
    State(app): AppState,
    SpaceAuth(creds): SpaceAuth,
    Query(q): Query<ListBlobsQ>,
) -> XResult<Json<J>> {
    let sp = spaces(&app)?;
    let space = Space::parse(&q.space)?;
    let self_read = assert_space_read(&creds, &space, &q.repo)?;
    assert_space_open(&app, &space, self_read).await?;
    let since = match q.since.as_deref() {
        Some(s) => Some(Tid::parse(s).ok_or_else(|| XrpcError::bad("InvalidRequest", "since must be a TID"))?),
        None => None,
    };
    let limit = super::extract::limit_param(q.limit, 500, 1, 1000)?;
    available(&app, &q.repo, self_read).await?;
    metrics::space_read("listBlobs", auth_label(&creds));
    let p = app.partition(&q.repo)?;
    if load_head(sp, &p, &q.repo, &space).await?.is_none() {
        return Ok(Json(json!({"cids": []})));
    }
    let prefix = state::space_prefix(state::SPACE_BLOB_FAMILY, &q.repo, &space.sid);
    let lo = match &q.cursor {
        // past every key of the cursor's CID
        Some(c) => state::prefix_end(&[&prefix[..], c.as_bytes(), b"\0"].concat()),
        None => prefix.clone(),
    };
    let opts = slatedb::config::ScanOptions::default();
    let mut iter = p.db.scan_with_options(lo..state::prefix_end(&prefix), &opts).await.map_err(XrpcError::from_err)?;
    // a blob only taken-down records name is left out, as getBlob refuses it
    let hidden = hidden_paths(&app, &q.repo, &space.sid).await?;
    let mut cids: Vec<String> = Vec::new();
    'scan: loop {
        let rows = iter.next_batch(limit.max(64)).await.map_err(XrpcError::from_err)?;
        if rows.is_empty() {
            break;
        }
        for kv in rows {
            let (cid, path) = crate::space::rows::blob_ref_parts(&kv.key[prefix.len()..])
                .ok_or_else(|| XrpcError::internal("bad space blob ref key"))?;
            if cids.last().is_some_and(|c| c == cid) {
                continue;
            }
            if since.is_some_and(|s| crate::space::rows::blob_ref_rev(&kv.value) <= s) {
                continue;
            }
            if hidden.iter().any(|h| h == path) {
                continue;
            }
            if cids.len() == limit {
                break 'scan;
            }
            cids.push(cid.to_string());
        }
    }
    let mut out = json!({"cids": cids});
    if cids.len() == limit {
        out["cursor"] = json!(cids.last());
    }
    Ok(Json(out))
}

#[derive(Deserialize)]
struct RepoQ {
    space: String,
    repo: String,
}

async fn get_latest_commit(
    State(app): AppState,
    SpaceAuth(creds): SpaceAuth,
    Query(q): Query<RepoQ>,
) -> XResult<Json<J>> {
    let sp = spaces(&app)?;
    let space = Space::parse(&q.space)?;
    let self_read = assert_space_read(&creds, &space, &q.repo)?;
    assert_space_open(&app, &space, self_read).await?;
    let key = available(&app, &q.repo, self_read).await?;
    metrics::space_read("getLatestCommit", auth_label(&creds));
    let p = app.partition(&q.repo)?;
    let (head, set) = served_head(&app, sp, &p, &q.repo, &space)
        .await?
        .ok_or_else(|| XrpcError::bad("RepoNotFound", format!("Could not find repo for space: {}", space.uri)))?;
    Ok(Json(json!({"commit": signed_commit(&key, &space, &q.repo, &head, set.as_ref())?})))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListRepoOpsQ {
    space: String,
    repo: String,
    since: Option<String>,
    limit: Option<i64>,
    cursor: Option<String>,
    exclude_values: Option<bool>,
}

/// `{rev}/{idx}`. The reference compares the rev as a string; a TID's
/// string order is its numeric order, and anything else can't be a rev.
fn parse_cursor(c: &str) -> XResult<(Tid, u16)> {
    let malformed = || XrpcError::bad("MalformedCursor", "Malformed cursor");
    let (rev, idx) = c.split_once('/').ok_or_else(malformed)?;
    Ok((Tid::parse(rev).ok_or_else(malformed)?, idx.parse().map_err(|_| malformed())?))
}

/// Ops after `since` (or the cursor), each with the record's current value
/// when it is still the op's (a superseded one is left off). A page that
/// reaches the head carries the signed commit; a full one, a cursor
/// instead. `since` at (or past) the head is answered from memory.
async fn list_repo_ops(
    State(app): AppState,
    SpaceAuth(creds): SpaceAuth,
    Query(q): Query<ListRepoOpsQ>,
) -> XResult<Response> {
    let sp = spaces(&app)?;
    let space = Space::parse(&q.space)?;
    let self_read = assert_space_read(&creds, &space, &q.repo)?;
    assert_space_open(&app, &space, self_read).await?;
    let since = match q.since.as_deref() {
        Some(s) => Some(Tid::parse(s).ok_or_else(|| XrpcError::bad("InvalidRequest", "since must be a valid tid"))?),
        None => None,
    };
    let limit = super::extract::limit_param(q.limit, 100, 1, 1000)?;
    let cursor = q.cursor.as_deref().map(parse_cursor).transpose()?;
    let key = available(&app, &q.repo, self_read).await?;
    metrics::space_read("listRepoOps", auth_label(&creds));
    let start = Instant::now();
    let p = app.partition(&q.repo)?;
    let hidden = hidden_paths(&app, &q.repo, &space.sid).await?;
    if hidden.is_empty() {
        let head = load_head(sp, &p, &q.repo, &space).await?;
        let caught_up = match (&head, cursor, since) {
            (None, ..) => true,
            (Some(h), None, Some(s)) => s >= h.rev,
            _ => false,
        };
        if caught_up {
            let mut out = json!({"ops": []});
            if let Some(h) = &head {
                out["commit"] = signed_commit(&key, &space, &q.repo, h, None)?;
            }
            metrics::space_list_repo_ops("noop", start.elapsed());
            return Ok(Json(out).into_response());
        }
    }
    // one snapshot: the commit describes exactly the ops' end state
    let snap = p.db.snapshot().map_err(XrpcError::from_err)?;
    let head = match snap.get(state::space_head_key(&q.repo, &space.sid)).await.map_err(XrpcError::from_err)? {
        Some(v) => head_of(HeadRow::decode(&v).map_err(XrpcError::from_err)?, &space, &p)?,
        None => return Ok(Json(json!({"ops": []})).into_response()),
    };
    let prefix = state::space_prefix(state::SPACE_OPLOG_FAMILY, &q.repo, &space.sid);
    let after = |rev: u64, idx: u32| -> Vec<u8> {
        let (rev, idx) = match u16::try_from(idx) {
            Ok(i) => (rev, i),
            Err(_) => (rev.saturating_add(1), 0),
        };
        [&prefix[..], &rev.to_be_bytes(), &idx.to_be_bytes()].concat()
    };
    let mut lo = prefix.clone();
    if let Some(s) = since {
        lo = lo.max(after(s.0.saturating_add(1), 0));
    }
    if let Some((rev, idx)) = cursor {
        lo = lo.max(after(rev.0, idx as u32 + 1));
    }
    let opts = slatedb::config::ScanOptions::default();
    let mut iter = snap.scan_with_options(lo..state::prefix_end(&prefix), &opts).await.map_err(XrpcError::from_err)?;
    let values = !q.exclude_values.unwrap_or(false);
    // values go straight into the page, never through a JSON tree
    let mut ops = Vec::with_capacity(limit.min(256) * 160);
    ops.push(b'[');
    let mut last = None;
    // a page is `limit` ops scanned, hidden ones included, so the cursor and
    // whether the page reaches the head don't depend on what's hidden; it
    // ends early (with a cursor) past PAGE_BYTES
    let (mut rows_seen, mut full) = (0, false);
    'page: while rows_seen < limit {
        let rows = iter.next_batch((limit - rows_seen).min(PAGE_BATCH)).await.map_err(XrpcError::from_err)?;
        if rows.is_empty() {
            break;
        }
        for kv in rows {
            if ops.len() >= PAGE_BYTES {
                full = true;
                break 'page;
            }
            rows_seen += 1;
            let (rev, idx) = crate::space::rows::oplog_position(&kv.key)
                .ok_or_else(|| XrpcError::internal("malformed space oplog key"))?;
            let op = OpRow::decode(&kv.value).map_err(XrpcError::from_err)?;
            last = Some((rev, idx));
            let path = format!("{}/{}", op.collection, op.rkey);
            if hidden.contains(&path) {
                continue;
            }
            if ops.len() > 1 {
                ops.push(b',');
            }
            let o = json!({
                "rev": rev.to_string(),
                "collection": op.collection,
                "rkey": op.rkey,
                "cid": op.cid.map(|c| c.to_string()),
                "prev": op.prev.map(|c| c.to_string()),
            });
            serde_json::to_writer(&mut ops, &o).map_err(XrpcError::from_err)?;
            if let (true, Some(cid)) = (values, op.cid) {
                let cur =
                    snap.get(state::space_record_key(&q.repo, &space.sid, &path)).await.map_err(XrpcError::from_err)?;
                if let Some(v) = cur {
                    let (c, bytes) = state::record_value_parts(&v).map_err(XrpcError::from_err)?;
                    if c == cid {
                        ops.pop();
                        ops.extend_from_slice(b",\"value\":");
                        crate::cbor::write_json(bytes, &mut ops).map_err(XrpcError::from_err)?;
                        ops.push(b'}');
                    }
                }
            }
        }
    }
    ops.push(b']');
    let mut out = Vec::with_capacity(ops.len() + 512);
    out.push(b'{');
    if rows_seen < limit && !full {
        let set = match hidden.is_empty() {
            true => None,
            false => Some(served_set(&snap, &q.repo, &space.sid, &head.hash, &hidden).await?),
        };
        out.extend_from_slice(b"\"commit\":");
        let commit = signed_commit(&key, &space, &q.repo, &head, set.as_ref())?;
        serde_json::to_writer(&mut out, &commit).map_err(XrpcError::from_err)?;
        out.push(b',');
    } else if let Some((rev, idx)) = last {
        out.extend_from_slice(b"\"cursor\":");
        serde_json::to_writer(&mut out, &format!("{rev}/{idx}")).map_err(XrpcError::from_err)?;
        out.push(b',');
    }
    out.extend_from_slice(b"\"ops\":");
    out.extend_from_slice(&ops);
    out.push(b'}');
    metrics::space_list_repo_ops("scan", start.elapsed());
    Ok(json_bytes(out))
}

#[derive(Deserialize)]
struct SpaceQ {
    space: String,
}

/// Reference getDelegationToken: only a whole-space `read` grant mints one
/// (and so only OAuth: space data is OAuth-only here).
async fn get_delegation_token(State(app): AppState, Auth(creds): Auth, Query(q): Query<SpaceQ>) -> XResult<Json<J>> {
    spaces(&app)?;
    let space = Space::parse(&q.space)?;
    creds.need_space(&space.target(), SpaceAccess::Read)?;
    let did = creds.user_did()?.to_string();
    let (key, status) = super::proxy::account_key_status(&app, &did).await?;
    if let Some(st) = status {
        return Err(inactive_account_error(&st));
    }
    let aud = token::space_host_aud(&space.authority);
    let mint = token::Mint { iss: &did, sub: &space.uri, aud: Some(&aud), ..Default::default() };
    let now = crate::tid::now_micros() as i64 / 1_000_000;
    let tok = token::encode(TokenType::Delegation, &mint, "ES256K", now, &token::new_jti(), |b| {
        Ok::<_, std::convert::Infallible>(key.sign(b))
    })
    .map_err(|e| XrpcError::internal(format!("delegation token: {e:?}")))?;
    metrics::space_delegation();
    Ok(Json(json!({"token": tok})))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CredentialIn {
    space: String,
    client_attestation: Option<String>,
}

/// At the space's authority (forwarded there by `space`): the delegation
/// token checked and claimed, then the simplespace policy. The credential
/// is bound to the key that signed this request.
async fn get_space_credential(
    State(app): AppState,
    headers: HeaderMap,
    Json(inp): Json<CredentialIn>,
) -> XResult<Json<J>> {
    spaces(&app)?;
    let r = issue_credential(&app, &headers, inp).await;
    metrics::space_credential_issued(match &r {
        Ok(_) => "ok",
        Err(e) if e.status.is_server_error() => "error",
        Err(e) if e.status == StatusCode::UNAUTHORIZED => "bad_token",
        Err(_) => "refused",
    });
    r
}

async fn issue_credential(app: &App, headers: &HeaderMap, inp: CredentialIn) -> XResult<Json<J>> {
    let d = verify_delegation(app, headers).await?;
    if d.space != inp.space {
        return Err(XrpcError::bad(
            "InvalidDelegationToken",
            "Delegation token subject does not match requested space",
        ));
    }
    let space = Space::parse(&inp.space)?;
    super::simplespace::assert_space_host(app, &space).await?;
    let client_id = match &inp.client_attestation {
        Some(a) => {
            let aud = token::space_host_aud(&space.authority);
            Some(crate::space::attestation::verify(app, a, &aud, &space.authority).await?)
        }
        None => None,
    };
    let row = super::simplespace::space_row(app, &space).await?;
    if !row.live() {
        // the durable signal that a space is gone, for a syncer that missed
        // notifySpaceDeleted
        return Err(XrpcError::bad("SpaceDeleted", "Space has been deleted"));
    }
    // told only to those it would otherwise admit: a non-member learns
    // nothing about the space from it
    let taken_down = space_takendown(app, &space).await?;
    // vlpds: no credential names a taken-down authority or member (the
    // reference admits both)
    let (key, status) = super::proxy::account_key_status(app, &space.authority).await?;
    if matches!(status.as_deref(), Some("takendown" | "suspended")) {
        return Err(XrpcError::bad("RepoTakendown", "Space authority has been taken down"));
    }
    if d.user != space.authority {
        match super::internal::account_anywhere(app, &d.user).await {
            Ok(a) if matches!(a.status.as_deref(), Some("takendown" | "suspended")) => {
                return Err(XrpcError::bad("AccountTakedown", "User account has been taken down"));
            }
            Ok(_) => {}
            // another host's account: its own host refuses it delegation tokens
            Err(e) if e.error == "AccountNotFound" => {}
            Err(e) => return Err(e),
        }
    }
    // the app perimeter first: decided from the config alone, so a refused
    // app is never disclosed to a managing app
    if let crate::space::rows::AppAccess::AllowList { allowed } = &row.app_access {
        if !client_id.as_ref().is_some_and(|c| allowed.contains(c)) {
            return Err(XrpcError::bad("AppNotAuthorized", "Application not authorized for this space"));
        }
    }
    if !super::simplespace::authorize_user(app, &space, &row, &d.user, "read", client_id.as_deref()).await? {
        return Err(XrpcError::bad("UserNotAuthorized", "User not authorized for this space"));
    }
    if taken_down {
        return Err(XrpcError::bad("NotAuthorized", "Space has been taken down"));
    }
    let mint = token::Mint { iss: &space.authority, sub: &space.uri, key_id: Some(&d.key_id), ..Default::default() };
    let now = crate::tid::now_micros() as i64 / 1_000_000;
    let cred = token::encode(TokenType::Credential, &mint, "ES256K", now, &token::new_jti(), |b| {
        Ok::<_, std::convert::Infallible>(key.sign(b))
    })
    .map_err(|e| XrpcError::internal(format!("space credential: {e:?}")))?;
    Ok(Json(json!({"credential": cred})))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListSpacesQ {
    space_type: Option<String>,
    did: Option<String>,
    limit: Option<i64>,
    cursor: Option<String>,
}

/// Reference listSpaces: the spaces the account holds a repo in, plus
/// those it governs (the reference's `ensureSpace` at createSpace), by
/// URI. The filters are the scope target, so an unfiltered listing needs
/// a wildcard grant.
async fn list_spaces(State(app): AppState, Auth(creds): Auth, Query(q): Query<ListSpacesQ>) -> XResult<Json<J>> {
    spaces(&app)?;
    if q.space_type.as_deref().is_some_and(|t| !super::syntax::valid_nsid(t)) {
        return Err(XrpcError::bad("InvalidRequest", "spaceType must be an NSID"));
    }
    if q.did.as_deref().is_some_and(|d| !super::syntax::valid_did(d)) {
        return Err(XrpcError::bad("InvalidRequest", "did must be a DID"));
    }
    let limit = super::extract::limit_param(q.limit, 50, 1, 100)?;
    let target = SpaceTarget {
        space_type: q.space_type.as_deref().unwrap_or("*"),
        authority: q.did.as_deref().unwrap_or("*"),
        skey: "*",
    };
    creds.need_space(&target, SpaceAccess::ReadSelf)?;
    super::authn::check_space_read_account(&creds)?;
    let did = creds.user_did()?.to_string();
    let p = app.partition(&did)?;
    let (page, scanned) = list_space_uris(&p.db, &did, &q, limit).await.map_err(XrpcError::from_err)?;
    let extra = (scanned / LIST_SPACES_ROWS_PER_POINT).min(u32::MAX as u64) as u32;
    if extra > 0 {
        // the next call is refused once these are spent
        let _ = crate::ratelimit::check(&[&crate::ratelimit::SPACE_READ_ACCOUNT], &did, extra);
    }
    let mut out = json!({"spaces": page.iter().map(|u| json!({"uri": u})).collect::<Vec<_>>()});
    if page.len() == limit {
        out["cursor"] = json!(page.last());
    }
    Ok(Json(out))
}

/// listSpaces charges a further `space-read-account` point per this many
/// rows it reads.
const LIST_SPACES_ROWS_PER_POINT: u64 = 1000;

/// Up to `limit` URIs past the cursor that `did` holds a repo in or governs
/// live, in URI order, from `sL/`, and how many rows that read. The `did`
/// filter (and `spaceType` with it) narrows the range; `spaceType` alone
/// seeks past each authority's other types, so a page reads about its own
/// rows plus one per authority skipped.
async fn list_space_uris(
    db: &slatedb::Db,
    did: &str,
    q: &ListSpacesQ,
    limit: usize,
) -> anyhow::Result<(Vec<String>, u64)> {
    let base = state::space_did_prefix(state::SPACE_LIST_FAMILY, did);
    let narrow = match (q.did.as_deref(), q.space_type.as_deref()) {
        (Some(a), Some(t)) => format!("at://{a}/space/{t}/"),
        (Some(a), None) => format!("at://{a}/space/"),
        (None, _) => String::new(),
    };
    let lo = [&base[..], narrow.as_bytes()].concat();
    let hi = state::prefix_end(&lo);
    // every key of the cursor's URI is `{uri}\0..`, below `{uri}\x01`
    let start = match q.cursor.as_deref() {
        Some(c) => std::cmp::max(lo.clone(), [&base[..], c.as_bytes(), b"\x01"].concat()),
        None => lo,
    };
    let mut uris: Vec<String> = Vec::with_capacity(limit);
    let mut scanned = 0u64;
    if start >= hi {
        return Ok((uris, scanned));
    }
    let opts = slatedb::config::ScanOptions::default();
    let mut iter = db.scan_with_options(start..hi.clone(), &opts).await?;
    while let Some(kv) = iter.next().await? {
        scanned += 1;
        let uri = state::space_list_uri(&kv.key, &base).ok_or_else(|| anyhow::anyhow!("bad space list key"))?;
        if uris.last().is_some_and(|l| l == uri) || q.cursor.as_deref().is_some_and(|c| uri <= c) {
            continue;
        }
        let Some(u) = super::syntax::parse_space_uri(uri) else { continue };
        if let Some(t) = q.space_type.as_deref().filter(|t| *t != u.space_type) {
            let want = [&base[..], format!("at://{}/space/{t}/", u.authority).as_bytes()].concat();
            let next = match want[..] > kv.key[..] {
                true => want,
                // '0' follows '/': past every space of this authority
                false => [&base[..], format!("at://{}/space0", u.authority).as_bytes()].concat(),
            };
            if next >= hi {
                break;
            }
            iter.seek(next).await?;
            continue;
        }
        uris.push(uri.to_string());
        if uris.len() == limit {
            break;
        }
    }
    Ok((uris, scanned))
}

#[derive(Deserialize)]
struct RevokedIn {
    space: String,
    credentials: Vec<String>,
}

const REVOKE_NUDGE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);
/// A peer that missed a nudge is nudged again this many times, backing off
/// from a second; past that, its own re-read (or [`revocations::STALE_AFTER`])
/// bounds it.
const REVOKE_NUDGE_RETRIES: u32 = 6;

/// Reference notifyCredentialRevoked: the space's authority, by service
/// auth addressed to an account hosted here, revokes credentials of its
/// space. Enforced cluster-wide: the 200 comes once the revocation is in
/// the bucket's control object and the live peers were asked to reload it
/// (each given a second to answer; one that misses it is asked again in the
/// background, and refuses credentials once its set is stale).
///
/// The object is read whole by every node, so only revocations with a
/// stake here go in, bounded per authority, space and audience
/// ([`revocations::PER_AUD`] and the rest), and the rate limits count only
/// jtis new here. A revocation that can't be stored blocks the space's
/// credentials instead, on every node: it fails closed.
async fn notify_credential_revoked(
    State(app): AppState,
    headers: HeaderMap,
    Json(inp): Json<RevokedIn>,
) -> XResult<StatusCode> {
    let sp = spaces(&app)?.clone();
    let lxm = "com.atproto.space.notifyCredentialRevoked";
    let auth = super::authn::verify_space_service_jwt(&app, &headers, lxm).await?;
    let space = Space::parse(&inp.space)?;
    if inp.credentials.is_empty()
        || inp.credentials.len() > 100
        || !inp.credentials.iter().all(|j| revocations::valid_jti(j))
    {
        return Err(XrpcError::bad(
            "InvalidRequest",
            format!(
                "credentials must hold 1 to 100 jtis of 1 to {} printable ASCII characters",
                revocations::MAX_JTI_LEN
            ),
        ));
    }
    if auth.iss != space.authority {
        return Err(forbidden("Revocation issuer is not the space authority"));
    }
    // unsure (its shard's owner unreachable) counts as hosted: refusing
    // would drop a revocation that may be ours
    let hosted = super::syntax::valid_did(&auth.aud)
        && !matches!(super::internal::account_anywhere(&app, &auth.aud).await, Err(e) if e.error == "AccountNotFound");
    if !hosted {
        return Err(forbidden("Revocation audience does not match a repo hosted here"));
    }
    let now = crate::tid::now_micros() as i64 / 1_000_000;
    let mut new: Vec<String> =
        inp.credentials.into_iter().filter(|j| !sp.revocations.is_revoked(&space.uri, j, now)).collect();
    new.sort();
    new.dedup();
    if new.is_empty() {
        return Ok(StatusCode::OK);
    }
    // Neither the audience's repo in the space nor its authority is here,
    // so no credential for it reads anything through this audience: there
    // is nothing to enforce, and nothing is written. An authority tells
    // each member's host, addressed to that member.
    // unsure counts as hosted: stored, and blocked alone rather than
    // escalated past it
    let local_authority = authority_hosted(&app, &space.authority).await.unwrap_or(true);
    if !local_authority && !aud_holds_repo(&app, &sp, &space, &auth.aud).await {
        return Ok(StatusCode::OK);
    }
    crate::ratelimit::check(&[&crate::ratelimit::SPACE_REVOKE], &auth.iss, new.len() as u32)?;
    // anyone with a DID can spend an account's bucket, so an exhausted one
    // is a revocation not stored: the space is blocked, never left open
    if let Err(e) = crate::ratelimit::check(&[&crate::ratelimit::SPACE_REVOKE_AUD], &auth.aud, new.len() as u32) {
        let now = crate::tid::now_micros() as i64 / 1_000_000;
        sp.revocations.block(&space.uri, local_authority, now);
        nudge_revocation_peers(&app, Some(&space.uri)).await;
        tracing::warn!(
            space = hex::encode(space.sid),
            refused = "aud_rate",
            "space revocation not stored: the space is blocked"
        );
        return Err(e);
    }
    match sp.revoke(&app.store, &space.uri, &auth.aud, &new, local_authority).await {
        Ok(Ok(wrote)) => {
            if wrote {
                nudge_revocation_peers(&app, None).await;
            }
            Ok(StatusCode::OK)
        }
        Ok(Err((refused, in_object))) => {
            nudge_revocation_peers(&app, (!in_object).then_some(space.uri.as_str())).await;
            tracing::warn!(
                space = hex::encode(space.sid),
                refused = refused.as_str(),
                "space revocation not stored: the space is blocked"
            );
            Err(XrpcError::unavailable("Unavailable", "revocation not stored: too many revocations held; retry later"))
        }
        Err(e) => {
            // blocked here by Spaces::revoke; the peers too
            nudge_revocation_peers(&app, Some(&space.uri)).await;
            Err(XrpcError::unavailable("Unavailable", format!("revocation not stored: {e:#}")))
        }
    }
}

/// Whether the revocation's audience holds a repo in `space` in this
/// cluster, asked of its shard's owner. Unsure (the owner unreachable, the
/// shard moving) is yes: a stored entry is bounded, a dropped revocation
/// leaves the credential readable.
async fn aud_holds_repo(app: &App, sp: &Spaces, space: &Space, aud: &str) -> bool {
    let held = match app.remote_owner(aud) {
        Some(owner) => {
            let q = [("did", aud), ("space", space.uri.as_str())];
            super::internal::owner_get(app, &owner, "/internal/v1/space/holdsRepo", &q)
                .await
                .map(|v| v["holds"].as_bool() != Some(false))
        }
        None => match app.partition(aud) {
            Ok(p) => load_head(sp, &p, aud, space).await.map(|h| h.is_some()),
            Err(e) => Err(e),
        },
    };
    held.unwrap_or_else(|e| {
        tracing::warn!(space = hex::encode(space.sid), "space revocation stake unknown, stored: {}", e.message);
        true
    })
}

#[derive(Deserialize)]
struct HoldsQ {
    did: String,
    space: String,
}

/// [`aud_holds_repo`] at the owner of `did`'s shard.
async fn internal_holds_repo(State(app): AppState, headers: HeaderMap, Query(q): Query<HoldsQ>) -> XResult<Json<J>> {
    super::internal::check(&app, &headers)?;
    let sp = spaces(&app)?;
    let space = Space::parse(&q.space)?;
    let p = app.partition(&q.did)?;
    Ok(Json(json!({"holds": load_head(sp, &p, &q.did, &space).await?.is_some()})))
}

/// Whether the cluster hosts `authority` (a revocation of its space has a
/// stake here, and its blocks never escalate to every remote authority).
pub(super) async fn authority_hosted(app: &App, authority: &str) -> XResult<bool> {
    match super::internal::account_anywhere(app, authority).await {
        Ok(_) => Ok(true),
        Err(e) if e.error == "AccountNotFound" => Ok(false),
        Err(e) => Err(e),
    }
}

/// Asks every live peer to re-read the revocations (and, with `block`, to
/// refuse that space's credentials); a peer that misses it is asked again in
/// the background.
async fn nudge_revocation_peers(app: &Arc<App>, block: Option<&str>) {
    let Some(c) = &app.cluster else { return };
    let me = c.cfg.node_id.clone();
    let block = block.map(str::to_string);
    let sends = c.peers().into_iter().filter(|l| l.node_id != me).map(|l| {
        let (app, block) = (app.clone(), block.clone());
        async move {
            if let Err(e) = nudge_revocation_peer(&app, &l.addr, block.as_deref()).await {
                tracing::warn!(peer = %l.node_id, "space revocation nudge failed (retrying): {}", e.without_url());
                tokio::spawn(async move {
                    let mut wait = std::time::Duration::from_secs(1);
                    for _ in 0..REVOKE_NUDGE_RETRIES {
                        tokio::time::sleep(wait).await;
                        if nudge_revocation_peer(&app, &l.addr, block.as_deref()).await.is_ok() {
                            return;
                        }
                        wait *= 2;
                    }
                    tracing::warn!(peer = %l.node_id, "space revocation nudges failed (it re-reads on its own)");
                });
            }
        }
    });
    futures::future::join_all(sends).await;
}

async fn nudge_revocation_peer(app: &App, addr: &str, block: Option<&str>) -> reqwest::Result<()> {
    let mut req = app
        .http
        .post(format!("{}/internal/v1/space/revocations/reload", addr.trim_end_matches('/')))
        .header(super::internal::HDR, &app.config.internal_token)
        .timeout(REVOKE_NUDGE_TIMEOUT);
    if let Some(b) = block {
        req = req.query(&[("block", b)]);
    }
    req.send().await.and_then(|r| r.error_for_status()).map(|_| ())
}

#[derive(Deserialize)]
struct ReloadQ {
    block: Option<String>,
}

async fn internal_reload_revocations(
    State(app): AppState,
    headers: HeaderMap,
    Query(q): Query<ReloadQ>,
) -> XResult<Json<J>> {
    super::internal::check(&app, &headers)?;
    let sp = spaces(&app)?;
    if let Some(space) = &q.block {
        let local = match crate::space::revocations::authority_of(space) {
            Some(a) => authority_hosted(&app, a).await.unwrap_or(true),
            None => false,
        };
        sp.revocations.block(space, local, crate::tid::now_micros() as i64 / 1_000_000);
    }
    sp.refresh_revocations(&app.store)
        .await
        .map_err(|e| XrpcError::unavailable("Unavailable", format!("revocations unreadable: {e:#}")))?;
    Ok(Json(json!({"revocations": sp.revocations.len()})))
}

const SWEEP_BATCH: usize = 500;

/// Deletes every Spaces row of `did` (its repos in spaces, the spaces it
/// governs and their host state), in bounded entries, whether or not
/// `--spaces` is on now. Rerun by a deletion that stopped part way.
pub(super) async fn delete_account_rows(app: &App, did: &str) -> XResult<()> {
    let p = app.partition(did)?;
    for fam in state::SPACE_FAMILIES {
        let prefix = state::space_did_prefix(fam, did);
        let end = state::prefix_end(&prefix);
        loop {
            let opts = slatedb::config::ScanOptions::default();
            let mut iter =
                p.db.scan_with_options(prefix.clone()..end.clone(), &opts).await.map_err(XrpcError::from_err)?;
            let rows = iter.next_batch(SWEEP_BATCH).await.map_err(XrpcError::from_err)?;
            if rows.is_empty() {
                break;
            }
            let muts = rows.into_iter().map(|kv| crate::segment::Mutation { key: kv.key, val: None }).collect();
            super::write_private_local(&p, muts).await?;
        }
    }
    if let Some(sp) = &app.spaces {
        sp.forget_account(did);
    }
    Ok(())
}

/// Whether `outcome` is worth another try: the reference retries network
/// failures and these statuses (`@atproto/lex` RETRYABLE_HTTP_STATUS_CODES).
pub(crate) fn retryable_status(status: u16) -> bool {
    matches!(status, 408 | 425 | 429 | 500 | 502 | 503 | 504 | 522 | 524)
}

const NOTIFY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// One outbox send of `p`: a writer's newest durable rev to its space's
/// authority. A local authority records it on its own worker; any other
/// gets notifyWrite at its space host with the writer's service auth.
pub async fn deliver(app: &App, p: &Pending) -> Outcome {
    // the shard may have moved since the row was taken
    if app.partition(&p.did).is_err() || app.remote_owner(&p.did).is_some() {
        return Outcome::Gone;
    }
    let (key, status) = match super::proxy::account_key_status(app, &p.did).await {
        Ok(a) => a,
        Err(e) if e.error == "AccountNotFound" => return Outcome::Gone,
        Err(e) => return Outcome::Retry(format!("{}: {}", e.error, e.message)),
    };
    match status.as_deref() {
        Some("deleted") => return Outcome::Gone,
        Some(_) => return Outcome::Wait,
        None => {}
    }
    let Ok(space) = Space::parse(&p.uri) else { return Outcome::Refused("not a space uri".into()) };
    // worked out now, so a resent row (a rescan, a takedown's renotify)
    // never hands the authority a hash the repo no longer serves
    let hash = match served_digest(app, &p.did, &space, p.repo_rev).await {
        Ok(h) => h.unwrap_or(p.hash),
        Err(e) => return Outcome::Retry(format!("{}: {}", e.error, e.message)),
    };
    let outcome = |r: XResult<()>| match r {
        Ok(()) => Outcome::Delivered,
        Err(e) if e.status.is_server_error() => Outcome::Retry(format!("{}: {}", e.error, e.message)),
        Err(e) => Outcome::Refused(format!("{}: {}", e.error, e.message)),
    };
    // an authority hosted by this cluster is told without HTTP or service
    // auth: here, or at its shard's owner
    if let Some(owner) = app.remote_owner(&space.authority) {
        let sp = app.spaces.as_ref();
        if !sp.is_some_and(|sp| sp.known_not_hosted(&space.authority)) {
            match notify_owner(app, &owner, &space, p, hash).await {
                Ok(Some(r)) => return outcome(r),
                Ok(None) => {
                    if let Some(sp) = sp {
                        sp.mark_not_hosted(&space.authority);
                    }
                }
                Err(e) => return Outcome::Retry(format!("{}: {}", e.error, e.message)),
            }
        }
    } else if app.partition(&space.authority).is_ok()
        && super::server::account_if_exists(app, &space.authority).await.is_ok_and(|a| a.is_some())
    {
        let r = process_notify_write(app, &space, &p.did, p.repo_rev, hash, SameRev::Sequence).await;
        metrics::space_notify("in", notify_in_result(&r));
        return outcome(r.map(|_| ()));
    }
    let endpoint = match app.did_resolver.resolve(&space.authority).await {
        Ok(doc) => crate::did_resolver::service_endpoint(&doc, "atproto_space_host")
            .or_else(|| crate::did_resolver::service_endpoint(&doc, "atproto_pds")),
        Err(e) => return Outcome::Retry(format!("could not resolve {}: {e:?}", space.authority)),
    };
    let Some(endpoint) = endpoint else { return Outcome::Retry(format!("{} names no space host", space.authority)) };
    let aud = token::space_host_aud(&space.authority);
    let lxm = "com.atproto.space.notifyWrite";
    let jwt = match crate::auth::service_auth_jwt(&key, &p.did, &aud, Some(lxm), 60) {
        Ok(j) => j,
        Err(e) => return Outcome::Retry(format!("service auth: {e}")),
    };
    let body = json!({
        "space": space.uri,
        "repo": &*p.did,
        "repoRev": p.repo_rev.to_string(),
        "hash": b64(&hash),
    });
    let url = format!("{}/xrpc/{lxm}", endpoint.trim_end_matches('/'));
    let req = match crate::http::guarded(app.config.dev_mode).request(reqwest::Method::POST, &url) {
        Ok(r) => r,
        Err(e) => return Outcome::Refused(format!("space host {url}: {e}")),
    };
    let sent = req.bearer_auth(jwt).timeout(NOTIFY_TIMEOUT).json(&body).send().await;
    match sent {
        Ok(r) if r.status().is_success() => Outcome::Delivered,
        Ok(r) if retryable_status(r.status().as_u16()) => Outcome::Retry(format!("{} from {url}", r.status())),
        Ok(r) => Outcome::Refused(format!("{} from {url}", r.status())),
        Err(e) => Outcome::Retry(crate::space::host::http_error(&url, e)),
    }
}

#[derive(serde::Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct InternalNotify {
    space: String,
    repo: String,
    repo_rev: String,
    hash: String,
}

/// An outbox send to the owner of the authority's shard, another node of
/// this cluster. Ok(None): the authority isn't an account of the cluster;
/// Ok(Some(the authority's answer)); Err: the owner couldn't be asked.
async fn notify_owner(
    app: &App,
    owner: &str,
    space: &Space,
    p: &Pending,
    hash: [u8; 32],
) -> XResult<Option<XResult<()>>> {
    let body = InternalNotify {
        space: space.uri.clone(),
        repo: p.did.to_string(),
        repo_rev: p.repo_rev.to_string(),
        hash: base64::engine::general_purpose::STANDARD_NO_PAD.encode(hash),
    };
    let r = app
        .http
        .post(format!("{}/internal/v1/space/notify", owner.trim_end_matches('/')))
        .header(super::internal::HDR, &app.config.internal_token)
        .timeout(NOTIFY_TIMEOUT)
        .json(&body)
        .send()
        .await
        .map_err(|e| XrpcError::unavailable("PartitionUnavailable", format!("partition owner: {e}")))?;
    let status = r.status();
    let v: J = r.json().await.unwrap_or_default();
    if status.is_success() {
        return Ok(v["hosted"].as_bool().unwrap_or(false).then_some(Ok(())));
    }
    let e = XrpcError {
        status,
        error: v["error"].as_str().unwrap_or("InternalServerError").into(),
        message: v["message"].as_str().unwrap_or_default().into(),
    };
    match status.is_server_error() {
        true => Err(e),
        false => Ok(Some(Err(e))),
    }
}

/// [`notify_owner`] at the owner: notifyWrite from a writer on another node
/// of the cluster, trusted as the cluster's own outbox (no service auth).
async fn internal_notify(
    State(app): AppState,
    headers: HeaderMap,
    Json(inp): Json<InternalNotify>,
) -> XResult<Json<J>> {
    super::internal::check(&app, &headers)?;
    let sp = spaces(&app)?;
    sp.peer_notifies.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let space = Space::parse(&inp.space)?;
    let bad = |m: &str| XrpcError::bad("InvalidRequest", m.to_string());
    let repo_rev = Tid::parse(&inp.repo_rev).ok_or_else(|| bad("repoRev must be a valid TID"))?;
    let hash: [u8; 32] = base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(&inp.hash)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| bad("hash must be 32 bytes"))?;
    if app.remote_owner(&space.authority).is_some() {
        return Err(XrpcError::unavailable(crate::forward::SHARD_MOVED, "the authority's shard moved"));
    }
    app.partition(&space.authority)?;
    if super::server::account_if_exists(&app, &space.authority).await?.is_none() {
        return Ok(Json(json!({"hosted": false})));
    }
    let r = process_notify_write(&app, &space, &inp.repo, repo_rev, hash, SameRev::Sequence).await;
    metrics::space_notify("in", notify_in_result(&r));
    r?;
    Ok(Json(json!({"hosted": true})))
}

/// Deletes `service`'s registration for the space `uri` at its authority
/// (whose shard is this node's), if it's still expired: renewed since, it
/// stays.
pub async fn prune_registration(app: &App, uri: &str, service: &str) -> anyhow::Result<()> {
    let space = Space::parse(uri).map_err(|e| anyhow::anyhow!("{}", e.message))?;
    let p = app.partition(&space.authority).map_err(|e| anyhow::anyhow!("{}", e.message))?;
    let Some(v) = p.db.get(state::space_notify_key(&space.authority, &space.sid, service)).await? else {
        return Ok(());
    };
    let now = crate::tid::now_micros();
    if crate::space::rows::NotifyRow::decode(&v)?.expires > now {
        return Ok(());
    }
    unregister_if_expired(app, uri, service, now).await
}

/// Deletes `service`'s registration for the space `uri` if it expired by
/// `t`, checked on the authority's worker, so a renewal that lands between
/// a prune's read and its delete survives.
pub async fn unregister_if_expired(app: &App, uri: &str, service: &str, t: u64) -> anyhow::Result<()> {
    let space = Space::parse(uri).map_err(|e| anyhow::anyhow!("{}", e.message))?;
    let op = SpaceOp::UnregisterNotify { service: service.to_string(), expired_by: Some(t) };
    submit_space(app, &space.authority, &space, op).await.map_err(|e| anyhow::anyhow!("{}", e.message))?;
    Ok(())
}

/// Tests: sets `service`'s registration for the space `uri` to expire at
/// `expires` (Unix microseconds), through the authority's worker as a
/// renewal would.
pub async fn set_registration_expiry(app: &App, uri: &str, service: &str, expires: u64) -> anyhow::Result<()> {
    let space = Space::parse(uri).map_err(|e| anyhow::anyhow!("{}", e.message))?;
    let p = app.partition(&space.authority).map_err(|e| anyhow::anyhow!("{}", e.message))?;
    let key = state::space_notify_key(&space.authority, &space.sid, service);
    let v = p.db.get(key).await?.ok_or_else(|| anyhow::anyhow!("not registered"))?;
    let row = crate::space::rows::NotifyRow { expires, ..crate::space::rows::NotifyRow::decode(&v)? };
    let op = SpaceOp::RegisterNotify { service: service.to_string(), row };
    submit_space(app, &space.authority, &space, op).await.map_err(|e| anyhow::anyhow!("{}", e.message))?;
    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GetRepoQ {
    space: String,
    repo: String,
    exclude_values: Option<bool>,
}

/// A signed commit as a CAR block (dag-cbor; the reference's `SignedCommit`
/// with byte fields as bytes).
fn commit_block(c: &crate::space::commit::SignedCommit) -> Vec<u8> {
    let mut b = Vec::with_capacity(256);
    crate::cbor::write_map_head(&mut b, 6);
    // canonical key order: by length, then bytes
    for (k, v) in [("ikm", &c.ikm), ("mac", &c.mac)] {
        crate::cbor::write_text(&mut b, k);
        crate::cbor::write_bytes(&mut b, v);
    }
    crate::cbor::write_text(&mut b, "rev");
    crate::cbor::write_text(&mut b, &c.rev);
    crate::cbor::write_text(&mut b, "sig");
    crate::cbor::write_bytes(&mut b, &c.sig);
    crate::cbor::write_text(&mut b, "ver");
    crate::cbor::write_int(&mut b, c.ver);
    crate::cbor::write_text(&mut b, "hash");
    crate::cbor::write_bytes(&mut b, &c.hash);
    b
}

/// Reference getRepo (`serializeRepo`), streamed in two passes over one
/// snapshot (src/space/car.rs) under an export slot (`--max-exports`), and
/// ended for a client that reads nothing for `--export-stall-secs`. Pass 1
/// holds the paths and CIDs only: at most `--space-repo-max-records` of
/// them. A record taken down is left out of the index and the blocks, and
/// the commit is signed over the set without it ([`hidden_paths`]); with
/// `excludeValues` only the roots go.
async fn get_repo(State(app): AppState, SpaceAuth(creds): SpaceAuth, Query(q): Query<GetRepoQ>) -> XResult<Response> {
    use crate::space::car::{Car, Entries, RepoEncoder};
    spaces(&app)?;
    let space = Space::parse(&q.space)?;
    let self_read = assert_space_read(&creds, &space, &q.repo)?;
    assert_space_open(&app, &space, self_read).await?;
    let key = available(&app, &q.repo, self_read).await?;
    metrics::space_read("getRepo", auth_label(&creds));
    let slot = super::sync::export_slot(&app).await?;
    let p = app.partition(&q.repo)?;
    let snap = Arc::new(p.db.snapshot().map_err(XrpcError::from_err)?);
    let not_found = || XrpcError::bad("RepoNotFound", format!("Could not find repo for space: {}", space.uri));
    let v = snap.get(state::space_head_key(&q.repo, &space.sid)).await.map_err(XrpcError::from_err)?;
    let head = head_of(HeadRow::decode(&v.ok_or_else(not_found)?).map_err(XrpcError::from_err)?, &space, &p)?;
    let values = !q.exclude_values.unwrap_or(false);
    let hidden = hidden_paths(&app, &q.repo, &space.sid).await?;
    let overloaded = || XrpcError {
        status: StatusCode::SERVICE_UNAVAILABLE,
        error: "Overloaded".into(),
        message: "too many space repo exports in progress; retry shortly".into(),
    };
    let sp = spaces(&app)?;
    let planned = crate::space::export_bytes(head.records);
    let mut room = sp.reserve_export(planned).await.ok_or_else(overloaded)?;
    let mut set = head.hash.clone();
    let prefix = state::space_prefix(state::SPACE_RECORD_FAMILY, &q.repo, &space.sid);
    let opts = slatedb::config::ScanOptions { read_ahead_bytes: 4 << 20, cache_blocks: true, ..Default::default() };
    let mut iter = state::BatchedScan::new(
        snap.scan_with_options(prefix.clone()..state::prefix_end(&prefix), &opts).await.map_err(XrpcError::from_err)?,
    );
    let mut entries = Entries::default();
    while let Some(kv) = iter.next().await.map_err(XrpcError::from_err)? {
        let path = std::str::from_utf8(&kv.key[prefix.len()..]).map_err(XrpcError::from_err)?;
        let (cid, _) = state::record_value_parts(&kv.value).map_err(XrpcError::from_err)?;
        if !hidden.is_empty() && hidden.iter().any(|h| h == path) {
            let (collection, rkey) = path.split_once('/').ok_or_else(|| XrpcError::internal("malformed space path"))?;
            set.remove(&crate::space::commit::element(collection, rkey, &cid.to_string()));
            continue;
        }
        entries.push(path, cid);
    }
    drop(iter);
    // long paths: what pass 1 holds past its estimate is reserved too
    let held = entries.heap_bytes() as u64 + super::sync::EXPORT_CHUNK as u64;
    if held > planned {
        room.merge(sp.reserve_export(held - planned).await.ok_or_else(overloaded)?);
    }
    let rev = head.rev.to_string();
    let ctx = crate::space::commit::CommitCtx { space: &space.uri, author: &q.repo, rev: &rev };
    let t = Instant::now();
    let commit =
        crate::space::commit::sign(&set, &ctx, rand::random(), |b| Ok::<_, std::convert::Infallible>(key.sign(b)))
            .map_err(|_| XrpcError::internal("space commit context too long"))?;
    metrics::space_sign(t.elapsed());
    let stall = app.config.export_stall;
    Ok(super::sync::export_body(slot, "application/vnd.ipld.car", move |tx| async move {
        let _room = room;
        const CHUNK: usize = super::sync::EXPORT_CHUNK;
        let mut car = Car::new(commit_block(&commit));
        let order = car.order(&entries);
        car.begin(&entries, &order);
        let held = entries.heap_bytes() + order.capacity() * std::mem::size_of::<std::ops::Range<usize>>();
        // what an export holds: pass 1's paths and CIDs and the chunk being
        // filled (the body queue is the sync exports' budget)
        metrics::space_export_bytes(held + CHUNK);
        let mut buf = Vec::with_capacity(CHUNK + 4096);
        while car.prelude(&mut buf, CHUNK) {
            flush_chunk(&tx, &mut buf, stall).await?;
        }
        if values {
            for run in &order {
                let (first, last) = (entries.path(run.start), entries.path(run.end - 1));
                let lo = [&prefix[..], first.as_bytes()].concat();
                let hi = [&prefix[..], last.as_bytes(), &[0]].concat();
                let mut it = match snap.scan_with_options(lo..hi, &opts).await {
                    Ok(it) => state::BatchedScan::new(it),
                    Err(e) => {
                        tracing::warn!("space getRepo: record scan failed: {e}");
                        return Err("error");
                    }
                };
                for i in run.clone() {
                    // a run's range also spans the hidden records among its paths
                    let kv = loop {
                        match it.next().await {
                            Ok(Some(kv)) if hidden.iter().any(|h| h.as_bytes() == &kv.key[prefix.len()..]) => {}
                            Ok(Some(kv)) => break kv,
                            Ok(None) => return Err("error"),
                            Err(e) => {
                                tracing::warn!("space getRepo: record scan failed: {e}");
                                return Err("error");
                            }
                        }
                    };
                    let path = entries.path(i);
                    let (cid, bytes) = match state::record_value_parts(&kv.value) {
                        Ok(v) if &kv.key[prefix.len()..] == path.as_bytes() && v.0 == *entries.cid(i) => v,
                        _ => {
                            tracing::warn!("space getRepo: the snapshot changed between passes");
                            return Err("error");
                        }
                    };
                    car.record(&cid, bytes, &mut buf);
                    if buf.len() >= CHUNK {
                        flush_chunk(&tx, &mut buf, stall).await?;
                    }
                }
            }
        }
        if !buf.is_empty() {
            flush_chunk(&tx, &mut buf, stall).await?;
        }
        Ok(())
    }))
}

async fn flush_chunk(
    tx: &super::sync::ChunkTx,
    buf: &mut Vec<u8>,
    stall: std::time::Duration,
) -> Result<(), &'static str> {
    let chunk = std::mem::replace(buf, Vec::with_capacity(super::sync::EXPORT_CHUNK + 4096));
    super::sync::send_chunk(tx, chunk, stall).await
}

/// How far ahead of this host's clock a notified repoRev may be.
pub(super) const FUTURE_REV: std::time::Duration = std::time::Duration::from_secs(300);

/// Reference `processNotifyWrite` at the space's authority: the space must
/// be live here, the writer admitted by the write policy (the authority
/// always), and its repoRev newer than the one recorded, or the same one
/// with another hash (a record takedown or its reversal; `same_rev` says
/// whether that hash is trusted or checked at the writer's host first).
/// Recorded through the authority's worker, which assigns the spaceRev and
/// queues the forward to registered services once it's durable.
pub(super) async fn process_notify_write(
    app: &App,
    space: &Space,
    writer: &str,
    repo_rev: Tid,
    hash: [u8; 32],
    same_rev: SameRev,
) -> XResult<Notified> {
    super::simplespace::assert_space_host(app, space).await?;
    if repo_rev.micros() > crate::tid::now_micros() + FUTURE_REV.as_micros() as u64 {
        return Err(XrpcError::bad("FutureRev", "Repo revision is in the future"));
    }
    let row = super::simplespace::live_space(app, space).await?;
    if space_takendown(app, space).await? {
        tracing::debug!(space = %hex::encode(space.sid), "notifyWrite to a taken-down space dropped");
        return Ok(Notified::Noop);
    }
    let managing_app = match &row.write_policy {
        crate::space::rows::Policy::ManagingApp { .. } if writer != space.authority => {
            Some(super::simplespace::authorize_user(app, space, &row, writer, "write", None).await?)
        }
        _ => None,
    };
    let op = |same_rev| SpaceOp::RecordWriter { writer: writer.to_string(), repo_rev, hash, managing_app, same_rev };
    match submit_space_once(app, &space.authority, space, op(same_rev)).await? {
        Ok(SpaceAck::Writer(seq)) => return Ok(if seq.is_some() { Notified::Sequenced } else { Notified::Noop }),
        Ok(_) => return Err(XrpcError::internal("unexpected space ack")),
        Err(SpaceError::SameRev) => {}
        Err(e) => return Err(space_error(e)),
    }
    // every same-rev forward sends each syncer to a full getRepo, and a
    // writer's host could make up hashes for free: the cap bounds even the
    // checks, and only a hash the writer's host signs is sequenced
    let log_id = hex::encode(space.sid);
    if !spaces(app)?.same_rev_budget(writer, space.sid) {
        tracing::info!(space = %log_id, "same-rev notify over the cap dropped");
        return Ok(Notified::SameRevCapped);
    }
    if let Err(e) =
        crate::space::host::check_served_hash(app, &space.uri, &space.authority, writer, repo_rev, &hash).await
    {
        tracing::info!(space = %log_id, "same-rev notify not confirmed by the writer's host, dropped: {e}");
        return Ok(Notified::SameRevUnverified);
    }
    match submit_space_once(app, &space.authority, space, op(SameRev::Sequence)).await? {
        Ok(SpaceAck::Writer(seq)) => Ok(if seq.is_some() { Notified::Sequenced } else { Notified::Noop }),
        Ok(_) => Err(XrpcError::internal("unexpected space ack")),
        Err(e) => Err(space_error(e)),
    }
}

/// What an inbound notifyWrite did.
pub(super) enum Notified {
    Sequenced,
    /// Not newer, or the space is taken down.
    Noop,
    /// The same repoRev with another hash, over [`crate::space::Spaces::same_rev_budget`].
    SameRevCapped,
    /// The same repoRev with another hash that the writer's host didn't
    /// serve, or couldn't be asked about. Polls catch a real one up.
    SameRevUnverified,
}

fn notify_in_result(r: &XResult<Notified>) -> &'static str {
    match r {
        Ok(Notified::Sequenced) => "ok",
        Ok(Notified::Noop) => "noop",
        Ok(Notified::SameRevCapped) => "same_rev_capped",
        Ok(Notified::SameRevUnverified) => "same_rev_unverified",
        Err(e) if e.status.is_server_error() => "error",
        Err(_) => "refused",
    }
}

/// `$bytes` of exactly `n` bytes.
fn bytes_field<const N: usize>(v: &J) -> Option<[u8; N]> {
    let s = v.get("$bytes")?.as_str()?;
    let b = base64::engine::general_purpose::STANDARD_NO_PAD.decode(s.trim_end_matches('=')).ok()?;
    b.try_into().ok()
}

/// Reference notifyWrite at a space host: the writer's repo host, by
/// service auth from the writer (`iss` is the claimed `repo`, so no host
/// notifies for another's account) addressed to the space's authority. The
/// repoRev is checked before auth, as the reference's input validation is.
async fn notify_write(State(app): AppState, headers: HeaderMap, Json(inp): Json<J>) -> XResult<StatusCode> {
    spaces(&app)?;
    let r = notify_write_inner(&app, &headers, &inp).await;
    metrics::space_notify("in", notify_in_result(&r));
    r.map(|_| StatusCode::OK)
}

async fn notify_write_inner(app: &App, headers: &HeaderMap, inp: &J) -> XResult<Notified> {
    let field = |k: &str| inp.get(k).and_then(|v| v.as_str());
    let repo_rev = field("repoRev")
        .and_then(Tid::parse)
        .ok_or_else(|| XrpcError::bad("InvalidRequest", "Input/repoRev must be a valid TID"))?;
    let space = Space::parse(field("space").unwrap_or(""))?;
    let repo = field("repo")
        .filter(|d| super::syntax::valid_did(d))
        .ok_or_else(|| XrpcError::bad("InvalidRequest", "Input/repo must be a valid did"))?;
    let hash = inp
        .get("hash")
        .and_then(bytes_field::<32>)
        .ok_or_else(|| XrpcError::bad("InvalidRequest", "Input/hash must be 32 bytes"))?;
    let auth = super::authn::verify_space_service_jwt(app, headers, "com.atproto.space.notifyWrite").await?;
    if auth.iss != repo {
        return Err(forbidden("notifyWrite iss does not match claimed writer"));
    }
    crate::ratelimit::check(&[&crate::ratelimit::SPACE_NOTIFY_IN], &auth.iss, 1)?;
    if auth.aud != space.authority && auth.aud != token::space_host_aud(&space.authority) {
        return Err(forbidden("notifyWrite aud does not match the space authority"));
    }
    process_notify_write(app, &space, repo, repo_rev, hash, SameRev::Verify).await
}

/// A request the space host answers for a credential holder only: the
/// credential is this space's and addressed to the authority.
/// The verified credential.
async fn host_credential(app: &App, headers: &HeaderMap, space: &Space) -> XResult<Credentials> {
    let cred = super::authn::verify_space_credential(app, headers).await?;
    match &cred {
        Credentials::SpaceCredential { audience, space: s, .. } => {
            assert_credential_space(audience, s, space, &space.authority)?
        }
        _ => return Err(XrpcError::internal("not a space credential")),
    }
    // a credential minted before the authority's takedown outlives it by up
    // to its 300 s; getSpaceCredential's gate alone wouldn't stop it. An
    // authority not hosted here is left to the callers' own checks.
    if let Ok((_, Some(st))) = super::proxy::account_key_status(app, &space.authority).await {
        if st == "takendown" || st == "suspended" {
            return Err(XrpcError::bad("RepoTakendown", "Space authority has been taken down"));
        }
    }
    Ok(cred)
}

#[derive(Deserialize)]
struct ListReposQ {
    space: String,
    limit: Option<i64>,
    cursor: Option<String>,
}

/// The first spaceRev a listRepos cursor admits. The reference compares it
/// with spaceRevs as a plain string; a TID's string order is its numeric
/// order, so the first TID whose string is greater is found by bisection.
fn space_rev_after(cursor: &str) -> Option<u64> {
    if let Some(t) = Tid::parse(cursor) {
        return t.0.checked_add(1);
    }
    let (mut lo, mut hi) = (0u64, 1u64 << 63);
    if Tid(hi - 1).to_string().as_str() <= cursor {
        return None;
    }
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if Tid(mid).to_string().as_str() > cursor {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    Some(lo)
}

/// Reference listRepos: each writer's latest state, in spaceRev order after
/// the cursor (`sQ` joined to `sW` in one snapshot). A writer updated while
/// a client pages may show up again, as the lexicon says.
async fn list_repos(State(app): AppState, headers: HeaderMap, Query(q): Query<ListReposQ>) -> XResult<Json<J>> {
    spaces(&app)?;
    let space = Space::parse(&q.space)?;
    let limit = super::extract::limit_param(q.limit, 100, 1, 1000)?;
    host_credential(&app, &headers, &space).await?;
    super::simplespace::live_space(&app, &space).await?;
    if space_takendown(&app, &space).await? {
        return Err(super::simplespace::space_not_found());
    }
    metrics::space_read("listRepos", "credential");
    let p = app.partition(&space.authority)?;
    let snap = p.db.snapshot().map_err(XrpcError::from_err)?;
    let prefix = state::space_prefix(state::SPACE_SEQ_FAMILY, &space.authority, &space.sid);
    let lo = match q.cursor.as_deref() {
        None => prefix.clone(),
        Some(c) => match space_rev_after(c) {
            Some(rev) => [&prefix[..], &rev.to_be_bytes()].concat(),
            None => return Ok(Json(json!({"repos": []}))),
        },
    };
    let opts = slatedb::config::ScanOptions::default();
    let mut iter = snap.scan_with_options(lo..state::prefix_end(&prefix), &opts).await.map_err(XrpcError::from_err)?;
    let mut repos = Vec::with_capacity(limit.min(256));
    let mut last = None;
    while repos.len() < limit {
        let rows = iter.next_batch(limit - repos.len()).await.map_err(XrpcError::from_err)?;
        if rows.is_empty() {
            break;
        }
        for kv in rows {
            let space_rev =
                crate::space::rows::seq_rev(&kv.key).ok_or_else(|| XrpcError::internal("malformed space seq key"))?;
            let writer = crate::space::rows::SeqRow::decode(&kv.value).map_err(XrpcError::from_err)?.writer;
            let k = state::space_writer_key(&space.authority, &space.sid, &writer);
            let Some(v) = snap.get(k).await.map_err(XrpcError::from_err)? else { continue };
            let w = crate::space::rows::WriterRow::decode(&v).map_err(XrpcError::from_err)?;
            repos.push(json!({
                "did": writer,
                "repoRev": w.repo_rev.to_string(),
                "hash": b64(&w.hash),
                "spaceRev": space_rev.to_string(),
            }));
            last = Some(space_rev);
        }
    }
    let mut out = json!({"repos": repos});
    if let Some(rev) = last {
        out["cursor"] = json!(rev.to_string());
    }
    Ok(Json(out))
}

#[derive(Deserialize)]
struct RegisterIn {
    space: String,
    service: String,
}

/// Reference registerNotify: a credential holder subscribes a service (a DID
/// with an optional fragment) to the space's write notifications for a
/// day. Registering again replaces the endpoint and extends the expiry.
async fn register_notify(State(app): AppState, headers: HeaderMap, Json(inp): Json<RegisterIn>) -> XResult<Json<J>> {
    let sp = spaces(&app)?.clone();
    let space = Space::parse(&inp.space)?;
    let cred = host_credential(&app, &headers, &space).await?;
    super::simplespace::assert_space_host(&app, &space).await?;
    if space_takendown(&app, &space).await? {
        return Err(super::simplespace::space_not_found());
    }
    use crate::space::host::{MAX_REGISTRATIONS, MAX_SERVICE_LEN};
    if inp.service.len() > MAX_SERVICE_LEN {
        return Err(XrpcError::bad("InvalidRequest", format!("service must be at most {MAX_SERVICE_LEN} bytes")));
    }
    if let Credentials::SpaceCredential { iss, jti, .. } = &cred {
        let key = super::authn::private_limit_key(&app, &format!("{iss} {jti}"));
        crate::ratelimit::check(&[&crate::ratelimit::SPACE_REGISTER], &key, 1)?;
    }
    // every write of the space is forwarded to each registration: one
    // member mustn't make that unbounded. Counted and made under the
    // space's lock, so concurrent registrations can't pass the cap together.
    let _registering = sp.registering(&space.sid).await;
    let (live, expired) =
        crate::space::host::registrations(&app, &space.authority, &space.sid).await.map_err(XrpcError::from_err)?;
    for service in expired {
        sp.fanout.prune(&app, &space.uri.as_str().into(), service);
    }
    let renewal = live.iter().any(|(s, _)| *s == inp.service);
    if live.iter().filter(|(s, _)| *s != inp.service).count() >= MAX_REGISTRATIONS {
        return Err(XrpcError::bad(
            "InvalidRequest",
            format!("this space has {MAX_REGISTRATIONS} notify registrations; unregister one first"),
        ));
    }
    if !renewal {
        let (_, cap) = sp.account_caps();
        let n = crate::space::host::authority_registrations(&app, &space.authority, cap)
            .await
            .map_err(XrpcError::from_err)?;
        if n >= cap {
            return Err(XrpcError::bad(
                "InvalidRequest",
                format!("this space's authority has {cap} notify registrations across its spaces"),
            ));
        }
    }
    let Some(endpoint) = crate::space::host::resolve_service_endpoint(&app, &inp.service).await else {
        return Err(XrpcError::bad(
            "ServiceNotResolvable",
            format!("Could not resolve a service endpoint for {}", inp.service),
        ));
    };
    let expires = crate::tid::now_micros() + crate::space::host::REGISTRATION_TTL.as_micros() as u64;
    let row = crate::space::rows::NotifyRow { endpoint, expires };
    submit_space(&app, &space.authority, &space, SpaceOp::RegisterNotify { service: inp.service, row }).await?;
    let at =
        chrono::DateTime::from_timestamp_micros(expires as i64).ok_or_else(|| XrpcError::internal("bad expiry"))?;
    Ok(Json(json!({"expiresAt": at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)})))
}

/// Reference unregisterNotify: not resolved again (a subscriber whose DID
/// document changed can still withdraw); fine when nothing was registered.
async fn unregister_notify(
    State(app): AppState,
    headers: HeaderMap,
    Json(inp): Json<RegisterIn>,
) -> XResult<StatusCode> {
    spaces(&app)?;
    let space = Space::parse(&inp.space)?;
    host_credential(&app, &headers, &space).await?;
    super::simplespace::assert_space_host(&app, &space).await?;
    submit_space(&app, &space.authority, &space, SpaceOp::UnregisterNotify { service: inp.service, expired_by: None })
        .await?;
    Ok(StatusCode::OK)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_repos_cursors_compare_as_strings() {
        let t = Tid::from_parts(1_790_000_000_000_000, 3);
        assert_eq!(space_rev_after(&t.to_string()), Some(t.0 + 1));
        for c in ["", "0", "2", "3jzfcijpj2z2", "3jzfcijpj2z2a0", "abc", "b", "bzzzzzzzzzzz"] {
            let first = space_rev_after(c).unwrap();
            assert!(Tid(first).to_string().as_str() > c, "{c}");
            if first > 0 {
                assert!(Tid(first - 1).to_string().as_str() <= c, "{c}");
            }
        }
        // past every TID
        assert_eq!(space_rev_after("c"), None);
        assert_eq!(space_rev_after("zzz"), None);
    }

    #[test]
    fn commit_blocks_are_canonical() {
        let c = crate::space::commit::SignedCommit {
            ver: 1,
            hash: vec![1; 32],
            ikm: vec![2; 32],
            sig: vec![3; 64],
            mac: vec![4; 32],
            rev: "3jzfcijpj2z2a".into(),
        };
        let b = commit_block(&c);
        let v = crate::cbor::Value::decode(&b).unwrap();
        assert_eq!(v.to_cbor(), b, "decodes and re-encodes to the same bytes");
        assert_eq!(v.get("rev").and_then(|r| r.as_str()), Some("3jzfcijpj2z2a"));
    }
}
