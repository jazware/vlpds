//! The space host role for spaces anchored on an account hosted here
//! (`--spaces`; reference `space-policy/`): the lifecycle methods
//! (`com.atproto.space.{create,update,get,delete}Space`, `removeWriter`)
//! and the member space's member list (`com.atproto.memberspace.*`). Space
//! state (`sS`, `sM`, `sW`/`sQ`, `sN`) lives in the authority's shard and
//! changes through its repo worker, so policy, member and spaceRev changes
//! serialize there with no lock, and the published policy and member
//! records (`crate::space::policy`) change in the same entry.

use super::space::{spaces, submit_space, Space};
use super::*;
use crate::oauth::scopes::SpaceAccess;
use crate::space::repo::{SpaceAck, SpaceOp};
use crate::space::rows::{MemberRow, SpacePolicy, SpaceRow, MANAGED_POLICY, MEMBER_POLICY, PERSONAL_POLICY};

pub fn routes() -> Router<Arc<App>> {
    Router::new()
        .route("/xrpc/com.atproto.space.createSpace", post(create_space))
        .route("/xrpc/com.atproto.space.getSpace", get(get_space))
        .route("/xrpc/com.atproto.space.updateSpace", post(update_space))
        .route("/xrpc/com.atproto.space.deleteSpace", post(delete_space))
        .route("/xrpc/com.atproto.space.removeWriter", post(remove_writer))
        .route("/xrpc/com.atproto.memberspace.putMember", post(put_member))
        .route("/xrpc/com.atproto.memberspace.removeMember", post(remove_member))
        .route("/xrpc/com.atproto.memberspace.listMembers", get(list_members))
}

fn opt_flag(v: &J, k: &str) -> XResult<bool> {
    match v.get(k) {
        None | Some(J::Null) => Ok(false),
        Some(J::Bool(b)) => Ok(*b),
        Some(_) => Err(XrpcError::bad("InvalidRequest", format!("policy.{k} must be a boolean"))),
    }
}

/// Reference `normalizePolicy`: a policy this host implements, its
/// defaults filled in and unknown fields dropped, so what is stored is
/// what is enforced. An unimplemented `$type` is UnsupportedPolicy.
pub(super) fn policy_from_lex(v: &J) -> XResult<SpacePolicy> {
    let J::Object(_) = v else {
        return Err(XrpcError::bad("InvalidRequest", "policy must be an object"));
    };
    let t = v.get("$type").and_then(|t| t.as_str()).unwrap_or("");
    match t {
        PERSONAL_POLICY => Ok(SpacePolicy::Personal),
        MEMBER_POLICY => {
            let allowed_apps = match v.get("allowedApps") {
                None | Some(J::Null) => None,
                Some(J::Array(a)) => Some(
                    a.iter()
                        .map(|c| c.as_str().map(String::from))
                        .collect::<Option<Vec<_>>>()
                        .ok_or_else(|| XrpcError::bad("InvalidRequest", "policy.allowedApps must be strings"))?,
                ),
                Some(_) => return Err(XrpcError::bad("InvalidRequest", "policy.allowedApps must be an array")),
            };
            Ok(SpacePolicy::Member {
                public_read: opt_flag(v, "publicRead")?,
                public_write: opt_flag(v, "publicWrite")?,
                allowed_apps,
                publish_policy: opt_flag(v, "publishPolicy")?,
                publish_members: opt_flag(v, "publishMembers")?,
            })
        }
        MANAGED_POLICY => {
            let app = v.get("managingApp").and_then(|a| a.as_str()).unwrap_or("");
            if !app.starts_with("did:") {
                return Err(XrpcError::bad(
                    "InvalidRequest",
                    format!("managingApp must be a DID with an optional service fragment, got: {app}"),
                ));
            }
            Ok(SpacePolicy::Managed { managing_app: app.into(), publish_policy: opt_flag(v, "publishPolicy")? })
        }
        _ => Err(XrpcError::bad("UnsupportedPolicy", format!("Unsupported policy: {t}"))),
    }
}

/// Reference `assertSpaceHost`: the authority is an account hosted here
/// (in any state), or this host doesn't govern the space.
pub(super) async fn assert_space_host(app: &App, space: &Space) -> XResult<()> {
    match super::server::account_if_exists(app, &space.authority).await? {
        Some(_) => Ok(()),
        None => Err(space_not_found()),
    }
}

pub(super) fn policy_mismatch() -> XrpcError {
    XrpcError::bad("PolicyMismatch", "Space is not governed by the memberspace policy")
}

pub(super) fn space_not_found() -> XrpcError {
    XrpcError::bad("SpaceNotFound", "Space not found")
}

/// The space's row at its authority, which must be an account hosted here.
/// A deleted space is its tombstone; None: never created.
pub(super) async fn space_row_opt(app: &App, space: &Space) -> XResult<Option<SpaceRow>> {
    assert_space_host(app, space).await?;
    let p = app.partition(&space.authority)?;
    let Some(v) = p.db.get(state::space_key(&space.authority, &space.sid)).await.map_err(XrpcError::from_err)? else {
        return Ok(None);
    };
    let row = SpaceRow::decode(&v).map_err(XrpcError::from_err)?;
    if row.uri != space.uri {
        return Err(XrpcError::internal(format!("space id collision: {} and {}", row.uri, space.uri)));
    }
    Ok(Some(row))
}

/// Live spaces `did` governs, counted up to `stop_at`.
pub(super) async fn live_spaces(app: &App, did: &str, stop_at: usize) -> XResult<usize> {
    let p = app.partition(did)?;
    let prefix = state::space_did_prefix(state::SPACE_FAMILY, did);
    let mut it =
        p.db.scan(prefix.clone()..vlsync_store::keys::prefix_end(&prefix)).await.map_err(XrpcError::from_err)?;
    let mut n = 0;
    while let Some(kv) = it.next().await.map_err(XrpcError::from_err)? {
        if SpaceRow::decode(&kv.value).map_err(XrpcError::from_err)?.live() {
            n += 1;
            if n >= stop_at {
                break;
            }
        }
    }
    Ok(n)
}

/// [`space_row_opt`], a space never created being SpaceNotFound.
pub(super) async fn space_row(app: &App, space: &Space) -> XResult<SpaceRow> {
    space_row_opt(app, space).await?.ok_or_else(space_not_found)
}

/// The live space (reference `getActiveSpaceConfig`).
pub(super) async fn live_space(app: &App, space: &Space) -> XResult<SpaceRow> {
    let row = space_row(app, space).await?;
    if !row.live() {
        return Err(space_not_found());
    }
    Ok(row)
}

/// Reference `authorizeUser`: the authority can't lock itself out of the
/// space it alone can reconfigure; otherwise the policy decides `access`
/// (`read` or `write`). A personal space admits no one else; a member
/// space anyone on the public side, else a member with the flag; a
/// managed space asks its managing app, which denies when it can't be
/// asked. `client_id` (the attested app) goes to the managing app on reads.
pub(super) async fn authorize_user(
    app: &App,
    space: &Space,
    row: &SpaceRow,
    user: &str,
    access: &str,
    client_id: Option<&str>,
) -> XResult<bool> {
    if user == space.authority {
        return Ok(true);
    }
    match &row.policy {
        SpacePolicy::Personal => Ok(false),
        SpacePolicy::Member { public_read, public_write, .. } => {
            if if access == "read" { *public_read } else { *public_write } {
                return Ok(true);
            }
            let p = app.partition(&space.authority)?;
            let k = state::space_member_key(&space.authority, &space.sid, user);
            let m = p.db.get(k).await.map_err(XrpcError::from_err)?;
            let m = m.map(|v| MemberRow::decode(&v)).transpose().map_err(XrpcError::from_err)?;
            Ok(m.is_some_and(|m| if access == "read" { m.read } else { m.write }))
        }
        SpacePolicy::Managed { managing_app, .. } => Ok(crate::space::host::check_user_access(
            app,
            &space.uri,
            &space.authority,
            managing_app,
            user,
            access,
            if access == "read" { client_id } else { None },
        )
        .await),
    }
}

/// Reference `assertSpaceOwner`: the scope for `access`, then the caller
/// must be the space's authority.
pub(super) fn assert_owner(creds: &Credentials, space: &Space, access: SpaceAccess) -> XResult<String> {
    creds.need_space(&space.target(), access)?;
    let did = creds.user_did()?;
    if did != space.authority {
        return Err(XrpcError::bad("NotSpaceOwner", "Not the space owner"));
    }
    Ok(did.to_string())
}

fn req_space(v: &J) -> XResult<Space> {
    let s =
        v.get("space").and_then(|s| s.as_str()).ok_or_else(|| XrpcError::bad("InvalidRequest", "space is required"))?;
    Space::parse(s)
}

fn req_did<'a>(v: &'a J, k: &str) -> XResult<&'a str> {
    v.get(k)
        .and_then(|s| s.as_str())
        .filter(|d| vlatproto::syntax::valid_did(d))
        .ok_or_else(|| XrpcError::bad("InvalidRequest", format!("{k} must be a DID")))
}

fn req_bool(v: &J, k: &str) -> XResult<bool> {
    v.get(k).and_then(|b| b.as_bool()).ok_or_else(|| XrpcError::bad("InvalidRequest", format!("{k} must be a boolean")))
}

/// Reference createSpace: anchored on the caller, `skey` a TID unless
/// given, governed by `policy`. Over a deleted space's tombstone it starts
/// fresh.
async fn create_space(State(app): AppState, Auth(creds): Auth, Json(inp): Json<J>) -> XResult<Json<J>> {
    spaces(&app)?;
    let did = creds.user_did()?.to_string();
    let space_type = inp.get("spaceType").and_then(|t| t.as_str()).unwrap_or("");
    if !vlatproto::syntax::valid_nsid(space_type) {
        return Err(XrpcError::bad("InvalidRequest", "spaceType must be an NSID"));
    }
    let skey = match inp.get("skey") {
        None | Some(J::Null) => app.tids.next().to_string(),
        Some(J::String(s)) if vlatproto::syntax::valid_rkey(s) => s.clone(),
        Some(_) => return Err(XrpcError::bad("InvalidRequest", "skey must be a valid record key")),
    };
    let space = Space::parse(&format!("at://{did}/space/{space_type}/{skey}"))?;
    creds.need_space(&space.target(), SpaceAccess::Manage("create"))?;
    let policy = policy_from_lex(inp.get("policy").unwrap_or(&J::Null))?;
    let row =
        SpaceRow { uri: space.uri.clone(), policy, created_at: vlatproto::events::now_rfc3339(), deleted_at: None };
    let existing = space_row_opt(&app, &space).await?;
    if existing.as_ref().is_none_or(|r| !r.live()) {
        crate::ratelimit::check(&[&crate::ratelimit::SPACE_CREATE], &did, 1)?;
        let (cap, _) = spaces(&app)?.account_caps();
        if live_spaces(&app, &did, cap).await? >= cap {
            return Err(XrpcError::bad(
                "InvalidRequest",
                format!("this account governs {cap} spaces; delete one first"),
            ));
        }
    }
    if existing.is_some_and(|r| !r.live()) {
        // a deletion's sweep may have stopped part way: nothing of the old
        // space (members above all) may carry over
        delete_space_rows(&app, &space).await?;
    }
    submit_space(&app, &did, &space, SpaceOp::CreateSpace { row }).await?;
    Ok(Json(json!({"uri": space.uri})))
}

#[derive(Deserialize)]
struct SpaceQ {
    space: String,
}

/// Reference getSpace: the owner only, with OAuth (or a session) and a
/// covering `read_self` grant. A space credential isn't taken: a member
/// hosted elsewhere, or a syncer, reads the published policy record.
async fn get_space(State(app): AppState, Auth(creds): Auth, Query(q): Query<SpaceQ>) -> XResult<Json<J>> {
    spaces(&app)?;
    let space = Space::parse(&q.space)?;
    assert_owner(&creds, &space, SpaceAccess::ReadSelf)?;
    let row = live_space(&app, &space).await?;
    Ok(Json(json!({"uri": row.uri, "policy": row.policy.to_json()})))
}

/// Reference updateSpace: the policy is replaced wholesale. A policy of
/// another `$type` migrates the space and discards the old policy's state
/// (a member list), and doesn't re-evaluate the writer set.
async fn update_space(State(app): AppState, Auth(creds): Auth, Json(inp): Json<J>) -> XResult<StatusCode> {
    spaces(&app)?;
    let space = req_space(&inp)?;
    let did = assert_owner(&creds, &space, SpaceAccess::Manage("update"))?;
    let policy = policy_from_lex(inp.get("policy").unwrap_or(&J::Null))?;
    let current = live_space(&app, &space).await?.policy;
    // the member list, to publish, withdraw or drop with the change
    let members = if current.is_member()
        && (current.type_name() != policy.type_name() || current.publishes_members() != policy.publishes_members())
    {
        all_members(&app, &space).await?
    } else {
        Vec::new()
    };
    submit_space(&app, &did, &space, SpaceOp::UpdateSpace { policy, members }).await?;
    Ok(StatusCode::OK)
}

/// The space's member list, whole.
async fn all_members(app: &App, space: &Space) -> XResult<Vec<(String, MemberRow)>> {
    let p = app.partition(&space.authority)?;
    let prefix = state::space_prefix(state::SPACE_MEMBER_FAMILY, &space.authority, &space.sid);
    let mut it =
        p.db.scan(prefix.clone()..vlsync_store::keys::prefix_end(&prefix)).await.map_err(XrpcError::from_err)?;
    let mut out = Vec::new();
    while let Some(kv) = it.next().await.map_err(XrpcError::from_err)? {
        let did = std::str::from_utf8(&kv.key[prefix.len()..]).map_err(XrpcError::from_err)?;
        out.push((did.to_string(), MemberRow::decode(&kv.value).map_err(XrpcError::from_err)?));
    }
    Ok(out)
}

/// Reference deleteSpace: the space becomes a tombstone (getSpaceCredential
/// answers SpaceDeleted from then on), its member list, writer states and
/// registrations go, and so does the authority's own repo in it; other
/// members' repos are theirs and stay. Each service registered at the time
/// is owed a notifySpaceDeleted, recorded before the tombstone and sent
/// until it lands ([`crate::space::deletions`]). Deleting a deleted space
/// finishes its sweep and is a no-op.
async fn delete_space(State(app): AppState, Auth(creds): Auth, Json(inp): Json<J>) -> XResult<StatusCode> {
    spaces(&app)?;
    let space = req_space(&inp)?;
    let did = assert_owner(&creds, &space, SpaceAccess::Manage("delete"))?;
    assert_space_host(&app, &space).await?;
    let owed = match space_row_opt(&app, &space).await? {
        Some(row) if row.live() => {
            let (regs, _) = crate::space::host::registrations(&app, &did, &space.sid)
                .await
                .map_err(|e| XrpcError::unavailable("Unavailable", format!("space registrations unreadable: {e:#}")))?;
            crate::space::deletions::record(&app, &did, &space.sid, &space.uri, &row.created_at, &regs).await?;
            !regs.is_empty()
        }
        _ => false,
    };
    let ack =
        submit_space(&app, &did, &space, SpaceOp::DeleteSpace { deleted_at: vlatproto::events::now_rfc3339() }).await?;
    if owed && matches!(ack, SpaceAck::Deleted { already: false }) {
        crate::space::deletions::send_now(&app, &did, space.sid);
    }
    delete_space_rows(&app, &space).await?;
    Ok(StatusCode::OK)
}

pub(super) const SWEEP_BATCH: usize = 500;

/// Every row of a deleted space at its authority but the tombstone: the
/// member list, writer states, sequence, registrations and the authority's
/// own repo, in bounded entries. Idempotent; rerun by a createSpace over
/// the tombstone in case a sweep stopped part way.
pub(super) async fn delete_space_rows(app: &App, space: &Space) -> XResult<()> {
    let p = app.partition(&space.authority)?;
    for fam in [
        state::SPACE_MEMBER_FAMILY,
        state::SPACE_WRITER_FAMILY,
        state::SPACE_SEQ_FAMILY,
        state::SPACE_NOTIFY_FAMILY,
        state::SPACE_BLOB_FAMILY,
        state::SPACE_RECORD_FAMILY,
        state::SPACE_OPLOG_FAMILY,
        state::SPACE_HEAD_FAMILY,
    ] {
        let prefix = state::space_prefix(fam, &space.authority, &space.sid);
        let end = vlsync_store::keys::prefix_end(&prefix);
        loop {
            let opts = slatedb::config::ScanOptions::default();
            let mut iter =
                p.db.scan_with_options(prefix.clone()..end.clone(), &opts).await.map_err(XrpcError::from_err)?;
            let rows = iter.next_batch(SWEEP_BATCH).await.map_err(XrpcError::from_err)?;
            if rows.is_empty() {
                break;
            }
            let mut muts = Vec::with_capacity(rows.len());
            for kv in rows {
                // a blob ref's CID-major twin goes in the same entry, so the
                // GC never keeps a blob for a ref that is gone
                if fam == state::SPACE_BLOB_FAMILY {
                    let (cid, path) = crate::space::rows::blob_ref_parts(&kv.key[prefix.len()..])
                        .ok_or_else(|| XrpcError::internal("bad space blob ref key"))?;
                    let cid = Cid::parse(cid).map_err(XrpcError::from_err)?;
                    let key = state::space_blob_cid_key(&space.authority, &cid, &space.sid, path);
                    muts.push(vlsync_store::segment::Mutation { key: key.into(), val: None });
                }
                if fam == state::SPACE_HEAD_FAMILY {
                    let key = state::space_list_key(&space.authority, &space.uri, state::SpaceListed::Repo);
                    muts.push(vlsync_store::segment::Mutation { key: key.into(), val: None });
                }
                muts.push(vlsync_store::segment::Mutation { key: kv.key, val: None });
            }
            super::write_private_local(&p, muts).await?;
        }
    }
    if let Some(sp) = &app.spaces {
        sp.forget_space(&space.authority, &space.sid);
    }
    Ok(())
}

/// Reference memberspace.putMember: both flags replace the member's; a
/// member who can't write leaves the writer set. PolicyMismatch on a space
/// another policy governs.
async fn put_member(State(app): AppState, Auth(creds): Auth, Json(inp): Json<J>) -> XResult<StatusCode> {
    spaces(&app)?;
    let space = req_space(&inp)?;
    let member = req_did(&inp, "did")?.to_string();
    let access = MemberRow { read: req_bool(&inp, "read")?, write: req_bool(&inp, "write")? };
    let did = assert_owner(&creds, &space, SpaceAccess::Manage("update"))?;
    assert_space_host(&app, &space).await?;
    submit_space(&app, &did, &space, SpaceOp::PutMember { member, access }).await?;
    Ok(StatusCode::OK)
}

/// Reference memberspace.removeMember: the member leaves the writer set
/// too (listRepos stops naming it; its records stay on its host).
async fn remove_member(State(app): AppState, Auth(creds): Auth, Json(inp): Json<J>) -> XResult<StatusCode> {
    spaces(&app)?;
    let space = req_space(&inp)?;
    let member = req_did(&inp, "did")?.to_string();
    let did = assert_owner(&creds, &space, SpaceAccess::Manage("update"))?;
    assert_space_host(&app, &space).await?;
    submit_space(&app, &did, &space, SpaceOp::RemoveMember { member }).await?;
    Ok(StatusCode::OK)
}

/// Reference space.removeWriter: the owner, with `manage=update`.
/// Idempotent; the writer is tracked again by its next write the policy
/// allows.
async fn remove_writer(State(app): AppState, Auth(creds): Auth, Json(inp): Json<J>) -> XResult<StatusCode> {
    spaces(&app)?;
    let space = req_space(&inp)?;
    let writer = req_did(&inp, "did")?.to_string();
    let did = assert_owner(&creds, &space, SpaceAccess::Manage("update"))?;
    assert_space_host(&app, &space).await?;
    submit_space(&app, &did, &space, SpaceOp::RemoveWriter { writer }).await?;
    Ok(StatusCode::OK)
}

#[derive(Deserialize)]
struct ListMembersQ {
    space: String,
    limit: Option<i64>,
    cursor: Option<String>,
}

/// Reference memberspace.listMembers: OAuth only (the member list is the
/// authority's own state; a credential doesn't reach it), by DID, the
/// cursor the last one listed. PolicyMismatch on another policy's space.
async fn list_members(State(app): AppState, Auth(creds): Auth, Query(q): Query<ListMembersQ>) -> XResult<Json<J>> {
    spaces(&app)?;
    let space = Space::parse(&q.space)?;
    let limit = super::extract::limit_param(q.limit, 100, 1, 1000)?;
    assert_owner(&creds, &space, SpaceAccess::ReadSelf)?;
    if !live_space(&app, &space).await?.policy.is_member() {
        return Err(policy_mismatch());
    }
    let p = app.partition(&space.authority)?;
    let prefix = state::space_prefix(state::SPACE_MEMBER_FAMILY, &space.authority, &space.sid);
    let lo = match &q.cursor {
        Some(c) => [&prefix[..], c.as_bytes(), &[0]].concat(),
        None => prefix.clone(),
    };
    let opts = slatedb::config::ScanOptions::default();
    let mut iter =
        p.db.scan_with_options(lo..vlsync_store::keys::prefix_end(&prefix), &opts)
            .await
            .map_err(XrpcError::from_err)?;
    let mut members = Vec::with_capacity(limit.min(256));
    while members.len() < limit {
        let rows = iter.next_batch(limit - members.len()).await.map_err(XrpcError::from_err)?;
        if rows.is_empty() {
            break;
        }
        for kv in rows {
            let did = std::str::from_utf8(&kv.key[prefix.len()..]).map_err(XrpcError::from_err)?;
            let m = MemberRow::decode(&kv.value).map_err(XrpcError::from_err)?;
            members.push(json!({"did": did, "read": m.read, "write": m.write}));
        }
    }
    let mut out = json!({});
    if let Some(last) = members.last() {
        out["cursor"] = last["did"].clone();
    }
    out["members"] = J::Array(members);
    Ok(Json(out))
}
