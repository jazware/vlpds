//! `com.atproto.simplespace.*` (`--spaces`): the space host role for spaces
//! anchored on an account hosted here (reference `simplespace/`). Space
//! state (`sS`, `sM`, `sW`/`sQ`, `sN`) lives in the authority's shard and
//! changes through its repo worker, so config, member and spaceRev changes
//! serialize there with no lock.

use super::authn::SpaceAuth;
use super::space::{assert_credential_space, spaces, submit_space, Space};
use super::*;
use crate::oauth::scopes::SpaceAccess;
use crate::space::repo::{SpaceAck, SpaceOp};
use crate::space::rows::{AppAccess, MemberRow, Policy, SpaceRow};

pub fn routes() -> Router<Arc<App>> {
    Router::new()
        .route("/xrpc/com.atproto.simplespace.createSpace", post(create_space))
        .route("/xrpc/com.atproto.simplespace.getSpace", get(get_space))
        .route("/xrpc/com.atproto.simplespace.updateSpace", post(update_space))
        .route("/xrpc/com.atproto.simplespace.deleteSpace", post(delete_space))
        .route("/xrpc/com.atproto.simplespace.putMember", post(put_member))
        .route("/xrpc/com.atproto.simplespace.removeMember", post(remove_member))
        .route("/xrpc/com.atproto.simplespace.listMembers", get(list_members))
}

const DEFS: &str = "com.atproto.simplespace.defs";

fn lex_type(v: &J) -> &str {
    v.get("$type").and_then(|t| t.as_str()).unwrap_or("")
}

/// Reference `lexPolicyToDb`.
fn policy_from_lex(v: &J) -> XResult<Policy> {
    let t = lex_type(v);
    match t.strip_prefix(DEFS).unwrap_or("") {
        "#publicPolicy" => Ok(Policy::Public),
        "#memberListPolicy" => Ok(Policy::MemberList),
        "#managingAppPolicy" => {
            let app = v.get("managingApp").and_then(|a| a.as_str()).unwrap_or("");
            if !app.starts_with("did:") {
                return Err(XrpcError::bad(
                    "UnsupportedPolicy",
                    format!("managingApp must be a DID with an optional service fragment, got: {app}"),
                ));
            }
            Ok(Policy::ManagingApp { managing_app: app.into() })
        }
        _ => Err(XrpcError::bad("UnsupportedPolicy", format!("Unsupported policy: {t}"))),
    }
}

fn policy_to_lex(p: &Policy) -> J {
    match p {
        Policy::Public => json!({"$type": format!("{DEFS}#publicPolicy")}),
        Policy::MemberList => json!({"$type": format!("{DEFS}#memberListPolicy")}),
        Policy::ManagingApp { managing_app } => {
            json!({"$type": format!("{DEFS}#managingAppPolicy"), "managingApp": managing_app})
        }
    }
}

/// Reference `lexAppAccessToDb`.
fn app_access_from_lex(v: &J) -> XResult<AppAccess> {
    let t = lex_type(v);
    match t.strip_prefix(DEFS).unwrap_or("") {
        "#open" => Ok(AppAccess::Open),
        "#allowList" => {
            let allowed = v
                .get("allowed")
                .and_then(|a| a.as_array())
                .map(|a| a.iter().filter_map(|c| c.as_str().map(String::from)).collect::<Vec<_>>());
            let allowed = allowed.ok_or_else(|| XrpcError::bad("InvalidRequest", "allowList requires allowed"))?;
            Ok(AppAccess::AllowList { allowed })
        }
        _ => Err(XrpcError::bad("UnsupportedAppAccess", format!("Unsupported appAccess: {t}"))),
    }
}

fn app_access_to_lex(a: &AppAccess) -> J {
    match a {
        AppAccess::Open => json!({"$type": format!("{DEFS}#open")}),
        AppAccess::AllowList { allowed } => json!({"$type": format!("{DEFS}#allowList"), "allowed": allowed}),
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
async fn live_spaces(app: &App, did: &str, stop_at: usize) -> XResult<usize> {
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
/// space it alone can reconfigure; otherwise the policy for `access`
/// (`read` or `write`) decides. A managing app that can't be asked denies.
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
    let policy = if access == "read" { &row.read_policy } else { &row.write_policy };
    match policy {
        Policy::Public => Ok(true),
        Policy::MemberList => {
            let p = app.partition(&space.authority)?;
            let k = state::space_member_key(&space.authority, &space.sid, user);
            let m = p.db.get(k).await.map_err(XrpcError::from_err)?;
            let m = m.map(|v| MemberRow::decode(&v)).transpose().map_err(XrpcError::from_err)?;
            Ok(m.is_some_and(|m| if access == "read" { m.read } else { m.write }))
        }
        Policy::ManagingApp { managing_app } => Ok(crate::space::host::check_user_access(
            app,
            &space.uri,
            &space.authority,
            managing_app,
            user,
            access,
            client_id,
        )
        .await),
    }
}

/// Reference `assertSpaceOwner`: the scope for `access`, then the caller
/// must be the space's authority.
fn assert_owner(creds: &Credentials, space: &Space, access: SpaceAccess) -> XResult<String> {
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
        .filter(|d| vlsync_atproto::syntax::valid_did(d))
        .ok_or_else(|| XrpcError::bad("InvalidRequest", format!("{k} must be a DID")))
}

fn req_bool(v: &J, k: &str) -> XResult<bool> {
    v.get(k).and_then(|b| b.as_bool()).ok_or_else(|| XrpcError::bad("InvalidRequest", format!("{k} must be a boolean")))
}

/// Reference createSpace: anchored on the caller, `skey` a TID unless
/// given. Over a deleted space's tombstone it starts fresh.
async fn create_space(State(app): AppState, Auth(creds): Auth, Json(inp): Json<J>) -> XResult<Json<J>> {
    spaces(&app)?;
    let did = creds.user_did()?.to_string();
    let space_type = inp.get("spaceType").and_then(|t| t.as_str()).unwrap_or("");
    if !vlsync_atproto::syntax::valid_nsid(space_type) {
        return Err(XrpcError::bad("InvalidRequest", "spaceType must be an NSID"));
    }
    let skey = match inp.get("skey") {
        None | Some(J::Null) => app.tids.next().to_string(),
        Some(J::String(s)) if vlsync_atproto::syntax::valid_rkey(s) => s.clone(),
        Some(_) => return Err(XrpcError::bad("InvalidRequest", "skey must be a valid record key")),
    };
    let space = Space::parse(&format!("at://{did}/space/{space_type}/{skey}"))?;
    creds.need_space(&space.target(), SpaceAccess::Manage("create"))?;
    let read_policy = policy_from_lex(&inp["readPolicy"])?;
    let write_policy = policy_from_lex(&inp["writePolicy"])?;
    let app_access = app_access_from_lex(&inp["appAccess"])?;
    let row = SpaceRow {
        uri: space.uri.clone(),
        read_policy,
        write_policy,
        app_access,
        created_at: vlsync_atproto::events::now_rfc3339(),
        deleted_at: None,
    };
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

/// Reference getSpace: the authority itself, or a credential addressed to
/// the authority (a member hosted elsewhere can't present OAuth here).
async fn get_space(State(app): AppState, SpaceAuth(creds): SpaceAuth, Query(q): Query<SpaceQ>) -> XResult<Json<J>> {
    spaces(&app)?;
    let space = Space::parse(&q.space)?;
    match &creds {
        Credentials::SpaceCredential { audience, space: s, .. } => {
            assert_credential_space(audience, s, &space, &space.authority)?
        }
        c => {
            assert_owner(c, &space, SpaceAccess::ReadSelf)?;
        }
    }
    let row = space_row(&app, &space).await?;
    if !row.live() {
        return Err(space_not_found());
    }
    Ok(Json(json!({
        "uri": row.uri,
        "readPolicy": policy_to_lex(&row.read_policy),
        "writePolicy": policy_to_lex(&row.write_policy),
        "appAccess": app_access_to_lex(&row.app_access),
    })))
}

/// Reference updateSpace: each policy given replaces the space's wholesale
/// (so a policy that isn't managing-app drops the managing app).
async fn update_space(State(app): AppState, Auth(creds): Auth, Json(inp): Json<J>) -> XResult<StatusCode> {
    spaces(&app)?;
    let space = req_space(&inp)?;
    let did = assert_owner(&creds, &space, SpaceAccess::Manage("update"))?;
    let given = |k: &str| inp.get(k).filter(|v| !v.is_null());
    let read_policy = given("readPolicy").map(policy_from_lex).transpose()?;
    let write_policy = given("writePolicy").map(policy_from_lex).transpose()?;
    let app_access = given("appAccess").map(app_access_from_lex).transpose()?;
    submit_space(&app, &did, &space, SpaceOp::UpdateSpace { read_policy, write_policy, app_access }).await?;
    Ok(StatusCode::OK)
}

/// Reference deleteSpace: the space becomes a tombstone (getSpaceCredential
/// answers SpaceDeleted from then on), its member list, writer states and
/// registrations go, and so does the authority's own repo in it; other
/// members' repos are theirs and stay. Registered services are told, best
/// effort. Deleting a deleted space finishes its sweep and is a no-op.
async fn delete_space(State(app): AppState, Auth(creds): Auth, Json(inp): Json<J>) -> XResult<StatusCode> {
    spaces(&app)?;
    let space = req_space(&inp)?;
    let did = assert_owner(&creds, &space, SpaceAccess::Manage("delete"))?;
    assert_space_host(&app, &space).await?;
    let ack =
        submit_space(&app, &did, &space, SpaceOp::DeleteSpace { deleted_at: vlsync_atproto::events::now_rfc3339() })
            .await?;
    if let SpaceAck::Deleted { already: false } = ack {
        match crate::space::host::registrations(&app, &did, &space.sid).await {
            Ok((regs, _)) if !regs.is_empty() => {
                let (app, uri) = (app.clone(), space.uri.clone());
                tokio::spawn(async move { crate::space::host::notify_space_deleted(&app, &did, &uri, regs).await });
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(space = %hex::encode(space.sid), "space registrations unreadable, none told of the deletion: {e:#}")
            }
        }
    }
    delete_space_rows(&app, &space).await?;
    Ok(StatusCode::OK)
}

const SWEEP_BATCH: usize = 500;

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

/// Reference putMember: both flags replace the member's.
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

/// Reference removeMember. A removed member's writer state stays (it is
/// in listRepos at its last repoRev), as the reference keeps it.
async fn remove_member(State(app): AppState, Auth(creds): Auth, Json(inp): Json<J>) -> XResult<StatusCode> {
    spaces(&app)?;
    let space = req_space(&inp)?;
    let member = req_did(&inp, "did")?.to_string();
    let did = assert_owner(&creds, &space, SpaceAccess::Manage("update"))?;
    assert_space_host(&app, &space).await?;
    submit_space(&app, &did, &space, SpaceOp::RemoveMember { member }).await?;
    Ok(StatusCode::OK)
}

#[derive(Deserialize)]
struct ListMembersQ {
    space: String,
    limit: Option<i64>,
    cursor: Option<String>,
}

/// Reference listMembers: OAuth only (the member list is the authority's
/// own state; a credential doesn't reach it), by DID, the cursor the last
/// one listed.
async fn list_members(State(app): AppState, Auth(creds): Auth, Query(q): Query<ListMembersQ>) -> XResult<Json<J>> {
    spaces(&app)?;
    let space = Space::parse(&q.space)?;
    let limit = super::extract::limit_param(q.limit, 100, 1, 1000)?;
    assert_owner(&creds, &space, SpaceAccess::ReadSelf)?;
    live_space(&app, &space).await?;
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
