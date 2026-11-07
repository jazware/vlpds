//! The space host methods of space policies (reference `space-policy/`
//! and the `com.atproto.space` lifecycle, `com.atproto.memberspace`
//! handlers; `--spaces`), for spaces anchored on an account hosted here.
//! Space state (`sS`, `sM`, `sW`/`sQ`, `sN`) lives in the authority's
//! shard and changes through its repo worker, so config, member, spaceRev
//! and published-record changes serialize there with no lock.

use super::space::{spaces, submit_space, Space};
use super::*;
use crate::oauth::scopes::SpaceAccess;
use crate::space::repo::{SpaceAck, SpaceOp};
use crate::space::rows::{MemberRow, Policy, PolicyError, SpaceRow};

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

fn req_policy(v: &J) -> XResult<Policy> {
    let p = v.get("policy").ok_or_else(|| XrpcError::bad("InvalidRequest", "policy is required"))?;
    Policy::from_lex(p).map_err(|e| match e {
        PolicyError::Unsupported(m) => XrpcError::bad("UnsupportedPolicy", m),
        PolicyError::Invalid(m) => XrpcError::bad("InvalidRequest", m),
    })
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
/// space it alone can reconfigure; otherwise the policy decides for
/// `access` (`read` or `write`). A managing app is asked about both, and
/// one that can't be asked denies.
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
        Policy::Personal => Ok(false),
        Policy::Member { public_read, public_write, .. } => {
            if *(if access == "read" { public_read } else { public_write }) {
                return Ok(true);
            }
            let p = app.partition(&space.authority)?;
            let k = state::space_member_key(&space.authority, &space.sid, user);
            let m = p.db.get(k).await.map_err(XrpcError::from_err)?;
            let m = m.map(|v| MemberRow::decode(&v)).transpose().map_err(XrpcError::from_err)?;
            Ok(m.is_some_and(|m| if access == "read" { m.read } else { m.write }))
        }
        Policy::Managed { managing_app, .. } => Ok(crate::space::host::check_user_access(
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
        .filter(|d| vlatproto::syntax::valid_did(d))
        .ok_or_else(|| XrpcError::bad("InvalidRequest", format!("{k} must be a DID")))
}

fn req_bool(v: &J, k: &str) -> XResult<bool> {
    v.get(k).and_then(|b| b.as_bool()).ok_or_else(|| XrpcError::bad("InvalidRequest", format!("{k} must be a boolean")))
}

/// Reference createSpace: anchored on the caller, governed by the policy
/// given (normalized; one this host doesn't implement is
/// UnsupportedPolicy), which publishes itself if it asks to. `skey` a TID unless
/// given. Over a deleted space's tombstone it starts fresh.
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
    let policy = req_policy(&inp)?;
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

/// Reference getSpace: OAuth as the owner with `read_self`. The policy is
/// the authority's own state, so a credential doesn't reach it; a policy
/// can publish itself to readers instead.
async fn get_space(State(app): AppState, Auth(creds): Auth, Query(q): Query<SpaceQ>) -> XResult<Json<J>> {
    spaces(&app)?;
    let space = Space::parse(&q.space)?;
    super::authn::check_space_read_account(&creds)?;
    assert_owner(&creds, &space, SpaceAccess::ReadSelf)?;
    let row = live_space(&app, &space).await?;
    Ok(Json(json!({"uri": row.uri, "policy": row.policy.to_lex()})))
}

/// Reference updateSpace: the policy replaced wholesale (omitted fields
/// take their defaults). Another `$type` migrates the space and drops the
/// old policy's state; the writer set is left as it is.
async fn update_space(State(app): AppState, Auth(creds): Auth, Json(inp): Json<J>) -> XResult<StatusCode> {
    spaces(&app)?;
    let space = req_space(&inp)?;
    let did = assert_owner(&creds, &space, SpaceAccess::Manage("update"))?;
    let policy = req_policy(&inp)?;
    assert_space_host(&app, &space).await?;
    submit_space(&app, &did, &space, SpaceOp::UpdateSpace { policy }).await?;
    Ok(StatusCode::OK)
}

/// Reference removeWriter: out of listRepos until it writes again while
/// authorized. Idempotent; not announced to syncers, and its records stay
/// where they are.
async fn remove_writer(State(app): AppState, Auth(creds): Auth, Json(inp): Json<J>) -> XResult<StatusCode> {
    spaces(&app)?;
    let space = req_space(&inp)?;
    let writer = req_did(&inp, "did")?.to_string();
    let did = assert_owner(&creds, &space, SpaceAccess::Manage("update"))?;
    assert_space_host(&app, &space).await?;
    submit_space(&app, &did, &space, SpaceOp::RemoveWriter { writer }).await?;
    Ok(StatusCode::OK)
}

/// Reference deleteSpace: the space becomes a tombstone (getSpaceCredential
/// answers SpaceDeleted from then on), its member list, writer states and
/// registrations go, and so does the authority's own repo in it; other
/// members' repos are theirs and stay. Registered services are told, and
/// a send that fails is retried ([`crate::space::deleted`]). Deleting a deleted space finishes its sweep and is a no-op.
async fn delete_space(State(app): AppState, Auth(creds): Auth, Json(inp): Json<J>) -> XResult<StatusCode> {
    spaces(&app)?;
    let space = req_space(&inp)?;
    let did = assert_owner(&creds, &space, SpaceAccess::Manage("delete"))?;
    assert_space_host(&app, &space).await?;
    let ack =
        submit_space(&app, &did, &space, SpaceOp::DeleteSpace { deleted_at: vlatproto::events::now_rfc3339() }).await?;
    if let SpaceAck::Deleted { already: false } = ack {
        match crate::space::host::registrations(&app, &did, &space.sid).await {
            Ok((regs, _)) if !regs.is_empty() => {
                let (app, uri) = (app.clone(), space.uri.clone());
                let sid = space.sid;
                tokio::spawn(async move { crate::space::deleted::notify(&app, &did, &uri, sid, regs).await });
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
    sweep_space_rows(
        app,
        space,
        &[
            state::SPACE_MEMBER_FAMILY,
            state::SPACE_WRITER_FAMILY,
            state::SPACE_SEQ_FAMILY,
            state::SPACE_NOTIFY_FAMILY,
            state::SPACE_BLOB_FAMILY,
            state::SPACE_RECORD_FAMILY,
            state::SPACE_OPLOG_FAMILY,
            state::SPACE_HEAD_FAMILY,
        ],
    )
    .await
}

/// The space's rows of `fams` at its authority, in bounded entries.
pub(super) async fn sweep_space_rows(app: &App, space: &Space, fams: &[&[u8]]) -> XResult<()> {
    let p = app.partition(&space.authority)?;
    for &fam in fams {
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

/// Reference putMember: both flags replace the member's; without write the
/// member leaves the writer set. PolicyMismatch outside a memberspace.
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

/// Reference removeMember, which also drops the member from the writer
/// set. PolicyMismatch outside a memberspace.
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
    super::authn::check_space_read_account(&creds)?;
    assert_owner(&creds, &space, SpaceAccess::ReadSelf)?;
    if !live_space(&app, &space).await?.policy.is_memberspace() {
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
