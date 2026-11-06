//! A space authority's account migrating (`--spaces`; reference
//! `space-policy/manager.ts` exportSpaceMeta/importSpaceMeta): the old host
//! serves each space the account governs as a space meta archive
//! ([`crate::space::meta_archive`]), and the new host takes it before the
//! account's own repo in that space (importRepo, `super::space_import`).
//!
//! The import replaces what this host holds for the space: its policy,
//! member list and writer set (each writer at its spaceRev, so syncers'
//! listRepos cursors stay valid). Notification registrations, credential
//! revocations and a deleted space's tombstone don't move; a tombstone
//! here is swept as createSpace sweeps it. Nothing is published: the policy
//! and member records arrive in the authority's repo.

use super::space::{spaces, submit_space, Space};
use super::*;
use crate::oauth::scopes::SpaceAccess;
use crate::space::meta_archive::{self, MetaWriter, SpaceMeta};
use crate::space::policy::{did_to_rkey, member_record, rkey_to_did, MEMBER_COLLECTION};
use crate::space::repo::SpaceOp;
use crate::space::rows::{MemberRow, SpaceRow, WriterRow};

pub fn routes() -> Router<Arc<App>> {
    Router::new()
        .route("/xrpc/com.atproto.space.exportSpaceMeta", get(export_space_meta))
        .route("/xrpc/com.atproto.space.importSpaceMeta", post(import_space_meta))
}

fn invalid(m: impl Into<String>) -> XrpcError {
    XrpcError::bad("InvalidRequest", m)
}

/// An import's caller (reference `ACCESS_FULL`): a password session, or
/// OAuth (held to its space grants by the caller). An app password, scoped
/// or not, can't move an account's data in.
pub(super) fn import_credentials(creds: &Credentials) -> XResult<()> {
    match creds {
        Credentials::Session { .. } | Credentials::OAuth { .. } => Ok(()),
        _ => Err(XrpcError {
            status: StatusCode::FORBIDDEN,
            error: "InsufficientScope".into(),
            message: "an import takes a full-access session or OAuth, not an app password".into(),
        }),
    }
}

/// A space grant, which only OAuth is held to here (a session is full
/// access).
pub(super) fn need_import_grant(creds: &Credentials, space: &Space, access: SpaceAccess) -> XResult<()> {
    match creds {
        Credentials::Session { .. } => Ok(()),
        c => c.need_space(&space.target(), access),
    }
}

/// The body, whole, within the import size.
pub(super) async fn read_body(app: &App, headers: &HeaderMap, body: Body) -> XResult<Vec<u8>> {
    let max = app.config.max_import_bytes;
    let declared =
        headers.get(header::CONTENT_LENGTH).and_then(|v| v.to_str().ok()).and_then(|v| v.parse::<u64>().ok());
    if declared.is_some_and(|n| n > max as u64) {
        return Err(super::import_stream::too_large(max));
    }
    let mut body =
        super::import_stream::TimedBody::new(body, app.config.import_body_idle, app.config.import_body_deadline);
    let mut out = Vec::new();
    while let Some(chunk) = body.next().await {
        let chunk = chunk?;
        if out.len() + chunk.len() > max {
            return Err(super::import_stream::too_large(max));
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

/// Scans `prefix`, handing each row's key past it and its value.
async fn scan_rows(
    app: &App,
    authority: &str,
    prefix: Vec<u8>,
    mut f: impl FnMut(&str, &[u8]) -> XResult<()>,
) -> XResult<()> {
    let p = app.partition(authority)?;
    let mut it =
        p.db.scan(prefix.clone()..vlsync_store::keys::prefix_end(&prefix)).await.map_err(XrpcError::from_err)?;
    while let Some(kv) = it.next().await.map_err(XrpcError::from_err)? {
        let rest = std::str::from_utf8(&kv.key[prefix.len()..]).map_err(XrpcError::from_err)?;
        f(rest, &kv.value)?;
    }
    Ok(())
}

async fn members(app: &App, space: &Space) -> XResult<Vec<(String, MemberRow)>> {
    let mut out = Vec::new();
    let prefix = state::space_prefix(state::SPACE_MEMBER_FAMILY, &space.authority, &space.sid);
    scan_rows(app, &space.authority, prefix, |did, v| {
        out.push((did.to_string(), MemberRow::decode(v).map_err(XrpcError::from_err)?));
        Ok(())
    })
    .await?;
    Ok(out)
}

async fn writers(app: &App, space: &Space) -> XResult<Vec<(String, WriterRow)>> {
    let mut out = Vec::new();
    let prefix = state::space_prefix(state::SPACE_WRITER_FAMILY, &space.authority, &space.sid);
    scan_rows(app, &space.authority, prefix, |did, v| {
        out.push((did.to_string(), WriterRow::decode(v).map_err(XrpcError::from_err)?));
        Ok(())
    })
    .await?;
    Ok(out)
}

#[derive(Deserialize)]
struct SpaceQ {
    space: String,
}

/// Reference exportSpaceMeta: the owner, with `read_self`, as getSpace.
/// The member list goes only under a member space.
async fn export_space_meta(State(app): AppState, Auth(creds): Auth, Query(q): Query<SpaceQ>) -> XResult<Response> {
    spaces(&app)?;
    let space = Space::parse(&q.space)?;
    super::space_policy::assert_owner(&creds, &space, SpaceAccess::ReadSelf)?;
    let row = super::space_policy::live_space(&app, &space).await?;
    let policy_state = match row.policy.is_member() {
        true => members(&app, &space)
            .await?
            .into_iter()
            .map(|(did, m)| {
                let key = format!("{MEMBER_COLLECTION}/{}", did_to_rkey(&did));
                (key, meta_archive::from_json(&member_record(m)))
            })
            .collect(),
        false => Vec::new(),
    };
    let writers = writers(&app, &space)
        .await?
        .into_iter()
        .map(|(did, w)| MetaWriter { did, rev: w.repo_rev, data: w.hash.to_vec(), space_rev: w.space_rev })
        .collect();
    let archive = SpaceMeta {
        space: space.uri.clone(),
        policy: meta_archive::from_json(&row.policy.to_json()),
        policy_state,
        writers,
    };
    Ok(([(header::CONTENT_TYPE, "application/octet-stream")], meta_archive::serialize(&archive)).into_response())
}

/// Reference `parsePolicyState`: under a member space, member entries
/// keyed by DID; anything else is refused rather than dropped, since
/// dropping it would quietly change who has access.
fn parse_members(is_member: bool, state: &[(String, vlatproto::cbor::Value)]) -> XResult<Vec<(String, MemberRow)>> {
    let prefix = format!("{MEMBER_COLLECTION}/");
    state
        .iter()
        .map(|(key, v)| {
            let did = key.strip_prefix(&prefix).map(rkey_to_did).filter(|d| vlatproto::syntax::valid_did(d));
            let (true, Some(did)) = (is_member, did) else {
                return Err(invalid(format!("Unrecognized policy state: {key}")));
            };
            let typed = match v.get("$type") {
                None => true,
                Some(t) => t.as_str() == Some(MEMBER_COLLECTION),
            };
            match (typed, meta_archive::bool_field(v, "read"), meta_archive::bool_field(v, "write")) {
                (true, Some(read), Some(write)) => Ok((did, MemberRow { read, write })),
                _ => Err(invalid(format!("Invalid member at {key}"))),
            }
        })
        .collect()
}

/// Reference importSpaceMeta: a space anchored on the caller
/// (NotSpaceOwner), with `manage=create` and `manage=update` under OAuth;
/// an unimplemented policy is UnsupportedPolicy. Replaces whatever this
/// host held for the space; retried, it lands the same.
async fn import_space_meta(
    State(app): AppState,
    Auth(creds): Auth,
    headers: HeaderMap,
    body: Body,
) -> XResult<StatusCode> {
    spaces(&app)?;
    let did = creds.user_did()?.to_string();
    import_credentials(&creds)?;
    let bytes = read_body(&app, &headers, body).await?;
    let a = meta_archive::parse(&bytes).map_err(|e| invalid(format!("invalid space meta archive: {e}")))?;
    let space = Space::parse(&a.space)?;
    need_import_grant(&creds, &space, SpaceAccess::Manage("create"))?;
    need_import_grant(&creds, &space, SpaceAccess::Manage("update"))?;
    if space.authority != did {
        return Err(XrpcError::bad("NotSpaceOwner", "Not the space owner"));
    }
    if let Some(st) = app.account(&did).await?.status {
        return Err(inactive_account_error(&st));
    }
    let policy = super::space_policy::policy_from_lex(&meta_archive::to_json(&a.policy))?;
    let members = parse_members(policy.is_member(), &a.policy_state)?;
    let mut imported = Vec::with_capacity(a.writers.len());
    for w in a.writers {
        let hash: [u8; 32] =
            w.data.as_slice().try_into().map_err(|_| invalid(format!("writer {}: data must be 32 bytes", w.did)))?;
        imported.push((w.did, WriterRow { repo_rev: w.rev, hash, space_rev: w.space_rev }));
    }
    let existing = super::space_policy::space_row_opt(&app, &space).await?;
    let created_at = match &existing {
        Some(r) if r.live() => r.created_at.clone(),
        _ => {
            let (cap, _) = spaces(&app)?.account_caps();
            if super::space_policy::live_spaces(&app, &did, cap).await? >= cap {
                return Err(invalid(format!("this account governs {cap} spaces; delete one first")));
            }
            vlatproto::events::now_rfc3339()
        }
    };
    if existing.is_some_and(|r| !r.live()) {
        // nothing of the deleted space may carry over
        super::space_policy::delete_space_rows(&app, &space).await?;
    }
    let drop_members = members_of(&app, &space).await?;
    let drop_writers = writers(&app, &space).await?.into_iter().map(|(d, w)| (d, w.space_rev)).collect();
    let row = SpaceRow { uri: space.uri.clone(), policy, created_at, deleted_at: None };
    let op = SpaceOp::ImportSpaceMeta { row, members, writers: imported, drop_members, drop_writers };
    submit_space(&app, &did, &space, op).await?;
    Ok(StatusCode::OK)
}

async fn members_of(app: &App, space: &Space) -> XResult<Vec<String>> {
    Ok(members(app, space).await?.into_iter().map(|(d, _)| d).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn policy_state_is_members_only() {
        let m = |v: serde_json::Value| meta_archive::from_json(&v);
        let ok = vec![
            (
                "com.atproto.memberspace.member/did:plc:a".to_string(),
                m(json!({"$type": MEMBER_COLLECTION, "read": true, "write": false})),
            ),
            (
                "com.atproto.memberspace.member/did:web:localhost:2583".to_string(),
                m(json!({"read": true, "write": true})),
            ),
        ];
        let got = parse_members(true, &ok).ok().unwrap();
        assert_eq!(got[0], ("did:plc:a".into(), MemberRow { read: true, write: false }));
        assert_eq!(got[1].0, "did:web:localhost%3A2583");
        assert!(parse_members(false, &ok).is_err(), "no state under another policy");
        for bad in [
            ("com.example.thing/did:plc:a", json!({"read": true, "write": true})),
            ("com.atproto.memberspace.member/nope", json!({"read": true, "write": true})),
            ("com.atproto.memberspace.member/did:plc:a", json!({"read": true})),
            ("com.atproto.memberspace.member/did:plc:a", json!({"$type": "x.y.z", "read": true, "write": true})),
        ] {
            assert!(parse_members(true, &[(bad.0.to_string(), m(bad.1.clone()))]).is_err(), "{bad:?}");
        }
    }
}
