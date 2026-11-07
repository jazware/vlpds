//! `com.atproto.space.exportSpaceMeta` and `importSpaceMeta` (`--spaces`):
//! a space's host state, carried when its authority's account moves, as
//! the `atproto-space-meta` STAR archive (`crate::space::meta`). The
//! policy, its state (memberspace's member list, keyed as the members'
//! published records would be) and the writer set with their spaceRevs,
//! so listRepos cursors keep working after the move.
//!
//! An import replaces what this host holds for the space: the member list,
//! writer states and sequence are swept and written again, then one entry
//! on the authority's worker puts the space's row in and has the worker
//! read its host state again. Registrations, revocations and a deleted
//! space's tombstone don't come with it, and nothing is published: the
//! published records arrive with the authority's own repo (importRepo).

use super::space::{spaces, submit_space, Space};
use super::*;
use crate::oauth::scopes::SpaceAccess;
use crate::space::meta::{self, Archive, Writer};
use crate::space::repo::SpaceOp;
use crate::space::rows::{MemberRow, Policy, PolicyError, SeqRow, SpaceRow, WriterRow};
use vlatproto::cbor::Value;
use vlatproto::tid::Tid;

pub fn routes() -> Router<Arc<App>> {
    Router::new()
        .route("/xrpc/com.atproto.space.exportSpaceMeta", get(export_space_meta))
        .route("/xrpc/com.atproto.space.importSpaceMeta", post(import_space_meta))
}

const MEMBER_PREFIX: &str = "com.atproto.memberspace.member/";
const BATCH: usize = 500;

fn owner(creds: &Credentials, space: &Space, access: SpaceAccess) -> XResult<String> {
    creds.need_space(&space.target(), access)?;
    let did = creds.user_did()?;
    if did != space.authority {
        return Err(XrpcError::bad("NotSpaceOwner", "Not the space owner"));
    }
    Ok(did.to_string())
}

#[derive(Deserialize)]
struct SpaceQ {
    space: String,
}

async fn scan(p: &crate::partition::Partition, prefix: &[u8]) -> XResult<Vec<(Vec<u8>, bytes::Bytes)>> {
    let opts = slatedb::config::ScanOptions::default();
    let mut it = vlsync_store::keys::BatchedScan::new(
        p.db.scan_with_options(prefix.to_vec()..vlsync_store::keys::prefix_end(prefix), &opts)
            .await
            .map_err(XrpcError::from_err)?,
    );
    let mut out = Vec::new();
    while let Some(kv) = it.next().await.map_err(XrpcError::from_err)? {
        out.push((kv.key[prefix.len()..].to_vec(), kv.value));
    }
    Ok(out)
}

/// Reference exportSpaceMeta: OAuth as the space's owner with `read_self`.
async fn export_space_meta(State(app): AppState, Auth(creds): Auth, Query(q): Query<SpaceQ>) -> XResult<Response> {
    spaces(&app)?;
    let space = Space::parse(&q.space)?;
    owner(&creds, &space, SpaceAccess::ReadSelf)?;
    let row = super::space_policy::live_space(&app, &space).await?;
    let p = app.partition(&space.authority)?;
    let mut policy_state = Vec::new();
    if row.policy.is_memberspace() {
        let prefix = state::space_prefix(state::SPACE_MEMBER_FAMILY, &space.authority, &space.sid);
        for (k, v) in scan(&p, &prefix).await? {
            let did = std::str::from_utf8(&k).map_err(XrpcError::from_err)?;
            let m = MemberRow::decode(&v).map_err(XrpcError::from_err)?;
            let value = Value::Map(vec![
                ("read".into(), Value::Bool(m.read)),
                ("$type".into(), Value::Text("com.atproto.memberspace.member".into())),
                ("write".into(), Value::Bool(m.write)),
            ]);
            policy_state.push((format!("{MEMBER_PREFIX}{}", crate::space::publish::did_rkey(did)), value));
        }
    }
    let mut writers = Vec::new();
    let prefix = state::space_prefix(state::SPACE_WRITER_FAMILY, &space.authority, &space.sid);
    for (k, v) in scan(&p, &prefix).await? {
        let did = std::str::from_utf8(&k).map_err(XrpcError::from_err)?.to_string();
        let w = WriterRow::decode(&v).map_err(XrpcError::from_err)?;
        writers.push(Writer { did, rev: w.repo_rev, data: w.hash, space_rev: w.space_rev });
    }
    let policy = Value::from_json(&row.policy.to_lex()).map_err(XrpcError::from_err)?;
    let body = meta::write(&Archive { space: space.uri.clone(), policy, policy_state, writers });
    Ok(([(header::CONTENT_TYPE, "application/octet-stream")], body).into_response())
}

/// The member list in an archive's policy state. A key the policy doesn't
/// define is refused, not dropped: dropping it would change who may read.
fn members_of(policy: &Policy, state: &[(String, Value)]) -> XResult<Vec<(String, MemberRow)>> {
    let mut out = Vec::with_capacity(state.len());
    for (k, v) in state {
        let did = k.strip_prefix(MEMBER_PREFIX).map(rkey_did);
        let Some(did) = did.filter(|d| policy.is_memberspace() && vlatproto::syntax::valid_did(d)) else {
            return Err(XrpcError::bad("InvalidRequest", format!("Unrecognized policy state: {k}")));
        };
        let Value::Map(m) = v else { unreachable!("meta::read checks values are maps") };
        let flag = |name: &str| match m.iter().find(|(key, _)| key == name).map(|(_, v)| v) {
            Some(Value::Bool(b)) => Ok(*b),
            _ => Err(XrpcError::bad("InvalidRequest", format!("Invalid member at {k}: {name} must be a boolean"))),
        };
        out.push((did, MemberRow { read: flag("read")?, write: flag("write")? }));
    }
    Ok(out)
}

/// Reference `recordKeyToDid`: a localhost did:web's port goes back to its
/// percent-encoded form.
fn rkey_did(rkey: &str) -> String {
    match rkey.strip_prefix("did:web:").and_then(|rest| rest.split_once(':')) {
        Some((host, port)) if !host.is_empty() && !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => {
            format!("did:web:{host}%3A{port}")
        }
        _ => rkey.to_string(),
    }
}

/// Reference importSpaceMeta: the space anchored on the caller (OAuth with
/// `manage=create` and `manage=update`), its policy one this host
/// implements.
async fn import_space_meta(
    State(app): AppState,
    Auth(creds): Auth,
    headers: HeaderMap,
    body: Body,
) -> XResult<StatusCode> {
    spaces(&app)?;
    creds.need_any_space_write()?;
    let did = creds.user_did()?.to_string();
    if let Some(st) = app.account(&did).await?.status {
        return Err(inactive_account_error(&st));
    }
    crate::ratelimit::check(&[&crate::ratelimit::SPACE_IMPORT], &did, 1)?;
    let max = app.config.max_import_bytes;
    let declared =
        headers.get(header::CONTENT_LENGTH).and_then(|v| v.to_str().ok()).and_then(|v| v.parse::<u64>().ok());
    if declared.is_some_and(|n| n > max as u64) {
        return Err(super::import_stream::too_large(max));
    }
    let mut body =
        super::import_stream::TimedBody::new(body, app.config.import_body_idle, app.config.import_body_deadline);
    let mut buf = Vec::new();
    while let Some(chunk) = body.next().await {
        let chunk = chunk?;
        if buf.len() + chunk.len() > max {
            return Err(super::import_stream::too_large(max));
        }
        buf.extend_from_slice(&chunk);
    }
    let a = meta::read(&buf).map_err(|e| XrpcError::bad("InvalidRequest", e.0))?;
    drop(buf);
    let space = Space::parse(&a.space)?;
    if space.authority != did {
        return Err(XrpcError::bad("NotSpaceOwner", "Not the space owner"));
    }
    owner(&creds, &space, SpaceAccess::Manage("create"))?;
    owner(&creds, &space, SpaceAccess::Manage("update"))?;
    let policy = Policy::from_lex(&a.policy.to_json()).map_err(|e| match e {
        PolicyError::Unsupported(m) => XrpcError::bad("UnsupportedPolicy", m),
        PolicyError::Invalid(m) => XrpcError::bad("InvalidRequest", m),
    })?;
    let members = members_of(&policy, &a.policy_state)?;
    let mut writers = a.writers;
    writers.sort_by_key(|w| w.space_rev);
    if writers.windows(2).any(|w| w[0].space_rev == w[1].space_rev) {
        return Err(XrpcError::bad("InvalidRequest", "two writers at one spaceRev"));
    }
    super::space_policy::sweep_space_rows(
        &app,
        &space,
        &[state::SPACE_MEMBER_FAMILY, state::SPACE_WRITER_FAMILY, state::SPACE_SEQ_FAMILY],
    )
    .await?;
    let p = app.partition(&did)?;
    let put = |key: Vec<u8>, val: bytes::Bytes| vlsync_store::segment::Mutation { key: key.into(), val: Some(val) };
    let mut muts = Vec::new();
    for (m, row) in &members {
        muts.push(put(state::space_member_key(&did, &space.sid, m), row.encode()));
        if muts.len() >= BATCH {
            write_private_local(&p, std::mem::take(&mut muts)).await?;
        }
    }
    let mut prev: Option<Tid> = None;
    for w in &writers {
        let row = WriterRow { repo_rev: w.rev, hash: w.data, space_rev: w.space_rev };
        muts.push(put(state::space_writer_key(&did, &space.sid, &w.did), row.encode()));
        let seq = SeqRow { prev, writer: w.did.clone() };
        muts.push(put(state::space_seq_key(&did, &space.sid, w.space_rev.0), seq.encode()));
        prev = Some(w.space_rev);
        if muts.len() >= BATCH {
            write_private_local(&p, std::mem::take(&mut muts)).await?;
        }
    }
    if !muts.is_empty() {
        write_private_local(&p, muts).await?;
    }
    let row =
        SpaceRow { uri: space.uri.clone(), policy, created_at: vlatproto::events::now_rfc3339(), deleted_at: None };
    submit_space(&app, &did, &space, SpaceOp::ImportSpaceMeta { row, max_space_rev: prev }).await?;
    Ok(StatusCode::OK)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn did_web_ports_round_trip() {
        for did in ["did:web:localhost%3A2583", "did:web:example.com", "did:plc:abc"] {
            assert_eq!(rkey_did(&crate::space::publish::did_rkey(did)), did);
        }
    }

    #[test]
    fn policy_state_must_be_the_policys() {
        let member = Value::Map(vec![("read".into(), Value::Bool(true)), ("write".into(), Value::Bool(false))]);
        let key = format!("{MEMBER_PREFIX}did:plc:a");
        let got = members_of(&Policy::member_defaults(), &[(key.clone(), member.clone())]).ok().unwrap();
        assert_eq!(got, [("did:plc:a".to_string(), MemberRow { read: true, write: false })]);
        assert!(members_of(&Policy::Personal, &[(key, member.clone())]).is_err());
        assert!(members_of(&Policy::member_defaults(), &[("x.y.z/k".into(), member)]).is_err());
    }
}
