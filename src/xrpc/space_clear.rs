//! `com.atproto.space.clearRecords` (`--spaces`): every record of the
//! caller's repo in a space deleted, with its blob refs and the whole
//! oplog, and the repo at a new rev over what's left. The authority's own
//! repo keeps the records its space host publishes. One entry on the
//! account's worker, as a write is, so readers see the repo before or
//! after, and the authority hears it like any write.

use super::space::{space_error, spaces, submit_space, writer, Space};
use super::space_import::Claim;
use super::*;
use crate::oauth::scopes::SpaceAccess;
use crate::space::lthash::LtHash;
use crate::space::repo::{SpaceAck, SpaceOp};
use crate::space::rows::HeadRow;
use std::collections::BTreeSet;
use vlsync_store::segment::Mutation;

pub fn routes() -> Router<Arc<App>> {
    Router::new().route("/xrpc/com.atproto.space.clearRecords", post(clear_records))
}

#[derive(Deserialize)]
struct ClearIn {
    space: String,
    repo: String,
}

async fn clear_records(State(app): AppState, Auth(creds): Auth, Json(inp): Json<ClearIn>) -> XResult<Json<J>> {
    let r = clear(&app, &creds, inp).await;
    crate::metrics::space_write(
        "clearRecords",
        match &r {
            Ok(_) => "ok",
            Err(e) if e.status.is_server_error() => "error",
            Err(_) => "refused",
        },
    );
    r.map(|_| Json(json!({})))
}

const SCAN_BATCH: usize = 1024;

fn del(key: Bytes) -> Mutation {
    Mutation { key, val: None }
}

async fn clear(app: &App, creds: &Credentials, inp: ClearIn) -> XResult<()> {
    let sp = spaces(app)?;
    let space = Space::parse(&inp.space)?;
    crate::ratelimit::check_repo_write(creds.did(), crate::ratelimit::DELETE_POINTS)?;
    let did = writer(creds, &inp.repo)?;
    let keep = |collection: &str| space.authority == did && crate::space::publish::is_published(collection);
    let nonce = rand::random::<u64>();
    let _claim = Claim { sp, did: &did, sid: space.sid, nonce };
    match super::space::submit_space_once(app, &did, &space, SpaceOp::Claim { nonce }).await? {
        Ok(_) => {}
        Err(e) => return Err(space_error(e)),
    }
    // under the claim, with every earlier write applied: this is the repo
    let p = app.partition(&did)?;
    let snap = p.db.snapshot().map_err(XrpcError::from_err)?;
    let Some(v) = snap.get(state::space_head_key(&did, &space.sid)).await.map_err(XrpcError::from_err)? else {
        return Ok(());
    };
    let head = HeadRow::decode(&v).map_err(XrpcError::from_err)?;
    if head.uri != space.uri {
        return Err(XrpcError::internal(format!("space id collision: {} and {}", head.uri, space.uri)));
    }
    let opts = slatedb::config::ScanOptions::default();
    let scan = |fam: &'static [u8]| {
        let prefix = state::space_prefix(fam, &did, &space.sid);
        let end = vlsync_store::keys::prefix_end(&prefix);
        let snap = &snap;
        let opts = &opts;
        async move { snap.scan_with_options(prefix.clone()..end, opts).await.map(|it| (prefix, it)) }
    };

    let (mut kept, mut records) = (LtHash::default(), 0u64);
    let mut collections = BTreeSet::new();
    let mut deletes = Vec::new();
    let (prefix, mut it) = scan(state::SPACE_RECORD_FAMILY).await.map_err(XrpcError::from_err)?;
    loop {
        let rows = it.next_batch(SCAN_BATCH).await.map_err(XrpcError::from_err)?;
        if rows.is_empty() {
            break;
        }
        for kv in rows {
            let path = std::str::from_utf8(&kv.key[prefix.len()..]).map_err(XrpcError::from_err)?;
            let (collection, rkey) = path.split_once('/').ok_or_else(|| XrpcError::internal("bad space record key"))?;
            if keep(collection) {
                let (cid, _) = state::record_value_parts(&kv.value).map_err(XrpcError::from_err)?;
                kept.add(&crate::space::commit::element(collection, rkey, &cid.to_string()));
                records += 1;
                continue;
            }
            if !collections.contains(collection) {
                collections.insert(collection.to_string());
            }
            deletes.push(del(kv.key));
        }
    }
    if deletes.is_empty() {
        return Ok(());
    }
    for c in &collections {
        creds.need_space(&space.target(), SpaceAccess::Write("delete", c))?;
    }
    let (prefix, mut it) = scan(state::SPACE_BLOB_FAMILY).await.map_err(XrpcError::from_err)?;
    loop {
        let rows = it.next_batch(SCAN_BATCH).await.map_err(XrpcError::from_err)?;
        if rows.is_empty() {
            break;
        }
        for kv in rows {
            let (cid, path) = crate::space::rows::blob_ref_parts(&kv.key[prefix.len()..])
                .ok_or_else(|| XrpcError::internal("bad space blob ref key"))?;
            if keep(path.split_once('/').map_or(path, |(c, _)| c)) {
                continue;
            }
            let cid = Cid::parse(cid).map_err(XrpcError::from_err)?;
            deletes.push(del(state::space_blob_cid_key(&did, &cid, &space.sid, path).into()));
            deletes.push(del(kv.key));
        }
    }
    let (_, mut it) = scan(state::SPACE_OPLOG_FAMILY).await.map_err(XrpcError::from_err)?;
    loop {
        let rows = it.next_batch(SCAN_BATCH).await.map_err(XrpcError::from_err)?;
        if rows.is_empty() {
            break;
        }
        deletes.extend(rows.into_iter().map(|kv| del(kv.key)));
    }
    drop(snap);
    let op = SpaceOp::Clear { nonce, prev: head.rev, deletes, hash: Box::new(kept), records };
    match submit_space(app, &did, &space, op).await? {
        SpaceAck::Write { .. } => Ok(()),
        _ => Err(XrpcError::internal("unexpected space ack")),
    }
}
