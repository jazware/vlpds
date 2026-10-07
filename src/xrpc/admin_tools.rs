//! Operator tools behind `vlpds admin`: the reference PDS's `pdsadmin` and
//! scripts that have no com.atproto.admin.* method (DESIGN.md "Admin CLI").

use super::admin::require_admin;
use super::*;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

pub fn routes() -> Router<Arc<App>> {
    Router::new()
        .route("/xrpc/vlpds.admin.publishIdentity", post(publish_identity))
        .route("/xrpc/vlpds.admin.checkRepo", get(check_repo))
        .route("/xrpc/vlpds.admin.rebuildRepo", post(rebuild_repo))
        .route("/xrpc/vlpds.admin.recountRepo", post(recount_repo))
}

fn invalid(message: impl Into<String>) -> XrpcError {
    XrpcError::bad("InvalidRequest", message)
}

fn not_found(did: &str) -> XrpcError {
    XrpcError::bad("RepoNotFound", format!("could not find repo: {did}"))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PublishIdentityIn {
    did: String,
    /// First make the DID's PLC `atproto` key the signing key held here (the
    /// reference's rotate-keys).
    #[serde(default)]
    sync_plc: bool,
}

/// The reference's `sequenceIdentity`. With `syncPlc`, the repo is also
/// re-signed (an empty commit, `#identity` + `#sync`) so relays that saw
/// commits fail against the old document resynchronize; a PLC failure emits
/// nothing.
async fn publish_identity(
    State(app): AppState,
    Auth(creds): Auth,
    Json(inp): Json<PublishIdentityIn>,
) -> XResult<Json<J>> {
    require_admin(&creds)?;
    let did = inp.did;
    let acct = app.account(&did).await.map_err(|_| not_found(&did))?;
    if !inp.sync_plc {
        // rewrites the unchanged row, ordered with the commits, for #identity
        let (_, after) = app.mutate_account(&did, true, false, false, |_| Ok(true)).await?;
        app.did_resolver.invalidate(&did);
        return Ok(Json(json!({"did": did, "handle": after.handle, "plcUpdated": J::Null})));
    }
    if acct.pending_signing_key.is_some() {
        return Err(invalid("a signing key rotation is in progress for this account"));
    }
    let mut plc_updated = J::Null;
    if did.starts_with("did:plc:") {
        let plc = app.plc.as_ref().ok_or_else(|| invalid("PLC registration is off on this PDS"))?;
        plc_updated = json!(plc.update_signing_key(&did, &format!("did:key:{}", acct.signing_pubkey)).await?);
    }
    let key = app.secrets.account_signing_key(&acct).await?;
    let head =
        app.account_op(&did, crate::worker::AccountOp::SigningKey(crate::worker::KeyStep::Resign { key })).await?;
    app.did_resolver.invalidate(&did);
    Ok(Json(json!({"did": did, "handle": acct.handle, "plcUpdated": plc_updated, "rev": head.rev.to_string()})))
}

/// As ReplaceRepo takes it: (path, cid, bytes, blob refs).
type StoredRecord = (String, Cid, Bytes, Vec<Cid>);

type NodeBlocks = HashMap<Cid, Arc<[u8]>>;

/// Problems listed per check (counts are exact).
const LIST_MAX: usize = 20;

struct Inspection {
    head: Head,
    records: Vec<StoredRecord>,
    /// Records that don't decode or don't hash to their CID.
    bad_records: Vec<String>,
    matches_head: bool,
    /// What a rebuild deletes: bad or unreferenced `M/` nodes, stale index
    /// entries.
    stale_keys: Vec<Bytes>,
    /// The repo's stats counted from the snapshot, bytes included.
    counted: state::RepoStats,
    report: J,
}

fn sample<T: ToString>(v: impl IntoIterator<Item = T>) -> Vec<String> {
    v.into_iter().take(LIST_MAX).map(|x| x.to_string()).collect()
}

async fn scan_keys<R: slatedb::DbReadOps + Sync + ?Sized>(db: &R, prefix: &[u8]) -> XResult<Vec<(Bytes, Bytes)>> {
    let mut it = db.scan(prefix.to_vec()..state::prefix_end(prefix)).await.map_err(XrpcError::from_err)?;
    let mut out = Vec::new();
    while let Some(kv) = it.next().await.map_err(XrpcError::from_err)? {
        out.push((kv.key, kv.value));
    }
    Ok(out)
}

fn check_commit(did: &str, head: &Head, pubkey: &str) -> J {
    let cid_ok = Cid::dag_cbor(&head.commit_block) == head.commit;
    let (mut data_ok, mut did_ok, mut sig_ok) = (false, false, false);
    if let Ok(c) = Value::decode(&head.commit_block) {
        let text = |k: &str| match c.get(k) {
            Some(Value::Text(s)) => Some(s.clone()),
            _ => None,
        };
        data_ok = matches!(c.get("data"), Some(Value::Link(d)) if *d == head.data);
        did_ok = text("did").as_deref() == Some(did);
        if let (Some(cdid), Some(rev), Some(Value::Link(data)), Some(Value::Bytes(sig))) =
            (text("did"), text("rev"), c.get("data"), c.get("sig"))
        {
            let unsigned = crate::events::encode_commit(&cdid, &rev, data, None);
            let sec1 = pubkey
                .strip_prefix('z')
                .and_then(|m| bs58::decode(m).into_vec().ok())
                .and_then(|raw| raw.strip_prefix(&[0xe7, 0x01][..]).map(<[u8]>::to_vec));
            sig_ok = sec1.is_some_and(|k| crypto::verify_k256(&k, &unsigned, sig).unwrap_or(false));
        }
    }
    json!({"cidOk": cid_ok, "dataOk": data_ok, "didOk": did_ok, "signatureOk": sig_ok})
}

/// (records, paths of records that don't decode or hash to their CID).
async fn read_records<R: slatedb::DbReadOps + Sync + ?Sized>(
    db: &R,
    did: &str,
    gen: u64,
) -> XResult<(Vec<StoredRecord>, Vec<String>)> {
    let rprefix = state::record_prefix(did, gen);
    let (mut records, mut bad) = (Vec::new(), Vec::new());
    for (k, v) in scan_keys(db, &rprefix).await? {
        let path = String::from_utf8_lossy(&k[rprefix.len()..]).into_owned();
        let Ok((cid, bytes)) = state::decode_record_value(&v) else {
            bad.push(path);
            continue;
        };
        let mut blobs = Vec::new();
        match Value::decode(&bytes) {
            Ok(v) if Cid::dag_cbor(&bytes) == cid => super::blob_refs(&v, &mut blobs),
            _ => {
                bad.push(path);
                continue;
            }
        }
        records.push((path, cid, bytes, blobs));
    }
    Ok((records, bad))
}

/// The backlink index (bl/) against the records: (entries missing or wrong,
/// stale keys, entries stored).
async fn check_backlinks<R: slatedb::DbReadOps + Sync + ?Sized>(
    db: &R,
    did: &str,
    gen: u64,
    records: &[StoredRecord],
) -> XResult<(usize, Vec<Bytes>, usize)> {
    let stored: HashMap<Bytes, Bytes> = scan_keys(db, &state::backlink_prefix(did, gen)).await?.into_iter().collect();
    let mut want: BTreeMap<Vec<u8>, crate::backlinks::Rkeys> = BTreeMap::new();
    for (path, _, bytes, _) in records {
        let coll = crate::worker::collection_of(path);
        if let Some(l) = crate::backlinks::link(coll, bytes) {
            want.entry(l).or_default().push(path[coll.len() + 1..].into());
        }
    }
    let want: HashMap<Bytes, Bytes> = want
        .into_iter()
        .map(|(l, mut rkeys)| {
            rkeys.sort();
            (Bytes::from(state::backlink_key(did, gen, &l)), crate::backlinks::encode(&rkeys))
        })
        .collect();
    let missing = want.iter().filter(|(k, v)| stored.get(*k) != Some(*v)).count();
    let stale = stored.keys().filter(|k| !want.contains_key(*k)).cloned().collect();
    Ok((missing, stale, stored.len()))
}

/// Reads `did`'s state from one snapshot (taken under the apply lock, so a
/// commit's batch is in it entirely or not at all) and checks it. Doesn't
/// touch the repo worker, so it works on a repo that fails to load.
async fn inspect(app: &App, did: &str) -> XResult<Inspection> {
    let p = app.partition(did)?;
    let snap = {
        let _g = p.apply_lock.read().await;
        p.db.snapshot().map_err(XrpcError::from_err)?
    };
    let get = |k: Vec<u8>| {
        let snap = snap.clone();
        async move { slatedb::DbReadOps::get(snap.as_ref(), k).await.map_err(XrpcError::from_err) }
    };
    let hv = get(state::head_key(did)).await?.ok_or_else(|| not_found(did))?;
    let head = Head::decode(&hv).map_err(XrpcError::from_err)?;
    let acct: Account = match get(state::account_key(did)).await? {
        Some(v) => serde_json::from_slice(&v).map_err(XrpcError::from_err)?,
        None => return Err(XrpcError::internal(format!("{did}: head without account"))),
    };
    let gen = acct.repo_gen;

    let (records, bad_records) = read_records(snap.as_ref(), did, gen).await?;

    let mprefix = state::mst_node_prefix(did, gen);
    let stored: Vec<(Bytes, Bytes)> = scan_keys(snap.as_ref(), &mprefix).await?;
    let cprefix = {
        let k = state::record_cid_prefix(did, gen, &head.data);
        k[..k.len() - 8].to_vec()
    };
    let cid_index: HashSet<Bytes> = scan_keys(snap.as_ref(), &cprefix).await?.into_iter().map(|(k, _)| k).collect();
    let blob_index: HashSet<Bytes> =
        scan_keys(snap.as_ref(), &state::blob_ref_prefix(did, gen)).await?.into_iter().map(|(k, _)| k).collect();
    let mut colls = BTreeSet::new();
    for (path, ..) in &records {
        colls.insert(crate::worker::collection_of(path).to_string());
    }
    let mut colls_missing = Vec::new();
    for c in &colls {
        if get(state::collection_key(c, did)).await?.is_none() {
            colls_missing.push(c.clone());
        }
    }

    let recs: Vec<(crate::mst_lazy::Key, Cid)> =
        records.iter().map(|(p, c, ..)| (Arc::from(p.as_bytes()), *c)).collect();
    let (rebuilt, want, tree_nodes, node_bytes) =
        tokio::task::spawn_blocking(move || -> XResult<(Cid, NodeBlocks, u64, u64)> {
            let mut tree = crate::mst_lazy::build_tree(&recs).map_err(XrpcError::from_err)?;
            let root = tree.root_cid().map_err(XrpcError::from_err)?;
            Ok((
                root,
                crate::mst_lazy::persisted_nodes(&tree, 1),
                crate::repo_stats::count_tree(&tree).map_err(XrpcError::from_err)?.1,
                crate::repo_stats::tree_bytes(&tree).map_err(XrpcError::from_err)?,
            ))
        })
        .await
        .map_err(XrpcError::from_err)??;
    let matches_head = rebuilt == head.data;
    let (mut have, mut corrupt, mut stale_keys) = (HashSet::new(), Vec::new(), Vec::new());
    let mut extra = Vec::new();
    for (k, v) in &stored {
        let Ok(digest) = <[u8; 32]>::try_from(&k[mprefix.len()..]) else {
            corrupt.push(hex::encode(&k[mprefix.len()..]));
            stale_keys.push(k.clone());
            continue;
        };
        let c = Cid { codec: crate::cid::CODEC_DAG_CBOR, digest };
        if Cid::dag_cbor(v) != c {
            corrupt.push(c.to_string());
            stale_keys.push(k.clone());
        } else if !want.contains_key(&c) {
            extra.push(c);
            stale_keys.push(k.clone());
        }
        have.insert(c);
    }
    let missing: Vec<&Cid> = want.keys().filter(|c| !have.contains(*c)).collect();

    let want_cids: HashSet<Bytes> =
        records.iter().map(|(p, c, ..)| Bytes::from(state::record_cid_key(did, gen, c, p))).collect();
    let want_blobs: HashSet<Bytes> = records
        .iter()
        .flat_map(|(p, _, _, bs)| bs.iter().map(move |b| Bytes::from(state::blob_ref_key(did, gen, b, p))))
        .collect();
    let cid_missing = want_cids.difference(&cid_index).count();
    let blob_missing = want_blobs.difference(&blob_index).count();
    let (n0, n1) = (stale_keys.len(), {
        stale_keys.extend(cid_index.difference(&want_cids).cloned());
        stale_keys.len()
    });
    stale_keys.extend(blob_index.difference(&want_blobs).cloned());
    let (cid_extra, blob_extra) = (n1 - n0, stale_keys.len() - n1);

    let (bl_missing, bl_stale, bl_stored) = check_backlinks(snap.as_ref(), did, gen, &records).await?;

    let counted = state::RepoStats {
        records: (records.len() + bad_records.len()) as u64,
        nodes: tree_nodes,
        blobs: records.iter().flat_map(|(_, _, _, bs)| bs.iter()).collect::<HashSet<_>>().len() as u64,
        bytes: Some(state::RepoBytes {
            records: records.iter().map(|(_, _, b, _)| b.len() as u64).sum(),
            nodes: node_bytes,
        }),
    };
    let stored_stats = match get(state::repo_stats_key(did)).await? {
        Some(v) => Some(state::RepoStats::decode(&v).map_err(XrpcError::from_err)?),
        None => None,
    };
    let bl_extra = bl_stale.len();
    stale_keys.extend(bl_stale);

    let commit = check_commit(did, &head, &acct.signing_pubkey);
    let mut problems: Vec<String> = Vec::new();
    for k in ["cidOk", "dataOk", "didOk", "signatureOk"] {
        if commit[k] != json!(true) {
            problems.push(format!("head commit: {k} is false"));
        }
    }
    if !bad_records.is_empty() {
        problems.push(format!("{} record(s) don't hash to their CID", bad_records.len()));
    }
    match stored_stats {
        None => problems.push("repo stats (S/) missing".into()),
        // bytes are kept close, not exact, between counts: not a problem
        Some(st) if st.counts() != counted.counts() => {
            problems.push(format!("repo stats (S/) are {:?}, the repo has {:?}", st.counts(), counted.counts()))
        }
        Some(_) => {}
    }
    if !matches_head {
        problems.push(format!("records rebuild to MST root {rebuilt}, head data is {}", head.data));
    }
    for (n, what) in [
        (missing.len(), "persisted MST node(s) missing"),
        (extra.len(), "persisted MST node(s) not in the tree"),
        (corrupt.len(), "persisted MST node(s) don't hash to their key"),
        (cid_missing, "record-CID index entries missing"),
        (cid_extra, "stale record-CID index entries"),
        (blob_missing, "blob-ref index entries missing"),
        (blob_extra, "stale blob-ref index entries"),
        (bl_missing, "backlink index entries missing or wrong"),
        (bl_extra, "stale backlink index entries"),
        (colls_missing.len(), "collection index entries missing"),
    ] {
        if n > 0 {
            problems.push(format!("{n} {what}"));
        }
    }
    let report = json!({
        "did": did,
        "ok": problems.is_empty(),
        "problems": problems,
        "status": acct.status,
        "head": {"commit": head.commit.to_string(), "data": head.data.to_string(), "rev": head.rev.to_string()},
        "commit": commit,
        "records": {"count": records.len() + bad_records.len(), "badCount": bad_records.len(), "bad": sample(&bad_records)},
        "mst": {"rebuiltRoot": rebuilt.to_string(), "matchesHead": matches_head},
        "stats": {
            "stored": stored_stats.map(|s| json!({
                "records": s.records, "nodes": s.nodes, "blobs": s.blobs,
                "recordBytes": s.bytes.map(|b| b.records), "nodeBytes": s.bytes.map(|b| b.nodes),
            })),
            "counted": {
                "records": counted.records, "nodes": counted.nodes, "blobs": counted.blobs,
                "recordBytes": counted.bytes.map(|b| b.records), "nodeBytes": counted.bytes.map(|b| b.nodes),
            },
        },
        "nodes": {
            "expected": want.len(), "stored": stored.len(),
            "missing": missing.len(), "extra": extra.len(), "corrupt": corrupt.len(),
            "missingSample": sample(missing), "extraSample": sample(&extra), "corruptSample": sample(&corrupt),
        },
        "indexes": {
            "recordCidMissing": cid_missing, "recordCidExtra": cid_extra,
            "blobRefMissing": blob_missing, "blobRefExtra": blob_extra,
            "backlinkMissing": bl_missing, "backlinkExtra": bl_extra, "backlinks": bl_stored,
            "collectionsMissing": colls_missing,
        },
    });
    Ok(Inspection { head, records, bad_records, matches_head, stale_keys, counted, report })
}

#[derive(Deserialize)]
struct DidQ {
    did: String,
}

async fn check_repo(State(app): AppState, Auth(creds): Auth, Query(q): Query<DidQ>) -> XResult<Json<J>> {
    require_admin(&creds)?;
    Ok(Json(inspect(&app, &q.did).await?.report))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RebuildIn {
    did: String,
    #[serde(default)]
    dry_run: bool,
}

/// The reference's rebuild-repo: re-derives the repo from its records under
/// a new signed commit. The replace is guarded by the head the records were
/// read at (`InvalidSwap` if a commit landed since: run it again). Refused
/// when the records can't be the repo's (records lost), and for taken-down
/// accounts.
async fn rebuild_repo(State(app): AppState, Auth(creds): Auth, Json(inp): Json<RebuildIn>) -> XResult<Json<J>> {
    require_admin(&creds)?;
    let did = inp.did;
    let ins = inspect(&app, &did).await?;
    let mut out = json!({"did": did, "dryRun": inp.dry_run, "records": ins.records.len(), "before": ins.report});
    let refuse = if !ins.bad_records.is_empty() {
        Some("records don't hash to their CIDs")
    } else if !ins.matches_head {
        Some("records don't rebuild to the head's data root (records lost: restore from a backup)")
    } else {
        None
    };
    if let Some(why) = refuse {
        return Err(XrpcError::bad("RepoUnrecoverable", format!("{did}: {why}")));
    }
    if inp.dry_run {
        return Ok(Json(out));
    }
    let (records, stale_keys) = (ins.records, ins.stale_keys);
    let swap = Some(ins.head.commit);
    let head = app
        .account_op(&did, crate::worker::AccountOp::ReplaceRepo { records, swap_commit: swap, stale_keys, tree: None })
        .await?;
    tracing::warn!(%did, commit = %head.commit, rev = %head.rev, "repo rebuilt from its records (admin rebuildRepo)");
    out["commit"] = json!(head.commit.to_string());
    out["rev"] = json!(head.rev.to_string());
    out["after"] = inspect(&app, &did).await?.report;
    Ok(Json(out))
}

/// Counts the repo's stats (repo bytes included) from a snapshot and
/// installs them, guarded by the head they were counted at (`InvalidSwap`
/// if a commit landed since: run it again). Costs a read of the whole repo,
/// as checkRepo; for a repo whose bytes have drifted. Rows written before
/// bytes were counted don't need it: the repo's next load counts them.
async fn recount_repo(
    State(app): AppState,
    Auth(creds): Auth,
    Json(inp): Json<super::console::DidIn>,
) -> XResult<Json<J>> {
    require_admin(&creds)?;
    let did = inp.did;
    let ins = inspect(&app, &did).await?;
    if !ins.bad_records.is_empty() {
        return Err(XrpcError::bad("RepoUnrecoverable", format!("{did}: records don't hash to their CIDs")));
    }
    let before = ins.report["stats"]["stored"].clone();
    let stats = ins.counted;
    app.account_op(&did, crate::worker::AccountOp::SetStats { stats, at_rev: ins.head.rev.0 }).await?;
    Ok(Json(json!({
        "did": did,
        "before": before,
        "after": ins.report["stats"]["counted"],
        "repoBytes": stats.bytes.map(|b| b.total()),
    })))
}

pub fn space_routes() -> Router<Arc<App>> {
    Router::new().route("/xrpc/vlpds.admin.checkSpace", get(check_space))
}

#[derive(Deserialize)]
struct SpaceQ {
    did: String,
    space: String,
    reason: Option<String>,
    actor: Option<String>,
}

/// check-space from one snapshot taken under the apply lock, as checkRepo's.
/// Its report names record paths and the head, so it's an operator read of
/// space data: audited first, as vlpds.admin.getSpaceRepo is.
async fn check_space(
    State(app): AppState,
    Auth(creds): Auth,
    super::moderation::ClientIp(ip): super::moderation::ClientIp,
    Query(q): Query<SpaceQ>,
) -> XResult<Json<J>> {
    use crate::space::check;
    require_admin(&creds)?;
    if check::authority(&q.space).is_none() {
        return Err(invalid(format!("not a space URI: {}", q.space)));
    }
    let who = super::moderation::Who {
        actor: q
            .actor
            .as_deref()
            .map(str::trim)
            .filter(|a| !a.is_empty())
            .unwrap_or("admin")
            .chars()
            .take(64)
            .collect(),
        ip: ip.map(|i| i.to_string()),
    };
    let subject = super::moderation::SubjectRef::space_repo(&q.space, &q.did);
    let reason = q.reason.as_deref().map(str::trim).filter(|r| !r.is_empty());
    let detail = json!({"space": q.space, "repo": q.did, "method": "checkSpace"});
    super::moderation::audit(&app, &who, "space.read", Some(&subject), reason, None, Some(detail)).await?;
    let p = app.partition(&q.did)?;
    let snap = {
        let _g = p.apply_lock.read().await;
        p.db.snapshot().map_err(XrpcError::from_err)?
    };
    let rows = check::load(snap.as_ref(), &q.did, &q.space).await.map_err(XrpcError::from_err)?;
    if rows.is_empty() {
        return Err(XrpcError::bad("RepoNotFound", format!("{} has no rows in {}", q.did, q.space)));
    }
    let report = check::check(&q.did, &q.space, &rows, crate::tid::now_micros(), app.config.space_oplog_retention);
    if report.pointer("/records/matchesHead") == Some(&J::Bool(false)) {
        tracing::warn!(did = %q.did, space = %crate::state::space_log_id(&q.space), "check-space: records don't hash to the space head");
        crate::metrics::space_digest_mismatch();
    }
    Ok(Json(report))
}
