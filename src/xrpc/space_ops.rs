//! The console's Spaces pages (docs/spaces/operating.md "Console"): what
//! spaces this cluster hosts, who's in them and how their notifies are
//! doing. Admin only, and metadata only (Q6): DIDs, revs, counts, policies,
//! times. A record's value is read only through vlpds.admin.getSpaceRecord
//! and listSpaceRecords, which are audited first (space_admin.rs).
//!
//! Every method answers 501 without `--spaces`, after the auth check, so
//! the console can tell "off here" from "not allowed".

use super::admin::require_admin;
use super::moderation::{audit, ClientIp, SubjectRef, Who};
use super::space::{space_takedown_name, takedown_name, Space};
use super::*;
use crate::space::rows::{AppAccess, HeadRow, MemberRow, Policy, SeqRow, SpaceRow, WriterRow};
use std::collections::HashMap;
use vlsync_atproto::tid::Tid;

pub fn routes() -> Router<Arc<App>> {
    Router::new()
        .route("/xrpc/vlpds.admin.listSpaces", get(list_spaces))
        .route("/xrpc/vlpds.admin.getSpaceInfo", get(get_space_info))
        .route("/xrpc/vlpds.admin.getAccountSpaces", get(get_account_spaces))
        .route("/xrpc/vlpds.admin.getSpacesStatus", get(get_spaces_status))
        .route("/xrpc/vlpds.admin.removeSpaceRegistration", post(remove_registration))
}

pub fn internal_routes() -> Router<Arc<App>> {
    Router::new().route("/internal/v1/admin/spaces", get(internal_spaces))
}

/// Spaces one node summarizes for listSpaces. Each costs a scan of its
/// members and writers, so the page is bounded rather than the cluster.
const SPACES_PER_NODE: usize = 2_000;
/// Space repo heads one node folds into per-space record counts.
const HEADS_PER_NODE: usize = 200_000;
/// Members or writers counted per space before the count reads "N+".
const COUNT_CAP: usize = 10_000;
/// Members and writers getSpaceInfo lists.
const LIST_MAX: usize = 1_000;
/// Newest spaceRevs getSpaceInfo shows.
const ACTIVITY: usize = 50;
/// Spaces getAccountSpaces lists.
const ACCOUNT_SPACES_MAX: usize = 1_000;
const MAX_REASON: usize = 2000;

fn spaces_on(app: &App) -> XResult<&Arc<crate::space::Spaces>> {
    app.spaces.as_ref().ok_or_else(|| XrpcError {
        status: StatusCode::NOT_IMPLEMENTED,
        error: "MethodNotImplemented".into(),
        message: "Spaces is off on this server (start it with --spaces)".into(),
    })
}

fn err(e: impl std::fmt::Display) -> XrpcError {
    XrpcError::from_err(e)
}

fn rfc3339(micros: u64) -> Option<String> {
    (micros != 0)
        .then(|| chrono::DateTime::from_timestamp_micros(micros as i64))
        .flatten()
        .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
}

fn tid_json(t: Tid) -> J {
    match t.0 {
        0 => J::Null,
        _ => json!({"rev": t.to_string(), "at": rfc3339(t.micros())}),
    }
}

fn policy_text(p: &Policy) -> String {
    match p {
        Policy::Public => "public".into(),
        Policy::MemberList => "member-list".into(),
        Policy::ManagingApp { managing_app } => format!("managing-app {managing_app}"),
    }
}

fn app_access_text(a: &AppAccess) -> String {
    match a {
        AppAccess::Open => "open".into(),
        AppAccess::AllowList { allowed } => format!("allow-list ({})", allowed.len()),
    }
}

/// The handle of an account whose shard this node owns.
async fn local_handle(app: &App, did: &str) -> Option<String> {
    app.partitions.for_key(did)?;
    app.account(did).await.ok().map(|a| a.handle)
}

/// Rows under `prefix`, counted up to [`COUNT_CAP`] (+1 means "more").
async fn count_prefix(db: &slatedb::Db, prefix: &[u8]) -> XResult<usize> {
    let opts = slatedb::config::ScanOptions::default();
    let mut it =
        db.scan_with_options(prefix.to_vec()..vlsync_store::keys::prefix_end(prefix), &opts).await.map_err(err)?;
    let mut n = 0;
    while n <= COUNT_CAP {
        let rows = it.next_batch(256).await.map_err(err)?;
        if rows.is_empty() {
            break;
        }
        n += rows.len();
    }
    Ok(n.min(COUNT_CAP + 1))
}

/// The newest `sQ` row of a space: (spaceRev, writer).
async fn last_seq(db: &slatedb::Db, authority: &str, sid: &state::SpaceId) -> XResult<Option<(Tid, String)>> {
    let prefix = state::space_prefix(state::SPACE_SEQ_FAMILY, authority, sid);
    let desc = slatedb::config::ScanOptions::default().with_order(slatedb::IterationOrder::Descending);
    let mut it =
        db.scan_with_options(prefix.clone()..vlsync_store::keys::prefix_end(&prefix), &desc).await.map_err(err)?;
    let Some(kv) = it.next().await.map_err(err)? else { return Ok(None) };
    let rev = crate::space::rows::seq_rev(&kv.key).ok_or_else(|| XrpcError::internal("malformed space seq key"))?;
    Ok(Some((rev, SeqRow::decode(&kv.value).map_err(err)?.writer)))
}

#[derive(Clone, Debug, Default, serde::Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SpaceSummary {
    uri: String,
    authority: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    handle: Option<String>,
    space_type: String,
    skey: String,
    read_policy: String,
    write_policy: String,
    app_access: String,
    created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    deleted_at: Option<String>,
    takendown: bool,
    /// [`COUNT_CAP`] + 1: more than the cap.
    members: usize,
    writers: usize,
    /// Space repos of this space stored in the cluster, and their records.
    repos: u64,
    records: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_space_rev: Option<String>,
    /// Unix µs of the newest spaceRev (0: none yet).
    last_activity_us: u64,
}

async fn summarize(app: &App, p: &Partition, row: SpaceRow) -> XResult<Option<SpaceSummary>> {
    let Ok(space) = Space::parse(&row.uri) else { return Ok(None) };
    let db = p.db.as_ref();
    let mp = state::space_prefix(state::SPACE_MEMBER_FAMILY, &space.authority, &space.sid);
    let wp = state::space_prefix(state::SPACE_WRITER_FAMILY, &space.authority, &space.sid);
    let (members, writers, last) =
        tokio::try_join!(count_prefix(db, &mp), count_prefix(db, &wp), last_seq(db, &space.authority, &space.sid))?;
    let takendown = super::server::ctl(app, &space.authority).await?.has_takedown(&space_takedown_name(&space.sid));
    Ok(Some(SpaceSummary {
        handle: local_handle(app, &space.authority).await,
        read_policy: policy_text(&row.read_policy),
        write_policy: policy_text(&row.write_policy),
        app_access: app_access_text(&row.app_access),
        created_at: row.created_at,
        deleted_at: row.deleted_at,
        takendown,
        members,
        writers,
        last_space_rev: last.as_ref().map(|(r, _)| r.to_string()),
        last_activity_us: last.map_or(0, |(r, _)| r.micros()),
        uri: space.uri,
        authority: space.authority,
        space_type: space.space_type,
        skey: space.skey,
        ..Default::default()
    }))
}

#[derive(Clone, Debug, Default, serde::Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RepoAgg {
    repos: u64,
    records: u64,
}

/// One node's half of listSpaces: the spaces its shards govern and the
/// space repos they hold, folded by space.
#[derive(Default, serde::Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LocalSpaces {
    owned: Vec<vlsync_store::slots::ShardId>,
    spaces: Vec<SpaceSummary>,
    repos: HashMap<String, RepoAgg>,
    truncated: bool,
}

async fn local_spaces(app: &App) -> XResult<LocalSpaces> {
    let layout = app.partitions.layout();
    let mut out = LocalSpaces::default();
    let opts = slatedb::config::ScanOptions::default();
    let mut heads = 0;
    for p in app.partitions.owned() {
        out.owned.push(p.id);
        // a split's children hold the parent's rows until they're swept
        let range = layout.range_of(p.id);
        let ours = |k: &[u8]| vlsync_store::keys::key_slot(k).is_some_and(|s| range.is_none_or(|r| r.contains(s)));
        let mut scan = state::FamilyScan::new(p.db.as_ref(), state::SPACE_FAMILY, None, &opts).await.map_err(err)?;
        while let Some(kv) = scan.next().await.map_err(err)? {
            if !ours(&kv.key) {
                continue;
            }
            if out.spaces.len() >= SPACES_PER_NODE {
                out.truncated = true;
                break;
            }
            let Ok(row) = SpaceRow::decode(&kv.value) else { continue };
            if let Some(s) = summarize(app, &p, row).await? {
                out.spaces.push(s);
            }
        }
        let mut scan =
            state::FamilyScan::new(p.db.as_ref(), state::SPACE_HEAD_FAMILY, None, &opts).await.map_err(err)?;
        while let Some(kv) = scan.next().await.map_err(err)? {
            if !ours(&kv.key) {
                continue;
            }
            if heads >= HEADS_PER_NODE {
                out.truncated = true;
                break;
            }
            heads += 1;
            let Ok(h) = HeadRow::decode(&kv.value) else { continue };
            let a = out.repos.entry(h.uri).or_default();
            a.repos += 1;
            a.records += h.records;
        }
    }
    Ok(out)
}

async fn internal_spaces(State(app): AppState, headers: HeaderMap) -> XResult<Json<LocalSpaces>> {
    super::internal::check(&app, &headers)?;
    spaces_on(&app)?;
    Ok(Json(local_spaces(&app).await?))
}

#[derive(Deserialize)]
struct ListQ {
    /// activity (default) | members | writers | records | created
    sort: Option<String>,
    limit: Option<i64>,
    /// An offset into the sorted list.
    cursor: Option<String>,
    /// Only the spaces this DID governs.
    authority: Option<String>,
}

/// Spaces hosted in the cluster (gathered from every node) with their
/// totals, sorted and paged. Counts only, no record of any space is read.
async fn list_spaces(State(app): AppState, Auth(creds): Auth, Query(q): Query<ListQ>) -> XResult<Json<J>> {
    require_admin(&creds)?;
    spaces_on(&app)?;
    let limit = super::extract::limit_param(q.limit, 50, 1, 100)?;
    let offset = match q.cursor.as_deref().filter(|c| !c.is_empty()) {
        Some(c) => c.parse::<usize>().map_err(|_| XrpcError::bad("InvalidRequest", "Malformed cursor"))?,
        None => 0,
    };
    let sort = q.sort.as_deref().unwrap_or("activity");
    if !["activity", "members", "writers", "records", "created"].contains(&sort) {
        return Err(XrpcError::bad("InvalidRequest", format!("unknown sort {sort}")));
    }
    let mine = local_spaces(&app).await?;
    let g = super::internal::gather(&app, "/internal/v1/admin/spaces", &[]).await;
    let mut covered: std::collections::HashSet<vlsync_store::slots::ShardId> = mine.owned.iter().copied().collect();
    let mut truncated = mine.truncated;
    let mut spaces = mine.spaces;
    let mut repos = mine.repos;
    for r in g.replies {
        let Ok(l) = serde_json::from_value::<LocalSpaces>(r.body) else { continue };
        covered.extend(l.owned);
        truncated |= l.truncated;
        spaces.extend(l.spaces);
        for (uri, a) in l.repos {
            let t = repos.entry(uri).or_default();
            t.repos += a.repos;
            t.records += a.records;
        }
    }
    spaces.sort_by(|a, b| a.uri.cmp(&b.uri));
    spaces.dedup_by(|a, b| a.uri == b.uri);
    for s in &mut spaces {
        if let Some(a) = repos.get(&s.uri) {
            (s.repos, s.records) = (a.repos, a.records);
        }
    }
    let live: Vec<&SpaceSummary> = spaces.iter().filter(|s| s.deleted_at.is_none()).collect();
    let totals = json!({
        "spaces": live.len(),
        "deletedSpaces": spaces.len() - live.len(),
        "takendown": live.iter().filter(|s| s.takendown).count(),
        "members": live.iter().map(|s| s.members).sum::<usize>(),
        "writers": live.iter().map(|s| s.writers).sum::<usize>(),
        "spaceRepos": repos.values().map(|a| a.repos).sum::<u64>(),
        "records": repos.values().map(|a| a.records).sum::<u64>(),
        // repos here in spaces governed elsewhere
        "foreignSpaces": repos.keys().filter(|u| spaces.binary_search_by(|s| s.uri.cmp(u)).is_err()).count(),
    });
    if let Some(a) = q.authority.as_deref().filter(|a| !a.is_empty()) {
        spaces.retain(|s| s.authority == a);
    }
    match sort {
        "members" => spaces.sort_by_key(|s| std::cmp::Reverse(s.members)),
        "writers" => spaces.sort_by_key(|s| std::cmp::Reverse(s.writers)),
        "records" => spaces.sort_by_key(|s| std::cmp::Reverse(s.records)),
        "created" => spaces.sort_by(|a, b| b.created_at.cmp(&a.created_at)),
        _ => spaces.sort_by_key(|s| std::cmp::Reverse(s.last_activity_us)),
    }
    let total = spaces.len();
    let page: Vec<SpaceSummary> = spaces.into_iter().skip(offset).take(limit).collect();
    let mut res = json!({"totals": totals, "count": total, "spaces": page, "countCap": COUNT_CAP});
    if offset + limit < total {
        res["cursor"] = json!((offset + limit).to_string());
    }
    if truncated {
        res["truncated"] = json!(true);
    }
    super::admin::partial_fields(&app, &mut res, g.unreachable, g.unsupported, &covered, 0);
    Ok(Json(res))
}

#[derive(Deserialize)]
struct InfoQ {
    /// The space's authority (routes the call to its owner).
    did: String,
    uri: String,
}

/// One space at its authority: identity, policy, members, writers and the
/// newest spaceRevs, the registrations, and its records taken down.
async fn get_space_info(State(app): AppState, Auth(creds): Auth, Query(q): Query<InfoQ>) -> XResult<Json<J>> {
    require_admin(&creds)?;
    spaces_on(&app)?;
    let space = Space::parse(&q.uri)?;
    if space.authority != q.did {
        return Err(XrpcError::bad("InvalidRequest", "a space is looked up at its authority"));
    }
    let p = app.partition(&space.authority)?;
    let snap = p.db.snapshot().map_err(err)?;
    let Some(v) = snap.get(state::space_key(&space.authority, &space.sid)).await.map_err(err)? else {
        return Err(XrpcError::bad("SpaceNotFound", format!("{} is not hosted here", space.uri)));
    };
    let row = SpaceRow::decode(&v).map_err(err)?;
    let ctl = super::server::ctl(&app, &space.authority).await?;
    let opts = slatedb::config::ScanOptions::default();

    let prefix = state::space_prefix(state::SPACE_MEMBER_FAMILY, &space.authority, &space.sid);
    let mut it =
        snap.scan_with_options(prefix.clone()..vlsync_store::keys::prefix_end(&prefix), &opts).await.map_err(err)?;
    let mut members = Vec::new();
    let mut more_members = false;
    while let Some(kv) = it.next().await.map_err(err)? {
        if members.len() >= LIST_MAX {
            more_members = true;
            break;
        }
        let did = std::str::from_utf8(&kv.key[prefix.len()..]).map_err(err)?;
        let m = MemberRow::decode(&kv.value).map_err(err)?;
        members.push(json!({"did": did, "handle": local_handle(&app, did).await, "read": m.read, "write": m.write}));
    }

    let prefix = state::space_prefix(state::SPACE_WRITER_FAMILY, &space.authority, &space.sid);
    let mut it =
        snap.scan_with_options(prefix.clone()..vlsync_store::keys::prefix_end(&prefix), &opts).await.map_err(err)?;
    let mut writers = Vec::new();
    let mut more_writers = false;
    let mut hidden = Vec::new();
    while let Some(kv) = it.next().await.map_err(err)? {
        if writers.len() >= LIST_MAX {
            more_writers = true;
            break;
        }
        let did = std::str::from_utf8(&kv.key[prefix.len()..]).map_err(err)?.to_string();
        let w = WriterRow::decode(&kv.value).map_err(err)?;
        let mut v = json!({
            "did": did,
            "handle": local_handle(&app, &did).await,
            "repoRev": tid_json(w.repo_rev),
            "spaceRev": tid_json(w.space_rev),
            "hash": hex::encode(&w.hash[..8]),
            "local": false,
        });
        // the writer's own repo, when its shard is ours: its size and the
        // records of it taken down (record paths are metadata; their
        // values are the audited reads)
        if let Some(wp) = app.partitions.for_key(&did) {
            if let Some(h) = wp.db.get(state::space_head_key(&did, &space.sid)).await.map_err(err)? {
                let h = HeadRow::decode(&h).map_err(err)?;
                v["local"] = json!(true);
                v["records"] = json!(h.records);
                v["headRev"] = tid_json(h.rev);
                let td = super::server::ctl(&app, &did).await?.takedowns_under(&takedown_name(&space.sid, ""));
                v["takendownRecords"] = json!(td.len());
                hidden.extend(
                    td.into_iter().map(|path| json!({"uri": format!("{}/{did}/{path}", space.uri), "did": did})),
                );
            }
        }
        writers.push(v);
    }

    let prefix = state::space_prefix(state::SPACE_SEQ_FAMILY, &space.authority, &space.sid);
    let desc = slatedb::config::ScanOptions::default().with_order(slatedb::IterationOrder::Descending);
    let mut it =
        snap.scan_with_options(prefix.clone()..vlsync_store::keys::prefix_end(&prefix), &desc).await.map_err(err)?;
    let mut activity = Vec::new();
    while activity.len() < ACTIVITY {
        let Some(kv) = it.next().await.map_err(err)? else { break };
        let Some(rev) = crate::space::rows::seq_rev(&kv.key) else { continue };
        let s = SeqRow::decode(&kv.value).map_err(err)?;
        activity.push(json!({"spaceRev": rev.to_string(), "at": rfc3339(rev.micros()), "writer": s.writer}));
    }
    drop(it);

    let registrations = registrations_view(&app, &space).await?;
    Ok(Json(json!({
        "space": {
            "uri": space.uri,
            "authority": space.authority,
            "handle": local_handle(&app, &space.authority).await,
            "spaceType": space.space_type,
            "skey": space.skey,
            "readPolicy": policy_text(&row.read_policy),
            "writePolicy": policy_text(&row.write_policy),
            "appAccess": app_access_text(&row.app_access),
            "createdAt": row.created_at,
            "deletedAt": row.deleted_at,
            "takendown": ctl.has_takedown(&space_takedown_name(&space.sid)),
        },
        "members": members,
        "moreMembers": more_members,
        "writers": writers,
        "moreWriters": more_writers,
        "activity": activity,
        "registrations": registrations,
        "takendownRecords": hidden,
    })))
}

#[derive(Deserialize)]
struct DidQ {
    did: String,
}

/// The spaces an account holds a repo in and the ones it governs, from its
/// `sL` index (routes to its owner by `did`).
async fn get_account_spaces(State(app): AppState, Auth(creds): Auth, Query(q): Query<DidQ>) -> XResult<Json<J>> {
    require_admin(&creds)?;
    spaces_on(&app)?;
    let p = app.partition(&q.did)?;
    let snap = p.db.snapshot().map_err(err)?;
    let prefix = state::space_did_prefix(state::SPACE_LIST_FAMILY, &q.did);
    let opts = slatedb::config::ScanOptions::default();
    let mut it =
        snap.scan_with_options(prefix.clone()..vlsync_store::keys::prefix_end(&prefix), &opts).await.map_err(err)?;
    let ctl = super::server::ctl(&app, &q.did).await?;
    let (mut repos, mut governs, mut more) = (Vec::new(), Vec::new(), false);
    while let Some(kv) = it.next().await.map_err(err)? {
        if repos.len() + governs.len() >= ACCOUNT_SPACES_MAX {
            more = true;
            break;
        }
        let Some(uri) = state::space_list_uri(&kv.key, &prefix) else { continue };
        let Ok(space) = Space::parse(uri) else { continue };
        match kv.key.last() {
            Some(b'h') => {
                let Some(v) = snap.get(state::space_head_key(&q.did, &space.sid)).await.map_err(err)? else { continue };
                let h = HeadRow::decode(&v).map_err(err)?;
                repos.push(json!({
                    "space": space.uri,
                    "authority": space.authority,
                    "records": h.records,
                    "rev": tid_json(h.rev),
                    "createdAt": rfc3339(h.created),
                    "takendownRecords": ctl.takedowns_under(&takedown_name(&space.sid, "")).len(),
                }));
            }
            Some(b's') => {
                let Some(v) = snap.get(state::space_key(&q.did, &space.sid)).await.map_err(err)? else { continue };
                let row = SpaceRow::decode(&v).map_err(err)?;
                governs.push(json!({
                    "uri": space.uri,
                    "createdAt": row.created_at,
                    "deletedAt": row.deleted_at,
                    "takendown": ctl.has_takedown(&space_takedown_name(&space.sid)),
                }));
            }
            _ => {}
        }
    }
    Ok(Json(json!({"repos": repos, "governs": governs, "more": more})))
}

/// This node's Spaces state that isn't a metric, beside /metrics.
async fn get_spaces_status(State(app): AppState, Auth(creds): Auth) -> XResult<Json<J>> {
    require_admin(&creds)?;
    let sp = spaces_on(&app)?;
    let node = app.cluster.as_ref().map(|c| c.cfg.node_id.clone());
    let mut out = node_status(sp);
    out["node"] = json!(node);
    Ok(Json(out))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RemoveIn {
    /// The space's authority (routes the call to its owner).
    did: String,
    space: String,
    service: String,
    reason: String,
    actor: Option<String>,
}

/// Drops a service's notify registration, as its unregisterNotify would,
/// audited first (`space.registration.remove`).
async fn remove_registration(
    State(app): AppState,
    Auth(creds): Auth,
    ClientIp(ip): ClientIp,
    Json(inp): Json<RemoveIn>,
) -> XResult<Json<J>> {
    require_admin(&creds)?;
    spaces_on(&app)?;
    let space = Space::parse(&inp.space)?;
    if space.authority != inp.did {
        return Err(XrpcError::bad("InvalidRequest", "a registration is removed at the space's authority"));
    }
    let reason = inp.reason.trim();
    if reason.is_empty() {
        return Err(XrpcError::bad("InvalidRequest", "a reason is required"));
    }
    if reason.chars().count() > MAX_REASON {
        return Err(XrpcError::bad("InvalidRequest", format!("reason: longer than {MAX_REASON} characters")));
    }
    if inp.service.is_empty() || inp.service.len() > crate::space::host::MAX_SERVICE_LEN {
        return Err(XrpcError::bad("InvalidRequest", "service: not a registered service"));
    }
    app.partition(&space.authority)?;
    let who = Who::of(&creds, inp.actor.as_deref(), ip);
    let subject = SubjectRef::space(&space.uri, &space.authority);
    let detail = json!({"space": space.uri, "service": inp.service});
    let e = audit(&app, &who, "space.registration.remove", Some(&subject), Some(reason), None, Some(detail)).await?;
    remove_registration_row(&app, &space, inp.service).await?;
    Ok(Json(json!({"auditId": e.id})))
}

// The accessors below read state that's still being reshaped (notify
// registrations, fan-out lanes, revocations): the rest of this file only
// goes through them.

/// The space's notify registrations, endpoints cut to their host.
async fn registrations_view(app: &App, space: &Space) -> XResult<Vec<J>> {
    let (live, expired) = crate::space::host::registrations(app, &space.authority, &space.sid).await.map_err(err)?;
    let host = |e: &str| reqwest::Url::parse(e).ok().and_then(|u| u.host_str().map(str::to_string));
    let mut out: Vec<J> = live
        .into_iter()
        .map(|(service, row)| {
            json!({"service": service, "host": host(&row.endpoint), "expiresAt": rfc3339(row.expires), "expired": false})
        })
        .collect();
    out.extend(expired.into_iter().map(|service| json!({"service": service, "expired": true})));
    Ok(out)
}

async fn remove_registration_row(app: &App, space: &Space, service: String) -> XResult<()> {
    use crate::space::repo::SpaceOp;
    super::space::submit_space(app, &space.authority, space, SpaceOp::UnregisterNotify { service, expired_by: None })
        .await?;
    Ok(())
}

// TODO(spaces-sec): a per-space "revoke every outstanding credential" may
// come with auto-revoke on removeMember, updateSpace and deleteSpace; the
// console's button waits for it.

fn node_status(sp: &crate::space::Spaces) -> J {
    use crate::space::revocations as rv;
    let r = &sp.revocations;
    let now = vlsync_atproto::tid::now_micros() as i64 / 1_000_000;
    let (blocked_spaces, blocked_authorities) = r.blocks(now);
    json!({
        "outbox": {"rows": sp.outbox.len(), "max": crate::space::outbox::MAX_ROWS},
        "fanout": {"pending": sp.fanout.pending(), "queueMax": crate::space::fanout::QUEUE},
        "revocations": {
            "entries": r.len(),
            "hardCap": rv::HARD_CAP,
            "blockedSpaces": blocked_spaces,
            "blockedAuthorities": blocked_authorities,
            "saturated": r.saturated(now),
            "loaded": r.loaded(),
            "fresh": r.fresh(),
            "refreshEverySecs": rv::REFRESH_EVERY.as_secs(),
            "staleAfterSecs": rv::STALE_AFTER.as_secs(),
        },
        "credentialCache": {"entries": sp.credentials.len(), "max": crate::space::credcache::DEFAULT_ENTRIES},
        "heads": {"entries": sp.heads.len()},
    })
}
