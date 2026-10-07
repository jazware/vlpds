//! The operator console's read models and the few actions that go with
//! them (docs/operations/admin-console.md, "Console API"): accounts with their repo stats, an
//! account's sign-in security, sessions and recent repo events, each node's
//! metrics, log segments, mail and factor lockouts, the effective config,
//! and kicking a firehose subscriber. Admin token only.
//!
//! Per-account calls name the account as `did` and are routed to its owner
//! (crate::forward). Per-node reads gather every live peer over the
//! internal API; a node that doesn't answer is listed in `unreachableNodes`.
//! Calls about one node's own state (getConfig, kickSubscriber) answer for
//! the node they reach: the console names another one with the
//! `x-vlpds-node` header, which relays the call over peer mTLS.

use super::admin::require_admin;
use super::moderation::{audit, ClientIp, SubjectRef, Who};
use super::*;
use std::collections::{BinaryHeap, HashMap};

pub fn routes() -> Router<Arc<App>> {
    Router::new()
        .route("/xrpc/vlpds.admin.listAccounts", get(list_accounts))
        .route("/xrpc/vlpds.admin.getAccountSecurity", get(get_account_security))
        .route("/xrpc/vlpds.admin.listSessions", get(list_sessions))
        .route("/xrpc/vlpds.admin.revokeSessions", post(revoke_sessions))
        .route("/xrpc/vlpds.admin.revokeAppPassword", post(revoke_app_password))
        .route("/xrpc/vlpds.admin.listRepoOps", get(list_repo_ops))
        .route("/xrpc/vlpds.admin.getNodeMetrics", get(get_node_metrics))
        .route("/xrpc/vlpds.admin.listSegments", get(list_segments))
        .route("/xrpc/vlpds.admin.listMail", get(list_mail))
        .route("/xrpc/vlpds.admin.listLockouts", get(list_lockouts))
        .route("/xrpc/vlpds.admin.clearLockout", post(clear_lockout))
        .route("/xrpc/vlpds.admin.getConfig", get(get_config))
        .route("/xrpc/vlpds.admin.kickSubscriber", post(kick_subscriber))
}

pub fn internal_routes() -> Router<Arc<App>> {
    Router::new()
        .route("/internal/v1/console/accounts", get(internal_accounts))
        .route("/internal/v1/console/nodeMetrics", get(internal_node_metrics))
        .route("/internal/v1/console/segments", get(internal_segments))
        .route("/internal/v1/console/mail", get(internal_mail))
        .route("/internal/v1/console/lockouts", get(internal_lockouts))
}

fn node_id(app: &App) -> String {
    app.cluster.as_ref().map(|c| c.cfg.node_id.clone()).unwrap_or_else(|| "single".into())
}

fn now_ms() -> u64 {
    crate::tid::now_micros() / 1000
}

fn bad(message: impl Into<String>) -> XrpcError {
    XrpcError::bad("InvalidRequest", message)
}

/// Unix ms of a TID rev (`rev` is its integer form).
fn rev_ms(rev: u64) -> u64 {
    (rev >> 10) / 1000
}

/// `{node, self, reachable, ...}` rows for a per-node gather: ours first,
/// then every peer that answered, then the ones that didn't.
fn gathered_nodes(app: &App, mine: J, g: internal::Gathered) -> (Vec<J>, Vec<String>) {
    let tag = |mut v: J, node: &str, me: bool| {
        v["node"] = json!(node);
        v["self"] = json!(me);
        v["reachable"] = json!(true);
        v
    };
    let mut nodes = vec![tag(mine, &node_id(app), true)];
    for r in g.replies {
        nodes.push(tag(r.body, &r.node, false));
    }
    let mut unreachable = g.unreachable;
    unreachable.extend(g.unsupported);
    for u in &unreachable {
        nodes.push(json!({"node": u, "self": false, "reachable": false}));
    }
    (nodes, unreachable)
}

fn with_unreachable(mut out: J, unreachable: Vec<String>) -> J {
    if !unreachable.is_empty() {
        out["unreachableNodes"] = json!(unreachable);
    }
    out
}

// ------------------------------------------------------------------ accounts

#[derive(Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub(super) struct AccountsQ {
    /// Handle prefix (a leading `@` is ignored), email prefix or DID; a
    /// full DID is looked up directly.
    #[serde(default)]
    q: Option<String>,
    /// all | attention | deactivated | takendown | no2fa | unconfirmed
    #[serde(default)]
    filter: Option<String>,
    /// recent (default without `q`): most recently committed first, from
    /// each shard's recent-repos list. slot (default with `q`): every
    /// account, in the hash-slot order cursors resume in.
    #[serde(default)]
    sort: Option<String>,
    #[serde(default)]
    cursor: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
}

/// Accounts a node examines per call before it answers with what it has and
/// where it stopped: a search that matches nothing must not read every
/// account in one request.
const SCAN_BUDGET: usize = 20_000;
/// Recent-repo candidates a node examines per call (each costs a head read).
const RECENT_BUDGET: usize = 5_000;

#[derive(Clone, Copy, PartialEq)]
enum Filter {
    All,
    Attention,
    Deactivated,
    Takendown,
    No2fa,
    Unconfirmed,
}

impl Filter {
    fn parse(s: Option<&str>) -> XResult<Filter> {
        Ok(match s.unwrap_or("all") {
            "" | "all" => Filter::All,
            "attention" => Filter::Attention,
            "deactivated" => Filter::Deactivated,
            "takendown" => Filter::Takendown,
            "no2fa" => Filter::No2fa,
            "unconfirmed" => Filter::Unconfirmed,
            f => return Err(bad(format!("unknown filter {f:?}"))),
        })
    }
}

struct Parsed {
    q: Option<String>,
    filter: Filter,
    recent: bool,
    limit: usize,
}

impl AccountsQ {
    fn parsed(&self) -> XResult<Parsed> {
        let q =
            self.q.as_deref().map(|q| q.trim().trim_start_matches('@').to_ascii_lowercase()).filter(|q| !q.is_empty());
        let recent = match self.sort.as_deref() {
            None | Some("") => q.is_none(),
            Some("recent") => true,
            Some("slot") => false,
            Some(s) => return Err(bad(format!("unknown sort {s:?}"))),
        };
        Ok(Parsed {
            q,
            filter: Filter::parse(self.filter.as_deref())?,
            recent,
            limit: self.limit.unwrap_or(50).clamp(1, 200),
        })
    }
}

/// `{slot}:{did}` (slot order) or `{rev}:{did}` (recent).
fn split_cursor(c: &str) -> XResult<(u64, String)> {
    let (n, d) = c.split_once(':').ok_or_else(|| bad("Malformed cursor"))?;
    let n = n.parse::<u64>().map_err(|_| bad("Malformed cursor"))?;
    if !d.starts_with("did:") {
        return Err(bad("Malformed cursor"));
    }
    Ok((n, d.to_string()))
}

/// What a row shows of an account, read from the partition that holds it.
async fn account_row(app: &App, p: &Partition, a: &Account) -> XResult<J> {
    let did = a.did.as_str();
    let get = |k: Vec<u8>| p.db.get(k);
    let stats = get(state::repo_stats_key(did))
        .await
        .map_err(XrpcError::from_err)?
        .and_then(|v| state::RepoStats::decode(&v).ok());
    let head = get(state::head_key(did)).await.map_err(XrpcError::from_err)?.and_then(|v| Head::decode(&v).ok());
    let usage: Option<super::blob_quota::Usage> = get(state::private_key(did, super::blob_quota::USAGE))
        .await
        .map_err(XrpcError::from_err)?
        .and_then(|v| serde_json::from_slice(&v).ok());
    let passkeys = get(state::private_key(did, super::passkeys::ROW))
        .await
        .map_err(XrpcError::from_err)?
        .and_then(|v| serde_json::from_slice::<super::passkeys::Passkeys>(&v).ok())
        .map_or(0, |p| p.creds.len());
    let totp = crate::totp::enabled_for(app, a).await?;
    let extra = |k: &str| a.extra.get(k).and_then(|v| v.as_str()).map(String::from);
    let mut row = json!({
        "did": did,
        "handle": a.handle,
        "email": a.email,
        "emailConfirmed": a.email_confirmed,
        "createdAt": a.created_at,
        "status": a.status.as_deref().unwrap_or("active"),
        "shard": p.id.0,
        "node": node_id(app),
        "invitesDisabled": a.extra.get("invitesDisabled").and_then(|v| v.as_bool()).unwrap_or(false),
        "secondFactors": {"passkeys": passkeys, "totp": totp, "emailCode": super::email2fa::enabled(a)},
        "blobBytes": usage.as_ref().map_or(0, |u| u.bytes),
        "overQuota": usage.as_ref().is_some_and(|u| u.over),
    });
    if let Some(s) = stats {
        row["records"] = json!(s.records);
        row["mstNodes"] = json!(s.nodes);
        row["blobs"] = json!(s.blobs);
        // absent until the repo's next load counts it (state::RepoBytes)
        if let Some(b) = s.bytes {
            row["repoBytes"] = json!(b.total());
            row["recordBytes"] = json!(b.records);
            row["mstBytes"] = json!(b.nodes);
        }
    }
    if let Some(h) = &head {
        row["rev"] = json!(h.rev.to_string());
        row["lastCommitAt"] = json!(rev_ms(h.rev.0));
    }
    for k in ["deactivatedAt", "deleteAfter", "takedownRef"] {
        if let Some(v) = extra(k) {
            row[k] = json!(v);
        }
    }
    Ok(row)
}

fn passes(f: Filter, row: &J, locked: &std::collections::HashSet<String>) -> bool {
    let status = row["status"].as_str().unwrap_or("active");
    let sf = &row["secondFactors"];
    match f {
        Filter::All => true,
        Filter::Deactivated => status == "deactivated",
        Filter::Takendown => status == "takendown",
        Filter::Unconfirmed => row["emailConfirmed"] == false,
        Filter::No2fa => status == "active" && sf["passkeys"] == 0 && sf["totp"] == false && sf["emailCode"] == false,
        Filter::Attention => {
            row["emailConfirmed"] == false
                || row["overQuota"] == true
                || row["did"].as_str().is_some_and(|d| locked.contains(d))
        }
    }
}

/// `did:method:id`, which names one account: looked up, never scanned for.
fn whole_did(pq: &Parsed) -> Option<&str> {
    pq.q.as_deref().filter(|d| {
        let mut parts = d.splitn(3, ':');
        parts.next() == Some("did")
            && parts.next().is_some_and(|m| !m.is_empty())
            && parts.next().is_some_and(|id| id.len() >= 16)
    })
}

fn matches_q(q: &str, a: &Account) -> bool {
    a.handle.starts_with(q) || a.did.starts_with(q) || a.email.as_deref().is_some_and(|e| e.starts_with(q))
}

/// The DIDs the lockout index of this node's shards lists as locked now:
/// only for the attention filter, the one that needs them.
async fn locked_dids(app: &App, f: Filter) -> XResult<std::collections::HashSet<String>> {
    if f != Filter::Attention {
        return Ok(Default::default());
    }
    let now = crate::totp::now_secs();
    Ok(indexed_lockouts(app).await?.0.into_iter().filter(|l| l.2 > now).map(|(d, _, _)| d).collect())
}

/// This node's half of listAccounts: `{owned, accounts, resumeAt}`.
/// Slot order: the hits after the cursor, and where the scan stopped if it
/// stopped early (everything up to there was examined). Recent: this
/// node's newest `limit` older than the cursor.
async fn local_accounts(app: &App, q: &AccountsQ) -> XResult<J> {
    let pq = q.parsed()?;
    let owned = app.partitions.owned();
    let ids: Vec<crate::slots::ShardId> = owned.iter().map(|p| p.id).collect();
    if let Some(d) = whole_did(&pq) {
        let mut out = Vec::new();
        if let Ok(p) = app.partition(d) {
            if let Some(v) = p.db.get(state::account_key(d)).await.map_err(XrpcError::from_err)? {
                let a: Account = serde_json::from_slice(&v).map_err(XrpcError::from_err)?;
                let row = account_row(app, &p, &a).await?;
                out.push(json!({"slot": crate::slots::slot_of(d), "did": d, "row": row}));
            }
        }
        return Ok(json!({"owned": ids, "accounts": out, "resumeAt": null}));
    }
    let locked = locked_dids(app, pq.filter).await?;
    if pq.recent {
        let cursor = q.cursor.as_deref().filter(|c| !c.is_empty()).map(split_cursor).transpose()?;
        let rows = recent_accounts(app, &owned, &pq, cursor, &locked).await?;
        return Ok(json!({"owned": ids, "accounts": rows}));
    }
    let layout = app.partitions.layout();
    let mut owned = owned;
    owned.sort_by_key(|p| layout.range_of(p.id).map_or(u32::MAX, |r| r.lo));
    let after = match q.cursor.as_deref().filter(|c| !c.is_empty()) {
        Some(c) => {
            let (slot, d) = split_cursor(c)?;
            if crate::slots::slot_of(&d) as u64 != slot {
                return Err(bad("Malformed cursor"));
            }
            Some(d)
        }
        None => None,
    };
    let start = after.as_deref().map(|d| [state::account_key(d), vec![0]].concat());
    let (mut out, mut examined, mut resume) = (Vec::new(), 0usize, None);
    'shards: for p in owned {
        let mut iter = state::FamilyScan::new(p.db.as_ref(), state::ACCOUNT_FAMILY, start.clone(), &Default::default())
            .await
            .map_err(XrpcError::from_err)?;
        while let Some(kv) = iter.next().await.map_err(XrpcError::from_err)? {
            let Ok(a) = serde_json::from_slice::<Account>(&kv.value) else { continue };
            examined += 1;
            let slot = crate::slots::slot_of(&a.did);
            if pq.q.as_deref().is_none_or(|q| matches_q(q, &a)) {
                let row = account_row(app, &p, &a).await?;
                if passes(pq.filter, &row, &locked) {
                    out.push(json!({"slot": slot, "did": a.did, "row": row}));
                }
            }
            if out.len() >= pq.limit || examined >= SCAN_BUDGET {
                resume = Some(format!("{slot}:{}", a.did));
                break 'shards;
            }
        }
    }
    Ok(json!({"owned": ids, "accounts": out, "resumeAt": resume}))
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct Candidate {
    rev: u64,
    did: String,
    list: usize,
}

async fn recent_accounts(
    app: &App,
    owned: &[Arc<Partition>],
    pq: &Parsed,
    cursor: Option<(u64, String)>,
    locked: &std::collections::HashSet<String>,
) -> XResult<Vec<J>> {
    let lists: Vec<Vec<Arc<str>>> = owned.iter().map(|p| p.recent.snapshot()).collect();
    let mut pos = vec![0usize; lists.len()];
    let mut heap = BinaryHeap::new();
    let mut examined = 0usize;
    // the shard's next repo older than the cursor; its list is newest first
    async fn next(
        p: &Partition,
        list: &[Arc<str>],
        pos: &mut usize,
        cursor: &Option<(u64, String)>,
        examined: &mut usize,
    ) -> XResult<Option<(u64, String)>> {
        while *pos < list.len() && *examined < RECENT_BUDGET {
            let did = list[*pos].to_string();
            *pos += 1;
            *examined += 1;
            let Some(h) = p.db.get(state::head_key(&did)).await.map_err(XrpcError::from_err)? else { continue };
            let Ok(h) = Head::decode(&h) else { continue };
            if cursor.as_ref().is_some_and(|(r, d)| (h.rev.0, &did) >= (*r, d)) {
                continue;
            }
            return Ok(Some((h.rev.0, did)));
        }
        Ok(None)
    }
    for (i, p) in owned.iter().enumerate() {
        if let Some((rev, did)) = next(p, &lists[i], &mut pos[i], &cursor, &mut examined).await? {
            heap.push(Candidate { rev, did, list: i });
        }
    }
    let mut out = Vec::new();
    while let Some(c) = heap.pop() {
        let p = &owned[c.list];
        if let Some(v) = p.db.get(state::account_key(&c.did)).await.map_err(XrpcError::from_err)? {
            if let Ok(a) = serde_json::from_slice::<Account>(&v) {
                let row = account_row(app, p, &a).await?;
                if passes(pq.filter, &row, locked) {
                    out.push(row);
                    if out.len() >= pq.limit {
                        break;
                    }
                }
            }
        }
        if let Some((rev, did)) = next(p, &lists[c.list], &mut pos[c.list], &cursor, &mut examined).await? {
            heap.push(Candidate { rev, did, list: c.list });
        }
    }
    Ok(out)
}

async fn internal_accounts(State(app): AppState, headers: HeaderMap, Query(q): Query<AccountsQ>) -> XResult<Json<J>> {
    internal::check(&app, &headers)?;
    let mut out = local_accounts(&app, &q).await?;
    out["counts"] = local_counts(&app);
    Ok(Json(out))
}

const COUNT_KEYS: [&str; 7] = ["total", "active", "deactivated", "takendown", "suspended", "unconfirmed", "no2fa"];

/// The filter counts of this node's open shards, from their totals
/// (crate::totals): in memory, no reads. A shard whose totals are still
/// loading counts nothing yet (`loadingShards`).
fn local_counts(app: &App) -> J {
    let (t, loading) = super::totals_loading(app);
    let n = [t.repos(), t.accounts[0], t.accounts[1], t.accounts[2], t.accounts[3], t.unconfirmed, t.no2fa];
    let mut out: serde_json::Map<String, J> =
        COUNT_KEYS.iter().zip(n).map(|(k, v)| (k.to_string(), json!(v))).collect();
    out.insert("loadingShards".into(), json!(loading));
    J::Object(out)
}

/// Sums each node's counts. Approximate while a shard's totals are loading,
/// a node didn't answer, or some shard has no owner.
fn sum_counts(app: &App, bodies: &[J], covered: &std::collections::HashSet<crate::slots::ShardId>) -> J {
    let mut sum = [0i64; COUNT_KEYS.len()];
    let mut approximate = false;
    for b in bodies {
        let c = &b["counts"];
        if !c.is_object() {
            approximate = true;
            continue;
        }
        approximate |= c["loadingShards"].as_u64().unwrap_or(0) > 0;
        for (s, k) in sum.iter_mut().zip(COUNT_KEYS) {
            *s += c[k].as_i64().unwrap_or(0);
        }
    }
    approximate |= app.partitions.layout().shards.iter().any(|r| !covered.contains(&r.id));
    let mut out: serde_json::Map<String, J> =
        COUNT_KEYS.iter().zip(sum).map(|(k, v)| (k.to_string(), json!(v.max(0)))).collect();
    out.insert("approximate".into(), json!(approximate));
    J::Object(out)
}

fn query_pairs(q: &AccountsQ) -> Vec<(&'static str, String)> {
    let mut v = Vec::new();
    for (k, val) in [("q", &q.q), ("filter", &q.filter), ("sort", &q.sort), ("cursor", &q.cursor)] {
        if let Some(x) = val {
            v.push((k, x.clone()));
        }
    }
    if let Some(l) = q.limit {
        v.push(("limit", l.to_string()));
    }
    v
}

fn row_rev(r: &J) -> u64 {
    r["rev"].as_str().and_then(crate::tid::Tid::parse).map_or(0, |t| t.0)
}

async fn list_accounts(State(app): AppState, Auth(creds): Auth, Query(q): Query<AccountsQ>) -> XResult<Json<J>> {
    require_admin(&creds)?;
    let pq = q.parsed()?;
    // a whole DID: one read at its owner instead of a scan
    if let Some(d) = whole_did(&pq) {
        let rows = match internal::account_anywhere(&app, d).await {
            Ok(a) => vec![exact_row(&app, &a).await?],
            Err(e) if e.error == "AccountNotFound" => Vec::new(),
            Err(e) => return Err(e),
        };
        return Ok(Json(json!({"accounts": rows, "exact": true})));
    }
    let mut mine = local_accounts(&app, &q).await?;
    mine["counts"] = local_counts(&app);
    let g = internal::gather(&app, "/internal/v1/console/accounts", &query_pairs(&q)).await;
    let mut covered: std::collections::HashSet<crate::slots::ShardId> =
        serde_json::from_value(mine["owned"].clone()).unwrap_or_default();
    let mut bodies = vec![mine];
    let (unreachable, unsupported) = (g.unreachable, g.unsupported);
    for r in g.replies {
        covered.extend(r.owned);
        bodies.push(r.body);
    }
    let counts = sum_counts(&app, &bodies, &covered);
    let mut res = if pq.recent {
        let mut rows: Vec<J> =
            bodies.iter().flat_map(|b| b["accounts"].as_array().cloned().unwrap_or_default()).collect();
        rows.sort_by(|a, b| (row_rev(b), b["did"].as_str()).cmp(&(row_rev(a), a["did"].as_str())));
        rows.truncate(pq.limit);
        let cursor = (rows.len() == pq.limit)
            .then(|| rows.last().map(|r| format!("{}:{}", row_rev(r), r["did"].as_str().unwrap_or(""))))
            .flatten();
        json!({"accounts": rows, "cursor": cursor, "sort": "recent"})
    } else {
        let key = |s: &str| split_cursor(s).ok();
        // nothing past the earliest place a node stopped is known complete
        let bound = bodies.iter().filter_map(|b| b["resumeAt"].as_str().and_then(key)).min();
        let mut hits: Vec<(u64, String, J)> = bodies
            .iter()
            .flat_map(|b| b["accounts"].as_array().cloned().unwrap_or_default())
            .filter_map(|h| Some((h["slot"].as_u64()?, h["did"].as_str()?.to_string(), h["row"].clone())))
            .filter(|(s, d, _)| bound.as_ref().is_none_or(|(bs, bd)| (s, d) <= (bs, bd)))
            .collect();
        hits.sort_by(|a, b| (a.0, &a.1).cmp(&(b.0, &b.1)));
        hits.dedup_by(|a, b| a.1 == b.1);
        let cursor = if hits.len() > pq.limit {
            hits.truncate(pq.limit);
            hits.last().map(|(s, d, _)| format!("{s}:{d}"))
        } else {
            bound.map(|(s, d)| format!("{s}:{d}"))
        };
        let from = q.cursor.as_deref().and_then(key).map_or(0, |(s, _)| s as u32);
        let mut res =
            json!({"accounts": hits.into_iter().map(|h| h.2).collect::<Vec<_>>(), "cursor": cursor, "sort": "slot"});
        super::admin::partial_fields(&app, &mut res, Vec::new(), Vec::new(), &covered, from);
        res
    };
    res["counts"] = counts;
    if !unreachable.is_empty() {
        res["unreachableNodes"] = json!(unreachable);
    }
    if !unsupported.is_empty() {
        res["unsupportedNodes"] = json!(unsupported);
    }
    if res["cursor"].is_null() {
        res.as_object_mut().map(|o| o.remove("cursor"));
    }
    Ok(Json(res))
}

/// The row of an account found by DID, read where it lives.
async fn exact_row(app: &App, a: &Account) -> XResult<J> {
    match app.partition(&a.did) {
        Ok(p) => account_row(app, &p, a).await,
        Err(_) => {
            let r = internal::owner_get(
                app,
                &app.remote_owner(&a.did).ok_or_else(|| XrpcError::internal("no owner"))?,
                "/internal/v1/console/accounts",
                &[("q", &a.did), ("sort", "slot"), ("limit", "1")],
            )
            .await?;
            r["accounts"]
                .as_array()
                .and_then(|v| v.iter().find(|h| h["did"] == a.did.as_str()))
                .map(|h| h["row"].clone())
                .ok_or_else(|| XrpcError::bad("NotFound", "account not found"))
        }
    }
}

// --------------------------------------------------------- account security

#[derive(Deserialize)]
struct DidQ {
    did: String,
}

#[derive(Deserialize)]
pub(super) struct DidIn {
    pub did: String,
}

fn secs_ms(s: u64) -> u64 {
    s * 1000
}

async fn get_account_security(State(app): AppState, Auth(creds): Auth, Query(q): Query<DidQ>) -> XResult<Json<J>> {
    require_admin(&creds)?;
    let did = q.did.as_str();
    let acct =
        internal::account_anywhere(&app, did).await.map_err(|_| XrpcError::bad("NotFound", "account not found"))?;
    let now = crate::totp::now_secs();
    let passkeys: Vec<J> = super::passkeys::load(&app, did)
        .await?
        .creds
        .into_iter()
        .map(|c| {
            json!({
                "name": c.name,
                "createdAt": secs_ms(c.created_at),
                "lastUsedAt": c.last_used_at.map(secs_ms),
                "backedUp": c.backed_up,
                "suspect": c.suspect_at.is_some(),
                "transports": c.transports,
            })
        })
        .collect();
    let totp = crate::totp::load(&app, did).await?;
    let mfa = super::mfa::load_raw(&app, did).await?.0;
    let email_lock: Option<super::email2fa::Lockout> =
        super::server::get_json(&app, did, super::email2fa::LOCKOUT_NAME).await?;
    let mut lockouts = Vec::new();
    if mfa.failures > 0 || mfa.locked_until > now {
        lockouts.push(json!({
            "factor": super::mfa::FACTOR_LOCK,
            "failures": mfa.failures,
            "lockedUntil": (mfa.locked_until > now).then(|| secs_ms(mfa.locked_until)),
        }));
    }
    if let Some(l) = email_lock.filter(|l| l.failures > 0 || l.locked_until > now) {
        lockouts.push(json!({
            "factor": super::mfa::EMAIL_LOCK,
            "failures": l.failures,
            "lockedUntil": (l.locked_until > now).then(|| secs_ms(l.locked_until)),
        }));
    }
    let prefs: super::signin::Prefs =
        super::server::get_json(&app, did, super::signin::PREFS).await?.unwrap_or_default();
    let epoch = super::auth_epoch(&app, did).await?;
    let fac = super::signin::factors(&app, &acct).await?;
    let mut browsers: Vec<J> = internal::scan_private_anywhere(&app, did, super::signin::TRUST)
        .await?
        .into_iter()
        .filter_map(|(_, v)| {
            let t: super::signin::Trust = serde_json::from_slice(&v).ok()?;
            (now < t.expires_at && t.epoch == epoch && t.factors == fac).then(|| {
                json!({
                    "device": super::signin::describe_user_agent(t.user_agent.as_deref()),
                    "ip": t.ip,
                    "createdAt": secs_ms(t.created_at),
                    "lastUsedAt": secs_ms(t.last_used_at),
                    "expiresAt": secs_ms(t.expires_at),
                })
            })
        })
        .collect();
    browsers.sort_by_key(|b| std::cmp::Reverse(b["lastUsedAt"].as_u64()));
    let mut app_passwords: Vec<J> = internal::scan_private_anywhere(&app, did, "apppass/")
        .await?
        .into_iter()
        .filter_map(|(_, v)| serde_json::from_slice::<J>(&v).ok())
        .map(|m| {
            json!({
                "name": m["name"],
                "createdAt": m["createdAt"],
                "privileged": m["privileged"].as_bool().unwrap_or(false),
                "scopes": m["scopes"],
            })
        })
        .collect();
    app_passwords.sort_by(|a, b| b["createdAt"].as_str().cmp(&a["createdAt"].as_str()));
    let log: super::signin::Log = super::server::get_json(&app, did, super::signin::LOG).await?.unwrap_or_default();
    let failed: super::signin::Failures =
        super::server::get_json(&app, did, super::signin::FAILED).await?.unwrap_or_default();
    // newest first within each, so the stable sort keeps that order within a second
    let mut recent: Vec<J> = log
        .entries
        .iter()
        .rev()
        .map(|e| {
            json!({
                "at": secs_ms(e.at),
                "method": e.method,
                "appPassword": e.app_password,
                "clientId": e.client_id,
                "device": super::signin::describe_user_agent(e.user_agent.as_deref()),
                "userAgent": e.user_agent,
                "ip": e.ip,
                "factor": e.factor,
                "newDevice": e.new_device,
            })
        })
        .chain(failed.entries.iter().rev().map(|f| {
            json!({
                "at": secs_ms(f.last_at),
                "firstAt": secs_ms(f.at),
                "method": f.method,
                "device": super::signin::describe_user_agent(f.user_agent.as_deref()),
                "userAgent": f.user_agent,
                "ip": f.ip,
                "newDevice": false,
                "failed": f.reason,
                "count": f.count,
            })
        }))
        .collect();
    recent.sort_by_key(|e| std::cmp::Reverse(e["at"].as_u64()));
    Ok(Json(json!({
        "did": did,
        "passwordSet": !acct.password_hash.is_empty(),
        "oauthOnly": prefs.oauth_only,
        "blockAppPasswords": prefs.block_app_passwords,
        "secondFactorRequired": super::signin::factor_enabled(&app, &acct).await?,
        "passkeys": passkeys,
        "totp": {"enabled": totp.enabled(), "enabledAt": totp.enabled_at},
        "emailCode": {
            "enabled": super::email2fa::enabled(&acct),
            "since": acct.extra.get(super::email2fa::FLAG).and_then(|v| v.as_str()),
        },
        "recoveryCodes": {
            "remaining": mfa.recovery.len(),
            "total": super::mfa::RECOVERY_CODES,
            "issuedAt": (mfa.issued_at > 0).then(|| secs_ms(mfa.issued_at)),
        },
        "lockouts": lockouts,
        "trustedBrowsers": browsers,
        "appPasswords": app_passwords,
        "recentSignIns": recent,
    })))
}

// ----------------------------------------------------------------- sessions

async fn list_sessions(State(app): AppState, Auth(creds): Auth, Query(q): Query<DidQ>) -> XResult<Json<J>> {
    require_admin(&creds)?;
    let did = q.did.as_str();
    internal::account_anywhere(&app, did).await.map_err(|_| XrpcError::bad("NotFound", "account not found"))?;
    let now = crate::oauth::util::now_secs();
    let mut oauth = Vec::new();
    for s in crate::oauth::store::list_sessions(&app, did).await.map_err(|e| XrpcError::internal(e.description))? {
        if s.expires_at > 0 && s.expires_at < now {
            continue;
        }
        let device = match &s.device_id {
            Some(id) => crate::oauth::store::get_device(&app, id).await.ok().flatten(),
            None => None,
        };
        let ms = |t: i64| (t.max(0) as u64) * 1000;
        oauth.push(json!({
            "id": format!("oauth:{}", s.id),
            "kind": "oauth",
            "clientId": s.client_id,
            "scope": s.scope,
            "signedInAt": ms(s.created_at),
            "refreshedAt": ms(s.updated_at),
            "expiresAt": (s.expires_at > 0).then(|| ms(s.expires_at)),
            "device": device.as_ref().map(|d| super::signin::describe_user_agent(d.user_agent.as_deref())),
            "userAgent": device.as_ref().and_then(|d| d.user_agent.clone()),
            "deviceLastSeenAt": device.as_ref().map(|d| ms(d.last_seen_at)),
            "passkey": s.auth_cred.is_some(),
            "ip": s.ip,
            "signedInIp": s.created_ip,
        }));
    }
    oauth.sort_by_key(|j| std::cmp::Reverse(j["refreshedAt"].as_u64()));
    let legacy = super::server::legacy_sessions(&app, did).await?;
    Ok(Json(json!({"did": did, "sessions": oauth.into_iter().chain(legacy).collect::<Vec<_>>()})))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RevokeSessionsIn {
    did: String,
    /// listSessions ids; absent: every session, OAuth grant, device sign-in
    /// and trusted browser (what a password change does).
    #[serde(default)]
    ids: Option<Vec<String>>,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    actor: Option<String>,
}

fn who(actor: Option<String>, ip: Option<std::net::IpAddr>) -> Who {
    let actor = actor
        .map(|a| a.trim().chars().take(64).collect::<String>())
        .filter(|a| !a.is_empty())
        .unwrap_or_else(|| "admin".into());
    Who { actor, ip: ip.map(|i| i.to_string()) }
}

fn reason_of(r: &Option<String>) -> XResult<Option<String>> {
    let r = r.as_deref().map(str::trim).filter(|r| !r.is_empty());
    if r.is_some_and(|r| r.chars().count() > 2000) {
        return Err(bad("reason: longer than 2000 characters"));
    }
    Ok(r.map(String::from))
}

async fn revoke_sessions(
    State(app): AppState,
    Auth(creds): Auth,
    ClientIp(ip): ClientIp,
    Json(inp): Json<RevokeSessionsIn>,
) -> XResult<Json<J>> {
    require_admin(&creds)?;
    let reason = reason_of(&inp.reason)?;
    let did = inp.did.as_str();
    internal::account_anywhere(&app, did).await.map_err(|_| XrpcError::bad("NotFound", "account not found"))?;
    let (mut oauth, mut legacy) = (0usize, 0usize);
    match &inp.ids {
        None => {
            oauth = crate::oauth::store::list_sessions(&app, did)
                .await
                .map_err(|e| XrpcError::internal(e.description))?
                .len();
            legacy = super::server::legacy_sessions(&app, did).await?.len();
            super::server::revoke_everything(&app, did).await?;
        }
        Some(ids) => {
            if ids.len() > 100 {
                return Err(bad("at most 100 ids"));
            }
            for id in ids {
                if let Some(sid) = id.strip_prefix("oauth:") {
                    crate::oauth::store::delete_session(&app, did, sid)
                        .await
                        .map_err(|e| XrpcError::internal(e.description))?;
                    oauth += 1;
                } else if let Some(fam) = id.strip_prefix("legacy:") {
                    super::server::revoke_legacy_family(&app, did, fam).await?;
                    legacy += 1;
                } else {
                    return Err(bad(format!("unknown session id {id:?}")));
                }
            }
        }
    }
    let detail = json!({"all": inp.ids.is_none(), "oauth": oauth, "legacy": legacy});
    let e = audit(
        &app,
        &who(inp.actor, ip),
        "sessions.revoke",
        Some(&SubjectRef::account(did)),
        reason.as_deref(),
        None,
        Some(detail.clone()),
    )
    .await?;
    Ok(Json(json!({"did": did, "revoked": detail, "auditId": e.id})))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RevokeAppPasswordIn {
    did: String,
    name: String,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    actor: Option<String>,
}

async fn revoke_app_password(
    State(app): AppState,
    Auth(creds): Auth,
    ClientIp(ip): ClientIp,
    Json(inp): Json<RevokeAppPasswordIn>,
) -> XResult<Json<J>> {
    require_admin(&creds)?;
    let reason = reason_of(&inp.reason)?;
    let name = inp.name.trim();
    if name.is_empty() {
        return Err(bad("name is required"));
    }
    internal::account_anywhere(&app, &inp.did).await.map_err(|_| XrpcError::bad("NotFound", "account not found"))?;
    let found = super::server::remove_app_password(&app, &inp.did, name).await?;
    if !found {
        return Err(XrpcError::bad("NotFound", format!("no app password named {name:?}")));
    }
    let e = audit(
        &app,
        &who(inp.actor, ip),
        "app_password.revoke",
        Some(&SubjectRef::account(&inp.did)),
        reason.as_deref(),
        None,
        Some(json!({"name": name})),
    )
    .await?;
    Ok(Json(json!({"did": inp.did, "name": name, "auditId": e.id})))
}

// ------------------------------------------------------------------ repo ops

#[derive(Deserialize)]
struct RepoOpsQ {
    did: String,
    #[serde(default)]
    limit: Option<usize>,
}

/// Events a listRepoOps call looks at before giving up on finding `limit`.
const OPS_SCAN_BUDGET: usize = 2_000_000;

fn cid_str(v: Option<&crate::cbor::ValueRef>) -> Option<String> {
    match v {
        Some(crate::cbor::ValueRef::Link(c)) => Some(c.to_string()),
        _ => None,
    }
}

/// The account's own events in the firehose ring, as the console lists them.
fn decode_event(seq: i64, kind: crate::firehose::FrameKind, frame: &[u8]) -> Option<J> {
    use crate::cbor::ValueRef;
    use crate::firehose::FrameKind;
    let (_, n) = ValueRef::decode_prefix(frame).ok()?;
    let body = ValueRef::decode(&frame[n..]).ok()?;
    let s = |k: &str| body.get(k).and_then(|v| v.as_str()).map(String::from);
    let mut e = json!({"seq": seq.to_string(), "time": s("time")});
    match kind {
        FrameKind::Commit => {
            e["kind"] = json!("commit");
            e["rev"] = json!(s("rev"));
            e["commit"] = json!(cid_str(body.get("commit")));
            let ops: Vec<J> = match body.get("ops") {
                Some(ValueRef::Array(a)) => a
                    .iter()
                    .map(|op| {
                        json!({
                            "action": op.get("action").and_then(|v| v.as_str()),
                            "path": op.get("path").and_then(|v| v.as_str()),
                            "cid": cid_str(op.get("cid")),
                        })
                    })
                    .collect(),
                _ => Vec::new(),
            };
            e["ops"] = json!(ops);
        }
        FrameKind::Sync => {
            e["kind"] = json!("sync");
            e["rev"] = json!(s("rev"));
        }
        FrameKind::Identity => {
            e["kind"] = json!("identity");
            e["handle"] = json!(s("handle"));
        }
        FrameKind::Account => {
            e["kind"] = json!("account");
            e["active"] = json!(matches!(body.get("active"), Some(ValueRef::Bool(true))));
            e["status"] = json!(s("status"));
        }
        FrameKind::Other => return None,
    }
    Some(e)
}

/// From this node's firehose ring, newest first: no bucket reads, so only
/// as far back as the ring reaches (`reachesBackTo`).
async fn list_repo_ops(State(app): AppState, Auth(creds): Auth, Query(q): Query<RepoOpsQ>) -> XResult<Json<J>> {
    require_admin(&creds)?;
    let limit = q.limit.unwrap_or(25).clamp(1, 100);
    let did = q.did.clone();
    let (batches, floor) = app.firehose.ring_snapshot();
    let renumbered = app.firehose.renumbered();
    let (events, scanned, exhausted, oldest) = tokio::task::spawn_blocking(move || {
        let target = did.as_bytes();
        let (mut out, mut scanned, mut oldest) = (Vec::new(), 0usize, None);
        for b in batches.iter().rev() {
            for (seq, frame) in b.events.iter().rev() {
                scanned += 1;
                oldest = Some(*seq);
                let m = crate::firehose::frame_meta(frame);
                if m.did == Some(target) {
                    if let Some(e) = decode_event(*seq, m.kind, frame) {
                        out.push(e);
                        if out.len() >= limit {
                            return (out, scanned, false, oldest);
                        }
                    }
                }
                if scanned >= OPS_SCAN_BUDGET {
                    return (out, scanned, false, oldest);
                }
            }
        }
        (out, scanned, true, oldest)
    })
    .await
    .map_err(XrpcError::from_err)?;
    let mut res = json!({
        "did": q.did,
        "events": events,
        "scanned": scanned,
        // the whole ring was read: nothing older is in memory
        "ringExhausted": exhausted,
        "ringFloor": floor.to_string(),
    });
    if let Some(o) = oldest {
        res["reachesBackTo"] = json!(o.to_string());
        if !renumbered {
            res["reachesBackToTime"] = json!(((o >> 8) / 1000) as u64);
        }
    }
    Ok(Json(res))
}

// -------------------------------------------------------------- node metrics

#[derive(Deserialize, Default)]
struct SinceQ {
    /// Unix ms.
    #[serde(default)]
    since: Option<u64>,
}

async fn internal_node_metrics(State(app): AppState, headers: HeaderMap, Query(q): Query<SinceQ>) -> XResult<Json<J>> {
    internal::check(&app, &headers)?;
    Ok(Json(serde_json::to_value(crate::node_metrics::report(q.since.unwrap_or(0))).map_err(XrpcError::from_err)?))
}

async fn get_node_metrics(State(app): AppState, Auth(creds): Auth, Query(q): Query<SinceQ>) -> XResult<Json<J>> {
    require_admin(&creds)?;
    let since = q.since.unwrap_or(0);
    let mine = serde_json::to_value(crate::node_metrics::report(since)).map_err(XrpcError::from_err)?;
    let g = internal::gather(&app, "/internal/v1/console/nodeMetrics", &[("since", since.to_string())]).await;
    let (nodes, unreachable) = gathered_nodes(&app, mine, g);
    Ok(Json(with_unreachable(json!({"time": now_ms(), "nodes": nodes}), unreachable)))
}

// ----------------------------------------------------------------- segments

/// What the strata view shows by default: the last 20 s.
const SEGMENTS_WINDOW_MS: u64 = 20_000;

fn local_segments(app: &App, since: u64) -> J {
    let wm = app.log.wm.get();
    let durable = app.log.durable_ordinal.load(Ordering::Acquire);
    let renumbered = app.firehose.renumbered();
    json!({
        "log": app.log.log_id.to_string(),
        "durableOrdinal": (durable != u64::MAX).then_some(durable),
        "nextOrdinal": app.log.next_ordinal(),
        "watermark": wm.to_string(),
        // seqs are unix micros × 256 + writer
        "watermarkLagMs": (!renumbered).then(|| now_ms().saturating_sub(((wm.max(0) >> 8) / 1000) as u64)),
        "segments": app.log.feed.since(since),
    })
}

async fn internal_segments(State(app): AppState, headers: HeaderMap, Query(q): Query<SinceQ>) -> XResult<Json<J>> {
    internal::check(&app, &headers)?;
    Ok(Json(local_segments(&app, q.since.unwrap_or(0))))
}

async fn list_segments(State(app): AppState, Auth(creds): Auth, Query(q): Query<SinceQ>) -> XResult<Json<J>> {
    require_admin(&creds)?;
    let since = q.since.unwrap_or_else(|| now_ms().saturating_sub(SEGMENTS_WINDOW_MS));
    let mine = local_segments(&app, since);
    let g = internal::gather(&app, "/internal/v1/console/segments", &[("since", since.to_string())]).await;
    let (nodes, unreachable) = gathered_nodes(&app, mine, g);
    let out = json!({
        "time": now_ms(),
        "since": since,
        "lastEmitted": app.firehose.last_emitted.load(Ordering::Acquire).to_string(),
        "minWatermark": app.firehose.min_watermark().map(|w| w.to_string()),
        "nodes": nodes,
    });
    Ok(Json(with_unreachable(out, unreachable)))
}

// --------------------------------------------------------------------- mail

#[derive(Deserialize, Default)]
struct MailQ {
    #[serde(default)]
    limit: Option<usize>,
    /// Only the mail sent for this account.
    #[serde(default)]
    did: Option<String>,
}

fn local_mail(q: &MailQ) -> J {
    let limit = q.limit.unwrap_or(100).clamp(1, crate::mail::MailLog::KEPT);
    json!({"mail": crate::mail::MAIL_LOG.recent(limit, q.did.as_deref()), "queued": crate::mail::MAIL_QUEUE.get()})
}

async fn internal_mail(State(app): AppState, headers: HeaderMap, Query(q): Query<MailQ>) -> XResult<Json<J>> {
    internal::check(&app, &headers)?;
    Ok(Json(local_mail(&q)))
}

async fn list_mail(State(app): AppState, Auth(creds): Auth, Query(q): Query<MailQ>) -> XResult<Json<J>> {
    require_admin(&creds)?;
    let limit = q.limit.unwrap_or(100).clamp(1, crate::mail::MailLog::KEPT);
    let mine = local_mail(&q);
    let mut params = vec![("limit", limit.to_string())];
    if let Some(d) = &q.did {
        params.push(("did", d.clone()));
    }
    let g = internal::gather(&app, "/internal/v1/console/mail", &params).await;
    let (nodes, unreachable) = gathered_nodes(&app, mine, g);
    let mut mail: Vec<J> = Vec::new();
    let mut summary = Vec::new();
    for n in &nodes {
        let node = n["node"].as_str().unwrap_or("").to_string();
        summary.push(json!({"node": node, "self": n["self"], "reachable": n["reachable"], "queued": n["queued"]}));
        for m in n["mail"].as_array().into_iter().flatten() {
            let mut m = m.clone();
            m["node"] = json!(node);
            mail.push(m);
        }
    }
    mail.sort_by_key(|m| std::cmp::Reverse(m["at"].as_u64()));
    mail.truncate(limit);
    Ok(Json(with_unreachable(json!({"mail": mail, "nodes": summary}), unreachable)))
}

// ----------------------------------------------------------------- lockouts

/// (did, factor, locked until) of every lockout index entry of this node's
/// shards (`mfa::lockout_index`), and the keys that don't parse.
async fn indexed_lockouts(app: &App) -> XResult<(Vec<(String, &'static str, u64)>, Vec<(Arc<Partition>, Bytes)>)> {
    let (mut entries, mut junk) = (Vec::new(), Vec::new());
    for p in app.partitions.owned() {
        let mut it = state::FamilyScan::new(p.db.as_ref(), state::LOCKOUT_FAMILY, None, &Default::default())
            .await
            .map_err(XrpcError::from_err)?;
        while let Some(kv) = it.next().await.map_err(XrpcError::from_err)? {
            let body = &state::key_body(&kv.key)[state::LOCKOUT_FAMILY.len()..];
            let parsed = body.iter().rposition(|b| *b == 0).and_then(|i| {
                let did = std::str::from_utf8(&body[..i]).ok()?;
                let factor = super::mfa::lockout_factor(&body[i + 1..])?;
                let until = u64::from_be_bytes(kv.value.as_ref().try_into().ok()?);
                Some((did.to_string(), factor, until))
            });
            match parsed {
                Some(l) => entries.push(l),
                None => junk.push((p.clone(), kv.key)),
            }
        }
    }
    Ok((entries, junk))
}

/// The lockouts in this node's shards' index, as their rows show them now.
/// An entry whose row no longer locks (it expired, or the account is gone)
/// is dropped by writing the row back unchanged under the conditional
/// write's lock, which deletes the entry with it: a lockout set meanwhile
/// fails the condition and keeps its entry.
async fn local_lockouts(app: &App) -> XResult<Vec<J>> {
    use super::cas::{Cond, Op};
    let now = crate::totp::now_secs();
    let mut out = Vec::new();
    let (entries, junk) = indexed_lockouts(app).await?;
    for (did, factor, _) in entries {
        let name = match factor {
            super::mfa::FACTOR_LOCK => super::mfa::ROW,
            _ => super::email2fa::LOCKOUT_NAME,
        };
        let raw = app.get_private(&did, name).await?;
        let (failures, until) = match (factor, raw.as_deref()) {
            (_, None) => (0, 0),
            (super::mfa::FACTOR_LOCK, Some(v)) => {
                serde_json::from_slice::<super::mfa::Mfa>(v).map_or((0, 0), |m| (m.failures, m.locked_until))
            }
            (_, Some(v)) => {
                serde_json::from_slice::<super::email2fa::Lockout>(v).map_or((0, 0), |l| (l.failures, l.locked_until))
            }
        };
        if until <= now {
            let (conds, ops) = (vec![Cond::eq(name, raw.clone())], vec![Op::put(name, raw)]);
            if let Err(e) = app.private_cas(&did, conds, ops).await {
                tracing::debug!(%did, "dropping a lockout index entry: {}", e.message);
            }
            continue;
        }
        let handle = internal::account_anywhere(app, &did).await.ok().map(|a| a.handle);
        out.push(json!({
            "did": did,
            "handle": handle,
            "factor": factor,
            "failures": failures,
            "lockedUntil": secs_ms(until),
        }));
    }
    for (p, key) in junk {
        let _ = super::write_private_local(&p, vec![crate::segment::Mutation { key, val: None }]).await;
    }
    Ok(out)
}

async fn internal_lockouts(State(app): AppState, headers: HeaderMap) -> XResult<Json<J>> {
    internal::check(&app, &headers)?;
    Ok(Json(json!({"lockouts": local_lockouts(&app).await?})))
}

async fn list_lockouts(State(app): AppState, Auth(creds): Auth) -> XResult<Json<J>> {
    require_admin(&creds)?;
    let mine = json!({"lockouts": local_lockouts(&app).await?});
    let g = internal::gather(&app, "/internal/v1/console/lockouts", &[]).await;
    let (nodes, unreachable) = gathered_nodes(&app, mine, g);
    let mut seen: HashMap<(String, String), J> = HashMap::new();
    for n in &nodes {
        for l in n["lockouts"].as_array().into_iter().flatten() {
            let k = (l["did"].as_str().unwrap_or("").to_string(), l["factor"].as_str().unwrap_or("").to_string());
            seen.insert(k, l.clone());
        }
    }
    let mut lockouts: Vec<J> = seen.into_values().collect();
    lockouts.sort_by_key(|l| std::cmp::Reverse(l["lockedUntil"].as_u64()));
    Ok(Json(with_unreachable(json!({"lockouts": lockouts}), unreachable)))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClearLockoutIn {
    did: String,
    reason: String,
    #[serde(default)]
    actor: Option<String>,
}

/// Clears both factor lockouts and their failure counts. The sign-in
/// rate-limit buckets are separate (a DID override lifts those).
async fn clear_lockout(
    State(app): AppState,
    Auth(creds): Auth,
    ClientIp(ip): ClientIp,
    Json(inp): Json<ClearLockoutIn>,
) -> XResult<Json<J>> {
    use super::cas::{Cond, Op};
    require_admin(&creds)?;
    let reason = reason_of(&Some(inp.reason.clone()))?.ok_or_else(|| bad("a reason is required"))?;
    let did = inp.did.as_str();
    internal::account_anywhere(&app, did).await.map_err(|_| XrpcError::bad("NotFound", "account not found"))?;
    let _g = crate::totp::lock(did).await;
    let mut done = false;
    for _ in 0..crate::totp::CAS_ROUNDS {
        let (mut m, raw) = super::mfa::load_raw(&app, did).await?;
        let lk_raw = app.get_private(did, super::email2fa::LOCKOUT_NAME).await?;
        m.failures = 0;
        m.locked_until = 0;
        let (c, op) = super::mfa::cas_parts(&m, raw);
        let conds = vec![c, Cond::eq(super::email2fa::LOCKOUT_NAME, lk_raw)];
        let ops = vec![op, Op::put(super::email2fa::LOCKOUT_NAME, None)];
        if app.private_cas(did, conds, ops).await?.applied {
            done = true;
            break;
        }
    }
    if !done {
        return Err(crate::totp::conflict());
    }
    let e =
        audit(&app, &who(inp.actor, ip), "lockout.clear", Some(&SubjectRef::account(did)), Some(&reason), None, None)
            .await?;
    Ok(Json(json!({"did": did, "auditId": e.id})))
}

// ------------------------------------------------------------------- config

async fn get_config(State(app): AppState, Auth(creds): Auth) -> XResult<Json<J>> {
    require_admin(&creds)?;
    let mut stored = json!({
        "handleDomains": app.handle_domains.list(),
        "rateLimitsVersion": app.ratelimit.policy().version,
    });
    if let Some(c) = &app.cluster {
        let l = c.layout();
        stored["shardLayout"] = json!({"version": l.version, "shards": l.shards.len()});
        stored["featureLevel"] = json!(c.cluster_version().map(|v| v.active));
    }
    Ok(Json(json!({
        "node": node_id(&app),
        "version": crate::version::version(),
        "rev": crate::version::build_rev(),
        "settings": crate::config_report::settings(),
        "recorded": !crate::config_report::settings().is_empty(),
        "stored": stored,
        "peerTls": app.config.peer_tls.as_ref().map(|t| t.report()),
        "secretFiles": crate::config_report::secret_files(crate::config_report::settings()),
    })))
}

// ------------------------------------------------------------------ firehose

#[derive(Deserialize)]
struct KickIn {
    /// The `conn` listFirehoseSubscribers shows.
    conn: String,
}

async fn kick_subscriber(State(app): AppState, Auth(creds): Auth, Json(inp): Json<KickIn>) -> XResult<Json<J>> {
    require_admin(&creds)?;
    let id =
        inp.conn.trim().trim_start_matches('#').parse::<u64>().map_err(|_| bad("conn: not a connection number"))?;
    if !app.firehose.kick(id) {
        return Err(XrpcError::bad(
            "NotFound",
            format!("no subscriber #{id} on {} (name its node with x-vlpds-node)", node_id(&app)),
        ));
    }
    tracing::info!(conn = id, node = %node_id(&app), "firehose subscriber kicked by the operator");
    Ok(Json(json!({"node": node_id(&app), "conn": id.to_string()})))
}
