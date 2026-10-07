//! The operator's handle domains (`crate::handle_domains`): list them with
//! their active accounts (from the kept totals, `crate::totals`; counted
//! from every account row with `recount`), add and remove them. A change is
//! stored for the cluster and every peer is nudged to re-read it.

use super::admin::require_admin;
use super::internal::HDR as INTERNAL_HDR;
use super::moderation::{audit, ClientIp, SubjectRef, Who};
use super::*;
use crate::handle_domains::{self as hd, SaveError};
use std::collections::{BTreeMap, HashSet};
use std::time::Duration;

const RELOAD_TIMEOUT: Duration = Duration::from_secs(2);

pub fn routes() -> Router<Arc<App>> {
    Router::new()
        .route("/xrpc/vlpds.admin.listHandleDomains", get(list_handle_domains))
        .route("/xrpc/vlpds.admin.addHandleDomain", post(add_handle_domain))
        .route("/xrpc/vlpds.admin.removeHandleDomain", post(remove_handle_domain))
}

pub fn internal_routes() -> Router<Arc<App>> {
    Router::new()
        .route("/internal/v1/handle-domains/reload", post(internal_reload))
        .route("/internal/v1/handle-domains/counts", get(internal_counts))
}

pub fn start(app: &Arc<App>) {
    hd::spawn_refresher(&app.handle_domains, app.store.clone());
}

fn node_id(app: &App) -> String {
    app.cluster.as_ref().map(|c| c.cfg.node_id.clone()).unwrap_or_else(|| "single".into())
}

type ShardCounts = Vec<(crate::slots::ShardId, BTreeMap<String, u64>)>;

/// The longest of `domains` that `suffix` is or is under.
fn domain_of<'d>(suffix: &str, domains: &'d [String]) -> Option<&'d str> {
    hd::longest(suffix, domains.iter().map(String::as_str)).map(|(_, d)| d)
}

/// Active accounts per domain of `domains`, per shard of this node, from
/// the kept totals (`crate::totals` counts them by handle suffix); and the
/// shards whose totals are still loading, left out.
fn counts_kept(app: &App, domains: &[String]) -> (ShardCounts, Vec<crate::slots::ShardId>) {
    let (mut out, mut loading) = (Vec::new(), Vec::new());
    for sink in app.log.sinks.all() {
        // copied out: the sequencer takes this lock for every account change
        let suffixes = match sink.totals.lock().sum() {
            Some(t) => t.suffixes.clone(),
            None => {
                loading.push(sink.id);
                continue;
            }
        };
        let mut counts: BTreeMap<String, u64> = domains.iter().map(|d| (d.clone(), 0)).collect();
        for (s, n) in suffixes {
            if let Some(d) = domain_of(&s, domains) {
                *counts.entry(d.to_string()).or_default() += n.max(0) as u64;
            }
        }
        out.push((sink.id, counts));
    }
    (out, loading)
}

/// [`counts_kept`] counted from scratch: every account row of this node's
/// shards. For `recount`, never on a schedule.
async fn counts_scanned(app: &App, domains: &[String]) -> XResult<ShardCounts> {
    #[derive(serde::Deserialize)]
    struct Row<'a> {
        #[serde(borrow)]
        handle: std::borrow::Cow<'a, str>,
        #[serde(borrow, default)]
        status: Option<std::borrow::Cow<'a, str>>,
    }
    let opts = slatedb::config::ScanOptions { read_ahead_bytes: 1 << 20, max_fetch_tasks: 2, ..Default::default() };
    let mut out = Vec::new();
    for p in app.partitions.owned() {
        let mut counts: BTreeMap<String, u64> = domains.iter().map(|d| (d.clone(), 0)).collect();
        let mut iter = state::FamilyScan::new(p.db.as_ref(), state::ACCOUNT_FAMILY, None, &opts)
            .await
            .map_err(XrpcError::from_err)?;
        while let Some(kv) = iter.next().await.map_err(XrpcError::from_err)? {
            let Ok(a) = serde_json::from_slice::<Row>(&kv.value) else { continue };
            if a.status.is_some() {
                continue;
            }
            if let Some(d) = hd::handle_suffix(&a.handle).as_deref().and_then(|s| domain_of(s, domains)) {
                *counts.entry(d.to_string()).or_default() += 1;
            }
        }
        out.push((p.id, counts));
    }
    Ok(out)
}

async fn counts_local(
    app: &App,
    domains: &[String],
    recount: bool,
) -> XResult<(ShardCounts, Vec<crate::slots::ShardId>)> {
    match recount {
        true => Ok((counts_scanned(app, domains).await?, Vec::new())),
        false => Ok(counts_kept(app, domains)),
    }
}

struct Counts {
    by_domain: BTreeMap<String, u64>,
    /// Set when some shards went uncounted.
    partial: Option<J>,
}

/// Cluster-wide [`counts_local`]; a shard reported twice (mid-move) counts
/// once.
async fn counts(app: &App, domains: &[String], recount: bool) -> XResult<Counts> {
    let (local, mut loading) = counts_local(app, domains, recount).await?;
    let mut by_shard: BTreeMap<crate::slots::ShardId, BTreeMap<String, u64>> = local.into_iter().collect();
    let mut query = vec![("domains", domains.join(","))];
    if recount {
        query.push(("recount", "true".into()));
    }
    let g = super::internal::gather(app, "/internal/v1/handle-domains/counts", &query).await;
    for r in g.replies {
        let shards: ShardCounts = serde_json::from_value(r.body["shards"].clone()).unwrap_or_default();
        for (s, c) in shards {
            by_shard.entry(s).or_insert(c);
        }
        loading.extend(
            serde_json::from_value::<Vec<crate::slots::ShardId>>(r.body["loading"].clone()).unwrap_or_default(),
        );
    }
    let covered: HashSet<crate::slots::ShardId> = by_shard.keys().copied().collect();
    let mut by_domain: BTreeMap<String, u64> = domains.iter().map(|d| (d.clone(), 0)).collect();
    for c in by_shard.into_values() {
        for (d, n) in c {
            *by_domain.entry(d).or_default() += n;
        }
    }
    let mut res = json!({});
    super::admin::partial_fields(app, &mut res, g.unreachable, g.unsupported, &covered, 0);
    loading.retain(|s| !covered.contains(s));
    if !loading.is_empty() {
        loading.sort();
        loading.dedup();
        res["loadingShards"] = json!(loading);
    }
    let partial = res.as_object().is_some_and(|o| !o.is_empty()).then_some(res);
    Ok(Counts { by_domain, partial })
}

fn rows(app: &App, counts: Option<&Counts>) -> Vec<J> {
    let primary = app.handle_domains.primary();
    app.handle_domains
        .list()
        .into_iter()
        .map(|a| {
            json!({
                "domain": a.domain,
                "primary": a.domain == primary,
                "accounts": counts.and_then(|c| c.by_domain.get(&a.domain)),
                "addedAt": a.added_at,
                "addedBy": a.added_by,
            })
        })
        .collect()
}

#[derive(Deserialize, Default)]
struct ListQ {
    /// Count every account row instead of reading the kept totals.
    #[serde(default)]
    recount: bool,
}

async fn list_handle_domains(State(app): AppState, Auth(creds): Auth, Query(q): Query<ListQ>) -> XResult<Json<J>> {
    require_admin(&creds)?;
    let c = counts(&app, &app.handle_domains.names(), q.recount).await?;
    let mut out = json!({
        "primary": app.handle_domains.primary(),
        "domains": rows(&app, Some(&c)),
        "refreshSecs": hd::REFRESH_EVERY.as_secs(),
        "updatedAt": app.handle_domains.updated_at(),
        "recounted": q.recount,
    });
    if let Some(p) = c.partial {
        out["countsPartial"] = json!(true);
        for (k, v) in p.as_object().into_iter().flatten() {
            out[k] = v.clone();
        }
    }
    Ok(Json(out))
}

fn save_error(e: SaveError) -> XrpcError {
    let message = e.to_string();
    match e {
        SaveError::Invalid(_) | SaveError::TooMany => XrpcError::bad("InvalidDomain", message),
        SaveError::Exists(_) => XrpcError::bad("DomainExists", message),
        SaveError::NotFound(_) => XrpcError::bad("DomainNotFound", message),
        SaveError::Primary => XrpcError::bad("CannotRemovePrimary", message),
        SaveError::Store(_) => XrpcError { status: StatusCode::BAD_GATEWAY, error: "UpstreamFailure".into(), message },
    }
}

/// Peers also re-read within [`hd::REFRESH_EVERY`]; this makes it now.
async fn nudge_peers(app: &Arc<App>) -> Vec<J> {
    let me = node_id(app);
    let mut applied = vec![json!({"node": me, "ok": true})];
    let Some(c) = &app.cluster else { return applied };
    let peers: Vec<_> = c.peers().into_iter().filter(|l| l.node_id != me).collect();
    let sends = peers.into_iter().map(|l| {
        let app = app.clone();
        async move {
            let r = app
                .http
                .post(format!("{}/internal/v1/handle-domains/reload", l.addr.trim_end_matches('/')))
                .header(INTERNAL_HDR, &app.config.internal_token)
                .timeout(RELOAD_TIMEOUT)
                .send()
                .await
                .and_then(|r| r.error_for_status());
            match r {
                Ok(_) => json!({"node": l.node_id, "ok": true}),
                Err(e) => {
                    tracing::warn!(peer = %l.node_id, "handle domain reload nudge failed (it re-reads on its own): {e}");
                    json!({"node": l.node_id, "ok": false, "error": e.to_string()})
                }
            }
        }
    });
    applied.extend(futures::future::join_all(sends).await);
    applied
}

#[derive(Deserialize)]
struct AddIn {
    domain: String,
    actor: Option<String>,
}

async fn add_handle_domain(
    State(app): AppState,
    Auth(creds): Auth,
    ClientIp(ip): ClientIp,
    Json(inp): Json<AddIn>,
) -> XResult<Json<J>> {
    require_admin(&creds)?;
    let domain = inp.domain.trim().to_string();
    let who = Who::of(&creds, inp.actor.as_deref(), ip);
    hd::add(&app.handle_domains, &app.store, &domain, creds.operator().unwrap_or("admin")).await.map_err(save_error)?;
    audit(&app, &who, "domain.add", Some(&SubjectRef::other("domain", &domain)), None, None, None).await?;
    let nodes = nudge_peers(&app).await;
    Ok(Json(json!({"domain": domain, "domains": rows(&app, None), "nodes": nodes})))
}

#[derive(Deserialize)]
struct RemoveIn {
    domain: String,
    #[serde(default)]
    force: bool,
    actor: Option<String>,
}

/// Refused while accounts hold handles under the domain (or they couldn't
/// all be counted), unless forced.
async fn remove_handle_domain(
    State(app): AppState,
    Auth(creds): Auth,
    ClientIp(ip): ClientIp,
    Json(inp): Json<RemoveIn>,
) -> XResult<Json<J>> {
    require_admin(&creds)?;
    let domain = inp.domain.trim().to_string();
    let names = app.handle_domains.names();
    if domain == app.handle_domains.primary() {
        return Err(save_error(SaveError::Primary));
    }
    if !names.contains(&domain) {
        return Err(save_error(SaveError::NotFound(domain)));
    }
    let c = counts(&app, &names, false).await?;
    let n = c.by_domain.get(&domain).copied().unwrap_or(0);
    if !inp.force && (n > 0 || c.partial.is_some()) {
        let accounts = if n == 1 {
            "1 active account has a handle".to_string()
        } else {
            format!("{n} active accounts have handles")
        };
        let unsure = if c.partial.is_some() {
            " (some shards didn't answer or are still loading their totals, so there may be more)"
        } else {
            ""
        };
        return Err(XrpcError {
            status: StatusCode::CONFLICT,
            error: "DomainInUse".into(),
            message: format!("{accounts} under {domain}{unsure}; pass force to remove it anyway"),
        });
    }
    hd::remove(&app.handle_domains, &app.store, &domain).await.map_err(save_error)?;
    let who = Who::of(&creds, inp.actor.as_deref(), ip);
    let detail = json!({"accounts": n, "force": inp.force});
    audit(&app, &who, "domain.remove", Some(&SubjectRef::other("domain", &domain)), None, None, Some(detail)).await?;
    let nodes = nudge_peers(&app).await;
    Ok(Json(json!({"domain": domain, "accounts": n, "nodes": nodes})))
}

async fn internal_reload(State(app): AppState, headers: HeaderMap) -> XResult<Json<J>> {
    super::internal::check(&app, &headers)?;
    hd::refresh(&app.handle_domains, &app.store).await.map_err(|e| XrpcError {
        status: StatusCode::BAD_GATEWAY,
        error: "UpstreamFailure".into(),
        message: format!("{e:#}"),
    })?;
    Ok(Json(json!({"node": node_id(&app), "domains": app.handle_domains.names()})))
}

#[derive(Deserialize)]
struct CountsQ {
    domains: String,
    #[serde(default)]
    recount: bool,
}

async fn internal_counts(State(app): AppState, headers: HeaderMap, Query(q): Query<CountsQ>) -> XResult<Json<J>> {
    super::internal::check(&app, &headers)?;
    let domains: Vec<String> = q.domains.split(',').filter(|d| !d.is_empty()).map(str::to_string).collect();
    if domains.is_empty() {
        return Err(XrpcError::bad("InvalidRequest", "no domains"));
    }
    let (shards, loading) = counts_local(&app, &domains, q.recount).await?;
    let owned: Vec<_> = shards.iter().map(|(s, _)| *s).collect();
    Ok(Json(json!({"owned": owned, "shards": shards, "loading": loading})))
}
