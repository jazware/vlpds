//! The console's storage calls (crate::store_stats): objects and bytes by
//! key component, and the one-time backfill that seeds them. Admin token
//! only. getStorageStats reads one control-plane object and asks each live
//! node for what it hasn't folded yet; neither call lists the bucket on the
//! request (the backfill lists it in the background, capped).

use super::admin::require_admin;
use super::moderation::{audit, ClientIp, Who};
use super::*;
use crate::store_stats::{self as ss, Comps, Counts};

pub fn routes() -> Router<Arc<App>> {
    Router::new()
        .route("/xrpc/vlpds.admin.getStorageStats", get(get_storage_stats))
        .route("/xrpc/vlpds.admin.backfillStorageStats", post(backfill_storage_stats))
}

pub fn internal_routes() -> Router<Arc<App>> {
    Router::new()
        .route("/internal/v1/console/storage", get(internal_storage))
        .route("/internal/v1/console/storageWindow", get(internal_window))
}

fn store_err(e: anyhow::Error) -> XrpcError {
    XrpcError::internal(format!("storage stats: {e:#}"))
}

async fn internal_storage(State(app): AppState, headers: HeaderMap) -> XResult<Json<J>> {
    internal::check(&app, &headers)?;
    Ok(Json(app.store_stats.local()))
}

#[derive(Deserialize)]
struct WindowQ {
    epoch: u64,
    phase: String,
}

/// A backfill's start or end, from the node running it.
async fn internal_window(State(app): AppState, headers: HeaderMap, Query(q): Query<WindowQ>) -> XResult<Json<J>> {
    internal::check(&app, &headers)?;
    match q.phase.as_str() {
        "begin" => app.store_stats.begin_window(q.epoch).await.map_err(store_err)?,
        "end" => app.store_stats.end_window(q.epoch).await.map_err(store_err)?,
        p => return Err(XrpcError::bad("InvalidRequest", format!("unknown phase {p:?}"))),
    }
    Ok(Json(json!({})))
}

/// Every node's view, merged: (totals, observed LISTs, per-node rows,
/// nodes that didn't answer, changes still kept aside by a backfill).
struct Gathered {
    totals: Comps,
    observed: ss::Observed,
    nodes: Vec<J>,
    unreachable: Vec<String>,
    windowed: u64,
    doc: ss::StatsDoc,
}

async fn gather_all(app: &App) -> XResult<Gathered> {
    let doc = app.store_stats.read_doc().await.map_err(store_err)?;
    let mut totals = doc.folded();
    let me = app.store_stats.node_id();
    let mut bodies = vec![(me.clone(), true, app.store_stats.local())];
    let g = internal::gather(app, "/internal/v1/console/storage", &[]).await;
    bodies.extend(g.replies.into_iter().map(|r| (r.node, false, r.body)));
    let mut unreachable = g.unreachable;
    unreachable.extend(g.unsupported);
    let (mut observed, mut nodes, mut windowed) = (ss::Observed::new(), Vec::new(), 0u64);
    let mut live = std::collections::HashSet::new();
    for (node, me, b) in &bodies {
        live.insert(node.clone());
        let pending: Comps = serde_json::from_value(b["pending"].clone()).unwrap_or_default();
        ss::add_all(&mut totals, &pending);
        let o: ss::Observed = serde_json::from_value(b["observed"].clone()).unwrap_or_default();
        ss::merge_observed(&mut observed, &o);
        let w = b["windowChanges"].as_u64().unwrap_or(0);
        windowed += w;
        let pend = pending.values().fold(Counts::default(), |mut a, c| {
            a.add(c);
            a
        });
        let mark = doc.nodes.get(node);
        nodes.push(json!({
            "node": node,
            "self": me,
            "reachable": true,
            "pendingObjects": pend.objects,
            "pendingBytes": pend.bytes,
            "windowChanges": w,
            "foldedAt": mark.map(|m| m.flushed_at),
        }));
    }
    for u in &unreachable {
        live.insert(u.clone());
        nodes.push(
            json!({"node": u, "self": false, "reachable": false, "foldedAt": doc.nodes.get(u).map(|m| m.flushed_at)}),
        );
    }
    // a node that last folded as running and isn't up: it crashed, and what
    // it hadn't folded is gone
    for (n, m) in &doc.nodes {
        if m.open && !live.contains(n) {
            nodes.push(json!({"node": n, "self": false, "reachable": false, "gone": true, "foldedAt": m.flushed_at}));
        }
    }
    app.store_stats.note_means(&totals);
    Ok(Gathered { totals, observed, nodes, unreachable, windowed, doc })
}

async fn get_storage_stats(State(app): AppState, Auth(creds): Auth) -> XResult<Json<J>> {
    require_admin(&creds)?;
    let g = gather_all(&app).await?;
    let backfill = app.store_stats.read_backfill().await.map_err(store_err)?;
    let seeded = g.doc.seed.is_some();
    let gone = g.nodes.iter().any(|n| n["gone"] == true);
    // what keeps every component from being exact, whatever its own changes
    let mut why: Vec<&str> = Vec::new();
    if !seeded {
        why.push("never backfilled: the counts are changes since this node started counting");
    }
    if g.doc.lost || gone {
        why.push("a node crashed since the last backfill: its unfolded changes are lost");
    }
    if !g.unreachable.is_empty() {
        why.push("a node didn't answer: its unfolded changes are missing");
    }
    if g.doc.window_active {
        why.push("a backfill is in progress");
    }
    let components: Vec<J> = g
        .totals
        .iter()
        .filter(|(_, c)| c.objects != 0 || c.bytes != 0)
        .map(|(k, c)| {
            json!({
                "component": k,
                "objects": c.objects,
                "bytes": c.bytes,
                "uncertain": c.uncertain,
                "exact": why.is_empty() && c.uncertain == 0,
            })
        })
        .collect();
    let uncertain: u64 = g.totals.values().map(|c| c.uncertain).sum();
    let (oo, ob, on) = ss::observed_total(&g.observed);
    let mut out = json!({
        "components": components,
        "totalObjects": g.totals.values().map(|c| c.objects).sum::<i64>(),
        "totalBytes": g.totals.values().map(|c| c.bytes).sum::<i64>(),
        "exact": why.is_empty() && uncertain == 0,
        "uncertainChanges": uncertain,
        "inexactBecause": why,
        "seeded": seeded,
        "lastBackfillAt": g.doc.seed.as_ref().map(|s| s.at),
        "backfill": backfill.as_ref().map(|b| b.summary()),
        "windowChanges": g.windowed,
        "observed": {"objects": oo, "bytes": ob, "prefixes": on},
        "nodes": g.nodes,
        "time": ss::now_ms(),
    });
    if !g.unreachable.is_empty() {
        out["unreachableNodes"] = json!(g.unreachable);
    }
    Ok(Json(out))
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct BackfillIn {
    #[serde(default)]
    dry_run: bool,
    /// LIST requests this call may make (each lists up to 1,000 keys).
    /// Required unless dryRun.
    #[serde(default)]
    max_requests: Option<u64>,
    #[serde(default)]
    pages_per_second: Option<f64>,
    /// Start over instead of resuming a stopped run.
    #[serde(default)]
    restart: bool,
    #[serde(default)]
    actor: Option<String>,
}

async fn backfill_storage_stats(
    State(app): AppState,
    Auth(creds): Auth,
    ClientIp(ip): ClientIp,
    Json(inp): Json<BackfillIn>,
) -> XResult<Json<J>> {
    require_admin(&creds)?;
    let g = gather_all(&app).await?;
    let prev = app.store_stats.read_backfill().await.map_err(store_err)?;
    let counted: i64 = g.totals.values().map(|c| c.objects).sum();
    let (observed, _, prefixes) = ss::observed_total(&g.observed);
    // the larger of what's counted and what the background jobs' LISTs saw
    // (both undercount before a first backfill: counts start at zero, and
    // the jobs list only some prefixes)
    let (estimate, basis) = if g.doc.seed.is_some() && counted.max(0) as u64 >= observed {
        (counted.max(0) as u64, "counters")
    } else {
        (observed, "observed LISTs")
    };
    let resume = !inp.restart && prev.as_ref().is_some_and(|p| p.phase != "done" && p.epoch == g.doc.epoch);
    let listed = if resume { prev.as_ref().map_or(0, |p| p.keys) } else { 0 };
    let remaining = estimate.saturating_sub(listed);
    let estimated_requests = remaining.div_ceil(ss::PAGE).max(1);
    let pps = inp.pages_per_second.unwrap_or(ss::DEFAULT_PAGES_PER_SECOND);
    if !(ss::MIN_PAGES_PER_SECOND..=ss::MAX_PAGES_PER_SECOND).contains(&pps) {
        return Err(XrpcError::bad(
            "InvalidRequest",
            format!("pagesPerSecond: {} to {}", ss::MIN_PAGES_PER_SECOND, ss::MAX_PAGES_PER_SECOND),
        ));
    }
    let plan = json!({
        "estimatedObjects": estimate,
        "estimatedRequests": estimated_requests,
        "estimateBasis": basis,
        "observedPrefixes": prefixes,
        "resume": resume,
        "alreadyListed": listed,
        "estimatedSeconds": (estimated_requests as f64 / pps).ceil() as u64,
        "pagesPerSecond": pps,
        "backfill": prev.as_ref().map(|b| b.summary()),
    });
    if inp.dry_run {
        let mut out = plan;
        out["dryRun"] = json!(true);
        return Ok(Json(out));
    }
    let max = inp.max_requests.ok_or_else(|| {
        XrpcError::bad("InvalidRequest", "maxRequests is required: run with dryRun first for the estimate")
    })?;
    if max == 0 || max > ss::MAX_REQUESTS {
        return Err(XrpcError::bad("InvalidRequest", format!("maxRequests: 1 to {}", ss::MAX_REQUESTS)));
    }
    let a = app.clone();
    let broadcast: ss::Broadcast = Arc::new(move |epoch, phase| {
        let a = a.clone();
        Box::pin(async move {
            let q = [("epoch", epoch.to_string()), ("phase", phase.to_string())];
            let g = internal::gather(&a, "/internal/v1/console/storageWindow", &q).await;
            g.unreachable.into_iter().chain(g.unsupported).collect()
        })
    });
    let busy = |node: &str| XrpcError::bad("AlreadyRunning", format!("a storage backfill is running on {node}"));
    if let Some(p) = prev.as_ref().filter(|p| ss::runner_alive(p) && p.runner != app.store_stats.node_id()) {
        return Err(busy(&p.runner));
    }
    // before the run: an entry written once its window is open could be
    // counted on both sides of the listing
    let detail = json!({"maxRequests": max, "pagesPerSecond": pps, "resume": resume});
    audit(&app, &Who::of(&creds, inp.actor.as_deref(), ip), "storage.backfill", None, None, None, Some(detail)).await?;
    let opts = ss::BackfillOpts { max_requests: max, pages_per_second: pps, restart: inp.restart };
    let doc = match ss::start_backfill(&app.store_stats, app.store.clone(), opts, broadcast).await {
        Ok(d) => d,
        Err(ss::StartError::Busy(node)) => return Err(busy(&node)),
        Err(ss::StartError::Store(e)) => return Err(store_err(e)),
    };
    let mut out = plan;
    out["started"] = json!(true);
    out["backfill"] = doc.summary();
    Ok(Json(out))
}
