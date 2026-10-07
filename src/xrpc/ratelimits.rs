//! Rate-limit observability and runtime configuration (DESIGN.md "Rate
//! limits: observability and runtime config").

use super::admin::require_admin;
use super::internal::HDR as INTERNAL_HDR;
use super::*;
use crate::ratelimit::config::Doc;
use crate::ratelimit::runtime::{self, SaveError, SaveReq};
use crate::ratelimit::{Consumer, NodeSnapshot, RejectionCount};
use std::collections::BTreeMap;
use std::time::Duration;

const RELOAD_TIMEOUT: Duration = Duration::from_secs(2);
const DEFAULT_TOP: usize = 10;
const MAX_TOP: usize = 50;

pub fn routes() -> Router<Arc<App>> {
    Router::new()
        .route("/xrpc/vlpds.admin.getRateLimits", get(get_rate_limits))
        .route("/xrpc/vlpds.admin.updateRateLimits", post(update_rate_limits))
}

pub fn internal_routes() -> Router<Arc<App>> {
    Router::new()
        .route("/internal/v1/ratelimits", get(internal_snapshot))
        .route("/internal/v1/ratelimits/reload", post(internal_reload))
}

/// Idempotent. Runs under `--no-rate-limits` too, so the console shows and
/// edits the cluster's config from any node.
pub fn start(app: &Arc<App>) {
    runtime::spawn_refresher(&app.ratelimit, app.store.clone());
    crate::ratelimit::mail_budget::spawn_refresher(&app.ratelimit, app.store.clone());
}

fn node_id(app: &App) -> String {
    app.cluster.as_ref().map(|c| c.cfg.node_id.clone()).unwrap_or_else(|| "single".into())
}

#[derive(Deserialize)]
struct TopQ {
    top: Option<usize>,
    #[serde(default)]
    local: bool,
}

/// The buckets in force on this node, with their defaults (`defaults`:
/// this node's, flags included).
fn limiter_rows(p: &crate::ratelimit::Policy, defaults: &crate::ratelimit::Policy) -> Vec<J> {
    p.specs()
        .map(|s| {
            let def = crate::ratelimit::BUILTIN.iter().find(|l| *l.name == *s.name).map(|l| defaults.builtin(l));
            json!({
                "name": &*s.name,
                "key": s.key,
                "scope": &*s.scope,
                "windowSecs": s.window_ms / 1000,
                "points": s.points,
                "enabled": s.enabled,
                "custom": def.is_none(),
                "default": def.map(|d| json!({"windowSecs": d.window_ms / 1000, "points": d.points})),
            })
        })
        .collect()
}

fn node_row(s: &NodeSnapshot, me: &str, reachable: bool) -> J {
    json!({
        "node": s.node,
        "self": s.node == me,
        "reachable": reachable,
        "enabledByFlag": s.enabled_by_flag,
        "configVersion": s.config_version,
        "configError": s.config_error,
        "loadedAtMs": s.loaded_at_ms,
        "checkedAtMs": s.checked_at_ms,
        "liveWindows": s.live_windows,
    })
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct ClusterConsumer {
    key: String,
    /// Summed over nodes (counters are per node), except the cluster
    /// budget's, which every node reads from the bucket.
    used: u32,
    /// What a node's limit is checked against.
    max_node_used: u32,
    limit: Option<u32>,
    reset_ms: u64,
    nodes: Vec<String>,
}

/// Heaviest first.
fn merge_top(snaps: &[NodeSnapshot], n: usize) -> BTreeMap<String, Vec<ClusterConsumer>> {
    let mut by: BTreeMap<String, BTreeMap<String, ClusterConsumer>> = BTreeMap::new();
    for s in snaps {
        for (bucket, list) in &s.top {
            let m = by.entry(bucket.clone()).or_default();
            for Consumer { key, used, limit, reset_ms } in list {
                let c = m.entry(key.clone()).or_insert_with(|| ClusterConsumer {
                    key: key.clone(),
                    used: 0,
                    max_node_used: 0,
                    limit: *limit,
                    reset_ms: *reset_ms,
                    nodes: Vec::new(),
                });
                c.used =
                    if key == crate::ratelimit::CLUSTER_KEY { c.used.max(*used) } else { c.used.saturating_add(*used) };
                c.max_node_used = c.max_node_used.max(*used);
                c.reset_ms = c.reset_ms.max(*reset_ms);
                c.nodes.push(s.node.clone());
            }
        }
    }
    by.into_iter()
        .map(|(b, m)| {
            let mut v: Vec<ClusterConsumer> = m.into_values().collect();
            v.sort_by(|a, b| b.used.cmp(&a.used).then_with(|| a.key.cmp(&b.key)));
            v.truncate(n);
            (b, v)
        })
        .collect()
}

/// By (bucket, route).
fn merge_rejections(snaps: &[NodeSnapshot]) -> Vec<RejectionCount> {
    let mut m: BTreeMap<(String, String), RejectionCount> = BTreeMap::new();
    for s in snaps {
        for r in &s.rejections {
            let e = m.entry((r.limiter.clone(), r.route.clone())).or_insert_with(|| RejectionCount {
                limiter: r.limiter.clone(),
                route: r.route.clone(),
                ..Default::default()
            });
            e.last1m += r.last1m;
            e.last5m += r.last5m;
            e.last15m += r.last15m;
            e.total += r.total;
        }
    }
    let mut v: Vec<RejectionCount> = m.into_values().collect();
    v.sort_by(|a, b| b.last5m.cmp(&a.last5m).then(b.total.cmp(&a.total)));
    v
}

async fn get_rate_limits(State(app): AppState, Auth(creds): Auth, Query(q): Query<TopQ>) -> XResult<Json<J>> {
    require_admin(&creds)?;
    let n = q.top.unwrap_or(DEFAULT_TOP).clamp(1, MAX_TOP);
    let me = node_id(&app);
    let limiter = &app.ratelimit;
    let mine = limiter.snapshot(&me, n);
    let mut snaps = vec![mine];
    let mut nodes = vec![node_row(&snaps[0], &me, true)];
    let mut unreachable = Vec::new();
    if !q.local {
        let g = internal::gather(&app, "/internal/v1/ratelimits", &[("top", n.to_string())]).await;
        for r in g.replies {
            match serde_json::from_value::<NodeSnapshot>(r.body) {
                Ok(s) => {
                    nodes.push(node_row(&s, &me, true));
                    snaps.push(s);
                }
                Err(e) => {
                    tracing::warn!(peer = %r.node, "rate-limit snapshot unreadable: {e}");
                    unreachable.push(r.node);
                }
            }
        }
        unreachable.extend(g.unreachable);
        for u in &unreachable {
            nodes.push(json!({"node": u, "self": false, "reachable": false}));
        }
    }
    nodes.sort_by(|a, b| a["node"].as_str().cmp(&b["node"].as_str()));
    let policy = limiter.policy();
    let st = limiter.runtime.status();
    let mut out = json!({
        "node": me,
        "enabledByFlag": limiter.enabled_by_flag,
        "enabled": policy.enabled,
        "configVersion": policy.version,
        "config": st.doc,
        "configError": st.error,
        "refreshSecs": runtime::REFRESH_EVERY.as_secs(),
        "limiters": limiter_rows(&policy, &limiter.defaults()),
        "nodes": nodes,
        "top": merge_top(&snaps, n),
        "rejections": merge_rejections(&snaps),
        "time": crate::ratelimit::now_ms(),
    });
    if !unreachable.is_empty() {
        out["unreachableNodes"] = json!(unreachable);
    }
    Ok(Json(out))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateIn {
    config: J,
    if_version: u64,
    actor: Option<String>,
    note: Option<String>,
}

/// The caller's address for the audit entry.
pub struct PeerIp(Option<std::net::IpAddr>);

impl axum::extract::FromRequestParts<Arc<App>> for PeerIp {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        app: &Arc<App>,
    ) -> Result<Self, Self::Rejection> {
        Ok(PeerIp(crate::ratelimit::request_client_ip(&parts.headers, &parts.extensions, &app.ratelimit.trusted)))
    }
}

fn upstream_failure(message: String) -> XrpcError {
    XrpcError { status: StatusCode::BAD_GATEWAY, error: "UpstreamFailure".into(), message }
}

fn save_error(e: SaveError) -> XrpcError {
    let message = e.to_string();
    match e {
        SaveError::Invalid(_) => XrpcError::bad("InvalidConfig", message),
        SaveError::Conflict { .. } => {
            XrpcError { status: StatusCode::CONFLICT, error: "ConfigConflict".into(), message }
        }
        SaveError::Store(_) => upstream_failure(message),
    }
}

async fn update_rate_limits(
    State(app): AppState,
    Auth(creds): Auth,
    PeerIp(peer): PeerIp,
    Json(inp): Json<UpdateIn>,
) -> XResult<Json<J>> {
    require_admin(&creds)?;
    let doc: Doc = serde_json::from_value(inp.config)
        .map_err(|e| XrpcError::bad("InvalidConfig", format!("invalid config: {e}")))?;
    let super::moderation::Who { actor, ip } = super::moderation::Who::of(&creds, inp.actor.as_deref(), peer);
    let me = node_id(&app);
    let req = SaveReq { doc, if_version: inp.if_version, actor, ip, node: me.clone(), note: inp.note };
    let saved = runtime::save(&app.ratelimit, &app.store, req).await.map_err(save_error)?;
    // peers also re-read within REFRESH_EVERY; this makes it now
    let mut applied = vec![json!({"node": me, "configVersion": app.ratelimit.policy().version, "ok": true})];
    if let Some(c) = &app.cluster {
        let peers: Vec<_> = c.peers().into_iter().filter(|l| l.node_id != me).collect();
        let sends = peers.into_iter().map(|l| {
            let app = app.clone();
            async move {
                let r = app
                    .http
                    .post(format!("{}/internal/v1/ratelimits/reload", l.addr.trim_end_matches('/')))
                    .header(INTERNAL_HDR, &app.config.internal_token)
                    .timeout(RELOAD_TIMEOUT)
                    .send()
                    .await
                    .and_then(|r| r.error_for_status());
                match r {
                    Ok(r) => {
                        let v: J = r.json().await.unwrap_or(J::Null);
                        json!({"node": l.node_id, "configVersion": v["configVersion"], "configError": v["configError"], "ok": true})
                    }
                    Err(e) => {
                        tracing::warn!(peer = %l.node_id, "rate-limit reload nudge failed (it re-reads on its own): {e}");
                        json!({"node": l.node_id, "ok": false, "error": e.to_string()})
                    }
                }
            }
        });
        applied.extend(futures::future::join_all(sends).await);
    }
    Ok(Json(json!({"version": saved.version, "config": saved, "nodes": applied})))
}

async fn internal_snapshot(State(app): AppState, headers: HeaderMap, Query(q): Query<TopQ>) -> XResult<Json<J>> {
    internal::check(&app, &headers)?;
    let n = q.top.unwrap_or(DEFAULT_TOP).clamp(1, MAX_TOP);
    let s = app.ratelimit.snapshot(&node_id(&app), n);
    Ok(Json(serde_json::to_value(s).map_err(XrpcError::from_err)?))
}

async fn internal_reload(State(app): AppState, headers: HeaderMap) -> XResult<Json<J>> {
    internal::check(&app, &headers)?;
    let l = &app.ratelimit;
    if let Err(e) = runtime::refresh(l, &app.store).await {
        return Err(upstream_failure(format!("{e:#}")));
    }
    let st = l.runtime.status();
    Ok(Json(json!({"node": node_id(&app), "configVersion": l.policy().version, "configError": st.error})))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(node: &str, top: &[(&str, &str, u32)], rej: &[(&str, &str, u64)]) -> NodeSnapshot {
        let mut s = NodeSnapshot { node: node.into(), ..Default::default() };
        for (b, k, used) in top {
            s.top.entry(b.to_string()).or_default().push(Consumer {
                key: k.to_string(),
                used: *used,
                limit: Some(100),
                reset_ms: 5,
            });
        }
        for (l, r, n) in rej {
            s.rejections.push(RejectionCount {
                limiter: l.to_string(),
                route: r.to_string(),
                last1m: *n,
                last5m: *n,
                last15m: *n,
                total: *n,
            });
        }
        s
    }

    #[test]
    fn merges_nodes() {
        let a = snap("a", &[("global-ip", "1.1.1.1", 50), ("global-ip", "2.2.2.2", 40)], &[("global-ip", "x.y.z", 3)]);
        let b = snap(
            "b",
            &[("global-ip", "2.2.2.2", 30), ("repo-write-hour", "did:plc:x", 9)],
            &[("global-ip", "x.y.z", 2), ("repo-write-hour", "x.y.w", 1)],
        );
        let t = merge_top(&[a.clone(), b.clone()], 10);
        let g = &t["global-ip"];
        assert_eq!((g[0].key.as_str(), g[0].used, g[0].max_node_used, g[0].nodes.len()), ("2.2.2.2", 70, 40, 2));
        assert_eq!((g[1].key.as_str(), g[1].used), ("1.1.1.1", 50));
        assert_eq!(t["repo-write-hour"][0].used, 9);
        assert_eq!(merge_top(&[a.clone(), b.clone()], 1)["global-ip"].len(), 1);
        // every node reports the cluster budget's one count
        let (x, y) = (
            snap("a", &[("mail-cluster-day", "cluster", 7)], &[]),
            snap("b", &[("mail-cluster-day", "cluster", 6)], &[]),
        );
        let c = &merge_top(&[x, y], 10)["mail-cluster-day"][0];
        assert_eq!((c.used, c.max_node_used), (7, 7));
        let r = merge_rejections(&[a, b]);
        assert_eq!((r[0].limiter.as_str(), r[0].route.as_str(), r[0].total), ("global-ip", "x.y.z", 5));
        assert_eq!(r.len(), 2);
    }

    #[test]
    fn rows_list_builtins_then_routes() {
        let d: Doc =
            serde_json::from_value(json!({"routes": [{"nsid": "a.b.c", "points": 1, "windowSecs": 2}]})).unwrap();
        let p = crate::ratelimit::config::compile_with(Some(&d), 40).unwrap();
        let rows = limiter_rows(&p, &crate::ratelimit::Policy::defaults(40));
        assert_eq!(rows.len(), crate::ratelimit::BUILTIN.len() + 1);
        assert_eq!(rows[0]["name"], "global-ip");
        assert_eq!(rows[0]["default"]["points"], 3000);
        // the flag sets the cluster mail budget's default
        let mail = rows.iter().find(|r| r["name"] == "mail-cluster-day").unwrap();
        assert_eq!(
            (mail["points"].as_u64(), mail["default"]["points"].as_u64(), mail["key"].as_str()),
            (Some(40), Some(40), Some("cluster"))
        );
        let last = rows.last().unwrap();
        assert_eq!(
            (last["name"].as_str(), last["custom"].as_bool(), last["key"].as_str()),
            (Some("route:a.b.c"), Some(true), Some("ip"))
        );
    }
}
