//! Node-to-node endpoints, served only on the mTLS peer listener and
//! authenticated also by the shared internal token (DESIGN.md "Exposure").

use super::*;
use base64::Engine;
use vlsync_store::segment::Mutation;

pub(super) const HDR: &str = "x-vlpds-internal";
const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

pub fn routes() -> Router<Arc<App>> {
    Router::new()
        .route("/internal/v1/log/stream", get(stream))
        .route("/internal/v1/private/put", post(put_private))
        .route("/internal/v1/private/get", get(get_private))
        .route("/internal/v1/private/scan", get(scan_private))
        .route("/internal/v1/private/cas", post(private_cas))
        .route("/internal/v1/account", get(get_account))
        .route("/internal/v1/oauth/replay", post(claim_replay))
        .route("/internal/v1/cluster", get(cluster_status))
        .route("/internal/v1/cluster/nudge", post(cluster_nudge))
        .route("/internal/v1/cluster/hello", post(cluster_hello))
        .route(
            "/internal/v1/cluster/prewarm",
            post(cluster_prewarm).layer(axum::extract::DefaultBodyLimit::max(PREWARM_BODY_MAX)),
        )
        .route("/internal/v1/admin/searchAccounts", get(admin_search_accounts))
        .route("/internal/v1/admin/inviteCodes", get(admin_invite_codes))
        .route("/internal/v1/sync/listRepos", get(sync_list_repos))
        .route("/internal/v1/sync/listReposByCollection", get(sync_list_repos_by_collection))
        .merge(super::ratelimits::internal_routes())
        .merge(super::handle_domains::internal_routes())
        .merge(super::firehose_subs::internal_routes())
        .merge(super::changes::internal_routes())
        .merge(super::console::internal_routes())
        .merge(super::console_storage::internal_routes())
}

/// For HA tests and ops.
async fn cluster_status(State(app): AppState, headers: HeaderMap) -> XResult<Json<J>> {
    check(&app, &headers)?;
    let owned: Vec<vlsync_store::slots::ShardId> = app.partitions.owned().iter().map(|p| p.id).collect();
    let (node, table, peers, lease_valid) = match &app.cluster {
        Some(c) => (
            c.cfg.node_id.clone(),
            c.layout().shards.iter().map(|r| (r.id, c.owner_of(r.id).map(|(id, _)| id))).collect::<Vec<_>>(),
            c.peers()
                .into_iter()
                .map(|l| json!({"node": l.node_id, "log": l.log_id, "addr": l.addr}))
                .collect::<Vec<_>>(),
            c.lease_valid(),
        ),
        None => (String::new(), Vec::new(), Vec::new(), false),
    };
    Ok(Json(json!({
        "node": node,
        "log": app.log.log_id.to_string(),
        "log_durable_ordinal": app.log.durable_ordinal.load(std::sync::atomic::Ordering::Acquire),
        "owned": owned,
        // routing by shard id, in slot order (ids are stable names: a split
        // or merge replaces some with new ones)
        "table": table,
        "layout": app.cluster.as_ref().map(|c| {
            let l = c.layout();
            json!({"version": l.version, "shards": l.ids(), "op": l.op})
        }),
        "peers": peers,
        "lease_valid": lease_valid,
        "firehose_last_emitted": app.firehose.last_emitted.load(std::sync::atomic::Ordering::Acquire),
        "firehose_min_watermark": app.firehose.min_watermark(),
    })))
}

#[derive(serde::Serialize, Deserialize, Default)]
struct NudgeIn {
    #[serde(default)]
    handoffs: Vec<crate::cluster::Handoff>,
}

/// A peer handed us shards (adopt them now, no control-plane read) or
/// released some / left the cluster (step now instead of on the next tick).
async fn cluster_nudge(
    State(app): AppState,
    headers: HeaderMap,
    axum::Json(inp): axum::Json<NudgeIn>,
) -> XResult<Json<J>> {
    check(&app, &headers)?;
    if let Some(c) = &app.cluster {
        c.nudge(inp.handoffs);
    }
    Ok(Json(json!({})))
}

/// What one prewarm request carries of the shards' recent repos, in JSON
/// bytes: about 30k plc DIDs, more than a recipient warms before its
/// deadline (`node::HANDOFF_WARM_MAX`).
pub const PREWARM_RECENT_BYTES: usize = 1 << 20;
/// [`PREWARM_RECENT_BYTES`] plus a few dozen bytes of framing per shard.
const PREWARM_BODY_MAX: usize = 4 << 20;

#[derive(serde::Serialize, Deserialize)]
pub struct PrewarmShard {
    pub shard: vlsync_store::slots::ShardId,
    /// Its recently written repos, newest first.
    #[serde(default)]
    pub recent: Vec<String>,
}

/// `shards` with their recent repos (each newest first) cut to
/// [`PREWARM_RECENT_BYTES`] in all, taken rank by rank across the shards:
/// the order `Node::warm_handoff` warms them in, so the cut is what the
/// recipient would reach last.
pub fn prewarm_request(shards: Vec<(vlsync_store::slots::ShardId, Vec<String>)>) -> Vec<PrewarmShard> {
    let mut out: Vec<PrewarmShard> =
        shards.iter().map(|(s, _)| PrewarmShard { shard: *s, recent: Vec::new() }).collect();
    let mut lists: Vec<std::vec::IntoIter<String>> = shards.into_iter().map(|(_, r)| r.into_iter()).collect();
    let mut left = PREWARM_RECENT_BYTES;
    loop {
        let mut more = false;
        for (o, l) in out.iter_mut().zip(lists.iter_mut()) {
            let Some(d) = l.next() else { continue };
            // quotes and a comma; a DID needs no escaping
            let cost = d.len() + 3;
            if cost > left {
                return out;
            }
            left -= cost;
            o.recent.push(d);
            more = true;
        }
        if !more {
            return out;
        }
    }
}

#[derive(serde::Serialize, Deserialize)]
struct PrewarmIn {
    shards: Vec<PrewarmShard>,
}

/// A peer is about to hand us these shards: warm our caches from their
/// state while it still serves them (`Node::warm_handoff`). Answers once
/// done or out of time.
async fn cluster_prewarm(
    State(app): AppState,
    headers: HeaderMap,
    axum::Json(inp): axum::Json<PrewarmIn>,
) -> XResult<Json<J>> {
    check(&app, &headers)?;
    app.node.warm_handoff(inp.shards).await;
    Ok(Json(json!({})))
}

/// Asks each recipient to warm the shards it is about to get (built by
/// [`prewarm_request`]), and waits (each at most `timeout`). A recipient
/// that doesn't answer starts cold and the handoff goes on; that is logged
/// and counted. Each recipient's outcome.
pub async fn prewarm_peers(
    http: &crate::http::PeerClient,
    token: &str,
    plan: Vec<(String, Vec<PrewarmShard>)>,
    timeout: std::time::Duration,
) -> Vec<(String, Result<(), String>)> {
    let sends = plan.into_iter().map(|(addr, shards)| async move {
        let n = shards.len() as u64;
        let r = http
            .post(format!("{}/internal/v1/cluster/prewarm", addr.trim_end_matches('/')))
            .header(HDR, token)
            .json(&PrewarmIn { shards })
            .timeout(timeout)
            .send()
            .await
            .and_then(|r| r.error_for_status());
        let r = match r {
            Ok(_) => {
                crate::metrics::SHARD_PREWARMS.with_label_values(&["ok"]).inc_by(n);
                Ok(())
            }
            Err(e) => {
                crate::metrics::SHARD_PREWARMS.with_label_values(&["failed"]).inc_by(n);
                tracing::warn!(%addr, shards = n, "handoff prewarm failed, the recipient starts them cold: {e}");
                Err(e.to_string())
            }
        };
        (addr, r)
    });
    futures::future::join_all(sends).await
}

#[derive(serde::Serialize, Deserialize)]
struct HelloIn {
    node_id: String,
    /// Informational: the joiner's lease is authoritative.
    rev: String,
    min_level: u32,
    max_level: u32,
}

fn note_peer_build(peer: &str, rev: &str, min: u32, max: u32, ours: vlsync_store::version::Window) {
    let window = (min, max);
    if window != (ours.min, ours.max) || rev != crate::build::rev() {
        tracing::info!(
            peer,
            rev,
            min_level = window.0,
            max_level = window.1,
            our_rev = crate::build::rev(),
            our_min = ours.min,
            our_max = ours.max,
            "peer runs a different build"
        );
    }
}

/// A joiner greets us: learn its lease and follow its log now (see
/// `Cluster::learn_peer`). 200 `{"ok": true, "floor": F}` once we do: we
/// deliver every event of its log with seq > F to our merged firehose.
async fn cluster_hello(
    State(app): AppState,
    headers: HeaderMap,
    axum::Json(inp): axum::Json<HelloIn>,
) -> XResult<Json<J>> {
    check(&app, &headers)?;
    let Some(c) = &app.cluster else {
        return Ok(Json(json!({"ok": false})));
    };
    note_peer_build(&inp.node_id, &inp.rev, inp.min_level, inp.max_level, c.cfg.levels);
    let host: Arc<dyn crate::cluster::ShardHost> = app.node.clone();
    let floor = c.learn_peer(&host, &inp.node_id).await.map_err(XrpcError::from_err)?;
    Ok(Json(json!({
        "ok": floor.is_some(), "floor": floor,
        "rev": crate::build::rev(), "minLevel": c.cfg.levels.min, "maxLevel": c.cfg.levels.max,
    })))
}

/// Per peer, the floor of its follower of our log, or None if it didn't
/// confirm.
pub async fn hello_peers(
    http: &crate::http::PeerClient,
    token: &str,
    node_id: &str,
    levels: vlsync_store::version::Window,
    addrs: Vec<String>,
) -> Vec<Option<i64>> {
    let sends = addrs.into_iter().map(|addr| async move {
        let hello = HelloIn {
            node_id: node_id.to_string(),
            rev: crate::build::rev().to_string(),
            min_level: levels.min,
            max_level: levels.max,
        };
        let r = http
            .post(format!("{}/internal/v1/cluster/hello", addr.trim_end_matches('/')))
            .header(HDR, token)
            .json(&hello)
            .timeout(std::time::Duration::from_secs(2))
            .send()
            .await
            .and_then(|r| r.error_for_status());
        match r {
            Ok(r) => {
                let v = r.json::<J>().await.ok()?;
                let level = |k: &str| v[k].as_u64().unwrap_or(0) as u32;
                note_peer_build(
                    &addr,
                    v["rev"].as_str().unwrap_or_default(),
                    level("minLevel"),
                    level("maxLevel"),
                    levels,
                );
                (v["ok"] == json!(true)).then(|| v["floor"].as_i64()).flatten()
            }
            Err(e) => {
                tracing::debug!(%addr, "hello failed: {e}");
                None
            }
        }
    });
    futures::future::join_all(sends).await
}

/// Best effort: a peer that misses one finds its handoffs on its next step.
pub async fn nudge_peers(
    http: &crate::http::PeerClient,
    token: &str,
    nudges: Vec<(String, Vec<crate::cluster::Handoff>)>,
) {
    let sends = nudges.into_iter().map(|(addr, handoffs)| async move {
        let r = http
            .post(format!("{}/internal/v1/cluster/nudge", addr.trim_end_matches('/')))
            .header(HDR, token)
            .json(&NudgeIn { handoffs })
            .timeout(std::time::Duration::from_secs(1))
            .send()
            .await
            .and_then(|r| r.error_for_status());
        if let Err(e) = r {
            crate::metrics::CLUSTER_NUDGES.with_label_values(&["failed"]).inc();
            tracing::warn!(%addr, "nudge failed: {e}");
        }
    });
    futures::future::join_all(sends).await;
}

pub(super) fn check(app: &App, headers: &HeaderMap) -> XResult<()> {
    let t = headers.get(HDR).and_then(|v| v.to_str().ok()).unwrap_or("");
    if internal_token_ok(&app.config, t) {
        Ok(())
    } else {
        Err(XrpcError::auth("internal endpoint"))
    }
}

/// Dev mode also accepts the admin token.
pub fn internal_token_ok(cfg: &crate::server::Config, t: &str) -> bool {
    vlatproto::xrpc::token_eq(&cfg.internal_token, t)
        || (cfg.dev_mode && vlatproto::xrpc::token_eq(&cfg.admin_token, t))
}

#[derive(Deserialize)]
struct StreamQ {
    log: Option<String>,
}

async fn stream(
    State(app): AppState,
    headers: HeaderMap,
    Query(q): Query<StreamQ>,
    ws: WebSocketUpgrade,
) -> XResult<Response> {
    check(&app, &headers)?;
    // A restarted node keeps its address: a peer still following its previous
    // log must not get the new log's batches under the old id (they would be
    // merged twice).
    if let Some(want) = &q.log {
        if **want != *app.log.log_id {
            return Err(XrpcError::bad("WrongLog", format!("this node serves log {}, not {want}", app.log.log_id)));
        }
    }
    if app.log.closed.load(std::sync::atomic::Ordering::Acquire) {
        // fenced on shutdown: the follower drains it from S3
        return Err(XrpcError {
            status: StatusCode::GONE,
            error: "LogClosed".into(),
            message: format!("log {} is fenced", app.log.log_id),
        });
    }
    let log = app.log.clone();
    Ok(ws.on_upgrade(move |socket| crate::remote::serve_stream(socket, log)))
}

#[derive(serde::Serialize, Deserialize)]
struct PutIn {
    routing: String,
    muts: Vec<(String, Option<String>)>,
}

// node-to-node: axum's 2 MB body limit, not the 150 KiB XRPC one
async fn put_private(State(app): AppState, headers: HeaderMap, axum::Json(inp): axum::Json<PutIn>) -> XResult<Json<J>> {
    check(&app, &headers)?;
    let muts = inp
        .muts
        .into_iter()
        .map(|(k, v)| {
            let key = B64.decode(k).map_err(XrpcError::from_err)?;
            // only the routing key's own private state (p/{routing}\0...),
            // never repo data, heads or another account's state
            if !key.starts_with(&state::private_prefix(&inp.routing)) {
                return Err(XrpcError::bad("InvalidRequest", "key outside the routing key's private state"));
            }
            Ok(Mutation { key: key.into(), val: b64_opt(v)? })
        })
        .collect::<XResult<Vec<_>>>()?;
    // must be local now (no forwarding loops)
    app.partition(&inp.routing)?;
    let sec = state::private_key(&inp.routing, super::server::SEC);
    let touches_sec = muts.iter().any(|m| m.key.starts_with(&sec));
    let keys: Vec<Mutation> = muts.iter().map(|m| Mutation { key: m.key.clone(), val: None }).collect();
    app.put_private(&inp.routing, muts).await?;
    if touches_sec {
        // a revocation/takedown written from another node: drop our view
        super::server::ctl_changed(&app, &inp.routing);
        super::space::sec_written(&app, &inp.routing, &keys).await;
    }
    Ok(Json(json!({})))
}

#[derive(serde::Serialize, Deserialize)]
struct CasIn {
    routing: String,
    /// (name, expected value: None = absent), base64
    conds: Vec<(String, Option<String>)>,
    /// (name, value: None = delete), base64
    puts: Vec<(String, Option<String>)>,
    #[serde(default)]
    delete_prefixes: Vec<String>,
}

fn b64_opt(v: Option<String>) -> XResult<Option<Bytes>> {
    v.map(|v| B64.decode(v).map(Bytes::from)).transpose().map_err(XrpcError::from_err)
}

async fn private_cas(State(app): AppState, headers: HeaderMap, axum::Json(inp): axum::Json<CasIn>) -> XResult<Json<J>> {
    use super::cas::{Cond, Op};
    check(&app, &headers)?;
    let conds =
        inp.conds.into_iter().map(|(name, v)| Ok(Cond::Eq { name, val: b64_opt(v)? })).collect::<XResult<Vec<_>>>()?;
    let mut ops =
        inp.puts.into_iter().map(|(name, v)| Ok(Op::Put { name, val: b64_opt(v)? })).collect::<XResult<Vec<_>>>()?;
    ops.extend(inp.delete_prefixes.into_iter().map(|prefix| Op::DeletePrefix { prefix }));
    // must be local now (no forwarding loops)
    app.partition(&inp.routing)?;
    let out = super::cas::private_cas_local(&app, &inp.routing, conds, ops).await?;
    let deleted: Vec<(String, String)> = out.deleted.into_iter().map(|(n, v)| (n, B64.encode(v))).collect();
    Ok(Json(json!({"applied": out.applied, "deleted": deleted})))
}

/// [`App::private_cas`] sent to `owner`.
pub async fn forward_private_cas(
    app: &App,
    owner: &str,
    routing: &str,
    conds: Vec<super::cas::Cond>,
    ops: Vec<super::cas::Op>,
) -> XResult<super::cas::Outcome> {
    use super::cas::{Cond, Op};
    let enc = |v: Option<Bytes>| v.map(|v| B64.encode(v));
    let mut body =
        CasIn { routing: routing.to_string(), conds: Vec::new(), puts: Vec::new(), delete_prefixes: Vec::new() };
    for c in conds {
        let Cond::Eq { name, val } = c;
        body.conds.push((name, enc(val)));
    }
    for o in ops {
        match o {
            Op::Put { name, val } => body.puts.push((name, enc(val))),
            Op::DeletePrefix { prefix } => body.delete_prefixes.push(prefix),
        }
    }
    let r = send(
        app.http.post(format!("{owner}/internal/v1/private/cas")).header(HDR, &app.config.internal_token).json(&body),
    )
    .await?;
    #[derive(Deserialize)]
    struct Out {
        applied: bool,
        #[serde(default)]
        deleted: Vec<(String, String)>,
    }
    let out: Out = r.json().await.map_err(upstream)?;
    Ok(super::cas::Outcome {
        applied: out.applied,
        deleted: out
            .deleted
            .into_iter()
            .map(|(n, v)| Ok((n, Bytes::from(B64.decode(v).map_err(upstream)?))))
            .collect::<XResult<Vec<_>>>()?,
    })
}

#[derive(Deserialize)]
struct GetQ {
    routing: String,
    name: String,
}

async fn get_private(State(app): AppState, headers: HeaderMap, Query(q): Query<GetQ>) -> XResult<Json<J>> {
    check(&app, &headers)?;
    app.partition(&q.routing)?;
    let v = app.get_private(&q.routing, &q.name).await?;
    Ok(Json(json!({"value": v.map(|b| B64.encode(b))})))
}

#[derive(Deserialize)]
struct ScanQ {
    routing: String,
    prefix: String,
}

/// Unbounded: callers scan small per-account sets such as `sec/`.
async fn scan_private(State(app): AppState, headers: HeaderMap, Query(q): Query<ScanQ>) -> XResult<Json<J>> {
    check(&app, &headers)?;
    app.partition(&q.routing)?;
    let rows = super::server::scan_private(&app, &q.routing, &q.prefix).await?;
    let rows: Vec<(String, String)> = rows.into_iter().map(|(n, v)| (n, B64.encode(v))).collect();
    Ok(Json(json!({"rows": rows})))
}

#[derive(Deserialize)]
struct AccountQ {
    did: String,
}

async fn get_account(State(app): AppState, headers: HeaderMap, Query(q): Query<AccountQ>) -> XResult<Json<J>> {
    check(&app, &headers)?;
    app.partition(&q.did)?;
    let a = app.account(&q.did).await?;
    Ok(Json(serde_json::to_value(a).map_err(XrpcError::from_err)?))
}

#[derive(serde::Serialize, Deserialize)]
struct ReplayIn {
    routing: String,
    key: String,
    until: i64,
    #[serde(default)]
    release: bool,
    /// A guard released right after: memory only.
    #[serde(default)]
    transient: bool,
    /// [`claim_proof_anywhere`]'s holder.
    #[serde(default)]
    holder: u64,
}

async fn claim_replay(
    State(app): AppState,
    headers: HeaderMap,
    axum::Json(inp): axum::Json<ReplayIn>,
) -> XResult<Json<J>> {
    check(&app, &headers)?;
    app.partition(&inp.routing)?;
    if inp.release {
        crate::oauth::util::release_replay_local(&app, &inp.key);
        return Ok(Json(json!({})));
    }
    let fresh =
        crate::oauth::util::claim_replay_owned(&app, &inp.routing, &inp.key, inp.until, !inp.transient, inp.holder)
            .await?;
    Ok(Json(json!({"fresh": fresh})))
}

/// [`super::server::scan_private`] at the routing key's owner.
pub async fn scan_private_anywhere(app: &App, routing: &str, prefix: &str) -> XResult<Vec<(String, Bytes)>> {
    let Some(owner) = app.remote_owner(routing) else {
        return super::server::scan_private(app, routing, prefix).await;
    };
    let r = app
        .http
        .get(format!("{owner}/internal/v1/private/scan"))
        .header(HDR, &app.config.internal_token)
        .timeout(OWNER_CALL_TIMEOUT)
        .query(&[("routing", routing), ("prefix", prefix)])
        .send()
        .await
        .map_err(upstream)?;
    if r.status() == StatusCode::SERVICE_UNAVAILABLE {
        // the shard left the owner we routed to (or is reopening there): a
        // move under way, which callers wait out rather than take for an outage
        let body = r.text().await.unwrap_or_default();
        let code = serde_json::from_str::<J>(&body).ok().and_then(|v| v["error"].as_str().map(str::to_string));
        return Err(match code.as_deref() {
            Some(c @ (crate::forward::SHARD_MOVED | crate::forward::REPO_LOADING)) => {
                XrpcError::unavailable(c, format!("partition owner: {body}"))
            }
            _ => upstream(format!("503: {body}")),
        });
    }
    if !r.status().is_success() {
        return Err(upstream(format!("{}: {}", r.status(), r.text().await.unwrap_or_default())));
    }
    #[derive(Deserialize)]
    struct Rows {
        rows: Vec<(String, String)>,
    }
    let rows: Rows = r.json().await.map_err(upstream)?;
    rows.rows.into_iter().map(|(n, v)| Ok((n, Bytes::from(B64.decode(v).map_err(upstream)?)))).collect()
}

pub async fn account_anywhere(app: &App, did: &str) -> XResult<Account> {
    let Some(owner) = app.remote_owner(did) else {
        return app.account(did).await;
    };
    let r = app
        .http
        .get(format!("{owner}/internal/v1/account"))
        .header(HDR, &app.config.internal_token)
        .timeout(OWNER_CALL_TIMEOUT)
        .query(&[("did", did)])
        .send()
        .await
        // the URL names the DID (a space's authority or member)
        .map_err(|e| upstream(e.without_url()))?;
    if r.status().is_client_error() {
        // the owner's own error (AccountNotFound, ...)
        let status = r.status();
        let v: J = r.json().await.unwrap_or_default();
        return Err(XrpcError {
            status,
            error: v["error"].as_str().unwrap_or("InvalidRequest").into(),
            message: v["message"].as_str().unwrap_or_default().into(),
        });
    }
    if !r.status().is_success() {
        return Err(upstream(format!("{}: {}", r.status(), r.text().await.unwrap_or_default())));
    }
    r.json().await.map_err(|e| upstream(e.without_url()))
}

/// GET `path` at `owner`, another node: its own 4xx comes back as is,
/// anything else that isn't a 2xx (or no answer) as an [`upstream`] error.
pub async fn owner_get(app: &App, owner: &str, path: &str, query: &[(&str, &str)]) -> XResult<J> {
    let r = app
        .http
        .get(format!("{}{path}", owner.trim_end_matches('/')))
        .header(HDR, &app.config.internal_token)
        .timeout(OWNER_CALL_TIMEOUT)
        .query(query)
        .send()
        .await
        .map_err(|e| upstream(e.without_url()))?;
    if r.status().is_client_error() {
        let status = r.status();
        let v: J = r.json().await.unwrap_or_default();
        return Err(XrpcError {
            status,
            error: v["error"].as_str().unwrap_or("InvalidRequest").into(),
            message: v["message"].as_str().unwrap_or_default().into(),
        });
    }
    if !r.status().is_success() {
        return Err(upstream(format!("{}: {}", r.status(), r.text().await.unwrap_or_default())));
    }
    r.json().await.map_err(|e| upstream(e.without_url()))
}

/// Single-use claim of an OAuth replay `key` until `until` (unix secs), at
/// the owner of `routing` so every node agrees, and persisted so a later
/// owner agrees too. Ok(false) = replayed.
pub async fn claim_replay_anywhere(app: &App, routing: &str, key: &str, until: i64) -> XResult<bool> {
    replay_call(app, routing, key, until, false, false, 0).await
}

/// [`claim_replay_anywhere`] for a short guard released right after (in
/// memory at the owner only).
pub async fn claim_transient_anywhere(app: &App, routing: &str, key: &str, until: i64) -> XResult<bool> {
    replay_call(app, routing, key, until, false, true, 0).await
}

/// A resource server's DPoP proof (in memory at the owner only). A nonzero
/// `holder` names the client request the entry node resends
/// ([`crate::forward::Resend`]): its own claim, met again, is not a replay.
pub async fn claim_proof_anywhere(app: &App, routing: &str, key: &str, until: i64, holder: u64) -> XResult<bool> {
    replay_call(app, routing, key, until, false, true, holder).await
}

pub async fn release_replay_anywhere(app: &App, routing: &str, key: &str) -> XResult<()> {
    replay_call(app, routing, key, 0, true, true, 0).await.map(|_| ())
}

async fn replay_call(
    app: &App,
    routing: &str,
    key: &str,
    until: i64,
    release: bool,
    transient: bool,
    holder: u64,
) -> XResult<bool> {
    let Some(owner) = app.remote_owner(routing) else {
        app.partition(routing)?;
        if release {
            crate::oauth::util::release_replay_local(app, key);
            return Ok(true);
        }
        return crate::oauth::util::claim_replay_owned(app, routing, key, until, !transient, holder).await;
    };
    let body = ReplayIn { routing: routing.into(), key: key.into(), until, release, transient, holder };
    let r = send(
        app.http
            .post(format!("{owner}/internal/v1/oauth/replay"))
            .header(HDR, &app.config.internal_token)
            .timeout(OWNER_CALL_TIMEOUT)
            .json(&body),
    )
    .await?;
    let v: J = r.json().await.map_err(upstream)?;
    Ok(v["fresh"].as_bool().unwrap_or(false))
}

/// Auth checks wait on these owner lookups: a frozen owner fails the
/// request fast instead of holding it.
const OWNER_CALL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

fn upstream(e: impl std::fmt::Display) -> XrpcError {
    XrpcError::unavailable("PartitionUnavailable", format!("partition owner: {e}"))
}

/// A non-2xx answer is an [`upstream`] error.
async fn send(req: reqwest::RequestBuilder) -> XResult<reqwest::Response> {
    let r = req.send().await.map_err(upstream)?;
    if !r.status().is_success() {
        return Err(upstream(format!("{}: {}", r.status(), r.text().await.unwrap_or_default())));
    }
    Ok(r)
}

pub async fn forward_put_private(app: &App, owner: &str, routing: &str, muts: Vec<Mutation>) -> XResult<()> {
    let body = PutIn {
        routing: routing.to_string(),
        muts: muts.into_iter().map(|m| (B64.encode(&m.key), m.val.map(|v| B64.encode(v)))).collect(),
    };
    send(app.http.post(format!("{owner}/internal/v1/private/put")).header(HDR, &app.config.internal_token).json(&body))
        .await?;
    Ok(())
}

pub async fn forward_get_private(app: &App, owner: &str, routing: &str, name: &str) -> XResult<Option<Bytes>> {
    let r = send(
        app.http
            .get(format!("{owner}/internal/v1/private/get"))
            .header(HDR, &app.config.internal_token)
            .query(&[("routing", routing), ("name", name)]),
    )
    .await?;
    let v: J = r.json().await.map_err(upstream)?;
    v["value"].as_str().map(|s| B64.decode(s).map(Bytes::from).map_err(upstream)).transpose()
}

/// Per-peer deadline of a scatter-gather leg (a slower peer is reported as
/// unreachable).
const GATHER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

async fn admin_search_accounts(
    State(app): AppState,
    headers: HeaderMap,
    Query(q): Query<super::admin::SearchQ>,
) -> XResult<Json<J>> {
    check(&app, &headers)?;
    let (hits, owned) = super::admin::search_accounts_local(&app, &q).await?;
    Ok(Json(json!({"owned": owned, "accounts": hits})))
}

async fn admin_invite_codes(
    State(app): AppState,
    headers: HeaderMap,
    Query(q): Query<super::admin::InviteCodesQ>,
) -> XResult<Json<J>> {
    check(&app, &headers)?;
    let (codes, owned) = super::admin::invite_codes_local(&app, &q).await?;
    Ok(Json(json!({"owned": owned, "codes": codes})))
}

/// From this node's shards only (the cursor's shard must be ours: 503
/// otherwise, never forwarded again), in the public response shape.
async fn sync_list_repos(State(app): AppState, headers: HeaderMap, Query(q): Query<ListPageQ>) -> XResult<Response> {
    check(&app, &headers)?;
    let pos = super::sync::parse_list_cursor(&q.cursor)?;
    let limit = super::extract::limit_param(Some(q.limit), 500, 1, 1000)?;
    let (repos, next) = super::sync::list_repos_local(&app, pos, limit).await?;
    let page = super::sync::ReposPage::new(repos, next);
    Ok((
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        serde_json::to_vec(&page).map_err(XrpcError::from_err)?,
    )
        .into_response())
}

#[derive(Deserialize)]
struct ListPageQ {
    cursor: String,
    limit: i64,
}

/// The raw body of the owner's listRepos page.
pub async fn owner_list_repos(app: &App, owner: &str, cursor: &str, limit: usize) -> XResult<Bytes> {
    let r = send(
        app.http
            .get(format!("{}/internal/v1/sync/listRepos", owner.trim_end_matches('/')))
            .header(HDR, &app.config.internal_token)
            .query(&[("cursor", cursor), ("limit", &limit.to_string())])
            .timeout(GATHER_TIMEOUT),
    )
    .await?;
    r.bytes().await.map_err(upstream)
}

async fn sync_list_repos_by_collection(
    State(app): AppState,
    headers: HeaderMap,
    Query(q): Query<super::sync::ByCollectionQ>,
) -> XResult<Json<J>> {
    check(&app, &headers)?;
    let (repos, owned) = super::sync::list_repos_by_collection_local(&app, &q).await?;
    Ok(Json(json!({"owned": owned, "repos": repos})))
}

pub struct PeerReply {
    pub node: String,
    /// Shards the peer scanned.
    pub owned: Vec<vlsync_store::slots::ShardId>,
    pub body: J,
}

#[derive(Default)]
pub struct Gathered {
    pub replies: Vec<PeerReply>,
    pub unreachable: Vec<String>,
    /// Peers that answered 404: their build lacks the endpoint (a rolling
    /// deploy), which is not "unreachable".
    pub unsupported: Vec<String>,
}

enum LegError {
    Unsupported,
    Failed(String),
}

/// GETs `path?query` on every live peer concurrently.
pub async fn gather(app: &App, path: &str, query: &[(&str, String)]) -> Gathered {
    let Some(c) = &app.cluster else {
        return Gathered::default();
    };
    let me = c.cfg.node_id.clone();
    let mut peers: Vec<_> = c.peers().into_iter().filter(|l| l.node_id != me).collect();
    peers.sort_by(|a, b| a.node_id.cmp(&b.node_id));
    let legs = peers.into_iter().map(|l| async move {
        let r = async {
            let r = app
                .http
                .get(format!("{}{path}", l.addr.trim_end_matches('/')))
                .header(HDR, &app.config.internal_token)
                .query(query)
                .timeout(GATHER_TIMEOUT)
                .send()
                .await
                .map_err(|e| LegError::Failed(e.to_string()))?;
            if r.status() == StatusCode::NOT_FOUND {
                return Err(LegError::Unsupported);
            }
            if !r.status().is_success() {
                return Err(LegError::Failed(format!("{}: {}", r.status(), r.text().await.unwrap_or_default())));
            }
            r.json::<J>().await.map_err(|e| LegError::Failed(e.to_string()))
        }
        .await;
        (l.node_id, r)
    });
    let mut out = Gathered::default();
    for (node, r) in futures::future::join_all(legs).await {
        match r {
            Ok(body) => {
                let owned = serde_json::from_value(body["owned"].clone()).unwrap_or_default();
                out.replies.push(PeerReply { node, owned, body });
            }
            Err(LegError::Unsupported) => {
                tracing::warn!(peer = %node, path, "admin scatter-gather: peer's build lacks this endpoint (404): its shards are missing from the result");
                out.unsupported.push(node);
            }
            Err(LegError::Failed(e)) => {
                tracing::warn!(peer = %node, path, "admin scatter-gather: peer unreachable: {e}");
                out.unreachable.push(node);
            }
        }
    }
    out
}
