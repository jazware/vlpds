//! `vlpds.admin.listFirehoseSubscribers`: who is connected to subscribeRepos.
//! Each node serves its own subscribers, so the answering node gathers every
//! peer's list over the internal API, as getRateLimits does.

use super::admin::require_admin;
use super::*;
use vlsync_firehose::firehose::SubscriberView;

/// Subscribers in one answer (the counts cover them all).
const MAX_LISTED: usize = 500;

pub fn routes() -> Router<Arc<App>> {
    Router::new().route("/xrpc/vlpds.admin.listFirehoseSubscribers", get(list_subscribers))
}

pub fn internal_routes() -> Router<Arc<App>> {
    Router::new().route("/internal/v1/firehose/subscribers", get(internal_list))
}

fn node_id(app: &App) -> String {
    app.cluster.as_ref().map(|c| c.cfg.node_id.clone()).unwrap_or_else(|| "single".into())
}

#[derive(serde::Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NodeList {
    node: String,
    subscribers: Vec<SubscriberView>,
    recent: Vec<SubscriberView>,
    total: usize,
    backfilling: usize,
    /// Events this node's merger emitted (`vlpds_firehose_events_total`):
    /// the rate a caught-up subscriber keeps up with.
    events_emitted: u64,
    /// `vlpds_firehose_bytes_sent_total`
    bytes_sent: u64,
}

/// PTR and AS from the caches (never waiting on DNS or whois), and the relay a
/// verified PTR names when the connect-time hint had none.
fn annotate(app: &App, s: &mut SubscriberView) {
    let Some(ip) = s.ip.as_deref().and_then(|i| i.parse::<std::net::IpAddr>().ok()) else { return };
    if let Some(p) = app.ptr.get(ip) {
        if s.relay.is_none() && p.verified {
            s.relay = app.crawlers.relay_hint(&app.store, Some(ip), &s.user_agent, p.name.as_deref());
        }
        s.ptr_verified = p.verified;
        s.ptr = p.name;
    }
    if let Some(a) = app.asn.get(ip) {
        s.asn = Some(a.asn);
        s.as_name = a.name;
        s.as_country = a.country;
    }
}

fn local(app: &App) -> NodeList {
    let (mut subscribers, mut recent) = app.firehose.subscribers();
    for s in subscribers.iter_mut().chain(recent.iter_mut()) {
        annotate(app, s);
    }
    let total = subscribers.len();
    let backfilling = subscribers.iter().filter(|s| s.state == "backfilling").count();
    subscribers.truncate(MAX_LISTED);
    NodeList {
        node: node_id(app),
        subscribers,
        recent,
        total,
        backfilling,
        events_emitted: vlsync_firehose::metrics::FIREHOSE_EVENTS.get(),
        bytes_sent: vlsync_firehose::metrics::FIREHOSE_SENT_BYTES.get(),
    }
}

async fn internal_list(State(app): AppState, headers: HeaderMap) -> XResult<Json<J>> {
    internal::check(&app, &headers)?;
    Ok(Json(serde_json::to_value(local(&app)).map_err(XrpcError::from_err)?))
}

fn tagged(node: &str, v: SubscriberView) -> J {
    let mut j = serde_json::to_value(v).unwrap_or(J::Null);
    j["node"] = json!(node);
    j
}

async fn list_subscribers(State(app): AppState, Auth(creds): Auth) -> XResult<Json<J>> {
    require_admin(&creds)?;
    let me = local(&app);
    let mut lists = vec![(me, true)];
    let mut unreachable = Vec::new();
    let g = internal::gather(&app, "/internal/v1/firehose/subscribers", &[]).await;
    for r in g.replies {
        match serde_json::from_value::<NodeList>(r.body) {
            Ok(l) => lists.push((l, false)),
            Err(e) => {
                tracing::warn!(peer = %r.node, "firehose subscriber list unreadable: {e}");
                unreachable.push(r.node);
            }
        }
    }
    unreachable.extend(g.unreachable);
    unreachable.extend(g.unsupported);
    let (mut subs, mut recent, mut nodes) = (Vec::new(), Vec::new(), Vec::new());
    let (mut total, mut backfilling) = (0, 0);
    for (l, is_self) in lists {
        total += l.total;
        backfilling += l.backfilling;
        nodes.push(json!({
            "node": l.node,
            "self": is_self,
            "reachable": true,
            "subscribers": l.total,
            "backfilling": l.backfilling,
            "eventsEmitted": l.events_emitted,
            "bytesSent": l.bytes_sent,
        }));
        subs.extend(l.subscribers.into_iter().map(|s| (s.connected_at, tagged(&l.node, s))));
        recent.extend(l.recent.into_iter().map(|s| (s.disconnected_at.unwrap_or(0), tagged(&l.node, s))));
    }
    for u in &unreachable {
        nodes.push(json!({"node": u, "self": false, "reachable": false}));
    }
    subs.sort_by_key(|(at, _)| *at);
    subs.truncate(MAX_LISTED);
    recent.sort_by_key(|(at, _)| std::cmp::Reverse(*at));
    recent.truncate(MAX_LISTED);
    let mut out = json!({
        "node": node_id(&app),
        "total": total,
        "live": total - backfilling,
        "backfilling": backfilling,
        "subscribers": subs.into_iter().map(|(_, s)| s).collect::<Vec<_>>(),
        "recentDisconnects": recent.into_iter().map(|(_, s)| s).collect::<Vec<_>>(),
        "nodes": nodes,
        "time": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64),
    });
    if !unreachable.is_empty() {
        out["unreachableNodes"] = json!(unreachable);
    }
    Ok(Json(out))
}
