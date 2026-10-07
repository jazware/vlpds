//! The admin change feed (`vlpds.admin.subscribeChanges`,
//! docs/operations/admin-console.md "Change feed"): a server-sent event
//! stream of `{kind, id, version, node}` whenever something the console shows
//! changes, so an open console refetches exactly that instead of waiting for
//! its next poll. It names what changed, never the change itself: the
//! console reads the entity back through the usual admin calls.
//!
//! Each node puts what changes on it on one bounded broadcast bus. The node
//! a console is connected to also follows every peer's bus over the peer
//! listener (`/internal/v1/admin/changes`), while at least one console
//! watches, and re-emits their changes on its own. A watcher that falls a
//! whole bus behind, or a peer stream that broke and came back, gets a
//! `resync`: the console then refetches everything it shows.

use super::admin::require_admin;
use super::moderation::AuditEntry;
use super::*;
use std::collections::HashMap;
use std::sync::atomic::AtomicUsize;
use std::time::Duration;
use tokio::sync::broadcast;

/// Changes buffered per watcher before it lags into a `resync`.
const BUS: usize = 1024;
/// Repeats of one entity within this window go out once.
const COALESCE: Duration = Duration::from_millis(100);
/// A comment line (SSE) or an empty line (peer stream) when nothing else
/// was sent, so proxies keep the stream open and a dead one is noticed.
const PING: Duration = Duration::from_secs(15);
/// A peer stream silent this long is dead: reconnect.
const PEER_IDLE: Duration = Duration::from_secs(45);
/// Peer streams stay up this long after the last console left (a reload).
const LINGER: Duration = Duration::from_secs(30);
/// How often the relay checks the peer list and the cluster's shape.
const TICK: Duration = Duration::from_secs(1);
/// Peer streams outlive the peer client's 15 s request deadline; a stream
/// cut at this one reconnects with a resync.
const PEER_STREAM_MAX: Duration = Duration::from_secs(24 * 3600);

/// The kinds a change can have, and what `id` names for each.
pub const KINDS: &[(&str, &str)] = &[
    ("audit", "an audit entry's id"),
    ("account", "a DID: its row, status, handle, email, sessions, sign-ins, second factors or quota"),
    ("case", "a moderation case's id"),
    ("takedown", "a taken-down or restored subject (`did`, a record or space URI, or `did cid`)"),
    ("lockout", "a DID whose second-factor or email-code lock was set or cleared"),
    ("mail", "a mail log entry, `node:id`"),
    ("subscriber", "a firehose connection that connected or left, `node/conn`"),
    ("cluster", "`*`: leases, shard ownership or the layout changed"),
    ("shard", "a shard split, merged or aborted"),
    ("node", "a node an operator acted on"),
    ("domain", "a handle domain added or removed"),
    ("invite", "`*`: invite codes created, disabled or used"),
    ("config", "a cluster setting: `ratelimits`, `crawlers` or `featureLevel`"),
    ("ratelimits", "a node applied a new rate-limit config"),
    ("space", "a space's URI"),
    ("resync", "missed changes: refetch everything"),
];

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, Deserialize)]
pub struct Change {
    pub kind: String,
    pub id: String,
    /// Orders changes to one entity: its own version where it has one (the
    /// rate-limit config's), else the change's time in unix ms.
    pub version: u64,
    /// The node it happened on.
    pub node: String,
}

pub struct Changes {
    node: String,
    tx: broadcast::Sender<Arc<Change>>,
    /// Consoles connected to this node.
    watchers: AtomicUsize,
    relay: parking_lot::Mutex<Option<tokio::task::JoinHandle<()>>>,
}

pub fn now_ms() -> u64 {
    crate::tid::now_micros() / 1000
}

impl Changes {
    pub fn new(node: impl Into<String>) -> Arc<Changes> {
        Arc::new(Changes {
            node: node.into(),
            tx: broadcast::channel(BUS).0,
            watchers: AtomicUsize::new(0),
            relay: Default::default(),
        })
    }

    /// Cheap with nobody watching: the send finds no receiver.
    pub fn emit(&self, kind: &str, id: impl Into<String>, version: u64) {
        let _ = self.tx.send(Arc::new(Change { kind: kind.into(), id: id.into(), version, node: self.node.clone() }));
    }

    pub fn account(&self, did: &str) {
        self.emit("account", did, now_ms());
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Arc<Change>> {
        self.tx.subscribe()
    }

    fn relayed(&self, c: Change) {
        let _ = self.tx.send(Arc::new(c));
    }

    pub fn watchers(&self) -> usize {
        self.watchers.load(Ordering::Acquire)
    }

    /// An audit entry and what it names.
    pub fn audited(&self, e: &AuditEntry) {
        for (kind, id, version) in from_audit(e) {
            self.emit(kind, id, version);
        }
    }
}

/// The changes an audit entry stands for: itself, its subject (and the
/// subject's account), its case, and what its action touches.
pub fn from_audit(e: &AuditEntry) -> Vec<(&'static str, String, u64)> {
    let at = u64::from_str_radix(e.id.split('-').next().unwrap_or(""), 16).map_or_else(|_| now_ms(), |us| us / 1000);
    let mut out = vec![("audit", e.id.clone(), at)];
    if let Some(s) = &e.subject {
        let id = s.id.clone().unwrap_or_default();
        match s.kind.as_str() {
            "shard" => out.push(("shard", id, at)),
            "node" => out.push(("node", id, at)),
            "domain" => out.push(("domain", id, at)),
            "config" => {
                let v = e.detail.as_ref().and_then(|d| d["version"].as_u64()).filter(|_| id == "ratelimits");
                out.push(("config", id, v.unwrap_or(at)));
            }
            "space" | "spaceRepo" => out.push(("space", s.uri.clone().unwrap_or_default(), at)),
            _ => {}
        }
        if !s.did.is_empty() {
            out.push(("account", s.did.clone(), at));
        }
        if matches!(e.action.as_str(), "takedown" | "restore") {
            let key = match s.kind.as_str() {
                "record" | "space" => s.uri.clone().unwrap_or_default(),
                "blob" => format!("{} {}", s.did, s.cid.as_deref().unwrap_or("")),
                _ => s.did.clone(),
            };
            out.push(("takedown", key, at));
        }
        if e.action == "lockout.clear" {
            out.push(("lockout", s.did.clone(), at));
        }
    }
    if let Some(c) = &e.case_id {
        out.push(("case", c.clone(), at));
    }
    if e.action.starts_with("invites.") || e.action == "account.create" {
        out.push(("invite", "*".into(), at));
    }
    out
}

/// Hooks the sources that live outside the request path: firehose
/// connections and the mail log (process-wide, so every app in a test
/// process hears every mail).
pub fn attach(app: &Arc<App>) {
    let node = app.changes.node.clone();
    let weak = Arc::downgrade(&app.changes);
    app.firehose.on_subscribers(Box::new(move |conn| {
        if let Some(c) = weak.upgrade() {
            c.emit("subscriber", format!("{node}/{conn}"), now_ms());
        }
    }));
    let node = app.changes.node.clone();
    let weak = Arc::downgrade(&app.changes);
    crate::mail::MAIL_LOG.watch(Box::new(move |id| match weak.upgrade() {
        Some(c) => {
            c.emit("mail", format!("{node}:{id}"), now_ms());
            true
        }
        None => false,
    }));
}

pub fn routes() -> Router<Arc<App>> {
    Router::new().route("/xrpc/vlpds.admin.subscribeChanges", get(subscribe_changes))
}

pub fn internal_routes() -> Router<Arc<App>> {
    Router::new().route("/internal/v1/admin/changes", get(internal_changes))
}

/// Counts a console for as long as its stream lives.
struct Watching(Arc<App>);

impl Watching {
    fn new(app: &Arc<App>) -> Watching {
        app.changes.watchers.fetch_add(1, Ordering::AcqRel);
        start_relay(app);
        Watching(app.clone())
    }
}

impl Drop for Watching {
    fn drop(&mut self) {
        self.0.changes.watchers.fetch_sub(1, Ordering::AcqRel);
    }
}

fn sse_data(c: &Change) -> String {
    format!("data: {}\n\n", serde_json::to_string(c).unwrap_or_default())
}

/// `vlpds.admin.subscribeChanges`: `text/event-stream`. A `hello` event
/// first, then one `data:` message per change, coalesced over 100 ms, and a
/// comment every 15 s. Ends when the node drains.
async fn subscribe_changes(State(app): AppState, Auth(creds): Auth) -> XResult<Response> {
    require_admin(&creds)?;
    let watching = Watching::new(&app);
    let rx = app.changes.subscribe();
    let hello = json!({
        "node": app.changes.node,
        "time": now_ms(),
        "peers": peer_ids(&app),
        "kinds": KINDS.iter().map(|(k, _)| *k).collect::<Vec<_>>(),
    });
    let (out, body) = tokio::sync::mpsc::channel::<Result<Bytes, std::convert::Infallible>>(64);
    let first = format!("retry: 2000\nevent: hello\ndata: {hello}\n\n");
    let _ = out.try_send(Ok(Bytes::from(first)));
    let drain = app.http_drain.clone();
    tokio::spawn(async move {
        let _w = watching;
        pump(rx, &out, drain, sse_data, Some(": ping\n\n"), None).await;
    });
    let stream = futures::stream::unfold(body, |mut rx| async move { rx.recv().await.map(|b| (b, rx)) });
    Ok((
        [
            (header::CONTENT_TYPE, "text/event-stream"),
            (header::CACHE_CONTROL, "no-store"),
            // nginx and the like buffer a response unless told not to
            (axum::http::HeaderName::from_static("x-accel-buffering"), "no"),
        ],
        Body::from_stream(stream),
    )
        .into_response())
}

/// Moves changes from the bus to one stream until it closes or the node
/// drains: coalesced, a `resync` after lagging, `ping` when idle. `only`
/// keeps changes from that node alone (a peer stream sends its own).
async fn pump(
    mut rx: broadcast::Receiver<Arc<Change>>,
    out: &tokio::sync::mpsc::Sender<Result<Bytes, std::convert::Infallible>>,
    drain: crate::server::Drain,
    fmt: fn(&Change) -> String,
    ping: Option<&'static str>,
    only: Option<&str>,
) {
    let mut pending: Vec<Change> = Vec::new();
    let mut at: HashMap<(String, String), usize> = HashMap::new();
    let mut flush_at: Option<tokio::time::Instant> = None;
    let mut idle = tokio::time::interval_at(tokio::time::Instant::now() + PING, PING);
    let draining = drain.draining();
    tokio::pin!(draining);
    loop {
        let wake = flush_at.unwrap_or_else(|| tokio::time::Instant::now() + PING * 4);
        tokio::select! {
            r = rx.recv() => match r {
                Ok(c) => {
                    if only.is_some_and(|n| c.node != n) {
                        continue;
                    }
                    let k = (c.kind.clone(), c.id.clone());
                    match at.get(&k) {
                        Some(&i) => pending[i].version = pending[i].version.max(c.version),
                        None => {
                            at.insert(k, pending.len());
                            pending.push((*c).clone());
                        }
                    }
                    flush_at.get_or_insert_with(|| tokio::time::Instant::now() + COALESCE);
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    tracing::debug!(missed = n, "admin change feed: a watcher lagged, sending resync");
                    pending.clear();
                    at.clear();
                    let node = only.map(str::to_string).unwrap_or_default();
                    pending.push(Change { kind: "resync".into(), id: String::new(), version: now_ms(), node });
                    flush_at = Some(tokio::time::Instant::now());
                }
                Err(broadcast::error::RecvError::Closed) => return,
            },
            _ = tokio::time::sleep_until(wake), if flush_at.is_some() => {
                let text: String = pending.drain(..).map(|c| fmt(&c)).collect();
                at.clear();
                flush_at = None;
                if out.send(Ok(Bytes::from(text))).await.is_err() {
                    return;
                }
                idle.reset();
            }
            _ = idle.tick() => {
                if let Some(p) = ping {
                    if out.send(Ok(Bytes::from_static(p.as_bytes()))).await.is_err() {
                        return;
                    }
                }
            }
            _ = out.closed() => return,
            _ = &mut draining => return,
        }
    }
}

fn peer_ids(app: &App) -> Vec<String> {
    let Some(c) = &app.cluster else { return Vec::new() };
    let mut v: Vec<String> = c.peers().into_iter().map(|l| l.node_id).filter(|n| *n != c.cfg.node_id).collect();
    v.sort();
    v
}

/// A peer's console follows this node's own changes: one JSON line each,
/// an empty line when idle.
async fn internal_changes(State(app): AppState, headers: HeaderMap) -> XResult<Response> {
    internal::check(&app, &headers)?;
    let rx = app.changes.subscribe();
    let (out, body) = tokio::sync::mpsc::channel::<Result<Bytes, std::convert::Infallible>>(64);
    let drain = app.http_drain.clone();
    let me = app.changes.node.clone();
    tokio::spawn(async move {
        let line = |c: &Change| format!("{}\n", serde_json::to_string(c).unwrap_or_default());
        pump(rx, &out, drain, line, Some("\n"), Some(&me)).await;
    });
    let stream = futures::stream::unfold(body, |mut rx| async move { rx.recv().await.map(|b| (b, rx)) });
    Ok(([(header::CONTENT_TYPE, "application/x-ndjson")], Body::from_stream(stream)).into_response())
}

/// Starts the relay unless it runs: it follows every peer and watches the
/// cluster's shape while consoles are connected, and stops [`LINGER`]
/// after the last one leaves.
fn start_relay(app: &Arc<App>) {
    let mut g = app.changes.relay.lock();
    if g.as_ref().is_some_and(|h| !h.is_finished()) {
        return;
    }
    let weak = Arc::downgrade(app);
    *g = Some(tokio::spawn(relay(weak)));
}

struct Leg {
    addr: String,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Leg {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn relay(app: std::sync::Weak<App>) {
    let mut legs: HashMap<String, Leg> = HashMap::new();
    let mut shape: Option<u64> = None;
    let mut unwatched_since: Option<Instant> = None;
    loop {
        let Some(app) = app.upgrade() else { return };
        if app.changes.watchers() == 0 {
            let since = *unwatched_since.get_or_insert_with(Instant::now);
            if since.elapsed() >= LINGER {
                return;
            }
        } else {
            unwatched_since = None;
        }
        if let Some(c) = &app.cluster {
            let peers: Vec<_> = c.peers().into_iter().filter(|l| l.node_id != c.cfg.node_id).collect();
            legs.retain(|node, leg| peers.iter().any(|l| l.node_id == *node && l.addr == leg.addr));
            for l in peers {
                if !legs.contains_key(&l.node_id) {
                    let task = tokio::spawn(follow(Arc::downgrade(&app), l.node_id.clone(), l.addr.clone()));
                    legs.insert(l.node_id, Leg { addr: l.addr, task });
                }
            }
            let now = cluster_shape(c);
            if shape.is_some_and(|s| s != now) {
                app.changes.emit("cluster", "*", c.layout().version);
            }
            shape = Some(now);
        }
        drop(app);
        tokio::time::sleep(TICK).await;
    }
}

/// Leases, their addresses and logs, shard owners and the layout, hashed:
/// what the console's cluster view is drawn from.
fn cluster_shape(c: &crate::cluster::Cluster) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    let mut peers: Vec<_> = c.peers().into_iter().map(|l| (l.node_id, l.addr, l.log_id.to_string())).collect();
    peers.sort();
    peers.hash(&mut h);
    let layout = c.layout();
    layout.version.hash(&mut h);
    layout.op.is_some().hash(&mut h);
    for id in layout.ids() {
        c.owner_of(id).map(|(n, _)| n).hash(&mut h);
    }
    c.lease_valid().hash(&mut h);
    h.finish()
}

/// Follows one peer's changes into this node's bus until aborted. A stream
/// that comes back after a break, or after a failed first try, sends a
/// `resync`: changes made meanwhile were missed.
async fn follow(app: std::sync::Weak<App>, node: String, addr: String) {
    let mut missed = false;
    let mut backoff = Duration::from_millis(250);
    loop {
        let Some(a) = app.upgrade() else { return };
        let url = format!("{}/internal/v1/admin/changes", addr.trim_end_matches('/'));
        let resp = a
            .http
            .get(&url)
            .header(internal::HDR, &a.config.internal_token)
            .timeout(PEER_STREAM_MAX)
            .send()
            .await
            .ok()
            .filter(|r| r.status().is_success());
        drop(a);
        let Some(resp) = resp else {
            missed = true;
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(Duration::from_secs(10));
            continue;
        };
        backoff = Duration::from_millis(250);
        if missed {
            if let Some(a) = app.upgrade() {
                a.changes.relayed(Change {
                    kind: "resync".into(),
                    id: node.clone(),
                    version: now_ms(),
                    node: node.clone(),
                });
            }
        }
        let mut body = resp.bytes_stream();
        let mut buf: Vec<u8> = Vec::new();
        loop {
            let chunk = match tokio::time::timeout(PEER_IDLE, futures::StreamExt::next(&mut body)).await {
                Ok(Some(Ok(b))) => b,
                _ => break,
            };
            buf.extend_from_slice(&chunk);
            while let Some(i) = buf.iter().position(|b| *b == b'\n') {
                let line: Vec<u8> = buf.drain(..=i).collect();
                let line = &line[..line.len() - 1];
                if line.is_empty() {
                    continue;
                }
                let Some(a) = app.upgrade() else { return };
                match serde_json::from_slice::<Change>(line) {
                    Ok(c) => a.changes.relayed(c),
                    Err(e) => tracing::debug!(peer = %node, "admin change feed: unreadable line: {e}"),
                }
            }
        }
        missed = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xrpc::moderation::SubjectRef;

    fn entry(action: &str, subject: Option<SubjectRef>, case: Option<&str>) -> AuditEntry {
        AuditEntry {
            id: format!("{:016x}-abcd1234", 1_700_000_000_123_456u64),
            at: String::new(),
            actor: "admin".into(),
            auth: None,
            ip: None,
            node: "a".into(),
            action: action.into(),
            subject,
            reason: None,
            case_id: case.map(str::to_string),
            detail: Some(json!({"version": 7})),
        }
    }

    fn kinds<'a>(v: &'a [(&'static str, String, u64)]) -> Vec<(&'static str, &'a str)> {
        v.iter().map(|(k, id, _)| (*k, id.as_str())).collect()
    }

    #[test]
    fn audit_entries_name_what_they_touch() {
        let td = from_audit(&entry("takedown", Some(SubjectRef::blob("did:plc:a", "bafyb")), Some("c1")));
        let id = entry("x", None, None).id;
        assert_eq!(
            kinds(&td),
            [("audit", id.as_str()), ("account", "did:plc:a"), ("takedown", "did:plc:a bafyb"), ("case", "c1")]
        );
        assert_eq!(td[0].2, 1_700_000_000_123, "version: the entry's time in ms");
        let rl = from_audit(&entry("ratelimits.update", Some(SubjectRef::other("config", "ratelimits")), None));
        assert_eq!(kinds(&rl)[1], ("config", "ratelimits"));
        assert_eq!(rl[1].2, 7, "the config's own version");
        let lock = from_audit(&entry("lockout.clear", Some(SubjectRef::account("did:plc:b")), None));
        assert!(kinds(&lock).contains(&("lockout", "did:plc:b")));
        let inv = from_audit(&entry("invites.create", None, None));
        assert_eq!(kinds(&inv), [("audit", id.as_str()), ("invite", "*")]);
        let shard = from_audit(&entry("shard.split", Some(SubjectRef::other("shard", 3)), None));
        assert_eq!(kinds(&shard)[1], ("shard", "3"));
        assert_eq!(shard.len(), 2, "no account for an operator subject");
    }

    #[test]
    fn every_kind_is_listed() {
        for k in ["audit", "account", "case", "takedown", "lockout", "invite", "config", "shard", "space"] {
            assert!(KINDS.iter().any(|(x, _)| *x == k), "{k}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn coalesces_and_resyncs_a_lagging_watcher() {
        let ch = Changes::new("a");
        let rx = ch.subscribe();
        let (out, mut body) = tokio::sync::mpsc::channel(64);
        let drain = crate::server::Drain::default();
        let task = tokio::spawn(async move { pump(rx, &out, drain, sse_data, None, None).await });
        ch.emit("account", "did:plc:x", 1);
        ch.emit("account", "did:plc:x", 3);
        ch.emit("case", "c1", 2);
        let got = body.recv().await.unwrap().unwrap();
        let text = std::str::from_utf8(&got).unwrap();
        assert_eq!(text.matches("data: ").count(), 2, "{text}");
        assert!(text.contains(r#""kind":"account","id":"did:plc:x","version":3"#), "{text}");
        // a whole bus behind: one resync instead
        for i in 0..(BUS + 10) {
            ch.emit("account", format!("did:plc:{i}"), 1);
        }
        let mut all = String::new();
        while !all.contains("resync") {
            all.push_str(std::str::from_utf8(&body.recv().await.unwrap().unwrap()).unwrap());
        }
        task.abort();
    }
}
