//! Keeping relays told to crawl us, as the reference PDS's `Crawlers`
//! (DESIGN.md "Relay crawl requests"): `com.atproto.sync.requestCrawl` to
//! each relay at startup and again after new activity, at most once per
//! interval per relay. One node sends (the owner of slot 0's shard); the
//! relay list, interval and per-relay results live in the bucket object
//! `{prefix}/config/crawlers.json`, so the throttle holds across nodes and
//! restarts and any node's console shows the same state.

use super::admin::require_admin;
use super::moderation::{audit, ClientIp, SubjectRef, Who};
use super::*;
use object_store::GetOptions;
use serde::Serialize;
use std::collections::BTreeMap;
use std::sync::atomic::AtomicBool;
use std::sync::Weak;
use std::time::Duration;

pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(20 * 60);
pub const MIN_INTERVAL_SECS: u64 = 1;
pub const MAX_INTERVAL_SECS: u64 = 7 * 24 * 3600;
const MAX_RELAYS: usize = 32;
/// Idle re-check: picks up relays added on another node and leadership moves.
const POLL: Duration = Duration::from_secs(60);
const SEND_TIMEOUT: Duration = Duration::from_secs(10);
const STORE_TIMEOUT: Duration = Duration::from_secs(5);
const CAS_RETRIES: usize = 5;
/// How long the relay list and its addresses are trusted for subscriber
/// hints before they're read and resolved again (in the background).
const HINTS_TTL: Duration = Duration::from_secs(300);
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(2);

pub fn routes() -> Router<Arc<App>> {
    Router::new()
        .route("/xrpc/vlpds.admin.getCrawlers", get(get_crawlers))
        .route("/xrpc/vlpds.admin.setCrawlers", post(set_crawlers))
        .route("/xrpc/vlpds.admin.requestCrawl", post(request_crawl))
}

/// Absent fields fall back to the node's flags (`--crawlers`,
/// `--crawl-interval-secs`).
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Doc {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relays: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interval_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    #[serde(default)]
    pub status: BTreeMap<String, RelayStatus>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RelayStatus {
    pub last_attempt_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_success_ms: Option<u64>,
    pub ok: bool,
    /// None: no HTTP answer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_status: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub node: String,
}

/// The node-local half: flag defaults and the sender loop's wake-up.
pub struct Crawlers {
    flag_relays: Vec<String>,
    flag_interval: Duration,
    wake: tokio::sync::Notify,
    started: AtomicBool,
    hints: parking_lot::Mutex<Hints>,
}

/// The configured relays as (name, lowercase hostname, addresses).
#[derive(Default)]
struct Hints {
    relays: Vec<(String, String, Vec<std::net::IpAddr>)>,
    refreshed: Option<std::time::Instant>,
    refreshing: bool,
}

impl Crawlers {
    /// Unparseable flag entries are dropped with a warning: a typo in one
    /// relay must not stop a node.
    pub fn new(flag_relays: &[String], flag_interval: Duration) -> Crawlers {
        let mut relays = Vec::new();
        for r in flag_relays.iter().filter(|r| !r.trim().is_empty()) {
            match normalize(r) {
                Ok(r) if !relays.contains(&r) => relays.push(r),
                Ok(_) => {}
                Err(e) => tracing::warn!(relay = %r, "--crawlers entry ignored: {e}"),
            }
        }
        metrics::init_request_crawl(&relays);
        Crawlers {
            flag_relays: relays,
            flag_interval,
            wake: Default::default(),
            started: AtomicBool::new(false),
            hints: Default::default(),
        }
    }

    fn relays<'a>(&'a self, doc: &'a Doc) -> &'a [String] {
        doc.relays.as_deref().unwrap_or(&self.flag_relays)
    }

    fn interval(&self, doc: &Doc) -> Duration {
        doc.interval_secs.map(Duration::from_secs).unwrap_or(self.flag_interval)
    }

    /// The configured relay a firehose subscriber looks like: its address is
    /// one the relay's hostname resolves to, its user agent names the
    /// hostname, or its forward-confirmed PTR name (`verified_ptr`, see
    /// `crate::ptr`) is in the hostname's domain. Answers from a cache and
    /// never waits on DNS or the bucket (a stale cache is refreshed in the
    /// background, so a relay connecting right after startup may go
    /// unnamed).
    pub fn relay_hint(
        self: &Arc<Self>,
        store: &Store,
        ip: Option<std::net::IpAddr>,
        ua: &str,
        verified_ptr: Option<&str>,
    ) -> Option<String> {
        self.refresh_hints(store);
        let ip = ip.map(|i| i.to_canonical());
        let ua = ua.to_ascii_lowercase();
        let h = self.hints.lock();
        h.relays
            .iter()
            .find(|(_, host, ips)| {
                ip.is_some_and(|i| ips.contains(&i))
                    || (!host.is_empty() && ua.contains(host.as_str()))
                    || verified_ptr.is_some_and(|p| in_domain(p, host))
            })
            .map(|(r, ..)| r.clone())
    }

    fn refresh_hints(self: &Arc<Self>, store: &Store) {
        {
            let mut h = self.hints.lock();
            if h.refreshing || h.refreshed.is_some_and(|t| t.elapsed() < HINTS_TTL) {
                return;
            }
            h.refreshing = true;
        }
        let (c, store) = (self.clone(), store.clone());
        tokio::spawn(async move {
            let relays = match load(&store).await {
                Ok((doc, _)) => c.relays(&doc).to_vec(),
                Err(_) => c.flag_relays.clone(),
            };
            let resolved = futures::future::join_all(relays.into_iter().map(|r| async move {
                let base = if r.contains("://") { r.clone() } else { format!("https://{r}") };
                let host = reqwest::Url::parse(&base)
                    .ok()
                    .and_then(|u| u.host_str().map(|h| h.trim_matches(['[', ']']).to_ascii_lowercase()))
                    .unwrap_or_default();
                let ips =
                    match tokio::time::timeout(RESOLVE_TIMEOUT, tokio::net::lookup_host((host.as_str(), 443))).await {
                        Ok(Ok(addrs)) => addrs.map(|a| a.ip().to_canonical()).collect(),
                        _ => Vec::new(),
                    };
                (r, host, ips)
            }))
            .await;
            let mut h = c.hints.lock();
            h.relays = resolved;
            h.refreshed = Some(std::time::Instant::now());
            h.refreshing = false;
        });
    }
}

/// `name` is `domain` or a name under it; an address literal is no domain.
fn in_domain(name: &str, domain: &str) -> bool {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    if domain.is_empty() || domain.parse::<std::net::IpAddr>().is_ok() {
        return false;
    }
    name == domain || name.strip_suffix(domain).is_some_and(|rest| rest.ends_with('.'))
}

/// A relay as stored and used as the metric label: a lowercase hostname
/// (`host[:port]`, sent over https) or an `http(s)://host[:port]` origin.
pub fn normalize(relay: &str) -> Result<String, String> {
    let r = relay.trim().trim_end_matches('/');
    if r.is_empty() {
        return Err("empty relay".into());
    }
    let (scheme, url) = if r.contains("://") { (true, r.to_string()) } else { (false, format!("https://{r}")) };
    let u = reqwest::Url::parse(&url).map_err(|e| format!("{r}: {e}"))?;
    if !matches!(u.scheme(), "http" | "https") {
        return Err(format!("{r}: only http(s) relays"));
    }
    let Some(host) = u.host_str().filter(|h| !h.is_empty()) else { return Err(format!("{r}: no host")) };
    if u.path() != "/"
        || u.query().is_some()
        || u.fragment().is_some()
        || !u.username().is_empty()
        || u.password().is_some()
    {
        return Err(format!("{r}: a hostname or origin, without path, query or credentials"));
    }
    if !host.contains('.') && !host.starts_with('[') && host != "localhost" {
        return Err(format!("{r}: not a fully qualified hostname"));
    }
    let host = match u.port() {
        Some(p) => format!("{host}:{p}"),
        None => host.to_string(),
    };
    Ok(if scheme { format!("{}://{host}", u.scheme()) } else { host })
}

fn endpoint(relay: &str) -> String {
    let base = if relay.contains("://") { relay.to_string() } else { format!("https://{relay}") };
    format!("{base}/xrpc/com.atproto.sync.requestCrawl")
}

fn host_of(relay: &str) -> String {
    super::sync::public_hostname(relay)
}

/// Loopback, private or link-local (`host[:port]`). A dev or bench node's
/// public URL is one: remote relays (the default bsky.network) are never
/// asked to crawl it, so local runs stay off the network.
pub fn is_local(hostport: &str) -> bool {
    let host = match hostport.strip_prefix('[') {
        Some(rest) => rest.split(']').next().unwrap_or(rest),
        None if hostport.matches(':').count() == 1 => hostport.split(':').next().unwrap_or(hostport),
        None => hostport,
    }
    .to_ascii_lowercase();
    if host == "localhost" || host.ends_with(".localhost") || host.ends_with(".test") {
        return true;
    }
    match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(ip)) => {
            ip.is_loopback() || ip.is_private() || ip.is_link_local() || ip.is_unspecified()
        }
        Ok(std::net::IpAddr::V6(ip)) => {
            ip.is_loopback() || ip.is_unspecified() || (ip.segments()[0] & 0xfe00) == 0xfc00
        }
        Err(_) => false,
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64)
}

/// Whether `relay` should be asked now: never asked, or there was activity
/// since the last ask and the interval has passed (the reference's
/// `notifyOfUpdate` throttle).
pub fn due(st: Option<&RelayStatus>, activity_ms: u64, now_ms: u64, interval: Duration) -> bool {
    match st {
        None => true,
        Some(s) => {
            activity_ms > s.last_attempt_ms && now_ms >= s.last_attempt_ms.saturating_add(interval.as_millis() as u64)
        }
    }
}

/// When the next relay with activity it hasn't been told about falls due.
pub fn next_due<'a>(
    relays: impl IntoIterator<Item = &'a String>,
    doc: &Doc,
    activity_ms: u64,
    interval: Duration,
) -> Option<u64> {
    relays
        .into_iter()
        .filter_map(|r| match doc.status.get(r) {
            None => Some(0),
            Some(s) if activity_ms > s.last_attempt_ms => {
                Some(s.last_attempt_ms.saturating_add(interval.as_millis() as u64))
            }
            Some(_) => None,
        })
        .min()
}

fn path(store: &Store) -> object_store::path::Path {
    object_store::path::Path::from(format!("{}/config/crawlers.json", store.prefix))
}

async fn bounded<T>(f: impl std::future::Future<Output = object_store::Result<T>>) -> anyhow::Result<T> {
    match tokio::time::timeout(STORE_TIMEOUT, f).await {
        Ok(r) => Ok(r?),
        Err(_) => anyhow::bail!("crawler config call timed out"),
    }
}

/// The stored doc (default when absent) and its ETag.
pub async fn load(store: &Store) -> anyhow::Result<(Doc, Option<String>)> {
    let got = bounded(async {
        let r = store.raw.get_opts(&path(store), GetOptions::default()).await?;
        let e = r.meta.e_tag.clone();
        Ok((r.bytes().await?, e))
    })
    .await;
    match got {
        Ok((b, e)) => {
            Ok((serde_json::from_slice(&b).map_err(|err| anyhow::anyhow!("crawlers.json unreadable: {err}"))?, e))
        }
        Err(e) if matches!(e.downcast_ref::<object_store::Error>(), Some(object_store::Error::NotFound { .. })) => {
            Ok((Doc::default(), None))
        }
        Err(e) => Err(e),
    }
}

/// Read-modify-write under CAS, retried on a concurrent change.
async fn update(store: &Store, f: impl Fn(&mut Doc)) -> anyhow::Result<Doc> {
    for _ in 0..CAS_RETRIES {
        let (mut doc, etag) = load(store).await?;
        f(&mut doc);
        let mode = match etag {
            Some(e) => crate::cluster::if_match(Some(e)),
            None => PutMode::Create,
        };
        let body = serde_json::to_vec_pretty(&doc)?;
        match bounded(store.raw.put_opts(
            &path(store),
            PutPayload::from(body),
            PutOptions { mode, ..Default::default() },
        ))
        .await
        {
            Ok(_) => return Ok(doc),
            Err(e)
                if matches!(
                    e.downcast_ref::<object_store::Error>(),
                    Some(object_store::Error::Precondition { .. } | object_store::Error::AlreadyExists { .. })
                ) =>
            {
                continue
            }
            Err(e) => return Err(e),
        }
    }
    anyhow::bail!("crawlers.json kept changing under the update")
}

fn node_id(app: &App) -> String {
    app.cluster.as_ref().map(|c| c.cfg.node_id.clone()).unwrap_or_else(|| "single".into())
}

/// Asks each relay once, concurrently; never fails as a whole.
async fn send(app: &App, relays: &[String]) -> Vec<(String, RelayStatus)> {
    let hostname = super::sync::public_hostname(&app.config.public_url);
    let client = vlsync_atproto::http::public();
    let node = node_id(app);
    futures::future::join_all(relays.iter().map(|relay| {
        let (hostname, node) = (hostname.clone(), node.clone());
        async move {
            let url = endpoint(relay);
            let at = now_ms();
            let mut st = RelayStatus { last_attempt_ms: at, node, ..Default::default() };
            if is_local(&hostname) && !is_local(&host_of(relay)) {
                st.error = Some(format!("not sent: {hostname} is a local address, which a remote relay can't crawl"));
                return (relay.clone(), st);
            }
            let r = client.post(&url).json(&json!({"hostname": hostname})).timeout(SEND_TIMEOUT).send().await;
            let result = match r {
                Ok(r) if r.status().is_success() => {
                    st.ok = true;
                    st.http_status = Some(r.status().as_u16());
                    st.last_success_ms = Some(at);
                    tracing::info!(%url, %hostname, "requestCrawl ok");
                    "ok"
                }
                Ok(r) => {
                    let code = r.status().as_u16();
                    let body: String = r.text().await.unwrap_or_default().chars().take(500).collect();
                    tracing::warn!(%url, %hostname, status = code, %body, "requestCrawl rejected");
                    st.http_status = Some(code);
                    st.error = Some(body);
                    "rejected"
                }
                Err(e) => {
                    tracing::warn!(%url, %hostname, "requestCrawl failed: {e}");
                    st.error = Some(e.to_string());
                    "failed"
                }
            };
            metrics::request_crawl(relay, result);
            (relay.clone(), st)
        }
    }))
    .await
}

/// Records results for relays in the current list (dropping statuses of
/// removed ones); keeps an earlier success time across failures.
async fn record(store: &Store, crawlers: &Crawlers, results: &[(String, RelayStatus)]) -> anyhow::Result<Doc> {
    update(store, |doc| {
        for (relay, st) in results {
            if !crawlers.relays(doc).contains(relay) {
                continue;
            }
            let mut st = st.clone();
            if st.last_success_ms.is_none() {
                st.last_success_ms = doc.status.get(relay).and_then(|s| s.last_success_ms);
            }
            doc.status.insert(relay.clone(), st);
        }
        let keep: Vec<String> = crawlers.relays(doc).to_vec();
        doc.status.retain(|r, _| keep.contains(r));
    })
    .await
}

/// Starts the sender loop once per app. Every node runs it; only the slot-0
/// leader reads the bucket or sends.
pub fn start(app: &Arc<App>) {
    if app.crawlers.started.swap(true, Ordering::AcqRel) {
        return;
    }
    let weak = Arc::downgrade(app);
    let head = app.firehose.subscribe();
    tokio::spawn(run(weak, head));
}

fn leads(app: &App) -> bool {
    app.cluster.as_ref().is_none_or(|c| c.leads_slot0())
}

async fn run(weak: Weak<App>, mut head: tokio::sync::watch::Receiver<u64>) {
    let mut activity_ms = now_ms();
    let mut leader = false;
    // When to look again; None: once there is activity (or after POLL).
    let mut next: Option<u64> = Some(0);
    loop {
        let wake = {
            let Some(app) = weak.upgrade() else { return };
            let c = app.crawlers.clone();
            async move { c.wake.notified().await }
        };
        let wait = next.map_or(POLL, |t| Duration::from_millis(t.saturating_sub(now_ms())).min(POLL));
        tokio::select! {
            r = head.changed(), if next.is_none() => {
                if r.is_err() {
                    return;
                }
                activity_ms = now_ms();
            }
            _ = tokio::time::sleep(wait) => {}
            _ = wake => {}
        }
        let Some(app) = weak.upgrade() else { return };
        if !leads(&app) {
            leader = false;
            next = Some(now_ms() + POLL.as_millis() as u64);
            continue;
        }
        if !leader {
            leader = true;
            // a new leader treats taking over as activity, as a restart does
            activity_ms = activity_ms.max(now_ms());
        }
        next = match tick(&app, &mut head, activity_ms).await {
            Ok(n) => n,
            Err(e) => {
                tracing::warn!("requestCrawl round failed (retrying): {e:#}");
                Some(now_ms() + POLL.as_millis() as u64)
            }
        };
    }
}

/// One leader pass: asks the relays that are due and returns when to look
/// again (None: after the next activity).
async fn tick(
    app: &App,
    head: &mut tokio::sync::watch::Receiver<u64>,
    activity_ms: u64,
) -> anyhow::Result<Option<u64>> {
    let c = &app.crawlers;
    let (mut doc, _) = load(&app.store).await?;
    let interval = c.interval(&doc);
    let now = now_ms();
    let asking: Vec<String> =
        c.relays(&doc).iter().filter(|r| due(doc.status.get(*r), activity_ms, now, interval)).cloned().collect();
    if !asking.is_empty() {
        metrics::init_request_crawl(&asking);
        // activity from here on is news to the relays asked now
        head.borrow_and_update();
        let results = send(app, &asking).await;
        doc = record(&app.store, c, &results).await?;
    }
    Ok(next_due(c.relays(&doc), &doc, activity_ms, interval))
}

fn view(app: &App, doc: &Doc) -> J {
    let c = &app.crawlers;
    let relays: Vec<J> = c
        .relays(doc)
        .iter()
        .map(|r| {
            let mut v = json!({"relay": r, "url": endpoint(r)});
            if let Some(s) = doc.status.get(r) {
                v["status"] = serde_json::to_value(s).unwrap_or(J::Null);
            }
            v
        })
        .collect();
    json!({
        "hostname": super::sync::public_hostname(&app.config.public_url),
        "relays": relays,
        "intervalSecs": c.interval(doc).as_secs(),
        "relaysSource": if doc.relays.is_some() { "stored" } else { "flags" },
        "intervalSource": if doc.interval_secs.is_some() { "stored" } else { "flags" },
        "flagRelays": c.flag_relays,
        "flagIntervalSecs": c.flag_interval.as_secs(),
        "updatedAt": doc.updated_at,
        "node": node_id(app),
        "sender": leads(app),
    })
}

fn store_error(e: anyhow::Error) -> XrpcError {
    XrpcError { status: StatusCode::BAD_GATEWAY, error: "UpstreamFailure".into(), message: format!("{e:#}") }
}

async fn get_crawlers(State(app): AppState, Auth(creds): Auth) -> XResult<Json<J>> {
    require_admin(&creds)?;
    let (doc, _) = load(&app.store).await.map_err(store_error)?;
    Ok(Json(view(&app, &doc)))
}

/// A field left out keeps its stored value; `null` returns it to the flags.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SetIn {
    #[serde(default, deserialize_with = "some")]
    relays: Option<Option<Vec<String>>>,
    #[serde(default, deserialize_with = "some")]
    interval_secs: Option<Option<u64>>,
    #[serde(default)]
    actor: Option<String>,
}

fn some<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Option<Option<T>>, D::Error> {
    Option::<T>::deserialize(d).map(Some)
}

fn invalid(message: impl Into<String>) -> XrpcError {
    XrpcError::bad("InvalidRequest", message)
}

/// Normalized, deduplicated and bounded.
fn validate_relays(given: &[String]) -> Result<Vec<String>, XrpcError> {
    let mut out = Vec::new();
    for r in given.iter().filter(|r| !r.trim().is_empty()) {
        let n = normalize(r).map_err(invalid)?;
        if !out.contains(&n) {
            out.push(n);
        }
    }
    if out.len() > MAX_RELAYS {
        return Err(invalid(format!("at most {MAX_RELAYS} relays")));
    }
    Ok(out)
}

async fn set_crawlers(
    State(app): AppState,
    Auth(creds): Auth,
    ClientIp(ip): ClientIp,
    Json(inp): Json<SetIn>,
) -> XResult<Json<J>> {
    require_admin(&creds)?;
    let relays = match &inp.relays {
        Some(Some(r)) => Some(Some(validate_relays(r)?)),
        Some(None) => Some(None),
        None => None,
    };
    if let Some(Some(s)) = inp.interval_secs {
        if !(MIN_INTERVAL_SECS..=MAX_INTERVAL_SECS).contains(&s) {
            return Err(invalid(format!("intervalSecs must be {MIN_INTERVAL_SECS}..={MAX_INTERVAL_SECS}")));
        }
    }
    let at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let c = app.crawlers.clone();
    let doc = update(&app.store, |doc| {
        if let Some(r) = &relays {
            doc.relays = r.clone();
        }
        if let Some(i) = inp.interval_secs {
            doc.interval_secs = i;
        }
        doc.updated_at = Some(at.clone());
        let keep: Vec<String> = c.relays(doc).to_vec();
        doc.status.retain(|r, _| keep.contains(r));
    })
    .await
    .map_err(store_error)?;
    metrics::init_request_crawl(c.relays(&doc));
    let detail = json!({"relays": c.relays(&doc), "intervalSecs": c.interval(&doc).as_secs()});
    let who = Who::of(&creds, inp.actor.as_deref(), ip);
    audit(&app, &who, "crawlers.set", Some(&SubjectRef::other("config", "crawlers")), None, None, Some(detail)).await?;
    // a relay added here is due at once; peers' loops see it within POLL
    c.wake.notify_one();
    c.hints.lock().refreshed = None;
    Ok(Json(view(&app, &doc)))
}

#[derive(Deserialize, Default)]
struct RequestCrawlIn {
    /// Hostnames or URLs (default: the configured relays).
    #[serde(default)]
    relays: Vec<String>,
    #[serde(default)]
    actor: Option<String>,
}

/// Asks now, whatever the throttle, and reports each relay's result.
/// Results for configured relays are recorded, so the sender's throttle
/// counts them.
async fn request_crawl(
    State(app): AppState,
    Auth(creds): Auth,
    ClientIp(ip): ClientIp,
    body: Option<Json<RequestCrawlIn>>,
) -> XResult<Json<J>> {
    require_admin(&creds)?;
    let inp = body.map(|Json(b)| b).unwrap_or_default();
    let given = validate_relays(&inp.relays)?;
    let relays = if given.is_empty() {
        let (doc, _) = load(&app.store).await.map_err(store_error)?;
        app.crawlers.relays(&doc).to_vec()
    } else {
        given
    };
    if relays.is_empty() {
        return Err(invalid("no relays given and none configured (--crawlers, vlpds.admin.setCrawlers)"));
    }
    let hostname = super::sync::public_hostname(&app.config.public_url);
    let results = send(&app, &relays).await;
    if let Err(e) = record(&app.store, &app.crawlers, &results).await {
        tracing::warn!("requestCrawl results not recorded: {e:#}");
    }
    let out: Vec<J> = results
        .iter()
        .map(|(relay, s)| {
            let mut v = json!({"relay": relay, "url": endpoint(relay), "ok": s.ok});
            if let Some(code) = s.http_status {
                v["status"] = json!(code);
            }
            if let Some(e) = &s.error {
                v["error"] = json!(e);
            }
            v
        })
        .collect();
    let ok = results.iter().filter(|(_, s)| s.ok).count();
    let detail = json!({"relays": results.iter().map(|(r, _)| r).collect::<Vec<_>>(), "ok": ok});
    let who = Who::of(&creds, inp.actor.as_deref(), ip);
    let subject = SubjectRef::other("config", "crawlers");
    audit(&app, &who, "crawlers.request", Some(&subject), None, None, Some(detail)).await?;
    Ok(Json(json!({"hostname": hostname, "results": out})))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn st(last_attempt_ms: u64) -> RelayStatus {
        RelayStatus { last_attempt_ms, ..Default::default() }
    }

    #[test]
    fn normalizes_relays() {
        assert_eq!(normalize(" bsky.network/ ").unwrap(), "bsky.network");
        assert_eq!(normalize("Relay.Example.COM:8443").unwrap(), "relay.example.com:8443");
        assert_eq!(normalize("https://bsky.network").unwrap(), "https://bsky.network");
        assert_eq!(normalize("http://127.0.0.1:1234/").unwrap(), "http://127.0.0.1:1234");
        assert_eq!(normalize("https://relay.example.com:443").unwrap(), "https://relay.example.com");
        for bad in [
            "",
            "relay",
            "ftp://relay.example.com",
            "https://relay.example.com/xrpc",
            "relay.example.com?x=1",
            "https://u:p@relay.example.com",
            "bad host.com",
        ] {
            assert!(normalize(bad).is_err(), "{bad}");
        }
        assert_eq!(endpoint("bsky.network"), "https://bsky.network/xrpc/com.atproto.sync.requestCrawl");
        assert_eq!(endpoint("http://127.0.0.1:9"), "http://127.0.0.1:9/xrpc/com.atproto.sync.requestCrawl");
    }

    #[test]
    fn local_addresses() {
        for h in ["127.0.0.1:2620", "localhost", "[::1]:80", "10.1.2.3", "192.168.1.2:9", "pds.test", "::1"] {
            assert!(is_local(h), "{h}");
        }
        for h in ["bsky.network", "relay.example.com:443", "8.8.8.8", "[2001:db8::1]:443"] {
            assert!(!is_local(h), "{h}");
        }
        assert_eq!(host_of("http://127.0.0.1:9"), "127.0.0.1:9");
        assert_eq!(host_of("bsky.network"), "bsky.network");
    }

    #[test]
    fn throttle() {
        let i = Duration::from_secs(60);
        // never asked: due whatever the activity
        assert!(due(None, 0, 0, i));
        // asked at 1000; activity after, but inside the interval
        assert!(!due(Some(&st(1000)), 2000, 30_000, i));
        assert!(due(Some(&st(1000)), 2000, 61_000, i));
        // past the interval, but nothing new since the last ask
        assert!(!due(Some(&st(1000)), 1000, 1_000_000, i));
        assert!(!due(Some(&st(1000)), 500, 1_000_000, i));
    }

    #[test]
    fn next_due_waits_for_activity() {
        let i = Duration::from_secs(60);
        let relays = vec!["a.example".to_string(), "b.example".to_string()];
        let mut doc = Doc::default();
        assert_eq!(next_due(&relays, &doc, 0, i), Some(0));
        doc.status.insert("a.example".into(), st(1000));
        doc.status.insert("b.example".into(), st(5000));
        assert_eq!(next_due(&relays, &doc, 900, i), None);
        assert_eq!(next_due(&relays, &doc, 2000, i), Some(61_000));
        assert_eq!(next_due(&relays, &doc, 9000, i), Some(61_000));
        doc.status.remove("b.example");
        assert_eq!(next_due(&relays, &doc, 900, i), Some(0));
    }

    #[test]
    fn stored_fields_override_flags() {
        let c = Crawlers::new(
            &["bsky.network".into(), "".into(), "not a host".into(), "bsky.network/".into()],
            DEFAULT_INTERVAL,
        );
        let mut doc = Doc::default();
        assert_eq!(c.relays(&doc), ["bsky.network".to_string()]);
        assert_eq!(c.interval(&doc), DEFAULT_INTERVAL);
        doc.relays = Some(vec![]);
        doc.interval_secs = Some(5);
        assert!(c.relays(&doc).is_empty());
        assert_eq!(c.interval(&doc), Duration::from_secs(5));
    }

    #[test]
    fn ptr_domain_match() {
        assert!(in_domain("relay1.us-east.bsky.network", "bsky.network"));
        assert!(in_domain("Bsky.Network.", "bsky.network"));
        assert!(!in_domain("evilbsky.network", "bsky.network"));
        assert!(!in_domain("bsky.network.evil.example", "bsky.network"));
        assert!(!in_domain("1.2.3.4", "1.2.3.4"));
        assert!(!in_domain("anything", ""));
    }

    #[tokio::test]
    async fn relay_hint_through_a_verified_ptr() {
        let c = Arc::new(Crawlers::new(&["bsky.network".into(), "relay.example.com:8443".into()], DEFAULT_INTERVAL));
        {
            let mut h = c.hints.lock();
            h.relays = vec![
                ("bsky.network".into(), "bsky.network".into(), vec!["192.0.2.1".parse().unwrap()]),
                ("relay.example.com:8443".into(), "relay.example.com".into(), vec![]),
            ];
            h.refreshed = Some(std::time::Instant::now());
        }
        let store = Store::memory(None);
        let other: Option<std::net::IpAddr> = Some("198.51.100.9".parse().unwrap());
        let ua = "indigo-relay (atproto-relay)";
        assert_eq!(c.relay_hint(&store, other, ua, None), None);
        assert_eq!(
            c.relay_hint(&store, other, ua, Some("relay1.us-west.bsky.network")).as_deref(),
            Some("bsky.network")
        );
        assert_eq!(
            c.relay_hint(&store, other, ua, Some("a.relay.example.com")).as_deref(),
            Some("relay.example.com:8443")
        );
        assert_eq!(c.relay_hint(&store, other, ua, Some("bsky.network.evil.example")), None);
        // the address and user agent still match on their own
        assert_eq!(c.relay_hint(&store, Some("192.0.2.1".parse().unwrap()), "", None).as_deref(), Some("bsky.network"));
        assert_eq!(
            c.relay_hint(&store, other, "relay.example.com/1.0", None).as_deref(),
            Some("relay.example.com:8443")
        );
    }

    #[test]
    fn set_fields_distinguish_absent_from_null() {
        let s: SetIn = serde_json::from_value(json!({"relays": null})).unwrap();
        assert_eq!((s.relays, s.interval_secs), (Some(None), None));
        let s: SetIn = serde_json::from_value(json!({"intervalSecs": 30})).unwrap();
        assert_eq!((s.relays, s.interval_secs), (None, Some(Some(30))));
    }
}
