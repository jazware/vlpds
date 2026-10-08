//! Service proxying (atproto-proxy), mirroring the reference's
//! `pipethrough.ts`, plus `app.bsky.actor.{get,put}Preferences` and
//! createReport. The rest of the policy is in DESIGN.md "7. HTTP".
//!
//! A response the client stops reading is dropped after
//! `http::stall::WRITE_STALL`; small ones (<= [`BUFFER_SMALL`]) are read
//! whole first, so the upstream connection goes back at once whatever the
//! client does.

use super::authn::Credentials;
use super::*;
use axum::extract::Request;
use axum::http::{Method, Uri};
use std::borrow::Cow;
use std::time::Duration;
use vlatproto::did_resolver;

/// Private-state name of the stored preferences (JSON array).
const PREFS_KEY: &str = "prefs:app.bsky";
const PREFS_NAMESPACE: &str = "app.bsky";
const PERSONAL_DETAILS_PREF: &str = "app.bsky.actor.defs#personalDetailsPref";
const DECLARED_AGE_PREF: &str = "app.bsky.actor.defs#declaredAgePref";

const GET_PREFERENCES: &str = "app.bsky.actor.getPreferences";
const PUT_PREFERENCES: &str = "app.bsky.actor.putPreferences";
const CREATE_REPORT: &str = "com.atproto.moderation.createReport";
const APPEAL_ACTIONED_SUBJECT: &str = "tools.ozone.inbox.appealActionedSubject";
const GET_FEED: &str = "app.bsky.feed.getFeed";
const GET_FEED_SKELETON: &str = "app.bsky.feed.getFeedSkeleton";

mod read_after_write;

/// The reference's proxy defaults.
const HEADERS_TIMEOUT: Duration = Duration::from_secs(10);
const BODY_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_RESPONSE_BYTES: usize = 10 << 20;
const SERVICE_JWT_TTL_SECS: u64 = 60;
/// By Content-Length.
const BUFFER_SMALL: u64 = 128 << 10;
/// On the wire and decoded.
const MAX_ERROR_BYTES: usize = 256 << 10;
/// Until each response body is done: one account could otherwise hold most
/// of the AppView connection pool with responses its client never reads.
pub const MAX_IN_FLIGHT_PER_ACCOUNT: u32 = 64;

const PROTECTED_METHODS: &[&str] = &[
    "com.atproto.admin.sendEmail",
    "com.atproto.identity.requestPlcOperationSignature",
    "com.atproto.identity.signPlcOperation",
    "com.atproto.identity.updateHandle",
    "com.atproto.server.activateAccount",
    "com.atproto.server.confirmEmail",
    "com.atproto.server.createAppPassword",
    "com.atproto.server.deactivateAccount",
    "com.atproto.server.getAccountInviteCodes",
    "com.atproto.server.getSession",
    "com.atproto.server.listAppPasswords",
    "com.atproto.server.requestAccountDelete",
    "com.atproto.server.requestEmailConfirmation",
    "com.atproto.server.requestEmailUpdate",
    "com.atproto.server.revokeAppPassword",
    "com.atproto.server.updateEmail",
];

/// Off limits to non-privileged app passwords.
const PRIVILEGED_METHODS: &[&str] = &[
    "chat.bsky.actor.deleteAccount",
    "chat.bsky.actor.exportAccountData",
    "chat.bsky.convo.deleteMessageForSelf",
    "chat.bsky.convo.getConvo",
    "chat.bsky.convo.getConvoForMembers",
    "chat.bsky.convo.getLog",
    "chat.bsky.convo.getMessages",
    "chat.bsky.convo.leaveConvo",
    "chat.bsky.convo.listConvos",
    "chat.bsky.convo.muteConvo",
    "chat.bsky.convo.sendMessage",
    "chat.bsky.convo.sendMessageBatch",
    "chat.bsky.convo.unmuteConvo",
    "chat.bsky.convo.updateRead",
    "com.atproto.server.createAccount",
];

/// Response headers passed on: all of them on success, all but the content
/// headers (the first four) on errors.
const RES_HEADERS: [header::HeaderName; 7] = [
    header::CONTENT_LENGTH,
    header::CONTENT_ENCODING,
    header::CONTENT_TYPE,
    header::CONTENT_LANGUAGE,
    header::HeaderName::from_static("atproto-repo-rev"),
    header::HeaderName::from_static("atproto-content-labelers"),
    header::RETRY_AFTER,
];

pub fn routes() -> Router<Arc<App>> {
    Router::new()
        .route("/xrpc/app.bsky.actor.getPreferences", get(get_preferences))
        .route("/xrpc/app.bsky.actor.putPreferences", post(put_preferences))
        .route("/xrpc/com.atproto.moderation.createReport", post(create_report))
        .route("/xrpc/app.bsky.notification.registerPush", post(push::register_push))
        .route("/xrpc/app.bsky.notification.unregisterPush", post(push::unregister_push))
}

mod push;

fn xerr(status: StatusCode, error: &str, message: impl Into<String>) -> XrpcError {
    XrpcError { status, error: error.into(), message: message.into() }
}

fn lxm_in(set: &[&str], lxm: &str) -> bool {
    set.iter().any(|m| m.eq_ignore_ascii_case(lxm))
}

fn has_prefix_ignore_case(s: &str, prefix: &str) -> bool {
    s.get(..prefix.len()).is_some_and(|p| p.eq_ignore_ascii_case(prefix))
}

fn valid_nsid(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    s.len() <= 317
        && parts.len() >= 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.len() <= 63 && p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
}

struct Target<'a> {
    /// Only its origin is used.
    url: Cow<'a, str>,
    /// Bare service DID: the service-auth JWT audience.
    did: Cow<'a, str>,
    service_id: Cow<'a, str>,
    /// Operator-configured: exempt from SSRF checks.
    trusted: bool,
}

impl Target<'_> {
    fn scope_aud(&self) -> String {
        format!("{}#{}", self.did, self.service_id)
    }
}

fn no_service(lxm: &str) -> XrpcError {
    XrpcError::bad("InvalidRequest", format!("No service configured for {lxm}"))
}

fn proxy_header(headers: &HeaderMap) -> XResult<Option<&str>> {
    match headers.get("atproto-proxy") {
        None => Ok(None),
        Some(v) => v.to_str().map(Some).map_err(|_| XrpcError::bad("InvalidRequest", "invalid proxy header format")),
    }
}

fn configured<'a>(svc: &'a Option<(String, String)>, service_id: &'static str) -> Option<Target<'a>> {
    svc.as_ref().map(|(url, did)| Target {
        url: Cow::Borrowed(url),
        did: Cow::Borrowed(did),
        service_id: Cow::Borrowed(service_id),
        trusted: true,
    })
}

/// For a method without an atproto-proxy header. Ok(None): not proxyable.
fn default_target<'a>(app: &'a App, lxm: &str) -> XResult<Option<Target<'a>>> {
    let svc = if lxm == CREATE_REPORT {
        configured(&app.config.report_service, "atproto_labeler")
    } else if has_prefix_ignore_case(lxm, "chat.bsky.") {
        // clients must name the DM service
        None
    } else if lxm.starts_with("app.bsky.") || lxm.starts_with("tools.ozone.") {
        configured(&app.config.appview, "bsky_appview")
    } else {
        return Ok(None);
    };
    svc.map(Some).ok_or_else(|| no_service(lxm))
}

/// Resolves `<did>#<service id>`.
async fn parse_proxy_header<'a>(app: &'a App, proxy_to: &str) -> XResult<Target<'a>> {
    let bad = |m: &str| XrpcError::bad("InvalidRequest", m);
    let hash = match proxy_to.find('#') {
        Some(0) => return Err(bad("no did specified in proxy header")),
        Some(i) if i == proxy_to.len() - 1 => return Err(bad("no service id specified in proxy header")),
        None => return Err(bad("no service id specified in proxy header")),
        Some(i) => i,
    };
    if proxy_to[hash + 1..].contains('#') {
        return Err(bad("invalid proxy header format"));
    }
    if proxy_to.contains(' ') {
        return Err(bad("proxy header cannot contain spaces"));
    }
    let (did, service_id) = (&proxy_to[..hash], &proxy_to[hash + 1..]);
    if service_id == "bsky_appview" && app.config.appview.as_ref().is_some_and(|(_, av)| av == did) {
        return Ok(configured(&app.config.appview, "bsky_appview").expect("checked"));
    }
    let doc = resolve_did(app, did).await.map_err(|_| bad("could not resolve proxy did"))?;
    let url = did_resolver::service_endpoint(&doc, service_id)
        .ok_or_else(|| bad("could not resolve proxy did service url"))?;
    Ok(Target {
        url: Cow::Owned(url),
        did: Cow::Owned(did.into()),
        service_id: Cow::Owned(service_id.into()),
        trusted: false,
    })
}

pub async fn resolve_did(app: &App, did: &str) -> Result<Arc<J>, did_resolver::ResolveError> {
    if !did.starts_with("did:") {
        return Err(did_resolver::ResolveError::BadDid(did.into()));
    }
    if let Ok(acct) = app.account(did).await {
        return super::identity::account_did_doc(app, &acct).await;
    }
    app.did_resolver.resolve(did).await
}

fn upstream_failure(message: &str) -> XrpcError {
    xerr(StatusCode::BAD_GATEWAY, "UpstreamFailure", message)
}

/// The reference's allow-list.
fn forward_headers(
    src: &HeaderMap,
    with_body: bool,
    authorization: Option<&str>,
    accept_encoding: Option<header::HeaderValue>,
) -> HeaderMap {
    const ACCEPT_LANGUAGE: header::HeaderName = header::ACCEPT_LANGUAGE;
    const ACCEPT_LABELERS: header::HeaderName = header::HeaderName::from_static("atproto-accept-labelers");
    const BSKY_TOPICS: header::HeaderName = header::HeaderName::from_static("x-bsky-topics");
    let mut out = HeaderMap::with_capacity(8);
    let copy = |out: &mut HeaderMap, name: &header::HeaderName| {
        for v in src.get_all(name) {
            out.append(name.clone(), v.clone());
        }
    };
    let ae = accept_encoding.or_else(|| src.get(header::ACCEPT_ENCODING).cloned());
    out.insert(header::ACCEPT_ENCODING, ae.unwrap_or(header::HeaderValue::from_static("identity")));
    copy(&mut out, &ACCEPT_LANGUAGE);
    copy(&mut out, &ACCEPT_LABELERS);
    for name in src.keys() {
        if name.as_str().starts_with("x-atproto-") {
            copy(&mut out, name);
        }
    }
    copy(&mut out, &BSKY_TOPICS);
    if with_body {
        copy(&mut out, &header::CONTENT_TYPE);
        copy(&mut out, &header::CONTENT_ENCODING);
        copy(&mut out, &header::CONTENT_LENGTH);
    }
    if let Some(Ok(v)) = authorization.map(|a| header::HeaderValue::from_str(&format!("Bearer {a}"))) {
        out.insert(header::AUTHORIZATION, v);
    }
    out
}

fn is_json_content_type(ct: &str) -> bool {
    let ct = ct.to_ascii_lowercase();
    let Some(rest) = ct.split_once("application/").map(|(_, r)| r) else {
        return false;
    };
    let sub: String = rest.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '+').collect();
    sub == "json" || sub.ends_with("+json")
}

/// The reference's (error, message) defaults by status.
fn response_type(status: u16) -> Option<(&'static str, &'static str)> {
    Some(match status {
        400 => ("InvalidRequest", "Invalid Request"),
        401 => ("AuthenticationRequired", "Authentication Required"),
        403 => ("Forbidden", "Forbidden"),
        404 => ("XRPCNotSupported", "XRPC Not Supported"),
        406 => ("NotAcceptable", "Not Acceptable"),
        413 => ("PayloadTooLarge", "Payload Too Large"),
        415 => ("UnsupportedMediaType", "Unsupported Media Type"),
        429 => ("RateLimitExceeded", "Rate Limit Exceeded"),
        500 => ("InternalServerError", "Internal Server Error"),
        501 => ("MethodNotImplemented", "Method Not Implemented"),
        502 => ("UpstreamFailure", "Upstream Failure"),
        503 => ("NotEnoughResources", "Not Enough Resources"),
        504 => ("UpstreamTimeout", "Upstream Timeout"),
        _ => return None,
    })
}

/// Reference PipethroughUpstreamError: 500 becomes 502.
struct UpstreamError {
    status: u16,
    headers: HeaderMap,
    error: Option<String>,
    message: Option<String>,
}

impl UpstreamError {
    async fn read(resp: axum::http::response::Parts, body: Body) -> UpstreamError {
        let upstream_status = resp.status.as_u16();
        let status = if upstream_status == 500 { 502 } else { upstream_status };
        let mut headers = HeaderMap::new();
        for name in &RES_HEADERS[4..] {
            if let Some(v) = resp.headers.get(name) {
                headers.insert(name.clone(), v.clone());
            }
        }
        // (the reference reads it unless it says it isn't JSON)
        let json_body =
            resp.headers.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).is_none_or(is_json_content_type);
        let (mut error, mut message) = (None, None);
        // decodable codings only, else the body is dropped unread
        if let Some(codings) = read_after_write::codings(&resp.headers).filter(|_| json_body) {
            let buf = axum::body::to_bytes(body, MAX_ERROR_BYTES).await;
            let decoded = buf.ok().and_then(|b| read_after_write::decode(b, &codings, MAX_ERROR_BYTES).ok());
            if let Some(v) = decoded.and_then(|b| serde_json::from_slice::<J>(&b).ok()) {
                error = v.get("error").and_then(|e| e.as_str()).map(String::from);
                message = v.get("message").and_then(|e| e.as_str()).map(String::from);
            }
        }
        UpstreamError { status, headers, error, message }
    }

    fn into_response(self) -> Response {
        let defaults = response_type(self.status);
        let error = self.error.or_else(|| defaults.map(|d| d.0.to_string()));
        let message = self.message.filter(|m| !m.is_empty()).or_else(|| defaults.map(|d| d.1.to_string()));
        let mut body = serde_json::Map::new();
        if let Some(e) = error {
            body.insert("error".into(), J::String(e));
        }
        if let Some(m) = message {
            body.insert("message".into(), J::String(m));
        }
        let code = StatusCode::from_u16(self.status).unwrap_or(StatusCode::BAD_GATEWAY);
        (code, self.headers, Json(J::Object(body))).into_response()
    }
}

async fn upstream_error(resp: axum::http::response::Parts, body: Body) -> Response {
    UpstreamError::read(resp, body).await.into_response()
}

struct Forward<'a> {
    method: Method,
    /// Forwarded verbatim (the reference uses req.originalUrl).
    path_and_query: &'a str,
    headers: &'a HeaderMap,
    body: Option<Body>,
    /// Service-auth issuer; None forwards without credentials.
    iss: Option<&'a str>,
    lxm: &'a str,
    /// Instead of the target's DID (getFeed: the feed generator's).
    aud: Option<&'a str>,
    /// Instead of the client's (read-after-write asks only for encodings it
    /// can decode).
    accept_encoding: Option<header::HeaderValue>,
}

impl<'a> Forward<'a> {
    fn new(
        method: Method,
        path_and_query: &'a str,
        headers: &'a HeaderMap,
        body: Option<Body>,
        iss: Option<&'a str>,
        lxm: &'a str,
    ) -> Self {
        Forward { method, path_and_query, headers, body, iss, lxm, aud: None, accept_encoding: None }
    }
}

fn path_and_query(uri: &Uri) -> &str {
    uri.path_and_query().map(|p| p.as_str()).unwrap_or(uri.path())
}

// Proxying is the hottest path a PDS serves, so per request it reads no
// account and signs no JWT:
// - an account's signing key + status are cached on its owner, valid only
//   in the partition epoch they were read in (another node's changes while
//   it owned the DID never show through). The owner's worker drops the
//   entry once an account change applies ([`account_changed`]), so
//   takedowns and key rotations apply to the next request; ACCT_TTL is a
//   backstop;
// - service JWTs are reused per (iss, aud, lxm, signing key) for half their
//   lifetime; the key is in the cache key so a rotation mints fresh tokens.

const ACCT_TTL: Duration = Duration::from_secs(60);
const JWT_REUSE: Duration = Duration::from_secs(SERVICE_JWT_TTL_SECS / 2);
const CACHE_SHARDS: usize = 64;

type Shard<K, V> = parking_lot::Mutex<std::collections::HashMap<K, (V, std::time::Instant)>>;

/// Capped by `kind`'s [`crate::caches`] cap.
struct TtlCache<K, V> {
    shards: Vec<Shard<K, V>>,
    kind: crate::caches::Cache,
    /// Per shard, bumped under its lock by every [`TtlCache::invalidate`], so
    /// a load that raced one is not cached.
    gens: Vec<std::sync::atomic::AtomicU64>,
}

fn fixed_hash<Q: std::hash::Hash + ?Sized>(k: &Q) -> u64 {
    use std::hash::Hasher;
    let mut h = std::hash::DefaultHasher::new();
    k.hash(&mut h);
    h.finish()
}

impl<K: Send, V: Send> crate::caches::Len for TtlCache<K, V> {
    fn len(&self) -> usize {
        self.shards.iter().map(|s| s.lock().len()).sum()
    }
}

impl<K: std::hash::Hash + Eq, V: Clone> TtlCache<K, V> {
    fn new(kind: crate::caches::Cache) -> Self {
        TtlCache {
            shards: (0..CACHE_SHARDS).map(|_| parking_lot::Mutex::new(Default::default())).collect(),
            gens: (0..CACHE_SHARDS).map(|_| Default::default()).collect(),
            kind,
        }
    }
    fn shard_of<Q: std::hash::Hash + ?Sized>(k: &Q) -> usize {
        (fixed_hash(k) as usize) % CACHE_SHARDS
    }
    fn shard<Q: std::hash::Hash + ?Sized>(&self, k: &Q) -> &Shard<K, V> {
        &self.shards[Self::shard_of(k)]
    }
    /// Taken before reading what will be cached under `k`; pass to
    /// [`TtlCache::put_unless_changed`].
    fn generation<Q: std::hash::Hash + ?Sized>(&self, k: &Q) -> u64 {
        self.gens[Self::shard_of(k)].load(std::sync::atomic::Ordering::SeqCst)
    }
    /// Drops `k`, and keeps loads that began before this from caching what
    /// they read.
    fn invalidate<Q>(&self, k: &Q)
    where
        K: std::borrow::Borrow<Q>,
        Q: std::hash::Hash + Eq + ?Sized,
    {
        let i = Self::shard_of(k);
        let mut m = self.shards[i].lock();
        self.gens[i].fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        m.remove(k);
    }
    fn get<Q>(&self, k: &Q, max_age: Duration) -> Option<V>
    where
        K: std::borrow::Borrow<Q>,
        Q: std::hash::Hash + Eq + ?Sized,
    {
        self.get_aged(k).filter(|(_, age)| *age < max_age).map(|(v, _)| v)
    }
    fn get_aged<Q>(&self, k: &Q) -> Option<(V, Duration)>
    where
        K: std::borrow::Borrow<Q>,
        Q: std::hash::Hash + Eq + ?Sized,
    {
        let m = self.shard(k).lock();
        m.get(k).map(|(v, t)| (v.clone(), t.elapsed()))
    }
    fn put(&self, k: K, v: V, max_age: Duration) {
        self.put_unless_changed(k, v, max_age, None)
    }
    /// [`TtlCache::put`], skipped if `k`'s shard was invalidated since `gen`
    /// was taken.
    fn put_unless_changed(&self, k: K, v: V, max_age: Duration, gen: Option<u64>) {
        let i = Self::shard_of(&k);
        let cap = crate::caches::cap(self.kind).div_ceil(CACHE_SHARDS).max(1);
        let mut m = self.shards[i].lock();
        if gen.is_some_and(|g| g != self.gens[i].load(std::sync::atomic::Ordering::SeqCst)) {
            return;
        }
        if m.len() >= cap {
            m.retain(|_, (_, t)| t.elapsed() < max_age);
            if m.len() >= cap {
                m.clear();
            }
        }
        m.insert(k, (v, std::time::Instant::now()));
    }
}

#[derive(Clone)]
struct CachedAcct {
    key: Arc<Keypair>,
    /// A hash of the public key: part of the JWT cache key.
    key_id: u64,
    status: Option<String>,
    /// (partition, epoch) it was read in
    part: (vlsync_store::slots::ShardId, u64),
}

/// (iss, aud, lxm, key id, jwt)
type CachedJwt = Arc<(String, String, String, u64, Arc<str>)>;

static ACCTS: std::sync::LazyLock<Arc<TtlCache<String, CachedAcct>>> = std::sync::LazyLock::new(|| {
    use crate::caches::{track, Cache};
    track(Cache::ProxyAccounts, Arc::new(TtlCache::new(Cache::ProxyAccounts)))
});
static JWTS: std::sync::LazyLock<Arc<TtlCache<u64, CachedJwt>>> = std::sync::LazyLock::new(|| {
    use crate::caches::{track, Cache};
    track(Cache::ProxyJwts, Arc::new(TtlCache::new(Cache::ProxyJwts)))
});

/// The worker calls this once an account change is applied, before acking.
pub(crate) fn account_changed(did: &str) {
    ACCTS.invalidate(did);
}

async fn cached_account(app: &App, did: &str) -> XResult<CachedAcct> {
    cached_account_counted(app, did, true).await
}

/// An account's signing key and status from the proxy's account cache, for
/// Spaces (a commit signed per read, the repo's availability): a hot repo's
/// reads touch no state. Not counted in `vlpds_proxy_cache_total`.
pub(crate) async fn account_key_status(app: &App, did: &str) -> XResult<(Arc<Keypair>, Option<String>)> {
    let a = cached_account_counted(app, did, false).await?;
    Ok((a.key, a.status))
}

async fn cached_account_counted(app: &App, did: &str, count: bool) -> XResult<CachedAcct> {
    let part = app.partition(did)?;
    let prev = match ACCTS.get_aged(did) {
        Some((a, age)) if age < ACCT_TTL && a.part == (part.id, part.epoch) => {
            if count {
                crate::metrics::PROXY_CACHE.with_label_values(&["account_hit"]).inc();
            }
            return Ok(a);
        }
        prev => prev.map(|(a, _)| a),
    };
    if count {
        crate::metrics::PROXY_CACHE.with_label_values(&["account_miss"]).inc();
    }
    // borrowed fields only: a full `Account` parse buffers the whole
    // document (its flattened extension map) and costs more than the read
    #[derive(serde::Deserialize)]
    struct KeyAndStatus<'a> {
        #[serde(borrow)]
        wrapped_signing_key: std::borrow::Cow<'a, str>,
        #[serde(borrow)]
        signing_pubkey: std::borrow::Cow<'a, str>,
        #[serde(default, borrow)]
        status: Option<std::borrow::Cow<'a, str>>,
    }
    let gen = ACCTS.generation(did);
    if let Some(sp) = &app.spaces {
        sp.cache_fills.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    let raw = part
        .db
        .get(state::account_key(did))
        .await
        .map_err(XrpcError::from_err)?
        .ok_or_else(|| XrpcError::bad("AccountNotFound", format!("no account {did}")))?;
    let acct: KeyAndStatus = serde_json::from_slice(&raw).map_err(XrpcError::from_err)?;
    // a rewrap under a new KEK changes the wrapped form, not the key
    let key_id = fixed_hash(&*acct.signing_pubkey);
    // an unchanged key skips the keyring (and a KMS unwrap)
    let key = match prev.filter(|p| p.key_id == key_id) {
        Some(p) => p.key,
        None => app.secrets.signing_key(did, &acct.wrapped_signing_key, &acct.signing_pubkey).await?,
    };
    let c = CachedAcct { key, key_id, status: acct.status.map(Into::into), part: (part.id, part.epoch) };
    ACCTS.put_unless_changed(did.to_string(), c.clone(), ACCT_TTL, Some(gen));
    Ok(c)
}

fn service_jwt(acct: &CachedAcct, iss: &str, aud: &str, lxm: &str) -> XResult<Arc<str>> {
    let h = fixed_hash(&(iss, aud, lxm, acct.key_id));
    let hit = |j: &CachedJwt| j.0 == iss && j.1 == aud && j.2 == lxm && j.3 == acct.key_id;
    if let Some(j) = JWTS.get(&h, JWT_REUSE).filter(hit) {
        crate::metrics::PROXY_CACHE.with_label_values(&["jwt_hit"]).inc();
        return Ok(j.4.clone());
    }
    crate::metrics::PROXY_CACHE.with_label_values(&["jwt_miss"]).inc();
    let j: Arc<str> = crate::auth::service_auth_jwt(&acct.key, iss, aud, Some(lxm), SERVICE_JWT_TTL_SECS)?.into();
    JWTS.put(h, Arc::new((iss.into(), aud.into(), lxm.into(), acct.key_id, j.clone())), JWT_REUSE);
    Ok(j)
}

#[derive(Clone)]
struct Endpoint {
    /// `scheme://host[:port]`
    origin: Arc<str>,
    /// `host:port` of a plain `http://` endpoint, for the HTTP/1.1 fast path
    h1: Option<Arc<str>>,
}

/// The last one per thread is kept: proxied calls nearly always go to the
/// one AppView.
fn endpoint(url: &str) -> XResult<Endpoint> {
    thread_local! {
        static LAST: std::cell::RefCell<Option<(String, Endpoint)>> = const { std::cell::RefCell::new(None) };
    }
    if let Some(e) = LAST.with_borrow(|l| l.as_ref().filter(|(u, _)| u == url).map(|(_, e)| e.clone())) {
        return Ok(e);
    }
    let base = reqwest::Url::parse(url).map_err(|_| XrpcError::bad("InvalidRequest", "invalid service endpoint"))?;
    let h1 = match (base.scheme(), base.host_str(), base.port_or_known_default()) {
        ("http", Some(host), Some(port)) => Some(format!("{host}:{port}").into()),
        _ => None,
    };
    let e = Endpoint { origin: base.origin().ascii_serialization().into(), h1 };
    LAST.set(Some((url.to_string(), e.clone())));
    Ok(e)
}

/// At most [`MAX_RESPONSE_BYTES`]; [`BODY_TIMEOUT`] without progress fails
/// it. The idle timer is armed only while the upstream keeps us waiting, so
/// a response that arrived with its head costs no timer (each tokio timer
/// operation takes the runtime's one timer-wheel lock).
struct UpstreamBody<B> {
    inner: B,
    seen: usize,
    idle: Option<std::pin::Pin<Box<tokio::time::Sleep>>>,
    progressed: bool,
}

impl<B> UpstreamBody<B> {
    fn new(inner: B) -> Self {
        UpstreamBody { inner, seen: 0, idle: None, progressed: false }
    }
}

type BoxError = Box<dyn std::error::Error + Send + Sync>;

impl<B> hyper::body::Body for UpstreamBody<B>
where
    B: hyper::body::Body<Data = Bytes> + Unpin,
    B::Error: Into<BoxError>,
{
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, BoxError>>> {
        use std::task::Poll;
        let this = &mut *self;
        match std::pin::Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(f))) => {
                if let Some(d) = f.data_ref() {
                    this.seen += d.len();
                    if this.seen > MAX_RESPONSE_BYTES {
                        return Poll::Ready(Some(Err("upstream response too large".into())));
                    }
                }
                this.progressed = true;
                Poll::Ready(Some(Ok(f)))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e.into()))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => {
                let deadline = tokio::time::Instant::now() + BODY_TIMEOUT;
                let progressed = std::mem::take(&mut this.progressed);
                let idle = match &mut this.idle {
                    Some(s) => {
                        if progressed {
                            s.as_mut().reset(deadline);
                        }
                        s
                    }
                    None => this.idle.insert(Box::pin(tokio::time::sleep_until(deadline))),
                };
                if std::future::Future::poll(idle.as_mut(), cx).is_ready() {
                    return Poll::Ready(Some(Err("upstream body timeout".into())));
                }
                Poll::Pending
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}

/// Read whole when small, so the upstream connection is released before
/// the client reads anything; else streamed under a write-progress deadline
/// ([`crate::http::stall`]).
async fn response_body<B>(r: axum::http::Response<B>) -> Result<(axum::http::response::Parts, Body), String>
where
    B: hyper::body::Body<Data = Bytes> + Send + Unpin + 'static,
    B::Error: Into<BoxError>,
{
    let (parts, body) = r.into_parts();
    let body = UpstreamBody::new(body);
    let len = parts.headers.get(header::CONTENT_LENGTH).and_then(|v| v.to_str().ok()?.parse::<u64>().ok());
    if len.is_some_and(|n| n <= BUFFER_SMALL) {
        let b = collect(body).await.map_err(|e| format!("upstream body: {e}"))?;
        return Ok((parts, Body::from(b)));
    }
    Ok((parts, Body::new(crate::http::stall::Watched::new(body))))
}

/// One chunk is passed on without a copy.
async fn collect<B>(mut body: B) -> Result<Bytes, BoxError>
where
    B: hyper::body::Body<Data = Bytes, Error = BoxError> + Unpin,
{
    let mut first: Option<Bytes> = None;
    let mut rest: Option<Vec<u8>> = None;
    while let Some(f) = std::future::poll_fn(|cx| std::pin::Pin::new(&mut body).poll_frame(cx)).await {
        let Ok(d) = f?.into_data() else { continue };
        match (&first, &mut rest) {
            (None, _) => first = Some(d),
            (Some(f), None) => {
                let mut v = Vec::with_capacity(f.len() + d.len());
                v.extend_from_slice(f);
                v.extend_from_slice(&d);
                rest = Some(v);
            }
            (Some(_), Some(v)) => v.extend_from_slice(&d),
        }
    }
    Ok(match rest {
        Some(v) => Bytes::from(v),
        None => first.unwrap_or_default(),
    })
}

/// `acct`: the issuer's account, if already loaded.
async fn forward(app: &App, target: &Target<'_>, f: Forward<'_>, acct: Option<&CachedAcct>) -> XResult<Response> {
    let (parts, body) = send(app, target, f, acct).await?;
    if parts.status.as_u16() >= 400 {
        return Ok(upstream_error(parts, body).await);
    }
    Ok(passthrough(parts, body))
}

fn passthrough(parts: axum::http::response::Parts, body: Body) -> Response {
    let mut out = Response::new(body);
    *out.status_mut() = parts.status;
    let headers = out.headers_mut();
    for name in RES_HEADERS {
        for v in parts.headers.get_all(&name) {
            headers.append(name.clone(), v.clone());
        }
    }
    out
}

/// The upstream response, whatever its status.
async fn send(
    app: &App,
    target: &Target<'_>,
    f: Forward<'_>,
    acct: Option<&CachedAcct>,
) -> XResult<(axum::http::response::Parts, Body)> {
    let authorization = match f.iss {
        Some(iss) => {
            let fetched;
            let acct = match acct {
                Some(a) => a,
                None => {
                    fetched = cached_account(app, iss).await?;
                    &fetched
                }
            };
            // the reference's phase 1 of service-auth updates: aud is the bare DID
            Some(service_jwt(acct, iss, f.aud.unwrap_or(&target.did), f.lxm)?)
        }
        None => None,
    };

    let ep = endpoint(&target.url)?;
    let with_body = f.body.is_some();
    let headers = forward_headers(f.headers, with_body, authorization.as_deref(), f.accept_encoding);
    let started = std::time::Instant::now();
    let report = f.lxm == CREATE_REPORT;
    let sent = match ep.h1.as_ref().filter(|_| target.trusted) {
        // operator-configured plain-HTTP upstream: the HTTP/1.1 fast path
        Some(authority) => {
            let mut req = axum::http::Request::new(f.body.unwrap_or_default());
            *req.method_mut() = f.method;
            *req.uri_mut() = axum::http::Uri::try_from(f.path_and_query)
                .map_err(|_| XrpcError::bad("InvalidRequest", "invalid xrpc path"))?;
            *req.headers_mut() = headers;
            let send = crate::http::h1::send("public", authority, req);
            match tokio::time::timeout(HEADERS_TIMEOUT, send).await {
                Ok(Ok(r)) => response_body(r).await,
                Ok(Err(e)) => Err(e.to_string()),
                Err(_) => Err("headers timeout".to_string()),
            }
        }
        None => {
            let mut url = String::with_capacity(ep.origin.len() + f.path_and_query.len());
            url.push_str(&ep.origin);
            url.push_str(f.path_and_query);
            let rb = if target.trusted {
                crate::http::proxy().request(f.method, &url)
            } else {
                vlatproto::http::guarded(app.config.dev_mode).request(f.method, &url).map_err(|e| {
                    tracing::warn!(endpoint = %target.url, "proxy target refused: {e}");
                    upstream_failure("Upstream service unreachable")
                })?
            };
            let mut rb = rb.headers(headers);
            if let Some(b) = f.body {
                rb = rb.body(reqwest::Body::wrap_stream(b.into_data_stream()));
            }
            match tokio::time::timeout(HEADERS_TIMEOUT, rb.send()).await {
                Ok(Ok(r)) => response_body(axum::http::Response::from(r)).await,
                Ok(Err(e)) => Err(e.to_string()),
                Err(_) => Err("headers timeout".to_string()),
            }
        }
    };
    observe_upstream(&target.service_id, started, sent.as_ref().ok().map(|(p, _)| p.status), report);
    sent.map_err(|e| {
        tracing::warn!(endpoint = %target.url, path = f.path_and_query, "proxy upstream error: {e}");
        upstream_failure("Upstream service unreachable")
    })
}

/// `status` None: unreachable.
fn observe_upstream(service_id: &str, started: std::time::Instant, status: Option<StatusCode>, report: bool) {
    let service = crate::metrics::upstream_service(service_id);
    crate::metrics::UPSTREAM_DURATION.with_label_values(&[service]).observe(started.elapsed().as_secs_f64());
    let result = match status.map(|s| s.as_u16()) {
        None => "unreachable",
        Some(500..) => "server_error",
        Some(400..) => "client_error",
        Some(_) => "ok",
    };
    crate::metrics::UPSTREAM_REQUESTS.with_label_values(&[service, result]).inc();
    if report {
        let ok = status.is_some_and(|s| s.is_success());
        crate::metrics::REPORTS.with_label_values(&[if ok { "ok" } else { "failed" }]).inc();
    }
}

/// Reference `pipethrough(ctx, req)` without an issuer, e.g. repo.getRecord
/// for repos not hosted here.
pub(super) async fn pipethrough_unauthed(app: &App, headers: &HeaderMap, uri: &Uri, lxm: &str) -> XResult<Response> {
    let target = match proxy_header(headers)? {
        Some(h) => parse_proxy_header(app, h).await?,
        None => default_target(app, lxm)?
            .or_else(|| configured(&app.config.appview, "bsky_appview"))
            .ok_or_else(|| no_service(lxm))?,
    };
    let f = Forward::new(Method::GET, path_and_query(uri), headers, None, None, lxm);
    forward(app, &target, f, None).await
}

/// Only a missing account is 403 `AccountNotFound`; anything else (shard
/// moving, store or KMS failure) keeps its own status, so clients retry a
/// 503 instead of treating the account as gone.
async fn check_takedown(app: &App, did: &str, allow_takendown: bool) -> XResult<CachedAcct> {
    let acct = cached_account(app, did).await.map_err(|e| match e.error.as_str() {
        "AccountNotFound" => xerr(StatusCode::FORBIDDEN, "AccountNotFound", "Account not found"),
        _ => e,
    })?;
    if !allow_takendown && matches!(acct.status.as_deref(), Some("takendown") | Some("suspended")) {
        return Err(super::takedown_error());
    }
    Ok(acct)
}

/// By DID hash.
static IN_FLIGHT: std::sync::LazyLock<Vec<parking_lot::Mutex<std::collections::HashMap<u64, u32>>>> =
    std::sync::LazyLock::new(|| (0..CACHE_SHARDS).map(|_| Default::default()).collect());

/// Dropped when its response body is done.
struct InFlight(u64);

impl InFlight {
    fn shard(h: u64) -> &'static parking_lot::Mutex<std::collections::HashMap<u64, u32>> {
        &IN_FLIGHT[(h % CACHE_SHARDS as u64) as usize]
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        let mut m = Self::shard(self.0).lock();
        if let Some(n) = m.get_mut(&self.0) {
            *n -= 1;
            if *n == 0 {
                m.remove(&self.0);
            }
        }
    }
}

/// Requests for an account are served by its owner, so this counts them
/// across entry nodes.
fn admit(did: &str) -> XResult<InFlight> {
    let h = fixed_hash(did);
    let mut m = InFlight::shard(h).lock();
    let n = m.entry(h).or_insert(0);
    if *n >= MAX_IN_FLIGHT_PER_ACCOUNT {
        crate::metrics::PROXY_REJECTED.with_label_values(&["account_cap"]).inc();
        return Err(xerr(
            StatusCode::TOO_MANY_REQUESTS,
            "RateLimitExceeded",
            "Too many concurrent proxied requests for this account",
        ));
    }
    *n += 1;
    Ok(InFlight(h))
}

fn user_did(creds: &Credentials) -> XResult<&str> {
    creds.user_did()
}

/// The identity-encoded JSON body, or the upstream's error.
async fn appview_json(app: &App, lxm: &str, params: &[(&str, &str)], iss: Option<(&str, &CachedAcct)>) -> XResult<J> {
    let target = configured(&app.config.appview, "bsky_appview").ok_or_else(|| no_service(lxm))?;
    let url = reqwest::Url::parse_with_params(&format!("http://x/xrpc/{lxm}"), params)
        .map_err(|_| XrpcError::bad("InvalidRequest", "invalid xrpc path"))?;
    let pq = match url.query() {
        Some(q) => format!("{}?{q}", url.path()),
        None => url.path().to_string(),
    };
    let headers = HeaderMap::new();
    let f = Forward::new(Method::GET, &pq, &headers, None, iss.map(|(d, _)| d), lxm);
    let (parts, body) = send(app, &target, f, iss.map(|(_, a)| a)).await?;
    if parts.status.as_u16() >= 400 {
        let e = UpstreamError::read(parts, body).await;
        let defaults = response_type(e.status);
        return Err(XrpcError {
            status: StatusCode::from_u16(e.status).unwrap_or(StatusCode::BAD_GATEWAY),
            message: e.message.or_else(|| defaults.map(|d| d.1.to_string())).unwrap_or_default(),
            error: e.error.or_else(|| defaults.map(|d| d.0.to_string())).unwrap_or_default(),
        });
    }
    let buf = axum::body::to_bytes(body, usize::MAX).await.map_err(|e| upstream_failure(&e.to_string()))?;
    serde_json::from_slice(&buf).map_err(|_| upstream_failure("invalid upstream response"))
}

/// By feed URI.
static FEED_DIDS: std::sync::LazyLock<TtlCache<String, Arc<str>>> =
    std::sync::LazyLock::new(|| TtlCache::new(crate::caches::Cache::DidDocs));
const FEED_DID_TTL: Duration = Duration::from_secs(60);

/// From the feed's record on the AppView (reference getFeed.ts).
async fn feed_generator_did(app: &App, pq: &str) -> XResult<Arc<str>> {
    let url = reqwest::Url::parse(&format!("http://x{pq}"))
        .map_err(|_| XrpcError::bad("InvalidRequest", "invalid xrpc path"))?;
    let feed = url
        .query_pairs()
        .find(|(k, _)| k == "feed")
        .map(|(_, v)| v.into_owned())
        .ok_or_else(|| XrpcError::bad("InvalidRequest", "Params must have the property \"feed\""))?;
    if let Some(d) = FEED_DIDS.get(feed.as_str(), FEED_DID_TTL) {
        return Ok(d);
    }
    let bad = || XrpcError::bad("InvalidRequest", "Invalid feed: must be an at-uri");
    let rest = feed.strip_prefix("at://").ok_or_else(bad)?;
    let mut parts = rest.splitn(3, '/');
    let (repo, collection, rkey) =
        (parts.next().ok_or_else(bad)?, parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    let rec = appview_json(
        app,
        "com.atproto.repo.getRecord",
        &[("repo", repo), ("collection", collection), ("rkey", rkey)],
        None,
    )
    .await?;
    let did: Arc<str> = rec
        .pointer("/value/did")
        .and_then(|d| d.as_str())
        .ok_or_else(|| XrpcError::bad("UnknownFeed", "could not resolve feed did"))?
        .into();
    FEED_DIDS.put(feed, did.clone(), FEED_DID_TTL);
    Ok(did)
}

pub async fn fallback(State(app): AppState, req: Request) -> Response {
    match proxy_request(&app, req).await {
        Ok(r) => r,
        Err(e) => e.into_response(),
    }
}

async fn proxy_request(app: &App, req: Request) -> XResult<Response> {
    let mut slot = None;
    let r = proxy_request_admitted(app, req, &mut slot).await;
    match (r, slot) {
        // the slot lasts until the response body is done
        (Ok(r), Some(slot)) => Ok(r.map(|b| Body::new(crate::http::stall::Watched::unwatched(b, slot)))),
        (r, _) => r,
    }
}

async fn proxy_request_admitted(app: &App, req: Request, slot: &mut Option<InFlight>) -> XResult<Response> {
    let Some(nsid) = req.uri().path().strip_prefix("/xrpc/") else {
        return Ok(StatusCode::NOT_FOUND.into_response());
    };
    let lxm = nsid.to_string();
    if !valid_nsid(&lxm) {
        return Err(XrpcError::bad("InvalidRequest", "invalid xrpc path"));
    }
    // never proxied, with --spaces on or off: an atproto-proxy header would
    // otherwise get service auth minted for these methods (a notifyWrite as
    // the account) sent wherever it names
    if crate::space::is_space_nsid(&lxm) {
        return Err(xerr(StatusCode::NOT_IMPLEMENTED, "MethodNotImplemented", "Method Not Implemented"));
    }
    let method = req.method().clone();
    if method != Method::GET && method != Method::HEAD && method != Method::POST {
        return Err(XrpcError::bad("InvalidRequest", "XRPC requests only supports GET and POST"));
    }
    if lxm_in(PROTECTED_METHODS, &lxm) {
        return Err(XrpcError::bad("InvalidToken", "Bad token method"));
    }
    let header = proxy_header(req.headers())?.map(String::from);
    // anything to proxy to? (before authenticating or touching the network)
    let default = match &header {
        Some(_) => None,
        None => Some(
            default_target(app, &lxm)?
                .ok_or_else(|| xerr(StatusCode::NOT_IMPLEMENTED, "MethodNotImplemented", "Method Not Implemented"))?,
        ),
    };

    let (parts, body) = req.into_parts();
    let creds = super::authn::authenticate(app, &parts).await?;
    let did = user_did(&creds)?;

    let target = match default {
        Some(t) => t,
        None => parse_proxy_header(app, header.as_deref().expect("no default without a header")).await?,
    };
    creds.need_rpc(&lxm, &target.scope_aud())?;
    if matches!(creds, Credentials::AppPassword { privileged: false, .. }) && lxm_in(PRIVILEGED_METHODS, &lxm) {
        return Err(XrpcError::bad("InvalidToken", "Bad token method"));
    }
    let acct = check_takedown(app, did, lxm == APPEAL_ACTIONED_SUBJECT).await?;
    *slot = Some(admit(did)?);

    let body = (method == Method::POST).then_some(body);
    let pq = path_and_query(&parts.uri);
    let mut fwd = Forward::new(method, pq, &parts.headers, body, Some(did), &lxm);
    // the AppView methods the reference serves itself, only with an AppView
    // configured like the reference
    let feed_did;
    if fwd.method == Method::GET && app.config.appview.is_some() {
        if lxm == GET_FEED {
            // the token is for the feed generator, which the AppView calls with it
            creds.need_rpc(GET_FEED_SKELETON, &target.scope_aud())?;
            feed_did = feed_generator_did(app, pq).await?;
            fwd.aud = Some(&feed_did);
            fwd.lxm = GET_FEED_SKELETON;
        } else if let Some(kind) = read_after_write::Kind::of(&lxm) {
            return read_after_write::proxy(app, &target, fwd, &acct, kind).await;
        }
    }
    forward(app, &target, fwd, Some(&acct)).await
}

/// The AppView audience whose preferences this PDS stores locally.
fn local_prefs_aud(app: &App) -> String {
    match &app.config.appview {
        Some((_, did)) => format!("{did}#bsky_appview"),
        None => format!("{}#bsky_appview", app.jwt.service_did),
    }
}

/// Scope audience and, when the request names a different AppView, the
/// target to pipe through to instead of serving locally.
async fn prefs_target<'a>(
    app: &'a App,
    creds: &Credentials,
    headers: &HeaderMap,
    lxm: &str,
) -> XResult<Option<Target<'a>>> {
    let local = local_prefs_aud(app);
    let aud = match proxy_header(headers)? {
        Some(h) => h.to_string(),
        None => local.clone(),
    };
    creds.need_rpc(lxm, &aud)?;
    if aud == local {
        return Ok(None);
    }
    Ok(Some(parse_proxy_header(app, &aud).await?))
}

/// May see and set personalDetailsPref.
fn has_access_full(creds: &Credentials) -> bool {
    matches!(creds, Credentials::Session { .. })
}

/// The preferences row with fixed values (golden fixtures, `super::private_rows`).
pub(super) fn fixture_rows(did: &str) -> Vec<super::private_rows::PrivateRow> {
    let prefs = json!([
        {"$type": "app.bsky.actor.defs#adultContentPref", "enabled": false},
        {"$type": "app.bsky.actor.defs#savedFeedsPrefV2", "items": [{"id": "3l3qo2vutsw2b", "type": "timeline", "value": "following", "pinned": true}]},
        {"$type": PERSONAL_DETAILS_PREF, "birthDate": "1990-01-01T00:00:00.000Z"},
    ]);
    vec![(did.into(), PREFS_KEY.into(), super::private_rows::enc(&prefs))]
}

/// None: not the preferences row.
pub(super) fn check_row(_routing: &str, name: &str, val: &[u8]) -> Option<anyhow::Result<&'static str>> {
    (name == PREFS_KEY).then(|| {
        let prefs: Vec<J> = serde_json::from_slice(val)?;
        anyhow::ensure!(prefs.iter().all(|p| pref_type(p).is_some()), "a preference without $type");
        anyhow::ensure!(serde_json::to_vec(&prefs)? == val, "preferences re-encode differently");
        Ok("preferences")
    })
}

fn pref_type(p: &J) -> Option<&str> {
    p.get("$type").and_then(|t| t.as_str())
}

fn pref_allowed(ty: &str, full: bool) -> bool {
    full || ty != PERSONAL_DETAILS_PREF
}

fn pref_in_namespace(ty: &str) -> bool {
    ty == PREFS_NAMESPACE || ty.starts_with("app.bsky.")
}

/// Age in whole years at `today` (UTC); None if the date can't be parsed
/// (JS `new Date()` gives NaN, so every age comparison is false).
fn age_from_datestring(birth: &str, today: chrono::NaiveDate) -> Option<i32> {
    use chrono::Datelike;
    let bday = chrono::DateTime::parse_from_rfc3339(birth)
        .map(|d| d.with_timezone(&chrono::Utc).date_naive())
        .ok()
        .or_else(|| chrono::NaiveDate::parse_from_str(birth.get(..10)?, "%Y-%m-%d").ok())?;
    let mut age = today.year() - bday.year();
    if (today.month(), today.day()) < (bday.month(), bday.day()) {
        age -= 1;
    }
    Some(age)
}

async fn load_prefs(app: &App, did: &str) -> XResult<Vec<J>> {
    match app.get_private(did, PREFS_KEY).await? {
        Some(b) => serde_json::from_slice(&b).map_err(XrpcError::from_err),
        None => Ok(Vec::new()),
    }
}

async fn get_preferences(State(app): AppState, Auth(creds): Auth, headers: HeaderMap, uri: Uri) -> XResult<Response> {
    // the moderation service reads any account's preferences (reference
    // authorizationOrModService, the undocumented `did` parameter)
    if let Credentials::ModService { .. } = creds {
        let did = mod_service_prefs_did(&app, &headers, &uri)?;
        return Ok(Json(json!({"preferences": visible_prefs(&app, &did, true).await?})).into_response());
    }
    let did = user_did(&creds)?.to_string();
    if let Some(target) = prefs_target(&app, &creds, &headers, GET_PREFERENCES).await? {
        let f = Forward::new(Method::GET, path_and_query(&uri), &headers, None, Some(&did), GET_PREFERENCES);
        return forward(&app, &target, f, None).await;
    }
    let full = has_access_full(&creds);
    Ok(Json(json!({"preferences": visible_prefs(&app, &did, full).await?})).into_response())
}

/// The account from `?did=`.
fn mod_service_prefs_did(app: &App, headers: &HeaderMap, uri: &Uri) -> XResult<String> {
    if proxy_header(headers)?.is_some_and(|h| h != local_prefs_aud(app)) {
        return Err(XrpcError::bad("InvalidRequest", "Moderator requests cannot be proxied to other app views"));
    }
    let did = reqwest::Url::parse(&format!("http://x/?{}", uri.query().unwrap_or("")))
        .ok()
        .and_then(|u| u.query_pairs().find(|(k, _)| k == "did").map(|(_, v)| v.into_owned()))
        .filter(|d| vlatproto::syntax::valid_did(d))
        .ok_or_else(|| XrpcError::bad("InvalidRequest", "Invalid or missing did parameter"))?;
    Ok(did)
}

/// With the derived declared-age pref; personalDetailsPref only with `full`.
async fn visible_prefs(app: &App, did: &str, full: bool) -> XResult<Vec<J>> {
    let mut prefs = load_prefs(app, did).await?;
    let birth = prefs
        .iter()
        .find(|p| pref_type(p) == Some(PERSONAL_DETAILS_PREF))
        .and_then(|p| p.get("birthDate").and_then(|b| b.as_str()))
        .filter(|b| !b.is_empty())
        .map(String::from);
    if let Some(birth) = birth {
        let age = age_from_datestring(&birth, chrono::Utc::now().date_naive());
        let over = |n: i32| age.is_some_and(|a| a >= n);
        prefs.push(json!({"$type": DECLARED_AGE_PREF, "isOverAge13": over(13), "isOverAge16": over(16), "isOverAge18": over(18)}));
    }
    prefs.retain(|p| pref_type(p).is_some_and(|t| pref_allowed(t, full)));
    Ok(prefs)
}

async fn put_preferences(
    State(app): AppState,
    Auth(creds): Auth,
    headers: HeaderMap,
    uri: Uri,
    body: AxBytes,
) -> XResult<Response> {
    let did = user_did(&creds)?.to_string();
    if let Some(target) = prefs_target(&app, &creds, &headers, PUT_PREFERENCES).await? {
        let f = Forward::new(
            Method::POST,
            path_and_query(&uri),
            &headers,
            Some(Body::from(body)),
            Some(&did),
            PUT_PREFERENCES,
        );
        return forward(&app, &target, f, None).await;
    }
    check_takedown(&app, &did, false).await?;

    let input: J = serde_json::from_slice(&body)
        .map_err(|_| XrpcError::bad("InvalidRequest", "Request body must be a JSON object"))?;
    let Some(input) = input.as_object() else {
        return Err(XrpcError::bad("InvalidRequest", "Input must be an object"));
    };
    let values = match input.get("preferences") {
        None => return Err(XrpcError::bad("InvalidRequest", "Input must have the property \"preferences\"")),
        Some(J::Array(a)) => a,
        Some(_) => return Err(XrpcError::bad("InvalidRequest", "Input/preferences must be an array")),
    };
    if !values.iter().all(|v| v.is_object() && pref_type(v).is_some()) {
        return Err(XrpcError::bad("InvalidRequest", "Preference is missing a $type"));
    }
    let types: Vec<&str> = values.iter().filter_map(pref_type).collect();
    if !types.iter().all(|t| pref_in_namespace(t)) {
        return Err(XrpcError::bad(
            "InvalidRequest",
            format!("Some preferences are not in the {PREFS_NAMESPACE} namespace"),
        ));
    }
    let full = has_access_full(&creds);
    let forbidden: Vec<&str> = types.into_iter().filter(|t| !pref_allowed(t, full)).collect();
    if !forbidden.is_empty() {
        return Err(XrpcError::bad(
            "InvalidRequest",
            format!("Do not have authorization to set preferences: {}", forbidden.join(", ")),
        ));
    }
    // Keep the stored prefs this caller can't set; declaredAgePref is derived,
    // never stored. Serialized per account so concurrent puts can't lose each
    // other's kept prefs (requests for a DID are served by its owner).
    let ext = super::server::ext(&app);
    let _g = ext.lock(&format!("prefs:{did}")).await;
    let mut stored: Vec<J> = load_prefs(&app, &did)
        .await?
        .into_iter()
        .filter(|p| pref_type(p).is_some_and(|t| !(pref_in_namespace(t) && pref_allowed(t, full))))
        .collect();
    stored.extend(values.iter().filter(|p| pref_type(p) != Some(DECLARED_AGE_PREF)).cloned());
    let val = Bytes::from(serde_json::to_vec(&stored).map_err(XrpcError::from_err)?);
    let m = vlsync_store::segment::Mutation { key: Bytes::from(state::private_key(&did, PREFS_KEY)), val: Some(val) };
    app.put_private(&did, vec![m]).await?;
    Ok(StatusCode::OK.into_response())
}

async fn create_report(
    State(app): AppState,
    Auth(creds): Auth,
    headers: HeaderMap,
    body: AxBytes,
) -> XResult<Response> {
    let did = user_did(&creds)?.to_string();
    let aud = match proxy_header(&headers)? {
        Some(h) => h.to_string(),
        None => default_target(&app, CREATE_REPORT)?.ok_or_else(|| no_service(CREATE_REPORT))?.scope_aud(),
    };
    creds.need_rpc(CREATE_REPORT, &aud)?;

    let input: J = serde_json::from_slice(&body)
        .map_err(|_| XrpcError::bad("InvalidRequest", "Request body must be a JSON object"))?;
    if !input.is_object() {
        return Err(XrpcError::bad("InvalidRequest", "Input must be an object"));
    }
    if !input.get("reasonType").is_some_and(|v| v.is_string()) {
        return Err(XrpcError::bad("InvalidRequest", "Input must have the property \"reasonType\""));
    }
    if !input.get("subject").is_some_and(|v| v.is_object()) {
        return Err(XrpcError::bad("InvalidRequest", "Input must have the property \"subject\""));
    }
    // taken-down accounts may still report (appeals)
    let acct = check_takedown(&app, &did, true).await?;

    let target = match proxy_header(&headers)? {
        Some(h) => parse_proxy_header(&app, h).await?,
        None => default_target(&app, CREATE_REPORT)?.expect("createReport has a default target"),
    };
    let mut fwd_headers = HeaderMap::new();
    for name in ["accept-language", "atproto-accept-labelers"] {
        if let Some(v) = headers.get(name) {
            fwd_headers.insert(name, v.clone());
        }
    }
    fwd_headers.insert(header::CONTENT_TYPE, header::HeaderValue::from_static("application/json"));
    let body = Bytes::from(serde_json::to_vec(&input).map_err(XrpcError::from_err)?);
    fwd_headers.insert(header::CONTENT_LENGTH, body.len().into());
    let path = format!("/xrpc/{CREATE_REPORT}");
    let f = Forward::new(Method::POST, &path, &fwd_headers, Some(Body::from(body)), Some(&did), CREATE_REPORT);
    forward(&app, &target, f, Some(&acct)).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ages() {
        let today = chrono::NaiveDate::from_ymd_opt(2026, 6, 15).unwrap();
        assert_eq!(age_from_datestring("2010-06-15T00:00:00.000Z", today), Some(16));
        assert_eq!(age_from_datestring("2010-06-16", today), Some(15));
        assert_eq!(age_from_datestring("garbage", today), None);
    }

    #[test]
    fn nsids_and_content_types() {
        assert!(valid_nsid("app.bsky.feed.getTimeline"));
        assert!(!valid_nsid("app.bsky"));
        assert!(!valid_nsid("app..bsky.x"));
        assert!(!valid_nsid("app.bsky.x/y"));
        assert!(is_json_content_type("application/json; charset=utf-8"));
        assert!(is_json_content_type("application/problem+json"));
        assert!(!is_json_content_type("text/plain"));
    }
}
