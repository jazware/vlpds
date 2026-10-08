//! OAuth clients: client_id parsing, metadata fetching and validation (as the
//! reference `ClientManager`), redirect-URI matching, `private_key_jwt`
//! authentication (RFC 7523) and request objects (RFC 9101).

use super::jose::{jwk_thumbprint, jwk_to_key, DecodedJwt};
use super::util::{client_routing, now_secs, parse_form, Replay};
use super::OAuthError;
use serde_json::{json, Value as J};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

const CLIENT_ASSERTION_TYPE_JWT_BEARER: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
pub const AUTH_METHODS_SUPPORTED: [&str; 2] = ["none", "private_key_jwt"];

const DAY: i64 = 86_400;
/// Public clients.
pub const SESSION_LIFETIME: i64 = 14 * DAY;
pub const REFRESH_LIFETIME: i64 = 14 * DAY;
/// Confidential clients (the spec caps refresh tokens at 180 days).
pub const SESSION_LIFETIME_EXTENDED: i64 = 730 * DAY;
pub const REFRESH_LIFETIME_EXTENDED: i64 = 91 * DAY;
const CLIENT_ASSERTION_MAX_AGE: i64 = 60;
/// RFC 9101 §10.2 "less than a minute", as the reference.
const JAR_MAX_AGE: i64 = 59;
/// For `iat` / `nbf` in the future.
const CLOCK_TOLERANCE: i64 = 10;

const METADATA_MAX_BYTES: usize = 64 << 10;
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);
/// Metadata and keys are re-fetched at least this often.
const CACHE_TTL: Duration = Duration::from_secs(600);

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq)]
#[serde(tag = "method")]
pub enum ClientAuth {
    #[serde(rename = "none")]
    None,
    #[serde(rename = "private_key_jwt")]
    PrivateKeyJwt { alg: String, kid: String, jkt: String },
}

#[derive(Clone, Debug)]
pub struct Client {
    pub id: String,
    pub metadata: J,
    pub redirect_uris: Vec<String>,
    pub scopes: Vec<String>,
    pub grant_types: Vec<String>,
    pub response_types: Vec<String>,
    pub auth_method: String,
    /// Inline `jwks` or fetched `jwks_uri`.
    pub jwks: Vec<J>,
    pub loopback: bool,
}

impl Client {
    pub fn is_confidential(&self) -> bool {
        self.auth_method != "none"
    }

    pub fn session_lifetime(&self) -> i64 {
        if self.is_confidential() {
            SESSION_LIFETIME_EXTENDED
        } else {
            SESSION_LIFETIME
        }
    }

    pub fn refresh_lifetime(&self) -> i64 {
        if self.is_confidential() {
            REFRESH_LIFETIME_EXTENDED
        } else {
            REFRESH_LIFETIME
        }
    }

    pub fn default_redirect_uri(&self) -> Option<&str> {
        (self.redirect_uris.len() == 1).then(|| self.redirect_uris[0].as_str())
    }

    pub fn allows_redirect_uri(&self, uri: &str) -> bool {
        self.redirect_uris.iter().any(|a| compare_redirect_uri(a, uri))
    }

    /// RFC 7523 §3. Returns the binding to store with the session and the
    /// assertion's `jti` as a [`Replay`] the caller must claim.
    pub fn authenticate(
        &self,
        creds: &ClientCredentials,
        issuer: &str,
    ) -> Result<(ClientAuth, Option<Replay>), OAuthError> {
        if creds.client_id != self.id {
            return Err(OAuthError::invalid_client("client_id mismatch"));
        }
        match self.auth_method.as_str() {
            "none" => {
                if creds.client_assertion.is_some() {
                    return Err(OAuthError::invalid_client("client authentication not expected for public clients"));
                }
                Ok((ClientAuth::None, None))
            }
            "private_key_jwt" => {
                let Some(assertion) = &creds.client_assertion else {
                    return Err(OAuthError::invalid_request(
                        "client authentication method \"private_key_jwt\" required a \"client_assertion\"",
                    ));
                };
                if creds.client_assertion_type.as_deref() != Some(CLIENT_ASSERTION_TYPE_JWT_BEARER) {
                    return Err(OAuthError::invalid_client(&format!(
                        "Unsupported client_assertion_type \"{}\"",
                        creds.client_assertion_type.as_deref().unwrap_or("")
                    )));
                }
                let fail =
                    |m: &str| OAuthError::invalid_client(&format!("Validation of \"client_assertion\" failed: {m}"));
                let jwt = DecodedJwt::decode(assertion).map_err(|e| fail(&e))?;
                let alg = jwt.alg().to_string();
                let expected_alg =
                    self.metadata.get("token_endpoint_auth_signing_alg").and_then(|v| v.as_str()).unwrap_or("ES256");
                if alg != "ES256" || alg != expected_alg {
                    return Err(fail("unsupported \"alg\""));
                }
                let kid = jwt
                    .header
                    .get("kid")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| OAuthError::invalid_client("\"kid\" required in client_assertion"))?;
                let jwk = self
                    .jwks
                    .iter()
                    .find(|k| k.get("kid").and_then(|v| v.as_str()) == Some(kid))
                    .ok_or_else(|| fail("no applicable key found in the client JWKS"))?;
                if jwk.get("use").and_then(|v| v.as_str()).is_some_and(|u| u != "sig") {
                    return Err(fail("key is not a signing key"));
                }
                if jwk.get("alg").and_then(|v| v.as_str()).is_some_and(|a| a != alg) {
                    return Err(fail("key \"alg\" mismatch"));
                }
                let key = jwk_to_key(jwk).map_err(|e| fail(&e))?;
                if !jwt.verify_es256(&key) {
                    return Err(fail("signature verification failed"));
                }
                if jwt.claim_str("iss") != Some(self.id.as_str()) {
                    return Err(fail("unexpected \"iss\" claim value"));
                }
                if jwt.claim_str("sub") != Some(self.id.as_str()) {
                    return Err(fail("unexpected \"sub\" claim value"));
                }
                if aud_matches(&jwt.payload, issuer) != Some(true) {
                    return Err(fail("unexpected \"aud\" claim value"));
                }
                let now = now_secs();
                let iat = jwt.claim_i64("iat").ok_or_else(|| fail("missing \"iat\" claim"))?;
                if iat > now + CLOCK_TOLERANCE || now - iat > CLIENT_ASSERTION_MAX_AGE {
                    return Err(fail("\"iat\" claim timestamp check failed"));
                }
                if let Some(exp) = jwt.claim_i64("exp") {
                    if exp <= now {
                        return Err(fail("\"exp\" claim timestamp check failed"));
                    }
                }
                if let Some(nbf) = jwt.claim_i64("nbf") {
                    if nbf > now + CLOCK_TOLERANCE {
                        return Err(fail("\"nbf\" claim timestamp check failed"));
                    }
                }
                let jti =
                    jwt.claim_str("jti").filter(|j| !j.is_empty()).ok_or_else(|| fail("missing \"jti\" claim"))?;
                // past iat + max age the assertion is refused anyway, so a
                // far-future `exp` must not pin the claim
                let until = iat + CLIENT_ASSERTION_MAX_AGE + CLOCK_TOLERANCE;
                let replay =
                    Replay { routing: client_routing(&self.id), key: format!("assert:{}\0{jti}", self.id), until };
                let jkt = jwk_thumbprint(jwk).map_err(|e| fail(&e))?;
                Ok((ClientAuth::PrivateKeyJwt { alg, kid: kid.to_string(), jkt }, Some(replay)))
            }
            m => Err(OAuthError::invalid_client(&format!("Unsupported token_endpoint_auth_method \"{m}\""))),
        }
    }

    /// Sessions whose key left the client's key set must be revoked.
    pub fn has_key(&self, auth: &ClientAuth) -> bool {
        match auth {
            ClientAuth::None => true,
            ClientAuth::PrivateKeyJwt { kid, jkt, .. } => self.jwks.iter().any(|k| {
                k.get("kid").and_then(|v| v.as_str()) == Some(kid.as_str())
                    && jwk_thumbprint(k).ok().as_deref() == Some(jkt.as_str())
            }),
        }
    }
}

impl Client {
    /// Reference `decodeRequestObject` + `decodeJAR`. Unsecured (`alg: none`)
    /// only when the client registered `request_object_signing_alg: "none"`,
    /// and then `iss` / `aud` are optional but checked when present. The
    /// `jti` comes back as a [`Replay`] for the caller to claim.
    pub fn decode_request_object(&self, jar: &str, issuer: &str) -> Result<(J, Replay), OAuthError> {
        let fail = |m: &str| OAuthError::invalid_request(&format!("Invalid \"request\" object: {m}"));
        let jwt = DecodedJwt::decode(jar).map_err(|e| fail(&e))?;
        let registered = self.metadata.get("request_object_signing_alg").and_then(|v| v.as_str());
        let alg = jwt.alg();
        let unsecured = registered == Some("none");
        if unsecured {
            if !jwt.is_unsecured() {
                return Err(fail("expected an unsecured (\"alg\": \"none\") request object"));
            }
        } else {
            if alg == "none" {
                return Err(fail("unsecured request objects are not allowed for this client"));
            }
            if !super::jose::VERIFY_ALGS.contains(&alg) || registered.is_some_and(|r| r != alg) {
                return Err(fail("unsupported \"alg\""));
            }
            let kid = jwt.header.get("kid").and_then(|v| v.as_str());
            let candidates: Vec<&J> = self
                .jwks
                .iter()
                .filter(|k| kid.is_none() || k.get("kid").and_then(|v| v.as_str()) == kid)
                .filter(|k| k.get("use").and_then(|v| v.as_str()).is_none_or(|u| u == "sig"))
                .filter(|k| k.get("alg").and_then(|v| v.as_str()).is_none_or(|a| a == alg))
                .collect();
            if candidates.is_empty() {
                return Err(fail("no applicable key found in the client JWKS"));
            }
            let verified = candidates.iter().any(|k| jwk_to_key(k).is_ok_and(|key| jwt.verify_es256(&key)));
            if !verified {
                return Err(fail("signature verification failed"));
            }
        }
        match jwt.payload.get("iss") {
            None if unsecured => {}
            Some(J::String(i)) if *i == self.id => {}
            _ => return Err(fail("unexpected \"iss\" claim value")),
        }
        if !aud_matches(&jwt.payload, issuer).unwrap_or(unsecured) {
            return Err(fail("unexpected \"aud\" claim value"));
        }
        let now = now_secs();
        let iat = jwt.claim_i64("iat").ok_or_else(|| fail("missing \"iat\" claim"))?;
        if iat > now + CLOCK_TOLERANCE || now - iat > JAR_MAX_AGE {
            return Err(fail("\"iat\" claim timestamp check failed"));
        }
        if jwt.claim_i64("exp").is_some_and(|exp| exp <= now) {
            return Err(fail("\"exp\" claim timestamp check failed"));
        }
        if jwt.claim_i64("nbf").is_some_and(|nbf| nbf > now + CLOCK_TOLERANCE) {
            return Err(fail("\"nbf\" claim timestamp check failed"));
        }
        let jti = jwt
            .claim_str("jti")
            .filter(|j| !j.is_empty())
            .ok_or_else(|| OAuthError::invalid_request("Request object payload must contain a \"jti\" claim"))?;
        let until = iat.max(now) + JAR_MAX_AGE + CLOCK_TOLERANCE;
        let replay = Replay { routing: client_routing(&self.id), key: format!("jar:{}\0{jti}", self.id), until };
        Ok((jwt.payload, replay))
    }
}

/// None: no `aud`.
fn aud_matches(payload: &J, issuer: &str) -> Option<bool> {
    Some(match payload.get("aud")? {
        J::String(a) => a == issuer,
        J::Array(a) => a.iter().any(|x| x.as_str() == Some(issuer)),
        _ => false,
    })
}

#[derive(Clone, Debug, Default)]
pub struct ClientCredentials {
    pub client_id: String,
    pub client_assertion_type: Option<String>,
    pub client_assertion: Option<String>,
}

impl ClientCredentials {
    pub fn from_params(p: &HashMap<String, String>) -> Result<ClientCredentials, OAuthError> {
        let client_id = p
            .get("client_id")
            .cloned()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| OAuthError::invalid_request("Missing \"client_id\""))?;
        Ok(ClientCredentials {
            client_id,
            client_assertion_type: p.get("client_assertion_type").cloned(),
            client_assertion: p.get("client_assertion").cloned(),
        })
    }
}

fn is_loopback_host(h: &str) -> bool {
    h == "localhost" || h == "127.0.0.1" || h == "[::1]"
}

/// `isLocalHostname`: single-label names and reserved TLDs.
fn is_local_hostname(h: &str) -> bool {
    let parts: Vec<&str> = h.split('.').collect();
    if parts.len() < 2 {
        return true;
    }
    let tld = parts.last().unwrap().to_ascii_lowercase();
    matches!(tld.as_str(), "test" | "local" | "localhost" | "invalid" | "example")
}

/// Host as in a JS URL's `hostname` (IPv6 literals in brackets).
fn host_str(u: &reqwest::Url) -> String {
    u.host_str().unwrap_or("").to_string()
}

fn is_ip_host(h: &str) -> bool {
    h.trim_start_matches('[').trim_end_matches(']').parse::<IpAddr>().is_ok()
}

/// RFC 8252 §8.4 / §7.3: loopback redirect URIs registered without a port
/// match any port.
fn compare_redirect_uri(allowed: &str, requested: &str) -> bool {
    if allowed == requested {
        return true;
    }
    let (Ok(a), Ok(r)) = (reqwest::Url::parse(allowed), reqwest::Url::parse(requested)) else {
        return false;
    };
    let ah = host_str(&a);
    if !is_loopback_host(&ah) {
        return false;
    }
    (a.port().is_none() || a.port() == r.port())
        && ah == host_str(&r)
        && a.path() == r.path()
        && a.scheme() == r.scheme()
        && a.query() == r.query()
        && a.fragment() == r.fragment()
        && a.username() == r.username()
        && a.password() == r.password()
}

fn is_private_use_scheme(u: &reqwest::Url) -> bool {
    u.scheme().contains('.')
}

fn parse_redirect_uri(uri: &str) -> Result<reqwest::Url, OAuthError> {
    let ok = if uri.starts_with("https:") || uri.starts_with("http:") {
        true
    } else {
        // private-use scheme: "<reverse.domain>:/path"
        match (uri.find('.'), uri.find(':')) {
            (Some(d), Some(c)) => d < c && !uri[c..].starts_with("://"),
            _ => false,
        }
    };
    if !ok {
        return Err(OAuthError::invalid_redirect_uri(&format!("Invalid redirect URI {uri}")));
    }
    reqwest::Url::parse(uri).map_err(|_| OAuthError::invalid_redirect_uri(&format!("Invalid redirect URI {uri}")))
}

/// RFC 8252 disallows "localhost".
fn is_loopback_redirect_uri(uri: &str) -> bool {
    if !uri.starts_with("http://") || uri.starts_with("http://localhost") {
        return false;
    }
    reqwest::Url::parse(uri).map(|u| matches!(host_str(&u).as_str(), "127.0.0.1" | "[::1]")).unwrap_or(false)
}

enum ClientIdKind {
    /// `http://localhost[/][?scope=...&redirect_uri=...]`
    Loopback {
        scope: String,
        redirect_uris: Vec<String>,
    },
    Discoverable(reqwest::Url),
}

fn parse_client_id(id: &str, dev_mode: bool) -> Result<ClientIdKind, OAuthError> {
    let bad = |m: &str| OAuthError::invalid_client_metadata(&format!("Invalid client ID \"{id}\": {m}"));
    const ORIGIN: &str = "http://localhost";
    if let Some(rest) = id.strip_prefix(ORIGIN) {
        if rest.starts_with(':') || (!rest.is_empty() && !rest.starts_with('/') && !rest.starts_with('?')) {
            // http://localhost:port or http://localhostfoo -> not a loopback client id
            if !dev_mode {
                return Err(bad("Loopback client IDs must not contain a port"));
            }
        } else {
            if rest.contains('#') {
                return Err(bad("Value must not contain a hash component"));
            }
            let q = rest.strip_prefix('/').unwrap_or(rest);
            if !q.is_empty() && !q.starts_with('?') {
                return Err(bad("Value must not contain a path component"));
            }
            let mut scope: Option<String> = None;
            let mut redirect_uris = Vec::new();
            for (k, v) in parse_form(q.strip_prefix('?').unwrap_or("")) {
                match k.as_str() {
                    "scope" => {
                        if scope.is_some() {
                            return Err(bad("Duplicate \"scope\" query parameter"));
                        }
                        scope = Some(v);
                    }
                    "redirect_uri" => {
                        if !is_loopback_redirect_uri(&v) {
                            return Err(bad("Invalid \"redirect_uri\" query parameter"));
                        }
                        redirect_uris.push(v);
                    }
                    _ => return Err(bad(&format!("Unexpected query parameter \"{k}\""))),
                }
            }
            let scope = scope.unwrap_or_else(|| "atproto".into());
            if !scope.split(' ').any(|s| s == "atproto") {
                return Err(bad("ATProto Loopback ClientID must include \"atproto\" scope"));
            }
            if redirect_uris.is_empty() {
                redirect_uris = vec!["http://127.0.0.1/".into(), "http://[::1]/".into()];
            }
            return Ok(ClientIdKind::Loopback { scope, redirect_uris });
        }
    }
    // discoverable: the metadata document's URL (dev mode: http too)
    let https = id.starts_with("https://");
    if !https && !(dev_mode && id.starts_with("http://")) {
        return Err(bad("ClientID must be an https URL"));
    }
    let url = reqwest::Url::parse(id).map_err(|_| bad("not a valid URL"))?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err(bad("ClientID must not contain credentials"));
    }
    if url.fragment().is_some() {
        return Err(bad("ClientID must not contain a fragment"));
    }
    if url.path() == "/" {
        return Err(bad("ClientID must contain a path component (e.g. \"/client-metadata.json\")"));
    }
    if url.path().ends_with('/') {
        return Err(bad("ClientID path must not end with a trailing slash"));
    }
    let host = host_str(&url);
    let is_ip = is_ip_host(&host);
    if https && is_loopback_host(&host) {
        return Err(bad("https: URL must not use a loopback host"));
    }
    if !dev_mode {
        if is_ip {
            return Err(bad("ClientID hostname must not be an IP address"));
        }
        if !host.contains('.') {
            return Err(bad("Domain name must contain at least two segments"));
        }
    }
    // Canonical form: the URL parser must not have rewritten the path
    // (no dot segments, no needless escapes).
    let raw_path = {
        let after_scheme = &id[id.find("://").unwrap() + 3..];
        let start = after_scheme.find('/').unwrap_or(after_scheme.len());
        let p = &after_scheme[start..];
        let end = p.find(['?', '#']).unwrap_or(p.len());
        p[..end].to_string()
    };
    if raw_path != url.path() {
        return Err(bad(&format!("ClientID must be in canonical form (\"{}\")", url.as_str())));
    }
    Ok(ClientIdKind::Discoverable(url))
}

/// From a user-controlled URL: https and public addresses only (outside dev
/// mode), no redirects, size-capped.
async fn fetch_json(url: &str, dev_mode: bool, max_bytes: usize) -> Result<J, String> {
    use futures::StreamExt;
    let resp = vlsync_atproto::http::guarded(dev_mode)
        .get(url)?
        .header("accept", "application/json")
        .timeout(FETCH_TIMEOUT)
        .send()
        .await
        .map_err(|e| format!("fetch failed: {e}"))?;
    if resp.status() != reqwest::StatusCode::OK {
        return Err(format!("unexpected HTTP status {}", resp.status().as_u16()));
    }
    if let Some(ct) = resp.headers().get(reqwest::header::CONTENT_TYPE) {
        let ct = ct.to_str().unwrap_or("").split(';').next().unwrap_or("").trim().to_ascii_lowercase();
        if ct != "application/json" && !(ct.starts_with("application/") && ct.ends_with("+json")) {
            return Err(format!("unexpected content-type \"{ct}\""));
        }
    }
    if resp.content_length().is_some_and(|l| l as usize > max_bytes) {
        return Err("response too large".into());
    }
    let mut buf = Vec::new();
    let mut s = resp.bytes_stream();
    while let Some(chunk) = s.next().await {
        let chunk = chunk.map_err(|e| e.to_string())?;
        if buf.len() + chunk.len() > max_bytes {
            return Err("response too large".into());
        }
        buf.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&buf).map_err(|e| format!("invalid JSON: {e}"))
}

struct Cache<T> {
    map: parking_lot::Mutex<HashMap<String, (Instant, T)>>,
}

impl<T: Send> crate::caches::Len for Cache<T> {
    fn len(&self) -> usize {
        self.map.lock().len()
    }
}

impl<T: Clone> Cache<T> {
    fn new() -> Self {
        Cache { map: parking_lot::Mutex::new(HashMap::new()) }
    }
    fn get(&self, k: &str) -> Option<T> {
        self.map.lock().get(k).filter(|(at, _)| at.elapsed() < CACHE_TTL).map(|(_, v)| v.clone())
    }
    fn put(&self, k: &str, v: T) {
        let cap = crate::caches::cap(crate::caches::Cache::OAuthClients);
        let mut m = self.map.lock();
        if m.len() >= cap {
            m.retain(|_, (at, _)| at.elapsed() < CACHE_TTL);
            if m.len() >= cap {
                m.clear();
            }
        }
        m.insert(k.to_string(), (Instant::now(), v));
    }
}

static CLIENTS: LazyLock<Arc<Cache<Arc<Client>>>> =
    LazyLock::new(|| crate::caches::track(crate::caches::Cache::OAuthClients, Arc::new(Cache::new())));

/// The web UI's own client (the migration page's and the account page's
/// OAuth sign-ins): a public client whose metadata this server serves at
/// [`FIRST_PARTY_PATH`].
pub const FIRST_PARTY_PATH: &str = "/oauth/client-metadata.json";
/// The UI's `CLIENT_SCOPE` (ui/src/lib/oauth.ts) lists the same values. The
/// last is the account page's owner grant: `authority` is left at its
/// default (`self`), so the token can only manage the user's own spaces.
pub const FIRST_PARTY_SCOPE: &str = "atproto space:*?authority=*&action=read_self \
space:*?authority=*&collection=*&action=create&action=read_self blob:*/* \
space:*?action=read_self&manage=update&manage=delete";
pub const FIRST_PARTY_CALLBACK: &str = "/migrate/oauth/callback";
/// The account page's "Your spaces" sign-in comes back here.
pub const FIRST_PARTY_ACCOUNT_CALLBACK: &str = "/account/oauth/callback";

pub fn first_party_id(public_url: &str) -> String {
    format!("{}{FIRST_PARTY_PATH}", public_url.trim_end_matches('/'))
}

pub fn first_party_metadata(public_url: &str) -> J {
    let origin = public_url.trim_end_matches('/');
    let host = reqwest::Url::parse(origin).ok().and_then(|u| u.host_str().map(String::from)).unwrap_or_default();
    json!({
        "client_id": first_party_id(public_url),
        "client_name": format!("{host} (account pages)"),
        "client_uri": origin,
        "redirect_uris": [format!("{origin}{FIRST_PARTY_CALLBACK}"), format!("{origin}{FIRST_PARTY_ACCOUNT_CALLBACK}")],
        "scope": FIRST_PARTY_SCOPE,
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "application_type": "web",
        "token_endpoint_auth_method": "none",
        "dpop_bound_access_tokens": true,
    })
}

/// `public_url`: this server's, so its own UI's client is built here
/// rather than fetched from itself.
pub async fn get_client(client_id: &str, dev_mode: bool, public_url: &str) -> Result<Arc<Client>, OAuthError> {
    if let Some(c) = CLIENTS.get(client_id) {
        return Ok(c);
    }
    let client = Arc::new(if client_id == first_party_id(public_url) {
        parse_client_id(client_id, dev_mode)?;
        validate_metadata(client_id, first_party_metadata(public_url), false, dev_mode)?
    } else {
        load_client(client_id, dev_mode).await?
    });
    if !client.loopback {
        CLIENTS.put(client_id, client.clone());
    }
    Ok(client)
}

async fn load_client(client_id: &str, dev_mode: bool) -> Result<Client, OAuthError> {
    let (metadata, loopback) = match parse_client_id(client_id, dev_mode)? {
        ClientIdKind::Loopback { scope, redirect_uris } => (
            json!({
                "client_id": client_id,
                "scope": scope,
                "redirect_uris": redirect_uris,
                "response_types": ["code"],
                "grant_types": ["authorization_code", "refresh_token"],
                "token_endpoint_auth_method": "none",
                "application_type": "native",
                "dpop_bound_access_tokens": true,
            }),
            true,
        ),
        ClientIdKind::Discoverable(url) => {
            let md = fetch_json(url.as_str(), dev_mode, METADATA_MAX_BYTES).await.map_err(|e| {
                OAuthError::invalid_client_metadata(&format!(
                    "Unable to obtain client metadata for \"{client_id}\": {e}"
                ))
            })?;
            (md, false)
        }
    };
    let mut client = validate_metadata(client_id, metadata, loopback, dev_mode)?;
    if let Some(uri) = client.metadata.get("jwks_uri").and_then(|v| v.as_str()) {
        let jwks = fetch_json(uri, dev_mode, METADATA_MAX_BYTES).await.map_err(|e| {
            OAuthError::invalid_client_metadata(&format!(
                "Unable to obtain jwks from \"{uri}\" for \"{client_id}\": {e}"
            ))
        })?;
        client.jwks = parse_jwks(&jwks)?;
    }
    if client.auth_method == "private_key_jwt" && client.jwks.is_empty() {
        return Err(OAuthError::invalid_client_metadata(
            "private_key_jwt auth method requires at least one key in jwks",
        ));
    }
    Ok(client)
}

fn parse_jwks(jwks: &J) -> Result<Vec<J>, OAuthError> {
    let keys = jwks
        .get("keys")
        .and_then(|k| k.as_array())
        .ok_or_else(|| OAuthError::invalid_client_metadata("invalid JWKS"))?;
    let mut out = Vec::new();
    for k in keys {
        if k.get("d").is_some() {
            return Err(OAuthError::invalid_client_metadata("JWKS must not contain private keys"));
        }
        // other keys are ignored, not refused
        if k.get("kid").and_then(|v| v.as_str()).is_some() && jwk_to_key(k).is_ok() {
            out.push(k.clone());
        }
    }
    Ok(out)
}

fn str_list(md: &J, k: &str) -> Result<Option<Vec<String>>, OAuthError> {
    match md.get(k) {
        None | Some(J::Null) => Ok(None),
        Some(J::Array(a)) => a
            .iter()
            .map(|v| {
                v.as_str()
                    .map(String::from)
                    .ok_or_else(|| OAuthError::invalid_client_metadata(&format!("\"{k}\" must be an array of strings")))
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Some),
        Some(_) => Err(OAuthError::invalid_client_metadata(&format!("\"{k}\" must be an array"))),
    }
}

fn has_dup(v: &[String]) -> Option<&String> {
    v.iter().enumerate().find(|(i, x)| v[i + 1..].contains(x)).map(|(_, x)| x)
}

fn check_redirect_uri(r: &str, application_type: &str, loopback: bool, dev_mode: bool) -> Result<(), OAuthError> {
    let bad_uri = |m: &str| OAuthError::invalid_redirect_uri(m);
    let u = parse_redirect_uri(r)?;
    if !u.username().is_empty() || u.password().is_some() {
        return Err(bad_uri(&format!("Redirect URI {r} must not contain credentials")));
    }
    let host = host_str(&u);
    if host == "localhost" {
        return Err(bad_uri(&format!("Loopback redirect URI {r} is not allowed (use explicit IPs instead)")));
    } else if host == "127.0.0.1" || host == "[::1]" {
        if application_type != "native" {
            return Err(bad_uri("Loopback redirect URIs are only allowed for native apps"));
        }
        if u.scheme() != "http" {
            return Err(bad_uri(&format!("Loopback redirect URI {r} must use HTTP")));
        }
    } else if u.scheme() == "http" {
        // dev mode: allow http redirect URIs of dev-mode http clients
        if !(dev_mode && !loopback) {
            return Err(bad_uri("Only loopback redirect URIs are allowed to use the \"http\" scheme"));
        }
    } else if u.scheme() == "https" {
        if is_local_hostname(&host) && !dev_mode {
            return Err(bad_uri(&format!("Redirect URI \"{r}\"'s domain name must not be a local hostname")));
        }
    } else if is_private_use_scheme(&u) {
        if application_type != "native" {
            return Err(bad_uri("Private-Use URI Scheme redirect URI are only allowed for native apps"));
        }
    } else {
        return Err(bad_uri(&format!("Invalid redirect URI scheme \"{}:\"", u.scheme())));
    }
    Ok(())
}

fn validate_metadata(client_id: &str, md: J, loopback: bool, dev_mode: bool) -> Result<Client, OAuthError> {
    let bad = |m: &str| OAuthError::invalid_client_metadata(m);
    let bad_uri = |m: &str| OAuthError::invalid_redirect_uri(m);
    if !md.is_object() {
        return Err(bad("client metadata must be a JSON object"));
    }
    if md.get("jwks").is_some() && md.get("jwks_uri").is_some() {
        return Err(bad("jwks_uri and jwks are mutually exclusive"));
    }
    for k in [
        "default_max_age",
        "userinfo_signed_response_alg",
        "id_token_signed_response_alg",
        "userinfo_encrypted_response_alg",
    ] {
        if md.get(k).is_some_and(|v| !v.is_null()) {
            return Err(bad(&format!("Unsupported \"{k}\" parameter")));
        }
    }
    let gs = |k: &str| md.get(k).and_then(|v| v.as_str());
    if let Some(cu) = gs("client_uri") {
        let u = reqwest::Url::parse(cu).map_err(|_| bad("client_uri must be a valid URL"))?;
        if is_local_hostname(&host_str(&u)) && !dev_mode {
            return Err(bad("client_uri hostname is invalid"));
        }
    }
    let scope = gs("scope").ok_or_else(|| bad("Missing scope property"))?;
    let scopes: Vec<String> = scope.split(' ').map(String::from).collect();
    if !scopes.iter().any(|s| s == "atproto") {
        return Err(bad("Missing \"atproto\" scope"));
    }
    if let Some(d) = has_dup(&scopes) {
        return Err(bad(&format!("Duplicate scope \"{d}\"")));
    }
    let grant_types = str_list(&md, "grant_types")?.unwrap_or_else(|| vec!["authorization_code".into()]);
    if let Some(d) = has_dup(&grant_types) {
        return Err(bad(&format!("Duplicate grant type \"{d}\"")));
    }
    for g in &grant_types {
        match g.as_str() {
            "implicit" => return Err(bad(&format!("Grant type \"{g}\" is not allowed"))),
            "authorization_code" | "refresh_token" => {}
            _ => return Err(bad(&format!("Grant type \"{g}\" is not supported"))),
        }
    }
    if let Some(id) = gs("client_id") {
        if id != client_id {
            return Err(bad("client_id does not match"));
        }
    }
    if gs("subject_type").is_some_and(|s| s != "public") {
        return Err(bad("Only \"public\" subject_type is supported"));
    }
    // OIDC default is client_secret_basic, which atproto does not support.
    let auth_method = gs("token_endpoint_auth_method").unwrap_or("client_secret_basic").to_string();
    let mut jwks = Vec::new();
    match auth_method.as_str() {
        "none" => {
            if gs("token_endpoint_auth_signing_alg").is_some() {
                return Err(bad("token_endpoint_auth_method \"none\" must not have token_endpoint_auth_signing_alg"));
            }
            // public clients may still sign request objects
            if let Some(j) = md.get("jwks") {
                jwks = parse_jwks(j)?;
            }
        }
        "private_key_jwt" => {
            if md.get("jwks").is_none() && md.get("jwks_uri").is_none() {
                return Err(bad("private_key_jwt auth method requires jwks or jwks_uri"));
            }
            if let Some(j) = md.get("jwks") {
                jwks = parse_jwks(j)?;
                if j.get("keys").and_then(|k| k.as_array()).is_some_and(|k| k.is_empty()) {
                    return Err(bad("private_key_jwt auth method requires at least one key in jwks"));
                }
            }
            if let Some(u) = gs("jwks_uri") {
                let url = reqwest::Url::parse(u).map_err(|_| bad("jwks_uri must be a valid URL"))?;
                if url.scheme() != "https" && !dev_mode {
                    return Err(bad("jwks_uri must use https"));
                }
            }
            match gs("token_endpoint_auth_signing_alg") {
                None => return Err(bad("Missing token_endpoint_auth_signing_alg client metadata")),
                Some("ES256") => {}
                Some(a) => return Err(bad(&format!("Unsupported token_endpoint_auth_signing_alg \"{a}\""))),
            }
        }
        m => {
            return Err(bad(&format!(
                "Unsupported client authentication method \"{m}\". Make sure \"token_endpoint_auth_method\" is set to one of: \"none\", \"private_key_jwt\""
            )))
        }
    }
    if md.get("authorization_encrypted_response_enc").is_some_and(|v| !v.is_null()) {
        return Err(bad("Encrypted authorization response is not supported"));
    }
    if md.get("tls_client_certificate_bound_access_tokens").and_then(|v| v.as_bool()) == Some(true) {
        return Err(bad("Mutual-TLS bound access tokens are not supported"));
    }
    if md.get("dpop_bound_access_tokens").and_then(|v| v.as_bool()) != Some(true) {
        return Err(bad("\"dpop_bound_access_tokens\" must be true"));
    }
    let response_types = str_list(&md, "response_types")?.unwrap_or_else(|| vec!["code".into()]);
    if !response_types.iter().any(|r| r == "code") {
        return Err(bad("response_types must include \"code\""));
    }
    if !grant_types.iter().any(|g| g == "authorization_code") {
        return Err(bad("The \"code\" response type requires that \"grant_types\" contains \"authorization_code\""));
    }
    if str_list(&md, "authorization_details_types")?.is_some_and(|v| !v.is_empty()) {
        return Err(bad("authorization_details_types are not supported"));
    }
    let application_type = gs("application_type").unwrap_or("web").to_string();
    if application_type != "web" && application_type != "native" {
        return Err(bad("application_type must be \"web\" or \"native\""));
    }
    let redirect_uris = str_list(&md, "redirect_uris")?.unwrap_or_default();
    if redirect_uris.is_empty() {
        return Err(bad("At least one redirect_uri is required"));
    }
    if application_type == "native" && auth_method != "none" {
        return Err(bad("Native clients must authenticate using \"none\" method"));
    }
    for r in &redirect_uris {
        check_redirect_uri(r, &application_type, loopback, dev_mode)?;
    }
    if loopback {
        if gs("client_uri").is_some() {
            return Err(bad("client_uri is not allowed for loopback clients"));
        }
        if application_type != "native" {
            return Err(bad("Loopback clients must have application_type \"native\""));
        }
        if auth_method != "none" {
            return Err(bad(&format!(
                "Loopback clients are not allowed to use \"token_endpoint_auth_method\" {auth_method}"
            )));
        }
    } else {
        if gs("client_id").is_none() {
            return Err(bad("client_id is required for discoverable clients"));
        }
        let id_url = reqwest::Url::parse(client_id).map_err(|_| bad("invalid client_id"))?;
        if let Some(cu) = gs("client_uri") {
            let cu = reqwest::Url::parse(cu).map_err(|_| bad("client_uri must be a valid URL"))?;
            if cu.origin() != id_url.origin() {
                return Err(bad("client_uri must have the same origin as the client_id"));
            }
            if id_url.path() != cu.path() {
                let parent = if cu.path().ends_with('/') { cu.path().to_string() } else { format!("{}/", cu.path()) };
                if !id_url.path().starts_with(&parent) {
                    return Err(bad("client_uri must be a parent URL of the client_id"));
                }
            }
        }
        for r in &redirect_uris {
            let u = parse_redirect_uri(r)?;
            if is_private_use_scheme(&u) {
                let expected: String = host_str(&id_url).split('.').rev().collect::<Vec<_>>().join(".");
                if u.scheme() != expected {
                    return Err(bad_uri(&format!(
                        "Private-Use URI Scheme redirect URI, for discoverable client metadata, must be the fully qualified domain name (FQDN) of the client_id, in reverse order ({expected}:)"
                    )));
                }
            }
        }
    }
    Ok(Client {
        id: client_id.to_string(),
        redirect_uris,
        scopes,
        grant_types,
        response_types,
        auth_method,
        jwks,
        loopback,
        metadata: md,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::elliptic_curve::Generate;

    #[test]
    fn first_party_client_validates() {
        let url = "https://pds.example.com";
        let id = first_party_id(url);
        assert_eq!(id, "https://pds.example.com/oauth/client-metadata.json");
        assert!(matches!(parse_client_id(&id, false), Ok(ClientIdKind::Discoverable(_))));
        let c = validate_metadata(&id, first_party_metadata(url), false, false).unwrap();
        assert!(!c.is_confidential());
        assert!(c.allows_redirect_uri("https://pds.example.com/migrate/oauth/callback"));
        assert!(c.allows_redirect_uri("https://pds.example.com/account/oauth/callback"));
        assert!(!c.allows_redirect_uri("https://pds.example.com/migrate"));
        assert!(!c.allows_redirect_uri("https://pds.example.com/account"));
        for s in [
            "space:*?authority=*&action=read_self",
            "space:*?authority=*&collection=*&action=create&action=read_self",
            "blob:*/*",
            "space:*?action=read_self&manage=update&manage=delete",
        ] {
            assert!(c.scopes.iter().any(|x| x == s), "{s}");
            assert!(crate::oauth::scopes::Permission::parse(s).is_some(), "{s}");
        }
    }

    /// The owner grant manages the granting account's spaces and nobody
    /// else's: `self` becomes the user when the token is issued.
    #[test]
    fn first_party_owner_scope_is_self_only() {
        use crate::oauth::scopes::{Permission, SpaceAccess, SpaceTarget};
        let Some(Permission::Space(p)) = Permission::parse("space:*?action=read_self&manage=update&manage=delete")
        else {
            panic!("not a space scope")
        };
        let p = p.with_resolved_authority("did:plc:owner");
        let mine = SpaceTarget { space_type: "com.example.group", authority: "did:plc:owner", skey: "a" };
        let theirs = SpaceTarget { space_type: "com.example.group", authority: "did:plc:other", skey: "a" };
        for op in ["update", "delete"] {
            assert!(p.matches(&mine, SpaceAccess::Manage(op)), "{op}");
            assert!(!p.matches(&theirs, SpaceAccess::Manage(op)), "{op}");
        }
        assert!(!p.matches(&mine, SpaceAccess::Manage("create")));
        assert!(p.matches(&mine, SpaceAccess::ReadSelf));
        assert!(!p.matches(&mine, SpaceAccess::Read));
        assert_eq!(
            Permission::Space(p).to_scope_string(),
            "space:*?authority=did:plc:owner&action=read_self&manage=update&manage=delete"
        );
    }

    #[test]
    fn loopback_ids() {
        assert!(matches!(parse_client_id("http://localhost", false), Ok(ClientIdKind::Loopback { .. })));
        assert!(matches!(parse_client_id("http://localhost/", false), Ok(ClientIdKind::Loopback { .. })));
        match parse_client_id(
            "http://localhost?scope=atproto%20transition:generic&redirect_uri=http%3A%2F%2F127.0.0.1%3A8080%2Fcb",
            false,
        ) {
            Ok(ClientIdKind::Loopback { scope, redirect_uris }) => {
                assert_eq!(scope, "atproto transition:generic");
                assert_eq!(redirect_uris, vec!["http://127.0.0.1:8080/cb"]);
            }
            _ => panic!(),
        }
        assert!(parse_client_id("http://localhost/path", false).is_err());
        assert!(parse_client_id("http://localhost?foo=bar", false).is_err());
        assert!(parse_client_id("http://localhost?redirect_uri=http%3A%2F%2Flocalhost%2Fcb", false).is_err());
        assert!(parse_client_id("http://localhost?scope=transition:generic", false).is_err());
    }

    #[test]
    fn discoverable_ids() {
        assert!(matches!(
            parse_client_id("https://app.example.com/client-metadata.json", false),
            Ok(ClientIdKind::Discoverable(_))
        ));
        assert!(parse_client_id("https://app.example.com/", false).is_err());
        assert!(parse_client_id("https://app.example.com/x/", false).is_err());
        assert!(parse_client_id("https://1.2.3.4/x.json", false).is_err());
        assert!(parse_client_id("https://app.example.com/a/../x.json", false).is_err());
        assert!(parse_client_id("http://app.example.com/x.json", false).is_err());
        assert!(parse_client_id("http://127.0.0.1:1234/x.json", true).is_ok());
    }

    #[test]
    fn redirect_compare() {
        assert!(compare_redirect_uri("http://127.0.0.1/cb", "http://127.0.0.1:5000/cb"));
        assert!(!compare_redirect_uri("http://127.0.0.1/cb", "http://127.0.0.1:5000/other"));
        assert!(!compare_redirect_uri("http://127.0.0.1:4000/cb", "http://127.0.0.1:5000/cb"));
        assert!(!compare_redirect_uri("https://app.example.com/cb", "https://app.example.com/cb?x=1"));
        assert!(compare_redirect_uri("https://app.example.com/cb", "https://app.example.com/cb"));
    }

    #[test]
    fn metadata_rules() {
        let base = json!({
            "client_id": "https://app.example.com/client-metadata.json",
            "redirect_uris": ["https://app.example.com/cb"],
            "scope": "atproto transition:generic",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
            "application_type": "web",
            "dpop_bound_access_tokens": true,
        });
        let id = "https://app.example.com/client-metadata.json";
        assert!(validate_metadata(id, base.clone(), false, false).is_ok());
        let mut m = base.clone();
        m["dpop_bound_access_tokens"] = json!(false);
        assert!(validate_metadata(id, m, false, false).is_err());
        let mut m = base.clone();
        m["scope"] = json!("transition:generic");
        assert!(validate_metadata(id, m, false, false).is_err());
        let mut m = base.clone();
        m["redirect_uris"] = json!(["http://app.example.com/cb"]);
        assert!(validate_metadata(id, m, false, false).is_err());
        let mut m = base.clone();
        m["redirect_uris"] = json!(["com.example.app:/cb"]);
        assert!(validate_metadata(id, m.clone(), false, false).is_err(), "private-use needs native");
        m["application_type"] = json!("native");
        assert!(validate_metadata(id, m.clone(), false, false).is_ok());
        m["redirect_uris"] = json!(["com.example.other:/cb"]);
        assert!(validate_metadata(id, m.clone(), false, false).is_err(), "scheme must be reversed client domain");
        let mut m = base.clone();
        m["token_endpoint_auth_method"] = json!("private_key_jwt");
        assert!(validate_metadata(id, m.clone(), false, false).is_err(), "needs jwks");
        m["jwks_uri"] = json!("https://app.example.com/jwks.json");
        assert!(validate_metadata(id, m.clone(), false, false).is_err(), "needs signing alg");
        m["token_endpoint_auth_signing_alg"] = json!("ES256");
        assert!(validate_metadata(id, m, false, false).is_ok());
        let mut m = base.clone();
        m["client_id"] = json!("https://other.example.com/client-metadata.json");
        assert!(validate_metadata(id, m, false, false).is_err());
    }

    /// A client assertion's single-use claim lasts as long as the assertion
    /// is accepted (`iat` + max age + skew), not until its `exp`: a client
    /// can't pin replay-cache entries (or persisted claim rows) for years.
    #[test]
    fn assertion_claim_is_bounded_by_iat_not_exp() {
        use super::super::util::b64u;
        use p256::ecdsa::signature::Signer;
        let sk = p256::ecdsa::SigningKey::generate();
        let mut jwk = super::super::jose::key_to_jwk(sk.verifying_key());
        jwk["kid"] = json!("k1");
        let id = "https://app.example/client-metadata.json";
        let client = Client {
            id: id.into(),
            metadata: json!({}),
            redirect_uris: vec![],
            scopes: vec![],
            grant_types: vec![],
            response_types: vec![],
            auth_method: "private_key_jwt".into(),
            jwks: vec![jwk],
            loopback: false,
        };
        let issuer = "https://pds.example";
        let sign = |exp: i64| {
            let header = json!({"alg": "ES256", "kid": "k1"});
            let now = now_secs();
            let payload = json!({"iss": id, "sub": id, "aud": issuer, "jti": "j1", "iat": now, "exp": exp});
            let input = format!(
                "{}.{}",
                b64u(serde_json::to_vec(&header).unwrap()),
                b64u(serde_json::to_vec(&payload).unwrap())
            );
            let sig: p256::ecdsa::Signature = sk.sign(input.as_bytes());
            format!("{input}.{}", b64u(sig.to_bytes()))
        };
        let creds = |a: String| ClientCredentials {
            client_id: id.into(),
            client_assertion_type: Some(CLIENT_ASSERTION_TYPE_JWT_BEARER.into()),
            client_assertion: Some(a),
        };
        let now = now_secs();
        let (_, r) = client.authenticate(&creds(sign(now + 10 * 365 * 86_400)), issuer).unwrap();
        let until = r.unwrap().until;
        assert!(until <= now + CLIENT_ASSERTION_MAX_AGE + CLOCK_TOLERANCE + 1, "claim until {until}, now {now}");
        assert!(until >= now + CLIENT_ASSERTION_MAX_AGE, "claimed for its whole acceptance window");
    }
}
