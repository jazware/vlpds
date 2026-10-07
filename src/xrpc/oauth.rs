//! The atproto OAuth authorization server's HTTP surface and DPoP
//! verification of resource requests. Keys, storage layout and HA notes:
//! `crate::oauth`.

use super::authn::Credentials;
use super::*;
use crate::oauth::client::{self, Client, ClientAuth, ClientCredentials};
use crate::oauth::jose::{self, DpopError, DpopNonces, DpopProof, ServerKey};
use crate::oauth::scopes::{is_atproto_did, is_atproto_oauth_scope};
use crate::oauth::store::{self, AuthParams, Device, DeviceAccount, RequestData, Session};
use crate::oauth::util::{self as ou, now_secs};
use crate::oauth::{
    lexicon, ui, OAuthError, ACCESS_TOKEN_TTL, AUTHENTICATION_MAX_AGE, AUTHORIZATION_INACTIVITY_TIMEOUT, PAR_EXPIRES_IN,
};
use axum::http::request::Parts;
use axum::http::{HeaderName, HeaderValue};
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::LazyLock;

pub use crate::oauth::ScopeSet;

const DEVICE_COOKIE: &str = "vlpds-device";
const PENDING_2FA_TTL: i64 = 5 * 60;
/// Per pending sign-in, before the password step must be redone (the
/// per-account lockout in `crate::totp` still applies).
const PENDING_2FA_MAX_FAILURES: u32 = 3;

struct Keys {
    server: ServerKey,
    nonces: DpopNonces,
    csrf: [u8; 32],
    refresh: [u8; 32],
}

/// A production process has one secret, so the per-request lookup (every
/// DPoP request) is a lock-free compare against it.
static FIRST_KEYS: std::sync::OnceLock<(Box<str>, Keys)> = std::sync::OnceLock::new();
/// In-process tests run servers with several secrets; their keys are leaked
/// once each.
static OTHER_KEYS: LazyLock<parking_lot::Mutex<HashMap<Box<str>, &'static Keys>>> = LazyLock::new(Default::default);

fn derive_keys(secret: &str) -> Keys {
    Keys {
        server: ServerKey::derive(secret),
        nonces: DpopNonces::new(secret),
        csrf: ou::derive_secret(secret, "csrf"),
        refresh: ou::derive_secret(secret, "refresh-token"),
    }
}

fn keys(app: &App) -> &'static Keys {
    let secret = app.config.jwt_secret.as_str();
    let (first, k) = FIRST_KEYS.get_or_init(|| (secret.into(), derive_keys(secret)));
    if **first == *secret {
        return k;
    }
    let mut m = OTHER_KEYS.lock();
    if let Some(k) = m.get(secret) {
        return k;
    }
    let k: &'static Keys = Box::leak(Box::new(derive_keys(secret)));
    m.insert(secret.into(), k);
    k
}

fn issuer(app: &App) -> String {
    app.public_url.trim_end_matches('/').to_string()
}

fn is_https(app: &App) -> bool {
    app.public_url.starts_with("https://")
}

pub fn routes() -> Router<Arc<App>> {
    Router::new()
        .route("/.well-known/oauth-protected-resource", get(protected_resource_metadata).options(preflight))
        .route("/.well-known/oauth-authorization-server", get(authorization_server_metadata).options(preflight))
        .route("/oauth/jwks", get(jwks).options(preflight))
        .route(client::FIRST_PARTY_PATH, get(first_party_metadata).options(preflight))
        .route("/oauth/par", post(par).options(preflight))
        .route("/oauth/token", post(token).options(preflight))
        .route("/oauth/revoke", post(revoke).options(preflight))
        .route("/oauth/authorize", get(authorize))
        .route("/oauth/authorize/sign-in", post(authorize_sign_in))
        .route("/oauth/authorize/sign-up", post(authorize_sign_up))
        .route("/oauth/authorize/select", post(authorize_select))
        .route("/oauth/authorize/consent", post(authorize_consent))
        .route("/oauth/account", get(account_page))
        .route("/oauth/account/sign-in", post(account_sign_in))
        .route("/oauth/account/sign-out", post(account_sign_out))
        .route("/oauth/account/revoke", post(account_revoke))
        .route("/xrpc/vlpds.oauth.listSessions", get(xrpc_list_sessions))
        .route("/xrpc/vlpds.oauth.revokeSession", post(xrpc_revoke_session))
}

/// Handle, DID or email to DID; global lookups, so any node can resolve.
pub async fn resolve_identifier(app: &App, ident: &str) -> Option<String> {
    let ident = ident.trim().trim_start_matches('@').to_ascii_lowercase();
    if ident.starts_with("did:") {
        return Some(ident);
    }
    if ident.contains('@') {
        return super::server::did_by_email(app, &ident).await.ok().flatten();
    }
    if !ident.contains('.') {
        return None;
    }
    app.resolve_handle(&ident).await.ok().flatten()
}

/// For `crate::forward`; None: any node.
pub async fn route_key(app: &App, path: &str, query: Option<&str>, headers: &HeaderMap, body: &[u8]) -> Option<String> {
    let params = || parse_params(headers, body).ok().unwrap_or_default();
    let request = |uri: Option<&String>| store::request_id_from_uri(uri?).map(store::req_routing);
    match path {
        // the account owner, so the whole flow tends to stay there (the
        // request id is minted local to whichever node runs PAR)
        "/oauth/par" => {
            let hint = params().remove("login_hint")?;
            resolve_identifier(app, &hint).await
        }
        "/oauth/authorize" => {
            let q: HashMap<String, String> = ou::parse_form(query.unwrap_or("")).into_iter().collect();
            request(q.get("request_uri"))
        }
        // sign-up mints the DID on the node that runs it; the request row's
        // owner, like the steps after it
        "/oauth/authorize/select" | "/oauth/authorize/consent" | "/oauth/authorize/sign-up" => {
            request(params().get("request_uri"))
        }
        // sign-in: the account's owner (its rate limits, 2FA lockout and
        // account record are there); the code step names no account, so the
        // device's pending one
        "/oauth/authorize/sign-in" | "/oauth/account/sign-in" => {
            let p = params();
            let step = p.get("step").map(String::as_str);
            if step == Some("passkey") {
                let did = p.get("user_handle").and_then(|h| super::passkeys::did_from_user_handle(h));
                return did.or_else(|| request(p.get("request_uri")));
            }
            let did = if step == Some("2fa") {
                let id = cookie(headers, DEVICE_COOKIE).filter(|i| store::valid_device_id(i))?;
                store::get_device(app, &id).await.ok()??.pending_2fa.map(|(did, _)| did)
            } else {
                match p.get("identifier") {
                    Some(i) => resolve_identifier(app, i).await,
                    None => None,
                }
            };
            did.or_else(|| request(p.get("request_uri")))
        }
        "/oauth/account/revoke" => params().remove("did").filter(|d| d.starts_with("did:")),
        // code -> its request row; refresh token -> its session's account
        "/oauth/token" => {
            let p = params();
            match p.get("grant_type").map(String::as_str) {
                Some("authorization_code") => store::code_request_id(p.get("code")?).map(|id| store::req_routing(&id)),
                Some("refresh_token") => store::parse_refresh_token(p.get("refresh_token")?).map(|r| r.did),
                _ => None,
            }
        }
        "/oauth/revoke" => {
            let p = params();
            let tok = p.get("token")?;
            if let Some(r) = store::parse_refresh_token(tok) {
                Some(r.did)
            } else if let Some(id) = store::code_request_id(tok) {
                Some(store::req_routing(&id))
            } else {
                // access token: its (unverified) sub; the owner verifies
                let payload = ou::b64u_decode(tok.split('.').nth(1)?)?;
                #[derive(Deserialize)]
                struct Sub {
                    sub: String,
                }
                serde_json::from_slice::<Sub>(&payload).ok().map(|s| s.sub)
            }
        }
        _ => None,
    }
}

fn cors(h: &mut HeaderMap) {
    h.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
    h.insert(header::ACCESS_CONTROL_EXPOSE_HEADERS, HeaderValue::from_static("DPoP-Nonce, WWW-Authenticate"));
}

async fn preflight() -> Response {
    let mut r = StatusCode::NO_CONTENT.into_response();
    let h = r.headers_mut();
    cors(h);
    h.insert(header::ACCESS_CONTROL_ALLOW_METHODS, HeaderValue::from_static("GET, POST, OPTIONS"));
    h.insert(header::ACCESS_CONTROL_ALLOW_HEADERS, HeaderValue::from_static("Content-Type, DPoP, Authorization"));
    h.insert(header::ACCESS_CONTROL_MAX_AGE, HeaderValue::from_static("86400"));
    r
}

fn as_json(app: &App, status: StatusCode, body: J) -> Response {
    let mut r = (status, Json(body)).into_response();
    finish_as(app, &mut r);
    r
}

fn finish_as(app: &App, r: &mut Response) {
    let h = r.headers_mut();
    cors(h);
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    if let Ok(v) = HeaderValue::from_str(&keys(app).nonces.next()) {
        h.insert(HeaderName::from_static("dpop-nonce"), v);
    }
}

fn as_error(app: &App, e: OAuthError) -> Response {
    let mut r = e.into_response();
    finish_as(app, &mut r);
    r
}

async fn protected_resource_metadata(State(app): AppState) -> Response {
    let iss = issuer(&app);
    let mut r = Json(json!({
        "resource": iss,
        "authorization_servers": [iss],
        "scopes_supported": [],
        "bearer_methods_supported": ["header"],
        "resource_documentation": "https://atproto.com",
    }))
    .into_response();
    cors(r.headers_mut());
    r
}

/// The web UI's own OAuth client, for other servers' authorization servers.
async fn first_party_metadata(State(app): AppState) -> Response {
    let mut r = Json(client::first_party_metadata(&app.public_url)).into_response();
    cors(r.headers_mut());
    r.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("public, max-age=600"));
    r
}

async fn authorization_server_metadata(State(app): AppState) -> Response {
    let iss = issuer(&app);
    let mut r = Json(json!({
        "issuer": iss,
        "scopes_supported": ["atproto", "transition:email", "transition:generic", "transition:chat.bsky"],
        "subject_types_supported": ["public"],
        "response_types_supported": ["code"],
        "response_modes_supported": ["query", "fragment", "form_post"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "ui_locales_supported": ["en-US"],
        "display_values_supported": ["page", "popup", "touch"],
        "prompt_values_supported": ["none", "login", "consent", "select_account", "create"],
        "authorization_response_iss_parameter_supported": true,
        "request_object_signing_alg_values_supported": [jose::VERIFY_ALGS[0], "none"],
        "request_object_encryption_alg_values_supported": [],
        "request_object_encryption_enc_values_supported": [],
        "request_parameter_supported": true,
        "request_uri_parameter_supported": true,
        "require_request_uri_registration": true,
        "jwks_uri": format!("{iss}/oauth/jwks"),
        "authorization_endpoint": format!("{iss}/oauth/authorize"),
        "token_endpoint": format!("{iss}/oauth/token"),
        "token_endpoint_auth_methods_supported": client::AUTH_METHODS_SUPPORTED,
        "token_endpoint_auth_signing_alg_values_supported": jose::VERIFY_ALGS,
        "revocation_endpoint": format!("{iss}/oauth/revoke"),
        "pushed_authorization_request_endpoint": format!("{iss}/oauth/par"),
        "require_pushed_authorization_requests": true,
        "dpop_signing_alg_values_supported": jose::VERIFY_ALGS,
        "protected_resources": [iss],
        "client_id_metadata_document_supported": true,
    }))
    .into_response();
    cors(r.headers_mut());
    r
}

async fn jwks(State(app): AppState) -> Response {
    let mut r = Json(json!({"keys": [keys(&app).server.public_jwk()]})).into_response();
    cors(r.headers_mut());
    r
}

/// Urlencoded or JSON. Repeated parameters are an error (RFC 6749 §3.1).
fn parse_params(headers: &HeaderMap, body: &[u8]) -> Result<HashMap<String, String>, OAuthError> {
    let ct = headers.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("").to_ascii_lowercase();
    let mut out = HashMap::new();
    if ct.starts_with("application/json") {
        let j: J = serde_json::from_slice(body).map_err(|_| OAuthError::invalid_request("Invalid JSON body"))?;
        let obj = j.as_object().ok_or_else(|| OAuthError::invalid_request("Invalid JSON body"))?;
        for (k, v) in obj {
            let s = match v {
                J::String(s) => s.clone(),
                J::Number(n) => n.to_string(),
                J::Bool(b) => b.to_string(),
                J::Null => continue,
                _ => return Err(OAuthError::invalid_request(&format!("Invalid \"{k}\" parameter"))),
            };
            out.insert(k.clone(), s);
        }
        return Ok(out);
    }
    let s = std::str::from_utf8(body).map_err(|_| OAuthError::invalid_request("Invalid request body"))?;
    for (k, v) in ou::parse_form(s) {
        if out.insert(k.clone(), v).is_some() {
            return Err(OAuthError::invalid_request(&format!("Duplicate \"{k}\" parameter")));
        }
    }
    Ok(out)
}

fn dpop_header(headers: &HeaderMap) -> Result<Option<String>, String> {
    let mut it = headers.get_all("dpop").iter();
    match (it.next(), it.next()) {
        (None, _) => Ok(None),
        (Some(v), None) => {
            let s = v.to_str().map_err(|_| "Invalid DPoP header".to_string())?;
            if s.is_empty() {
                Err("DPoP header cannot be empty".into())
            } else {
                Ok(Some(s.to_string()))
            }
        }
        _ => Err("DPoP header must contain a single proof".into()),
    }
}

/// Required, and single use cluster-wide.
async fn check_as_dpop(app: &App, headers: &HeaderMap, path: &str) -> Result<DpopProof, OAuthError> {
    let proof = dpop_header(headers)
        .map_err(|e| OAuthError::invalid_dpop_proof(&e))?
        .ok_or_else(|| OAuthError::invalid_dpop_proof("DPoP proof required"))?;
    let htu = jose::normalize_htu(&format!("{}{path}", issuer(app)))
        .ok_or_else(|| OAuthError::server_error("bad public_url"))?;
    let proof = jose::check_proof(&proof, "POST", &htu, None, &keys(app).nonces).map_err(|e| match e {
        DpopError::UseNonce(m) => OAuthError::use_dpop_nonce(&m),
        DpopError::Invalid(m) => OAuthError::invalid_dpop_proof(&m),
    })?;
    let replay = proof.replay(ou::jkt_routing(&proof.jkt));
    claim(app, &replay, OAuthError::invalid_dpop_proof("DPoP proof replayed")).await?;
    Ok(proof)
}

async fn claim(app: &App, r: &ou::Replay, replayed: OAuthError) -> Result<(), OAuthError> {
    match super::internal::claim_replay_anywhere(app, &r.routing, &r.key, r.until).await {
        Ok(true) => Ok(()),
        Ok(false) => Err(replayed),
        Err(e) => Err(unavailable(&e.message)),
    }
}

fn unavailable(msg: &str) -> OAuthError {
    OAuthError::new(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable", msg)
}

/// Single-use state is read-modify-written only by its owner, under a local
/// lock there. Forwarding sends the request to the owner; this refuses
/// (retryably) if it isn't us, e.g. mid-handoff.
fn require_owner(app: &App, routing: &str) -> Result<(), OAuthError> {
    if app.remote_owner(routing).is_some() || app.partition(routing).is_err() {
        return Err(unavailable("this grant's partition is moving; retry"));
    }
    Ok(())
}

async fn account_any(app: &App, did: &str) -> XResult<Account> {
    super::internal::account_anywhere(app, did).await
}

async fn ensure_active_any(app: &App, did: &str) -> XResult<Account> {
    let a = account_any(app, did)
        .await
        .map_err(|_| XrpcError::bad("RepoNotFound", format!("could not find repo: {did}")))?;
    match &a.status {
        Some(st) => Err(super::inactive_account_error(st)),
        None => Ok(a),
    }
}

async fn par(State(app): AppState, headers: HeaderMap, body: AxBytes) -> Response {
    match par_inner(&app, &headers, &body).await {
        Ok(j) => as_json(&app, StatusCode::CREATED, j),
        Err(e) => as_error(&app, e),
    }
}

async fn par_inner(app: &App, headers: &HeaderMap, body: &[u8]) -> Result<J, OAuthError> {
    let p = parse_params(headers, body)?;
    let proof = check_as_dpop(app, headers, "/oauth/par").await?;
    let creds = ClientCredentials::from_params(&p)?;
    let client = client::get_client(&creds.client_id, app.config.dev_mode, &app.public_url).await?;
    let (client_auth, assertion) = client.authenticate(&creds, &issuer(app))?;
    if let Some(r) = &assertion {
        claim(app, r, OAuthError::invalid_client("client assertion replayed")).await?;
    }
    if p.contains_key("request_uri") {
        return Err(OAuthError::invalid_request("\"request_uri\" is not supported in pushed authorization requests"));
    }
    // JAR (RFC 9101): only the request object's parameters are used
    let p = match p.get("request") {
        Some(jar) => {
            let (payload, r) = client.decode_request_object(jar, &issuer(app))?;
            claim(app, &r, OAuthError::invalid_request("Request object was replayed")).await?;
            request_object_params(&payload)?
        }
        None => p,
    };
    let params = validate_authorization_request(app, &client, &p, &proof).await?;
    if !store::claim_code_challenge(app, &params.code_challenge).await? {
        return Err(OAuthError::invalid_request("code_challenge was already used"));
    }
    let id = store::new_local_request_id(app);
    let now = now_secs();
    let req = RequestData {
        client_id: client.id.clone(),
        client_auth,
        params,
        created_at: now,
        expires_at: now + PAR_EXPIRES_IN,
        device_id: None,
        did: None,
        code_hash: None,
        consumed: None,
        auth_epoch: String::new(),
        auth_cred: None,
        space_collections: None,
    };
    store::put_request(app, &id, Some(&req)).await?;
    Ok(json!({"request_uri": store::request_uri(&id), "expires_in": PAR_EXPIRES_IN - 1}))
}

/// The reference's `oauthAuthorizationRequestParametersSchema`: scalars
/// stringified, registered JWT claims dropped.
fn request_object_params(payload: &J) -> Result<HashMap<String, String>, OAuthError> {
    let bad = |k: &str| OAuthError::invalid_request(&format!("Invalid parameters in JAR: invalid \"{k}\""));
    let obj = payload.as_object().ok_or_else(|| OAuthError::invalid_request("Invalid parameters in JAR"))?;
    let mut out = HashMap::new();
    for (k, v) in obj {
        if matches!(k.as_str(), "iss" | "aud" | "sub" | "iat" | "exp" | "nbf" | "jti") {
            continue;
        }
        let s = match v {
            J::Null => continue,
            J::String(s) => s.clone(),
            J::Number(n) => n.to_string(),
            J::Bool(b) => b.to_string(),
            // rejected with its own error by validate_authorization_request
            J::Array(_) if k == "authorization_details" => v.to_string(),
            _ => return Err(bad(k)),
        };
        out.insert(k.clone(), s);
    }
    if !out.contains_key("client_id") {
        return Err(bad("client_id"));
    }
    Ok(out)
}

/// `RequestManager.validate` + `Client.validateRequest`.
async fn validate_authorization_request(
    app: &App,
    client: &Client,
    p: &HashMap<String, String>,
    proof: &DpopProof,
) -> Result<AuthParams, OAuthError> {
    let g = |k: &str| p.get(k).filter(|v| !v.is_empty()).cloned();
    if g("client_id").is_some_and(|c| c != client.id) {
        return Err(OAuthError::invalid_request(
            "The \"client_id\" parameter field does not match the value used to authenticate the client",
        ));
    }
    for k in ["request", "request_uri"] {
        if p.contains_key(k) {
            return Err(OAuthError::invalid_request(&format!(
                "\"{k}\" is not supported in pushed authorization requests"
            )));
        }
    }
    for k in ["claims", "id_token_hint", "nonce"] {
        if p.contains_key(k) {
            return Err(OAuthError::invalid_request(&format!("Unsupported \"{k}\" parameter")));
        }
    }
    if p.contains_key("authorization_details") {
        return Err(OAuthError::new(
            StatusCode::BAD_REQUEST,
            "invalid_authorization_details",
            "Unsupported \"authorization_details\"",
        ));
    }
    let response_type = g("response_type").ok_or_else(|| OAuthError::invalid_request("Missing \"response_type\""))?;
    if response_type != "code" {
        return Err(OAuthError::new(
            StatusCode::BAD_REQUEST,
            "unsupported_response_type",
            &format!("Unsupported response_type \"{response_type}\""),
        ));
    }
    if !client.response_types.contains(&response_type) {
        return Err(OAuthError::invalid_request(&format!(
            "Invalid response_type \"{response_type}\" requested by the client"
        )));
    }
    if !client.grant_types.iter().any(|g| g == "authorization_code") {
        return Err(OAuthError::unauthorized_client(
            "This client is not allowed to use the \"authorization_code\" grant type",
        ));
    }
    let redirect_uri = match g("redirect_uri") {
        Some(r) => {
            if !client.allows_redirect_uri(&r) {
                return Err(OAuthError::invalid_request(&format!("Invalid redirect_uri {r}")));
            }
            r
        }
        None => client
            .default_redirect_uri()
            .map(String::from)
            .ok_or_else(|| OAuthError::invalid_request("redirect_uri is required"))?,
    };
    let scope = requested_scope(client, &g("scope").unwrap_or_default(), app.config.spaces)?;
    let (code_challenge, method) = pkce_challenge(p)?;
    let response_mode = g("response_mode");
    match response_mode.as_deref() {
        None | Some("query") | Some("fragment") | Some("form_post") => {}
        Some(m) => return Err(OAuthError::invalid_request(&format!("Unsupported response_mode \"{m}\""))),
    }
    let mut prompt = g("prompt");
    match prompt.as_deref() {
        None | Some("none") | Some("login") | Some("consent") | Some("select_account") | Some("create") => {}
        Some(v) => return Err(OAuthError::invalid_request(&format!("Unsupported prompt \"{v}\""))),
    }
    // atproto: public clients may not sign in silently and always get the
    // consent screen (prompt=create keeps its prompt; consent_required
    // still holds for them)
    if !client.is_confidential() {
        if prompt.as_deref() == Some("none") {
            return Err(OAuthError::new(
                StatusCode::BAD_REQUEST,
                "consent_required",
                "Public clients are not allowed to use silent-sign-on",
            ));
        }
        if prompt.as_deref() != Some("create") {
            prompt = Some("consent".into());
        }
    }
    let login_hint = match g("login_hint") {
        Some(h) => {
            let h = h.to_lowercase();
            let h = h.strip_prefix('@').unwrap_or(&h).to_string();
            if !is_atproto_did(&h) && !super::syntax::valid_handle(&h) {
                return Err(OAuthError::invalid_request(&format!("Invalid login_hint \"{h}\"")));
            }
            Some(h)
        }
        None => None,
    };
    if let Some(jkt) = g("dpop_jkt") {
        if jkt != proof.jkt {
            return Err(OAuthError::invalid_dpop_proof("DPoP proof does not match the dpop_jkt parameter"));
        }
    }
    // every include: scope must resolve to a permission set
    lexicon::permission_sets_for_scope(app, &scope).await.map_err(|e| OAuthError::invalid_scope(&e))?;
    Ok(AuthParams {
        client_id: client.id.clone(),
        response_type,
        redirect_uri,
        scope,
        state: g("state"),
        code_challenge,
        code_challenge_method: method,
        response_mode,
        prompt,
        login_hint,
        dpop_jkt: proof.jkt.clone(),
        display: g("display"),
        ui_locales: g("ui_locales"),
    })
}

/// Declared by the client, deduplicated, with `atproto`. `space:` scopes
/// only with `--spaces`.
fn requested_scope(client: &Client, requested: &str, spaces: bool) -> Result<String, OAuthError> {
    let mut scopes: Vec<&str> = Vec::new();
    for s in requested.split(' ').filter(|s| !s.is_empty()) {
        if !client.scopes.iter().any(|c| c == s) {
            return Err(OAuthError::invalid_scope(&format!("Scope \"{s}\" is not declared in the client metadata")));
        }
    }
    for s in requested.split(' ').filter(|s| !s.is_empty()) {
        if s == "openid" {
            return Err(OAuthError::invalid_scope("OpenID Connect is not compatible with atproto"));
        }
        let known = is_atproto_oauth_scope(s) || (spaces && crate::oauth::scopes::is_space_scope(s));
        if known && !scopes.contains(&s) {
            scopes.push(s);
        }
    }
    if !scopes.contains(&"atproto") {
        return Err(OAuthError::invalid_scope("The \"atproto\" scope is required"));
    }
    Ok(scopes.join(" "))
}

/// (code_challenge, method): S256 only.
fn pkce_challenge(p: &HashMap<String, String>) -> Result<(String, String), OAuthError> {
    let g = |k: &str| p.get(k).filter(|v| !v.is_empty()).cloned();
    let code_challenge = g("code_challenge").ok_or_else(|| {
        if p.contains_key("code_challenge_method") {
            OAuthError::invalid_request("code_challenge is required when code_challenge_method is provided")
        } else {
            OAuthError::invalid_request("Use of PKCE is required")
        }
    })?;
    let method = g("code_challenge_method").unwrap_or_else(|| "plain".into());
    if method != "S256" {
        return Err(OAuthError::invalid_request("atproto requires use of \"S256\" code_challenge_method"));
    }
    if code_challenge.len() != 43 || ou::b64u_decode(&code_challenge).map(|b| b.len()) != Some(32) {
        return Err(OAuthError::invalid_request("Invalid code_challenge"));
    }
    Ok((code_challenge, method))
}

fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    for v in headers.get_all(header::COOKIE) {
        for part in v.to_str().ok()?.split(';') {
            if let Some((k, val)) = part.trim().split_once('=') {
                if k == name {
                    return Some(val.to_string());
                }
            }
        }
    }
    None
}

/// The browser's device id, when its cookie is well-formed.
pub(crate) fn device_cookie_id(headers: &HeaderMap) -> Option<String> {
    cookie(headers, DEVICE_COOKIE).filter(|i| store::valid_device_id(i))
}

/// Loads or starts the browser device session; true: a cookie must be set.
pub(crate) async fn device_for(app: &App, headers: &HeaderMap) -> Result<(Device, bool), OAuthError> {
    let ua =
        headers.get(header::USER_AGENT).and_then(|v| v.to_str().ok()).map(|s| s.chars().take(256).collect::<String>());
    if let Some(id) = cookie(headers, DEVICE_COOKIE).filter(|i| store::valid_device_id(i)) {
        if let Some(mut d) = store::get_device(app, &id).await? {
            let now = now_secs();
            if now - d.last_seen_at > 3600 {
                d.last_seen_at = now;
                store::put_device(app, &d).await?;
            }
            return Ok((d, false));
        }
    }
    let now = now_secs();
    let d = Device {
        id: store::new_device_id(),
        created_at: now,
        last_seen_at: now,
        user_agent: ua,
        accounts: vec![],
        pending_2fa: None,
        pending_2fa_failures: 0,
        pending_2fa_epoch: String::new(),
        trusted_until: 0,
    };
    store::put_device(app, &d).await?;
    Ok((d, true))
}

pub(crate) fn device_cookie(app: &App, d: &Device) -> HeaderValue {
    let secure = if is_https(app) { "; Secure" } else { "" };
    HeaderValue::from_str(&format!(
        "{DEVICE_COOKIE}={}; Path=/; HttpOnly; SameSite=Lax; Max-Age=31536000{secure}",
        d.id
    ))
    .unwrap()
}

fn csrf_token(app: &App, device_id: &str, scope: &str) -> String {
    ou::b64u(ou::hmac_sha256(&keys(app).csrf, &[device_id.as_bytes(), scope.as_bytes()]))
}

/// A token bound to the device cookie and the request, plus Fetch-Metadata
/// and Origin checks when the browser sends them.
fn check_csrf(app: &App, headers: &HeaderMap, device: &Device, scope: &str, token: Option<&String>) -> bool {
    if let Some(site) = headers.get("sec-fetch-site").and_then(|v| v.to_str().ok()) {
        if site != "same-origin" && site != "none" {
            return false;
        }
    }
    if let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
        if origin != "null"
            && reqwest::Url::parse(&issuer(app)).map(|u| u.origin().ascii_serialization()).ok().as_deref()
                != Some(origin)
        {
            return false;
        }
    }
    match token {
        Some(t) => crate::auth::ct_eq(t.as_bytes(), csrf_token(app, &device.id, scope).as_bytes()),
        None => false,
    }
}

/// The form-action source allowing the post-consent redirect.
fn redirect_source(redirect_uri: &str) -> Option<String> {
    let u = reqwest::Url::parse(redirect_uri).ok()?;
    match u.scheme() {
        "http" | "https" => Some(u.origin().ascii_serialization()),
        s => Some(format!("{s}:")),
    }
}

fn html(app: &App, status: StatusCode, body: String, form_action: &[String], set_cookie: Option<&Device>) -> Response {
    let mut r = (status, body).into_response();
    let h = r.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"));
    h.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_str(&ui::csp(form_action)).unwrap());
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(HeaderName::from_static("cross-origin-resource-policy"), HeaderValue::from_static("same-origin"));
    if let Some(d) = set_cookie {
        h.insert(header::SET_COOKIE, device_cookie(app, d));
    }
    r
}

fn error_page(app: &App, status: StatusCode, title: &str, msg: &str) -> Response {
    html(app, status, ui::error(title, msg), &[], None)
}

fn server_error_page(app: &App, title: &str, msg: &str) -> Response {
    error_page(app, StatusCode::INTERNAL_SERVER_ERROR, title, msg)
}

/// A 503 from the sign-in/sign-up forms (password hashing shed).
const BUSY_MESSAGE: &str = "The server is busy. Please try again in a moment.";

fn with_retry_after(mut r: Response) -> Response {
    r.headers_mut().insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
    r
}

/// RFC 6749 §4.1.2 + RFC 9207 `iss`, in the request's response mode.
fn client_redirect(app: &App, params: &AuthParams, mut pairs: Vec<(String, String)>) -> Response {
    if let Some(s) = &params.state {
        pairs.push(("state".into(), s.clone()));
    }
    pairs.push(("iss".into(), issuer(app)));
    if params.response_mode.as_deref() == Some("form_post") {
        let form_action: Vec<String> = redirect_source(&params.redirect_uri).into_iter().collect();
        let mut r = html(app, StatusCode::OK, ui::form_post(&params.redirect_uri, &pairs), &form_action, None);
        let h = r.headers_mut();
        h.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_str(&ui::csp_form_post(&form_action)).unwrap());
        // out of the back/forward cache, so going "back" never re-posts the
        // response (as the reference does)
        h.append(header::SET_COOKIE, HeaderValue::from_static("bfCacheBypass=1; Path=/; Max-Age=1; SameSite=Lax"));
        return r;
    }
    let enc = ou::form_encode(&pairs);
    let url = if params.response_mode.as_deref() == Some("fragment") {
        format!("{}#{enc}", params.redirect_uri.split('#').next().unwrap_or(""))
    } else if params.redirect_uri.contains('?') {
        format!("{}&{enc}", params.redirect_uri)
    } else {
        format!("{}?{enc}", params.redirect_uri)
    };
    let mut r = StatusCode::SEE_OTHER.into_response();
    let h = r.headers_mut();
    h.insert(header::LOCATION, HeaderValue::from_str(&url).unwrap_or(HeaderValue::from_static("/")));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    r
}

fn redirect_error(app: &App, params: &AuthParams, error: &str, desc: &str) -> Response {
    client_redirect(app, params, vec![("error".into(), error.into()), ("error_description".into(), desc.into())])
}

struct Flow {
    id: String,
    uri: String,
    req: RequestData,
    client: Arc<Client>,
    device: Device,
    new_cookie: bool,
}

enum FlowError {
    /// The redirect target is not trustworthy or unknown.
    Page(StatusCode, String),
    Redirect(Box<AuthParams>, &'static str, String),
}

impl FlowError {
    fn into_response(self, app: &App) -> Response {
        match self {
            FlowError::Page(s, m) => error_page(app, s, "Authorization failed", &m),
            FlowError::Redirect(p, e, m) => redirect_error(app, &p, e, &m),
        }
    }
}

impl From<OAuthError> for FlowError {
    fn from(e: OAuthError) -> FlowError {
        FlowError::Page(StatusCode::INTERNAL_SERVER_ERROR, e.description)
    }
}

/// `RequestManager.get`: binds the request to this device.
async fn load_flow(
    app: &App,
    headers: &HeaderMap,
    request_uri: Option<&str>,
    client_id: Option<&str>,
) -> Result<Flow, FlowError> {
    let uri = request_uri.ok_or_else(|| {
        FlowError::Page(
            StatusCode::BAD_REQUEST,
            "Pushed Authorization Request (PAR) is required: missing request_uri".into(),
        )
    })?;
    let id = store::request_id_from_uri(uri)
        .ok_or_else(|| FlowError::Page(StatusCode::BAD_REQUEST, "Invalid request_uri".into()))?
        .to_string();
    let (device, new_cookie) = device_for(app, headers).await?;
    let mut req = store::get_request(app, &id)
        .await?
        .ok_or_else(|| FlowError::Page(StatusCode::BAD_REQUEST, "Unknown request_uri".into()))?;
    let fail = |m: &str| FlowError::Redirect(Box::new(req.params.clone()), "access_denied", m.to_string());
    let now = now_secs();
    let authorized = req.did.is_some() || req.code_hash.is_some() || req.consumed.is_some();
    let err = if authorized {
        Some(fail("This request was already authorized"))
    } else if req.expires_at < now {
        Some(fail("This request has expired"))
    } else if client_id.is_some_and(|c| c != req.client_id) {
        Some(fail("This request was initiated for another client"))
    } else if req.device_id.as_ref().is_some_and(|d| *d != device.id) {
        Some(fail("This request was initiated from another device"))
    } else {
        None
    };
    if let Some(e) = err {
        // Only an expired, unauthorized request is deleted. The reference
        // deletes on every failure, but anyone holding the request_uri (it
        // is in the browser's URL) reaches these checks: deleting would break
        // the client's code exchange or the user's flow in progress.
        if !authorized && req.expires_at < now {
            store::put_request(app, &id, None).await?;
        }
        return Err(e);
    }
    req.device_id = Some(device.id.clone());
    req.expires_at = now + AUTHORIZATION_INACTIVITY_TIMEOUT;
    store::put_request(app, &id, Some(&req)).await?;
    let client = client::get_client(&req.client_id, app.config.dev_mode, &app.public_url)
        .await
        .map_err(|e| FlowError::Redirect(Box::new(req.params.clone()), "invalid_client", e.description))?;
    Ok(Flow { id, uri: uri.to_string(), req, client, device, new_cookie })
}

impl Flow {
    fn csrf(&self, app: &App) -> String {
        csrf_token(app, &self.device.id, &self.id)
    }

    fn form_action(&self) -> Vec<String> {
        redirect_source(&self.req.params.redirect_uri).into_iter().collect()
    }

    fn page(&self, app: &App, body: String) -> Response {
        html(app, StatusCode::OK, body, &self.form_action(), self.new_cookie.then_some(&self.device))
    }

    fn ctx<'a>(&'a self, csrf: &'a str, server_name: &'a str) -> ui::Ctx<'a> {
        ui::Ctx {
            request_uri: &self.uri,
            csrf,
            client_id: &self.client.id,
            loopback: self.client.loopback,
            server_name,
        }
    }
}

fn server_name(app: &App) -> String {
    reqwest::Url::parse(&app.public_url)
        .ok()
        .and_then(|u| u.host_str().map(String::from))
        .unwrap_or_else(|| app.public_url.clone())
}

/// (did, handle) of fresh logins. A login from before a password change or
/// takedown (its credential epoch changed) no longer counts.
async fn device_accounts(app: &App, d: &Device) -> Vec<(String, String)> {
    let now = now_secs();
    let mut out = Vec::new();
    for a in &d.accounts {
        if now - a.authenticated_at > AUTHENTICATION_MAX_AGE {
            continue;
        }
        if crate::xrpc::auth_epoch(app, &a.did).await.ok().as_deref() != Some(a.auth_epoch.as_str()) {
            continue;
        }
        // signed in with a passkey that has since been removed
        if !super::passkeys::still_registered(app, &a.did, a.auth_cred.as_deref()).await.unwrap_or(false) {
            continue;
        }
        if let Ok(acct) = account_any(app, &a.did).await {
            if acct.status.is_none() {
                out.push((acct.did.clone(), acct.handle.clone()));
            }
        }
    }
    out
}

async fn consent_required(app: &App, flow: &Flow, did: &str) -> Result<bool, OAuthError> {
    if flow.req.params.prompt.as_deref() == Some("consent") || !flow.client.is_confidential() {
        return Ok(true);
    }
    let Some(a) = store::get_authorization(app, did, &flow.client.id).await? else {
        return Ok(true);
    };
    Ok(!flow.req.params.scope.split(' ').all(|s| a.scopes.iter().any(|x| x == s)))
}

fn login_page(app: &App, flow: &Flow, identifier: &str, error: Option<&str>, status: StatusCode) -> Response {
    let csrf = flow.csrf(app);
    let name = server_name(app);
    let pk = passwordless_ui(app, &passkey_binding(&flow.device.id, &flow.id, None));
    let body = ui::login(
        Some(&flow.ctx(&csrf, &name)),
        &ui::LoginForm {
            action: "/oauth/authorize/sign-in",
            identifier,
            error,
            second: None,
            passkey: pk.as_ref().map(|(c, r)| ui::PasskeyUi { challenge: c, rp_id: r, allow: "[]" }),
        },
        "",
    );
    let mut r = flow.page(app, body);
    set_passkey_csp(&mut r, &flow.form_action());
    *r.status_mut() = status;
    r
}

/// A passwordless challenge for the sign-in page: (challenge, RP ID).
/// Stateless, so rendering the page writes nothing.
fn passwordless_ui(app: &App, binding: &str) -> Option<(String, String)> {
    let rp = super::passkeys::rp(app).ok()?;
    let ch =
        crate::webauthn::mint_challenge(&super::passkeys::challenge_key(app), "signin", binding, now_secs() as u64);
    Some((ou::b64u(ch), rp.id))
}

/// Approves directly when the user already granted these scopes to this
/// confidential client.
async fn consent_step(app: &App, mut flow: Flow, did: &str) -> Response {
    let acct = match account_any(app, did).await {
        Ok(a) => a,
        Err(_) => return login_page(app, &flow, "", Some("Account not found"), StatusCode::OK),
    };
    let required = match consent_required(app, &flow, did).await {
        Ok(r) => r,
        Err(e) => return server_error_page(app, "Authorization failed", &e.description),
    };
    if !required {
        return approve_without_consent(app, flow, did).await;
    }
    let sets = lexicon::permission_sets_for_scope(app, &flow.req.params.scope).await.unwrap_or_default();
    let names = match app.config.spaces {
        true => Some(space_names(app, &flow.req.params.scope, &sets, true).await),
        false => None,
    };
    // what the screen shows is exactly what the token will carry
    let resolved = names.as_ref().filter(|n| !n.decls.is_empty());
    flow.req.space_collections = resolved.map(space_collections);
    if resolved.is_some() {
        if let Err(e) = store::put_request(app, &flow.id, Some(&flow.req)).await {
            return server_error_page(app, "Authorization failed", &e.description);
        }
    }
    let rows = ui::describe_scopes(&flow.req.params.scope, &sets, names.as_ref());
    let csrf = flow.csrf(app);
    let name = server_name(app);
    let body = ui::consent(&flow.ctx(&csrf, &name), did, &acct.handle, &flow.req.params.scope, &rows);
    flow.page(app, body)
}

/// A login the account already approved for this client: with `--spaces`,
/// its bare writing grants take the collections their types declare now.
async fn approve_without_consent(app: &App, mut flow: Flow, did: &str) -> Response {
    if app.config.spaces {
        let sets = lexicon::permission_sets_for_scope(app, &flow.req.params.scope).await.unwrap_or_default();
        let names = space_names(app, &flow.req.params.scope, &sets, false).await;
        flow.req.space_collections = (!names.decls.is_empty()).then(|| space_collections(&names));
    }
    issue_code(app, flow, did).await
}

fn space_collections(n: &ui::SpaceNames) -> std::collections::BTreeMap<String, Vec<String>> {
    n.decls.iter().map(|(t, d)| (t.clone(), d.collections.clone())).collect()
}

/// The consent screen's names for the `space:` grants requested, directly
/// or through permission sets (reference `getSpacesFromScope` and
/// `getSpaceHandlesFromScope`), each looked up in bounded time and shown
/// raw when it doesn't resolve. Without a screen (`screen` false), only
/// the declarations the token needs: an auto-approved login whose grants
/// all name their collections or only read waits on no lookup.
async fn space_names(
    app: &App,
    scope: &str,
    sets: &[(crate::oauth::scopes::IncludeScope, J)],
    screen: bool,
) -> ui::SpaceNames {
    use crate::oauth::scopes::Permission;
    const MAX_LOOKUPS: usize = 16;
    let mut perms: Vec<Permission> = scope.split(' ').filter_map(Permission::parse).collect();
    for (inc, set) in sets {
        perms.extend(inc.to_permissions(set, true));
    }
    let (mut types, mut dids) = (Vec::new(), Vec::new());
    for p in perms {
        let Permission::Space(p) = p else { continue };
        if p.space_type != "*" && (screen || p.needs_declaration()) && !types.contains(&p.space_type) {
            types.push(p.space_type.clone());
        }
        if screen && !["*", "self"].contains(&p.authority.as_str()) && !dids.contains(&p.authority) {
            dids.push(p.authority);
        }
    }
    let budget = std::time::Duration::from_secs(3);
    let decls = futures::future::join_all(types.into_iter().take(MAX_LOOKUPS).map(|t| async move {
        let d = lexicon::space_declaration(app, &t).await.ok();
        d.map(|d| (t, d))
    }));
    let handles = futures::future::join_all(dids.into_iter().take(MAX_LOOKUPS).map(|did| async move {
        let h = tokio::time::timeout(budget, super::identity::verified_handle(app, &did)).await.ok().flatten();
        h.map(|h| (did, h))
    }));
    let (decls, handles) = tokio::join!(decls, handles);
    ui::SpaceNames { decls: decls.into_iter().flatten().collect(), handles: handles.into_iter().flatten().collect() }
}

/// `RequestManager.setAuthorized`.
async fn issue_code(app: &App, mut flow: Flow, did: &str) -> Response {
    if let Err(e) = ensure_active_any(app, did).await {
        let _ = store::put_request(app, &flow.id, None).await;
        return redirect_error(app, &flow.req.params, "access_denied", &format!("Account unavailable: {}", e.message));
    }
    // the code's session is created only while this login's credential
    // epoch is current (code_grant)
    let Some((epoch, auth_cred)) =
        flow.device.accounts.iter().find(|a| a.did == did).map(|a| (a.auth_epoch.clone(), a.auth_cred.clone()))
    else {
        return login_page(app, &flow, "", Some("Please sign in again"), StatusCode::UNAUTHORIZED);
    };
    let code = store::new_code(&flow.id);
    flow.req.auth_epoch = epoch;
    flow.req.auth_cred = auth_cred;
    flow.req.did = Some(did.to_string());
    flow.req.code_hash = Some(store::hash_secret(&code));
    flow.req.expires_at = now_secs() + AUTHORIZATION_INACTIVITY_TIMEOUT;
    if let Err(e) = store::put_request(app, &flow.id, Some(&flow.req)).await {
        return server_error_page(app, "Authorization failed", &e.description);
    }
    // remember consent, union with earlier grants
    let mut scopes: Vec<String> = flow.req.params.scope.split(' ').map(String::from).collect();
    if let Ok(Some(prev)) = store::get_authorization(app, did, &flow.client.id).await {
        for s in prev.scopes {
            if !scopes.contains(&s) {
                scopes.push(s);
            }
        }
    }
    let _ = store::put_authorization(
        app,
        did,
        &store::Authorization { client_id: flow.client.id.clone(), scopes, updated_at: now_secs() },
    )
    .await;
    let mut r = client_redirect(app, &flow.req.params, vec![("code".into(), code)]);
    if flow.new_cookie {
        r.headers_mut().append(header::SET_COOKIE, device_cookie(app, &flow.device));
    }
    r
}

async fn authorize(State(app): AppState, headers: HeaderMap, Query(q): Query<HashMap<String, String>>) -> Response {
    if !q.contains_key("client_id") {
        return error_page(&app, StatusCode::BAD_REQUEST, "Authorization failed", "Missing client_id");
    }
    let flow = match load_flow(
        &app,
        &headers,
        q.get("request_uri").map(String::as_str),
        q.get("client_id").map(String::as_str),
    )
    .await
    {
        Ok(f) => f,
        Err(e) => return e.into_response(&app),
    };
    let accounts = device_accounts(&app, &flow.device).await;
    let params = flow.req.params.clone();
    let hint = params.login_hint.clone().unwrap_or_default();
    let hinted = accounts.iter().find(|(d, h)| !hint.is_empty() && (hint == *d || hint == *h)).cloned();
    // the sign-in <-> sign-up links between the two pages
    match q.get("screen").map(String::as_str) {
        Some("sign-up") => return signup_page(&app, &flow, &SignupValues::default(), None, StatusCode::OK),
        Some("sign-in") => return login_page(&app, &flow, &hint, None, StatusCode::OK),
        _ => {}
    }
    match params.prompt.as_deref() {
        Some("none") => {
            let chosen = match (&hinted, accounts.len()) {
                (Some(a), _) => a.clone(),
                (None, 1) if hint.is_empty() => accounts[0].clone(),
                (None, n) if n == 0 || !hint.is_empty() => {
                    return redirect_error(&app, &params, "login_required", "Login is required")
                }
                (None, _) => {
                    return redirect_error(&app, &params, "account_selection_required", "Account selection is required")
                }
            };
            match consent_required(&app, &flow, &chosen.0).await {
                Ok(false) => approve_without_consent(&app, flow, &chosen.0).await,
                Ok(true) => redirect_error(&app, &params, "consent_required", "Consent is required"),
                Err(e) => redirect_error(&app, &params, "server_error", &e.description),
            }
        }
        Some("login") => login_page(&app, &flow, &hint, None, StatusCode::OK),
        // prompt=create: the sign-up page (which links to sign-in)
        Some("create") => signup_page(&app, &flow, &SignupValues::default(), None, StatusCode::OK),
        Some("select_account") if !accounts.is_empty() => chooser_page(&app, &flow, &accounts),
        _ => {
            if let Some((did, _)) = hinted {
                consent_step(&app, flow, &did).await
            } else if !hint.is_empty() || accounts.is_empty() {
                login_page(&app, &flow, &hint, None, StatusCode::OK)
            } else {
                chooser_page(&app, &flow, &accounts)
            }
        }
    }
}

fn chooser_page(app: &App, flow: &Flow, accounts: &[(String, String)]) -> Response {
    let csrf = flow.csrf(app);
    let name = server_name(app);
    flow.page(app, ui::chooser(&flow.ctx(&csrf, &name), accounts))
}

fn form_fields(body: &[u8]) -> HashMap<String, String> {
    ou::parse_form(std::str::from_utf8(body).unwrap_or("")).into_iter().collect()
}

/// Also checks CSRF.
#[allow(clippy::result_large_err)]
async fn form_flow(app: &App, headers: &HeaderMap, body: &[u8]) -> Result<(Flow, HashMap<String, String>), Response> {
    let f = form_fields(body);
    let flow = load_flow(app, headers, f.get("request_uri").map(String::as_str), None)
        .await
        .map_err(|e| e.into_response(app))?;
    if flow.new_cookie || !check_csrf(app, headers, &flow.device, &flow.id, f.get("csrf")) {
        return Err(error_page(
            app,
            StatusCode::FORBIDDEN,
            "Authorization failed",
            "Invalid or missing CSRF token; please restart the sign-in from the app.",
        ));
    }
    Ok((flow, f))
}

enum SignIn {
    Ok(String),
    /// Password accepted, a second factor is needed.
    NeedFactor(Pending),
    /// A wrong code or passkey, still pending.
    NeedFactorErr(Pending, LoginError),
    /// (identifier to pre-fill, why)
    Failed(String, LoginError),
}

/// A sign-in waiting for its second factor, and what its page offers.
struct Pending {
    did: String,
    handle: String,
    /// The code was mailed to this (obfuscated) address: the only factor.
    email_hint: Option<String>,
    totp: bool,
    /// `allowCredentials` for the passkey button; empty without passkeys.
    passkeys: Vec<J>,
    /// It has passkeys, every one flagged as copied.
    flagged: bool,
}

impl Pending {
    async fn of(app: &App, acct: &Account, factor: &super::email2fa::Factor) -> Result<Pending, OAuthError> {
        let email_hint = match factor {
            super::email2fa::Factor::Email { hint } => Some(hint.clone()),
            _ => None,
        };
        let all = if email_hint.is_some() { Default::default() } else { super::passkeys::load(app, &acct.did).await? };
        let passkeys = super::passkeys::descriptors(&all);
        Ok(Pending {
            did: acct.did.clone(),
            handle: acct.handle.clone(),
            totp: email_hint.is_none() && crate::totp::enabled_for(app, acct).await?,
            email_hint,
            flagged: !all.creds.is_empty() && passkeys.is_empty(),
            passkeys,
        })
    }
}

/// Pages show only these fixed messages, and `/oauth/account?error=` carries
/// the code, never request-supplied text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LoginError {
    Invalid,
    Timeout,
    BadCode,
    /// Password step again, or the account's factor is locked out.
    TooManyCodes,
    RateLimited,
    Inactive,
    /// One message for every passkey failure: nothing says whether an
    /// account has passkeys, or which check failed.
    Passkey,
}

impl LoginError {
    const ALL: [LoginError; 7] = [
        LoginError::Invalid,
        LoginError::Timeout,
        LoginError::BadCode,
        LoginError::TooManyCodes,
        LoginError::RateLimited,
        LoginError::Inactive,
        LoginError::Passkey,
    ];

    pub(crate) fn code(self) -> &'static str {
        match self {
            LoginError::Invalid => "invalid",
            LoginError::Timeout => "timeout",
            LoginError::BadCode => "bad_code",
            LoginError::TooManyCodes => "too_many_codes",
            LoginError::RateLimited => "rate_limited",
            LoginError::Inactive => "inactive",
            LoginError::Passkey => "passkey",
        }
    }

    pub(crate) fn from_code(c: &str) -> Option<LoginError> {
        Self::ALL.into_iter().find(|e| e.code() == c)
    }

    pub(crate) fn message(self) -> &'static str {
        match self {
            LoginError::Invalid => "Invalid handle or password",
            LoginError::Timeout => "Your sign-in timed out. Please enter your password again.",
            LoginError::BadCode => "Invalid authenticator code",
            LoginError::TooManyCodes => "Too many invalid authenticator codes. Please sign in again later.",
            LoginError::RateLimited => "Too many sign-in attempts. Please try again later.",
            LoginError::Inactive => "This account is deactivated or suspended",
            LoginError::Passkey => "Passkey not recognized",
        }
    }

    fn status(self) -> StatusCode {
        match self {
            LoginError::TooManyCodes | LoginError::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            _ => StatusCode::UNAUTHORIZED,
        }
    }
}

/// Records the login on the device. Wrong codes count against the account's
/// TOTP lockout and, past [`PENDING_2FA_MAX_FAILURES`], drop the pending
/// sign-in; a refused passkey only counts toward the latter, since there's
/// nothing to guess.
async fn sign_in(
    app: &App,
    device: &mut Device,
    f: &HashMap<String, String>,
    req: &SignInReq<'_>,
) -> Result<SignIn, OAuthError> {
    let passwordless = f.get("step").map(String::as_str) == Some("passkey");
    let r = sign_in_inner(app, device, f, req).await;
    let result = match &r {
        Ok(SignIn::Ok(_)) => "success",
        Ok(SignIn::NeedFactor(..)) => "second_factor_required",
        Ok(SignIn::NeedFactorErr(..)) | Ok(SignIn::Failed(_, LoginError::BadCode | LoginError::TooManyCodes)) => {
            "second_factor_failed"
        }
        Ok(SignIn::Failed(_, LoginError::RateLimited)) => "rate_limited",
        Ok(SignIn::Failed(_, LoginError::Inactive)) => "inactive",
        Ok(SignIn::Failed(_, LoginError::Invalid | LoginError::Timeout | LoginError::Passkey)) => "failed",
        Err(_) => "error",
    };
    crate::metrics::login(if passwordless { "passkey" } else { "oauth" }, result);
    r
}

/// Where a sign-in form post came from, for the sign-in log and the
/// passkey challenge's binding.
struct SignInReq<'a> {
    ip: Option<std::net::IpAddr>,
    user_agent: Option<&'a str>,
    /// None: `/oauth/account`.
    client_id: Option<&'a str>,
    /// The OAuth request id, or "account".
    flow_key: &'a str,
}

/// A passkey challenge can only finish the flow, in the browser, (and for
/// the second factor, the account) it was minted for.
fn passkey_binding(device_id: &str, flow_key: &str, did: Option<&str>) -> String {
    match did {
        Some(d) => format!("{device_id}\0{flow_key}\0{d}"),
        None => format!("{device_id}\0{flow_key}"),
    }
}

/// The assertion the page's script posted.
fn posted_assertion(f: &HashMap<String, String>) -> Option<super::passkeys::AssertionIn> {
    let g = |k: &str| f.get(k).map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
    Some(super::passkeys::AssertionIn {
        id: g("passkey_id")?,
        client_data_json: g("client_data")?,
        authenticator_data: g("auth_data")?,
        signature: g("signature")?,
        user_handle: g("user_handle"),
    })
}

/// For the console's list of failed sign-ins.
async fn sign_in_failed(
    app: &App,
    req: &SignInReq<'_>,
    who: super::signin::FailedFor<'_>,
    reason: super::signin::FailReason,
) {
    let ctx = super::signin::Ctx { ip: req.ip, user_agent: req.user_agent, device_id: None };
    super::signin::failed(app, who, "oauth", reason, &ctx).await;
}

async fn sign_in_inner(
    app: &App,
    device: &mut Device,
    f: &HashMap<String, String>,
    req: &SignInReq<'_>,
) -> Result<SignIn, OAuthError> {
    use crate::ratelimit as rl;
    let now = now_secs();
    let code = f.get("code").map(|c| c.trim()).filter(|c| !c.is_empty());
    let ident = f.get("identifier").map(|s| s.trim().trim_start_matches('@').to_lowercase()).unwrap_or_default();
    let limited = |ident: String| Ok(SignIn::Failed(ident, LoginError::RateLimited));
    use super::signin::{FailReason as R, FailedFor as For};
    if rl::check_ip(&[&rl::GLOBAL_IP, &rl::OAUTH_SIGN_IN_IP], 1).is_err() {
        return limited(ident);
    }
    if f.get("step").map(String::as_str) == Some("passkey") {
        return passwordless_sign_in(app, device, f, req).await;
    }
    let password_step = f.get("step").map(String::as_str) != Some("2fa");
    let (acct, ident, epoch) = if !password_step {
        // password already verified for the pending account
        let Some((did, _)) = device.pending_2fa.clone().filter(|(_, at)| now - at < PENDING_2FA_TTL) else {
            return Ok(SignIn::Failed(String::new(), LoginError::Timeout));
        };
        if rl::check_with_ip(&[&rl::CREATE_SESSION_DAY, &rl::CREATE_SESSION_5MIN], &did, 1).is_err()
            || rl::check(&[&rl::SIGN_IN_ACCOUNT], &did, 1).is_err()
        {
            sign_in_failed(app, req, For::Did(&did), R::RateLimited).await;
            return limited(String::new());
        }
        (account_any(app, &did).await?, String::new(), device.pending_2fa_epoch.clone())
    } else {
        let invalid = || Ok(SignIn::Failed(ident.clone(), LoginError::Invalid));
        let password = f.get("password").cloned().unwrap_or_default();
        if ident.is_empty() || password.is_empty() {
            return invalid();
        }
        // createSession's buckets (shared with it), before any Argon2 work
        if rl::check_with_ip(&[&rl::CREATE_SESSION_DAY, &rl::CREATE_SESSION_5MIN], &ident, 1).is_err() {
            sign_in_failed(app, req, For::Identifier(&ident), R::RateLimited).await;
            return limited(ident);
        }
        let Some(did) = resolve_identifier(app, &ident).await else {
            return invalid();
        };
        if rl::check(&[&rl::SIGN_IN_ACCOUNT], &did, 1).is_err() {
            sign_in_failed(app, req, For::Did(&did), R::RateLimited).await;
            return limited(ident);
        }
        let Ok(acct) = account_any(app, &did).await else {
            return invalid();
        };
        if ident.contains('@') && acct.email.as_deref() != Some(ident.as_str()) {
            return invalid();
        }
        // 503 rather than queue behind a login flood
        match state::try_verify_password_hash(&acct.password_hash, &password).await {
            Ok(true) => {}
            Ok(false) => {
                sign_in_failed(app, req, For::Did(&acct.did), R::WrongPassword).await;
                return invalid();
            }
            Err(busy) => {
                crate::metrics::ARGON2_SHED.inc();
                return Err(unavailable(&busy.to_string()));
            }
        }
        if acct.status.is_some() {
            return Ok(SignIn::Failed(ident, LoginError::Inactive));
        }
        // a password change since the check above fails it
        let Some(epoch) = crate::xrpc::epoch_for_login(app, &acct).await? else {
            return invalid();
        };
        (acct, ident, epoch)
    };
    let has_passkeys = super::passkeys::has_any(app, &acct.did).await?;
    // a trusted browser skips every factor, whichever are set up
    let trusted = password_step && super::signin::trusted(app, &acct, &epoch, &device.id).await?;
    let mut auth_cred = None;
    let checked = match (trusted, posted_assertion(f).filter(|_| !password_step)) {
        (true, _) => Ok(()),
        (false, Some(a)) => {
            let ex = super::passkeys::Expect {
                purpose: "2fa",
                binding: passkey_binding(&device.id, req.flow_key, Some(&acct.did)),
                require_uv: false,
            };
            match super::passkeys::use_passkey(app, &acct.did, &a, &ex).await {
                Ok(used) => {
                    auth_cred = Some(used.cred.auth_ref());
                    Ok(())
                }
                Err(super::passkeys::UseErr::Server(e)) => return Err(e.into()),
                Err(super::passkeys::UseErr::Refused(_)) => {
                    sign_in_failed(app, req, For::Did(&acct.did), R::WrongCode).await;
                    device.pending_2fa_failures += 1;
                    if device.pending_2fa_failures >= PENDING_2FA_MAX_FAILURES {
                        device.pending_2fa = None;
                        device.pending_2fa_failures = 0;
                        store::put_device(app, device).await?;
                        return Ok(SignIn::Failed(ident, LoginError::Passkey));
                    }
                    store::put_device(app, device).await?;
                    let p = Pending::of(app, &acct, &super::email2fa::Factor::Passkey).await?;
                    return Ok(SignIn::NeedFactorErr(p, LoginError::Passkey));
                }
            }
        }
        // TOTP, a recovery code with passkeys, else the email factor (which
        // mails the code on the password step)
        (false, None) => super::email2fa::check_second_factor(app, &acct, code, false, has_passkeys).await,
    };
    match checked {
        Ok(()) => {}
        Err(fe) if fe.err.error == "AuthFactorTokenRequired" => {
            device.pending_2fa = Some((acct.did.clone(), now));
            device.pending_2fa_epoch = epoch;
            device.pending_2fa_failures = 0;
            store::put_device(app, device).await?;
            return Ok(SignIn::NeedFactor(Pending::of(app, &acct, &fe.factor).await?));
        }
        Err(fe) if fe.err.status.is_server_error() => return Err(fe.err.into()),
        // no code could be mailed: not a wrong code
        Err(fe) if super::server::is_mail_limited(&fe.err) => {
            sign_in_failed(app, req, For::Did(&acct.did), R::RateLimited).await;
            return Ok(SignIn::Failed(ident, LoginError::RateLimited));
        }
        Err(fe) => {
            let e = fe.err;
            let locked = crate::totp::is_lockout(&e);
            sign_in_failed(app, req, For::Did(&acct.did), if locked { R::FactorLocked } else { R::WrongCode }).await;
            // a password step starts a new pending sign-in
            if password_step {
                device.pending_2fa = Some((acct.did.clone(), now));
                device.pending_2fa_epoch = epoch;
                device.pending_2fa_failures = 0;
            }
            device.pending_2fa_failures += 1;
            if locked || device.pending_2fa_failures >= PENDING_2FA_MAX_FAILURES {
                device.pending_2fa = None;
                device.pending_2fa_failures = 0;
                store::put_device(app, device).await?;
                return Ok(SignIn::Failed(ident, LoginError::TooManyCodes));
            }
            store::put_device(app, device).await?;
            let p = Pending::of(app, &acct, &fe.factor).await?;
            return Ok(SignIn::NeedFactorErr(p, LoginError::BadCode));
        }
    }
    let factor = if trusted {
        Some("trusted")
    } else if auth_cred.is_some() {
        Some("passkey")
    } else if password_step {
        None
    } else if crate::totp::enabled_for(app, &acct).await? {
        Some("totp")
    } else if has_passkeys {
        Some("recovery")
    } else {
        Some("email")
    };
    let device_id = device.id.clone();
    let ctx = super::signin::Ctx { ip: req.ip, user_agent: req.user_agent, device_id: Some(&device_id) };
    if !password_step && matches!(f.get("trust").map(String::as_str), Some("1" | "on")) {
        if let Some(until) = super::signin::trust(app, &acct, &epoch, &device_id, &ctx).await? {
            device.trusted_until = device.trusted_until.max(until as i64);
        }
    }
    let method = super::signin::Method::OAuth(req.client_id.map(String::from));
    super::signin::record(app, &acct, method, factor, &ctx).await;
    finish_device_sign_in(app, device, acct.did, epoch, auth_cred).await
}

/// A discoverable passkey with user verification in place of the password
/// and second factor. Its user handle names the account (routing sent the
/// post to that account's owner); every failure is the same "Passkey not
/// recognized", so nothing says which accounts have passkeys.
async fn passwordless_sign_in(
    app: &App,
    device: &mut Device,
    f: &HashMap<String, String>,
    req: &SignInReq<'_>,
) -> Result<SignIn, OAuthError> {
    use crate::webauthn::Fail;
    let refused = |f: Fail| {
        super::passkeys::count_failure(f);
        Ok(SignIn::Failed(String::new(), LoginError::Passkey))
    };
    let Some(a) = posted_assertion(f) else { return refused(Fail::Malformed) };
    let Some(did) = a.user_handle.as_deref().and_then(super::passkeys::did_from_user_handle) else {
        return refused(Fail::Malformed);
    };
    // no per-account charge: anyone can name any DID here, and a passkey
    // can't be guessed; the IP buckets above bound the posts
    let Ok(acct) = account_any(app, &did).await else { return refused(Fail::UnknownCredential) };
    // read before the check: a password change or revoke-all racing this
    // sign-in either lands first or voids it
    let epoch = crate::xrpc::auth_epoch(app, &did).await?;
    let ex = super::passkeys::Expect {
        purpose: "signin",
        binding: passkey_binding(&device.id, req.flow_key, None),
        require_uv: true,
    };
    let used = match super::passkeys::use_passkey(app, &did, &a, &ex).await {
        Ok(u) => u,
        Err(super::passkeys::UseErr::Server(e)) => return Err(e.into()),
        Err(super::passkeys::UseErr::Refused(_)) => return Ok(SignIn::Failed(String::new(), LoginError::Passkey)),
    };
    if acct.status.is_some() {
        return Ok(SignIn::Failed(String::new(), LoginError::Inactive));
    }
    let device_id = device.id.clone();
    let ctx = super::signin::Ctx { ip: req.ip, user_agent: req.user_agent, device_id: Some(&device_id) };
    let method = super::signin::Method::Passkey(req.client_id.map(String::from));
    super::signin::record(app, &acct, method, Some("passkey"), &ctx).await;
    finish_device_sign_in(app, device, did, epoch, Some(used.cred.auth_ref())).await
}

/// The device's account list gains this sign-in.
async fn finish_device_sign_in(
    app: &App,
    device: &mut Device,
    did: String,
    epoch: String,
    auth_cred: Option<String>,
) -> Result<SignIn, OAuthError> {
    let now = now_secs();
    device.pending_2fa = None;
    device.pending_2fa_failures = 0;
    device.accounts.retain(|a| a.did != did);
    device.accounts.push(DeviceAccount { did: did.clone(), authenticated_at: now, auth_epoch: epoch, auth_cred });
    device.last_seen_at = now;
    store::put_device(app, device).await?;
    Ok(SignIn::Ok(did))
}

/// The passkey parts of a second-factor page.
fn passkey_ui(app: &App, binding: &str, allow: &[J]) -> Option<(String, String, String)> {
    if allow.is_empty() {
        return None;
    }
    let rp = super::passkeys::rp(app).ok()?;
    let ch = crate::webauthn::mint_challenge(&super::passkeys::challenge_key(app), "2fa", binding, now_secs() as u64);
    Some((ou::b64u(ch), rp.id, J::Array(allow.to_vec()).to_string()))
}

fn second_factor_form<'a>(p: &'a Pending, pk: &'a Option<(String, String, String)>, trust_days: u32) -> ui::Second<'a> {
    ui::Second {
        email_hint: p.email_hint.as_deref(),
        totp: p.totp,
        trust_days,
        passkey: pk.as_ref().map(|(c, r, a)| ui::PasskeyUi { challenge: c, rp_id: r, allow: a }),
        flagged: p.flagged,
    }
}

fn code_page(app: &App, flow: &Flow, p: &Pending, error: Option<LoginError>) -> Response {
    let csrf = flow.csrf(app);
    let name = server_name(app);
    let msg = error.map(|e| match (e, &p.email_hint) {
        (LoginError::BadCode, Some(_)) => "Invalid sign-in code",
        _ => e.message(),
    });
    let pk = passkey_ui(app, &passkey_binding(&flow.device.id, &flow.id, Some(&p.did)), &p.passkeys);
    let body = ui::login(
        Some(&flow.ctx(&csrf, &name)),
        &ui::LoginForm {
            action: "/oauth/authorize/sign-in",
            identifier: &p.handle,
            error: msg,
            second: Some(second_factor_form(p, &pk, super::signin::trust_days(app))),
            passkey: None,
        },
        "",
    );
    let mut r = flow.page(app, body);
    set_passkey_csp(&mut r, &flow.form_action());
    if error.is_some() {
        *r.status_mut() = StatusCode::UNAUTHORIZED;
    }
    r
}

/// The sign-in pages run one fixed script, allowed by its hash.
fn set_passkey_csp(r: &mut Response, form_action: &[String]) {
    r.headers_mut()
        .insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_str(&ui::csp_passkey(form_action)).unwrap());
}

async fn authorize_sign_in(
    State(app): AppState,
    super::moderation::ClientIp(ip): super::moderation::ClientIp,
    headers: HeaderMap,
    body: AxBytes,
) -> Response {
    let (mut flow, f) = match form_flow(&app, &headers, &body).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    if f.get("action").map(String::as_str) == Some("deny") {
        let _ = store::put_request(&app, &flow.id, None).await;
        return redirect_error(&app, &flow.req.params, "access_denied", "Access denied");
    }
    let client_id = flow.client.id.clone();
    let flow_key = flow.id.clone();
    let req = SignInReq {
        ip,
        user_agent: super::signin::user_agent(&headers),
        client_id: Some(&client_id),
        flow_key: &flow_key,
    };
    match sign_in(&app, &mut flow.device, &f, &req).await {
        Ok(SignIn::Ok(did)) => consent_step(&app, flow, &did).await,
        Ok(SignIn::NeedFactor(p)) => code_page(&app, &flow, &p, None),
        Ok(SignIn::NeedFactorErr(p, e)) => code_page(&app, &flow, &p, Some(e)),
        Ok(SignIn::Failed(ident, e)) => login_page(&app, &flow, &ident, Some(e.message()), e.status()),
        Err(e) if e.status == StatusCode::SERVICE_UNAVAILABLE => {
            let ident = f.get("identifier").map(|s| s.trim().to_string()).unwrap_or_default();
            with_retry_after(login_page(&app, &flow, &ident, Some(BUSY_MESSAGE), e.status))
        }
        Err(e) => server_error_page(&app, "Sign-in failed", &e.description),
    }
}

/// Kept when the sign-up form is shown again after an error.
#[derive(Default)]
struct SignupValues {
    handle: String,
    /// Empty: the primary.
    domain: String,
    email: String,
    invite_code: String,
}

fn signup_page(app: &App, flow: &Flow, v: &SignupValues, error: Option<&str>, status: StatusCode) -> Response {
    let csrf = flow.csrf(app);
    let name = server_name(app);
    let domains = app.handle_domains.names();
    let domain = domains.iter().find(|d| **d == v.domain).unwrap_or(&domains[0]);
    let body = ui::signup(
        &flow.ctx(&csrf, &name),
        &ui::SignupForm {
            handle: &v.handle,
            domain,
            domains: &domains,
            email: &v.email,
            invite_code: &v.invite_code,
            invite_required: app.config.invite_required,
            error,
        },
    );
    let mut r = flow.page(app, body);
    *r.status_mut() = status;
    r
}

/// Creates the account as createAccount does (without a legacy session),
/// signs it in on this device and continues to consent.
async fn authorize_sign_up(State(app): AppState, headers: HeaderMap, body: AxBytes) -> Response {
    use crate::ratelimit as rl;
    let (mut flow, f) = match form_flow(&app, &headers, &body).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    if f.get("action").map(String::as_str) == Some("deny") {
        let _ = store::put_request(&app, &flow.id, None).await;
        return redirect_error(&app, &flow.req.params, "access_denied", "Access denied");
    }
    let field = |k: &str| f.get(k).map(|v| v.trim().to_string()).unwrap_or_default();
    let v = SignupValues {
        handle: field("handle").trim_start_matches('@').to_ascii_lowercase(),
        domain: field("domain").to_ascii_lowercase(),
        email: field("email"),
        invite_code: field("invite_code"),
    };
    if rl::check_ip(&[&rl::GLOBAL_IP, &rl::CREATE_ACCOUNT], 1).is_err() {
        let msg = "Too many sign-up attempts. Please try again later.";
        return signup_page(&app, &flow, &v, Some(msg), StatusCode::TOO_MANY_REQUESTS);
    }
    // the form asks for the first label; a full handle under a served domain is fine too
    let handle = match app.handle_domains.under(&v.handle) {
        Some(_) => v.handle.clone(),
        None => {
            let domain = app.handle_domains.served(&v.domain).filter(|d| *d == v.domain);
            format!("{}.{}", v.handle, domain.as_deref().unwrap_or(app.handle_domains.primary()))
        }
    };
    let inp = super::server::CreateAccountIn {
        handle,
        email: Some(v.email.clone()),
        password: f.get("password").cloned().filter(|p| !p.is_empty()),
        invite_code: Some(v.invite_code.clone()).filter(|c| !c.is_empty()),
        ..Default::default()
    };
    let acct = match super::server::create_account_inner(&app, inp, None).await {
        Ok(a) => a,
        Err(e) if e.status == StatusCode::SERVICE_UNAVAILABLE => {
            return with_retry_after(signup_page(&app, &flow, &v, Some(BUSY_MESSAGE), e.status))
        }
        Err(e) if e.status.is_server_error() => return server_error_page(&app, "Sign-up failed", &e.message),
        Err(e) => return signup_page(&app, &flow, &v, Some(&e.message), StatusCode::BAD_REQUEST),
    };
    let now = now_secs();
    let epoch = match crate::xrpc::auth_epoch(&app, &acct.did).await {
        Ok(e) => e,
        Err(e) => return server_error_page(&app, "Sign-up failed", &e.message),
    };
    flow.device.accounts.retain(|a| a.did != acct.did);
    flow.device.accounts.push(DeviceAccount {
        did: acct.did.clone(),
        authenticated_at: now,
        auth_epoch: epoch,
        auth_cred: None,
    });
    flow.device.last_seen_at = now;
    if let Err(e) = store::put_device(&app, &flow.device).await {
        return server_error_page(&app, "Sign-up failed", &e.description);
    }
    consent_step(&app, flow, &acct.did).await
}

async fn authorize_select(State(app): AppState, headers: HeaderMap, body: AxBytes) -> Response {
    let (flow, f) = match form_flow(&app, &headers, &body).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    let did = f.get("did").cloned().unwrap_or_default();
    if did.is_empty() {
        return login_page(&app, &flow, "", None, StatusCode::OK);
    }
    let accounts = device_accounts(&app, &flow.device).await;
    match accounts.iter().find(|(d, _)| *d == did) {
        Some(_) if flow.req.params.prompt.as_deref() != Some("login") => consent_step(&app, flow, &did).await,
        Some((_, handle)) => {
            let h = handle.clone();
            login_page(&app, &flow, &h, None, StatusCode::OK)
        }
        None => login_page(&app, &flow, "", Some("Please sign in again"), StatusCode::OK),
    }
}

async fn authorize_consent(State(app): AppState, headers: HeaderMap, body: AxBytes) -> Response {
    let (flow, f) = match form_flow(&app, &headers, &body).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    if f.get("action").map(String::as_str) != Some("allow") {
        crate::metrics::OAUTH_CONSENTS.with_label_values(&["denied"]).inc();
        let _ = store::put_request(&app, &flow.id, None).await;
        return redirect_error(&app, &flow.req.params, "access_denied", "Access denied");
    }
    let did = f.get("did").cloned().unwrap_or_default();
    let accounts = device_accounts(&app, &flow.device).await;
    if !accounts.iter().any(|(d, _)| *d == did) {
        return login_page(&app, &flow, "", Some("Please sign in again"), StatusCode::UNAUTHORIZED);
    }
    let mut flow = flow;
    match granted_scope(&flow.req.params.scope, consent_scopes(&body).as_deref()) {
        Some(scope) => {
            let narrowed =
                scope.split(' ').count() < flow.req.params.scope.split(' ').filter(|s| !s.is_empty()).count();
            crate::metrics::OAUTH_CONSENTS.with_label_values(&[if narrowed { "narrowed" } else { "full" }]).inc();
            flow.req.params.scope = scope;
        }
        None => {
            crate::metrics::OAUTH_CONSENTS.with_label_values(&["refused"]).inc();
            let _ = store::put_request(&app, &flow.id, None).await;
            return redirect_error(&app, &flow.req.params, "access_denied", "The \"atproto\" scope is required");
        }
    }
    issue_code(&app, flow, &did).await
}

/// Every `scope` field: one per ticked checkbox, or a space-separated list.
/// None when the form has none (grant as requested).
fn consent_scopes(body: &[u8]) -> Option<Vec<String>> {
    let mut out: Option<Vec<String>> = None;
    for (k, v) in ou::parse_form(std::str::from_utf8(body).unwrap_or("")) {
        if k == "scope" {
            out.get_or_insert_with(Vec::new).extend(v.split(' ').filter(|s| !s.is_empty()).map(String::from));
        }
    }
    out
}

/// The reference's `setAuthorized` scope override: the form can only remove
/// scopes, never add them. None if a required scope was removed, so a forged
/// post can't get a token without one.
fn granted_scope(requested: &str, ticked: Option<&[String]>) -> Option<String> {
    let mut granted: Vec<&str> = requested
        .split(' ')
        .filter(|s| !s.is_empty())
        .filter(|s| ticked.is_none_or(|t| t.iter().any(|x| x == s)))
        .collect();
    if !ui::REQUIRED_SCOPES.iter().all(|r| granted.contains(r)) {
        return None;
    }
    // the spec: transition:chat.bsky "depends on and does not function
    // without" transition:generic, so it goes when generic is refused
    if requested.split(' ').any(|s| s == "transition:generic") && !granted.contains(&"transition:generic") {
        granted.retain(|s| *s != "transition:chat.bsky");
    }
    Some(granted.join(" "))
}

async fn token(
    State(app): AppState,
    super::moderation::ClientIp(ip): super::moderation::ClientIp,
    headers: HeaderMap,
    body: AxBytes,
) -> Response {
    match token_inner(&app, &headers, &body, ip.map(|i| i.to_string())).await {
        Ok(j) => as_json(&app, StatusCode::OK, j),
        Err(e) => as_error(&app, e),
    }
}

async fn token_inner(app: &Arc<App>, headers: &HeaderMap, body: &[u8], ip: Option<String>) -> Result<J, OAuthError> {
    let p = parse_params(headers, body)?;
    let proof = check_as_dpop(app, headers, "/oauth/token").await?;
    let creds = ClientCredentials::from_params(&p)?;
    let client = client::get_client(&creds.client_id, app.config.dev_mode, &app.public_url).await?;
    let (client_auth, assertion) = client.authenticate(&creds, &issuer(app))?;
    if let Some(r) = &assertion {
        claim(app, r, OAuthError::invalid_client("client assertion replayed")).await?;
    }
    let grant_type = p.get("grant_type").map(String::as_str).unwrap_or("");
    if !client.grant_types.iter().any(|g| g == grant_type)
        && matches!(grant_type, "authorization_code" | "refresh_token")
    {
        return Err(OAuthError::unauthorized_client(&format!(
            "This client is not allowed to use the \"{grant_type}\" grant type"
        )));
    }
    match grant_type {
        "authorization_code" => code_grant(app, &client, client_auth, &p, &proof, ip).await,
        "refresh_token" => refresh_grant(app, &client, client_auth, &p, &proof, ip).await,
        "" => Err(OAuthError::invalid_request("Missing \"grant_type\"")),
        g => Err(OAuthError::unsupported_grant_type(&format!("Unsupported grant_type \"{g}\""))),
    }
}

fn code_matches(req: &RequestData, code: &str) -> bool {
    req.code_hash.as_deref().is_some_and(|h| crate::auth::ct_eq(h.as_bytes(), store::hash_secret(code).as_bytes()))
}

fn verify_pkce(verifier: &str, challenge: &str) -> bool {
    let ok_chars = verifier.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b));
    (43..=128).contains(&verifier.len())
        && ok_chars
        && crate::auth::ct_eq(ou::sha256_b64u(verifier).as_bytes(), challenge.as_bytes())
}

async fn code_grant(
    app: &Arc<App>,
    client: &Client,
    client_auth: ClientAuth,
    p: &HashMap<String, String>,
    proof: &DpopProof,
    ip: Option<String>,
) -> Result<J, OAuthError> {
    let code =
        p.get("code").filter(|c| !c.is_empty()).ok_or_else(|| OAuthError::invalid_request("Missing \"code\""))?;
    let rid = store::code_request_id(code).ok_or_else(|| OAuthError::invalid_grant("Invalid code"))?;
    require_owner(app, &store::req_routing(&rid))?;
    let _g = store::lock(app, &format!("req:{rid}")).await;
    let mut req = store::get_request(app, &rid).await?.ok_or_else(|| OAuthError::invalid_grant("Invalid code"))?;
    if !code_matches(&req, code) {
        return Err(OAuthError::invalid_grant("Invalid code"));
    }
    if let Some((did, sid)) = &req.consumed {
        // code reuse: revoke what the first use issued
        store::delete_session(app, did, sid).await?;
        return Err(OAuthError::invalid_grant("Code replayed"));
    }
    let did = req.did.clone().ok_or_else(|| OAuthError::invalid_grant("Invalid code"))?;
    let params = req.params.clone();
    let fail = |m: &str| OAuthError::invalid_grant(m);
    if req.expires_at < now_secs() {
        store::put_request(app, &rid, None).await?;
        return Err(fail("This code has expired"));
    }
    if req.client_id != client.id {
        return Err(fail("The code was not issued to this client"));
    }
    if req.client_auth != client_auth {
        return Err(fail("Client authentication mismatch"));
    }
    if p.get("redirect_uri").map(String::as_str) != Some(params.redirect_uri.as_str()) {
        return Err(fail("Invalid redirect_uri"));
    }
    let verifier = p.get("code_verifier").ok_or_else(|| OAuthError::invalid_grant("Missing code_verifier"))?;
    if !verify_pkce(verifier, &params.code_challenge) {
        return Err(fail("Invalid code_verifier"));
    }
    if proof.jkt != params.dpop_jkt {
        return Err(OAuthError::invalid_dpop_proof("DPoP proof does not match the expected JKT"));
    }
    ensure_active_any(app, &did).await.map_err(|e| OAuthError::invalid_grant(&e.message))?;
    if !super::passkeys::still_registered(app, &did, req.auth_cred.as_deref()).await? {
        return Err(fail("The passkey that approved this code was removed"));
    }
    let token_scope = lexicon::build_token_scope_cached(app, &params.scope, &did, req.space_collections.as_ref())
        .await
        .map_err(|e| OAuthError::invalid_request(&e.to_string()))?;
    let now = now_secs();
    let mut s = Session {
        id: ou::random_id("ses-", 16),
        did: did.clone(),
        client_id: client.id.clone(),
        client_auth,
        dpop_jkt: params.dpop_jkt.clone(),
        scope: params.scope.clone(),
        token_scope,
        created_at: now,
        updated_at: now,
        expires_at: 0,
        token_id: String::new(),
        refresh_gen: 0,
        refresh_salt: ou::random_id("", 16),
        device_id: req.device_id.clone(),
        request_id: Some(rid.clone()),
        auth_cred: req.auth_cred.clone(),
        space_collections: req.space_collections.clone(),
        created_ip: ip.clone(),
        ip,
    };
    req.consumed = Some((did.clone(), s.id.clone()));
    store::put_request(app, &rid, Some(&req)).await?;
    super::cas::pause_point("oauth_code", &did).await;
    // a password change or takedown since the approval voids the code
    let guard = store::SessionGuard::New { auth_epoch: req.auth_epoch.clone() };
    let out = issue_tokens(app, client, &mut s, guard).await?;
    // a removal writes the passkeys row before it looks for sessions, so a
    // session it missed (made after its scan) sees the passkey gone here
    if !super::passkeys::still_registered(app, &did, req.auth_cred.as_deref()).await? {
        store::delete_session(app, &did, &s.id).await?;
        return Err(fail("The passkey that approved this code was removed"));
    }
    Ok(out)
}

/// A session revoked meanwhile is not brought back (`guard`).
async fn issue_tokens(
    app: &App,
    client: &Client,
    s: &mut Session,
    guard: store::SessionGuard,
) -> Result<J, OAuthError> {
    let now = now_secs();
    let lifetime = ACCESS_TOKEN_TTL.min(s.created_at + client.session_lifetime() - now);
    if lifetime <= 1 {
        store::delete_session(app, &s.did, &s.id).await?;
        return Err(OAuthError::invalid_grant("Session expired"));
    }
    s.token_id = ou::random_id("tok-", 16);
    s.updated_at = now;
    s.expires_at = now + lifetime;
    let claims = json!({
        "iss": issuer(app),
        "aud": app.jwt.service_did,
        "sub": s.did,
        "iat": now,
        "exp": s.expires_at,
        "jti": s.token_id,
        "scope": s.token_scope,
        "client_id": s.client_id,
        "cnf": {"jkt": s.dpop_jkt},
        "sid": s.id,
    });
    // signed and verified (src/crypto.rs) before the session row names the
    // new token: a signature fault (503) never stores a token id that no
    // client received
    let access = keys(app).server.sign("at+jwt", &claims).map_err(|e| unavailable(&e.to_string()))?;
    if !store::put_session_if(app, s, guard).await? {
        return Err(OAuthError::invalid_grant("The session was revoked"));
    }
    let mut out = json!({
        "access_token": access,
        "token_type": "DPoP",
        "expires_in": lifetime,
        "scope": s.token_scope,
        "sub": s.did,
    });
    if client.grant_types.iter().any(|g| g == "refresh_token") {
        out["refresh_token"] = J::String(store::refresh_token(&keys(app).refresh, s));
    }
    Ok(out)
}

async fn refresh_grant(
    app: &Arc<App>,
    client: &Client,
    client_auth: ClientAuth,
    p: &HashMap<String, String>,
    proof: &DpopProof,
    ip: Option<String>,
) -> Result<J, OAuthError> {
    let tok = p
        .get("refresh_token")
        .filter(|t| !t.is_empty())
        .ok_or_else(|| OAuthError::invalid_request("Missing \"refresh_token\""))?;
    let invalid = || OAuthError::invalid_grant("Invalid refresh token");
    let parsed = store::parse_refresh_token(tok).ok_or_else(invalid)?;
    require_owner(app, &parsed.did)?;
    let _g = store::lock(app, &format!("ses:{}", parsed.session_id)).await;
    let (mut s, raw) = store::get_session_raw(app, &parsed.did, &parsed.session_id).await?.ok_or_else(invalid)?;
    let k = keys(app);
    if !parsed.authentic(&k.refresh, &s) || parsed.generation > s.refresh_gen {
        return Err(invalid());
    }
    if parsed.generation < s.refresh_gen {
        // a rotated-out token presented again: assume theft
        store::delete_session(app, &s.did, &s.id).await?;
        return Err(OAuthError::invalid_grant("Refresh token replayed"));
    }
    if s.client_id != client.id {
        return Err(OAuthError::invalid_grant("Refresh token was issued to another client"));
    }
    if !client.has_key(&s.client_auth) {
        store::delete_session(app, &s.did, &s.id).await?;
        return Err(OAuthError::invalid_grant("Client authentication key no longer available"));
    }
    if s.client_auth != client_auth {
        return Err(OAuthError::invalid_grant("Client authentication mismatch"));
    }
    if proof.jkt != s.dpop_jkt {
        return Err(OAuthError::invalid_dpop_proof("DPoP proof does not match the expected JKT"));
    }
    let now = now_secs();
    if now - s.created_at > client.session_lifetime() {
        store::delete_session(app, &s.did, &s.id).await?;
        return Err(OAuthError::invalid_grant("Session expired"));
    }
    if now - s.updated_at > client.refresh_lifetime() {
        store::delete_session(app, &s.did, &s.id).await?;
        return Err(OAuthError::invalid_grant("Refresh token expired"));
    }
    ensure_active_any(app, &s.did).await.map_err(|e| OAuthError::invalid_grant(&e.message))?;
    s.token_scope = match lexicon::build_token_scope_cached(app, &s.scope, &s.did, s.space_collections.as_ref()).await {
        Ok(t) => t,
        Err(lexicon::TokenScopeError::Lookup(m)) => return Err(OAuthError::server_error(&m)),
        // retrying can't help, and a client only re-authenticates on invalid_grant
        Err(lexicon::TokenScopeError::NotApproved(m)) => {
            store::delete_session(app, &s.did, &s.id).await?;
            return Err(OAuthError::invalid_grant(&m));
        }
    };
    s.refresh_gen += 1;
    super::cas::pause_point("oauth_refresh", &s.did).await;
    // only if the row is still the one read: a revocation since is not undone
    if ip.is_some() {
        s.ip = ip;
    }
    issue_tokens(app, client, &mut s, store::SessionGuard::Row(raw)).await
}

/// RFC 7009.
async fn revoke(State(app): AppState, headers: HeaderMap, body: AxBytes) -> Response {
    match revoke_inner(&app, &headers, &body).await {
        Ok(()) => as_json(&app, StatusCode::OK, json!({})),
        Err(e) => as_error(&app, e),
    }
}

async fn revoke_inner(app: &App, headers: &HeaderMap, body: &[u8]) -> Result<(), OAuthError> {
    let p = parse_params(headers, body)?;
    let tok =
        p.get("token").filter(|t| !t.is_empty()).ok_or_else(|| OAuthError::invalid_request("Missing \"token\""))?;
    let creds = ClientCredentials::from_params(&p)?;
    let client = client::get_client(&creds.client_id, app.config.dev_mode, &app.public_url).await?;
    if let (_, Some(r)) = client.authenticate(&creds, &issuer(app))? {
        claim(app, &r, OAuthError::invalid_client("client assertion replayed")).await?;
    }
    let k = keys(app);
    // invalid or unknown tokens are not an error (RFC 7009 §2.2)
    if let Some(r) = store::parse_refresh_token(tok) {
        if let Some(s) = store::get_session(app, &r.did, &r.session_id).await? {
            if r.authentic(&k.refresh, &s) && s.client_id == client.id {
                store::delete_session(app, &s.did, &s.id).await?;
            }
        }
    } else if let Ok(jwt) = k.server.verify(tok, "at+jwt") {
        if let (Some(did), Some(sid)) = (jwt.claim_str("sub"), jwt.claim_str("sid")) {
            if let Some(s) = store::get_session(app, did, sid).await? {
                if s.client_id == client.id {
                    store::delete_session(app, did, sid).await?;
                }
            }
        }
    } else if let Some(rid) = store::code_request_id(tok) {
        require_owner(app, &store::req_routing(&rid))?;
        let _g = store::lock(app, &format!("req:{rid}")).await;
        if let Some(req) = store::get_request(app, &rid).await? {
            if code_matches(&req, tok) && req.client_id == client.id {
                if let Some((did, sid)) = &req.consumed {
                    store::delete_session(app, did, sid).await?;
                }
                store::put_request(app, &rid, None).await?;
            }
        }
    }
    Ok(())
}

#[derive(Default)]
struct DpopCtx {
    /// XrpcError can't carry headers.
    challenge: Option<String>,
}

tokio::task_local! {
    /// Shared with the response layer.
    static DPOP_CTX: RefCell<DpopCtx>;
}

fn dpop_fail(error: &str, desc: &str) -> XrpcError {
    let challenge = format!("DPoP algs=\"ES256\", error=\"{error}\", error_description=\"{}\"", desc.replace('"', "'"));
    let _ = DPOP_CTX.try_with(|c| c.borrow_mut().challenge = Some(challenge));
    XrpcError { status: StatusCode::UNAUTHORIZED, error: error.into(), message: desc.into() }
}

/// Adds a fresh `DPoP-Nonce` (RFC 9449 §8.2/§9) and, when verification
/// failed, the `WWW-Authenticate` challenge. [`with_dpop_layer`] clones the
/// app only for DPoP requests, not once per request.
async fn dpop_layer(app: Option<Arc<App>>, req: axum::extract::Request, next: axum::middleware::Next) -> Response {
    let Some(app) = app else {
        return next.run(req).await;
    };
    DPOP_CTX
        .scope(RefCell::new(DpopCtx::default()), async move {
            let mut r = next.run(req).await;
            let challenge = DPOP_CTX.with(|c| c.borrow_mut().challenge.take());
            let h = r.headers_mut();
            if let Ok(v) = HeaderValue::from_str(&keys(&app).nonces.next()) {
                h.insert(HeaderName::from_static("dpop-nonce"), v);
            }
            let mut expose = "DPoP-Nonce".to_string();
            if let Some(c) = challenge.filter(|_| r.status() == StatusCode::UNAUTHORIZED) {
                if let Ok(v) = HeaderValue::from_str(&c) {
                    r.headers_mut().insert(header::WWW_AUTHENTICATE, v);
                    expose.push_str(", WWW-Authenticate");
                }
            }
            if let Ok(v) = HeaderValue::from_str(&expose) {
                r.headers_mut().append(header::ACCESS_CONTROL_EXPOSE_HEADERS, v);
            }
            r
        })
        .await
}

pub fn with_dpop_layer(r: axum::Router<Arc<App>>, app: &Arc<App>) -> axum::Router<Arc<App>> {
    let app = app.clone();
    r.layer(axum::middleware::from_fn(move |req: axum::extract::Request, next: axum::middleware::Next| {
        let is_dpop = req.headers().get(header::AUTHORIZATION).is_some_and(|v| v.as_bytes().starts_with(b"DPoP "));
        dpop_layer(is_dpop.then(|| app.clone()), req, next)
    }))
}

/// The DID of a validly signed access token, nothing else checked.
pub fn access_token_sub(app: &App, token: &str) -> Option<String> {
    let jwt = super::authn::verify_access_token(&keys(app).server, token).ok()?;
    jwt.claim_str("sub").map(String::from)
}

/// 503 for a resend whose DPoP proof another request claimed (never
/// resent: not [`crate::forward::REPO_LOADING`] / `SHARD_MOVED`).
pub const RESEND_REFUSED: &str = "ResendRefused";

pub async fn verify_dpop(app: &App, token: &str, parts: &Parts) -> XResult<Credentials> {
    let k = keys(app);
    let jwt = super::authn::verify_access_token(&k.server, token).map_err(|e| dpop_fail("invalid_token", &e))?;
    let now = now_secs();
    let claims_ok = jwt.claim_str("iss") == Some(issuer(app).as_str())
        && jwt.claim_str("aud") == Some(app.jwt.service_did.as_str());
    if !claims_ok {
        return Err(dpop_fail("invalid_token", "Invalid token audience or issuer"));
    }
    if jwt.claim_i64("exp").is_none_or(|e| e <= now) {
        return Err(dpop_fail("invalid_token", "Token expired"));
    }
    let (Some(did), Some(sid), Some(jti), Some(client_id)) =
        (jwt.claim_str("sub"), jwt.claim_str("sid"), jwt.claim_str("jti"), jwt.claim_str("client_id"))
    else {
        return Err(dpop_fail("invalid_token", "Malformed token"));
    };
    let jkt = jwt
        .payload
        .get("cnf")
        .and_then(|c| c.get("jkt"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| dpop_fail("invalid_token", "Token is not DPoP-bound"))?;
    let proof = dpop_header(&parts.headers)
        .map_err(|e| dpop_fail("invalid_dpop_proof", &e))?
        .ok_or_else(|| dpop_fail("invalid_dpop_proof", "DPoP proof required"))?;
    let htu = jose::normalize_htu(&format!("{}{}", issuer(app), parts.uri.path()))
        .ok_or_else(|| XrpcError::internal("bad public_url"))?;
    let checked =
        jose::check_proof(&proof, parts.method.as_str(), &htu, Some(token), &k.nonces).map_err(|e| match e {
            DpopError::UseNonce(m) => dpop_fail("use_dpop_nonce", &m),
            DpopError::Invalid(m) => dpop_fail("invalid_dpop_proof", &m),
        })?;
    if checked.jkt != jkt {
        return Err(dpop_fail("invalid_token", "Access token is bound to another DPoP key"));
    }
    // claimed at the token DID's owner (normally this node: the request was
    // routed by that DID), in memory only (crate::oauth: residual risk); for
    // the client request, so the entry node's resends of it pass
    let replay = checked.replay(did.to_string());
    let resend = parts.extensions.get::<crate::forward::Resend>().copied();
    let holder = resend.map_or(0, |r| r.id);
    match super::internal::claim_proof_anywhere(app, &replay.routing, &replay.key, replay.until, holder).await {
        Ok(true) => {}
        // someone else's request took the proof between our attempts: ours
        // did nothing, but a resend never ends in a definite refusal
        Ok(false) if resend.is_some_and(|r| r.attempt > 0) => {
            return Err(XrpcError::unavailable(
                RESEND_REFUSED,
                "the DPoP proof was used by another request while this one was being resent; retry with a new proof",
            ))
        }
        Ok(false) => return Err(dpop_fail("invalid_dpop_proof", "DPoP proof replayed")),
        Err(e) => return Err(e),
    }
    // rotation and revocation take effect immediately; a takedown is
    // checked too, in case its session revocation was missed
    let (s, acct) = tokio::join!(store::get_session(app, did, sid), account_any(app, did));
    let s = s.map_err(|e| XrpcError::internal(e.description))?;
    if acct.is_ok_and(|a| super::server::is_takendown_account(&a)) {
        return Err(super::takedown_error());
    }
    match s {
        Some(s) if s.token_id == jti && s.client_id == client_id => {}
        _ => return Err(dpop_fail("invalid_token", "Token has been revoked")),
    }
    let scopes = ScopeSet::new(jwt.claim_str("scope").unwrap_or(""));
    if !scopes.has("atproto") {
        return Err(dpop_fail("invalid_token", "OAuth token does not have \"atproto\" scope"));
    }
    Ok(Credentials::OAuth { did: did.to_string(), client_id: client_id.to_string(), scopes })
}

fn redirect_to(path: &str) -> Response {
    let mut r = StatusCode::SEE_OTHER.into_response();
    r.headers_mut().insert(header::LOCATION, HeaderValue::from_str(path).unwrap());
    r
}

fn rfc3339(secs: i64) -> String {
    chrono::DateTime::from_timestamp(secs, 0)
        .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
        .unwrap_or_default()
}

fn fmt_time(secs: i64) -> String {
    chrono::DateTime::from_timestamp(secs, 0).map(|t| t.format("%Y-%m-%d %H:%M UTC").to_string()).unwrap_or_default()
}

async fn account_page(State(app): AppState, headers: HeaderMap, Query(q): Query<HashMap<String, String>>) -> Response {
    let (device, new_cookie) = match device_for(&app, &headers).await {
        Ok(d) => d,
        Err(e) => return server_error_page(&app, "Error", &e.description),
    };
    let csrf = csrf_token(&app, &device.id, "account");
    let accounts = device_accounts(&app, &device).await;
    let cookie = new_cookie.then_some(&device);
    if accounts.is_empty() || q.contains_key("add") {
        // never echo the query text
        let error = q.get("error").and_then(|c| LoginError::from_code(c)).map(LoginError::message);
        let pending_did = device
            .pending_2fa
            .as_ref()
            .filter(|(_, at)| now_secs() - at < PENDING_2FA_TTL && q.contains_key("2fa"))
            .map(|(d, _)| d.clone());
        let mut pending = None;
        if let Some(did) = pending_did {
            let acct = match account_any(&app, &did).await {
                Ok(a) => a,
                Err(e) => return server_error_page(&app, "Error", &e.message),
            };
            // the address isn't put in the URL; the page says "your email"
            let factor = match q.contains_key("email") {
                true => super::email2fa::Factor::Email { hint: "your email address".into() },
                false => super::email2fa::Factor::Totp,
            };
            match Pending::of(&app, &acct, &factor).await {
                Ok(p) => pending = Some(p),
                Err(e) => return server_error_page(&app, "Error", &e.description),
            }
        }
        let pk = pending
            .as_ref()
            .and_then(|p| passkey_ui(&app, &passkey_binding(&device.id, "account", Some(&p.did)), &p.passkeys));
        let pwless =
            if pending.is_none() { passwordless_ui(&app, &passkey_binding(&device.id, "account", None)) } else { None };
        let body = ui::login(
            None,
            &ui::LoginForm {
                action: "/oauth/account/sign-in",
                identifier: pending.as_ref().map_or("", |p| p.handle.as_str()),
                error,
                second: pending.as_ref().map(|p| second_factor_form(p, &pk, super::signin::trust_days(&app))),
                passkey: pwless.as_ref().map(|(c, r)| ui::PasskeyUi { challenge: c, rp_id: r, allow: "[]" }),
            },
            &csrf,
        );
        let mut r = html(&app, StatusCode::OK, body, &[], cookie);
        set_passkey_csp(&mut r, &[]);
        return r;
    }
    let mut rows = Vec::new();
    for (did, handle) in accounts {
        let mut sessions = store::list_sessions(&app, &did).await.unwrap_or_default();
        sessions.sort_by_key(|s| -s.updated_at);
        let list = sessions
            .into_iter()
            .map(|s| ui::SessionRow {
                id: s.id,
                client_id: s.client_id,
                scope: s.scope,
                created_at: fmt_time(s.created_at),
                updated_at: fmt_time(s.updated_at),
            })
            .collect();
        rows.push((did, handle, list));
    }
    html(&app, StatusCode::OK, ui::account_page(&csrf, &rows), &[], cookie)
}

#[allow(clippy::result_large_err)]
async fn account_form(
    app: &App,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<(Device, HashMap<String, String>), Response> {
    let f = form_fields(body);
    let (device, new_cookie) =
        device_for(app, headers).await.map_err(|e| server_error_page(app, "Error", &e.description))?;
    if new_cookie || !check_csrf(app, headers, &device, "account", f.get("csrf")) {
        return Err(error_page(app, StatusCode::FORBIDDEN, "Request failed", "Invalid or missing CSRF token."));
    }
    Ok((device, f))
}

async fn account_sign_in(
    State(app): AppState,
    super::moderation::ClientIp(ip): super::moderation::ClientIp,
    headers: HeaderMap,
    body: AxBytes,
) -> Response {
    let (mut device, f) = match account_form(&app, &headers, &body).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    let req = SignInReq { ip, user_agent: super::signin::user_agent(&headers), client_id: None, flow_key: "account" };
    match sign_in(&app, &mut device, &f, &req).await {
        Ok(SignIn::Ok(_)) => redirect_to("/oauth/account"),
        Ok(SignIn::NeedFactor(p)) => {
            redirect_to(&format!("/oauth/account?add=1&2fa=1{}", if p.email_hint.is_some() { "&email=1" } else { "" }))
        }
        Ok(SignIn::NeedFactorErr(p, e)) => redirect_to(&format!(
            "/oauth/account?add=1&2fa=1{}&error={}",
            if p.email_hint.is_some() { "&email=1" } else { "" },
            e.code()
        )),
        Ok(SignIn::Failed(_, e)) => redirect_to(&format!("/oauth/account?add=1&error={}", e.code())),
        Err(e) if e.status == StatusCode::SERVICE_UNAVAILABLE => {
            with_retry_after(error_page(&app, e.status, "Sign-in failed", BUSY_MESSAGE))
        }
        Err(e) => server_error_page(&app, "Sign-in failed", &e.description),
    }
}

async fn account_sign_out(State(app): AppState, headers: HeaderMap, body: AxBytes) -> Response {
    let (mut device, f) = match account_form(&app, &headers, &body).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    let did = f.get("did").cloned().unwrap_or_default();
    device.accounts.retain(|a| a.did != did);
    if let Err(e) = store::put_device(&app, &device).await {
        return server_error_page(&app, "Error", &e.description);
    }
    redirect_to("/oauth/account")
}

async fn account_revoke(State(app): AppState, headers: HeaderMap, body: AxBytes) -> Response {
    let (device, f) = match account_form(&app, &headers, &body).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    let did = f.get("did").cloned().unwrap_or_default();
    let sid = f.get("session").cloned().unwrap_or_default();
    let signed_in = device_accounts(&app, &device).await.iter().any(|(d, _)| *d == did);
    if !signed_in {
        return error_page(
            &app,
            StatusCode::FORBIDDEN,
            "Request failed",
            "You are not signed in to that account on this device.",
        );
    }
    if let Err(e) = store::delete_session(&app, &did, &sid).await {
        return server_error_page(&app, "Error", &e.description);
    }
    redirect_to("/oauth/account")
}

/// Only full account sessions (password login) may manage OAuth grants.
fn full_session(creds: &Credentials) -> XResult<String> {
    match creds {
        Credentials::Session { did } => Ok(did.clone()),
        _ => Err(XrpcError {
            status: StatusCode::FORBIDDEN,
            error: "InsufficientScope".into(),
            message: "a full account session is required".into(),
        }),
    }
}

async fn xrpc_list_sessions(State(app): AppState, Auth(creds): Auth) -> XResult<Json<J>> {
    let did = full_session(&creds)?;
    let mut sessions = store::list_sessions(&app, &did).await.map_err(|e| XrpcError::internal(e.description))?;
    sessions.sort_by_key(|s| -s.updated_at);
    let out: Vec<J> = sessions
        .iter()
        .map(|s| {
            json!({
                "id": s.id,
                "clientId": s.client_id,
                "scope": s.scope,
                "createdAt": rfc3339(s.created_at),
                "updatedAt": rfc3339(s.updated_at),
                "accessExpiresAt": rfc3339(s.expires_at),
            })
        })
        .collect();
    Ok(Json(json!({"sessions": out})))
}

#[derive(Deserialize)]
struct RevokeSessionIn {
    id: String,
}

async fn xrpc_revoke_session(
    State(app): AppState,
    Auth(creds): Auth,
    Json(inp): Json<RevokeSessionIn>,
) -> XResult<Json<J>> {
    let did = full_session(&creds)?;
    if store::get_session(&app, &did, &inp.id).await.map_err(|e| XrpcError::internal(e.description))?.is_none() {
        return Err(XrpcError::bad("SessionNotFound", "no such OAuth session"));
    }
    store::delete_session(&app, &did, &inp.id).await.map_err(|e| XrpcError::internal(e.description))?;
    Ok(Json(json!({})))
}
