//! Third-party sign-in (docs/federated-sign-in.html): the operator's
//! provider API, the account's linked identities, their cluster-wide
//! claims, and the browser flow (start, callback, link, unlink) that ends in
//! the OAuth pages' ordinary device sign-in.
//!
//! Storage:
//! - `{prefix}/fedid/{hex sha256(iss \0 sub)}`: the DID the identity
//!   belongs to, a conditional create like handle and email claims.
//! - `p/{did}\0fedid` ([`Identities`]): the account's identities, written
//!   only by conditional writes. The row is what counts; a claim without it
//!   is stale once old enough.
//! - `p/oauth:fed:{state}\0oauth/fed` ([`FedState`]): one flow, bound to
//!   the browser's device cookie, deleted by the callback that uses it.
//!
//! Nothing here is offered or written below feature level 2.

use super::cas::{Cond, Op};
use super::*;
use crate::federated::config::{self as cfg, AuthMethod, Provider, SaveError, SecretRef, SignedSecret};
use std::collections::BTreeMap;
use vlsync_store::version;

pub(super) const ROW: &str = "fedid";
pub(super) const STATE_ROW: &str = "oauth/fed";
pub const MAX_IDENTITIES: usize = 10;
const RELOAD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);
const CAS_ROUNDS: usize = 8;

/// The node's own view of `cluster/version`: in-process test clusters at
/// different levels share the process-wide one.
pub(crate) fn level(app: &App) -> u32 {
    app.cluster.as_ref().and_then(|c| c.cluster_version()).map_or_else(version::active, |v| v.active)
}

pub(crate) fn enabled(app: &App) -> bool {
    level(app) >= version::FEDERATED_SIGN_IN_LEVEL
}

/// Providers to offer: none below level 2.
pub(crate) fn offered(app: &App) -> Vec<Provider> {
    if !enabled(app) {
        return Vec::new();
    }
    app.federated.providers.doc().providers.clone()
}

pub fn start(app: &Arc<App>) {
    cfg::spawn_refresher(&app.federated.providers, app.store.clone());
}

pub fn xrpc_routes() -> Router<Arc<App>> {
    Router::new()
        .route("/xrpc/vlpds.admin.listSignInProviders", get(list_providers))
        .route("/xrpc/vlpds.admin.putSignInProvider", post(put_provider))
        .route("/xrpc/vlpds.admin.removeSignInProvider", post(remove_provider))
        .route("/xrpc/vlpds.server.listFederatedIdentities", get(list_identities))
        .route("/xrpc/vlpds.server.describeSignInProviders", get(describe_providers))
        .route("/xrpc/vlpds.server.createFederatedSession", post(create_federated_session))
}

/// The browser flow.
pub fn routes() -> Router<Arc<App>> {
    Router::new()
        .route("/oauth/federated/start", get(start_flow))
        .route("/oauth/federated/callback/{provider}", get(callback_get).post(callback_post))
        .route("/oauth/federated/signup", post(signup_post))
}

pub fn internal_routes() -> Router<Arc<App>> {
    Router::new().route("/internal/v1/signin-providers/reload", post(internal_reload))
}

fn node_id(app: &App) -> String {
    app.cluster.as_ref().map(|c| c.cfg.node_id.clone()).unwrap_or_else(|| "single".into())
}

/// One per provider (RFC 9700 §4.4.2): the callback checks it names the
/// provider the state was made for.
pub fn callback_url(app: &App, provider: &str) -> String {
    format!("{}{}", app.public_url.trim_end_matches('/'), callback_path(provider))
}

fn callback_path(provider: &str) -> String {
    format!("/oauth/federated/callback/{provider}")
}

fn level_required(app: &App) -> XResult<()> {
    if enabled(app) {
        return Ok(());
    }
    Err(XrpcError::bad(
        "FeatureLevelRequired",
        format!(
            "third-party sign-in needs feature level {}; the cluster runs {}: finalize it first",
            version::FEDERATED_SIGN_IN_LEVEL,
            level(app)
        ),
    ))
}

// ---------------------------------------------------------------- the operator's API

fn secret_view(r: &Option<SecretRef>) -> J {
    match r {
        None => J::Null,
        Some(SecretRef::Wrapped(_)) => json!({"stored": "wrapped"}),
    }
}

/// Never the secrets themselves.
fn provider_view(app: &App, p: &Provider) -> J {
    let a = &p.client_auth;
    json!({
        "id": p.id,
        "callbackUrl": callback_url(app, &p.id),
        "name": p.name,
        "icon": p.icon,
        "issuer": p.issuer,
        "clientId": p.client_id,
        "clientAuth": {
            "method": a.method,
            "secret": secret_view(&a.secret),
            "key": secret_view(&a.key),
            "keyId": a.key_id,
            "signedSecret": a.signed_secret,
        },
        "scopes": p.scopes,
        "responseMode": p.response_mode,
        "signup": p.signup,
        "signupsPerDay": p.signups_per_day,
        "trustEmail": p.trust_email,
        "requiredClaims": p.required_claims,
        "idTokenAlgs": p.id_token_algs,
        "updatedAt": p.updated_at,
        "updatedBy": p.updated_by,
    })
}

fn level_fields(app: &App, out: &mut J) {
    let (active, required) = (level(app), version::FEDERATED_SIGN_IN_LEVEL);
    out["featureLevel"] = json!({"active": active, "required": required});
    out["available"] = json!(active >= required);
    if active < required {
        out["reason"] = json!(format!(
            "the cluster runs feature level {active}: providers can't be saved or offered until level {required} is finalized"
        ));
    }
}

async fn list_providers(State(app): AppState, Auth(creds): Auth) -> XResult<Json<J>> {
    super::admin::require_admin(&creds)?;
    let doc = app.federated.providers.doc();
    let mut out = json!({
        "providers": doc.providers.iter().map(|p| provider_view(&app, p)).collect::<Vec<_>>(),
        "version": doc.version,
        "updatedAt": doc.updated_at,
        "max": cfg::MAX_PROVIDERS,
    });
    level_fields(&app, &mut out);
    Ok(Json(out))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
enum SecretIn {
    /// Wrapped under the KEK before it is stored.
    Value(String),
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ClientAuthIn {
    method: AuthMethod,
    /// Left out: keep the stored one.
    #[serde(default)]
    secret: Option<SecretIn>,
    #[serde(default)]
    key: Option<SecretIn>,
    #[serde(default)]
    key_id: Option<String>,
    #[serde(default)]
    signed_secret: Option<SignedSecret>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProviderIn {
    id: String,
    name: String,
    #[serde(default)]
    icon: Option<String>,
    issuer: String,
    client_id: String,
    client_auth: ClientAuthIn,
    #[serde(default)]
    scopes: Option<Vec<String>>,
    #[serde(default)]
    response_mode: Option<cfg::ResponseMode>,
    #[serde(default)]
    signup: Option<cfg::Signup>,
    #[serde(default)]
    signups_per_day: Option<u32>,
    #[serde(default)]
    trust_email: Option<bool>,
    #[serde(default)]
    required_claims: Option<BTreeMap<String, String>>,
    #[serde(default)]
    id_token_algs: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PutIn {
    provider: ProviderIn,
    #[serde(default)]
    if_version: Option<u64>,
    /// Save even if the issuer's discovery document can't be fetched now.
    #[serde(default)]
    force: bool,
    #[serde(default)]
    actor: Option<String>,
}

fn save_error(e: SaveError) -> XrpcError {
    let message = e.to_string();
    match e {
        SaveError::Invalid(_) | SaveError::TooMany => XrpcError::bad("InvalidProvider", message),
        SaveError::NotFound(_) => XrpcError::bad("ProviderNotFound", message),
        SaveError::Conflict(_) => XrpcError { status: StatusCode::CONFLICT, error: "VersionMismatch".into(), message },
        SaveError::Store(_) => XrpcError { status: StatusCode::BAD_GATEWAY, error: "UpstreamFailure".into(), message },
    }
}

async fn secret_ref(app: &App, id: &str, s: SecretIn, key: bool) -> XResult<SecretRef> {
    match s {
        SecretIn::Value(v) => {
            let v = v.trim();
            if v.is_empty() || v.len() > 16 * 1024 {
                return Err(XrpcError::bad("InvalidProvider", format!("{id}: empty or oversized secret")));
            }
            if key {
                crate::federated::oidc::parse_p256_key(v.as_bytes()).map_err(|e| {
                    XrpcError::bad("InvalidProvider", format!("{id}: key is not a P-256 PKCS#8 key: {e}"))
                })?;
            }
            Ok(SecretRef::Wrapped(
                app.secrets.wrap(crate::secrets::Purpose::SignInProviderSecret, id, v.as_bytes()).await?,
            ))
        }
    }
}

async fn put_provider(
    State(app): AppState,
    Auth(creds): Auth,
    super::moderation::ClientIp(ip): super::moderation::ClientIp,
    Json(inp): Json<PutIn>,
) -> XResult<Json<J>> {
    super::admin::require_admin(&creds)?;
    level_required(&app)?;
    let p = inp.provider;
    // checked before anything is wrapped under it
    if !cfg::valid_id(&p.id) {
        return Err(XrpcError::bad(
            "InvalidProvider",
            format!("id {:?}: 1 to 32 lowercase letters, digits or hyphens", p.id),
        ));
    }
    let old = app.federated.providers.get(&p.id);
    // a stored secret is kept only for the same issuer and method
    let keep = |r: Option<SecretRef>| {
        r.filter(|_| {
            old.as_ref().is_some_and(|o| o.client_auth.method == p.client_auth.method && o.issuer == p.issuer.trim())
        })
    };
    let (old_secret, old_key) = match &old {
        Some(o) => (keep(o.client_auth.secret.clone()), keep(o.client_auth.key.clone())),
        None => (None, None),
    };
    let secret = match p.client_auth.secret {
        Some(s) => Some(secret_ref(&app, &p.id, s, false).await?),
        None if p.client_auth.signed_secret.is_none() => old_secret,
        None => None,
    };
    let key = match p.client_auth.key {
        Some(s) => Some(secret_ref(&app, &p.id, s, true).await?),
        None if p.client_auth.key_id.is_some() => old_key,
        None => None,
    };
    let who = super::moderation::Who::of(&creds, inp.actor.as_deref(), ip);
    let provider = Provider {
        id: p.id.clone(),
        name: p.name.trim().to_string(),
        icon: p.icon.filter(|i| !i.is_empty()),
        issuer: p.issuer.trim().to_string(),
        client_id: p.client_id.trim().to_string(),
        client_auth: cfg::ClientAuth {
            method: p.client_auth.method,
            secret,
            key,
            key_id: p.client_auth.key_id.filter(|k| !k.is_empty()),
            signed_secret: p.client_auth.signed_secret,
        },
        scopes: p.scopes.unwrap_or_else(|| vec!["openid".into(), "email".into()]),
        response_mode: p.response_mode.unwrap_or_default(),
        signup: p.signup.unwrap_or_default(),
        signups_per_day: p.signups_per_day.unwrap_or(cfg::DEFAULT_SIGNUPS_PER_DAY),
        trust_email: p.trust_email.unwrap_or(false),
        required_claims: p.required_claims.unwrap_or_default(),
        id_token_algs: p.id_token_algs.unwrap_or_default(),
        updated_at: Some(vlatproto::events::now_rfc3339()),
        updated_by: Some(creds.operator().unwrap_or("admin").to_string()),
    };
    if let Some(m) = cfg::invalid(&provider, app.config.dev_mode) {
        return Err(XrpcError::bad("InvalidProvider", m));
    }
    if !inp.force {
        app.federated.oidc.forget(&provider.issuer);
        if let Err(e) = app.federated.oidc.discovery(&provider, app.config.dev_mode).await {
            return Err(XrpcError::bad(
                "ProviderUnreachable",
                format!(
                    "{}: the issuer's discovery document didn't check out ({e}); pass force to save anyway",
                    provider.id
                ),
            ));
        }
    }
    let doc =
        cfg::put(&app.federated.providers, &app.store, provider.clone(), inp.if_version).await.map_err(save_error)?;
    let detail = json!({"issuer": provider.issuer, "replaced": old.is_some()});
    let subject = super::moderation::SubjectRef::other("config", format!("signin-provider:{}", provider.id));
    super::moderation::audit(&app, &who, "signin_provider.put", Some(&subject), None, None, Some(detail)).await?;
    app.changes.emit("config", "signin-providers", super::changes::now_ms());
    let nodes = nudge_peers(&app).await;
    Ok(Json(json!({"provider": provider_view(&app, &provider), "version": doc.version, "nodes": nodes})))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RemoveIn {
    id: String,
    #[serde(default)]
    if_version: Option<u64>,
    #[serde(default)]
    actor: Option<String>,
}

/// The provider's identities stay on their accounts, dormant.
async fn remove_provider(
    State(app): AppState,
    Auth(creds): Auth,
    super::moderation::ClientIp(ip): super::moderation::ClientIp,
    Json(inp): Json<RemoveIn>,
) -> XResult<Json<J>> {
    super::admin::require_admin(&creds)?;
    level_required(&app)?;
    let issuer = app.federated.providers.get(&inp.id).map(|p| p.issuer);
    let doc = cfg::remove(&app.federated.providers, &app.store, &inp.id, inp.if_version).await.map_err(save_error)?;
    if let Some(i) = &issuer {
        app.federated.oidc.forget(i);
    }
    let who = super::moderation::Who::of(&creds, inp.actor.as_deref(), ip);
    let subject = super::moderation::SubjectRef::other("config", format!("signin-provider:{}", inp.id));
    let detail = json!({"issuer": issuer});
    super::moderation::audit(&app, &who, "signin_provider.remove", Some(&subject), None, None, Some(detail)).await?;
    app.changes.emit("config", "signin-providers", super::changes::now_ms());
    let nodes = nudge_peers(&app).await;
    Ok(Json(json!({"id": inp.id, "version": doc.version, "nodes": nodes})))
}

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
                .post(format!("{}/internal/v1/signin-providers/reload", l.addr.trim_end_matches('/')))
                .header(super::internal::HDR, &app.config.internal_token)
                .timeout(RELOAD_TIMEOUT)
                .send()
                .await
                .and_then(|r| r.error_for_status());
            match r {
                Ok(_) => json!({"node": l.node_id, "ok": true}),
                Err(e) => {
                    tracing::warn!(peer = %l.node_id, "sign-in provider reload nudge failed (it re-reads on its own): {e}");
                    json!({"node": l.node_id, "ok": false, "error": e.to_string()})
                }
            }
        }
    });
    applied.extend(futures::future::join_all(sends).await);
    applied
}

async fn internal_reload(State(app): AppState, headers: HeaderMap) -> XResult<Json<J>> {
    super::internal::check(&app, &headers)?;
    cfg::refresh(&app.federated.providers, &app.store).await.map_err(|e| XrpcError {
        status: StatusCode::BAD_GATEWAY,
        error: "UpstreamFailure".into(),
        message: format!("{e:#}"),
    })?;
    Ok(Json(json!({"node": node_id(&app), "version": app.federated.providers.doc().version})))
}

fn button_view(p: &Provider) -> J {
    json!({"id": p.id, "name": p.name, "icon": p.icon})
}

/// The buttons a sign-in page shows; empty when there are none to offer.
async fn describe_providers(State(app): AppState) -> Json<J> {
    Json(json!({"providers": offered(&app).iter().map(button_view).collect::<Vec<_>>()}))
}

/// `vlpds.admin.rewrapSecrets`' share: the providers' wrapped secrets and
/// keys. (stale found or rewrapped, blobs stored afterwards, errors)
pub(super) async fn rewrap_provider_secrets(app: &App, check: bool, dry: bool) -> (u64, Vec<String>, Vec<String>) {
    use crate::secrets::Purpose;
    let (mut stale, mut kept, mut errors) = (0u64, Vec::new(), Vec::new());
    let mut fresh: Vec<(String, String, String)> = Vec::new();
    for p in &app.federated.providers.doc().providers {
        for r in [&p.client_auth.secret, &p.client_auth.key].into_iter().flatten() {
            let SecretRef::Wrapped(blob) = r;
            if !check && app.secrets.is_current(blob) {
                kept.push(blob.clone());
                continue;
            }
            let res = match dry {
                true => app
                    .secrets
                    .unwrap(Purpose::SignInProviderSecret, &p.id, blob)
                    .await
                    .map(|u| u.stale.then(String::new)),
                false => app.secrets.rewrap(Purpose::SignInProviderSecret, &p.id, blob).await,
            };
            match res {
                Ok(None) => kept.push(blob.clone()),
                Ok(Some(_)) if dry => {
                    stale += 1;
                    kept.push(blob.clone());
                }
                Ok(Some(new)) => {
                    stale += 1;
                    kept.push(new.clone());
                    fresh.push((p.id.clone(), blob.clone(), new));
                }
                Err(e) => {
                    kept.push(blob.clone());
                    errors.push(format!("sign-in provider {}: {e}", p.id));
                }
            }
        }
    }
    if !fresh.is_empty() {
        let swap = |r: &mut Option<SecretRef>, id: &str| {
            if let Some(SecretRef::Wrapped(b)) = r {
                if let Some((_, _, new)) = fresh.iter().find(|(i, old, _)| i == id && old == b) {
                    *b = new.clone();
                }
            }
        };
        let r = cfg::update(&app.federated.providers, &app.store, None, |doc| {
            for p in &mut doc.providers {
                swap(&mut p.client_auth.secret, &p.id.clone());
                swap(&mut p.client_auth.key, &p.id.clone());
            }
            Ok(())
        })
        .await;
        if let Err(e) = r {
            errors.push(format!("sign-in providers: {e}"));
        }
    }
    (stale, kept, errors)
}

// ---------------------------------------------------------------- the browser flow

/// A flow's state row and the OAuth request it continues live this long:
/// the provider's own sign-in can take longer than the page's 5 minutes.
pub const STATE_TTL: i64 = 10 * 60;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct FedState {
    pub provider: String,
    /// "sign_in" or "link".
    pub purpose: String,
    /// sign_in on the OAuth page; None: `/oauth/account`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// link: the account it's for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub did: Option<String>,
    /// The browser that started it; the only one that may finish it.
    pub device_id: String,
    pub created_at: i64,
    pub expires_at: i64,
    /// A `form_post` response, kept for the same-origin GET that checks the
    /// device.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handoff: Option<Handoff>,
    /// Started from the account page app, which gets the session.
    #[serde(default, skip_serializing_if = "is_false")]
    pub app: bool,
    /// Started from `/oauth/account`'s step-up page, which it returns to.
    #[serde(default, skip_serializing_if = "is_false")]
    pub methods: bool,
    /// A signup ticket (purpose "signup"): the identity and what the
    /// provider said about its email.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<TicketIdentity>,
}

fn is_false(b: &bool) -> bool {
    !*b
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct TicketIdentity {
    pub iss: String,
    pub sub: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub email_verified: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Handoff {
    /// SHA-256 of the one-time id in the GET's URL.
    pub id_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
}

pub(super) fn state_routing(state: &str) -> String {
    format!("oauth:fed:{state}")
}

fn valid_state(s: &str) -> bool {
    (16..=64).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Nonce and PKCE verifier are MACs of the state, so the row holds nothing
/// secret and any node recomputes them.
fn flow_secret(app: &App, what: &str, state: &str) -> String {
    let key = crate::oauth::util::derive_secret(&app.config.jwt_secret, "federated-sign-in");
    crate::oauth::util::b64u(crate::oauth::util::hmac_sha256(&key, &[what.as_bytes(), b"\0", state.as_bytes()]))
}

fn nonce(app: &App, state: &str) -> String {
    flow_secret(app, "nonce", state)
}

fn verifier(app: &App, state: &str) -> String {
    flow_secret(app, "pkce", state)
}

fn not_found() -> Response {
    StatusCode::NOT_FOUND.into_response()
}

fn page(app: &App, status: StatusCode, msg: &str) -> Response {
    super::oauth::error_page(app, status, "Sign-in failed", msg)
}

#[derive(Deserialize)]
struct StartQ {
    provider: String,
    #[serde(default)]
    request_uri: Option<String>,
    #[serde(default)]
    account: Option<String>,
    #[serde(default)]
    link: Option<String>,
    #[serde(default)]
    csrf: Option<String>,
    /// With `account`: the account page app gets the session.
    #[serde(default)]
    app: Option<String>,
    /// With `account`: only [`crate::oauth::ui::METHODS_RETURN`] means anything.
    #[serde(default, rename = "return")]
    ret: Option<String>,
}

/// `link`: the provider asks which of its accounts to use, so a link never
/// silently takes whichever account the browser is signed in to there.
fn authorize_url(app: &App, p: &Provider, d: &crate::federated::oidc::Discovery, state: &str, link: bool) -> String {
    let challenge = crate::oauth::util::sha256_b64u(verifier(app, state));
    let mut pairs = vec![
        ("response_type".to_string(), "code".to_string()),
        ("client_id".into(), p.client_id.clone()),
        ("redirect_uri".into(), callback_url(app, &p.id)),
        ("scope".into(), p.scope()),
        ("state".into(), state.into()),
        ("nonce".into(), nonce(app, state)),
        ("code_challenge".into(), challenge),
        ("code_challenge_method".into(), "S256".into()),
    ];
    if p.response_mode == cfg::ResponseMode::FormPost {
        pairs.push(("response_mode".into(), "form_post".into()));
    }
    if link {
        pairs.push(("prompt".into(), "select_account".into()));
    }
    let sep = if d.authorization_endpoint.contains('?') { '&' } else { '?' };
    format!("{}{sep}{}", d.authorization_endpoint, crate::oauth::util::form_encode(&pairs))
}

fn see_other(location: &str) -> Response {
    let mut r = StatusCode::SEE_OTHER.into_response();
    let h = r.headers_mut();
    if let Ok(v) = header::HeaderValue::from_str(location) {
        h.insert(header::LOCATION, v);
    }
    h.insert(header::CACHE_CONTROL, header::HeaderValue::from_static("no-store"));
    h.insert(header::REFERRER_POLICY, header::HeaderValue::from_static("no-referrer"));
    r
}

/// A GET link from a sign-in page or `/oauth/account`: a state row bound to
/// this browser, then off to the provider.
async fn start_flow(State(app): AppState, headers: HeaderMap, Query(q): Query<StartQ>) -> Response {
    use crate::ratelimit as rl;
    if !enabled(&app) {
        return not_found();
    }
    let Some(p) = app.federated.providers.get(&q.provider) else { return not_found() };
    if rl::check_ip(&[&rl::GLOBAL_IP, &rl::OAUTH_SIGN_IN_IP], 1).is_err() {
        return page(&app, StatusCode::TOO_MANY_REQUESTS, "Too many sign-in attempts. Please try again later.");
    }
    let (purpose, request_id, did, device, new_cookie) = if let Some(ru) = &q.request_uri {
        match super::oauth::flow_for_federated(&app, &headers, ru, STATE_TTL).await {
            Ok((id, d, new)) => ("sign_in", Some(id), None, d, new),
            Err(r) => return r,
        }
    } else if let Some(did) = &q.link {
        let (d, new) = match super::oauth::device_for(&app, &headers).await {
            Ok(x) => x,
            Err(e) => return page(&app, StatusCode::INTERNAL_SERVER_ERROR, &e.description),
        };
        if new || !super::oauth::link_csrf_ok(&app, &d.id, did, q.csrf.as_deref().unwrap_or("")) {
            return page(&app, StatusCode::FORBIDDEN, "Invalid or missing CSRF token.");
        }
        if !super::oauth::fresh_sign_in(&app, &d, did).await {
            return super::oauth::account_notice(super::oauth::AccountNotice::Stale);
        }
        if rl::check(&[&rl::FEDERATED_LINK_ACCOUNT], did, 1).is_err() {
            return page(&app, StatusCode::TOO_MANY_REQUESTS, "Too many changes. Please try again later.");
        }
        ("link", None, Some(did.clone()), d, false)
    } else if q.account.is_some() {
        match super::oauth::device_for(&app, &headers).await {
            Ok((d, new)) => ("sign_in", None, None, d, new),
            Err(e) => return page(&app, StatusCode::INTERNAL_SERVER_ERROR, &e.description),
        }
    } else {
        return page(&app, StatusCode::BAD_REQUEST, "Missing where to continue.");
    };
    let d = match app.federated.oidc.discovery(&p, app.config.dev_mode).await {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!(provider = %p.id, "sign-in provider unavailable: {e}");
            let msg = format!("{} isn't answering right now. Try again later, or sign in another way.", p.name);
            return page(&app, StatusCode::BAD_GATEWAY, &msg);
        }
    };
    let state = crate::oauth::util::random_id("", 24);
    let now = super::server::now_secs() as i64;
    let row = FedState {
        provider: p.id.clone(),
        purpose: purpose.into(),
        request_id,
        did,
        device_id: device.id.clone(),
        created_at: now,
        expires_at: now + STATE_TTL,
        handoff: None,
        app: purpose == "sign_in" && q.request_uri.is_none() && q.app.is_some(),
        methods: purpose == "sign_in"
            && q.request_uri.is_none()
            && q.ret.as_deref() == Some(crate::oauth::ui::METHODS_RETURN),
        identity: None,
    };
    let val = Bytes::from(super::server::to_json_bytes(&row));
    let routing = state_routing(&state);
    match app.private_cas(&routing, vec![Cond::eq(STATE_ROW, None)], vec![Op::put(STATE_ROW, Some(val))]).await {
        Ok(o) if o.applied => {}
        Ok(_) => return page(&app, StatusCode::INTERNAL_SERVER_ERROR, "Please try again."),
        Err(e) => return page(&app, e.status, &e.message),
    }
    let mut r = see_other(&authorize_url(&app, &p, &d, &state, purpose == "link"));
    if new_cookie {
        r.headers_mut().insert(header::SET_COOKIE, super::oauth::device_cookie(&app, &device));
    }
    r
}

#[derive(Deserialize, Default)]
struct CallbackQ {
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    iss: Option<String>,
    #[serde(default)]
    handoff: Option<String>,
}

/// What the provider sent back, from the query or a stashed form post.
struct Response_ {
    code: Option<String>,
    error: Option<String>,
    iss: Option<String>,
}

const EXPIRED: &str = "This sign-in expired or was already used. Please start again.";

fn refused(app: &App, purpose: &str, msg: &str) -> Response {
    crate::metrics::FEDERATED_SIGN_INS.with_label_values(&[purpose, "refused"]).inc();
    page(app, StatusCode::BAD_REQUEST, msg)
}

/// The provider's redirect (query mode), or the same-origin GET a
/// `form_post` was handed to. Only the browser that started the flow may
/// finish it, and only once.
async fn callback_get(
    State(app): AppState,
    super::moderation::ClientIp(ip): super::moderation::ClientIp,
    axum::extract::Path(provider): axum::extract::Path<String>,
    headers: HeaderMap,
    Query(q): Query<CallbackQ>,
) -> Response {
    use crate::ratelimit as rl;
    if !enabled(&app) {
        return not_found();
    }
    if rl::check_ip(&[&rl::GLOBAL_IP, &rl::OAUTH_SIGN_IN_IP], 1).is_err() {
        return page(&app, StatusCode::TOO_MANY_REQUESTS, "Too many sign-in attempts. Please try again later.");
    }
    let (state, handoff) = match &q.handoff {
        Some(h) => match h.split_once('.') {
            Some((s, h)) => (s.to_string(), Some(h.to_string())),
            None => return refused(&app, "sign_in", EXPIRED),
        },
        None => (q.state.clone().unwrap_or_default(), None),
    };
    if !valid_state(&state) {
        return refused(&app, "sign_in", EXPIRED);
    }
    let routing = state_routing(&state);
    let raw = match app.get_private(&routing, STATE_ROW).await {
        Ok(Some(r)) => r,
        Ok(None) => return refused(&app, "sign_in", EXPIRED),
        Err(e) => return page(&app, e.status, &e.message),
    };
    let Ok(st) = serde_json::from_slice::<FedState>(&raw) else { return refused(&app, "sign_in", EXPIRED) };
    let purpose = if st.purpose == "link" { "link" } else { "sign_in" };
    if st.provider != provider || st.purpose == "signup" {
        return refused(&app, purpose, EXPIRED);
    }
    let resp = match (&handoff, &st.handoff) {
        (Some(h), Some(ho))
            if crate::auth::ct_eq(ho.id_hash.as_bytes(), crate::oauth::util::sha256_b64u(h).as_bytes()) =>
        {
            Response_ { code: ho.code.clone(), error: ho.error.clone(), iss: ho.iss.clone() }
        }
        (None, None) => Response_ { code: q.code.clone(), error: q.error.clone(), iss: q.iss.clone() },
        _ => return refused(&app, purpose, EXPIRED),
    };
    if st.expires_at < super::server::now_secs() as i64 {
        return refused(&app, purpose, EXPIRED);
    }
    if super::oauth::device_cookie_id(&headers).as_deref() != Some(st.device_id.as_str()) {
        return refused(&app, purpose, "This sign-in was started in another browser. Please start again here.");
    }
    let consumed =
        app.private_cas(&routing, vec![Cond::eq(STATE_ROW, Some(raw))], vec![Op::put(STATE_ROW, None)]).await;
    match consumed {
        Ok(o) if o.applied => {}
        Ok(_) => return refused(&app, purpose, EXPIRED),
        Err(e) => return page(&app, e.status, &e.message),
    }
    finish(&app, &headers, ip, &state, st, resp).await
}

/// A `form_post` response arrives cross-site, without the device cookie: it
/// is kept on the state row under a one-time id, and the browser is sent to
/// a same-origin GET that carries the cookie.
async fn callback_post(
    State(app): AppState,
    axum::extract::Path(provider): axum::extract::Path<String>,
    body: AxBytes,
) -> Response {
    use crate::ratelimit as rl;
    if !enabled(&app) {
        return not_found();
    }
    if rl::check_ip(&[&rl::GLOBAL_IP, &rl::OAUTH_SIGN_IN_IP], 1).is_err() {
        return page(&app, StatusCode::TOO_MANY_REQUESTS, "Too many sign-in attempts. Please try again later.");
    }
    let f: std::collections::HashMap<String, String> =
        crate::oauth::util::parse_form(std::str::from_utf8(&body).unwrap_or("")).into_iter().collect();
    let state = f.get("state").cloned().unwrap_or_default();
    if !valid_state(&state) {
        return refused(&app, "sign_in", EXPIRED);
    }
    let routing = state_routing(&state);
    let raw = match app.get_private(&routing, STATE_ROW).await {
        Ok(Some(r)) => r,
        Ok(None) => return refused(&app, "sign_in", EXPIRED),
        Err(e) => return page(&app, e.status, &e.message),
    };
    let Ok(mut st) = serde_json::from_slice::<FedState>(&raw) else { return refused(&app, "sign_in", EXPIRED) };
    if st.provider != provider || st.purpose == "signup" {
        return refused(&app, &st.purpose, EXPIRED);
    }
    if st.handoff.is_some() || st.expires_at < super::server::now_secs() as i64 {
        return refused(&app, &st.purpose, EXPIRED);
    }
    let id = crate::oauth::util::random_id("", 24);
    let cap = |k: &str| f.get(k).map(|v| v.chars().take(2048).collect::<String>());
    st.handoff = Some(Handoff {
        id_hash: crate::oauth::util::sha256_b64u(&id),
        code: cap("code"),
        error: cap("error"),
        iss: cap("iss"),
    });
    let val = Bytes::from(super::server::to_json_bytes(&st));
    match app.private_cas(&routing, vec![Cond::eq(STATE_ROW, Some(raw))], vec![Op::put(STATE_ROW, Some(val))]).await {
        Ok(o) if o.applied => see_other(&format!("{}?handoff={state}.{id}", callback_path(&st.provider))),
        Ok(_) => refused(&app, &st.purpose, EXPIRED),
        Err(e) => page(&app, e.status, &e.message),
    }
}

/// The used state's flow: the code exchange, the id_token checks, then the
/// account it signs in to or the account it links to.
async fn finish(
    app: &App,
    headers: &HeaderMap,
    ip: Option<std::net::IpAddr>,
    state: &str,
    st: FedState,
    resp: Response_,
) -> Response {
    use super::oauth::{AccountNotice as N, LoginError as L};
    let link = st.purpose == "link";
    let purpose = if link { "link" } else { "sign_in" };
    let count = |r: &str| crate::metrics::FEDERATED_SIGN_INS.with_label_values(&[purpose, r]).inc();
    let failed = async |e: L, n: N| match link {
        true => super::oauth::account_notice(n),
        false => super::oauth::federated_failed(app, headers, st.request_id.as_deref(), e).await,
    };
    let Some(p) = app.federated.providers.get(&st.provider) else {
        count("refused");
        return failed(L::Federated, N::Failed).await;
    };
    let (Some(code), None) = (resp.code.as_deref().filter(|c| !c.is_empty()), &resp.error) else {
        count("provider_error");
        return failed(L::Federated, N::Failed).await;
    };
    let d = match app.federated.oidc.discovery(&p, app.config.dev_mode).await {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!(provider = %p.id, "sign-in provider unavailable: {e}");
            count("provider_error");
            return failed(L::Federated, N::Failed).await;
        }
    };
    let iss_ok = match &resp.iss {
        Some(i) => *i == p.issuer,
        None => !d.authorization_response_iss_parameter_supported,
    };
    if !iss_ok {
        count("refused");
        return failed(L::Federated, N::Failed).await;
    }
    let token = app
        .federated
        .oidc
        .exchange(&app.secrets, &p, &d, code, &verifier(app, state), &callback_url(app, &p.id), app.config.dev_mode)
        .await;
    let id_token = match token {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(provider = %p.id, "sign-in provider code exchange failed: {e}");
            count("provider_error");
            return failed(L::Federated, N::Failed).await;
        }
    };
    let id = match app.federated.oidc.validate(&p, &d, &id_token, &nonce(app, state), app.config.dev_mode).await {
        Ok(id) => id,
        Err(e) => {
            tracing::warn!(provider = %p.id, "id_token refused: {e}");
            count("refused");
            return failed(L::Federated, N::Failed).await;
        }
    };
    if link {
        let did = st.did.clone().unwrap_or_default();
        let device = match super::oauth::device_for(app, headers).await {
            Ok((d, _)) => d,
            Err(_) => return failed(L::Federated, N::Failed).await,
        };
        if !super::oauth::fresh_sign_in(app, &device, &did).await {
            count("refused");
            return super::oauth::account_notice(N::Stale);
        }
        return match link_identity(app, &did, &p, &id).await {
            Ok(()) => {
                count("ok");
                let what = match &id.display {
                    Some(d) => format!("You can now sign in to your account with {} ({d}).", p.name),
                    None => format!("You can now sign in to your account with {}.", p.name),
                };
                super::passkeys::security_mail(app, &did, &what).await;
                super::oauth::account_notice(N::Linked)
            }
            Err(LinkErr::Taken) => {
                count("refused");
                super::oauth::account_notice(N::Taken)
            }
            Err(LinkErr::Full) => {
                count("refused");
                super::oauth::account_notice(N::Full)
            }
            Err(LinkErr::Xrpc(e)) => {
                tracing::warn!(%did, "linking a sign-in identity failed: {}", e.message);
                count("error");
                super::oauth::account_notice(N::Failed)
            }
        };
    }
    let acct = match resolve(app, &id).await {
        Ok(Some(x)) => x,
        Ok(None) if p.signup != cfg::Signup::Off && st.purpose == "sign_in" => {
            count("unknown_identity");
            return signup_ticket(app, headers, &p, &st, &id).await;
        }
        Ok(None) => {
            count("unknown_identity");
            return failed(L::UnknownIdentity, N::Failed).await;
        }
        Err(e) => {
            count("error");
            return page(app, e.status, &e.message);
        }
    };
    let (acct, epoch) = acct;
    if acct.status.is_some() {
        count("refused");
        return failed(L::Inactive, N::Failed).await;
    }
    count("ok");
    note_used(app, &acct.did, &id.iss, &id.sub).await;
    let first = crate::oauth::store::FirstFactor {
        app: st.app,
        cred: crate::federated::auth_ref(&id.iss, &id.sub),
        provider: p.name.clone(),
    };
    super::oauth::federated_continue(app, headers, ip, st.request_id.as_deref(), acct, epoch, first, st.methods).await
}

/// A signup ticket lives this long: the user picks a handle and email.
pub const SIGNUP_TTL: i64 = 15 * 60;

fn invite_needed(app: &App, p: &Provider) -> bool {
    p.signup == cfg::Signup::Invite || app.config.invite_required
}

/// An identity no account uses, on a provider that allows signup: a
/// one-time ticket for this browser, and the form.
async fn signup_ticket(
    app: &App,
    headers: &HeaderMap,
    p: &Provider,
    st: &FedState,
    id: &crate::federated::oidc::Identity,
) -> Response {
    let ticket = crate::oauth::util::random_id("", 24);
    let now = super::server::now_secs() as i64;
    let row = FedState {
        provider: p.id.clone(),
        purpose: "signup".into(),
        request_id: st.request_id.clone(),
        did: None,
        device_id: st.device_id.clone(),
        created_at: now,
        expires_at: now + SIGNUP_TTL,
        handoff: None,
        app: st.app,
        methods: false,
        identity: Some(TicketIdentity {
            iss: id.iss.clone(),
            sub: id.sub.clone(),
            email: id.email.clone(),
            email_verified: id.email_verified,
            display: id.display.clone(),
        }),
    };
    let val = Bytes::from(super::server::to_json_bytes(&row));
    let routing = state_routing(&ticket);
    match app.private_cas(&routing, vec![Cond::eq(STATE_ROW, None)], vec![Op::put(STATE_ROW, Some(val))]).await {
        Ok(o) if o.applied => {}
        Ok(_) => return page(app, StatusCode::INTERNAL_SERVER_ERROR, "Please try again."),
        Err(e) => return page(app, e.status, &e.message),
    }
    let v = super::oauth::SignupValues {
        handle: String::new(),
        domain: String::new(),
        email: id.email.clone().unwrap_or_default(),
        invite_code: String::new(),
    };
    let verified = p.trust_email && id.email_verified;
    super::oauth::federated_signup_page(
        app,
        headers,
        st.request_id.as_deref(),
        &ticket,
        &p.name,
        &v,
        verified,
        invite_needed(app, p),
        None,
        StatusCode::OK,
    )
    .await
}

/// The signup form: the ticket must be this browser's and current, the
/// provider must still allow it, and the account is created with the
/// identity and no password. The ticket is spent only once the account
/// exists, so a refused handle can be retried; a second account can't be
/// made with it, since the identity's claim already names the first.
async fn signup_post(
    State(app): AppState,
    super::moderation::ClientIp(ip): super::moderation::ClientIp,
    headers: HeaderMap,
    body: AxBytes,
) -> Response {
    use crate::ratelimit as rl;
    if !enabled(&app) {
        return not_found();
    }
    let f: std::collections::HashMap<String, String> =
        crate::oauth::util::parse_form(std::str::from_utf8(&body).unwrap_or("")).into_iter().collect();
    let field = |k: &str| f.get(k).map(|v| v.trim().to_string()).unwrap_or_default();
    let ticket = field("ticket");
    if !valid_state(&ticket) {
        return refused(&app, "sign_in", EXPIRED);
    }
    let routing = state_routing(&ticket);
    let raw = match app.get_private(&routing, STATE_ROW).await {
        Ok(Some(r)) => r,
        Ok(None) => return refused(&app, "sign_in", EXPIRED),
        Err(e) => return page(&app, e.status, &e.message),
    };
    let st = match serde_json::from_slice::<FedState>(&raw) {
        Ok(st) if st.purpose == "signup" && st.expires_at >= super::server::now_secs() as i64 => st,
        _ => return refused(&app, "sign_in", EXPIRED),
    };
    let Some(device) = super::oauth::device_cookie_id(&headers).filter(|d| *d == st.device_id) else {
        return refused(&app, "sign_in", "This sign-up was started in another browser. Please start again here.");
    };
    let csrf = super::oauth::device_csrf(&app, &device, &format!("fedsignup\0{ticket}"));
    if !crate::auth::ct_eq(field("csrf").as_bytes(), csrf.as_bytes()) {
        return page(&app, StatusCode::FORBIDDEN, "Invalid or missing CSRF token.");
    }
    let (Some(id), Some(p)) = (st.identity.clone(), app.federated.providers.get(&st.provider)) else {
        return refused(&app, "sign_in", EXPIRED);
    };
    if p.issuer != id.iss || p.signup == cfg::Signup::Off {
        return refused(&app, "sign_in", "Signing up this way is no longer offered here.");
    }
    if field("action") == "deny" {
        let _ = app.private_cas(&routing, vec![Cond::eq(STATE_ROW, Some(raw))], vec![Op::put(STATE_ROW, None)]).await;
        return super::oauth::federated_failed(
            &app,
            &headers,
            st.request_id.as_deref(),
            super::oauth::LoginError::Federated,
        )
        .await;
    }
    let v = super::oauth::SignupValues {
        handle: field("handle").trim_start_matches('@').to_ascii_lowercase(),
        domain: field("domain").to_ascii_lowercase(),
        email: field("email"),
        invite_code: field("invite_code"),
    };
    let verified = p.trust_email && id.email_verified;
    let again = |msg: String, status: StatusCode| {
        let (app, headers, st, ticket, p, v) = (&app, &headers, &st, &ticket, &p, &v);
        async move {
            super::oauth::federated_signup_page(
                app,
                headers,
                st.request_id.as_deref(),
                ticket,
                &p.name,
                v,
                verified,
                invite_needed(app, p),
                Some(&msg),
                status,
            )
            .await
        }
    };
    if rl::check_ip(&[&rl::GLOBAL_IP, &rl::CREATE_ACCOUNT], 1).is_err() {
        return again("Too many sign-up attempts. Please try again later.".into(), StatusCode::TOO_MANY_REQUESTS).await;
    }
    if invite_needed(&app, &p) && v.invite_code.is_empty() {
        return again("An invite code is required.".into(), StatusCode::BAD_REQUEST).await;
    }
    let handle = match app.handle_domains.under(&v.handle) {
        Some(_) => v.handle.clone(),
        None => {
            let domain = app.handle_domains.served(&v.domain).filter(|d| *d == v.domain);
            format!("{}.{}", v.handle, domain.as_deref().unwrap_or(app.handle_domains.primary()))
        }
    };
    let email_confirmed = verified && id.email.as_deref().is_some_and(|e| e.eq_ignore_ascii_case(&v.email));
    let inp = super::server::CreateAccountIn {
        handle,
        email: Some(v.email.clone()),
        password: None,
        invite_code: Some(v.invite_code.clone()).filter(|c| !c.is_empty()),
        federated: Some(NewIdentity {
            iss: id.iss.clone(),
            sub: id.sub.clone(),
            provider: p.id.clone(),
            display: id.display.clone(),
        }),
        email_confirmed,
        ..Default::default()
    };
    let slot = match take_signup_slot(&app, &p).await {
        Ok(Slot::Full) => {
            let msg = format!("No more accounts can be created with {} today. Please try again tomorrow.", p.name);
            return again(msg, StatusCode::TOO_MANY_REQUESTS).await;
        }
        Ok(slot) => slot,
        Err(e) => return page(&app, e.status, &e.message),
    };
    let acct = match super::server::create_account_inner(&app, inp, None).await {
        Ok(a) => a,
        Err(e) if e.status == StatusCode::SERVICE_UNAVAILABLE => return again(e.message, e.status).await,
        Err(e) if e.status.is_server_error() => return page(&app, e.status, &e.message),
        Err(e) => {
            // refused before any account existed (a taken handle, a bad invite): the user retries
            give_back_signup_slot(&app, &p.id, slot).await;
            return again(e.message, StatusCode::BAD_REQUEST).await;
        }
    };
    let _ = app.private_cas(&routing, vec![Cond::eq(STATE_ROW, Some(raw))], vec![Op::put(STATE_ROW, None)]).await;
    crate::metrics::FEDERATED_IDENTITIES.with_label_values(&["linked"]).inc();
    let epoch = match super::server::auth_epoch(&app, &acct.did).await {
        Ok(e) => e,
        Err(e) => return page(&app, e.status, &e.message),
    };
    let cred = crate::federated::auth_ref(&id.iss, &id.sub);
    let ctx =
        super::signin::Ctx { ip, user_agent: super::signin::user_agent(&headers), device_id: Some(&st.device_id) };
    super::signin::record(&app, &acct, super::signin::Method::Federated(p.name.clone(), None), None, &ctx).await;
    super::oauth::federated_signed_up(&app, &headers, st.request_id.as_deref(), &acct.did, epoch, cred, st.app).await
}

#[derive(Clone, Copy)]
enum Slot {
    Uncapped,
    /// Counted against this UTC day.
    Taken(u64),
    Full,
}

/// One of the provider's signups today (UTC), counted cluster-wide in a
/// private row the GC drops after two days.
async fn take_signup_slot(app: &App, p: &Provider) -> XResult<Slot> {
    if p.signups_per_day == 0 {
        return Ok(Slot::Uncapped);
    }
    let day = super::server::now_secs() / 86_400;
    let routing = signup_count_routing(&p.id, day);
    for _ in 0..CAS_ROUNDS {
        let raw = app.get_private(&routing, SIGNUP_COUNT_ROW).await?;
        let n: u32 = raw.as_deref().and_then(|b| serde_json::from_slice(b).ok()).unwrap_or(0);
        if n >= p.signups_per_day {
            return Ok(Slot::Full);
        }
        let val = Bytes::from(super::server::to_json_bytes(&(n + 1)));
        let op = Op::put(SIGNUP_COUNT_ROW, Some(val));
        if app.private_cas(&routing, vec![Cond::eq(SIGNUP_COUNT_ROW, raw)], vec![op]).await?.applied {
            return Ok(Slot::Taken(day));
        }
    }
    Err(super::server::cas_conflict())
}

/// Best effort: a lost race or a store error leaves the slot used.
async fn give_back_signup_slot(app: &App, provider: &str, slot: Slot) {
    let Slot::Taken(day) = slot else { return };
    let routing = signup_count_routing(provider, day);
    for _ in 0..CAS_ROUNDS {
        let Ok(raw) = app.get_private(&routing, SIGNUP_COUNT_ROW).await else { return };
        let n: u32 = raw.as_deref().and_then(|b| serde_json::from_slice(b).ok()).unwrap_or(0);
        if n == 0 {
            return;
        }
        let val = Bytes::from(super::server::to_json_bytes(&(n - 1)));
        let op = Op::put(SIGNUP_COUNT_ROW, Some(val));
        match app.private_cas(&routing, vec![Cond::eq(SIGNUP_COUNT_ROW, raw)], vec![op]).await {
            Ok(o) if o.applied => return,
            Ok(_) => continue,
            Err(_) => return,
        }
    }
}

pub const SIGNUP_COUNT_ROW: &str = "fedsignup/n";

pub fn signup_count_routing(provider: &str, day: u64) -> String {
    format!("fedsignup:{provider}:{day}")
}

/// The account page app's provider sign-in: a sign-in this browser just
/// finished on the server's pages, asked for by the app (within two
/// minutes), traded once for the session `createSession` would give.
/// Same-origin only.
async fn create_federated_session(
    State(app): AppState,
    super::moderation::ClientIp(ip): super::moderation::ClientIp,
    headers: HeaderMap,
) -> XResult<Response> {
    crate::ratelimit::check_ip(&[&crate::ratelimit::OAUTH_SIGN_IN_IP], 1)?;
    let none = || XrpcError::auth("No sign-in to pick up on this browser");
    if !enabled(&app) || !super::server::own_page(&headers) {
        return Err(none());
    }
    let id = super::oauth::device_cookie_id(&headers).ok_or_else(none)?;
    let oauth_err =
        |e: crate::oauth::OAuthError| XrpcError { status: e.status, error: e.error, message: e.description };
    let (mut d, raw) = crate::oauth::store::get_device_raw(&app, &id).await.map_err(oauth_err)?.ok_or_else(none)?;
    let now = super::server::now_secs() as i64;
    let Some(i) = d
        .accounts
        .iter()
        .enumerate()
        .filter(|(_, a)| a.app_handoff_until >= now)
        .max_by_key(|(_, a)| a.authenticated_at)
        .map(|(i, _)| i)
    else {
        return Err(none());
    };
    let a = d.accounts[i].clone();
    d.accounts[i].app_handoff_until = 0;
    // once: the device row is cleared only if unchanged, and the pickup is
    // claimed cluster-wide, so a writer holding an older copy of the row
    // can't hand the same sign-in out again
    if !crate::oauth::store::put_device_if(&app, &d, raw).await.map_err(oauth_err)? {
        return Err(none());
    }
    let claim = format!("fedapp:{}:{}:{}", d.id, a.did, a.authenticated_at);
    if !super::internal::claim_replay_anywhere(&app, &a.did, &claim, a.app_handoff_until).await? {
        return Err(none());
    }
    if !super::oauth::device_accounts(&app, &d).await.iter().any(|(did, _)| *did == a.did) {
        return Err(none());
    }
    let acct = super::internal::account_anywhere(&app, &a.did).await?;
    let (access, refresh) =
        super::server::create_session_tokens(&app, &a.did, None, false, Some(&a.auth_epoch), a.auth_cred.clone(), ip)
            .await?;
    // an unlink racing this either found the session or left the identity
    // gone for this check (it writes the row before its scan)
    if !super::passkeys::credentials_live(&app, &a.did, a.auth_cred.as_deref()).await? {
        for r in crate::federated::cred_refs(a.auth_cred.as_deref()) {
            super::server::revoke_signed_in_with(&app, &a.did, r).await?;
        }
        return Err(none());
    }
    let mut out = super::server::session_info(&app, &acct, true).await;
    out["accessJwt"] = json!(access);
    out["refreshJwt"] = json!(refresh);
    Ok(Json(out).into_response())
}

/// The account the identity signs in to, and the credential epoch to sign
/// in under: read before the row is checked, so an unlink racing this
/// either lands first or finds the sign-in when it scans.
async fn resolve(app: &App, id: &crate::federated::oidc::Identity) -> XResult<Option<(Account, String)>> {
    let Some(did) = claimed_by(app, &id.iss, &id.sub).await? else { return Ok(None) };
    let acct = match super::internal::account_anywhere(app, &did).await {
        Ok(a) => a,
        Err(e) if e.error == "AccountNotFound" => return Ok(None),
        Err(e) => return Err(e),
    };
    let epoch = super::server::auth_epoch(app, &did).await?;
    if !has(app, &did, &id.iss, &id.sub).await? {
        return Ok(None);
    }
    Ok(Some((acct, epoch)))
}

// ---------------------------------------------------------------- the account's identities

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Identities {
    #[serde(default)]
    pub identities: Vec<Linked>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Linked {
    pub iss: String,
    pub sub: String,
    /// The provider id when it was linked: a label, never a key.
    pub provider: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,
    pub added_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<u64>,
}

impl Linked {
    pub fn auth_ref(&self) -> String {
        crate::federated::auth_ref(&self.iss, &self.sub)
    }
}

pub(super) async fn load_raw(app: &App, did: &str) -> XResult<(Identities, Option<Bytes>)> {
    match app.get_private(did, ROW).await? {
        Some(v) => Ok((serde_json::from_slice(&v).map_err(XrpcError::from_err)?, Some(v))),
        None => Ok((Identities::default(), None)),
    }
}

pub(super) async fn has(app: &App, did: &str, iss: &str, sub: &str) -> XResult<bool> {
    Ok(load_raw(app, did).await?.0.identities.iter().any(|l| l.iss == iss && l.sub == sub))
}

/// Whether every identity `auth_cred` names is still linked; true for
/// sign-ins without one.
pub(super) async fn still_linked(app: &App, did: &str, auth_cred: Option<&str>) -> XResult<bool> {
    let refs: Vec<&str> = crate::federated::cred_refs(auth_cred).filter(|r| r.starts_with("fed:")).collect();
    if refs.is_empty() {
        return Ok(true);
    }
    let ids = load_raw(app, did).await?.0;
    Ok(refs.iter().all(|r| ids.identities.iter().any(|l| l.auth_ref() == *r)))
}

fn claim_path(app: &App, iss: &str, sub: &str) -> object_store::path::Path {
    let h = hex::encode(crate::federated::identity_hash(iss, sub));
    object_store::path::Path::from(format!("{}/fedid/{h}", app.store.prefix))
}

/// The DID the identity's claim names, if any. Not proof by itself: the
/// account's row must list the identity.
pub(super) async fn claimed_by(app: &App, iss: &str, sub: &str) -> XResult<Option<String>> {
    Ok(super::server::read_claim(app, &claim_path(app, iss, sub)).await?.map(|(holder, _, _)| holder))
}

/// Ok(false): another account holds it.
async fn claim(app: &App, iss: &str, sub: &str, did: &str) -> XResult<bool> {
    super::server::claim_with(app, &claim_path(app, iss, sub), did, |holder: String| async move {
        match super::internal::account_anywhere(app, &holder).await {
            Ok(_) => has(app, &holder, iss, sub).await,
            Err(e) if e.error == "AccountNotFound" => Ok(false),
            Err(e) => Err(e),
        }
    })
    .await
}

/// Only if `did` holds it.
pub(super) async fn release(app: &App, iss: &str, sub: &str, did: &str) {
    let path = claim_path(app, iss, sub);
    let r = async {
        if super::server::read_claim(app, &path).await?.is_some_and(|(h, _, _)| h == did) {
            super::server::delete_claim(app, &path).await?;
        }
        XResult::Ok(())
    }
    .await;
    if let Err(e) = r {
        tracing::warn!(%did, "failed to release a sign-in identity claim (taken over once stale): {}", e.message);
    }
}

/// For account deletion: every identity's claim.
pub(super) async fn release_all(app: &App, did: &str) {
    let Ok((ids, _)) = load_raw(app, did).await else { return };
    for l in ids.identities {
        release(app, &l.iss, &l.sub, did).await;
    }
}

/// The identity a provider signup creates its account with.
#[derive(Clone, Debug)]
pub struct NewIdentity {
    pub iss: String,
    pub sub: String,
    pub provider: String,
    pub display: Option<String>,
}

/// Account creation's claim, next to the handle's and the email's.
pub(super) async fn claim_new(app: &App, f: &NewIdentity, did: &str) -> XResult<bool> {
    claim(app, &f.iss, &f.sub, did).await
}

/// The new account's row, written before the account itself.
pub(super) async fn write_new(app: &App, f: &NewIdentity, did: &str) -> XResult<()> {
    let ids = Identities {
        identities: vec![Linked {
            iss: f.iss.clone(),
            sub: f.sub.clone(),
            provider: f.provider.clone(),
            display: f.display.clone(),
            added_at: super::server::now_secs(),
            last_used_at: None,
        }],
    };
    let val = Bytes::from(super::server::to_json_bytes(&ids));
    if !app.private_cas(did, vec![Cond::eq(ROW, None)], vec![Op::put(ROW, Some(val))]).await?.applied {
        return Err(super::server::cas_conflict());
    }
    Ok(())
}

/// A failed creation's claim and row; the DID is this creation's alone.
pub(super) async fn release_new(app: &App, f: &NewIdentity, did: &str) {
    release(app, &f.iss, &f.sub, did).await;
    if let Err(e) = app.private_cas(did, Vec::new(), vec![Op::put(ROW, None)]).await {
        tracing::warn!(%did, "dropping a failed creation's sign-in identities: {}", e.message);
    }
}

pub(super) enum LinkErr {
    /// Another account has it.
    Taken,
    Full,
    Xrpc(XrpcError),
}

impl From<XrpcError> for LinkErr {
    fn from(e: XrpcError) -> LinkErr {
        LinkErr::Xrpc(e)
    }
}

/// Claims the identity for `did`, then adds it to the account's row. A row
/// write that doesn't happen releases the claim.
pub(super) async fn link_identity(
    app: &App,
    did: &str,
    provider: &Provider,
    id: &crate::federated::oidc::Identity,
) -> Result<(), LinkErr> {
    if has(app, did, &id.iss, &id.sub).await? {
        return Ok(());
    }
    if !claim(app, &id.iss, &id.sub, did).await? {
        return Err(LinkErr::Taken);
    }
    let added = async {
        for _ in 0..CAS_ROUNDS {
            let (mut ids, raw) = load_raw(app, did).await?;
            if ids.identities.iter().any(|l| l.iss == id.iss && l.sub == id.sub) {
                return Ok(true);
            }
            if ids.identities.len() >= MAX_IDENTITIES || ids.identities.iter().any(|l| l.iss == id.iss) {
                return Ok(false);
            }
            ids.identities.push(Linked {
                iss: id.iss.clone(),
                sub: id.sub.clone(),
                provider: provider.id.clone(),
                display: id.display.clone(),
                added_at: super::server::now_secs(),
                last_used_at: None,
            });
            let val = Bytes::from(super::server::to_json_bytes(&ids));
            if app.private_cas(did, vec![Cond::eq(ROW, raw)], vec![Op::put(ROW, Some(val))]).await?.applied {
                return Ok(true);
            }
        }
        Err(super::server::cas_conflict())
    }
    .await;
    match added {
        Ok(true) => {
            crate::metrics::FEDERATED_IDENTITIES.with_label_values(&["linked"]).inc();
            Ok(())
        }
        Ok(false) => {
            release(app, &id.iss, &id.sub, did).await;
            Err(LinkErr::Full)
        }
        Err(e) => {
            release(app, &id.iss, &id.sub, did).await;
            Err(LinkErr::Xrpc(e))
        }
    }
}

pub(super) enum UnlinkErr {
    NotLinked,
    /// It's the account's last way in.
    LastCredential,
    Xrpc(XrpcError),
}

impl From<XrpcError> for UnlinkErr {
    fn from(e: XrpcError) -> UnlinkErr {
        UnlinkErr::Xrpc(e)
    }
}

/// Removes the identity whose reference is `r` from the row unless nothing
/// else could sign in: a password, a passkey or another identity. The
/// passkeys row is held to what was read, so a racing passkey removal can't
/// leave the account with nothing. Then releases its claim and ends what it
/// signed in.
pub(super) async fn unlink(app: &App, did: &str, r: &str) -> Result<Linked, UnlinkErr> {
    let gone = 'cas: {
        for _ in 0..CAS_ROUNDS {
            let (mut ids, raw) = load_raw(app, did).await?;
            let Some(i) = ids.identities.iter().position(|l| l.auth_ref() == r) else {
                return Err(UnlinkErr::NotLinked);
            };
            let gone = ids.identities.remove(i);
            let acct = app.account(did).await?;
            let (pk, pk_raw) = super::passkeys::load_raw(app, did).await?;
            // a dormant identity (its provider gone) is no way in
            let live = ids.identities.iter().any(|l| app.federated.providers.by_issuer(&l.iss).is_some());
            if acct.password_hash.is_empty() && pk.creds.is_empty() && !(live && enabled(app)) {
                return Err(UnlinkErr::LastCredential);
            }
            let val = (!ids.identities.is_empty()).then(|| Bytes::from(super::server::to_json_bytes(&ids)));
            let conds = vec![Cond::eq(ROW, raw), Cond::eq(super::passkeys::ROW, pk_raw)];
            if app.private_cas(did, conds, vec![Op::put(ROW, val)]).await?.applied {
                break 'cas gone;
            }
        }
        return Err(UnlinkErr::Xrpc(super::server::cas_conflict()));
    };
    crate::metrics::FEDERATED_IDENTITIES.with_label_values(&["unlinked"]).inc();
    release(app, &gone.iss, &gone.sub, did).await;
    super::server::revoke_signed_in_with(app, did, &gone.auth_ref()).await?;
    Ok(gone)
}

/// Best effort, at most hourly: the user's list shows when each was last
/// used.
pub(super) async fn note_used(app: &App, did: &str, iss: &str, sub: &str) {
    let now = super::server::now_secs();
    let r = async {
        let (mut ids, raw) = load_raw(app, did).await?;
        let Some(l) = ids.identities.iter_mut().find(|l| l.iss == iss && l.sub == sub) else { return Ok(()) };
        if l.last_used_at.is_some_and(|t| now.saturating_sub(t) < 3600) {
            return Ok(());
        }
        l.last_used_at = Some(now);
        let val = Bytes::from(super::server::to_json_bytes(&ids));
        app.private_cas(did, vec![Cond::eq(ROW, raw)], vec![Op::put(ROW, Some(val))]).await.map(|_| ())
    }
    .await;
    if let Err(e) = r {
        tracing::debug!(did, "noting a sign-in identity's use: {}", e.message);
    }
}

fn rfc3339(secs: u64) -> String {
    chrono::DateTime::from_timestamp(secs as i64, 0)
        .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
        .unwrap_or_default()
}

pub(super) fn identity_view(app: &App, l: &Linked) -> J {
    let p = app.federated.providers.by_issuer(&l.iss);
    json!({
        "ref": l.auth_ref(),
        "issuer": l.iss,
        "provider": p.as_ref().map(|p| &p.id),
        "providerName": p.as_ref().map(|p| &p.name),
        "display": l.display,
        "addedAt": rfc3339(l.added_at),
        "lastUsedAt": l.last_used_at.map(rfc3339),
        "dormant": p.is_none(),
    })
}

/// Full account sessions only, like the passkey list.
async fn list_identities(State(app): AppState, Auth(creds): Auth) -> XResult<Json<J>> {
    let did = super::server::full_access(&creds)?;
    let (ids, _) = load_raw(&app, &did).await?;
    Ok(Json(json!({
        "identities": ids.identities.iter().map(|l| identity_view(&app, l)).collect::<Vec<_>>(),
        "providers": offered(&app).iter().map(button_view).collect::<Vec<_>>(),
        "available": enabled(&app),
        "max": MAX_IDENTITIES,
        "manageUrl": "/oauth/account",
    })))
}

// ---------------------------------------------------------------- golden fixtures

/// `private/federated.json` (`super::private_rows`).
pub(super) fn fixture_rows(did: &str) -> Vec<super::private_rows::PrivateRow> {
    let ids = Identities {
        identities: vec![
            Linked {
                iss: "https://accounts.example.com".into(),
                sub: "110248495921238986420".into(),
                provider: "example".into(),
                display: Some("alice@example.com".into()),
                added_at: 1_790_000_000,
                last_used_at: Some(1_790_000_500),
            },
            Linked {
                iss: "https://siwe.example.org".into(),
                sub: "eip155:1:0x0000000000000000000000000000000000000001".into(),
                provider: "wallet".into(),
                display: None,
                added_at: 1_790_000_100,
                last_used_at: None,
            },
        ],
    };
    let state = |handoff| FedState {
        provider: "example".into(),
        purpose: "sign_in".into(),
        request_id: Some("req-fixture".into()),
        did: None,
        device_id: "dev-fixture".into(),
        created_at: 1_790_000_000,
        expires_at: 1_790_000_600,
        handoff,
        app: false,
        methods: false,
        identity: None,
    };
    let link = FedState {
        provider: "wallet".into(),
        purpose: "link".into(),
        request_id: None,
        did: Some(did.into()),
        device_id: "dev-fixture".into(),
        created_at: 1_790_000_000,
        expires_at: 1_790_000_600,
        handoff: None,
        app: false,
        methods: false,
        identity: None,
    };
    let ticket = FedState {
        provider: "example".into(),
        purpose: "signup".into(),
        request_id: None,
        did: None,
        device_id: "dev-fixture".into(),
        created_at: 1_790_000_000,
        expires_at: 1_790_000_900,
        handoff: None,
        app: true,
        methods: false,
        identity: Some(TicketIdentity {
            iss: "https://accounts.example.com".into(),
            sub: "110248495921238986421".into(),
            email: Some("new@example.com".into()),
            email_verified: true,
            display: Some("new@example.com".into()),
        }),
    };
    let handoff = Handoff {
        id_hash: "n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg".into(),
        code: Some("provider-code".into()),
        error: None,
        iss: Some("https://accounts.example.com".into()),
    };
    use super::server::to_json_bytes as enc;
    vec![
        (did.into(), ROW.into(), enc(&ids)),
        (state_routing("st0aaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), STATE_ROW.into(), enc(&state(None))),
        (state_routing("st1aaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), STATE_ROW.into(), enc(&state(Some(handoff)))),
        (state_routing("st2aaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), STATE_ROW.into(), enc(&link)),
        (state_routing("st3aaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), STATE_ROW.into(), enc(&ticket)),
        (signup_count_routing("example", 20_717), SIGNUP_COUNT_ROW.into(), enc(&3u32)),
    ]
}

pub(super) fn check_row(routing: &str, name: &str, val: &[u8]) -> Option<anyhow::Result<&'static str>> {
    use super::private_rows::typed_row;
    match name {
        ROW if routing.starts_with("did:") => Some(typed_row::<Identities>("sign-in identities", val)),
        STATE_ROW if routing.starts_with("oauth:fed:") => Some(typed_row::<FedState>("sign-in provider flow", val)),
        SIGNUP_COUNT_ROW if routing.starts_with("fedsignup:") => Some(typed_row::<u32>("provider signups today", val)),
        _ => None,
    }
}
