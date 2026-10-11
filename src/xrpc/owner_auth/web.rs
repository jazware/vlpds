//! The owner-auth HTTP surface.
//!
//! `/auth/*` serves both frontends: the SPA calls it as JSON, and the
//! server-rendered pages use it for the provider round trip. No token ever
//! rides a URL: a provider callback returns to `/auth/resume` with an opaque
//! transaction id, and the SPA redeems its session with a same-origin POST to
//! `/auth/complete`.

use axum::extract::Path;
use axum::response::Redirect;

use super::flow::{self, ACTIONS, ACTION_DELETE, ACTION_LINK, ACTION_UNLINK};
use super::provider::SiweProof;
use super::store::Continuation;
use super::types::*;
use crate::oauth::store::Device;
use crate::oauth::OAuthError;
use crate::xrpc::*;

fn oauth_err(e: OAuthError) -> XrpcError {
    XrpcError { status: e.status, error: e.error, message: e.description }
}

fn challenge_json(c: &Challenge) -> J {
    match c {
        Challenge::Redirect { url } => json!({"kind": "redirect", "url": url}),
        Challenge::Siwe { message, address } => json!({"kind": "siwe", "message": message, "address": address}),
    }
}

fn cred_json(c: &super::Cred) -> J {
    json!({
        "id": c.id,
        "provider": c.provider.as_str(),
        "label": c.label,
        "createdAt": c.created_at,
        "lastUsedAt": c.last_used_at,
    })
}

fn parse_provider(s: &str) -> XResult<ProviderId> {
    ProviderId::parse(s).ok_or_else(|| bad_request("unknown sign-in method"))
}

/// A JSON body plus, when the browser had no device row yet, the Set-Cookie
/// that binds this login to it.
fn json_with_device(app: &App, device: &Device, new_cookie: bool, body: J) -> Response {
    let mut r = Json(body).into_response();
    if new_cookie {
        r.headers_mut().append(header::SET_COOKIE, super::oauth::device_cookie(app, device));
    }
    r
}

pub fn routes() -> Router<Arc<App>> {
    Router::new()
        .route("/auth/methods", get(methods))
        .route("/auth/start", post(start))
        .route("/auth/link", post(start_link))
        .route("/auth/reauth", post(start_reauth))
        .route("/auth/continue", post(continue_))
        .route("/auth/complete", post(complete))
        .route("/auth/callback/{provider}", get(callback_get).post(callback_post))
        .route("/auth/resume", get(resume))
        .route("/xrpc/vlpds.auth.listCredentials", get(xrpc_list))
        .route("/xrpc/vlpds.auth.unlinkCredential", post(xrpc_unlink))
        .route("/xrpc/vlpds.auth.deleteAccount", post(xrpc_delete))
}

/// Configured methods. No identifier is taken and no account looked up, so
/// this says nothing about who has an account here.
async fn methods(State(app): AppState) -> Json<J> {
    let providers: Vec<J> = app
        .auth
        .enabled()
        .into_iter()
        .map(|p| {
            json!({
                "id": p.as_str(),
                "label": p.label(),
                "presentation": match p.presentation() {
                    Presentation::Redirect => "redirect",
                    Presentation::Siwe => "siwe",
                },
            })
        })
        .collect();
    Json(json!({"providers": providers}))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct StartIn {
    provider: String,
    /// Only `/auth/start` needs one; the link and reauth endpoints fix it.
    #[serde(default)]
    intent: Option<String>,
    #[serde(default)]
    address: Option<String>,
    #[serde(default)]
    screen: Option<String>,
    /// Linking to an account that has a local password: confirm with it, the
    /// same way adding a passkey does.
    #[serde(default)]
    password: Option<String>,
    /// Linking to a provider-only account: confirm with a fresh proof.
    #[serde(default)]
    grant: Option<String>,
    /// A server-rendered page's OAuth request to resume once the login
    /// succeeds. Its CSRF token, when sent, binds the start to this browser.
    #[serde(default)]
    request_uri: Option<String>,
    #[serde(default)]
    csrf: Option<String>,
}

async fn start(State(app): AppState, headers: HeaderMap, Json(inp): Json<StartIn>) -> XResult<Response> {
    let pid = parse_provider(&inp.provider)?;
    let intent = inp.intent.as_deref().and_then(Intent::parse).ok_or_else(|| bad_request("unknown sign-in intent"))?;
    if intent.needs_owner() {
        return Err(bad_request("use /auth/link or /auth/reauth for this"));
    }
    let (device, new_cookie) = super::oauth::device_for(&app, &headers).await.map_err(oauth_err)?;
    let cont = match inp.request_uri.as_deref().map(str::trim).filter(|u| !u.is_empty()) {
        Some(uri) => {
            // A server-rendered sign-in page: the request and its CSRF token
            // bind this login to the browser, exactly as the form does.
            let id = crate::oauth::store::request_id_from_uri(uri).ok_or_else(|| bad_request("invalid request"))?;
            if let Some(t) = &inp.csrf {
                if !super::oauth::check_csrf(&app, &headers, &device, id, Some(t)) {
                    return Err(XrpcError {
                        status: StatusCode::FORBIDDEN,
                        error: "InvalidRequest".into(),
                        message: "Invalid or missing CSRF token".into(),
                    });
                }
            }
            Continuation::OAuth { request_uri: uri.to_string() }
        }
        None => Continuation::Account { screen: inp.screen.clone().unwrap_or_else(|| "sign_in".into()) },
    };
    let started = flow::start(&app, pid, intent, cont, Some(device.id.clone()), inp.address).await?;
    Ok(json_with_device(
        &app,
        &device,
        new_cookie,
        json!({"txnId": started.id, "provider": pid.as_str(), "challenge": challenge_json(&started.challenge)}),
    ))
}

async fn start_link(
    State(app): AppState,
    Auth(creds): Auth,
    headers: HeaderMap,
    Json(inp): Json<StartIn>,
) -> XResult<Response> {
    let did = super::server::full_access(&creds)?;
    let pid = parse_provider(&inp.provider)?;
    // Attaching a new way to sign in needs proof of the account, not just a
    // session token: its own password, or a fresh proof of another method.
    super::passkeys::confirm_owner(
        &app,
        &did,
        inp.password.as_deref().unwrap_or(""),
        inp.grant.as_deref(),
        ACTION_LINK,
        Some(pid.as_str()),
    )
    .await?;
    let (device, new_cookie) = super::oauth::device_for(&app, &headers).await.map_err(oauth_err)?;
    let cont = Continuation::Did { did, action: Some(ACTION_LINK.into()), target: Some(pid.as_str().into()) };
    let started = flow::start(&app, pid, Intent::Link, cont, Some(device.id.clone()), inp.address).await?;
    Ok(json_with_device(
        &app,
        &device,
        new_cookie,
        json!({"txnId": started.id, "provider": pid.as_str(), "challenge": challenge_json(&started.challenge)}),
    ))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReauthIn {
    provider: String,
    action: String,
    #[serde(default)]
    target: Option<String>,
    #[serde(default)]
    address: Option<String>,
}

async fn start_reauth(
    State(app): AppState,
    Auth(creds): Auth,
    headers: HeaderMap,
    Json(inp): Json<ReauthIn>,
) -> XResult<Response> {
    let did = super::server::full_access(&creds)?;
    if !ACTIONS.contains(&inp.action.as_str()) {
        return Err(bad_request("unknown action"));
    }
    let pid = parse_provider(&inp.provider)?;
    let (device, new_cookie) = super::oauth::device_for(&app, &headers).await.map_err(oauth_err)?;
    let cont = Continuation::Did { did, action: Some(inp.action), target: inp.target };
    let started = flow::start(&app, pid, Intent::Reauth, cont, Some(device.id.clone()), inp.address).await?;
    Ok(json_with_device(
        &app,
        &device,
        new_cookie,
        json!({"txnId": started.id, "provider": pid.as_str(), "challenge": challenge_json(&started.challenge)}),
    ))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ContinueIn {
    txn: String,
    step: String,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    signature: Option<String>,
    #[serde(default)]
    address: Option<String>,
    #[serde(default)]
    handle: Option<String>,
    #[serde(default)]
    domain: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    invite_code: Option<String>,
}

/// A server-rendered completion: verify the proof, then hand the browser to
/// the one landing that finishes a login, so the next page (consent, a second
/// factor, or a sign-up) is rendered as a document rather than handed to a
/// script. None means the page should fall back to the JSON answer.
async fn form_completion(
    app: &App,
    _headers: &HeaderMap,
    _device: &mut Device,
    inp: &ContinueIn,
) -> XResult<Option<Response>> {
    if inp.step != "siwe" {
        return Ok(None);
    }
    let pid = flow::txn_provider(app, &inp.txn).await?;
    let proof = SiweProof {
        message: inp.message.clone().unwrap_or_default(),
        signature: inp.signature.clone().unwrap_or_default(),
        address: inp.address.clone(),
    };
    flow::ensure_verified(app, pid, &inp.txn, &proof).await?;
    let t = crate::oauth::util::encode_uri_component(&inp.txn);
    Ok(Some(Redirect::to(&format!("/auth/resume?t={t}")).into_response()))
}

async fn continue_(
    State(app): AppState,
    headers: HeaderMap,
    Query(q): Query<std::collections::HashMap<String, String>>,
    Json(inp): Json<ContinueIn>,
) -> XResult<Response> {
    let (mut device, new_cookie) = super::oauth::device_for(&app, &headers).await.map_err(oauth_err)?;
    let device_id = device.id.clone();
    if q.contains_key("form") {
        if let Some(r) = form_completion(&app, &headers, &mut device, &inp).await? {
            return Ok(r);
        }
    }
    let body = match inp.step.as_str() {
        // One proof, then whatever the transaction was started for: the intent is
        // server-owned, so naming a different step cannot turn a link into a
        // sign-in.
        "siwe" | "link" | "reauth" => {
            let pid = flow::txn_provider(&app, &inp.txn).await?;
            let proof = SiweProof {
                message: inp.message.clone().unwrap_or_default(),
                signature: inp.signature.clone().unwrap_or_default(),
                address: inp.address.clone(),
            };
            flow::ensure_verified(&app, pid, &inp.txn, &proof).await?;
            let ready = flow::ready(&app, &inp.txn, Some(&device_id)).await?;
            match ready.txn.intent {
                Intent::Link => {
                    let did = match &ready.txn.cont {
                        Continuation::Did { did, .. } => did.clone(),
                        _ => return Err(bad_request("this sign-in is not a link")),
                    };
                    let cred = flow::link(&app, &did, &ready.ident).await?;
                    flow::consume(&app, &inp.txn).await?;
                    json!({"status": "linked", "credential": cred_json(&cred)})
                }
                Intent::Reauth => {
                    let (did, action, target) = match &ready.txn.cont {
                        Continuation::Did { did, action, target } => (did.clone(), action.clone(), target.clone()),
                        _ => return Err(bad_request("this sign-in is not a confirmation")),
                    };
                    let action = action.ok_or_else(|| bad_request("no action"))?;
                    let grant = flow::grant(&app, &did, &action, target, Some(&device_id)).await?;
                    flow::consume(&app, &inp.txn).await?;
                    json!({"status": "confirmed", "grant": grant})
                }
                _ => finish_or_signup(&app, &mut device, &inp.txn, ready.txn.cont.clone()).await?,
            }
        }
        "signup" => {
            let ready = flow::ready(&app, &inp.txn, Some(&device_id)).await?;
            let acct = flow::create_account_for(
                &app,
                &ready.ident,
                flow::SignupIn {
                    handle: inp.handle.clone().unwrap_or_default(),
                    domain: inp.domain.clone(),
                    email: inp.email.clone().unwrap_or_default(),
                    invite_code: inp.invite_code.clone(),
                },
            )
            .await?;
            sign_in_device(&app, &mut device, &acct.did, Some(ready.ident.cred_ref())).await?;
            flow::consume(&app, &inp.txn).await?;
            json!({"status": "done", "did": acct.did, "handle": acct.handle})
        }
        other => return Err(bad_request(&format!("unknown step {other:?}"))),
    };
    Ok(json_with_device(&app, &device, new_cookie, body))
}

/// Resolve a staged identity: sign in when it maps to an account, else ask
/// for the account fields.
async fn finish_or_signup(app: &App, device: &mut Device, txn_id: &str, cont: Continuation) -> XResult<J> {
    let ready = flow::ready(app, txn_id, Some(&device.id)).await?;
    match flow::resolve_account(app, &ready.ident).await? {
        Some(acct) if acct.status.is_none() => {
            let cred = Some(ready.ident.cred_ref());
            // The account's own second factors still apply to a provider
            // login; a factor is completed on the server-rendered page,
            // which keeps the provider credential as the login's provenance.
            match super::oauth::start_provider_factor(app, device, &acct, cred.clone()).await? {
                super::oauth::ProviderFactor::NotNeeded { .. } => {}
                super::oauth::ProviderFactor::Needed(_) => {
                    return Ok(json!({"status": "factor", "url": "/oauth/account?2fa=1"}))
                }
            }
            sign_in_device(app, device, &acct.did, cred).await?;
            flow::consume(app, txn_id).await?;
            Ok(json!({"status": "done", "did": acct.did, "handle": acct.handle}))
        }
        Some(_) => Err(XrpcError {
            status: StatusCode::UNAUTHORIZED,
            error: "AccountInactive".into(),
            message: "This account is deactivated or suspended".into(),
        }),
        None => Ok(json!({
            "status": "signup",
            "txnId": txn_id,
            "provider": ready.ident.provider.as_str(),
            "email": ready.ident.email.as_ref().map(|e| e.address.clone()),
            "continuation": match cont {
                Continuation::OAuth { .. } => "oauth",
                Continuation::Account { .. } => "account",
                Continuation::Did { .. } => "did",
            },
        })),
    }
}

/// Record a DID on the browser's device row, reading the current credential
/// epoch first so a revoke-all racing this refuses the sign-in.
async fn sign_in_device(app: &App, device: &mut Device, did: &str, cred: Option<String>) -> XResult<()> {
    let epoch = crate::xrpc::auth_epoch(app, did).await?;
    super::oauth::note_device_sign_in(app, device, did.to_string(), epoch, cred).await
}

/// Redeem a completed provider login for an ordinary first-party session.
async fn complete(
    State(app): AppState,
    super::moderation::ClientIp(ip): super::moderation::ClientIp,
    headers: HeaderMap,
) -> XResult<Json<J>> {
    let (device, _) = super::oauth::device_for(&app, &headers).await.map_err(oauth_err)?;
    let now = crate::oauth::util::now_secs();
    let entry = device
        .accounts
        .iter()
        .filter(|a| now - a.authenticated_at <= 7 * 24 * 3600)
        .max_by_key(|a| a.authenticated_at)
        .ok_or_else(|| XrpcError::auth("no completed sign-in on this browser"))?;
    let acct = super::internal::account_anywhere(&app, &entry.did).await?;
    if acct.status.is_some() {
        return Err(XrpcError::auth("this account is not active"));
    }
    if crate::xrpc::auth_epoch(&app, &entry.did).await? != entry.auth_epoch {
        return Err(XrpcError::auth("your sign-in is no longer valid; sign in again"));
    }
    if !super::passkeys::still_registered(&app, &entry.did, entry.auth_cred.as_deref()).await? {
        return Err(XrpcError::auth("the credential that signed you in was removed"));
    }
    let (access, refresh) = super::server::create_session_tokens(
        &app,
        &entry.did,
        None,
        false,
        Some(&entry.auth_epoch),
        entry.auth_cred.clone(),
        ip,
    )
    .await?;
    let mut out = super::server::session_info(&app, &acct, true).await;
    out["accessJwt"] = json!(access);
    out["refreshJwt"] = json!(refresh);
    Ok(Json(out))
}

// ---------------------------------------------------------------- callbacks

async fn callback_get(
    State(app): AppState,
    Path(provider): Path<String>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let pairs: Vec<(String, String)> = q.into_iter().collect();
    callback_common(&app, &provider, &pairs).await
}

async fn callback_post(State(app): AppState, Path(provider): Path<String>, body: AxBytes) -> Response {
    let pairs = crate::oauth::util::parse_form(&String::from_utf8_lossy(&body));
    callback_common(&app, &provider, &pairs).await
}

async fn callback_common(app: &App, provider: &str, q: &[(String, String)]) -> Response {
    let Some(pid) = ProviderId::parse(provider) else {
        return err_page(StatusCode::NOT_FOUND, "Not found", "That sign-in method does not exist.");
    };
    match flow::callback(app, pid, q).await {
        Ok(flow::CallbackEnd::Verified { txn_id }) => {
            Redirect::to(&format!("/auth/resume?t={}", crate::oauth::util::encode_uri_component(&txn_id)))
                .into_response()
        }
        Ok(flow::CallbackEnd::Cancelled { .. }) => Redirect::to("/account?auth=cancelled").into_response(),
        Err(e) => err_page(e.status, "Sign-in failed", &e.message),
    }
}

/// Same-origin landing after a provider callback: the device cookie is
/// present here, so this is where the login binds to the browser.
async fn resume(
    State(app): AppState,
    headers: HeaderMap,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let Some(t) = q.get("t").cloned() else {
        return err_page(StatusCode::BAD_REQUEST, "Sign-in failed", "Missing sign-in reference.");
    };
    let (device, _) = match super::oauth::device_for(&app, &headers).await {
        Ok(x) => x,
        Err(e) => return err_page(e.status, "Sign-in failed", &e.description),
    };
    let ready = match flow::ready(&app, &t, Some(&device.id)).await {
        Ok(r) => r,
        Err(e) => return err_page(e.status, "Sign-in failed", &e.message),
    };
    let did = match &ready.txn.cont {
        Continuation::OAuth { .. } | Continuation::Account { .. } => {
            match flow::resolve_account(&app, &ready.ident).await {
                Ok(Some(a)) => a.did,
                Ok(None) => {
                    // An identity with no account here. The account page is
                    // the surface that collects a handle and contact address,
                    // so hand the verified identity back to it; the
                    // server-rendered pages do not collect them yet.
                    if matches!(ready.txn.cont, Continuation::Account { .. }) {
                        let t = crate::oauth::util::encode_uri_component(&t);
                        return Redirect::to(&format!("/account?auth=signup&t={t}")).into_response();
                    }
                    return err_page(
                        StatusCode::NOT_FOUND,
                        "No account linked",
                        "No account here is linked to that identity. Create an account, then link it from your account settings.",
                    );
                }
                Err(e) => return err_page(e.status, "Sign-in failed", &e.message),
            }
        }
        // A link or a confirmation: the identity is proved, but the app makes
        // the change, so hand the transaction back to it.
        Continuation::Did { action, .. } => {
            let step = if action.as_deref() == Some("link") { "link" } else { "reauth" };
            let t = crate::oauth::util::encode_uri_component(&t);
            return Redirect::to(&format!("/account?auth=pending&step={step}&t={t}")).into_response();
        }
    };
    match &ready.txn.cont {
        Continuation::OAuth { request_uri } => {
            super::oauth::provider_finish_oauth(&app, &headers, request_uri, &did, Some(ready.ident.cred_ref())).await
        }
        _ => super::oauth::provider_finish_account(&app, &headers, &did, Some(ready.ident.cred_ref())).await,
    }
}

// ------------------------------------------------------------------- XRPC

async fn xrpc_list(State(app): AppState, Auth(creds): Auth) -> XResult<Json<J>> {
    let did = super::server::full_access(&creds)?;
    let list: Vec<J> = flow::list_credentials(&app, &did).await?.iter().map(cred_json).collect();
    // Whether a local password exists tells the page which way to confirm a
    // credential change. It is the owner's own state, not an account probe.
    let acct = super::internal::account_anywhere(&app, &did).await?;
    Ok(Json(json!({"credentials": list, "hasPassword": !acct.password_hash.is_empty()})))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UnlinkIn {
    id: String,
    /// Always required: removing a way to sign in needs a fresh proof.
    grant: String,
}

async fn xrpc_unlink(State(app): AppState, Auth(creds): Auth, Json(inp): Json<UnlinkIn>) -> XResult<Json<J>> {
    let did = super::server::full_access(&creds)?;
    flow::may(&app, &did, &inp.grant, ACTION_UNLINK, Some(&inp.id)).await?;
    // Removing the last way in would lock the owner out; an account with a
    // local password always has another way.
    let (current, _) = crate::xrpc::owner_auth::store::load_creds(&app, &did).await?;
    let acct = super::internal::account_anywhere(&app, &did).await?;
    if current.list.len() <= 1 && acct.password_hash.is_empty() {
        return Err(XrpcError::bad(
            "InvalidRequest",
            "This is the only way to sign in to your account. Add another first.",
        ));
    }
    let gone = flow::unlink(&app, &did, &inp.id).await?;
    Ok(Json(json!({"removed": gone.is_some()})))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeleteIn {
    did: String,
    /// The code `requestAccountDelete` mailed, as the reference's
    /// `deleteAccount` takes it.
    token: String,
    /// A fresh proof of one of the account's own sign-in methods, in place of
    /// the password that endpoint asks for.
    grant: String,
}

/// Deletion for an account that has no local password: the same mailed
/// deletion code the reference requires, plus a fresh-owner confirmation
/// instead of a password. The deletion itself is the same retry-safe path the
/// public `deleteAccount` uses.
async fn xrpc_delete(State(app): AppState, Json(inp): Json<DeleteIn>) -> XResult<StatusCode> {
    let did = inp.did.trim().to_string();
    let from = super::server::delete_from(&app, &did).await.map_err(|e| match e.error.as_str() {
        "AccountNotFound" => bad_request("account not found"),
        _ => e,
    })?;
    flow::may(&app, &did, &inp.grant, ACTION_DELETE, None).await?;
    // A deletion that already passed the repo delete was authorized when it
    // began; its token row may be gone with the private rows.
    if matches!(from, super::server::DeleteFrom::Account(_)) {
        super::server::assert_email_token(&app, &did, "delete_account", &inp.token).await?;
    }
    super::server::finish_delete(&app, &did, from, "user", None).await?;
    Ok(StatusCode::OK)
}

fn err_page(status: StatusCode, title: &str, msg: &str) -> Response {
    let body = format!(
        "<!doctype html><meta charset=\"utf-8\"><title>{0}</title><h1>{0}</h1><p>{1}</p>",
        crate::oauth::util::html_escape(title),
        crate::oauth::util::html_escape(msg)
    );
    (status, [(header::CONTENT_TYPE, "text/html; charset=utf-8")], body).into_response()
}
