use super::*;

pub fn routes() -> Router<Arc<App>> {
    Router::new()
        .route("/xrpc/com.atproto.identity.resolveHandle", get(resolve_handle))
        .route("/xrpc/com.atproto.identity.resolveDid", get(resolve_did))
        .route("/xrpc/com.atproto.identity.resolveIdentity", get(resolve_identity))
        .route("/xrpc/com.atproto.identity.refreshIdentity", post(refresh_identity))
        .route("/xrpc/com.atproto.identity.updateHandle", post(update_handle))
        .route("/xrpc/com.atproto.identity.getRecommendedDidCredentials", get(get_recommended_did_credentials))
        .route("/xrpc/com.atproto.identity.requestPlcOperationSignature", post(request_plc_operation_signature))
        .route("/xrpc/com.atproto.identity.signPlcOperation", post(sign_plc_operation))
        .route("/xrpc/com.atproto.identity.submitPlcOperation", post(submit_plc_operation))
        .route("/xrpc/vlpds.identity.getPlcData", get(get_plc_data))
        .route("/xrpc/vlpds.identity.getPlcAuditLog", get(get_plc_audit_log))
        .route("/xrpc/vlpds.identity.checkHandle", get(check_handle))
        .route("/.well-known/atproto-did", get(well_known_atproto_did))
        .route("/.well-known/did.json", get(well_known_did_json))
        .route("/tls-check", get(tls_check))
}

/// None for an inactive account too (reference getAccount(handle)); an error
/// only when the owner can't tell (unreachable, shard moving: retry).
async fn active_handle_did(app: &Arc<App>, handle: &str) -> Result<Option<String>, XrpcError> {
    let Ok(Some(did)) = app.resolve_handle(handle).await else {
        return Ok(None);
    };
    match super::internal::account_anywhere(app, &did).await {
        Ok(a) if a.status.is_none() && a.handle == handle => Ok(Some(did)),
        Err(e) if e.status.is_server_error() => Err(e),
        _ => Ok(None),
    }
}

fn public_host(app: &App) -> Option<String> {
    reqwest::Url::parse(&app.public_url).ok()?.host_str().map(|h| h.to_ascii_lowercase())
}

#[derive(Deserialize)]
struct TlsCheckQ {
    domain: Option<String>,
}

/// Caddy's on-demand TLS `ask` endpoint, as the reference PDS
/// distribution's: Caddy issues a certificate only on 2xx.
async fn tls_check(State(app): AppState, Query(q): Query<TlsCheckQ>) -> Response {
    let err = |status: StatusCode, error: &str, message: &str| {
        (status, Json(json!({"error": error, "message": message}))).into_response()
    };
    let domain = match q.domain.as_deref().map(|d| d.trim_end_matches('.').to_ascii_lowercase()) {
        Some(d) if !d.is_empty() => d,
        _ => return err(StatusCode::BAD_REQUEST, "InvalidRequest", "bad or missing domain query param"),
    };
    if public_host(&app).as_deref() == Some(domain.as_str()) {
        return Json(json!({"success": true})).into_response();
    }
    if app.handle_domains.under(&domain).is_none() {
        return err(StatusCode::BAD_REQUEST, "InvalidRequest", "handles are not provided on this domain");
    }
    match active_handle_did(&app, &domain).await {
        Ok(Some(_)) => Json(json!({"success": true})).into_response(),
        Ok(None) => err(StatusCode::NOT_FOUND, "NotFound", "handle not found for this domain"),
        Err(e) => e.into_response(),
    }
}

/// The document of our own did:web `--service-did`, so the DID we accept
/// service auth for resolves here. The reference PDS serves none; the shape
/// is the reference AppView's, with no verification method (the service
/// DID signs nothing).
async fn well_known_did_json(State(app): AppState) -> Response {
    let did = &app.jwt.service_did;
    if !did.starts_with("did:web:") {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }
    Json(service_did_doc(did, &app.public_url)).into_response()
}

pub(crate) fn service_did_doc(did: &str, public_url: &str) -> J {
    json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "service": [{"id": "#atproto_pds", "type": "AtprotoPersonalDataServer", "serviceEndpoint": public_url.trim_end_matches('/')}],
    })
}

/// HTTPS handle verification (reference well-known.ts): the Host is the
/// handle.
async fn well_known_atproto_did(State(app): AppState, headers: HeaderMap) -> Response {
    let host = headers.get(header::HOST).and_then(|v| v.to_str().ok()).unwrap_or("");
    let handle = match host.rsplit_once(':') {
        Some((h, port)) if port.bytes().all(|b| b.is_ascii_digit()) => h,
        _ => host,
    }
    .to_ascii_lowercase();
    let not_found = || (StatusCode::NOT_FOUND, "User not found").into_response();
    if app.handle_domains.under(&handle).is_none() {
        return not_found();
    }
    match active_handle_did(&app, &handle).await {
        Ok(Some(did)) => ([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], did).into_response(),
        Ok(None) => not_found(),
        Err(e) => e.into_response(),
    }
}

pub(super) fn did_doc(app: &App, acct: &Account) -> J {
    json!({
        "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1", "https://w3id.org/security/suites/secp256k1-2019/v1"],
        "id": acct.did,
        "alsoKnownAs": [format!("at://{}", acct.handle)],
        "verificationMethod": [{
            "id": format!("{}#atproto", acct.did),
            "type": "Multikey",
            "controller": acct.did,
            "publicKeyMultibase": acct.signing_pubkey,
        }],
        "service": [{"id": "#atproto_pds", "type": "AtprotoPersonalDataServer", "serviceEndpoint": app.public_url}],
    })
}

/// Whether the document generated here is the account's current one. It is
/// while the account is active here (every change of a registered DID goes
/// through this PDS). A deactivated account may have migrated away or not
/// arrived yet, so its DID resolves like any other. Unregistered local DIDs
/// (`--plc-mode unregistered`) have no other document.
pub(crate) fn serves_local_doc(app: &App, acct: &Account) -> bool {
    let deactivated = acct.extra.get("deactivatedAt").is_some_and(|v| !v.is_null());
    let resolvable = app.plc.is_some() || super::server::has_external_did(acct);
    // a did:plc that can change without us (a signed op handed out, a user
    // rotation key) is the directory's to describe, active or not
    let external_ops = app.plc.is_some() && has_plc_external(acct);
    !acct.signing_pubkey.is_empty() && !(deactivated && resolvable) && !external_ops
}

/// An active account whose did:plc may change elsewhere falls back to our
/// document when the directory can't be reached.
pub(crate) async fn account_did_doc(app: &App, acct: &Account) -> Result<Arc<J>, crate::did_resolver::ResolveError> {
    if serves_local_doc(app, acct) {
        return Ok(Arc::new(did_doc(app, acct)));
    }
    match app.did_resolver.resolve(&acct.did).await {
        Err(crate::did_resolver::ResolveError::Failed(..))
            if acct.status.is_none() && !acct.signing_pubkey.is_empty() =>
        {
            Ok(Arc::new(did_doc(app, acct)))
        }
        r => r,
    }
}

fn resolve_error(e: crate::did_resolver::ResolveError) -> XrpcError {
    use crate::did_resolver::ResolveError as E;
    match e {
        E::NotFound(did) | E::BadDid(did) => XrpcError::bad("DidNotFound", format!("DID not found: {did}")),
        E::Failed(..) => {
            XrpcError { status: StatusCode::BAD_GATEWAY, error: "UpstreamFailure".into(), message: e.to_string() }
        }
    }
}

#[derive(Deserialize)]
struct HandleQ {
    handle: String,
}

async fn resolve_handle(State(app): AppState, Query(q): Query<HandleQ>) -> XResult<Json<J>> {
    let handle = q.handle.to_ascii_lowercase();
    if !super::syntax::valid_handle(&handle) {
        return Err(XrpcError::bad("InvalidRequest", "Error: handle must be a valid handle"));
    }
    match resolve_any_handle(&app, &handle).await? {
        Some(did) => Ok(Json(json!({"did": did}))),
        // (the reference answers an unresolvable external handle with
        // InvalidRequest; a valid handle is never a parameter error here)
        None => Err(XrpcError::bad("HandleNotFound", "Unable to resolve handle")),
    }
}

/// Reference `serviceHandleDomains` check.
fn is_service_handle(app: &App, handle: &str) -> bool {
    app.handle_domains.served(handle).is_some()
}

/// Inactive accounts don't resolve (reference getAccount(handle)).
async fn local_handle_did(app: &App, handle: &str) -> XResult<Option<String>> {
    let Some(did) = app.resolve_handle(handle).await? else { return Ok(None) };
    let acct = super::server::account_if_exists(app, &did).await?;
    Ok(acct.is_some_and(|a| a.status.is_none() && a.handle == handle).then_some(did))
}

/// Other servers' handles resolve too: the Bluesky app resolves @-mention
/// facets through its PDS.
async fn resolve_any_handle(app: &App, handle: &str) -> XResult<Option<String>> {
    if let Some(did) = local_handle_did(app, handle).await? {
        return Ok(Some(did));
    }
    if is_service_handle(app, handle) {
        return Ok(None);
    }
    Ok(resolve_external_handle(app, handle).await)
}

const APPVIEW_RESOLVE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// The configured AppView's answer is final, as in the reference; without
/// one, or when it fails, the handle is resolved here. A dev server looks up
/// no arbitrary names.
pub(super) async fn resolve_external_handle(app: &App, handle: &str) -> Option<String> {
    if let Some((url, _)) = &app.config.appview {
        match appview_resolve_handle(url, handle).await {
            Ok(r) => return r,
            Err(e) => tracing::warn!(%handle, "AppView resolveHandle failed, resolving the handle here: {e}"),
        }
    }
    if app.config.dev_mode {
        return None;
    }
    dns_or_https_did(app, handle).await.filter(|d| super::syntax::valid_did(d))
}

/// DNS TXT `_atproto.<handle>`, then `https://<handle>/.well-known/atproto-did`
/// (reference HandleResolver).
async fn dns_or_https_did(app: &App, handle: &str) -> Option<String> {
    let txt = crate::handle_resolver::resolver(app.config.txt_resolver.as_ref());
    let http = async { fetch_well_known(app, handle).await.ok() };
    crate::handle_resolver::resolve(txt.as_ref(), handle, http).await
}

/// Guarded whatever `--dev-mode` says: the handle is the caller's input.
async fn fetch_well_known(app: &App, handle: &str) -> Result<String, String> {
    match &app.config.well_known_fetcher {
        Some(f) => f.0.fetch(handle).await,
        None => well_known_did(handle, false).await,
    }
}

/// Ok(None): the AppView answered that the handle doesn't resolve (4xx).
async fn appview_resolve_handle(base: &str, handle: &str) -> Result<Option<String>, String> {
    let url = format!("{}/xrpc/com.atproto.identity.resolveHandle", base.trim_end_matches('/'));
    let fetch = async {
        let r = crate::http::public().get(&url).query(&[("handle", handle)]).send().await.map_err(|e| e.to_string())?;
        let status = r.status();
        if status.is_client_error() {
            return Ok(None);
        }
        if !status.is_success() {
            return Err(format!("status {status}"));
        }
        let body = r.bytes().await.map_err(|e| e.to_string())?;
        if body.len() > 16 << 10 {
            return Err("response too large".into());
        }
        let j: J = serde_json::from_slice(&body).map_err(|e| e.to_string())?;
        match j["did"].as_str() {
            Some(d) if super::syntax::valid_did(d) => Ok(Some(d.to_string())),
            _ => Err("no valid did in the response".into()),
        }
    };
    tokio::time::timeout(APPVIEW_RESOLVE_TIMEOUT, fetch).await.map_err(|_| "timed out".to_string())?
}

/// In dev mode, where nothing external is looked up, a claim here suffices.
async fn handle_resolves_to(app: &App, handle: &str, did: &str) -> XResult<bool> {
    let service = is_service_handle(app, handle);
    if service || app.config.dev_mode {
        if app.resolve_handle(handle).await?.as_deref() == Some(did) {
            return Ok(true);
        }
        if service {
            return Ok(false);
        }
    }
    Ok(resolve_external_handle(app, handle).await.as_deref() == Some(did))
}

#[derive(Deserialize)]
struct DidQ {
    did: String,
}

async fn resolve_did(State(app): AppState, Query(q): Query<DidQ>) -> XResult<Json<J>> {
    if !super::syntax::valid_did(&q.did) {
        return Err(XrpcError::bad("InvalidRequest", "Error: did must be a valid did"));
    }
    let acct = super::server::account_if_exists(&app, &q.did)
        .await?
        .ok_or_else(|| XrpcError::bad("DidNotFound", format!("DID not found: {}", q.did)))?;
    let doc = account_did_doc(&app, &acct).await.map_err(resolve_error)?;
    Ok(Json(json!({"didDoc": doc})))
}

/// `did`'s handle when its document claims one that resolves back to it.
pub(crate) async fn verified_handle(app: &App, did: &str) -> Option<String> {
    let (_, info) = identity_info(app, did, false).await.ok()?;
    info["handle"].as_str().filter(|h| *h != "handle.invalid").map(String::from)
}

/// (the account, if hosted here; {did, handle, didDoc}) of anyone, so a
/// client can look up any identity through its PDS. The handle is
/// "handle.invalid" unless it resolves back to the DID. `fresh` skips the
/// resolver's cache.
async fn identity_info(app: &App, identifier: &str, fresh: bool) -> XResult<(Option<Account>, J)> {
    let bad_ident = || XrpcError::bad("InvalidRequest", "Error: identifier must be a valid at-identifier");
    let not_found = |h: &str| XrpcError::bad("HandleNotFound", format!("Unable to resolve handle: {h}"));
    let (did, by_handle) = if identifier.starts_with("did:") {
        if !super::syntax::valid_did(identifier) {
            return Err(bad_ident());
        }
        (identifier.to_string(), None)
    } else {
        let handle = identifier.to_ascii_lowercase();
        if !super::syntax::valid_handle(&handle) {
            return Err(bad_ident());
        }
        // a claim here names an account here (whatever its status)
        let did = match app.resolve_handle(&handle).await? {
            Some(d) => Some(d),
            None if is_service_handle(app, &handle) => None,
            None => resolve_external_handle(app, &handle).await,
        };
        (did.ok_or_else(|| not_found(&handle))?, Some(handle))
    };
    if let Some(acct) = super::server::account_if_exists(app, &did).await? {
        let valid = handle_resolves_to(app, &acct.handle, &acct.did).await?;
        let handle = if valid { acct.handle.clone() } else { "handle.invalid".to_string() };
        if fresh && !serves_local_doc(app, &acct) {
            app.did_resolver.invalidate(&acct.did);
        }
        let doc = account_did_doc(app, &acct).await.map_err(resolve_error)?;
        let info = json!({"did": acct.did, "handle": handle, "didDoc": doc});
        return Ok((Some(acct), info));
    }
    if let Some(h) = by_handle.as_deref().filter(|h| is_service_handle(app, h)) {
        // a stale claim under our domains: no account behind it
        return Err(not_found(h));
    }
    if fresh {
        app.did_resolver.invalidate(&did);
    }
    let doc = app.did_resolver.resolve(&did).await.map_err(resolve_error)?;
    let claimed = doc["alsoKnownAs"]
        .as_array()
        .and_then(|a| a.iter().filter_map(J::as_str).find_map(|h| h.strip_prefix("at://")))
        .map(str::to_ascii_lowercase);
    let verified = match (&claimed, &by_handle) {
        // resolved from the handle: the document must name it back
        (Some(c), Some(h)) => c == h,
        (Some(c), None) => super::syntax::valid_handle(c) && handle_resolves_to(app, c, &did).await?,
        (None, _) => false,
    };
    if let (Some(h), false) = (&by_handle, verified) {
        return Err(not_found(h));
    }
    let handle = match (verified, claimed) {
        (true, Some(c)) => c,
        _ => "handle.invalid".to_string(),
    };
    Ok((None, json!({"did": did, "handle": handle, "didDoc": *doc})))
}

#[derive(Deserialize)]
struct IdentifierQ {
    identifier: String,
}

async fn resolve_identity(State(app): AppState, Query(q): Query<IdentifierQ>) -> XResult<Json<J>> {
    Ok(Json(identity_info(&app, &q.identifier, false).await?.1))
}

/// Emits `#identity` only for the account itself or an admin.
async fn refresh_identity(
    State(app): AppState,
    MaybeAuth(creds): MaybeAuth,
    Json(inp): Json<IdentifierQ>,
) -> XResult<Json<J>> {
    let (acct, info) = identity_info(&app, &inp.identifier, true).await?;
    let Some(acct) = acct else { return Ok(Json(info)) };
    let may_emit = match &creds {
        Some(Credentials::Admin { .. }) => true,
        Some(c) => c.did() == Some(acct.did.as_str()) && c.allows_identity("*"),
        None => false,
    };
    if may_emit {
        // writes nothing: the worker re-announces its current account (a
        // snapshot sent from here could undo a concurrent takedown)
        app.mutate_account(&acct.did, true, false, false, |a| Ok(a.status.as_deref() != Some("takendown"))).await?;
    }
    Ok(Json(info))
}

#[derive(Deserialize)]
struct UpdateHandleIn {
    handle: String,
}

/// A handle under our domain follows createAccount's rules; an external one
/// must resolve to `did` (skipped in dev mode).
pub(super) async fn check_new_handle(app: &App, handle: &str, did: &str) -> XResult<()> {
    // syntax + disallowed TLDs, then the slur filter (reference order)
    super::server::normalize_handle(handle)?;
    super::server::ensure_no_slur(handle)?;
    if app.handle_domains.under(handle).is_some() {
        // same rules as createAccount, reserved names included
        return super::server::ensure_service_handle(app, handle, false);
    }
    if app.config.dev_mode {
        return Ok(());
    }
    if dns_or_https_did(app, handle).await.as_deref() != Some(did) {
        return Err(XrpcError::bad("InvalidRequest", "External handle did not resolve to DID"));
    }
    Ok(())
}

/// SSRF-guarded: outside dev mode a handle resolving to a private or
/// loopback address is refused before connecting.
async fn well_known_did(handle: &str, dev_mode: bool) -> Result<String, String> {
    use futures::StreamExt;
    const MAX_BYTES: usize = 2048;
    let url = format!("https://{handle}/.well-known/atproto-did");
    let fetch = async {
        let r = crate::http::guarded(dev_mode).get(&url)?.send().await.map_err(|e| format!("{e:?}"))?;
        if !r.status().is_success() {
            return Err(format!("status {}", r.status()));
        }
        let mut buf = Vec::new();
        let mut s = r.bytes_stream();
        while let Some(c) = s.next().await {
            buf.extend_from_slice(&c.map_err(|e| e.to_string())?);
            if buf.len() > MAX_BYTES {
                return Err("response too large".into());
            }
        }
        let body = String::from_utf8_lossy(&buf);
        Ok(body.lines().next().unwrap_or("").trim().to_string())
    };
    tokio::time::timeout(crate::handle_resolver::TIMEOUT, fetch).await.map_err(|_| "timed out".to_string())?
}

async fn update_handle(
    State(app): AppState,
    Auth(creds): Auth,
    Json(inp): Json<UpdateHandleIn>,
) -> XResult<StatusCode> {
    creds.need_identity("handle")?;
    let did = creds.user_did()?.to_string();
    {
        use crate::ratelimit::*;
        check(&[&UPDATE_HANDLE_5MIN, &UPDATE_HANDLE_DAY], &did, 1)?;
    }
    // early refusal; set_handle re-checks against the worker's state
    let acct = app.account(&did).await?;
    if super::server::is_takendown_account(&acct) {
        return Err(super::takedown_error());
    }
    let handle = inp.handle.trim().to_ascii_lowercase();
    if handle != acct.handle {
        // the slow part (external .well-known proof) runs before the op
        check_new_handle(&app, &handle, &did).await?;
    }
    // same handle: the reference still re-announces it
    set_handle(&app, &did, &handle, true).await?;
    Ok(StatusCode::OK)
}

#[derive(Deserialize)]
struct CheckHandleQ {
    /// Not `handle`: forwarding routes a query by its `handle`, which would
    /// send the call to whichever node owns the account holding it now.
    name: String,
}

/// Why `check_new_handle` would refuse `handle` on syntax or policy, in
/// words for the account page: (status, message).
fn handle_problem(app: &App, handle: &str) -> Option<(&'static str, String)> {
    let invalid = |m: &str| Some(("invalid", m.to_string()));
    if handle.is_empty() {
        return invalid("Enter a handle.");
    }
    let service = app.handle_domains.under(handle).is_some();
    if let Some((front, _)) = app.handle_domains.under(handle) {
        if front.contains('.') {
            return invalid(
                "A name on this server can't contain dots. To use a domain you own, choose \"Your own domain\".",
            );
        }
        if !front.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
            return invalid("Use only letters, numbers and hyphens.");
        }
        if front.starts_with('-') || front.ends_with('-') {
            return invalid("A name can't start or end with a hyphen.");
        }
        if front.len() < 3 {
            return invalid("That's too short. Use at least 3 characters.");
        }
        if front.len() > 18 {
            return invalid("That's too long. Use at most 18 characters.");
        }
    }
    if let Err(e) = super::server::normalize_handle(handle) {
        return if e.message.contains("TLD") {
            let tld = handle.rsplit('.').next().unwrap_or("");
            invalid(&format!("Domains ending in .{tld} can't be used as handles."))
        } else {
            invalid("That doesn't look like a domain. It should look like alice.com or me.alice.com.")
        };
    }
    if super::server::ensure_no_slur(handle).is_err() {
        return invalid("That name isn't allowed. Try another.");
    }
    if service {
        if let Err(e) = super::server::ensure_service_handle(app, handle, false) {
            return Some(match e.error.as_str() {
                "HandleNotAvailable" => ("reserved", "That name is reserved on this server. Try another.".into()),
                _ => ("invalid", e.message),
            });
        }
    }
    None
}

/// A failed `.well-known` fetch, for people: (result, detail).
fn well_known_failure(e: &str) -> (&'static str, &'static str) {
    if e.contains("non-unicast") || e.contains("public unicast address") {
        ("refused", "That domain points at a private address, so it can't be checked from here.")
    } else if e.starts_with("status ") {
        ("none", "The file isn't there yet (the site answered, but not with the file).")
    } else if e.contains("timed out") {
        ("none", "The site took too long to answer.")
    } else {
        ("none", "We couldn't reach the site over HTTPS.")
    }
}

/// The account page's check before updateHandle. A name under the handle
/// domain: is it free? A domain of the caller's: does DNS or HTTPS prove
/// the caller's DID, the same way updateHandle will check it (DNS first)?
async fn check_handle(State(app): AppState, Auth(creds): Auth, Query(q): Query<CheckHandleQ>) -> XResult<Json<J>> {
    use crate::handle_resolver::DnsAnswer;
    creds.need_identity("handle")?;
    let did = creds.user_did()?.to_string();
    {
        use crate::ratelimit::*;
        check(&[&CHECK_HANDLE_5MIN, &CHECK_HANDLE_DAY], &did, 1)?;
    }
    let acct = app.account(&did).await?;
    let handle = q.name.trim().trim_start_matches('@').trim_end_matches('.').to_ascii_lowercase();
    let service = app.handle_domains.under(&handle).is_some();
    let kind = if service { "service" } else { "external" };
    let base = |status: &str, message: Option<String>| {
        crate::metrics::HANDLE_CHECKS.with_label_values(&[kind, status]).inc();
        json!({"handle": handle, "kind": kind, "status": status, "message": message, "proofRequired": !app.config.dev_mode})
    };
    if let Some((status, message)) = handle_problem(&app, &handle) {
        return Ok(Json(base(status, Some(message))));
    }
    if handle == acct.handle {
        return Ok(Json(base("current", Some("That's already your handle.".into()))));
    }
    if app.resolve_handle(&handle).await?.is_some_and(|holder| holder != did) {
        return Ok(Json(base("taken", Some("Another account on this server already has that handle.".into()))));
    }
    if service {
        return Ok(Json(base("available", None)));
    }
    let txt = crate::handle_resolver::resolver(app.config.txt_resolver.as_ref());
    let (dns, http) =
        tokio::join!(crate::handle_resolver::lookup_dns(txt.as_ref(), &handle), fetch_well_known(&app, &handle));
    let (dns_result, dns_did) = match &dns {
        DnsAnswer::One(d) if *d == did => ("match", Some(d.as_str())),
        DnsAnswer::One(d) => ("other", Some(d.as_str())),
        DnsAnswer::Several => ("several", None),
        DnsAnswer::Nothing => ("none", None),
    };
    let (http_result, http_did, http_detail) = match &http {
        Ok(d) if *d == did => ("match", Some(d.as_str()), None),
        Ok(d) if d.starts_with("did:") => ("other", Some(d.as_str()), None),
        Ok(_) => ("none", None, Some("The file is there but doesn't hold a DID.")),
        Err(e) => {
            let (r, detail) = well_known_failure(e);
            (r, None, Some(detail))
        }
    };
    // updateHandle takes DNS's answer whenever there is one
    let method = match (dns_result, http_result) {
        ("match", _) => Some("dns"),
        ("other", _) => None,
        (_, "match") => Some("http"),
        _ => None,
    };
    let mut out = base(if method.is_some() { "verified" } else { "unverified" }, None);
    out["method"] = json!(method);
    out["dns"] = json!({"result": dns_result, "did": dns_did});
    out["http"] = json!({"result": http_result, "did": http_did, "detail": http_detail});
    Ok(Json(out))
}

/// Moves the account to the already-validated `handle` and emits #identity.
/// Global uniqueness is a conditional create of handle/{handle}; one already
/// holding our DID is a retry of an interrupted update. `user`: the
/// account's own request, refused while taken down (admins may rename).
pub(super) async fn set_handle(app: &App, did: &str, handle: &str, user: bool) -> XResult<()> {
    // only decides whether to claim; the op re-checks against current state
    let read = app.account(did).await?.handle;
    let claimed = handle != read;
    if claimed && !super::server::claim_handle(app, handle, did).await? {
        return Err(XrpcError::bad("HandleNotAvailable", format!("Handle already taken: {handle}")));
    }
    // The DID document first (reference AccountManager.updateHandle), so a
    // failure changes nothing here; PLC updated and the local swap failing
    // is fixed by retrying (the PLC step is then a no-op).
    if let Err(e) = update_did_doc_handle(app, did, handle).await {
        if claimed {
            release_unless_current(app, did, handle).await;
        }
        return Err(e);
    }
    let h = handle.to_string();
    let res = app
        .mutate_account(did, true, false, false, move |a| {
            if user && super::server::is_takendown_account(a) {
                return Err(super::takedown_error());
            }
            if a.handle != h && !claimed {
                // renamed since the read above: we hold no claim on `h`
                return Err(XrpcError::bad("InvalidRequest", "Handle changed concurrently, retry"));
            }
            a.handle = h;
            Ok(true)
        })
        .await;
    match res {
        Ok((before, _)) => {
            if before.handle != handle {
                super::server::release_handle(app, &before.handle, did).await;
            }
            // a concurrent update of the same DID that failed may have
            // released the claim we now stand on: take it back (a no-op
            // when it's still ours)
            if claimed && !super::server::claim_handle(app, handle, did).await.unwrap_or(true) {
                tracing::error!(%did, %handle, "handle claim lost to another account during an update");
            }
            reconcile_did_doc_handle(app, did).await;
            Ok(())
        }
        Err(e) => {
            // keep the claim if a concurrent update moved us onto it anyway
            if claimed {
                release_unless_current(app, did, handle).await;
            }
            reconcile_did_doc_handle(app, did).await;
            Err(e)
        }
    }
}

/// A concurrent update of the same DID to the same handle may have
/// succeeded. An unreadable account keeps the claim (stale claims are taken
/// over after a grace period: `server::claim_handle`).
async fn release_unless_current(app: &App, did: &str, handle: &str) {
    if super::internal::account_anywhere(app, did).await.is_ok_and(|a| a.handle != handle) {
        super::server::release_handle(app, handle, did).await;
    }
}

/// Two updates of one DID can finish their PLC and local steps in opposite
/// orders. Every update ends with this, which re-reads the account after
/// each PLC step until they agree, so the last update to finish leaves them
/// agreeing whichever node ran it. Failures are only logged: the next
/// update or a refreshIdentity fixes them.
async fn reconcile_did_doc_handle(app: &App, did: &str) {
    let Some(plc) = &app.plc else { return };
    if !did.starts_with("did:plc:") {
        return;
    }
    for _ in 0..3 {
        let Ok(before) = super::internal::account_anywhere(app, did).await else { return };
        match plc.update_handle(did, &before.handle).await {
            Ok(false) => return,
            Ok(true) => {
                app.did_resolver.invalidate(did);
                tracing::info!(%did, handle = %before.handle, "PLC handle reconciled with the account's");
            }
            Err(e) => {
                tracing::warn!(%did, "reconciling the PLC handle: {e}");
                return;
            }
        }
        match super::internal::account_anywhere(app, did).await {
            Ok(a) if a.handle == before.handle => return,
            Ok(_) => continue,
            Err(_) => return,
        }
    }
}

/// A did:web must already name the handle in its document.
async fn update_did_doc_handle(app: &App, did: &str, handle: &str) -> XResult<()> {
    let Some(plc) = &app.plc else { return Ok(()) };
    if did.starts_with("did:plc:") {
        plc.update_handle(did, handle).await?;
    } else {
        app.did_resolver.invalidate(did);
        let doc = app.did_resolver.resolve(did).await.map_err(|e| XrpcError::bad("InvalidRequest", e.to_string()))?;
        let at =
            doc["alsoKnownAs"].as_array().and_then(|a| a.iter().filter_map(J::as_str).find(|h| h.starts_with("at://")));
        if at != Some(format!("at://{handle}").as_str()) {
            return Err(XrpcError::bad("InvalidRequest", "DID is not properly configured for handle"));
        }
    }
    app.did_resolver.invalidate(did);
    Ok(())
}

async fn get_recommended_did_credentials(State(app): AppState, Auth(creds): Auth) -> XResult<Json<J>> {
    let acct = app.account(creds.user_did()?).await?;
    Ok(Json(json!({
        "alsoKnownAs": [format!("at://{}", acct.handle)],
        "verificationMethods": {"atproto": format!("did:key:{}", acct.signing_pubkey)},
        // [server recovery key?, server rotation key]; none when PLC
        // registration is off (no rotation key here)
        "rotationKeys": app.plc.as_ref().map(|p| p.recommended_rotation_keys()).unwrap_or_default(),
        "services": {"atproto_pds": {"type": "AtprotoPersonalDataServer", "endpoint": app.public_url}},
    })))
}

fn plc_service(app: &App) -> XResult<&Arc<crate::plc::Plc>> {
    app.plc.as_ref().ok_or_else(|| XrpcError {
        status: StatusCode::NOT_IMPLEMENTED,
        error: "MethodNotImplemented".into(),
        message:
            "PLC operations are not supported: PLC registration is off on this PDS (--plc-mode unregistered, dev only)"
                .into(),
    })
}

/// Reference ACCESS_FULL plus taken-down sessions; OAuth needs `identity:*`.
fn plc_signer(creds: &Credentials) -> XResult<String> {
    match creds {
        Credentials::Session { did } | Credentials::Takendown { did } => Ok(did.clone()),
        Credentials::OAuth { did, .. } => {
            creds.need_identity("*")?;
            Ok(did.clone())
        }
        Credentials::AppPassword { .. } => Err(XrpcError {
            status: StatusCode::BAD_REQUEST,
            error: "InvalidToken".into(),
            message: "Bad token scope".into(),
        }),
        Credentials::Admin { .. }
        | Credentials::ModService { .. }
        | Credentials::UserServiceAuth { .. }
        | Credentials::SpaceCredential { .. } => Err(XrpcError::auth("user credentials required")),
    }
}

/// The caller's current PLC data, for a client composing a
/// signPlcOperation that keeps what is there (the account page's recovery
/// keys), plus which rotation keys are this server's and its operator's.
async fn get_plc_data(State(app): AppState, Auth(creds): Auth) -> XResult<Json<J>> {
    let plc = plc_service(&app)?.clone();
    let did = plc_signer(&creds)?;
    if !did.starts_with("did:plc:") {
        return Err(XrpcError::bad("InvalidRequest", format!("not a did:plc: {did}")));
    }
    let data = plc.client.document_data(&did).await?;
    Ok(Json(json!({
        "did": did,
        "rotationKeys": data["rotationKeys"],
        "verificationMethods": data["verificationMethods"],
        "alsoKnownAs": data["alsoKnownAs"],
        "services": data["services"],
        "serverKeys": plc.server_did_keys(),
        "recoveryKey": plc.recovery_did_key(),
        "recommendedRotationKeys": plc.recommended_rotation_keys(),
    })))
}

/// A hosted account's PLC audit log, for the account backup: the account
/// page's CSP only allows this origin, and the browser has no other way to
/// learn which directory this server uses. Accounts here only (any status),
/// so it is no open proxy.
async fn get_plc_audit_log(State(app): AppState, Query(q): Query<DidQ>) -> XResult<Json<J>> {
    if !crate::plc::valid_plc_did(&q.did) {
        return Err(XrpcError::bad("InvalidRequest", format!("not a did:plc: {}", q.did)));
    }
    if super::server::account_if_exists(&app, &q.did).await?.is_none() {
        return Err(XrpcError::bad("DidNotFound", format!("DID not found: {}", q.did)));
    }
    let client = match &app.plc {
        Some(p) => p.client.clone(),
        None => crate::plc::PlcClient::new(&app.config.plc_url),
    };
    let log = client.audit_log(&q.did).await.map_err(|e| match e {
        crate::plc::PlcError::NotFound(_) => {
            XrpcError::bad("DidNotFound", format!("{} is not in the PLC directory", q.did))
        }
        e => e.into(),
    })?;
    Ok(Json(json!({"did": q.did, "log": log})))
}

/// Deactivated and taken-down accounts too.
async fn request_plc_operation_signature(State(app): AppState, Auth(creds): Auth) -> XResult<StatusCode> {
    plc_service(&app)?;
    let did = plc_signer(&creds)?;
    {
        use crate::ratelimit::*;
        check(&[&REQUEST_PLC_OPERATION_SIGNATURE_DAY, &REQUEST_PLC_OPERATION_SIGNATURE_HOUR], &did, 1)?;
    }
    let acct = app.account(&did).await.map_err(|_| XrpcError::bad("InvalidRequest", "account not found"))?;
    let email =
        acct.email.clone().ok_or_else(|| XrpcError::bad("InvalidRequest", "account does not have an email address"))?;
    let permit = super::server::mail_permit(&app, Some(&did), &email, "plc_operation", true).await?;
    let token = super::server::create_email_token(&app, &did, "plc_operation").await?;
    super::server::deliver(&app, permit, &email, crate::mail::Email::PlcOperation { token: &token });
    Ok(StatusCode::OK)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignPlcIn {
    token: Option<String>,
    rotation_keys: Option<J>,
    also_known_as: Option<J>,
    verification_methods: Option<J>,
    services: Option<J>,
}

/// Not submitted: the client sends it to the PDS that will host the account
/// (migration out) or to submitPlcOperation here.
async fn sign_plc_operation(State(app): AppState, Auth(creds): Auth, Json(inp): Json<SignPlcIn>) -> XResult<Json<J>> {
    let plc = plc_service(&app)?.clone();
    let did = plc_signer(&creds)?;
    let token =
        inp.token.as_deref().filter(|t| !t.is_empty()).ok_or_else(|| {
            XrpcError::bad("InvalidRequest", "email confirmation token required to sign PLC operations")
        })?;
    super::server::assert_email_token(&app, &did, "plc_operation", token).await?;
    if !did.starts_with("did:plc:") {
        return Err(XrpcError::bad("InvalidRequest", format!("not a did:plc: {did}")));
    }
    let last = plc.last_op(&did).await?;
    // (the reference casts the requested fields without checking them; an
    // op of the wrong shape is refused here rather than signed)
    let operation = plc.update_op(&last, |m| {
        for (k, v) in [
            ("rotationKeys", inp.rotation_keys),
            ("alsoKnownAs", inp.also_known_as),
            ("verificationMethods", inp.verification_methods),
            ("services", inp.services),
        ] {
            if let Some(v) = v {
                m.insert(k.into(), v);
            }
        }
        Ok(())
    })?;
    // the op may be submitted by anyone: this DID can now change without us
    mark_plc_external(&app, &did).await?;
    // consumed only once the op is made (reference: deleteEmailToken last),
    // so a directory outage doesn't burn the emailed token
    super::server::delete_email_tokens(&app, &did, &["plc_operation"]).await?;
    Ok(Json(json!({"operation": operation})))
}

/// Account extension flag: this did:plc may change without going through
/// this PDS, so its document is the directory's ([`serves_local_doc`]).
pub(super) const PLC_EXTERNAL: &str = "plcExternalOps";

fn has_plc_external(a: &Account) -> bool {
    a.extra.get(PLC_EXTERNAL).and_then(J::as_bool).unwrap_or(false)
}

async fn mark_plc_external(app: &App, did: &str) -> XResult<()> {
    app.mutate_account(did, false, false, false, |a| {
        if has_plc_external(a) {
            return Ok(false);
        }
        super::server::set_extra(a, PLC_EXTERNAL, json!(true));
        Ok(true)
    })
    .await?;
    app.did_resolver.invalidate(did);
    Ok(())
}

#[derive(Deserialize)]
struct SubmitPlcIn {
    operation: J,
}

/// The reference's submitPlcOperation checks, then #identity.
async fn submit_plc_operation(
    State(app): AppState,
    Auth(creds): Auth,
    Json(inp): Json<SubmitPlcIn>,
) -> XResult<StatusCode> {
    creds.need_identity("*")?;
    let did = creds.user_did()?.to_string();
    let plc = plc_service(&app)?.clone();
    let op = inp.operation;
    let bad = |m: &str| XrpcError::bad("InvalidRequest", m);
    if crate::plc::op_type(&op, true).ok() != Some(crate::plc::OpType::Operation) {
        return Err(bad("Invalid operation"));
    }
    if !op["rotationKeys"].as_array().is_some_and(|a| a.iter().any(|k| k == plc.rotation_did_key())) {
        return Err(bad("Rotation keys do not include server's rotation key"));
    }
    let pds = &op["services"]["atproto_pds"];
    if pds["type"] != "AtprotoPersonalDataServer" {
        return Err(bad("Incorrect type on atproto_pds service"));
    }
    if pds["endpoint"] != app.public_url.as_str() {
        return Err(bad("Incorrect endpoint on atproto_pds service"));
    }
    let acct = app.account(&did).await?;
    // a signing-key rotation in flight: the op names the old key, and
    // submitting it after the directory took the new one would point the
    // DID back at a key the repo is no longer signed with
    if acct.pending_signing_key.is_some() {
        return Err(bad("A signing key rotation is in progress, retry when it completes"));
    }
    if op["verificationMethods"]["atproto"] != format!("did:key:{}", acct.signing_pubkey).as_str() {
        return Err(bad("Incorrect signing key"));
    }
    if !acct.handle.is_empty() && op["alsoKnownAs"].get(0) != Some(&J::String(format!("at://{}", acct.handle))) {
        return Err(bad("Incorrect handle in alsoKnownAs"));
    }
    if !did.starts_with("did:plc:") {
        return Err(bad(&format!("not a did:plc: {did}")));
    }
    plc.client.send(&did, &op, "submit").await?;
    app.did_resolver.invalidate(&did);
    let foreign_keys =
        op["rotationKeys"].as_array().is_some_and(|a| a.iter().filter_map(J::as_str).any(|k| !plc.is_operator_key(k)));
    if foreign_keys {
        mark_plc_external(&app, &did).await?;
    }
    // #identity only (writes nothing); not for a taken-down account
    app.mutate_account(&did, true, false, false, |a| Ok(a.status.as_deref() != Some("takendown"))).await?;
    Ok(StatusCode::OK)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn well_known_check_refuses_private_hosts() {
        // refused before any connection: loopback names and IP literals
        // (valid handles can't be IP literals, but the fetch doesn't rely on it)
        for h in ["localhost", "a.localhost", "127.0.0.1", "169.254.169.254", "2130706433", "[::1]"] {
            let e = well_known_did(h, false).await.unwrap_err();
            assert!(e.contains("non-unicast"), "{h}: {e}");
            assert_eq!(well_known_failure(&e).0, "refused", "{h}: {e}");
        }
    }

    #[test]
    fn well_known_failures_in_words() {
        assert_eq!(well_known_failure("a.test did not resolve to a public unicast address").0, "refused");
        assert_eq!(well_known_failure("status 404 Not Found").0, "none");
        assert_eq!(well_known_failure("timed out").0, "none");
    }
}
