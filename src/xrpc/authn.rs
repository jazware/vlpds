//! Request authentication: `Auth` dispatches on the Authorization scheme
//! (Bearer session or service JWT, DPoP OAuth, Basic admin) and yields
//! `Credentials`, whose `allows_*` methods are the one place permission
//! checks (OAuth scopes, app-password limits) happen.

use super::*;
use crate::oauth::scopes::{SpaceAccess, SpaceTarget};
use crate::space::token::{self, TokenType};
use axum::extract::FromRequestParts;
use axum::http::request::Parts;

#[derive(Clone, Debug)]
pub enum Credentials {
    Session {
        did: String,
    },
    /// Privileged app passwords may use DMs. A scoped one (vlpds) is also
    /// held to `scopes` as an OAuth token is: it gets what both the app
    /// password and the scopes allow.
    AppPassword {
        did: String,
        privileged: bool,
        scopes: Option<super::oauth::ScopeSet>,
    },
    OAuth {
        did: String,
        client_id: String,
        scopes: super::oauth::ScopeSet,
    },
    /// The admin token, or (`operator`) a login the admin listener's proxy
    /// named ([`crate::admin_proxy`]), which the audit log records.
    Admin {
        operator: Option<Arc<str>>,
    },
    /// A taken-down account's session (`allowTakendown`), accepted only by
    /// [`TAKENDOWN_METHODS`].
    Takendown {
        did: String,
    },
    /// The `--mod-service-did` service on [`MODERATOR_METHODS`] or
    /// getPreferences. `iss` is the DID or `DID#atproto_labeler`.
    ModService {
        iss: String,
    },
    /// A local user's own service JWT (reference `userServiceAuth`), only on
    /// [`USER_SERVICE_AUTH_METHODS`].
    UserServiceAuth {
        did: String,
    },
    /// A space credential (`Authorization: Atproto-Space`), taken by the
    /// space read methods only ([`SpaceAuth`]). It names a syncer, never an
    /// account, so it is no one's own repo and grants nothing else.
    SpaceCredential {
        space: String,
        iss: String,
        jti: String,
        exp: i64,
        cnf_kid: String,
        audience: String,
    },
}

/// Methods that also take a user's service JWT (reference
/// `authorizationOrUserServiceAuth`): the Bluesky app hands an uploadBlob
/// token from getServiceAuth to the video service, which uploads the
/// processed video here. createAccount verifies its own service auth.
pub const USER_SERVICE_AUTH_METHODS: &[&str] = &["com.atproto.repo.uploadBlob"];

/// Admin methods the moderation service may call (reference
/// `authVerifier.moderator`): a Bearer token on these is only ever a
/// moderation-service JWT. Other admin methods take Basic auth only.
pub const MODERATOR_METHODS: &[&str] = &[
    "com.atproto.admin.disableAccountInvites",
    "com.atproto.admin.disableInviteCodes",
    "com.atproto.admin.enableAccountInvites",
    "com.atproto.admin.getAccountInfo",
    "com.atproto.admin.getAccountInfos",
    "com.atproto.admin.getInviteCodes",
    "com.atproto.admin.getSubjectStatus",
    "com.atproto.admin.sendEmail",
    "com.atproto.admin.updateSubjectStatus",
    "vlpds.admin.getSpaceRecord",
    "vlpds.admin.getSpaceRepo",
    "vlpds.admin.listSpaceRecords",
];

/// Reference `authorizationOrModService`.
const MOD_SERVICE_OR_USER_METHODS: &[&str] = &["app.bsky.actor.getPreferences"];

/// Reference `additional: [AuthScope.Takendown]`.
pub const TAKENDOWN_METHODS: &[&str] = &[
    "app.bsky.actor.getPreferences",
    "com.atproto.identity.requestPlcOperationSignature",
    "com.atproto.identity.signPlcOperation",
    "com.atproto.moderation.createReport",
    "com.atproto.server.deactivateAccount",
    "com.atproto.server.getServiceAuth",
    "com.atproto.sync.getBlob",
    "com.atproto.sync.getRepo",
    "com.atproto.sync.listBlobs",
    "tools.ozone.inbox.appealActionedSubject",
];

impl Credentials {
    pub fn did(&self) -> Option<&str> {
        match self {
            Credentials::Session { did }
            | Credentials::AppPassword { did, .. }
            | Credentials::OAuth { did, .. }
            | Credentials::Takendown { did }
            | Credentials::UserServiceAuth { did } => Some(did),
            Credentials::Admin { .. } | Credentials::ModService { .. } | Credentials::SpaceCredential { .. } => None,
        }
    }

    /// The proxy-named operator of an admin request.
    pub fn operator(&self) -> Option<&str> {
        match self {
            Credentials::Admin { operator } => operator.as_deref(),
            _ => None,
        }
    }

    pub fn user_did(&self) -> XResult<&str> {
        self.did().ok_or_else(|| XrpcError::auth("user credentials required"))
    }

    /// A scoped app password's scopes.
    pub fn app_pass_scopes(&self) -> Option<&super::oauth::ScopeSet> {
        match self {
            Credentials::AppPassword { scopes, .. } => scopes.as_ref(),
            _ => None,
        }
    }

    fn scoped(&self, f: impl FnOnce(&super::oauth::ScopeSet) -> bool) -> bool {
        self.app_pass_scopes().is_none_or(f)
    }

    /// action: "create" | "update" | "delete"
    pub fn allows_repo(&self, collection: &str, action: &str) -> bool {
        self.base_repo(collection, action) && self.scoped(|s| s.allows_repo(collection, action))
    }

    fn base_repo(&self, collection: &str, action: &str) -> bool {
        match self {
            Credentials::OAuth { scopes, .. } => scopes.allows_repo(collection, action),
            Credentials::Takendown { .. }
            | Credentials::ModService { .. }
            | Credentials::UserServiceAuth { .. }
            | Credentials::SpaceCredential { .. } => false,
            _ => true,
        }
    }

    pub fn allows_rpc(&self, lxm: &str, aud: &str) -> bool {
        self.base_rpc(lxm, aud) && self.scoped(|s| s.allows_rpc(lxm, aud))
    }

    fn base_rpc(&self, lxm: &str, aud: &str) -> bool {
        match self {
            Credentials::OAuth { scopes, .. } => scopes.allows_rpc(lxm, aud),
            Credentials::AppPassword { privileged, .. } => {
                *privileged || !lxm.get(..10).is_some_and(|p| p.eq_ignore_ascii_case("chat.bsky."))
            }
            Credentials::ModService { .. }
            | Credentials::UserServiceAuth { .. }
            | Credentials::SpaceCredential { .. } => false,
            _ => true,
        }
    }

    pub fn allows_blob(&self, mime: &str) -> bool {
        self.base_blob(mime) && self.scoped(|s| s.allows_blob(mime))
    }

    fn base_blob(&self, mime: &str) -> bool {
        match self {
            Credentials::OAuth { scopes, .. } => scopes.allows_blob(mime),
            Credentials::Takendown { .. } | Credentials::ModService { .. } | Credentials::SpaceCredential { .. } => {
                false
            }
            _ => true,
        }
    }

    /// action: "read" | "manage"
    pub fn allows_account(&self, attr: &str, action: &str) -> bool {
        self.base_account(attr, action) && self.scoped(|s| s.allows_account(attr, action))
    }

    fn base_account(&self, attr: &str, action: &str) -> bool {
        match self {
            Credentials::OAuth { scopes, .. } => scopes.allows_account(attr, action),
            Credentials::AppPassword { .. } => action == "read",
            Credentials::Takendown { .. }
            | Credentials::ModService { .. }
            | Credentials::UserServiceAuth { .. }
            | Credentials::SpaceCredential { .. } => false,
            _ => true,
        }
    }

    pub fn allows_identity(&self, attr: &str) -> bool {
        match self {
            Credentials::OAuth { scopes, .. } => scopes.allows_identity(attr),
            Credentials::AppPassword { .. }
            | Credentials::Takendown { .. }
            | Credentials::ModService { .. }
            | Credentials::UserServiceAuth { .. }
            | Credentials::SpaceCredential { .. } => false,
            _ => true,
        }
    }

    /// Space data is OAuth-only: an app password, scoped or not, a session
    /// and every other credential get none (a vlpds divergence: the
    /// reference lets legacy auth read and write space records).
    pub fn allows_space(&self, t: &SpaceTarget, access: SpaceAccess) -> bool {
        match self {
            Credentials::OAuth { scopes, .. } => scopes.allows_space(t, access),
            _ => false,
        }
    }

    pub fn need_space(&self, t: &SpaceTarget, access: SpaceAccess) -> XResult<()> {
        match self {
            _ if self.allows_space(t, access) => Ok(()),
            Credentials::OAuth { .. } => {
                Err(scope_refused("oauth", &crate::oauth::scopes::SpacePermission::needed_for(t, access)))
            }
            _ => self.require(false),
        }
    }

    /// OAuth refusals name the scope that would grant it (reference
    /// `ScopeMissingError`), and so do a scoped app password's when its
    /// scopes are all that is missing (`base`: the app password allows it).
    fn require_scope(&self, base: bool, ok: bool, scope: impl FnOnce() -> String) -> XResult<()> {
        if ok {
            return Ok(());
        }
        match self {
            Credentials::OAuth { .. } => Err(scope_refused("oauth", &scope())),
            Credentials::AppPassword { scopes: Some(_), .. } if base => Err(scope_refused("app_password", &scope())),
            _ => self.require(false),
        }
    }

    pub fn need_repo(&self, collection: &str, action: &str) -> XResult<()> {
        self.require_scope(self.base_repo(collection, action), self.allows_repo(collection, action), || {
            format!("repo:{collection}?action={action}")
        })
    }

    pub fn need_rpc(&self, lxm: &str, aud: &str) -> XResult<()> {
        let base = self.base_rpc(lxm, aud);
        // the reference pipethrough's answer to a non-privileged app password
        if matches!(self, Credentials::AppPassword { .. }) && !base {
            return Err(XrpcError::bad("InvalidToken", "Bad token method"));
        }
        self.require_scope(base, self.allows_rpc(lxm, aud), || format!("rpc:{lxm}?aud={}", aud.replace('#', "%23")))
    }

    pub fn need_blob(&self, mime: &str) -> XResult<()> {
        self.require_scope(self.base_blob(mime), self.allows_blob(mime), || format!("blob:{mime}"))
    }

    pub fn need_account(&self, attr: &str, action: &str) -> XResult<()> {
        self.require_scope(self.base_account(attr, action), self.allows_account(attr, action), || {
            account_scope(attr, action)
        })
    }

    pub fn need_identity(&self, attr: &str) -> XResult<()> {
        let ok = self.allows_identity(attr);
        self.require_scope(ok, ok, || format!("identity:{attr}"))
    }

    fn require(&self, ok: bool) -> XResult<()> {
        if ok {
            Ok(())
        } else {
            Err(XrpcError {
                status: StatusCode::FORBIDDEN,
                error: "InsufficientScope".into(),
                message: "credentials do not grant this action".into(),
            })
        }
    }
}

/// `credential` labels `vlpds_scope_rejections_total`.
pub fn scope_refused(credential: &str, scope: &str) -> XrpcError {
    crate::metrics::scope_rejected(credential, scope);
    XrpcError {
        status: StatusCode::FORBIDDEN,
        error: "ScopeMissingError".into(),
        message: format!("Missing required scope \"{scope}\""),
    }
}

pub fn account_scope(attr: &str, action: &str) -> String {
    match action {
        "read" => format!("account:{attr}"),
        _ => format!("account:{attr}?action={action}"),
    }
}

/// Without an Authorization header: the operator the admin listener's proxy
/// named, if any.
fn proxy_operator(parts: &Parts) -> Option<XResult<Credentials>> {
    if parts.headers.contains_key(header::AUTHORIZATION) {
        return None;
    }
    Some(match parts.extensions.get::<crate::admin_proxy::ProxyIdentity>()? {
        crate::admin_proxy::ProxyIdentity::Operator(login) => Ok(Credentials::Admin { operator: Some(login.clone()) }),
        crate::admin_proxy::ProxyIdentity::Refused(why) => {
            Err(XrpcError { status: StatusCode::FORBIDDEN, error: "OperatorRefused".into(), message: why.clone() })
        }
    })
}

pub async fn authenticate(app: &App, parts: &Parts) -> XResult<Credentials> {
    if let Some(r) = proxy_operator(parts) {
        return r;
    }
    let h = parts
        .headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| XrpcError::auth("Authentication Required"))?;
    if let Some(tok) = h.strip_prefix("Bearer ") {
        let nsid = parts.uri.path().strip_prefix("/xrpc/").unwrap_or("");
        if MODERATOR_METHODS.contains(&nsid)
            || (MOD_SERVICE_OR_USER_METHODS.contains(&nsid) && is_mod_service_token(app, tok))
        {
            return verify_mod_service(app, tok.trim(), nsid).await;
        }
        if USER_SERVICE_AUTH_METHODS.contains(&nsid) && has_lxm(tok.trim()) {
            return verify_user_service_auth(app, tok.trim(), nsid).await;
        }
        let creds = super::server::verify_bearer(app, tok).await?;
        if matches!(creds, Credentials::Takendown { .. }) && !TAKENDOWN_METHODS.contains(&nsid) {
            return Err(XrpcError::bad("InvalidToken", "Bad token scope"));
        }
        return Ok(creds);
    }
    if let Some(tok) = h.strip_prefix("DPoP ") {
        return super::oauth::verify_dpop(app, tok, parts).await;
    }
    if let Some(b) = h.strip_prefix("Basic ") {
        if crate::auth::basic_admin_ok(b, &app.admin_token) {
            return Ok(Credentials::Admin { operator: None });
        }
        return Err(XrpcError::auth("invalid admin credentials"));
    }
    Err(XrpcError::auth("unsupported authorization scheme"))
}

/// Reference `authVerifier.modService`.
async fn verify_mod_service(app: &App, tok: &str, nsid: &str) -> XResult<Credentials> {
    let Some(m) = app.config.mod_service_did.as_deref() else {
        return Err(service_auth_err("UntrustedIss", "Untrusted issuer"));
    };
    let trusted = [m.to_string(), format!("{m}#atproto_labeler")];
    let sa = verify_jwt(app, tok, Some(nsid), Some(&trusted), false, false).await?;
    Ok(Credentials::ModService { iss: sa.iss })
}

/// Reference `userServiceAuth`: no `jti` replay check and no `iat` bound,
/// as there (getServiceAuth tokens live at most an hour). Account status is
/// the handler's business.
async fn verify_user_service_auth(app: &App, tok: &str, nsid: &str) -> XResult<Credentials> {
    let sa = verify_jwt(app, tok, Some(nsid), None, true, false).await?;
    Ok(Credentials::UserServiceAuth { did: sa.iss })
}

/// Anything but an account hosted here is the reference's actor-store miss.
async fn local_account_iss(app: &App, iss: &str) -> XResult<()> {
    if iss.contains('#') || super::server::account_if_exists(app, iss).await?.is_none() {
        return Err(XrpcError::bad("NotFound", "Repo not found"));
    }
    Ok(())
}

/// A JWT's payload, unverified: only for routing a token to its verifier.
fn unverified_claims(tok: &str) -> Option<J> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
    use base64::Engine;
    let b = B64.decode(tok.split('.').nth(1)?).ok()?;
    serde_json::from_slice(&b).ok()
}

/// Reference `isDefinitelyServiceAuth`: session and OAuth tokens never carry
/// `lxm`.
fn has_lxm(tok: &str) -> bool {
    unverified_claims(tok).is_some_and(|c| c.get("lxm").is_some_and(|l| !l.is_null()))
}

fn is_mod_service_token(app: &App, tok: &str) -> bool {
    let Some(m) = app.config.mod_service_did.as_deref() else {
        return false;
    };
    unverified_claims(tok).is_some_and(|c| c["iss"].as_str().is_some_and(|i| i.split('#').next() == Some(m)))
}

/// Signature and `typ` checked once per token until its `exp`; claims, the
/// DPoP proof and the session are still checked per request. Entries
/// remember the verifying key: one process can run several servers.
pub fn verify_access_token(
    server: &crate::oauth::jose::ServerKey,
    token: &str,
) -> Result<Arc<crate::oauth::jose::DecodedJwt>, String> {
    type Verified = (Arc<str>, Arc<crate::oauth::jose::DecodedJwt>);
    static CACHE: std::sync::LazyLock<Arc<crate::auth::TokenCache<Verified>>> =
        std::sync::LazyLock::new(|| crate::auth::TokenCache::tracked(crate::caches::Cache::OAuthTokens));
    let now = crate::tid::now_micros() / 1_000_000;
    if let Some((kid, jwt)) = CACHE.get(token, now) {
        if *kid == *server.kid {
            return Ok(jwt);
        }
    }
    let jwt = Arc::new(server.verify(token, "at+jwt")?);
    if let Some(exp) = jwt.claim_i64("exp").and_then(|e| u64::try_from(e).ok()) {
        CACHE.put(token, (server.kid.as_str().into(), jwt.clone()), exp, now);
    }
    Ok(jwt)
}

/// A forwarded request's authentication waits at most this long, leaving
/// the owner's write start (`--forwarded-write-start-ms`) its time before
/// the entry node's [`crate::forward::TTFB_FAST`].
const FORWARDED_AUTH_WAIT: std::time::Duration = std::time::Duration::from_millis(1500);

/// [`authenticate`]; on a forwarded Bearer request (with not-applied answers
/// on), past [`FORWARDED_AUTH_WAIT`] it answers 503 `RepoLoading` instead:
/// nothing was done, so the entry node resends it rather than failing it at
/// its deadline. That wait is the account's security controls loading cold
/// (every account of a shard after a takeover); the load goes on in the
/// background, so the resend finds it cached. A DPoP proof claimed by then
/// is given back with that answer (`oauth::dpop_layer`), so the resend's
/// same proof is accepted; one cancelled while its claim was in flight
/// stays claimed, and its resend is refused.
async fn authenticate_within(app: &Arc<App>, parts: &Parts) -> XResult<Credentials> {
    let h = parts.headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok());
    let (bearer, dpop) = (h.and_then(|h| h.strip_prefix("Bearer ")), h.and_then(|h| h.strip_prefix("DPoP ")));
    if (bearer.is_none() && dpop.is_none())
        || app.config.forwarded_write_start.is_none()
        || !crate::forward::is_forwarded()
    {
        return authenticate(app, parts).await;
    }
    match tokio::time::timeout(FORWARDED_AUTH_WAIT, authenticate(app, parts)).await {
        Ok(r) => r,
        Err(_) => {
            let sub = match (bearer, dpop) {
                (Some(t), _) => app.jwt.verify_signature_cached(t.trim()).map(|c| c.sub.clone()),
                (_, Some(t)) => super::oauth::access_token_sub(app, t.trim()),
                _ => None,
            };
            if let Some(did) = sub.filter(|d| d.starts_with("did:")) {
                let app = app.clone();
                tokio::spawn(async move {
                    let _ = super::server::ctl(&app, &did).await;
                });
            }
            Err(XrpcError::unavailable(
                crate::forward::REPO_LOADING,
                format!("account state still loading after {} ms; not applied, retry", FORWARDED_AUTH_WAIT.as_millis()),
            ))
        }
    }
}

pub struct Auth(pub Credentials);

impl FromRequestParts<Arc<App>> for Auth {
    type Rejection = XrpcError;
    async fn from_request_parts(parts: &mut Parts, app: &Arc<App>) -> Result<Self, Self::Rejection> {
        authenticate_within(app, parts).await.map(Auth)
    }
}

pub struct MaybeAuth(pub Option<Credentials>);

impl FromRequestParts<Arc<App>> for MaybeAuth {
    type Rejection = XrpcError;
    async fn from_request_parts(parts: &mut Parts, app: &Arc<App>) -> Result<Self, Self::Rejection> {
        if parts.headers.get(header::AUTHORIZATION).is_none() {
            // a refused proxy identity reads as anonymous here
            return Ok(MaybeAuth(proxy_operator(parts).and_then(Result::ok)));
        }
        authenticate_within(app, parts).await.map(|c| MaybeAuth(Some(c)))
    }
}

/// The caller's DID, which `repo` (handle or DID) must name.
pub async fn authed_repo(app: &App, creds: &Credentials, repo: &str) -> XResult<Arc<str>> {
    let did = creds.user_did()?;
    let target = app.resolve_repo(repo).await?;
    if *target != *did {
        // reference createRecord/putRecord/deleteRecord/applyWrites:
        // `if (did !== auth.credentials.did) throw new AuthRequiredError()`
        return Err(XrpcError::auth("Authentication Required"));
    }
    Ok(target)
}

/// A verified inter-service JWT: `iss` is a DID, optionally `#service`.
#[derive(Clone, Debug)]
pub struct ServiceAuth {
    pub iss: String,
    pub aud: String,
}

fn service_auth_err(error: &str, message: &str) -> XrpcError {
    XrpcError { status: StatusCode::UNAUTHORIZED, error: error.into(), message: message.into() }
}

/// The `#atproto` (`#atproto_label` for a `#atproto_labeler` issuer) key of
/// `iss`, as multibase. `fresh` skips the resolver's cache.
async fn issuer_key(app: &App, iss: &str, fresh: bool) -> XResult<String> {
    let (did, service) = iss.split_once('#').unwrap_or((iss, ""));
    let key_id = if service == "atproto_labeler" { "atproto_label" } else { "atproto" };
    if key_id == "atproto" {
        if let Ok(a) = app.account(did).await {
            if super::identity::serves_local_doc(app, &a) {
                return Ok(a.signing_pubkey);
            }
        }
    }
    if fresh && !app.did_resolver.refresh(did) {
        // refreshed recently: the cached key is the current one as far as
        // we may know (no re-fetch per forged token)
        return Err(service_auth_err("BadJwtSignature", "jwt signature does not match jwt issuer"));
    }
    let doc = app
        .did_resolver
        .resolve(did)
        .await
        .map_err(|_| service_auth_err("AuthenticationRequired", "could not resolve iss did"))?;
    let full = format!("{did}#{key_id}");
    let short = format!("#{key_id}");
    doc.get("verificationMethod")
        .and_then(|v| v.as_array())
        .and_then(|ms| {
            ms.iter().find_map(|m| {
                let id = m.get("id")?.as_str()?;
                (id == full || id == short).then(|| m.get("publicKeyMultibase")?.as_str().map(String::from))?
            })
        })
        .ok_or_else(|| service_auth_err("AuthenticationRequired", "missing or bad key in did doc"))
}

/// An inter-service JWT addressed to this PDS, with the reference's errors
/// (xrpc-server verifyJwt). High-S signatures are accepted, as the
/// reference does for service JWTs (`allowMalleableSig`).
pub async fn verify_service_jwt(app: &App, token: &str, lxm: Option<&str>) -> XResult<ServiceAuth> {
    verify_jwt(app, token, lxm, None, false, false).await
}

/// Service auth for the space methods whose audience depends on the
/// request (reference `serviceAuth`, `audience: null`): notifyWrite to a
/// space host (`{authority}#atproto_space_host` or the bare authority DID)
/// and notifyCredentialRevoked to a repo host (a local account's DID).
/// `lxm` must be the method. The handler checks `aud`, as the reference's
/// do (403).
pub async fn verify_space_service_jwt(app: &App, headers: &HeaderMap, lxm: &str) -> XResult<ServiceAuth> {
    let tok = match authorization(headers)? {
        Some((scheme, tok)) if scheme.eq_ignore_ascii_case("bearer") => tok,
        _ => return Err(service_auth_err("MissingJwt", "missing jwt")),
    };
    verify_jwt(app, tok, Some(lxm), None, false, true).await
}

/// `trusted` (exact `iss`) and `local_iss` are checked before the issuer's
/// key is resolved, so a forged token naming a foreign DID costs no
/// outbound DID fetch.
async fn verify_jwt(
    app: &App,
    token: &str,
    lxm: Option<&str>,
    trusted: Option<&[String]>,
    local_iss: bool,
    any_aud: bool,
) -> XResult<ServiceAuth> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
    use base64::Engine;
    let parts: Vec<&str> = token.split('.').collect();
    let [h, p, s] = parts[..] else {
        return Err(service_auth_err("BadJwt", "poorly formatted jwt"));
    };
    let decode = |x: &str| -> XResult<J> {
        let b = B64.decode(x).map_err(|_| service_auth_err("BadJwt", "poorly formatted jwt"))?;
        serde_json::from_slice(&b).map_err(|_| service_auth_err("BadJwt", "poorly formatted jwt"))
    };
    let header = decode(h)?;
    let payload = decode(p)?;
    if let Some(t @ ("at+jwt" | "refresh+jwt" | "dpop+jwt")) = header["typ"].as_str() {
        return Err(service_auth_err("BadJwtType", &format!("Invalid jwt type \"{t}\"")));
    }
    let exp = payload["exp"].as_f64().ok_or_else(|| service_auth_err("BadJwt", "poorly formatted jwt"))?;
    if (crate::tid::now_micros() as f64) / 1e6 > exp {
        return Err(service_auth_err("JwtExpired", "jwt expired"));
    }
    let aud = payload["aud"].as_str().unwrap_or("");
    if any_aud {
        if aud.is_empty() {
            return Err(service_auth_err("BadJwt", "poorly formatted jwt"));
        }
    } else if aud != app.jwt.service_did {
        return Err(service_auth_err("BadJwtAudience", "jwt audience does not match service did"));
    }
    if let Some(lxm) = lxm {
        let got = payload["lxm"].as_str();
        if got != Some(lxm) {
            let what = if got.is_some() { "bad" } else { "missing" };
            return Err(service_auth_err(
                "BadJwtLexiconMethod",
                &format!("{what} jwt lexicon method (\"lxm\"). must match: {lxm}"),
            ));
        }
    }
    let iss = payload["iss"].as_str().unwrap_or("");
    if !super::syntax::valid_did(iss.split('#').next().unwrap_or("")) {
        return Err(service_auth_err("BadJwtIss", "jwt iss is not a valid did"));
    }
    if trusted.is_some_and(|t| !t.iter().any(|x| x == iss)) {
        return Err(service_auth_err("UntrustedIss", "Untrusted issuer"));
    }
    if local_iss {
        local_account_iss(app, iss).await?;
    }
    let msg = format!("{h}.{p}");
    let sig = B64.decode(s).map_err(|_| service_auth_err("BadJwtSignature", "could not verify jwt signature"))?;
    let check = |key: &str| {
        crate::oauth::lexicon::verify_sig_malleable(key, msg.as_bytes(), &sig)
            .map_err(|_| service_auth_err("BadJwtSignature", "could not verify jwt signature"))
    };
    let key = issuer_key(app, iss, false).await?;
    if !check(&key)? {
        // the key may have just been rotated
        let fresh = issuer_key(app, iss, true).await?;
        if fresh == key || !check(&fresh)? {
            return Err(service_auth_err("BadJwtSignature", "jwt signature does not match jwt issuer"));
        }
    }
    Ok(ServiceAuth { iss: iss.to_string(), aud: aud.to_string() })
}

/// Reference `userServiceAuthOptional`: a Bearer token must be a valid
/// service JWT for `lxm`; no header or another scheme is unauthenticated.
pub async fn optional_service_auth(app: &App, headers: &HeaderMap, lxm: &str) -> XResult<Option<ServiceAuth>> {
    let bearer =
        headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).and_then(|v| v.strip_prefix("Bearer "));
    match bearer {
        Some(tok) => verify_jwt(app, tok.trim(), Some(lxm), None, false, false).await.map(Some),
        None => Ok(None),
    }
}

/// The scheme of space credentials: `Authorization: Atproto-Space <jwt>`.
pub const SPACE_SCHEME: &str = "atproto-space";

/// (scheme, token) of the Authorization header, the scheme matched
/// case-insensitively as the reference does; Err on a malformed header
/// (not exactly "scheme token").
fn authorization(headers: &HeaderMap) -> XResult<Option<(&str, &str)>> {
    let Some(h) = headers.get(header::AUTHORIZATION) else { return Ok(None) };
    let h = h.to_str().map_err(|_| XrpcError::bad("InvalidToken", "Malformed authorization header"))?;
    let mut parts = h.split(' ');
    match (parts.next(), parts.next(), parts.next()) {
        (Some(scheme), Some(tok), None) => Ok(Some((scheme, tok))),
        _ => Err(XrpcError::bad("InvalidToken", "Malformed authorization header")),
    }
}

fn is_space_credential(headers: &HeaderMap) -> XResult<bool> {
    Ok(authorization(headers)?.is_some_and(|(scheme, _)| scheme.eq_ignore_ascii_case(SPACE_SCHEME)))
}

/// An `AuthRequiredError` with the reference's code.
fn space_auth_err(code: &str, message: impl Into<String>) -> XrpcError {
    XrpcError { status: StatusCode::UNAUTHORIZED, error: code.into(), message: message.into() }
}

fn token_err(e: token::TokenError) -> XrpcError {
    space_auth_err(e.code, e.message)
}

fn sig_err(e: crate::space::httpsig::SigError) -> XrpcError {
    space_auth_err(crate::space::httpsig::SigError::CODE, e.0)
}

/// Every value of `name`: duplicates are refused, not joined.
fn single_header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut all = headers.get_all(name).iter();
    match (all.next(), all.next()) {
        (Some(v), None) => v.to_str().ok(),
        _ => None,
    }
}

/// The did:key a space token's `kid` names in `iss`'s DID document
/// (reference PDS `resolveSpaceKey`). An account hosted here whose document
/// is ours answers from its account. `fresh` skips the resolver's cache.
async fn space_token_key(app: &App, iss: &str, kid: Option<&str>, fresh: bool) -> XResult<String> {
    let key_id = token::key_id(kid).map_err(token_err)?;
    if key_id == "atproto" && app.partition(iss).is_ok() {
        if let Ok(a) = app.account(iss).await {
            if super::identity::serves_local_doc(app, &a) {
                return Ok(format!("did:key:{}", a.signing_pubkey));
            }
        }
    }
    if fresh && !app.did_resolver.refresh(iss) {
        return Err(space_auth_err("BadJwtSignature", "invalid token signature"));
    }
    let doc = app
        .did_resolver
        .resolve(iss)
        .await
        .map_err(|_| space_auth_err("BadJwtIss", format!("could not resolve DID: {iss}")))?;
    let (full, short) = (format!("{iss}#{key_id}"), format!("#{key_id}"));
    doc.get("verificationMethod")
        .and_then(|v| v.as_array())
        .and_then(|ms| {
            ms.iter().find_map(|m| {
                let id = m.get("id")?.as_str()?;
                (id == full || id == short)
                    .then(|| m.get("publicKeyMultibase")?.as_str().map(|k| format!("did:key:{k}")))?
            })
        })
        .ok_or_else(|| space_auth_err("BadJwtIss", format!("missing or bad key (#{key_id}) in did doc: {iss}")))
}

/// `verifySpaceToken` of a parsed token: times, then the issuer's
/// signature, once more against a freshly resolved key if that fails (a
/// rotation).
async fn verify_space_token(app: &App, t: &token::SpaceToken) -> XResult<()> {
    t.check(crate::tid::now_micros() as i64 / 1_000_000, None, None).map_err(token_err)?;
    let kid = t.header.kid.as_deref();
    let key = space_token_key(app, &t.claims.iss, kid, false).await?;
    if let Err(e) = t.verify_signature(&key) {
        let fresh = space_token_key(app, &t.claims.iss, kid, true).await.map_err(|_| token_err(e.clone()))?;
        if fresh == key {
            return Err(token_err(e));
        }
        t.verify_signature(&fresh).map_err(token_err)?;
    }
    Ok(())
}

/// A rate-limit key the console can show without naming who talks to which
/// space authority: keyed by the server secret, so it can't be matched
/// against a list of DIDs.
pub(super) fn private_limit_key(app: &App, key: &str) -> String {
    let k = crate::oauth::util::derive_secret(&app.config.jwt_secret, "space-rate-limit-key");
    hex::encode(&crate::prims::hmac_sha256(&k, &[key.as_bytes()])[..16])
}

/// Reference `spaceCredentialAuth`: the credential, issued by its space's
/// authority; a DID audience; the request signed by the credential's key
/// over exactly the authorization and audience headers, each sent once;
/// not revoked. The handler checks the space and the audience against the
/// request ([`super::space::assert_credential_space`]).
///
/// A credential verified once is cached until it expires
/// ([`crate::space::credcache`]): later requests with it skip the chain
/// but still check revocation and their own signature.
pub async fn verify_space_credential(app: &App, headers: &HeaderMap) -> XResult<Credentials> {
    let r = check_space_credential(app, headers).await;
    // `ok`, and the audience and space checks, are counted by the handler
    let refused = match &r {
        Err(e) if e.status.is_server_error() => None,
        Err(e) if e.error == "JwtExpired" => Some("expired"),
        Err(e) if e.error == "CredentialRevoked" => Some("revoked"),
        Err(e) if e.message.contains("audience") => Some("audience"),
        Err(_) => Some("bad_sig"),
        Ok(_) => None,
    };
    if let Some(result) = refused {
        crate::metrics::space_credential_check(result);
    }
    if let Ok(Credentials::SpaceCredential { iss, jti, .. }) = &r {
        use crate::ratelimit::{check, SPACE_READ_CREDENTIAL};
        check(&[&SPACE_READ_CREDENTIAL], &private_limit_key(app, &format!("{iss} {jti}")), 1)?;
    }
    r
}

async fn check_space_credential(app: &App, headers: &HeaderMap) -> XResult<Credentials> {
    let tok = match authorization(headers)? {
        Some((scheme, tok)) if scheme.eq_ignore_ascii_case(SPACE_SCHEME) => tok,
        _ => return Err(space_auth_err("MissingJwt", "missing space credential")),
    };
    let Some(sp) = app.spaces.as_ref() else {
        return Err(space_auth_err("MissingJwt", "missing space credential"));
    };
    if !sp.revocations.fresh() {
        return Err(XrpcError::unavailable("Unavailable", "space credential revocations are not loaded; retry"));
    }
    let now = crate::tid::now_micros() as i64 / 1_000_000;
    let key = crate::space::credcache::key(tok);
    let cached = sp.credentials.get(&key, now);
    crate::metrics::space_credential_cache(cached.is_some());
    let v = match cached {
        Some(v) => v,
        None => {
            let t = token::parse(TokenType::Credential, tok).map_err(token_err)?;
            verify_space_token(app, &t).await?;
            let space = token::check_credential(&t).map_err(token_err)?;
            let v = Arc::new(crate::space::credcache::Verified {
                space: format!("at://{}/space/{}/{}", space.authority, space.space_type, space.skey),
                iss: t.claims.iss.clone(),
                jti: t.claims.jti.clone(),
                exp: t.claims.exp,
                cnf_kid: t.claims.cnf_kid.clone().unwrap_or_default(),
            });
            sp.credentials.insert(key, v.clone());
            v
        }
    };
    let audience = single_header(headers, crate::space::httpsig::AUDIENCE_HEADER)
        .filter(|a| super::syntax::valid_did(a))
        .ok_or_else(|| space_auth_err("BadSpaceSignature", "missing or invalid space audience DID"))?
        .to_string();
    if headers.get_all(header::AUTHORIZATION).iter().count() != 1 {
        return Err(space_auth_err("BadSpaceSignature", "request requires exactly one \"authorization\" field"));
    }
    crate::space::httpsig::verify(headers, Some(&v.cnf_kid)).map_err(sig_err)?;
    if sp.revocations.is_revoked(&v.space, &v.jti, now) {
        return Err(space_auth_err("CredentialRevoked", "space credential has been revoked"));
    }
    let blocked = || XrpcError::unavailable("Unavailable", "this space's credentials are refused for now; retry later");
    match sp.revocations.blocked(&v.space, now) {
        crate::space::revocations::Blocked::No => {}
        crate::space::revocations::Blocked::Yes => return Err(blocked()),
        crate::space::revocations::Blocked::IfRemote => {
            let authority = crate::space::revocations::authority_of(&v.space).unwrap_or_default();
            if !super::space::authority_hosted(app, authority).await? {
                return Err(blocked());
            }
        }
    }
    Ok(Credentials::SpaceCredential {
        space: v.space.clone(),
        iss: v.iss.clone(),
        jti: v.jti.clone(),
        exp: v.exp as i64,
        cnf_kid: v.cnf_kid.clone(),
        audience,
    })
}

/// A verified delegation token: who it delegates, for which space, and the
/// P-256 did:key the credential will be bound to.
#[derive(Clone, Debug)]
pub struct Delegation {
    pub user: String,
    pub space: String,
    pub authority: String,
    pub key_id: String,
}

/// Reference `delegationTokenAuth`, for getSpaceCredential only: a
/// delegation token addressed to its space's authority, the request signed
/// over exactly `authorization` by the key `keyid` names, and the token's
/// `jti` claimed once (at the authority's owner, durably, so a failover
/// doesn't reopen it).
pub async fn verify_delegation(app: &App, headers: &HeaderMap) -> XResult<Delegation> {
    let tok = match authorization(headers)? {
        Some((scheme, tok)) if scheme.eq_ignore_ascii_case("bearer") => tok,
        _ => return Err(space_auth_err("MissingJwt", "missing delegation token")),
    };
    let t = token::parse(TokenType::Delegation, tok).map_err(token_err)?;
    verify_space_token(app, &t).await?;
    let space = token::check_delegation(&t).map_err(token_err)?;
    let authority = space.authority.to_string();
    let space = format!("at://{authority}/space/{}/{}", space.space_type, space.skey);
    if headers.get_all(header::AUTHORIZATION).iter().count() != 1 {
        return Err(space_auth_err("BadSpaceSignature", "request requires exactly one \"authorization\" field"));
    }
    let key_id = crate::space::httpsig::verify(headers, None).map_err(sig_err)?;
    // before the claim, which a refused exchange would otherwise spend
    let limit_key = private_limit_key(app, &format!("{} {authority}", t.claims.iss));
    crate::ratelimit::check(&[&crate::ratelimit::SPACE_CREDENTIAL], &limit_key, 1)?;
    let claim = format!("space-delegation:{}:{}", t.claims.iss, t.claims.jti);
    if !super::internal::claim_replay_anywhere(app, &authority, &claim, t.claims.exp.ceil() as i64).await? {
        return Err(space_auth_err("JwtReplayed", "delegation token has already been used"));
    }
    Ok(Delegation { user: t.claims.iss.clone(), space, authority, key_id })
}

/// An account reading its own space data.
pub fn check_space_read_account(creds: &Credentials) -> XResult<()> {
    match creds.did() {
        Some(did) => crate::ratelimit::check(&[&crate::ratelimit::SPACE_READ_ACCOUNT], did, 1),
        None => Ok(()),
    }
}

/// The space read methods: a space credential, or the account's own auth.
pub struct SpaceAuth(pub Credentials);

impl FromRequestParts<Arc<App>> for SpaceAuth {
    type Rejection = XrpcError;
    async fn from_request_parts(parts: &mut Parts, app: &Arc<App>) -> Result<Self, Self::Rejection> {
        if is_space_credential(&parts.headers)? {
            return verify_space_credential(app, &parts.headers).await.map(SpaceAuth);
        }
        let creds = authenticate_within(app, parts).await?;
        check_space_read_account(&creds)?;
        Ok(SpaceAuth(creds))
    }
}
