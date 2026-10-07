//! com.atproto.server.* (sessions, accounts, app passwords, email flows,
//! invites, service auth), com.atproto.temp.{checkSignupQueue,
//! checkHandleAvailability} and the vlpds.server.*Totp second factor.
//!
//! Durable state (all through the partition log via `put_private` /
//! `account_op`):
//!   p/{did}\0sess/{refresh id}     refresh-token session (rotated on refresh)
//!   p/{did}\0apppass/{name}        app password metadata
//!   p/{did}\0apphash/{hash}        app password hash -> name (login lookup)
//!   p/{did}\0etok/{purpose}        current email token per purpose (keyed digest)
//!   p/{did}\0totp                  TOTP state (src/totp.rs; secrets wrapped)
//!   p/_reset:{digest}\0t           password-reset token digest -> did
//!   p/_invite:{code}\0c            invite code (+ p/{account}\0invite/{code} index)
//!   p/{did}\0sec/rvk/f/{family}    revoked session family (access tokens), TTL'd
//!   p/{did}\0sec/rvk/d/{before}    all sessions of the DID revoked before a time
//!   p/{did}\0auth_epoch            credential epoch, replaced by every revoke-all
//!                                  ([`auth_epoch`]; logins racing one fail)
//!   p/{did}\0sec/td/rec/{coll}/{rkey}, p/{did}\0sec/td/blob/{cid}
//!                                  record / blob takedowns (admin.rs)
//!   {prefix}/email/{sha256(email)} global email claim -> did (object store,
//!                                  conditional create, like handle claims)
//! Account fields owned here live in `Account.extra`: deactivatedAt,
//! deleteAfter, takedownRef, emailConfirmedAt, invitesDisabled, invitedBy,
//! totpEnabled, emailAuthFactorAt (src/xrpc/email2fa.rs).
//!
//! Access tokens carry `jti` = session family id (`{issue micros:016x}{rand}`),
//! refresh tokens `jti` = refresh id. Revocations and takedowns live in the
//! account's own partition (`sec/`) so its owner enforces them and a successor
//! reads them back after a failover; the hot path checks a cached view ([`ctl`]).

use super::authn::Credentials;
use super::*;
use crate::segment::Mutation;
use crate::worker::AccountOp;
use parking_lot::{Mutex as PMutex, RwLock};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::AtomicU64;

pub fn routes() -> Router<Arc<App>> {
    Router::new()
        .route("/xrpc/com.atproto.server.describeServer", get(describe_server))
        .route("/xrpc/com.atproto.server.createAccount", post(create_account))
        .route("/xrpc/com.atproto.server.createSession", post(create_session))
        .route("/xrpc/com.atproto.server.getSession", get(get_session))
        .route("/xrpc/com.atproto.server.refreshSession", post(refresh_session))
        .route("/xrpc/com.atproto.server.deleteSession", post(delete_session))
        .route("/xrpc/com.atproto.server.createAppPassword", post(create_app_password))
        .route("/xrpc/com.atproto.server.listAppPasswords", get(list_app_passwords))
        .route("/xrpc/com.atproto.server.revokeAppPassword", post(revoke_app_password))
        .route("/xrpc/com.atproto.server.deactivateAccount", post(deactivate_account))
        .route("/xrpc/com.atproto.server.activateAccount", post(activate_account))
        .route("/xrpc/com.atproto.server.checkAccountStatus", get(check_account_status))
        .route("/xrpc/com.atproto.server.requestAccountDelete", post(request_account_delete))
        .route("/xrpc/com.atproto.server.deleteAccount", post(delete_account))
        .route("/xrpc/com.atproto.server.reserveSigningKey", post(reserve_signing_key))
        .route("/xrpc/com.atproto.server.requestEmailConfirmation", post(request_email_confirmation))
        .route("/xrpc/com.atproto.server.confirmEmail", post(confirm_email))
        .route("/xrpc/com.atproto.server.requestEmailUpdate", post(request_email_update))
        .route("/xrpc/com.atproto.server.updateEmail", post(update_email))
        .route("/xrpc/com.atproto.server.requestPasswordReset", post(request_password_reset))
        .route("/xrpc/com.atproto.server.resetPassword", post(reset_password))
        .route("/xrpc/com.atproto.server.createInviteCode", post(create_invite_code))
        .route("/xrpc/com.atproto.server.createInviteCodes", post(create_invite_codes))
        .route("/xrpc/com.atproto.server.getAccountInviteCodes", get(get_account_invite_codes))
        .route("/xrpc/com.atproto.server.getServiceAuth", get(get_service_auth))
        .route("/xrpc/com.atproto.temp.checkSignupQueue", get(check_signup_queue))
        .route("/xrpc/com.atproto.temp.checkHandleAvailability", get(check_handle_availability))
        .route("/xrpc/vlpds.server.setupTotp", post(setup_totp))
        .route("/xrpc/vlpds.server.confirmTotp", post(confirm_totp))
        .route("/xrpc/vlpds.server.disableTotp", post(disable_totp))
        .route("/xrpc/vlpds.server.getTotpStatus", get(get_totp_status))
}

const ACCESS_TTL: u64 = 2 * 3600;
const REFRESH_TTL: u64 = 90 * 86400;
/// A rotated refresh token stays usable this long (reference REFRESH_GRACE_MS).
const REFRESH_GRACE: u64 = 2 * 3600;
const REVOKE_TTL: u64 = ACCESS_TTL + 600;
/// Revoke-all rows outlive every refresh token they cover, not just the
/// access tokens: defense in depth should a refresh row ever come back.
const REVOKE_ALL_TTL: u64 = REFRESH_TTL + 600;
const CAS_ROUNDS: usize = 8;
pub const AUTH_EPOCH: &str = "auth_epoch";
/// Re-read period of a DID's revocations/takedowns cached from its owner.
const RELOAD_SECS: u64 = 10;
/// ... and when read locally: local changes invalidate it at once, so this
/// only bounds a missed one.
const LOCAL_RELOAD_SECS: u64 = 60;
/// An unreachable owner's cached view is used while at most this old (how
/// late a revocation made during an owner outage can be enforced here);
/// older fails closed.
const STALE_MAX_SECS: u64 = 300;
const CTL_RETRY_FOR: std::time::Duration = std::time::Duration::from_secs(3);
const CTL_MOVE_WAIT_FORWARDED: std::time::Duration =
    crate::forward::TTFB_FAST.saturating_sub(std::time::Duration::from_millis(500));
const EMAIL_TOKEN_TTL_MS: u64 = 15 * 60 * 1000;
pub(super) const NEW_PASSWORD_MAX_LENGTH: usize = 256;
pub(super) const OLD_PASSWORD_MAX_LENGTH: usize = 512;

pub(crate) const SEC: &str = "sec/";
/// `sec/rvk/d/{before:016x}`: every session issued at or before `before`
/// (micros) is revoked until `exp`. One immutable row per revocation (the
/// newest dominates), so the GC can delete an expired one without racing a
/// newer revocation.
const REVOKED_ALL: &str = "sec/rvk/d/";
const REVOKED_FAMILY: &str = "sec/rvk/f/";
/// `sec/td/rec/{collection}/{rkey}`, `sec/td/blob/{cid}`.
pub(super) const TAKEDOWN: &str = "sec/td/";

pub(super) const SCOPE_ACCESS: &str = "com.atproto.access";
pub(super) const SCOPE_APP_PASS: &str = "com.atproto.appPass";
pub(super) const SCOPE_APP_PASS_PRIVILEGED: &str = "com.atproto.appPassPrivileged";
pub(super) const SCOPE_REFRESH: &str = "com.atproto.refresh";
pub(super) const SCOPE_TAKENDOWN: &str = "com.atproto.takendown";

/// The host of `--public-url`.
pub(super) fn public_host(app: &App) -> &str {
    app.public_url.split("://").nth(1).unwrap_or(&app.public_url).split(['/', ':']).next().unwrap_or("vlpds")
}

pub(super) fn now_secs() -> u64 {
    crate::tid::now_micros() / 1_000_000
}

pub(super) fn now_ms() -> u64 {
    crate::tid::now_micros() / 1000
}

fn err(status: StatusCode, error: &str, message: impl Into<String>) -> XrpcError {
    XrpcError { status, error: error.into(), message: message.into() }
}

pub(super) fn invalid_request(message: impl Into<String>) -> XrpcError {
    XrpcError::bad("InvalidRequest", message)
}

fn invalid_token(message: &str) -> XrpcError {
    XrpcError::bad("InvalidToken", message)
}

fn expired_token(message: &str) -> XrpcError {
    XrpcError::bad("ExpiredToken", message)
}

fn oauth_forbidden() -> XrpcError {
    err(StatusCode::FORBIDDEN, "Forbidden", "OAuth credentials are not supported for this endpoint")
}

fn bad_scope() -> XrpcError {
    invalid_token("Bad token scope")
}

fn random_hex(n: usize) -> String {
    hex::encode((0..n).map(|_| rand::random::<u8>()).collect::<Vec<u8>>())
}

/// TS getRandomToken(): `xxxxx-xxxxx` in base32.
pub(super) fn random_token() -> String {
    let s = crate::cid::base32_encode(&rand::random::<[u8; 8]>());
    format!("{}-{}", &s[..5], &s[5..10])
}

pub(super) fn pmut(routing: &str, name: &str, val: Option<Vec<u8>>) -> Mutation {
    Mutation { key: state::private_key(routing, name).into(), val: val.map(Bytes::from) }
}

pub(super) fn to_json_bytes<T: serde::Serialize>(v: &T) -> Vec<u8> {
    serde_json::to_vec(v).expect("serializable")
}

pub(super) async fn get_json<T: serde::de::DeserializeOwned>(
    app: &App,
    routing: &str,
    name: &str,
) -> XResult<Option<T>> {
    app.get_private(routing, name).await?.map(|v| serde_json::from_slice(&v).map_err(XrpcError::from_err)).transpose()
}

/// (name, value) of `routing`'s private rows under `name_prefix`, from this
/// node's partition. Blocks are cached: a security-control view is re-read
/// every LOCAL_RELOAD_SECS, and an uncached scan GETs a block per sorted run.
pub(super) async fn scan_private(app: &App, routing: &str, name_prefix: &str) -> XResult<Vec<(String, Bytes)>> {
    let p = app.partition(routing)?;
    let base = state::private_prefix(routing);
    let lo = [base.as_slice(), name_prefix.as_bytes()].concat();
    let hi = state::prefix_end(&lo);
    let opts = slatedb::config::ScanOptions { cache_blocks: true, ..Default::default() };
    let mut iter = p.db.scan_with_options(lo..hi, &opts).await.map_err(XrpcError::from_err)?;
    let mut out = Vec::new();
    while let Some(kv) = iter.next().await.map_err(XrpcError::from_err)? {
        out.push((String::from_utf8_lossy(&kv.key[base.len()..]).to_string(), kv.value));
    }
    Ok(out)
}

/// (routing key, name, value) of every private row whose routing key starts
/// with `routing_prefix`, across the partitions this node owns.
pub(super) async fn scan_private_routing(app: &App, routing_prefix: &str) -> XResult<Vec<(String, String, Bytes)>> {
    scan_private_routing_in(&app.partitions.owned(), routing_prefix).await
}

pub(super) async fn scan_private_routing_in(
    parts: &[Arc<Partition>],
    routing_prefix: &str,
) -> XResult<Vec<(String, String, Bytes)>> {
    // keys are slot-major: walk each slot's run of p/{routing_prefix}
    let fam = [state::PRIVATE_FAMILY, routing_prefix.as_bytes()].concat();
    let mut out = Vec::new();
    for p in parts {
        let mut iter = state::FamilyScan::new(p.db.as_ref(), &fam, None, &Default::default())
            .await
            .map_err(XrpcError::from_err)?;
        while let Some(kv) = iter.next().await.map_err(XrpcError::from_err)? {
            let rest = String::from_utf8_lossy(&state::key_body(&kv.key)[state::PRIVATE_FAMILY.len()..]).to_string();
            if let Some((routing, name)) = rest.split_once('\0') {
                out.push((routing.to_string(), name.to_string(), kv.value));
            }
        }
    }
    Ok(out)
}

pub(super) fn set_extra(a: &mut Account, k: &str, v: J) {
    if v.is_null() {
        a.extra.remove(k);
    } else {
        a.extra.insert(k.to_string(), v);
    }
}

/// A takedown wins over a deactivation; statuses set elsewhere (e.g.
/// "suspended") are kept.
pub(super) fn recompute_status(a: &mut Account) {
    if a.extra.get("takedownRef").is_some_and(|v| !v.is_null()) {
        a.status = Some("takendown".into());
    } else if a.extra.get("deactivatedAt").is_some_and(|v| !v.is_null()) {
        a.status = Some("deactivated".into());
    } else if matches!(a.status.as_deref(), Some("takendown") | Some("deactivated")) {
        a.status = None;
    }
}

pub(super) fn is_takendown_account(a: &Account) -> bool {
    matches!(a.status.as_deref(), Some("takendown") | Some("suspended"))
}

/// 503 `Overloaded` instead of queueing when every Argon2 permit stays busy.
pub(super) async fn verify_password(a: &Account, password: &str) -> XResult<bool> {
    if password.len() > OLD_PASSWORD_MAX_LENGTH || a.password_hash.is_empty() {
        return Ok(false);
    }
    Ok(state::try_verify_password_hash(&a.password_hash, password).await?)
}

pub(super) fn valid_email(e: &str) -> bool {
    let Some((local, domain)) = e.rsplit_once('@') else {
        return false;
    };
    e.len() <= 254
        && !local.is_empty()
        && local.len() <= 64
        && !e.chars().any(|c| c.is_whitespace() || c.is_control())
        && !local.contains('@')
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && domain.split('.').all(|l| !l.is_empty() && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'))
}

/// The reference's `isEmailValid(email) && !isDisposableEmail(email)`.
pub(super) fn email_supported(e: &str) -> bool {
    valid_email(e) && !crate::email_policy::is_disposable_email(e)
}

fn user_did(creds: &Credentials) -> XResult<String> {
    creds.did().map(str::to_string).ok_or_else(|| XrpcError::auth("user credentials required"))
}

/// The reference's ACCESS_FULL (OAuth refused).
pub(super) fn full_access(creds: &Credentials) -> XResult<String> {
    match creds {
        // takendown tokens only reach the methods that accept them
        Credentials::Session { did } | Credentials::Takendown { did } => Ok(did.clone()),
        Credentials::AppPassword { .. } => Err(bad_scope()),
        Credentials::OAuth { .. } => Err(oauth_forbidden()),
        Credentials::Admin
        | Credentials::ModService { .. }
        | Credentials::UserServiceAuth { .. }
        | Credentials::SpaceCredential { .. } => Err(XrpcError::auth("user credentials required")),
    }
}

/// The reference's ACCESS_STANDARD (OAuth and scoped app passwords refused).
fn standard_no_oauth(creds: &Credentials) -> XResult<String> {
    match creds {
        Credentials::AppPassword { scopes: Some(_), .. } => {
            Err(err(StatusCode::FORBIDDEN, "InsufficientScope", "Scoped app passwords can't use this method"))
        }
        Credentials::Session { did } | Credentials::AppPassword { did, .. } | Credentials::Takendown { did } => {
            Ok(did.clone())
        }
        Credentials::OAuth { .. } => Err(oauth_forbidden()),
        Credentials::Admin
        | Credentials::ModService { .. }
        | Credentials::UserServiceAuth { .. }
        | Credentials::SpaceCredential { .. } => Err(XrpcError::auth("user credentials required")),
    }
}

/// `full_access`, or OAuth holding `account:{attr}?action={action}`.
fn full_or_oauth_account(creds: &Credentials, attr: &str, action: &str) -> XResult<String> {
    match creds {
        Credentials::OAuth { did, .. } => creds.need_account(attr, action).map(|_| did.clone()),
        _ => full_access(creds),
    }
}

/// `standard_no_oauth`, or OAuth or a scoped app password holding
/// `account:{attr}?action={action}`.
fn standard_or_oauth_account(creds: &Credentials, attr: &str, action: &str) -> XResult<String> {
    match creds {
        Credentials::OAuth { did, .. } => creds.need_account(attr, action).map(|_| did.clone()),
        // an unscoped app password may, so the scopes alone decide
        Credentials::AppPassword { did, scopes: Some(s), .. } => match s.allows_account(attr, action) {
            true => Ok(did.clone()),
            false => Err(super::authn::scope_refused("app_password", &super::authn::account_scope(attr, action))),
        },
        _ => standard_no_oauth(creds),
    }
}

/// Per-App in-memory state (per `App`, so in-process test clusters behave
/// like separate machines).
pub(super) struct Ext {
    ctl: Arc<RwLock<HashMap<String, Arc<Ctl>>>>,
    ctl_loads: super::ctl_load::Loads<Ctl>,
    /// Bumped by every change, so a load racing one is not cached.
    gen: AtomicU64,
    pub(super) dev_mail: PMutex<HashMap<String, Vec<Mail>>>,
    locks: Vec<tokio::sync::Mutex<()>>,
    pub(super) cas_locks: super::cas::Locks,
    claim_grace_ms: AtomicU64,
}

static EXTS: RwLock<Vec<(usize, Arc<Ext>)>> = RwLock::new(Vec::new());

pub(super) fn ext(app: &App) -> Arc<Ext> {
    let id = app as *const App as usize;
    if let Some((_, e)) = EXTS.read().iter().find(|(k, _)| *k == id) {
        return e.clone();
    }
    let mut w = EXTS.write();
    if let Some((_, e)) = w.iter().find(|(k, _)| *k == id) {
        return e.clone();
    }
    let e = Arc::new(Ext {
        ctl: crate::caches::track(crate::caches::Cache::SecurityControls, Default::default()),
        ctl_loads: Default::default(),
        gen: AtomicU64::new(0),
        dev_mail: PMutex::new(HashMap::new()),
        locks: (0..64).map(|_| tokio::sync::Mutex::new(())).collect(),
        cas_locks: Default::default(),
        claim_grace_ms: AtomicU64::new(STALE_CLAIM_GRACE.as_millis() as u64),
    });
    w.push((id, e.clone()));
    e
}

impl Ext {
    /// Node-local only: cross-node races need `private_cas`.
    pub(super) async fn lock(&self, key: &str) -> tokio::sync::MutexGuard<'_, ()> {
        self.locks[(state::did_hash(key) % self.locks.len() as u64) as usize].lock().await
    }
}

/// One account's session revocations and record/blob takedowns
/// (`p/{did}\0sec/...`).
#[derive(Default)]
pub(super) struct Ctl {
    /// Unix secs.
    at: u64,
    /// (partition, epoch) when read locally; None = read from the owner.
    local: Option<(crate::slots::ShardId, u64)>,
    /// Sessions issued at or before these micros are revoked until exp secs.
    before: Option<(u64, u64)>,
    /// Family -> expiry (unix secs).
    families: HashMap<String, u64>,
    /// Names below [`TAKEDOWN`].
    takedowns: HashSet<String>,
}

impl Ctl {
    fn is_revoked(&self, jti: Option<&str>, iat: u64) -> bool {
        let now = now_secs();
        let issued_us = jti.and_then(family_micros).unwrap_or(iat.saturating_mul(1_000_000));
        if self.before.is_some_and(|(before, exp)| exp >= now && issued_us <= before) {
            return true;
        }
        jti.is_some_and(|j| self.families.get(j).is_some_and(|exp| *exp >= now))
    }

    /// `name` relative to [`TAKEDOWN`].
    pub(super) fn has_takedown(&self, name: &str) -> bool {
        !self.takedowns.is_empty() && self.takedowns.contains(name)
    }

    /// What follows `prefix` in each name under it.
    pub(super) fn takedowns_under(&self, prefix: &str) -> Vec<String> {
        self.takedowns.iter().filter_map(|n| n.strip_prefix(prefix)).map(String::from).collect()
    }
}

fn family_micros(jti: &str) -> Option<u64> {
    if jti.len() < 16 {
        return None;
    }
    u64::from_str_radix(&jti[..16], 16).ok()
}

fn new_family_id() -> String {
    format!("{:016x}{}", crate::tid::now_micros(), random_hex(8))
}

async fn load_sets(app: &App, did: &str, local: Option<(crate::slots::ShardId, u64)>) -> XResult<Ctl> {
    let rows = if local.is_some() {
        scan_private(app, did, SEC).await?
    } else {
        super::internal::scan_private_anywhere(app, did, SEC).await?
    };
    let now = now_secs();
    let mut c = Ctl { at: now, local, ..Default::default() };
    for (name, v) in rows {
        if let Some(td) = name.strip_prefix(TAKEDOWN) {
            c.takedowns.insert(td.to_string());
            continue;
        }
        let Ok(j) = serde_json::from_slice::<J>(&v) else { continue };
        let exp = j["exp"].as_u64().unwrap_or(0);
        if exp < now {
            continue;
        }
        if name.starts_with(REVOKED_ALL) {
            let before = j["before"].as_u64().unwrap_or(0);
            if c.before.is_none_or(|(b, _)| before > b) {
                c.before = Some((before, exp));
            }
        } else if let Some(f) = name.strip_prefix(REVOKED_FAMILY) {
            c.families.insert(f.to_string(), exp);
        }
    }
    Ok(c)
}

/// `did`'s revocations and takedowns, cached: on the owner until a change
/// ([`ctl_changed`]) or an ownership move, elsewhere for [`RELOAD_SECS`].
/// Fails closed (503) rather than let revoked sessions or taken-down records
/// through: an owner that can't be read falls back to a view at most
/// [`STALE_MAX_SECS`] old. A shard in flight (moving, reopening) takes no
/// writes, so a view from before the move is used at once, and without one
/// the load waits for the move (one probe per shard), then answers
/// ShardMoved: nothing was done, so the entry node resends the request (a
/// write or a query) to whoever owns the shard by then.
pub(super) async fn ctl(app: &App, did: &str) -> XResult<Arc<Ctl>> {
    let e = ext(app);
    let now = now_secs();
    let local = app.partitions.for_key(did).map(|p| (p.id, p.epoch));
    let cached = e.ctl.read().get(did).cloned();
    if let Some(c) = &cached {
        let fresh = match (c.local, local) {
            (Some(a), Some(b)) => a == b && now.saturating_sub(c.at) < LOCAL_RELOAD_SECS,
            (None, None) => now.saturating_sub(c.at) < RELOAD_SECS,
            _ => false,
        };
        if fresh {
            return Ok(c.clone());
        }
    }
    let gen0 = e.gen.load(Ordering::SeqCst);
    let (r, joined) = e.ctl_loads.single_flight(did, gen0, || load_ctl(app, &e, did, gen0, cached)).await;
    if joined {
        crate::metrics::CTL_LOADS.with_label_values(&["coalesced"]).inc();
    }
    r
}

async fn load_ctl(app: &App, e: &Ext, did: &str, gen0: u64, cached: Option<Arc<Ctl>>) -> XResult<Arc<Ctl>> {
    use super::ctl_load::{in_flight, Attempt};
    let start = std::time::Instant::now();
    // waiting out the move here is what lets a read through; a forwarded
    // request still answers before its entry node's deadline (which then
    // resends it)
    let move_budget = if crate::forward::is_forwarded() { CTL_MOVE_WAIT_FORWARDED } else { CTL_RETRY_FOR };
    let mut wait = std::time::Duration::from_millis(50);
    let failed = loop {
        let now = now_secs();
        let shard = app.partitions.shard_of(did);
        let probe = match e.ctl_loads.attempt(shard) {
            Attempt::Go(p) => p,
            Attempt::Wait(d) => {
                if let Some(c) = stale(&cached, now) {
                    crate::metrics::CTL_LOADS.with_label_values(&["stale_moving"]).inc();
                    return Ok(c);
                }
                let left = move_budget.saturating_sub(start.elapsed());
                if left.is_zero() {
                    break moved(did);
                }
                e.ctl_loads.wait(shard, d.min(left)).await;
                continue;
            }
        };
        let local = app.partitions.for_key(did).map(|p| (p.id, p.epoch));
        if let Some(sp) = &app.spaces {
            sp.cache_fills.fetch_add(1, Ordering::Relaxed);
        }
        match load_sets(app, did, local).await {
            Ok(c) => {
                e.ctl_loads.reachable(shard, probe);
                crate::metrics::CTL_LOADS.with_label_values(&["loaded"]).inc();
                let c = Arc::new(c);
                let mut m = e.ctl.write();
                // a change since the read began: use it for this check only
                if e.gen.load(Ordering::SeqCst) == gen0 {
                    // full: evict the views older than RELOAD_SECS, else all of
                    // them (a dropped view only costs a re-read)
                    let cap = crate::caches::cap(crate::caches::Cache::SecurityControls);
                    if m.len() >= cap && !m.contains_key(did) {
                        m.retain(|_, v| now.saturating_sub(v.at) < RELOAD_SECS);
                        if m.len() >= cap {
                            m.clear();
                        }
                    }
                    m.insert(did.to_string(), c.clone());
                }
                return Ok(c);
            }
            Err(err) if in_flight(&err) => {
                e.ctl_loads.moving(shard, probe);
                if let Some(c) = stale(&cached, now) {
                    crate::metrics::CTL_LOADS.with_label_values(&["stale_moving"]).inc();
                    return Ok(c);
                }
                if start.elapsed() >= move_budget {
                    break moved(did);
                }
            }
            // an owner timing out or erroring: retried briefly, then the
            // stale view or 503
            Err(err) => {
                drop(probe);
                if start.elapsed() + wait >= CTL_RETRY_FOR {
                    tracing::warn!(%did, "loading session revocations/takedowns failed: {}", err.message);
                    let r = stale_or_unavailable(cached, now);
                    crate::metrics::CTL_LOADS
                        .with_label_values(&[if r.is_ok() { "stale_unreachable" } else { "unavailable" }])
                        .inc();
                    return r;
                }
                tokio::time::sleep(wait).await;
                wait = (wait * 2).min(std::time::Duration::from_millis(500));
            }
        }
    };
    crate::metrics::CTL_LOADS.with_label_values(&["moved"]).inc();
    tracing::debug!(%did, "security controls unavailable: shard in flight");
    Err(failed)
}

/// `cached` if young enough to stand in for an unreadable owner.
fn stale(cached: &Option<Arc<Ctl>>, now: u64) -> Option<Arc<Ctl>> {
    cached.as_ref().filter(|c| now.saturating_sub(c.at) <= STALE_MAX_SECS).cloned()
}

fn moved(did: &str) -> XrpcError {
    XrpcError::unavailable(
        crate::forward::SHARD_MOVED,
        format!("security state of {did} is unavailable while its shard moves; try again"),
    )
}

fn stale_or_unavailable(cached: Option<Arc<Ctl>>, now: u64) -> XResult<Arc<Ctl>> {
    stale(&cached, now)
        .ok_or_else(|| XrpcError::unavailable("Unavailable", "account security state is unavailable; try again"))
}

pub(super) fn ctl_changed(app: &App, did: &str) {
    let e = ext(app);
    e.gen.fetch_add(1, Ordering::SeqCst);
    e.ctl.write().remove(did);
}

pub(super) async fn put_sec(app: &App, did: &str, muts: Vec<Mutation>) -> XResult<()> {
    let keys: Vec<Mutation> = muts.iter().map(|m| Mutation { key: m.key.clone(), val: None }).collect();
    let r = app.put_private(did, muts).await;
    ctl_changed(app, did);
    if r.is_ok() {
        super::space::sec_written(app, did, &keys).await;
    }
    r
}

#[derive(Clone, Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Mail {
    pub to: String,
    pub subject: String,
    /// Plain text; with `html`, sent as multipart/alternative.
    pub body: String,
    pub html: Option<String>,
    /// confirm_email | update_email | reset_password | delete_account | plc_operation | auth_factor | admin
    pub purpose: String,
    /// The account it's for, kept in the console's mail log.
    pub did: Option<String>,
    pub token: Option<String>,
    pub sent_at: String,
}

pub trait Mailer: Send + Sync {
    fn send(&self, mail: &Mail);
}

pub struct LogMailer;

impl Mailer for LogMailer {
    fn send(&self, m: &Mail) {
        // Never the token or body, at any level: they are credentials (a
        // debug log is still shipped to log storage).
        tracing::info!(to = %m.to, subject = %m.subject, purpose = %m.purpose, has_token = m.token.is_some(), body_bytes = m.body.len(), "mail (log mailer: email disabled, not sent)");
        crate::mail::MAIL_LOG.logged(&m.purpose, m.did.as_deref(), &m.to);
    }
}

/// What [`deliver`] needs: the recipient's, the node's and the cluster's
/// mail budgets spent ([`mail_permit`]).
#[must_use]
pub(super) struct MailPermit(&'static str, Option<String>);

const MAIL_LIMITED: &str = "Too many emails sent to this account; try again later";

pub(crate) fn is_mail_limited(e: &XrpcError) -> bool {
    e.status == StatusCode::TOO_MANY_REQUESTS && e.message == MAIL_LIMITED
}

/// Taken before the token is minted, so a refused request leaves the last
/// mailed token working. The recipient is the account `did`, else the
/// normalized address. `report`: see `Limiter::consume_unbypassable`.
pub(super) async fn mail_permit(
    app: &App,
    did: Option<&str>,
    to: &str,
    purpose: &'static str,
    report: bool,
) -> XResult<MailPermit> {
    use crate::ratelimit::{MAIL_NODE_HOUR, MAIL_RECIPIENT_DAY, MAIL_RECIPIENT_HOUR, NODE_KEY};
    let key = match did {
        Some(d) => d.to_string(),
        None => format!("mailto:{}", to.trim().to_ascii_lowercase()),
    };
    let route = format!("mail:{purpose}");
    let limited = |reason: &str| {
        crate::mail::MAIL_SUPPRESSED.with_label_values(&[purpose, reason]).inc();
        crate::mail::MAIL_LOG.suppressed(purpose, did, to, reason);
        XrpcError {
            status: StatusCode::TOO_MANY_REQUESTS,
            error: "RateLimitExceeded".into(),
            message: MAIL_LIMITED.into(),
        }
    };
    let rl = &app.ratelimit;
    rl.consume_unbypassable(&[&MAIL_RECIPIENT_DAY, &MAIL_RECIPIENT_HOUR], &key, &route, report)
        .map_err(|_| limited("recipient_limit"))?;
    rl.consume_unbypassable(&[&MAIL_NODE_HOUR], NODE_KEY, &route, report).map_err(|_| {
        tracing::warn!(purpose, "mail not sent: this node's mail budget (mail-node-hour) is spent");
        limited("node_limit")
    })?;
    rl.consume_cluster_mail(&app.store, &route, report).await.map_err(|_| {
        tracing::warn!(purpose, "mail not sent: the cluster's mail budget (mail-cluster-day) is spent");
        limited("cluster_limit")
    })?;
    Ok(MailPermit(purpose, did.map(String::from)))
}

pub(super) fn deliver(app: &App, permit: MailPermit, to: &str, email: crate::mail::Email<'_>) {
    debug_assert_eq!(permit.0, email.purpose());
    let r = email.render(&app.config.email_branding, &app.public_url);
    let mail = Mail {
        to: to.to_string(),
        subject: r.subject,
        body: r.text,
        html: Some(r.html),
        purpose: email.purpose().to_string(),
        did: permit.1,
        token: Some(email.token()).filter(|t| !t.is_empty()).map(String::from),
        sent_at: crate::events::now_rfc3339(),
    };
    send_mail(app, mail, app.config.mailer.as_ref());
}

/// `content` is HTML, as in the reference's ModerationMailer.
pub(super) fn deliver_moderation(app: &App, did: &str, to: &str, subject: &str, content: &str) {
    let mail = Mail {
        to: to.to_string(),
        subject: subject.to_string(),
        body: crate::mail::html_to_text(content),
        html: Some(content.to_string()),
        purpose: "admin".into(),
        did: Some(did.to_string()),
        token: None,
        sent_at: crate::events::now_rfc3339(),
    };
    let m = app.config.moderation_mailer.as_ref().or(app.config.mailer.as_ref());
    send_mail(app, mail, m);
}

/// Dev mode also keeps the mail for vlpds.admin.getDevMail.
fn send_mail(app: &App, mail: Mail, mailer: Option<&crate::mail::SharedMailer>) {
    match mailer {
        Some(m) => m.send(&mail),
        None => LogMailer.send(&mail),
    }
    if app.config.dev_mode {
        let e = ext(app);
        let mut box_ = e.dev_mail.lock();
        let v = box_.entry(mail.to.to_ascii_lowercase()).or_default();
        v.push(mail);
        if v.len() > 50 {
            v.remove(0);
        }
    }
}

/// Only a keyed digest of the token is stored, so bucket readers can't use a
/// live one.
#[derive(serde::Serialize, serde::Deserialize)]
struct EmailToken {
    token_hash: String,
    requested_at: u64,
}

/// Keyed by the server secret (not in the bucket): tokens have ~50 bits, so
/// an unkeyed hash could be brute-forced offline within their 15 minutes.
fn email_token_digest(app: &App, token: &str) -> String {
    let key = crate::oauth::util::derive_secret(&app.config.jwt_secret, "email-token");
    hex::encode(crate::oauth::util::hmac_sha256(&key, &[token.trim().to_ascii_uppercase().as_bytes()]))
}

pub(super) const EMAIL_PURPOSES: &[&str] =
    &["confirm_email", "update_email", "reset_password", "delete_account", "plc_operation", super::email2fa::PURPOSE];

/// Replaces any previous token for `purpose`.
pub(super) async fn create_email_token(app: &App, did: &str, purpose: &str) -> XResult<String> {
    let token = random_token().to_ascii_uppercase();
    let digest = email_token_digest(app, &token);
    let rec = EmailToken { token_hash: digest.clone(), requested_at: now_ms() };
    app.put_private(did, vec![pmut(did, &format!("etok/{purpose}"), Some(to_json_bytes(&rec)))]).await?;
    if purpose == "reset_password" {
        let routing = format!("_reset:{digest}");
        app.put_private(&routing, vec![pmut(&routing, "t", Some(did.as_bytes().to_vec()))]).await?;
    }
    Ok(token)
}

pub(super) async fn assert_email_token(app: &App, did: &str, purpose: &str, token: &str) -> XResult<()> {
    let rec: Option<EmailToken> = get_json(app, did, &format!("etok/{purpose}")).await?;
    let Some(rec) = rec.filter(|r| crate::auth::token_eq(&r.token_hash, &email_token_digest(app, token))) else {
        return Err(invalid_token("Token is invalid"));
    };
    if now_ms().saturating_sub(rec.requested_at) > EMAIL_TOKEN_TTL_MS {
        return Err(expired_token("Token is expired"));
    }
    Ok(())
}

/// How long ago the live token for `purpose` was minted, if there is one.
pub(super) async fn email_token_age_ms(app: &App, did: &str, purpose: &str) -> XResult<Option<u64>> {
    let rec: Option<EmailToken> = get_json(app, did, &format!("etok/{purpose}")).await?;
    Ok(rec.map(|r| now_ms().saturating_sub(r.requested_at)).filter(|age| *age <= EMAIL_TOKEN_TTL_MS))
}

pub(super) async fn delete_email_tokens(app: &App, did: &str, purposes: &[&str]) -> XResult<()> {
    let muts = purposes.iter().map(|p| pmut(did, &format!("etok/{p}"), None)).collect();
    app.put_private(did, muts).await
}

fn email_path(app: &App, email: &str) -> object_store::path::Path {
    let h = hex::encode(Sha256::digest(email.to_ascii_lowercase().as_bytes()));
    object_store::path::Path::from(format!("{}/email/{}", app.store.prefix, h))
}

pub(super) async fn did_by_email(app: &App, email: &str) -> XResult<Option<String>> {
    match app.store.raw.get(&email_path(app, email)).await {
        Ok(r) => Ok(Some(String::from_utf8_lossy(&r.bytes().await.map_err(XrpcError::from_err)?).to_string())),
        Err(object_store::Error::NotFound { .. }) => Ok(None),
        Err(e) => Err(XrpcError::from_err(e)),
    }
}

/// Ok(false) when another account holds it.
pub(super) async fn claim_email(app: &App, email: &str, did: &str) -> XResult<bool> {
    let email = email.to_ascii_lowercase();
    claim(app, &email_path(app, &email), did, move |a: &Account| {
        a.email.as_deref().is_some_and(|e| e.eq_ignore_ascii_case(&email))
    })
    .await
}

/// How old a handle or email claim must be before it can be taken over
/// from a holder without an account standing on it ([`claim`]): longer than
/// any createAccount / updateHandle / updateEmail between its claim and
/// its account write (the account doesn't exist yet while it's created).
pub const STALE_CLAIM_GRACE: std::time::Duration = std::time::Duration::from_secs(15 * 60);

#[doc(hidden)]
pub fn set_stale_claim_grace(app: &App, grace: std::time::Duration) {
    ext(app).claim_grace_ms.store(grace.as_millis() as u64, Ordering::Relaxed);
}

/// (holder, version, age)
async fn read_claim(
    app: &App,
    path: &object_store::path::Path,
) -> XResult<Option<(String, object_store::UpdateVersion, std::time::Duration)>> {
    match app.store.raw.get(path).await {
        Ok(r) => {
            let meta = r.meta.clone();
            let holder = String::from_utf8_lossy(&r.bytes().await.map_err(XrpcError::from_err)?).to_string();
            let age = (chrono::Utc::now() - meta.last_modified).to_std().unwrap_or_default();
            Ok(Some((holder, object_store::UpdateVersion { e_tag: meta.e_tag, version: meta.version }, age)))
        }
        Err(object_store::Error::NotFound { .. }) => Ok(None),
        Err(e) => Err(XrpcError::from_err(e)),
    }
}

/// Global uniqueness of a handle or email: a conditional create of the claim
/// object holding `did`. Ok(true): claimed or already ours. Another DID's
/// claim is taken over only when stale (past the grace period, and its
/// holder definitely has no account standing on it per `holds`; a failed
/// lookup is not "no account"), by a compare-and-swap on the version read,
/// so two takers can't both win and a holder mid-createAccount keeps it.
async fn claim(
    app: &App,
    path: &object_store::path::Path,
    did: &str,
    holds: impl Fn(&Account) -> bool,
) -> XResult<bool> {
    let payload = || PutPayload::from(did.as_bytes().to_vec());
    let grace = std::time::Duration::from_millis(ext(app).claim_grace_ms.load(Ordering::Relaxed));
    for _ in 0..3 {
        let create = PutOptions { mode: PutMode::Create, ..Default::default() };
        match app.store.raw.put_opts(path, payload(), create).await {
            Ok(_) => return Ok(true),
            Err(object_store::Error::AlreadyExists { .. }) => {}
            Err(e) => return Err(XrpcError::from_err(e)),
        }
        // released meanwhile: create again
        let Some((holder, version, age)) = read_claim(app, path).await? else { continue };
        if holder == did {
            return Ok(true);
        }
        if age < grace {
            return Ok(false);
        }
        let stale = match super::internal::account_anywhere(app, &holder).await {
            Ok(a) => !holds(&a),
            Err(e) => e.error == "AccountNotFound",
        };
        if !stale || (version.e_tag.is_none() && version.version.is_none()) {
            return Ok(false);
        }
        let swap = PutOptions { mode: PutMode::Update(version), ..Default::default() };
        match app.store.raw.put_opts(path, payload(), swap).await {
            Ok(_) => {
                tracing::info!(%did, %holder, claim = %path, "took over a stale claim");
                return Ok(true);
            }
            // changed since read (another taker, or released): look again
            Err(
                object_store::Error::Precondition { .. }
                | object_store::Error::AlreadyExists { .. }
                | object_store::Error::NotFound { .. },
            ) => {}
            Err(e) => return Err(XrpcError::from_err(e)),
        }
    }
    Ok(false)
}

pub(super) async fn release_email(app: &App, email: &str, did: &str) {
    if let Err(e) = try_release_email(app, email, did).await {
        tracing::warn!(%did, "failed to release email claim: {}", e.message);
    }
}

async fn try_release_email(app: &App, email: &str, did: &str) -> XResult<()> {
    if did_by_email(app, email).await?.as_deref() == Some(did) {
        delete_claim(app, &email_path(app, email)).await?;
    }
    Ok(())
}

async fn delete_claim(app: &App, path: &object_store::path::Path) -> XResult<()> {
    match app.store.raw.delete(path).await {
        Ok(()) | Err(object_store::Error::NotFound { .. }) => Ok(()),
        Err(e) => Err(XrpcError::from_err(e)),
    }
}

fn handle_path(app: &App, handle: &str) -> object_store::path::Path {
    object_store::path::Path::from(format!("{}/handle/{}", app.store.prefix, handle))
}

/// Ok(false) when taken.
pub(super) async fn claim_handle(app: &App, handle: &str, did: &str) -> XResult<bool> {
    let h = handle.to_string();
    claim(app, &handle_path(app, handle), did, move |a: &Account| a.handle == h).await
}

pub(super) async fn release_handle(app: &App, handle: &str, did: &str) {
    if let Err(e) = try_release_handle(app, handle, did).await {
        tracing::warn!(%did, %handle, "failed to release handle claim: {}", e.message);
    }
}

async fn try_release_handle(app: &App, handle: &str, did: &str) -> XResult<()> {
    if app.resolve_handle(handle).await?.as_deref() == Some(did) {
        delete_claim(app, &handle_path(app, handle)).await?;
    }
    Ok(())
}

pub(super) fn normalize_handle(h: &str) -> XResult<String> {
    let h = h.trim().to_ascii_lowercase();
    if !super::syntax::valid_handle(&h) {
        return Err(XrpcError::bad("InvalidHandle", "Input/handle must be a valid handle"));
    }
    if super::syntax::disallowed_handle_tld(&h) {
        return Err(XrpcError::bad("InvalidHandle", "Handle TLD is invalid or disallowed"));
    }
    Ok(h)
}

/// Admins skip it. Runs after normalization, before the domain checks (the
/// reference's order).
pub(super) fn ensure_no_slur(handle: &str) -> XResult<()> {
    if crate::handle_policy::has_explicit_slur(handle) {
        return Err(XrpcError::bad("InvalidHandle", "Inappropriate language in handle"));
    }
    Ok(())
}

/// The reference's ensureHandleServiceConstraints.
pub(super) fn ensure_service_handle(app: &App, handle: &str, allow_reserved: bool) -> XResult<()> {
    let Some((front, _)) = app.handle_domains.under(handle) else {
        return Err(XrpcError::bad("UnsupportedDomain", "Not a supported handle domain"));
    };
    if front.contains('.') {
        return Err(XrpcError::bad("InvalidHandle", "Invalid characters in handle"));
    }
    if front.len() < 3 {
        return Err(XrpcError::bad("InvalidHandle", "Handle too short"));
    }
    if front.len() > 18 {
        return Err(XrpcError::bad("InvalidHandle", "Handle too long"));
    }
    if !allow_reserved && crate::handle_policy::is_reserved(front) {
        return Err(XrpcError::bad("HandleNotAvailable", "Reserved handle"));
    }
    Ok(())
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct AppPassRef {
    pub name: String,
    pub privileged: bool,
    /// A scoped app password's scopes, which its sessions keep across
    /// refreshes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scopes: Option<String>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct RefreshState {
    family: String,
    exp: u64,
    #[serde(default)]
    app_password: Option<AppPassRef>,
    created_at: u64,
    /// Set once rotated: reuse within the grace period re-issues this id.
    #[serde(default)]
    next_id: Option<String>,
    /// The passkey that signed this in (`super::passkeys::auth_ref`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    auth_cred: Option<String>,
    /// The client address at sign-in, and at this row's refresh (as rate
    /// limits resolve it), for the console.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    created_ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ip: Option<String>,
}

fn access_scope(ap: &Option<AppPassRef>) -> &'static str {
    match ap {
        None => SCOPE_ACCESS,
        Some(a) if a.privileged => SCOPE_APP_PASS_PRIVILEGED,
        Some(_) => SCOPE_APP_PASS,
    }
}

fn issue_pair(
    app: &App,
    did: &str,
    scope: &str,
    app_pass_scope: Option<&str>,
    family: &str,
    refresh_id: &str,
) -> (String, String) {
    (
        app.jwt.issue_scoped(did, scope, app_pass_scope, ACCESS_TTL, "at+jwt", Some(family)),
        app.jwt.issue_with_jti(did, SCOPE_REFRESH, REFRESH_TTL, "refresh+jwt", Some(refresh_id)),
    )
}

/// The account's credential epoch, "" if never revoked. Every revoke-all
/// replaces it in the same conditional write that deletes the sessions, and
/// a login creates its session only on condition that the epoch it read
/// ([`epoch_for_login`]) is unchanged, so a login racing a revocation either
/// lands first (and is deleted) or fails, with no clocks involved. DESIGN.md
/// "Auth state under concurrency".
pub async fn auth_epoch(app: &App, did: &str) -> XResult<String> {
    Ok(get_json::<String>(app, did, AUTH_EPOCH).await?.unwrap_or_default())
}

pub fn auth_epoch_cond(epoch: &str) -> super::cas::Cond {
    super::cas::Cond::eq(AUTH_EPOCH, (!epoch.is_empty()).then(|| Bytes::from(to_json_bytes(&epoch))))
}

pub fn new_auth_epoch_op() -> super::cas::Op {
    super::cas::Op::put(AUTH_EPOCH, Some(Bytes::from(to_json_bytes(&random_hex(16)))))
}

/// The epoch to create a session under after a password check against
/// `checked`, or None if the password changed since (the login must fail).
/// The epoch is read first, so a password change the re-read misses
/// replaced the epoch after it was read.
pub async fn epoch_for_login(app: &App, checked: &Account) -> XResult<Option<String>> {
    let epoch = auth_epoch(app, &checked.did).await?;
    let now = super::internal::account_anywhere(app, &checked.did).await?;
    Ok((now.password_hash == checked.password_hash).then_some(epoch))
}

pub(super) fn cas_conflict() -> XrpcError {
    XrpcError::unavailable("TemporarilyUnavailable", "concurrent update; retry")
}

/// Starts a new session family: (accessJwt, refreshJwt). `takendown` gives
/// the access token the restricted scope (the reference's createSession for
/// a soft-deleted account). `epoch` ([`epoch_for_login`]) must still be
/// current for the session to be created.
pub(super) async fn create_session_tokens(
    app: &App,
    did: &str,
    ap: Option<AppPassRef>,
    takendown: bool,
    epoch: Option<&str>,
    auth_cred: Option<String>,
    ip: Option<std::net::IpAddr>,
) -> XResult<(String, String)> {
    use super::cas::{Cond, Op};
    let family = new_family_id();
    let rid = random_hex(24);
    let scope = if takendown { SCOPE_TAKENDOWN } else { access_scope(&ap) };
    let ip = ip.map(|i| i.to_string());
    let st = RefreshState {
        family: family.clone(),
        exp: now_secs() + REFRESH_TTL,
        app_password: ap,
        created_at: now_secs(),
        next_id: None,
        auth_cred,
        created_ip: ip.clone(),
        ip,
    };
    let name = format!("sess/{rid}");
    let mut conds = vec![Cond::eq(&name, None)];
    conds.extend(epoch.map(auth_epoch_cond));
    let out = app.private_cas(did, conds, vec![Op::put(&name, Some(Bytes::from(to_json_bytes(&st))))]).await?;
    if !out.applied {
        return Err(XrpcError::auth("Credentials were revoked during sign-in"));
    }
    let ap_scope = st.app_password.as_ref().and_then(|a| a.scopes.as_deref()).filter(|_| !takendown);
    Ok(issue_pair(app, did, scope, ap_scope, &family, &rid))
}

/// Revokes the families' access tokens.
async fn revoke_families(app: &App, did: &str, families: &[String]) -> XResult<()> {
    if families.is_empty() {
        return Ok(());
    }
    let exp = now_secs() + REVOKE_TTL;
    let muts = families
        .iter()
        .map(|fam| pmut(did, &format!("{REVOKED_FAMILY}{fam}"), Some(to_json_bytes(&json!({"exp": exp})))))
        .collect();
    put_sec(app, did, muts).await
}

/// Deletes the refresh rows, rejects outstanding access tokens and replaces
/// the credential epoch in one conditional write at the owner: a refresh
/// racing it either rotated first (its rows are deleted here) or finds its
/// row gone, and a login racing it fails ([`auth_epoch`]).
pub(super) async fn revoke_all_sessions(app: &App, did: &str) -> XResult<()> {
    use super::cas::Op;
    let before = crate::tid::now_micros();
    let exp = now_secs() + REVOKE_ALL_TTL;
    let ops = vec![
        Op::put(
            format!("{REVOKED_ALL}{before:016x}"),
            Some(Bytes::from(to_json_bytes(&json!({"before": before, "exp": exp})))),
        ),
        new_auth_epoch_op(),
        Op::DeletePrefix { prefix: "sess/".into() },
        Op::DeletePrefix { prefix: super::signin::TRUST.into() },
    ];
    app.private_cas(did, Vec::new(), ops).await?;
    Ok(())
}

/// For the private-row GC: Some(expired) for a revocation row, None for any
/// other. Unparseable rows count as expired. Deleted accounts keep these
/// rows until they expire, so a DID that comes back can't revive old tokens.
pub fn revocation_expired(routing: &str, name: &str, val: &[u8], now: u64) -> Option<bool> {
    if !routing.starts_with("did:") || !(name.starts_with(REVOKED_ALL) || name.starts_with(REVOKED_FAMILY)) {
        return None;
    }
    Some(serde_json::from_slice::<J>(val).ok().and_then(|j| j["exp"].as_u64()).is_none_or(|exp| exp < now))
}

/// No lock needed: a revocation row is never rewritten once expired (a new
/// revocation is a new `d/` row; a family is revoked once).
pub async fn drop_revocation(app: &App, did: &str, name: &str) -> XResult<()> {
    put_sec(app, did, vec![pmut(did, name, None)]).await
}

/// Access tokens stay valid until they expire, as the reference's takedown
/// (`revokeRefreshTokensByDid`): a taken-down account may still e.g. sync its
/// own repo. A conditional write, so no rotation lands between the listing
/// and the delete.
pub(super) async fn revoke_refresh_tokens(app: &App, did: &str) -> XResult<()> {
    app.private_cas(did, Vec::new(), vec![super::cas::Op::DeletePrefix { prefix: "sess/".into() }]).await?;
    Ok(())
}

/// Deletes the refresh rows matching `pred`, each on condition that it is
/// unchanged: a racing rotation changes its row, so the delete is redone
/// over the new rows and no rotation of a matched session survives.
async fn delete_sessions_where(
    app: &App,
    did: &str,
    pred: impl Fn(&str, &RefreshState) -> bool,
) -> XResult<Vec<RefreshState>> {
    use super::cas::{Cond, Op};
    for _ in 0..CAS_ROUNDS {
        let (mut conds, mut ops, mut out) = (Vec::new(), Vec::new(), Vec::new());
        for (name, v) in super::internal::scan_private_anywhere(app, did, "sess/").await? {
            let Ok(st) = serde_json::from_slice::<RefreshState>(&v) else { continue };
            if pred(&name, &st) {
                conds.push(Cond::eq(&name, Some(v)));
                ops.push(Op::put(&name, None));
                out.push(st);
            }
        }
        if ops.is_empty() || app.private_cas(did, conds, ops).await?.applied {
            return Ok(out);
        }
    }
    Err(cas_conflict())
}

/// Every OAuth and legacy session, every device sign-in and code (the
/// credential epoch) and every trusted browser: what a password change does.
pub(super) async fn revoke_everything(app: &App, did: &str) -> XResult<()> {
    crate::oauth::store::revoke_all_sessions(app, did).await.map_err(|e| XrpcError::internal(e.description))?;
    revoke_all_sessions(app, did).await
}

/// The OAuth and legacy sessions a passkey (`auth_ref`) signed in. Device
/// sign-ins and codes it approved are refused when used
/// (`passkeys::still_registered`).
pub(super) async fn revoke_signed_in_with(app: &App, did: &str, auth_ref: &str) -> XResult<()> {
    let gone = delete_sessions_where(app, did, |_, st| st.auth_cred.as_deref() == Some(auth_ref)).await?;
    let fams: Vec<String> = gone.into_iter().map(|st| st.family).collect();
    revoke_families(app, did, &fams).await?;
    for s in crate::oauth::store::list_sessions(app, did).await.map_err(|e| XrpcError::internal(e.description))? {
        if s.auth_cred.as_deref() == Some(auth_ref) {
            crate::oauth::store::delete_session(app, did, &s.id)
                .await
                .map_err(|e| XrpcError::internal(e.description))?;
        }
    }
    Ok(())
}

/// The account's password and app-password sessions (`sess/` rows), one per
/// session family: rotation adds rows, the family stays.
pub(super) async fn legacy_sessions(app: &App, did: &str) -> XResult<Vec<J>> {
    let mut fams: HashMap<String, RefreshState> = HashMap::new();
    for (_, v) in super::internal::scan_private_anywhere(app, did, "sess/").await? {
        let Ok(st) = serde_json::from_slice::<RefreshState>(&v) else { continue };
        let live = |s: &RefreshState| (s.next_id.is_none(), s.created_at);
        match fams.get(&st.family) {
            Some(cur) if live(cur) >= live(&st) => {}
            _ => {
                fams.insert(st.family.clone(), st);
            }
        }
    }
    let now = now_secs();
    let mut out: Vec<J> = fams
        .into_values()
        .filter(|st| st.exp > now)
        .map(|st| {
            // the family id starts with its issue time (micros, hex)
            let started = u64::from_str_radix(st.family.get(..16).unwrap_or(""), 16).ok().map(|us| us / 1000);
            json!({
                "id": format!("legacy:{}", st.family),
                "kind": if st.app_password.is_some() { "appPassword" } else { "legacy" },
                "appPassword": st.app_password.as_ref().map(|a| &a.name),
                "privileged": st.app_password.as_ref().is_some_and(|a| a.privileged),
                "signedInAt": started,
                "refreshedAt": st.created_at * 1000,
                "expiresAt": st.exp * 1000,
                "passkey": st.auth_cred.is_some(),
                "ip": st.ip,
                "signedInIp": st.created_ip,
            })
        })
        .collect();
    out.sort_by_key(|j| std::cmp::Reverse(j["refreshedAt"].as_u64()));
    Ok(out)
}

/// One password or app-password session family: its refresh rows and its
/// access tokens. How many rows went.
pub(super) async fn revoke_legacy_family(app: &App, did: &str, family: &str) -> XResult<usize> {
    let gone = delete_sessions_where(app, did, |_, st| st.family == family).await?;
    revoke_families(app, did, &[family.to_string()]).await?;
    Ok(gone.len())
}

async fn revoke_app_password_sessions(app: &App, did: &str, name: &str) -> XResult<()> {
    let gone =
        delete_sessions_where(app, did, |_, st| st.app_password.as_ref().is_some_and(|a| a.name == name)).await?;
    let fams: Vec<String> = gone.into_iter().map(|st| st.family).collect();
    revoke_families(app, did, &fams).await
}

/// Legacy (non-OAuth) access JWTs. Hot path: no storage reads.
pub async fn verify_bearer(app: &App, token: &str) -> XResult<Credentials> {
    let c = app.jwt.verify_signature_cached(token).ok_or_else(|| invalid_token("Token could not be verified"))?;
    if c.aud != app.jwt.service_did || !c.sub.starts_with("did:") {
        return Err(invalid_token("Malformed token"));
    }
    if c.exp < now_secs() {
        return Err(expired_token("Token has expired"));
    }
    let app_pass = |privileged| Credentials::AppPassword {
        did: c.sub.clone(),
        privileged,
        scopes: c.app_pass_scope.as_deref().map(super::oauth::ScopeSet::new),
    };
    let creds = match c.scope.as_str() {
        SCOPE_APP_PASS => app_pass(false),
        SCOPE_APP_PASS_PRIVILEGED => app_pass(true),
        _ if c.app_pass_scope.is_some() => return Err(bad_scope()),
        SCOPE_ACCESS => Credentials::Session { did: c.sub.clone() },
        SCOPE_TAKENDOWN => Credentials::Takendown { did: c.sub.clone() },
        _ => return Err(bad_scope()),
    };
    if ctl(app, &c.sub).await?.is_revoked(c.jti.as_deref(), c.iat) {
        return Err(expired_token("Token has been revoked"));
    }
    Ok(creds)
}

fn refresh_claims(app: &App, headers: &HeaderMap, allow_expired: bool) -> XResult<crate::auth::Claims> {
    let tok = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "AuthMissing", "Authentication Required"))?;
    let c = app.jwt.verify_signature(tok.trim()).ok_or_else(|| invalid_token("Token could not be verified"))?;
    // the reference's jose typ check (refresh+jwt) fails first for an
    // access token: "Token could not be verified", not "Bad token scope"
    if c.scope != SCOPE_REFRESH {
        return Err(invalid_token("Token could not be verified"));
    }
    if c.aud != app.jwt.service_did || c.jti.is_none() {
        return Err(invalid_token("Malformed token"));
    }
    if !allow_expired && c.exp < now_secs() {
        return Err(expired_token("Token has expired"));
    }
    Ok(c)
}

pub(super) async fn session_info(app: &App, a: &Account, include_email: bool) -> J {
    let mut out = json!({"did": a.did, "handle": a.handle, "active": a.status.is_none()});
    // reference safeResolveDidDoc: omitted when it doesn't resolve
    if let Ok(doc) = super::identity::account_did_doc(app, a).await {
        out["didDoc"] = (*doc).clone();
    }
    if let Some(s) = &a.status {
        out["status"] = json!(s);
    }
    if let Some(t) = super::scheduled_deletion::scheduled_at(app, a) {
        out["deletionScheduledAt"] = json!(t);
    }
    if include_email {
        if let Some(e) = &a.email {
            out["email"] = json!(e);
        }
        out["emailConfirmed"] = json!(a.email_confirmed);
        out["emailAuthFactor"] = json!(super::email2fa::enabled(a));
    }
    out
}

async fn describe_server(State(app): AppState) -> Json<J> {
    // As the reference: unset links and contact fields are omitted.
    let mut links = serde_json::Map::new();
    if let Some(u) = &app.config.privacy_policy_url {
        links.insert("privacyPolicy".into(), json!(u));
    }
    if let Some(u) = &app.config.terms_of_service_url {
        links.insert("termsOfService".into(), json!(u));
    }
    let mut contact = serde_json::Map::new();
    if let Some(e) = &app.config.contact_email_address {
        contact.insert("email".into(), json!(e));
    }
    let mut out = json!({
        "did": app.jwt.service_did,
        "availableUserDomains": app.handle_domains.names().iter().map(|d| format!(".{d}")).collect::<Vec<_>>(),
        "inviteCodeRequired": app.config.invite_required,
        "blobUploadLimit": app.config.max_blob_size,
        "links": links,
        "contact": contact,
    });
    // Under a vlpds key so other clients don't read it as protocol; absent
    // without --spaces, so that response stays the reference's shape.
    if app.config.spaces {
        out["vlpds"] = json!({"spaces": true});
    }
    Json(out)
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub(super) struct CreateAccountIn {
    pub handle: String,
    pub email: Option<String>,
    pub password: Option<String>,
    pub invite_code: Option<String>,
    pub did: Option<String>,
    pub plc_op: Option<J>,
    /// Put first in the new DID's rotation keys.
    pub recovery_key: Option<String>,
}

/// Account flag: the DID was migrated in, so its document is not ours to
/// generate; activation and checkAccountStatus check the resolved one.
pub(super) const EXTERNAL_DID: &str = "externalDid";

pub(super) fn has_external_did(a: &Account) -> bool {
    a.extra.get(EXTERNAL_DID).and_then(|v| v.as_bool()).unwrap_or(false)
}

/// createAccount, with the reference's optional service auth
/// (`userServiceAuthOptional`): a Bearer token must be a service JWT for
/// this method, and its issuer may then bring its own DID (migration in).
async fn create_account(
    State(app): AppState,
    super::moderation::ClientIp(ip): super::moderation::ClientIp,
    headers: HeaderMap,
    Json(inp): Json<CreateAccountIn>,
) -> XResult<Json<J>> {
    const LXM: &str = "com.atproto.server.createAccount";
    let requester = super::authn::optional_service_auth(&app, &headers, LXM).await?;
    // The requester is the token's whole `iss` (the reference's
    // userServiceAuth credentials.did = payload.iss): a `did#service` issuer
    // (e.g. `#atproto_labeler`, verified with the DID's label key) is a
    // service of the DID, never the account holder, so it can't bring the DID.
    let requester = requester.filter(|r| !r.iss.contains('#'));
    let acct = create_account_inner(&app, inp, requester.as_ref().map(|r| r.iss.as_str())).await?;
    let (access, refresh) = create_session_tokens(&app, &acct.did, None, false, None, None, ip).await?;
    let mut out = json!({"handle": acct.handle, "did": acct.did, "accessJwt": access, "refreshJwt": refresh});
    if let Some(doc) = account_did_doc(&app, &acct).await {
        out["didDoc"] = doc;
    }
    Ok(Json(out))
}

/// The reference's safeResolveDidDoc with a forced refresh.
async fn account_did_doc(app: &App, a: &Account) -> Option<J> {
    if has_external_did(a) {
        app.did_resolver.invalidate(&a.did);
        return app.did_resolver.resolve(&a.did).await.ok().map(|d| (*d).clone());
    }
    Some(super::identity::did_doc(app, a))
}

/// createAccount and the OAuth sign-up page; the reference's local-PDS path
/// (validateInputsForLocalPds + createAccount):
/// - `plcOp` is refused (no entryway mode).
/// - Without `did`, the DID is minted; with PLC registration on, the account
///   is written only after the directory accepted its genesis op (a local
///   failure after that tombstones the DID, as the reference does).
/// - With `did` (migration in), `requester` (the verified service-auth
///   issuer) must be that DID. The account starts deactivated with an empty
///   repo and no firehose events until activateAccount.
/// - A given invite code is checked and recorded even if not required.
pub(super) async fn create_account_inner(app: &App, inp: CreateAccountIn, requester: Option<&str>) -> XResult<Account> {
    count_signup(create_account_checked(app, inp, requester, false).await)
}

/// The operator's createAccount (vlpds.admin.createAccount): as a sign-up,
/// but no invite code is needed when the server requires one.
pub(super) async fn create_account_by_operator(app: &App, inp: CreateAccountIn) -> XResult<Account> {
    count_signup(create_account_checked(app, inp, None, true).await)
}

fn count_signup(r: XResult<Account>) -> XResult<Account> {
    let result = match &r {
        Ok(_) => "created",
        Err(e) => signup_refusal(e),
    };
    crate::metrics::SIGNUPS.with_label_values(&[result]).inc();
    if r.is_ok() {
        crate::metrics::ACCOUNT_EVENTS.with_label_values(&["created"]).inc();
    }
    r
}

/// The `vlpds_signups_total` result.
fn signup_refusal(e: &XrpcError) -> &'static str {
    if e.status.is_server_error() {
        return "error";
    }
    match (e.error.as_str(), e.message.as_str()) {
        ("InvalidInviteCode", _) => "invite",
        (_, m) if m.starts_with("This email address is not supported") => "email_policy",
        (_, "Inappropriate language in handle" | "Reserved handle") => "handle_policy",
        ("HandleNotAvailable", _) => "taken",
        (_, m) if m.starts_with("Email already taken") => "taken",
        _ => "invalid",
    }
}

async fn create_account_checked(
    app: &App,
    inp: CreateAccountIn,
    requester: Option<&str>,
    operator: bool,
) -> XResult<Account> {
    if inp.plc_op.is_some() {
        return Err(invalid_request("Unsupported input: \"plcOp\""));
    }
    let password = inp.password.ok_or_else(|| invalid_request("Password is required"))?;
    if password.len() > NEW_PASSWORD_MAX_LENGTH {
        return Err(invalid_request(format!(
            "Password too long. Maximum length is {NEW_PASSWORD_MAX_LENGTH} characters."
        )));
    }
    let invite = inp.invite_code.as_deref().map(str::trim).filter(|c| !c.is_empty()).map(str::to_string);
    if app.config.invite_required && invite.is_none() && !operator {
        return Err(XrpcError::bad("InvalidInviteCode", "No invite code provided"));
    }
    // the request's spelling, echoed in "Email already taken" as the reference does
    let email_input = inp.email.as_deref().map(str::trim).unwrap_or_default().to_string();
    if email_input.is_empty() {
        return Err(invalid_request("Email is required"));
    }
    let email = email_input.to_ascii_lowercase();
    if !email_supported(&email) {
        return Err(invalid_request("This email address is not supported, please use a different email."));
    }
    let handle = normalize_handle(&inp.handle)?;
    ensure_no_slur(&handle)?;

    let recovery_key = inp.recovery_key.as_deref().filter(|k| !k.is_empty());
    if let (Some(k), Some(_)) = (recovery_key, &app.plc) {
        if !crate::plc::valid_did_key(k) {
            return Err(invalid_request("recoveryKey must be a secp256k1 or P-256 did:key"));
        }
    }
    let key = Arc::new(Keypair::generate());
    let mut genesis: Option<(Arc<crate::plc::Plc>, J)> = None;
    let (did, external) = match inp.did.as_deref() {
        Some(d) => {
            // checked before the handle, whose proof may be fetched
            if requester != Some(d) {
                return Err(XrpcError::auth(&format!("Missing auth to create account with did: {d}")));
            }
            if !is_atproto_did(d) {
                return Err(invalid_request("Invalid DID"));
            }
            super::identity::check_new_handle(app, &handle, d).await?;
            if account_if_exists(app, d).await?.is_some() {
                return Err(invalid_request("Account already exists"));
            }
            (d.to_string(), true)
        }
        None => {
            ensure_service_handle(app, &handle, false)?;
            match &app.plc {
                Some(plc) => {
                    let (did, op) = app.mint_plc_did(plc, &key.did_key(), &handle, recovery_key)?;
                    genesis = Some((plc.clone(), op));
                    (did, false)
                }
                None => (app.mint_local_did()?, false),
            }
        }
    };
    let claim = match &invite {
        Some(code) => Some(super::admin::claim_invite_use(app, code, &did, &handle).await?),
        None => None,
    };
    let release = |handle_ok: bool, email_ok: bool, claim: Option<super::admin::InviteClaim>| {
        let (handle, email, did) = (&handle, &email, &did);
        async move {
            if handle_ok {
                release_handle(app, handle, did).await;
            }
            if email_ok {
                release_email(app, email, did).await;
            }
            if let Some(c) = claim {
                super::admin::release_invite_use(app, c).await;
            }
        }
    };
    // Concurrent: run one after the other, the claims' store round trips, the
    // password hash and the key wrap (KMS) were most of the latency.
    let (h, e, password_hash, wrapped) = tokio::join!(
        claim_handle(app, &handle, &did),
        claim_email(app, &email, &did),
        state::try_hash_password(&password),
        app.secrets.wrap_signing_key(&did, &key)
    );
    let (h_ok, e_ok) = (matches!(h, Ok(true)), matches!(e, Ok(true)));
    let wrapped = match &password_hash {
        Ok(_) => wrapped.map_err(XrpcError::from),
        // Argon2 saturated: 503 Overloaded, the claims released below
        Err(_) => Err(XrpcError::from(state::Argon2Busy)),
    };
    let (wrapped_signing_key, signing_pubkey) = match wrapped {
        Ok(w) => w,
        Err(err) => {
            release(h_ok, e_ok, claim).await;
            return Err(err);
        }
    };
    if !(h_ok && e_ok) {
        release(h_ok, e_ok, claim).await;
        if !h? {
            return Err(XrpcError::bad("HandleNotAvailable", format!("Handle already taken: {handle}")));
        }
        e?;
        return Err(invalid_request(format!("Email already taken: {email_input}")));
    }
    // the reference too registers the DID before writing the account
    if let Some((plc, op)) = &genesis {
        if let Err(err) = plc.create(&did, op).await {
            release(true, true, claim).await;
            if matches!(err, crate::plc::PlcError::Unavailable(_)) {
                // maybe registered (a timeout after the directory applied
                // it); a retry mints another DID, so this one is an orphan
                tombstone_if_registered(plc.clone(), did.clone());
            }
            return Err(err.into());
        }
    }
    let mut acct = Account {
        did: did.clone(),
        handle: handle.clone(),
        wrapped_signing_key,
        signing_pubkey,
        created_at: crate::events::now_rfc3339(),
        email: Some(email.clone()),
        ..Default::default()
    };
    acct.password_hash = password_hash.expect("checked with the signing key");
    set_extra(&mut acct, "totpEnabled", json!(false));
    if let Some(code) = &invite {
        set_extra(&mut acct, "invitedBy", json!(code));
    }
    if genesis.is_some() && recovery_key.is_some() {
        // the user's own rotation key can change the DID without us
        set_extra(&mut acct, super::identity::PLC_EXTERNAL, json!(true));
    }
    if external {
        // deactivated until the migration completes (activateAccount); the
        // worker sequences no events for an account created inactive
        set_extra(&mut acct, EXTERNAL_DID, json!(true));
        set_extra(&mut acct, "deactivatedAt", json!(crate::events::now_rfc3339()));
        recompute_status(&mut acct);
    }
    let created = create_repo(app, &did, &handle, key, &acct).await;
    if let Err((e, false)) = &created {
        // Ambiguous: the account may exist (or still appear). Ours if it
        // carries this request's password hash (salted: unique per request).
        match account_if_exists(app, &did).await {
            Ok(Some(a)) if a.password_hash == acct.password_hash => {
                tracing::warn!(%did, "account creation reported {} but the account exists: completed", e.message);
            }
            r => {
                // Not known to be absent for good (the write may still
                // land): compensate nothing. The claims are taken over once
                // stale if no account appears (`claim`); the DID, if
                // registered, stays registered.
                tracing::error!(%did, existing = matches!(r, Ok(Some(_))), "account creation outcome unknown, leaving its claims and DID: {}", e.message);
                return Err(XrpcError { status: e.status, error: e.error.clone(), message: e.message.clone() });
            }
        }
    }
    if let Err((e, true)) = created {
        release(true, true, claim).await;
        if let Some((plc, _)) = &genesis {
            // the DID was registered for an account that doesn't exist
            if let Err(t) = plc.tombstone(&did).await {
                tracing::error!(%did, "tombstoning the DID of a failed account creation: {t}");
            }
        }
        return Err(e);
    }
    if let Some(c) = &claim {
        if let Err(e) = super::admin::record_invite_use(app, c, &did).await {
            tracing::warn!(%did, "recording invite use failed: {}", e.message);
        }
    }
    Ok(acct)
}

/// Err((error, definite)): a definite failure applied nothing.
async fn create_repo(
    app: &App,
    did: &str,
    handle: &str,
    key: Arc<Keypair>,
    acct: &Account,
) -> Result<(), (XrpcError, bool)> {
    let (tx, rx) = oneshot::channel();
    let req = CreateRepoReq {
        did: did.into(),
        handle: handle.to_string(),
        key,
        account_json: Bytes::from(serde_json::to_vec(acct).unwrap()),
        records: Vec::new(),
        reply: tx,
    };
    if let Err(e) = app.workers.route(did).send(WorkerMsg::CreateRepo(req)) {
        return Err((XrpcError::from_err(e), true));
    }
    match rx.await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => {
            let definite = match &e {
                WriteError::Unavailable(_) | WriteError::KeyUnavailable(_) | WriteError::SignatureFault(_) => true,
                // "repo already exists": maybe an earlier attempt of ours
                WriteError::Invalid(m) => m != crate::worker::REPO_EXISTS,
                // incl. the log write failing or timing out: maybe durable
                _ => false,
            };
            Err((e.into(), definite))
        }
        Err(_) => Err((XrpcError::internal("worker dropped request"), false)),
    }
}

/// Best effort, in the background: tombstones a DID whose genesis op landed
/// after all, after its submission failed ambiguously (the account was never
/// created, and a retried createAccount mints another DID).
fn tombstone_if_registered(plc: Arc<crate::plc::Plc>, did: String) {
    tokio::spawn(async move {
        for wait in [5u64, 30, 120] {
            tokio::time::sleep(std::time::Duration::from_secs(wait)).await;
            match plc.client.last_op(&did).await {
                Err(crate::plc::PlcError::NotFound(_)) => return,
                Ok(last) if last["type"] == "plc_tombstone" => return,
                Ok(_) => match plc.tombstone(&did).await {
                    Ok(()) | Err(crate::plc::PlcError::Tombstoned) => {
                        tracing::warn!(%did, "tombstoned the DID of a failed account creation (its genesis op had landed)");
                        return;
                    }
                    Err(e) => tracing::warn!(%did, "tombstoning an orphaned DID: {e}"),
                },
                Err(e) => tracing::warn!(%did, "checking for an orphaned DID: {e}"),
            }
        }
        tracing::error!(%did, "a genesis op of a failed account creation may be registered; not tombstoned");
    });
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateSessionIn {
    identifier: String,
    password: String,
    auth_factor_token: Option<String>,
    #[serde(default)]
    allow_takendown: bool,
    /// vlpds: after a second factor on this server's own page, trust the
    /// browser (its device cookie) to skip the factor next time.
    #[serde(default)]
    trust_device: bool,
}

/// The account a login identifier (handle, DID or email) names. A moving
/// shard is an error, not Ok(None), so a client retries instead of being
/// told its credentials are wrong.
pub(super) async fn login_account(app: &App, identifier: &str) -> XResult<Option<Account>> {
    let ident = identifier.trim().to_ascii_lowercase();
    let did = if ident.contains('@') {
        match did_by_email(app, &ident).await? {
            Some(d) => d,
            None => return Ok(None),
        }
    } else {
        match app.resolve_repo(&ident).await {
            Ok(d) => d.to_string(),
            Err(e) if e.status.is_client_error() => return Ok(None),
            Err(e) => return Err(e),
        }
    };
    let Some(a) = account_if_exists(app, &did).await? else {
        return Ok(None);
    };
    if ident.contains('@') && a.email.as_deref() != Some(ident.as_str()) {
        return Ok(None);
    }
    Ok(Some(a))
}

pub(super) async fn account_if_exists(app: &App, did: &str) -> XResult<Option<Account>> {
    match app.account(did).await {
        Ok(a) => Ok(Some(a)),
        Err(e) if e.error == "AccountNotFound" => Ok(None),
        Err(e) => Err(e),
    }
}

/// App passwords are server-generated with ~80 bits of randomness, so a fast
/// deterministic hash is safe (no dictionary to attack) and lets us look
/// them up by hash.
fn app_password_hash(did: &str, password: &str) -> String {
    hex::encode(Sha256::digest(format!("vlpds-app-password:{did}:{password}").as_bytes()))
}

async fn verify_app_password(app: &App, did: &str, password: &str) -> XResult<Option<AppPassRef>> {
    let h = app_password_hash(did, password.trim());
    let Some(name) = app.get_private(did, &format!("apphash/{h}")).await? else {
        return Ok(None);
    };
    let name = String::from_utf8_lossy(&name).to_string();
    let meta: Option<J> = get_json(app, did, &format!("apppass/{name}")).await?;
    Ok(meta.map(|m| AppPassRef {
        name,
        privileged: m["privileged"].as_bool().unwrap_or(false),
        scopes: m["scopes"].as_str().map(String::from),
    }))
}

/// For `vlpds_logins_total`.
struct LoginStep {
    method: &'static str,
    second_factor: bool,
    /// The normalized identifier, then the account once it's known: whose
    /// failure to record.
    ident: String,
    did: Option<String>,
}

/// A browser request from this server's own pages (the account page).
/// Fetch metadata can't be set by a cross-site page, so only those pages
/// get to use the device cookie on createSession, and the OAuth-only switch
/// lets them through to the second factor.
pub(super) fn own_page(headers: &HeaderMap) -> bool {
    headers.get("sec-fetch-site").and_then(|v| v.to_str().ok()) == Some("same-origin")
}

async fn create_session(
    State(app): AppState,
    super::moderation::ClientIp(ip): super::moderation::ClientIp,
    headers: HeaderMap,
    Json(inp): Json<CreateSessionIn>,
) -> XResult<Response> {
    let mut step = LoginStep { method: "password", second_factor: false, ident: String::new(), did: None };
    let r = create_session_inner(&app, inp, &mut step, ip, &headers).await;
    if let Err(e) = &r {
        record_login_failure(&app, &step, e, ip, &headers).await;
    }
    let result = match &r {
        Ok(_) => "success",
        Err(e) if e.status == StatusCode::TOO_MANY_REQUESTS => "rate_limited",
        Err(e) if e.status.is_server_error() => "error",
        Err(e) if e.error == "AuthFactorTokenRequired" => "second_factor_required",
        Err(_) if step.second_factor => "second_factor_failed",
        Err(e) if e.error == "AccountTakedown" => "inactive",
        Err(e) if e.error == OAUTH_REQUIRED => "oauth_required",
        Err(e) if e.error == APP_PASSWORDS_BLOCKED => "app_passwords_blocked",
        Err(e) if e.error == PASSKEY_REQUIRED => "passkey_required",
        Err(_) => "failed",
    };
    crate::metrics::login(step.method, result);
    r
}

/// The refusals the console's account page lists: a wrong password, a
/// wrong or locked second factor, a rate limit.
async fn record_login_failure(
    app: &App,
    step: &LoginStep,
    e: &XrpcError,
    ip: Option<std::net::IpAddr>,
    headers: &HeaderMap,
) {
    use super::signin::{FailReason, FailedFor};
    let reason = if e.status == StatusCode::TOO_MANY_REQUESTS {
        if step.second_factor && !is_mail_limited(e) {
            FailReason::FactorLocked
        } else {
            FailReason::RateLimited
        }
    } else if step.second_factor {
        if e.error == "AuthFactorTokenRequired" || e.status.is_server_error() {
            return;
        }
        FailReason::WrongCode
    } else if e.status == StatusCode::UNAUTHORIZED && e.message == INVALID_LOGIN && step.did.is_some() {
        FailReason::WrongPassword
    } else {
        return;
    };
    let who = match (&step.did, step.ident.as_str()) {
        (Some(d), _) => FailedFor::Did(d),
        (None, "") => return,
        (None, i) => FailedFor::Identifier(i),
    };
    let ctx = super::signin::Ctx { ip, user_agent: super::signin::user_agent(headers), device_id: None };
    super::signin::failed(app, who, step.method, reason, &ctx).await;
}

const INVALID_LOGIN: &str = "Invalid identifier or password";

const OAUTH_REQUIRED: &str = "OAuthRequired";
pub(super) const PASSKEY_REQUIRED: &str = "PasskeyRequired";

/// A passkey is the account's only strong factor, and no browser vouched
/// for this request's origin: its main password only works on this
/// server's own pages, with the passkey. Not "Authentication Required",
/// which the Bluesky app reads as a wrong password.
fn passkey_required() -> XrpcError {
    err(
        StatusCode::UNAUTHORIZED,
        PASSKEY_REQUIRED,
        "This account signs in with a passkey. Sign in with OAuth on its server's sign-in page, or use an app password.",
    )
}
const APP_PASSWORDS_BLOCKED: &str = "AppPasswordsBlocked";

/// Not "Authentication Required" or "Invalid identifier or password": the
/// Bluesky app turns those into "Incorrect username or password", and shows
/// any other message as it is.
fn oauth_required() -> XrpcError {
    err(
        StatusCode::UNAUTHORIZED,
        OAUTH_REQUIRED,
        "This account only accepts its main password on its server's sign-in page. Sign in with OAuth, or use an app password.",
    )
}

fn app_passwords_blocked() -> XrpcError {
    err(
        StatusCode::UNAUTHORIZED,
        APP_PASSWORDS_BLOCKED,
        "This account doesn't accept app passwords. Sign in with OAuth on its server's sign-in page.",
    )
}

async fn create_session_inner(
    app: &App,
    inp: CreateSessionIn,
    step: &mut LoginStep,
    ip: Option<std::net::IpAddr>,
    headers: &HeaderMap,
) -> XResult<Response> {
    if inp.password.len() > OLD_PASSWORD_MAX_LENGTH {
        return Err(XrpcError::auth("Password too long. Consider resetting your password."));
    }
    // reference: 300/day and 30/5min per `${identifier}-${ip}`, normalized
    // like the OAuth sign-in's key (whose buckets these are too), so case
    // variants of one handle or email share a bucket
    {
        use crate::ratelimit::*;
        let key = inp.identifier.trim().trim_start_matches('@').to_lowercase();
        step.ident = key.clone();
        check_with_ip(&[&CREATE_SESSION_DAY, &CREATE_SESSION_5MIN], &key, 1)?;
    }
    let invalid = || XrpcError::auth(INVALID_LOGIN);
    let acct = login_account(app, &inp.identifier).await?.ok_or_else(invalid)?;
    step.did = Some(acct.did.clone());
    // vlpds: a per-account cap from any IP (shared with the OAuth sign-in),
    // before the password hash
    crate::ratelimit::check(&[&crate::ratelimit::SIGN_IN_ACCOUNT], &acct.did, 1)?;
    let soft_deleted = is_takendown_account(&acct);
    let mut app_pass = None;
    if !verify_password(&acct, &inp.password).await? {
        // takendown/suspended accounts cannot log in with an app password
        if soft_deleted {
            return Err(invalid());
        }
        app_pass = Some(verify_app_password(app, &acct.did, &inp.password).await?.ok_or_else(invalid)?);
        step.method = "app_password";
    }
    if soft_deleted && !inp.allow_takendown {
        return Err(takedown_error());
    }
    let prefs = super::signin::prefs(app, &acct.did).await?;
    if app_pass.is_some() && prefs.block_app_passwords {
        return Err(app_passwords_blocked());
    }
    let own = own_page(headers);
    // only while a factor is on: without one there's nothing to get around
    if app_pass.is_none() && prefs.oauth_only && !own && super::signin::factor_enabled(app, &acct).await? {
        return Err(oauth_required());
    }
    let epoch = epoch_for_login(app, &acct).await?.ok_or_else(invalid)?;
    let cookie_id = if own { super::oauth::device_cookie_id(headers) } else { None };
    let trusted = match (&app_pass, &cookie_id) {
        (None, Some(id)) => super::signin::trusted(app, &acct, &epoch, id).await?,
        _ => false,
    };
    let code = inp.auth_factor_token.as_deref().map(str::trim).filter(|c| !c.is_empty());
    let passkeys = app_pass.is_none() && super::passkeys::has_any(app, &acct.did).await?;
    // a passkey can't be checked here (no browser vouches for the origin),
    // and the email code doesn't stand in for it: only the account page,
    // which runs the passkey itself, or with a recovery code
    if passkeys && !trusted && !crate::totp::enabled_for(app, &acct).await? && (!own || code.is_none()) {
        return Err(passkey_required());
    }
    let factor = if trusted {
        Some("trusted")
    } else {
        step.second_factor = true;
        super::email2fa::check_second_factor(app, &acct, code, app_pass.is_some(), passkeys).await?;
        step.second_factor = false;
        match (&app_pass, code) {
            (None, Some(_)) if crate::totp::enabled_for(app, &acct).await? => Some("totp"),
            (None, Some(_)) if passkeys => Some("recovery"),
            (None, Some(_)) if super::email2fa::enabled(&acct) => Some("email"),
            _ => None,
        }
    };
    super::cas::pause_point("legacy_login", &acct.did).await;
    let method = match &app_pass {
        Some(a) => super::signin::Method::AppPassword(a.name.clone()),
        None => super::signin::Method::Password,
    };
    let include_email = shows_email(app_pass.as_ref());
    let (access, refresh) =
        create_session_tokens(app, &acct.did, app_pass, soft_deleted, Some(epoch.as_str()), None, ip).await?;
    let ua = super::signin::user_agent(headers);
    // a new browser gets its device cookie here, as on the OAuth pages
    let mut set_cookie = None;
    let mut device_id = cookie_id;
    if inp.trust_device && own && matches!(factor, Some("totp" | "email" | "recovery")) {
        let oauth_err =
            |e: crate::oauth::OAuthError| XrpcError { status: e.status, error: e.error, message: e.description };
        let (mut d, _) = super::oauth::device_for(app, headers).await.map_err(oauth_err)?;
        let ctx = super::signin::Ctx { ip, user_agent: ua, device_id: Some(&d.id) };
        if let Some(until) = super::signin::trust(app, &acct, &epoch, &d.id.clone(), &ctx).await? {
            d.trusted_until = d.trusted_until.max(until as i64);
            crate::oauth::store::put_device(app, &d).await.map_err(oauth_err)?;
            set_cookie = Some(super::oauth::device_cookie(app, &d));
        }
        device_id = Some(d.id);
    }
    let ctx = super::signin::Ctx { ip, user_agent: ua, device_id: device_id.as_deref() };
    super::signin::record(app, &acct, method, factor, &ctx).await;
    let mut out = session_info(app, &acct, include_email).await;
    out["accessJwt"] = json!(access);
    out["refreshJwt"] = json!(refresh);
    let mut r = Json(out).into_response();
    if let Some(c) = set_cookie {
        r.headers_mut().insert(header::SET_COOKIE, c);
    }
    Ok(r)
}

/// Whether a login's or refresh's answer may show the email: getSession's
/// rule for the tokens it hands out.
fn shows_email(ap: Option<&AppPassRef>) -> bool {
    ap.and_then(|a| a.scopes.as_deref()).is_none_or(|s| super::oauth::ScopeSet::new(s).allows_account("email", "read"))
}

async fn get_session(State(app): AppState, Auth(creds): Auth) -> XResult<Json<J>> {
    let did = user_did(&creds)?;
    let acct =
        app.account(&did).await.map_err(|_| invalid_request(format!("Could not find user info for account: {did}")))?;
    let scoped = matches!(creds, Credentials::OAuth { .. }) || creds.app_pass_scopes().is_some();
    let include_email = !scoped || creds.allows_account("email", "read");
    Ok(Json(session_info(&app, &acct, include_email).await))
}

async fn refresh_session(
    State(app): AppState,
    super::moderation::ClientIp(ip): super::moderation::ClientIp,
    headers: HeaderMap,
) -> XResult<Json<J>> {
    let c = refresh_claims(&app, &headers, false)?;
    let did = c.sub.clone();
    let rid = c.jti.clone().unwrap_or_default();
    let acct =
        app.account(&did).await.map_err(|_| invalid_request(format!("Could not find user info for account: {did}")))?;
    if is_takendown_account(&acct) {
        return Err(takedown_error());
    }
    let e = ext(&app);
    // an economy: the conditional write is what is correct across nodes
    let _g = e.lock(&did).await;
    let (st, next) = rotate_refresh(&app, &did, &rid, ip).await?;
    let ap_scope = st.app_password.as_ref().and_then(|a| a.scopes.as_deref());
    let (access, refresh) = issue_pair(&app, &did, access_scope(&st.app_password), ap_scope, &st.family, &next);
    let mut out = session_info(&app, &acct, shows_email(st.app_password.as_ref())).await;
    out["accessJwt"] = json!(access);
    out["refreshJwt"] = json!(refresh);
    Ok(Json(out))
}

/// (the session, the next refresh id). Rewritten on condition the rows are
/// unchanged, so a revocation landing meanwhile is never undone.
async fn rotate_refresh(
    app: &App,
    did: &str,
    rid: &str,
    ip: Option<std::net::IpAddr>,
) -> XResult<(RefreshState, String)> {
    use super::cas::{Cond, Op};
    let name = format!("sess/{rid}");
    for _ in 0..CAS_ROUNDS {
        let raw = app.get_private(did, &name).await?;
        let st: Option<RefreshState> =
            raw.as_deref().map(serde_json::from_slice).transpose().map_err(XrpcError::from_err)?;
        let now = now_secs();
        let st = st.filter(|s| s.exp >= now).ok_or_else(|| expired_token("Token has been revoked"))?;
        if ctl(app, did).await?.is_revoked(Some(&st.family), 0) {
            return Err(expired_token("Token has been revoked"));
        }
        // Rotation as in the reference: the old token stays usable for a
        // grace period (min(2h, its expiry)) and reuse yields the same next
        // token id; after that it is rejected.
        let next = st.next_id.clone().unwrap_or_else(|| random_hex(24));
        let next_name = format!("sess/{next}");
        let next_raw = app.get_private(did, &next_name).await?;
        let rotated = RefreshState { exp: st.exp.min(now + REFRESH_GRACE), next_id: Some(next.clone()), ..st.clone() };
        let mut ops = vec![Op::put(&name, Some(Bytes::from(to_json_bytes(&rotated))))];
        if next_raw.is_none() {
            let ip = ip.map(|i| i.to_string()).or_else(|| st.ip.clone());
            let next_st = RefreshState { exp: now + REFRESH_TTL, created_at: now, next_id: None, ip, ..st.clone() };
            ops.push(Op::put(&next_name, Some(Bytes::from(to_json_bytes(&next_st)))));
        }
        super::cas::pause_point("legacy_refresh", did).await;
        let conds = vec![Cond::eq(&name, raw), Cond::eq(&next_name, next_raw)];
        if app.private_cas(did, conds, ops).await?.applied {
            return Ok((st, next));
        }
    }
    Err(cas_conflict())
}

async fn delete_session(State(app): AppState, headers: HeaderMap) -> XResult<StatusCode> {
    let c = refresh_claims(&app, &headers, true)?;
    let did = c.sub.clone();
    let rid = c.jti.clone().unwrap_or_default();
    let e = ext(&app);
    let _g = e.lock(&did).await;
    let name = format!("sess/{rid}");
    if let Some(st) = get_json::<RefreshState>(&app, &did, &name).await? {
        // the whole session: this token, its rotations and their access tokens
        delete_sessions_where(&app, &did, |n, o| n == name || o.family == st.family).await?;
        revoke_families(&app, &did, &[st.family]).await?;
    }
    Ok(StatusCode::OK)
}

#[derive(Deserialize)]
struct CreateAppPasswordIn {
    name: String,
    #[serde(default)]
    privileged: Option<bool>,
    /// vlpds extension: OAuth scopes the password's sessions are held to.
    #[serde(default)]
    scopes: Option<String>,
}

/// Every access token of the password's sessions carries them.
const MAX_APP_PASSWORD_SCOPES_LEN: usize = 2048;

/// `scopes` normalized to single spaces, None if blank. `include:` is
/// refused: a permission set resolves over the network when an OAuth grant
/// is made, and an app password has no such step, so its grant would change
/// under it whenever the set's lexicon does.
fn app_password_scopes(scopes: Option<&str>) -> XResult<Option<String>> {
    let Some(raw) = scopes else { return Ok(None) };
    let mut out: Vec<&str> = Vec::new();
    for s in raw.split_whitespace() {
        if crate::oauth::scopes::IncludeScope::parse(s).is_some() {
            return Err(invalid_request(format!(
                "Permission sets (include:) can't be used in app password scopes: {s}"
            )));
        }
        if !crate::oauth::scopes::is_atproto_oauth_scope(s) {
            return Err(invalid_request(format!("Invalid scope: {s}")));
        }
        if !out.contains(&s) {
            out.push(s);
        }
    }
    let joined = out.join(" ");
    if joined.len() > MAX_APP_PASSWORD_SCOPES_LEN {
        return Err(invalid_request("Too many scopes"));
    }
    Ok((!joined.is_empty()).then_some(joined))
}

async fn create_app_password(
    State(app): AppState,
    Auth(creds): Auth,
    Json(inp): Json<CreateAppPasswordIn>,
) -> XResult<Json<J>> {
    let did = full_access(&creds)?;
    let acct = app.account(&did).await?;
    if is_takendown_account(&acct) {
        return Err(takedown_error());
    }
    let name = inp.name.trim().to_string();
    if name.is_empty() || name.len() > 256 || name.contains('\0') {
        return Err(invalid_request("Invalid app password name"));
    }
    let privileged = inp.privileged.unwrap_or(false);
    let scopes = app_password_scopes(inp.scopes.as_deref())?;
    let e = ext(&app);
    let _g = e.lock(&did).await;
    if app.get_private(&did, &format!("apppass/{name}")).await?.is_some() {
        return Err(invalid_request("could not create app-specific password"));
    }
    let s = crate::cid::base32_encode(&rand::random::<[u8; 10]>());
    let password = format!("{}-{}-{}-{}", &s[0..4], &s[4..8], &s[8..12], &s[12..16]);
    let created_at = crate::events::now_rfc3339();
    let h = app_password_hash(&did, &password);
    let mut meta = json!({"name": name, "createdAt": created_at, "privileged": privileged, "hash": h});
    let mut out = json!({"name": name, "password": password, "createdAt": created_at, "privileged": privileged});
    if let Some(s) = &scopes {
        meta["scopes"] = json!(s);
        out["scopes"] = json!(s);
    }
    let muts = vec![
        pmut(&did, &format!("apppass/{name}"), Some(to_json_bytes(&meta))),
        pmut(&did, &format!("apphash/{h}"), Some(name.as_bytes().to_vec())),
    ];
    app.put_private(&did, muts).await?;
    Ok(Json(out))
}

async fn list_app_passwords(State(app): AppState, Auth(creds): Auth) -> XResult<Json<J>> {
    let did = standard_no_oauth(&creds)?;
    let mut out: Vec<J> = scan_private(&app, &did, "apppass/")
        .await?
        .into_iter()
        .filter_map(|(_, v)| serde_json::from_slice::<J>(&v).ok())
        .map(|m| {
            let mut p = json!({"name": m["name"], "createdAt": m["createdAt"], "privileged": m["privileged"].as_bool().unwrap_or(false)});
            if let Some(s) = m["scopes"].as_str() {
                p["scopes"] = json!(s);
            }
            p
        })
        .collect();
    out.sort_by(|a, b| b["createdAt"].as_str().cmp(&a["createdAt"].as_str()));
    let mut res = json!({"passwords": out});
    // vlpds: the audience a "read only" scope names (the account page's preset)
    if let Some((_, did)) = &app.config.appview {
        res["appviewAud"] = json!(format!("{did}#bsky_appview"));
    }
    Ok(Json(res))
}

#[derive(Deserialize)]
struct RevokeAppPasswordIn {
    name: String,
}

async fn revoke_app_password(
    State(app): AppState,
    Auth(creds): Auth,
    Json(inp): Json<RevokeAppPasswordIn>,
) -> XResult<StatusCode> {
    // app passwords can't revoke app passwords (stricter than the reference)
    let did = full_access(&creds)?;
    remove_app_password(&app, &did, inp.name.trim()).await?;
    Ok(StatusCode::OK)
}

/// The password and the sessions it signed in. False if there was none by
/// that name (its sessions are ended all the same).
pub(super) async fn remove_app_password(app: &App, did: &str, name: &str) -> XResult<bool> {
    let e = ext(app);
    let _g = e.lock(did).await;
    let found = match get_json::<J>(app, did, &format!("apppass/{name}")).await? {
        Some(meta) => {
            let mut muts = vec![pmut(did, &format!("apppass/{name}"), None)];
            if let Some(h) = meta["hash"].as_str() {
                muts.push(pmut(did, &format!("apphash/{h}"), None));
            }
            app.put_private(did, muts).await?;
            true
        }
        None => false,
    };
    revoke_app_password_sessions(app, did, name).await?;
    Ok(found)
}

/// [`App::mutate_account`] that always writes; returns the account as written.
pub(super) async fn update_account<F>(
    app: &App,
    did: &str,
    identity_event: bool,
    account_event: bool,
    f: F,
) -> XResult<Account>
where
    F: FnOnce(&mut Account) -> XResult<()> + Send + 'static,
{
    let (_, a) = app.mutate_account(did, identity_event, account_event, false, |a| f(a).map(|_| true)).await?;
    Ok(a)
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct DeactivateIn {
    delete_after: Option<String>,
}

pub(super) async fn set_deactivated(
    app: &App,
    did: &str,
    deactivated: bool,
    delete_after: Option<String>,
) -> XResult<Account> {
    update_account(app, did, !deactivated, true, move |a| {
        if deactivated {
            if a.extra.get("deactivatedAt").is_none_or(|v| v.is_null()) {
                set_extra(a, "deactivatedAt", json!(crate::events::now_rfc3339()));
            }
            set_extra(a, "deleteAfter", delete_after.map(J::String).unwrap_or(J::Null));
        } else {
            if a.extra.get("takedownRef").is_some_and(|v| !v.is_null()) {
                return Err(XrpcError::bad("AccountNotFound", "user not found"));
            }
            set_extra(a, "deactivatedAt", J::Null);
            set_extra(a, "deleteAfter", J::Null);
        }
        recompute_status(a);
        Ok(())
    })
    .await
    .inspect(|_| {
        // a deactivated account's DID resolves through the directory from
        // now on (identity::serves_local_doc): not from a stale cache entry
        app.did_resolver.invalidate(did);
        let event = if deactivated { "deactivated" } else { "reactivated" };
        crate::metrics::ACCOUNT_EVENTS.with_label_values(&[event]).inc();
    })
}

async fn deactivate_account(
    State(app): AppState,
    Auth(creds): Auth,
    body: Option<Json<DeactivateIn>>,
) -> XResult<StatusCode> {
    let did = full_or_oauth_account(&creds, "status", "manage")?;
    let inp = body.map(|Json(b)| b).unwrap_or_default();
    if let Some(d) = &inp.delete_after {
        if chrono::DateTime::parse_from_rfc3339(d).is_err() {
            return Err(invalid_request("deleteAfter must be a valid datetime"));
        }
    }
    app.account(&did).await.map_err(|_| invalid_request("Account not found"))?;
    // the reference's `deleteCredentials` for OAuth callers
    if matches!(creds, Credentials::OAuth { .. }) {
        delete_delegated_credentials(&app, &did).await?;
    }
    set_deactivated(&app, &did, true, inp.delete_after).await?;
    Ok(StatusCode::OK)
}

/// The reference's `deactivateAccount({deleteCredentials: true})`: OAuth
/// sessions, client authorizations and app passwords with their sessions.
/// Password sessions stay.
pub(super) async fn delete_delegated_credentials(app: &App, did: &str) -> XResult<()> {
    crate::oauth::store::revoke_all_sessions(app, did).await.map_err(|e| XrpcError::internal(e.description))?;
    let mut dels: Vec<_> =
        scan_private(app, did, "oauth/authz/").await?.into_iter().map(|(name, _)| pmut(did, &name, None)).collect();
    let mut names = Vec::new();
    for (key, v) in scan_private(app, did, "apppass/").await? {
        dels.push(pmut(did, &key, None));
        if let Some(h) = serde_json::from_slice::<J>(&v).ok().and_then(|m| m["hash"].as_str().map(String::from)) {
            dels.push(pmut(did, &format!("apphash/{h}"), None));
        }
        names.push(key.trim_start_matches("apppass/").to_string());
    }
    if !dels.is_empty() {
        let e = ext(app);
        let _g = e.lock(did).await;
        app.put_private(did, dels).await?;
    }
    for name in names {
        revoke_app_password_sessions(app, did, &name).await?;
    }
    Ok(())
}

async fn activate_account(State(app): AppState, Auth(creds): Auth) -> XResult<StatusCode> {
    if matches!(creds, Credentials::OAuth { .. }) {
        return Err(err(
            StatusCode::FORBIDDEN,
            "Forbidden",
            "Account reactivation is not available with OAuth credentials. Sign in to your account management page to reactivate.",
        ));
    }
    let did = full_access(&creds)?;
    let acct = app.account(&did).await.map_err(|_| XrpcError::bad("AccountNotFound", "user not found"))?;
    assert_valid_did_doc(&app, &acct).await?;
    // #account, #identity and #sync (reference sequenceAccountActivation)
    app.mutate_account(&did, true, true, true, |a| {
        if a.extra.get("takedownRef").is_some_and(|v| !v.is_null()) {
            return Err(XrpcError::bad("AccountNotFound", "user not found"));
        }
        set_extra(a, "deactivatedAt", J::Null);
        set_extra(a, "deleteAfter", J::Null);
        recompute_status(a);
        Ok(true)
    })
    .await?;
    crate::metrics::ACCOUNT_EVENTS.with_label_values(&["reactivated"]).inc();
    Ok(StatusCode::OK)
}

const WRONG_PDS: &str = "DID document atproto_pds service endpoint does not match PDS public url";
const WRONG_SIGNING_KEY: &str = "DID document verification method does not match expected signing key";

/// The reference's assertValidDidDocumentForService. With PLC registration
/// on, a did:plc is checked against the directory, which must also keep the
/// server rotation key. Without it, a DID minted here is documented by this
/// server only, so only a migrated-in DID is checked.
async fn assert_valid_did_doc(app: &App, a: &Account) -> XResult<()> {
    if let (Some(plc), true) = (&app.plc, a.did.starts_with("did:plc:")) {
        let data = plc.client.document_data(&a.did).await?;
        // (a retired server key counts: `vlpds.admin.rotatePlcKeys` moves it)
        let has_key = data["rotationKeys"]
            .as_array()
            .is_some_and(|k| k.iter().any(|k| k.as_str().is_some_and(|k| plc.is_server_key(k))));
        if !has_key {
            return Err(invalid_request("Server rotation key not included in PLC DID data"));
        }
        let pds = data["services"]["atproto_pds"]["endpoint"].as_str();
        if pds != Some(app.public_url.as_str()) {
            return Err(invalid_request(WRONG_PDS));
        }
        if data["verificationMethods"]["atproto"] != format!("did:key:{}", a.signing_pubkey).as_str() {
            return Err(invalid_request(WRONG_SIGNING_KEY));
        }
        return Ok(());
    }
    if !has_external_did(a) {
        return Ok(());
    }
    app.did_resolver.invalidate(&a.did);
    let doc = app.did_resolver.resolve(&a.did).await.map_err(|_| invalid_request("Could not resolve DID"))?;
    let pds = crate::did_resolver::service_endpoint(&doc, "atproto_pds");
    if pds.as_deref().map(|p| p.trim_end_matches('/')) != Some(app.public_url.trim_end_matches('/')) {
        return Err(invalid_request(WRONG_PDS));
    }
    if crate::did_resolver::signing_key_multibase(&doc).as_deref() != Some(a.signing_pubkey.as_str()) {
        return Err(invalid_request(WRONG_SIGNING_KEY));
    }
    Ok(())
}

/// Migration progress. `importedBlobs` counts every stored blob, referenced
/// or not yet.
/// O(1) in the repo: the counts are kept with each commit (`S/{did}`), and
/// the stored blobs are private rows (`blobs::STORED`) counted from the
/// same snapshot as the head.
async fn check_account_status(State(app): AppState, Auth(creds): Auth) -> XResult<Json<J>> {
    let did = user_did(&creds)?;
    let acct = app.account(&did).await?;
    let p = app.partition(&did)?;
    let snap = p.db.snapshot().map_err(XrpcError::from_err)?;
    let (hv, sv) = tokio::try_join!(
        slatedb::DbReadOps::get(snap.as_ref(), state::head_key(&did)),
        slatedb::DbReadOps::get(snap.as_ref(), state::repo_stats_key(&did))
    )
    .map_err(XrpcError::from_err)?;
    let hv = hv.ok_or_else(|| XrpcError::bad("RepoNotFound", format!("could not find repo: {did}")))?;
    let head = Head::decode(&hv).map_err(XrpcError::from_err)?;
    let stats = state::RepoStats::decode(&sv.ok_or_else(|| XrpcError::internal(format!("{did}: repo stats missing")))?)
        .map_err(XrpcError::from_err)?;
    let count_blobs = async { super::blobs::count_stored(snap.as_ref(), &did).await.map_err(XrpcError::from_err) };
    let (imported, valid_did) = tokio::join!(count_blobs, assert_valid_did_doc(&app, &acct));
    Ok(Json(json!({
        "activated": acct.status.is_none(),
        "validDid": valid_did.is_ok(),
        "repoCommit": head.commit.to_string(),
        "repoRev": head.rev.to_string(),
        "repoBlocks": stats.repo_blocks(),
        "indexedRecords": stats.records,
        "privateStateValues": 0,
        "expectedBlobs": stats.blobs,
        "importedBlobs": imported?,
    })))
}

/// The account to mail a token to: not taken down, with an email.
async fn mailable_account(app: &App, did: &str) -> XResult<(Account, String)> {
    let acct = app.account(did).await.map_err(|_| invalid_request("account not found"))?;
    if is_takendown_account(&acct) {
        return Err(takedown_error());
    }
    let email = acct.email.clone().ok_or_else(|| invalid_request("account does not have an email address"))?;
    Ok((acct, email))
}

async fn request_account_delete(State(app): AppState, Auth(creds): Auth) -> XResult<StatusCode> {
    let did = full_access(&creds)?;
    {
        use crate::ratelimit::*;
        check(&[&REQUEST_ACCOUNT_DELETE_DAY, &REQUEST_ACCOUNT_DELETE_HOUR], &did, 1)?;
    }
    let (_, email) = mailable_account(&app, &did).await?;
    let permit = mail_permit(&app, Some(&did), &email, "delete_account", true).await?;
    let token = create_email_token(&app, &did, "delete_account").await?;
    deliver(&app, permit, &email, crate::mail::Email::DeleteAccount { token: &token });
    Ok(StatusCode::OK)
}

/// A deletion in progress: written before the repo is deleted, removed once
/// everything else is, so a retry after a failure past the repo delete (the
/// account row gone) still knows the claims to release and the password
/// that authorizes the user's retry.
pub(super) const DELETING: &str = "deleting";

#[derive(serde::Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Deleting {
    handle: String,
    email: Option<String>,
    password_hash: String,
}

static DELETE_HOOKS: crate::lifecycle::CrashHooks = crate::lifecycle::CrashHooks::new();

/// Tests: `h("deleted")` true fails a deletion of `did` right after its repo
/// delete, leaving the claims and private rows behind.
pub fn set_delete_crash_hook(did: &str, h: Option<crate::lifecycle::CrashHook>) {
    DELETE_HOOKS.set(did, h)
}

/// What deleting `did` has to do. Err(AccountNotFound): no account and no
/// deletion of one left unfinished.
pub(super) enum DeleteFrom {
    /// The account row: the whole deletion.
    Account(Deleting),
    /// A deletion that got past the repo delete: the rest.
    Leftovers(Deleting),
    /// An unreadable account row: the repo delete, the private rows; its
    /// claims are taken over once stale.
    Unreadable,
}

pub(super) async fn delete_from(app: &App, did: &str) -> XResult<DeleteFrom> {
    match super::internal::account_anywhere(app, did).await {
        Ok(a) => Ok(DeleteFrom::Account(Deleting { handle: a.handle, email: a.email, password_hash: a.password_hash })),
        Err(e) if e.error == "AccountNotFound" => match get_json::<Deleting>(app, did, DELETING).await? {
            Some(d) => Ok(DeleteFrom::Leftovers(d)),
            None => Err(e),
        },
        Err(_) => Ok(DeleteFrom::Unreadable),
    }
}

/// Sessions, repo and account (#account deleted event), handle and email
/// claims, private state. Retry-safe: a failure anywhere leaves either the
/// account or its `DELETING` row, and a retry finishes from it.
pub(super) async fn delete_account_fully(app: &App, did: &str) -> XResult<()> {
    finish_delete(app, did, delete_from(app, did).await?, "admin", None).await
}

fn count_deleted(reason: &str) {
    crate::metrics::ACCOUNT_EVENTS.with_label_values(&["deleted"]).inc();
    crate::metrics::ACCOUNT_DELETIONS.with_label_values(&[reason]).inc();
}

/// `reason` labels `vlpds_account_deletions_total`. `only_if` refuses the
/// repo delete unless the account still passes it; a refused deletion
/// leaves the account as it was.
pub(super) async fn finish_delete(
    app: &App,
    did: &str,
    from: DeleteFrom,
    reason: &str,
    only_if: Option<crate::worker::AccountCheck>,
) -> XResult<()> {
    let intent = match from {
        DeleteFrom::Account(d) => {
            app.put_private(did, vec![pmut(did, DELETING, Some(to_json_bytes(&d)))]).await?;
            if only_if.is_some() {
                // revoking first would sign out an account whose reactivation
                // then wins the race and refuses the delete
                if let Err(e) = app.account_op(did, AccountOp::Delete { only_if }).await {
                    // a refusal applied nothing; other failures may have
                    if e.error == "InvalidRequest" {
                        app.put_private(did, vec![pmut(did, DELETING, None)]).await?;
                    }
                    return Err(e);
                }
                revoke_all_sessions(app, did).await?;
            } else {
                revoke_all_sessions(app, did).await?;
                app.account_op(did, AccountOp::Delete { only_if: None }).await?;
            }
            count_deleted(reason);
            Some(d)
        }
        DeleteFrom::Unreadable => {
            revoke_all_sessions(app, did).await?;
            app.account_op(did, AccountOp::Delete { only_if: None }).await?;
            count_deleted(reason);
            None
        }
        DeleteFrom::Leftovers(d) => {
            // a guarded deletion revokes only after its repo delete
            revoke_all_sessions(app, did).await?;
            Some(d)
        }
    };
    if DELETE_HOOKS.fires(did, "deleted") {
        return Err(XrpcError::internal(format!("deletion of {did} stopped after the repo delete (crash hook)")));
    }
    super::space::delete_account_rows(app, did).await?;
    if let Some(d) = &intent {
        try_release_handle(app, &d.handle, did).await?;
        if let Some(e) = &d.email {
            try_release_email(app, e, did).await?;
        }
    }
    // revocations stay (TTL'd), so a DID that comes back (migration) doesn't
    // revive access tokens issued before; so does the credential epoch
    // (device logins and codes from before must not match a fresh account)
    let mut private = scan_private(app, did, "").await?;
    private.retain(|(name, _)| {
        !name.starts_with(REVOKED_ALL) && !name.starts_with(REVOKED_FAMILY) && name != AUTH_EPOCH && name != DELETING
    });
    for chunk in private.chunks(500) {
        app.put_private(did, chunk.iter().map(|(name, _)| pmut(did, name, None)).collect()).await?;
    }
    if intent.is_some() {
        app.put_private(did, vec![pmut(did, DELETING, None)]).await?;
    }
    ctl_changed(app, did);
    Ok(())
}

#[derive(Deserialize)]
struct DeleteAccountIn {
    did: String,
    password: String,
    token: String,
}

async fn delete_account(State(app): AppState, Json(inp): Json<DeleteAccountIn>) -> XResult<StatusCode> {
    if inp.password.len() > OLD_PASSWORD_MAX_LENGTH {
        return Err(XrpcError::auth("Password too long. Consider resetting your password."));
    }
    let from = delete_from(&app, &inp.did).await.map_err(|e| match e.error.as_str() {
        "AccountNotFound" => invalid_request("account not found"),
        _ => e,
    })?;
    let hash = match &from {
        DeleteFrom::Account(d) | DeleteFrom::Leftovers(d) => &d.password_hash,
        DeleteFrom::Unreadable => return Err(XrpcError::internal("account unreadable")),
    };
    if hash.is_empty() || !state::try_verify_password_hash(hash, &inp.password).await? {
        return Err(XrpcError::auth("Invalid did or password"));
    }
    // A deletion past the repo delete was authorized with a token when it
    // began (the token row may be gone with the private rows): the
    // password alone lets its owner finish it.
    if matches!(from, DeleteFrom::Account(_)) {
        assert_email_token(&app, &inp.did, "delete_account", &inp.token).await?;
    }
    finish_delete(&app, &inp.did, from, "user", None).await?;
    Ok(StatusCode::OK)
}

#[derive(Deserialize, Default)]
struct ReserveSigningKeyIn {
    did: Option<String>,
}

pub const RESERVED_KEY_TTL: std::time::Duration = std::time::Duration::from_secs(24 * 3600);

/// By did:key for the key itself, by DID for the per-DID index.
fn reserved_routing(id: &str) -> String {
    format!("_reserved:{id}")
}

fn reservation_expired(rec: &J, ttl: std::time::Duration) -> bool {
    let created = rec["createdAt"].as_str().and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok());
    match created {
        Some(t) => chrono::Utc::now().signed_duration_since(t).to_std().unwrap_or_default() >= ttl,
        None => true,
    }
}

/// With `did`, the same key comes back while its reservation is live (the
/// reference's actorStore.reserveKeypair keys the reservation by DID).
async fn reserve_signing_key(State(app): AppState, body: Option<Json<ReserveSigningKeyIn>>) -> XResult<Json<J>> {
    let inp = body.map(|Json(b)| b).unwrap_or_default();
    let did = inp.did.filter(|d| !d.is_empty());
    if let Some(did) = &did {
        if !did.starts_with("did:") {
            return Err(invalid_request("did must be a DID"));
        }
        let idx = reserved_routing(did);
        if let Some(rec) = get_json::<J>(&app, &idx, "k").await? {
            let dk = rec["signingKey"].as_str().unwrap_or("").to_string();
            let live = !reservation_expired(&rec, RESERVED_KEY_TTL)
                && get_json::<J>(&app, &reserved_routing(&dk), "k").await?.is_some();
            if live {
                return Ok(Json(json!({"signingKey": dk})));
            }
        }
    }
    // a new reservation costs a key-service wrap and a stored row (24 h):
    // capped per node on top of the layer's per-IP bucket
    crate::ratelimit::check(&[&crate::ratelimit::RESERVE_SIGNING_KEY_NODE], crate::ratelimit::NODE_KEY, 1)?;
    let key = Keypair::generate();
    let did_key = key.did_key();
    let routing = reserved_routing(&did_key);
    let now = crate::events::now_rfc3339();
    let wrapped = app.secrets.wrap(crate::secrets::Purpose::ReservedKey, &did_key, &key.to_bytes()).await?;
    let rec = json!({"key": wrapped, "did": did, "createdAt": now});
    app.put_private(&routing, vec![pmut(&routing, "k", Some(to_json_bytes(&rec)))]).await?;
    if let Some(did) = &did {
        let idx = reserved_routing(did);
        let rec = json!({"signingKey": did_key, "createdAt": now});
        app.put_private(&idx, vec![pmut(&idx, "k", Some(to_json_bytes(&rec)))]).await?;
    }
    Ok(Json(json!({"signingKey": did_key})))
}

/// Clears the reservation and its per-DID index; an expired one yields None.
pub(super) async fn take_reserved_key(app: &App, did_key: &str) -> XResult<Option<Keypair>> {
    let routing = reserved_routing(did_key);
    let Some(rec) = get_json::<J>(app, &routing, "k").await? else {
        return Ok(None);
    };
    // unwrap before consuming the reservation: with the key service down
    // the caller retries and the reservation is still there
    let raw = if reservation_expired(&rec, RESERVED_KEY_TTL) {
        None
    } else {
        let blob = rec["key"].as_str().unwrap_or("");
        Some(app.secrets.unwrap(crate::secrets::Purpose::ReservedKey, did_key, blob).await?.plaintext)
    };
    app.put_private(&routing, vec![pmut(&routing, "k", None)]).await?;
    if let Some(did) = rec["did"].as_str() {
        let idx = reserved_routing(did);
        app.put_private(&idx, vec![pmut(&idx, "k", None)]).await?;
    }
    raw.map(|raw| Keypair::from_bytes(&raw).map_err(XrpcError::from_err)).transpose()
}

/// Sweeps this node's partitions; returns how many rows were removed.
pub async fn sweep_reserved_keys(app: &App, ttl: std::time::Duration) -> Result<usize, XrpcError> {
    let mut n = 0;
    for (routing, name, val) in scan_private_routing(app, "_reserved:").await? {
        let expired = serde_json::from_slice::<J>(&val).map(|rec| reservation_expired(&rec, ttl)).unwrap_or(true);
        if expired {
            app.put_private(&routing, vec![pmut(&routing, &name, None)]).await?;
            n += 1;
        }
    }
    Ok(n)
}

pub fn spawn_reserved_key_gc(app: Arc<App>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(3600));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            match sweep_reserved_keys(&app, RESERVED_KEY_TTL).await {
                Ok(n) if n > 0 => tracing::info!(removed = n, "reserved signing key gc"),
                Ok(_) => {}
                Err(e) => tracing::warn!("reserved signing key gc: {}", e.message),
            }
        }
    })
}

async fn request_email_confirmation(State(app): AppState, Auth(creds): Auth) -> XResult<StatusCode> {
    let did = standard_or_oauth_account(&creds, "email", "manage")?;
    {
        use crate::ratelimit::*;
        check(&[&REQUEST_EMAIL_CONFIRMATION_DAY, &REQUEST_EMAIL_CONFIRMATION_HOUR], &did, 1)?;
    }
    let (_, email) = mailable_account(&app, &did).await?;
    let permit = mail_permit(&app, Some(&did), &email, "confirm_email", true).await?;
    let token = create_email_token(&app, &did, "confirm_email").await?;
    deliver(&app, permit, &email, crate::mail::Email::ConfirmEmail { token: &token });
    Ok(StatusCode::OK)
}

#[derive(Deserialize)]
struct ConfirmEmailIn {
    email: String,
    token: String,
}

async fn confirm_email(
    State(app): AppState,
    Auth(creds): Auth,
    Json(inp): Json<ConfirmEmailIn>,
) -> XResult<StatusCode> {
    let did = standard_or_oauth_account(&creds, "email", "manage")?;
    let acct = app.account(&did).await.map_err(|_| XrpcError::bad("AccountNotFound", "user not found"))?;
    if is_takendown_account(&acct) {
        return Err(takedown_error());
    }
    if acct.email.as_deref() != Some(inp.email.trim().to_ascii_lowercase().as_str()) {
        return Err(XrpcError::bad("InvalidEmail", "invalid email"));
    }
    assert_email_token(&app, &did, "confirm_email", &inp.token).await?;
    delete_email_tokens(&app, &did, &["confirm_email"]).await?;
    update_account(&app, &did, false, false, move |a| {
        a.email_confirmed = true;
        set_extra(a, "emailConfirmedAt", json!(crate::events::now_rfc3339()));
        Ok(())
    })
    .await?;
    Ok(StatusCode::OK)
}

async fn request_email_update(State(app): AppState, Auth(creds): Auth) -> XResult<Json<J>> {
    let did = full_or_oauth_account(&creds, "email", "manage")?;
    {
        use crate::ratelimit::*;
        check(&[&REQUEST_EMAIL_UPDATE_DAY, &REQUEST_EMAIL_UPDATE_HOUR], &did, 1)?;
    }
    let (acct, email) = mailable_account(&app, &did).await?;
    let token_required = acct.email_confirmed;
    if token_required {
        let permit = mail_permit(&app, Some(&did), &email, "update_email", true).await?;
        let token = create_email_token(&app, &did, "update_email").await?;
        deliver(&app, permit, &email, crate::mail::Email::UpdateEmail { token: &token });
    }
    Ok(Json(json!({"tokenRequired": token_required})))
}

/// Sets a new, unconfirmed email: claims it, releases the old one, clears
/// email tokens.
pub(super) async fn set_email(app: &App, did: &str, email: &str) -> XResult<()> {
    let email = email.trim().to_ascii_lowercase();
    if !valid_email(&email) {
        return Err(invalid_request("This email address is not supported, please use a different email."));
    }
    let acct = app.account(did).await?;
    if acct.email.as_deref() == Some(email.as_str()) {
        return Ok(());
    }
    if !claim_email(app, &email, did).await? {
        return Err(invalid_request("This email address is already in use, please use a different email."));
    }
    let new = email.clone();
    let res = app
        .mutate_account(did, false, false, false, move |a| {
            if a.email.as_deref() == Some(new.as_str()) {
                return Ok(false);
            }
            a.email = Some(new);
            a.email_confirmed = false;
            set_extra(a, "emailConfirmedAt", J::Null);
            // codes must not go to an unconfirmed inbox (as the reference)
            a.extra.remove(super::email2fa::FLAG);
            Ok(true)
        })
        .await;
    let before = match res {
        Ok((before, _)) => before,
        Err(e) => {
            release_email(app, &email, did).await;
            return Err(e);
        }
    };
    // the email replaced is the one the worker saw, not the one read above
    if let Some(o) = before.email.filter(|o| *o != email) {
        release_email(app, &o, did).await;
    }
    delete_email_tokens(app, did, EMAIL_PURPOSES).await
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateEmailIn {
    email: String,
    token: Option<String>,
    email_auth_factor: Option<bool>,
}

async fn update_email(State(app): AppState, Auth(creds): Auth, Json(inp): Json<UpdateEmailIn>) -> XResult<StatusCode> {
    // app passwords can't change the email (stricter than the reference)
    let did = full_or_oauth_account(&creds, "email", "manage")?;
    let acct =
        app.account(&did).await.map_err(|_| invalid_request(format!("Could not find user info for account: {did}")))?;
    if is_takendown_account(&acct) {
        return Err(takedown_error());
    }
    let email = inp.email.trim().to_ascii_lowercase();
    // explicit factor toggles on the current address (reference updateEmail)
    if let Some(want) = inp.email_auth_factor {
        let same = acct.email.as_deref() == Some(email.as_str());
        if want {
            if !(same && acct.email_confirmed) {
                return Err(invalid_request("Please change and verify your email before enabling OTP"));
            }
            super::email2fa::enable(&app, &did).await?;
            return Ok(StatusCode::OK);
        }
        if same {
            super::email2fa::disable(&app, &acct, inp.token.as_deref()).await?;
            return Ok(StatusCode::OK);
        }
        // disabling while changing the address: the change clears it
    }
    if !email_supported(&email) {
        return Err(invalid_request("This email address is not supported, please use a different email."));
    }
    match inp.token.as_deref().filter(|t| !t.is_empty()) {
        Some(t) => assert_email_token(&app, &did, "update_email", t).await?,
        None if acct.email_confirmed => return Err(XrpcError::bad("TokenRequired", "confirmation token required")),
        None => {}
    }
    set_email(&app, &did, &email).await?;
    Ok(StatusCode::OK)
}

#[derive(Deserialize)]
struct RequestPasswordResetIn {
    email: String,
}

async fn request_password_reset(State(app): AppState, Json(inp): Json<RequestPasswordResetIn>) -> XResult<StatusCode> {
    let email = inp.email.trim().to_ascii_lowercase();
    let acct = match did_by_email(&app, &email).await? {
        Some(did) => account_if_exists(&app, &did).await?.filter(|a| a.email.as_deref() == Some(email.as_str())),
        None => None,
    };
    // An unknown address answers like a mailed one so the endpoint can't be
    // used to learn which addresses have accounts (the reference errors here).
    let Some(acct) = acct else {
        crate::metrics::PASSWORD_RESETS.with_label_values(&["unknown_email"]).inc();
        return Ok(StatusCode::OK);
    };
    // Over a budget it answers exactly as a mailed request does (no headers
    // from these buckets either): the caller is unauthenticated, and an
    // account's mail budget is nobody else's business.
    let acct_limits: [&'static crate::ratelimit::Limit; 2] =
        [&crate::ratelimit::PASSWORD_RESET_ACCOUNT_DAY, &crate::ratelimit::PASSWORD_RESET_ACCOUNT_HOUR];
    if app.ratelimit.consume_unbypassable(&acct_limits, &acct.did, "mail:reset_password", false).is_err() {
        crate::mail::MAIL_SUPPRESSED.with_label_values(&["reset_password", "account_limit"]).inc();
        return Ok(StatusCode::OK);
    }
    let Ok(permit) = mail_permit(&app, Some(&acct.did), &email, "reset_password", false).await else {
        return Ok(StatusCode::OK);
    };
    let token = create_email_token(&app, &acct.did, "reset_password").await?;
    deliver(&app, permit, &email, crate::mail::Email::ResetPassword { handle: &acct.handle, token: &token });
    crate::metrics::PASSWORD_RESETS.with_label_values(&["requested"]).inc();
    Ok(StatusCode::OK)
}

#[derive(Deserialize)]
struct ResetPasswordIn {
    token: String,
    password: String,
}

/// The account a password-reset token was issued for (HA routing sends
/// resetPassword to its owner).
pub async fn reset_token_did(app: &App, token: &str) -> XResult<Option<String>> {
    let routing = format!("_reset:{}", email_token_digest(app, token));
    Ok(app.get_private(&routing, "t").await?.map(|v| String::from_utf8_lossy(&v).to_string()))
}

/// Sets a new password and revokes every session, OAuth grants included.
/// Waits for an Argon2 permit: request paths shed instead, with
/// [`state::try_hash_password`] and [`change_password_hashed`].
pub(super) async fn change_password(app: &App, did: &str, password: &str) -> XResult<()> {
    change_password_hashed(app, did, state::hash_password(password).await).await
}

pub(super) async fn change_password_hashed(app: &App, did: &str, hash: String) -> XResult<()> {
    update_account(app, did, false, false, move |a| {
        a.password_hash = hash.clone();
        Ok(())
    })
    .await?;
    delete_email_tokens(app, did, &["reset_password"]).await?;
    crate::oauth::store::revoke_all_sessions(app, did).await.map_err(|e| XrpcError::internal(e.description))?;
    revoke_all_sessions(app, did).await
}

async fn reset_password(State(app): AppState, Json(inp): Json<ResetPasswordIn>) -> XResult<StatusCode> {
    if inp.password.len() > NEW_PASSWORD_MAX_LENGTH {
        return Err(invalid_request("Invalid password length."));
    }
    let token = inp.token.trim().to_ascii_uppercase();
    let routing = format!("_reset:{}", email_token_digest(&app, &token));
    let did = reset_token_did(&app, &token).await?.ok_or_else(|| invalid_token("Token is invalid"))?;
    assert_email_token(&app, &did, "reset_password", &token).await?;
    // shed (503, token still valid) rather than queue behind a login flood
    let hash = state::try_hash_password(&inp.password).await?;
    change_password_hashed(&app, &did, hash).await?;
    app.put_private(&routing, vec![pmut(&routing, "t", None)]).await?;
    crate::metrics::PASSWORD_RESETS.with_label_values(&["completed"]).inc();
    Ok(StatusCode::OK)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateInviteCodeIn {
    use_count: i64,
    for_account: Option<String>,
    /// vlpds: limit the code to handles under this served domain.
    handle_domain: Option<String>,
}

async fn create_invite_code(
    State(app): AppState,
    Auth(creds): Auth,
    Json(inp): Json<CreateInviteCodeIn>,
) -> XResult<Json<J>> {
    super::admin::require_admin(&creds)?;
    let account = inp.for_account.unwrap_or_else(|| "admin".into());
    let code = super::admin::gen_invite_code(&app);
    let domain = inp.handle_domain.as_deref();
    super::admin::create_invites(&app, &account, std::slice::from_ref(&code), inp.use_count, false, "admin", domain)
        .await?;
    Ok(Json(json!({"code": code})))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateInviteCodesIn {
    #[serde(default = "one")]
    code_count: usize,
    use_count: i64,
    for_accounts: Option<Vec<String>>,
    handle_domain: Option<String>,
}

fn one() -> usize {
    1
}

async fn create_invite_codes(
    State(app): AppState,
    Auth(creds): Auth,
    Json(inp): Json<CreateInviteCodesIn>,
) -> XResult<Json<J>> {
    super::admin::require_admin(&creds)?;
    let accounts = inp.for_accounts.unwrap_or_else(|| vec!["admin".into()]);
    let mut out = Vec::new();
    for account in accounts {
        let codes: Vec<String> = (0..inp.code_count.min(1000)).map(|_| super::admin::gen_invite_code(&app)).collect();
        let domain = inp.handle_domain.as_deref();
        super::admin::create_invites(&app, &account, &codes, inp.use_count, false, "admin", domain).await?;
        out.push(json!({"account": account, "codes": codes}));
    }
    Ok(Json(json!({"codes": out})))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AccountInviteCodesQ {
    include_used: Option<bool>,
    create_available: Option<bool>,
}

fn rfc3339_ms(s: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(s).ok().map(|d| d.timestamp_millis())
}

/// The reference's `calculateCodesToCreate`: (codes earned and not yet
/// given, possibly <= 0; the routine-code total once they are created).
/// Admin-gifted codes don't count.
pub(super) fn codes_to_create(
    now_ms: i64,
    created_at_ms: i64,
    codes: &[super::admin::InviteCode],
    epoch_ms: i64,
    interval_ms: i64,
) -> (i64, i64) {
    let interval_ms = interval_ms.max(1);
    let routine: Vec<_> = codes.iter().filter(|c| c.created_by != "admin").collect();
    let unused = routine.iter().filter(|c| !c.disabled && c.available > c.uses.len() as i64).count() as i64;
    let lifespan = now_ms - created_at_ms;
    let could_create = if created_at_ms >= epoch_ms {
        lifespan.div_euclid(interval_ms)
    } else {
        lifespan.div_euclid(interval_ms) - (epoch_ms - created_at_ms).div_euclid(interval_ms)
    };
    let epoch_codes = routine.iter().filter(|c| rfc3339_ms(&c.created_at).is_some_and(|t| t > epoch_ms)).count() as i64;
    let to_create = (5 - unused).min(could_create - epoch_codes);
    (to_create, routine.len() as i64 + to_create)
}

/// With `--invite-interval` (and invites required), creates the codes the
/// account has earned; returns all its codes. A concurrent creation on
/// another node is caught afterwards (`DuplicateCreate`), as the reference.
async fn create_earned_invites(
    app: &App,
    acct: &Account,
    codes: Vec<super::admin::InviteCode>,
) -> XResult<Vec<super::admin::InviteCode>> {
    let Some(interval) = app.config.invite_interval.filter(|_| app.config.invite_required) else {
        return Ok(codes);
    };
    let did = acct.did.as_str();
    let e = ext(app);
    let _g = e.lock(&format!("invites-earned:{did}")).await;
    let codes = super::admin::account_invites(app, did).await?;
    let created_at = rfc3339_ms(&acct.created_at).unwrap_or(0);
    let now = (crate::tid::now_micros() / 1000) as i64;
    let interval_ms = i64::try_from(interval.as_millis()).unwrap_or(i64::MAX);
    let (n, total) = codes_to_create(now, created_at, &codes, app.config.invite_epoch_ms, interval_ms);
    if n <= 0 {
        return Ok(codes);
    }
    let new: Vec<String> = (0..n).map(|_| super::admin::gen_invite_code(app)).collect();
    let disabled = acct.extra.get("invitesDisabled").and_then(|v| v.as_bool()).unwrap_or(false);
    super::admin::create_invites(app, did, &new, 1, disabled, did, None).await?;
    let after = super::admin::account_invites(app, did).await?;
    if after.iter().filter(|c| c.created_by != "admin").count() as i64 > total {
        return Err(XrpcError::bad("DuplicateCreate", "attempted to create additional codes in another request"));
    }
    Ok(after)
}

async fn get_account_invite_codes(
    State(app): AppState,
    Auth(creds): Auth,
    Query(q): Query<AccountInviteCodesQ>,
) -> XResult<Json<J>> {
    let did = full_access(&creds)?;
    let acct = app.account(&did).await.map_err(|_| XrpcError::bad("NotFound", "Account not found"))?;
    if is_takendown_account(&acct) {
        return Err(takedown_error());
    }
    let include_used = q.include_used.unwrap_or(true);
    let mut codes = super::admin::account_invites(&app, &did).await?;
    if q.create_available.unwrap_or(true) {
        codes = create_earned_invites(&app, &acct, codes).await?;
    }
    let codes: Vec<J> = codes
        .into_iter()
        .filter(|c| !c.disabled && (include_used || (c.uses.len() as i64) < c.available))
        .map(|c| serde_json::to_value(c).unwrap())
        .collect();
    Ok(Json(json!({"codes": codes})))
}

/// Never via service auth (the reference's PROTECTED_METHODS).
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

/// The reference's PRIVILEGED_METHODS, case-insensitive like its LxmSet.
fn privileged_method(lxm: &str) -> bool {
    let l = lxm.to_ascii_lowercase();
    l.starts_with("chat.bsky.") || l == "com.atproto.server.createaccount"
}

fn protected_method(lxm: &str) -> bool {
    PROTECTED_METHODS.iter().any(|m| m.eq_ignore_ascii_case(lxm))
}

#[derive(Deserialize)]
struct ServiceAuthQ {
    aud: String,
    exp: Option<i64>,
    lxm: Option<String>,
}

async fn get_service_auth(State(app): AppState, Auth(creds): Auth, Query(q): Query<ServiceAuthQ>) -> XResult<Json<J>> {
    let did = user_did(&creds)?;
    let lxm = q.lxm.as_deref().filter(|l| !l.is_empty());
    let (aud_did, fragment) = match q.aud.split_once('#') {
        Some((d, f)) => (d, Some(f)),
        None => (q.aud.as_str(), None),
    };
    if !is_atproto_did(aud_did) || fragment.is_some_and(|f| f.is_empty()) {
        return Err(invalid_request("aud must be a valid atproto DID or did#serviceId reference"));
    }
    if let Credentials::AppPassword { privileged: false, .. } = &creds {
        if let Some(l) = lxm.filter(|l| privileged_method(l)) {
            return Err(invalid_request(format!(
                "insufficient access to request a service auth token for the following method: {l}"
            )));
        }
    }
    // A space-method token carries authority (a notifyWrite as a writer, a
    // revocation as an authority) to another host: OAuth apps get one only
    // with a space: grant covering it, never from transition:generic or rpc:
    // alone, and other credentials never (space data is OAuth-only).
    if let Some(l) = lxm.filter(|l| crate::space::is_space_nsid(l)) {
        let ok = match &creds {
            Credentials::OAuth { scopes, .. } => scopes.allows_space_service_auth(l, &did),
            _ => false,
        };
        if !ok {
            return Err(invalid_request(format!(
                "insufficient access to request a service auth token for the following method: {l} (needs an OAuth space: grant covering it)"
            )));
        }
    }
    // a scoped app password is held to its scopes here as OAuth is: else a
    // service token would carry what the scopes withhold
    if matches!(creds, Credentials::OAuth { .. }) || creds.app_pass_scopes().is_some() {
        creds.need_rpc(lxm.unwrap_or("*"), &q.aud)?;
    }
    let acct = app.account(&did).await?;
    if is_takendown_account(&acct) && lxm != Some("com.atproto.server.createAccount") {
        return Err(bad_scope());
    }
    let now = now_secs() as i64;
    let ttl = match q.exp {
        Some(exp) => {
            let diff = exp - now;
            if diff < 0 {
                return Err(XrpcError::bad("BadExpiration", "expiration is in past"));
            } else if diff > 3600 {
                return Err(XrpcError::bad(
                    "BadExpiration",
                    "cannot request a token with an expiration more than an hour in the future",
                ));
            } else if lxm.is_none() && diff > 60 {
                return Err(XrpcError::bad(
                    "BadExpiration",
                    "cannot request a method-less token with an expiration more than a minute in the future",
                ));
            }
            diff as u64
        }
        None => 60,
    };
    if let Some(l) = lxm.filter(|l| protected_method(l)) {
        return Err(invalid_request(format!(
            "cannot request a service auth token for the following protected method: {l}"
        )));
    }
    let key = app.secrets.account_signing_key(&acct).await?;
    let token = crate::auth::service_auth_jwt(&key, &did, &q.aud, lxm, ttl)?;
    Ok(Json(json!({"token": token})))
}

/// The reference's @atproto/did isAtprotoDid.
pub(super) fn is_atproto_did(s: &str) -> bool {
    if let Some(id) = s.strip_prefix("did:plc:") {
        return id.len() == 24 && id.bytes().all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7'));
    }
    if let Some(host) = s.strip_prefix("did:web:") {
        return super::syntax::valid_did(s)
            && !host.contains(':')
            && (!host.contains("%3A") || host.starts_with("localhost%3A"));
    }
    false
}

async fn check_signup_queue(Auth(creds): Auth) -> XResult<Json<J>> {
    standard_no_oauth(&creds)?;
    Ok(Json(json!({"activated": true})))
}

#[derive(Deserialize)]
struct HandleAvailabilityQ {
    handle: String,
    email: Option<String>,
}

async fn handle_available(app: &App, handle: &str) -> XResult<bool> {
    if ensure_no_slur(handle).is_err() || ensure_service_handle(app, handle, false).is_err() {
        return Ok(false);
    }
    Ok(app.resolve_handle(handle).await?.is_none())
}

async fn check_handle_availability(State(app): AppState, Query(q): Query<HandleAvailabilityQ>) -> XResult<Json<J>> {
    if let Some(e) = q.email.as_deref().filter(|e| !e.is_empty()) {
        if !valid_email(&e.to_ascii_lowercase()) {
            return Err(XrpcError::bad("InvalidEmail", "An invalid email was provided."));
        }
    }
    let handle = normalize_handle(&q.handle)?;
    if handle_available(&app, &handle).await? {
        return Ok(Json(json!({
            "handle": handle,
            "result": {"$type": "com.atproto.temp.checkHandleAvailability#resultAvailable"},
        })));
    }
    let domain = app.handle_domains.served(&handle).unwrap_or_else(|| app.handle_domains.primary().to_string());
    let suffix = format!(".{domain}");
    let base: String =
        handle.split('.').next().unwrap_or("user").chars().filter(|c| c.is_ascii_alphanumeric()).take(14).collect();
    let base = if base.len() < 3 { format!("{base}user") } else { base };
    let mut suggestions = Vec::new();
    for _ in 0..12 {
        if suggestions.len() >= 3 {
            break;
        }
        let cand = format!("{base}{}{suffix}", rand::random::<u16>() % 10_000);
        if handle_available(&app, &cand).await? && !suggestions.iter().any(|s: &J| s["handle"] == cand) {
            suggestions.push(json!({"handle": cand, "method": "random_digits"}));
        }
    }
    Ok(Json(json!({
        "handle": handle,
        "result": {"$type": "com.atproto.temp.checkHandleAvailability#resultUnavailable", "suggestions": suggestions},
    })))
}

async fn set_totp_flag(app: &App, did: &str, enabled: bool) -> XResult<()> {
    update_account(app, did, false, false, move |a| {
        set_extra(a, "totpEnabled", json!(enabled));
        Ok(())
    })
    .await
    .map(|_| ())
}

/// The operator's reset (`vlpds.admin.resetSecondFactors`): passkeys, TOTP,
/// the shared recovery codes and lockout, and trusted browsers, in one
/// write; what the passkeys signed in is ended as a removal would. What
/// was removed, for the audit entry.
pub(super) async fn reset_second_factors(app: &App, did: &str, revoke_sessions: bool) -> XResult<J> {
    use super::cas::Op;
    let passkeys = super::passkeys::load(app, did).await?;
    let totp = crate::totp::load(app, did).await?.enabled();
    let trusted = super::internal::scan_private_anywhere(app, did, super::signin::TRUST).await?.len();
    let ops = vec![
        Op::put(super::passkeys::ROW, None),
        Op::put(crate::totp::PRIVATE_NAME, None),
        Op::put(super::mfa::ROW, None),
        Op::DeletePrefix { prefix: super::signin::TRUST.into() },
    ];
    app.private_cas(did, Vec::new(), ops).await?;
    set_totp_flag(app, did, false).await?;
    super::passkeys::note_count(app, did, 0).await;
    if revoke_sessions {
        revoke_everything(app, did).await?;
    } else {
        for c in &passkeys.creds {
            revoke_signed_in_with(app, did, &c.auth_ref()).await?;
        }
    }
    if !passkeys.creds.is_empty() {
        crate::metrics::PASSKEYS.with_label_values(&["reset"]).inc();
    }
    super::passkeys::security_mail(
        app,
        did,
        "This server's operator reset your two-factor sign-in: your passkeys, authenticator app, recovery codes and trusted browsers were removed. Set them up again on the Security page.",
    )
    .await;
    Ok(
        json!({"passkeys": passkeys.creds.len(), "totp": totp, "trustedBrowsers": trusted, "signedOut": revoke_sessions}),
    )
}

async fn setup_totp(State(app): AppState, Auth(creds): Auth) -> XResult<Json<J>> {
    let did = full_access(&creds)?;
    let acct = app.account(&did).await?;
    let _g = crate::totp::lock(&did).await;
    let secret = crate::totp::base32_encode(&crate::totp::generate_secret());
    'cas: {
        for _ in 0..crate::totp::CAS_ROUNDS {
            let (mut st, raw) = crate::totp::load_raw(&app, &did).await?;
            if st.enabled() {
                return Err(invalid_request("TOTP is already enabled; disable it first"));
            }
            st.pending = Some(secret.clone());
            if crate::totp::save_if(&app, &did, &st, raw).await? {
                break 'cas;
            }
        }
        return Err(crate::totp::conflict());
    }
    let uri = crate::totp::otpauth_uri(&secret, public_host(&app), &acct.handle);
    Ok(Json(json!({"secret": secret, "uri": uri})))
}

#[derive(Deserialize)]
struct ConfirmTotpIn {
    code: String,
}

async fn confirm_totp(State(app): AppState, Auth(creds): Auth, Json(inp): Json<ConfirmTotpIn>) -> XResult<Json<J>> {
    let did = full_access(&creds)?;
    let codes = 'cas: {
        let _g = crate::totp::lock(&did).await;
        for _ in 0..crate::totp::CAS_ROUNDS {
            let (mut st, raw, mut m, mraw) = crate::totp::load_both(&app, &did).await?;
            if st.enabled() {
                return Err(invalid_request("TOTP is already enabled"));
            }
            let pending = st
                .pending
                .clone()
                .ok_or_else(|| invalid_request("No pending TOTP setup; call vlpds.server.setupTotp first"))?;
            let secret = crate::totp::base32_decode(&pending)
                .ok_or_else(|| XrpcError::internal("corrupt pending TOTP secret"))?;
            let step = crate::totp::verify_code(&secret, &inp.code, crate::totp::now_secs(), 0)
                .ok_or_else(|| invalid_token("Token is invalid"))?;
            st.secret = Some(pending);
            st.pending = None;
            st.last_step = step;
            st.enabled_at = Some(crate::events::now_rfc3339());
            // the first strong factor brings the shared recovery codes; a
            // passkey may have already
            let codes = if m.recovery.is_empty() { m.issue(&did, crate::totp::now_secs()) } else { Vec::new() };
            // flag first: a crash between the two writes must not leave TOTP
            // enabled with the login fast path (totpEnabled=false) skipping it
            set_totp_flag(&app, &did, true).await?;
            if crate::totp::save_both(&app, &did, &st, raw, &m, mraw, Vec::new()).await? {
                break 'cas codes;
            }
        }
        return Err(crate::totp::conflict());
    };
    super::passkeys::security_mail(&app, &did, "An authenticator app was turned on for two-factor sign-in.").await;
    Ok(Json(json!({"enabled": true, "recoveryCodes": codes})))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DisableTotpIn {
    code: Option<String>,
    recovery_code: Option<String>,
    password: String,
}

async fn disable_totp(State(app): AppState, Auth(creds): Auth, Json(inp): Json<DisableTotpIn>) -> XResult<StatusCode> {
    let did = full_access(&creds)?;
    super::passkeys::check_password(&app, &did, &inp.password).await?;
    'cas: {
        let _g = crate::totp::lock(&did).await;
        for _ in 0..crate::totp::CAS_ROUNDS {
            let (mut st, raw, mut m, mraw) = crate::totp::load_both(&app, &did).await?;
            // read in this round and held to it: a passkey removed meanwhile
            // can't leave the account with a factor and no codes
            let (pk, pkraw) = super::passkeys::load_raw(&app, &did).await?;
            let passkeys = !pk.creds.is_empty();
            super::cas::pause_point("totp_off", &did).await;
            if !st.enabled() {
                return Err(invalid_request("TOTP is not enabled"));
            }
            let code = inp
                .code
                .as_deref()
                .or(inp.recovery_code.as_deref())
                .filter(|c| !c.trim().is_empty())
                .ok_or_else(|| invalid_request("code or recoveryCode is required"))?;
            // counts toward the lockout like a sign-in attempt
            let r = crate::totp::attempt(&mut st, &mut m, &did, code, crate::totp::now_secs());
            if r.is_ok() {
                st = crate::totp::TotpState::default();
                // the last strong factor takes the recovery codes with it
                if !passkeys {
                    m = super::mfa::Mfa::default();
                }
            }
            let extra = vec![super::cas::Cond::eq(super::passkeys::ROW, pkraw)];
            if crate::totp::save_both(&app, &did, &st, raw, &m, mraw, extra).await? {
                r?;
                break 'cas;
            }
        }
        return Err(crate::totp::conflict());
    }
    set_totp_flag(&app, &did, false).await?;
    super::passkeys::security_mail(&app, &did, "The authenticator app was turned off for two-factor sign-in.").await;
    Ok(StatusCode::OK)
}

async fn get_totp_status(State(app): AppState, Auth(creds): Auth) -> XResult<Json<J>> {
    let did = standard_no_oauth(&creds)?;
    let st = crate::totp::load(&app, &did).await?;
    let left = super::mfa::remaining(&app, &did).await?;
    let mut out = json!({"enabled": st.enabled(), "pending": st.pending.is_some(), "recoveryCodesRemaining": left});
    if let Some(at) = &st.enabled_at {
        out["enabledAt"] = json!(at);
    }
    Ok(Json(out))
}

/// A scoped app password and one of its sessions (`super::private_rows`).
pub(super) fn scoped_app_password_fixture_rows(did: &str) -> Vec<super::private_rows::PrivateRow> {
    use super::private_rows::enc;
    let scopes = "atproto repo:app.bsky.feed.post?action=create blob:image/*";
    let st = RefreshState {
        family: "0006439b2a1c0000aabbccddeeff0022".into(),
        exp: 1_797_776_000,
        app_password: Some(AppPassRef { name: "bot".into(), privileged: false, scopes: Some(scopes.into()) }),
        created_at: 1_790_000_000,
        next_id: None,
        auth_cred: None,
        created_ip: None,
        ip: None,
    };
    let hash = "5e2d1cf1".repeat(8);
    let meta = json!({"name": "bot", "createdAt": "2026-10-01T00:00:00.000Z", "privileged": false, "hash": hash, "scopes": scopes});
    let r = |name: String, v: Vec<u8>| (did.to_string(), name, v);
    vec![
        r("sess/00112233445566778899aabbccddeeff0011223344556611".into(), enc(&st)),
        r("apppass/bot".into(), enc(&meta)),
        r(format!("apphash/{hash}"), b"bot".to_vec()),
    ]
}

/// A legacy session signed in with a passkey (`super::private_rows`).
pub(super) fn passkey_session_fixture_rows(did: &str, cred: &str) -> Vec<super::private_rows::PrivateRow> {
    let st = RefreshState {
        family: "0006439b2a1c0000aabbccddeeff0033".into(),
        exp: 1_797_776_000,
        app_password: None,
        created_at: 1_790_000_000,
        next_id: None,
        auth_cred: Some(cred.into()),
        created_ip: None,
        ip: None,
    };

    vec![(did.into(), "sess/00112233445566778899aabbccddeeff0011223344556622".into(), super::private_rows::enc(&st))]
}

/// Golden fixtures (`super::private_rows`); the `json!` rows repeat their
/// writers' shapes.
pub(super) fn fixture_rows(did: &str) -> Vec<super::private_rows::PrivateRow> {
    use super::private_rows::enc;
    let fam = "0006439b2a1c0000aabbccddeeff0011";
    let st = RefreshState {
        family: fam.into(),
        exp: 1_797_776_000,
        app_password: Some(AppPassRef { name: "ci".into(), privileged: true, scopes: None }),
        created_at: 1_790_000_000,
        next_id: Some("00112233445566778899aabbccddeeff0011223344556677".into()),
        auth_cred: None,
        created_ip: None,
        ip: None,
    };
    let hash = "4f1c0de0".repeat(8);
    let et = EmailToken { token_hash: "ab".repeat(32), requested_at: 1_790_000_000_000 };
    let before: u64 = 1_790_000_000_000_000;
    let digest = "cd".repeat(32);
    let did_key = "did:key:zQ3shfixture";
    let r = |name: String, v: Vec<u8>| (did.to_string(), name, v);
    vec![
        r("sess/00112233445566778899aabbccddeeff0011223344556600".into(), enc(&st)),
        r(
            "apppass/ci".into(),
            enc(&json!({"name": "ci", "createdAt": "2026-10-01T00:00:00.000Z", "privileged": true, "hash": hash})),
        ),
        r(format!("apphash/{hash}"), b"ci".to_vec()),
        r("etok/update_email".into(), enc(&et)),
        r(format!("{REVOKED_ALL}{before:016x}"), enc(&json!({"before": before, "exp": 1_790_007_200u64}))),
        r(format!("{REVOKED_FAMILY}{fam}"), enc(&json!({"exp": 1_790_007_200u64}))),
        // no AUTH_EPOCH row: it postdates L1, whose rows.json is frozen
        r(
            format!("{TAKEDOWN}rec/app.bsky.feed.post/3l3qo2vutsw2b"),
            enc(
                &json!({"uri": format!("at://{did}/app.bsky.feed.post/3l3qo2vutsw2b"), "did": did, "cid": "bafyreie5737gdxlw5i64vzichcalba3z2v5n6icifvx5xytvske7mr3hpm", "ref": "mod-1"}),
            ),
        ),
        r(
            format!("{TAKEDOWN}blob/bafkreie5737gdxlw5i64vzichcalba3z2v5n6icifvx5xytvske7mr3hpm"),
            enc(
                &json!({"did": did, "cid": "bafkreie5737gdxlw5i64vzichcalba3z2v5n6icifvx5xytvske7mr3hpm", "ref": null}),
            ),
        ),
        (format!("_reset:{digest}"), "t".into(), did.as_bytes().to_vec()),
        (
            reserved_routing(did_key),
            "k".into(),
            enc(&json!({"key": "vw1.kid.cmVzZXJ2ZWQ", "did": did, "createdAt": "2026-10-01T00:00:00.000Z"})),
        ),
        (
            reserved_routing(did),
            "k".into(),
            enc(&json!({"signingKey": did_key, "createdAt": "2026-10-01T00:00:00.000Z"})),
        ),
    ]
}

/// None: not one of this module's rows.
pub(super) fn check_row(routing: &str, name: &str, val: &[u8]) -> Option<anyhow::Result<&'static str>> {
    use super::private_rows::{json_row, typed_row, utf8_row};
    if routing.starts_with("_reset:") && name == "t" {
        return Some(utf8_row("reset token", val));
    }
    if routing.starts_with("_reserved:") && name == "k" {
        let fields: &[(&str, char)] = if routing.starts_with("_reserved:did:key:") {
            &[("key", 's'), ("createdAt", 's')]
        } else {
            &[("signingKey", 's'), ("createdAt", 's')]
        };
        return Some(json_row("reserved signing key", val, fields));
    }
    if !routing.starts_with("did:") {
        return None;
    }
    Some(if name.starts_with("sess/") {
        typed_row::<RefreshState>("session", val)
    } else if name.starts_with("apppass/") {
        json_row("app password", val, &[("name", 's'), ("createdAt", 's'), ("privileged", 'b'), ("hash", 's')])
            .and_then(|k| {
                let scopes = serde_json::from_slice::<J>(val)?["scopes"].clone();
                anyhow::ensure!(scopes.is_null() || scopes.is_string(), "app password: scopes is not a string");
                Ok(k)
            })
    } else if name.starts_with("apphash/") {
        utf8_row("app password hash", val)
    } else if name.starts_with("etok/") {
        typed_row::<EmailToken>("email token", val)
    } else if name == AUTH_EPOCH {
        typed_row::<String>("credential epoch", val)
    } else if name == DELETING {
        typed_row::<Deleting>("deletion in progress", val)
    } else if name.starts_with(REVOKED_ALL) || name.starts_with(REVOKED_FAMILY) {
        let fields: &[(&str, char)] =
            if name.starts_with(REVOKED_ALL) { &[("before", 'u'), ("exp", 'u')] } else { &[("exp", 'u')] };
        json_row("session revocation", val, fields).and_then(|k| {
            anyhow::ensure!(
                revocation_expired(routing, name, val, 0) == Some(false),
                "the revocation GC can't read it"
            );
            Ok(k)
        })
    } else if name.starts_with(&format!("{TAKEDOWN}rec/")) {
        json_row("record takedown", val, &[("uri", 's'), ("did", 's'), ("cid", 's')])
    } else if name.starts_with(&format!("{TAKEDOWN}blob/")) {
        json_row("blob takedown", val, &[("did", 's'), ("cid", 's')])
    } else {
        return None;
    })
}

#[cfg(test)]
mod invite_interval_tests {
    use super::super::admin::{InviteCode, InviteUse};
    use super::codes_to_create;

    const DAY: i64 = 86_400_000;
    const NOW: i64 = 1_800_000_000_000;

    fn iso(ms: i64) -> String {
        chrono::DateTime::from_timestamp_millis(ms).unwrap().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
    }

    fn used() -> InviteUse {
        InviteUse { used_by: "did:example:test".into(), used_at: iso(NOW) }
    }

    fn code(by: &str, at_ms: i64) -> InviteCode {
        InviteCode {
            code: format!("c-{at_ms}-{}", rand::random::<u32>()),
            available: 1,
            disabled: false,
            for_account: "did:plc:a".into(),
            created_by: by.into(),
            created_at: iso(at_ms),
            uses: vec![],
            handle_domain: None,
        }
    }

    /// invite-codes.test.ts (interval 1 day, epoch 3 days ago): "allow users
    /// to get available user invites"
    #[test]
    fn earns_one_code_per_interval() {
        let epoch = NOW - 3 * DAY;
        // a new account: nothing yet
        assert_eq!(codes_to_create(NOW, NOW - 1000, &[], epoch, DAY).0, 0);
        // made 2 days ago: 2 codes
        assert_eq!(codes_to_create(NOW, NOW - 2 * DAY, &[], epoch, DAY), (2, 2));
        // both used: no more
        let mut got = [code("did:plc:a", NOW), code("did:plc:a", NOW)];
        got.iter_mut().for_each(|c| c.uses.push(used()));
        assert!(codes_to_create(NOW, NOW - 2 * DAY, &got, epoch, DAY).0 <= 0);
    }

    /// "admin gifted codes to not impact a users available codes"
    #[test]
    fn admin_codes_do_not_count() {
        let admin: Vec<_> = (0..3).map(|i| code("admin", NOW - i)).collect();
        assert_eq!(codes_to_create(NOW, NOW - 2 * DAY, &admin, NOW - 3 * DAY, DAY), (2, 2));
    }

    /// "creates invites based on epoch"
    #[test]
    fn counts_only_age_since_the_epoch() {
        let epoch = NOW - 3 * DAY;
        // 2 codes taken while the account looked 2 days old
        let mut codes: Vec<_> = (0..2).map(|i| code("did:plc:a", NOW - 1000 + i)).collect();
        // it turns out ~10 days old: the 3-day epoch caps it at 3
        let created = NOW - (10.01 * DAY as f64) as i64;
        assert_eq!(codes_to_create(NOW, created, &codes, epoch, DAY), (1, 3));
        codes.push(code("did:plc:a", NOW - 500));
        codes.iter_mut().for_each(|c| c.uses.push(used()));
        assert!(codes_to_create(NOW, created, &codes, epoch, DAY).0 <= 0);
        // 10 unused codes from before the epoch: over the 5-unused cap
        let mut padded = codes.clone();
        padded.extend((0..10).map(|i| code("did:plc:a", NOW - 5 * DAY + i)));
        assert!(codes_to_create(NOW, created, &padded, epoch, DAY).0 <= 0);
        // ...and once they are used, the epoch's 3 are still spent
        padded.iter_mut().filter(|c| c.uses.is_empty()).for_each(|c| c.uses.push(used()));
        assert!(codes_to_create(NOW, created, &padded, epoch, DAY).0 <= 0);
    }

    /// At most 5 unused routine codes; disabled ones aren't "unused".
    #[test]
    fn caps_unused_codes_at_five() {
        assert_eq!(codes_to_create(NOW, NOW - 100 * DAY, &[], 0, DAY), (5, 5));
        let mut four: Vec<_> = (0..4).map(|i| code("did:plc:a", NOW - DAY + i)).collect();
        assert_eq!(codes_to_create(NOW, NOW - 100 * DAY, &four, 0, DAY).0, 1);
        four.iter_mut().for_each(|c| c.disabled = true);
        assert_eq!(codes_to_create(NOW, NOW - 100 * DAY, &four, 0, DAY).0, 5);
    }
}

#[cfg(test)]
mod ctl_tests {
    use super::*;

    /// An unreadable owner: a recent cached view is still used, an old one
    /// or none fails closed (503).
    #[test]
    fn ctl_fails_closed_without_a_recent_view() {
        let now = 1_000_000;
        let view = |age: u64| Some(Arc::new(Ctl { at: now - age, ..Default::default() }));
        assert!(stale_or_unavailable(view(STALE_MAX_SECS), now).is_ok());
        let status = |r: XResult<Arc<Ctl>>| r.err().map(|e| e.status);
        assert_eq!(status(stale_or_unavailable(view(STALE_MAX_SECS + 1), now)), Some(StatusCode::SERVICE_UNAVAILABLE));
        assert_eq!(status(stale_or_unavailable(None, now)), Some(StatusCode::SERVICE_UNAVAILABLE));
    }

    /// A shard in flight: the same bound for the view standing in, and
    /// without one a ShardMoved the entry node resends a write on.
    #[test]
    fn moving_shard_uses_the_same_stale_bound() {
        let now = 1_000_000;
        let view = |age: u64| Some(Arc::new(Ctl { at: now - age, ..Default::default() }));
        assert!(stale(&view(0), now).is_some());
        assert!(stale(&view(STALE_MAX_SECS), now).is_some());
        assert!(stale(&view(STALE_MAX_SECS + 1), now).is_none());
        assert!(stale(&None, now).is_none());
        let e = moved("did:plc:a");
        assert!(super::super::ctl_load::in_flight(&e));
        assert_eq!(e.error, crate::forward::SHARD_MOVED);
        assert!(CTL_MOVE_WAIT_FORWARDED < crate::forward::TTFB_FAST);
    }
}
