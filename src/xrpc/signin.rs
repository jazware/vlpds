//! Sign-in security (docs/oauth-2fa.md "Trusted browsers", "Sign-in alerts
//! and recent sign-ins", "OAuth only"): browsers trusted to skip the second
//! factor, the recent-sign-ins log with its new-device alerts, and the
//! switch that refuses the main password on `createSession`.
//!
//! Rows, all in the account's private state, so its owner serializes them
//! and they move, fail over and get deleted with the account:
//!   p/{did}\0signin/prefs          [`Prefs`]
//!   p/{did}\0signin/log            [`Log`]: recent sign-ins, known devices
//!                                  and today's alert count, one row
//!   p/{did}\0signin/failed         [`Failures`]: recent failed sign-ins for
//!                                  the console, written only on a failure
//!   p/{did}\0trust/{device hash}   [`Trust`]: one trusted browser
//!
//! A trust is valid while the account's credential epoch and its second
//! factors are what they were when it was granted, so a revoke-all
//! (password change, takedown) or any 2FA change voids every trust without
//! having to find them (revoke-all also deletes them).

use super::authn::Credentials;
use super::cas::{Cond, Op};
use super::server::{get_json, now_secs, to_json_bytes};
use super::*;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::LazyLock;

pub(super) const PREFS: &str = "signin/prefs";
pub(super) const LOG: &str = "signin/log";
pub(super) const FAILED: &str = "signin/failed";
pub const TRUST: &str = "trust/";
pub const DEFAULT_TRUST_DAYS: u32 = 30;
const LOG_MAX: usize = 50;
const LOG_MAX_AGE: u64 = 30 * 86_400;
const KNOWN_MAX: usize = 100;
/// A device unseen this long alerts again.
const KNOWN_MAX_AGE: u64 = 180 * 86_400;
/// Per account per UTC day, so alerts never use more than a tenth of the
/// recipient's `mail-recipient-day` budget, which its sign-in codes need.
pub const ALERTS_PER_DAY: u32 = 3;
pub(super) const ALERT_PURPOSE: &str = "sign_in_alert";
const CAS_ROUNDS: usize = 8;

fn is_false(b: &bool) -> bool {
    !*b
}

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Prefs {
    /// createSession refuses the main password (except this server's own
    /// account page after a second factor).
    #[serde(default, skip_serializing_if = "is_false")]
    pub oauth_only: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub block_app_passwords: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub mute_password_alerts: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub mute_app_password_alerts: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Entry {
    /// Minted once per sign-in: a resent write finds it and adds nothing.
    pub id: String,
    pub at: u64,
    /// "password" | "app_password" | "oauth" | "passkey" (in place of the
    /// password)
    pub method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    pub device: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    /// "totp" | "email" | "passkey" | "recovery" | "trusted" (a trusted
    /// browser skipped it)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub factor: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub new_device: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub alerted: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, Deserialize)]
pub(super) struct Known {
    pub device: String,
    pub last: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Log {
    /// Oldest first.
    #[serde(default)]
    pub entries: Vec<Entry>,
    #[serde(default)]
    pub known: Vec<Known>,
    /// UTC day number of `alerts`.
    #[serde(default)]
    pub alert_day: u64,
    #[serde(default)]
    pub alerts: u32,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Trust {
    pub created_at: u64,
    pub last_used_at: u64,
    pub expires_at: u64,
    /// The credential epoch when granted.
    pub epoch: String,
    /// [`factors`] when granted.
    pub factors: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
}

/// For the private-row GC: Some(expired) for a trust row, None for any other.
pub fn trust_expired(routing: &str, name: &str, val: &[u8], now: i64) -> Option<bool> {
    if !routing.starts_with("did:") || !name.starts_with(TRUST) {
        return None;
    }
    Some(serde_json::from_slice::<Trust>(val).map(|t| (t.expires_at as i64) < now).unwrap_or(true))
}

/// The request facts a sign-in records. `device_id` is the browser's
/// `vlpds-device` cookie, only when this server's own pages sent it.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Ctx<'a> {
    pub ip: Option<IpAddr>,
    pub user_agent: Option<&'a str>,
    pub device_id: Option<&'a str>,
}

impl Ctx<'_> {
    /// The cookie's id when there is one. Without it (apps), the user agent
    /// and network stand in for the device.
    fn device_key(&self) -> String {
        match self.device_id {
            Some(id) => format!("b:{}", device_hash(id)),
            None => {
                let ip = self.ip.map(crate::ratelimit::ip_key).unwrap_or_default();
                let h = Sha256::digest(format!("{}\0{ip}", self.user_agent.unwrap_or("")).as_bytes());
                format!("a:{}", &hex::encode(h)[..32])
            }
        }
    }
}

pub(crate) fn user_agent(headers: &HeaderMap) -> Option<&str> {
    headers.get(header::USER_AGENT).and_then(|v| v.to_str().ok()).map(|s| truncate(s, 256))
}

fn truncate(s: &str, n: usize) -> &str {
    match s.char_indices().nth(n) {
        Some((i, _)) => &s[..i],
        None => s,
    }
}

/// The trust row's name: a bucket reader learns no usable cookie.
fn device_hash(device_id: &str) -> String {
    hex::encode(&Sha256::digest(format!("vlpds-device:{device_id}").as_bytes())[..16])
}

/// "Firefox on macOS", or the app's own name for one that isn't a browser.
pub(crate) fn describe_user_agent(ua: Option<&str>) -> String {
    let Some(ua) = ua.map(str::trim).filter(|u| !u.is_empty()) else {
        return "Unknown device".into();
    };
    let has = |s: &str| ua.contains(s);
    let browser = if has("Edg/") || has("EdgA/") || has("EdgiOS/") {
        Some("Edge")
    } else if has("OPR/") || has("Opera") {
        Some("Opera")
    } else if has("Firefox/") || has("FxiOS/") {
        Some("Firefox")
    } else if has("Chrome/") || has("CriOS/") {
        Some("Chrome")
    } else if has("Safari/") && has("Version/") {
        Some("Safari")
    } else {
        None
    };
    let os = if has("iPhone") {
        Some("iPhone")
    } else if has("iPad") {
        Some("iPad")
    } else if has("Android") {
        Some("Android")
    } else if has("Windows") {
        Some("Windows")
    } else if has("CrOS") {
        Some("ChromeOS")
    } else if has("Macintosh") || has("Mac OS X") {
        Some("macOS")
    } else if has("Linux") {
        Some("Linux")
    } else {
        None
    };
    match (browser, os) {
        (Some(b), Some(o)) => format!("{b} on {o}"),
        (Some(b), None) => b.to_string(),
        (None, _) => {
            let name = ua.split_whitespace().next().unwrap_or(ua);
            let name = truncate(name, 40);
            match os {
                Some(o) => format!("{name} on {o}"),
                None => name.to_string(),
            }
        }
    }
}

pub(super) async fn prefs(app: &App, did: &str) -> XResult<Prefs> {
    Ok(get_json::<Prefs>(app, did, PREFS).await?.unwrap_or_default())
}

/// Which second factors are set up, and since when. Any 2FA change changes
/// it, so it voids the trusts granted before. A new factor kind adds a part.
pub(super) async fn factors(app: &App, acct: &Account) -> XResult<String> {
    let totp = crate::totp::load(app, &acct.did).await?;
    let totp_at = if totp.enabled() { totp.enabled_at.clone().unwrap_or_else(|| "on".into()) } else { String::new() };
    let email_at = acct.extra.get(super::email2fa::FLAG).and_then(|v| v.as_str()).unwrap_or("");
    let mut keys: Vec<String> = super::passkeys::load(app, &acct.did).await?.creds.into_iter().map(|c| c.id).collect();
    keys.sort();
    let h = Sha256::digest(format!("totp={totp_at}\0email={email_at}\0passkeys={}", keys.join(",")).as_bytes());
    Ok(hex::encode(&h[..16]))
}

/// Whether a second factor is asked for on a password sign-in.
pub(super) async fn factor_enabled(app: &App, acct: &Account) -> XResult<bool> {
    Ok(super::email2fa::enabled(acct)
        || crate::totp::enabled_for(app, acct).await?
        || super::passkeys::has_any(app, &acct.did).await?)
}

/// 0: trusting is off.
pub(super) fn trust_days(app: &App) -> u32 {
    app.config.trusted_device_days
}

/// Whether this browser may skip the second factor for `acct`. `epoch` is
/// the one the sign-in's password check read.
pub(super) async fn trusted(app: &App, acct: &Account, epoch: &str, device_id: &str) -> XResult<bool> {
    if trust_days(app) == 0 {
        return Ok(false);
    }
    let name = format!("{TRUST}{}", device_hash(device_id));
    let Some(raw) = app.get_private(&acct.did, &name).await? else {
        return Ok(false);
    };
    let Ok(t) = serde_json::from_slice::<Trust>(&raw) else {
        return Ok(false);
    };
    let now = now_secs();
    if now >= t.expires_at || t.epoch != epoch || t.factors != factors(app, acct).await? {
        return Ok(false);
    }
    // a lost race only leaves last-used a bit stale
    let used = Trust { last_used_at: now, ..t };
    let _ = app
        .private_cas(&acct.did, vec![Cond::eq(&name, Some(raw))], vec![Op::put(&name, Some(json_bytes(&used)))])
        .await;
    Ok(true)
}

fn json_bytes<T: serde::Serialize>(v: &T) -> Bytes {
    Bytes::from(to_json_bytes(v))
}

/// Trusts the browser for the configured days; Ok(None) if trusting is off
/// or a password change landed since `epoch` was read. Returns the expiry,
/// which the device row must outlive.
pub(super) async fn trust(
    app: &App,
    acct: &Account,
    epoch: &str,
    device_id: &str,
    ctx: &Ctx<'_>,
) -> XResult<Option<u64>> {
    let days = trust_days(app);
    if days == 0 {
        return Ok(None);
    }
    let now = now_secs();
    let t = Trust {
        created_at: now,
        last_used_at: now,
        expires_at: now + u64::from(days) * 86_400,
        epoch: epoch.to_string(),
        factors: factors(app, acct).await?,
        user_agent: ctx.user_agent.map(String::from),
        ip: ctx.ip.map(|i| i.to_string()),
    };
    let name = format!("{TRUST}{}", device_hash(device_id));
    let out = app
        .private_cas(&acct.did, vec![super::auth_epoch_cond(epoch)], vec![Op::put(&name, Some(json_bytes(&t)))])
        .await?;
    if out.applied {
        crate::metrics::TRUSTED_BROWSERS.with_label_values(&["granted"]).inc();
    }
    Ok(out.applied.then_some(t.expires_at))
}

/// How a sign-in proved itself, for the log.
#[derive(Clone, Debug)]
pub(crate) enum Method {
    Password,
    AppPassword(String),
    /// The OAuth sign-in page, for this client (None: `/oauth/account`).
    OAuth(Option<String>),
    /// A passkey in place of the password: on the OAuth page for this
    /// client, or (None) on this server's own pages.
    Passkey(Option<String>),
}

impl Method {
    fn name(&self) -> &'static str {
        match self {
            Method::Password => "password",
            Method::AppPassword(_) => "app_password",
            Method::OAuth(_) => "oauth",
            Method::Passkey(_) => "passkey",
        }
    }

    fn muted(&self, p: &Prefs) -> bool {
        match self {
            Method::AppPassword(_) => p.mute_app_password_alerts,
            _ => p.mute_password_alerts,
        }
    }

    fn describe(&self) -> String {
        match self {
            Method::Password => "with your password".into(),
            Method::AppPassword(n) => format!("with the app password \u{201c}{n}\u{201d}"),
            Method::OAuth(Some(c)) => format!("with your password, for {}", client_name(c)),
            Method::OAuth(None) => "with your password, on the sign-in page".into(),
            Method::Passkey(Some(c)) => format!("with a passkey, for {}", client_name(c)),
            Method::Passkey(None) => "with a passkey".into(),
        }
    }
}

fn client_name(client_id: &str) -> String {
    reqwest::Url::parse(client_id)
        .ok()
        .and_then(|u| u.host_str().map(String::from))
        .unwrap_or_else(|| client_id.to_string())
}

/// Logs a successful sign-in and mails a new-device alert if one is due.
/// Never fails the sign-in: a lost record is logged. `factor`: "totp",
/// "email", "trusted" or None.
pub(crate) async fn record(app: &App, acct: &Account, method: Method, factor: Option<&str>, ctx: &Ctx<'_>) {
    crate::metrics::SIGN_IN_FACTORS.with_label_values(&[method.name(), factor.unwrap_or("none")]).inc();
    if let Err(e) = record_inner(app, acct, &method, factor, ctx).await {
        tracing::warn!(did = %acct.did, error = %e.message, "sign-in not recorded");
    }
}

async fn record_inner(app: &App, acct: &Account, method: &Method, factor: Option<&str>, ctx: &Ctx<'_>) -> XResult<()> {
    let did = acct.did.as_str();
    let now = now_secs();
    let entry = Entry {
        id: hex::encode(rand::random::<[u8; 8]>()),
        at: now,
        method: method.name().into(),
        app_password: match method {
            Method::AppPassword(n) => Some(n.clone()),
            _ => None,
        },
        client_id: match method {
            Method::OAuth(c) | Method::Passkey(c) => c.clone(),
            _ => None,
        },
        device: ctx.device_key(),
        user_agent: ctx.user_agent.map(String::from),
        ip: ctx.ip.map(|i| i.to_string()),
        factor: factor.map(String::from),
        new_device: false,
        alerted: false,
    };
    let prefs = prefs(app, did).await?;
    let mut alert = None;
    'cas: {
        for _ in 0..CAS_ROUNDS {
            let raw = app.get_private(did, LOG).await?;
            // the first sign-in recorded sets the baseline: a new account,
            // or every account when this shipped, mails nothing
            let first = raw.is_none();
            let mut log: Log =
                raw.as_deref().map(serde_json::from_slice).transpose().unwrap_or_default().unwrap_or_default();
            if log.entries.iter().any(|e| e.id == entry.id) {
                break 'cas;
            }
            let mut e = entry.clone();
            alert = apply(&mut log, &mut e, now, first, method.muted(&prefs), acct.email.is_some());
            let ops = vec![Op::put(LOG, Some(json_bytes(&log)))];
            if app.private_cas(did, vec![Cond::eq(LOG, raw)], ops).await?.applied {
                break 'cas;
            }
        }
        return Err(super::server::cas_conflict());
    }
    let result = match (alert, &acct.email) {
        (Some(MAILED), Some(email)) => send_alert(app, acct, email, method, &entry).await,
        (r, _) => r,
    };
    if let Some(r) = result {
        crate::metrics::SIGN_IN_ALERTS.with_label_values(&[r]).inc();
    }
    Ok(())
}

/// [`apply`]'s answer for a sign-in that is mailed (`vlpds_sign_in_alerts_total`).
const MAILED: &str = "mailed";

/// Prunes `log`, adds `e` and decides whether it is mailed (and counts it):
/// None for a known device, else [`MAILED`] or why not.
fn apply(log: &mut Log, e: &mut Entry, now: u64, first: bool, muted: bool, has_email: bool) -> Option<&'static str> {
    log.entries.retain(|x| now.saturating_sub(x.at) <= LOG_MAX_AGE);
    log.known.retain(|k| now.saturating_sub(k.last) <= KNOWN_MAX_AGE);
    e.new_device = !log.known.iter().any(|k| k.device == e.device);
    log.known.retain(|k| k.device != e.device);
    log.known.push(Known { device: e.device.clone(), last: now });
    if log.known.len() > KNOWN_MAX {
        log.known.drain(..log.known.len() - KNOWN_MAX);
    }
    let today = now / 86_400;
    if log.alert_day != today {
        log.alert_day = today;
        log.alerts = 0;
    }
    let result = if !e.new_device {
        None
    } else if first {
        Some("baseline")
    } else if muted {
        Some("muted")
    } else if !has_email {
        Some("no_email")
    } else if e.factor.as_deref() == Some("email") {
        // an emailed code just went to the same inbox
        Some("email_code")
    } else if log.alerts >= ALERTS_PER_DAY {
        Some("account_limit")
    } else {
        Some(MAILED)
    };
    let alert = result == Some(MAILED);
    if alert {
        log.alerts += 1;
    }
    e.alerted = alert;
    log.entries.push(e.clone());
    if log.entries.len() > LOG_MAX {
        log.entries.drain(..log.entries.len() - LOG_MAX);
    }
    result
}

/// [`MAILED`], or "budget" when a mail budget refused it.
async fn send_alert(app: &App, acct: &Account, email: &str, method: &Method, e: &Entry) -> Option<&'static str> {
    // no RateLimit headers: the caller is whoever just signed in
    let permit = match super::server::mail_permit(app, Some(&acct.did), email, ALERT_PURPOSE, false).await {
        Ok(p) => p,
        Err(_) => return Some("budget"),
    };
    let device = describe_user_agent(e.user_agent.as_deref());
    let ip = e.ip.clone().unwrap_or_else(|| "an unknown address".into());
    let at = chrono::DateTime::from_timestamp(e.at as i64, 0)
        .map(|t| t.format("%Y-%m-%d %H:%M UTC").to_string())
        .unwrap_or_default();
    let how = method.describe();
    super::server::deliver(
        app,
        permit,
        email,
        crate::mail::Email::SignInAlert { handle: &acct.handle, device: &device, ip: &ip, method: &how, at: &at },
    );
    Some(MAILED)
}

// ------------------------------------------------------- failed sign-ins

const FAILED_MAX: usize = 20;
/// A failure like the newest one (method, reason, address) within this
/// adds to its count instead of a new entry.
const FAILED_MERGE_SECS: u64 = 600;

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Failure {
    pub at: u64,
    pub last_at: u64,
    /// Attempts this entry stands for.
    pub count: u32,
    /// "password" | "app_password" | "oauth"
    pub method: String,
    /// A [`FailReason`] name.
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, Deserialize)]
pub(super) struct Failures {
    /// Oldest first.
    #[serde(default)]
    pub entries: Vec<Failure>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FailReason {
    WrongPassword,
    /// A wrong second-factor code, recovery code or passkey.
    WrongCode,
    /// The factor's lockout was in force, or this attempt set it.
    FactorLocked,
    RateLimited,
}

impl FailReason {
    fn name(self) -> &'static str {
        match self {
            FailReason::WrongPassword => "wrong_password",
            FailReason::WrongCode => "wrong_code",
            FailReason::FactorLocked => "factor_locked",
            FailReason::RateLimited => "rate_limited",
        }
    }

    /// A flood of refused requests costs a write a second per account and
    /// reason at most (rate-limited ones, which need no work to send, one
    /// per 10 s).
    fn gate_secs(self) -> u64 {
        match self {
            FailReason::RateLimited => 10,
            _ => 1,
        }
    }
}

/// Whose sign-in failed: an account, or the identifier typed (a refusal
/// before the account was looked up).
#[derive(Clone, Copy, Debug)]
pub(crate) enum FailedFor<'a> {
    Did(&'a str),
    Identifier(&'a str),
}

/// Per node: the last write per account and reason, and the attempts since
/// that weren't written (added to the next one).
static GATE: LazyLock<parking_lot::Mutex<HashMap<String, (u64, u32)>>> = LazyLock::new(Default::default);
const GATE_MAX: usize = 10_000;

/// None: a write for this key went out under `secs` ago (the attempt is
/// counted for the next). Some(n): write, standing for n + 1 attempts.
fn gate(key: String, now: u64, secs: u64) -> Option<u32> {
    let mut g = GATE.lock();
    if g.len() >= GATE_MAX {
        g.retain(|_, (t, _)| now.saturating_sub(*t) < 10);
        if g.len() >= GATE_MAX {
            g.clear();
        }
    }
    let e = g.entry(key).or_insert((0, 0));
    if e.0 != 0 && now.saturating_sub(e.0) < secs {
        e.1 = e.1.saturating_add(1);
        return None;
    }
    let skipped = e.1;
    *e = (now, 0);
    Some(skipped)
}

/// Records a refused sign-in for the console (`getAccountSecurity`). Never
/// fails the request; a successful sign-in never reaches here.
pub(crate) async fn failed(app: &App, who: FailedFor<'_>, method: &str, reason: FailReason, ctx: &Ctx<'_>) {
    let now = now_secs();
    let key = match who {
        FailedFor::Did(d) => format!("{d}\0{}", reason.name()),
        FailedFor::Identifier(i) => format!("@{i}\0{}", reason.name()),
    };
    let Some(skipped) = gate(key, now, reason.gate_secs()) else { return };
    let did = match who {
        FailedFor::Did(d) => d.to_string(),
        FailedFor::Identifier(i) => match super::server::login_account(app, i).await {
            Ok(Some(a)) => a.did,
            _ => return,
        },
    };
    let f = Failure {
        at: now,
        last_at: now,
        count: skipped.saturating_add(1),
        method: method.into(),
        reason: reason.name().into(),
        ip: ctx.ip.map(|i| i.to_string()),
        user_agent: ctx.user_agent.map(String::from),
    };
    if let Err(e) = write_failure(app, &did, f, now).await {
        tracing::debug!(%did, error = %e.message, "failed sign-in not recorded");
    }
}

async fn write_failure(app: &App, did: &str, f: Failure, now: u64) -> XResult<()> {
    for _ in 0..CAS_ROUNDS {
        let raw = app.get_private(did, FAILED).await?;
        let mut log: Failures =
            raw.as_deref().map(serde_json::from_slice).transpose().unwrap_or_default().unwrap_or_default();
        merge_failure(&mut log, f.clone(), now);
        let ops = vec![Op::put(FAILED, Some(json_bytes(&log)))];
        if app.private_cas(did, vec![Cond::eq(FAILED, raw)], ops).await?.applied {
            return Ok(());
        }
    }
    Err(super::server::cas_conflict())
}

fn merge_failure(log: &mut Failures, f: Failure, now: u64) {
    log.entries.retain(|x| now.saturating_sub(x.last_at) <= LOG_MAX_AGE);
    if let Some(last) = log.entries.last_mut().filter(|x| {
        x.method == f.method
            && x.reason == f.reason
            && x.ip == f.ip
            && f.at.saturating_sub(x.last_at) <= FAILED_MERGE_SECS
    }) {
        last.last_at = f.at;
        last.count = last.count.saturating_add(f.count);
        last.user_agent = f.user_agent;
        return;
    }
    log.entries.push(f);
    if log.entries.len() > FAILED_MAX {
        log.entries.drain(..log.entries.len() - FAILED_MAX);
    }
}

/// Golden fixtures (`private/sign_in_failures.json`).
pub(super) fn failure_fixture_rows(did: &str) -> Vec<super::private_rows::PrivateRow> {
    let log = Failures {
        entries: vec![Failure {
            at: 1_790_000_000,
            last_at: 1_790_000_060,
            count: 3,
            method: "password".into(),
            reason: "wrong_password".into(),
            ip: Some("203.0.113.7".into()),
            user_agent: Some("Mozilla/5.0".into()),
        }],
    };
    vec![(did.into(), FAILED.into(), to_json_bytes(&log))]
}

/// Golden fixtures (`super::private_rows`).
pub(super) fn fixture_rows(did: &str) -> Vec<super::private_rows::PrivateRow> {
    let prefs = Prefs {
        oauth_only: true,
        block_app_passwords: true,
        mute_password_alerts: true,
        mute_app_password_alerts: true,
    };
    let log = Log {
        entries: vec![Entry {
            id: "0011223344556677".into(),
            at: 1_790_000_000,
            method: "oauth".into(),
            app_password: Some("phone".into()),
            client_id: Some("https://app.example/client-metadata.json".into()),
            device: "b:00112233445566778899aabbccddeeff".into(),
            user_agent: Some("Mozilla/5.0".into()),
            ip: Some("203.0.113.7".into()),
            factor: Some("totp".into()),
            new_device: true,
            alerted: true,
        }],
        known: vec![Known { device: "b:00112233445566778899aabbccddeeff".into(), last: 1_790_000_000 }],
        alert_day: 20_717,
        alerts: 1,
    };
    let trust = Trust {
        created_at: 1_790_000_000,
        last_used_at: 1_790_000_100,
        expires_at: 1_792_592_000,
        epoch: "00ff".into(),
        factors: "aabb".into(),
        user_agent: Some("Mozilla/5.0".into()),
        ip: Some("203.0.113.7".into()),
    };
    vec![
        (did.into(), PREFS.into(), to_json_bytes(&prefs)),
        (did.into(), LOG.into(), to_json_bytes(&log)),
        (did.into(), format!("{TRUST}00112233445566778899aabbccddeeff"), to_json_bytes(&trust)),
    ]
}

pub(super) fn check_row(routing: &str, name: &str, val: &[u8]) -> Option<anyhow::Result<&'static str>> {
    use super::private_rows::typed_row;
    if !routing.starts_with("did:") {
        return None;
    }
    Some(match name {
        PREFS => typed_row::<Prefs>("sign-in prefs", val),
        LOG => typed_row::<Log>("sign-in log", val),
        FAILED => typed_row::<Failures>("failed sign-ins", val),
        n if n.starts_with(TRUST) => typed_row::<Trust>("trusted browser", val),
        _ => return None,
    })
}

// ---------------------------------------------------------------- XRPC

pub fn routes() -> Router<Arc<App>> {
    Router::new()
        .route("/xrpc/vlpds.server.getSignInSecurity", get(get_sign_in_security))
        .route("/xrpc/vlpds.server.updateSignInSecurity", post(update_sign_in_security))
        .route("/xrpc/vlpds.server.revokeTrustedBrowser", post(revoke_trusted_browser))
}

fn rfc3339(secs: u64) -> String {
    chrono::DateTime::from_timestamp(secs as i64, 0)
        .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
        .unwrap_or_default()
}

/// Full access only: it shows addresses, and changes how the account signs in.
fn owner_did(creds: &Credentials) -> XResult<String> {
    super::server::full_access(creds)
}

async fn get_sign_in_security(State(app): AppState, Auth(creds): Auth, headers: HeaderMap) -> XResult<Json<J>> {
    let did = owner_did(&creds)?;
    let acct = app.account(&did).await?;
    let p = prefs(&app, &did).await?;
    let epoch = super::auth_epoch(&app, &did).await?;
    let fac = factors(&app, &acct).await?;
    let now = now_secs();
    let current = super::oauth::device_cookie_id(&headers).map(|id| device_hash(&id));
    let mut browsers: Vec<J> = super::internal::scan_private_anywhere(&app, &did, TRUST)
        .await?
        .into_iter()
        .filter_map(|(name, v)| {
            let t: Trust = serde_json::from_slice(&v).ok()?;
            if now >= t.expires_at || t.epoch != epoch || t.factors != fac {
                return None;
            }
            let id = name.strip_prefix(TRUST)?.to_string();
            Some(json!({
                "id": id,
                "device": describe_user_agent(t.user_agent.as_deref()),
                "userAgent": t.user_agent,
                "ip": t.ip,
                "createdAt": rfc3339(t.created_at),
                "lastUsedAt": rfc3339(t.last_used_at),
                "expiresAt": rfc3339(t.expires_at),
                "current": current.as_deref() == Some(id.as_str()),
            }))
        })
        .collect();
    browsers.sort_by(|a, b| b["lastUsedAt"].as_str().cmp(&a["lastUsedAt"].as_str()));
    let log: Log = get_json(&app, &did, LOG).await?.unwrap_or_default();
    let recent: Vec<J> = log
        .entries
        .iter()
        .rev()
        .filter(|e| now.saturating_sub(e.at) <= LOG_MAX_AGE)
        .map(|e| {
            json!({
                "at": rfc3339(e.at),
                "method": e.method,
                "appPassword": e.app_password,
                "clientId": e.client_id,
                "device": describe_user_agent(e.user_agent.as_deref()),
                "userAgent": e.user_agent,
                "ip": e.ip,
                "factor": e.factor,
                "newDevice": e.new_device,
                "alerted": e.alerted,
            })
        })
        .collect();
    Ok(Json(json!({
        "oauthOnly": p.oauth_only,
        "blockAppPasswords": p.block_app_passwords,
        "alerts": {"password": !p.mute_password_alerts, "appPassword": !p.mute_app_password_alerts},
        "alertsPerDay": ALERTS_PER_DAY,
        "secondFactor": factor_enabled(&app, &acct).await?,
        "trustDays": trust_days(&app),
        "trustedBrowsers": browsers,
        "recentSignIns": recent,
    })))
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct AlertsIn {
    password: Option<bool>,
    app_password: Option<bool>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateIn {
    oauth_only: Option<bool>,
    block_app_passwords: Option<bool>,
    #[serde(default)]
    alerts: AlertsIn,
}

async fn update_sign_in_security(
    State(app): AppState,
    Auth(creds): Auth,
    Json(inp): Json<UpdateIn>,
) -> XResult<StatusCode> {
    let did = owner_did(&creds)?;
    let acct = app.account(&did).await?;
    for _ in 0..CAS_ROUNDS {
        let raw = app.get_private(&did, PREFS).await?;
        let mut p: Prefs =
            raw.as_deref().map(serde_json::from_slice).transpose().map_err(XrpcError::from_err)?.unwrap_or_default();
        if inp.oauth_only == Some(true) && !p.oauth_only && !factor_enabled(&app, &acct).await? {
            return Err(XrpcError::bad(
                "InvalidRequest",
                "Turn on two-factor sign-in before requiring OAuth: without it the switch doesn't protect anything",
            ));
        }
        let before = p.clone();
        if let Some(v) = inp.oauth_only {
            p.oauth_only = v;
        }
        if let Some(v) = inp.block_app_passwords {
            p.block_app_passwords = v;
        }
        if let Some(v) = inp.alerts.password {
            p.mute_password_alerts = !v;
        }
        if let Some(v) = inp.alerts.app_password {
            p.mute_app_password_alerts = !v;
        }
        let val = (p != Prefs::default()).then(|| json_bytes(&p));
        if app.private_cas(&did, vec![Cond::eq(PREFS, raw)], vec![Op::put(PREFS, val)]).await?.applied {
            count_settings(&before, &p);
            return Ok(StatusCode::OK);
        }
    }
    Err(super::server::cas_conflict())
}

/// `vlpds_sign_in_settings_total`: the settings that changed, and to what.
fn count_settings(before: &Prefs, after: &Prefs) {
    for (setting, was, now) in [
        ("oauth_only", before.oauth_only, after.oauth_only),
        ("block_app_passwords", before.block_app_passwords, after.block_app_passwords),
        ("password_alerts", !before.mute_password_alerts, !after.mute_password_alerts),
        ("app_password_alerts", !before.mute_app_password_alerts, !after.mute_app_password_alerts),
    ] {
        if was != now {
            crate::metrics::SIGN_IN_SETTINGS.with_label_values(&[setting, if now { "on" } else { "off" }]).inc();
        }
    }
}

#[derive(Deserialize)]
struct RevokeIn {
    id: Option<String>,
    #[serde(default)]
    all: bool,
}

async fn revoke_trusted_browser(
    State(app): AppState,
    Auth(creds): Auth,
    Json(inp): Json<RevokeIn>,
) -> XResult<StatusCode> {
    let did = owner_did(&creds)?;
    let op = match (inp.all, inp.id.as_deref()) {
        (true, _) => Op::DeletePrefix { prefix: TRUST.into() },
        (false, Some(id)) if id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit()) => {
            Op::put(format!("{TRUST}{id}"), None)
        }
        _ => return Err(XrpcError::bad("InvalidRequest", "id (a trusted browser's) or all: true is required")),
    };
    app.private_cas(&did, Vec::new(), vec![op]).await?;
    crate::metrics::TRUSTED_BROWSERS.with_label_values(&["revoked"]).inc();
    Ok(StatusCode::OK)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(device: &str, factor: Option<&str>) -> Entry {
        Entry {
            id: hex::encode(rand::random::<[u8; 8]>()),
            device: device.into(),
            factor: factor.map(String::from),
            ..Default::default()
        }
    }

    #[test]
    fn alerts_once_per_new_device_within_the_daily_cap() {
        let mut log = Log::default();
        let day = 20_000 * 86_400;
        // the baseline sign-in mails nothing
        assert_eq!(apply(&mut log, &mut entry("b:1", None), day, true, false, true), Some("baseline"));
        assert_eq!(apply(&mut log, &mut entry("b:1", None), day + 1, false, false, true), None);
        assert_eq!(apply(&mut log, &mut entry("b:2", None), day + 2, false, false, true), Some(MAILED));
        assert_eq!(apply(&mut log, &mut entry("b:2", None), day + 3, false, false, true), None);
        // muted, no address, or right after an emailed code
        assert_eq!(apply(&mut log, &mut entry("b:3", None), day + 4, false, true, true), Some("muted"));
        assert_eq!(apply(&mut log, &mut entry("b:4", None), day + 5, false, false, false), Some("no_email"));
        assert_eq!(apply(&mut log, &mut entry("b:5", Some("email")), day + 6, false, false, true), Some("email_code"));
        assert_eq!(apply(&mut log, &mut entry("b:6", None), day + 7, false, false, true), Some(MAILED));
        assert_eq!(apply(&mut log, &mut entry("b:7", None), day + 8, false, false, true), Some(MAILED));
        assert_eq!(log.alerts, ALERTS_PER_DAY);
        assert_eq!(apply(&mut log, &mut entry("b:8", None), day + 9, false, false, true), Some("account_limit"));
        // a new UTC day starts a new count
        assert_eq!(apply(&mut log, &mut entry("b:9", None), day + 86_400, false, false, true), Some(MAILED));
        assert_eq!(log.alerts, 1);
    }

    #[test]
    fn retention_is_bounded() {
        let mut log = Log::default();
        let apply = |log: &mut Log, e: &mut Entry, now: u64, first, muted, email| {
            e.at = now;
            apply(log, e, now, first, muted, email)
        };
        let t0 = 1_000_000_000;
        for i in 0..(LOG_MAX as u64 + 20) {
            apply(&mut log, &mut entry(&format!("b:{i}"), None), t0 + i, false, true, true);
        }
        assert_eq!(log.entries.len(), LOG_MAX);
        assert_eq!(log.known.len(), LOG_MAX + 20);
        assert_eq!(log.entries.last().unwrap().device, format!("b:{}", LOG_MAX + 19));
        apply(&mut log, &mut entry("b:new", None), t0 + LOG_MAX_AGE + 1_000, false, true, true);
        assert_eq!(log.entries.len(), 1);
        for i in 0..(KNOWN_MAX + 10) {
            apply(&mut log, &mut entry(&format!("k:{i}"), None), t0 + LOG_MAX_AGE + 2_000, false, true, true);
        }
        assert_eq!(log.known.len(), KNOWN_MAX);
        // a device unseen for the known window is new again
        let mut e = entry(&format!("k:{}", KNOWN_MAX + 9), None);
        apply(&mut log, &mut e, t0 + LOG_MAX_AGE + 2_000 + KNOWN_MAX_AGE + 1, false, true, true);
        assert!(e.new_device);
    }

    #[test]
    fn device_keys() {
        let a = Ctx { ip: Some("203.0.113.7".parse().unwrap()), user_agent: Some("Bluesky/1.0"), device_id: None };
        let b = Ctx { ip: Some("203.0.113.8".parse().unwrap()), ..a };
        assert_ne!(a.device_key(), b.device_key());
        let c = Ctx { device_id: Some("dev-x"), ..a };
        let d = Ctx { device_id: Some("dev-x"), ..b };
        assert_eq!(c.device_key(), d.device_key());
        assert!(c.device_key().starts_with("b:"));
    }

    #[test]
    fn describes_user_agents() {
        let mac_ff = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.5; rv:128.0) Gecko/20100101 Firefox/128.0";
        assert_eq!(describe_user_agent(Some(mac_ff)), "Firefox on macOS");
        let iphone = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1";
        assert_eq!(describe_user_agent(Some(iphone)), "Safari on iPhone");
        let win_chrome = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36";
        assert_eq!(describe_user_agent(Some(win_chrome)), "Chrome on Windows");
        let edge =
            "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36 Edg/126.0";
        assert_eq!(describe_user_agent(Some(edge)), "Edge on Windows");
        assert_eq!(describe_user_agent(Some("Bluesky/1.92 (Android 14)")), "Bluesky/1.92 on Android");
        assert_eq!(describe_user_agent(Some("curl/8.6.0")), "curl/8.6.0");
        assert_eq!(describe_user_agent(None), "Unknown device");
    }
}
