//! TOTP second factor (RFC 6238, SHA-1, 6 digits, 30 s, ±1 step), for
//! password logins and the OAuth sign-in page. Recovery codes and the
//! wrong-code lockout are shared with passkeys (`xrpc::mfa`).
//!
//! Accepted codes advance `last_step`, so a code can't be replayed inside its
//! window. Guessing is bounded per account across both login paths and
//! restarts: every [`MAX_FAILURES`] wrong codes in a row lock the factor,
//! doubling per lockout. Every state change is a conditional write over
//! this row and the shared one ([`save_both`], src/xrpc/cas.rs) redone on
//! conflict, so concurrent attempts on several nodes neither lose failures
//! nor accept one code twice.

use crate::auth::ct_eq;
use crate::state::{self, Account};
use crate::xrpc::mfa::{self, Mfa};
use crate::xrpc::App;
use axum::http::StatusCode;
use bytes::Bytes;
use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use vlsync_atproto::xrpc::XrpcError;

pub const STEP_SECS: u64 = 30;
pub const DIGITS: u32 = 6;
/// Accepted clock skew, in steps, on either side of now.
pub const SKEW: u64 = 1;
pub const PRIVATE_NAME: &str = "totp";
pub const MAX_FAILURES: u32 = 5;
/// First lockout; doubles per further lockout up to [`MAX_LOCKOUT_SECS`].
pub const LOCKOUT_SECS: u64 = 5 * 60;
pub const MAX_LOCKOUT_SECS: u64 = 24 * 3600;

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct TotpState {
    /// Base32 in memory, KEK-wrapped in storage (see [`seal`]). None: disabled.
    #[serde(default)]
    pub secret: Option<String>,
    /// From setupTotp, awaiting confirmTotp.
    #[serde(default)]
    pub pending: Option<String>,
    /// Codes for steps <= this are replays.
    #[serde(default)]
    pub last_step: u64,
    #[serde(default)]
    pub enabled_at: Option<String>,
    /// The wrapped forms `load` read, by plaintext: `seal` reuses one while
    /// its secret is unchanged (no KEK call per login attempt).
    #[serde(skip)]
    sealed: Vec<(zeroize::Zeroizing<String>, String)>,
}

async fn seal(app: &App, did: &str, st: &TotpState) -> Result<TotpState, XrpcError> {
    let mut out = st.clone();
    out.sealed.clear();
    for f in [&mut out.secret, &mut out.pending] {
        if let Some(plain) = f.take() {
            let wrapped = match st.sealed.iter().find(|(p, _)| **p == plain) {
                Some((_, w)) => w.clone(),
                None => app.secrets.wrap(crate::secrets::Purpose::Totp, did, plain.as_bytes()).await?,
            };
            drop(zeroize::Zeroizing::new(plain));
            *f = Some(wrapped);
        }
    }
    Ok(out)
}

async fn unseal(app: &App, did: &str, mut st: TotpState) -> Result<TotpState, XrpcError> {
    for f in [&mut st.secret, &mut st.pending] {
        if let Some(wrapped) = f.take() {
            let u = app.secrets.unwrap(crate::secrets::Purpose::Totp, did, &wrapped).await?;
            let plain =
                String::from_utf8(u.plaintext.to_vec()).map_err(|_| XrpcError::internal("corrupt TOTP secret"))?;
            *f = Some(plain.clone());
            // a stale blob (old KEK) isn't reused: the next save rewraps it
            if !u.stale {
                st.sealed.push((zeroize::Zeroizing::new(plain), wrapped));
            }
        }
    }
    Ok(st)
}

impl TotpState {
    pub fn enabled(&self) -> bool {
        self.secret.is_some()
    }
}

/// RFC 4226.
fn hotp(secret: &[u8], counter: u64) -> u32 {
    let mut mac = Hmac::<Sha1>::new_from_slice(secret).expect("hmac accepts any key length");
    mac.update(&counter.to_be_bytes());
    let h = mac.finalize().into_bytes();
    let off = (h[h.len() - 1] & 0x0f) as usize;
    let bin =
        ((h[off] as u32 & 0x7f) << 24) | ((h[off + 1] as u32) << 16) | ((h[off + 2] as u32) << 8) | h[off + 3] as u32;
    bin % 10u32.pow(DIGITS)
}

pub fn step_at(unix_secs: u64) -> u64 {
    unix_secs / STEP_SECS
}

pub fn code_for_step(secret: &[u8], step: u64) -> String {
    format!("{:0width$}", hotp(secret, step), width = DIGITS as usize)
}

pub fn now_secs() -> u64 {
    vlsync_atproto::tid::now_micros() / 1_000_000
}

/// The matched step, if within ±SKEW of `now` and after `after_step`.
pub fn verify_code(secret: &[u8], code: &str, now: u64, after_step: u64) -> Option<u64> {
    let code = code.trim();
    if code.len() != DIGITS as usize || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let now_step = step_at(now);
    let mut found = None;
    for step in now_step.saturating_sub(SKEW)..=now_step + SKEW {
        // compare every candidate (no early exit) in constant time
        if ct_eq(code_for_step(secret, step).as_bytes(), code.as_bytes()) && step > after_step && found.is_none() {
            found = Some(step);
        }
    }
    found
}

pub fn generate_secret() -> Vec<u8> {
    rand::random::<[u8; 20]>().to_vec()
}

/// Uppercase, no padding: what authenticator apps expect.
pub fn base32_encode(b: &[u8]) -> String {
    vlsync_atproto::cid::base32_encode(b).to_ascii_uppercase()
}

pub fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let norm: String = s.chars().filter(|c| !c.is_whitespace() && *c != '=').collect::<String>().to_ascii_lowercase();
    vlsync_atproto::cid::base32_decode(&norm)
}

fn uri_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

pub fn otpauth_uri(secret_b32: &str, issuer: &str, account: &str) -> String {
    format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits={}&period={}",
        uri_encode(issuer),
        uri_encode(account),
        secret_b32,
        uri_encode(issuer),
        DIGITS,
        STEP_SECS
    )
}

pub async fn load(app: &App, did: &str) -> Result<TotpState, XrpcError> {
    Ok(load_raw(app, did).await?.0)
}

/// Also returns the stored bytes: the condition for [`save_if`].
pub async fn load_raw(app: &App, did: &str) -> Result<(TotpState, Option<Bytes>), XrpcError> {
    match app.get_private(did, PRIVATE_NAME).await? {
        Some(v) => Ok((unseal(app, did, serde_json::from_slice(&v).map_err(XrpcError::from_err)?).await?, Some(v))),
        None => Ok((TotpState::default(), None)),
    }
}

async fn stored(app: &App, did: &str, st: &TotpState) -> Result<Option<Bytes>, XrpcError> {
    if st.secret.is_none() && st.pending.is_none() {
        return Ok(None);
    }
    Ok(Some(Bytes::from(serde_json::to_vec(&seal(app, did, st).await?).map_err(XrpcError::from_err)?)))
}

/// Ok(false): the row is no longer `read` and nothing was written; reload
/// and redo.
pub async fn save_if(app: &App, did: &str, st: &TotpState, read: Option<Bytes>) -> Result<bool, XrpcError> {
    use crate::xrpc::cas::{Cond, Op};
    let val = stored(app, did, st).await?;
    let out = app.private_cas(did, vec![Cond::eq(PRIVATE_NAME, read)], vec![Op::put(PRIVATE_NAME, val)]).await?;
    Ok(out.applied)
}

/// This row and the shared `mfa` row, both read as `read` / `mread`.
pub async fn load_both(app: &App, did: &str) -> Result<(TotpState, Option<Bytes>, Mfa, Option<Bytes>), XrpcError> {
    let (st, read) = load_raw(app, did).await?;
    let (m, mread) = mfa::load_raw(app, did).await?;
    Ok((st, read, m, mread))
}

/// [`save_if`] over both rows in one write, and only while `extra` holds.
pub async fn save_both(
    app: &App,
    did: &str,
    st: &TotpState,
    read: Option<Bytes>,
    m: &Mfa,
    mread: Option<Bytes>,
    extra: Vec<crate::xrpc::cas::Cond>,
) -> Result<bool, XrpcError> {
    use crate::xrpc::cas::{Cond, Op};
    let (mc, mop) = mfa::cas_parts(m, mread);
    let val = stored(app, did, st).await?;
    let mut conds = vec![Cond::eq(PRIVATE_NAME, read), mc];
    conds.extend(extra);
    let out = app.private_cas(did, conds, vec![Op::put(PRIVATE_NAME, val), mop]).await?;
    Ok(out.applied)
}

pub const CAS_ROUNDS: usize = 8;

pub fn conflict() -> XrpcError {
    XrpcError {
        status: StatusCode::SERVICE_UNAVAILABLE,
        error: "TemporarilyUnavailable".into(),
        message: "concurrent two-factor update; retry".into(),
    }
}

/// `vlpds.admin.rewrapSecrets`. Returns whether a secret was stale, and the
/// wrapped secrets as they were found.
pub async fn rewrap(
    app: &App,
    did: &str,
    check_versions: bool,
    dry_run: bool,
) -> Result<(bool, Vec<String>), XrpcError> {
    let Some(v) = app.get_private(did, PRIVATE_NAME).await? else {
        return Ok((false, Vec::new()));
    };
    let stored: TotpState = serde_json::from_slice(&v).map_err(XrpcError::from_err)?;
    let blobs: Vec<String> = [&stored.secret, &stored.pending].into_iter().flatten().cloned().collect();
    if !check_versions && blobs.iter().all(|b| app.secrets.is_current(b)) {
        return Ok((false, blobs));
    }
    let _g = lock(did).await;
    for _ in 0..CAS_ROUNDS {
        let (st, raw) = load_raw(app, did).await?;
        // unseal memoized only the blobs that are current
        let stale = st.sealed.len() < [&st.secret, &st.pending].into_iter().flatten().count();
        if !stale || dry_run || save_if(app, did, &st, raw).await? {
            return Ok((stale, blobs));
        }
    }
    Err(conflict())
}

/// An economy only: [`save_if`] is what is correct across nodes.
static LOCKS: [tokio::sync::Mutex<()>; 32] = [const { tokio::sync::Mutex::const_new(()) }; 32];

pub async fn lock(did: &str) -> tokio::sync::MutexGuard<'static, ()> {
    LOCKS[(state::did_hash(did) % LOCKS.len() as u64) as usize].lock().await
}

fn factor_required() -> XrpcError {
    XrpcError {
        status: StatusCode::UNAUTHORIZED,
        error: "AuthFactorTokenRequired".into(),
        message: "A two-factor authentication code is required".into(),
    }
}

fn invalid_code() -> XrpcError {
    XrpcError::bad("InvalidToken", "Token is invalid")
}

pub fn locked_out() -> XrpcError {
    XrpcError {
        status: StatusCode::TOO_MANY_REQUESTS,
        error: "RateLimitExceeded".into(),
        message: "Too many invalid two-factor codes; try again later".into(),
    }
}

pub fn is_lockout(e: &XrpcError) -> bool {
    e.status == StatusCode::TOO_MANY_REQUESTS
}

/// Shared with the email factor so both bound guessing the same way.
pub fn record_failure_in(failures: &mut u32, locked_until: &mut u64, now: u64) {
    *failures = failures.saturating_add(1);
    if failures.is_multiple_of(MAX_FAILURES) {
        let n = (*failures / MAX_FAILURES - 1).min(16);
        *locked_until = now + (LOCKOUT_SECS << n).min(MAX_LOCKOUT_SECS);
    }
}

/// Most accounts never enable TOTP: their `totpEnabled` flag skips the read.
fn flagged_off(account: &Account) -> bool {
    account.extra.get("totpEnabled").and_then(|v| v.as_bool()) == Some(false)
}

pub async fn enabled_for(app: &App, account: &Account) -> Result<bool, XrpcError> {
    if flagged_off(account) {
        return Ok(false);
    }
    Ok(load(app, &account.did).await?.enabled())
}

/// `code` is a TOTP code or an unused recovery code. Caller persists.
fn consume(st: &mut TotpState, m: &mut Mfa, did: &str, code: &str, now: u64) -> Result<(), XrpcError> {
    let secret =
        st.secret.as_deref().and_then(base32_decode).ok_or_else(|| XrpcError::internal("corrupt TOTP secret"))?;
    let trimmed = code.trim();
    if trimmed.len() == DIGITS as usize && trimmed.bytes().all(|b| b.is_ascii_digit()) {
        st.last_step = verify_code(&secret, trimmed, now, st.last_step).ok_or_else(invalid_code)?;
        return Ok(());
    }
    if m.take(did, trimmed) {
        Ok(())
    } else {
        Err(invalid_code())
    }
}

/// 401 AuthFactorTokenRequired when `code` is missing, 400 InvalidToken when
/// wrong, 429 RateLimitExceeded while locked out.
pub async fn check_second_factor(app: &App, account: &Account, code: Option<&str>) -> Result<(), XrpcError> {
    if flagged_off(account) {
        return Ok(());
    }
    let did = account.did.as_str();
    let _g = lock(did).await;
    for _ in 0..CAS_ROUNDS {
        let (mut st, raw, mut m, mraw) = load_both(app, did).await?;
        if !st.enabled() {
            return Ok(());
        }
        let now = now_secs();
        if now < m.locked_until {
            return Err(locked_out());
        }
        let code = code.map(str::trim).filter(|c| !c.is_empty()).ok_or_else(factor_required)?;
        // saved even on failure: the count must survive restarts and be
        // shared by both login paths
        let r = attempt(&mut st, &mut m, did, code, now);
        crate::xrpc::cas::pause_point("totp", did).await;
        if save_both(app, did, &st, raw, &m, mraw, Vec::new()).await? {
            return r;
        }
    }
    Err(conflict())
}

/// The caller holds [`lock`] and persists both rows whatever the outcome.
pub fn attempt(st: &mut TotpState, m: &mut Mfa, did: &str, code: &str, now: u64) -> Result<(), XrpcError> {
    if now < m.locked_until {
        return Err(locked_out());
    }
    let r = consume(st, m, did, code, now);
    mfa::settle(m, r, now)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc6238_vectors() {
        // RFC 6238 appendix B (SHA-1 seed), truncated to 6 digits.
        let k = b"12345678901234567890";
        assert_eq!(code_for_step(k, step_at(59)), "287082");
        assert_eq!(code_for_step(k, step_at(1111111109)), "081804");
        assert_eq!(code_for_step(k, step_at(1234567890)), "005924");
        assert_eq!(code_for_step(k, step_at(2000000000)), "279037");
    }

    #[test]
    fn verify_window_and_replay() {
        let k = b"12345678901234567890";
        let now = 1111111109;
        let s = step_at(now);
        assert_eq!(verify_code(k, &code_for_step(k, s), now, 0), Some(s));
        assert_eq!(verify_code(k, &code_for_step(k, s - 1), now, 0), Some(s - 1));
        assert_eq!(verify_code(k, &code_for_step(k, s + 1), now, 0), Some(s + 1));
        assert_eq!(verify_code(k, &code_for_step(k, s + 2), now, 0), None);
        // replay: already accepted step s
        assert_eq!(verify_code(k, &code_for_step(k, s), now, s), None);
        assert_eq!(verify_code(k, "12345", now, 0), None);
    }

    #[test]
    fn lockout_backoff() {
        let mut m = Mfa::default();
        for _ in 0..MAX_FAILURES - 1 {
            record_failure_in(&mut m.failures, &mut m.locked_until, 1000);
        }
        assert_eq!(m.locked_until, 0, "a few wrong codes don't lock");
        record_failure_in(&mut m.failures, &mut m.locked_until, 1000);
        assert_eq!(m.locked_until, 1000 + LOCKOUT_SECS);
        for _ in 0..MAX_FAILURES {
            record_failure_in(&mut m.failures, &mut m.locked_until, 5000);
        }
        assert_eq!(m.locked_until, 5000 + 2 * LOCKOUT_SECS, "doubles");
        for _ in 0..20 * MAX_FAILURES {
            record_failure_in(&mut m.failures, &mut m.locked_until, 9000);
        }
        assert_eq!(m.locked_until, 9000 + MAX_LOCKOUT_SECS, "capped");
    }

    #[test]
    fn attempt_locks_and_resets() {
        let k = generate_secret();
        let did = "did:plc:abcdefghijklmnopqrstuvwx";
        let mut st = TotpState { secret: Some(base32_encode(&k)), ..Default::default() };
        let mut m = Mfa::default();
        let now = now_secs();
        let good = code_for_step(&k, step_at(now));
        assert!(attempt(&mut st, &mut m, did, "000000", now).is_err());
        assert!(attempt(&mut st, &mut m, did, &good, now).is_ok());
        assert_eq!(m.failures, 0, "success resets the count");
        for i in 0..MAX_FAILURES {
            let e = attempt(&mut st, &mut m, did, "000000", now).unwrap_err();
            assert_eq!(is_lockout(&e), i == MAX_FAILURES - 1);
        }
        let next = code_for_step(&k, step_at(now) + 1);
        assert!(is_lockout(&attempt(&mut st, &mut m, did, &next, now).unwrap_err()), "right code refused while locked");
        let later = now + LOCKOUT_SECS;
        let fresh = code_for_step(&k, step_at(later));
        assert!(attempt(&mut st, &mut m, did, &fresh, later).is_ok(), "accepted after the lock");
    }

    #[test]
    fn base32_roundtrip_and_recovery() {
        let sec = generate_secret();
        let enc = base32_encode(&sec);
        assert_eq!(enc.len(), 32);
        assert_eq!(base32_decode(&enc).unwrap(), sec);
        let did = "did:plc:abcdefghijklmnopqrstuvwx";
        let mut m = Mfa::default();
        let codes = m.issue(did, 1);
        let mut st = TotpState { secret: Some(enc), ..Default::default() };
        assert!(consume(&mut st, &mut m, did, &codes[3].to_uppercase(), now_secs()).is_ok());
        assert_eq!(m.recovery.len(), 9);
        assert!(consume(&mut st, &mut m, did, &codes[3], now_secs()).is_err());
    }
}
