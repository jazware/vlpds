//! What the strong second factors (TOTP and passkeys) share: one set of 10
//! recovery codes and the wrong-code lockout, in the `p/{did}\0mfa` row.
//!
//! The codes are 80 bits and stored as SHA-256 like app passwords, so
//! checking one needs neither the TOTP secret nor the key service. They're
//! issued when the first strong factor goes on and dropped when the last
//! one goes off. Every change is a compare-and-set at the account's owner,
//! often together with the factor's own row, so N nodes don't get N times
//! the guesses and a code is spent once.

use super::cas::{Cond, Op};
use super::server::to_json_bytes;
use super::*;
use sha2::{Digest, Sha256};

pub(super) const ROW: &str = "mfa";
/// [`Mfa`]'s lockout: TOTP codes and recovery codes.
pub const FACTOR_LOCK: &str = "second_factor";
/// The email sign-in code's own lockout (`email2fa`).
pub const EMAIL_LOCK: &str = "email_code";

/// The lockout index (`L/{did}\0{factor}` -> locked until, u64 BE seconds)
/// that `vlpds.admin.listLockouts` scans: the index entry of a lockout row
/// (`mfa`, the email code's) written in the same batch as the row, by the
/// conditional write at the account's owner (`cas::private_cas_local`). Set
/// while the row is locked, deleted when it's written unlocked or deleted.
/// An entry that outlived its row (expired, or the account went) is
/// dropped when the listing finds it so.
pub(super) fn lockout_index(routing: &str, name: &str, val: Option<&Bytes>) -> Option<vlsync_store::segment::Mutation> {
    let factor = match name {
        ROW => FACTOR_LOCK,
        super::email2fa::LOCKOUT_NAME => EMAIL_LOCK,
        _ => return None,
    };
    let until = match (factor, val) {
        (_, None) => 0,
        (FACTOR_LOCK, Some(v)) => serde_json::from_slice::<Mfa>(v).map_or(0, |m| m.locked_until),
        (_, Some(v)) => serde_json::from_slice::<super::email2fa::Lockout>(v).map_or(0, |l| l.locked_until),
    };
    let key = state::lockout_key(routing, factor).into();
    let locked = until > crate::totp::now_secs();
    Some(vlsync_store::segment::Mutation { key, val: locked.then(|| Bytes::copy_from_slice(&until.to_be_bytes())) })
}

/// The factor named in a lockout index key's body, after the DID.
pub fn lockout_factor(f: &[u8]) -> Option<&'static str> {
    [FACTOR_LOCK, EMAIL_LOCK].into_iter().find(|x| x.as_bytes() == f)
}
pub const RECOVERY_CODES: usize = 10;
const CAS_ROUNDS: usize = 8;

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Mfa {
    /// SHA-256 (hex) of each unused code.
    #[serde(default)]
    pub recovery: Vec<String>,
    /// Unix seconds; 0 when no set was ever issued.
    #[serde(default)]
    pub issued_at: u64,
    /// Wrong codes in a row, across TOTP and recovery codes.
    #[serde(default)]
    pub failures: u32,
    /// Unix seconds.
    #[serde(default)]
    pub locked_until: u64,
}

impl Mfa {
    /// Ten fresh codes in place of any left; returns them in the clear.
    pub fn issue(&mut self, did: &str, now: u64) -> Vec<String> {
        let codes: Vec<String> = (0..RECOVERY_CODES).map(|_| new_code()).collect();
        self.recovery = codes.iter().map(|c| hash_code(did, c)).collect();
        self.issued_at = now;
        codes
    }

    /// Spends `code` if it's an unused one.
    pub fn take(&mut self, did: &str, code: &str) -> bool {
        let h = hash_code(did, code);
        match self.recovery.iter().position(|r| crate::auth::ct_eq(r.as_bytes(), h.as_bytes())) {
            Some(i) => {
                self.recovery.remove(i);
                true
            }
            None => false,
        }
    }

    pub fn is_empty(&self) -> bool {
        *self == Mfa::default()
    }
}

/// `xxxx-xxxx-xxxx-xxxx`, base32: 80 bits.
fn new_code() -> String {
    let s = vlatproto::cid::base32_encode(&rand::random::<[u8; 10]>());
    format!("{}-{}-{}-{}", &s[..4], &s[4..8], &s[8..12], &s[12..16])
}

/// Case, spaces and dashes don't matter; salted by the DID, so one hash
/// table doesn't serve every account.
pub fn hash_code(did: &str, code: &str) -> String {
    let norm: String = code.chars().filter(|c| c.is_ascii_alphanumeric()).collect::<String>().to_ascii_lowercase();
    hex::encode(Sha256::digest(format!("vlpds-recovery:{did}:{norm}").as_bytes()))
}

pub async fn load_raw(app: &App, did: &str) -> XResult<(Mfa, Option<Bytes>)> {
    match app.get_private(did, ROW).await? {
        Some(v) => Ok((serde_json::from_slice(&v).map_err(XrpcError::from_err)?, Some(v))),
        None => Ok((Mfa::default(), None)),
    }
}

pub async fn load(app: &App, did: &str) -> XResult<Mfa> {
    Ok(load_raw(app, did).await?.0)
}

/// The condition and write for this row inside a larger compare-and-set.
pub fn cas_parts(m: &Mfa, read: Option<Bytes>) -> (Cond, Op) {
    let val = (!m.is_empty()).then(|| Bytes::from(to_json_bytes(m)));
    (Cond::eq(ROW, read), Op::put(ROW, val))
}

/// Applies the outcome of one guess: a success clears the count, a failure
/// adds to it and may lock. `Ok` passes through; a failure becomes 429
/// while locked.
pub fn settle(m: &mut Mfa, r: XResult<()>, now: u64) -> XResult<()> {
    match r {
        Ok(()) => {
            m.failures = 0;
            Ok(())
        }
        Err(e) if e.status.is_server_error() => Err(e),
        Err(e) => {
            crate::totp::record_failure_in(&mut m.failures, &mut m.locked_until, now);
            Err(if now < m.locked_until { crate::totp::locked_out() } else { e })
        }
    }
}

fn invalid_code() -> XrpcError {
    XrpcError::bad("InvalidToken", "Token is invalid")
}

/// A recovery code standing in for a passkey (an account without TOTP):
/// spent once, under the shared lockout.
pub async fn use_recovery_code(app: &App, did: &str, code: &str) -> XResult<()> {
    let _g = crate::totp::lock(did).await;
    for _ in 0..CAS_ROUNDS {
        let (mut m, raw) = load_raw(app, did).await?;
        let now = crate::totp::now_secs();
        if now < m.locked_until {
            return Err(crate::totp::locked_out());
        }
        let r = if m.take(did, code) { Ok(()) } else { Err(invalid_code()) };
        let r = settle(&mut m, r, now);
        let (c, op) = cas_parts(&m, raw);
        if app.private_cas(did, vec![c], vec![op]).await?.applied {
            return r;
        }
    }
    Err(crate::totp::conflict())
}

/// Codes left, for the Security page.
pub async fn remaining(app: &App, did: &str) -> XResult<usize> {
    Ok(load(app, did).await?.recovery.len())
}

#[derive(Deserialize)]
struct RegenerateIn {
    #[serde(default)]
    password: String,
}

pub fn routes() -> Router<Arc<App>> {
    Router::new().route("/xrpc/vlpds.server.regenerateRecoveryCodes", post(regenerate))
}

/// A new set in place of the old, behind the password; only while a strong
/// factor is on.
async fn regenerate(State(app): AppState, Auth(creds): Auth, Json(inp): Json<RegenerateIn>) -> XResult<Json<J>> {
    let did = super::server::full_access(&creds)?;
    let acct = super::passkeys::check_password(&app, &did, &inp.password).await?;
    if !crate::totp::enabled_for(&app, &acct).await? && !super::passkeys::has_any(&app, &did).await? {
        return Err(XrpcError::bad("InvalidRequest", "Recovery codes come with an authenticator app or a passkey"));
    }
    let _g = crate::totp::lock(&did).await;
    for _ in 0..CAS_ROUNDS {
        let (mut m, raw) = load_raw(&app, &did).await?;
        let codes = m.issue(&did, crate::totp::now_secs());
        let (c, op) = cas_parts(&m, raw);
        if app.private_cas(&did, vec![c], vec![op]).await?.applied {
            super::passkeys::security_mail(
                &app,
                &did,
                "Your recovery codes were replaced with a new set. The old ones no longer work.",
            )
            .await;
            return Ok(Json(json!({"recoveryCodes": codes})));
        }
    }
    Err(crate::totp::conflict())
}

/// Golden fixtures (`super::private_rows`).
pub(super) fn fixture_rows(did: &str) -> Vec<super::private_rows::PrivateRow> {
    let m = Mfa {
        recovery: vec!["0f".repeat(32), "1e".repeat(32)],
        issued_at: 1_790_000_000,
        failures: 2,
        locked_until: 1_790_000_300,
    };
    vec![(did.into(), ROW.into(), to_json_bytes(&m))]
}

pub(super) fn check_row(routing: &str, name: &str, val: &[u8]) -> Option<anyhow::Result<&'static str>> {
    (routing.starts_with("did:") && name == ROW).then(|| super::private_rows::typed_row::<Mfa>("mfa", val))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_80_bits_hashed_and_spent_once() {
        let did = "did:plc:abcdefghijklmnopqrstuvwx";
        let mut m = Mfa::default();
        let codes = m.issue(did, 1);
        assert_eq!(codes.len(), RECOVERY_CODES);
        assert_eq!(codes[0].len(), 19);
        assert!(codes.iter().all(|c| !m.recovery.contains(c)), "stored hashed");
        assert_ne!(hash_code(did, &codes[0]), hash_code("did:plc:other", &codes[0]), "salted by the DID");
        assert!(m.take(did, &codes[3].to_uppercase().replace('-', " ")));
        assert!(!m.take(did, &codes[3]), "once");
        assert_eq!(m.recovery.len(), 9);
        assert!(!m.take("did:plc:other", &codes[4]));
        // a new set replaces the old
        let fresh = m.issue(did, 2);
        assert!(!m.take(did, &codes[4]));
        assert!(m.take(did, &fresh[0]));
    }

    #[test]
    fn settle_locks_after_repeated_failures() {
        let mut m = Mfa::default();
        for i in 0..crate::totp::MAX_FAILURES {
            let e = settle(&mut m, Err(invalid_code()), 1000).unwrap_err();
            assert_eq!(crate::totp::is_lockout(&e), i == crate::totp::MAX_FAILURES - 1);
        }
        assert!(m.locked_until > 1000);
        assert!(settle(&mut m, Ok(()), 5000).is_ok());
        assert_eq!(m.failures, 0);
    }
}
