//! Email second factor: the reference PDS's `emailAuthFactor`, plus a
//! wrong-code lockout on TOTP's schedule (DESIGN.md "Email second factor").
//! When TOTP or a passkey is also set up, the email code isn't offered: the
//! weaker factor never stands in for a stronger one.

use super::server::{
    assert_email_token, create_email_token, delete_email_tokens, deliver, email_token_age_ms, invalid_request,
    mail_permit, to_json_bytes,
};
use super::*;

/// RFC 3339; absent = off.
pub(super) const FLAG: &str = "emailAuthFactorAt";
pub(super) const PURPOSE: &str = "auth_factor";
/// A sign-in without a code mails none while the last one is younger:
/// retries, double submits and a password-holding attacker can't flood
/// the inbox, and the code already sent still works.
pub(super) const RESEND_AFTER_MS: u64 = 60_000;
pub(super) const LOCKOUT_NAME: &str = "eotp_lock";

pub(super) fn enabled(a: &Account) -> bool {
    a.extra.get(FLAG).is_some_and(|v| v.is_string())
}

#[derive(Default, serde::Serialize, serde::Deserialize)]
pub(super) struct Lockout {
    pub failures: u32,
    pub locked_until: u64,
}

/// Golden fixtures (`super::private_rows`).
pub(super) fn fixture_rows(did: &str) -> Vec<super::private_rows::PrivateRow> {
    vec![(
        did.into(),
        LOCKOUT_NAME.into(),
        super::private_rows::enc(&Lockout { failures: 3, locked_until: 1_790_000_300 }),
    )]
}

pub(super) fn check_row(_routing: &str, name: &str, val: &[u8]) -> Option<anyhow::Result<&'static str>> {
    (name == LOCKOUT_NAME).then(|| super::private_rows::typed_row::<Lockout>("email 2fa lockout", val))
}

/// What a failed second-factor check asked for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Factor {
    Totp,
    /// The account has passkeys and no TOTP: an assertion (checked by the
    /// caller), or a recovery code.
    Passkey,
    /// A code was (or would have been) mailed; `hint` is the obfuscated
    /// address, as the reference shows it (`a***e@e***m`).
    Email {
        hint: String,
    },
}

pub(super) struct FactorErr {
    pub err: XrpcError,
    pub factor: Factor,
}

impl From<FactorErr> for XrpcError {
    fn from(e: FactorErr) -> XrpcError {
        e.err
    }
}

/// The reference's `obfuscateEmail`.
pub(super) fn obfuscate_email(email: &str) -> String {
    fn word(w: &str) -> String {
        let first = w.chars().next().map(String::from).unwrap_or_default();
        let last = w.chars().last().map(String::from).unwrap_or_default();
        format!("{first}***{last}")
    }
    let (local, domain) = email.split_once('@').unwrap_or((email, ""));
    format!("{}@{}", word(local), word(domain))
}

fn factor_required() -> XrpcError {
    XrpcError {
        status: StatusCode::UNAUTHORIZED,
        error: "AuthFactorTokenRequired".into(),
        message: "A sign in code has been sent to your email address".into(),
    }
}

/// TOTP when enabled; else, with passkeys, a recovery code (the caller
/// checks a passkey itself); else the email factor when enabled. App
/// passwords bypass all of them. A code sent anyway is still checked as an
/// email sign-in code, as the reference's `login()` does, and counts
/// against the lockout like any wrong code.
pub(super) async fn check_second_factor(
    app: &App,
    acct: &Account,
    code: Option<&str>,
    app_password: bool,
    passkeys: bool,
) -> Result<(), FactorErr> {
    let code = code.map(str::trim).filter(|c| !c.is_empty());
    let hint = || Factor::Email { hint: acct.email.as_deref().map(obfuscate_email).unwrap_or_default() };
    if app_password {
        return match code {
            Some(c) => {
                check_email_code(app, acct, None, Some(c)).await.map_err(|err| FactorErr { err, factor: hint() })
            }
            None => Ok(()),
        };
    }
    let totp = crate::totp::enabled_for(app, acct).await.map_err(|err| FactorErr { err, factor: Factor::Totp })?;
    if totp {
        return crate::totp::check_second_factor(app, acct, code)
            .await
            .map_err(|err| FactorErr { err, factor: Factor::Totp });
    }
    if passkeys {
        let err = match code {
            None => XrpcError {
                status: StatusCode::UNAUTHORIZED,
                error: "AuthFactorTokenRequired".into(),
                message: "Use your passkey, or a recovery code".into(),
            },
            Some(c) => match super::mfa::use_recovery_code(app, &acct.did, c).await {
                Ok(()) => return Ok(()),
                Err(e) => e,
            },
        };
        return Err(FactorErr { err, factor: Factor::Passkey });
    }
    match (&acct.email, enabled(acct), code) {
        (Some(email), true, _) => {
            check_email_code(app, acct, Some(email), code).await.map_err(|err| FactorErr { err, factor: hint() })
        }
        (_, _, Some(c)) => {
            check_email_code(app, acct, None, Some(c)).await.map_err(|err| FactorErr { err, factor: hint() })
        }
        _ => Ok(()),
    }
}

/// Checks `code` under the lockout, or mails a fresh one to `email`.
async fn check_email_code(app: &App, acct: &Account, email: Option<&str>, code: Option<&str>) -> XResult<()> {
    use super::cas::{Cond, Op};
    let did = acct.did.as_str();
    // across nodes every update is conditional on the rows read, redone
    // otherwise: no lost failure, and a code is accepted once
    let _g = crate::totp::lock(did).await;
    let token_name = format!("etok/{PURPOSE}");
    for _ in 0..crate::totp::CAS_ROUNDS {
        let lk_raw = app.get_private(did, LOCKOUT_NAME).await?;
        let mut lk: Lockout =
            lk_raw.as_deref().map(serde_json::from_slice).transpose().map_err(XrpcError::from_err)?.unwrap_or_default();
        let now = crate::totp::now_secs();
        if now < lk.locked_until {
            return Err(crate::totp::locked_out());
        }
        let Some(code) = code else {
            let Some(email) = email else { return Ok(()) };
            if email_token_age_ms(app, did, PURPOSE).await?.is_some_and(|age| age < RESEND_AFTER_MS) {
                crate::mail::MAIL_SUPPRESSED.with_label_values(&[PURPOSE, "dedup"]).inc();
                return Err(factor_required());
            }
            let permit = mail_permit(app, Some(did), email, PURPOSE, true).await?;
            let token = create_email_token(app, did, PURPOSE).await?;
            deliver(
                app,
                permit,
                email,
                crate::mail::Email::SignInAuthFactor { handle: Some(&acct.handle), token: &token },
            );
            return Err(factor_required());
        };
        let token_raw = app.get_private(did, &token_name).await?;
        let (r, ops) = match assert_email_token(app, did, PURPOSE, code).await {
            // consumed with the counter reset, in one write
            Ok(()) => (Ok(()), vec![Op::put(&token_name, None), Op::put(LOCKOUT_NAME, None)]),
            // an expired code was right once: not a guess
            Err(e) if e.error != "InvalidToken" => return Err(e),
            Err(e) => {
                crate::totp::record_failure_in(&mut lk.failures, &mut lk.locked_until, now);

                let e = if now < lk.locked_until { crate::totp::locked_out() } else { e };
                (Err(e), vec![Op::put(LOCKOUT_NAME, Some(Bytes::from(to_json_bytes(&lk))))])
            }
        };
        let conds = vec![Cond::eq(LOCKOUT_NAME, lk_raw), Cond::eq(&token_name, token_raw)];
        if app.private_cas(did, conds, ops).await?.applied {
            return r;
        }
    }
    Err(crate::totp::conflict())
}

/// No token needed: enabling only adds protection.
pub(super) async fn enable(app: &App, did: &str) -> XResult<()> {
    app.mutate_account(did, false, false, false, |a| {
        if enabled(a) {
            return Ok(false);
        }
        if a.email.is_none() || !a.email_confirmed {
            return Err(invalid_request(
                "A confirmed email address is required to enable email-based two-factor authentication",
            ));
        }
        super::server::set_extra(a, FLAG, json!(crate::events::now_rfc3339()));
        Ok(true)
    })
    .await?;
    Ok(())
}

/// Two-phase, so a hijacked session can't silently drop the factor: without
/// a token, mails an `update_email` code (what the Bluesky app sends back)
/// and fails `TokenRequired`.
pub(super) async fn disable(app: &App, acct: &Account, token: Option<&str>) -> XResult<()> {
    if !enabled(acct) {
        return Ok(());
    }
    let did = acct.did.as_str();
    let email = acct.email.clone().ok_or_else(|| XrpcError::internal("account has no email address"))?;
    let Some(token) = token.map(str::trim).filter(|t| !t.is_empty()) else {
        {
            use crate::ratelimit::*;
            check(&[&REQUEST_EMAIL_UPDATE_DAY, &REQUEST_EMAIL_UPDATE_HOUR], did, 1)?;
        }
        let permit = mail_permit(app, Some(did), &email, "update_email", true).await?;
        let otp = create_email_token(app, did, "update_email").await?;
        deliver(app, permit, &email, crate::mail::Email::UpdateEmail { token: &otp });
        return Err(XrpcError::bad("TokenRequired", "confirmation token required"));
    };
    assert_email_token(app, did, "update_email", token).await?;
    delete_email_tokens(app, did, &["update_email"]).await?;
    app.mutate_account(did, false, false, false, move |a| {
        // only the address the code went to (an email change clears it anyway)
        if !enabled(a) || a.email.as_deref() != Some(email.as_str()) {
            return Ok(false);
        }
        a.extra.remove(FLAG);
        Ok(true)
    })
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn obfuscates_like_the_reference() {
        assert_eq!(obfuscate_email("alice@example.com"), "a***e@e***m");
        assert_eq!(obfuscate_email("a@b.co"), "a***a@b***o");
    }
}
