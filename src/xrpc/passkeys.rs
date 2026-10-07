//! Passkeys (docs/oauth-2fa.md "Passkeys"): the account's WebAuthn
//! credentials, their registration and removal on the Security page, and
//! the checks the sign-in paths share (`crate::webauthn` does the
//! cryptography).
//!
//! One private row per account, `p/{did}\0passkeys` ([`Passkeys`]), written
//! with a compare-and-set at the account's owner. Public keys aren't
//! secrets, so it isn't KEK-wrapped: a passkey sign-in never needs the key
//! service.
//!
//! Challenges are stateless (`webauthn::mint_challenge`, keyed from
//! `jwt_secret`): any node mints and checks them, rendering a sign-in page
//! writes nothing, and each is claimed once, cluster-wide, at the account's
//! owner after its signature verified.

use super::cas::{Cond, Op};
use super::server::{now_secs, to_json_bytes};
use super::*;
use crate::oauth::util::{b64u, b64u_decode};
use crate::webauthn::{self, Fail};
use sha2::{Digest, Sha256};

pub(super) const ROW: &str = "passkeys";
pub const MAX_PASSKEYS: usize = 20;
pub const MAX_NAME: usize = 64;
const CAS_ROUNDS: usize = 8;

fn is_false(b: &bool) -> bool {
    !*b
}

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Passkeys {
    #[serde(default)]
    pub creds: Vec<Cred>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Cred {
    /// The credential id, base64url.
    pub id: String,
    /// The COSE_Key as registered, base64url.
    pub public_key: String,
    pub alg: i64,
    pub sign_count: u32,
    #[serde(default, skip_serializing_if = "is_false")]
    pub backup_eligible: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub backed_up: bool,
    /// `credProps.rk`, when the browser said.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discoverable: Option<bool>,
    /// The registration was user-verified (a PIN or biometric).
    #[serde(default, skip_serializing_if = "is_false")]
    pub uv: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transports: Vec<String>,
    /// Hex; all zeros for most passkeys (attestation "none").
    pub aaguid: String,
    pub name: String,
    pub created_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<u64>,
    /// A counter went backwards on a key that can't be synced: refused from
    /// then on until the owner removes it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suspect_at: Option<u64>,
}

impl Cred {
    /// What a session records as the passkey that signed it in.
    pub fn auth_ref(&self) -> String {
        auth_ref(&self.id)
    }
}

/// Short and fixed-size, so session rows don't carry a 1 KiB credential id.
pub(super) fn auth_ref(id: &str) -> String {
    format!("pk:{}", hex::encode(&Sha256::digest(id.as_bytes())[..12]))
}

pub(super) async fn load_raw(app: &App, did: &str) -> XResult<(Passkeys, Option<Bytes>)> {
    match app.get_private(did, ROW).await? {
        Some(v) => Ok((serde_json::from_slice(&v).map_err(XrpcError::from_err)?, Some(v))),
        None => Ok((Passkeys::default(), None)),
    }
}

pub(super) async fn load(app: &App, did: &str) -> XResult<Passkeys> {
    Ok(load_raw(app, did).await?.0)
}

/// The passkey count on the account row, which account totals count second
/// factors by (crate::totals::flags): written after each change. The change
/// itself stands if this fails; only the count is off until the next one.
pub(super) async fn note_count(app: &App, did: &str, n: usize) {
    let r = app
        .mutate_account(did, false, false, false, move |a| {
            let want = (n > 0).then(|| json!(n));
            if a.extra.get("passkeys") == want.as_ref() {
                return Ok(false);
            }
            super::server::set_extra(a, "passkeys", want.unwrap_or(J::Null));
            Ok(true)
        })
        .await;
    if let Err(e) = r {
        tracing::warn!(did, "noting the passkey count on the account row: {}", e.message);
    }
}

/// Ok(false): the row changed since `read`; nothing was written.
pub(super) async fn save_if(app: &App, did: &str, p: &Passkeys, read: Option<Bytes>) -> XResult<bool> {
    let val = (!p.creds.is_empty()).then(|| Bytes::from(to_json_bytes(p)));
    Ok(app.private_cas(did, vec![Cond::eq(ROW, read)], vec![Op::put(ROW, val)]).await?.applied)
}

pub(super) async fn has_any(app: &App, did: &str) -> XResult<bool> {
    Ok(!load(app, did).await?.creds.is_empty())
}

/// The challenge MAC key, from `jwt_secret` like the CSRF and DPoP keys.
pub(super) fn challenge_key(app: &App) -> [u8; 32] {
    crate::oauth::util::derive_secret(&app.config.jwt_secret, "webauthn")
}

pub(super) fn rp(app: &App) -> XResult<webauthn::Rp> {
    webauthn::Rp::from_public_url(&app.public_url).ok_or_else(|| XrpcError::internal("public URL has no host"))
}

/// The WebAuthn user handle: the DID's bytes, which a discoverable sign-in
/// hands back so the finish goes to that account's owner with no index.
/// None for a DID over the spec's 64 bytes (a long did:web), whose passkeys
/// are second factors only.
pub fn user_handle(did: &str) -> Option<&[u8]> {
    (did.len() <= webauthn::MAX_USER_HANDLE).then_some(did.as_bytes())
}

/// The DID a user handle names, if it could be one.
pub fn did_from_user_handle(b64: &str) -> Option<String> {
    if b64.len() > 88 {
        return None;
    }
    let b = b64u_decode(b64)?;
    let s = String::from_utf8(b).ok()?;
    (s.starts_with("did:") && s.len() <= webauthn::MAX_USER_HANDLE && s.bytes().all(|c| c.is_ascii_graphic()))
        .then_some(s)
}

pub(super) fn count_failure(f: Fail) {
    crate::metrics::PASSKEY_FAILURES.with_label_values(&[f.reason()]).inc();
}

/// An assertion as the browser posted it, each part base64url.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct AssertionIn {
    pub id: String,
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    pub authenticator_data: String,
    pub signature: String,
    #[serde(default)]
    pub user_handle: Option<String>,
}

/// Base64 text over these is refused before decoding.
const MAX_ID_B64: usize = (webauthn::MAX_CREDENTIAL_ID * 4).div_ceil(3);
const MAX_CDJ_B64: usize = (webauthn::MAX_CLIENT_DATA * 4).div_ceil(3);
const MAX_AD_B64: usize = (webauthn::MAX_AUTHENTICATOR_DATA * 4).div_ceil(3);
const MAX_SIG_B64: usize = (webauthn::MAX_SIGNATURE * 4).div_ceil(3);
pub(super) const MAX_ATT_B64: usize = (webauthn::MAX_ATTESTATION_OBJECT * 4).div_ceil(3);

pub(super) fn decode_capped(s: &str, max: usize) -> Result<Vec<u8>, Fail> {
    if s.len() > max {
        return Err(Fail::TooLarge);
    }
    webauthn::b64u_strict(s).ok_or(Fail::Malformed)
}

struct Decoded {
    id: Vec<u8>,
    cdj: Vec<u8>,
    ad: Vec<u8>,
    sig: Vec<u8>,
}

fn decode(a: &AssertionIn) -> Result<Decoded, Fail> {
    Ok(Decoded {
        id: decode_capped(&a.id, MAX_ID_B64)?,
        cdj: decode_capped(&a.client_data_json, MAX_CDJ_B64)?,
        ad: decode_capped(&a.authenticator_data, MAX_AD_B64)?,
        sig: decode_capped(&a.signature, MAX_SIG_B64)?,
    })
}

/// What a challenge was minted for: `purpose` and `binding` are checked by
/// its MAC.
pub(super) struct Expect<'a> {
    pub purpose: &'a str,
    pub binding: String,
    /// Passwordless needs a PIN or biometric; a second factor only presence.
    pub require_uv: bool,
}

/// A passkey that just signed in.
pub(super) struct Used {
    pub cred: Cred,
}

/// Why a passkey sign-in failed: a [`Fail`] for the metrics, or a server
/// error to pass on.
pub(super) enum UseErr {
    Refused(Fail),
    Server(XrpcError),
}

impl From<XrpcError> for UseErr {
    fn from(e: XrpcError) -> UseErr {
        UseErr::Server(e)
    }
}

impl From<Fail> for UseErr {
    fn from(f: Fail) -> UseErr {
        UseErr::Refused(f)
    }
}

/// Checks an assertion for `did` end to end: the challenge (purpose,
/// binding, expiry), every ceremony check, that the credential is one of
/// the account's, then claims the challenge once cluster-wide (after the
/// signature, so junk never costs a write) and applies the counter rule
/// with a compare-and-set, which also fails if the passkey was removed
/// meanwhile. Counts the failure reason.
pub(super) async fn use_passkey(app: &App, did: &str, a: &AssertionIn, ex: &Expect<'_>) -> Result<Used, UseErr> {
    let r = use_inner(app, did, a, ex).await;
    if let Err(UseErr::Refused(f)) = &r {
        count_failure(*f);
    }
    r
}

async fn use_inner(app: &App, did: &str, a: &AssertionIn, ex: &Expect<'_>) -> Result<Used, UseErr> {
    let d = decode(a)?;
    let now = now_secs();
    let challenge = webauthn::client_data_challenge(&d.cdj)?;
    let ch = webauthn::open_challenge(&challenge_key(app), ex.purpose, &ex.binding, &challenge, now)?;
    let id = b64u(&d.id);
    let (row, _) = load_raw(app, did).await?;
    let cred = row.creds.iter().find(|c| c.id == id).cloned().ok_or(Fail::UnknownCredential)?;
    if cred.suspect_at.is_some() {
        return Err(Fail::Counter.into());
    }
    let key = webauthn::PublicKey::from_cose(&b64u_decode(&cred.public_key).ok_or(Fail::Key)?)?;
    let rp = rp(app)?;
    let got = webauthn::verify_assertion(&rp, &challenge, &key, &d.cdj, &d.ad, &d.sig, ex.require_uv)?;
    // the BE flag is fixed for a credential's life
    if got.backup_eligible != cred.backup_eligible {
        return Err(Fail::Malformed.into());
    }
    match super::internal::claim_replay_anywhere(app, did, &ch.replay_key(), ch.exp as i64).await? {
        true => {}
        false => return Err(Fail::Replay.into()),
    }
    let mut regressed = None;
    for _ in 0..CAS_ROUNDS {
        let (mut row, raw) = load_raw(app, did).await?;
        let Some(c) = row.creds.iter_mut().find(|c| c.id == id) else {
            return Err(Fail::UnknownCredential.into());
        };
        if c.suspect_at.is_some() {
            return Err(Fail::Counter.into());
        }
        let back = webauthn::counter_regressed(c.sign_count, got.sign_count);
        if back && !c.backup_eligible {
            // a hardware key reporting an older count: a clone, or replayed
            // signatures. Refused, and flagged until the owner removes it.
            c.suspect_at = Some(now);
        } else {
            c.sign_count = c.sign_count.max(got.sign_count);
            c.last_used_at = Some(now);
            c.backed_up = got.backed_up;
        }
        let out = c.clone();
        if save_if(app, did, &row, raw).await? {
            if back {
                regressed = Some(out.backup_eligible);
            }
            if out.suspect_at.is_some() {
                crate::metrics::PASSKEY_COUNTER_REGRESSIONS.with_label_values(&["refused"]).inc();
                tracing::warn!(did, "passkey counter went backwards on a hardware key: flagged");
                suspect_mail(app, did, &out).await;
                return Err(Fail::Counter.into());
            }
            if regressed == Some(true) {
                crate::metrics::PASSKEY_COUNTER_REGRESSIONS.with_label_values(&["accepted"]).inc();
                tracing::info!(did, "passkey counter went backwards on a synced passkey: accepted");
            }
            return Ok(Used { cred: out });
        }
    }
    Err(super::server::cas_conflict().into())
}

async fn suspect_mail(app: &App, did: &str, c: &Cred) {
    let what = format!(
        "Your passkey \u{201c}{}\u{201d} was refused because it looks like it was copied. Remove it on the Security page, and add it again if it's yours.",
        c.name
    );
    security_mail(app, did, &what).await;
}

/// Mails the owner about a change to how the account signs in. Never fails
/// the change: a refused budget or a missing address is only logged.
pub(super) async fn security_mail(app: &App, did: &str, what: &str) {
    let Ok(acct) = super::internal::account_anywhere(app, did).await else { return };
    let Some(email) = acct.email.clone() else { return };
    let permit = match super::server::mail_permit(app, Some(did), &email, crate::mail::SECURITY_PURPOSE, false).await {
        Ok(p) => p,
        Err(e) => {
            tracing::info!(did, error = %e.message, "security mail not sent");
            return;
        }
    };
    let at = chrono::DateTime::from_timestamp(now_secs() as i64, 0)
        .map(|t| t.format("%Y-%m-%d %H:%M UTC").to_string())
        .unwrap_or_default();
    super::server::deliver(
        app,
        permit,
        &email,
        crate::mail::Email::SecurityChange { handle: &acct.handle, what, at: &at },
    );
}

// ---------------------------------------------------------------- XRPC

pub fn routes() -> Router<Arc<App>> {
    Router::new()
        .route("/xrpc/vlpds.server.listPasskeys", get(list_passkeys))
        .route("/xrpc/vlpds.server.startPasskeyRegistration", post(start_registration))
        .route("/xrpc/vlpds.server.finishPasskeyRegistration", post(finish_registration))
        .route("/xrpc/vlpds.server.renamePasskey", post(rename_passkey))
        .route("/xrpc/vlpds.server.removePasskey", post(remove_passkey))
        .route("/xrpc/vlpds.server.startPasskeySignIn", post(start_sign_in))
        .route("/xrpc/vlpds.server.createPasskeySession", post(create_session))
}

const TRANSPORTS: [&str; 6] = ["usb", "nfc", "ble", "internal", "hybrid", "smart-card"];

fn rfc3339(secs: u64) -> String {
    chrono::DateTime::from_timestamp(secs as i64, 0)
        .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
        .unwrap_or_default()
}

fn bad(msg: &str) -> XrpcError {
    XrpcError::bad("InvalidRequest", msg)
}

/// Full account sessions only: a stolen app password or OAuth token can't
/// add a lasting way in, or take one away.
fn owner(creds: &super::authn::Credentials) -> XResult<String> {
    super::server::full_access(creds)
}

/// The password again, for a change to how the account signs in. Charged to
/// the account's sign-in bucket before Argon2, so a stolen session can't
/// guess it any faster than a sign-in could.
pub(super) async fn check_password(app: &App, did: &str, password: &str) -> XResult<Account> {
    crate::ratelimit::check(&[&crate::ratelimit::SIGN_IN_ACCOUNT], did, 1)?;
    let acct = app.account(did).await?;
    if password.is_empty() || !super::server::verify_password(&acct, password).await? {
        return Err(XrpcError::auth("Invalid password"));
    }
    Ok(acct)
}

fn clean_name(name: &str) -> XResult<String> {
    let n: String = name.trim().chars().filter(|c| !c.is_control()).collect();
    if n.is_empty() || n.chars().count() > MAX_NAME {
        return Err(bad("name: 1 to 64 characters"));
    }
    Ok(n)
}

/// `allowCredentials` / `excludeCredentials` entries.
pub(super) fn descriptors(p: &Passkeys) -> Vec<J> {
    p.creds
        .iter()
        .filter(|c| c.suspect_at.is_none())
        .map(|c| json!({"type": "public-key", "id": c.id, "transports": c.transports}))
        .collect()
}

async fn list_passkeys(State(app): AppState, Auth(creds): Auth) -> XResult<Json<J>> {
    let did = owner(&creds)?;
    let p = load(&app, &did).await?;
    let rp = rp(&app)?;
    let list: Vec<J> = p
        .creds
        .iter()
        .map(|c| {
            json!({
                "id": c.id,
                "name": c.name,
                "createdAt": rfc3339(c.created_at),
                "lastUsedAt": c.last_used_at.map(rfc3339),
                "synced": c.backup_eligible,
                "backedUp": c.backed_up,
                "discoverable": c.discoverable,
                "userVerified": c.uv,
                "passwordless": c.uv && c.discoverable != Some(false) && user_handle(&did).is_some(),
                "suspectAt": c.suspect_at.map(rfc3339),
                "transports": c.transports,
            })
        })
        .collect();
    Ok(Json(json!({
        "passkeys": list,
        "max": MAX_PASSKEYS,
        "passwordlessAvailable": user_handle(&did).is_some(),
        "recoveryCodesRemaining": super::mfa::remaining(&app, &did).await?,
        "rpId": rp.id,
        "origin": rp.origin,
    })))
}

#[derive(Deserialize)]
struct StartIn {
    #[serde(default)]
    password: String,
}

/// The password is checked here, so a stolen session token alone can't add
/// a passkey. Returns `PublicKeyCredentialCreationOptions` as JSON.
async fn start_registration(
    State(app): AppState,
    Auth(creds): Auth,
    headers: HeaderMap,
    Json(inp): Json<StartIn>,
) -> XResult<Json<J>> {
    let did = owner(&creds)?;
    let acct = check_password(&app, &did, &inp.password).await?;
    // after the password, so a wrong one doesn't spend the day's additions
    crate::ratelimit::check(&[&crate::ratelimit::PASSKEY_REGISTER_ACCOUNT], &did, 1)?;
    let p = load(&app, &did).await?;
    if p.creds.len() >= MAX_PASSKEYS {
        return Err(bad("This account has the most passkeys it can have. Remove one first."));
    }
    let rp = rp(&app)?;
    let challenge =
        webauthn::mint_challenge(&challenge_key(&app), "register", &register_binding(&did, &headers), now_secs());
    let (user_id, resident) = match user_handle(&did) {
        Some(h) => (b64u(h), "preferred"),
        // too long to be the user handle: a second factor only, so it needn't be discoverable
        None => (b64u(Sha256::digest(did.as_bytes())), "discouraged"),
    };
    let algs: Vec<J> = webauthn::ALGS.iter().map(|a| json!({"type": "public-key", "alg": a})).collect();
    Ok(Json(json!({
        "rp": {"id": rp.id, "name": rp.id},
        "user": {"id": user_id, "name": acct.handle, "displayName": acct.handle},
        "challenge": b64u(&challenge),
        "pubKeyCredParams": algs,
        "timeout": webauthn::CHALLENGE_TTL * 1000,
        "attestation": "none",
        "authenticatorSelection": {"residentKey": resident, "requireResidentKey": false, "userVerification": "preferred"},
        "excludeCredentials": descriptors(&p),
        "extensions": {"credProps": true},
    })))
}

#[derive(Deserialize, Default)]
struct CredPropsIn {
    rk: Option<bool>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct ExtResultsIn {
    #[serde(default)]
    cred_props: Option<CredPropsIn>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AttestationIn {
    #[serde(rename = "clientDataJSON")]
    client_data_json: String,
    attestation_object: String,
    #[serde(default)]
    transports: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegistrationIn {
    raw_id: String,
    response: AttestationIn,
    #[serde(default)]
    client_extension_results: ExtResultsIn,
}

#[derive(Deserialize)]
struct FinishIn {
    #[serde(default)]
    name: String,
    credential: RegistrationIn,
}

/// A registration challenge finishes only for its account, with the
/// credential (the session token) that started it.
fn register_binding(did: &str, headers: &HeaderMap) -> String {
    let token = headers.get(header::AUTHORIZATION).map(|v| v.as_bytes()).unwrap_or_default();
    format!("{did}\0{}", hex::encode(&Sha256::digest(token)[..16]))
}

async fn finish_registration(
    State(app): AppState,
    Auth(creds): Auth,
    headers: HeaderMap,
    Json(inp): Json<FinishIn>,
) -> XResult<Json<J>> {
    let did = owner(&creds)?;
    let name = clean_name(&inp.name)?;
    let (cred, ch) = match verify_new(&app, &register_binding(&did, &headers), &inp.credential) {
        Ok(x) => x,
        Err(f) => {
            count_failure(f);
            return Err(refused(f));
        }
    };
    let cred = Cred { name, ..cred };
    if !super::internal::claim_replay_anywhere(&app, &did, &ch.replay_key(), ch.exp as i64).await? {
        count_failure(Fail::Replay);
        return Err(refused(Fail::Replay));
    }
    let _g = crate::totp::lock(&did).await;
    for _ in 0..CAS_ROUNDS {
        let (mut p, raw) = load_raw(&app, &did).await?;
        let (mut m, mraw) = super::mfa::load_raw(&app, &did).await?;
        if p.creds.iter().any(|x| x.id == cred.id) {
            return Err(bad("This passkey is already registered"));
        }
        if p.creds.len() >= MAX_PASSKEYS {
            return Err(bad("This account has the most passkeys it can have. Remove one first."));
        }
        p.creds.push(cred.clone());
        // the first strong factor brings the shared recovery codes
        let codes = if m.recovery.is_empty() { m.issue(&did, now_secs()) } else { Vec::new() };
        let (mc, mop) = super::mfa::cas_parts(&m, mraw);
        let ops = vec![Op::put(ROW, Some(Bytes::from(to_json_bytes(&p)))), mop];
        if app.private_cas(&did, vec![Cond::eq(ROW, raw), mc], ops).await?.applied {
            crate::metrics::PASSKEYS.with_label_values(&["registered"]).inc();
            note_count(&app, &did, p.creds.len()).await;
            let what = format!(
                "A passkey \u{201c}{}\u{201d} was added to your account. If you didn't add it, remove it on the Security page, then change your password: changing the password alone doesn't remove a passkey.",
                cred.name
            );
            security_mail(&app, &did, &what).await;
            return Ok(Json(json!({
                "id": cred.id,
                "name": cred.name,
                "createdAt": rfc3339(cred.created_at),
                "recoveryCodes": codes,
            })));
        }
    }
    Err(super::server::cas_conflict())
}

/// Every check of a new credential; nothing written.
fn verify_new(app: &App, binding: &str, c: &RegistrationIn) -> Result<(Cred, webauthn::Challenge), Fail> {
    let raw_id = decode_capped(&c.raw_id, MAX_ID_B64)?;
    let cdj = decode_capped(&c.response.client_data_json, MAX_CDJ_B64)?;
    let att = decode_capped(&c.response.attestation_object, MAX_ATT_B64)?;
    let now = now_secs();
    let challenge = webauthn::client_data_challenge(&cdj)?;
    let ch = webauthn::open_challenge(&challenge_key(app), "register", binding, &challenge, now)?;
    let rp = rp(app).map_err(|_| Fail::RpId)?;
    let r = webauthn::verify_registration(&rp, &challenge, &raw_id, &cdj, &att, false)?;
    let mut transports: Vec<String> = Vec::new();
    for t in c.response.transports.iter().take(TRANSPORTS.len()) {
        if TRANSPORTS.contains(&t.as_str()) && !transports.contains(t) {
            transports.push(t.clone());
        }
    }
    let cred = Cred {
        id: b64u(&r.credential_id),
        public_key: b64u(&r.cose_key),
        alg: r.alg,
        sign_count: r.sign_count,
        backup_eligible: r.backup_eligible,
        backed_up: r.backed_up,
        discoverable: c.client_extension_results.cred_props.as_ref().and_then(|p| p.rk),
        uv: r.uv,
        transports,
        aaguid: hex::encode(r.aaguid),
        name: String::new(),
        created_at: now,
        last_used_at: None,
        suspect_at: None,
    };
    Ok((cred, ch))
}

/// A registration the signed-in owner made: the check that failed helps
/// them, and tells nobody else anything.
pub(super) fn refused(f: Fail) -> XrpcError {
    XrpcError::bad("PasskeyRefused", format!("The passkey was not accepted ({})", f.reason()))
}

/// A sign-in: one message whatever failed (the reason is in the metrics),
/// so nothing says which accounts have passkeys or which check failed.
fn not_recognized() -> XrpcError {
    XrpcError::bad("PasskeyRefused", "Passkey not recognized")
}

#[derive(Deserialize)]
struct RenameIn {
    id: String,
    name: String,
}

async fn rename_passkey(State(app): AppState, Auth(creds): Auth, Json(inp): Json<RenameIn>) -> XResult<StatusCode> {
    let did = owner(&creds)?;
    let name = clean_name(&inp.name)?;
    for _ in 0..CAS_ROUNDS {
        let (mut p, raw) = load_raw(&app, &did).await?;
        let c = p.creds.iter_mut().find(|c| c.id == inp.id).ok_or_else(|| bad("No such passkey"))?;
        let old = std::mem::replace(&mut c.name, name.clone());
        if save_if(&app, &did, &p, raw).await? {
            if old != name {
                let what = format!("Your passkey \u{201c}{old}\u{201d} was renamed \u{201c}{name}\u{201d}.");
                security_mail(&app, &did, &what).await;
            }
            return Ok(StatusCode::OK);
        }
    }
    Err(super::server::cas_conflict())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RemoveIn {
    id: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    sign_out_everywhere: bool,
}

/// Needs the password. Ends what the passkey signed in (OAuth sessions and
/// account-page sessions record it; device sign-ins and unexchanged codes
/// are checked against the row when they're used), or everything.
async fn remove_passkey(State(app): AppState, Auth(creds): Auth, Json(inp): Json<RemoveIn>) -> XResult<Json<J>> {
    let did = owner(&creds)?;
    check_password(&app, &did, &inp.password).await?;
    let gone = 'cas: {
        let _g = crate::totp::lock(&did).await;
        for _ in 0..CAS_ROUNDS {
            let (mut p, raw) = load_raw(&app, &did).await?;
            let i = p.creds.iter().position(|c| c.id == inp.id).ok_or_else(|| bad("No such passkey"))?;
            let gone = p.creds.remove(i);
            let mut conds = vec![Cond::eq(ROW, raw)];
            let mut ops = vec![Op::put(ROW, (!p.creds.is_empty()).then(|| Bytes::from(to_json_bytes(&p))))];
            // the last strong factor takes the recovery codes with it; TOTP
            // read in this round and held to it, so a TOTP change racing
            // this can't leave a factor without codes
            let traw = app.get_private(&did, crate::totp::PRIVATE_NAME).await?;
            let totp = traw
                .as_deref()
                .and_then(|v| serde_json::from_slice::<crate::totp::TotpState>(v).ok())
                .is_some_and(|t| t.enabled());
            conds.push(Cond::eq(crate::totp::PRIVATE_NAME, traw));
            if p.creds.is_empty() && !totp {
                let (_, mraw) = super::mfa::load_raw(&app, &did).await?;
                let (mc, mop) = super::mfa::cas_parts(&super::mfa::Mfa::default(), mraw);
                conds.push(mc);
                ops.push(mop);
            }
            if app.private_cas(&did, conds, ops).await?.applied {
                note_count(&app, &did, p.creds.len()).await;
                break 'cas gone;
            }
        }
        return Err(super::server::cas_conflict());
    };
    crate::metrics::PASSKEYS.with_label_values(&["removed"]).inc();
    if inp.sign_out_everywhere {
        super::server::revoke_everything(&app, &did).await?;
    } else {
        super::server::revoke_signed_in_with(&app, &did, &gone.auth_ref()).await?;
    }
    security_mail(&app, &did, &format!("The passkey \u{201c}{}\u{201d} was removed from your account.", gone.name))
        .await;
    Ok(Json(json!({"signedOutEverywhere": inp.sign_out_everywhere})))
}

// ---------------------------------------------------------------- the account page's sign-in

#[derive(Deserialize, Default)]
struct StartSignInIn {
    /// With the password: the second factor after a `PasskeyRequired`
    /// (or alongside TOTP). Without: passwordless.
    #[serde(default)]
    identifier: Option<String>,
    #[serde(default)]
    password: Option<String>,
}

/// The second-factor challenge carries the credential epoch the password
/// check read: a password change since voids it.
fn spa_2fa_binding(did: &str, epoch: &str) -> String {
    format!("{did}\0{epoch}")
}

/// `vlpds.server.startPasskeySignIn`: options for `navigator.credentials.get`.
/// Passwordless options name no account; `allowCredentials` only comes after
/// a correct password, so nothing here says whether an account has passkeys.
async fn start_sign_in(State(app): AppState, Json(inp): Json<StartSignInIn>) -> XResult<Json<J>> {
    use crate::ratelimit as rl;
    rl::check_ip(&[&rl::PASSKEY_SIGN_IN_IP], 1)?;
    let rp = rp(&app)?;
    let key = challenge_key(&app);
    let now = now_secs();
    let (Some(ident), Some(password)) = (inp.identifier, inp.password) else {
        let ch = webauthn::mint_challenge(&key, "spa-signin", "", now);
        return Ok(Json(json!({
            "challenge": b64u(ch),
            "rpId": rp.id,
            "timeout": webauthn::CHALLENGE_TTL * 1000,
            "userVerification": "required",
            "allowCredentials": [],
        })));
    };
    let invalid = || XrpcError::auth("Invalid identifier or password");
    let norm = ident.trim().trim_start_matches('@').to_lowercase();
    rl::check_with_ip(&[&rl::CREATE_SESSION_DAY, &rl::CREATE_SESSION_5MIN], &norm, 1)?;
    let acct = super::server::login_account(&app, &norm).await?.ok_or_else(invalid)?;
    rl::check(&[&rl::SIGN_IN_ACCOUNT], &acct.did, 1)?;
    if password.len() > 512 || !super::server::verify_password(&acct, &password).await? {
        return Err(invalid());
    }
    if super::server::is_takendown_account(&acct) {
        return Err(super::takedown_error());
    }
    let epoch = super::server::epoch_for_login(&app, &acct).await?.ok_or_else(invalid)?;
    let p = load(&app, &acct.did).await?;
    if descriptors(&p).is_empty() {
        if !p.creds.is_empty() {
            return Err(XrpcError::bad(
                "PasskeyFlagged",
                "Your passkey was refused because it may have been copied. Sign in with a recovery code, then remove it on the Security page.",
            ));
        }
        return Err(bad("This account has no passkeys"));
    }
    let ch = webauthn::mint_challenge(&key, "spa-2fa", &spa_2fa_binding(&acct.did, &epoch), now);
    Ok(Json(json!({
        "did": acct.did,
        "challenge": b64u(ch),
        "rpId": rp.id,
        "timeout": webauthn::CHALLENGE_TTL * 1000,
        "userVerification": "preferred",
        "allowCredentials": descriptors(&p),
    })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateSessionIn {
    /// The account: routes the call to its owner. Passwordless, it must be
    /// the credential's user handle.
    did: String,
    credential: AssertionIn,
    #[serde(default)]
    trust_device: bool,
}

/// `vlpds.server.createPasskeySession`: the legacy session `createSession`
/// would give, for an assertion over a `startPasskeySignIn` challenge.
async fn create_session(
    State(app): AppState,
    super::moderation::ClientIp(ip): super::moderation::ClientIp,
    headers: HeaderMap,
    Json(inp): Json<CreateSessionIn>,
) -> XResult<Response> {
    let mut second = false;
    let r = create_session_inner(&app, inp, ip, &headers, &mut second).await;
    let result = match &r {
        Ok(_) => "success",
        Err(e) if e.status == StatusCode::TOO_MANY_REQUESTS => "rate_limited",
        Err(e) if e.status.is_server_error() => "error",
        Err(e) if e.error == "AccountTakedown" => "inactive",
        Err(_) if second => "second_factor_failed",
        Err(_) => "failed",
    };
    crate::metrics::login(if second { "password" } else { "passkey" }, result);
    r
}

async fn create_session_inner(
    app: &App,
    inp: CreateSessionIn,
    ip: Option<std::net::IpAddr>,
    headers: &HeaderMap,
    second: &mut bool,
) -> XResult<Response> {
    use crate::ratelimit as rl;
    rl::check_ip(&[&rl::PASSKEY_SIGN_IN_IP], 1)?;
    let did = inp.did.trim().to_string();
    if !did.starts_with("did:") || did.len() > 2048 {
        return Err(bad("did is required"));
    }
    // no per-account charge: anyone can name any DID here (it would let them
    // spend the account's password sign-ins), and a passkey can't be guessed
    rl::check_with_ip(&[&rl::CREATE_SESSION_DAY, &rl::CREATE_SESSION_5MIN], &did, 1)?;
    let refuse = |f: Fail| {
        count_failure(f);
        not_recognized()
    };
    let acct = match super::server::account_if_exists(app, &did).await? {
        Some(a) => a,
        None => return Err(refuse(Fail::UnknownCredential)),
    };
    // read before the check: a revoke-all racing this sign-in lands first
    // (and voids it) or after
    let epoch = super::server::auth_epoch(app, &did).await?;
    let cdj = decode_capped(&inp.credential.client_data_json, MAX_CDJ_B64).map_err(refuse)?;
    let challenge = webauthn::client_data_challenge(&cdj).map_err(refuse)?;
    let key = challenge_key(app);
    *second = webauthn::open_challenge(&key, "spa-2fa", &spa_2fa_binding(&did, &epoch), &challenge, now_secs()).is_ok();
    let ex = if *second {
        Expect { purpose: "spa-2fa", binding: spa_2fa_binding(&did, &epoch), require_uv: false }
    } else {
        let handle = inp.credential.user_handle.as_deref().and_then(did_from_user_handle);
        if handle.as_deref() != Some(did.as_str()) {
            return Err(refuse(Fail::UnknownCredential));
        }
        Expect { purpose: "spa-signin", binding: String::new(), require_uv: true }
    };
    let used = match use_passkey(app, &did, &inp.credential, &ex).await {
        Ok(u) => u,
        Err(UseErr::Server(e)) => return Err(e),
        Err(UseErr::Refused(_)) => return Err(not_recognized()),
    };
    if super::server::is_takendown_account(&acct) {
        return Err(super::takedown_error());
    }
    let auth_ref = used.cred.auth_ref();
    super::cas::pause_point("passkey_session", &did).await;
    let (access, refresh) =
        super::server::create_session_tokens(app, &did, None, false, Some(&epoch), Some(auth_ref.clone()), ip).await?;
    // a removal racing this either found the session above or left the
    // passkey gone for this check (it writes the row before its scan)
    if !still_registered(app, &did, Some(&auth_ref)).await? {
        super::server::revoke_signed_in_with(app, &did, &auth_ref).await?;
        return Err(not_recognized());
    }
    let ua = super::signin::user_agent(headers);
    let own = super::server::own_page(headers);
    let mut set_cookie = None;
    let mut device_id = if own { super::oauth::device_cookie_id(headers) } else { None };
    if *second && inp.trust_device && own {
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
    let method = if *second { super::signin::Method::Password } else { super::signin::Method::Passkey(None) };
    super::signin::record(app, &acct, method, Some("passkey"), &ctx).await;
    let mut out = super::server::session_info(app, &acct, true).await;
    out["accessJwt"] = json!(access);
    out["refreshJwt"] = json!(refresh);
    let mut r = Json(out).into_response();
    if let Some(c) = set_cookie {
        r.headers_mut().insert(header::SET_COOKIE, c);
    }
    Ok(r)
}

/// Whether the passkey a sign-in recorded is still on the account; true
/// for sign-ins without one.
pub(super) async fn still_registered(app: &App, did: &str, auth_cred: Option<&str>) -> XResult<bool> {
    let Some(r) = auth_cred else { return Ok(true) };
    Ok(load(app, did).await?.creds.iter().any(|c| c.auth_ref() == r))
}

/// Golden fixtures (`super::private_rows`).
pub(super) fn fixture_rows(did: &str) -> Vec<super::private_rows::PrivateRow> {
    let p = Passkeys {
        creds: vec![
            Cred {
                id: "9y1xA8Tmg1FEmT-c7_fvWZ_uoTuoih3OvR45_oAK-cwHWhAbXrl2q62iLVTjiyEZ7O7n-CROOY494k7Q3xrs_w".into(),
                public_key: "pQECAyYgASFYIEhW1CRfuNlIN6XTPKw0RbvzeaIlRMrDwwep-uq_-3WQIlgg1FZwd_RZRsqS_qgKCDvcVh7ScoKNo3w5h5fv3ihUSww".into(),
                alg: webauthn::ALG_ES256,
                sign_count: 23,
                backup_eligible: true,
                backed_up: true,
                discoverable: Some(true),
                uv: true,
                transports: vec!["internal".into(), "hybrid".into()],
                aaguid: "00".repeat(16),
                name: "iPhone".into(),
                created_at: 1_790_000_000,
                last_used_at: Some(1_790_000_100),
                suspect_at: None,
            },
            Cred {
                id: "AAEC".into(),
                public_key: "pAEBAycgBiFYIMz6_SUFLiDid2Yhlq0YboyJ-CDrIrNpkPUGmJp4D3Dp".into(),
                alg: webauthn::ALG_EDDSA,
                sign_count: 7,
                aaguid: "ee".repeat(16),
                name: "YubiKey".into(),
                created_at: 1_790_000_200,
                suspect_at: Some(1_790_000_300),
                ..Default::default()
            },
        ],
    };
    vec![(did.into(), ROW.into(), to_json_bytes(&p))]
}

pub(super) fn check_row(routing: &str, name: &str, val: &[u8]) -> Option<anyhow::Result<&'static str>> {
    (routing.starts_with("did:") && name == ROW).then(|| super::private_rows::typed_row::<Passkeys>("passkeys", val))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_handles() {
        let did = "did:plc:abcdefghijklmnopqrstuvwx";
        assert_eq!(user_handle(did), Some(did.as_bytes()));
        assert_eq!(did_from_user_handle(&b64u(did)).as_deref(), Some(did));
        let long = format!("did:web:{}.example", "a".repeat(60));
        assert_eq!(user_handle(&long), None);
        assert_eq!(did_from_user_handle(&b64u(&long)), None);
        assert_eq!(did_from_user_handle(&b64u("not a did")), None);
        assert_eq!(did_from_user_handle("!!"), None);
        assert_eq!(auth_ref("AAEC").len(), 3 + 24);
    }

    #[test]
    fn challenge_claims_have_their_own_cache() {
        use crate::oauth::util::ClaimKind;
        let ch = webauthn::Challenge { nonce: [1; 16], exp: 0 };
        assert_eq!(ClaimKind::of(&ch.replay_key(), true), ClaimKind::Passkey);
    }
}
