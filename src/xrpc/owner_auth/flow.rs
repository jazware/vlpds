//! The coordinator: everything a provider must not do.
//!
//! A login is a state machine over one transaction row. `/auth/start` (or an
//! SSR form) creates it and asks the provider for a challenge; the provider's
//! callback — or a browser-submitted SIWE signature — is verified and the
//! resulting identity is *staged* on the row; `ready` hands the staged
//! identity back only to the browser that started the login, and the caller
//! resolves it to an account, runs the local second factors, and finishes.
//!
//! Account resolution is by the global subject claim plus the DID's own
//! credential row, so a half-finished link never authenticates and an
//! unlinked identity never becomes an account by accident.

use super::provider::SiweProof;
use super::store::{self, Continuation, Cred, Txn};
use super::types::*;
use super::*;
use crate::state::Account;

/// A started login: the id to remember and what the browser does next.
pub struct Started {
    pub id: String,
    pub provider: ProviderId,
    pub challenge: Challenge,
}

/// This server's canonical origin, from `--public-url` (never the Host
/// header).
pub fn origin(app: &App) -> String {
    match reqwest::Url::parse(&app.public_url) {
        Ok(u) => match (u.host_str(), u.port()) {
            (Some(h), Some(p)) => format!("{}://{h}:{p}", u.scheme()),
            (Some(h), None) => format!("{}://{h}", u.scheme()),
            _ => app.public_url.trim_end_matches('/').to_string(),
        },
        Err(_) => app.public_url.trim_end_matches('/').to_string(),
    }
}

pub fn provider(app: &App, id: ProviderId) -> XResult<Arc<dyn AuthProvider>> {
    app.auth.provider(id).ok_or_else(|| bad_request(&format!("{} sign-in is not enabled on this server", id.label())))
}

/// Begin a login. `address` is the wallet address a SIWE client must supply.
pub async fn start(
    app: &App,
    provider_id: ProviderId,
    intent: Intent,
    cont: Continuation,
    device_id: Option<String>,
    address: Option<String>,
) -> XResult<Started> {
    if intent.needs_owner() && !matches!(cont, Continuation::Did { .. }) {
        return Err(bad_request("that intent requires a signed-in account"));
    }
    let p = provider(app, provider_id)?;
    let id = store::new_txn_id();
    let redirect_uri = Config::redirect_uri(&app.public_url, provider_id);
    let origin = origin(app);
    let owner = match &cont {
        Continuation::Did { did, .. } => Some(did.as_str()),
        _ => None,
    };
    let b =
        Begin { txn_id: &id, intent, origin: &origin, redirect_uri: &redirect_uri, owner, address: address.as_deref() };
    let out = p.begin(app, &b).await?;
    let (challenge, state) = match out {
        BeginOut::Redirect { url, state } => (Challenge::Redirect { url }, state),
        BeginOut::Siwe { message, state } => (Challenge::Siwe { message, address: address.clone() }, state),
    };
    let now = now_secs();
    let txn = Txn {
        id: id.clone(),
        provider: provider_id,
        intent,
        device_id,
        cont,
        created_at: now,
        expires_at: now + store::TXN_TTL_SECS,
        state: Some(state),
        verified: None,
        attempts: 0,
    };
    store::put_txn(app, &txn).await?;
    Ok(Started { id, provider: provider_id, challenge })
}

/// The provider sent the browser back.
pub enum CallbackEnd {
    Cancelled { txn_id: String },
    Verified { txn_id: String },
}

/// Handle a provider callback: verify, then stage the identity on the row.
pub async fn callback(app: &App, provider_id: ProviderId, q: &[(String, String)]) -> XResult<CallbackEnd> {
    let p = provider(app, provider_id)?;
    // Redirect providers carry the transaction id as `state`.
    let id = q.iter().find(|(k, _)| k == "state").map(|(_, v)| v.clone()).unwrap_or_default();
    if id.is_empty() {
        return Err(bad_request("callback has no state"));
    }
    let Some((txn, raw)) = store::load_txn_raw(app, &id).await? else {
        return Err(bad_request("this sign-in is unknown or has expired"));
    };
    if txn.provider != provider_id {
        return Err(bad_request("this sign-in belongs to another provider"));
    }
    if txn.expired(now_secs()) {
        return Err(bad_request("this sign-in has expired"));
    }
    match p.callback(app, &txn, q).await? {
        CallbackOut::Cancelled => {
            store::save_txn(app, &id, Some(raw), None).await?;
            Ok(CallbackEnd::Cancelled { txn_id: id })
        }
        CallbackOut::Verified(ident) => {
            stage(app, &id, raw, txn, *ident).await?;
            Ok(CallbackEnd::Verified { txn_id: id })
        }
    }
}

/// The provider a transaction belongs to, so a verifier can be chosen before
/// the proof is checked.
pub async fn txn_provider(app: &App, id: &str) -> XResult<ProviderId> {
    let Some((txn, _)) = store::load_txn_raw(app, id).await? else {
        return Err(bad_request("this sign-in is unknown or has expired"));
    };
    Ok(txn.provider)
}

/// Verify a proof the browser submitted directly (SIWE) and stage it.
pub async fn verify_proof(app: &App, provider_id: ProviderId, txn_id: &str, proof: &SiweProof) -> XResult<()> {
    let p = provider(app, provider_id)?;
    let Some((txn, raw)) = store::load_txn_raw(app, txn_id).await? else {
        return Err(bad_request("this sign-in is unknown or has expired"));
    };
    if txn.provider != provider_id {
        return Err(bad_request("this sign-in belongs to another provider"));
    }
    if txn.expired(now_secs()) {
        return Err(bad_request("this sign-in has expired"));
    }
    if txn.verified.is_some() {
        return Err(bad_request("this sign-in is already verified"));
    }
    let ident = p.verify(app, &txn, proof).await?;
    stage(app, txn_id, raw, txn, ident).await
}

/// Make sure a transaction carries a verified identity. A redirect provider's
/// proof was consumed at its callback, so a later client step (a link, or a
/// confirmation) must not ask for it again; a direct-proof provider's must be
/// checked here.
pub async fn ensure_verified(app: &App, provider_id: ProviderId, txn_id: &str, proof: &SiweProof) -> XResult<()> {
    let Some((txn, _)) = store::load_txn_raw(app, txn_id).await? else {
        return Err(bad_request("this sign-in is unknown or has expired"));
    };
    if txn.verified.is_some() {
        return Ok(());
    }
    verify_proof(app, provider_id, txn_id, proof).await
}

async fn stage(app: &App, id: &str, raw: Bytes, mut txn: Txn, ident: VerifiedIdentity) -> XResult<()> {
    txn.verified = Some(ident);
    if !store::save_txn(app, id, Some(raw), Some(&txn)).await? {
        return Err(bad_request("this sign-in was already used"));
    }
    Ok(())
}

/// A staged identity, ready for the browser that started the login.
pub struct Ready {
    pub txn: Txn,
    pub ident: VerifiedIdentity,
}

/// Hand the staged identity back, but only to the browser that started the
/// login, and only while the transaction is live. Does not consume it: the
/// caller finishes (and consumes) once the account and second factors are
/// settled.
pub async fn ready(app: &App, txn_id: &str, device_id: Option<&str>) -> XResult<Ready> {
    let Some((txn, _)) = store::load_txn_raw(app, txn_id).await? else {
        return Err(bad_request("this sign-in is unknown or has expired"));
    };
    if txn.expired(now_secs()) {
        return Err(bad_request("this sign-in has expired"));
    }
    match (&txn.device_id, device_id) {
        (Some(want), Some(have)) if want == have => {}
        (Some(_), _) => return Err(proof_rejected("this sign-in belongs to another browser")),
        _ => {}
    }
    let ident = txn.verified.clone().ok_or_else(|| bad_request("this sign-in has no verified identity yet"))?;
    Ok(Ready { txn, ident })
}

/// Consume a transaction; a completed login is single-use.
pub async fn consume(app: &App, txn_id: &str) -> XResult<()> {
    if let Some((_, raw)) = store::load_txn_raw(app, txn_id).await? {
        store::save_txn(app, txn_id, Some(raw), None).await?;
    }
    Ok(())
}

/// The account an external identity signs in as: the subject's holder, which
/// must still list the credential. An interrupted link leaves one half or the
/// other missing and resolves to no account.
pub async fn resolve_account(app: &App, ident: &VerifiedIdentity) -> XResult<Option<Account>> {
    let Some(did) = store::did_for_subject(app, ident.provider, &ident.subject).await? else {
        return Ok(None);
    };
    if !store::creds_has(app, &did, ident.provider, &ident.subject).await? {
        return Ok(None);
    }
    match super::internal::account_anywhere(app, &did).await {
        Ok(a) => Ok(Some(a)),
        Err(e) if e.error == "AccountNotFound" => Ok(None),
        Err(e) => Err(e),
    }
}

// ------------------------------------------------------------------ linking

pub async fn link(app: &App, did: &str, ident: &VerifiedIdentity) -> XResult<Cred> {
    store::attach_cred(app, did, ident).await
}

pub async fn unlink(app: &App, did: &str, id: &str) -> XResult<Option<Cred>> {
    let gone = store::detach_cred(app, did, id).await?;
    if let Some(c) = &gone {
        // End exactly what this credential signed in.
        let _ = super::server::revoke_signed_in_with(app, did, &c.auth_ref()).await;
    }
    Ok(gone)
}

pub async fn list_credentials(app: &App, did: &str) -> XResult<Vec<Cred>> {
    Ok(store::load_creds(app, did).await?.0.list)
}

// ------------------------------------------------------------------ signup

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignupIn {
    pub handle: String,
    pub domain: Option<String>,
    pub email: String,
    #[serde(default)]
    pub invite_code: Option<String>,
}

/// Create the account a new external identity asked for, then attach the
/// credential. No local password: the credential is the way in.
pub async fn create_account_for(app: &App, ident: &VerifiedIdentity, inp: SignupIn) -> XResult<Account> {
    let handle = resolve_handle(app, &inp.handle, inp.domain.as_deref())?;
    let acct = super::server::create_account_external(
        app,
        super::server::CreateAccountIn {
            handle,
            email: Some(inp.email.clone()),
            password: None,
            invite_code: inp.invite_code.clone().filter(|c| !c.trim().is_empty()),
            did: None,
            plc_op: None,
            recovery_key: None,
        },
    )
    .await?;
    match store::attach_cred(app, &acct.did, ident).await {
        Ok(_) => {}
        Err(e) => {
            // Roll back the account rather than leave one nobody can sign in
            // to: a failed attach means someone else holds the identity.
            if let Err(d) = super::server::delete_account_for_failed_link(app, &acct.did).await {
                tracing::error!(did = %acct.did, "failed to delete account after a failed credential attach: {}", d.message);
            }
            return Err(e);
        }
    }
    Ok(acct)
}

fn resolve_handle(app: &App, handle: &str, domain: Option<&str>) -> XResult<String> {
    let h = handle.trim().trim_start_matches('@').to_ascii_lowercase();
    if h.is_empty() {
        return Err(bad_request("a handle is required"));
    }
    if app.handle_domains.under(&h).is_some() {
        return Ok(h);
    }
    let d = domain
        .map(|d| d.trim().trim_start_matches('.').to_ascii_lowercase())
        .filter(|d| !d.is_empty())
        .or_else(|| app.handle_domains.names().first().cloned())
        .ok_or_else(|| bad_request("this server serves no handle domains"))?;
    Ok(format!("{h}.{d}"))
}

// -------------------------------------------------------------- reauth grants

/// What a fresh-owner confirmation can be for. Fixed here so a client cannot
/// name an arbitrary privileged operation, and so every caller that checks one
/// uses the same string.
pub const ACTION_UNLINK: &str = "unlink";
pub const ACTION_LINK: &str = "link";
pub const ACTION_ADD_PASSKEY: &str = "add_passkey";
pub const ACTION_REMOVE_PASSKEY: &str = "remove_passkey";
pub const ACTION_RECOVERY_CODES: &str = "recovery_codes";
pub const ACTION_DISABLE_TOTP: &str = "disable_totp";
pub const ACTION_DELETE: &str = "delete_account";

/// Every action a client may ask a fresh proof for.
pub const ACTIONS: [&str; 7] = [
    ACTION_UNLINK,
    ACTION_LINK,
    ACTION_ADD_PASSKEY,
    ACTION_REMOVE_PASSKEY,
    ACTION_RECOVERY_CODES,
    ACTION_DISABLE_TOTP,
    ACTION_DELETE,
];

/// Approve one sensitive operation for an account. `action` is chosen by the
/// server, never the client.
pub async fn grant(
    app: &App,
    did: &str,
    action: &str,
    target: Option<String>,
    device_id: Option<&str>,
) -> XResult<String> {
    let id = store::new_grant_id();
    let g = store::Grant {
        did: did.to_string(),
        action: action.to_string(),
        target,
        exp: now_secs() + store::GRANT_TTL_SECS,
        device_id: device_id.map(String::from),
    };
    store::put_grant(app, &id, &g).await?;
    Ok(id)
}

/// Consume a grant for exactly this operation. A grant for another account,
/// another action or another object is refused **without** spending it, so a
/// mismatched or stolen grant cannot be retargeted, and cannot be used to
/// burn the owner's approval either.
pub async fn may(app: &App, did: &str, grant_id: &str, action: &str, target: Option<&str>) -> XResult<()> {
    let expired = || bad_request("that confirmation has expired; approve the change again");
    let Some((g, raw)) = store::load_grant(app, grant_id).await? else {
        return Err(expired());
    };
    if g.did != did || g.exp < now_secs() {
        return Err(expired());
    }
    if g.action != action || g.target.as_deref() != target {
        return Err(bad_request("that confirmation is for a different change"));
    }
    if !store::consume_grant(app, grant_id, raw).await? {
        return Err(expired());
    }
    Ok(())
}
