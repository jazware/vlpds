//! Durable owner-auth rows.
//!
//! Three kinds, all written only through the owner-routed conditional-write
//! path ([`App::private_cas`]) so a check and its write cannot be split by a
//! concurrent writer or a shard move:
//!
//! * a **transaction** (`auth:{id}` / `auth/txn`): one short-lived login,
//!   bound to the browser that started it, consumed once;
//! * a DID's **credentials** (`{did}` / `authcreds`): what the account can use
//!   to prove itself, each naming a provider identity;
//! * a fresh-owner **grant** (`auth:grant:{id}` / `g`): one sensitive
//!   operation, approved once by a new proof.
//!
//! The global half — "this provider identity belongs to that DID" — is a
//! claim object in the bucket (`{prefix}/authsub/…`), the same conditional
//! create-and-take-over mechanism handles and emails use, because a subject
//! index and a DID row cannot be one atomic write.

use serde::{Deserialize, Serialize};

use super::types::{cred_ref, Intent, ProviderId, VerifiedIdentity};
use super::*;
use crate::xrpc::cas::{Cond, Op};

/// One login's row under routing `auth:{id}`.
pub const TXN_ROW: &str = "auth/txn";
/// A DID's external credentials.
pub const CREDS_ROW: &str = "authcreds";

/// How long a started login may take before its row expires.
pub const TXN_TTL_SECS: i64 = 15 * 60;
/// How long an approved sensitive operation may wait to be used.
pub const GRANT_TTL_SECS: i64 = 5 * 60;

pub fn txn_routing(id: &str) -> String {
    format!("auth:{id}")
}

pub fn new_txn_id() -> String {
    crate::oauth::util::random_id("txn-", 16)
}

/// A started login.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Txn {
    pub id: String,
    pub provider: ProviderId,
    pub intent: Intent,
    /// The browser that started it. Finishing requires this cookie.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    pub cont: Continuation,
    pub created_at: i64,
    pub expires_at: i64,
    /// Provider state: OAuth `state`, PKCE verifier, nonce, or the SIWE
    /// message. Server-only; the client sees only the challenge it needs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<J>,
    /// Set when the proof is accepted; `finish` consumes it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified: Option<VerifiedIdentity>,
    /// Failed proof attempts, to bound brute force on a transaction.
    #[serde(default)]
    pub attempts: u32,
}

/// Where a finished login goes next. Server-owned: a client cannot name an
/// arbitrary return location.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Continuation {
    /// An AT Protocol authorization request to resume with `consent_step`.
    OAuth { request_uri: String },
    /// The account page's own sign-in or sign-up.
    Account { screen: String },
    /// Link an identity to, or reauthorize, one account.
    Did {
        did: String,
        #[serde(default)]
        action: Option<String>,
        #[serde(default)]
        target: Option<String>,
    },
}

impl Txn {
    pub fn expired(&self, now: i64) -> bool {
        now >= self.expires_at
    }
}

/// A stored external credential.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Cred {
    /// Opaque local id.
    pub id: String,
    pub provider: ProviderId,
    /// The provider's stable identity.
    pub subject: String,
    /// A label for the credential list (email, or `0x…`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub created_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<i64>,
    /// Provider token material needed later (Apple), sealed at rest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealed_token: Option<String>,
}

impl Cred {
    pub fn auth_ref(&self) -> String {
        cred_ref(self.provider, &self.subject)
    }
}

/// One account's credentials.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Creds {
    #[serde(default)]
    pub list: Vec<Cred>,
}

impl Creds {
    pub fn has(&self, provider: ProviderId, subject: &str) -> bool {
        self.list.iter().any(|c| c.provider == provider && c.subject == subject)
    }

    /// Whether any credential's `auth_cred` reference is still live.
    pub fn ref_live(&self, auth_ref: &str) -> bool {
        self.list.iter().any(|c| c.auth_ref() == auth_ref)
    }
}

// --------------------------------------------------------------- transactions

fn row(_routing: &str, name: &str, val: Option<Bytes>) -> Op {
    Op::put(name, val)
}

/// Write a transaction row, unguarded (a fresh start, or an idempotent
/// rewrite). Goes through the owner's conditional-write lock, as every
/// private row that a conditional write might race must.
pub async fn put_txn(app: &App, txn: &Txn) -> XResult<()> {
    let val = Bytes::from(serde_json::to_vec(txn).expect("serializable"));
    let out = app.private_cas(&txn_routing(&txn.id), Vec::new(), vec![row(TXN_ROW, TXN_ROW, Some(val))]).await?;
    if !out.applied {
        return Err(XrpcError::internal("unconditional transaction write refused"));
    }
    Ok(())
}

pub async fn load_txn(app: &App, id: &str) -> XResult<Option<Txn>> {
    match app.get_private(&txn_routing(id), TXN_ROW).await? {
        None => Ok(None),
        Some(b) => serde_json::from_slice(&b).map(Some).map_err(XrpcError::from_err),
    }
}

/// The row plus the bytes read, for a compare-and-set rewrite.
pub async fn load_txn_raw(app: &App, id: &str) -> XResult<Option<(Txn, Bytes)>> {
    match app.get_private(&txn_routing(id), TXN_ROW).await? {
        None => Ok(None),
        Some(b) => {
            let t = serde_json::from_slice(&b).map_err(XrpcError::from_err)?;
            Ok(Some((t, b)))
        }
    }
}

/// Replace the row only if it is still `read` (None = absent). Ok(false):
/// someone else got there first.
pub async fn save_txn(app: &App, id: &str, read: Option<Bytes>, txn: Option<&Txn>) -> XResult<bool> {
    let val = txn.map(|t| Bytes::from(serde_json::to_vec(t).expect("serializable")));
    let out =
        app.private_cas(&txn_routing(id), vec![Cond::eq(TXN_ROW, read)], vec![row(TXN_ROW, TXN_ROW, val)]).await?;
    Ok(out.applied)
}

// ----------------------------------------------------------------- credentials

pub async fn load_creds(app: &App, did: &str) -> XResult<(Creds, Option<Bytes>)> {
    let raw = app.get_private(did, CREDS_ROW).await?;
    let creds = match &raw {
        None => Creds::default(),
        Some(b) => serde_json::from_slice(b).map_err(XrpcError::from_err)?,
    };
    Ok((creds, raw))
}

pub async fn creds_has(app: &App, did: &str, provider: ProviderId, subject: &str) -> XResult<bool> {
    Ok(load_creds(app, did).await?.0.has(provider, subject))
}

/// Replace the credential row only if it is still `read`. An empty list
/// deletes the row.
pub async fn save_creds(app: &App, did: &str, read: Option<Bytes>, creds: &Creds) -> XResult<bool> {
    let val = (!creds.list.is_empty()).then(|| Bytes::from(serde_json::to_vec(creds).expect("serializable")));
    let out = app.private_cas(did, vec![Cond::eq(CREDS_ROW, read)], vec![row(did, CREDS_ROW, val)]).await?;
    Ok(out.applied)
}

/// Whether a session's `auth_cred` reference still names a live credential.
pub async fn ref_live(app: &App, did: &str, auth_ref: &str) -> XResult<bool> {
    Ok(load_creds(app, did).await?.0.ref_live(auth_ref))
}

// ------------------------------------------------------------ subject claims

fn subject_path(app: &App, provider: ProviderId, subject: &str) -> object_store::path::Path {
    let h = hex::encode(crate::oauth::util::sha256(subject.as_bytes()));
    object_store::path::Path::from(format!("{}/authsub/{}/{h}", app.store.prefix, provider.as_str()))
}

/// The DID that holds an external identity, if any.
pub async fn did_for_subject(app: &App, provider: ProviderId, subject: &str) -> XResult<Option<String>> {
    Ok(super::server::read_claim(app, &subject_path(app, provider, subject)).await?.map(|(h, _, _)| h))
}

/// Reserve an external identity for `did`. Ok(true): the claim is ours (now
/// or already). Ok(false): another account holds it and still stands on it.
///
/// A different holder keeps its claim while its credential row still has the
/// subject; otherwise the claim is taken over only once it is older than the
/// stale-claim grace, so a holder whose account write is still in flight is
/// not robbed.
pub async fn claim_subject(app: &App, provider: ProviderId, subject: &str, did: &str) -> XResult<bool> {
    let path = subject_path(app, provider, subject);
    let payload = || PutPayload::from(did.as_bytes().to_vec());
    let grace = super::server::claim_grace(app);
    for _ in 0..3 {
        let create = PutOptions { mode: PutMode::Create, ..Default::default() };
        match app.store.raw.put_opts(&path, payload(), create).await {
            Ok(_) => return Ok(true),
            Err(object_store::Error::AlreadyExists { .. }) => {}
            Err(e) => return Err(XrpcError::from_err(e)),
        }
        // Released meanwhile: try the create again.
        let Some((holder, version, age)) = super::server::read_claim(app, &path).await? else { continue };
        if holder == did {
            return Ok(true);
        }
        let held = match super::internal::account_anywhere(app, &holder).await {
            Ok(_) => creds_has(app, &holder, provider, subject).await?,
            Err(e) if e.error == "AccountNotFound" => false,
            Err(e) => return Err(e),
        };
        if held {
            return Ok(false);
        }
        if age < grace {
            return Ok(false);
        }
        if version.e_tag.is_none() && version.version.is_none() {
            return Ok(false);
        }
        let swap = PutOptions { mode: PutMode::Update(version), ..Default::default() };
        match app.store.raw.put_opts(&path, payload(), swap).await {
            Ok(_) => {
                tracing::info!(%did, %holder, provider = provider.as_str(), "took over a stale external-identity claim");
                return Ok(true);
            }
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

/// Release a claim this DID holds. Best-effort, like the handle/email ones.
pub async fn release_subject(app: &App, provider: ProviderId, subject: &str, did: &str) {
    match did_for_subject(app, provider, subject).await {
        Ok(Some(h)) if h == did => {
            if let Err(e) = super::server::delete_claim(app, &subject_path(app, provider, subject)).await {
                tracing::warn!(%did, provider = provider.as_str(), "failed to release external-identity claim: {}", e.message);
            }
        }
        Ok(_) => {}
        Err(e) => tracing::warn!(%did, "external-identity claim lookup failed: {}", e.message),
    }
}

/// Attach a credential to an account: reserve the subject globally, then
/// write the DID's credential row. An interrupted attach leaves the subject
/// reserved but with no credential row, which never authenticates and is
/// reclaimed by the same DID on retry.
pub async fn attach_cred(app: &App, did: &str, ident: &VerifiedIdentity) -> XResult<Cred> {
    if !claim_subject(app, ident.provider, &ident.subject, did).await? {
        return Err(XrpcError {
            status: StatusCode::CONFLICT,
            error: "AuthIdentityTaken".into(),
            message: format!(
                "That {} account is already linked to another account here. Sign in to it and remove the link first.",
                ident.provider.label()
            ),
        });
    }
    let _g = crate::totp::lock(did).await;
    for _ in 0..8 {
        let (mut creds, raw) = load_creds(app, did).await?;
        if let Some(existing) = creds.list.iter().find(|c| c.provider == ident.provider && c.subject == ident.subject) {
            return Ok(existing.clone());
        }
        let cred = Cred {
            id: hex::encode(rand::random::<[u8; 12]>()),
            provider: ident.provider,
            subject: ident.subject.clone(),
            label: ident.label.clone().or_else(|| ident.email.as_ref().map(|e| e.address.clone())),
            created_at: ident.verified_at,
            last_used_at: None,
            sealed_token: ident.sealed_token.clone(),
        };
        creds.list.push(cred.clone());
        if save_creds(app, did, raw, &creds).await? {
            return Ok(cred);
        }
    }
    Err(super::server::cas_conflict())
}

/// Detach a credential: revoke the DID's row first (so nothing can sign in
/// with it), then release the global claim. Returns what was removed.
pub async fn detach_cred(app: &App, did: &str, id: &str) -> XResult<Option<Cred>> {
    let _g = crate::totp::lock(did).await;
    for _ in 0..8 {
        let (mut creds, raw) = load_creds(app, did).await?;
        let Some(pos) = creds.list.iter().position(|c| c.id == id) else { return Ok(None) };
        let gone = creds.list.remove(pos);
        if !save_creds(app, did, raw, &creds).await? {
            continue;
        }
        release_subject(app, gone.provider, &gone.subject, did).await;
        return Ok(Some(gone));
    }
    Err(super::server::cas_conflict())
}

// -------------------------------------------------------------------- grants

/// One sensitive operation, approved by a fresh proof.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Grant {
    pub did: String,
    /// The operation this grant authorizes (server-chosen).
    pub action: String,
    /// The object it authorizes it on, when the operation names one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    pub exp: i64,
    /// The browser that approved it, when the approval came from a browser.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
}

/// A grant's own routing key, so the expiry sweep finds it without walking
/// every account's rows. The DID it belongs to is checked from the value.
pub fn grant_routing(id: &str) -> String {
    format!("auth:grant:{id}")
}

const GRANT_ROW: &str = "g";

pub fn new_grant_id() -> String {
    crate::oauth::util::random_id("grant-", 16)
}

pub async fn put_grant(app: &App, id: &str, g: &Grant) -> XResult<()> {
    let val = Bytes::from(serde_json::to_vec(g).expect("serializable"));
    let routing = grant_routing(id);
    let out = app.private_cas(&routing, Vec::new(), vec![row(&routing, GRANT_ROW, Some(val))]).await?;
    if !out.applied {
        return Err(XrpcError::internal("unconditional grant write refused"));
    }
    Ok(())
}

/// Read a grant without consuming it, with the bytes to guard a later
/// consume. Checking first matters: presenting a grant for the wrong object
/// must not burn the approval.
pub async fn load_grant(app: &App, id: &str) -> XResult<Option<(Grant, Bytes)>> {
    match app.get_private(&grant_routing(id), GRANT_ROW).await? {
        None => Ok(None),
        Some(b) => {
            let g = serde_json::from_slice(&b).map_err(XrpcError::from_err)?;
            Ok(Some((g, b)))
        }
    }
}

/// Consume exactly the grant that was read. Ok(false): it changed or went
/// meanwhile, so this caller did not spend it.
pub async fn consume_grant(app: &App, id: &str, read: Bytes) -> XResult<bool> {
    let routing = grant_routing(id);
    let out =
        app.private_cas(&routing, vec![Cond::eq(GRANT_ROW, Some(read))], vec![row(&routing, GRANT_ROW, None)]).await?;
    Ok(out.applied)
}
