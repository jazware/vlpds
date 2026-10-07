//! Durable OAuth rows (key layout in mod.rs).

use super::client::ClientAuth;
use super::util::{b64u, b64u_decode, hmac_sha256, now_secs, random_id, sha256_b64u};
use super::OAuthError;
use crate::xrpc::cas::{Cond, Op};
use crate::xrpc::App;
use bytes::Bytes;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

pub const REQUEST_URI_PREFIX: &str = "urn:ietf:params:oauth:request_uri:";

/// None deletes. Goes through the owner's conditional-write lock with no
/// condition, so a blind write (a session revoked, a request consumed) never
/// slips between the check and the write of a conditional one.
pub(super) async fn put<T: Serialize>(app: &App, routing: &str, name: &str, v: Option<&T>) -> Result<(), OAuthError> {
    put_if(app, routing, name, v, Vec::new()).await.and_then(|applied| {
        applied.then_some(()).ok_or_else(|| OAuthError::server_error("unconditional write refused"))
    })
}

/// Ok(false): a condition failed and nothing was written.
pub(super) async fn put_if<T: Serialize>(
    app: &App,
    routing: &str,
    name: &str,
    v: Option<&T>,
    conds: Vec<Cond>,
) -> Result<bool, OAuthError> {
    let val = v.map(|v| Bytes::from(serde_json::to_vec(v).expect("serialize")));
    let out = app.private_cas(routing, conds, vec![Op::put(name, val)]).await?;
    Ok(out.applied)
}

pub(super) async fn get<T: DeserializeOwned>(app: &App, routing: &str, name: &str) -> Result<Option<T>, OAuthError> {
    match app.get_private(routing, name).await? {
        None => Ok(None),
        Some(b) => serde_json::from_slice(&b)
            .map(Some)
            .map_err(|e| OAuthError::server_error(&format!("corrupt oauth record: {e}"))),
    }
}

/// Striped node-local locks for read-modify-writes of one object. Requests
/// are routed to the object's owner, so they serialize cluster-wide.
pub async fn lock(app: &App, key: &str) -> tokio::sync::OwnedMutexGuard<()> {
    let h = super::util::sha256(key.as_bytes());
    let n = super::util::node_state(app);
    n.locks[h[0] as usize].clone().lock_owned().await
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthParams {
    pub client_id: String,
    pub response_type: String,
    pub redirect_uri: String,
    pub scope: String,
    #[serde(default)]
    pub state: Option<String>,
    pub code_challenge: String,
    pub code_challenge_method: String,
    #[serde(default)]
    pub response_mode: Option<String>,
    #[serde(default)]
    pub prompt: Option<String>,
    #[serde(default)]
    pub login_hint: Option<String>,
    pub dpop_jkt: String,
    #[serde(default)]
    pub display: Option<String>,
    #[serde(default)]
    pub ui_locales: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequestData {
    pub client_id: String,
    pub client_auth: ClientAuth,
    pub params: AuthParams,
    pub created_at: i64,
    pub expires_at: i64,
    #[serde(default)]
    pub device_id: Option<String>,
    /// Set once the user approved the request.
    #[serde(default)]
    pub did: Option<String>,
    #[serde(default)]
    pub code_hash: Option<String>,
    /// The session the code created, kept for reuse detection.
    #[serde(default)]
    pub consumed: Option<(String, String)>,
    /// Of the approving login: a password change or takedown after the
    /// approval voids the code.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub auth_epoch: String,
    /// The passkey that signed this in (`xrpc::passkeys::auth_ref`):
    /// removing it ends what it signed in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_cred: Option<String>,
    /// `--spaces`: the collections each space type declared, by type, as
    /// resolved for the consent screen. A bare grant that writes gets these
    /// and nothing wider, at the code exchange and every refresh.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub space_collections: Option<std::collections::BTreeMap<String, Vec<String>>>,
}

pub fn req_routing(id: &str) -> String {
    format!("oauth:req:{id}")
}

pub fn new_request_id() -> String {
    random_id("req-", 16)
}

/// Its row lands in a partition this node owns, so the PAR write is local
/// and the rest of the flow, routed by the id, comes back here.
pub fn new_local_request_id(app: &App) -> String {
    for _ in 0..1_000 {
        let id = new_request_id();
        let r = req_routing(&id);
        if app.remote_owner(&r).is_none() && app.partition(&r).is_ok() {
            return id;
        }
    }
    new_request_id()
}

pub fn request_uri(id: &str) -> String {
    format!("{REQUEST_URI_PREFIX}{id}")
}

fn valid_id(id: &str, prefix: &str) -> bool {
    id.starts_with(prefix) && id.len() < 64 && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

pub fn request_id_from_uri(uri: &str) -> Option<&str> {
    let id = uri.strip_prefix(REQUEST_URI_PREFIX)?;
    valid_id(id, "req-").then_some(id)
}

pub async fn get_request(app: &App, id: &str) -> Result<Option<RequestData>, OAuthError> {
    get(app, &req_routing(id), "oauth/req").await
}

pub async fn put_request(app: &App, id: &str, r: Option<&RequestData>) -> Result<(), OAuthError> {
    put(app, &req_routing(id), "oauth/req", r).await
}

/// Codes embed their request id, so lookups need no index.
pub fn new_code(request_id: &str) -> String {
    format!("cod-{}.{}", b64u(request_id.as_bytes()), random_id("", 32))
}

pub fn code_request_id(code: &str) -> Option<String> {
    let rest = code.strip_prefix("cod-")?;
    let (id, _) = rest.split_once('.')?;
    let id = String::from_utf8(b64u_decode(id)?).ok()?;
    id.starts_with("req-").then_some(id)
}

pub fn hash_secret(s: &str) -> String {
    sha256_b64u(s.as_bytes())
}

/// False if used in the last 24 h. The durable marker covers earlier uses,
/// and a claim at the marker's owner settles concurrent ones.
pub async fn claim_code_challenge(app: &App, challenge: &str) -> Result<bool, OAuthError> {
    let routing = format!("oauth:cc:{}", hash_secret(challenge));
    let now = now_secs();
    if let Some(at) = get::<i64>(app, &routing, "oauth/cc").await? {
        if now - at < super::CODE_CHALLENGE_REPLAY_TIMEFRAME {
            return Ok(false);
        }
    }
    // guards the window between the read above and the put
    let key = format!("cc:{routing}");
    if !crate::xrpc::internal::claim_transient_anywhere(app, &routing, &key, now + 60).await? {
        return Ok(false);
    }
    let r = put(app, &routing, "oauth/cc", Some(&now)).await;
    let _ = crate::xrpc::internal::release_replay_anywhere(app, &routing, &key).await;
    r.map(|_| true)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub did: String,
    pub client_id: String,
    pub client_auth: ClientAuth,
    pub dpop_jkt: String,
    /// As approved: may contain `include:` scopes.
    pub scope: String,
    /// `include:` expanded.
    pub token_scope: String,
    pub created_at: i64,
    /// Last token issuance: the refresh-token lifetime counts from here.
    pub updated_at: i64,
    pub expires_at: i64,
    /// The current access token's `jti`; older access tokens are rejected.
    pub token_id: String,
    /// Tokens of older generations are replays.
    pub refresh_gen: u64,
    pub refresh_salt: String,
    #[serde(default)]
    pub device_id: Option<String>,
    #[serde(default)]
    pub request_id: Option<String>,
    /// The passkey that signed this in (`xrpc::passkeys::auth_ref`):
    /// removing it ends what it signed in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_cred: Option<String>,
    /// `--spaces`: the collections each space type declared, by type, as
    /// resolved for the consent screen. A bare grant that writes gets these
    /// and nothing wider, at the code exchange and every refresh.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub space_collections: Option<std::collections::BTreeMap<String, Vec<String>>>,
    /// The client address of the code exchange, and of the latest token
    /// issuance (as rate limits resolve it), for the console.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
}

pub fn session_key(id: &str) -> String {
    format!("oauth/ses/{id}")
}

pub async fn get_session(app: &App, did: &str, id: &str) -> Result<Option<Session>, OAuthError> {
    get(app, did, &session_key(id)).await
}

/// The stored bytes are the condition of its rewrite.
pub async fn get_session_raw(app: &App, did: &str, id: &str) -> Result<Option<(Session, Bytes)>, OAuthError> {
    match app.get_private(did, &session_key(id)).await? {
        None => Ok(None),
        Some(b) => serde_json::from_slice(&b)
            .map(|s| Some((s, b)))
            .map_err(|e| OAuthError::server_error(&format!("corrupt oauth record: {e}"))),
    }
}

pub enum SessionGuard {
    /// A refresh: not revoked or rotated meanwhile.
    Row(Bytes),
    /// A code exchange: no such row yet, and the credential epoch is still
    /// the approving login's.
    New { auth_epoch: String },
}

/// Ok(false): revoked or rotated meanwhile, nothing written.
pub async fn put_session_if(app: &App, s: &Session, guard: SessionGuard) -> Result<bool, OAuthError> {
    let name = session_key(&s.id);
    let conds = match guard {
        SessionGuard::Row(b) => vec![Cond::eq(&name, Some(b))],
        SessionGuard::New { auth_epoch } => vec![Cond::eq(&name, None), crate::xrpc::auth_epoch_cond(&auth_epoch)],
    };
    put_if(app, &s.did, &name, Some(s), conds).await
}

pub async fn delete_session(app: &App, did: &str, id: &str) -> Result<(), OAuthError> {
    put::<Session>(app, did, &session_key(id), None).await
}

pub async fn list_sessions(app: &App, did: &str) -> Result<Vec<Session>, OAuthError> {
    let rows = crate::xrpc::internal::scan_private_anywhere(app, did, "oauth/ses/").await?;
    Ok(rows.iter().filter_map(|(_, v)| serde_json::from_slice::<Session>(v).ok()).collect())
}

/// Also replaces the credential epoch in the same write, so neither a
/// refresh nor a code exchange racing this can bring a session back, and
/// device logins and codes approved before it are void. Returns how many
/// sessions were revoked.
pub async fn revoke_all_sessions(app: &App, did: &str) -> Result<usize, OAuthError> {
    let ops = vec![
        crate::xrpc::new_auth_epoch_op(),
        Op::DeletePrefix { prefix: "oauth/ses/".into() },
        Op::DeletePrefix { prefix: crate::xrpc::TRUST_PREFIX.into() },
    ];
    let out = app.private_cas(did, Vec::new(), ops).await?;
    Ok(out.deleted.len())
}

/// `ref-{b64u(did)}.{session id}.{generation}.{mac}`: the routing info
/// avoids a token index, and the per-session salt in the MAC means tokens
/// can't be minted from the server secret alone.
pub fn refresh_token(key: &[u8; 32], s: &Session) -> String {
    let mac = refresh_mac(key, s, s.refresh_gen);
    format!("ref-{}.{}.{}.{}", b64u(s.did.as_bytes()), s.id, s.refresh_gen, b64u(mac))
}

fn refresh_mac(key: &[u8; 32], s: &Session, generation: u64) -> [u8; 32] {
    hmac_sha256(key, &[s.did.as_bytes(), s.id.as_bytes(), &generation.to_be_bytes(), s.refresh_salt.as_bytes()])
}

pub struct ParsedRefresh {
    pub did: String,
    pub session_id: String,
    pub generation: u64,
    mac: Vec<u8>,
}

pub fn parse_refresh_token(t: &str) -> Option<ParsedRefresh> {
    let mut it = t.strip_prefix("ref-")?.split('.');
    let did = String::from_utf8(b64u_decode(it.next()?)?).ok()?;
    let session_id = it.next()?.to_string();
    let generation = it.next()?.parse().ok()?;
    let mac = b64u_decode(it.next()?)?;
    if it.next().is_some() || !did.starts_with("did:") || !session_id.starts_with("ses-") {
        return None;
    }
    Some(ParsedRefresh { did, session_id, generation, mac })
}

impl ParsedRefresh {
    /// Issued for `s`, any generation.
    pub fn authentic(&self, key: &[u8; 32], s: &Session) -> bool {
        crate::auth::ct_eq(&refresh_mac(key, s, self.generation), &self.mac)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeviceAccount {
    pub did: String,
    pub authenticated_at: i64,
    /// At the password check: a password change or takedown signs the
    /// device out.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub auth_epoch: String,
    /// The passkey that signed this in (`xrpc::passkeys::auth_ref`):
    /// removing it ends what it signed in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_cred: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Device {
    pub id: String,
    pub created_at: i64,
    pub last_seen_at: i64,
    #[serde(default)]
    pub user_agent: Option<String>,
    #[serde(default)]
    pub accounts: Vec<DeviceAccount>,
    /// Password verified, second factor pending: (did, at).
    #[serde(default)]
    pub pending_2fa: Option<(String, i64)>,
    /// Past a few, the password step must be redone.
    #[serde(default)]
    pub pending_2fa_failures: u32,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub pending_2fa_epoch: String,
    /// Kept past the idle expiry until then: an account trusts this browser
    /// (`xrpc::signin`), and the trust is keyed by this id.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub trusted_until: i64,
}

fn is_zero(v: &i64) -> bool {
    *v == 0
}

pub fn new_device_id() -> String {
    random_id("dev-", 16)
}

pub fn valid_device_id(id: &str) -> bool {
    valid_id(id, "dev-")
}

pub async fn get_device(app: &App, id: &str) -> Result<Option<Device>, OAuthError> {
    get(app, &format!("oauth:dev:{id}"), "oauth/dev").await
}

pub async fn put_device(app: &App, d: &Device) -> Result<(), OAuthError> {
    put(app, &format!("oauth:dev:{}", d.id), "oauth/dev", Some(d)).await
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Authorization {
    pub client_id: String,
    pub scopes: Vec<String>,
    pub updated_at: i64,
}

fn authz_key(client_id: &str) -> String {
    format!("oauth/authz/{}", hash_secret(client_id))
}

pub async fn get_authorization(app: &App, did: &str, client_id: &str) -> Result<Option<Authorization>, OAuthError> {
    get(app, did, &authz_key(client_id)).await
}

pub async fn put_authorization(app: &App, did: &str, a: &Authorization) -> Result<(), OAuthError> {
    put(app, did, &authz_key(&a.client_id), Some(a)).await
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredLexicon {
    pub uri: String,
    pub doc: serde_json::Value,
    pub updated_at: i64,
}

pub async fn get_lexicon(app: &App, nsid: &str) -> Result<Option<StoredLexicon>, OAuthError> {
    get(app, &format!("oauth:lex:{nsid}"), "oauth/lex").await
}

pub async fn put_lexicon(app: &App, nsid: &str, l: &StoredLexicon) -> Result<(), OAuthError> {
    put(app, &format!("oauth:lex:{nsid}"), "oauth/lex", Some(l)).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_and_refresh_tokens() {
        let id = new_request_id();
        let code = new_code(&id);
        assert_eq!(code_request_id(&code).as_deref(), Some(id.as_str()));
        assert!(code_request_id("cod-garbage").is_none());
        let s = Session {
            id: random_id("ses-", 16),
            did: "did:plc:abcdefghijklmnopqrstuvwx".into(),
            client_id: "c".into(),
            client_auth: ClientAuth::None,
            dpop_jkt: "j".into(),
            scope: "atproto".into(),
            token_scope: "atproto".into(),
            created_at: 0,
            updated_at: 0,
            expires_at: 0,
            token_id: "t".into(),
            refresh_gen: 3,
            refresh_salt: "salt".into(),
            device_id: None,
            request_id: None,
            auth_cred: None,
            space_collections: None,
            created_ip: None,
            ip: None,
        };

        let key = [7u8; 32];
        let t = refresh_token(&key, &s);
        let p = parse_refresh_token(&t).unwrap();
        assert_eq!(p.did, s.did);
        assert_eq!(p.session_id, s.id);
        assert_eq!(p.generation, 3);
        assert!(p.authentic(&key, &s));
        assert!(!p.authentic(&[8u8; 32], &s));
        let mut forged = parse_refresh_token(&t).unwrap();
        forged.generation = 4;
        assert!(!forged.authentic(&key, &s));
    }
}
