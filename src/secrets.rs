//! Secrets at rest (DESIGN.md "Secrets at rest"): recoverable key material
//! is stored only wrapped under a key-encryption key (KEK), with its purpose
//! and subject as authenticated data so a blob copied into another row or
//! used for another purpose does not unwrap. Wrapped form: `vw1.{kid}.{b64url}`.
//!
//! Wraps (some reachable without an account) have their own, smaller permit
//! pool and never start the unwraps' fail-fast window, so a flood of them
//! can't starve or fail-fast cold signing-key unwraps.

use async_trait::async_trait;
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use prometheus::{register_histogram_vec, register_int_counter_vec, HistogramVec, IntCounterVec};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};
use vlsync_atproto::crypto::Keypair;
use zeroize::{Zeroize, Zeroizing};

mod vault;
pub use vault::{
    VaultAuth, VaultClient, VaultConfig, VaultTransit, DEFAULT_APPROLE_MOUNT, DEFAULT_K8S_JWT_FILE, DEFAULT_K8S_MOUNT,
};

const WRAP_VERSION: &str = "vw1";
/// Per KMS request, token fetch included.
const KMS_TIMEOUT: Duration = Duration::from_secs(5);
/// After a KMS request fails as unavailable, remote unwraps fail at once for
/// this long (one probe per interval goes through), so an outage doesn't
/// queue every cold write behind a timeout.
const KMS_BACKOFF: Duration = Duration::from_secs(1);
pub const DEFAULT_KMS_CONCURRENCY: usize = 64;

fn wrap_concurrency(n: usize) -> usize {
    (n / 4).max(1)
}

static KMS_REQUESTS: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "vlpds_kms_requests_total",
        "Key-encryption-key operations by backend (local, gcpkms, vault), op (wrap, unwrap) and result (ok, unavailable, rejected)",
        &["backend", "op", "result"]
    )
    .unwrap()
});
static KMS_SECONDS: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec!(
        "vlpds_kms_request_seconds",
        "Key-encryption-key operation latency by backend and op",
        &["backend", "op"],
        prometheus::exponential_buckets(0.00001, 2.0, 20).unwrap()
    )
    .unwrap()
});
static KEY_CACHE: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "vlpds_signing_key_cache_total",
        "Unwrapped signing-key cache lookups (hit, miss) and unwraps that failed (unavailable, rejected)",
        &["result"]
    )
    .unwrap()
});

#[derive(Debug, Clone, thiserror::Error)]
pub enum SecretError {
    /// Timeout, 5xx or auth failure: retry later.
    #[error("key service unavailable: {0}")]
    Unavailable(String),
    /// Wrong KEK, wrong purpose/subject, or corrupt.
    #[error("wrapped secret rejected: {0}")]
    Rejected(String),
    #[error("wrapped under unknown key-encryption key {0}")]
    UnknownKek(String),
    #[error("malformed wrapped secret")]
    Malformed,
}

impl SecretError {
    pub fn retryable(&self) -> bool {
        matches!(self, SecretError::Unavailable(_))
    }
}

/// Part of the authenticated data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Purpose {
    SigningKey,
    /// Subject: its did:key.
    ReservedKey,
    Totp,
    /// Subject: `plc::ROTATION_KEY_SUBJECT`.
    PlcRotationKey,
}

impl Purpose {
    pub fn label(self) -> &'static str {
        match self {
            Purpose::SigningKey => "repo-signing-key",
            Purpose::ReservedKey => "reserved-signing-key",
            Purpose::Totp => "totp-secret",
            Purpose::PlcRotationKey => "plc-rotation-key",
        }
    }
}

fn aad(purpose: Purpose, subject: &str) -> Vec<u8> {
    [b"vlpds-secret-v1\0", purpose.label().as_bytes(), b"\0", subject.as_bytes()].concat()
}

/// `stale`: wrapped under a KEK (or KMS key version) other than the current
/// one.
pub struct Unwrapped {
    pub plaintext: Zeroizing<Vec<u8>>,
    pub stale: bool,
}

#[async_trait]
pub trait KeyWrapper: Send + Sync {
    fn kid(&self) -> &str;
    fn backend(&self) -> &'static str;
    /// A network round trip: limited and failing fast.
    fn remote(&self) -> bool;
    /// Checks a remote key service can serve as this KEK at all (Vault:
    /// that it enforces the AAD and the policy allows the calls). Startup
    /// runs it on every KEK: a non-retryable error stops the node.
    async fn self_test(&self) -> Result<(), SecretError> {
        Ok(())
    }
    /// Asks the key service for the current key's latest version, where
    /// staleness depends on it (Vault Transit).
    async fn refresh_version(&self) -> Result<(), SecretError> {
        Ok(())
    }
    /// The key version a ciphertext names, read without unwrapping it.
    fn ciphertext_version(&self, _ct: &[u8]) -> Option<u64> {
        None
    }
    async fn wrap(&self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, SecretError>;
    async fn unwrap(&self, aad: &[u8], ciphertext: &[u8]) -> Result<Unwrapped, SecretError>;
}

/// Never printed.
#[derive(Clone, zeroize::ZeroizeOnDrop)]
pub struct KekBytes([u8; 32]);

impl std::fmt::Debug for KekBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "KekBytes({})", local_kid(&self.0))
    }
}

impl PartialEq for KekBytes {
    fn eq(&self, o: &KekBytes) -> bool {
        self.0.iter().zip(o.0.iter()).fold(0u8, |a, (x, y)| a | (x ^ y)) == 0
    }
}

impl KekBytes {
    pub fn new(b: [u8; 32]) -> KekBytes {
        KekBytes(b)
    }

    pub fn random() -> KekBytes {
        KekBytes(rand::random())
    }

    /// 64 hex chars or any base64 flavour.
    pub fn parse(s: &str) -> anyhow::Result<KekBytes> {
        let s = Zeroizing::new(s.trim().to_string());
        let mut raw = Zeroizing::new(if s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()) {
            hex::decode(s.as_bytes())?
        } else {
            let b64 = s.trim_end_matches('=');
            base64::engine::general_purpose::STANDARD_NO_PAD
                .decode(b64)
                .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(b64))
                .map_err(|_| anyhow::anyhow!("KEK must be 32 bytes as 64 hex chars or base64"))?
        });
        anyhow::ensure!(raw.len() == 32, "KEK must be 32 bytes (got {})", raw.len());
        let mut k = [0u8; 32];
        k.copy_from_slice(&raw);
        raw.zeroize();
        Ok(KekBytes(k))
    }

    /// 32 raw bytes, or the text forms of [`parse`](Self::parse).
    pub fn from_file(path: &std::path::Path) -> anyhow::Result<KekBytes> {
        let b = Zeroizing::new(
            std::fs::read(path).map_err(|e| anyhow::anyhow!("reading KEK file {}: {e}", path.display()))?,
        );
        if b.len() == 32 {
            let mut k = [0u8; 32];
            k.copy_from_slice(&b);
            return Ok(KekBytes(k));
        }
        let s = std::str::from_utf8(&b)
            .map_err(|_| anyhow::anyhow!("KEK file {} is neither 32 raw bytes nor text", path.display()))?;
        KekBytes::parse(s)
    }

    pub fn kid(&self) -> String {
        local_kid(&self.0)
    }
}

fn local_kid(k: &[u8; 32]) -> String {
    let h = Sha256::digest([b"vlpds-kek-id\0".as_slice(), k].concat());
    format!("L{}", hex::encode(&h[..8]))
}

/// Derived from a public string: it protects nothing, and is refused
/// outside dev mode.
pub fn dev_kek() -> KekBytes {
    KekBytes(Sha256::digest(b"vlpds dev-mode KEK: not a secret").into())
}

/// XChaCha20-Poly1305, random 192-bit nonce: `nonce (24) ‖ ciphertext ‖ tag`.
pub struct LocalKek {
    kid: String,
    aead: XChaCha20Poly1305,
}

impl LocalKek {
    pub fn new(k: &KekBytes) -> LocalKek {
        LocalKek { kid: k.kid(), aead: XChaCha20Poly1305::new((&k.0).into()) }
    }

    pub fn wrap_sync(&self, aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let nonce: [u8; 24] = rand::random();
        let ct = self
            .aead
            .encrypt(&XNonce::from(nonce), Payload { msg: plaintext, aad })
            .expect("xchacha20poly1305 encrypt");
        [nonce.as_slice(), &ct].concat()
    }

    pub fn unwrap_sync(&self, aad: &[u8], ct: &[u8]) -> Result<Zeroizing<Vec<u8>>, SecretError> {
        if ct.len() < 24 + 16 {
            return Err(SecretError::Malformed);
        }
        let (nonce, body) = ct.split_at(24);
        let nonce: [u8; 24] = nonce.try_into().expect("24 bytes");
        self.aead
            .decrypt(&XNonce::from(nonce), Payload { msg: body, aad })
            .map(Zeroizing::new)
            .map_err(|_| SecretError::Rejected(format!("authentication failed under {}", self.kid)))
    }
}

#[async_trait]
impl KeyWrapper for LocalKek {
    fn kid(&self) -> &str {
        &self.kid
    }
    fn backend(&self) -> &'static str {
        "local"
    }
    fn remote(&self) -> bool {
        false
    }
    async fn wrap(&self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, SecretError> {
        Ok(self.wrap_sync(aad, plaintext))
    }
    async fn unwrap(&self, aad: &[u8], ct: &[u8]) -> Result<Unwrapped, SecretError> {
        Ok(Unwrapped { plaintext: self.unwrap_sync(aad, ct)?, stale: false })
    }
}

#[derive(Clone)]
pub enum GcpToken {
    /// The metadata server's token endpoint.
    Metadata(String),
    ServiceAccount(Arc<ServiceAccount>),
    /// Tests, or an operator running an admin task off-cluster.
    Static(String),
}

/// Redacts a static token.
impl std::fmt::Debug for GcpToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GcpToken::Metadata(u) => f.debug_tuple("Metadata").field(u).finish(),
            GcpToken::ServiceAccount(sa) => f.debug_tuple("ServiceAccount").field(sa).finish(),
            GcpToken::Static(_) => f.debug_tuple("Static").field(&"<redacted>").finish(),
        }
    }
}

impl GcpToken {
    /// `file`, else `GOOGLE_APPLICATION_CREDENTIALS`, else the metadata server.
    pub fn from_credentials(file: Option<&std::path::Path>) -> anyhow::Result<GcpToken> {
        let env =
            std::env::var_os("GOOGLE_APPLICATION_CREDENTIALS").filter(|v| !v.is_empty()).map(std::path::PathBuf::from);
        match file.map(std::path::Path::to_path_buf).or(env) {
            Some(p) => Ok(GcpToken::ServiceAccount(ServiceAccount::from_file(&p)?)),
            None => Ok(GcpToken::default()),
        }
    }
}

const CLOUD_KMS_SCOPE: &str = "https://www.googleapis.com/auth/cloudkms";
/// When the key file names none.
const GOOGLE_TOKEN_URI: &str = "https://oauth2.googleapis.com/token";

/// A service-account JSON key, exchanged for access tokens with the RFC 7523
/// JWT bearer grant. The token cache is shared by every Cloud KMS key using
/// this account.
pub struct ServiceAccount {
    pub client_email: String,
    pub token_uri: String,
    key_id: Option<String>,
    key: ring::signature::RsaKeyPair,
    cached: tokio::sync::Mutex<Option<(String, Instant)>>,
}

impl std::fmt::Debug for ServiceAccount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceAccount")
            .field("client_email", &self.client_email)
            .field("token_uri", &self.token_uri)
            .finish_non_exhaustive()
    }
}

impl ServiceAccount {
    pub fn from_file(path: &std::path::Path) -> anyhow::Result<Arc<ServiceAccount>> {
        let text = Zeroizing::new(
            std::fs::read_to_string(path).map_err(|e| anyhow::anyhow!("GCP credentials {}: {e}", path.display()))?,
        );
        ServiceAccount::from_json(&text).map_err(|e| e.context(format!("GCP credentials {}", path.display())))
    }

    pub fn from_json(text: &str) -> anyhow::Result<Arc<ServiceAccount>> {
        #[derive(serde::Deserialize)]
        struct KeyFile {
            #[serde(rename = "type")]
            kind: Option<String>,
            client_email: Option<String>,
            private_key: Option<String>,
            private_key_id: Option<String>,
            token_uri: Option<String>,
        }
        let f: KeyFile = serde_json::from_str(text).map_err(|e| anyhow::anyhow!("not a JSON key file: {e}"))?;
        anyhow::ensure!(
            f.kind.as_deref() == Some("service_account"),
            "only service-account key files are supported (\"type\": \"service_account\"), not {:?}",
            f.kind.as_deref().unwrap_or("(none)")
        );
        let client_email =
            f.client_email.filter(|e| !e.is_empty()).ok_or_else(|| anyhow::anyhow!("key file has no client_email"))?;
        let pem = Zeroizing::new(f.private_key.ok_or_else(|| anyhow::anyhow!("key file has no private_key"))?);
        let body: Zeroizing<String> =
            Zeroizing::new(pem.lines().filter(|l| !l.starts_with("-----")).map(str::trim).collect());
        let der = Zeroizing::new(
            base64::engine::general_purpose::STANDARD
                .decode(body.as_bytes())
                .map_err(|e| anyhow::anyhow!("private_key is not PEM: {e}"))?,
        );
        let key = ring::signature::RsaKeyPair::from_pkcs8(&der)
            .map_err(|e| anyhow::anyhow!("private_key is not a PKCS#8 RSA key: {e}"))?;
        Ok(Arc::new(ServiceAccount {
            client_email,
            token_uri: f.token_uri.filter(|u| !u.is_empty()).unwrap_or_else(|| GOOGLE_TOKEN_URI.into()),
            key_id: f.private_key_id.filter(|k| !k.is_empty()),
            key,
            cached: tokio::sync::Mutex::new(None),
        }))
    }

    /// `now`: Unix seconds.
    fn assertion(&self, now: u64) -> anyhow::Result<String> {
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let mut header = serde_json::json!({"alg": "RS256", "typ": "JWT"});
        if let Some(kid) = &self.key_id {
            header["kid"] = kid.as_str().into();
        }
        let claims = serde_json::json!({
            "iss": self.client_email,
            "scope": CLOUD_KMS_SCOPE,
            "aud": self.token_uri,
            "iat": now,
            "exp": now + 3600,
        });
        let msg = format!("{}.{}", b64.encode(header.to_string()), b64.encode(claims.to_string()));
        let mut sig = vec![0u8; self.key.public().modulus_len()];
        self.key
            .sign(&ring::signature::RSA_PKCS1_SHA256, &ring::rand::SystemRandom::new(), msg.as_bytes(), &mut sig)
            .map_err(|_| anyhow::anyhow!("RS256 signing failed"))?;
        Ok(format!("{msg}.{}", b64.encode(sig)))
    }

    async fn fetch(&self, http: &reqwest::Client) -> Result<(String, u64), SecretError> {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
        let jwt = self.assertion(now).map_err(|e| SecretError::Unavailable(format!("service-account token: {e}")))?;
        // the assertion is base64url and dots: nothing to escape
        let body = format!("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion={jwt}");
        let r = http
            .post(&self.token_uri)
            .header(reqwest::header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(body)
            .timeout(KMS_TIMEOUT)
            .send()
            .await
            .map_err(|e| SecretError::Unavailable(format!("service-account token: {e}")))?;
        let status = r.status();
        if !status.is_success() {
            let text = r.text().await.unwrap_or_default();
            return Err(SecretError::Unavailable(format!(
                "service-account token ({}): HTTP {status}: {}",
                self.client_email,
                truncate(&text)
            )));
        }
        let t: Tok = r.json().await.map_err(|e| SecretError::Unavailable(format!("service-account token: {e}")))?;
        Ok((t.access_token, t.expires_in))
    }
}

#[derive(serde::Deserialize)]
struct Tok {
    access_token: String,
    expires_in: u64,
}

/// Kept until a minute before it expires.
async fn cached_token<F>(
    cache: &tokio::sync::Mutex<Option<(String, Instant)>>,
    refresh: bool,
    fetch: F,
) -> Result<String, SecretError>
where
    F: std::future::Future<Output = Result<(String, u64), SecretError>>,
{
    let mut g = cache.lock().await;
    if let Some((t, exp)) = g.as_ref() {
        if !refresh && Instant::now() < *exp {
            return Ok(t.clone());
        }
    }
    let (token, expires_in) = fetch.await?;
    let exp = Instant::now() + Duration::from_secs(expires_in.saturating_sub(60).max(1));
    *g = Some((token.clone(), exp));
    Ok(token)
}

impl Default for GcpToken {
    fn default() -> GcpToken {
        let host = std::env::var("GCE_METADATA_HOST").unwrap_or_else(|_| "metadata.google.internal".into());
        GcpToken::Metadata(format!("http://{host}/computeMetadata/v1/instance/service-accounts/default/token"))
    }
}

pub const GCP_KMS_ENDPOINT: &str = "https://cloudkms.googleapis.com";

/// Symmetric `encrypt`/`decrypt` on one CryptoKey. The secret itself is the
/// KMS plaintext, so a bucket copy is useless without decrypt permission and
/// every unwrap is audited. KMS picks the version itself, so version
/// rotation needs no config change; `usedPrimary: false` marks a blob stale.
pub struct GcpKms {
    kid: String,
    name: String,
    endpoint: String,
    token: GcpToken,
    http: reqwest::Client,
    cached: tokio::sync::Mutex<Option<(String, Instant)>>,
}

impl GcpKms {
    pub fn new(name: &str, endpoint: &str, token: GcpToken) -> anyhow::Result<GcpKms> {
        anyhow::ensure!(
            name.starts_with("projects/") && name.contains("/cryptoKeys/") && !name.contains("/cryptoKeyVersions/"),
            "Cloud KMS key must be projects/P/locations/L/keyRings/R/cryptoKeys/K (no version): {name}"
        );
        let h = Sha256::digest(name.as_bytes());
        Ok(GcpKms {
            kid: format!("G{}", hex::encode(&h[..8])),
            name: name.to_string(),
            endpoint: endpoint.trim_end_matches('/').to_string(),
            token,
            http: vlsync_atproto::http::public().clone(),
            cached: tokio::sync::Mutex::new(None),
        })
    }

    async fn access_token(&self, refresh: bool) -> Result<String, SecretError> {
        match &self.token {
            GcpToken::Static(t) => Ok(t.clone()),
            GcpToken::ServiceAccount(sa) => cached_token(&sa.cached, refresh, sa.fetch(&self.http)).await,
            GcpToken::Metadata(url) => cached_token(&self.cached, refresh, self.metadata_token(url)).await,
        }
    }

    async fn metadata_token(&self, url: &str) -> Result<(String, u64), SecretError> {
        let r = self
            .http
            .get(url)
            .header("Metadata-Flavor", "Google")
            .timeout(KMS_TIMEOUT)
            .send()
            .await
            .map_err(|e| SecretError::Unavailable(format!("metadata token: {e}")))?;
        if !r.status().is_success() {
            return Err(SecretError::Unavailable(format!("metadata token: HTTP {}", r.status())));
        }
        let t: Tok = r.json().await.map_err(|e| SecretError::Unavailable(format!("metadata token: {e}")))?;
        Ok((t.access_token, t.expires_in))
    }

    async fn call(&self, op: &str, body: serde_json::Value) -> Result<serde_json::Value, SecretError> {
        let url = format!("{}/v1/{}:{op}", self.endpoint, self.name);
        for attempt in 0..2 {
            let token = self.access_token(attempt > 0).await?;
            let r = self
                .http
                .post(&url)
                .bearer_auth(token)
                .json(&body)
                .timeout(KMS_TIMEOUT)
                .send()
                .await
                .map_err(|e| SecretError::Unavailable(format!("cloud kms {op}: {e}")))?;
            let status = r.status();
            if status.is_success() {
                return r.json().await.map_err(|e| SecretError::Unavailable(format!("cloud kms {op}: {e}")));
            }
            let text = r.text().await.unwrap_or_default();
            match status.as_u16() {
                // an expired token: refresh once
                401 if attempt == 0 && !matches!(self.token, GcpToken::Static(_)) => continue,
                // wrong AAD, corrupt ciphertext, or a ciphertext of another key
                400 => return Err(SecretError::Rejected(format!("cloud kms {op}: {}", truncate(&text)))),
                _ => {
                    return Err(SecretError::Unavailable(format!("cloud kms {op}: HTTP {status}: {}", truncate(&text))))
                }
            }
        }
        Err(SecretError::Unavailable(format!("cloud kms {op}: unauthorized")))
    }
}

fn truncate(s: &str) -> &str {
    &s[..s.floor_char_boundary(300)]
}

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}

/// Castagnoli, bitwise: tiny inputs only.
fn crc32c(b: &[u8]) -> u32 {
    let mut c = !0u32;
    for &x in b {
        c ^= x as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 { (c >> 1) ^ 0x82F6_3B78 } else { c >> 1 };
        }
    }
    !c
}

#[async_trait]
impl KeyWrapper for GcpKms {
    fn kid(&self) -> &str {
        &self.kid
    }
    fn backend(&self) -> &'static str {
        "gcpkms"
    }
    fn remote(&self) -> bool {
        true
    }
    async fn wrap(&self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, SecretError> {
        let pt = Zeroizing::new(b64(plaintext));
        let body = serde_json::json!({
            "plaintext": &*pt,
            "additionalAuthenticatedData": b64(aad),
            "plaintextCrc32c": crc32c(plaintext).to_string(),
            "additionalAuthenticatedDataCrc32c": crc32c(aad).to_string(),
        });
        let r = self.call("encrypt", body).await?;
        if r.get("verifiedPlaintextCrc32c").and_then(|v| v.as_bool()) == Some(false) {
            return Err(SecretError::Unavailable("cloud kms encrypt: plaintext checksum not verified".into()));
        }
        let ct = r["ciphertext"]
            .as_str()
            .ok_or_else(|| SecretError::Unavailable("cloud kms encrypt: no ciphertext".into()))?;
        base64::engine::general_purpose::STANDARD
            .decode(ct)
            .map_err(|_| SecretError::Unavailable("cloud kms encrypt: bad ciphertext".into()))
    }
    async fn unwrap(&self, aad: &[u8], ct: &[u8]) -> Result<Unwrapped, SecretError> {
        let body = serde_json::json!({
            "ciphertext": b64(ct),
            "additionalAuthenticatedData": b64(aad),
            "ciphertextCrc32c": crc32c(ct).to_string(),
            "additionalAuthenticatedDataCrc32c": crc32c(aad).to_string(),
        });
        let mut r = self.call("decrypt", body).await?;
        let stale = r.get("usedPrimary").and_then(|v| v.as_bool()) == Some(false);
        let pt = match r.get_mut("plaintext").map(serde_json::Value::take) {
            Some(serde_json::Value::String(s)) => Zeroizing::new(s),
            // an empty plaintext is omitted from the JSON
            _ => Zeroizing::new(String::new()),
        };
        let plaintext = Zeroizing::new(
            base64::engine::general_purpose::STANDARD
                .decode(pt.as_bytes())
                .map_err(|_| SecretError::Unavailable("cloud kms decrypt: bad plaintext".into()))?,
        );
        Ok(Unwrapped { plaintext, stale })
    }
}

/// The current KEK wraps (the Cloud KMS or Vault Transit key if set, else
/// the local KEK, else [`dev_kek`]); every configured one unwraps.
#[derive(Clone, Debug, Default)]
pub struct KekConfig {
    pub local: Option<KekBytes>,
    /// Unwrap only.
    pub local_old: Vec<KekBytes>,
    pub gcp_key: Option<String>,
    /// Unwrap only.
    pub gcp_old_keys: Vec<String>,
    pub gcp_endpoint: Option<String>,
    pub gcp_token: Option<GcpToken>,
    /// `<mount>/<key>`.
    pub vault_key: Option<String>,
    /// Unwrap only, on the same server.
    pub vault_old_keys: Vec<String>,
    pub vault: Option<VaultConfig>,
    /// 0: default.
    pub kms_concurrency: usize,
}

impl KekConfig {
    pub fn check(&self, dev_mode: bool) -> anyhow::Result<()> {
        self.check_backends()?;
        if dev_mode {
            return Ok(());
        }
        anyhow::ensure!(
            self.local.is_some() || self.gcp_key.is_some() || self.vault_key.is_some(),
            "a key-encryption key is required outside --dev-mode: set --kek-file / VLPDS_KEK (32 random bytes), --gcp-kms-key or --vault-transit-key"
        );
        let dev = dev_kek();
        anyhow::ensure!(
            self.local.as_ref() != Some(&dev) && !self.local_old.contains(&dev),
            "the dev-mode KEK is not accepted outside --dev-mode"
        );
        Ok(())
    }

    fn check_backends(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.gcp_key.is_none() || self.vault_key.is_none(),
            "set one current key service, --gcp-kms-key or --vault-transit-key, not both (the other one's key can stay as --gcp-kms-old-key / --vault-transit-old-key)"
        );
        anyhow::ensure!(
            self.vault.is_some() || (self.vault_key.is_none() && self.vault_old_keys.is_empty()),
            "a Vault Transit key needs --vault-addr and a Vault auth method"
        );
        Ok(())
    }
}

const CACHE_SHARDS: usize = 16;

/// An entry is valid only for the public key it was validated against, so a
/// key rotation misses.
struct KeyCache {
    shards: Vec<KeyShard>,
}

/// DID -> (public multibase, unwrapped key).
type KeyShard = parking_lot::Mutex<lru::LruCache<Arc<str>, (Arc<str>, Arc<Keypair>)>>;

impl KeyCache {
    fn new() -> KeyCache {
        KeyCache { shards: (0..CACHE_SHARDS).map(|_| parking_lot::Mutex::new(lru::LruCache::unbounded())).collect() }
    }

    fn shard(&self, did: &str) -> &KeyShard {
        &self.shards[(crate::state::did_hash(did) % CACHE_SHARDS as u64) as usize]
    }

    fn get(&self, did: &str, pubkey: &str) -> Option<Arc<Keypair>> {
        let mut s = self.shard(did).lock();
        match s.get(did) {
            Some((pk, k)) if &**pk == pubkey => Some(k.clone()),
            _ => None,
        }
    }

    fn put(&self, did: &str, pubkey: &str, key: Arc<Keypair>) {
        let cap = (crate::caches::cap(crate::caches::Cache::SigningKeys) / CACHE_SHARDS).max(1);
        let mut s = self.shard(did).lock();
        s.put(did.into(), (pubkey.into(), key));
        while s.len() > cap {
            s.pop_lru();
        }
    }

    fn remove(&self, did: &str) {
        self.shard(did).lock().pop(did);
    }

    #[cfg(test)]
    fn clear(&self) {
        for s in &self.shards {
            s.lock().clear();
        }
    }
}

impl crate::caches::Len for KeyCache {
    fn len(&self) -> usize {
        self.shards.iter().map(|s| s.lock().len()).sum()
    }
}

pub struct Secrets {
    /// `[0]` wraps; all unwrap (by kid).
    wrappers: Vec<Arc<dyn KeyWrapper>>,
    dev_kek: bool,
    keys: Arc<KeyCache>,
    permits: tokio::sync::Semaphore,
    wrap_permits: tokio::sync::Semaphore,
    /// Coalesce concurrent cold unwraps of one DID.
    stripes: Vec<tokio::sync::Mutex<()>>,
    /// Remote unwraps fail fast until this (micros since `epoch`).
    down_until: AtomicU64,
    epoch: Instant,
}

impl std::fmt::Debug for Secrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Secrets").field("kids", &self.wrappers.iter().map(|w| w.kid()).collect::<Vec<_>>()).finish()
    }
}

impl Secrets {
    /// `wrappers[0]` is the current KEK.
    pub fn new(wrappers: Vec<Arc<dyn KeyWrapper>>, kms_concurrency: usize) -> anyhow::Result<Secrets> {
        anyhow::ensure!(!wrappers.is_empty(), "no key-encryption key");
        let n = if kms_concurrency == 0 { DEFAULT_KMS_CONCURRENCY } else { kms_concurrency };
        let keys = crate::caches::track(crate::caches::Cache::SigningKeys, Arc::new(KeyCache::new()));
        // exported at 0 so the alerts' increase() sees the first failure
        for w in &wrappers {
            for op in ["wrap", "unwrap"] {
                for r in ["ok", "unavailable", "rejected"] {
                    KMS_REQUESTS.with_label_values(&[w.backend(), op, r]);
                }
            }
        }
        Ok(Secrets {
            wrappers,
            dev_kek: false,
            keys,
            permits: tokio::sync::Semaphore::new(n),
            wrap_permits: tokio::sync::Semaphore::new(wrap_concurrency(n)),
            stripes: (0..256).map(|_| tokio::sync::Mutex::new(())).collect(),
            down_until: AtomicU64::new(0),
            epoch: Instant::now(),
        })
    }

    /// With no KEK configured it wraps under [`dev_kek`]: the binary refuses
    /// that outside dev mode first ([`KekConfig::check`]); in-process tests
    /// may run non-dev servers without a KEK.
    pub fn from_config(cfg: &KekConfig, dev_mode: bool) -> anyhow::Result<Secrets> {
        cfg.check_backends()?;
        let endpoint = cfg.gcp_endpoint.as_deref().unwrap_or(GCP_KMS_ENDPOINT);
        let token = cfg.gcp_token.clone().unwrap_or_default();
        let n = if cfg.kms_concurrency == 0 { DEFAULT_KMS_CONCURRENCY } else { cfg.kms_concurrency };
        let vault = cfg.vault.as_ref().map(|v| VaultClient::new(v, dev_mode, n + wrap_concurrency(n))).transpose()?;
        let mut ws: Vec<Arc<dyn KeyWrapper>> = Vec::new();
        if let Some(k) = &cfg.gcp_key {
            ws.push(Arc::new(GcpKms::new(k, endpoint, token.clone())?));
        }
        let vault_key = |k: &str, current: bool| -> anyhow::Result<Arc<dyn KeyWrapper>> {
            let v = vault.clone().expect("checked");
            let addr = v.addr().to_string();
            let t = VaultTransit::new(v, k, current)?;
            tracing::info!(kid = t.kid(), key = t.name(), addr, current, "vault transit key");
            Ok(Arc::new(t))
        };
        if let Some(k) = &cfg.vault_key {
            ws.push(vault_key(k, true)?);
        }
        let mut dev = false;
        match &cfg.local {
            Some(k) => ws.push(Arc::new(LocalKek::new(k))),
            None if ws.is_empty() => {
                dev = true;
                ws.push(Arc::new(LocalKek::new(&dev_kek())));
            }
            None => {}
        }
        for k in &cfg.gcp_old_keys {
            ws.push(Arc::new(GcpKms::new(k, endpoint, token.clone())?));
        }
        for k in &cfg.vault_old_keys {
            ws.push(vault_key(k, false)?);
        }
        for k in &cfg.local_old {
            ws.push(Arc::new(LocalKek::new(k)));
        }
        if dev_mode && !dev {
            // dev clusters keep reading state written under the dev KEK
            ws.push(Arc::new(LocalKek::new(&dev_kek())));
        }
        let mut seen = std::collections::HashSet::new();
        ws.retain(|w| seen.insert(w.kid().to_string()));
        let mut s = Secrets::new(ws, cfg.kms_concurrency)?;
        s.dev_kek = dev;
        Ok(s)
    }

    pub fn dev() -> Arc<Secrets> {
        static DEV: LazyLock<Arc<Secrets>> = LazyLock::new(|| {
            let mut s = Secrets::new(vec![Arc::new(LocalKek::new(&dev_kek()))], 0).expect("dev keyring");
            s.dev_kek = true;
            Arc::new(s)
        });
        DEV.clone()
    }

    /// Every KEK's [`KeyWrapper::self_test`]. A key service that doesn't
    /// answer only logs: the check runs again before the key's first use.
    pub async fn check_key_service(&self) -> anyhow::Result<()> {
        for w in &self.wrappers {
            let r = match tokio::time::timeout(KMS_TIMEOUT * 6, w.self_test()).await {
                Ok(r) => r,
                Err(_) => Err(SecretError::Unavailable(format!("{} self-test timed out", w.backend()))),
            };
            match r {
                Ok(()) => {}
                Err(e) if e.retryable() => {
                    tracing::warn!(
                        kid = w.kid(),
                        backend = w.backend(),
                        "key service check deferred to first use: {e}"
                    );
                }
                Err(e) => anyhow::bail!("key-encryption key {} ({}) is unusable: {e}", w.kid(), w.backend()),
            }
        }
        Ok(())
    }

    /// Before a rewrap: the current key's latest version, from the key
    /// service, so stale blobs aren't missed. Fails if it can't be asked.
    pub async fn refresh_versions(&self) -> Result<(), SecretError> {
        let w = &self.wrappers[0];
        self.run(w, "wrap", w.refresh_version()).await
    }

    /// (kid, key version) for a blob whose KEK has versions it can read
    /// without unwrapping (Vault Transit).
    pub fn blob_version(&self, blob: &str) -> Option<(String, u64)> {
        let (kid, ct) = parse_blob(blob).ok()?;
        let v = self.wrapper(kid)?.ciphertext_version(&ct)?;
        Some((kid.to_string(), v))
    }

    pub fn is_dev(&self) -> bool {
        self.dev_kek
    }

    pub fn current_kid(&self) -> &str {
        self.wrappers[0].kid()
    }

    pub fn kids(&self) -> Vec<String> {
        self.wrappers.iter().map(|w| w.kid().to_string()).collect()
    }

    fn wrapper(&self, kid: &str) -> Option<&Arc<dyn KeyWrapper>> {
        self.wrappers.iter().find(|w| w.kid() == kid)
    }

    fn now_us(&self) -> u64 {
        self.epoch.elapsed().as_micros() as u64
    }

    async fn run<T>(
        &self,
        w: &Arc<dyn KeyWrapper>,
        op: &'static str,
        f: impl std::future::Future<Output = Result<T, SecretError>>,
    ) -> Result<T, SecretError> {
        let t = Instant::now();
        // only a failure of the key service itself starts a backoff window,
        // never a fast-fail or a full queue
        let mut called = false;
        let r = if w.remote() {
            let now = self.now_us();
            let until = self.down_until.load(Ordering::Relaxed);
            if now < until {
                Err(SecretError::Unavailable("key service recently unavailable; backing off".into()))
            } else {
                let wrap = op == "wrap";
                let permits = if wrap { &self.wrap_permits } else { &self.permits };
                match tokio::time::timeout(KMS_TIMEOUT, permits.acquire()).await {
                    Err(_) => Err(SecretError::Unavailable("too many key service calls queued".into())),
                    Ok(p) => {
                        let _p = p.expect("permits never closed");
                        // a wrap's failure (e.g. a 429 from a flood of
                        // reservations) must not fail the unwraps fast
                        called = !wrap;
                        match tokio::time::timeout(KMS_TIMEOUT, f).await {
                            Ok(r) => r,
                            Err(_) => Err(SecretError::Unavailable(format!("{} {op} timed out", w.backend()))),
                        }
                    }
                }
            }
        } else {
            f.await
        };
        let result = match &r {
            Ok(_) => "ok",
            Err(SecretError::Unavailable(_)) => "unavailable",
            Err(_) => "rejected",
        };
        KMS_REQUESTS.with_label_values(&[w.backend(), op, result]).inc();
        KMS_SECONDS.with_label_values(&[w.backend(), op]).observe(t.elapsed().as_secs_f64());
        if let Err(SecretError::Unavailable(e)) = &r {
            if called {
                let now = self.now_us();
                let prev = self.down_until.swap(now + KMS_BACKOFF.as_micros() as u64, Ordering::Relaxed);
                // one log line per backoff window, not per request
                if prev <= now {
                    tracing::warn!(kid = w.kid(), backend = w.backend(), op, "key service unavailable: {e}");
                }
            }
        }
        r
    }

    pub async fn wrap(&self, purpose: Purpose, subject: &str, plaintext: &[u8]) -> Result<String, SecretError> {
        let w = &self.wrappers[0];
        let a = aad(purpose, subject);
        let ct = self.run(w, "wrap", w.wrap(&a, plaintext)).await?;
        Ok(format!("{WRAP_VERSION}.{}.{}", w.kid(), base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(ct)))
    }

    pub async fn unwrap(&self, purpose: Purpose, subject: &str, blob: &str) -> Result<Unwrapped, SecretError> {
        let (kid, ct) = parse_blob(blob)?;
        let w = self.wrapper(kid).ok_or_else(|| SecretError::UnknownKek(kid.to_string()))?;
        let a = aad(purpose, subject);
        let mut u = self.run(w, "unwrap", w.unwrap(&a, &ct)).await?;
        u.stale |= kid != self.current_kid();
        Ok(u)
    }

    /// A cheap pre-filter for rewraps: a key version rotation inside one
    /// Cloud KMS or Vault Transit key only shows on unwrap.
    pub fn is_current(&self, blob: &str) -> bool {
        parse_blob(blob).is_ok_and(|(kid, _)| kid == self.current_kid())
    }

    /// None if already current.
    pub async fn rewrap(&self, purpose: Purpose, subject: &str, blob: &str) -> Result<Option<String>, SecretError> {
        let u = self.unwrap(purpose, subject, blob).await?;
        if !u.stale {
            return Ok(None);
        }
        Ok(Some(self.wrap(purpose, subject, &u.plaintext).await?))
    }

    /// Also caches it, so new accounts never unwrap. Returns (wrapped,
    /// public multibase).
    pub async fn wrap_signing_key(&self, did: &str, key: &Arc<Keypair>) -> Result<(String, String), SecretError> {
        let raw = Zeroizing::new(key.to_bytes());
        let wrapped = self.wrap(Purpose::SigningKey, did, &raw).await?;
        let pubkey = key.public_multibase();
        self.keys.put(did, &pubkey, key.clone());
        Ok((wrapped, pubkey))
    }

    /// Unwrapped at most once per DID at a time, and checked against `pubkey`.
    pub async fn signing_key(&self, did: &str, wrapped: &str, pubkey: &str) -> Result<Arc<Keypair>, SecretError> {
        if let Some(k) = self.keys.get(did, pubkey) {
            KEY_CACHE.with_label_values(&["hit"]).inc();
            return Ok(k);
        }
        let _g = self.stripes[(crate::state::did_hash(did) % self.stripes.len() as u64) as usize].lock().await;
        if let Some(k) = self.keys.get(did, pubkey) {
            KEY_CACHE.with_label_values(&["hit"]).inc();
            return Ok(k);
        }
        KEY_CACHE.with_label_values(&["miss"]).inc();
        let u = match self.unwrap(Purpose::SigningKey, did, wrapped).await {
            Ok(u) => u,
            Err(e) => {
                KEY_CACHE.with_label_values(&[if e.retryable() { "unavailable" } else { "rejected" }]).inc();
                return Err(e);
            }
        };
        let key = Arc::new(
            Keypair::from_bytes(&u.plaintext)
                .map_err(|e| SecretError::Rejected(format!("signing key of {did}: {e}")))?,
        );
        // an empty expected key is refused too: an unchecked unwrap would let
        // a swapped wrapped key sign for the account
        if pubkey.is_empty() || key.public_multibase() != pubkey {
            KEY_CACHE.with_label_values(&["rejected"]).inc();
            return Err(SecretError::Rejected(format!("signing key of {did} does not match its public key")));
        }
        self.keys.put(did, &key.public_multibase(), key.clone());
        Ok(key)
    }

    pub async fn account_signing_key(&self, a: &crate::state::Account) -> Result<Arc<Keypair>, SecretError> {
        self.signing_key(&a.did, &a.wrapped_signing_key, &a.signing_pubkey).await
    }

    pub fn forget(&self, did: &str) {
        self.keys.remove(did);
    }
}

fn parse_blob(blob: &str) -> Result<(&str, Vec<u8>), SecretError> {
    let mut it = blob.splitn(3, '.');
    match (it.next(), it.next(), it.next()) {
        (Some(WRAP_VERSION), Some(kid), Some(b)) if !kid.is_empty() => {
            Ok((kid, base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(b).map_err(|_| SecretError::Malformed)?))
        }
        _ => Err(SecretError::Malformed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ring(keys: &[&KekBytes]) -> Secrets {
        Secrets::new(keys.iter().map(|k| Arc::new(LocalKek::new(k)) as Arc<dyn KeyWrapper>).collect(), 0).unwrap()
    }

    #[tokio::test]
    async fn roundtrip_and_binding() {
        let k = KekBytes::random();
        let s = ring(&[&k]);
        let secret = [7u8; 32];
        let w = s.wrap(Purpose::SigningKey, "did:plc:a", &secret).await.unwrap();
        assert!(w.starts_with(&format!("vw1.{}.", k.kid())));
        assert!(!w.contains(&hex::encode(secret)));
        let u = s.unwrap(Purpose::SigningKey, "did:plc:a", &w).await.unwrap();
        assert_eq!(&u.plaintext[..], &secret);
        assert!(!u.stale);
        // two wraps of one secret differ (random nonces)
        assert_ne!(w, s.wrap(Purpose::SigningKey, "did:plc:a", &secret).await.unwrap());
        // another subject or purpose: rejected
        assert!(matches!(s.unwrap(Purpose::SigningKey, "did:plc:b", &w).await, Err(SecretError::Rejected(_))));
        assert!(matches!(s.unwrap(Purpose::Totp, "did:plc:a", &w).await, Err(SecretError::Rejected(_))));
        // another KEK: unknown kid; the same kid with a different key can't happen
        // (the kid is the key's hash), but a forged kid is rejected by the tag
        let other = ring(&[&KekBytes::random()]);
        assert!(matches!(other.unwrap(Purpose::SigningKey, "did:plc:a", &w).await, Err(SecretError::UnknownKek(_))));
        let forged = w.replacen(&k.kid(), other.current_kid(), 1);
        assert!(matches!(other.unwrap(Purpose::SigningKey, "did:plc:a", &forged).await, Err(SecretError::Rejected(_))));
        // tampered ciphertext
        let mut bad = w.clone().into_bytes();
        let n = bad.len();
        bad[n - 3] = if bad[n - 3] == b'A' { b'B' } else { b'A' };
        assert!(s.unwrap(Purpose::SigningKey, "did:plc:a", std::str::from_utf8(&bad).unwrap()).await.is_err());
        assert!(matches!(
            s.unwrap(Purpose::SigningKey, "did:plc:a", "hex-or-whatever").await,
            Err(SecretError::Malformed)
        ));
    }

    #[tokio::test]
    async fn rotation_and_rewrap() {
        let (old, new) = (KekBytes::random(), KekBytes::random());
        let before = ring(&[&old]);
        let w = before.wrap(Purpose::Totp, "did:plc:x", b"JBSWY3DPEHPK3PXP").await.unwrap();
        // new current, old kept for unwrap
        let during = ring(&[&new, &old]);
        assert!(!during.is_current(&w));
        let u = during.unwrap(Purpose::Totp, "did:plc:x", &w).await.unwrap();
        assert!(u.stale);
        let w2 = during.rewrap(Purpose::Totp, "did:plc:x", &w).await.unwrap().expect("stale blob rewrapped");
        assert!(during.is_current(&w2));
        assert_eq!(during.rewrap(Purpose::Totp, "did:plc:x", &w2).await.unwrap(), None);
        // after the old KEK is retired only the rewrapped blob opens
        let after = ring(&[&new]);
        assert_eq!(&after.unwrap(Purpose::Totp, "did:plc:x", &w2).await.unwrap().plaintext[..], b"JBSWY3DPEHPK3PXP");
        assert!(matches!(after.unwrap(Purpose::Totp, "did:plc:x", &w).await, Err(SecretError::UnknownKek(_))));
    }

    #[tokio::test]
    async fn signing_key_cache() {
        let s = ring(&[&KekBytes::random()]);
        let key = Arc::new(Keypair::generate());
        let (w, pk) = s.wrap_signing_key("did:plc:c", &key).await.unwrap();
        assert_eq!(pk, key.public_multibase());
        // cached by wrap: same Arc, no unwrap
        assert!(Arc::ptr_eq(&s.keys.get("did:plc:c", &pk).unwrap(), &key));
        s.keys.clear();
        assert!(s.keys.get("did:plc:c", &pk).is_none());
        let k1 = s.signing_key("did:plc:c", &w, &pk).await.unwrap();
        assert_eq!(k1.to_bytes(), key.to_bytes());
        let k2 = s.signing_key("did:plc:c", &w, &pk).await.unwrap();
        assert!(Arc::ptr_eq(&k1, &k2), "second lookup is a cache hit");
        // a row whose public key doesn't match the wrapped secret
        s.keys.clear();
        let other = Keypair::generate().public_multibase();
        assert!(matches!(s.signing_key("did:plc:c", &w, &other).await, Err(SecretError::Rejected(_))));
        assert!(
            matches!(s.signing_key("did:plc:c", &w, "").await, Err(SecretError::Rejected(_))),
            "no expected key: refused"
        );
        // a cached key isn't served for another public key (rotated)
        let _ = s.signing_key("did:plc:c", &w, &pk).await.unwrap();
        assert!(s.keys.get("did:plc:c", &other).is_none());
    }

    #[test]
    fn kek_parsing_and_dev_check() {
        let k = KekBytes::random();
        assert_eq!(KekBytes::parse(&hex::encode(k.0)).unwrap(), k);
        assert_eq!(
            KekBytes::parse(&format!(" {}\n", base64::engine::general_purpose::STANDARD.encode(k.0))).unwrap(),
            k
        );
        assert_eq!(KekBytes::parse(&base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(k.0)).unwrap(), k);
        assert!(KekBytes::parse("abcd").is_err());
        assert!(!format!("{k:?}").contains(&hex::encode(k.0)));
        // dev mode: no KEK needed, the dev KEK wraps
        let s = Secrets::from_config(&KekConfig::default(), true).unwrap();
        assert!(s.is_dev());
        assert_eq!(s.current_kid(), dev_kek().kid());
        // production: a KEK is required, and not the dev one
        assert!(KekConfig::default().check(false).is_err());
        assert!(KekConfig { local: Some(dev_kek()), ..Default::default() }.check(false).is_err());
        assert!(KekConfig { local: Some(k.clone()), ..Default::default() }.check(false).is_ok());
        let s = Secrets::from_config(&KekConfig { local: Some(k.clone()), ..Default::default() }, false).unwrap();
        assert!(!s.is_dev());
        assert_eq!(s.kids(), vec![k.kid()]);
        // dev mode with a real KEK still reads dev-KEK blobs
        let s = Secrets::from_config(&KekConfig { local: Some(k.clone()), ..Default::default() }, true).unwrap();
        assert_eq!(s.kids(), vec![k.kid(), dev_kek().kid()]);
    }

    /// Cost of the keyring on the write path: a cache hit (every load of a
    /// warm account, the proxy's misses) and a local-KEK unwrap (a cold
    /// load with `--kek-file`), next to one commit signature for scale.
    /// `cargo test --profile dev-release --lib bench_keyring -- --ignored --nocapture`
    #[tokio::test]
    #[ignore]
    async fn bench_keyring() {
        let s = ring(&[&KekBytes::random()]);
        let dids: Vec<String> = (0..10_000).map(|i| format!("did:plc:bench{i:019}")).collect();
        let mut rows = Vec::new();
        for d in &dids {
            let k = Arc::new(Keypair::generate());
            let (w, pk) = s.wrap_signing_key(d, &k).await.unwrap();
            rows.push((w, pk));
        }
        let t = Instant::now();
        for (d, (w, pk)) in dids.iter().zip(&rows) {
            std::hint::black_box(s.signing_key(d, w, pk).await.unwrap());
        }
        let hit = t.elapsed().as_nanos() as f64 / dids.len() as f64;
        s.keys.clear();
        let t = Instant::now();
        for (d, (w, pk)) in dids.iter().zip(&rows) {
            std::hint::black_box(s.signing_key(d, w, pk).await.unwrap());
        }
        let miss = t.elapsed().as_nanos() as f64 / dids.len() as f64;
        let k = Keypair::generate();
        let t = Instant::now();
        for i in 0..10_000u32 {
            std::hint::black_box(k.sign(&i.to_be_bytes()));
        }
        let sign = t.elapsed().as_nanos() as f64 / 10_000.0;
        println!("bench_keyring: cache hit {hit:.0} ns, local unwrap + parse + pubkey check {miss:.0} ns, one signature {sign:.0} ns");
    }

    #[test]
    fn crc32c_known_value() {
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
    }

    fn sa_json(token_uri: &str) -> String {
        let pem =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/gcp-test-sa-key.pem")).unwrap();
        serde_json::json!({
            "type": "service_account",
            "project_id": "p",
            "private_key_id": "kid-1",
            "private_key": pem,
            "client_email": "vlpds@p.iam.gserviceaccount.com",
            "token_uri": token_uri,
        })
        .to_string()
    }

    #[test]
    fn service_account_key_files() {
        let sa = ServiceAccount::from_json(&sa_json("https://oauth2.example/token")).unwrap();
        assert_eq!(sa.client_email, "vlpds@p.iam.gserviceaccount.com");
        assert!(!format!("{sa:?}").contains("PRIVATE"));
        // no token_uri: Google's
        let mut j: serde_json::Value = serde_json::from_str(&sa_json("")).unwrap();
        j.as_object_mut().unwrap().remove("token_uri");
        assert_eq!(ServiceAccount::from_json(&j.to_string()).unwrap().token_uri, GOOGLE_TOKEN_URI);
        // other credential types and broken keys are refused at startup
        let user = serde_json::json!({"type": "authorized_user", "client_id": "x", "refresh_token": "y"}).to_string();
        assert!(format!("{:#}", ServiceAccount::from_json(&user).unwrap_err()).contains("service_account"));
        j["private_key"] = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n".into();
        assert!(ServiceAccount::from_json(&j.to_string()).is_err());
        assert!(ServiceAccount::from_json("not json").is_err());
    }

    /// A token endpoint that checks the JWT bearer grant (RS256 signature
    /// by the key file's key, claims) and a Cloud KMS that accepts only the
    /// latest token it minted.
    struct MockGoogle {
        url: String,
        tokens: AtomicU64,
        /// the token KMS accepts (0 = none)
        valid: AtomicU64,
        expires_in: AtomicU64,
        kms_calls: AtomicU64,
    }

    async fn mock_google(public_key: Vec<u8>) -> Arc<MockGoogle> {
        use axum::extract::State;
        use axum::http::{HeaderMap, StatusCode};
        use axum::response::IntoResponse;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let m = Arc::new(MockGoogle {
            url: format!("http://{}", listener.local_addr().unwrap()),
            tokens: AtomicU64::new(0),
            valid: AtomicU64::new(0),
            expires_in: AtomicU64::new(3600),
            kms_calls: AtomicU64::new(0),
        });
        type S = State<(Arc<MockGoogle>, Arc<Vec<u8>>)>;
        async fn token(State((m, pk)): S, headers: HeaderMap, body: String) -> axum::response::Response {
            let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
            assert_eq!(headers["content-type"], "application/x-www-form-urlencoded");
            let form: std::collections::HashMap<String, String> = body
                .split('&')
                .filter_map(|kv| kv.split_once('='))
                .map(|(k, v)| (k.to_string(), v.replace("%3A", ":")))
                .collect();
            assert_eq!(form["grant_type"], "urn:ietf:params:oauth:grant-type:jwt-bearer");
            let jwt = &form["assertion"];
            let (msg, sig) = jwt.rsplit_once('.').unwrap();
            let key =
                ring::signature::UnparsedPublicKey::new(&ring::signature::RSA_PKCS1_2048_8192_SHA256, pk.as_slice());
            if key.verify(msg.as_bytes(), &b64.decode(sig).unwrap()).is_err() {
                return (StatusCode::BAD_REQUEST, "invalid_grant").into_response();
            }
            let (h, c) = msg.split_once('.').unwrap();
            let h: serde_json::Value = serde_json::from_slice(&b64.decode(h).unwrap()).unwrap();
            let c: serde_json::Value = serde_json::from_slice(&b64.decode(c).unwrap()).unwrap();
            assert_eq!(h["alg"], "RS256");
            assert_eq!(h["kid"], "kid-1");
            assert_eq!(c["iss"], "vlpds@p.iam.gserviceaccount.com");
            assert_eq!(c["scope"], CLOUD_KMS_SCOPE);
            assert_eq!(c["aud"], format!("{}/token", m.url));
            assert_eq!(c["exp"].as_u64().unwrap() - c["iat"].as_u64().unwrap(), 3600);
            let n = m.tokens.fetch_add(1, Ordering::SeqCst) + 1;
            m.valid.store(n, Ordering::SeqCst);
            axum::Json(serde_json::json!({"access_token": format!("sa-token-{n}"), "expires_in": m.expires_in.load(Ordering::SeqCst), "token_type": "Bearer"})).into_response()
        }
        async fn kms(
            State((m, _)): S,
            headers: HeaderMap,
            axum::Json(body): axum::Json<serde_json::Value>,
        ) -> axum::response::Response {
            m.kms_calls.fetch_add(1, Ordering::SeqCst);
            let want = format!("Bearer sa-token-{}", m.valid.load(Ordering::SeqCst));
            if headers.get("authorization").and_then(|v| v.to_str().ok()) != Some(want.as_str()) {
                return (StatusCode::UNAUTHORIZED, "expired").into_response();
            }
            // identity "encryption" is enough to test the auth path
            let v = body.get("plaintext").or(body.get("ciphertext")).cloned().unwrap();
            axum::Json(serde_json::json!({"name": "k/cryptoKeyVersions/1", "ciphertext": v, "plaintext": v, "usedPrimary": true})).into_response()
        }
        let app = axum::Router::new()
            .route("/token", axum::routing::post(token))
            .route("/v1/{*rest}", axum::routing::post(kms))
            .with_state((m.clone(), Arc::new(public_key)));
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        m
    }

    /// Off GCE, a service-account key file mints Cloud KMS tokens: one token
    /// exchange serves many calls (and every key using that account), a
    /// 401 refreshes it once, and an expiring token is replaced.
    #[tokio::test]
    async fn service_account_tokens_are_cached_and_refreshed() {
        let probe = ServiceAccount::from_json(&sa_json("http://unused/token")).unwrap();
        let m = mock_google(probe.key.public().as_ref().to_vec()).await;
        let path = std::env::temp_dir().join(format!("vlpds-sa-{}.json", std::process::id()));
        std::fs::write(&path, sa_json(&format!("{}/token", m.url))).unwrap();
        let token = GcpToken::from_credentials(Some(&path)).unwrap();
        std::fs::remove_file(&path).ok();
        assert!(matches!(token, GcpToken::ServiceAccount(_)));
        let cfg = KekConfig {
            gcp_key: Some("projects/p/locations/global/keyRings/r/cryptoKeys/a".into()),
            gcp_old_keys: vec!["projects/p/locations/global/keyRings/r/cryptoKeys/b".into()],
            gcp_endpoint: Some(m.url.clone()),
            gcp_token: Some(token),
            ..Default::default()
        };
        let s = Secrets::from_config(&cfg, false).unwrap();
        assert!(s.current_kid().starts_with('G'));
        let secret = [9u8; 32];
        for i in 0..5 {
            let w = s.wrap(Purpose::SigningKey, &format!("did:plc:{i}"), &secret).await.unwrap();
            assert_eq!(
                &s.unwrap(Purpose::SigningKey, &format!("did:plc:{i}"), &w).await.unwrap().plaintext[..],
                &secret
            );
        }
        assert_eq!(m.tokens.load(Ordering::SeqCst), 1, "one token exchange for every call");
        // the old key's wrapper shares the account's token
        let old =
            GcpKms::new("projects/p/locations/global/keyRings/r/cryptoKeys/b", &m.url, cfg.gcp_token.clone().unwrap())
                .unwrap();
        old.wrap(b"aad", &secret).await.unwrap();
        assert_eq!(m.tokens.load(Ordering::SeqCst), 1);
        // revoked upstream (KMS says 401): refreshed once, the call succeeds
        m.valid.store(0, Ordering::SeqCst);
        s.wrap(Purpose::SigningKey, "did:plc:x", &secret).await.unwrap();
        assert_eq!(m.tokens.load(Ordering::SeqCst), 2);
        // a token about to expire is replaced before KMS sees it
        m.expires_in.store(61, Ordering::SeqCst);
        m.valid.store(0, Ordering::SeqCst);
        s.wrap(Purpose::SigningKey, "did:plc:y", &secret).await.unwrap();
        assert_eq!(m.tokens.load(Ordering::SeqCst), 3);
        tokio::time::sleep(Duration::from_millis(1100)).await;
        let calls = m.kms_calls.load(Ordering::SeqCst);
        s.wrap(Purpose::SigningKey, "did:plc:z", &secret).await.unwrap();
        assert_eq!(m.tokens.load(Ordering::SeqCst), 4, "expired token refreshed proactively");
        assert_eq!(m.kms_calls.load(Ordering::SeqCst), calls + 1, "no 401 round trip");
        // a token endpoint refusing the grant is a retryable outage, not a panic
        let bad = ServiceAccount::from_json(&sa_json(&format!("{}/nope", m.url))).unwrap();
        let k =
            GcpKms::new("projects/p/locations/global/keyRings/r/cryptoKeys/c", &m.url, GcpToken::ServiceAccount(bad))
                .unwrap();
        assert!(matches!(k.wrap(b"aad", &secret).await, Err(SecretError::Unavailable(_))));
    }

    /// A remote key service whose wraps can be held and then refused with
    /// a 429 (a flood of reservations), unwraps answering at once.
    struct Throttling {
        inner: LocalKek,
        hold: std::sync::atomic::AtomicBool,
        release: tokio::sync::Notify,
        wraps_in: AtomicU64,
    }

    #[async_trait]
    impl KeyWrapper for Throttling {
        fn kid(&self) -> &str {
            self.inner.kid()
        }
        fn backend(&self) -> &'static str {
            "mock"
        }
        fn remote(&self) -> bool {
            true
        }
        async fn wrap(&self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, SecretError> {
            if !self.hold.load(Ordering::SeqCst) {
                return self.inner.wrap(aad, plaintext).await;
            }
            self.wraps_in.fetch_add(1, Ordering::SeqCst);
            self.release.notified().await;
            Err(SecretError::Unavailable("cloud kms encrypt: HTTP 429 Too Many Requests: quota".into()))
        }
        async fn unwrap(&self, aad: &[u8], ct: &[u8]) -> Result<Unwrapped, SecretError> {
            self.inner.unwrap(aad, ct).await
        }
    }

    /// A flood of wraps (reserveSigningKey) neither takes the unwraps'
    /// permits nor, when the key service refuses them (429), starts the
    /// fail-fast window that would fail cold signing-key unwraps.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn wrap_flood_does_not_stall_unwraps() {
        let m = Arc::new(Throttling {
            inner: LocalKek::new(&KekBytes::random()),
            hold: std::sync::atomic::AtomicBool::new(false),
            release: tokio::sync::Notify::new(),
            wraps_in: AtomicU64::new(0),
        });
        let s = Arc::new(Secrets::new(vec![m.clone() as Arc<dyn KeyWrapper>], 8).unwrap());
        let secret = [5u8; 32];
        let blob = s.wrap(Purpose::SigningKey, "did:plc:cold", &secret).await.unwrap();
        // 40 wraps pile up: 2 hold the wrap pool (8 / 4), the rest queue
        m.hold.store(true, Ordering::SeqCst);
        let flood: Vec<_> = (0..40)
            .map(|i| {
                let s = s.clone();
                tokio::spawn(async move { s.wrap(Purpose::ReservedKey, &format!("did:key:z{i}"), &[1u8; 32]).await })
            })
            .collect();
        for _ in 0..100 {
            if m.wraps_in.load(Ordering::SeqCst) >= wrap_concurrency(8) as u64 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(m.wraps_in.load(Ordering::SeqCst), wrap_concurrency(8) as u64, "wraps limited to their own pool");
        // cold unwraps still go straight through
        let t = Instant::now();
        for _ in 0..20 {
            let u = s.unwrap(Purpose::SigningKey, "did:plc:cold", &blob).await.unwrap();
            assert_eq!(&u.plaintext[..], &secret);
        }
        assert!(t.elapsed() < Duration::from_secs(1), "{:?}", t.elapsed());
        // the key service refuses the held wraps (429): no fail-fast window
        m.release.notify_waiters();
        tokio::time::sleep(Duration::from_millis(50)).await;
        m.release.notify_waiters();
        let u = s.unwrap(Purpose::SigningKey, "did:plc:cold", &blob).await;
        assert!(u.is_ok(), "unwrap right after refused wraps: {:?}", u.err());
        m.hold.store(false, Ordering::SeqCst);
        loop {
            m.release.notify_waiters();
            if flood.iter().all(|h| h.is_finished()) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        for h in flood {
            let _ = h.await.unwrap();
        }
        assert_eq!(s.down_until.load(Ordering::Relaxed), 0, "wraps never start the backoff");
    }
}
