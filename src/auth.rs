//! HS256 session JWTs (access + refresh), and the verified-token cache
//! shared with OAuth access tokens.

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Clone)]
pub struct Jwt {
    secret: Vec<u8>,
    pub service_did: String,
    verified: Arc<TokenCache<Arc<Claims>>>,
}

const TOKEN_CACHE_SHARDS: usize = 64;

/// Verified bearer tokens (signature checked, claims parsed) until their
/// `exp`. A hit compares the whole token. Revocation, sessions and account
/// status are not cached: callers check them on every request. A full shard
/// drops its expired entries, then all of them.
pub struct TokenCache<V> {
    shards: Vec<TokenShard<V>>,
    kind: crate::caches::Cache,
    /// Tests: a cap of its own instead of the process-wide one.
    fixed_cap: Option<usize>,
}

/// signature segment -> (whole token, value, exp unix secs)
type TokenShard<V> = parking_lot::Mutex<HashMap<Box<str>, (Box<str>, V, u64)>>;

impl<V: Send> crate::caches::Len for TokenCache<V> {
    fn len(&self) -> usize {
        self.shards.iter().map(|s| s.lock().len()).sum()
    }
}

impl<V: Clone + Send + 'static> TokenCache<V> {
    pub fn tracked(kind: crate::caches::Cache) -> Arc<Self> {
        crate::caches::track(kind, Arc::new(Self::build(kind, None)))
    }
}

impl<V: Clone> TokenCache<V> {
    pub fn with_capacity(capacity: usize) -> Self {
        Self::build(crate::caches::Cache::SessionTokens, Some(capacity))
    }

    fn build(kind: crate::caches::Cache, fixed_cap: Option<usize>) -> Self {
        TokenCache { shards: (0..TOKEN_CACHE_SHARDS).map(|_| Default::default()).collect(), kind, fixed_cap }
    }

    fn cap_per_shard(&self) -> usize {
        self.fixed_cap.unwrap_or_else(|| crate::caches::cap(self.kind)).div_ceil(TOKEN_CACHE_SHARDS).max(1)
    }

    /// The signature is random-looking, so its last bytes pick the shard
    /// without hashing the token.
    fn slot<'t>(&self, token: &'t str) -> (&TokenShard<V>, &'t str) {
        let sig = token.rsplit_once('.').map_or(token, |(_, s)| s);
        let b = sig.as_bytes();
        let tail =
            b[b.len().saturating_sub(4)..].iter().fold(0usize, |h, &x| h.wrapping_mul(131).wrapping_add(x as usize));
        (&self.shards[tail % self.shards.len()], sig)
    }

    pub fn get(&self, token: &str, now: u64) -> Option<V> {
        let (shard, sig) = self.slot(token);
        let m = shard.lock();
        let (tok, v, exp) = m.get(sig)?;
        (**tok == *token && *exp >= now).then(|| v.clone())
    }

    /// The caller verified `token`'s signature.
    pub fn put(&self, token: &str, v: V, exp: u64, now: u64) {
        if exp < now {
            return;
        }
        let (shard, sig) = self.slot(token);
        let cap = self.cap_per_shard();
        let mut m = shard.lock();
        if m.len() >= cap {
            m.retain(|_, (_, _, e)| *e >= now);
            if m.len() >= cap {
                m.clear();
            }
        }
        m.insert(sig.into(), (token.into(), v, exp));
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Claims {
    pub scope: String,
    pub sub: String,
    pub aud: String,
    pub iat: u64,
    pub exp: u64,
    /// Refresh tokens: the token id; access tokens: the session family id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    /// vlpds: a scoped app password's OAuth scopes, on its access tokens.
    #[serde(default, rename = "appPassScope", skip_serializing_if = "Option::is_none")]
    pub app_pass_scope: Option<String>,
}

impl Jwt {
    pub fn new(secret: &str, service_did: &str) -> Jwt {
        Jwt {
            secret: secret.as_bytes().to_vec(),
            service_did: service_did.to_string(),
            verified: TokenCache::tracked(crate::caches::Cache::SessionTokens),
        }
    }

    fn mac(&self) -> Hmac<Sha256> {
        Hmac::<Sha256>::new_from_slice(&self.secret).unwrap()
    }

    pub fn issue_with_jti(&self, did: &str, scope: &str, ttl_secs: u64, typ: &str, jti: Option<&str>) -> String {
        self.issue_scoped(did, scope, None, ttl_secs, typ, jti)
    }

    pub fn issue_scoped(
        &self,
        did: &str,
        scope: &str,
        app_pass_scope: Option<&str>,
        ttl_secs: u64,
        typ: &str,
        jti: Option<&str>,
    ) -> String {
        let now = vlatproto::tid::now_micros() / 1_000_000;
        let header = B64.encode(format!(r#"{{"alg":"HS256","typ":"{typ}"}}"#));
        let claims = Claims {
            scope: scope.into(),
            sub: did.into(),
            aud: self.service_did.clone(),
            iat: now,
            exp: now + ttl_secs,
            jti: jti.map(Into::into),
            app_pass_scope: app_pass_scope.map(Into::into),
        };
        let payload = B64.encode(serde_json::to_vec(&claims).unwrap());
        let signing_input = format!("{header}.{payload}");
        let mut mac = self.mac();
        mac.update(signing_input.as_bytes());
        format!("{signing_input}.{}", B64.encode(mac.finalize().into_bytes()))
    }

    pub fn access(&self, did: &str) -> String {
        self.issue_with_jti(did, "com.atproto.access", 2 * 3600, "at+jwt", None)
    }

    /// Expiry and scope are the caller's to check.
    pub fn verify_signature(&self, token: &str) -> Option<Claims> {
        let (signing_input, sig) = token.rsplit_once('.')?;
        let sig = B64.decode(sig).ok()?;
        let mut mac = self.mac();
        mac.update(signing_input.as_bytes());
        mac.verify_slice(&sig).ok()?;
        let (_, payload) = signing_input.split_once('.')?;
        serde_json::from_slice(&B64.decode(payload).ok()?).ok()
    }

    /// Expiry, scope and revocation are the caller's to check.
    pub fn verify_signature_cached(&self, token: &str) -> Option<Arc<Claims>> {
        let now = vlatproto::tid::now_micros() / 1_000_000;
        if let Some(c) = self.verified.get(token, now) {
            return Some(c);
        }
        let c = Arc::new(self.verify_signature(token)?);
        self.verified.put(token, c.clone(), c.exp, now);
        Some(c)
    }
}

/// ES256K service-auth JWT. `aud` may carry a #fragment. Err: signing failed
/// verification twice and nothing was issued.
pub fn service_auth_jwt(
    key: &vlatproto::crypto::Keypair,
    iss: &str,
    aud: &str,
    lxm: Option<&str>,
    ttl_secs: u64,
) -> Result<String, vlatproto::crypto::SignatureFault> {
    let now = vlatproto::tid::now_micros() / 1_000_000;
    let header = B64.encode(r#"{"typ":"JWT","alg":"ES256K"}"#);
    let mut claims = serde_json::json!({
        "iat": now,
        "iss": iss,
        "aud": aud,
        "exp": now + ttl_secs,
        "jti": hex::encode(rand::random::<[u8; 16]>()),
    });
    if let Some(lxm) = lxm {
        claims["lxm"] = serde_json::Value::String(lxm.to_string());
    }
    let payload = B64.encode(serde_json::to_vec(&claims).unwrap());
    let signing_input = format!("{header}.{payload}");
    let sig = key.sign_verified(vlatproto::crypto::Purpose::ServiceAuth, signing_input.as_bytes())?;
    Ok(format!("{signing_input}.{}", B64.encode(sig)))
}

pub use crate::prims::ct_eq;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_cache() {
        let c: TokenCache<u32> = TokenCache::with_capacity(TOKEN_CACHE_SHARDS * 2);
        c.put("h.p.sig", 1, 100, 50);
        assert_eq!(c.get("h.p.sig", 50), Some(1));
        assert_eq!(c.get("h.p.sig", 100), Some(1));
        assert_eq!(c.get("h.p.sig", 101), None, "expired");
        assert_eq!(c.get("h.other.sig", 50), None, "same signature, another token");
        c.put("h.p.old", 2, 10, 50);
        assert_eq!(c.get("h.p.old", 5), None, "already expired when put");
        // bounded: a full shard drops its expired entries, then everything
        for i in 0..10_000 {
            c.put(&format!("h.p.{i:08}"), i, 100, 50);
        }
        let n: usize = c.shards.iter().map(|s| s.lock().len()).sum();
        assert!(n <= TOKEN_CACHE_SHARDS * 2, "{n} entries");

        let jwt = Jwt::new("secret", "did:web:pds.test");
        let tok = jwt.access("did:plc:abc");
        assert_eq!(jwt.verify_signature_cached(&tok).unwrap().sub, "did:plc:abc");
        assert_eq!(jwt.verify_signature_cached(&tok).unwrap().sub, "did:plc:abc");
        let other = Jwt::new("other secret", "did:web:pds.test");
        assert!(other.verify_signature_cached(&tok).is_none(), "cached per secret");
        let (input, _) = tok.rsplit_once('.').unwrap();
        let (_, sig) =
            other.access("did:plc:abc").rsplit_once('.').map(|(a, b)| (a.to_string(), b.to_string())).unwrap();
        assert!(jwt.verify_signature_cached(&format!("{input}.{sig}")).is_none());
    }
}
