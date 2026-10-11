//! JWT and JWKS helpers for provider identity tokens.
//!
//! Separate from `oauth::jose`, which is the authorization server's own
//! ES256 surface. Here we verify RS256 ID tokens (Google, Apple) against a
//! cached JWKS, and mint Apple's ES256 client-secret assertion from the
//! configured signing key.

use base64::Engine;
use ring::signature as sig;

use super::*;

const B64: base64::engine::general_purpose::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

fn b64u(s: &str) -> Result<Vec<u8>, String> {
    B64.decode(s.trim_end_matches('=')).map_err(|e| format!("bad base64url: {e}"))
}

/// A decoded, unverified JWT.
pub struct Jwt {
    pub header: J,
    pub payload: J,
    signing_input: String,
    sig: Vec<u8>,
}

impl Jwt {
    pub fn decode(token: &str) -> Result<Jwt, String> {
        let mut parts = token.split('.');
        let (h, p, s) = match (parts.next(), parts.next(), parts.next(), parts.next()) {
            (Some(h), Some(p), Some(s), None) => (h, p, s),
            _ => return Err("malformed JWT".into()),
        };
        let header: J = serde_json::from_slice(&b64u(h)?).map_err(|e| format!("bad JWT header: {e}"))?;
        let payload: J = serde_json::from_slice(&b64u(p)?).map_err(|e| format!("bad JWT payload: {e}"))?;
        let sig = b64u(s)?;
        Ok(Jwt { header, payload, signing_input: format!("{h}.{p}"), sig })
    }

    pub fn alg(&self) -> &str {
        self.header.get("alg").and_then(J::as_str).unwrap_or("")
    }

    pub fn kid(&self) -> Option<&str> {
        self.header.get("kid").and_then(J::as_str)
    }

    pub fn claim_str(&self, k: &str) -> Option<&str> {
        self.payload.get(k).and_then(J::as_str)
    }

    pub fn claim_i64(&self, k: &str) -> Option<i64> {
        self.payload.get(k).and_then(J::as_i64)
    }

    pub fn claim_bool(&self, k: &str) -> Option<bool> {
        self.payload.get(k).and_then(J::as_bool)
    }

    pub fn claim(&self, k: &str) -> Option<&J> {
        self.payload.get(k)
    }

    /// RS256 verification over the signing input. Only RS256 is accepted:
    /// Google and Apple sign identity tokens with it, and refusing `none`,
    /// HS256 and algorithm confusion is the point.
    pub fn verify_rs256(&self, n: &[u8], e: &[u8]) -> bool {
        if self.alg() != "RS256" {
            return false;
        }
        sig::RsaPublicKeyComponents { n, e }
            .verify(&sig::RSA_PKCS1_2048_8192_SHA256, self.signing_input.as_bytes(), &self.sig)
            .is_ok()
    }

    /// A JWK's RSA public key as (modulus, exponent).
    pub fn rsa_parts(jwk: &J) -> Option<(Vec<u8>, Vec<u8>)> {
        if jwk.get("kty").and_then(J::as_str) != Some("RSA") {
            return None;
        }
        let n = b64u(jwk.get("n").and_then(J::as_str)?).ok()?;
        let e = b64u(jwk.get("e").and_then(J::as_str)?).ok()?;
        Some((n, e))
    }

    /// Every RSA JWK in a `{"keys":[…]}` set, as (kid, n, e).
    pub fn rsa_keys(set: &J) -> Vec<(Option<String>, Vec<u8>, Vec<u8>)> {
        set.get("keys")
            .and_then(J::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(|k| {
                        let (n, e) = Jwt::rsa_parts(k)?;
                        let kid = k.get("kid").and_then(J::as_str).map(String::from);
                        Some((kid, n, e))
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// What `alg` a key advertises, so a caller can also refuse a key that
    /// is not for signing.
    pub fn jwk_use_ok(jwk: &J) -> bool {
        match jwk.get("use").and_then(J::as_str) {
            None => true,
            Some(u) => u == "sig",
        }
    }
}

/// A cached JWKS, refreshed on expiry and on an unknown key id (a rotation).
pub struct Jwks {
    url: String,
    ttl: std::time::Duration,
    cached: parking_lot::Mutex<Option<(std::time::Instant, J)>>,
}

const JWKS_TTL: std::time::Duration = std::time::Duration::from_secs(3600);
/// A minimum interval between forced refetches, so an attacker cannot drive
/// unbounded outbound requests with bogus `kid`s.
const JWKS_MIN_REFRESH: std::time::Duration = std::time::Duration::from_secs(60);

impl Jwks {
    pub fn new(url: &str) -> Jwks {
        Jwks { url: url.to_string(), ttl: JWKS_TTL, cached: parking_lot::Mutex::new(None) }
    }

    #[cfg(test)]
    pub fn with_ttl(url: &str, ttl: std::time::Duration) -> Jwks {
        Jwks { url: url.to_string(), ttl, cached: parking_lot::Mutex::new(None) }
    }

    fn fresh(&self) -> Option<J> {
        let g = self.cached.lock();
        match &*g {
            Some((at, set)) if at.elapsed() < self.ttl => Some(set.clone()),
            _ => None,
        }
    }

    /// Refresh the cached set if it is stale or `force` (a kid miss), at most
    /// once a minute.
    async fn refresh(&self, app: &App, force: bool) -> Result<J, String> {
        if !force {
            if let Some(s) = self.fresh() {
                return Ok(s);
            }
        } else if let Some((at, set)) = &*self.cached.lock() {
            if at.elapsed() < JWKS_MIN_REFRESH {
                return Ok(set.clone());
            }
        }
        let f = fetcher(&app.config.owner_auth);
        let set = f.get_json(&self.url, MAX_PROVIDER_BODY).await?;
        *self.cached.lock() = Some((std::time::Instant::now(), set.clone()));
        Ok(set)
    }

    /// Verify a token's signature against this set, refetching once if the
    /// key id is unknown.
    pub async fn verify(&self, app: &App, jwt: &Jwt) -> Result<(), String> {
        let mut set = self.refresh(app, false).await?;
        for attempt in 0..2 {
            for key in set.get("keys").and_then(J::as_array).into_iter().flatten() {
                if let Some(kid) = jwt.kid() {
                    if key.get("kid").and_then(J::as_str) != Some(kid) {
                        continue;
                    }
                }
                if !Jwt::jwk_use_ok(key) {
                    continue;
                }
                if let Some((n, e)) = Jwt::rsa_parts(key) {
                    if jwt.verify_rs256(&n, &e) {
                        return Ok(());
                    }
                }
            }
            if attempt == 0 {
                set = self.refresh(app, true).await?;
            }
        }
        Err("no JWKS key verified the token".into())
    }
}

/// A provider ID token, checked the way the specs require.
pub struct IdTokenClaims {
    pub sub: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub name: Option<String>,
}

/// The shared checks every ID token must pass, then the provider adds its
/// own (`hd`, Apple's nonce, …). Never falls back to userinfo.
pub fn check_common(jwt: &Jwt, issuer: &str, audience: &str, now: i64) -> Result<(), String> {
    if jwt.alg() != "RS256" {
        return Err(format!("unsupported id_token alg {:?}", jwt.alg()));
    }
    let iss = jwt.claim_str("iss").ok_or("id_token has no iss")?;
    if iss != issuer && iss.trim_end_matches('/') != issuer.trim_end_matches('/') {
        return Err(format!("id_token issuer {iss:?} is not {issuer:?}"));
    }
    match jwt.claim("aud") {
        Some(J::String(a)) => {
            if a != audience {
                return Err("id_token audience mismatch".into());
            }
        }
        Some(J::Array(a)) => {
            if !a.iter().any(|v| v.as_str() == Some(audience)) {
                return Err("id_token audience mismatch".into());
            }
            // With multiple audiences azp must name us.
            if let Some(azp) = jwt.claim_str("azp") {
                if azp != audience {
                    return Err("id_token azp mismatch".into());
                }
            }
        }
        _ => return Err("id_token has no aud".into()),
    }
    let exp = jwt.claim_i64("exp").ok_or("id_token has no exp")?;
    if exp <= now {
        return Err("id_token expired".into());
    }
    if let Some(iat) = jwt.claim_i64("iat") {
        if iat > now + 300 {
            return Err("id_token issued in the future".into());
        }
    }
    if let Some(nbf) = jwt.claim_i64("nbf") {
        if nbf > now + 300 {
            return Err("id_token not yet valid".into());
        }
    }
    Ok(())
}

pub fn claims(jwt: &Jwt) -> Result<IdTokenClaims, String> {
    Ok(IdTokenClaims {
        sub: jwt.claim_str("sub").ok_or("id_token has no sub")?.to_string(),
        email: jwt.claim_str("email").map(String::from),
        email_verified: jwt.claim_bool("email_verified").unwrap_or(false),
        name: jwt.claim_str("name").map(String::from),
    })
}

/// Sign an ES256 JWT with a PKCS#8 PEM private key (Apple's client secret).
pub fn sign_es256_pem(pem: &str, kid: &str, claims: &J) -> Result<String, String> {
    let der = pem_to_der(pem)?;
    let rng = ring::rand::SystemRandom::new();
    let key = sig::EcdsaKeyPair::from_pkcs8(&sig::ECDSA_P256_SHA256_FIXED_SIGNING, &der, &rng)
        .map_err(|e| format!("bad ES256 key: {e}"))?;
    let header = json!({"alg": "ES256", "kid": kid, "typ": "JWT"});
    let h = B64.encode(serde_json::to_vec(&header).expect("serializable"));
    let p = B64.encode(serde_json::to_vec(claims).expect("serializable"));
    let input = format!("{h}.{p}");
    let s = key.sign(&rng, input.as_bytes()).map_err(|e| format!("ES256 sign failed: {e}"))?;
    Ok(format!("{input}.{}", B64.encode(s.as_ref())))
}

/// PEM → DER (PKCS#8), accepting literal `\n` escapes as Apple's downloads
/// sometimes carry.
pub fn pem_to_der(pem: &str) -> Result<Vec<u8>, String> {
    let pem = pem.replace("\\n", "\n");
    let body: String =
        pem.lines().filter(|l| !l.starts_with("-----") && !l.trim().is_empty()).collect::<Vec<_>>().join("");
    base64::engine::general_purpose::STANDARD.decode(body.trim()).map_err(|e| format!("bad PEM body: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pem_roundtrip_strips_headers() {
        let pem = "-----BEGIN PRIVATE KEY-----\nAAECAw==\n-----END PRIVATE KEY-----";
        assert_eq!(pem_to_der(pem).unwrap(), vec![0, 1, 2, 3]);
        let escaped = "-----BEGIN PRIVATE KEY-----\\nAAECAw==\\n-----END PRIVATE KEY-----";
        assert_eq!(pem_to_der(escaped).unwrap(), vec![0, 1, 2, 3]);
    }

    #[test]
    fn jwks_set_parses_rsa_keys_only() {
        let set = json!({"keys": [
            {"kty": "RSA", "kid": "a", "n": "AQAB", "e": "AQAB"},
            {"kty": "EC", "kid": "b", "crv": "P-256"},
        ]});
        let keys = Jwt::rsa_keys(&set);
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].0.as_deref(), Some("a"));
    }

    #[test]
    fn rejects_none_alg() {
        let token = {
            let h = B64.encode(br#"{"alg":"none","typ":"JWT"}"#);
            let p = B64.encode(br#"{"sub":"x"}"#);
            format!("{h}.{p}.")
        };
        let jwt = Jwt::decode(&token).unwrap();
        assert!(!jwt.verify_rs256(&[1], &[1]));
    }
}
