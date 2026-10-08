//! ES256 JWKs and JWTs, RFC 7638 thumbprints, DPoP proofs (RFC 9449) and
//! server-issued DPoP nonces.

use super::util::{b64u, b64u_decode, derive_secret, hmac_sha256, now_secs, sha256_b64u, Replay};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::Sec1Point;
use serde_json::{json, Value as J};

/// For DPoP proofs and client assertions.
pub const VERIFY_ALGS: [&str; 1] = ["ES256"];

/// DPoP proof `iat` window, as in the reference.
const DPOP_MAX_AGE: i64 = 10;
const DPOP_CLOCK_TOLERANCE: i64 = 180;

/// Rejects private keys.
pub fn jwk_to_key(jwk: &J) -> Result<VerifyingKey, String> {
    if jwk.get("kty").and_then(|v| v.as_str()) != Some("EC") || jwk.get("crv").and_then(|v| v.as_str()) != Some("P-256")
    {
        return Err("unsupported JWK (expected EC P-256)".into());
    }
    if jwk.get("d").is_some() {
        return Err("JWK must be a public key".into());
    }
    let x = jwk.get("x").and_then(|v| v.as_str()).and_then(b64u_decode).ok_or("JWK missing x")?;
    let y = jwk.get("y").and_then(|v| v.as_str()).and_then(b64u_decode).ok_or("JWK missing y")?;
    let (Ok(x), Ok(y)) = (p256::FieldBytes::try_from(x.as_slice()), p256::FieldBytes::try_from(y.as_slice())) else {
        return Err("invalid JWK coordinates".into());
    };
    let pt = Sec1Point::from_affine_coordinates(&x, &y, false);
    VerifyingKey::from_sec1_point(&pt).map_err(|_| "invalid JWK point".to_string())
}

pub fn key_to_jwk(k: &VerifyingKey) -> J {
    let pt = k.to_sec1_point(false);
    json!({"kty": "EC", "crv": "P-256", "x": b64u(pt.x().unwrap()), "y": b64u(pt.y().unwrap())})
}

/// RFC 7638.
pub fn jwk_thumbprint(jwk: &J) -> Result<String, String> {
    let k = jwk_to_key(jwk)?;
    let c = key_to_jwk(&k);
    let canon = format!(
        r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
        c["x"].as_str().unwrap(),
        c["y"].as_str().unwrap()
    );
    Ok(sha256_b64u(canon))
}

pub struct DecodedJwt {
    pub header: J,
    pub payload: J,
    signing_input: String,
    sig: Vec<u8>,
}

impl DecodedJwt {
    pub fn decode(token: &str) -> Result<DecodedJwt, String> {
        let mut parts = token.split('.');
        let (h, p, s) = match (parts.next(), parts.next(), parts.next(), parts.next()) {
            (Some(h), Some(p), Some(s), None) => (h, p, s),
            _ => return Err("malformed JWT".into()),
        };
        let header: J = serde_json::from_slice(&b64u_decode(h).ok_or("malformed JWT header")?)
            .map_err(|_| "malformed JWT header")?;
        let payload: J = serde_json::from_slice(&b64u_decode(p).ok_or("malformed JWT payload")?)
            .map_err(|_| "malformed JWT payload")?;
        if !header.is_object() || !payload.is_object() {
            return Err("malformed JWT".into());
        }
        let sig = b64u_decode(s).ok_or("malformed JWT signature")?;
        Ok(DecodedJwt { header, payload, signing_input: format!("{h}.{p}"), sig })
    }

    pub fn alg(&self) -> &str {
        self.header.get("alg").and_then(|v| v.as_str()).unwrap_or("")
    }

    pub fn verify_es256(&self, key: &VerifyingKey) -> bool {
        if self.alg() != "ES256" || self.sig.len() != 64 {
            return false;
        }
        // ring's P-256 verify takes ~30 µs to p256's ~110, and every OAuth
        // request checks a DPoP proof; it accepts the same signatures
        // (high-S included, `verify_es256_matches_p256`)
        let pt = key.to_sec1_point(false);
        ring::signature::UnparsedPublicKey::new(&ring::signature::ECDSA_P256_SHA256_FIXED, pt.as_bytes())
            .verify(self.signing_input.as_bytes(), &self.sig)
            .is_ok()
    }

    pub fn is_unsecured(&self) -> bool {
        self.alg() == "none" && self.sig.is_empty()
    }

    pub fn claim_str(&self, k: &str) -> Option<&str> {
        self.payload.get(k).and_then(|v| v.as_str())
    }

    pub fn claim_i64(&self, k: &str) -> Option<i64> {
        self.payload.get(k).and_then(|v| v.as_i64().or_else(|| v.as_f64().map(|f| f as i64)))
    }
}

/// Derived from the server secret so every node has the same key without
/// shared state.
pub struct ServerKey {
    pub sk: SigningKey,
    pub kid: String,
}

impl ServerKey {
    pub fn derive(server_secret: &str) -> ServerKey {
        let mut ctr = 0u32;
        loop {
            let seed = derive_secret(server_secret, &format!("access-token-es256/{ctr}"));
            if let Ok(sk) = SigningKey::from_bytes(&seed.into()) {
                let kid = jwk_thumbprint(&key_to_jwk(sk.verifying_key())).unwrap();
                return ServerKey { sk, kid };
            }
            ctr += 1;
        }
    }

    pub fn public_jwk(&self) -> J {
        let mut j = key_to_jwk(self.sk.verifying_key());
        j["kid"] = J::String(self.kid.clone());
        j["use"] = J::String("sig".into());
        j["alg"] = J::String("ES256".into());
        j
    }

    /// Hedged and verified before it is returned, as commit signatures are
    /// (vlatproto/src/crypto.rs). Err: failed twice.
    pub fn sign(&self, typ: &str, payload: &J) -> Result<String, vlatproto::crypto::SignatureFault> {
        use p256::ecdsa::signature::RandomizedSigner;
        use p256::elliptic_curve::{common::getrandom::SysRng, rand_core::UnwrapErr};
        use vlatproto::crypto::{fault, record_fault, Purpose, SignatureFault};
        let header = json!({"alg": "ES256", "typ": typ, "kid": self.kid});
        let input =
            format!("{}.{}", b64u(serde_json::to_vec(&header).unwrap()), b64u(serde_json::to_vec(payload).unwrap()));
        let vk = self.sk.verifying_key();
        for _ in 0..2 {
            let sig: Signature = self.sk.sign_with_rng(&mut UnwrapErr(SysRng), input.as_bytes());
            let mut bytes = sig.to_bytes();
            if fault::armed() && fault::take(vk.to_sec1_point(true).as_bytes()).is_some() {
                bytes[40] ^= 0x04;
            }
            let ok = Signature::from_slice(&bytes).is_ok_and(|s| vk.verify(input.as_bytes(), &s).is_ok());
            if ok {
                return Ok(format!("{input}.{}", b64u(bytes)));
            }
            record_fault(Purpose::OAuthToken);
        }
        Err(SignatureFault { purpose: Purpose::OAuthToken.as_str() })
    }

    /// Claims are the caller's to check.
    pub fn verify(&self, token: &str, typ: &str) -> Result<DecodedJwt, String> {
        let jwt = DecodedJwt::decode(token)?;
        if jwt.header.get("typ").and_then(|v| v.as_str()) != Some(typ) {
            return Err("unexpected token type".into());
        }
        if !jwt.verify_es256(self.sk.verifying_key()) {
            return Err("invalid token signature".into());
        }
        Ok(jwt)
    }
}

/// Stateless, as the reference `DpopNonce`: HMAC(secret, window). The
/// previous, current and next windows are accepted, so a nonce lives at most
/// ~3 minutes (the spec caps it at 5).
pub struct DpopNonces {
    secret: [u8; 32],
}

const NONCE_ROTATION_SECS: i64 = 60;

impl DpopNonces {
    pub fn new(server_secret: &str) -> DpopNonces {
        DpopNonces { secret: derive_secret(server_secret, "dpop-nonce") }
    }

    fn compute(&self, counter: i64) -> String {
        b64u(hmac_sha256(&self.secret, &[&counter.to_be_bytes()]))
    }

    /// The upcoming window's, so it stays valid for the longest time.
    pub fn next(&self) -> String {
        self.compute(now_secs() / NONCE_ROTATION_SECS + 1)
    }

    pub fn check(&self, nonce: &str) -> bool {
        let c = now_secs() / NONCE_ROTATION_SECS;
        (c - 1..=c + 1).any(|n| crate::auth::ct_eq(self.compute(n).as_bytes(), nonce.as_bytes()))
    }
}

#[derive(Debug)]
pub enum DpopError {
    /// The client must retry with a fresh server nonce.
    UseNonce(String),
    Invalid(String),
}

#[derive(Debug, Clone)]
pub struct DpopProof {
    pub jkt: String,
    pub jti: String,
    /// Until when the proof could be replayed.
    pub until: i64,
}

impl DpopProof {
    /// `routing`: the access token's DID for resource requests (`ath` binds
    /// the proof to that token), [`super::util::jkt_routing`] at the AS.
    pub fn replay(&self, routing: String) -> Replay {
        Replay { routing, key: format!("dpop:{}:{}", self.jkt, self.jti), until: self.until }
    }
}

/// Origin + path: no query or fragment.
pub fn normalize_htu(u: &str) -> Option<String> {
    let url = reqwest::Url::parse(u).ok()?;
    if !matches!(url.scheme(), "http" | "https") || !url.username().is_empty() || url.password().is_some() {
        return None;
    }
    let origin = url.origin().ascii_serialization();
    Some(format!("{origin}{}", url.path()))
}

/// RFC 9449 §4.3. `access_token`: Some for resource requests (`ath`
/// required), None at the authorization server (`ath` forbidden). Replay
/// protection is the caller's: claim [`DpopProof::replay`] at its owner.
pub fn check_proof(
    proof: &str,
    htm: &str,
    expected_htu: &str,
    access_token: Option<&str>,
    nonces: &DpopNonces,
) -> Result<DpopProof, DpopError> {
    let inv = |m: &str| DpopError::Invalid(m.to_string());
    let jwt = DecodedJwt::decode(proof).map_err(|e| DpopError::Invalid(format!("Failed to verify DPoP proof: {e}")))?;
    if jwt.header.get("typ").and_then(|v| v.as_str()) != Some("dpop+jwt") {
        return Err(inv("Failed to verify DPoP proof: unexpected \"typ\" JWT header value"));
    }
    if !VERIFY_ALGS.contains(&jwt.alg()) {
        return Err(inv("Failed to verify DPoP proof: unsupported \"alg\""));
    }
    let jwk = jwt.header.get("jwk").ok_or_else(|| inv("Failed to verify DPoP proof: missing \"jwk\" header"))?;
    let key = jwk_to_key(jwk).map_err(|e| DpopError::Invalid(format!("Failed to verify DPoP proof: {e}")))?;
    if !jwt.verify_es256(&key) {
        return Err(inv("Failed to verify DPoP proof: signature verification failed"));
    }
    let now = now_secs();
    let iat = jwt.claim_i64("iat").ok_or_else(|| inv("Failed to verify DPoP proof: missing \"iat\" claim"))?;
    if iat > now + DPOP_CLOCK_TOLERANCE {
        return Err(inv(
            "Failed to verify DPoP proof: \"iat\" claim timestamp check failed (it should be in the past)",
        ));
    }
    if iat < now - DPOP_MAX_AGE - DPOP_CLOCK_TOLERANCE {
        return Err(inv("Failed to verify DPoP proof: \"iat\" claim timestamp check failed (too far in the past)"));
    }
    if let Some(exp) = jwt.claim_i64("exp") {
        if exp < now - DPOP_CLOCK_TOLERANCE {
            return Err(inv("Failed to verify DPoP proof: \"exp\" claim timestamp check failed"));
        }
    }
    let nonce = match jwt.payload.get("nonce") {
        None => None,
        Some(J::String(s)) => Some(s.clone()),
        Some(_) => return Err(inv("Invalid DPoP \"nonce\" type")),
    };
    let jti = jwt
        .claim_str("jti")
        .filter(|s| !s.is_empty() && s.len() <= 256)
        .ok_or_else(|| inv("DPoP \"jti\" missing"))?
        .to_string();
    if jwt.claim_str("htm") != Some(htm) {
        return Err(inv("DPoP \"htm\" mismatch"));
    }
    let htu = jwt.claim_str("htu").ok_or_else(|| inv("Invalid DPoP \"htu\" type"))?;
    let htu_norm = normalize_htu(htu).ok_or_else(|| inv("DPoP \"htu\" is not a valid URL"))?;
    if htu_norm != expected_htu {
        return Err(inv("DPoP \"htu\" mismatch"));
    }
    match &nonce {
        None => return Err(DpopError::UseNonce("Authorization server requires nonce in DPoP proof".into())),
        Some(n) if !nonces.check(n) => return Err(DpopError::UseNonce("DPoP \"nonce\" mismatch".into())),
        _ => {}
    }
    let ath = jwt.claim_str("ath");
    match access_token {
        Some(tok) => {
            if ath != Some(sha256_b64u(tok).as_str()) {
                return Err(inv("DPoP \"ath\" mismatch"));
            }
        }
        None => {
            if jwt.payload.get("ath").is_some() {
                return Err(inv("DPoP \"ath\" claim not allowed"));
            }
        }
    }
    let jkt = jwk_thumbprint(jwk).map_err(|e| DpopError::Invalid(format!("Failed to calculate jkt: {e}")))?;
    Ok(DpopProof { jkt, jti, until: now + DPOP_MAX_AGE + 2 * DPOP_CLOCK_TOLERANCE })
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Signer;
    use p256::elliptic_curve::Generate;

    fn proof(sk: &SigningKey, htm: &str, htu: &str, nonce: Option<&str>, ath: Option<&str>) -> String {
        let jwk = key_to_jwk(sk.verifying_key());
        let header = json!({"typ": "dpop+jwt", "alg": "ES256", "jwk": jwk});
        let mut payload =
            json!({"jti": super::super::util::random_id("", 12), "htm": htm, "htu": htu, "iat": now_secs()});
        if let Some(n) = nonce {
            payload["nonce"] = J::String(n.into());
        }
        if let Some(a) = ath {
            payload["ath"] = J::String(sha256_b64u(a));
        }
        let input =
            format!("{}.{}", b64u(serde_json::to_vec(&header).unwrap()), b64u(serde_json::to_vec(&payload).unwrap()));
        let sig: Signature = sk.sign(input.as_bytes());
        format!("{input}.{}", b64u(sig.to_bytes()))
    }

    /// ring and p256 agree on valid, high-S, tampered and out-of-range
    /// signatures (r or s zero, n or above), and only the first two verify.
    #[test]
    fn verify_es256_matches_p256() {
        use p256::elliptic_curve::ops::Reduce;
        // the P-256 group order
        let n = hex::decode("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551").unwrap();
        let n_plus_1 = hex::decode("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552").unwrap();
        let sk = SigningKey::generate();
        let vk = *sk.verifying_key();
        let jwt = |input: &str, sig: Vec<u8>| DecodedJwt {
            header: json!({"alg": "ES256"}),
            payload: json!({}),
            signing_input: input.to_string(),
            sig,
        };
        let n_minus = |s: &[u8]| {
            let s = <p256::Scalar as Reduce<p256::FieldBytes>>::reduce(&p256::FieldBytes::try_from(s).unwrap());
            (-s).to_bytes().to_vec()
        };
        for i in 0..64 {
            let input = format!("header.payload-{i}");
            let sig: Signature = sk.sign(input.as_bytes());
            let b = sig.to_bytes().to_vec();
            let high = [&b[..32], &n_minus(&b[32..])[..]].concat();
            let mut flipped = b.clone();
            flipped[i % 64] ^= 1;
            let zero_s = [&b[..32], &[0u8; 32][..]].concat();
            let big_r = [&[0xffu8; 32][..], &b[32..]].concat();
            let with_s = |s: &[u8]| [&b[..32], s].concat();
            let with_r = |r: &[u8]| [r, &b[32..]].concat();
            for (what, sig, other) in [
                ("valid", b.clone(), &input),
                ("high-S", high, &input),
                ("flipped", flipped, &input),
                ("zero s", zero_s, &input),
                ("r over n", big_r, &input),
                ("s = n", with_s(&n), &input),
                ("s = n + 1", with_s(&n_plus_1), &input),
                ("s = 2^256 - 1", with_s(&[0xff; 32]), &input),
                ("r = 0", with_r(&[0; 32]), &input),
                ("r = n", with_r(&n), &input),
                ("other input", b.clone(), &format!("{input}x")),
            ] {
                let p256_ok = Signature::from_slice(&sig).is_ok_and(|s| vk.verify(other.as_bytes(), &s).is_ok());
                assert_eq!(jwt(other, sig).verify_es256(&vk), p256_ok, "{what} #{i}");
                assert_eq!(p256_ok, what == "valid" || what == "high-S", "{what} #{i}");
            }
        }
    }

    #[test]
    fn dpop_roundtrip() {
        let nonces = DpopNonces::new("secret");
        let sk = SigningKey::generate();
        let htu = "https://pds.example/xrpc/foo";
        let p = proof(&sk, "POST", htu, None, None);
        assert!(matches!(check_proof(&p, "POST", htu, None, &nonces), Err(DpopError::UseNonce(_))));
        let n = nonces.next();
        let p = proof(&sk, "POST", "https://pds.example/xrpc/foo?x=1", Some(&n), Some("tok"));
        let ok = check_proof(&p, "POST", htu, Some("tok"), &nonces).unwrap();
        assert_eq!(ok.jkt, jwk_thumbprint(&key_to_jwk(sk.verifying_key())).unwrap());
        // single use is claimed by the caller, at the routing key's owner
        let r = ok.replay("did:plc:x".into());
        let c = super::super::util::ReplayCache::new(10, 10);
        assert!(c.insert_unique(&r.routing, &r.key, r.until));
        assert!(!c.insert_unique(&r.routing, &r.key, r.until), "replay");
        let p = proof(&sk, "GET", htu, Some(&n), Some("tok"));
        assert!(check_proof(&p, "POST", htu, Some("tok"), &nonces).is_err());
        let p = proof(&sk, "POST", htu, Some(&n), Some("other"));
        assert!(check_proof(&p, "POST", htu, Some("tok"), &nonces).is_err());
        let p = proof(&sk, "POST", htu, Some("bogus"), None);
        assert!(matches!(check_proof(&p, "POST", htu, None, &nonces), Err(DpopError::UseNonce(_))));
    }

    #[test]
    fn server_key_stable() {
        let a = ServerKey::derive("s1");
        let b = ServerKey::derive("s1");
        assert_eq!(a.kid, b.kid);
        let t = a.sign("at+jwt", &json!({"sub": "x"})).unwrap();
        assert!(b.verify(&t, "at+jwt").is_ok());
        assert!(ServerKey::derive("s2").verify(&t, "at+jwt").is_err());
        // hedged: the same token signs differently each time
        assert_ne!(t, a.sign("at+jwt", &json!({"sub": "x"})).unwrap());
    }

    /// A corrupted access-token signature is never returned: one fault is
    /// re-signed, two fail.
    #[test]
    fn server_key_faults_are_caught() {
        use vlatproto::crypto::fault::{inject, Fault};
        // the three faults below reach the fail-stop count, which would end
        // this test binary (vlatproto only skips the exit in its own tests)
        vlatproto::crypto::set_fail_stop_hook(Some(std::sync::Arc::new(|_| {})));
        let a = ServerKey::derive("fault-test");
        let id = a.sk.verifying_key().to_sec1_point(true);
        let failures = || vlatproto::crypto::SIGNATURE_VERIFY_FAILURES.with_label_values(&["oauth_token"]).get();
        let before = failures();
        inject(id.as_bytes(), Fault::Signature, 1);
        let t = a.sign("at+jwt", &json!({"sub": "x"})).unwrap();
        assert!(a.verify(&t, "at+jwt").is_ok());
        inject(id.as_bytes(), Fault::Signature, 2);
        assert!(a.sign("at+jwt", &json!({"sub": "x"})).is_err());
        assert!(failures() >= before + 3);
        assert!(a.verify(&a.sign("at+jwt", &json!({"sub": "x"})).unwrap(), "at+jwt").is_ok());
    }
}
