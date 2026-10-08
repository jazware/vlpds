//! Space JWTs (@atproto/space `credential.ts`). Each kind has its own
//! `typ`, so one can never pass for another:
//!
//! - delegation (`atproto-space-delegation+jwt`): minted by the user's PDS
//!   with the account key (`kid #atproto`) for an app holding `space:`
//!   read access; `iss` the user, `sub` the space, `aud` the authority's
//!   `#atproto_space_host`; 60 s, single use.
//! - credential (`atproto-space-credential+jwt`): minted by the space
//!   authority in exchange; `iss` the authority, `sub` the space, no `aud`,
//!   `cnf.kid` the P-256 did:key requests must be signed with
//!   ([`super::httpsig`]); 10 min by default, at most 60.
//! - client attestation (`atproto-client-attestation+jwt`): an app's own
//!   claim, `iss` = `sub` = its client_id; its key comes from the client's
//!   JWKS, so this checks structure only.
//!
//! Pure: callers resolve keys. On a bad signature the reference resolves
//! the issuer's key once more, bypassing its cache, and retries if the key
//! changed (rotation); [`SpaceToken::verify_signature`] is one attempt.

use base64::Engine;
use serde_json::Value as J;
use vlatproto::syntax;

pub const CLOCK_SKEW_SECS: i64 = 5;
pub const CREDENTIAL_MAX_AGE_SECS: i64 = 3600;
/// Delegation tokens and client attestations live 60 s. The reference
/// bounds neither, but a single-use `jti` is held until `exp`, so an
/// unbounded one would pin replay state forever.
pub const SINGLE_USE_MAX_SECS: i64 = 300;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenType {
    Delegation,
    Credential,
    ClientAttestation,
}

impl TokenType {
    pub fn typ(self) -> &'static str {
        match self {
            TokenType::Delegation => "atproto-space-delegation+jwt",
            TokenType::Credential => "atproto-space-credential+jwt",
            TokenType::ClientAttestation => "atproto-client-attestation+jwt",
        }
    }

    fn default_kid(self) -> Option<&'static str> {
        match self {
            TokenType::Delegation | TokenType::Credential => Some("#atproto"),
            TokenType::ClientAttestation => None,
        }
    }

    pub fn default_lifetime_secs(self) -> i64 {
        match self {
            TokenType::Credential => 600,
            TokenType::Delegation | TokenType::ClientAttestation => 60,
        }
    }

    fn requires_aud(self) -> bool {
        self != TokenType::Credential
    }
}

/// The reference's `SpaceTokenError`: `code` is the XRPC error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenError {
    pub code: &'static str,
    pub message: String,
}

fn err(code: &'static str, message: impl Into<String>) -> TokenError {
    TokenError { code, message: message.into() }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Header {
    pub alg: String,
    pub typ: String,
    pub kid: Option<String>,
}

/// Times are JSON numbers, which the reference doesn't require to be
/// integers.
#[derive(Debug, Clone, PartialEq)]
pub struct Claims {
    pub iss: String,
    /// The space URI; a client attestation's client_id.
    pub sub: String,
    /// Only when a string.
    pub aud: Option<String>,
    pub iat: Option<f64>,
    pub exp: f64,
    pub jti: String,
    pub cnf_kid: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SpaceToken {
    pub ty: TokenType,
    pub header: Header,
    pub claims: Claims,
    signing_input: String,
    sig: Vec<u8>,
}

/// Base64url, `=` padding optional and unused bits ignored, as the
/// reference decodes JWT parts.
const B64: base64::engine::GeneralPurpose = base64::engine::GeneralPurpose::new(
    &base64::alphabet::URL_SAFE,
    base64::engine::GeneralPurposeConfig::new()
        .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent)
        .with_decode_allow_trailing_bits(true),
);

fn truthy(v: Option<&J>) -> bool {
    match v {
        None | Some(J::Null) => false,
        Some(J::Bool(b)) => *b,
        Some(J::String(s)) => !s.is_empty(),
        Some(J::Number(n)) => n.as_f64().is_some_and(|f| f != 0.0),
        Some(J::Array(_) | J::Object(_)) => true,
    }
}

fn finite(v: Option<&J>) -> Option<f64> {
    v?.as_f64().filter(|f| f.is_finite())
}

fn decode_part(b64: &str, part: &str) -> Result<serde_json::Map<String, J>, TokenError> {
    let bytes = B64.decode(b64).map_err(|e| err("BadJwt", format!("could not parse token {part}: {e}")))?;
    match serde_json::from_slice(&bytes) {
        Ok(J::Object(m)) => Ok(m),
        Ok(_) => Err(err("BadJwt", format!("could not parse token {part}: not an object"))),
        Err(e) => Err(err("BadJwt", format!("could not parse token {part}: {e}"))),
    }
}

/// Structure only (`parseSpaceToken`): no signature, time, audience or
/// subject check.
pub fn parse(ty: TokenType, jwt: &str) -> Result<SpaceToken, TokenError> {
    let parts: Vec<&str> = jwt.split('.').collect();
    let &[header_b64, payload_b64, sig_b64] = parts.as_slice() else {
        return Err(err("BadJwt", "malformed token: expected 3 parts"));
    };
    let h = decode_part(header_b64, "header")?;
    let p = decode_part(payload_b64, "payload")?;
    let s = |m: &serde_json::Map<String, J>, k: &str| m.get(k).and_then(|v| v.as_str()).map(String::from);

    let typ = s(&h, "typ").filter(|t| t == ty.typ()).ok_or_else(|| {
        err(
            "BadJwtType",
            format!("wrong token type: expected \"{}\", got {}", ty.typ(), h.get("typ").unwrap_or(&J::Null)),
        )
    })?;
    let alg = s(&h, "alg").filter(|a| !a.is_empty()).ok_or_else(|| err("BadJwt", "missing token \"alg\""))?;
    // the reference only requires these to be truthy; a non-string fails
    // later there (key resolution, the space ref), here up front
    let iss = s(&p, "iss").filter(|v| !v.is_empty()).ok_or_else(|| err("BadJwtIss", "missing token \"iss\""))?;
    let sub = s(&p, "sub").filter(|v| !v.is_empty()).ok_or_else(|| err("BadJwtSub", "missing token \"sub\""))?;
    let exp = finite(p.get("exp")).ok_or_else(|| err("BadJwt", "missing token \"exp\""))?;
    if ty.requires_aud() && !truthy(p.get("aud")) {
        return Err(err("BadJwtAudience", "missing token \"aud\""));
    }
    let cnf_kid = p.get("cnf").and_then(|c| c.get("kid")).and_then(|k| k.as_str()).map(String::from);
    if ty == TokenType::Credential && !cnf_kid.as_deref().is_some_and(syntax::valid_did) {
        return Err(err("BadJwtCnf", "missing token \"cnf.kid\""));
    }
    let jti = s(&p, "jti").filter(|v| !v.is_empty()).ok_or_else(|| err("BadJwt", "a token requires a \"jti\""))?;
    // a credential's jti must be one a revocation can name
    if !super::revocations::valid_jti(&jti) {
        return Err(err("BadJwt", "a token's \"jti\" must be at most 128 printable ASCII characters"));
    }
    let iat = finite(p.get("iat"));
    if ty == TokenType::Credential && !iat.is_some_and(|iat| exp > iat && exp - iat <= CREDENTIAL_MAX_AGE_SECS as f64) {
        return Err(err("BadJwt", "invalid space credential lifetime"));
    }
    if ty == TokenType::ClientAttestation && iss != sub {
        return Err(err("BadJwtIss", "client attestation \"iss\" and \"sub\" must both be the client_id"));
    }
    let sig = B64.decode(sig_b64).map_err(|_| err("BadJwt", "could not parse token signature"))?;
    Ok(SpaceToken {
        ty,
        header: Header { alg, typ, kid: s(&h, "kid") },
        claims: Claims { iss, sub, aud: s(&p, "aud"), iat, exp, jti, cnf_kid },
        signing_input: format!("{header_b64}.{payload_b64}"),
        sig,
    })
}

impl SpaceToken {
    /// `verifySpaceToken` before the signature: issued in the future
    /// (credentials only), expiry, and `aud`/`sub` when given. `now` in
    /// Unix seconds.
    pub fn check(&self, now: i64, aud: Option<&str>, sub: Option<&str>) -> Result<(), TokenError> {
        let c = &self.claims;
        let now = now as f64;
        if self.ty == TokenType::Credential && c.iat.is_some_and(|iat| iat > now + CLOCK_SKEW_SECS as f64) {
            return Err(err("BadJwt", "space credential issued in the future"));
        }
        if now - CLOCK_SKEW_SECS as f64 >= c.exp {
            return Err(err("JwtExpired", "token expired"));
        }
        if self.ty != TokenType::Credential && c.exp > now + (SINGLE_USE_MAX_SECS + CLOCK_SKEW_SECS) as f64 {
            return Err(err("BadJwt", "token lifetime too long"));
        }
        if aud.is_some_and(|a| c.aud.as_deref() != Some(a)) {
            return Err(err("BadJwtAudience", "token audience does not match this service"));
        }
        if sub.is_some_and(|s| c.sub != s) {
            return Err(err("BadJwtSub", "token subject does not match the requested space"));
        }
        Ok(())
    }

    /// Signed by `did_key`, whose algorithm must be the header's `alg`.
    /// Low-S compact signatures only.
    pub fn verify_signature(&self, did_key: &str) -> Result<(), TokenError> {
        if super::did_key_alg(did_key) != Some(self.header.alg.as_str()) {
            return Err(err("BadJwtSignature", "could not verify token signature: key does not match \"alg\""));
        }
        match super::verify_did_key(did_key, self.signing_input.as_bytes(), &self.sig, false) {
            Ok(true) => Ok(()),
            Ok(false) => Err(err("BadJwtSignature", "invalid token signature")),
            Err(e) => Err(err("BadJwtSignature", format!("could not verify token signature: {e}"))),
        }
    }
}

/// The DID document verification method a token's `kid` names: the
/// account key, or a dedicated space key (reference PDS
/// `resolveSpaceKey`). The `#` is optional.
pub fn key_id(kid: Option<&str>) -> Result<&str, TokenError> {
    let kid = kid.ok_or_else(|| err("BadJwt", "missing token \"kid\""))?;
    match kid.strip_prefix('#').unwrap_or(kid) {
        k @ ("atproto" | "atproto_space") => Ok(k),
        _ => Err(err("BadJwt", format!("unsupported space token \"kid\": {kid}"))),
    }
}

/// The audience a delegation token (and a client attestation) names.
pub fn space_host_aud(authority: &str) -> String {
    format!("{authority}#atproto_space_host")
}

/// A token's `sub` as a space ref: the 3-part URI exactly (reference PDS
/// `parseSpaceSub`).
pub fn space_of(t: &SpaceToken) -> Result<syntax::SpaceUri<'_>, TokenError> {
    syntax::parse_space_uri(&t.claims.sub)
        .filter(|u| u.record.is_none())
        .ok_or_else(|| err("BadJwtSub", format!("space token subject is not a space URI: {}", t.claims.sub)))
}

/// The reference PDS's checks on a verified delegation token: addressed to
/// the space's authority (so one minted for one authority is refused at
/// another sharing this host), issued by a DID. Single use is the caller's.
pub fn check_delegation(t: &SpaceToken) -> Result<syntax::SpaceUri<'_>, TokenError> {
    let space = space_of(t)?;
    if t.claims.aud.as_deref() != Some(space_host_aud(space.authority).as_str()) {
        return Err(err("BadJwtAudience", "delegation token audience does not match the space authority"));
    }
    if !syntax::valid_did(&t.claims.iss) {
        return Err(err("BadJwtIss", "delegation token issuer is not a DID"));
    }
    Ok(space)
}

/// The reference PDS's check on a verified credential: issued by the
/// space's authority. Revocation is the caller's.
pub fn check_credential(t: &SpaceToken) -> Result<syntax::SpaceUri<'_>, TokenError> {
    let space = space_of(t)?;
    if t.claims.iss != space.authority {
        return Err(err("BadJwtIss", "space credential issuer is not the space authority"));
    }
    Ok(space)
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Mint<'a> {
    pub iss: &'a str,
    pub sub: &'a str,
    pub aud: Option<&'a str>,
    /// `cnf.kid`: credentials only.
    pub key_id: Option<&'a str>,
    /// Default: the type's.
    pub expires_in_secs: Option<i64>,
    /// Default: `#atproto` (none for a client attestation).
    pub kid: Option<&'a str>,
}

#[derive(Debug)]
pub enum MintError<E> {
    Invalid(&'static str),
    Sign(E),
}

/// 16 random bytes, hex (the reference's `randomStr(16, 'hex')`).
pub fn new_jti() -> String {
    hex::encode(rand::random::<[u8; 16]>())
}

/// `createSpaceToken`: the header and claims serialize in the reference's
/// order. `alg` is the signing key's (ES256K for an account key); `now`
/// and `jti` are the caller's ([`new_jti`]).
pub fn encode<E>(
    ty: TokenType,
    m: &Mint,
    alg: &str,
    now: i64,
    jti: &str,
    sign: impl FnOnce(&[u8]) -> Result<[u8; 64], E>,
) -> Result<String, MintError<E>> {
    if ty.requires_aud() && m.aud.is_none_or(str::is_empty) {
        return Err(MintError::Invalid("token requires an \"aud\""));
    }
    if ty == TokenType::Credential && m.key_id.is_none_or(str::is_empty) {
        return Err(MintError::Invalid("token requires a \"keyId\""));
    }
    let lifetime = m.expires_in_secs.unwrap_or(ty.default_lifetime_secs());
    if ty == TokenType::Credential && !(1..=CREDENTIAL_MAX_AGE_SECS).contains(&lifetime) {
        return Err(MintError::Invalid("invalid space credential lifetime"));
    }
    let q = |s: &str| J::String(s.into()).to_string();
    let mut header = format!("{{\"alg\":{},\"typ\":{}", q(alg), q(ty.typ()));
    if let Some(kid) = m.kid.or(ty.default_kid()).filter(|k| !k.is_empty()) {
        header += &format!(",\"kid\":{}", q(kid));
    }
    header.push('}');
    let mut payload = format!("{{\"iss\":{},\"sub\":{}", q(m.iss), q(m.sub));
    if let Some(aud) = m.aud.filter(|a| !a.is_empty()) {
        payload += &format!(",\"aud\":{}", q(aud));
    }
    if let Some(k) = m.key_id.filter(|k| !k.is_empty()) {
        payload += &format!(",\"cnf\":{{\"kid\":{}}}", q(k));
    }
    payload += &format!(",\"iat\":{now},\"exp\":{},\"jti\":{}}}", now + lifetime, q(jti));
    let input = format!("{}.{}", B64_OUT.encode(header), B64_OUT.encode(payload));
    let sig = sign(input.as_bytes()).map_err(MintError::Sign)?;
    Ok(format!("{input}.{}", B64_OUT.encode(sig)))
}

const B64_OUT: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::space::vectors::VECTORS;
    use sha2::Digest;
    use vlatproto::crypto::Keypair;

    const SPACE: &str = "at://did:example:space/space/app.bsky.group/test";
    const USER: &str = "did:example:alice";
    const AUTHORITY: &str = "did:example:space";
    const NOW: i64 = 1_790_000_000;

    fn space_host() -> String {
        space_host_aud(AUTHORITY)
    }

    fn mint(ty: TokenType, m: &Mint, key: &Keypair, now: i64) -> String {
        encode(ty, m, "ES256K", now, &new_jti(), |b| Ok::<_, ()>(key.sign(b))).unwrap()
    }

    fn verify(
        ty: TokenType,
        jwt: &str,
        key: &str,
        now: i64,
        aud: Option<&str>,
        sub: Option<&str>,
    ) -> Result<SpaceToken, TokenError> {
        let t = parse(ty, jwt)?;
        t.check(now, aud, sub)?;
        t.verify_signature(key)?;
        Ok(t)
    }

    /// Re-signs a token after changing its claims (the reference test's
    /// `withClaims`).
    fn with_claims(jwt: &str, claims: J, key: &Keypair) -> String {
        let mut parts = jwt.split('.');
        let header = parts.next().unwrap();
        let mut p: J = serde_json::from_slice(&B64.decode(parts.next().unwrap()).unwrap()).unwrap();
        for (k, v) in claims.as_object().unwrap() {
            match v {
                J::Null => p.as_object_mut().unwrap().remove(k),
                v => p.as_object_mut().unwrap().insert(k.clone(), v.clone()),
            };
        }
        let input = format!("{header}.{}", B64_OUT.encode(p.to_string()));
        format!("{input}.{}", B64_OUT.encode(key.sign(input.as_bytes())))
    }

    fn retype(jwt: &str, typ: &str) -> String {
        let mut parts: Vec<String> = jwt.split('.').map(String::from).collect();
        let mut h: J = serde_json::from_slice(&B64.decode(&parts[0]).unwrap()).unwrap();
        h["typ"] = typ.into();
        parts[0] = B64_OUT.encode(h.to_string());
        parts.join(".")
    }

    /// testdata/spaces-alpha/vectors.json `tokens`: minted by the
    /// reference (secp256k1 and P-256 issuers), verified here at the
    /// reference's pinned clock; and minting here with the same inputs and
    /// RFC 6979 gives the reference's bytes.
    #[test]
    fn generated_vectors() {
        let now = VECTORS["now"].as_i64().unwrap();
        let cases = VECTORS["tokens"].as_array().unwrap();
        assert_eq!(cases.len(), 4);
        for c in cases {
            let ty = match c["type"].as_str().unwrap() {
                "delegation" => TokenType::Delegation,
                "credential" => TokenType::Credential,
                t => panic!("{t}"),
            };
            let jwt = c["jwt"].as_str().unwrap();
            let key = c["signingKey"].as_str().unwrap();
            let o = &c["opts"];
            let t = verify(ty, jwt, key, now, o["aud"].as_str(), Some(o["sub"].as_str().unwrap())).unwrap();
            assert_eq!(t.claims.iss, o["iss"].as_str().unwrap());
            assert_eq!(t.claims.cnf_kid.as_deref(), o["keyId"].as_str());
            assert_eq!(t.claims.iat, Some(now as f64));
            let lifetime = o["expiresInSec"].as_i64().unwrap_or(ty.default_lifetime_secs());
            assert_eq!(t.claims.exp, (now + lifetime) as f64);
            assert_eq!(t.header.kid.as_deref(), Some(o["kid"].as_str().unwrap_or("#atproto")));
            match ty {
                TokenType::Delegation => assert!(check_delegation(&t).is_ok()),
                _ => assert!(check_credential(&t).is_ok()),
            }
            assert!(key_id(t.header.kid.as_deref()).is_ok());
            // expired at exp + skew, not before
            assert!(t.check(t.claims.exp as i64 + 4, None, None).is_ok());
            assert_eq!(t.check(t.claims.exp as i64 + 5, None, None).unwrap_err().code, "JwtExpired");

            if t.header.alg == "ES256K" {
                let seed = match ty {
                    TokenType::Delegation => "vlpds spaces alpha user k256",
                    _ => "vlpds spaces alpha authority k256",
                };
                let k = Keypair::from_bytes(&sha2::Sha256::digest(seed.as_bytes())).unwrap();
                assert_eq!(k.did_key(), key);
                let m = Mint {
                    iss: o["iss"].as_str().unwrap(),
                    sub: o["sub"].as_str().unwrap(),
                    aud: o["aud"].as_str(),
                    key_id: o["keyId"].as_str(),
                    expires_in_secs: o["expiresInSec"].as_i64(),
                    kid: o["kid"].as_str(),
                };
                let mine =
                    encode(ty, &m, "ES256K", now, &t.claims.jti, |b| Ok::<_, ()>(k.sign_deterministic(b))).unwrap();
                assert_eq!(mine, jwt);
            }
        }
    }

    // The cases below are the reference's tests/credential.test.ts.

    #[test]
    fn delegation() {
        let (user, authority) = (Keypair::generate(), Keypair::generate());
        let host = space_host();
        let m = Mint { iss: USER, sub: SPACE, aud: Some(&host), ..Default::default() };
        let jwt = mint(TokenType::Delegation, &m, &user, NOW);
        let t = verify(TokenType::Delegation, &jwt, &user.did_key(), NOW, Some(&host), Some(SPACE)).unwrap();
        assert_eq!(
            (t.header.typ.as_str(), t.header.kid.as_deref(), t.header.alg.as_str()),
            ("atproto-space-delegation+jwt", Some("#atproto"), "ES256K")
        );
        assert_eq!(
            (t.claims.iss.as_str(), t.claims.sub.as_str(), t.claims.aud.as_deref()),
            (USER, SPACE, Some(host.as_str()))
        );
        assert_eq!(t.claims.exp - t.claims.iat.unwrap(), 60.0);
        assert!(t.claims.jti.len() == 32 && t.claims.jti.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(check_delegation(&t).unwrap().authority, AUTHORITY);

        let no_aud = Mint { aud: None, ..m };
        assert!(matches!(
            encode(TokenType::Delegation, &no_aud, "ES256K", NOW, "j", |_| Ok::<_, ()>([0; 64])),
            Err(MintError::Invalid(_))
        ));
        let code = |r: Result<SpaceToken, TokenError>| r.unwrap_err().code;
        assert_eq!(
            code(verify(
                TokenType::Delegation,
                &jwt,
                &user.did_key(),
                NOW,
                Some("did:example:other#atproto_space_host"),
                None
            )),
            "BadJwtAudience"
        );
        assert_eq!(
            code(verify(
                TokenType::Delegation,
                &jwt,
                &user.did_key(),
                NOW,
                Some(&host),
                Some("at://did:example:space/space/app.bsky.group/other")
            )),
            "BadJwtSub"
        );
        assert_eq!(
            code(verify(TokenType::Delegation, &jwt, &authority.did_key(), NOW, Some(&host), None)),
            "BadJwtSignature"
        );
        assert_eq!(code(verify(TokenType::Credential, &jwt, &user.did_key(), NOW, None, None)), "BadJwtType");

        // single-use tokens can't outlive the replay window
        let long = Mint { expires_in_secs: Some(306), ..m };
        let jwt = mint(TokenType::Delegation, &long, &user, NOW);
        assert_eq!(code(verify(TokenType::Delegation, &jwt, &user.did_key(), NOW, None, None)), "BadJwt");
        let ok = mint(TokenType::Delegation, &Mint { expires_in_secs: Some(305), ..m }, &user, NOW);
        assert!(verify(TokenType::Delegation, &ok, &user.did_key(), NOW, None, None).is_ok());

        // addressed to another authority than the space's
        let elsewhere = Mint { aud: Some("did:example:other#atproto_space_host"), ..m };
        let t = parse(TokenType::Delegation, &mint(TokenType::Delegation, &elsewhere, &user, NOW)).unwrap();
        assert_eq!(check_delegation(&t).unwrap_err().code, "BadJwtAudience");
        let not_did = Mint { iss: "alice.test", ..m };
        let t = parse(TokenType::Delegation, &mint(TokenType::Delegation, &not_did, &user, NOW)).unwrap();
        assert_eq!(check_delegation(&t).unwrap_err().code, "BadJwtIss");
        for sub in [
            "at://did:example:space/space/app.bsky.group/test/did:example:alice/app.bsky.feed.post/1",
            "at://did:example:space/space/app.bsky.group/test#/x",
            "at://did:example:space/app.bsky.group/test",
        ] {
            let t = parse(TokenType::Delegation, &mint(TokenType::Delegation, &Mint { sub, ..m }, &user, NOW)).unwrap();
            assert_eq!(check_delegation(&t).unwrap_err().code, "BadJwtSub", "{sub}");
        }
    }

    #[test]
    fn credential() {
        let authority = Keypair::generate();
        let key_did = VECTORS["httpsig"][0]["keyDid"].as_str().unwrap();
        let m = Mint { iss: AUTHORITY, sub: SPACE, key_id: Some(key_did), ..Default::default() };
        let ak = authority.did_key();
        let jwt = mint(TokenType::Credential, &m, &authority, NOW);
        let t = verify(TokenType::Credential, &jwt, &ak, NOW, None, Some(SPACE)).unwrap();
        assert_eq!(
            (t.header.typ.as_str(), t.header.kid.as_deref()),
            ("atproto-space-credential+jwt", Some("#atproto"))
        );
        assert_eq!((t.claims.aud.as_deref(), t.claims.exp - t.claims.iat.unwrap()), (None, 600.0));
        assert_eq!(t.claims.cnf_kid.as_deref(), Some(key_did));
        assert_eq!(check_credential(&t).unwrap().skey, "test");

        let hour = mint(TokenType::Credential, &Mint { expires_in_secs: Some(3600), ..m }, &authority, NOW);
        assert_eq!(verify(TokenType::Credential, &hour, &ak, NOW, None, None).unwrap().claims.exp, (NOW + 3600) as f64);
        for bad in [0, -1, 3601] {
            let r =
                encode(TokenType::Credential, &Mint { expires_in_secs: Some(bad), ..m }, "ES256K", NOW, "j", |_| {
                    Ok::<_, ()>([0; 64])
                });
            assert!(matches!(r, Err(MintError::Invalid("invalid space credential lifetime"))), "{bad}");
        }
        assert!(matches!(
            encode(TokenType::Credential, &Mint { key_id: None, ..m }, "ES256K", NOW, "j", |_| Ok::<_, ()>([0; 64])),
            Err(MintError::Invalid(_))
        ));

        for claims in [
            serde_json::json!({"iat": null}),
            serde_json::json!({"iat": "now"}),
            serde_json::json!({"jti": null}),
            serde_json::json!({"jti": ""}),
            serde_json::json!({"jti": 123}),
            serde_json::json!({"exp": NOW + 3601}),
            serde_json::json!({"exp": NOW}),
            serde_json::json!({"exp": "later"}),
        ] {
            let jwt = with_claims(&jwt, claims.clone(), &authority);
            assert_eq!(
                verify(TokenType::Credential, &jwt, &ak, NOW, None, None).unwrap_err().code,
                "BadJwt",
                "{claims}"
            );
        }
        for (claims, code) in [
            (serde_json::json!({"cnf": null}), "BadJwtCnf"),
            (serde_json::json!({"cnf": {"kid": "not a did"}}), "BadJwtCnf"),
            (serde_json::json!({"iss": null}), "BadJwtIss"),
            (serde_json::json!({"iss": 1}), "BadJwtIss"),
            (serde_json::json!({"sub": ""}), "BadJwtSub"),
        ] {
            let jwt = with_claims(&jwt, claims.clone(), &authority);
            assert_eq!(verify(TokenType::Credential, &jwt, &ak, NOW, None, None).unwrap_err().code, code, "{claims}");
        }
        // future issuance beyond the skew
        let future = with_claims(&jwt, serde_json::json!({"iat": NOW + 60, "exp": NOW + 660}), &authority);
        assert_eq!(verify(TokenType::Credential, &future, &ak, NOW, None, None).unwrap_err().code, "BadJwt");
        let near = with_claims(&jwt, serde_json::json!({"iat": NOW + 5, "exp": NOW + 605}), &authority);
        assert!(verify(TokenType::Credential, &near, &ak, NOW, None, None).is_ok());
        // a delegation token retyped as a credential carries no binding
        let host = space_host();
        let unbound = mint(
            TokenType::Delegation,
            &Mint { iss: AUTHORITY, sub: SPACE, aud: Some(&host), ..Default::default() },
            &authority,
            NOW,
        );
        assert_eq!(
            parse(TokenType::Credential, &retype(&unbound, TokenType::Credential.typ())).unwrap_err().code,
            "BadJwtCnf"
        );
        // expiry, with the 5 s skew
        let short = mint(TokenType::Credential, &Mint { expires_in_secs: Some(1), ..m }, &authority, NOW);
        assert_eq!(verify(TokenType::Credential, &short, &ak, NOW + 60, None, None).unwrap_err().code, "JwtExpired");
        assert!(verify(TokenType::Credential, &short, &ak, NOW + 3, None, None).is_ok());
        // issued by someone other than the space's authority
        let t = parse(TokenType::Credential, &mint(TokenType::Credential, &Mint { iss: USER, ..m }, &authority, NOW))
            .unwrap();
        assert_eq!(check_credential(&t).unwrap_err().code, "BadJwtIss");
    }

    #[test]
    fn signatures() {
        let authority = Keypair::generate();
        let key_did = VECTORS["httpsig"][0]["keyDid"].as_str().unwrap();
        let m = Mint { iss: AUTHORITY, sub: SPACE, key_id: Some(key_did), ..Default::default() };
        let jwt = mint(TokenType::Credential, &m, &authority, NOW);
        let t = parse(TokenType::Credential, &jwt).unwrap();
        assert!(t.verify_signature(&authority.did_key()).is_ok());
        // a key of another algorithm than the header's
        assert_eq!(t.verify_signature(key_did).unwrap_err().code, "BadJwtSignature");
        assert_eq!(t.verify_signature("did:plc:abc").unwrap_err().code, "BadJwtSignature");
        // alg none, or a header claiming another algorithm
        for alg in ["none", "ES256", "HS256"] {
            let jwt = encode(TokenType::Credential, &m, alg, NOW, "j", |b| Ok::<_, ()>(authority.sign(b))).unwrap();
            let t = parse(TokenType::Credential, &jwt).unwrap();
            assert_eq!(t.verify_signature(&authority.did_key()).unwrap_err().code, "BadJwtSignature", "{alg}");
        }
        // high-S and DER are refused
        let parts: Vec<&str> = jwt.split('.').collect();
        let sig = B64.decode(parts[2]).unwrap();
        let n = hex::decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141").unwrap();
        let mut high = sig[..32].to_vec();
        high.extend(crate::space::commit::tests::sub_be(&n, &sig[32..]));
        let high = format!("{}.{}.{}", parts[0], parts[1], B64_OUT.encode(high));
        assert_eq!(
            parse(TokenType::Credential, &high).unwrap().verify_signature(&authority.did_key()).unwrap_err().code,
            "BadJwtSignature"
        );
        let der = secp256k1::ecdsa::Signature::from_compact(&sig).unwrap().serialize_der();
        let der = format!("{}.{}.{}", parts[0], parts[1], B64_OUT.encode(der));
        assert_eq!(
            parse(TokenType::Credential, &der).unwrap().verify_signature(&authority.did_key()).unwrap_err().code,
            "BadJwtSignature"
        );
        // a tampered payload
        let tampered = format!("{}.{}.{}", parts[0], B64_OUT.encode(br#"{"iss":"did:example:space"}"#), parts[2]);
        assert!(parse(TokenType::Credential, &tampered).is_err());
    }

    #[test]
    fn kids() {
        assert_eq!(key_id(Some("#atproto")), Ok("atproto"));
        assert_eq!(key_id(Some("atproto_space")), Ok("atproto_space"));
        assert_eq!(key_id(Some("#atproto_space")), Ok("atproto_space"));
        for bad in [None, Some("#atproto_pds"), Some(""), Some("#"), Some("did:plc:x#atproto")] {
            assert_eq!(key_id(bad).unwrap_err().code, "BadJwt", "{bad:?}");
        }
        let key = Keypair::generate();
        let m = Mint {
            iss: AUTHORITY,
            sub: SPACE,
            key_id: Some("did:key:zx"),
            kid: Some("#atproto_space"),
            ..Default::default()
        };
        let t = parse(TokenType::Credential, &mint(TokenType::Credential, &m, &key, NOW)).unwrap();
        assert_eq!(t.header.kid.as_deref(), Some("#atproto_space"));
    }

    #[test]
    fn client_attestation() {
        let key = Keypair::generate();
        let client = "https://app.example.com/client-metadata.json";
        let host = space_host();
        let m = Mint { iss: client, sub: client, aud: Some(&host), kid: Some("key-1"), ..Default::default() };
        let t = parse(TokenType::ClientAttestation, &mint(TokenType::ClientAttestation, &m, &key, NOW)).unwrap();
        assert_eq!((t.header.typ.as_str(), t.header.kid.as_deref()), ("atproto-client-attestation+jwt", Some("key-1")));
        assert!(t.check(NOW, Some(&host), None).is_ok());
        assert!(t.verify_signature(&key.did_key()).is_ok());
        let other = Mint { sub: "https://other.example/x", ..m };
        let e =
            parse(TokenType::ClientAttestation, &mint(TokenType::ClientAttestation, &other, &key, NOW)).unwrap_err();
        assert_eq!(e.code, "BadJwtIss");
        // no default kid
        let t = parse(
            TokenType::ClientAttestation,
            &mint(TokenType::ClientAttestation, &Mint { kid: None, ..m }, &key, NOW),
        )
        .unwrap();
        assert_eq!(t.header.kid, None);
    }

    #[test]
    fn malformed() {
        for jwt in ["nope", "aaa.bbb", "!!!.e30.c2ln", "e30.e30.c2ln.x", "", "..", "W10.e30.c2ln", "bnVsbA.e30.c2ln"] {
            assert!(parse(TokenType::Credential, jwt).is_err(), "{jwt}");
        }
        let header = B64_OUT.encode(br#"{"alg":"ES256K","typ":"atproto-space-credential+jwt"}"#);
        let payload = B64_OUT.encode(br#"{"iss":"did:example:space"}"#);
        assert_eq!(parse(TokenType::Credential, &format!("{header}.{payload}.c2ln")).unwrap_err().code, "BadJwtSub");
        let header = B64_OUT.encode(br#"{"typ":"atproto-space-credential+jwt"}"#);
        assert_eq!(parse(TokenType::Credential, &format!("{header}.{payload}.c2ln")).unwrap_err().code, "BadJwt");
        // padded parts decode too
        let header = base64::engine::general_purpose::URL_SAFE
            .encode(br#"{"alg":"ES256K","typ":"atproto-space-delegation+jwt"}"#);
        let payload = base64::engine::general_purpose::URL_SAFE
            .encode(br#"{"iss":"did:x:a","sub":"s","aud":"a","exp":1,"jti":"j"}"#);
        assert!(parse(TokenType::Delegation, &format!("{header}.{payload}.c2ln")).is_ok());
    }
}
