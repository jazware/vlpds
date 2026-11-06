//! The shared secret a syncer and a repo host MAC a response with
//! (@atproto/space `kem.ts`): ECDH on P-256 against the author's
//! `#atproto_kem` key, derived as DHKEM(P-256, HKDF-SHA256) does (RFC 9180
//! §4.1) with the syncer's ephemeral public key as `enc`.
//!
//! ```text
//! dh     = x(ECDH(syncer, author))          (32 bytes)
//! keys   = uncompressed(syncer) || uncompressed(author)
//! prefix = "HPKE-v1" || "KEM" || u16be(0x0010)
//! secret = HKDF-SHA256(ikm = prefix || "eae_prk" || dh, salt = "",
//!                      info = u16be(32) || prefix || "shared_secret" || keys, L = 32)
//! ```
//!
//! The syncer's key is new for every request (retries and pages too), and
//! unrelated to the key a credential is bound to.

use hmac::{Hmac, KeyInit, Mac};
use p256::elliptic_curve::point::AffineCoordinates;
use p256::elliptic_curve::sec1::ToSec1Point;
use sha2::Sha256;

/// The reference's `SpaceMacError` (`BadSpaceMac`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacError(pub &'static str);

impl MacError {
    pub const CODE: &str = "BadSpaceMac";
}

impl std::fmt::Display for MacError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

/// An account's KEM keypair (the repo host's half).
#[derive(Clone)]
pub struct KemKey(p256::SecretKey);

impl KemKey {
    pub fn generate() -> KemKey {
        loop {
            if let Ok(k) = p256::SecretKey::from_slice(&rand::random::<[u8; 32]>()) {
                return KemKey(k);
            }
        }
    }

    /// The 32-byte scalar, as it's stored (wrapped).
    pub fn from_bytes(b: &[u8]) -> Option<KemKey> {
        p256::SecretKey::from_slice(b).ok().map(KemKey)
    }

    pub fn to_bytes(&self) -> zeroize::Zeroizing<Vec<u8>> {
        zeroize::Zeroizing::new(self.0.to_bytes().to_vec())
    }

    /// The public key as a multikey multibase (`z…`), as a DID document's
    /// `publicKeyMultibase` and a PLC op's `did:key` carry it.
    pub fn public_multibase(&self) -> String {
        multibase(&self.0.public_key())
    }

    pub fn did_key(&self) -> String {
        format!("did:key:{}", self.public_multibase())
    }
}

fn multibase(pk: &p256::PublicKey) -> String {
    let mut mk = vec![0x80, 0x24];
    mk.extend_from_slice(pk.to_sec1_point(true).as_bytes());
    format!("z{}", bs58::encode(mk).into_string())
}

/// A P-256 did:key's public key.
pub fn parse_p256_did_key(did_key: &str) -> Result<p256::PublicKey, MacError> {
    let raw = did_key
        .strip_prefix("did:key:z")
        .and_then(|mb| bs58::decode(mb).into_vec().ok())
        .ok_or(MacError("invalid KEM key"))?;
    let point = raw.strip_prefix(&[0x80, 0x24][..]).ok_or(MacError("KEM key must be a P-256 did:key"))?;
    p256::PublicKey::from_sec1_bytes(point).map_err(|_| MacError("invalid KEM key"))
}

fn ecdh(sk: &p256::SecretKey, pk: &p256::PublicKey) -> [u8; 32] {
    let shared = (pk.to_projective() * *sk.to_nonzero_scalar()).to_affine();
    shared.x().into()
}

fn uncompressed(pk: &p256::PublicKey) -> Vec<u8> {
    pk.to_sec1_point(false).as_bytes().to_vec()
}

/// Fixed labels from RFC 9180; 0x0010 is DHKEM(P-256, HKDF-SHA256).
const KEM_PREFIX: &[u8] = b"HPKE-v1KEM\x00\x10";

fn hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC takes any key length");
    for p in parts {
        m.update(p);
    }
    m.finalize().into_bytes().into()
}

/// HKDF-SHA256 with an empty salt (RFC 5869 extract, then the first
/// expand block: 32 bytes is one).
fn hkdf32(ikm: &[&[u8]], info: &[&[u8]]) -> [u8; 32] {
    let prk = hmac(&[0u8; 32], ikm);
    let mut parts = info.to_vec();
    parts.push(&[1]);
    hmac(&prk, &parts)
}

fn derive(dh: &[u8; 32], syncer: &p256::PublicKey, author: &p256::PublicKey) -> [u8; 32] {
    hkdf32(
        &[KEM_PREFIX, b"eae_prk", dh],
        &[&32u16.to_be_bytes(), KEM_PREFIX, b"shared_secret", &uncompressed(syncer), &uncompressed(author)],
    )
}

/// The syncer's side: a fresh ephemeral key against the author's
/// `#atproto_kem` did:key. (its did:key for `key_share`, the shared secret)
pub fn encapsulate(author_kem_did_key: &str) -> Result<(String, [u8; 32]), MacError> {
    let author = parse_p256_did_key(author_kem_did_key)?;
    let eph = KemKey::generate();
    let pk = eph.0.public_key();
    Ok((eph.did_key(), derive(&ecdh(&eph.0, &author), &pk, &author)))
}

/// The repo host's side: the same secret from the syncer's `key_share`.
pub fn decapsulate(kem: &KemKey, key_share: &str) -> Result<[u8; 32], MacError> {
    let syncer = parse_p256_did_key(key_share)?;
    Ok(derive(&ecdh(&kem.0, &syncer), &syncer, &kem.0.public_key()))
}

/// The `#atproto_kem` key a DID document publishes, as a did:key: the
/// verification method `{did}#atproto_kem` (or `#atproto_kem`), a P-256
/// multikey.
pub fn kem_key_of(doc: &serde_json::Value) -> Option<String> {
    let did = doc.get("id").and_then(|v| v.as_str()).unwrap_or("");
    let full = format!("{did}#atproto_kem");
    doc.get("verificationMethod")?.as_array()?.iter().find_map(|m| {
        let id = m.get("id")?.as_str()?;
        if id != full && id != "#atproto_kem" {
            return None;
        }
        let mb = m.get("publicKeyMultibase")?.as_str()?;
        let k = format!("did:key:{mb}");
        parse_p256_did_key(&k).is_ok().then_some(k)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::space::vectors::VECTORS;

    /// testdata/spaces-alpha/vectors.json `kem`: the reference's
    /// `decapsulate` with fixed keys on both sides.
    #[test]
    fn generated_vectors() {
        let cases = VECTORS["kem"].as_array().unwrap();
        assert!(!cases.is_empty());
        for c in cases {
            let author = KemKey::from_bytes(&hex::decode(c["authorPrivate"].as_str().unwrap()).unwrap()).unwrap();
            assert_eq!(author.did_key(), c["authorKem"].as_str().unwrap());
            let secret = decapsulate(&author, c["keyShare"].as_str().unwrap()).unwrap();
            assert_eq!(hex::encode(secret), c["sharedSecret"].as_str().unwrap());
            // and from the syncer's side, with its fixed key
            let syncer = KemKey::from_bytes(&hex::decode(c["syncerPrivate"].as_str().unwrap()).unwrap()).unwrap();
            assert_eq!(syncer.did_key(), c["keyShare"].as_str().unwrap());
            let pk = syncer.0.public_key();
            let a = parse_p256_did_key(&author.did_key()).unwrap();
            assert_eq!(derive(&ecdh(&syncer.0, &a), &pk, &a), secret);
        }
    }

    #[test]
    fn round_trip() {
        let author = KemKey::generate();
        let (share, s1) = encapsulate(&author.did_key()).unwrap();
        assert_eq!(decapsulate(&author, &share).unwrap(), s1);
        let (share2, s2) = encapsulate(&author.did_key()).unwrap();
        assert!(share2 != share && s2 != s1, "a fresh key per call");
        assert_ne!(decapsulate(&KemKey::generate(), &share).unwrap(), s1);
        let back = KemKey::from_bytes(&author.to_bytes()).unwrap();
        assert_eq!(back.did_key(), author.did_key());
    }

    #[test]
    fn keys_must_be_p256() {
        let k256 = vlatproto::crypto::Keypair::generate().did_key();
        assert_eq!(encapsulate(&k256).unwrap_err().0, "KEM key must be a P-256 did:key");
        assert!(encapsulate("did:plc:abc").is_err());
        assert!(encapsulate("did:key:zNotBase58!").is_err());
        assert!(decapsulate(&KemKey::generate(), &k256).is_err());
    }

    #[test]
    fn doc_keys() {
        let k = KemKey::generate();
        let doc = serde_json::json!({
            "id": "did:plc:abc",
            "verificationMethod": [
                {"id": "did:plc:abc#atproto", "type": "Multikey", "publicKeyMultibase": "zQ3sh"},
                {"id": "did:plc:abc#atproto_kem", "type": "Multikey", "publicKeyMultibase": k.public_multibase()},
            ],
        });
        assert_eq!(kem_key_of(&doc), Some(k.did_key()));
        let short = serde_json::json!({"id": "did:plc:abc", "verificationMethod": [
            {"id": "#atproto_kem", "publicKeyMultibase": k.public_multibase()}]});
        assert_eq!(kem_key_of(&short), Some(k.did_key()));
        let other = serde_json::json!({"id": "did:plc:abc", "verificationMethod": [
            {"id": "did:plc:other#atproto_kem", "publicKeyMultibase": k.public_multibase()}]});
        assert_eq!(kem_key_of(&other), None);
        let k256 = vlatproto::crypto::Keypair::generate().public_multibase();
        let bad = serde_json::json!({"id": "did:plc:abc", "verificationMethod": [
            {"id": "#atproto_kem", "publicKeyMultibase": k256}]});
        assert_eq!(kem_key_of(&bad), None);
    }
}
