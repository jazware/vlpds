//! The shared secret a syncer and a repo host MAC a response with
//! (@atproto/space `kem.ts`, `mac.ts`): DHKEM(P-256, HKDF-SHA256) of
//! RFC 9180 §4.1 between the syncer's ephemeral key (its `key_share`,
//! fresh for every request) and the author's `#atproto_kem` key, and the
//! two headers that carry it:
//!
//! ```text
//! Atproto-Space-Want-Mac: type="atproto-space-repo", ver=1, key_share="did:key:zDna…"
//! Atproto-Space-Mac: type="atproto-space-repo", ver=1, mac=:<base64>:
//! ```

use super::sfv::{self, Bare, Member};
use base64::Engine;
use hmac::{Hmac, KeyInit, Mac};
use p256::elliptic_curve::sec1::ToSec1Point;
use sha2::Sha256;

pub const WANT_MAC_HEADER: &str = "atproto-space-want-mac";
pub const MAC_HEADER: &str = "atproto-space-mac";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacType {
    /// getLatestCommit, getRepo, listRepoOps: the commit.
    Repo,
    /// getRecord: the record's URI and CID.
    Record,
}

impl MacType {
    pub fn name(self) -> &'static str {
        match self {
            MacType::Repo => "atproto-space-repo",
            MacType::Record => "atproto-space-record",
        }
    }

    pub fn version(self) -> i64 {
        match self {
            MacType::Repo => super::commit::COMMIT_VERSION,
            MacType::Record => super::commit::RECORD_MAC_VERSION,
        }
    }
}

/// The reference's `SpaceMacError`; its XRPC error is `BadSpaceMac`.
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

/// A header far over what it holds (a did:key is ~57 bytes).
const MAX_HEADER: usize = 1024;

/// The uncompressed point (0x04 ‖ x ‖ y) of a P-256 did:key.
fn p256_point(did_key: &str) -> Result<p256::PublicKey, MacError> {
    if super::did_key_alg(did_key) != Some("ES256") {
        return match super::did_key_alg(did_key) {
            Some(_) => Err(MacError("KEM key must be a P-256 did:key")),
            None => Err(MacError("invalid KEM key")),
        };
    }
    let raw = bs58::decode(&did_key["did:key:z".len()..]).into_vec().map_err(|_| MacError("invalid KEM key"))?;
    p256::PublicKey::from_sec1_bytes(&raw[2..]).map_err(|_| MacError("invalid KEM key"))
}

fn uncompressed(k: &p256::PublicKey) -> Vec<u8> {
    k.to_sec1_point(false).as_bytes().to_vec()
}

pub fn did_key(k: &p256::PublicKey) -> String {
    let mut mk = vec![0x80, 0x24];
    mk.extend_from_slice(k.to_sec1_point(true).as_bytes());
    format!("did:key:z{}", bs58::encode(mk).into_string())
}

fn hkdf_sha256(ikm: &[u8], info: &[u8]) -> [u8; 32] {
    // extract with an empty salt (HMAC's key is then 32 zero bytes), then
    // one block of expand
    let mut e = <Hmac<Sha256> as KeyInit>::new_from_slice(&[]).expect("HMAC takes any key length");
    e.update(ikm);
    let prk = e.finalize().into_bytes();
    let mut x = <Hmac<Sha256> as KeyInit>::new_from_slice(&prk).expect("HMAC takes any key length");
    x.update(info);
    x.update(&[1]);
    x.finalize().into_bytes().into()
}

const KEM_PREFIX: &[u8] = b"HPKE-v1KEM\x00\x10";

fn shared_secret(dh: &[u8], syncer: &p256::PublicKey, author: &p256::PublicKey) -> [u8; 32] {
    let input = [KEM_PREFIX, b"eae_prk", dh].concat();
    let info = [&32u16.to_be_bytes()[..], KEM_PREFIX, b"shared_secret", &uncompressed(syncer), &uncompressed(author)]
        .concat();
    hkdf_sha256(&input, &info)
}

/// Repo host side: the shared secret for the syncer's `key_share`, from the
/// author's KEM key.
pub fn decapsulate(author: &p256::SecretKey, key_share: &str) -> Result<[u8; 32], MacError> {
    let syncer = p256_point(key_share)?;
    let dh = p256::ecdh::diffie_hellman(author.to_nonzero_scalar(), syncer.as_affine());
    Ok(shared_secret(dh.raw_secret_bytes(), &syncer, &author.public_key()))
}

/// Syncer side: a fresh ephemeral key against the author's `#atproto_kem`
/// key. (key_share, shared secret); use one per request.
pub fn encapsulate(author_kem_key: &str) -> Result<(String, [u8; 32]), MacError> {
    let author = p256_point(author_kem_key)?;
    let eph = <p256::SecretKey as p256::elliptic_curve::Generate>::generate();
    let dh = p256::ecdh::diffie_hellman(eph.to_nonzero_scalar(), author.as_affine());
    let syncer = eph.public_key();
    Ok((did_key(&syncer), shared_secret(dh.raw_secret_bytes(), &syncer, &author)))
}

/// The did:key of a DID document's `#atproto_kem` verification method.
pub fn kem_key_of(doc: &serde_json::Value) -> Option<String> {
    let did = doc.get("id").and_then(|v| v.as_str()).unwrap_or("");
    let full = format!("{did}#atproto_kem");
    doc.get("verificationMethod")?.as_array()?.iter().find_map(|m| {
        let id = m.get("id")?.as_str()?;
        (id == "#atproto_kem" || id == full)
            .then(|| m.get("publicKeyMultibase")?.as_str().map(|k| format!("did:key:{k}")))?
    })
}

pub fn format_want_mac(ty: MacType, key_share: &str) -> String {
    format!("type=\"{}\", ver={}, key_share=\"{key_share}\"", ty.name(), ty.version())
}

/// Padded base64, as RFC 9651 serializes a byte sequence.
pub fn format_mac(ty: MacType, mac: &[u8; 32]) -> String {
    format!(
        "type=\"{}\", ver={}, mac=:{}:",
        ty.name(),
        ty.version(),
        base64::engine::general_purpose::STANDARD.encode(mac)
    )
}

/// Either header's fields once `type` and `ver` are `ty`'s.
fn parse_fields(value: Option<&str>, ty: MacType) -> Result<Vec<(String, Bare)>, MacError> {
    let value = value.ok_or(MacError("missing or malformed MAC header"))?;
    if value.len() > MAX_HEADER {
        return Err(MacError("malformed MAC header"));
    }
    let dict = sfv::parse_dictionary(value).map_err(|_| MacError("malformed MAC header"))?;
    let mut fields = Vec::with_capacity(dict.len());
    for (k, m) in dict {
        match m {
            Member::Item(b, _) => fields.push((k, b)),
            Member::InnerList(..) => return Err(MacError("malformed MAC header field")),
        }
    }
    if sfv::get(&fields, "type") != Some(&Bare::String(ty.name().into())) {
        return Err(MacError(match ty {
            MacType::Repo => "unsupported MAC type, expected atproto-space-repo",
            MacType::Record => "unsupported MAC type, expected atproto-space-record",
        }));
    }
    if sfv::get(&fields, "ver") != Some(&Bare::Number(ty.version() as f64)) {
        return Err(MacError(match ty {
            MacType::Repo => "unsupported MAC version for atproto-space-repo",
            MacType::Record => "unsupported MAC version for atproto-space-record",
        }));
    }
    Ok(fields)
}

/// A request's `Atproto-Space-Want-Mac`: its `key_share`.
pub fn parse_want_mac(value: Option<&str>, ty: MacType) -> Result<String, MacError> {
    match sfv::get(&parse_fields(value, ty)?, "key_share") {
        Some(Bare::String(k)) => Ok(k.clone()),
        _ => Err(MacError("missing or malformed key_share")),
    }
}

/// A response's `Atproto-Space-Mac`: its MAC.
pub fn parse_mac(value: Option<&str>, ty: MacType) -> Result<Vec<u8>, MacError> {
    match sfv::get(&parse_fields(value, ty)?, "mac") {
        Some(Bare::Bytes(b)) => base64::engine::GeneralPurpose::new(
            &base64::alphabet::STANDARD,
            base64::engine::GeneralPurposeConfig::new()
                .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent)
                .with_decode_allow_trailing_bits(true),
        )
        .decode(b)
        .map_err(|_| MacError("missing or malformed mac")),
        _ => Err(MacError("missing or malformed mac")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::space::vectors::VECTORS;

    fn secret(hex_key: &str) -> p256::SecretKey {
        p256::SecretKey::from_slice(&hex::decode(hex_key).unwrap()).unwrap()
    }

    /// testdata/spaces-alpha/vectors.json `kem`, `wantMac`, and the
    /// `macHeader`s of `commits` and `recordMacs`.
    #[test]
    fn generated_vectors() {
        for k in VECTORS["kem"].as_array().unwrap() {
            let author = secret(k["authorPrivate"].as_str().unwrap());
            assert_eq!(did_key(&author.public_key()), k["authorKey"].as_str().unwrap());
            let syncer = secret(k["syncerPrivate"].as_str().unwrap());
            let share = k["keyShare"].as_str().unwrap();
            assert_eq!(did_key(&syncer.public_key()), share);
            let want = k["sharedSecret"].as_str().unwrap();
            assert_eq!(hex::encode(decapsulate(&author, share).unwrap()), want);
            // the syncer's side, from its private key
            let dh = p256::ecdh::diffie_hellman(syncer.to_nonzero_scalar(), author.public_key().as_affine());
            let theirs = shared_secret(dh.raw_secret_bytes(), &syncer.public_key(), &author.public_key());
            assert_eq!(hex::encode(theirs), want);
        }
        for w in VECTORS["wantMac"].as_array().unwrap() {
            let ty = if w["type"] == "atproto-space-repo" { MacType::Repo } else { MacType::Record };
            let share = w["keyShare"].as_str().unwrap();
            assert_eq!(format_want_mac(ty, share), w["header"].as_str().unwrap());
            assert_eq!(parse_want_mac(w["header"].as_str(), ty).unwrap(), share);
        }
        for (cases, ty) in [("commits", MacType::Repo), ("recordMacs", MacType::Record)] {
            for c in VECTORS[cases].as_array().unwrap() {
                let mac: [u8; 32] = hex::decode(c["mac"].as_str().unwrap()).unwrap().try_into().unwrap();
                assert_eq!(format_mac(ty, &mac), c["macHeader"].as_str().unwrap());
                assert_eq!(parse_mac(c["macHeader"].as_str(), ty).unwrap(), mac);
            }
        }
    }

    // The cases below are the reference's tests/kem.test.ts and
    // tests/mac.test.ts.

    #[test]
    fn round_trips() {
        let author = <p256::SecretKey as p256::elliptic_curve::Generate>::generate();
        let (share, a) = encapsulate(&did_key(&author.public_key())).unwrap();
        assert_eq!(decapsulate(&author, &share).unwrap(), a);
        // a fresh key share every time
        let (share2, b) = encapsulate(&did_key(&author.public_key())).unwrap();
        assert_ne!(share, share2);
        assert_ne!(a, b);
        // another author's key derives another secret
        let other = <p256::SecretKey as p256::elliptic_curve::Generate>::generate();
        assert_ne!(decapsulate(&other, &share).unwrap(), a);
    }

    #[test]
    fn keys_must_be_p256() {
        let k256 = vlatproto::crypto::Keypair::generate().did_key();
        assert_eq!(encapsulate(&k256), Err(MacError("KEM key must be a P-256 did:key")));
        assert_eq!(encapsulate("did:key:znope"), Err(MacError("invalid KEM key")));
        let author = <p256::SecretKey as p256::elliptic_curve::Generate>::generate();
        assert!(decapsulate(&author, &k256).is_err());
        assert!(decapsulate(&author, "not a key").is_err());
    }

    #[test]
    fn headers() {
        assert_eq!(
            format_want_mac(MacType::Repo, "did:key:zDnaExample"),
            "type=\"atproto-space-repo\", ver=1, key_share=\"did:key:zDnaExample\""
        );
        let mac: [u8; 32] = std::array::from_fn(|i| i as u8);
        assert_eq!(
            format_mac(MacType::Repo, &mac),
            "type=\"atproto-space-repo\", ver=1, mac=:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=:"
        );
        let want = format_want_mac(MacType::Record, "did:key:zDnaX");
        assert_eq!(parse_want_mac(Some(&want), MacType::Record).unwrap(), "did:key:zDnaX");
        assert_eq!(parse_mac(Some(&format_mac(MacType::Record, &mac)), MacType::Record).unwrap(), mac);

        assert!(parse_want_mac(None, MacType::Repo).is_err());
        assert!(parse_want_mac(Some("???"), MacType::Repo).is_err());
        assert!(parse_want_mac(Some("type=\"atproto-space-repo\", ver=1"), MacType::Repo).unwrap_err().0.contains("key_share"));
        assert!(parse_mac(Some("type=\"atproto-space-repo\", ver=1, mac=\"abc\""), MacType::Repo).unwrap_err().0.contains("mac"));
        assert!(parse_want_mac(Some(&want), MacType::Repo).unwrap_err().0.contains("unsupported MAC type"));
        assert!(parse_want_mac(Some("type=\"atproto-space-repo\", ver=2, key_share=\"did:key:zDnaX\""), MacType::Repo)
            .unwrap_err()
            .0
            .contains("unsupported MAC version"));
        assert!(parse_want_mac(Some("type=\"atproto-space-repo\", ver=1, key_share=(\"a\")"), MacType::Repo).is_err());
    }
}
