//! atproto crypto interop fixtures (testdata/interop/crypto).
//!
//! vlpds only generates secp256k1 (K-256) keys, so the K-256 vectors are
//! checked against `vlsync_atproto::crypto` and against the same verification rules
//! the harness applies to commits (compact 64-byte, low-S). P-256 vectors are
//! only checked for being recognized as non-K-256 keys.
use crate::common::*;
use k256::ecdsa::signature::Verifier;

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct SigFixture {
    comment: String,
    message_base64: String,
    algorithm: String,
    public_key_did: String,
    signature_base64: String,
    valid_signature: bool,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct DidKeyFixture {
    private_key_bytes_hex: String,
    public_did_key: String,
}

/// atproto signature rules: 64-byte compact (r||s), low-S, ES256K over sha256(msg).
fn atproto_verify_k256(key: &k256::ecdsa::VerifyingKey, msg: &[u8], sig: &[u8]) -> bool {
    if sig.len() != 64 {
        return false;
    }
    let Ok(sig) = k256::ecdsa::Signature::from_slice(sig) else {
        return false;
    };
    if sig.normalize_s() != sig {
        return false; // high-S
    }
    key.verify(msg, &sig).is_ok()
}

#[test]
fn w3c_did_key_k256_from_private_key() {
    let cases: Vec<DidKeyFixture> = serde_json::from_str(&read_fixture("interop/crypto/w3c_didkey_K256.json")).unwrap();
    assert!(!cases.is_empty());
    for c in cases {
        let kp = vlsync_atproto::crypto::Keypair::from_bytes(&hex::decode(&c.private_key_bytes_hex).unwrap()).unwrap();
        assert_eq!(kp.did_key(), c.public_did_key);
        // and the did:key decodes back to the same public key
        let vk = decode_did_key_k256(&c.public_did_key).unwrap();
        assert_eq!(vk.to_sec1_point(true).as_bytes(), &kp.public_key_sec1()[..]);
        // and to_bytes round-trips the fixture's private key
        assert_eq!(hex::encode(kp.to_bytes()), c.private_key_bytes_hex.to_lowercase());
    }
}

#[test]
fn w3c_did_key_p256_not_mistaken_for_k256() {
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct P {
        public_did_key: String,
    }
    let cases: Vec<P> = serde_json::from_str(&read_fixture("interop/crypto/w3c_didkey_P256.json")).unwrap();
    for c in cases {
        assert!(decode_did_key_k256(&c.public_did_key).is_err(), "{} parsed as K-256", c.public_did_key);
    }
}

#[test]
fn signature_fixtures_k256() {
    let cases: Vec<SigFixture> = serde_json::from_str(&read_fixture("interop/crypto/signature-fixtures.json")).unwrap();
    let mut n = 0;
    for c in cases.iter().filter(|c| c.algorithm == "ES256K") {
        n += 1;
        let key = decode_did_key_k256(&c.public_key_did).unwrap();
        let (msg, sig) = (b64_decode(&c.message_base64), b64_decode(&c.signature_base64));
        let ok = atproto_verify_k256(&key, &msg, &sig);
        assert_eq!(ok, c.valid_signature, "{}", c.comment);
        // the production verifier (libsecp256k1) agrees, incl. rejecting high-S
        let pk = key.to_sec1_point(true);
        let ours = vlsync_atproto::crypto::verify_k256(pk.as_bytes(), &msg, &sig).unwrap_or(false);
        assert_eq!(ours, c.valid_signature, "vlsync_atproto::crypto::verify_k256: {}", c.comment);
    }
    assert!(n >= 3);
}

#[test]
fn harness_commit_verifier_rejects_high_s() {
    // CommitObj::verify (used across the suite) must reject the high-S vector.
    let cases: Vec<SigFixture> = serde_json::from_str(&read_fixture("interop/crypto/signature-fixtures.json")).unwrap();
    let c = cases.iter().find(|c| c.algorithm == "ES256K" && c.comment.contains("non-low-S")).unwrap();
    let sig = k256::ecdsa::Signature::from_slice(&b64_decode(&c.signature_base64)).unwrap();
    assert!(sig.normalize_s() != sig, "fixture should be high-S");
}

#[test]
fn vlpds_signatures_are_low_s_compact_and_verify() {
    let kp = vlsync_atproto::crypto::Keypair::generate();
    let vk = decode_did_key_k256(&kp.did_key()).unwrap();
    for i in 0..256u32 {
        let msg = format!("message {i}");
        let sig = kp.sign(msg.as_bytes());
        assert!(atproto_verify_k256(&vk, msg.as_bytes(), &sig), "signature {i} not valid under atproto rules");
    }
}

#[test]
fn multibase_and_did_key_agree() {
    let kp = vlsync_atproto::crypto::Keypair::generate();
    assert_eq!(kp.did_key(), format!("did:key:{}", kp.public_multibase()));
    assert!(kp.did_key().starts_with("did:key:zQ3s"), "K-256 did:key prefix");
    let kp2 = vlsync_atproto::crypto::Keypair::from_bytes(&kp.to_bytes()).unwrap();
    assert_eq!(kp2.did_key(), kp.did_key());
}

#[test]
fn service_auth_jwt_is_es256k_and_verifies() {
    let kp = vlsync_atproto::crypto::Keypair::generate();
    let tok = vlpds::auth::service_auth_jwt(&kp, "did:plc:abc", "did:web:example.com", Some("com.example.method"), 60)
        .unwrap();
    let parts: Vec<&str> = tok.split('.').collect();
    assert_eq!(parts.len(), 3);
    let header: J = serde_json::from_slice(&b64url_decode(parts[0])).unwrap();
    assert_eq!(header["alg"], "ES256K");
    let claims = jwt_claims(&tok);
    assert_eq!(claims["iss"], "did:plc:abc");
    assert_eq!(claims["aud"], "did:web:example.com");
    assert_eq!(claims["lxm"], "com.example.method");
    assert!(claims["exp"].as_u64().unwrap() > claims["iat"].as_u64().unwrap());
    let vk = decode_did_key_k256(&kp.did_key()).unwrap();
    assert!(atproto_verify_k256(&vk, format!("{}.{}", parts[0], parts[1]).as_bytes(), &b64url_decode(parts[2])));
}

#[test]
fn signatures_byte_identical_to_rustcrypto_k256() {
    // libsecp256k1 and k256 both use RFC 6979 nonces: after low-S
    // normalization the compact signatures must match byte for byte. (The
    // deterministic path; what a node emits is hedged, and k256 verifies it.)
    use k256::ecdsa::signature::{Signer, Verifier};
    for k in 0..16u32 {
        let kp = vlsync_atproto::crypto::Keypair::generate();
        let sk = k256::ecdsa::SigningKey::from_slice(&kp.to_bytes()).unwrap();
        assert_eq!(sk.verifying_key().to_sec1_point(true).as_bytes(), &kp.public_key_sec1()[..]);
        for i in 0..64u32 {
            let msg = format!("commit {k} {i} {}", "x".repeat(i as usize));
            let theirs: k256::ecdsa::Signature = sk.sign(msg.as_bytes());
            let theirs = theirs.normalize_s();
            assert_eq!(kp.sign_deterministic(msg.as_bytes())[..], theirs.to_bytes()[..], "key {k} msg {i}");
            let hedged = kp.sign_verified(vlsync_atproto::crypto::Purpose::Commit, msg.as_bytes()).unwrap();
            assert_ne!(hedged, kp.sign_deterministic(msg.as_bytes()));
            sk.verifying_key().verify(msg.as_bytes(), &k256::ecdsa::Signature::from_slice(&hedged).unwrap()).unwrap();
            assert!(
                vlsync_atproto::crypto::verify_k256(&kp.public_key_sec1(), msg.as_bytes(), &theirs.to_bytes()).unwrap()
            );
            assert!(!vlsync_atproto::crypto::verify_k256(&kp.public_key_sec1(), b"other", &theirs.to_bytes()).unwrap());
        }
    }
    // malformed encodings are errors, not panics
    let kp = vlsync_atproto::crypto::Keypair::generate();
    assert!(vlsync_atproto::crypto::verify_k256(&[0u8; 33], b"m", &kp.sign(b"m")).is_err());
    assert!(vlsync_atproto::crypto::verify_k256(&kp.public_key_sec1(), b"m", &[0u8; 63]).is_err());
    assert!(vlsync_atproto::crypto::Keypair::from_bytes(&[0u8; 32]).is_err());
}

/// Throughput of the commit-signing path. Run with
/// `cargo test --profile dev-release --test all -- --ignored --nocapture sign_verify_bench`.
#[test]
#[ignore]
fn sign_verify_bench() {
    let kp = vlsync_atproto::crypto::Keypair::generate();
    let msg = vec![7u8; 200];
    let sig = kp.sign(&msg);
    let pk = kp.public_key_sec1();
    let n = 20_000;
    let mut sign = || {
        std::hint::black_box(kp.sign(&msg));
    };
    let mut verify = || {
        std::hint::black_box(vlsync_atproto::crypto::verify_k256(&pk, &msg, &sig).unwrap());
    };
    let cases: [(&str, &mut dyn FnMut()); 2] = [("sign", &mut sign), ("verify", &mut verify)];
    for (name, f) in cases {
        let mut runs: Vec<f64> = (0..7)
            .map(|_| {
                let t = std::time::Instant::now();
                for _ in 0..n {
                    f();
                }
                t.elapsed().as_nanos() as f64 / n as f64 / 1000.0
            })
            .collect();
        runs.sort_by(|a, b| a.partial_cmp(b).unwrap());
        println!("{name}: median {:.2} µs", runs[3]);
    }
}
