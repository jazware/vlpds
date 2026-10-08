//! Port of atproto/packages/pds/tests/get-service-auth.test.ts, extended with
//! independent verification of the issued JWT: the ES256K signature must
//! verify against the `#atproto` key in the account's DID document (what a
//! receiving service does), and iss/aud/lxm/exp/iat/jti must be well formed.
use crate::common::*;
use base64::Engine;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

struct Jwt {
    header: J,
    claims: J,
    signing_input: String,
    sig: Vec<u8>,
}

fn decode_jwt(t: &str) -> Jwt {
    let parts: Vec<&str> = t.split('.').collect();
    assert_eq!(parts.len(), 3, "JWT must have 3 parts: {t}");
    Jwt {
        header: serde_json::from_slice(&B64.decode(parts[0]).expect("header b64url")).unwrap(),
        claims: serde_json::from_slice(&B64.decode(parts[1]).expect("claims b64url")).unwrap(),
        signing_input: format!("{}.{}", parts[0], parts[1]),
        sig: B64.decode(parts[2]).expect("sig b64url"),
    }
}

/// Verifies the JWT like a receiving service would: ES256K, compact 64-byte
/// low-S signature over the signing input, by the issuer's atproto key.
fn verify_jwt(j: &Jwt, key: &k256::ecdsa::VerifyingKey) -> anyhow::Result<()> {
    use k256::ecdsa::signature::Verifier;
    anyhow::ensure!(j.header["alg"] == json!("ES256K"), "alg {}", j.header["alg"]);
    anyhow::ensure!(j.sig.len() == 64, "signature is {} bytes, want 64 (compact r||s)", j.sig.len());
    let sig = k256::ecdsa::Signature::from_slice(&j.sig)?;
    anyhow::ensure!(sig.normalize_s() == sig, "signature is not low-S");
    key.verify(j.signing_input.as_bytes(), &sig)?;
    Ok(())
}

async fn service_auth(s: &TestServer, auth: &Auth, q: &[(&str, &str)]) -> Resp {
    s.xrpc.get("com.atproto.server.getServiceAuth", q, auth).await
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn issues_verifiable_token_for_bare_did_aud() {
    let s = TestServer::spawn().await;
    let a = s.create_account("alice").await;
    let aud = s.pds_did().await;
    let r = service_auth(&s, &a.auth(), &[("aud", &aud), ("lxm", "com.atproto.server.describeServer")]).await;
    let token = r.ok()["token"].as_str().expect("token").to_string();
    let j = decode_jwt(&token);
    assert_eq!(j.claims["aud"], json!(aud));
    assert_eq!(j.claims["iss"], json!(a.did));
    assert_eq!(j.claims["lxm"], json!("com.atproto.server.describeServer"));
    let iat = j.claims["iat"].as_i64().expect("iat");
    let exp = j.claims["exp"].as_i64().expect("exp");
    assert!((iat - now()).abs() <= 5, "iat {iat} not ~now");
    assert!(exp > iat && exp - iat <= 60, "default lifetime should be <= 60s, got {}", exp - iat);
    assert!(j.claims["jti"].as_str().map(|s| !s.is_empty()).unwrap_or(false), "jti required (replay protection)");

    // signature verifies against the DID document's #atproto key
    let key = s.signing_key(&a.did).await;
    verify_jwt(&j, &key).expect("service auth JWT must verify against the account's atproto key");

    // ...and not against an unrelated key
    let other = vlsync_atproto::crypto::Keypair::generate();
    assert!(
        verify_jwt(&j, &k256::ecdsa::VerifyingKey::from_sec1_bytes(&other.public_key_sec1()).unwrap()).is_err(),
        "JWT verified with an unrelated key"
    );

    // each token is unique
    let t2 = service_auth(&s, &a.auth(), &[("aud", &aud), ("lxm", "com.atproto.server.describeServer")]).await.ok();
    assert_ne!(decode_jwt(t2["token"].as_str().unwrap()).claims["jti"], j.claims["jti"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn issues_token_for_did_service_id_aud() {
    let s = TestServer::spawn().await;
    let a = s.create_account("alice").await;
    let aud = format!("{}#atproto_pds", s.pds_did().await);
    let r = service_auth(&s, &a.auth(), &[("aud", &aud), ("lxm", "com.atproto.server.describeServer")]).await;
    let j = decode_jwt(r.ok()["token"].as_str().unwrap());
    assert_eq!(j.claims["aud"], json!(aud));
    assert_eq!(j.claims["iss"], json!(a.did));
    verify_jwt(&j, &s.signing_key(&a.did).await).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rejects_malformed_aud() {
    let s = TestServer::spawn().await;
    let a = s.create_account("alice").await;
    let pds = s.pds_did().await;
    for aud in ["not-a-did".to_string(), "did:foo:bar".to_string(), format!("{pds}#")] {
        let r = service_auth(&s, &a.auth(), &[("aud", &aud), ("lxm", "com.atproto.server.describeServer")]).await;
        r.err(400, "InvalidRequest");
        assert!(
            r.json["message"]
                .as_str()
                .unwrap_or("")
                .contains("aud must be a valid atproto DID or did#serviceId reference"),
            "aud {aud}: {}",
            r.text()
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn requires_auth() {
    let s = TestServer::spawn().await;
    let pds = s.pds_did().await;
    service_auth(&s, &Auth::None, &[("aud", &pds)]).await.err_status(401);
    // admin basic auth is not a user identity
    let r = service_auth(&s, &Auth::Admin, &[("aud", &pds)]).await;
    r.client_err();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn expiration_rules() {
    let s = TestServer::spawn().await;
    let a = s.create_account("alice").await;
    let pds = s.pds_did().await;
    let lxm = "app.bsky.feed.getFeedSkeleton";

    // explicit exp within an hour, bound to a method: honored
    let exp = (now() + 1800).to_string();
    let j = decode_jwt(
        service_auth(&s, &a.auth(), &[("aud", &pds), ("lxm", lxm), ("exp", &exp)]).await.ok()["token"]
            .as_str()
            .unwrap(),
    );
    assert!((j.claims["exp"].as_i64().unwrap() - (now() + 1800)).abs() <= 5, "exp not honored: {}", j.claims);

    // in the past
    let past = (now() - 10).to_string();
    service_auth(&s, &a.auth(), &[("aud", &pds), ("lxm", lxm), ("exp", &past)]).await.err(400, "BadExpiration");
    // more than an hour
    let far = (now() + 7200).to_string();
    service_auth(&s, &a.auth(), &[("aud", &pds), ("lxm", lxm), ("exp", &far)]).await.err(400, "BadExpiration");
    // method-less tokens are limited to a minute
    let min5 = (now() + 300).to_string();
    service_auth(&s, &a.auth(), &[("aud", &pds), ("exp", &min5)]).await.err(400, "BadExpiration");
    // ...but a method-less 30s token is fine and carries no lxm
    let s30 = (now() + 30).to_string();
    let j =
        decode_jwt(service_auth(&s, &a.auth(), &[("aud", &pds), ("exp", &s30)]).await.ok()["token"].as_str().unwrap());
    assert!(j.claims.get("lxm").map(|v| v.is_null()).unwrap_or(true), "unexpected lxm: {}", j.claims);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_protected_methods() {
    let s = TestServer::spawn().await;
    let a = s.create_account("alice").await;
    let pds = s.pds_did().await;
    for lxm in [
        "com.atproto.server.createAppPassword",
        "com.atproto.identity.updateHandle",
        "com.atproto.server.deactivateAccount",
        "com.atproto.server.requestAccountDelete",
        "com.atproto.identity.signPlcOperation",
    ] {
        let r = service_auth(&s, &a.auth(), &[("aud", &pds), ("lxm", lxm)]).await;
        r.err(400, "InvalidRequest");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn token_and_commit_key_track_signing_key_rotation() {
    // After an admin rotates the account's signing key, the DID document
    // publishes the new key, new service-auth tokens and new commits are
    // signed with it, and an #identity event announces the change.
    let s = TestServer::spawn().await;
    let a = s.create_account("alice").await;
    let pds = s.pds_did().await;
    let old = s.signing_key(&a.did).await;
    let mut sub = s.subscribe(None).await;
    let r = s.xrpc.post("com.atproto.admin.updateAccountSigningKey", &json!({"did": a.did}), &Auth::Admin).await.ok();
    let new_did_key = r["signingKey"].as_str().expect("signingKey in response").to_string();
    let new = decode_did_key_k256(&new_did_key).unwrap();
    let cur = s.signing_key(&a.did).await;
    assert_ne!(cur, old, "describeRepo still shows the old key after rotation");
    assert_eq!(cur, new, "describeRepo key != key returned by updateAccountSigningKey");

    let j = decode_jwt(
        service_auth(&s, &a.auth(), &[("aud", &pds), ("lxm", "app.bsky.feed.getTimeline")]).await.ok()["token"]
            .as_str()
            .unwrap(),
    );
    verify_jwt(&j, &cur).expect("token after rotation must verify with the DID document's current key");
    assert!(verify_jwt(&j, &old).is_err(), "token after rotation still signed with the old key");

    // the next commit is signed with the new key
    let p = s.post(&a, "after rotation").await;
    let (head, _) = s.latest_commit(&a.did).await;
    assert_eq!(Some(head.to_string()), p.commit_cid);
    let repo = s.get_repo(&a.did).await;
    repo.commit().verify(&cur).expect("commit after rotation must be signed with the new key");

    // relays learn about the key change via #identity
    let (frames, ok) = sub
        .try_until(FH_TIMEOUT, |fs| fs.iter().any(|f| f.did() == Some(a.did.as_str()) && f.kind() == "#identity"))
        .await;
    assert!(
        ok,
        "no #identity event after signing key rotation; got {:?}",
        frames.iter().map(|f| f.kind().to_string()).collect::<Vec<_>>()
    );
}
