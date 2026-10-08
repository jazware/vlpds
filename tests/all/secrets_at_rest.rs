//! Secrets at rest (src/secrets.rs, DESIGN.md "Secrets at rest"): signing
//! keys, reserved keys and TOTP secrets reach the bucket only wrapped under
//! the KEK, email tokens only as keyed digests; KEK rotation rewraps them;
//! with the key service (Cloud KMS, mocked here) down, cold writes fail with
//! a retryable 503 while reads work; unwrapped keys are cached; the PLC
//! rotation key never reaches the bucket.

use crate::common::*;
use object_store::ObjectStoreExt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use vlpds::secrets::{GcpToken, KekBytes, KekConfig};

fn local(k: &KekBytes, old: &[&KekBytes]) -> KekConfig {
    KekConfig { local: Some(k.clone()), local_old: old.iter().map(|k| (*k).clone()).collect(), ..Default::default() }
}

fn has(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

/// Every byte the node keeps durably or could serve from state: each
/// object in the bucket (log segments decoded: their bodies are zstd), and
/// every key and value of the owned shards' state, read through SlateDB
/// (SST blocks are compressed too; this includes the memtable).
async fn node(id: &str, store: &Arc<dyn object_store::ObjectStore>, kek: KekConfig) -> TestServer {
    cluster_node(id, store.clone(), 4, |c| c.kek = kek).await
}

async fn everything(s: &TestServer) -> Vec<(String, Vec<u8>)> {
    use futures::StreamExt;
    let raw = s.app.store.raw.clone();
    let metas: Vec<_> = raw.list(None).map(|m| m.unwrap()).collect().await;
    let mut out = Vec::new();
    for m in metas {
        let Ok(r) = raw.get(&m.location).await else { continue };
        let data = r.bytes().await.unwrap();
        let path = m.location.to_string();
        let data =
            if path.contains("/log/") { vlsync_store::segment::decode(data.clone()).unwrap_or(data) } else { data };
        out.push((path, data.to_vec()));
    }
    for p in s.app.partitions.owned() {
        let mut it = p.db.scan(Vec::<u8>::new()..vec![0xffu8; 8]).await.unwrap();
        let mut b = Vec::new();
        while let Some(kv) = it.next().await.unwrap() {
            b.extend_from_slice(&kv.key);
            b.extend_from_slice(&kv.value);
        }
        out.push((format!("state shard {}", p.id), b));
    }
    out
}

/// The forms a leaked secret could take in storage.
fn forms(raw: &[u8]) -> Vec<Vec<u8>> {
    use base64::Engine;
    vec![
        raw.to_vec(),
        hex::encode(raw).into_bytes(),
        hex::encode_upper(raw).into_bytes(),
        base64::engine::general_purpose::STANDARD.encode(raw).into_bytes(),
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw).into_bytes(),
        vlpds::totp::base32_encode(raw).into_bytes(),
        vlpds::totp::base32_encode(raw).to_ascii_lowercase().into_bytes(),
    ]
}

async fn signing_secret(s: &TestServer, did: &str) -> Vec<u8> {
    let a = s.app.account(did).await.ok().unwrap();
    s.app.secrets.account_signing_key(&a).await.unwrap().to_bytes().to_vec()
}

pub(crate) async fn totp_login(s: &TestServer, a: &TestAccount, secret: &[u8], step_offset: u64) -> Resp {
    let code = vlpds::totp::code_for_step(secret, vlpds::totp::step_at(vlpds::totp::now_secs()) + step_offset);
    s.xrpc
        .post(
            "com.atproto.server.createSession",
            &json!({"identifier": a.handle, "password": a.password, "authFactorToken": code}),
            &Auth::None,
        )
        .await
}

async fn reserved_secret(s: &TestServer, did_key: &str) -> Vec<u8> {
    let v = s.app.get_private(&format!("_reserved:{did_key}"), "k").await.ok().unwrap().expect("reservation");
    let rec: J = serde_json::from_slice(&v).unwrap();
    let blob = rec["key"].as_str().unwrap();
    assert!(blob.starts_with("vw1."), "reserved key stored wrapped: {blob}");
    s.app.secrets.unwrap(vlpds::secrets::Purpose::ReservedKey, did_key, blob).await.unwrap().plaintext.to_vec()
}

/// No signing key (current, rotated-out, reserved), TOTP secret or email
/// token appears in the bucket or the state in any common encoding, while
/// the scan does see plain account data (the decode works).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_plaintext_secrets_in_bucket_or_state() {
    let store: Arc<dyn object_store::ObjectStore> = Arc::new(object_store::memory::InMemory::new());
    let kek_raw: [u8; 32] = rand::random();
    let kek = KekBytes::new(kek_raw);
    let s = node("plain", &store, local(&kek, &[])).await;
    let mut needles: Vec<(String, Vec<u8>)> = Vec::new();
    let mut accts = Vec::new();
    for _ in 0..3 {
        let a = s.create_account("sec").await;
        s.post(&a, "hello").await;
        needles.push((format!("signing key of {}", a.did), signing_secret(&s, &a.did).await));
        accts.push(a);
    }
    // rotation: the old and the new key
    let a0 = &accts[0];
    s.xrpc.post("com.atproto.admin.updateAccountSigningKey", &json!({"did": a0.did}), &Auth::Admin).await.ok();
    s.post(a0, "after rotation").await;
    let new_key = signing_secret(&s, &a0.did).await;
    assert_ne!(new_key, needles[0].1);
    needles.push(("rotated-in signing key".into(), new_key));
    // the commit after rotation is signed with the new key
    let repo = s.get_repo(&a0.did).await;
    repo.commit().verify(&s.signing_key(&a0.did).await).expect("signed with the new key");
    // a reserved key
    let dk = s
        .xrpc
        .post("com.atproto.server.reserveSigningKey", &json!({"did": "did:plc:reservedfortest2345678"}), &Auth::None)
        .await
        .ok()["signingKey"]
        .as_str()
        .unwrap()
        .to_string();
    needles.push(("reserved key".into(), reserved_secret(&s, &dk).await));
    // a TOTP secret, used once
    let (secret, _) = s.enable_totp(&accts[1]).await;
    totp_login(&s, &accts[1], &secret, 1).await.ok();
    needles.push(("totp secret".into(), secret));
    // email tokens (password reset, email confirmation)
    s.xrpc.post("com.atproto.server.requestPasswordReset", &json!({"email": accts[2].email}), &Auth::None).await.ok();
    let token = s.mail_token(&accts[2].email).await.expect("reset token");
    needles.push(("reset token".into(), token.clone().into_bytes()));
    needles.push(("reset token (lowercase)".into(), token.to_ascii_lowercase().into_bytes()));

    s.app.log.checkpoint_all().await;
    let all = everything(&s).await;
    assert!(all.iter().any(|(p, _)| p.contains("/log/")), "log segments scanned");
    // control: plain account data is visible to this scan, in segments and state
    let handle = accts[2].handle.as_bytes();
    assert!(all.iter().any(|(p, b)| p.contains("/log/") && has(b, handle)), "decoded segments hold account rows");
    assert!(all.iter().any(|(p, b)| p.starts_with("state") && has(b, handle)), "state holds account rows");
    for (what, raw) in &needles {
        for f in forms(raw) {
            if f.len() < 8 {
                continue;
            }
            for (path, b) in &all {
                assert!(!has(b, &f), "{what} found in {path}");
            }
        }
    }
    // nor is the KEK itself
    for f in forms(&kek_raw) {
        for (path, b) in &all {
            assert!(!has(b, &f), "KEK found in {path}");
        }
    }
}

/// KEK rotation: a new KEK with the old one kept for unwrap serves every
/// account; rewrapSecrets moves every secret to the new KEK (dry runs count
/// what is left); then the old KEK can go. A node without the right KEK
/// can't sign (500) but still serves reads.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kek_rotation_and_rewrap() {
    let store: Arc<dyn object_store::ObjectStore> = Arc::new(object_store::memory::InMemory::new());
    let (k1, k2) = (KekBytes::random(), KekBytes::random());
    let a = node("rot", &store, local(&k1, &[])).await;
    let mut accts = Vec::new();
    for _ in 0..4 {
        let t = a.create_account("rot").await;
        a.post(&t, "before rotation").await;
        accts.push(t);
    }
    let (totp, _) = a.enable_totp(&accts[0]).await;
    let dk = a.xrpc.post("com.atproto.server.reserveSigningKey", &json!({}), &Auth::None).await.ok()["signingKey"]
        .as_str()
        .unwrap()
        .to_string();
    let keys_before: Vec<Vec<u8>> = futures::future::join_all(accts.iter().map(|t| signing_secret(&a, &t.did))).await;
    a.app.log.checkpoint_all().await;
    vlpds::server::shutdown(&a.app).await;

    // new KEK current, old for unwrap
    let b = node("rot", &store, local(&k2, &[&k1])).await;
    assert_eq!(b.app.secrets.current_kid(), k2.kid());
    for t in &accts {
        b.post(t, "during rotation").await;
    }
    // TOTP state (under k1) still opens
    let st = b.xrpc.get("vlpds.server.getTotpStatus", &[], &accts[0].auth()).await.ok();
    assert_eq!(st["enabled"], json!(true));
    let rewrap = |s: &TestServer, dry: bool| {
        let x = s.xrpc.clone();
        async move { x.post("vlpds.admin.rewrapSecrets", &json!({"dryRun": dry}), &Auth::Admin).await.ok() }
    };
    let dry = rewrap(&b, true).await;
    assert_eq!(dry["failed"], json!(0), "{dry}");
    assert_eq!(dry["signingKeys"], json!(4), "{dry}");
    assert_eq!(dry["totpSecrets"], json!(1), "{dry}");
    assert_eq!(dry["reservedKeys"], json!(1), "{dry}");
    let done = rewrap(&b, false).await;
    assert_eq!((done["stale"].clone(), done["failed"].clone()), (json!(6), json!(0)), "{done}");
    let again = rewrap(&b, true).await;
    assert_eq!(again["stale"], json!(0), "{again}");
    // rewrapped, not rotated: same keys, same public keys
    let keys_mid: Vec<Vec<u8>> = futures::future::join_all(accts.iter().map(|t| signing_secret(&b, &t.did))).await;
    assert_eq!(keys_before, keys_mid);
    for t in &accts {
        let row = b.app.account(&t.did).await.ok().unwrap();
        assert!(row.wrapped_signing_key.starts_with(&format!("vw1.{}.", k2.kid())), "{}", row.wrapped_signing_key);
    }
    // writes keep working right after the rewrap (cached repos keep their key)
    b.post(&accts[1], "after rewrap").await;
    b.app.log.checkpoint_all().await;
    vlpds::server::shutdown(&b.app).await;

    // old KEK retired
    let c = node("rot", &store, local(&k2, &[])).await;
    for t in &accts {
        c.post(t, "after rotation").await;
        let repo = c.get_repo(&t.did).await;
        repo.commit().verify(&c.signing_key(&t.did).await).unwrap();
    }
    totp_login(&c, &accts[0], &totp, 1).await.ok();
    // the reserved key, rewrapped, still installs
    c.xrpc
        .post(
            "com.atproto.admin.updateAccountSigningKey",
            &json!({"did": accts[2].did, "signingKey": dk}),
            &Auth::Admin,
        )
        .await
        .ok();
    c.post(&accts[2], "with the reserved key").await;
    assert_eq!(format!("did:key:{}", c.app.account(&accts[2].did).await.ok().unwrap().signing_pubkey), dk);
    c.app.log.checkpoint_all().await;
    vlpds::server::shutdown(&c.app).await;

    // a node with neither KEK: reads work, writes fail without data loss
    let d = node("rot", &store, local(&KekBytes::random(), &[])).await;
    let rec = d.list_records(&accts[3].did, "app.bsky.feed.post", &[]).await.ok();
    assert_eq!(rec["records"].as_array().unwrap().len(), 3);
    let r = d
        .xrpc
        .post(
            "com.atproto.repo.createRecord",
            &json!({"repo": accts[3].did, "collection": "app.bsky.feed.post", "record": post_record("x")}),
            &accts[3].auth(),
        )
        .await;
    assert!(r.status >= 500, "{} {}", r.status, r.text());
    vlpds::server::shutdown(&d.app).await;
}

// ---------------------------------------------------------------------------
// Cloud KMS (mocked)
// ---------------------------------------------------------------------------

/// A Cloud KMS stand-in: `encrypt`/`decrypt` on any CryptoKey with an
/// AAD-bound local AEAD, a bearer-token check, an up/down switch and call
/// counters.
pub(crate) struct MockKms {
    url: String,
    up: AtomicBool,
    encrypts: AtomicU64,
    decrypts: AtomicU64,
}

pub(crate) async fn mock_kms() -> Arc<MockKms> {
    use axum::extract::{Path, State};
    use axum::http::{HeaderMap, StatusCode};
    use axum::response::IntoResponse;
    use base64::Engine;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let m = Arc::new(MockKms {
        url: format!("http://{}", listener.local_addr().unwrap()),
        up: AtomicBool::new(true),
        encrypts: AtomicU64::new(0),
        decrypts: AtomicU64::new(0),
    });
    let aead = Arc::new(vlpds::secrets::LocalKek::new(&KekBytes::random()));
    async fn handle(
        State((m, aead)): State<(Arc<MockKms>, Arc<vlpds::secrets::LocalKek>)>,
        Path(rest): Path<String>,
        headers: HeaderMap,
        axum::Json(body): axum::Json<J>,
    ) -> axum::response::Response {
        let b64 = base64::engine::general_purpose::STANDARD;
        if !m.up.load(Ordering::SeqCst) {
            return (StatusCode::SERVICE_UNAVAILABLE, "down").into_response();
        }
        if headers.get("authorization").and_then(|v| v.to_str().ok()) != Some("Bearer test-token") {
            return (StatusCode::UNAUTHORIZED, "no token").into_response();
        }
        let aad = b64.decode(body["additionalAuthenticatedData"].as_str().unwrap_or("")).unwrap();
        if let Some(name) = rest.strip_suffix(":encrypt") {
            m.encrypts.fetch_add(1, Ordering::SeqCst);
            let pt = b64.decode(body["plaintext"].as_str().unwrap()).unwrap();
            let ct = aead.wrap_sync(&aad, &pt);
            return axum::Json(json!({"name": format!("{name}/cryptoKeyVersions/1"), "ciphertext": b64.encode(ct)}))
                .into_response();
        }
        if rest.ends_with(":decrypt") {
            m.decrypts.fetch_add(1, Ordering::SeqCst);
            let ct = b64.decode(body["ciphertext"].as_str().unwrap()).unwrap();
            return match aead.unwrap_sync(&aad, &ct) {
                Ok(pt) => axum::Json(json!({"plaintext": b64.encode(&*pt), "usedPrimary": true})).into_response(),
                Err(_) => (StatusCode::BAD_REQUEST, "Decryption failed").into_response(),
            };
        }
        StatusCode::NOT_FOUND.into_response()
    }
    let app = axum::Router::new().route("/v1/{*rest}", axum::routing::post(handle)).with_state((m.clone(), aead));
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    m
}

pub(crate) fn gcp(m: &MockKms) -> KekConfig {
    KekConfig {
        gcp_key: Some("projects/p/locations/global/keyRings/r/cryptoKeys/vlpds".into()),
        gcp_endpoint: Some(m.url.clone()),
        gcp_token: Some(GcpToken::Static("test-token".into())),
        ..Default::default()
    }
}

/// Keys are wrapped by KMS at account creation and cached, so writes make
/// no KMS calls; after a restart each account costs one decrypt however
/// many writes race for it; with KMS down a cold account's writes get a
/// retryable 503 (nothing written) while reads, sync exports and warm
/// accounts keep working, and writes resume once KMS is back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kms_unwraps_are_cached_and_outages_are_retryable() {
    let store: Arc<dyn object_store::ObjectStore> = Arc::new(object_store::memory::InMemory::new());
    let kms = mock_kms().await;
    let a = node("kms", &store, gcp(&kms)).await;
    assert!(a.app.secrets.current_kid().starts_with('G'));
    let mut accts = Vec::new();
    for _ in 0..3 {
        accts.push(a.create_account("kms").await);
    }
    assert_eq!(kms.encrypts.load(Ordering::SeqCst), 3, "one wrap per account");
    for t in &accts {
        for i in 0..5 {
            a.post(t, &format!("post {i}")).await;
        }
    }
    assert_eq!(kms.decrypts.load(Ordering::SeqCst), 0, "writes after creation never unwrap");
    a.app.log.checkpoint_all().await;
    vlpds::server::shutdown(&a.app).await;

    // cold: one decrypt per account, even with racing writes
    let b = node("kms", &store, gcp(&kms)).await;
    let posts = futures::future::join_all(accts.iter().flat_map(|t| (0..4).map(move |i| (t, i))).map(|(t, i)| {
        let b = &b;
        async move { b.post(t, &format!("cold {i}")).await }
    }))
    .await;
    assert_eq!(posts.len(), 12);
    let cold = kms.decrypts.load(Ordering::SeqCst);
    assert!((1..=3).contains(&cold), "decrypts after restart: {cold}");
    for t in &accts {
        a_few_writes(&b, t).await;
    }
    assert_eq!(kms.decrypts.load(Ordering::SeqCst), cold, "warm accounts never call KMS");
    // service auth (signs with the cached key)
    b.xrpc.get("com.atproto.server.getServiceAuth", &[("aud", "did:web:example.com")], &accts[0].auth()).await.ok();
    assert_eq!(kms.decrypts.load(Ordering::SeqCst), cold);
    b.app.log.checkpoint_all().await;
    vlpds::server::shutdown(&b.app).await;

    // KMS down, cold node
    kms.up.store(false, Ordering::SeqCst);
    let c = node("kms", &store, gcp(&kms)).await;
    let t = &accts[0];
    let (head, _) = c.latest_commit(&t.did).await;
    let r = c
        .xrpc
        .post(
            "com.atproto.repo.createRecord",
            &json!({"repo": t.did, "collection": "app.bsky.feed.post", "record": post_record("while down")}),
            &t.auth(),
        )
        .await;
    assert_eq!(r.status, 503, "{}", r.text());
    assert_eq!(r.json["error"], json!("KeyUnavailable"), "{}", r.text());
    // nothing was written; reads and exports work
    assert_eq!(c.latest_commit(&t.did).await.0, head);
    c.list_records(&t.did, "app.bsky.feed.post", &[]).await.ok();
    c.get_repo(&t.did).await;
    c.xrpc.get("com.atproto.repo.describeRepo", &[("repo", t.did.as_str())], &Auth::None).await.ok();
    // new accounts can't be created either (their key can't be wrapped): 503, no account
    let r = c
        .xrpc
        .post("com.atproto.server.createAccount", &json!({"handle": format!("{}.{HANDLE_DOMAIN}", unique_name("down")), "password": PASSWORD, "email": "down@example.com"}), &Auth::None)
        .await;
    assert_eq!(r.status, 503, "{}", r.text());
    // back up: writes resume (after the client retries past the backoff)
    kms.up.store(true, Ordering::SeqCst);
    let ok = eventually(Duration::from_secs(10), || async {
        let r = c
            .xrpc
            .post(
                "com.atproto.repo.createRecord",
                &json!({"repo": t.did, "collection": "app.bsky.feed.post", "record": post_record("after")}),
                &t.auth(),
            )
            .await;
        (r.status == 200).then_some(())
    })
    .await;
    assert!(ok.is_some(), "writes resume once KMS is back");
    let repo = c.get_repo(&t.did).await;
    repo.commit().verify(&c.signing_key(&t.did).await).unwrap();
    vlpds::server::shutdown(&c.app).await;
}

async fn a_few_writes(s: &TestServer, t: &TestAccount) {
    for i in 0..3 {
        s.post(t, &format!("warm {i}")).await;
    }
}

/// The PLC rotation key (src/plc) is held only by the node: provisioned as
/// a KMS-wrapped file and unwrapped at startup (one KMS decrypt), it signs
/// genesis and update ops, and appears nowhere in the bucket or state in
/// any common encoding.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn plc_rotation_key_never_reaches_the_bucket() {
    let store: Arc<dyn object_store::ObjectStore> = Arc::new(object_store::memory::InMemory::new());
    let kms = mock_kms().await;
    let plc = vlpds::plc::mock::MockPlc::start().await;
    let rot = vlsync_atproto::crypto::Keypair::generate();
    let raw = rot.to_bytes().to_vec();
    // `vlpds --wrap-plc-rotation-key` with the node's KEK, into a file
    let ring = vlpds::secrets::Secrets::from_config(&gcp(&kms), false).unwrap();
    let wrapped = vlpds::plc::wrap_rotation_key(&ring, &rot).await.unwrap();
    let path = std::env::temp_dir().join(format!("{}.plc-key", unique_name("rk")));
    std::fs::write(&path, format!("{wrapped}\n")).unwrap();
    let src = vlpds::plc::RotationKey::from_file(&path).unwrap();
    std::fs::remove_file(&path).unwrap();
    assert!(matches!(src, vlpds::plc::RotationKey::Wrapped(_)));
    let decrypts = kms.decrypts.load(Ordering::SeqCst);
    let (st, kek, url) = (store.clone(), gcp(&kms), plc.url.clone());
    let s = TestServer::spawn_with(move |c| {
        c.memory_store = Some(st);
        c.kek = kek;
        c.plc_url = url;
        c.plc = vlpds::plc::PlcConfig { rotation_key: Some(src), ..Default::default() };
    })
    .await;
    assert_eq!(kms.decrypts.load(Ordering::SeqCst), decrypts + 1, "unwrapped once at startup");
    assert_eq!(s.app.plc.as_ref().unwrap().rotation_did_key(), rot.did_key());
    let a = s.create_account("plcsec").await;
    s.post(&a, "hello").await;
    let h2 = format!("{}.{HANDLE_DOMAIN}", unique_name("plcsec"));
    s.xrpc.post("com.atproto.identity.updateHandle", &json!({"handle": h2}), &a.auth()).await.ok();
    s.xrpc.post_empty("com.atproto.identity.requestPlcOperationSignature", &a.auth()).await.ok();
    let tok = s.mail_token(&a.email).await.unwrap();
    s.xrpc.post("com.atproto.identity.signPlcOperation", &json!({"token": tok}), &a.auth()).await.ok();
    assert_eq!(plc.ops(&a.did).len(), 2);
    vlpds::plc::verify_sig(&[rot.did_key()], &plc.last_op(&a.did).unwrap()).unwrap();

    s.app.log.checkpoint_all().await;
    let all = everything(&s).await;
    assert!(all.iter().any(|(p, b)| p.contains("/log/") && has(b, h2.as_bytes())), "the scan sees account data");
    for f in forms(&raw) {
        for (path, b) in &all {
            assert!(!has(b, &f), "PLC rotation key found in {path}");
        }
    }
}
