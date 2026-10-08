//! User service auth on com.atproto.repo.uploadBlob (the reference's
//! `authorizationOrUserServiceAuth`): a service JWT the user got from
//! getServiceAuth (iss = the user, aud = this PDS, lxm = uploadBlob) uploads
//! a blob owned by the user. This is how the Bluesky app's video upload
//! reaches the PDS: the app hands such a token to video.bsky.app, which
//! uploads the processed video here. No reference test covers it (the
//! reference suite only drives uploadBlob with sessions), so this file is
//! written against auth-verifier.ts / xrpc-server auth.ts directly.

use crate::common::*;
use base64::Engine;
use std::time::Duration;
use vlatproto::crypto::Keypair;
use vlpds::plc::mock::MockPlc;

const UPLOAD: &str = "com.atproto.repo.uploadBlob";
const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// An MP4 header (sniffed as video/mp4) and some payload.
fn mp4(n: usize, seed: u8) -> Vec<u8> {
    let mut b = b"\x00\x00\x00\x18ftypmp42\x00\x00\x00\x00mp42isom".to_vec();
    b.extend((0..n).map(|i| (i as u8).wrapping_mul(37).wrapping_add(seed)));
    b
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

/// getServiceAuth as the account, returning the token.
async fn service_token(s: &TestServer, a: &TestAccount, aud: &str, lxm: Option<&str>, exp: Option<i64>) -> String {
    let exp = exp.map(|e| e.to_string());
    let mut q = vec![("aud", aud)];
    if let Some(l) = lxm {
        q.push(("lxm", l));
    }
    if let Some(e) = &exp {
        q.push(("exp", e));
    }
    let r = s.xrpc.get("com.atproto.server.getServiceAuth", &q, &a.auth()).await.ok();
    r["token"].as_str().expect("token").to_string()
}

async fn upload(s: &TestServer, token: &str, body: Vec<u8>) -> Resp {
    s.xrpc.post_bytes(UPLOAD, body, "video/mp4", &Auth::Bearer(token.to_string())).await
}

fn assert_err(r: &Resp, status: u16, name: &str, message: &str) {
    r.err(status, name);
    assert_eq!(r.json["message"].as_str(), Some(message), "{}", r.text());
}

async fn list_blobs(s: &TestServer, did: &str) -> Vec<String> {
    let r = s.xrpc.get("com.atproto.sync.listBlobs", &[("did", did)], &Auth::None).await.ok();
    r["cids"].as_array().unwrap().iter().map(|c| c.as_str().unwrap().to_string()).collect()
}

fn video_post(blob: &J) -> J {
    json!({
        "$type": "app.bsky.feed.post",
        "text": "a video",
        "createdAt": now_iso(),
        "embed": {
            "$type": "app.bsky.embed.video",
            "video": blob,
            "aspectRatio": {"width": 16, "height": 9},
        },
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn upload_with_user_service_auth_is_owned_by_the_issuer() {
    let s = TestServer::spawn().await;
    let a = s.create_account("usa").await;
    let pds = s.pds_did().await;
    // what the app asks for: lxm uploadBlob, 30 minutes
    let tok = service_token(&s, &a, &pds, Some(UPLOAD), Some(now() + 1800)).await;
    let bytes = mp4(5000, 1);
    let r = upload(&s, &tok, bytes.clone()).await.ok();
    assert_eq!(r["blob"]["mimeType"], "video/mp4", "{r}");
    assert_eq!(r["blob"]["size"], bytes.len());
    let cid = r["blob"]["ref"]["$link"].as_str().unwrap().to_string();
    // the token is not single-use (the reference has no jti replay check):
    // the video service may retry
    upload(&s, &tok, bytes.clone()).await.ok();

    // the blob is the user's: a record of theirs can reference it
    let rec = s.create_record(&a, "app.bsky.feed.post", video_post(&r["blob"])).await;
    let got = s.get_record(&a.did, "app.bsky.feed.post", rec.rkey()).await.ok();
    assert_eq!(got["value"]["embed"]["video"]["ref"]["$link"], json!(cid));
    assert!(list_blobs(&s, &a.did).await.contains(&cid));
    let g = s.xrpc.get("com.atproto.sync.getBlob", &[("did", &a.did), ("cid", &cid)], &Auth::None).await;
    assert_eq!(g.status, 200);
    assert_eq!(g.body.as_ref() as &[u8], bytes.as_slice());
    assert_eq!(g.header("content-type").as_deref(), Some("video/mp4"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bad_user_service_tokens_are_refused_with_the_reference_errors() {
    let s = TestServer::spawn().await;
    let a = s.create_account("usa").await;
    let b = s.create_account("usb").await;
    let pds = s.pds_did().await;
    let body = || mp4(100, 2);

    // a token for another method
    let t = service_token(&s, &a, &pds, Some("com.atproto.repo.createRecord"), None).await;
    assert_err(
        &upload(&s, &t, body()).await,
        401,
        "BadJwtLexiconMethod",
        "bad jwt lexicon method (\"lxm\"). must match: com.atproto.repo.uploadBlob",
    );

    // addressed elsewhere: another service, or this PDS's service id (the
    // reference compares `aud` to the bare service DID exactly)
    for aud in ["did:web:video.bsky.app".to_string(), format!("{pds}#atproto_pds")] {
        let t = service_token(&s, &a, &aud, Some(UPLOAD), None).await;
        assert_err(&upload(&s, &t, body()).await, 401, "BadJwtAudience", "jwt audience does not match service did");
    }

    // expired
    let exp = now() + 1;
    let t = service_token(&s, &a, &pds, Some(UPLOAD), Some(exp)).await;
    while vlatproto::tid::now_micros() as f64 / 1e6 <= exp as f64 {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_err(&upload(&s, &t, body()).await, 401, "JwtExpired", "jwt expired");

    // signed by another user's key: bob's token, claiming to be alice's
    let bt = service_token(&s, &b, &pds, Some(UPLOAD), None).await;
    let parts: Vec<&str> = bt.split('.').collect();
    let mut claims: J = serde_json::from_slice(&B64.decode(parts[1]).unwrap()).unwrap();
    claims["iss"] = json!(a.did);
    let forged = format!("{}.{}.{}", parts[0], B64.encode(serde_json::to_vec(&claims).unwrap()), parts[2]);
    assert_err(&upload(&s, &forged, body()).await, 401, "BadJwtSignature", "jwt signature does not match jwt issuer");
    // (bob's own token still works, for bob)
    let r = upload(&s, &bt, body()).await.ok();
    let cid = r["blob"]["ref"]["$link"].as_str().unwrap().to_string();
    s.create_record(&b, "app.bsky.feed.post", video_post(&r["blob"])).await;
    assert!(list_blobs(&s, &b.did).await.contains(&cid));
    assert!(!list_blobs(&s, &a.did).await.contains(&cid));

    // signed with a key the account no longer has
    let old = service_token(&s, &a, &pds, Some(UPLOAD), None).await;
    upload(&s, &old, body()).await.ok();
    s.xrpc.post("com.atproto.admin.updateAccountSigningKey", &json!({"did": a.did}), &Auth::Admin).await.ok();
    assert_err(&upload(&s, &old, body()).await, 401, "BadJwtSignature", "jwt signature does not match jwt issuer");
    let new = service_token(&s, &a, &pds, Some(UPLOAD), None).await;
    upload(&s, &new, body()).await.ok();

    // a method-less service token is not "definitely service auth": it is
    // taken for a session, and is not one
    let t = service_token(&s, &a, &pds, None, None).await;
    upload(&s, &t, body()).await.err(400, "InvalidToken");

    // garbage that claims an lxm
    let junk = format!("e30.{}.AAAA", B64.encode(br#"{"lxm":"com.atproto.repo.uploadBlob"}"#));
    assert_err(&upload(&s, &junk, body()).await, 401, "BadJwt", "poorly formatted jwt");
}

/// Issuers that verify but are not accounts here: the reference's actor
/// store miss, 400 NotFound "Repo not found".
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn foreign_issuers_are_refused() {
    let plc = MockPlc::start().await;
    let url = plc.url.clone();
    let s = TestServer::spawn_with(move |c| c.plc_url = url).await;
    let pds = s.pds_did().await;
    let key = Keypair::generate();
    let op = json!({
        "type": "plc_operation",
        "rotationKeys": [key.did_key()],
        "verificationMethods": {"atproto": key.did_key()},
        "alsoKnownAs": ["at://elsewhere.test"],
        "services": {},
        "prev": null,
    });
    let op = vlpds::plc::sign(op, &key).unwrap();
    let did = vlpds::plc::did_for_genesis(&op).unwrap();
    let r = reqwest::Client::new().post(format!("{}/{did}", plc.url)).json(&op).send().await.unwrap();
    assert!(r.status().is_success());

    for iss in [did.clone(), format!("{did}#atproto_pds")] {
        let t = vlpds::auth::service_auth_jwt(&key, &iss, &pds, Some(UPLOAD), 60).unwrap();
        assert_err(&upload(&s, &t, mp4(10, 3)).await, 400, "NotFound", "Repo not found");
    }
    // ...and so is a wrong key for that issuer: the issuer is checked before
    // its key is resolved (stricter ordering than the reference, which
    // resolves first), so forged tokens cause no outbound DID fetches
    let other = Keypair::generate();
    let t = vlpds::auth::service_auth_jwt(&other, &did, &pds, Some(UPLOAD), 60).unwrap();
    assert_err(&upload(&s, &t, mp4(10, 3)).await, 400, "NotFound", "Repo not found");
    assert!(s.app.did_resolver.cached(&did).is_none(), "the foreign issuer was never resolved");
}

/// Account status: deactivated accounts upload (as with a session, and as
/// the reference); taken-down ones are refused even with a token issued
/// before the takedown (stricter than the reference, which skips the status
/// check for service auth; see DESIGN.md).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn account_status_with_user_service_auth() {
    let s = TestServer::spawn().await;
    let a = s.create_account("usa").await;
    let b = s.create_account("usb").await;
    let pds = s.pds_did().await;
    let ta = service_token(&s, &a, &pds, Some(UPLOAD), Some(now() + 600)).await;
    let tb = service_token(&s, &b, &pds, Some(UPLOAD), Some(now() + 600)).await;

    s.xrpc.post("com.atproto.server.deactivateAccount", &json!({}), &a.auth()).await.ok();
    upload(&s, &ta, mp4(10, 4)).await.ok();

    set_repo_takedown(&s, &b.did, true).await;
    assert_err(&upload(&s, &tb, mp4(10, 5)).await, 401, "AccountTakedown", "Account has been taken down");
    set_repo_takedown(&s, &b.did, false).await;
    upload(&s, &tb, mp4(10, 5)).await.ok();
}

/// The token is accepted on uploadBlob only: on every other method (each
/// with a token minted for it, or the uploadBlob token for methods
/// getServiceAuth won't mint) it is taken for a session and refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn user_service_auth_is_refused_on_every_other_method() {
    // an upstream for the proxied methods, so they get as far as auth (it
    // would answer getUploadLimits)
    let upstream = stub_video_service("http://127.0.0.1:1".into()).await;
    let s = TestServer::spawn_with(move |c| c.appview = Some((upstream, "did:web:appview.test".into()))).await;
    let a = s.create_account("usa").await;
    let pds = s.pds_did().await;
    let upload_tok = service_token(&s, &a, &pds, Some(UPLOAD), None).await;
    let post = || json!({"repo": a.did, "collection": "app.bsky.feed.post", "record": post_record("x")});
    // (method, is a procedure, body)
    let methods: Vec<(&str, bool, J)> = vec![
        ("com.atproto.repo.createRecord", true, post()),
        (
            "com.atproto.repo.putRecord",
            true,
            json!({"repo": a.did, "collection": "app.bsky.feed.post", "rkey": "x", "record": post_record("x")}),
        ),
        (
            "com.atproto.repo.deleteRecord",
            true,
            json!({"repo": a.did, "collection": "app.bsky.feed.post", "rkey": "x"}),
        ),
        ("com.atproto.repo.applyWrites", true, json!({"repo": a.did, "writes": []})),
        ("com.atproto.repo.listMissingBlobs", false, J::Null),
        ("com.atproto.repo.importRepo", true, J::Null),
        ("com.atproto.server.getSession", false, J::Null),
        ("com.atproto.server.getServiceAuth", false, J::Null),
        ("com.atproto.server.createAppPassword", true, json!({"name": "x"})),
        ("com.atproto.server.deactivateAccount", true, json!({})),
        ("com.atproto.server.deleteSession", true, J::Null),
        ("com.atproto.server.refreshSession", true, J::Null),
        ("com.atproto.server.requestAccountDelete", true, J::Null),
        ("com.atproto.server.updateEmail", true, json!({"email": "x@example.com"})),
        ("com.atproto.identity.updateHandle", true, json!({"handle": "other.test"})),
        ("com.atproto.identity.getRecommendedDidCredentials", false, J::Null),
        (
            "com.atproto.moderation.createReport",
            true,
            json!({"reasonType": "com.atproto.moderation.defs#reasonSpam", "subject": {"$type": "com.atproto.admin.defs#repoRef", "did": a.did}}),
        ),
        ("com.atproto.admin.getAccountInfo", false, J::Null),
        ("app.bsky.actor.getPreferences", false, J::Null),
        ("app.bsky.actor.putPreferences", true, json!({"preferences": []})),
        ("app.bsky.feed.getTimeline", false, J::Null),
        ("app.bsky.video.getUploadLimits", false, J::Null),
        ("com.atproto.server.createAccount", true, json!({"handle": "x.vlpds.test"})),
    ];
    for (m, procedure, body) in methods {
        let own = s.xrpc.get("com.atproto.server.getServiceAuth", &[("aud", &pds), ("lxm", m)], &a.auth()).await;
        let tok = if own.is_ok() { own.json["token"].as_str().unwrap().to_string() } else { upload_tok.clone() };
        for tok in [tok, upload_tok.clone()] {
            let auth = Auth::Bearer(tok);
            let r = if procedure { s.xrpc.post(m, &body, &auth).await } else { s.xrpc.get(m, &[], &auth).await };
            assert!(matches!(r.status, 400 | 401 | 403), "{m} accepted a user service token: {}", r.text());
            // createAccount takes service auth itself (migration in), and
            // refuses a token for another method with lxm mismatch
            let want: &[&str] = if m == "com.atproto.server.createAccount" {
                &["BadJwtLexiconMethod", "InvalidRequest", "InvalidHandle", "HandleNotAvailable"]
            } else {
                &["InvalidToken", "AuthenticationRequired", "UntrustedIss"]
            };
            assert!(want.contains(&r.error_name().unwrap_or("")), "{m}: {}", r.text());
        }
    }
}

// ---------------------------------------------------------------------------
// the app's video upload, end to end with a stub video service
// ---------------------------------------------------------------------------

/// A stand-in for video.bsky.app's `app.bsky.video.uploadVideo`: takes the
/// user's PDS service token (Authorization) and the video, "processes" it
/// (passes it through) and uploads the result to the user's PDS with that
/// token, answering a completed job with the blob.
async fn stub_video_service(pds_url: String) -> String {
    use axum::extract::{Query, State};
    use axum::http::HeaderMap;
    use axum::routing::{get, post};
    use axum::Json;
    use std::collections::HashMap;
    async fn upload_video(
        State(pds): State<String>,
        Query(q): Query<HashMap<String, String>>,
        headers: HeaderMap,
        body: axum::body::Bytes,
    ) -> (axum::http::StatusCode, Json<J>) {
        let auth = headers.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
        let r = reqwest::Client::new()
            .post(format!("{pds}/xrpc/com.atproto.repo.uploadBlob"))
            .header("authorization", auth)
            .header("content-type", "video/mp4")
            .body(body.to_vec())
            .send()
            .await
            .unwrap();
        let status = r.status().as_u16();
        let j: J = r.json().await.unwrap_or(J::Null);
        if status != 200 {
            return (axum::http::StatusCode::BAD_GATEWAY, Json(json!({"error": "UploadFailed", "message": j})));
        }
        let job = json!({"jobId": "job-1", "did": q.get("did"), "state": "JOB_STATE_COMPLETED", "blob": j["blob"]});
        (axum::http::StatusCode::OK, Json(json!({"jobStatus": job})))
    }
    async fn limits() -> Json<J> {
        Json(json!({"canUpload": true}))
    }
    let app = axum::Router::new()
        .route("/xrpc/app.bsky.video.uploadVideo", post(upload_video))
        .route("/xrpc/app.bsky.video.getUploadLimits", get(limits))
        .layer(axum::extract::DefaultBodyLimit::disable())
        .with_state(pds_url);
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    format!("http://{addr}")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn video_upload_flow_through_a_video_service() {
    let s = TestServer::spawn_with(|c| c.max_blob_size = 20 << 20).await;
    let a = s.create_account("vid").await;
    let video = stub_video_service(s.url.clone()).await;

    // the app: a service token for its PDS (`did:web:<pds host>`), lxm
    // uploadBlob, 30 minutes
    let pds = s.pds_did().await;
    let tok = service_token(&s, &a, &pds, Some(UPLOAD), Some(now() + 1800)).await;
    // ...and sends the video straight to the video service (not via the PDS)
    let bytes = mp4(9_000_000, 7); // > one 8 MiB part: the multipart path
    let r = reqwest::Client::new()
        .post(format!("{video}/xrpc/app.bsky.video.uploadVideo?did={}&name=clip.mp4", a.did))
        .header("authorization", format!("Bearer {tok}"))
        .header("content-type", "video/mp4")
        .body(bytes.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    let job: J = r.json().await.unwrap();
    let blob = job["jobStatus"]["blob"].clone();
    assert_eq!(blob["mimeType"], "video/mp4", "{job}");
    assert_eq!(blob["size"], bytes.len());
    let cid = blob["ref"]["$link"].as_str().unwrap().to_string();

    // the app then posts the video with its session
    let rec = s.create_record(&a, "app.bsky.feed.post", video_post(&blob)).await;
    let got = s.get_record(&a.did, "app.bsky.feed.post", rec.rkey()).await.ok();
    assert_eq!(got["value"]["embed"]["$type"], "app.bsky.embed.video");
    assert_eq!(got["value"]["embed"]["video"]["ref"]["$link"], json!(cid));
    assert!(list_blobs(&s, &a.did).await.contains(&cid));
    let missing = s.xrpc.get("com.atproto.repo.listMissingBlobs", &[], &a.auth()).await.ok();
    assert_eq!(missing["blobs"], json!([]));
    let g = s.xrpc.get("com.atproto.sync.getBlob", &[("did", &a.did), ("cid", &cid)], &Auth::None).await;
    assert_eq!(g.status, 200);
    assert_eq!(g.body.len(), bytes.len());
    assert!(g.body.as_ref() == bytes.as_slice());
}
