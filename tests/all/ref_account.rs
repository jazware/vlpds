//! Cases from the reference PDS's account tests (account.test.ts,
//! account-deletion.test.ts, account-migration.test.ts, recovery.test.ts,
//! takedown-appeal.test.ts, blob-transactor.test.ts) that the older ports
//! did not assert. tests/REFERENCE_COVERAGE.md maps every reference case.
use crate::common::*;
use parking_lot::Mutex;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// account.test.ts
// ---------------------------------------------------------------------------

/// "serves the accounts system config": blobUploadLimit, links and contact
/// come from the server config.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ref_describe_server_links_contact_and_blob_limit() {
    let s = TestServer::spawn_with(|c| {
        c.max_blob_size = 123_456;
        c.privacy_policy_url = Some("https://example.com/privacy-policy".into());
        c.terms_of_service_url = Some("https://example.com/tos".into());
        c.contact_email_address = Some("abuse@example.com".into());
    })
    .await;
    let j = s.xrpc.get("com.atproto.server.describeServer", &[], &Auth::None).await.ok();
    assert_eq!(j["inviteCodeRequired"], json!(false));
    assert_eq!(j["availableUserDomains"][0], json!(format!(".{HANDLE_DOMAIN}")));
    assert_eq!(j["blobUploadLimit"], json!(123_456));
    assert_eq!(j["links"]["privacyPolicy"], json!("https://example.com/privacy-policy"));
    assert_eq!(j["links"]["termsOfService"], json!("https://example.com/tos"));
    assert_eq!(j["contact"]["email"], json!("abuse@example.com"));

    // unset: omitted (the reference's JSON drops undefined fields)
    let s = TestServer::spawn().await;
    let j = s.xrpc.get("com.atproto.server.describeServer", &[], &Auth::None).await.ok();
    assert_eq!(j["links"], json!({}), "{j}");
    assert_eq!(j["contact"], json!({}), "{j}");
}

/// The exact error names and messages the reference returns for
/// createAccount's handle and uniqueness checks.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ref_create_account_error_messages() {
    let s = TestServer::spawn().await;
    let create = |handle: String, email: String| {
        let x = s.xrpc.clone();
        async move {
            x.post(
                "com.atproto.server.createAccount",
                &json!({"handle": handle, "email": email, "password": "test123"}),
                &Auth::None,
            )
            .await
        }
    };
    let fresh_email = || format!("{}@test.com", unique_name("e"));
    let msg = |r: &Resp| r.json["message"].as_str().unwrap_or_default().to_string();

    // lexicon-level handle syntax
    let r = create("did:bad-handle.vlpds.test".into(), fresh_email()).await;
    r.err(400, "InvalidRequest");
    assert!(msg(&r).contains("handle"), "{}", r.text());

    let r = create(format!("j.{HANDLE_DOMAIN}"), fresh_email()).await;
    r.err(400, "InvalidHandle");
    assert_eq!(msg(&r), "Handle too short");
    let r = create(format!("jayromy-johnber12345678910.{HANDLE_DOMAIN}"), fresh_email()).await;
    r.err(400, "InvalidHandle");
    assert_eq!(msg(&r), "Handle too long");
    let r = create("john.bsky.io".into(), fresh_email()).await;
    r.err(400, "UnsupportedDomain");
    assert_eq!(msg(&r), "Not a supported handle domain");
    for reserved in ["about", "atp"] {
        let r = create(format!("{reserved}.{HANDLE_DOMAIN}"), fresh_email()).await;
        r.err(400, "HandleNotAvailable");
        assert_eq!(msg(&r), "Reserved handle");
    }

    // duplicates: the email echoes the request's spelling, the handle is normalized
    let name = unique_name("bob");
    let handle = format!("{name}.{HANDLE_DOMAIN}");
    let email = format!("{name}@test.com");
    create(handle.clone(), email.clone()).await.ok();
    let r = create(format!("{}.{HANDLE_DOMAIN}", unique_name("carol")), email.to_uppercase()).await;
    r.err(400, "InvalidRequest");
    assert_eq!(msg(&r), format!("Email already taken: {}", email.to_uppercase()));
    let r = create(handle.to_uppercase(), fresh_email()).await;
    r.err(400, "HandleNotAvailable");
    assert_eq!(msg(&r), format!("Handle already taken: {handle}"));
}

/// account.test.ts "email validation > fails on disallowed emails": a
/// disposable domain (the reference's `disposable-email-domains-js` list,
/// vendored in src/email_policy) is refused with the not-supported message,
/// case-insensitively; a subdomain of a listed domain is not.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ref_fails_on_disallowed_emails() {
    let s = TestServer::spawn().await;
    let create = |email: &str| {
        let (x, email) = (s.xrpc.clone(), email.to_string());
        async move {
            let handle = format!("{}.{HANDLE_DOMAIN}", unique_name("bad-email"));
            x.post(
                "com.atproto.server.createAccount",
                &json!({"handle": handle, "email": email, "password": "asdf"}),
                &Auth::None,
            )
            .await
        }
    };
    for email in ["bad-email@disposeamail.com", "Bad-Email@DisposeAMail.com", "x@mailinator.com"] {
        let r = create(email).await;
        r.err(400, "InvalidRequest");
        assert_eq!(
            r.json["message"],
            json!("This email address is not supported, please use a different email."),
            "{email}"
        );
    }
    create(&format!("{}@sub.disposeamail.com", unique_name("ok"))).await.ok();
}

/// "can reset account password" (the mail) and "allows only unexpired
/// password reset tokens".
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ref_password_reset_mail_and_expired_token() {
    let s = TestServer::spawn().await;
    let a = s.create_account("alice").await;
    s.xrpc.post("com.atproto.server.requestPasswordReset", &json!({"email": a.email}), &Auth::None).await.ok();
    let mail = latest_mail(&s, &a.email).await;
    assert_eq!(mail["to"], json!(a.email));
    assert_eq!(mail["subject"], json!("Password Reset Requested"));
    let html = mail["html"].as_str().unwrap();
    assert!(html.contains("Reset password"), "{html}");
    assert!(html.contains(&a.handle), "{html}");
    let token = mail["token"].as_str().unwrap().to_string();

    // 16 minutes old: ExpiredToken, and the password is unchanged
    age_email_token(&s, &a.did, "reset_password", 16 * 60 * 1000).await;
    let r = s
        .xrpc
        .post("com.atproto.server.resetPassword", &json!({"token": token, "password": "the-alt-password"}), &Auth::None)
        .await;
    r.err(400, "ExpiredToken");
    let r = s.create_session(&a.handle, "the-alt-password").await;
    r.err(401, "AuthenticationRequired");
    assert_eq!(r.json["message"], json!("Invalid identifier or password"));
    s.create_session(&a.handle, &a.password).await.ok();
}

// ---------------------------------------------------------------------------
// account-deletion.test.ts
// ---------------------------------------------------------------------------

/// "requests account deletion" (the mail) and "deletes account with a valid
/// token & password" while the account is taken down.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ref_delete_account_mail_and_taken_down_delete() {
    let s = TestServer::spawn().await;
    let carol = s.create_account("carol").await;
    s.post(&carol, "hi").await;
    s.xrpc.post_empty("com.atproto.server.requestAccountDelete", &carol.auth()).await.ok();
    let mail = latest_mail(&s, &carol.email).await;
    assert_eq!(mail["to"], json!(carol.email));
    assert_eq!(mail["subject"], json!("Account Deletion Requested"));
    assert!(mail["html"].as_str().unwrap().contains("To permanently delete your account"), "{mail}");
    let token = mail["token"].as_str().unwrap().to_string();

    let r = s
        .xrpc
        .post(
            "com.atproto.server.deleteAccount",
            &json!({"did": carol.did, "password": carol.password, "token": "123456"}),
            &Auth::None,
        )
        .await;
    r.err(400, "InvalidToken");
    assert_eq!(r.json["message"], json!("Token is invalid"));
    let r = s
        .xrpc
        .post(
            "com.atproto.server.deleteAccount",
            &json!({"did": carol.did, "password": "bad-pass", "token": token}),
            &Auth::None,
        )
        .await;
    r.err(401, "AuthenticationRequired");
    assert_eq!(r.json["message"], json!("Invalid did or password"));

    // deletion works on an account that is already taken down
    set_repo_takedown(&s, &carol.did, true).await;
    let mut sub = s.subscribe_from_now().await;
    s.xrpc
        .post(
            "com.atproto.server.deleteAccount",
            &json!({"did": carol.did, "password": carol.password, "token": token}),
            &Auth::None,
        )
        .await
        .ok();
    let ev = sub.wait_for(FH_TIMEOUT, &carol.did, "#account").await.pop().unwrap();
    assert_eq!((ev.bool("active"), ev.str("status")), (Some(false), Some("deleted")));
    let r = s.create_session(&carol.handle, &carol.password).await;
    r.err(401, "AuthenticationRequired");
    assert_eq!(r.json["message"], json!("Invalid identifier or password"));
    s.xrpc.get("com.atproto.sync.getRepo", &[("did", &carol.did)], &Auth::None).await.err(400, "RepoNotFound");
    s.xrpc.get("com.atproto.admin.getAccountInfo", &[("did", &carol.did)], &Auth::Admin).await.client_err();
}

// ---------------------------------------------------------------------------
// account-migration.test.ts
// ---------------------------------------------------------------------------

/// The migration's preference copy targets a not-yet-activated account:
/// putPreferences/getPreferences work while deactivated (the reference's
/// putPreferences checks takedown only).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ref_preferences_on_deactivated_account() {
    let s = TestServer::spawn().await;
    let a = s.create_account("prefs").await;
    s.xrpc.post("com.atproto.server.deactivateAccount", &json!({}), &a.auth()).await.ok();
    let prefs = json!([{"$type": "app.bsky.actor.defs#adultContentPref", "enabled": false}]);
    s.xrpc.post("app.bsky.actor.putPreferences", &json!({"preferences": prefs}), &a.auth()).await.ok();
    let j = s.xrpc.get("app.bsky.actor.getPreferences", &[], &a.auth()).await.ok();
    assert_eq!(j["preferences"], prefs);
}

/// requestPlcOperationSignature mails the token ("PLC Update Operation
/// Requested").
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ref_plc_operation_signature_mail() {
    use vlpds::plc::mock::MockPlc;
    let plc = MockPlc::start().await;
    let s = TestServer::spawn_plc(&plc.url, Arc::new(vlatproto::crypto::Keypair::generate())).await;
    let a = s.create_account("plcmail").await;
    s.xrpc.post_empty("com.atproto.identity.requestPlcOperationSignature", &a.auth()).await.ok();
    let mail = latest_mail(&s, &a.email).await;
    assert_eq!(mail["to"], json!(a.email));
    assert_eq!(mail["subject"], json!("PLC Update Operation Requested"));
    assert!(mail["html"].as_str().unwrap().contains("We received a request to update your PLC"), "{mail}");
    assert!(mail["token"].is_string());
}

// ---------------------------------------------------------------------------
// recovery.test.ts ("rotates keys for users")
// ---------------------------------------------------------------------------

/// The reference's rotate-keys script updates the DID's signing key, then
/// writes an empty commit signed with the new key and sequences #identity
/// and #sync, so the served repo verifies against the new key right away.
/// vlpds's admin.updateAccountSigningKey does the same (the worker's
/// KeyStep::Finish; tests/all/key_rotation.rs covers concurrent writes,
/// PLC failures and crashes mid-rotation).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ref_signing_key_rotation_resigns_the_repo() {
    let s = TestServer::spawn().await;
    let a = s.create_account("rot").await;
    s.post(&a, "before").await;
    let (_, rev_before) = s.latest_commit(&a.did).await;
    let mut sub = s.subscribe_from_now().await;
    let j = s.xrpc.post("com.atproto.admin.updateAccountSigningKey", &json!({"did": a.did}), &Auth::Admin).await.ok();
    let new_key = decode_did_key_k256(j["signingKey"].as_str().unwrap()).unwrap();

    let frames =
        sub.until(FH_TIMEOUT, |fs| fs.iter().any(|f| f.kind() == "#sync" && f.did() == Some(a.did.as_str()))).await;
    let kinds: Vec<&str> = frames.iter().filter(|f| f.did() == Some(a.did.as_str())).map(|f| f.kind()).collect();
    assert_eq!(kinds, vec!["#identity", "#sync"], "{frames:?}");
    let sync = frames.iter().find(|f| f.kind() == "#sync").unwrap().sync().unwrap();
    sync.commit_obj().verify(&new_key).expect("#sync commit signed with the new key");

    // no write needed: the served head is already signed with the new key
    let repo = s.get_repo(&a.did).await;
    repo.commit().verify(&new_key).expect("repo re-signed with the rotated key");
    assert_eq!(repo.entries().len(), 1);
    let (_, rev_after) = s.latest_commit(&a.did).await;
    assert!(rev_after > rev_before, "{rev_after} <= {rev_before}");
}

// ---------------------------------------------------------------------------
// takedown-appeal.test.ts
// ---------------------------------------------------------------------------

#[derive(Clone, Default)]
struct Reports {
    seen: Arc<Mutex<Vec<(String, axum::http::HeaderMap, J)>>>,
}

async fn spawn_report_service() -> (Reports, String) {
    use axum::extract::{Request, State};
    use axum::response::IntoResponse;
    async fn handle(State(r): State<Reports>, req: Request) -> axum::response::Response {
        let (parts, body) = req.into_parts();
        let body = axum::body::to_bytes(body, 1 << 20).await.unwrap();
        let mut v: J = serde_json::from_slice(&body).unwrap_or(J::Null);
        r.seen.lock().push((parts.uri.path().to_string(), parts.headers.clone(), v.clone()));
        v["id"] = json!(1);
        v["reportedBy"] = json!("did:example:x");
        v["createdAt"] = json!("2026-01-01T00:00:00Z");
        axum::Json(v).into_response()
    }
    let reports = Reports::default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let router = axum::Router::new().fallback(handle).with_state(reports.clone());
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (reports, url)
}

/// "actor takedown allows appeal request" and "takendown actor is not
/// allowed to create records", PDS side: a plain login is refused, an
/// allowTakendown session's createReport is forwarded to the moderation
/// service with service auth (the "not accepted from takendown account"
/// rejection of non-appeal reports is Ozone's), and repo writes are refused
/// with "Bad token scope".
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ref_takendown_session_appeal_is_forwarded() {
    let (reports, url) = spawn_report_service().await;
    let s = TestServer::spawn_with(move |c| c.report_service = Some((url, "did:web:mod.test".into()))).await;
    let jeff = s.create_account("jeff").await;
    set_repo_takedown(&s, &jeff.did, true).await;

    let r = s.create_session(&jeff.handle, &jeff.password).await;
    r.err(401, "AccountTakedown");
    assert_eq!(r.json["message"], json!("Account has been taken down"));
    let j = s
        .xrpc
        .post(
            "com.atproto.server.createSession",
            &json!({"identifier": jeff.handle, "password": jeff.password, "allowTakendown": true}),
            &Auth::None,
        )
        .await
        .ok();
    let tok = Auth::Bearer(j["accessJwt"].as_str().unwrap().to_string());

    let appeal = json!({
        "reasonType": "com.atproto.moderation.defs#reasonAppeal",
        "reason": "I want my account back",
        "subject": {"$type": "com.atproto.admin.defs#repoRef", "did": jeff.did},
    });
    let out = s.xrpc.post("com.atproto.moderation.createReport", &appeal, &tok).await.ok();
    assert_eq!(out["reasonType"], appeal["reasonType"]);
    let (path, headers, body) = reports.seen.lock().last().cloned().expect("report forwarded");
    assert_eq!(path, "/xrpc/com.atproto.moderation.createReport");
    assert_eq!(body, appeal);
    let bearer = headers.get("authorization").unwrap().to_str().unwrap().strip_prefix("Bearer ").unwrap().to_string();
    let claims: J = {
        use base64::Engine;
        let mid = bearer.split('.').nth(1).unwrap();
        serde_json::from_slice(&base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(mid).unwrap()).unwrap()
    };
    assert_eq!(claims["iss"], json!(jeff.did));
    assert_eq!(claims["aud"], json!("did:web:mod.test"));
    assert_eq!(claims["lxm"], json!("com.atproto.moderation.createReport"));

    let r = s
        .xrpc
        .post(
            "com.atproto.repo.createRecord",
            &json!({"repo": jeff.did, "collection": "app.bsky.feed.post", "record": post_record("test")}),
            &tok,
        )
        .await;
    r.err(400, "InvalidToken");
    assert_eq!(r.json["message"], json!("Bad token scope"));
}

// ---------------------------------------------------------------------------
// blob-transactor.test.ts
// ---------------------------------------------------------------------------

/// "drains the MIME stream without stalling other consumers": a 25 MiB
/// upload whose bytes start with the JPEG magic is stored whole, hashed over
/// all of it, and typed by sniffing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ref_large_upload_is_sniffed_and_hashed_whole() {
    let s = TestServer::spawn().await;
    let a = s.create_account("big").await;
    let mut file = vec![0u8; 25 * 1024 * 1024];
    file[..3].copy_from_slice(&[0xff, 0xd8, 0xff]);
    let r = s
        .xrpc
        .post_bytes("com.atproto.repo.uploadBlob", file.clone(), "application/octet-stream", &a.auth())
        .await
        .ok();
    let blob = &r["blob"];
    assert_eq!(blob["mimeType"], json!("image/jpeg"));
    assert_eq!(blob["size"], json!(file.len()));
    assert_eq!(blob["ref"]["$link"], json!(Cid::raw(&file).to_string()));
}
