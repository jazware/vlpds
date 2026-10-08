//! Cases of the reference PDS's auth.test.ts, app-passwords.test.ts,
//! email-confirmation.test.ts and rate-limits.test.ts that the older ports
//! (auth, app_passwords, email_flows, rate_limits) did not assert, mostly
//! the exact error names and messages clients match on. See
//! tests/REFERENCE_COVERAGE.md.

use crate::common::*;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;

fn jti(tok: &str) -> String {
    let p = tok.split('.').nth(1).unwrap();
    serde_json::from_slice::<J>(&B64.decode(p).unwrap()).unwrap()["jti"].as_str().unwrap().to_string()
}

async fn refresh(s: &TestServer, tok: &str) -> Resp {
    s.xrpc.post_empty("com.atproto.server.refreshSession", &Auth::Bearer(tok.into())).await
}

#[track_caller]
fn assert_err_msg(r: &Resp, status: u16, error: &str, message: &str) {
    r.err(status, error);
    assert_eq!(r.json["message"], json!(message), "{}", r.text());
}

/// auth.test.ts: "refresh token is revoked after grace period completes."
/// The reference ends the grace period by editing the refresh_token row;
/// this ages the rotated token's stored state the same way.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ref_refresh_token_revoked_after_grace_period() {
    let s = TestServer::spawn().await;
    let a = s.create_account("evan").await;
    refresh(&s, &a.refresh).await.ok();
    // within the grace period the old token still works
    refresh(&s, &a.refresh).await.ok();
    let name = format!("sess/{}", jti(&a.refresh));
    let raw = s.app.get_private(&a.did, &name).await.ok().flatten().expect("stored refresh token");
    let mut st: J = serde_json::from_slice(&raw).unwrap();
    st["exp"] = json!(chrono::Utc::now().timestamp() - 1);
    s.app
        .put_private(
            &a.did,
            vec![vlsync_store::segment::Mutation {
                key: vlpds::state::private_key(&a.did, &name).into(),
                val: Some(serde_json::to_vec(&st).unwrap().into()),
            }],
        )
        .await
        .unwrap_or_else(|e| panic!("put_private: {}", e.message));
    assert_err_msg(&refresh(&s, &a.refresh).await, 400, "ExpiredToken", "Token has been revoked");
}

/// auth.test.ts: the exact errors of the refresh paths ("Token has been
/// revoked", "Token could not be verified").
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ref_refresh_error_messages() {
    let s = TestServer::spawn().await;
    let a = s.create_account("finn").await;
    // access token cannot be used to refresh a session
    assert_err_msg(&refresh(&s, &a.access).await, 400, "InvalidToken", "Token could not be verified");
    // refresh token is revoked when session is deleted
    s.xrpc.post_empty("com.atproto.server.deleteSession", &a.refresh_auth()).await.ok();
    assert_err_msg(&refresh(&s, &a.refresh).await, 400, "ExpiredToken", "Token has been revoked");
}

async fn app_session(s: &TestServer, a: &TestAccount, name: &str, privileged: bool) -> (String, Auth, String) {
    let pw = s
        .xrpc
        .post("com.atproto.server.createAppPassword", &json!({"name": name, "privileged": privileged}), &a.auth())
        .await
        .ok()["password"]
        .as_str()
        .unwrap()
        .to_string();
    let j = s.create_session(&a.handle, &pw).await.ok();
    (pw, Auth::Bearer(j["accessJwt"].as_str().unwrap().into()), j["refreshJwt"].as_str().unwrap().into())
}

/// app-passwords.test.ts: the errors clients see ("Bad token scope",
/// "Bad token method", the getServiceAuth refusal, revocation).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ref_app_password_error_messages() {
    let s = TestServer::spawn_with(|c| {
        // the chat check runs before anything is forwarded: never contacted
        c.appview = Some(("http://127.0.0.1:1".into(), "did:web:appview.test".into()));
    })
    .await;
    let a = s.create_account("alice").await;
    let (app_pass, app, app_refresh) = app_session(&s, &a, "test-pass", false).await;
    let (_, privi, _) = app_session(&s, &a, "privi-pass", true).await;

    // restricts full access actions
    for auth in [&app, &privi] {
        let r = s.xrpc.post("com.atproto.server.createAppPassword", &json!({"name": "another-one"}), auth).await;
        assert_err_msg(&r, 400, "InvalidToken", "Bad token scope");
    }

    // restricts privileged app password actions (chat)
    let rb = s
        .xrpc
        .http
        .get(format!("{}/xrpc/chat.bsky.convo.listConvos", s.url))
        .header(
            "authorization",
            match &app {
                Auth::Bearer(t) => format!("Bearer {t}"),
                _ => unreachable!(),
            },
        )
        .header("atproto-proxy", "did:web:appview.test#bsky_appview");
    let r = s.xrpc.send(rb).await;
    assert_err_msg(&r, 400, "InvalidToken", "Bad token method");

    // restricts service auth token methods for non-privileged access tokens
    let pds = s.xrpc.get("com.atproto.server.describeServer", &[], &Auth::None).await.ok()["did"]
        .as_str()
        .unwrap()
        .to_string();
    for lxm in ["com.atproto.server.createAccount", "com.atproto.server.createaccount"] {
        let r = s.xrpc.get("com.atproto.server.getServiceAuth", &[("aud", pds.as_str()), ("lxm", lxm)], &app).await;
        r.err(400, "InvalidRequest");
        assert!(
            r.json["message"]
                .as_str()
                .unwrap()
                .contains("insufficient access to request a service auth token for the following method"),
            "{}",
            r.text()
        );
    }

    // no longer allows session refresh / creation after revocation
    s.xrpc.post("com.atproto.server.revokeAppPassword", &json!({"name": "test-pass"}), &a.auth()).await.ok();
    assert_err_msg(&refresh(&s, &app_refresh).await, 400, "ExpiredToken", "Token has been revoked");
    assert_err_msg(
        &s.create_session(&a.handle, &app_pass).await,
        401,
        "AuthenticationRequired",
        "Invalid identifier or password",
    );
}

async fn messages(s: &TestServer, email: &str) -> Vec<J> {
    s.dev_mail(email).await.ok()["messages"].as_array().cloned().unwrap_or_default()
}

/// email-confirmation.test.ts: the mails ("Email Confirmation" / "Confirm
/// your email", "Email Update Requested" / "Update your email") and the
/// in-use message.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ref_email_confirmation_and_update_mails() {
    let s = TestServer::spawn().await;
    let alice = s.create_account("alice").await;
    let bob = s.create_account("bob").await;

    s.xrpc.post_empty("com.atproto.server.requestEmailConfirmation", &alice.auth()).await.ok();
    let msgs = messages(&s, &alice.email).await;
    assert_eq!(msgs.len(), 1);
    let m = &msgs[0];
    assert_eq!(m["to"].as_str().unwrap().to_ascii_lowercase(), alice.email.to_ascii_lowercase());
    assert_eq!(m["subject"], json!("Email Confirmation"));
    assert!(m["html"].as_str().unwrap().contains("Confirm your email"), "{m}");
    let tok = m["token"].as_str().unwrap().to_string();
    s.xrpc
        .post("com.atproto.server.confirmEmail", &json!({"email": alice.email, "token": tok}), &alice.auth())
        .await
        .ok();

    let r = s.xrpc.post_empty("com.atproto.server.requestEmailUpdate", &alice.auth()).await.ok();
    assert_eq!(r["tokenRequired"], json!(true));
    let msgs = messages(&s, &alice.email).await;
    assert_eq!(msgs.len(), 2);
    let m = &msgs[1];
    assert_eq!(m["subject"], json!("Email Update Requested"));
    assert!(m["html"].as_str().unwrap().contains("Update your email"), "{m}");
    let tok = m["token"].as_str().unwrap().to_string();

    // fails email update with in-use email
    let r =
        s.xrpc.post("com.atproto.server.updateEmail", &json!({"email": bob.email, "token": tok}), &alice.auth()).await;
    assert_err_msg(&r, 400, "InvalidRequest", "This email address is already in use, please use a different email.");
    // a malformed address: the reference's "not supported" message
    let r = s
        .xrpc
        .post("com.atproto.server.updateEmail", &json!({"email": "not an email", "token": tok}), &alice.auth())
        .await;
    assert_err_msg(&r, 400, "InvalidRequest", "This email address is not supported, please use a different email.");
    // "fails email update with a badly formatted email": a disposable domain
    let r = s
        .xrpc
        .post(
            "com.atproto.server.updateEmail",
            &json!({"email": "bad-email@disposeamail.com", "token": tok}),
            &alice.auth(),
        )
        .await;
    assert_err_msg(&r, 400, "InvalidRequest", "This email address is not supported, please use a different email.");
}

/// rate-limits.test.ts: "rate limits by ip" (resetPassword: 50 per 5
/// minutes per IP), then "Rate Limit Exceeded".
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ref_rate_limits_by_ip() {
    let s = TestServer::spawn_with(|c| c.rate_limits_enabled = true).await;
    let body = json!({"token": "ABCD", "password": "asdf1234"});
    let attempt = || s.xrpc.post("com.atproto.server.resetPassword", &body, &Auth::None);
    for i in 0..50 {
        let r = attempt().await;
        assert_ne!(r.status, 429, "attempt {i}: {}", r.text());
    }
    assert_err_msg(&attempt().await, 429, "RateLimitExceeded", "Rate Limit Exceeded");
}
