//! Outbound email over Cloudflare Email Sending's REST API (src/mail.rs)
//! against an in-test HTTP server: a password reset arrives as one JSON
//! POST with the bearer token, the from address's display name, the token
//! in the text and HTML parts; admin sendEmail can use an API moderation
//! mailer; 429 and 5xx are retried, other 4xx are not.
use crate::common::*;
use parking_lot::Mutex;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use vlpds::mail::{ApiConfig, QueueMailer, SharedMailer, MAIL_MESSAGES, MAIL_RETRIES};
use vlpds::xrpc::{Mail, Mailer};

const PATH: &str = "/client/v4/accounts/acct123/email/sending/send";

#[derive(Debug)]
struct Received {
    auth: String,
    content_type: String,
    body: J,
}

/// Answers each POST with the next scripted (status, body), then with
/// Cloudflare's success shape. Every request, scripted or not, is counted.
async fn fake_api(script: &[(u16, J)]) -> (String, mpsc::UnboundedReceiver<Received>, Arc<Mutex<usize>>) {
    use axum::http::{HeaderMap, StatusCode};
    let (tx, rx) = mpsc::unbounded_channel();
    let script = Arc::new(Mutex::new(script.iter().cloned().collect::<VecDeque<_>>()));
    let hits = Arc::new(Mutex::new(0usize));
    let seen = hits.clone();
    let app = axum::Router::new().route(
        PATH,
        axum::routing::post(move |h: HeaderMap, axum::Json(body): axum::Json<J>| {
            let (tx, script, seen) = (tx.clone(), script.clone(), seen.clone());
            async move {
                *seen.lock() += 1;
                if let Some((status, b)) = script.lock().pop_front() {
                    return (StatusCode::from_u16(status).unwrap(), axum::Json(b));
                }
                let header = |k: &str| h.get(k).and_then(|v| v.to_str().ok()).unwrap_or_default().to_string();
                let to = body["to"].clone();
                let _ = tx.send(Received { auth: header("authorization"), content_type: header("content-type"), body });
                (
                    StatusCode::OK,
                    axum::Json(json!({
                        "success": true, "errors": [], "messages": [],
                        "result": {"delivered": [to], "permanent_bounces": [], "queued": []}
                    })),
                )
            }
        }),
    );
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}{PATH}", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    (url, rx, hits)
}

fn cfg(url: &str, from: &str) -> ApiConfig {
    ApiConfig { backoff: vec![Duration::from_millis(20); 3], ..ApiConfig::new(url, "test-token", from) }
}

fn mail(purpose: &str, to: &str) -> Mail {
    Mail {
        to: to.into(),
        subject: "Test".into(),
        body: "code ABCDE-12345".into(),
        html: None,
        purpose: purpose.into(),
        token: Some("ABCDE-12345".into()),
        sent_at: String::new(),
    }
}

async fn next_with_subject(rx: &mut mpsc::UnboundedReceiver<Received>, subject: &str) -> Received {
    loop {
        let r = tokio::time::timeout(Duration::from_secs(20), rx.recv())
            .await
            .expect("no mail within 20 s")
            .expect("api server stopped");
        if r.body["subject"] == subject {
            return r;
        }
    }
}

fn count(result: &str, purpose: &str) -> u64 {
    MAIL_MESSAGES.with_label_values(&[result, purpose]).get()
}

async fn wait_count(result: &str, purpose: &str, n: u64) {
    for _ in 0..250 {
        if count(result, purpose) >= n {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("{result}/{purpose} counter not bumped");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn password_reset_is_mailed_over_the_api() {
    let (url, mut rx, _) = fake_api(&[]).await;
    let mailer = QueueMailer::start_api(cfg(&url, "vlpds <noreply@vlpds.test>")).unwrap();
    let s = TestServer::spawn_with(|c| c.mailer = Some(SharedMailer(Arc::new(mailer)))).await;
    let a = s.create_account("apimail").await;

    s.xrpc.post("com.atproto.server.requestPasswordReset", &json!({"email": a.email}), &Auth::None).await.ok();
    let r = next_with_subject(&mut rx, "Password Reset Requested").await;
    assert_eq!(r.auth, "Bearer test-token");
    assert!(r.content_type.starts_with("application/json"), "{}", r.content_type);
    assert_eq!(r.body["from"], json!({"address": "noreply@vlpds.test", "name": "vlpds"}));
    assert_eq!(r.body["to"], json!(a.email.to_ascii_lowercase()));
    let token = s.mail_token(&a.email).await.expect("dev mailbox token");
    let text = r.body["text"].as_str().unwrap();
    let html = r.body["html"].as_str().unwrap();
    assert!(text.contains(&format!("\n{token}\n")), "token {token} not in text: {text}");
    assert!(html.contains(&format!(">{token}</code>")), "token {token} not in html: {html}");
    assert!(r.body.get("headers").is_none(), "{}", r.body);
    wait_count("sent", "reset_password", 1).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn admin_send_email_uses_an_api_moderation_mailer() {
    let (url, mut rx, _) = fake_api(&[]).await;
    let modm = QueueMailer::start_api(cfg(&url, "Moderation <moderation@vlpds.test>")).unwrap();
    let s = TestServer::spawn_with(|c| c.moderation_mailer = Some(SharedMailer(Arc::new(modm)))).await;
    let a = s.create_account("apimod").await;
    let html = "<p>Your post was <b>removed</b>.</p>";
    let r = s
        .xrpc
        .post(
            "com.atproto.admin.sendEmail",
            &json!({"recipientDid": a.did, "content": html, "subject": "Moderation notice", "senderDid": "did:plc:admin"}),
            &Auth::Admin,
        )
        .await
        .ok();
    assert_eq!(r["sent"], json!(true));
    let m = next_with_subject(&mut rx, "Moderation notice").await;
    assert_eq!(m.body["from"], json!({"address": "moderation@vlpds.test", "name": "Moderation"}));
    assert_eq!(m.body["html"], json!(html));
    assert_eq!(m.body["text"], json!("Your post was removed."));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn throttling_and_5xx_are_retried() {
    let (url, mut rx, hits) = fake_api(&[
        (429, json!({"success": false, "errors": [{"code": 10004, "message": "email.sending.error.throttled"}]})),
        (503, json!({"success": false, "errors": [{"code": 10100, "message": "email.sending.error.authentication.upstream"}]})),
    ])
    .await;
    let m = QueueMailer::start_api(cfg(&url, "noreply@vlpds.test")).unwrap();
    let retries = MAIL_RETRIES.get();
    m.send(&mail("test_api_transient", "bob@example.com"));
    let r = next_with_subject(&mut rx, "Test").await;
    assert_eq!(r.body["to"], json!("bob@example.com"));
    assert_eq!(r.body["text"], json!("code ABCDE-12345"));
    assert_eq!(*hits.lock(), 3);
    assert!(MAIL_RETRIES.get() >= retries + 2);
    wait_count("sent", "test_api_transient", 1).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_errors_are_not_retried() {
    let (url, _rx, hits) = fake_api(&[(
        403,
        json!({"success": false, "errors": [{"code": 10102, "message": "email.sending.error.authentication.forbidden"}]}),
    )])
    .await;
    let m = QueueMailer::start_api(cfg(&url, "noreply@vlpds.test")).unwrap();
    m.send(&mail("test_api_permanent", "carol@example.com"));
    wait_count("failed", "test_api_permanent", 1).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(*hits.lock(), 1, "a 403 must not be retried");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bounced_recipient_is_a_failure() {
    let (url, _rx, hits) = fake_api(&[(
        200,
        json!({"success": true, "errors": [], "result": {"delivered": [], "permanent_bounces": ["dan@example.com"], "queued": []}}),
    )])
    .await;
    let m = QueueMailer::start_api(cfg(&url, "noreply@vlpds.test")).unwrap();
    m.send(&mail("test_api_bounce", "dan@example.com"));
    wait_count("failed", "test_api_bounce", 1).await;
    assert_eq!(*hits.lock(), 1);
}
