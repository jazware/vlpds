//! Mail rate limits (src/ratelimit.rs "Mail"): each mailing endpoint's own
//! buckets, the per-recipient budget across mail kinds, the node budget,
//! and requestPasswordReset answering a limited request exactly like a
//! mailed one. The email sign-in code's resend de-dup is in email_2fa.rs.
use crate::common::*;
use std::sync::Arc;

fn set_limits(s: &TestServer, doc: J) {
    let d: vlpds::ratelimit::config::Doc = serde_json::from_value(doc).unwrap();
    s.app.ratelimit.install(vlpds::ratelimit::config::compile(Some(&d)).unwrap());
}

async fn limited() -> TestServer {
    TestServer::spawn_with(|c| c.rate_limits_enabled = true).await
}

/// Lifts the shared mail budgets so a test sees one endpoint's own buckets.
const ROOMY_MAIL: &str =
    r#"{"limiters": {"mail-recipient-hour": {"points": 1000}, "mail-recipient-day": {"points": 1000}}}"#;

fn mail_limited(r: &Resp) {
    r.err(429, "RateLimitExceeded");
    assert!(r.text().contains("Too many emails"), "{}", r.text());
}

async fn confirm(s: &TestServer, a: &TestAccount) {
    let (tok, _, _) =
        mailed(s, &a.email, s.xrpc.post_empty("com.atproto.server.requestEmailConfirmation", &a.auth())).await;
    s.xrpc.post("com.atproto.server.confirmEmail", &json!({"email": a.email, "token": tok}), &a.auth()).await.ok();
}

/// requestEmailConfirmation, requestEmailUpdate and requestAccountDelete:
/// 5 per hour per DID (the reference's values).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn each_account_mail_endpoint_has_its_limit() {
    let s = limited().await;
    set_limits(&s, serde_json::from_str(ROOMY_MAIL).unwrap());
    for nsid in [
        "com.atproto.server.requestEmailConfirmation",
        "com.atproto.server.requestEmailUpdate",
        "com.atproto.server.requestAccountDelete",
    ] {
        let a = s.create_account("mle").await;
        if nsid.ends_with("requestEmailUpdate") {
            // only a confirmed address is mailed an update token
            confirm(&s, &a).await;
        }
        for i in 0..5 {
            let (r, _) = mailed_n(&s, &a.email, 1, s.xrpc.post_empty(nsid, &a.auth())).await;
            assert_eq!(r.status, 200, "{nsid} #{i}: {}", r.text());
        }
        let (r, _) = mailed_n(&s, &a.email, 0, s.xrpc.post_empty(nsid, &a.auth())).await;
        r.err(429, "RateLimitExceeded");
        assert!(r.header("retry-after").is_some(), "{nsid}");
    }
}

/// Turning the email factor off without a token mails an update_email code
/// each time: it shares requestEmailUpdate's buckets (it used to have none).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn email_factor_disable_shares_the_email_update_limit() {
    let s = limited().await;
    set_limits(&s, serde_json::from_str(ROOMY_MAIL).unwrap());
    let a = s.create_account("mld").await;
    confirm(&s, &a).await;
    s.xrpc
        .post("com.atproto.server.updateEmail", &json!({"email": a.email, "emailAuthFactor": true}), &a.auth())
        .await
        .ok();
    let off = json!({"email": a.email, "emailAuthFactor": false});
    for _ in 0..5 {
        let (r, _) = mailed_n(&s, &a.email, 1, s.xrpc.post("com.atproto.server.updateEmail", &off, &a.auth())).await;
        r.err(400, "TokenRequired");
    }
    let (r, _) = mailed_n(&s, &a.email, 0, s.xrpc.post("com.atproto.server.updateEmail", &off, &a.auth())).await;
    r.err(429, "RateLimitExceeded");
    // and with requestEmailUpdate itself
    let (r, _) = mailed_n(&s, &a.email, 0, s.xrpc.post_empty("com.atproto.server.requestEmailUpdate", &a.auth())).await;
    r.err(429, "RateLimitExceeded");
}

/// The reference has no limit here; vlpds uses its siblings' 5/h, 15/day
/// per DID.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn plc_operation_signature_requests_are_limited() {
    let plc = vlpds::plc::mock::MockPlc::start().await;
    let rot = Arc::new(vlsync_atproto::crypto::Keypair::generate());
    let url = plc.url.clone();
    let s = TestServer::spawn_with(move |c| {
        use_plc(c, url, rot);
        c.rate_limits_enabled = true;
    })
    .await;
    set_limits(&s, serde_json::from_str(ROOMY_MAIL).unwrap());
    let a = s.create_account("mlp").await;
    for _ in 0..5 {
        let (r, _) = mailed_n(
            &s,
            &a.email,
            1,
            s.xrpc.post_empty("com.atproto.identity.requestPlcOperationSignature", &a.auth()),
        )
        .await;
        r.ok();
    }
    let (r, _) =
        mailed_n(&s, &a.email, 0, s.xrpc.post_empty("com.atproto.identity.requestPlcOperationSignature", &a.auth()))
            .await;
    r.err(429, "RateLimitExceeded");
    let top = s.app.ratelimit.snapshot("single", 10).top;
    assert!(top["com.atproto.identity.requestPlcOperationSignature-1"].iter().any(|c| c.key == a.did));
}

/// One budget per recipient across every mail kind; a refused request
/// doesn't replace the token last mailed; a DID override lifts it; the
/// rate-limit bypass key doesn't.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn recipient_budget_spans_mail_kinds() {
    let s = TestServer::spawn_with(|c| {
        c.rate_limits_enabled = true;
        c.rate_limit_bypass_key = Some("bypass-key".into());
    })
    .await;
    set_limits(&s, json!({"limiters": {"mail-recipient-hour": {"points": 4}}}));
    let a = s.create_account("mlr").await;
    let b = s.create_account("mlr").await;
    let post = |nsid: &'static str, who: &TestAccount| {
        let (s, auth) = (&s, who.auth());
        async move { s.xrpc.post_empty(nsid, &auth).await }
    };
    confirm(&s, &a).await;
    mailed(&s, &a.email, post("com.atproto.server.requestAccountDelete", &a)).await.1.ok();
    let (update_tok, r, _) = mailed(&s, &a.email, post("com.atproto.server.requestEmailUpdate", &a)).await;
    r.ok();
    let reset = json!({"email": a.email});
    mailed(&s, &a.email, s.xrpc.post("com.atproto.server.requestPasswordReset", &reset, &Auth::None)).await.1.ok();
    // the fifth mail of the hour, whatever its kind
    for nsid in ["com.atproto.server.requestEmailUpdate", "com.atproto.server.requestAccountDelete"] {
        let (r, _) = mailed_n(&s, &a.email, 0, post(nsid, &a)).await;
        mail_limited(&r);
    }
    // the bypass key lifts endpoint buckets, not the recipient's budget
    let rb = s
        .xrpc
        .http
        .post(format!("{}/xrpc/com.atproto.server.requestEmailConfirmation", s.url))
        .bearer_auth(&a.access)
        .header("x-ratelimit-bypass", "bypass-key");
    let (r, _) = mailed_n(&s, &a.email, 0, s.xrpc.send(rb)).await;
    mail_limited(&r);
    // another recipient has its own budget
    mailed(&s, &b.email, post("com.atproto.server.requestEmailConfirmation", &b)).await.1.ok();
    // an operator can lift one recipient's
    set_limits(
        &s,
        json!({
            "limiters": {"mail-recipient-hour": {"points": 4}},
            "overrides": [{"did": a.did, "limiters": ["mail-recipient-hour"], "exempt": true}],
        }),
    );
    mailed(&s, &a.email, post("com.atproto.server.requestAccountDelete", &a)).await.1.ok();
    // the update token mailed before the refusals still works
    let body = json!({"email": format!("new-{}", a.email), "token": update_tok});
    s.xrpc.post("com.atproto.server.updateEmail", &body, &a.auth()).await.ok();
}

/// Over its per-account or the recipient budget, requestPasswordReset
/// answers exactly as when it mails (status, body, headers) and mails
/// nothing; an unknown address answers the same way.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn password_reset_over_budget_answers_like_a_mailed_one() {
    let s = limited().await;
    let a = s.create_account("mlw").await;
    let reset = |email: String| {
        let s = &s;
        async move { s.xrpc.post("com.atproto.server.requestPasswordReset", &json!({"email": email}), &Auth::None).await }
    };
    let shape = |r: &Resp| {
        let mut names: Vec<String> = r
            .headers
            .keys()
            .map(|k| k.to_string())
            .filter(|k| k.starts_with("ratelimit") || k == "retry-after")
            .collect();
        names.sort();
        (r.status, r.text(), names, r.header("ratelimit-limit"), r.header("ratelimit-policy"))
    };
    let mut mailed_shape = None;
    for _ in 0..5 {
        let (r, _) = mailed_n(&s, &a.email, 1, reset(a.email.clone())).await;
        mailed_shape = Some(shape(&r));
    }
    let mailed_shape = mailed_shape.unwrap();
    assert_eq!(mailed_shape.0, 200);
    // password-reset-account-hour (5) is spent
    let (r, _) = mailed_n(&s, &a.email, 0, reset(a.email.clone())).await;
    assert_eq!(shape(&r), mailed_shape);
    // with per-account room again, the recipient budget (5 spent) stops it
    set_limits(
        &s,
        json!({"limiters": {"password-reset-account-hour": {"points": 100}, "mail-recipient-hour": {"points": 6}}}),
    );
    let (r, _) = mailed_n(&s, &a.email, 1, reset(a.email.clone())).await;
    assert_eq!(shape(&r), mailed_shape);
    let (r, _) = mailed_n(&s, &a.email, 0, reset(a.email.clone())).await;
    assert_eq!(shape(&r), mailed_shape);
    // the account's own requests over the budget get a clear 429
    let (r, _) =
        mailed_n(&s, &a.email, 0, s.xrpc.post_empty("com.atproto.server.requestEmailConfirmation", &a.auth())).await;
    mail_limited(&r);
    // unknown addresses answer like known ones (the reference errors instead)
    reset("nobody-mlw@example.com".into()).await.ok();
}

fn scraped(text: &str, series: &str) -> f64 {
    text.lines().find_map(|l| l.strip_prefix(series).and_then(|v| v.trim().parse().ok())).unwrap_or(0.0)
}

/// mail-node-hour caps everything the node mails; admin sendEmail is
/// exempt. Counted in vlpds_mail_suppressed_total{reason="node_limit"}.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn node_budget_caps_all_account_mail() {
    let s = limited().await;
    let series = r#"vlpds_mail_suppressed_total{purpose="confirm_email",reason="node_limit"}"#;
    let metric =
        || async { scraped(&reqwest::get(format!("{}/metrics", s.url)).await.unwrap().text().await.unwrap(), series) };
    let before = metric().await;
    let mut accts = Vec::new();
    for _ in 0..4 {
        accts.push(s.create_account("mln").await);
    }
    set_limits(&s, json!({"limiters": {"mail-node-hour": {"points": 3}}}));
    for a in &accts[..3] {
        mailed(&s, &a.email, s.xrpc.post_empty("com.atproto.server.requestEmailConfirmation", &a.auth())).await.1.ok();
    }
    let a = &accts[3];
    let (r, _) =
        mailed_n(&s, &a.email, 0, s.xrpc.post_empty("com.atproto.server.requestEmailConfirmation", &a.auth())).await;
    mail_limited(&r);
    assert!(metric().await > before, "{series} moved");
    // reset requests over it are answered as mailed
    let (r, _) = mailed_n(
        &s,
        &a.email,
        0,
        s.xrpc.post("com.atproto.server.requestPasswordReset", &json!({"email": a.email}), &Auth::None),
    )
    .await;
    r.ok();
    // moderation mail still goes out
    let body = json!({"recipientDid": a.did, "content": "<p>hello</p>", "senderDid": "did:example:mod"});
    let (r, _) = mailed_n(&s, &a.email, 1, s.xrpc.post("com.atproto.admin.sendEmail", &body, &Auth::Admin)).await;
    r.ok();
}

/// An email sign-in over the recipient budget is refused 429 (not
/// AuthFactorTokenRequired for a code that never comes); a code already
/// mailed still signs in.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn email_sign_in_code_over_budget() {
    let s = limited().await;
    let a = s.create_account("mls").await;
    confirm(&s, &a).await;
    s.xrpc
        .post("com.atproto.server.updateEmail", &json!({"email": a.email, "emailAuthFactor": true}), &a.auth())
        .await
        .ok();
    // one mail (the confirmation) spent; one more allowed
    set_limits(&s, json!({"limiters": {"mail-recipient-hour": {"points": 2}}}));
    let (code, r, _) = mailed(&s, &a.email, s.login(&a.handle, &a.password, None)).await;
    r.err(401, "AuthFactorTokenRequired");
    age_email_token(&s, &a.did, "auth_factor", 61_000).await;
    let (r, _) = mailed_n(&s, &a.email, 0, s.login(&a.handle, &a.password, None)).await;
    mail_limited(&r);
    s.login(&a.handle, &a.password, Some(&code)).await.ok();
}
