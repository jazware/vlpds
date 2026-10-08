//! Sign-in security on createSession (src/xrpc/signin.rs): new-device
//! alerts (once per device, opt-outs, the daily cap), the recent-sign-ins
//! log, browsers trusted to skip the second factor (expiry, revocation,
//! cleared by a password change or a 2FA change), the OAuth-only switch, and
//! a forwarded sign-in recorded once. The OAuth page's side is in oauth.rs.

use crate::common::*;
use std::sync::Arc;

const ALERT: &str = "sign_in_alert";

/// A process-wide counter: other tests move it too, so check growth.
fn count(v: &prometheus::IntCounterVec, labels: &[&str]) -> u64 {
    v.with_label_values(labels).get()
}

/// A createSession as a client would send it: `ua` as its User-Agent,
/// `own` as this server's account page (same-origin fetch metadata), with
/// the browser's device `cookie`.
struct Login<'a> {
    ua: &'a str,
    own: bool,
    cookie: Option<&'a str>,
    code: Option<&'a str>,
    trust: bool,
}

impl Default for Login<'_> {
    fn default() -> Self {
        Login { ua: "test-client/1.0", own: false, cookie: None, code: None, trust: false }
    }
}

async fn login(s: &TestServer, ident: &str, password: &str, l: Login<'_>) -> Resp {
    let mut body = json!({"identifier": ident, "password": password});
    if let Some(c) = l.code {
        body["authFactorToken"] = json!(c);
    }
    if l.trust {
        body["trustDevice"] = json!(true);
    }
    let mut rb = s
        .xrpc
        .http
        .post(format!("{}/xrpc/com.atproto.server.createSession", s.url))
        .header("user-agent", l.ua)
        .json(&body);
    if l.own {
        rb = rb.header("sec-fetch-site", "same-origin");
    }
    if let Some(c) = l.cookie {
        rb = rb.header("cookie", c);
    }
    s.xrpc.send(rb).await
}

/// From this server's account page.
fn own(cookie: Option<&str>) -> Login<'_> {
    Login { own: true, cookie, ..Default::default() }
}

fn device_cookie(r: &Resp) -> String {
    let sc = r.header("set-cookie").unwrap_or_else(|| panic!("no device cookie: {r:?}"));
    let c = sc.split(';').next().unwrap().to_string();
    assert!(c.starts_with("vlpds-device=dev-"), "{sc}");
    c
}

async fn security(s: &TestServer, a: &TestAccount) -> J {
    s.xrpc.get("vlpds.server.getSignInSecurity", &[], &a.auth()).await.ok()
}

async fn update(s: &TestServer, a: &TestAccount, body: J) -> Resp {
    s.xrpc.post("vlpds.server.updateSignInSecurity", &body, &a.auth()).await
}

/// TOTP on; returns (secret, the step its confirmation spent, recovery codes).
async fn enable_totp(s: &TestServer, a: &TestAccount) -> (Vec<u8>, u64, Vec<String>) {
    let setup = s.xrpc.post_empty("vlpds.server.setupTotp", &a.auth()).await.ok();
    let secret = vlpds::totp::base32_decode(setup["secret"].as_str().unwrap()).unwrap();
    let step = vlpds::totp::step_at(vlpds::totp::now_secs());
    let code = vlpds::totp::code_for_step(&secret, step);
    let r = s.xrpc.post("vlpds.server.confirmTotp", &json!({"code": code}), &a.auth()).await.ok();
    let codes = r["recoveryCodes"].as_array().unwrap().iter().map(|c| c.as_str().unwrap().to_string()).collect();
    (secret, step, codes)
}

fn alerts(ms: &[J]) -> Vec<J> {
    ms.iter().filter(|m| m["purpose"] == ALERT).cloned().collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn alerts_once_per_new_device_with_opt_outs_and_a_daily_cap() {
    use vlpds::metrics::SIGN_IN_ALERTS as M;
    let before: Vec<u64> = ["baseline", "mailed", "muted", "account_limit"].map(|r| count(&M, &[r])).into();
    let s = TestServer::spawn().await;
    let a = s.create_account("alert").await;
    let pw = a.password.clone();
    let go = |ua: &'static str| login(&s, &a.handle, &pw, Login { ua, ..Default::default() });
    // the first recorded sign-in is the baseline, and a known device is quiet
    mailed_n(&s, &a.email, 0, go("ua-a")).await.0.ok();
    mailed_n(&s, &a.email, 0, go("ua-a")).await.0.ok();
    // a new device: one alert, and only once
    let (r, m) = mailed_n(&s, &a.email, 1, go("ua-b")).await;
    r.ok();
    let m = m.unwrap();
    assert_eq!(m["purpose"], json!(ALERT));
    assert_eq!(m["subject"], json!("New Sign-in to Your Account"));
    assert!(m["token"].is_null(), "{m}");
    let body = m["body"].as_str().unwrap();
    assert!(
        body.contains(&format!("@{}", a.handle)) && body.contains("ua-b") && body.contains("with your password"),
        "{body}"
    );
    assert!(body.contains("127.0.0.1"), "{body}");
    mailed_n(&s, &a.email, 0, go("ua-b")).await.0.ok();

    // an app password from a known device is quiet, from a new one it alerts
    let ap = s.xrpc.post("com.atproto.server.createAppPassword", &json!({"name": "phone"}), &a.auth()).await.ok()
        ["password"]
        .as_str()
        .unwrap()
        .to_string();
    let app = |ua: &'static str| login(&s, &a.handle, &ap, Login { ua, ..Default::default() });
    mailed_n(&s, &a.email, 0, app("ua-a")).await.0.ok();
    let (_, m) = mailed_n(&s, &a.email, 1, app("ua-g")).await;
    assert!(m.unwrap()["body"].as_str().unwrap().contains("app password \u{201c}phone\u{201d}"));

    // opting out of password alerts
    update(&s, &a, json!({"alerts": {"password": false}})).await.ok();
    assert_eq!(security(&s, &a).await["alerts"], json!({"password": false, "appPassword": true}));
    mailed_n(&s, &a.email, 0, go("ua-c")).await.0.ok();
    // ... app password alerts are their own switch
    update(&s, &a, json!({"alerts": {"password": true, "appPassword": false}})).await.ok();
    mailed_n(&s, &a.email, 0, app("ua-h")).await.0.ok();

    // the third alert of the day is the last
    mailed_n(&s, &a.email, 1, go("ua-d")).await.0.ok();
    assert_eq!(vlpds::xrpc::ALERTS_PER_DAY, 3);
    mailed_n(&s, &a.email, 0, go("ua-e")).await.0.ok();
    assert_eq!(alerts(&mails(&s, &a.email).await).len(), 3);

    // every sign-in is in the log, newest first, with its method
    let st = security(&s, &a).await;
    let recent = st["recentSignIns"].as_array().unwrap();
    assert_eq!(recent.len(), 10, "{st}");
    let e = &recent[0];
    assert_eq!(
        (e["method"].as_str(), e["newDevice"].as_bool(), e["alerted"].as_bool()),
        (Some("password"), Some(true), Some(false))
    );
    assert_eq!(e["ip"], json!("127.0.0.1"));
    let h = recent.iter().find(|e| e["userAgent"] == "ua-h").unwrap();
    assert_eq!((h["method"].as_str(), h["appPassword"].as_str()), (Some("app_password"), Some("phone")));
    let alerted: Vec<&str> =
        recent.iter().filter(|e| e["alerted"] == true).map(|e| e["userAgent"].as_str().unwrap()).collect();
    assert_eq!(alerted, ["ua-d", "ua-g", "ua-b"]);
    for ((r, n), b) in [("baseline", 1), ("mailed", 3), ("muted", 2), ("account_limit", 1)].iter().zip(before) {
        assert!(count(&M, &[r]) >= b + n, "vlpds_sign_in_alerts_total{{result={r}}} grew by {n}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn trusted_browser_on_the_account_page() {
    use vlpds::metrics::{SIGN_IN_FACTORS, TRUSTED_BROWSERS};
    let skipped = count(&SIGN_IN_FACTORS, &["password", "trusted"]);
    let granted = count(&TRUSTED_BROWSERS, &["granted"]);
    let revoked = count(&TRUSTED_BROWSERS, &["revoked"]);
    let s = TestServer::spawn().await;
    let a = s.create_account("trust").await;
    let (secret, step, recovery) = enable_totp(&s, &a).await;
    let pw = a.password.clone();

    // a code plus "trust this browser": the response sets the device cookie
    let next = vlpds::totp::code_for_step(&secret, step + 1);
    let r = login(&s, &a.handle, &pw, Login { code: Some(&next), trust: true, ..own(None) }).await;
    r.ok();
    let b1 = device_cookie(&r);
    // that browser skips the code; the code is still asked for elsewhere
    login(&s, &a.handle, &pw, own(Some(&b1))).await.ok();
    login(&s, &a.handle, &pw, own(None)).await.err(401, "AuthFactorTokenRequired");
    // the cookie only counts on this server's own pages
    login(&s, &a.handle, &pw, Login { cookie: Some(&b1), ..Default::default() })
        .await
        .err(401, "AuthFactorTokenRequired");
    // a second browser, trusted with a recovery code
    let r = login(&s, &a.handle, &pw, Login { code: Some(&recovery[0]), trust: true, ..own(None) }).await;
    r.ok();
    let b2 = device_cookie(&r);
    assert_ne!(b1, b2);
    login(&s, &a.handle, &pw, own(Some(&b2))).await.ok();

    // listed, with this browser marked; the log names the factor
    let st = s
        .xrpc
        .send(
            s.xrpc
                .http
                .get(format!("{}/xrpc/vlpds.server.getSignInSecurity", s.url))
                .bearer_auth(&a.access)
                .header("cookie", &b1),
        )
        .await
        .ok();
    let browsers = st["trustedBrowsers"].as_array().unwrap();
    assert_eq!(browsers.len(), 2, "{st}");
    let first = browsers.iter().find(|b| b["current"] == true).expect("this browser");
    assert_eq!(st["trustDays"], json!(30));
    let factors: Vec<&str> =
        st["recentSignIns"].as_array().unwrap().iter().filter_map(|e| e["factor"].as_str()).collect();
    assert_eq!(factors, ["trusted", "totp", "trusted", "totp"]);
    assert!(count(&SIGN_IN_FACTORS, &["password", "trusted"]) >= skipped + 2);
    assert!(count(&TRUSTED_BROWSERS, &["granted"]) >= granted + 2);

    // revoke one: only that browser is asked again
    let id = first["id"].as_str().unwrap();
    s.xrpc.post("vlpds.server.revokeTrustedBrowser", &json!({"id": id}), &a.auth()).await.ok();
    login(&s, &a.handle, &pw, own(Some(&b1))).await.err(401, "AuthFactorTokenRequired");
    login(&s, &a.handle, &pw, own(Some(&b2))).await.ok();
    // revoke all
    s.xrpc.post("vlpds.server.revokeTrustedBrowser", &json!({"all": true}), &a.auth()).await.ok();
    login(&s, &a.handle, &pw, own(Some(&b2))).await.err(401, "AuthFactorTokenRequired");
    assert_eq!(security(&s, &a).await["trustedBrowsers"], json!([]));
    assert!(count(&TRUSTED_BROWSERS, &["revoked"]) >= revoked + 2);

    // expiry: a trust past its end is ignored
    let r = login(&s, &a.handle, &pw, Login { code: Some(&recovery[1]), trust: true, ..own(Some(&b2)) }).await;
    r.ok();
    login(&s, &a.handle, &pw, own(Some(&b2))).await.ok();
    let id = security(&s, &a).await["trustedBrowsers"][0]["id"].as_str().unwrap().to_string();
    let name = format!("trust/{id}");
    let raw = s.app.get_private(&a.did, &name).await.ok().flatten().expect("trust row");
    let mut t: J = serde_json::from_slice(&raw).unwrap();
    t["expiresAt"] = json!(now_secs() - 1);
    put_row(&s, &a.did, &name, &t).await;
    login(&s, &a.handle, &pw, own(Some(&b2))).await.err(401, "AuthFactorTokenRequired");
    assert_eq!(security(&s, &a).await["trustedBrowsers"], json!([]));

    // a password change clears every trust
    let r = login(&s, &a.handle, &pw, Login { code: Some(&recovery[2]), trust: true, ..own(Some(&b2)) }).await;
    r.ok();
    login(&s, &a.handle, &pw, own(Some(&b2))).await.ok();
    s.xrpc
        .post(
            "com.atproto.admin.updateAccountPassword",
            &json!({"did": a.did, "password": "new-password-1"}),
            &Auth::Admin,
        )
        .await
        .ok();
    login(&s, &a.handle, "new-password-1", own(Some(&b2))).await.err(401, "AuthFactorTokenRequired");
    assert!(s.app.get_private(&a.did, &name).await.ok().flatten().is_none(), "trust row survived the revoke-all");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_2fa_change_clears_trust() {
    let s = TestServer::spawn().await;
    let a = s.create_account("trust2fa").await;
    let (_, _, recovery) = enable_totp(&s, &a).await;
    let pw = a.password.clone();
    let r = login(&s, &a.handle, &pw, Login { own: true, code: Some(&recovery[0]), trust: true, ..Default::default() })
        .await;
    r.ok();
    let b = device_cookie(&r);
    login(&s, &a.handle, &pw, Login { own: true, cookie: Some(&b), ..Default::default() }).await.ok();
    // TOTP off, then on again with a new secret
    s.xrpc
        .post("vlpds.server.disableTotp", &json!({"password": pw, "recoveryCode": recovery[1]}), &a.auth())
        .await
        .ok();
    enable_totp(&s, &a).await;
    login(&s, &a.handle, &pw, Login { own: true, cookie: Some(&b), ..Default::default() })
        .await
        .err(401, "AuthFactorTokenRequired");
    assert_eq!(security(&s, &a).await["trustedBrowsers"], json!([]));
}

async fn put_row(s: &TestServer, did: &str, name: &str, v: &J) {
    s.app
        .put_private(
            did,
            vec![vlsync_store::segment::Mutation {
                key: vlpds::state::private_key(did, name).into(),
                val: Some(serde_json::to_vec(v).unwrap().into()),
            }],
        )
        .await
        .unwrap_or_else(|e| panic!("put_private: {}", e.message));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn oauth_only_refuses_the_main_password() {
    use vlpds::metrics::{LOGINS, SIGN_IN_SETTINGS};
    let refused = count(&LOGINS, &["password", "oauth_required"]);
    let blocked = count(&LOGINS, &["app_password", "app_passwords_blocked"]);
    let (on, off) = (count(&SIGN_IN_SETTINGS, &["oauth_only", "on"]), count(&SIGN_IN_SETTINGS, &["oauth_only", "off"]));
    let s = TestServer::spawn().await;
    let a = s.create_account("oauthonly").await;
    let pw = a.password.clone();
    // offered only with a second factor
    update(&s, &a, json!({"oauthOnly": true})).await.err(400, "InvalidRequest");
    let (secret, step, _) = enable_totp(&s, &a).await;
    let ap = s.xrpc.post("com.atproto.server.createAppPassword", &json!({"name": "bot"}), &a.auth()).await.ok()
        ["password"]
        .as_str()
        .unwrap()
        .to_string();
    update(&s, &a, json!({"oauthOnly": true})).await.ok();
    assert_eq!(security(&s, &a).await["oauthOnly"], json!(true));

    // the main password is refused before any code is asked for, with a
    // message clients show as it is
    let r = login(&s, &a.handle, &pw, Login::default()).await;
    r.err(401, "OAuthRequired");
    let msg = r.json["message"].as_str().unwrap();
    assert!(!msg.contains("Authentication Required") && !msg.contains("Invalid identifier or password"), "{msg}");
    let code = vlpds::totp::code_for_step(&secret, step + 1);
    login(&s, &a.handle, &pw, Login { code: Some(&code), ..Default::default() }).await.err(401, "OAuthRequired");
    // a wrong password still says so
    login(&s, &a.handle, "wrong", Login::default()).await.err(401, "AuthenticationRequired");
    // app passwords work
    login(&s, &a.handle, &ap, Login::default()).await.ok();
    // the account page still signs in, with the second factor
    login(&s, &a.handle, &pw, Login { own: true, ..Default::default() }).await.err(401, "AuthFactorTokenRequired");
    login(&s, &a.handle, &pw, Login { own: true, code: Some(&code), ..Default::default() }).await.ok();

    // blocking app passwords too
    update(&s, &a, json!({"blockAppPasswords": true})).await.ok();
    login(&s, &a.handle, &ap, Login::default()).await.err(401, "AppPasswordsBlocked");
    update(&s, &a, json!({"oauthOnly": false, "blockAppPasswords": false})).await.ok();
    login(&s, &a.handle, &ap, Login::default()).await.ok();
    login(&s, &a.handle, &pw, Login::default()).await.err(401, "AuthFactorTokenRequired");
    assert!(count(&LOGINS, &["password", "oauth_required"]) >= refused + 2);
    assert!(count(&LOGINS, &["app_password", "app_passwords_blocked"]) > blocked);
    assert!(count(&SIGN_IN_SETTINGS, &["oauth_only", "on"]) > on);
    assert!(count(&SIGN_IN_SETTINGS, &["oauth_only", "off"]) > off);
}

/// createSession reaching a node that doesn't own the account is forwarded
/// to the owner, which records it once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forwarded_sign_in_is_recorded_once() {
    let store = Arc::new(object_store::memory::InMemory::new());
    let n1 = cluster_node("sis-a", store.clone(), 8, |_| {}).await;
    let n2 = cluster_node("sis-b", store.clone(), 8, |_| {}).await;
    balanced(&[&n1, &n2]).await;
    let a = n1.create_account("fwd").await;
    let owner = owner_of(&[&n1, &n2], &a.did);
    let other = if std::ptr::eq(owner, &n1) { &n2 } else { &n1 };
    login(other, &a.handle, &a.password, Login::default()).await.ok();
    login(other, &a.handle, &a.password, Login { ua: "other-ua", ..Default::default() }).await.ok();
    let st = security(other, &a).await;
    let recent = st["recentSignIns"].as_array().unwrap();
    assert_eq!(recent.len(), 2, "{st}");
    assert!(recent.iter().all(|e| e["ip"] == "127.0.0.1"), "{st}");
    // the alert went out once, from the owner
    let sent = alerts(&mails(owner, &a.email).await).len() + alerts(&mails(other, &a.email).await).len();
    assert_eq!(sent, 1);
}
