//! The console API's second round on the account side (src/xrpc/console.rs,
//! console_accounts.rs): filter counts kept in the totals rows through
//! status and factor changes and a restart, repo bytes and recountRepo,
//! cases by subject, identity keys, the operator's createAccount, session
//! IPs, and the lockout index across a restart.

use crate::common::*;
use std::sync::Arc;
use std::time::Duration;
use vlpds::plc::mock::MockPlc;

async fn admin_get(s: &TestServer, nsid: &str, q: &[(&str, &str)]) -> J {
    s.xrpc.get(nsid, q, &Auth::Admin).await.ok()
}

async fn on_store(store: &Arc<object_store::memory::InMemory>) -> TestServer {
    let raw = store.clone() as Arc<dyn object_store::ObjectStore>;
    TestServer::spawn_with(move |c| c.memory_store = Some(raw)).await
}

/// listAccounts' counts once they are exact.
async fn counts(s: &TestServer) -> J {
    let r = eventually(Duration::from_secs(20), || async {
        let r = admin_get(s, "vlpds.admin.listAccounts", &[("limit", "1")]).await;
        (r["counts"]["approximate"] == json!(false)).then(|| r["counts"].clone())
    })
    .await;
    r.expect("counts never settled")
}

fn pick(c: &J) -> [i64; 6] {
    ["total", "active", "deactivated", "takendown", "unconfirmed", "no2fa"].map(|k| c[k].as_i64().unwrap())
}

/// What a slot-order scan with each filter finds: the counts must match it.
async fn scanned(s: &TestServer) -> [i64; 6] {
    let n = |f: &'static str| async move {
        let r = admin_get(s, "vlpds.admin.listAccounts", &[("filter", f), ("sort", "slot"), ("limit", "200")]).await;
        r["accounts"].as_array().unwrap().len() as i64
    };
    let (all, deact, td, unconf, no2fa) =
        (n("all").await, n("deactivated").await, n("takendown").await, n("unconfirmed").await, n("no2fa").await);
    [all, all - deact - td, deact, td, unconf, no2fa]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn filter_counts_follow_changes_and_a_restart() {
    let store = Arc::new(object_store::memory::InMemory::new());
    let s = on_store(&store).await;
    let a = s.create_account("cnt").await;
    let b = s.create_account("cnt").await;
    let c = s.create_account("cnt").await;
    assert_eq!(pick(&counts(&s).await), [3, 3, 0, 0, 3, 3]);

    // a confirms its email and turns on TOTP; b is taken down; c deactivates
    let (tok, _, _) =
        mailed(&s, &a.email, s.xrpc.post_empty("com.atproto.server.requestEmailConfirmation", &a.auth())).await;
    s.xrpc.post("com.atproto.server.confirmEmail", &json!({"email": a.email, "token": tok}), &a.auth()).await.ok();
    s.enable_totp(&a).await;
    set_repo_takedown(&s, &b.did, true).await;
    s.xrpc.post("com.atproto.server.deactivateAccount", &json!({}), &c.auth()).await.ok();
    let want = [3, 1, 1, 1, 2, 0];
    assert_eq!(pick(&counts(&s).await), want);
    assert_eq!(scanned(&s).await, want, "the counts agree with the filters");

    // b back: active without a factor again
    set_repo_takedown(&s, &b.did, false).await;
    let want = [3, 2, 1, 0, 2, 1];

    assert_eq!(pick(&counts(&s).await), want);

    // a restart reads them back from the totals rows
    vlpds::server::shutdown(&s.app).await;
    drop(s);
    let s = on_store(&store).await;
    assert_eq!(pick(&counts(&s).await), want);
    assert_eq!(scanned(&s).await, want);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn repo_bytes_and_recount() {
    let s = TestServer::spawn().await;
    let a = s.create_account("rbytes").await;
    let mut posts = Vec::new();
    for i in 0..40 {
        posts.push(s.post(&a, &format!("post number {i} {}", "x".repeat(i * 7))).await);
    }
    let row = |r: J| r["accounts"][0].clone();
    let check = admin_get(&s, "vlpds.admin.checkRepo", &[("did", &a.did)]).await;
    let counted = &check["stats"]["counted"];
    let r = row(admin_get(&s, "vlpds.admin.listAccounts", &[("q", &a.did)]).await);
    // creates add their exact size
    assert_eq!(r["recordBytes"], counted["recordBytes"], "{r} {check}");
    assert!(r["mstBytes"].as_u64().unwrap() > 0, "{r}");
    assert_eq!(r["repoBytes"].as_u64(), Some(r["recordBytes"].as_u64().unwrap() + r["mstBytes"].as_u64().unwrap()));
    assert_eq!(check["ok"], true, "bytes kept close aren't a problem: {check}");

    // deletes take the mean: close, then exact after a recount
    for p in &posts[..15] {
        s.delete_record(&a, p.collection(), p.rkey()).await.ok();
    }
    let check = admin_get(&s, "vlpds.admin.checkRepo", &[("did", &a.did)]).await;
    let counted = check["stats"]["counted"].clone();
    let r = row(admin_get(&s, "vlpds.admin.listAccounts", &[("q", &a.did)]).await);
    let (kept, exact) = (
        r["repoBytes"].as_f64().unwrap(),
        (counted["recordBytes"].as_u64().unwrap() + counted["nodeBytes"].as_u64().unwrap()) as f64,
    );
    assert!((kept - exact).abs() / exact < 0.25, "kept {kept}, exact {exact}");
    let rc = s.xrpc.post("vlpds.admin.recountRepo", &json!({"did": a.did}), &Auth::Admin).await.ok();
    assert_eq!(rc["after"], counted, "{rc}");
    let r = row(admin_get(&s, "vlpds.admin.listAccounts", &[("q", &a.did)]).await);
    assert_eq!(
        (r["recordBytes"].clone(), r["mstBytes"].clone()),
        (counted["recordBytes"].clone(), counted["nodeBytes"].clone())
    );
    s.xrpc.post("vlpds.admin.recountRepo", &json!({"did": a.did}), &a.auth()).await.err(401, "AuthenticationRequired");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cases_by_subject() {
    let s = TestServer::spawn().await;
    let a = s.create_account("csub").await;
    let b = s.create_account("csub").await;
    let p = s.post(&a, "reported").await;
    let case = |subjects: J| {
        let s = &s;
        async move {
            let body = json!({"source": "a report", "subjects": subjects});
            s.xrpc.post("vlpds.admin.createCase", &body, &Auth::Admin).await.ok()["id"].as_str().unwrap().to_string()
        }
    };
    let c1 = case(json!([{"kind": "account", "did": a.did}])).await;
    let c2 = case(json!([{"kind": "record", "did": a.did, "uri": p.uri}])).await;
    let c3 = case(json!([{"kind": "account", "did": b.did}])).await;
    let ids = |r: J| {
        let mut v: Vec<String> =
            r["cases"].as_array().unwrap().iter().map(|c| c["id"].as_str().unwrap().into()).collect();
        v.sort();
        v
    };
    let mut want = vec![c1.clone(), c2.clone()];
    want.sort();
    assert_eq!(ids(admin_get(&s, "vlpds.admin.listCases", &[("did", &a.did)]).await), want);
    assert_eq!(ids(admin_get(&s, "vlpds.admin.listCases", &[("did", &a.did), ("subject", &p.uri)]).await), vec![c2]);
    assert_eq!(ids(admin_get(&s, "vlpds.admin.listCases", &[("did", &b.did)]).await), vec![c3]);
    assert_eq!(ids(admin_get(&s, "vlpds.admin.listCases", &[]).await).len(), 3);
    s.xrpc.get("vlpds.admin.listCases", &[("subject", &p.uri)], &Auth::Admin).await.err(400, "InvalidRequest");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn account_keys_from_the_did_doc_and_the_directory() {
    let plc = MockPlc::start().await;
    let rotation = Arc::new(vlpds::crypto::Keypair::generate());
    let s = TestServer::spawn_plc(&plc.url, rotation.clone()).await;
    let a = s.create_account("keys").await;
    let k = admin_get(&s, "vlpds.admin.getAccountKeys", &[("did", &a.did)]).await;
    let vm = k["verificationMethods"].as_array().expect("methods").clone();
    assert_eq!(vm.len(), 1, "{k}");
    assert_eq!(vm[0]["matchesAccount"], true, "{k}");
    assert_eq!(vm[0]["publicKeyMultibase"], k["signingKey"]);
    let rot = k["rotationKeys"].as_array().expect("rotation keys").clone();
    assert!(rot.iter().any(|r| r["didKey"] == rotation.did_key().as_str() && r["role"] == "server"), "{k}");
    let k = admin_get(&s, "vlpds.admin.getAccountKeys", &[("did", &a.did), ("refresh", "true")]).await;
    assert_eq!(k["verificationMethods"].as_array().unwrap().len(), 1);
    s.xrpc.get("vlpds.admin.getAccountKeys", &[("did", &a.did)], &a.auth()).await.err(401, "AuthenticationRequired");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn operator_creates_an_account_without_an_invite() {
    let s = TestServer::spawn_with(|c| c.invite_required = true).await;
    let handle = format!("{}.{HANDLE_DOMAIN}", unique_name("opc"));
    let body = json!({"handle": handle, "email": format!("{handle}@example.com"), "reason": "support ticket"});
    let r = s.xrpc.post("vlpds.admin.createAccount", &body, &Auth::Admin).await.ok();
    let password = r["password"].as_str().expect("a generated password").to_string();
    assert_eq!(password.len(), 24);
    assert!(r["did"].as_str().unwrap().starts_with("did:"));
    s.login(&handle, &password, None).await.ok();
    // the same handle again: as createAccount refuses it
    s.xrpc.post("vlpds.admin.createAccount", &body, &Auth::Admin).await.client_err();
    // a given password isn't echoed
    let h2 = format!("{}.{HANDLE_DOMAIN}", unique_name("opc"));
    let body = json!({"handle": h2, "email": format!("{h2}@example.com"), "password": "a-long-enough-password"});
    let r2 = s.xrpc.post("vlpds.admin.createAccount", &body, &Auth::Admin).await.ok();
    assert!(r2.get("password").is_none(), "{r2}");
    s.login(&h2, "a-long-enough-password", None).await.ok();
    let log = admin_get(&s, "vlpds.admin.getAuditLog", &[("did", r["did"].as_str().unwrap())]).await;
    let e =
        log["entries"].as_array().unwrap().iter().find(|e| e["action"] == "account.create").expect("audited").clone();
    assert_eq!(e["reason"], "support ticket", "{e}");
    assert!(!log.to_string().contains(&password), "the password isn't audited");
    // and without the admin token, nothing
    s.xrpc.post("vlpds.admin.createAccount", &body, &Auth::None).await.err(401, "AuthenticationRequired");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sessions_show_their_ip() {
    let s = TestServer::spawn().await;
    let a = s.create_account("sip").await;
    let refreshed = s.xrpc.post("com.atproto.server.refreshSession", &json!({}), &a.refresh_auth()).await.ok();
    assert!(refreshed["accessJwt"].is_string());
    let list = admin_get(&s, "vlpds.admin.listSessions", &[("did", &a.did)]).await;
    let ses = list["sessions"].as_array().unwrap();
    assert_eq!(ses.len(), 1, "{list}");
    assert_eq!(ses[0]["ip"], "127.0.0.1", "{list}");
    assert_eq!(ses[0]["signedInIp"], "127.0.0.1", "{list}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lockouts_survive_a_restart() {
    let store = Arc::new(object_store::memory::InMemory::new());
    let s = on_store(&store).await;
    let a = s.create_account("lkr").await;
    let (secret, step) = s.enable_totp(&a).await;
    let wrong = vlpds::totp::code_for_step(&secret, step + 1000);
    for _ in 1..vlpds::totp::MAX_FAILURES {
        s.login(&a.handle, &a.password, Some(&wrong)).await.client_err();
    }
    s.login(&a.handle, &a.password, Some(&wrong)).await.err(429, "RateLimitExceeded");
    let listed = |r: &J| r["lockouts"].as_array().unwrap().iter().any(|l| l["did"] == a.did.as_str());
    assert!(listed(&admin_get(&s, "vlpds.admin.listLockouts", &[]).await));

    vlpds::server::shutdown(&s.app).await;
    drop(s);
    let s = on_store(&store).await;
    let r = admin_get(&s, "vlpds.admin.listLockouts", &[]).await;
    assert!(listed(&r), "still listed after the restart: {r}");
    let attention =
        admin_get(&s, "vlpds.admin.listAccounts", &[("filter", "attention"), ("sort", "slot"), ("limit", "200")]).await;
    assert!(attention["accounts"].as_array().unwrap().iter().any(|x| x["did"] == a.did.as_str()), "{attention}");

    s.xrpc.post("vlpds.admin.clearLockout", &json!({"did": a.did, "reason": "verified"}), &Auth::Admin).await.ok();
    assert!(!listed(&admin_get(&s, "vlpds.admin.listLockouts", &[]).await));
    let p = s.app.partition(&a.did).ok().expect("owned here");
    for f in [vlpds::xrpc::mfa::FACTOR_LOCK, vlpds::xrpc::mfa::EMAIL_LOCK] {
        assert!(p.db.get(vlpds::state::lockout_key(&a.did, f)).await.unwrap().is_none(), "{f} index entry cleared");
    }
}

/// A passkey is a second factor for the no-2FA count: registering one takes
/// the account out of it, removing the last puts it back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn passkeys_move_the_no2fa_count() {
    use crate::common::webauthn::{register_passkey, SoftKey};
    let s = TestServer::spawn().await;
    let a = s.create_account("pkc").await;
    let before = counts(&s).await["no2fa"].as_i64().unwrap();
    let mut k = SoftKey::new(&s.url);
    register_passkey(&s, &a, &mut k, "phone").await;
    assert_eq!(counts(&s).await["no2fa"].as_i64().unwrap(), before - 1);
    let rm = json!({"id": k.id_b64(), "password": a.password});
    s.xrpc.post("vlpds.server.removePasskey", &rm, &a.auth()).await.ok();
    assert_eq!(counts(&s).await["no2fa"].as_i64().unwrap(), before);
}
