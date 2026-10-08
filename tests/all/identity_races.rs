//! Identity fixes (DESIGN.md "PLC identity"): handles of other servers
//! resolved for clients (resolveHandle / resolveIdentity through the AppView
//! or the handle resolver), the createAccount service-auth issuer, races
//! on handle/email claims and on PLC updates, stale-claim takeover,
//! submitPlcOperation during a key rotation, signPlcOperation's token and
//! the directory-resolved document of a DID that can change elsewhere.

use crate::common::*;
use axum::extract::{Query, State};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use vlatproto::crypto::Keypair;
use vlpds::plc::mock::MockPlc;

/// An AppView stand-in answering resolveHandle from `handles` (400
/// "Unable to resolve handle" otherwise, 500 for `boom.*`), counting calls.
async fn stub_appview(handles: HashMap<String, String>) -> (String, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let st = (Arc::new(handles), calls.clone());
    type St = (Arc<HashMap<String, String>>, Arc<AtomicUsize>);
    let app = axum::Router::new()
        .route(
            "/xrpc/com.atproto.identity.resolveHandle",
            axum::routing::get(|State((h, n)): State<St>, Query(q): Query<HashMap<String, String>>| async move {
                n.fetch_add(1, Ordering::SeqCst);
                let handle = q.get("handle").cloned().unwrap_or_default();
                if handle.starts_with("boom.") {
                    return (
                        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                        axum::Json(json!({"error": "InternalServerError"})),
                    );
                }
                match h.get(&handle) {
                    Some(did) => (axum::http::StatusCode::OK, axum::Json(json!({"did": did}))),
                    None => (
                        axum::http::StatusCode::BAD_REQUEST,
                        axum::Json(json!({"error": "InvalidRequest", "message": "Unable to resolve handle"})),
                    ),
                }
            }),
        )
        .with_state(st);
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    (url, calls)
}

/// Registers a did:plc (rotation + `#atproto` key `key`, `#atproto_label`
/// key `label`) claiming `handle`.
async fn register(plc: &MockPlc, handle: &str, key: &Keypair, label: &Keypair) -> String {
    let op = json!({
        "type": "plc_operation",
        "rotationKeys": [key.did_key()],
        "verificationMethods": {"atproto": key.did_key(), "atproto_label": label.did_key()},
        "alsoKnownAs": [format!("at://{handle}")],
        "services": {"atproto_pds": {"type": "AtprotoPersonalDataServer", "endpoint": "https://elsewhere.test"}},
        "prev": null,
    });
    let op = vlpds::plc::sign(op, key).unwrap();
    let did = vlpds::plc::did_for_genesis(&op).unwrap();
    let r = reqwest::Client::new().post(format!("{}/{did}", plc.url)).json(&op).send().await.unwrap();
    assert!(r.status().is_success(), "{}", r.text().await.unwrap());
    did
}

async fn identity(s: &TestServer, ident: &str) -> Resp {
    s.xrpc.get("com.atproto.identity.resolveIdentity", &[("identifier", ident)], &Auth::None).await
}

/// The Bluesky app resolves @-mentions through its PDS: handles of other
/// servers resolve (AppView first, as the reference); ours only locally.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn external_handles_resolve_through_the_appview() {
    let plc = MockPlc::start().await;
    let (k, label) = (Keypair::generate(), Keypair::generate());
    let ext_did = register(&plc, "carol.elsewhere.test", &k, &label).await;
    let liar_did = register(&plc, "someone-else.elsewhere.test", &k, &label).await;
    let mut map = HashMap::new();
    map.insert("carol.elsewhere.test".to_string(), ext_did.clone());
    map.insert("liar.elsewhere.test".to_string(), liar_did.clone());
    let (av, calls) = stub_appview(map).await;
    let url = plc.url.clone();
    let s = TestServer::spawn_with(move |c| {
        c.plc_url = url;
        c.appview = Some((av, "did:web:appview.test".into()));
    })
    .await;
    let a = s.create_account("alice").await;

    assert_eq!(s.resolve_handle(&a.handle).await.ok()["did"], json!(a.did));
    // under our domain: never asked elsewhere
    s.resolve_handle(&format!("{}.{HANDLE_DOMAIN}", unique_name("nobody"))).await.err(400, "HandleNotFound");
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(s.resolve_handle("Carol.Elsewhere.Test").await.ok()["did"], json!(ext_did));
    s.resolve_handle("unknown.elsewhere.test").await.err(400, "HandleNotFound");
    // an AppView failure falls back to the resolver: none in dev mode
    s.resolve_handle("boom.elsewhere.test").await.err(400, "HandleNotFound");
    assert_eq!(calls.load(Ordering::SeqCst), 3);

    // resolveIdentity: by handle and by DID, for someone hosted elsewhere
    let j = identity(&s, "carol.elsewhere.test").await.ok();
    assert_eq!((j["did"].clone(), j["handle"].clone()), (json!(ext_did), json!("carol.elsewhere.test")), "{j}");
    assert_eq!(j["didDoc"]["id"], json!(ext_did));
    let j = identity(&s, &ext_did).await.ok();
    assert_eq!(j["handle"], json!("carol.elsewhere.test"), "{j}");
    // a handle whose DID's document names another handle doesn't resolve
    identity(&s, "liar.elsewhere.test").await.err(400, "HandleNotFound");
    // by DID: the document's handle doesn't resolve back -> handle.invalid
    let j = identity(&s, &liar_did).await.ok();
    assert_eq!(j["handle"], json!("handle.invalid"), "{j}");
    identity(&s, "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa").await.err(400, "DidNotFound");
    // local accounts as before
    let j = identity(&s, &a.handle).await.ok();
    assert_eq!((j["did"].clone(), j["handle"].clone()), (json!(a.did), json!(a.handle)));
    // refreshIdentity of someone elsewhere: the info, no event
    let r = s.xrpc.post("com.atproto.identity.refreshIdentity", &json!({"identifier": ext_did}), &a.auth()).await.ok();
    assert_eq!(r["did"], json!(ext_did));
}

/// Without an AppView (and outside dev mode) the handle resolver is asked:
/// DNS TXT here.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn external_handles_resolve_through_dns_without_an_appview() {
    #[derive(Default)]
    struct Txt(parking_lot::Mutex<HashMap<String, Vec<String>>>);
    impl vlpds::handle_resolver::TxtResolver for Txt {
        fn txt<'a>(&'a self, name: &'a str) -> futures::future::BoxFuture<'a, Result<Vec<String>, String>> {
            Box::pin(async move { self.0.lock().get(name).cloned().ok_or_else(|| "NXDOMAIN".to_string()) })
        }
    }
    let txt = Arc::new(Txt::default());
    txt.0.lock().insert("_atproto.dave.dns.test.".into(), vec!["did=did:plc:davedavedavedavedavedave".into()]);
    let r = vlpds::handle_resolver::TxtResolverRef(txt.clone());
    let s = TestServer::spawn_with(move |c| {
        c.dev_mode = false;
        c.txt_resolver = Some(r);
    })
    .await;
    assert_eq!(s.resolve_handle("dave.dns.test").await.ok()["did"], json!("did:plc:davedavedavedavedavedave"));
    s.resolve_handle("nobody.dns.test").await.err(400, "HandleNotFound");
}

/// createAccount with an existing DID needs service auth from the DID
/// itself: a `did#atproto_labeler` issuer (verified with the label key) is
/// a service of the DID, not its holder.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn create_account_refuses_a_fragment_issuer() {
    let plc = MockPlc::start().await;
    let (k, label) = (Keypair::generate(), Keypair::generate());
    let did = register(&plc, "mig.elsewhere.test", &k, &label).await;
    let url = plc.url.clone();
    let s = TestServer::spawn_with(move |c| c.plc_url = url).await;
    let aud = "did:web:localhost";
    let lxm = "com.atproto.server.createAccount";
    let body = |name: &str| {
        let h = format!("{}.{HANDLE_DOMAIN}", unique_name(name));
        json!({"handle": h, "email": format!("{h}@example.com"), "password": PASSWORD, "did": did})
    };
    let labeler = vlpds::auth::service_auth_jwt(&label, &format!("{did}#atproto_labeler"), aud, Some(lxm), 60).unwrap();
    let r = s.xrpc.post(lxm, &body("lab"), &Auth::Bearer(labeler)).await;
    r.err(401, "AuthenticationRequired");
    assert!(r.text().contains("Missing auth to create account with did"), "{}", r.text());
    assert!(s.app.account(&did).await.is_err(), "no account");
    // the DID itself (its #atproto key) may
    let own = vlpds::auth::service_auth_jwt(&k, &did, aud, Some(lxm), 60).unwrap();
    let j = s.xrpc.post(lxm, &body("own"), &Auth::Bearer(own)).await.ok();
    assert_eq!(j["did"], json!(did));
}

/// Two signups with one email at once: exactly one gets it (a claim held by
/// an account still being created is not stale).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_signups_with_one_email() {
    let s = Arc::new(TestServer::spawn().await);
    for _ in 0..5 {
        let email = format!("{}@example.com", unique_name("dup"));
        let mut tasks = Vec::new();
        for _ in 0..4 {
            let (s, email) = (s.clone(), email.clone());
            tasks.push(tokio::spawn(async move {
                let h = format!("{}.{HANDLE_DOMAIN}", unique_name("dup"));
                s.xrpc
                    .post(
                        "com.atproto.server.createAccount",
                        &json!({"handle": h, "email": email, "password": PASSWORD}),
                        &Auth::None,
                    )
                    .await
            }));
        }
        let mut ok = 0;
        for t in tasks {
            let r = t.await.unwrap();
            if r.is_ok() {
                ok += 1;
            } else {
                r.err(400, "InvalidRequest");
                assert!(r.text().contains("Email already taken"), "{}", r.text());
            }
        }
        assert_eq!(ok, 1, "exactly one signup gets {email}");
    }
}

/// Claims whose holder has no account (a deletion or release that didn't
/// finish) are taken over once older than the grace period; younger ones,
/// and ones whose holder stands on them, are not.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stale_claims_are_taken_over_after_the_grace_period() {
    let s = TestServer::spawn().await;
    let a = s.create_account("holder").await;
    let ghost = "did:plc:ghostghostghostghostghos";
    let handle = format!("{}.{HANDLE_DOMAIN}", unique_name("stale"));
    let email = format!("{}@example.com", unique_name("stale"));
    let put = |path: String| {
        let s = &s;
        async move {
            s.app.store.raw.put(&object_store::path::Path::from(path), ghost.as_bytes().to_vec().into()).await.unwrap()
        }
    };
    use object_store::ObjectStoreExt;
    use sha2::Digest;
    put(format!("{}/handle/{handle}", s.app.store.prefix)).await;
    put(format!("{}/email/{}", s.app.store.prefix, hex::encode(sha2::Sha256::digest(email.as_bytes())))).await;
    let body = json!({"handle": handle, "email": email, "password": PASSWORD});
    // young: still held
    s.xrpc.post("com.atproto.server.createAccount", &body, &Auth::None).await.err(400, "HandleNotAvailable");
    vlpds::xrpc::set_stale_claim_grace(&s.app, std::time::Duration::ZERO);
    // a live holder keeps its handle and email whatever their age
    let mut taken = body.clone();
    taken["handle"] = json!(a.handle);
    s.xrpc.post("com.atproto.server.createAccount", &taken, &Auth::None).await.err(400, "HandleNotAvailable");
    let mut taken =
        json!({"handle": format!("{}.{HANDLE_DOMAIN}", unique_name("other")), "email": a.email, "password": PASSWORD});
    s.xrpc.post("com.atproto.server.createAccount", &taken, &Auth::None).await.err(400, "InvalidRequest");
    // the ghost's are taken over
    let j = s.xrpc.post("com.atproto.server.createAccount", &body, &Auth::None).await.ok();
    assert_eq!(j["handle"], json!(handle));
    assert_eq!(s.resolve_handle(&handle).await.ok()["did"], j["did"]);
    taken["email"] = json!(email);
    s.xrpc.post("com.atproto.server.createAccount", &taken, &Auth::None).await.err(400, "InvalidRequest");
}

fn plc_handle(plc: &MockPlc, did: &str) -> String {
    plc.data(did).unwrap()["alsoKnownAs"][0].as_str().unwrap().trim_start_matches("at://").to_string()
}

/// Concurrent handle updates of one account: whichever wins, the account,
/// the directory and the claims agree afterwards.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_handle_updates_leave_plc_and_account_agreeing() {
    let plc = MockPlc::start().await;
    let s = Arc::new(TestServer::spawn_plc(&plc.url, Arc::new(Keypair::generate())).await);
    let a = Arc::new(s.create_account("race").await);
    for _ in 0..4 {
        let hs: Vec<String> = (0..3).map(|_| format!("{}.{HANDLE_DOMAIN}", unique_name("rh"))).collect();
        let mut tasks = Vec::new();
        for h in hs.clone() {
            let (s, a) = (s.clone(), a.clone());
            tasks.push(tokio::spawn(async move {
                s.xrpc.post("com.atproto.identity.updateHandle", &json!({"handle": h}), &a.auth()).await
            }));
        }
        for t in tasks {
            let r = t.await.unwrap();
            assert!(r.is_ok() || r.status == 400, "{}", r.text());
        }
        let local = s.app.account(&a.did).await.ok().unwrap().handle;
        assert_eq!(plc_handle(&plc, &a.did), local, "directory and account agree");
        for h in &hs {
            let r = s.resolve_handle(h).await;
            if *h == local {
                assert_eq!(r.ok()["did"], json!(a.did));
            } else {
                r.err(400, "HandleNotFound");
            }
        }
        assert_eq!(
            s.app.resolve_handle(&local).await.ok().unwrap().as_deref(),
            Some(a.did.as_str()),
            "the current handle's claim is held"
        );
    }
}

/// submitPlcOperation is refused while a signing-key rotation is pending
/// (its op would name the old key); a handle update racing the rotation's
/// PLC step is rebuilt on it, not a fork that aborts the rotation.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn plc_ops_during_a_key_rotation() {
    let plc = MockPlc::start().await;
    let rot = Arc::new(Keypair::generate());
    let s = TestServer::spawn_plc(&plc.url, rot.clone()).await;
    let a = s.create_account("rk").await;
    s.xrpc.post_empty("com.atproto.identity.requestPlcOperationSignature", &a.auth()).await.ok();
    let token = s.mail_token(&a.email).await.unwrap();
    let op = s.xrpc.post("com.atproto.identity.signPlcOperation", &json!({"token": token}), &a.auth()).await.ok()
        ["operation"]
        .clone();

    // a rotation stopped after its first step (pending)
    vlpds::xrpc::key_rotation::set_crash_hook(&a.did, Some(Arc::new(|p: &str| p == "begun")));
    let r = s.xrpc.post("com.atproto.admin.updateAccountSigningKey", &json!({"did": a.did}), &Auth::Admin).await;
    vlpds::xrpc::key_rotation::set_crash_hook(&a.did, None);
    assert!(!r.is_ok());
    assert!(s.app.account(&a.did).await.ok().unwrap().pending_signing_key.is_some());
    let r = s.xrpc.post("com.atproto.identity.submitPlcOperation", &json!({"operation": op}), &a.auth()).await;
    r.err(400, "InvalidRequest");
    assert!(r.text().contains("signing key rotation is in progress"), "{}", r.text());

    // the rotation's PLC update racing a handle update landing first
    let h = format!("{}.{HANDLE_DOMAIN}", unique_name("rk2"));
    let last = plc.last_op(&a.did).unwrap();
    let raced = vlpds::plc::Plc::new(&plc.url, rot.clone(), None)
        .update_op(&last, |m| {
            m.insert("alsoKnownAs".into(), json!([format!("at://{h}")]));
            Ok(())
        })
        .unwrap();
    plc.race_next_post(&a.did, raced);
    let pending = s.app.account(&a.did).await.ok().unwrap().pending_signing_key.unwrap();
    // a retry finishes the pending rotation
    let j = s.xrpc.post("com.atproto.admin.updateAccountSigningKey", &json!({"did": a.did}), &Auth::Admin).await.ok();
    assert_eq!(j["signingKey"], json!(format!("did:key:{}", pending.pubkey)));
    let acct = s.app.account(&a.did).await.ok().unwrap();
    assert!(acct.pending_signing_key.is_none());
    let data = plc.data(&a.did).unwrap();
    assert_eq!(data["verificationMethods"]["atproto"], json!(format!("did:key:{}", acct.signing_pubkey)));
    assert_eq!(data["alsoKnownAs"], json!([format!("at://{h}")]), "the racing op stays");
}

/// signPlcOperation consumes its token only once the op is made; the op it
/// hands out can be submitted by anyone, so from then on the DID's
/// document is the directory's, also while the account is active here.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn signed_ops_make_the_directory_authoritative() {
    let plc = MockPlc::start().await;
    let rot = Arc::new(Keypair::generate());
    let s = TestServer::spawn_plc(&plc.url, rot.clone()).await;
    let a = s.create_account("so").await;
    s.xrpc.post_empty("com.atproto.identity.requestPlcOperationSignature", &a.auth()).await.ok();
    let token = s.mail_token(&a.email).await.unwrap();
    let sign = |body: J| {
        let (s, a) = (&s, &a);
        async move { s.xrpc.post("com.atproto.identity.signPlcOperation", &body, &a.auth()).await }
    };
    plc.set_down(true);
    sign(json!({"token": token})).await.err(500, "InternalServerError");
    plc.set_down(false);
    let other = format!("{}.elsewhere.test", unique_name("moved"));
    let op = sign(json!({"token": token, "alsoKnownAs": [format!("at://{other}")]})).await.ok()["operation"].clone();
    sign(json!({"token": token})).await.err(400, "InvalidToken");
    // submitted elsewhere (a new PDS would), never seen here
    let r = reqwest::Client::new().post(format!("{}/{}", plc.url, a.did)).json(&op).send().await.unwrap();
    assert!(r.status().is_success());
    let doc =
        s.xrpc.get("com.atproto.identity.resolveDid", &[("did", &a.did)], &Auth::None).await.ok()["didDoc"].clone();
    assert_eq!(doc["alsoKnownAs"], json!([format!("at://{other}")]), "the directory's document");
    // the directory down: the local document rather than an error
    plc.set_down(true);
    let sess = s.get_session(&a.auth()).await.ok();
    assert_eq!(sess["did"], json!(a.did));
    plc.set_down(false);

    // an account with a user recovery key is the directory's from the start
    let h = format!("{}.{HANDLE_DOMAIN}", unique_name("rec"));
    let body = json!({"handle": h, "email": format!("{h}@example.com"), "password": PASSWORD, "recoveryKey": Keypair::generate().did_key()});
    let j = s.xrpc.post("com.atproto.server.createAccount", &body, &Auth::None).await.ok();
    let did = j["did"].as_str().unwrap();
    let acct = s.app.account(did).await.ok().unwrap();
    assert_eq!(acct.extra.get("plcExternalOps"), Some(&json!(true)));
}
