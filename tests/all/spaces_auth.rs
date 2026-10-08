//! Spaces read path and auth (`--spaces`; src/space/credcache.rs,
//! src/space/revocations.rs, src/xrpc/space.rs): the credential cache,
//! revocation through the control object, repo availability, record
//! takedowns, account deletion, listSpaces and listRecords paging.
//!
//! A did:web authority stub on loopback ([`Stub`]) stands in for a space
//! authority hosted elsewhere: it signs credentials and service auth with
//! its own key and records the notifies it gets.

use crate::common::spaces::{resp, signed_get_as, xrpc_url, Holder, SpaceClient};
use crate::common::*;
use axum::body::Body;
use axum::extract::Request;
use axum::response::Response;
use parking_lot::Mutex;
use std::sync::Arc;
use std::time::Duration;
use vlpds::space::token::{self, Mint, TokenType};

const TYPE: &str = "com.example.group";
const COLL: &str = "com.example.post";
const COLL2: &str = "com.example.reply";
const SCOPE: &str = "space:com.example.group?collection=com.example.post&collection=com.example.reply&action=read&action=create&manage=create";
const ANY_SCOPE: &str =
    "space:com.example.group?authority=*&collection=com.example.post&action=read&action=create&action=read_self";
const REVOKE: &str = "com.atproto.space.notifyCredentialRevoked";

fn rec(text: &str) -> J {
    json!({"$type": COLL, "text": text, "createdAt": "2026-10-01T00:00:00.000Z"})
}

fn now() -> i64 {
    vlatproto::tid::now_micros() as i64 / 1_000_000
}

async fn spawn() -> TestServer {
    TestServer::spawn_with(|c| c.spaces = true).await
}

fn scraped(text: &str, series: &str) -> f64 {
    text.lines().find_map(|l| l.strip_prefix(series).and_then(|v| v.trim().parse().ok())).unwrap_or(0.0)
}

async fn metric(s: &TestServer, series: &str) -> f64 {
    scraped(&reqwest::get(format!("{}/metrics", s.url)).await.unwrap().text().await.unwrap(), series)
}

fn spaces(s: &TestServer) -> &vlpds::space::Spaces {
    s.app.spaces.as_deref().unwrap()
}

async fn eventually<T>(within: Duration, mut f: impl FnMut() -> Option<T>) -> Option<T> {
    let deadline = tokio::time::Instant::now() + within;
    loop {
        if let Some(v) = f() {
            return Some(v);
        }
        if tokio::time::Instant::now() > deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// A did:web space authority on loopback: its `#atproto` key signs
/// credentials and service auth; its space host answers notifyWrite with
/// `status` and records each.
struct Stub {
    did: String,
    key: vlatproto::crypto::Keypair,
    notifies: Arc<Mutex<Vec<J>>>,
    status: Arc<Mutex<u16>>,
}

impl Stub {
    async fn new() -> Stub {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let (base, did) = (format!("http://{addr}"), format!("did:web:127.0.0.1%3A{}", addr.port()));
        let key = vlatproto::crypto::Keypair::generate();
        let doc = json!({
            "id": did,
            "verificationMethod": [{
                "id": format!("{did}#atproto"),
                "type": "Multikey",
                "controller": did,
                "publicKeyMultibase": key.public_multibase(),
            }],
            "service": [{"id": "#atproto_space_host", "type": "AtprotoSpaceHost", "serviceEndpoint": base}],
        });
        let notifies: Arc<Mutex<Vec<J>>> = Default::default();
        let status = Arc::new(Mutex::new(200u16));
        let (n, st) = (notifies.clone(), status.clone());
        let router = axum::Router::new().fallback(move |req: Request| {
            let (doc, n, st) = (doc.clone(), n.clone(), st.clone());
            async move {
                let json = |status: u16, body: J| {
                    Response::builder()
                        .status(status)
                        .header("content-type", "application/json")
                        .body(Body::from(body.to_string()))
                        .unwrap()
                };
                match req.uri().path() {
                    "/.well-known/did.json" => json(200, doc),
                    "/xrpc/com.atproto.space.notifyWrite" => {
                        let body = axum::body::to_bytes(req.into_body(), 1 << 20).await.unwrap();
                        n.lock().push(serde_json::from_slice(&body).unwrap());
                        let s = *st.lock();
                        json(s, if s == 200 { json!({}) } else { json!({"error": "Unavailable"}) })
                    }
                    _ => json(404, json!({"error": "NotFound"})),
                }
            }
        });
        tokio::spawn(async move { axum::serve(l, router).await.unwrap() });
        Stub { did, key, notifies, status }
    }

    fn space(&self, skey: &str) -> String {
        format!("at://{}/space/{TYPE}/{skey}", self.did)
    }

    /// A credential for `space` bound to `holder`, issued `age` seconds
    /// ago and good for `lifetime` from then.
    fn credential(&self, space: &str, holder: &Holder, jti: &str, age: i64, lifetime: i64) -> String {
        let m = Mint {
            iss: &self.did,
            sub: space,
            key_id: Some(&holder.did),
            expires_in_secs: Some(lifetime),
            ..Default::default()
        };
        token::encode(TokenType::Credential, &m, "ES256K", now() - age, jti, |b| {
            Ok::<_, std::convert::Infallible>(self.key.sign(b))
        })
        .unwrap()
    }

    fn service_jwt(&self, aud: &str, lxm: &str) -> String {
        vlpds::auth::service_auth_jwt(&self.key, &self.did, aud, Some(lxm), 60).unwrap()
    }
}

async fn revoke(s: &TestServer, jwt: &str, space: &str, jtis: &[&str]) -> Resp {
    s.xrpc.post(REVOKE, &json!({"space": space, "credentials": jtis}), &Auth::Bearer(jwt.into())).await
}

fn record_q<'a>(space: &'a str, repo: &'a str, rkey: &'a str) -> [(&'a str, &'a str); 4] {
    [("space", space), ("repo", repo), ("collection", COLL), ("rkey", rkey)]
}

/// One credential reads three times: one full verification, then cache
/// hits. A hit still checks the request's own signature.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn credential_cache_hits_still_check_signatures() {
    let s = spawn().await;
    let a = SpaceClient::new(&s, "sca", SCOPE).await;
    let space = a.create_space(TYPE, "main").await;
    a.create_record(&space, COLL, Some("r"), rec("x")).await.ok();
    let cred = a.credential(&space).await;
    let q = record_q(&space, &a.did, "r");
    let hits = metric(&s, "vlpds_space_credential_cache_total{result=\"hit\"}").await;
    assert!(spaces(&s).credentials.is_empty());
    for _ in 0..3 {
        a.signed_get(&s.url, "com.atproto.space.getRecord", &q, &cred, &a.did).await.ok();
    }
    assert_eq!(spaces(&s).credentials.len(), 1);
    let after = metric(&s, "vlpds_space_credential_cache_total{result=\"hit\"}").await;
    assert!(after - hits >= 2.0, "hits {hits} -> {after}");
    let get = xrpc_url(&s.url, "com.atproto.space.getRecord", &q);
    // cached, but signed by another key than the credential binds
    let r = signed_get_as(&a.srv.http, &Holder::new(), &s.url, "com.atproto.space.getRecord", &q, &cred, &a.did).await;
    r.err(401, "BadSpaceSignature");
    // cached, signed for one audience and sent with another
    let mut rb = a.srv.http.get(&get);
    for (k, v) in a.holder.headers(&format!("Atproto-Space {cred}"), Some(&a.did)) {
        let v = if k == "atproto-space-audience" { "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa".to_string() } else { v };
        rb = rb.header(k, v);
    }
    resp(rb.send().await.unwrap()).await.err(401, "BadSpaceSignature");
    // cached, properly signed for an audience that isn't the repo read
    let other = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";
    a.signed_get(&s.url, "com.atproto.space.getRecord", &q, &cred, other).await.err(401, "BadSpaceAudience");
    // and the credential still works as it was
    a.signed_get(&s.url, "com.atproto.space.getRecord", &q, &cred, &a.did).await.ok();
    assert!(metric(&s, "vlpds_space_credential_checks_total{result=\"audience\"}").await >= 1.0);
    assert!(metric(&s, "vlpds_space_credential_checks_total{result=\"bad_sig\"}").await >= 2.0);
}

/// A cached credential is never served past its expiry.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn expired_credential_falls_out_of_the_cache() {
    let stub = Stub::new().await;
    let s = spawn().await;
    let m = SpaceClient::new(&s, "sce", ANY_SCOPE).await;
    let space = stub.space("main");
    m.create_record(&space, COLL, Some("r"), rec("x")).await.ok();
    let holder = Holder::new();
    // the longest lifetime, issued just short of it ago: about 6 s left
    // (5 s of them clock skew)
    let cred = stub.credential(&space, &holder, "short", 3599, 3600);
    let q = record_q(&space, &m.did, "r");
    let read = || signed_get_as(&m.srv.http, &holder, &s.url, "com.atproto.space.getRecord", &q, &cred, &m.did);
    read().await.ok();
    assert_eq!(spaces(&s).credentials.len(), 1);
    tokio::time::sleep(Duration::from_secs(7)).await;
    read().await.err(401, "JwtExpired");
    assert!(spaces(&s).credentials.is_empty(), "dropped");
    // a credential that never verified is never cached
    let forged = format!("{}x", stub.credential(&space, &holder, "forged", 0, 600));
    signed_get_as(&m.srv.http, &holder, &s.url, "com.atproto.space.getRecord", &q, &forged, &m.did).await.client_err();
    assert!(spaces(&s).credentials.is_empty());
}

/// notifyCredentialRevoked: the authority revokes by jti, scoped to its
/// space, enforced at once on this node and after a restart; only the
/// space's authority may revoke, only to an account hosted here.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn revocation_is_durable_scoped_and_authorized() {
    let stub = Stub::new().await;
    let store: Arc<dyn object_store::ObjectStore> = Arc::new(object_store::memory::InMemory::new());
    let first = cluster_node("scr", store.clone(), 8, |c| c.spaces = true).await;
    let m = SpaceClient::new(&first, "scr", ANY_SCOPE).await;
    let (sp1, sp2) = (stub.space("one"), stub.space("two"));
    m.create_record(&sp1, COLL, Some("r"), rec("x")).await.ok();
    m.create_record(&sp2, COLL, Some("r"), rec("y")).await.ok();
    let holder = Holder::new();
    let c1 = stub.credential(&sp1, &holder, "j1", 0, 600);
    let c2 = stub.credential(&sp1, &holder, "j2", 0, 600);
    let c4 = stub.credential(&sp2, &holder, "j1", 0, 600);
    let read = |s: &TestServer, space: &str, cred: &str| {
        let (url, http, holder) = (s.url.clone(), m.srv.http.clone(), &holder);
        let (space, cred, did) = (space.to_string(), cred.to_string(), m.did.clone());
        async move {
            let q = record_q(&space, &did, "r");
            signed_get_as(&http, holder, &url, "com.atproto.space.getRecord", &q, &cred, &did).await
        }
    };
    read(&first, &sp1, &c1).await.ok();
    read(&first, &sp2, &c4).await.ok();
    assert_eq!(spaces(&first).credentials.len(), 2);

    // refused: not the space's authority, not addressed to an account here
    // (nor with a service fragment), another method, a bad body
    let other = Stub::new().await;
    revoke(&first, &other.service_jwt(&m.did, REVOKE), &sp1, &["j1"]).await.err(403, "Forbidden");
    revoke(&first, &stub.service_jwt("did:plc:aaaaaaaaaaaaaaaaaaaaaaaa", REVOKE), &sp1, &["j1"])
        .await
        .err(403, "Forbidden");
    let frag = format!("{}#atproto_space_host", m.did);
    revoke(&first, &stub.service_jwt(&frag, REVOKE), &sp1, &["j1"]).await.err(403, "Forbidden");
    let wrong_lxm = stub.service_jwt(&m.did, "com.atproto.space.notifyWrite");
    revoke(&first, &wrong_lxm, &sp1, &["j1"]).await.err(401, "BadJwtLexiconMethod");
    // naming the authority, signed by another key
    let forged = vlpds::auth::service_auth_jwt(&other.key, &stub.did, &m.did, Some(REVOKE), 60).unwrap();
    revoke(&first, &forged, &sp1, &["j1"]).await.err(401, "BadJwtSignature");
    let ok_jwt = stub.service_jwt(&m.did, REVOKE);
    revoke(&first, &ok_jwt, &sp1, &[]).await.err(400, "InvalidRequest");
    let many: Vec<String> = (0..101).map(|i| format!("j{i}")).collect();
    let many: Vec<&str> = many.iter().map(String::as_str).collect();
    revoke(&first, &ok_jwt, &sp1, &many).await.err(400, "InvalidRequest");
    read(&first, &sp1, &c1).await.ok();

    let revoked_before = metric(&first, "vlpds_space_credential_checks_total{result=\"revoked\"}").await;
    // three jtis, twice: idempotent
    revoke(&first, &ok_jwt, &sp1, &["j1", "j2", "j3"]).await.ok();
    revoke(&first, &stub.service_jwt(&m.did, REVOKE), &sp1, &["j1", "j2", "j3"]).await.ok();
    let now = now();
    assert!(spaces(&first).credentials.get(&vlpds::space::credcache::key(&c1), now).is_none(), "cache entry dropped");
    read(&first, &sp1, &c1).await.err(401, "CredentialRevoked");
    read(&first, &sp1, &c2).await.err(401, "CredentialRevoked");
    // the same jti in another space is another credential
    read(&first, &sp2, &c4).await.ok();
    assert_eq!(spaces(&first).revocations.len(), 3);
    assert!(metric(&first, "vlpds_space_credential_checks_total{result=\"revoked\"}").await >= revoked_before + 2.0);

    // a restart reads them back before it serves a credential
    vlpds::server::shutdown(&first.app).await;
    let second = cluster_node("scr", store.clone(), 8, |c| c.spaces = true).await;
    assert!(spaces(&second).revocations.loaded());
    read(&second, &sp1, &c1).await.err(401, "CredentialRevoked");
    read(&second, &sp1, &c2).await.err(401, "CredentialRevoked");
    read(&second, &sp2, &c4).await.ok();
}

/// Credential readers get RepoTakendown and RepoDeactivated; the owner
/// still reads its deactivated repo; writes are refused while inactive.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn availability_for_credential_readers() {
    let s = spawn().await;
    let a = SpaceClient::new(&s, "sva", SCOPE).await;
    let space = a.create_space(TYPE, "main").await;
    let b = SpaceClient::new(&s, "svb", ANY_SCOPE).await;
    b.create_record(&space, COLL, Some("r"), rec("x")).await.ok();
    let cred = a.credential(&space).await;
    let q = record_q(&space, &b.did, "r");
    let read = || a.signed_get(&s.url, "com.atproto.space.getRecord", &q, &cred, &b.did);
    read().await.ok();
    // a repo this host doesn't hold, and one the account never wrote:
    // the same answer
    let none = record_q(&space, "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa", "r");
    let aud = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";
    a.signed_get(&s.url, "com.atproto.space.getRecord", &none, &cred, aud).await.err(400, "RepoNotFound");
    let c = SpaceClient::new(&s, "svc", ANY_SCOPE).await;
    let lc = [("space", space.as_str()), ("repo", c.did.as_str())];
    a.signed_get(&s.url, "com.atproto.space.getLatestCommit", &lc, &cred, &c.did).await.err(400, "RepoNotFound");

    let lro = [("space", space.as_str()), ("repo", b.did.as_str())];
    let session = Auth::Bearer(b.session_jwt.clone());
    s.xrpc.post("com.atproto.server.deactivateAccount", &json!({}), &session).await.ok();
    read().await.err(400, "RepoDeactivated");
    a.signed_get(&s.url, "com.atproto.space.listRepoOps", &lro, &cred, &b.did).await.err(400, "RepoDeactivated");
    // the owner reads its own (to move it elsewhere), and writes nothing
    b.get("com.atproto.space.getRecord", &q).await.ok();
    b.get("com.atproto.space.getLatestCommit", &lro).await.ok();
    b.create_record(&space, COLL, Some("d"), rec("y")).await.err(401, "AccountDeactivated");
    s.xrpc.post_empty("com.atproto.server.activateAccount", &session).await.ok();
    read().await.ok();
    b.create_record(&space, COLL, Some("d"), rec("y")).await.ok();

    // (a takedown also revokes b's OAuth sessions, so it comes last)
    let takedown = |applied: bool| {
        let body = json!({"subject": repo_ref(&b.did), "takedown": {"applied": applied, "ref": "t1"}});
        let s = &s;
        async move { s.xrpc.post("com.atproto.admin.updateSubjectStatus", &body, &Auth::Admin).await.ok() }
    };
    takedown(true).await;
    read().await.err(400, "RepoTakendown");
    a.signed_get(&s.url, "com.atproto.space.listRepoOps", &lro, &cred, &b.did).await.err(400, "RepoTakendown");
    b.create_record(&space, COLL, Some("t"), rec("y")).await.client_err();
    takedown(false).await;
    read().await.ok();
}

/// A notify owed by an account that goes inactive waits, and goes as soon
/// as the account is active again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn outbox_waits_out_deactivation() {
    let stub = Stub::new().await;
    *stub.status.lock() = 503;
    let s = spawn().await;
    let m = SpaceClient::new(&s, "svo", ANY_SCOPE).await;
    let space = stub.space("main");
    m.create_record(&space, COLL, Some("r"), rec("x")).await.ok();
    assert!(eventually(Duration::from_secs(10), || (!stub.notifies.lock().is_empty()).then_some(())).await.is_some());
    let session = Auth::Bearer(m.session_jwt.clone());
    s.xrpc.post("com.atproto.server.deactivateAccount", &json!({}), &session).await.ok();
    *stub.status.lock() = 200;
    // due now, but the account is inactive: nothing is sent
    let sent = stub.notifies.lock().len();
    spaces(&s).outbox.resume(&m.did);
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(stub.notifies.lock().len(), sent);
    assert_eq!(spaces(&s).outbox.len(), 1, "the row waits");
    s.xrpc.post_empty("com.atproto.server.activateAccount", &session).await.ok();
    assert!(
        eventually(Duration::from_secs(5), || spaces(&s).outbox.is_empty().then_some(())).await.is_some(),
        "not delivered on reactivation"
    );
    assert!(stub.notifies.lock().len() > sent);
}

/// A taken-down space record is hidden from getRecord, listRecords and
/// listRepoOps, and the served commit is signed over the set without it
/// (spaces_sync::record_takedown_serves_a_consistent_view has the sync
/// side).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn record_takedown_hides_the_record() {
    let s = spawn().await;
    let a = SpaceClient::new(&s, "srt", SCOPE).await;
    let space = a.create_space(TYPE, "main").await;
    a.create_record(&space, COLL, Some("hidden"), rec("x")).await.ok();
    a.create_record(&space, COLL, Some("shown"), rec("y")).await.ok();
    let uri = format!("{space}/{}/{COLL}/hidden", a.did);
    let cred = a.credential(&space).await;
    let set = |applied: bool| {
        let body = json!({
            "subject": {"$type": "com.atproto.repo.strongRef", "uri": uri, "cid": "bafyreie5737gdxlw5i64vzichcalba3z2v5n6icifvx5xytvske7mr3hpm"},
            "takedown": {"applied": applied, "ref": "t"},
        });
        let s = &s;
        async move { s.xrpc.post("com.atproto.admin.updateSubjectStatus", &body, &Auth::Admin).await.ok() }
    };
    let q = record_q(&space, &a.did, "hidden");
    let lr = [("space", space.as_str()), ("repo", a.did.as_str())];
    let check = |hidden: bool| {
        let (a, s, cred, q, lr) = (&a, &s, &cred, q, lr);
        async move {
            let own = a.get("com.atproto.space.getRecord", &q).await;
            let viacred = a.signed_get(&s.url, "com.atproto.space.getRecord", &q, cred, &a.did).await;
            let list = a.signed_get(&s.url, "com.atproto.space.listRecords", &lr, cred, &a.did).await.ok();
            let ops = a.signed_get(&s.url, "com.atproto.space.listRepoOps", &lr, cred, &a.did).await.ok();
            let rkeys: Vec<&str> =
                list["records"].as_array().unwrap().iter().map(|r| r["rkey"].as_str().unwrap()).collect();
            let op = ops["ops"].as_array().unwrap().iter().find(|o| o["rkey"] == json!("hidden")).cloned();
            let shown = ops["ops"].as_array().unwrap().iter().find(|o| o["rkey"] == json!("shown")).unwrap();
            assert!(shown.get("value").is_some(), "{ops}");
            if hidden {
                own.err(400, "RecordNotFound");
                viacred.err(400, "RecordNotFound");
                assert_eq!(rkeys, ["shown"]);
                assert!(op.is_none(), "{ops}");
            } else {
                own.ok();
                viacred.ok();
                assert_eq!(rkeys, ["shown", "hidden"]);
                assert_eq!(op.unwrap()["value"]["text"], json!("x"));
            }
            ops["commit"]["hash"].clone()
        }
    };
    let before = check(false).await;
    set(true).await;
    let during = check(true).await;
    assert_ne!(before, during, "the served commit leaves the record out");
    set(false).await;
    assert_eq!(check(false).await, before);
}

async fn space_keys(s: &TestServer, did: &str) -> Vec<String> {
    let p = s.app.partition(did).ok().expect("local partition");
    let mut out = Vec::new();
    for fam in vlpds::state::SPACE_FAMILIES {
        let mut scan = vlpds::state::FamilyScan::new(p.db.as_ref(), fam, None, &Default::default()).await.unwrap();
        while let Some(kv) = scan.next().await.unwrap() {
            // an sL key names other authorities' DIDs in its URIs
            if fam == vlpds::state::SPACE_LIST_FAMILY {
                if vlsync_store::keys::key_body(&kv.key).starts_with(format!("sL/{did}\0").as_bytes()) {
                    out.push(String::from_utf8_lossy(vlsync_store::keys::key_body(&kv.key)).into_owned());
                }
                continue;
            }
            if vlpds::space::rows::did_sid(&kv.key).is_some_and(|(d, _)| d == did)
                || vlsync_store::keys::key_body(&kv.key).windows(did.len()).any(|w| w == did.as_bytes())
            {
                out.push(String::from_utf8_lossy(vlsync_store::keys::key_body(&kv.key)).into_owned());
            }
        }
    }
    out
}

/// deleteAccount leaves no Spaces row of the account: its repos in spaces
/// (its own and another's), the spaces it governs, its owed notifies.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delete_account_sweeps_every_space_family() {
    let stub = Stub::new().await;
    *stub.status.lock() = 503;
    let s = spawn().await;
    let a = SpaceClient::new(
        &s,
        "sdl",
        "space:com.example.group?authority=*&collection=com.example.post&action=read&action=create&manage=create",
    )
    .await;
    let b = SpaceClient::new(&s, "sdk", ANY_SCOPE).await;
    let mine = a.create_space(TYPE, "main").await;
    for i in 0..3 {
        a.create_record(&mine, COLL, Some(&format!("r{i}")), rec("x")).await.ok();
    }
    a.create_record(&stub.space("x"), COLL, Some("r"), rec("x")).await.ok();
    b.create_record(&mine, COLL, Some("b"), rec("b")).await.ok();
    let session = TestAccount {
        did: a.did.clone(),
        handle: a.handle.clone(),
        password: String::new(),
        email: String::new(),
        access: a.session_jwt.clone(),
        refresh: String::new(),
    };
    let blob = s.upload_blob(&session, &random_png(1), "image/png").await;
    let with_blob = json!({"$type": COLL, "text": "img", "img": blob, "createdAt": "2026-10-01T00:00:00.000Z"});
    a.create_record(&mine, COLL, Some("img"), with_blob.clone()).await.ok();
    a.create_record(&stub.space("x"), COLL, Some("img"), with_blob).await.ok();
    let keys = space_keys(&s, &a.did).await;
    for fam in ["sH/", "sR/", "sO/", "sS/", "sW/", "sQ/", "sP/", "sb/", "sc/", "sL/"] {
        assert!(keys.iter().any(|k| k.starts_with(fam)), "no {fam} row before: {keys:?}");
    }
    let b_keys = space_keys(&s, &b.did).await;
    s.xrpc.post("com.atproto.admin.deleteAccount", &json!({"did": a.did}), &Auth::Admin).await.ok();
    let keys = space_keys(&s, &a.did).await;
    assert!(keys.is_empty(), "left behind: {keys:?}");
    assert_eq!(space_keys(&s, &b.did).await, b_keys, "another account's rows stay");
    assert_eq!(spaces(&s).outbox.len(), 0, "nothing owed for a deleted account");
}

/// listSpaces: spaces written to and spaces governed, by URI, filtered by
/// type and authority; an unfiltered listing needs a wildcard grant.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn list_spaces_with_filters() {
    let stub = Stub::new().await;
    let s = spawn().await;
    let a = SpaceClient::new(
        &s,
        "sls",
        "space:*?authority=*&collection=com.example.post&action=read&action=create&manage=create",
    )
    .await;
    const OTHER: &str = "com.example.board";
    let one = a.create_space(TYPE, "one").await;
    let two = a.create_space(TYPE, "two").await;
    let three = a.create_space(OTHER, "three").await;
    a.create_record(&one, COLL, Some("r"), rec("x")).await.ok();
    let remote = stub.space("main");
    a.create_record(&remote, COLL, Some("r"), rec("x")).await.ok();
    let list = |q: Vec<(&'static str, String)>| {
        let a = &a;
        async move {
            let q: Vec<(&str, &str)> = q.iter().map(|(k, v)| (*k, v.as_str())).collect();
            a.get("com.atproto.space.listSpaces", &q).await
        }
    };
    let uris = |j: &J| {
        j["spaces"].as_array().unwrap().iter().map(|s| s["uri"].as_str().unwrap().to_string()).collect::<Vec<_>>()
    };
    let mut all = vec![one.clone(), two.clone(), three.clone(), remote.clone()];
    all.sort();
    let r = list(vec![]).await.ok();
    assert_eq!(uris(&r), all);
    assert!(r.get("cursor").is_none());
    assert_eq!(uris(&list(vec![("spaceType", OTHER.into())]).await.ok()), std::slice::from_ref(&three));
    assert_eq!(uris(&list(vec![("did", stub.did.clone())]).await.ok()), std::slice::from_ref(&remote));
    let mine = list(vec![("did", a.did.clone()), ("spaceType", TYPE.into())]).await.ok();
    assert_eq!(uris(&mine), [one.clone(), two.clone()]);
    // pages
    let p1 = list(vec![("limit", "3".into())]).await.ok();
    assert_eq!(uris(&p1), all[..3]);
    let p2 = list(vec![("limit", "3".into()), ("cursor", p1["cursor"].as_str().unwrap().into())]).await.ok();
    assert_eq!(uris(&p2), all[3..]);
    assert!(p2.get("cursor").is_none());
    list(vec![("spaceType", "not an nsid".into())]).await.err(400, "InvalidRequest");

    // a grant for one type and its own authority lists only that
    let g = SpaceClient::new(&s, "slg", "space:com.example.group?action=read_self&manage=create").await;
    g.get("com.atproto.space.listSpaces", &[]).await.err(403, "ScopeMissingError");
    g.get("com.atproto.space.listSpaces", &[("spaceType", TYPE)]).await.err(403, "ScopeMissingError");
    let gq = [("spaceType", TYPE), ("did", g.did.as_str())];
    assert!(uris(&g.get("com.atproto.space.listSpaces", &gq).await.ok()).is_empty());
    // legacy auth: nothing
    let session = Auth::Bearer(a.session_jwt.clone());
    s.xrpc.get("com.atproto.space.listSpaces", &[], &session).await.err(403, "InsufficientScope");
}

/// listSpaces under a one-type grant at any authority (the e2e harness's
/// app scope), checked the way the reference does: `spaceType ?? '*'` and
/// `did ?? '*'` are the target, so the grant's type must be named, and a
/// type it doesn't cover is refused rather than filtered to nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn list_spaces_one_type_grant() {
    let s = spawn().await;
    let app = "space:com.example.group?authority=*&collection=*&action=read&action=create&action=update&action=delete&manage=create&manage=update&manage=delete";
    let a = SpaceClient::new(&s, "slt", &format!("{app} blob:*/* repo:*")).await;
    let space = a.create_space(TYPE, "one").await;
    let uris = |j: &J| {
        j["spaces"].as_array().unwrap().iter().map(|s| s["uri"].as_str().unwrap().to_string()).collect::<Vec<_>>()
    };
    let wildcard = |r: Resp| {
        r.err(403, "ScopeMissingError");
        assert_eq!(r.json["message"], r#"Missing required scope "space:*?authority=*&action=read_self""#);
    };

    wildcard(a.get("com.atproto.space.listSpaces", &[]).await);
    let listed = a.get("com.atproto.space.listSpaces", &[("spaceType", TYPE)]).await.ok();
    assert_eq!(uris(&listed), std::slice::from_ref(&space));
    let mine = a.get("com.atproto.space.listSpaces", &[("spaceType", TYPE), ("did", &a.did)]).await.ok();
    assert_eq!(uris(&mine), std::slice::from_ref(&space));
    let other = a.get("com.atproto.space.listSpaces", &[("spaceType", "com.example.otherType")]).await;
    other.err(403, "ScopeMissingError");
    assert_eq!(
        other.json["message"],
        r#"Missing required scope "space:com.example.otherType?authority=*&action=read_self""#
    );

    // a grant for another type covers neither this type nor everything
    let b = SpaceClient::new(&s, "slu", "space:com.example.board?authority=*&action=read").await;
    wildcard(b.get("com.atproto.space.listSpaces", &[]).await);
    b.get("com.atproto.space.listSpaces", &[("spaceType", TYPE)]).await.err(403, "ScopeMissingError");
    assert!(uris(&b.get("com.atproto.space.listSpaces", &[("spaceType", "com.example.board")]).await.ok()).is_empty());

    // no space: grant at all
    let c = SpaceClient::new(&s, "slv", "blob:*/* repo:*").await;
    wildcard(c.get("com.atproto.space.listSpaces", &[]).await);
    c.get("com.atproto.space.listSpaces", &[("spaceType", TYPE)]).await.err(403, "ScopeMissingError");
}

/// listSpaces pages from its index (`sL`) and lists what the full scan did:
/// many spaces of two types at three authorities, held, governed or both
/// (listed once), deleted ones gone, under every filter and a small page.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn list_spaces_index_pages() {
    let (s1, s2) = (Stub::new().await, Stub::new().await);
    let s = spawn().await;
    let a = SpaceClient::new(
        &s,
        "sli",
        "space:*?authority=*&collection=com.example.post&action=read&action=create&manage=create&manage=delete",
    )
    .await;
    const OTHER: &str = "com.example.board";
    let mut want = std::collections::BTreeSet::new();
    for i in 0..12 {
        want.insert(a.create_space(TYPE, &format!("g{i:02}")).await);
        want.insert(a.create_space(OTHER, &format!("b{i:02}")).await);
    }
    let own = |t: &str, k: &str| format!("at://{}/space/{t}/{k}", a.did);
    for i in 0..4 {
        a.create_record(&own(TYPE, &format!("g{i:02}")), COLL, Some("r"), rec("x")).await.ok();
    }
    for (stub, n) in [(&s1, 5), (&s2, 3)] {
        for i in 0..n {
            let space = stub.space(&format!("x{i}"));
            a.create_record(&space, COLL, Some("r"), rec("x")).await.ok();
            want.insert(space);
        }
    }
    // a deleted space goes, whether the authority wrote in it or not
    for (t, k) in [(TYPE, "g01"), (TYPE, "g05"), (OTHER, "b07")] {
        a.post("com.atproto.simplespace.deleteSpace", json!({"space": own(t, k)})).await.ok();
        want.remove(&own(t, k));
    }
    assert_eq!(want.len(), 21 + 8);

    let filters: Vec<(Option<&str>, Option<&str>)> = vec![
        (None, None),
        (Some(TYPE), None),
        (Some(OTHER), None),
        (Some("com.example.none"), None),
        (None, Some(&a.did)),
        (None, Some(&s1.did)),
        (Some(TYPE), Some(&a.did)),
        (Some(OTHER), Some(&s2.did)),
        (Some(TYPE), Some(&s2.did)),
    ];
    for (t, d) in filters {
        let expect: Vec<String> = want
            .iter()
            .filter(|u| {
                let p: Vec<&str> = u.trim_start_matches("at://").split('/').collect();
                t.is_none_or(|t| p[2] == t) && d.is_none_or(|d| p[0] == d)
            })
            .cloned()
            .collect();
        for limit in [100, 5, 1] {
            let (mut got, mut cursor) = (Vec::new(), None::<String>);
            for _ in 0..100 {
                let mut q = vec![("limit", limit.to_string())];
                q.extend(t.map(|t| ("spaceType", t.to_string())));
                q.extend(d.map(|d| ("did", d.to_string())));
                q.extend(cursor.clone().map(|c| ("cursor", c)));
                let q: Vec<(&str, &str)> = q.iter().map(|(k, v)| (*k, v.as_str())).collect();
                let r = a.get("com.atproto.space.listSpaces", &q).await.ok();
                let page = r["spaces"].as_array().unwrap();
                assert!(page.len() <= limit, "{r}");
                got.extend(page.iter().map(|s| s["uri"].as_str().unwrap().to_string()));
                match r["cursor"].as_str() {
                    Some(c) => {
                        assert_eq!(page.len(), limit, "a cursor on a short page: {r}");
                        cursor = Some(c.to_string());
                    }
                    None => break,
                }
            }
            assert_eq!(got, expect, "spaceType {t:?}, did {d:?}, limit {limit}");
        }
    }
    // a cursor that isn't a listed URI pages from where it sorts
    let mid = own(OTHER, "b05x");
    let r = a.get("com.atproto.space.listSpaces", &[("cursor", mid.as_str())]).await.ok();
    let after: Vec<&String> = want.iter().filter(|u| **u > mid).take(50).collect();
    let got: Vec<&str> = r["spaces"].as_array().unwrap().iter().map(|s| s["uri"].as_str().unwrap()).collect();
    assert_eq!(got, after);
}

/// listRecords: newest URI first by default, `reverse` oldest first, a
/// `collection` filter, and a cursor that pages either way.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn list_records_paging() {
    let s = spawn().await;
    let a = SpaceClient::new(&s, "slr", SCOPE).await;
    let space = a.create_space(TYPE, "main").await;
    for i in 1..=5 {
        a.create_record(&space, COLL, Some(&format!("p{i}")), rec("x")).await.ok();
    }
    for i in 1..=2 {
        let r = json!({"$type": COLL2, "text": "re", "createdAt": "2026-10-01T00:00:00.000Z"});
        a.create_record(&space, COLL2, Some(&format!("q{i}")), r).await.ok();
    }
    let cred = a.credential(&space).await;
    let page = |extra: Vec<(&'static str, String)>| {
        let (a, s, cred, space) = (&a, &s, &cred, &space);
        async move {
            let mut q = vec![("space", space.clone()), ("repo", a.did.clone())];
            q.extend(extra);
            let q: Vec<(&str, &str)> = q.iter().map(|(k, v)| (*k, v.as_str())).collect();
            a.signed_get(&s.url, "com.atproto.space.listRecords", &q, cred, &a.did).await.ok()
        }
    };
    let walk = |extra: Vec<(&'static str, String)>| async move {
        let mut out = Vec::new();
        let mut cursor: Option<String> = None;
        for _ in 0..10 {
            let mut q = extra.clone();
            q.push(("limit", "2".into()));
            if let Some(c) = &cursor {
                q.push(("cursor", c.clone()));
            }
            let r = page(q).await;
            for rec in r["records"].as_array().unwrap() {
                out.push(format!("{}/{}", rec["collection"].as_str().unwrap(), rec["rkey"].as_str().unwrap()));
            }
            match r["cursor"].as_str() {
                Some(c) => cursor = Some(c.to_string()),
                None => return out,
            }
        }
        panic!("cursor never ends")
    };
    let mut asc: Vec<String> = (1..=5).map(|i| format!("{COLL}/p{i}")).collect();
    asc.extend((1..=2).map(|i| format!("{COLL2}/q{i}")));
    let desc: Vec<String> = asc.iter().rev().cloned().collect();
    assert_eq!(walk(vec![]).await, desc);
    assert_eq!(walk(vec![("reverse", "true".into())]).await, asc);
    assert_eq!(walk(vec![("collection", COLL2.into())]).await, desc[..2]);
    assert_eq!(walk(vec![("collection", COLL.into()), ("reverse", "true".into())]).await, asc[..5]);
    let first = page(vec![("limit", "1".into())]).await;
    assert_eq!(first["cursor"], json!(format!("{space}/{}/{COLL2}/q2", a.did)));
    let bare = page(vec![("excludeValues", "true".into())]).await;
    assert!(bare["records"].as_array().unwrap().iter().all(|r| r.get("value").is_none() && r["cid"].is_string()));
}

/// The revocations object stays bounded whoever notifies: jtis are checked,
/// a space with no stake here is answered 200 and nothing is stored, and
/// one past a cap blocks its space's credentials rather than leaving them
/// readable. A jti already revoked costs no rate-limit point, and the
/// account giving the stake has its own bucket. A node whose set has gone
/// stale refuses credentials until a read succeeds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn revocations_are_bounded_and_fail_closed() {
    let stub = Stub::new().await;
    let s = TestServer::spawn_with(|c| {
        c.spaces = true;
        c.rate_limits_enabled = true;
    })
    .await;
    let m = SpaceClient::new(&s, "scb", ANY_SCOPE).await;
    let (staked, loose, other) = (stub.space("staked"), stub.space("loose"), stub.space("other"));
    m.create_record(&staked, COLL, Some("r"), rec("x")).await.ok();
    m.create_record(&other, COLL, Some("r"), rec("y")).await.ok();
    let holder = Holder::new();
    let read = |space: &str, jti: &str| {
        let (url, http, holder) = (s.url.clone(), m.srv.http.clone(), &holder);
        let cred = stub.credential(space, holder, jti, 0, 600);
        let (space, did) = (space.to_string(), m.did.clone());
        async move {
            let q = record_q(&space, &did, "r");
            signed_get_as(&http, holder, &url, "com.atproto.space.getRecord", &q, &cred, &did).await
        }
    };
    let jwt = || stub.service_jwt(&m.did, REVOKE);
    let long = "a".repeat(vlpds::space::revocations::MAX_JTI_LEN + 1);
    for bad in ["a b", "", long.as_str()] {
        revoke(&s, &jwt(), &staked, &[bad]).await.err(400, "InvalidRequest");
    }
    // a credential whose jti no revocation could name is refused
    read(&staked, &long).await.err(401, "BadJwt");

    spaces(&s).revocations.set_caps(2, 100, 100, 100);
    // no stake: answered, never stored, however many
    for i in 0..20 {
        revoke(&s, &jwt(), &loose, &[&format!("l{i}")]).await.ok();
    }
    assert_eq!(spaces(&s).revocations.len(), 0);
    assert!(!spaces(&s).revocations.is_blocked(&loose, 0));
    revoke(&s, &jwt(), &staked, &["c", "d"]).await.ok();
    read(&staked, "c").await.err(401, "CredentialRevoked");
    read(&staked, "e").await.ok();
    revoke(&s, &jwt(), &staked, &["e"]).await.err(503, "Unavailable");
    read(&staked, "e").await.err(503, "Unavailable");
    assert_eq!(spaces(&s).revocations.len(), 2);
    read(&other, "q").await.ok();

    // only new jtis are charged: one point buys one, then repeats are free
    // (another authority, whose bucket nothing has spent yet)
    let limits = json!({"config": {"limiters": {"space-revoke": {"points": 1}, "space-revoke-aud": {"points": 7}}}, "ifVersion": 0, "actor": "it-test"});
    s.xrpc.post("vlpds.admin.updateRateLimits", &limits, &Auth::Admin).await.ok();
    spaces(&s).revocations.set_caps(100, 100, 100, 100);
    let second = Stub::new().await;
    let (sp2, jwt2) = (second.space("main"), || second.service_jwt(&m.did, REVOKE));
    m.create_record(&sp2, COLL, Some("r"), rec("z")).await.ok();
    for _ in 0..3 {
        revoke(&s, &jwt2(), &sp2, &["n1"]).await.ok();
    }
    revoke(&s, &jwt2(), &sp2, &["n2"]).await.err(429, "RateLimitExceeded");
    // the stake's account: 7 points, 4 spent above (c, d, the refused e,
    // n1); other authorities, with their own buckets, spend the rest
    for (i, name) in ["third", "fourth"].iter().enumerate() {
        let st = Stub::new().await;
        let sp = st.space(name);
        m.create_record(&sp, COLL, Some("r"), rec("z")).await.ok();
        revoke(&s, &st.service_jwt(&m.did, REVOKE), &sp, &[&format!("a{i}")]).await.ok();
    }
    let fifth = Stub::new().await;
    let sp5 = fifth.space("main");
    m.create_record(&sp5, COLL, Some("r"), rec("z")).await.ok();
    revoke(&s, &fifth.service_jwt(&m.did, REVOKE), &sp5, &["a8"]).await.ok();
    let sixth = Stub::new().await;
    let sp6 = sixth.space("main");
    m.create_record(&sp6, COLL, Some("r"), rec("z")).await.ok();
    revoke(&s, &sixth.service_jwt(&m.did, REVOKE), &sp6, &["a9"]).await.err(429, "RateLimitExceeded");
    // an exhausted stake bucket is a revocation not stored: the space is
    // blocked, not left readable
    assert!(spaces(&s).revocations.is_blocked(&sp6, crate::common::now_secs()));

    // stale: refused until a read succeeds
    spaces(&s).revocations.age_last_read(vlpds::space::revocations::STALE_AFTER);
    read(&other, "q").await.err(503, "Unavailable");
    spaces(&s).refresh_revocations(&s.app.store).await.unwrap();
    read(&other, "q").await.ok();
}

/// A flood of revocations from many authorities, unstaked or staked by one
/// account here, can't get a legitimate authority's revocation refused:
/// unstaked ones are answered and never stored, one account's stake is
/// capped, and the object stays bounded.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_revocation_flood_never_refuses_other_authorities() {
    let s = TestServer::spawn_with(|c| c.spaces = true).await;
    let (victim, attacker) =
        (SpaceClient::new(&s, "rfv", ANY_SCOPE).await, SpaceClient::new(&s, "rfa", ANY_SCOPE).await);
    let legit = Stub::new().await;
    let lsp = legit.space("main");
    victim.create_record(&lsp, COLL, Some("r"), rec("x")).await.ok();
    spaces(&s).revocations.set_caps(300, 100, 100, 150);
    let jtis = |p: &str, n: usize| (0..n).map(|i| format!("{p}{i}")).collect::<Vec<_>>();
    let mut stubs = Vec::new();
    for _ in 0..12 {
        stubs.push(Stub::new().await);
    }
    // unstaked: addressed to the victim, whose repo isn't in their spaces
    let floods = stubs.iter().map(|st| {
        let (s, sp, did) = (&s, st.space("x"), victim.did.clone());
        async move {
            let j = jtis("u", 100);
            let j: Vec<&str> = j.iter().map(String::as_str).collect();
            revoke(s, &st.service_jwt(&did, REVOKE), &sp, &j).await
        }
    });
    for r in futures::future::join_all(floods).await {
        r.ok();
    }
    assert_eq!(spaces(&s).revocations.len(), 0, "unstaked revocations are never stored");
    // staked by one account here, in each flooding authority's space
    for st in &stubs {
        attacker.create_record(&st.space("y"), COLL, Some("r"), rec("y")).await.ok();
    }
    let mut refused = 0;
    for st in &stubs {
        let j = jtis("s", 50);
        let j: Vec<&str> = j.iter().map(String::as_str).collect();
        let r = revoke(&s, &st.service_jwt(&attacker.did, REVOKE), &st.space("y"), &j).await;
        if r.status == 503 {
            refused += 1;
        } else {
            r.ok();
        }
    }
    assert!(refused > 0, "the account's stake is capped");
    assert!(spaces(&s).revocations.len() <= 150, "{}", spaces(&s).revocations.len());
    // the legitimate authority's revocation still goes in, and is enforced
    let j = jtis("legit", 20);
    let j: Vec<&str> = j.iter().map(String::as_str).collect();
    revoke(&s, &legit.service_jwt(&victim.did, REVOKE), &lsp, &j).await.ok();
    assert!(spaces(&s).revocations.is_revoked(&lsp, "legit0", 0));
    assert!(!spaces(&s).revocations.is_blocked(&lsp, 0));
}

/// An account here staking its own remote authorities' revocations past
/// every cap blocks their spaces, then those authorities, then every remote
/// authority, but never a local authority's spaces: their credentials keep
/// reading. The saturation shows on its metric.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn saturated_blocks_never_refuse_local_authorities() {
    use vlpds::space::revocations::BlockCaps;
    let s = spawn().await;
    let (local, attacker) = (SpaceClient::new(&s, "rsl", SCOPE).await, SpaceClient::new(&s, "rsa", ANY_SCOPE).await);
    let mine = local.create_space(TYPE, "main").await;
    local.create_record(&mine, COLL, Some("r"), rec("x")).await.ok();
    let cred = local.credential(&mine).await;
    let q = record_q(&mine, &local.did, "r");
    local.signed_get(&s.url, "com.atproto.space.getRecord", &q, &cred, &local.did).await.ok();
    let rv = &spaces(&s).revocations;
    rv.set_caps(1, 100, 100, 100);
    rv.set_block_caps(BlockCaps { per_authority: 2, spaces: 100, authorities: 2 });
    let first = Stub::new().await;
    let fill = first.space("fill");
    attacker.create_record(&fill, COLL, Some("r"), rec("f")).await.ok();
    revoke(&s, &first.service_jwt(&attacker.did, REVOKE), &fill, &["f"]).await.ok();
    // three remote authorities, three spaces each, every revocation refused
    let mut stubs = Vec::new();
    for _ in 0..3 {
        let st = Stub::new().await;
        for k in 0..3 {
            let sp = st.space(&format!("s{k}"));
            attacker.create_record(&sp, COLL, Some("r"), rec("y")).await.ok();
            revoke(&s, &st.service_jwt(&attacker.did, REVOKE), &sp, &["j"]).await.err(503, "Unavailable");
        }
        stubs.push(st);
    }
    // (what the saturated gauge reports; the gauge is process-wide, and
    // other tests' nodes set it too)
    assert!(rv.saturated(0));
    assert_eq!(rv.blocks(0), (0, 2));
    // a remote authority's credential is refused, even one never blocked
    let holder = Holder::new();
    let other = first.space("other");
    attacker.create_record(&other, COLL, Some("r"), rec("z")).await.ok();
    let rcred = first.credential(&other, &holder, "fresh", 0, 600);
    let rq = record_q(&other, &attacker.did, "r");
    signed_get_as(&attacker.srv.http, &holder, &s.url, "com.atproto.space.getRecord", &rq, &rcred, &attacker.did)
        .await
        .err(503, "Unavailable");
    // a local authority's spaces keep working
    local.signed_get(&s.url, "com.atproto.space.getRecord", &q, &cred, &local.did).await.ok();
    let fresh = local.credential(&mine).await;
    local.signed_get(&s.url, "com.atproto.space.getRecord", &q, &fresh, &local.did).await.ok();
}

/// A shard's `sP` rescan (what a takeover or a restart runs) sends what's
/// owed even past rows that don't decode: those are skipped, not the shard.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn outbox_rescan_skips_bad_rows() {
    let stub = Stub::new().await;
    *stub.status.lock() = 503;
    let s = spawn().await;
    let m = SpaceClient::new(&s, "svr", ANY_SCOPE).await;
    let space = stub.space("main");
    m.create_record(&space, COLL, Some("r"), rec("x")).await.ok();
    assert!(eventually(Duration::from_secs(10), || (!stub.notifies.lock().is_empty()).then_some(())).await.is_some());
    // as if the node that sent it went away: only the bucket remembers
    spaces(&s).outbox.drop_did(&m.did);
    let p = s.app.partition(&m.did).ok().expect("local partition");
    for sid in [[0u8; 16], [0xff; 16]] {
        p.db.put(vlpds::state::space_outbox_key(&m.did, &sid), b"not a row".to_vec()).await.unwrap();
    }
    *stub.status.lock() = 200;
    let sent = stub.notifies.lock().len();
    let table = Arc::downgrade(&s.app.partitions);
    s.app.spaces.clone().unwrap().spawn_outbox_rescan(table, vec![(p.id, p.db.clone())], false);
    assert!(
        eventually(Duration::from_secs(5), || (stub.notifies.lock().len() > sent).then_some(())).await.is_some(),
        "the owed notify wasn't resent"
    );
    let last = stub.notifies.lock().last().cloned().unwrap();
    assert_eq!(last["repo"], json!(m.did));
}
