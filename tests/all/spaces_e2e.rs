//! Spaces end to end on one node (`--spaces`; src/space, src/xrpc/space.rs):
//! an OAuth account writes into a space it governs and reads it back as
//! itself and through a space credential; listRepoOps replays to the
//! commit's hash and polls at the head from memory; every way a credential
//! read can be wrong is refused on its own terms; legacy auth gets nothing;
//! and a write into a space governed elsewhere reaches its authority
//! through the durable outbox, across a restart.

use crate::common::spaces::{resp, signed_get_as, xrpc_url, Holder, SpaceClient};
use crate::common::*;
use axum::body::Body;
use axum::extract::Request;
use axum::response::Response;
use base64::Engine;
use parking_lot::Mutex;
use std::sync::Arc;
use std::time::Duration;
use vlpds::space::{commit, lthash::LtHash};

const TYPE: &str = "com.example.group";
const COLL: &str = "com.example.post";

fn rec(text: &str) -> J {
    json!({"$type": COLL, "text": text, "createdAt": "2026-10-01T00:00:00.000Z"})
}

fn bytes(v: &J) -> Vec<u8> {
    let s = v["$bytes"].as_str().unwrap_or_else(|| panic!("not $bytes: {v}"));
    base64::engine::general_purpose::STANDARD_NO_PAD.decode(s.trim_end_matches('=')).unwrap()
}

fn signed_commit(c: &J) -> commit::Commit {
    commit::Commit {
        ver: c["ver"].as_i64().unwrap(),
        hash: bytes(&c["data"]),
        ikm: bytes(&c["ikm"]),
        sig: bytes(&c["sig"]),
        mac: bytes(&c["mac"]),
        rev: c["rev"].as_str().unwrap().to_string(),
    }
}

/// The account's `#atproto` key as a did:key.
async fn did_key(s: &TestServer, did: &str) -> String {
    let j = s.xrpc.get("com.atproto.repo.describeRepo", &[("repo", did)], &Auth::None).await.ok();
    let vm = j["didDoc"]["verificationMethod"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["id"].as_str().is_some_and(|i| i.ends_with("#atproto")))
        .unwrap()
        .clone();
    format!("did:key:{}", vm["publicKeyMultibase"].as_str().unwrap())
}

/// Applies listRepoOps ops to a running set hash, as a syncer does.
fn apply_ops(set: &mut LtHash, ops: &J) {
    for op in ops.as_array().unwrap() {
        let (c, r) = (op["collection"].as_str().unwrap(), op["rkey"].as_str().unwrap());
        if let Some(p) = op["prev"].as_str() {
            set.remove(&commit::element(c, r, p));
        }
        if let Some(n) = op["cid"].as_str() {
            set.add(&commit::element(c, r, n));
        }
    }
}

/// The commit verifies against the author's key and describes `set`.
fn check_commit(c: &J, space: &str, author: &str, key: &str, set: &LtHash) {
    let sc = signed_commit(c);
    let ctx = commit::CommitCtx { space, author, rev: &sc.rev };
    assert!(commit::verify(&sc, &ctx, key), "commit signature: {c}");
    assert!(commit::matches(set, &sc), "LtHash of the ops != commit.hash");
}

fn scraped(text: &str, series: &str) -> f64 {
    text.lines().find_map(|l| l.strip_prefix(series).and_then(|v| v.trim().parse().ok())).unwrap_or(0.0)
}

async fn metric(s: &TestServer, series: &str) -> f64 {
    scraped(&reqwest::get(format!("{}/metrics", s.url)).await.unwrap().text().await.unwrap(), series)
}

fn loads(s: &TestServer) -> u64 {
    s.app.spaces.as_ref().unwrap().heads.loads.load(std::sync::atomic::Ordering::Relaxed)
}

async fn spawn() -> TestServer {
    TestServer::spawn_with(|c| c.spaces = true).await
}

const SCOPE: &str = "space:com.example.group?collection=com.example.post&action=read&action=create&manage=create";

/// The account UI shows its space-repos backup notice only when describeServer
/// says the server runs Spaces; without --spaces the field is absent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn describe_server_says_whether_spaces_run() {
    let on = spawn().await;
    let j = on.xrpc.get("com.atproto.server.describeServer", &[], &Auth::None).await.ok();
    assert_eq!(j["vlpds"], json!({"spaces": true}), "{j}");
    let off = TestServer::spawn().await;
    let j = off.xrpc.get("com.atproto.server.describeServer", &[], &Auth::None).await.ok();
    assert!(j.get("vlpds").is_none(), "{j}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn spaces_e2e_single_node() {
    let s = spawn().await;
    let a = SpaceClient::new(&s, "spe", SCOPE).await;
    let space = a.create_space(TYPE, "main").await;
    assert_eq!(space, format!("at://{}/space/{TYPE}/main", a.did));
    let key = did_key(&s, &a.did).await;
    let mut sub = s.subscribe_from_now().await;
    let (pub_cid, pub_rev) = s.latest_commit(&a.did).await;

    let w = a.create_record(&space, COLL, Some("one"), rec("hello")).await.ok();
    assert_eq!(w["uri"], json!(format!("{space}/{}/{COLL}/one", a.did)));
    let cid1 = w["cid"].as_str().unwrap().to_string();
    // read_self, as the owner
    let r = a
        .get(
            "com.atproto.space.getRecord",
            &[("space", &space), ("repo", &a.did), ("collection", COLL), ("rkey", "one")],
        )
        .await;
    assert_eq!(r.ok()["value"]["text"], json!("hello"));
    assert_eq!(r.json["cid"], json!(cid1));

    // through a credential: delegation token, exchange, signed reads
    let cred = a.credential(&space).await;
    let q = [("space", space.as_str()), ("repo", a.did.as_str()), ("collection", COLL), ("rkey", "one")];
    let r = a.signed_get(&s.url, "com.atproto.space.getRecord", &q, &cred, &a.did).await;
    assert_eq!(r.ok()["value"]["text"], json!("hello"));
    let r = a.signed_get(&s.url, "com.atproto.space.listRecords", &q[..2], &cred, &a.did).await;
    assert_eq!(r.ok()["records"].as_array().unwrap().len(), 1);
    assert_eq!(r.json["records"][0]["rkey"], json!("one"));

    // a full sync: the ops replay to the signed commit's hash
    let rq = [("space", space.as_str()), ("repo", a.did.as_str())];
    let r = a.signed_get(&s.url, "com.atproto.space.listRepoOps", &rq, &cred, &a.did).await.ok();
    assert_eq!(r["ops"].as_array().unwrap().len(), 1);
    assert_eq!(r["ops"][0]["value"]["text"], json!("hello"));
    assert!(r.get("cursor").is_none());
    let mut set = LtHash::default();
    apply_ops(&mut set, &r["ops"]);
    check_commit(&r["commit"], &space, &a.did, &key, &set);
    let head = r["commit"]["rev"].as_str().unwrap().to_string();

    // at the head: no ops, a fresh commit, and no state read
    let noop = "vlpds_space_list_repo_ops_total{path=\"noop\"}";
    let (before, loaded) = (metric(&s, noop).await, loads(&s));
    let since = [("space", space.as_str()), ("repo", a.did.as_str()), ("since", head.as_str())];
    let r = a.signed_get(&s.url, "com.atproto.space.listRepoOps", &since, &cred, &a.did).await.ok();
    assert_eq!(r["ops"], json!([]));
    check_commit(&r["commit"], &space, &a.did, &key, &set);
    assert_eq!(metric(&s, noop).await, before + 1.0);
    assert_eq!(loads(&s), loaded, "a poll at the head read the space head from the store");
    let r2 = a.signed_get(&s.url, "com.atproto.space.getLatestCommit", &rq, &cred, &a.did).await.ok();
    assert_ne!(r2["commit"]["ikm"], r["commit"]["ikm"], "a fresh ikm per response");
    check_commit(&r2["commit"], &space, &a.did, &key, &set);

    // a delta: the second write only, up to the new head
    a.create_record(&space, COLL, Some("two"), rec("again")).await.ok();
    let r = a.signed_get(&s.url, "com.atproto.space.listRepoOps", &since, &cred, &a.did).await.ok();
    assert_eq!(r["ops"].as_array().unwrap().len(), 1);
    assert_eq!(r["ops"][0]["rkey"], json!("two"));
    apply_ops(&mut set, &r["ops"]);
    check_commit(&r["commit"], &space, &a.did, &key, &set);
    assert!(r["commit"]["rev"].as_str().unwrap() > head.as_str());

    // a page short of the head carries a cursor, not the commit
    let page = [("space", space.as_str()), ("repo", a.did.as_str()), ("limit", "1")];
    let r = a.signed_get(&s.url, "com.atproto.space.listRepoOps", &page, &cred, &a.did).await.ok();
    assert!(r.get("commit").is_none(), "{r}");
    let cursor = r["cursor"].as_str().unwrap().to_string();
    let next = [("space", space.as_str()), ("repo", a.did.as_str()), ("cursor", cursor.as_str())];
    let r = a.signed_get(&s.url, "com.atproto.space.listRepoOps", &next, &cred, &a.did).await.ok();
    assert_eq!(r["ops"][0]["rkey"], json!("two"));
    assert!(r.get("commit").is_some());

    // the public repo never saw any of it
    assert_eq!(s.latest_commit(&a.did).await, (pub_cid, pub_rev));
    let b = s.create_account("spm").await;
    s.post(&b, "marker").await;
    let frames = sub.wait_for(Duration::from_secs(10), &b.did, "#commit").await;
    assert!(frames.iter().all(|f| f.did() != Some(a.did.as_str())), "a space write reached the firehose");
}

/// Each way a credential read can be wrong has its own refusal.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn credential_refusals() {
    let s = spawn().await;
    let a = SpaceClient::new(&s, "spr", SCOPE).await;
    let space = a.create_space(TYPE, "one").await;
    let other = a.create_space(TYPE, "two").await;
    a.create_record(&space, COLL, Some("r"), rec("x")).await.ok();
    let cred = a.credential(&space).await;
    let q = [("space", space.as_str()), ("repo", a.did.as_str()), ("collection", COLL), ("rkey", "r")];
    let get = |cred: String, aud: String| {
        let (a, q) = (&a, q);
        async move { a.signed_get(&a.srv.base, "com.atproto.space.getRecord", &q, &cred, &aud).await }
    };
    get(cred.clone(), a.did.clone()).await.ok();

    get(cred.clone(), "not-a-did".into()).await.err(401, "BadSpaceSignature");
    get(cred.clone(), "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa".into()).await.err(401, "BadSpaceAudience");
    let foreign = a.credential(&other).await;
    get(foreign, a.did.clone()).await.err(400, "InvalidCredential");
    // signed by another key than the credential's
    let r = signed_get_as(&a.srv.http, &Holder::new(), &s.url, "com.atproto.space.getRecord", &q, &cred, &a.did).await;
    r.err(401, "BadSpaceSignature");
    // unsigned
    let url = xrpc_url(&s.url, "com.atproto.space.getRecord", &q);
    let r = resp(
        a.srv
            .http
            .get(&url)
            .header("authorization", format!("Atproto-Space-Credential {cred}"))
            .header("atproto-space-audience", &a.did)
            .send()
            .await
            .unwrap(),
    )
    .await;
    r.err(401, "BadSpaceSignature");
    assert!(r.json["message"].as_str().unwrap().contains("signature"), "{r:?}");
    // presented as a bearer token: not an access token
    let r = resp(a.srv.http.get(&url).header("authorization", format!("Bearer {cred}")).send().await.unwrap()).await;
    assert!(matches!(r.status, 400 | 401), "{r:?}");
    // a delegation token is good for one exchange
    let tok = a.delegation_token(&space).await.ok()["token"].as_str().unwrap().to_string();
    a.exchange(&s.url, &space, &tok).await.ok();
    a.exchange(&s.url, &space, &tok).await.err(400, "InvalidDelegationToken");
    // one for another space than the request names
    let tok = a.delegation_token(&other).await.ok()["token"].as_str().unwrap().to_string();
    a.exchange(&s.url, &space, &tok).await.err(400, "InvalidDelegationToken");
    // a credential isn't a delegation token
    a.exchange(&s.url, &space, &cred).await.err(400, "InvalidDelegationToken");
}

/// Space data is OAuth-only: a password session or an app password reads
/// and writes nothing, and an OAuth token without the space scope is told
/// which one it lacks.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn legacy_auth_and_missing_scopes() {
    let s = spawn().await;
    let a = SpaceClient::new(&s, "spl", SCOPE).await;
    let space = a.create_space(TYPE, "main").await;
    a.create_record(&space, COLL, Some("r"), rec("x")).await.ok();
    let read = [("space", space.as_str()), ("repo", a.did.as_str()), ("collection", COLL), ("rkey", "r")];
    let write = json!({"space": space, "repo": a.did, "collection": COLL, "record": rec("y")});
    let session = Auth::Bearer(a.session_jwt.clone());
    let ap = s
        .xrpc
        .post("com.atproto.server.createAppPassword", &json!({"name": "spaces", "privileged": true}), &session)
        .await
        .ok();
    let ap = s.create_session(&a.handle, ap["password"].as_str().unwrap()).await.ok();
    let app_pw = Auth::Bearer(ap["accessJwt"].as_str().unwrap().into());
    for auth in [&session, &app_pw] {
        s.xrpc.get("com.atproto.space.getRecord", &read, auth).await.err(403, "InsufficientScope");
        s.xrpc.post("com.atproto.space.createRecord", &write, auth).await.err(403, "InsufficientScope");
        let q = [("space", space.as_str())];
        s.xrpc.get("com.atproto.space.getDelegationToken", &q, auth).await.err(403, "InsufficientScope");
        // nor a service token for a space method, which would carry it
        for lxm in ["com.atproto.space.notifyWrite", "com.atproto.space.notifyCredentialRevoked"] {
            let q = [("aud", "did:web:space.example"), ("lxm", lxm)];
            s.xrpc.get("com.atproto.server.getServiceAuth", &q, auth).await.err(400, "InvalidRequest");
        }
    }
    // an OAuth app gets a space-method token only with a space: grant that
    // covers it (an authority's app revoking at member hosts, a writer's
    // notifying): transition:generic or rpc: alone never
    let lxms = [
        "com.atproto.space.notifyWrite",
        "com.atproto.space.notifyCredentialRevoked",
        "com.atproto.space.getRecord",
        "com.atproto.simplespace.getSpace",
        "COM.ATPROTO.SPACE.notifyWrite",
    ];
    async fn mint(sc: &SpaceClient, lxm: &str) -> Resp {
        sc.get("com.atproto.server.getServiceAuth", &[("aud", "did:web:space.example#svc"), ("lxm", lxm)]).await
    }
    let generic = SpaceClient::new(&s, "spgs", "transition:generic").await;
    let rpc = SpaceClient::new(&s, "spgr", "rpc:*?aud=did:web:space.example%23svc").await;
    for sc in [&generic, &rpc] {
        for lxm in lxms {
            mint(sc, lxm).await.err(400, "InvalidRequest");
        }
        // other methods still get one where the grant allows it
        mint(sc, "app.bsky.feed.getTimeline").await.ok();
    }
    let g = |scope: &str| format!("transition:generic space:{TYPE}?authority=*&{scope}");
    let manager = SpaceClient::new(&s, "spgm", &g("action=read&manage=update")).await;
    mint(&manager, "com.atproto.space.notifyCredentialRevoked").await.ok();
    mint(&manager, "com.atproto.space.notifyWrite").await.err(400, "InvalidRequest");
    let writer = SpaceClient::new(&s, "spgw", &g(&format!("collection={COLL}&action=create"))).await;
    mint(&writer, "com.atproto.space.notifyWrite").await.ok();
    mint(&writer, "COM.ATPROTO.SPACE.notifyWrite").await.ok();
    mint(&writer, "com.atproto.space.notifyCredentialRevoked").await.err(400, "InvalidRequest");
    let reader = SpaceClient::new(&s, "spgd", &g("action=read")).await;
    mint(&reader, "com.atproto.space.notifyWrite").await.err(400, "InvalidRequest");
    mint(&reader, "com.atproto.space.getRecord").await.ok();
    // the user's own spaces (authority=self) carry authority powers
    let own = SpaceClient::new(&s, "spgo", &format!("transition:generic space:{TYPE}?action=read")).await;
    mint(&own, "com.atproto.space.notifyCredentialRevoked").await.ok();
    // other credentials never, with the flag off too
    let off = TestServer::spawn().await;
    let acct = off.create_account("splo").await;
    for lxm in lxms {
        let q = [("aud", "did:web:space.example#svc"), ("lxm", lxm)];
        off.xrpc
            .get("com.atproto.server.getServiceAuth", &q, &Auth::Bearer(acct.access.clone()))
            .await
            .err(400, "InvalidRequest");
    }
    // OAuth without the space scope
    let g = SpaceClient::new(&s, "spg", "transition:generic").await;
    let mine = format!("at://{}/space/{TYPE}/main", g.did);
    let r = g.create_record(&mine, COLL, None, rec("z")).await;
    r.err(403, "ScopeMissingError");
    let want = format!("space:{TYPE}?authority={}&skey=main&collection={COLL}&action=create", g.did);
    assert_eq!(r.json["message"], json!(format!("Missing required scope \"{want}\"")));
    // read_self is no delegation: only a whole-space read mints a token
    let rs = SpaceClient::new(&s, "sps", "space:com.example.group?action=read_self").await;
    let theirs = format!("at://{}/space/{TYPE}/main", rs.did);
    rs.delegation_token(&theirs).await.err(403, "ScopeMissingError");
    // and nobody reads another account's repo as themselves
    let q = [("space", space.as_str()), ("repo", a.did.as_str()), ("collection", COLL), ("rkey", "r")];
    g.get("com.atproto.space.getRecord", &q).await.err(400, "RepoNotFound");
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Mode {
    /// The first send waits until released, then this stub answers 200.
    StallFirst,
    Fail,
    Ok,
}

#[derive(Default)]
struct Seen {
    /// (body, authorization)
    sends: Vec<(J, String)>,
}

/// A did:web space authority on loopback whose space host records
/// notifyWrite.
struct Authority {
    did: String,
    seen: Arc<Mutex<Seen>>,
    mode: Arc<Mutex<Mode>>,
    release: Arc<tokio::sync::Notify>,
}

async fn authority(mode: Mode) -> Authority {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let (base, did) = (format!("http://{addr}"), format!("did:web:127.0.0.1%3A{}", addr.port()));
    let seen: Arc<Mutex<Seen>> = Default::default();
    let mode = Arc::new(Mutex::new(mode));
    let release = Arc::new(tokio::sync::Notify::new());
    let (s, m, r, d, b) = (seen.clone(), mode.clone(), release.clone(), did.clone(), base.clone());
    let router = axum::Router::new().fallback(move |req: Request| {
        let (s, m, r, d, b) = (s.clone(), m.clone(), r.clone(), d.clone(), b.clone());
        async move {
            let json = |status: u16, body: J| {
                Response::builder()
                    .status(status)
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap()
            };
            if req.uri().path() == "/.well-known/did.json" {
                return json(
                    200,
                    json!({"id": d, "service": [{"id": "#atproto_space_host", "type": "AtprotoSpaceHost", "serviceEndpoint": b}]}),
                );
            }
            if req.uri().path() != "/xrpc/com.atproto.space.notifyWrite" {
                return json(404, json!({"error": "NotFound"}));
            }
            let auth = req.headers().get("authorization").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
            let body = axum::body::to_bytes(req.into_body(), 1 << 20).await.unwrap();
            let first = {
                let mut g = s.lock();
                g.sends.push((serde_json::from_slice(&body).unwrap(), auth));
                g.sends.len() == 1
            };
            let mode = *m.lock();
            match mode {
                Mode::StallFirst if first => {
                    r.notified().await;
                    json(200, json!({}))
                }
                Mode::Fail => json(503, json!({"error": "Unavailable"})),
                _ => json(200, json!({})),
            }
        }
    });
    tokio::spawn(async move { axum::serve(l, router).await.unwrap() });
    Authority { did, seen, mode, release }
}

/// The service JWT of a notifyWrite: from the writer, to the authority's
/// space host, for notifyWrite, signed by the writer's key.
fn check_service_jwt(auth: &str, writer: &str, aud: &str, key: &k256::ecdsa::VerifyingKey) {
    use k256::ecdsa::signature::Verifier;
    let tok = auth.strip_prefix("Bearer ").expect("bearer service auth");
    let parts: Vec<&str> = tok.split('.').collect();
    let dec = |s: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s).unwrap();
    let payload: J = serde_json::from_slice(&dec(parts[1])).unwrap();
    assert_eq!(payload["iss"], json!(writer));
    assert_eq!(payload["aud"], json!(format!("{aud}#atproto_space_host")));
    assert_eq!(payload["lxm"], json!("com.atproto.space.notifyWrite"));
    let sig = k256::ecdsa::Signature::from_slice(&dec(parts[2])).unwrap();
    key.verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &sig).expect("signed by the writer");
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

/// The newest rev and hash of `a`'s repo in `space`, as its owner reads them.
async fn head(a: &SpaceClient, space: &str) -> (String, Vec<u8>) {
    let r = a.get("com.atproto.space.getLatestCommit", &[("space", space), ("repo", &a.did)]).await.ok();
    (r["commit"]["rev"].as_str().unwrap().to_string(), bytes(&r["commit"]["data"]))
}

const ANY_SCOPE: &str = "space:com.example.group?authority=*&collection=com.example.post&action=read&action=create";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn outbound_notify_through_durable_outbox() {
    let auth = authority(Mode::StallFirst).await;
    let s = spawn().await;
    let a = SpaceClient::new(&s, "spn", ANY_SCOPE).await;
    let space = format!("at://{}/space/{TYPE}/x", auth.did);
    a.create_record(&space, COLL, Some("1"), rec("one")).await.ok();
    assert!(eventually(Duration::from_secs(10), || (auth.seen.lock().sends.len() == 1).then_some(())).await.is_some());
    // acked while the first send is stalled: they coalesce into one more
    a.create_record(&space, COLL, Some("2"), rec("two")).await.ok();
    a.create_record(&space, COLL, Some("3"), rec("three")).await.ok();
    let (rev, hash) = head(&a, &space).await;
    auth.release.notify_one();
    let last = eventually(Duration::from_secs(10), || {
        let g = auth.seen.lock();
        g.sends.last().filter(|(b, _)| b["repoRev"] == json!(rev)).cloned()
    })
    .await
    .expect("the newest rev delivered");
    tokio::time::sleep(Duration::from_millis(300)).await;
    let sends = auth.seen.lock().sends.clone();
    assert!(sends.len() <= 2, "{} sends: {:?}", sends.len(), sends.iter().map(|s| &s.0).collect::<Vec<_>>());
    assert_eq!(last.0["space"], json!(space));
    assert_eq!(last.0["repo"], json!(a.did));
    assert_eq!(bytes(&last.0["data"]), hash);
    let key = s.signing_key(&a.did).await;
    for (_, jwt) in &sends {
        check_service_jwt(jwt, &a.did, &auth.did, &key);
    }
    let rows = s.app.spaces.as_ref().unwrap().outbox.len();
    assert_eq!(rows, 0, "delivered rows leave the outbox");
}

/// A notify the authority refuses (503) stays in the bucket's outbox row:
/// the node that opens the shard next (a restart here) sends it again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn outbox_survives_a_restart() {
    let auth = authority(Mode::Fail).await;
    let store: Arc<dyn object_store::ObjectStore> = Arc::new(object_store::memory::InMemory::new());
    let first = cluster_node("spo", store.clone(), 8, |c| c.spaces = true).await;
    let a = SpaceClient::new(&first, "spo", ANY_SCOPE).await;
    let space = format!("at://{}/space/{TYPE}/x", auth.did);
    a.create_record(&space, COLL, Some("1"), rec("one")).await.ok();
    a.create_record(&space, COLL, Some("2"), rec("two")).await.ok();
    let (rev, _) = head(&a, &space).await;
    assert!(eventually(Duration::from_secs(10), || {
        auth.seen.lock().sends.iter().any(|(b, _)| b["repoRev"] == json!(rev)).then_some(())
    })
    .await
    .is_some());
    // retried no sooner than 30 s: nothing more arrives meanwhile
    let refused = auth.seen.lock().sends.len();
    vlpds::server::shutdown(&first.app).await;
    *auth.mode.lock() = Mode::Ok;
    let second = cluster_node("spo", store.clone(), 8, |c| c.spaces = true).await;
    let delivered = eventually(Duration::from_secs(15), || {
        let g = auth.seen.lock();
        (g.sends.len() > refused && g.sends.last().unwrap().0["repoRev"] == json!(rev)).then_some(())
    })
    .await;
    assert!(delivered.is_some(), "not resent after the restart: {:?}", auth.seen.lock().sends.len());
    assert!(eventually(Duration::from_secs(5), || second.app.spaces.as_ref().unwrap().outbox.is_empty().then_some(()))
        .await
        .is_some());
}
