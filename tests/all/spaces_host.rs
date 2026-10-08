//! The space host role (`--spaces`; src/xrpc/simplespace.rs, the host
//! methods of src/xrpc/space.rs, src/space/host.rs): simplespace management
//! and its policies, the gates of getSpaceCredential (member lists, public
//! spaces, managing apps, app allow lists with client attestations),
//! deleteSpace's tombstone, inbound notifyWrite from another vlpds with
//! listRepos, and registrations that get writes forwarded.

use crate::common::spaces::{resp, SpaceClient};
use crate::common::*;
use crate::oauth;
use axum::body::Body;
use axum::extract::Request;
use axum::response::Response;
use base64::Engine;
use parking_lot::Mutex;
use std::sync::Arc;
use std::time::Duration;
use vlatproto::tid::Tid;

const TYPE: &str = "com.example.group";
const COLL: &str = "com.example.post";
/// The authority's own grant: its spaces of TYPE, managed and written.
const OWNER: &str =
    "space:com.example.group?collection=com.example.post&action=read&action=create&action=delete&manage=create&manage=update&manage=delete";
/// A member's grant: anyone's spaces of TYPE.
const ANY: &str = "space:com.example.group?authority=*&collection=com.example.post&action=read&action=create";
/// Another account that may manage anyone's spaces (and so is refused only
/// for not being the owner).
const MANAGER: &str = "space:com.example.group?authority=*&action=read&manage=create&manage=update&manage=delete";

fn rec(text: &str) -> J {
    json!({"$type": COLL, "text": text, "createdAt": "2026-10-01T00:00:00.000Z"})
}

fn policy(name: &str) -> J {
    json!({"$type": format!("com.atproto.simplespace.defs#{name}")})
}

fn managing(app: &str) -> J {
    json!({"$type": "com.atproto.simplespace.defs#managingAppPolicy", "managingApp": app})
}

fn allow(clients: &[&str]) -> J {
    json!({"$type": "com.atproto.simplespace.defs#allowList", "allowed": clients})
}

async fn spawn() -> TestServer {
    TestServer::spawn_with(|c| c.spaces = true).await
}

async fn create(owner: &SpaceClient, skey: &str, read: J, write: J, app: J) -> Resp {
    owner
        .post(
            "com.atproto.simplespace.createSpace",
            json!({"spaceType": TYPE, "skey": skey, "readPolicy": read, "writePolicy": write, "appAccess": app}),
        )
        .await
}

async fn put_member(owner: &SpaceClient, space: &str, did: &str, read: bool, write: bool) -> Resp {
    owner
        .post("com.atproto.simplespace.putMember", json!({"space": space, "did": did, "read": read, "write": write}))
        .await
}

async fn get_space(c: &SpaceClient, space: &str) -> Resp {
    c.get("com.atproto.simplespace.getSpace", &[("space", space)]).await
}

async fn members(c: &SpaceClient, space: &str, extra: &[(&str, &str)]) -> Resp {
    let mut q = vec![("space", space)];
    q.extend_from_slice(extra);
    c.get("com.atproto.simplespace.listMembers", &q).await
}

async fn eventually<F, Fut>(within: Duration, mut f: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + within;
    loop {
        if f().await {
            return true;
        }
        if tokio::time::Instant::now() > deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

fn b64_bytes(b: &[u8]) -> J {
    json!({"$bytes": base64::engine::general_purpose::STANDARD_NO_PAD.encode(b)})
}

fn jwt_payload(auth: &str) -> J {
    let tok = auth.strip_prefix("Bearer ").expect("bearer");
    let p = tok.split('.').nth(1).unwrap();
    serde_json::from_slice(&base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(p).unwrap()).unwrap()
}

#[derive(Clone, Debug)]
struct Seen {
    path: String,
    query: String,
    body: J,
    auth: String,
}

#[derive(Clone, Copy)]
enum Answer {
    Authorized(bool),
    Status(u16),
}

/// A did:web service on loopback (a managing app, a syncer) whose document
/// names it under `#{fragment}`, recording every call. checkUserAccess
/// answers as told; anything else 200.
struct Stub {
    did: String,
    seen: Arc<Mutex<Vec<Seen>>>,
    answer: Arc<Mutex<Answer>>,
}

impl Stub {
    fn service(&self, fragment: &str) -> String {
        format!("{}#{fragment}", self.did)
    }

    fn calls(&self, path: &str) -> Vec<Seen> {
        self.seen.lock().iter().filter(|s| s.path == path).cloned().collect()
    }
}

async fn stub(fragment: &str) -> Stub {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let (base, did) = (format!("http://{addr}"), format!("did:web:127.0.0.1%3A{}", addr.port()));
    let seen: Arc<Mutex<Vec<Seen>>> = Default::default();
    let answer = Arc::new(Mutex::new(Answer::Authorized(true)));
    let (s, a, d, f) = (seen.clone(), answer.clone(), did.clone(), fragment.to_string());
    let router = axum::Router::new().fallback(move |req: Request| {
        let (s, a, d, f, b) = (s.clone(), a.clone(), d.clone(), f.clone(), base.clone());
        async move {
            let json = |status: u16, body: J| {
                Response::builder()
                    .status(status)
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap()
            };
            let path = req.uri().path().to_string();
            if path == "/.well-known/did.json" {
                return json(
                    200,
                    json!({"id": d, "service": [{"id": format!("#{f}"), "type": "Test", "serviceEndpoint": b}]}),
                );
            }
            let query = req.uri().query().unwrap_or("").to_string();
            let auth = req.headers().get("authorization").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
            let body = axum::body::to_bytes(req.into_body(), 1 << 20).await.unwrap();
            let body = serde_json::from_slice(&body).unwrap_or(J::Null);
            s.lock().push(Seen { path: path.clone(), query, body, auth });
            match (path.as_str(), *a.lock()) {
                ("/xrpc/com.atproto.simplespace.checkUserAccess", Answer::Authorized(ok)) => {
                    json(200, json!({"authorized": ok}))
                }
                ("/xrpc/com.atproto.simplespace.checkUserAccess", Answer::Status(st)) => {
                    json(st, json!({"error": "InternalServerError"}))
                }
                _ => json(200, json!({})),
            }
        }
    });
    tokio::spawn(async move { axum::serve(l, router).await.unwrap() });
    Stub { did, seen, answer }
}

/// A did:web nobody answers.
async fn dead_did() -> String {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    drop(l);
    format!("did:web:127.0.0.1%3A{port}")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn space_lifecycle_and_config() {
    let s = spawn().await;
    let owner = SpaceClient::new(&s, "shl1", OWNER).await;
    let other = SpaceClient::new(&s, "shl2", MANAGER).await;
    let ml = || policy("memberListPolicy");
    let r = create(&owner, "main", ml(), ml(), policy("open")).await;
    let space = r.ok()["uri"].as_str().unwrap().to_string();
    assert_eq!(space, format!("at://{}/space/{TYPE}/main", owner.did));
    create(&owner, "main", ml(), ml(), policy("open")).await.err(400, "SpaceAlreadyExists");
    // an auto-generated skey is a TID
    let auto = owner
        .post(
            "com.atproto.simplespace.createSpace",
            json!({"spaceType": TYPE, "readPolicy": ml(), "writePolicy": ml(), "appAccess": policy("open")}),
        )
        .await
        .ok();
    let skey = auto["uri"].as_str().unwrap().rsplit('/').next().unwrap().to_string();
    assert!(Tid::parse(&skey).is_some(), "{auto}");
    for bad in ["a b", "..", "a/b", ""] {
        create(&owner, bad, ml(), ml(), policy("open")).await.err(400, "InvalidRequest");
    }
    let r = owner
        .post(
            "com.atproto.simplespace.createSpace",
            json!({"spaceType": "nope", "readPolicy": ml(), "writePolicy": ml(), "appAccess": policy("open")}),
        )
        .await;
    r.err(400, "InvalidRequest");
    // unknown variants are refused, not stored
    create(&owner, "x1", policy("someOtherPolicy"), ml(), policy("open")).await.err(400, "UnsupportedPolicy");
    create(&owner, "x2", managing("not-a-did"), ml(), policy("open")).await.err(400, "UnsupportedPolicy");
    create(&owner, "x3", ml(), ml(), policy("someOtherAccess")).await.err(400, "UnsupportedAppAccess");
    get_space(&owner, &format!("at://{}/space/{TYPE}/x1", owner.did)).await.err(400, "SpaceNotFound");

    let got = get_space(&owner, &space).await.ok();
    assert_eq!(got["readPolicy"], ml());
    assert_eq!(got["appAccess"], policy("open"));
    get_space(&other, &space).await.err(400, "NotSpaceOwner");

    // patches are independent
    let update = |body: J| async { owner.post("com.atproto.simplespace.updateSpace", body).await };
    update(json!({"space": space, "readPolicy": policy("publicPolicy")})).await.ok();
    let got = get_space(&owner, &space).await.ok();
    assert_eq!((got["readPolicy"].clone(), got["writePolicy"].clone()), (policy("publicPolicy"), ml()));
    update(json!({"space": space, "writePolicy": managing("did:web:app.example#forum")})).await.ok();
    update(json!({"space": space, "appAccess": allow(&["https://app.example/client-metadata.json"])})).await.ok();
    let got = get_space(&owner, &space).await.ok();
    assert_eq!(got["readPolicy"], policy("publicPolicy"));
    assert_eq!(got["writePolicy"], managing("did:web:app.example#forum"));
    assert_eq!(got["appAccess"], allow(&["https://app.example/client-metadata.json"]));
    // switching policy drops the managing app
    update(json!({"space": space, "writePolicy": ml()})).await.ok();
    let got = get_space(&owner, &space).await.ok();
    assert_eq!(got["writePolicy"], ml(), "{got}");
    // nothing given: nothing changes
    update(json!({"space": space})).await.ok();
    assert_eq!(get_space(&owner, &space).await.ok(), got);
    update(json!({"space": space, "readPolicy": policy("nope")})).await.err(400, "UnsupportedPolicy");
    update(json!({"space": format!("at://{}/space/{TYPE}/none", owner.did), "readPolicy": ml()}))
        .await
        .err(400, "SpaceNotFound");
    let r = other.post("com.atproto.simplespace.updateSpace", json!({"space": space, "readPolicy": ml()})).await;
    r.err(400, "NotSpaceOwner");
    // a grant without manage=update is refused for its scope
    let reader = SpaceClient::new(&s, "shl3", "space:com.example.group?action=read").await;
    let r = reader
        .post(
            "com.atproto.simplespace.updateSpace",
            json!({"space": format!("at://{}/space/{TYPE}/main", reader.did), "readPolicy": ml()}),
        )
        .await;
    assert_eq!(r.status, 403, "{r:?}");

    // listSpaces by type and authority, a deleted space left out
    let second = create(&owner, "second", ml(), ml(), policy("open")).await.ok()["uri"].as_str().unwrap().to_string();
    owner.post("com.atproto.simplespace.deleteSpace", json!({"space": second})).await.ok();
    let listed = owner.get("com.atproto.space.listSpaces", &[("spaceType", TYPE), ("did", &owner.did)]).await.ok();
    let uris: Vec<&str> = listed["spaces"].as_array().unwrap().iter().map(|s| s["uri"].as_str().unwrap()).collect();
    assert_eq!(uris.len(), 2, "{listed}");
    assert!(uris.contains(&space.as_str()) && !uris.contains(&second.as_str()), "{listed}");
    let other_type =
        owner.get("com.atproto.space.listSpaces", &[("spaceType", "com.example.other"), ("did", &owner.did)]).await;
    assert_eq!(other_type.status, 403, "no grant for another type: {other_type:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn member_list() {
    let s = spawn().await;
    let owner = SpaceClient::new(&s, "shm1", OWNER).await;
    let other = SpaceClient::new(&s, "shm2", MANAGER).await;
    let member = SpaceClient::new(&s, "shm3", ANY).await;
    let ml = || policy("memberListPolicy");
    let space = create(&owner, "m", ml(), ml(), policy("open")).await.ok()["uri"].as_str().unwrap().to_string();
    assert_eq!(members(&owner, &space, &[]).await.ok(), json!({"members": []}));
    put_member(&owner, &space, &member.did, true, false).await.ok();
    let m = members(&owner, &space, &[]).await.ok();
    assert_eq!(m["members"], json!([{"did": member.did, "read": true, "write": false}]));
    // both flags are replaced
    put_member(&owner, &space, &member.did, false, true).await.ok();
    let m = members(&owner, &space, &[]).await.ok();
    assert_eq!(m["members"], json!([{"did": member.did, "read": false, "write": true}]));
    // the owner only
    put_member(&other, &space, &other.did, true, true).await.err(400, "NotSpaceOwner");
    let r = other.post("com.atproto.simplespace.removeMember", json!({"space": space, "did": member.did})).await;
    r.err(400, "NotSpaceOwner");
    members(&other, &space, &[]).await.err(400, "NotSpaceOwner");
    put_member(&owner, &space, "not-a-did", true, true).await.err(400, "InvalidRequest");
    let r =
        owner.post("com.atproto.simplespace.putMember", json!({"space": space, "did": member.did, "read": true})).await;
    r.err(400, "InvalidRequest");
    let none = format!("at://{}/space/{TYPE}/none", owner.did);
    put_member(&owner, &none, &member.did, true, true).await.err(400, "SpaceNotFound");
    members(&owner, &none, &[]).await.err(400, "SpaceNotFound");

    // paging by DID
    let dids =
        ["did:plc:aaaaaaaaaaaaaaaaaaaaaaaa", "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb", "did:plc:cccccccccccccccccccccccc"];
    for d in dids {
        put_member(&owner, &space, d, true, true).await.ok();
    }
    // the member's random DID sorts anywhere among them
    let mut all: Vec<&str> = dids.iter().copied().chain([member.did.as_str()]).collect();
    all.sort();
    let p1 = members(&owner, &space, &[("limit", "2")]).await.ok();
    let got: Vec<&str> = p1["members"].as_array().unwrap().iter().map(|m| m["did"].as_str().unwrap()).collect();
    assert_eq!(got, &all[..2]);
    let cursor = p1["cursor"].as_str().unwrap().to_string();
    let p2 = members(&owner, &space, &[("limit", "2"), ("cursor", &cursor)]).await.ok();
    let got: Vec<&str> = p2["members"].as_array().unwrap().iter().map(|m| m["did"].as_str().unwrap()).collect();
    assert_eq!(got, &all[2..]);

    // a credential doesn't reach the member list
    put_member(&owner, &space, &member.did, true, true).await.ok();
    let cred = member.credential(&space).await;
    let r =
        member.signed_get(&s.url, "com.atproto.simplespace.listMembers", &[("space", &space)], &cred, &owner.did).await;
    assert_eq!(r.status, 401, "{r:?}");
    // but getSpace does, addressed to the authority
    let r =
        member.signed_get(&s.url, "com.atproto.simplespace.getSpace", &[("space", &space)], &cred, &owner.did).await;
    assert_eq!(r.ok()["uri"], json!(space));

    owner.post("com.atproto.simplespace.removeMember", json!({"space": space, "did": member.did})).await.ok();
    let m = members(&owner, &space, &[]).await.ok();
    assert!(m["members"].as_array().unwrap().iter().all(|x| x["did"] != json!(member.did)), "{m}");
    member.try_credential_at(&s.url, &space, None).await.err(400, "UserNotAuthorized");
    // removing a non-member is fine
    owner.post("com.atproto.simplespace.removeMember", json!({"space": space, "did": member.did})).await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn credential_gates() {
    let s = spawn().await;
    let owner = SpaceClient::new(&s, "shg1", OWNER).await;
    let reader = SpaceClient::new(&s, "shg2", ANY).await;
    let writer_only = SpaceClient::new(&s, "shg3", ANY).await;
    let stranger = SpaceClient::new(&s, "shg4", ANY).await;
    let ml = || policy("memberListPolicy");
    let listed = create(&owner, "listed", ml(), ml(), policy("open")).await.ok()["uri"].as_str().unwrap().to_string();
    put_member(&owner, &listed, &reader.did, true, false).await.ok();
    put_member(&owner, &listed, &writer_only.did, false, true).await.ok();
    reader.try_credential_at(&s.url, &listed, None).await.ok();
    writer_only.try_credential_at(&s.url, &listed, None).await.err(400, "UserNotAuthorized");
    stranger.try_credential_at(&s.url, &listed, None).await.err(400, "UserNotAuthorized");
    // the authority is always admitted, listed or not
    owner.try_credential_at(&s.url, &listed, None).await.ok();
    let public = create(&owner, "public", policy("publicPolicy"), ml(), policy("open")).await.ok()["uri"]
        .as_str()
        .unwrap()
        .to_string();
    stranger.try_credential_at(&s.url, &public, None).await.ok();
    // a space this host doesn't govern, or that was never created
    let elsewhere = format!("at://{}/space/{TYPE}/x", dead_did().await);
    let r = stranger.try_credential_at(&s.url, &elsewhere, None).await;
    r.err(400, "SpaceNotFound");
    let uncreated = format!("at://{}/space/{TYPE}/never", owner.did);
    stranger.try_credential_at(&s.url, &uncreated, None).await.err(400, "SpaceNotFound");
}

/// A client attestation signed by `sk` for `client_id`, addressed to `aud`.
fn attestation(sk: &p256::ecdsa::SigningKey, client_id: &str, aud: &str, iat: i64, exp: i64) -> String {
    let jti: String = (0..16).map(|_| format!("{:02x}", rand::random::<u8>())).collect();
    oauth::sign_jwt(
        sk,
        &json!({"alg": "ES256", "typ": "atproto-client-attestation+jwt", "kid": "k1"}),
        &json!({"iss": client_id, "sub": client_id, "aud": aud, "jti": jti, "iat": iat, "exp": exp}),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn allow_list_takes_client_attestations() {
    let s = spawn().await;
    let owner = SpaceClient::new(&s, "sha1", OWNER).await;
    let user = SpaceClient::new(&s, "sha2", ANY).await;
    let (sk, jwk) = oauth::client_key();
    let client =
        oauth::serve_metadata(|id| oauth::confidential_metadata(id, "https://app.example.com/callback", &jwk)).await;
    let (other_sk, other_jwk) = oauth::client_key();
    let unlisted =
        oauth::serve_metadata(|id| oauth::confidential_metadata(id, "https://app.example.com/callback", &other_jwk))
            .await;
    let space = create(&owner, "apps", policy("publicPolicy"), policy("publicPolicy"), allow(&[&client])).await.ok()
        ["uri"]
        .as_str()
        .unwrap()
        .to_string();
    let aud = format!("{}#atproto_space_host", owner.did);
    let now = chrono::Utc::now().timestamp();
    user.try_credential_at(&s.url, &space, None).await.err(400, "AppNotAuthorized");
    let good = attestation(&sk, &client, &aud, now, now + 60);
    user.try_credential_at(&s.url, &space, Some(&good)).await.ok();
    // single use
    user.try_credential_at(&s.url, &space, Some(&good)).await.err(400, "InvalidClientAttestation");
    // signed by a key the client doesn't publish
    let forged = attestation(&other_sk, &client, &aud, now, now + 60);
    user.try_credential_at(&s.url, &space, Some(&forged)).await.err(400, "InvalidClientAttestation");
    // for another authority
    let elsewhere = attestation(&sk, &client, "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa#atproto_space_host", now, now + 60);
    user.try_credential_at(&s.url, &space, Some(&elsewhere)).await.err(400, "InvalidClientAttestation");
    let bare = attestation(&sk, &client, &owner.did, now, now + 60);
    user.try_credential_at(&s.url, &space, Some(&bare)).await.err(400, "InvalidClientAttestation");
    // expired, and longer-lived than the 300 s cap
    let expired = attestation(&sk, &client, &aud, now - 120, now - 60);
    user.try_credential_at(&s.url, &space, Some(&expired)).await.err(400, "InvalidClientAttestation");
    let long = attestation(&sk, &client, &aud, now, now + 900);
    user.try_credential_at(&s.url, &space, Some(&long)).await.err(400, "InvalidClientAttestation");
    // a real client that isn't on the list
    let other = attestation(&other_sk, &unlisted, &aud, now, now + 60);
    user.try_credential_at(&s.url, &space, Some(&other)).await.err(400, "AppNotAuthorized");
    // not a JWT at all
    user.try_credential_at(&s.url, &space, Some("nope")).await.err(400, "InvalidClientAttestation");
    // an open space takes an attestation too, and ignores the client
    let open = create(&owner, "open", policy("publicPolicy"), policy("publicPolicy"), policy("open")).await.ok()["uri"]
        .as_str()
        .unwrap()
        .to_string();
    let fresh = attestation(&other_sk, &unlisted, &aud, now, now + 60);
    user.try_credential_at(&s.url, &open, Some(&fresh)).await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn managing_app_decides() {
    let s = spawn().await;
    let owner = SpaceClient::new(&s, "shp1", OWNER).await;
    let user = SpaceClient::new(&s, "shp2", ANY).await;
    let app = stub("forum").await;
    let managed = managing(&app.service("forum"));
    let space = create(&owner, "managed", managed.clone(), managed.clone(), policy("open")).await.ok()["uri"]
        .as_str()
        .unwrap()
        .to_string();
    user.try_credential_at(&s.url, &space, None).await.ok();
    let calls = app.calls("/xrpc/com.atproto.simplespace.checkUserAccess");
    assert_eq!(calls.len(), 1);
    let q: std::collections::HashMap<String, String> =
        reqwest::Url::parse(&format!("http://x/?{}", calls[0].query)).unwrap().query_pairs().into_owned().collect();
    assert_eq!(
        (q["space"].as_str(), q["user"].as_str(), q["access"].as_str()),
        (space.as_str(), user.did.as_str(), "read")
    );
    let p = jwt_payload(&calls[0].auth);
    assert_eq!(p["iss"], json!(owner.did));
    assert_eq!(p["aud"], json!(app.service("forum")));
    assert_eq!(p["lxm"], json!("com.atproto.simplespace.checkUserAccess"));
    *app.answer.lock() = Answer::Authorized(false);
    user.try_credential_at(&s.url, &space, None).await.err(400, "UserNotAuthorized");
    *app.answer.lock() = Answer::Status(500);
    user.try_credential_at(&s.url, &space, None).await.err(400, "UserNotAuthorized");
    // the authority isn't asked about
    let before = app.calls("/xrpc/com.atproto.simplespace.checkUserAccess").len();
    owner.try_credential_at(&s.url, &space, None).await.ok();
    assert_eq!(app.calls("/xrpc/com.atproto.simplespace.checkUserAccess").len(), before);
    // an app that can't be resolved denies
    let gone = managing(&format!("{}#forum", dead_did().await));
    owner.post("com.atproto.simplespace.updateSpace", json!({"space": space, "readPolicy": gone})).await.ok();
    user.try_credential_at(&s.url, &space, None).await.err(400, "UserNotAuthorized");
    let nameless = managing(&app.service("other"));
    owner.post("com.atproto.simplespace.updateSpace", json!({"space": space, "readPolicy": nameless})).await.ok();
    user.try_credential_at(&s.url, &space, None).await.err(400, "UserNotAuthorized");

    // the write policy: a local writer's notify asks the app too
    let cred = owner.credential(&space).await;
    let repos = || async {
        let r = owner.signed_get(&s.url, "com.atproto.space.listRepos", &[("space", &space)], &cred, &owner.did).await;
        r.ok()["repos"].as_array().unwrap().iter().map(|r| r["did"].as_str().unwrap().to_string()).collect::<Vec<_>>()
    };
    *app.answer.lock() = Answer::Authorized(false);
    user.create_record(&space, COLL, Some("1"), rec("refused")).await.ok();
    assert!(
        eventually(Duration::from_secs(10), || async {
            app.calls("/xrpc/com.atproto.simplespace.checkUserAccess").iter().any(|c| c.query.contains("access=write"))
        })
        .await
    );
    assert!(repos().await.is_empty());
    *app.answer.lock() = Answer::Authorized(true);
    user.create_record(&space, COLL, Some("2"), rec("admitted")).await.ok();
    assert!(eventually(Duration::from_secs(10), || async { repos().await == vec![user.did.clone()] }).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delete_space_tombstones_and_recreates_fresh() {
    let s = spawn().await;
    let owner = SpaceClient::new(&s, "shd1", OWNER).await;
    let member = SpaceClient::new(&s, "shd2", ANY).await;
    let syncer = stub("atproto_space_syncer").await;
    let ml = || policy("memberListPolicy");
    let space = create(&owner, "d", ml(), ml(), policy("open")).await.ok()["uri"].as_str().unwrap().to_string();
    put_member(&owner, &space, &member.did, true, true).await.ok();
    owner.create_record(&space, COLL, Some("own"), rec("owner's")).await.ok();
    member.create_record(&space, COLL, Some("mine"), rec("member's")).await.ok();
    let cred = owner.credential(&space).await;
    let listed = || async {
        let r = owner.signed_get(&s.url, "com.atproto.space.listRepos", &[("space", &space)], &cred, &owner.did).await;
        r.ok()["repos"].as_array().unwrap().len()
    };
    assert!(eventually(Duration::from_secs(10), || async { listed().await == 2 }).await);
    let service = syncer.service("atproto_space_syncer");
    owner
        .signed_post(
            &s.url,
            "com.atproto.space.registerNotify",
            json!({"space": space, "service": service}),
            &cred,
            &owner.did,
        )
        .await
        .ok();

    // only the owner deletes
    let r = member.post("com.atproto.simplespace.deleteSpace", json!({"space": space})).await;
    assert!(r.status == 400 || r.status == 403, "{r:?}");
    owner.post("com.atproto.simplespace.deleteSpace", json!({"space": space})).await.ok();
    get_space(&owner, &space).await.err(400, "SpaceNotFound");
    members(&owner, &space, &[]).await.err(400, "SpaceNotFound");
    member.try_credential_at(&s.url, &space, None).await.err(400, "SpaceDeleted");
    owner.try_credential_at(&s.url, &space, None).await.err(400, "SpaceDeleted");
    let r = owner.signed_get(&s.url, "com.atproto.space.listRepos", &[("space", &space)], &cred, &owner.did).await;
    r.err(400, "SpaceNotFound");
    assert!(
        eventually(Duration::from_secs(10), || async {
            syncer.calls("/xrpc/com.atproto.space.notifySpaceDeleted").iter().any(|c| c.body["space"] == json!(space))
        })
        .await,
        "registrations are told"
    );
    let told = &syncer.calls("/xrpc/com.atproto.space.notifySpaceDeleted")[0];
    assert_eq!(jwt_payload(&told.auth)["aud"], json!(service));
    // the authority's own repo goes; the member's stays its own
    let own = owner
        .get(
            "com.atproto.space.getRecord",
            &[("space", &space), ("repo", &owner.did), ("collection", COLL), ("rkey", "own")],
        )
        .await;
    own.err(400, "RecordNotFound");
    let mine = member
        .get(
            "com.atproto.space.getRecord",
            &[("space", &space), ("repo", &member.did), ("collection", COLL), ("rkey", "mine")],
        )
        .await;
    assert_eq!(mine.ok()["value"]["text"], json!("member's"));
    owner.create_record(&space, COLL, Some("late"), rec("late")).await.err(400, "SpaceDeleted");
    // deleting again is fine
    owner.post("com.atproto.simplespace.deleteSpace", json!({"space": space})).await.ok();
    owner
        .post("com.atproto.simplespace.deleteSpace", json!({"space": format!("at://{}/space/{TYPE}/never", owner.did)}))
        .await
        .err(400, "SpaceNotFound");

    // re-created, it starts fresh: no members, no writers, no registrations
    create(&owner, "d", ml(), ml(), policy("open")).await.ok();
    assert_eq!(members(&owner, &space, &[]).await.ok(), json!({"members": []}));
    member.try_credential_at(&s.url, &space, None).await.err(400, "UserNotAuthorized");
    let cred = owner.credential(&space).await;
    let r = owner.signed_get(&s.url, "com.atproto.space.listRepos", &[("space", &space)], &cred, &owner.did).await;
    assert_eq!(r.ok(), json!({"repos": []}));
    let r = owner.get("com.atproto.space.listRecords", &[("space", &space), ("repo", &owner.did)]).await;
    assert_eq!(r.ok()["records"], json!([]));
    let before = syncer.calls("/xrpc/com.atproto.space.notifyWrite").len();
    owner.create_record(&space, COLL, Some("new"), rec("new")).await.ok();
    assert!(eventually(Duration::from_secs(10), || async { listed().await == 1 }).await);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(syncer.calls("/xrpc/com.atproto.space.notifyWrite").len(), before, "the old registration is gone");
}

/// The authority's writes before createSpace are its own; creating the
/// space later puts them in listRepos, and deleting a space only written
/// to drops them (the reference's `ensureSpace`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn written_before_created() {
    let s = spawn().await;
    let owner = SpaceClient::new(&s, "shw1", OWNER).await;
    let space = format!("at://{}/space/{TYPE}/early", owner.did);
    owner.create_record(&space, COLL, Some("1"), rec("early")).await.ok();
    get_space(&owner, &space).await.err(400, "SpaceNotFound");
    let ml = || policy("memberListPolicy");
    create(&owner, "early", ml(), ml(), policy("open")).await.ok();
    let cred = owner.credential(&space).await;
    let r = owner.signed_get(&s.url, "com.atproto.space.listRepos", &[("space", &space)], &cred, &owner.did).await;
    assert_eq!(r.ok()["repos"][0]["did"], json!(owner.did), "{:?}", r.json);
    let only = format!("at://{}/space/{TYPE}/written", owner.did);
    owner.create_record(&only, COLL, Some("1"), rec("only written")).await.ok();
    owner.post("com.atproto.simplespace.deleteSpace", json!({"space": only})).await.ok();
    let r = owner.get("com.atproto.space.listRecords", &[("space", &only), ("repo", &owner.did)]).await;
    assert_eq!(r.ok()["records"], json!([]));
}

/// Two vlpds on separate stores sharing a PLC directory.
async fn pair(plc: &vlpds::plc::mock::MockPlc) -> (TestServer, TestServer) {
    let spawn = || {
        let url = plc.url.clone();
        TestServer::spawn_with(move |c| {
            use_plc(c, url, Arc::new(vlatproto::crypto::Keypair::generate()));
            c.spaces = true;
        })
    };
    (spawn().await, spawn().await)
}

/// notifyWrite to `host` with service auth minted by `iss` (an account of
/// `signer`) for `aud`.
async fn notify(host: &TestServer, signer: &TestServer, iss: &str, aud: &str, body: J) -> Resp {
    let acct = signer.app.account(iss).await.ok().unwrap();
    let key = signer.app.secrets.account_signing_key(&acct).await.unwrap();
    let jwt = vlpds::auth::service_auth_jwt(&key, iss, aud, Some("com.atproto.space.notifyWrite"), 60).unwrap();
    let r = reqwest::Client::new()
        .post(format!("{}/xrpc/com.atproto.space.notifyWrite", host.url))
        .bearer_auth(jwt)
        .json(&body)
        .send()
        .await
        .unwrap();
    resp(r).await
}

async fn head(c: &SpaceClient, space: &str) -> String {
    let r = c.get("com.atproto.space.getLatestCommit", &[("space", space), ("repo", &c.did)]).await.ok();
    r["commit"]["rev"].as_str().unwrap().to_string()
}

fn rev_at(micros: u64) -> String {
    Tid::from_parts(micros, 0).to_string()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn notify_write_from_another_vlpds() {
    let plc = vlpds::plc::mock::MockPlc::start().await;
    let (a, b) = pair(&plc).await;
    let owner = SpaceClient::new(&b, "sho1", OWNER).await;
    let member = SpaceClient::new(&a, "shn1", ANY).await;
    let stranger = SpaceClient::new(&a, "shs1", ANY).await;
    let reader = SpaceClient::new(&a, "shr1", ANY).await;
    let syncer = stub("atproto_space_syncer").await;
    let ml = || policy("memberListPolicy");
    let space = create(&owner, "pair", ml(), ml(), policy("open")).await.ok()["uri"].as_str().unwrap().to_string();
    put_member(&owner, &space, &member.did, true, true).await.ok();
    put_member(&owner, &space, &reader.did, true, false).await.ok();
    let cred = owner.credential(&space).await;
    let repos = || async {
        let r = owner.signed_get(&b.url, "com.atproto.space.listRepos", &[("space", &space)], &cred, &owner.did).await;
        r.ok()["repos"].as_array().unwrap().clone()
    };

    // a syncer registered by a member's credential, addressed to the authority
    let mcred = member.credential_at(&b.url, &space).await;
    let service = syncer.service("atproto_space_syncer");
    let reg = member
        .signed_post(
            &b.url,
            "com.atproto.space.registerNotify",
            json!({"space": space, "service": service}),
            &mcred,
            &owner.did,
        )
        .await
        .ok();
    let expires = chrono::DateTime::parse_from_rfc3339(reg["expiresAt"].as_str().unwrap()).unwrap();
    let ttl = expires.timestamp() - chrono::Utc::now().timestamp();
    assert!((24 * 3600 - 60..=24 * 3600).contains(&ttl), "{reg}");
    let r = member
        .signed_post(
            &b.url,
            "com.atproto.space.registerNotify",
            json!({"space": space, "service": format!("{}#x", dead_did().await)}),
            &mcred,
            &owner.did,
        )
        .await;
    r.err(400, "ServiceNotResolvable");

    // A's outbox notifies B, which sequences the write
    member.create_record(&space, COLL, Some("1"), rec("one")).await.ok();
    let rev1 = head(&member, &space).await;
    assert!(
        eventually(Duration::from_secs(10), || async {
            repos().await.iter().any(|r| r["did"] == json!(member.did) && r["repoRev"] == json!(rev1))
        })
        .await
    );
    let first = repos().await;
    assert_eq!(first.len(), 1, "{first:?}");
    let space_rev1 = first[0]["spaceRev"].as_str().unwrap().to_string();
    member.create_record(&space, COLL, Some("2"), rec("two")).await.ok();
    let rev2 = head(&member, &space).await;
    assert!(eventually(Duration::from_secs(10), || async { repos().await[0]["repoRev"] == json!(rev2) }).await);
    let second = repos().await;
    assert_eq!(second.len(), 1, "one state per writer: {second:?}");
    let space_rev2 = second[0]["spaceRev"].as_str().unwrap().to_string();
    assert!(space_rev2 > space_rev1);

    // the syncer got both, in order, each naming the one before
    assert!(
        eventually(Duration::from_secs(10), || async {
            syncer.calls("/xrpc/com.atproto.space.notifyWrite").len() >= 2
        })
        .await
    );
    let fwd = syncer.calls("/xrpc/com.atproto.space.notifyWrite");
    assert_eq!(fwd[0].body["spaceRev"], json!(space_rev1));
    assert!(fwd[0].body.get("prevSpaceRev").is_none(), "{:?}", fwd[0].body);
    assert_eq!(fwd[1].body["spaceRev"], json!(space_rev2));
    assert_eq!(fwd[1].body["prevSpaceRev"], json!(space_rev1));
    assert_eq!((fwd[1].body["repo"].clone(), fwd[1].body["repoRev"].clone()), (json!(member.did), json!(rev2)));
    let p = jwt_payload(&fwd[1].auth);
    assert_eq!((p["iss"].clone(), p["aud"].clone()), (json!(owner.did), json!(service)));

    // inbound notifies, one wrong thing at a time
    let aud = format!("{}#atproto_space_host", owner.did);
    let body =
        |repo: &str, rev: &str| json!({"space": space, "repo": repo, "repoRev": rev, "hash": b64_bytes(&[7; 32])});
    // the same repoRev with the hash held, and an older one: no-ops (the
    // same rev with another hash is a takedown's adjusted view, sequenced
    // again: spaces_side::takedowns)
    let held = repos().await[0]["hash"].clone();
    let dup = json!({"space": space, "repo": member.did, "repoRev": rev2, "hash": held});
    notify(&b, &a, &member.did, &aud, dup).await.ok();
    notify(&b, &a, &member.did, &owner.did, body(&member.did, &rev1)).await.ok();
    assert_eq!(repos().await[0]["spaceRev"], json!(space_rev2));
    let future = rev_at(vlatproto::tid::now_micros() + 10 * 60 * 1_000_000);
    notify(&b, &a, &member.did, &aud, body(&member.did, &future)).await.err(400, "FutureRev");
    // a writer claimed by someone else's service auth
    notify(&b, &a, &member.did, &aud, body(&stranger.did, &rev2)).await.err_status(403);
    // addressed to another authority
    notify(&b, &a, &member.did, &format!("{}#atproto_space_host", stranger.did), body(&member.did, &rev2))
        .await
        .err_status(403);
    // not a member, and a member without write
    let now = rev_at(vlatproto::tid::now_micros());
    notify(&b, &a, &stranger.did, &aud, body(&stranger.did, &now)).await.err_status(403);
    notify(&b, &a, &reader.did, &aud, body(&reader.did, &now)).await.err_status(403);
    // a space B doesn't govern
    let foreign = format!("at://{}/space/{TYPE}/x", member.did);
    let r = notify(
        &b,
        &a,
        &member.did,
        &format!("{}#atproto_space_host", member.did),
        json!({"space": foreign, "repo": member.did, "repoRev": now, "hash": b64_bytes(&[7; 32])}),
    )
    .await;
    r.err(400, "SpaceNotFound");
    // the repoRev is checked before auth
    let r = resp(
        reqwest::Client::new()
            .post(format!("{}/xrpc/com.atproto.space.notifyWrite", b.url))
            .json(&body(&member.did, "not-a-tid"))
            .send()
            .await
            .unwrap(),
    )
    .await;
    r.err(400, "InvalidRequest");
    let r = resp(
        reqwest::Client::new()
            .post(format!("{}/xrpc/com.atproto.space.notifyWrite", b.url))
            .json(&body(&member.did, &now))
            .send()
            .await
            .unwrap(),
    )
    .await;
    r.err_status(401);
    // a refused writer's own outbox gives up rather than retrying
    stranger.create_record(&space, COLL, Some("1"), rec("nope")).await.ok();
    let a_spaces = a.app.spaces.as_ref().unwrap();
    assert!(eventually(Duration::from_secs(10), || async { a_spaces.outbox.is_empty() }).await);
    let listed = repos().await;
    assert_eq!(listed.len(), 1, "{listed:?}");

    // a removed member stays at its last repoRev
    owner.post("com.atproto.simplespace.removeMember", json!({"space": space, "did": member.did})).await.ok();
    assert_eq!(repos().await[0]["repoRev"], json!(rev2));

    // unregistered: forwards stop
    put_member(&owner, &space, &member.did, true, true).await.ok();
    member
        .signed_post(
            &b.url,
            "com.atproto.space.unregisterNotify",
            json!({"space": space, "service": service}),
            &mcred,
            &owner.did,
        )
        .await
        .ok();
    let before = syncer.calls("/xrpc/com.atproto.space.notifyWrite").len();
    member.create_record(&space, COLL, Some("3"), rec("three")).await.ok();
    let rev3 = head(&member, &space).await;
    assert!(eventually(Duration::from_secs(10), || async { repos().await[0]["repoRev"] == json!(rev3) }).await);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(syncer.calls("/xrpc/com.atproto.space.notifyWrite").len(), before);
    // an expired registration gets nothing either
    member
        .signed_post(
            &b.url,
            "com.atproto.space.registerNotify",
            json!({"space": space, "service": service}),
            &mcred,
            &owner.did,
        )
        .await
        .ok();
    vlpds::xrpc::space::set_registration_expiry(&b.app, &space, &service, vlatproto::tid::now_micros() - 1)
        .await
        .unwrap();
    member.create_record(&space, COLL, Some("4"), rec("four")).await.ok();
    let rev4 = head(&member, &space).await;
    assert!(eventually(Duration::from_secs(10), || async { repos().await[0]["repoRev"] == json!(rev4) }).await);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(syncer.calls("/xrpc/com.atproto.space.notifyWrite").len(), before);
    // unregistering what isn't registered is fine
    member
        .signed_post(
            &b.url,
            "com.atproto.space.unregisterNotify",
            json!({"space": space, "service": service}),
            &mcred,
            &owner.did,
        )
        .await
        .ok();

    // listRepos pages by spaceRev; the cursor is a plain string
    let p1 = owner
        .signed_get(&b.url, "com.atproto.space.listRepos", &[("space", &space), ("limit", "1")], &cred, &owner.did)
        .await
        .ok();
    assert_eq!(p1["repos"].as_array().unwrap().len(), 1);
    let c = p1["cursor"].as_str().unwrap().to_string();
    let p2 = owner
        .signed_get(&b.url, "com.atproto.space.listRepos", &[("space", &space), ("cursor", &c)], &cred, &owner.did)
        .await
        .ok();
    assert_eq!(p2, json!({"repos": []}), "an empty page has no cursor");
    let p3 = owner
        .signed_get(&b.url, "com.atproto.space.listRepos", &[("space", &space), ("cursor", "0")], &cred, &owner.did)
        .await
        .ok();
    assert_eq!(p3["repos"].as_array().unwrap().len(), 1, "{p3}");
    let p4 = owner
        .signed_get(&b.url, "com.atproto.space.listRepos", &[("space", &space), ("cursor", "zzz")], &cred, &owner.did)
        .await
        .ok();
    assert_eq!(p4, json!({"repos": []}));
    // a credential addressed to a member, not the authority
    let r = owner.signed_get(&b.url, "com.atproto.space.listRepos", &[("space", &space)], &cred, &member.did).await;
    r.err(401, "BadSpaceAudience");
    // OAuth doesn't list repos
    owner.get("com.atproto.space.listRepos", &[("space", &space)]).await.err_status(401);
}

/// getRepo: the commit and the index as roots, the records in the index's
/// (dag-cbor key) order, and only the roots with excludeValues.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn get_repo_car() {
    use vlpds::space::{commit, lthash::LtHash};
    let s = spawn().await;
    let owner = SpaceClient::new(&s, "shc1", OWNER).await;
    let ml = || policy("memberListPolicy");
    let space = create(&owner, "car", ml(), ml(), policy("open")).await.ok()["uri"].as_str().unwrap().to_string();
    for rkey in ["b", "aa", "a", "c"] {
        owner.create_record(&space, COLL, Some(rkey), rec(rkey)).await.ok();
    }
    owner.delete_record(&space, COLL, "c").await.ok();
    let get = |exclude: bool| {
        let space = space.clone();
        let owner = &owner;
        async move {
            let mut q = vec![("space", space.as_str()), ("repo", owner.did.as_str())];
            if exclude {
                q.push(("excludeValues", "true"));
            }
            owner.get_raw("com.atproto.space.getRepo", &q).await
        }
    };
    let (status, ctype, car) = get(false).await;
    assert_eq!((status, ctype.as_str()), (200, "application/vnd.ipld.car"));
    let (roots, blocks) = vlatproto::car::read_car(&car).unwrap();
    assert_eq!(roots.len(), 2);
    assert_eq!(blocks[0].0, roots[0]);
    assert_eq!(blocks[1].0, roots[1]);
    let c = Value::decode(blocks[0].1).unwrap().to_json();
    let index = Value::decode(blocks[1].1).unwrap();
    let paths: Vec<String> = match &index {
        Value::Map(m) => m.iter().map(|(k, _)| k.clone()).collect(),
        other => panic!("index: {other:?}"),
    };
    assert_eq!(paths, vec![format!("{COLL}/a"), format!("{COLL}/b"), format!("{COLL}/aa")]);
    assert_eq!(blocks.len(), 5, "commit, index, three records");
    let mut set = LtHash::default();
    for (i, p) in paths.iter().enumerate() {
        let (coll, rkey) = p.split_once('/').unwrap();
        let cid = blocks[2 + i].0;
        assert!(vlatproto::car::block_matches(&cid, blocks[2 + i].1));
        set.add(&commit::element(coll, rkey, &cid.to_string()));
    }
    let bytes = |k: &str| {
        let s = c[k]["$bytes"].as_str().unwrap_or_else(|| panic!("{k}: {c}"));
        base64::engine::general_purpose::STANDARD_NO_PAD.decode(s.trim_end_matches('=')).unwrap()
    };
    let sc = commit::SignedCommit {
        ver: c["ver"].as_i64().unwrap(),
        hash: bytes("hash"),
        ikm: bytes("ikm"),
        sig: bytes("sig"),
        mac: bytes("mac"),
        rev: c["rev"].as_str().unwrap().to_string(),
    };
    assert!(commit::matches(&set, &sc), "the index folds to the commit's hash");
    let (_, _, idx_only) = get(true).await;
    let (roots2, blocks2) = vlatproto::car::read_car(&idx_only).unwrap();
    assert_eq!((roots2.len(), blocks2.len()), (2, 2));
    assert_eq!(roots2[1], roots[1], "the same index");
    let r = owner
        .get(
            "com.atproto.space.getRepo",
            &[("space", &format!("at://{}/space/{TYPE}/none", owner.did)), ("repo", &owner.did)],
        )
        .await;
    r.err(400, "RepoNotFound");
}

/// Fan-out lanes are in memory, so when a shard opens (a start, a
/// takeover) each registered space gets one forward of its newest writer,
/// naming the spaceRev before it: a syncer that missed one sees the gap.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shard_open_sends_registrations_a_catch_up() {
    let s = spawn().await;
    let owner = SpaceClient::new(&s, "shcu", OWNER).await;
    let member = SpaceClient::new(&s, "shcm", ANY).await;
    let space = owner.create_space(TYPE, "main").await;
    put_member(&owner, &space, &member.did, true, true).await.ok();
    let syncer = stub("atproto_space_syncer").await;
    let cred = owner.credential(&space).await;
    let reg = json!({"space": space, "service": syncer.service("atproto_space_syncer")});
    owner.signed_post(&s.url, "com.atproto.space.registerNotify", reg, &cred, &owner.did).await.ok();
    let notifies = || syncer.calls("/xrpc/com.atproto.space.notifyWrite");
    owner.create_record(&space, COLL, Some("0"), rec("zero")).await.ok();
    member.create_record(&space, COLL, Some("1"), rec("one")).await.ok();
    let rev1 = head(&member, &space).await;
    let heard = |rev: String| async move {
        eventually(Duration::from_secs(10), || async { notifies().iter().any(|n| n.body["repoRev"] == json!(rev)) })
            .await
    };
    assert!(heard(rev1).await);
    let list = || async {
        let q = [("space", space.as_str())];
        let r = owner.signed_get(&s.url, "com.atproto.space.listRepos", &q, &cred, &owner.did).await.ok();
        r["repos"].as_array().unwrap().clone()
    };
    let first = list().await.last().unwrap().clone();
    member.create_record(&space, COLL, Some("2"), rec("two")).await.ok();
    let rev2 = head(&member, &space).await;
    assert!(heard(rev2.clone()).await);
    let repos = list().await;
    let (before, newest) = (repos[repos.len() - 2].clone(), repos[repos.len() - 1].clone());
    let sent = notifies().len();

    // as a shard open does: one forward of the newest writer
    let p = s.app.partition(&owner.did).ok().expect("local partition");
    let table = std::sync::Arc::downgrade(&s.app.partitions);
    s.app.spaces.clone().unwrap().spawn_outbox_rescan(table, vec![(p.id, p.db.clone())], false);
    assert!(eventually(Duration::from_secs(10), || async { notifies().len() > sent }).await, "no catch-up");
    tokio::time::sleep(Duration::from_millis(200)).await;
    let all = notifies();
    assert_eq!(all.len(), sent + 1, "one per registered space");
    let catch_up = &all[sent].body;
    assert_eq!((catch_up["repo"].clone(), catch_up["repoRev"].clone()), (json!(member.did), json!(rev2)));
    assert_eq!(catch_up["spaceRev"], newest["spaceRev"]);
    // the spaceRev sequenced just before, not the row before it in listRepos
    // (the member's first write, whose row its second replaced): naming
    // that one would fork the chain the syncer heard
    assert_eq!(catch_up["prevSpaceRev"], first["spaceRev"], "{catch_up}");
    assert_ne!(catch_up["prevSpaceRev"], before["spaceRev"], "{catch_up}");
}

/// What one authority account can make its writes fan out to is bounded:
/// its live spaces, its registrations across them, and how fast it makes
/// spaces and a credential registers (each over its own bucket).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn spaces_and_registrations_are_capped_per_authority() {
    let s = TestServer::spawn_with(|c| {
        c.spaces = true;
        c.rate_limits_enabled = true;
    })
    .await;
    s.app.spaces.as_deref().unwrap().set_account_caps(2, 3);
    let limits = json!({"config": {"limiters": {"space-create": {"points": 4}, "space-register": {"points": 3}}}, "ifVersion": 0, "actor": "it-test"});
    s.xrpc.post("vlpds.admin.updateRateLimits", &limits, &Auth::Admin).await.ok();
    let owner = SpaceClient::new(&s, "shc1", OWNER).await;
    let ml = || policy("memberListPolicy");
    let mut spaces = vec![];
    for k in ["a", "b"] {
        spaces.push(create(&owner, k, ml(), ml(), policy("open")).await.ok()["uri"].as_str().unwrap().to_string());
    }
    let r = create(&owner, "c", ml(), ml(), policy("open")).await;
    assert!(r.status == 400 && r.text().contains("governs 2 spaces"), "{r:?}");
    // updating one isn't creating one
    owner
        .post("com.atproto.simplespace.updateSpace", json!({"space": spaces[0], "readPolicy": policy("publicPolicy")}))
        .await
        .ok();

    let mut syncers = vec![];
    for _ in 0..4 {
        syncers.push(stub("atproto_space_syncer").await);
    }
    let register = |space: String, service: String, cred: String| {
        let owner = &owner;
        let url = s.url.clone();
        async move {
            let body = json!({"space": space, "service": service});
            owner.signed_post(&url, "com.atproto.space.registerNotify", body, &cred, &owner.did).await
        }
    };
    let (c0, c1) = (owner.credential(&spaces[0]).await, owner.credential(&spaces[1]).await);
    let svc = |i: usize| syncers[i].service("atproto_space_syncer");
    register(spaces[0].clone(), svc(0), c0.clone()).await.ok();
    register(spaces[0].clone(), svc(1), c0.clone()).await.ok();
    register(spaces[1].clone(), svc(2), c1.clone()).await.ok();
    let r = register(spaces[1].clone(), svc(3), c1.clone()).await;
    assert!(r.status == 400 && r.text().contains("3 notify registrations across its spaces"), "{r:?}");
    // a renewal isn't a new registration
    register(spaces[1].clone(), svc(2), c1.clone()).await.ok();
    // space-register: 3 a credential; c0's third
    register(spaces[0].clone(), svc(0), c0.clone()).await.ok();
    register(spaces[0].clone(), svc(0), c0.clone()).await.err(429, "RateLimitExceeded");

    // space-create: 4 a day; 3 spent (2 made, 1 refused at the cap)
    owner.post("com.atproto.simplespace.deleteSpace", json!({"space": spaces[1]})).await.ok();
    create(&owner, "d", ml(), ml(), policy("open")).await.ok();
    owner.post("com.atproto.simplespace.deleteSpace", json!({"space": spaces[0]})).await.ok();
    create(&owner, "e", ml(), ml(), policy("open")).await.err(429, "RateLimitExceeded");
}
