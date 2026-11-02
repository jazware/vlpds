//! The space host role (`--spaces`; src/xrpc/space_policy.rs, the host
//! methods of src/xrpc/space.rs, src/space/host.rs, src/space/policy.rs):
//! space management under the baseline policies (personal, member and
//! managed spaces), published policy and member records, the writer set,
//! the gates of getSpaceCredential (member lists, public reads, managing
//! apps, allowed apps with client attestations), deleteSpace's tombstone,
//! inbound notifyWrite from another vlpds with listRepos, and registrations
//! that get writes forwarded.

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
const POLICY_REC: &str = "com.atproto.space.policy";
const MEMBER_REC: &str = "com.atproto.memberspace.member";
const CHECK: &str = "/xrpc/com.atproto.managedspace.checkUserAccess";

fn rec(text: &str) -> J {
    json!({"$type": COLL, "text": text, "createdAt": "2026-10-01T00:00:00.000Z"})
}

/// A member space: `fields` over the defaults, as getSpace returns it.
fn members_policy(fields: J) -> J {
    let mut p = json!({
        "$type": "com.atproto.memberspace.policy",
        "publicRead": false,
        "publicWrite": false,
        "publishPolicy": false,
        "publishMembers": false,
    });
    for (k, v) in fields.as_object().unwrap() {
        p[k] = v.clone();
    }
    p
}

fn ml() -> J {
    members_policy(json!({}))
}

fn public_read() -> J {
    members_policy(json!({"publicRead": true}))
}

fn managed(app: &str) -> J {
    json!({"$type": "com.atproto.managedspace.policy", "managingApp": app, "publishPolicy": false})
}

fn personal() -> J {
    json!({"$type": "com.atproto.personalspace.policy"})
}

async fn spawn() -> TestServer {
    TestServer::spawn_with(|c| c.spaces = true).await
}

async fn create(owner: &SpaceClient, skey: &str, policy: J) -> Resp {
    owner.post("com.atproto.space.createSpace", json!({"spaceType": TYPE, "skey": skey, "policy": policy})).await
}

async fn created(owner: &SpaceClient, skey: &str, policy: J) -> String {
    create(owner, skey, policy).await.ok()["uri"].as_str().unwrap().to_string()
}

async fn update(owner: &SpaceClient, space: &str, policy: J) -> Resp {
    owner.post("com.atproto.space.updateSpace", json!({"space": space, "policy": policy})).await
}

async fn put_member(owner: &SpaceClient, space: &str, did: &str, read: bool, write: bool) -> Resp {
    owner
        .post("com.atproto.memberspace.putMember", json!({"space": space, "did": did, "read": read, "write": write}))
        .await
}

async fn remove_member(owner: &SpaceClient, space: &str, did: &str) -> Resp {
    owner.post("com.atproto.memberspace.removeMember", json!({"space": space, "did": did})).await
}

async fn get_space(c: &SpaceClient, space: &str) -> Resp {
    c.get("com.atproto.space.getSpace", &[("space", space)]).await
}

async fn delete_space(c: &SpaceClient, space: &str) -> Resp {
    c.post("com.atproto.space.deleteSpace", json!({"space": space})).await
}

async fn members(c: &SpaceClient, space: &str, extra: &[(&str, &str)]) -> Resp {
    let mut q = vec![("space", space)];
    q.extend_from_slice(extra);
    c.get("com.atproto.memberspace.listMembers", &q).await
}

/// A record in `c`'s own repo in the space (None: not there).
async fn own_record(c: &SpaceClient, space: &str, collection: &str, rkey: &str) -> Option<J> {
    let r = c
        .get(
            "com.atproto.space.getRecord",
            &[("space", space), ("repo", &c.did), ("collection", collection), ("rkey", rkey)],
        )
        .await;
    if r.status == 400 && r.json["error"] == json!("RecordNotFound") {
        return None;
    }
    Some(r.ok()["value"].clone())
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
                (CHECK, Answer::Authorized(ok)) => json(200, json!({"authorized": ok})),
                (CHECK, Answer::Status(st)) => {
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
async fn space_lifecycle_and_policies() {
    let s = spawn().await;
    let owner = SpaceClient::new(&s, "shl1", OWNER).await;
    let other = SpaceClient::new(&s, "shl2", MANAGER).await;
    let r = create(&owner, "main", json!({"$type": "com.atproto.memberspace.policy"})).await;
    let space = r.ok()["uri"].as_str().unwrap().to_string();
    assert_eq!(space, format!("at://{}/space/{TYPE}/main", owner.did));
    create(&owner, "main", ml()).await.err(400, "SpaceAlreadyExists");
    // an auto-generated skey is a TID
    let auto = owner.post("com.atproto.space.createSpace", json!({"spaceType": TYPE, "policy": ml()})).await.ok();
    let skey = auto["uri"].as_str().unwrap().rsplit('/').next().unwrap().to_string();
    assert!(Tid::parse(&skey).is_some(), "{auto}");
    for bad in ["a b", "..", "a/b", ""] {
        create(&owner, bad, ml()).await.err(400, "InvalidRequest");
    }
    let r = owner.post("com.atproto.space.createSpace", json!({"spaceType": "nope", "policy": ml()})).await;
    r.err(400, "InvalidRequest");
    owner.post("com.atproto.space.createSpace", json!({"spaceType": TYPE, "skey": "np"})).await.err(400, "InvalidRequest");
    // an unknown policy is refused, not stored; so is a managing app that
    // isn't a DID
    create(&owner, "x1", json!({"$type": "com.example.somePolicy"})).await.err(400, "UnsupportedPolicy");
    create(&owner, "x2", managed("not-a-did")).await.err(400, "InvalidRequest");
    get_space(&owner, &format!("at://{}/space/{TYPE}/x1", owner.did)).await.err(400, "SpaceNotFound");

    // stored with its defaults filled in and unknown fields dropped
    assert_eq!(get_space(&owner, &space).await.ok(), json!({"uri": space, "policy": ml()}));
    let p = created(&owner, "p", json!({"$type": "com.atproto.personalspace.policy", "extra": 1})).await;
    assert_eq!(get_space(&owner, &p).await.ok()["policy"], personal());
    let m = created(&owner, "mg", json!({"$type": "com.atproto.managedspace.policy", "managingApp": "did:web:a.example#x"})).await;
    assert_eq!(get_space(&owner, &m).await.ok()["policy"], managed("did:web:a.example#x"));
    get_space(&other, &space).await.err(400, "NotSpaceOwner");

    // the policy is replaced wholesale: omitted fields go back to defaults
    let apps = members_policy(json!({"publicRead": true, "allowedApps": ["https://app.example/client-metadata.json"]}));
    update(&owner, &space, apps.clone()).await.ok();
    assert_eq!(get_space(&owner, &space).await.ok()["policy"], apps);
    update(&owner, &space, json!({"$type": "com.atproto.memberspace.policy", "publicWrite": true})).await.ok();
    assert_eq!(get_space(&owner, &space).await.ok()["policy"], members_policy(json!({"publicWrite": true})));
    update(&owner, &space, json!({"$type": "nope"})).await.err(400, "UnsupportedPolicy");
    owner.post("com.atproto.space.updateSpace", json!({"space": space})).await.err(400, "InvalidRequest");
    update(&owner, &format!("at://{}/space/{TYPE}/none", owner.did), ml()).await.err(400, "SpaceNotFound");
    update(&other, &space, ml()).await.err(400, "NotSpaceOwner");
    // a grant without manage=update is refused for its scope
    let reader = SpaceClient::new(&s, "shl3", "space:com.example.group?action=read").await;
    let r = update(&reader, &format!("at://{}/space/{TYPE}/main", reader.did), ml()).await;
    assert_eq!(r.status, 403, "{r:?}");

    // listSpaces by type and authority, a deleted space left out
    let second = created(&owner, "second", ml()).await;
    delete_space(&owner, &second).await.ok();
    let listed = owner.get("com.atproto.space.listSpaces", &[("spaceType", TYPE), ("did", &owner.did)]).await.ok();
    let uris: Vec<&str> = listed["spaces"].as_array().unwrap().iter().map(|s| s["uri"].as_str().unwrap()).collect();
    assert_eq!(uris.len(), 4, "{listed}");
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
    let space = created(&owner, "m", ml()).await;
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
    remove_member(&other, &space, &member.did).await.err(400, "NotSpaceOwner");
    members(&other, &space, &[]).await.err(400, "NotSpaceOwner");
    put_member(&owner, &space, "not-a-did", true, true).await.err(400, "InvalidRequest");
    let r = owner.post("com.atproto.memberspace.putMember", json!({"space": space, "did": member.did, "read": true})).await;
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

    // a credential reaches neither the member list nor getSpace, which are
    // the owner's
    put_member(&owner, &space, &member.did, true, true).await.ok();
    let cred = member.credential(&space).await;
    let r =
        member.signed_get(&s.url, "com.atproto.memberspace.listMembers", &[("space", &space)], &cred, &owner.did).await;
    assert_eq!(r.status, 401, "{r:?}");
    let r = member.signed_get(&s.url, "com.atproto.space.getSpace", &[("space", &space)], &cred, &owner.did).await;
    assert_eq!(r.status, 401, "{r:?}");

    remove_member(&owner, &space, &member.did).await.ok();
    let m = members(&owner, &space, &[]).await.ok();
    assert!(m["members"].as_array().unwrap().iter().all(|x| x["did"] != json!(member.did)), "{m}");
    // a refused user learns nothing about the space
    member.try_credential_at(&s.url, &space, None).await.err(400, "SpaceNotFound");
    // removing a non-member is fine
    remove_member(&owner, &space, &member.did).await.ok();

    // the member methods are the member space's own
    for policy in [personal(), managed("did:web:a.example#x")] {
        let skey = if policy == personal() { "pers" } else { "mgd" };
        let other_policy = created(&owner, skey, policy).await;
        put_member(&owner, &other_policy, &member.did, true, true).await.err(400, "PolicyMismatch");
        remove_member(&owner, &other_policy, &member.did).await.err(400, "PolicyMismatch");
        members(&owner, &other_policy, &[]).await.err(400, "PolicyMismatch");
    }
}

/// A new `$type` migrates the space and discards the member list, which
/// migrating back doesn't restore.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn migrating_the_policy_discards_its_state() {
    let s = spawn().await;
    let owner = SpaceClient::new(&s, "shx1", OWNER).await;
    let member = SpaceClient::new(&s, "shx2", ANY).await;
    let space = created(&owner, "mig", ml()).await;
    put_member(&owner, &space, &member.did, true, true).await.ok();
    member.try_credential_at(&s.url, &space, None).await.ok();
    update(&owner, &space, personal()).await.ok();
    member.try_credential_at(&s.url, &space, None).await.err(400, "SpaceNotFound");
    owner.try_credential_at(&s.url, &space, None).await.ok();
    update(&owner, &space, ml()).await.ok();
    assert_eq!(members(&owner, &space, &[]).await.ok(), json!({"members": []}));
    member.try_credential_at(&s.url, &space, None).await.err(400, "SpaceNotFound");
    // a same-type update keeps the list
    put_member(&owner, &space, &member.did, true, false).await.ok();
    update(&owner, &space, public_read()).await.ok();
    assert_eq!(members(&owner, &space, &[]).await.ok()["members"].as_array().unwrap().len(), 1);
}

/// publishPolicy and publishMembers: the authority's repo in the space
/// holds the policy and member records, created, updated and withdrawn as
/// the configuration changes, and nobody writes them directly.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn published_policy_and_members() {
    let s = spawn().await;
    let owner = SpaceClient::new(&s, "shb1", OWNER).await;
    let member = SpaceClient::new(&s, "shb2", ANY).await;
    let reader = SpaceClient::new(&s, "shb3", ANY).await;
    let published = members_policy(json!({"publishPolicy": true, "publishMembers": true}));
    let space = created(&owner, "pub", published.clone()).await;
    assert_eq!(
        own_record(&owner, &space, POLICY_REC, "self").await,
        Some(json!({"$type": POLICY_REC, "policy": published}))
    );
    put_member(&owner, &space, &member.did, true, true).await.ok();
    put_member(&owner, &space, &reader.did, true, false).await.ok();
    assert_eq!(
        own_record(&owner, &space, MEMBER_REC, &member.did).await,
        Some(json!({"$type": MEMBER_REC, "read": true, "write": true}))
    );
    put_member(&owner, &space, &member.did, true, false).await.ok();
    assert_eq!(own_record(&owner, &space, MEMBER_REC, &member.did).await.unwrap()["write"], json!(false));
    remove_member(&owner, &space, &member.did).await.ok();
    assert_eq!(own_record(&owner, &space, MEMBER_REC, &member.did).await, None);

    // readers sync them like any record: a member reads them with a credential
    let cred = reader.credential(&space).await;
    let r = reader
        .signed_get(
            &s.url,
            "com.atproto.space.listRecords",
            &[("space", &space), ("repo", &owner.did), ("collection", MEMBER_REC)],
            &cred,
            &owner.did,
        )
        .await
        .ok();
    let rkeys: Vec<&str> = r["records"].as_array().unwrap().iter().map(|r| r["rkey"].as_str().unwrap()).collect();
    assert_eq!(rkeys, [reader.did.as_str()], "{r}");

    // clearing a flag withdraws its records; setting it again republishes
    let only_policy = members_policy(json!({"publishPolicy": true}));
    update(&owner, &space, only_policy.clone()).await.ok();
    assert_eq!(own_record(&owner, &space, MEMBER_REC, &reader.did).await, None);
    assert_eq!(own_record(&owner, &space, POLICY_REC, "self").await.unwrap()["policy"], only_policy);
    update(&owner, &space, published.clone()).await.ok();
    assert!(own_record(&owner, &space, MEMBER_REC, &reader.did).await.is_some());
    // a migration away withdraws both (and drops the member list)
    update(&owner, &space, personal()).await.ok();
    assert_eq!(own_record(&owner, &space, MEMBER_REC, &reader.did).await, None);
    assert_eq!(own_record(&owner, &space, POLICY_REC, "self").await, None);
    let mp = json!({"$type": "com.atproto.managedspace.policy", "managingApp": "did:web:a.example#x", "publishPolicy": true});
    update(&owner, &space, mp.clone()).await.ok();
    assert_eq!(own_record(&owner, &space, POLICY_REC, "self").await.unwrap()["policy"], mp);
    // an unchanged policy writes nothing new
    let head = || async {
        owner.get("com.atproto.space.getLatestCommit", &[("space", &space), ("repo", &owner.did)]).await.ok()["rev"].clone()
    };
    let before = head().await;
    update(&owner, &space, mp.clone()).await.ok();
    assert_eq!(head().await, before);

    // direct writes to either collection are refused, in any repo
    for c in [&owner, &member] {
        let r = c
            .post(
                "com.atproto.space.createRecord",
                json!({"space": space, "repo": c.did, "collection": POLICY_REC, "rkey": "self", "record": {"policy": ml()}}),
            )
            .await;
        r.err(400, "InvalidRequest");
        let r = c
            .post(
                "com.atproto.space.putRecord",
                json!({"space": space, "repo": c.did, "collection": MEMBER_REC, "rkey": c.did, "record": {"read": true, "write": true}}),
            )
            .await;
        r.err(400, "InvalidRequest");
        let r = c
            .post(
                "com.atproto.space.deleteRecord",
                json!({"space": space, "repo": c.did, "collection": POLICY_REC, "rkey": "self"}),
            )
            .await;
        r.err(400, "InvalidRequest");
        let r = c
            .post(
                "com.atproto.space.applyWrites",
                json!({"space": space, "repo": c.did, "writes": [{"$type": "com.atproto.space.applyWrites#delete", "collection": MEMBER_REC, "rkey": c.did}]}),
            )
            .await;
        r.err(400, "InvalidRequest");
    }
    assert!(own_record(&owner, &space, POLICY_REC, "self").await.is_some());
}

/// removeWriter, and the member changes that take a writer out of
/// listRepos; a writer comes back with its next authorized write.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_writer_set() {
    let s = spawn().await;
    let owner = SpaceClient::new(&s, "shz1", OWNER).await;
    let other = SpaceClient::new(&s, "shz2", MANAGER).await;
    let member = SpaceClient::new(&s, "shz3", ANY).await;
    let space = created(&owner, "w", ml()).await;
    put_member(&owner, &space, &member.did, true, true).await.ok();
    let cred = owner.credential(&space).await;
    let repos = || async {
        let r = owner.signed_get(&s.url, "com.atproto.space.listRepos", &[("space", &space)], &cred, &owner.did).await;
        r.ok()["repos"].as_array().unwrap().iter().map(|r| r["did"].as_str().unwrap().to_string()).collect::<Vec<_>>()
    };
    let has = |dids: Vec<String>| {
        let repos = &repos;
        async move {
            eventually(Duration::from_secs(10), || async {
                let mut got = repos().await;
                got.sort();
                let mut want = dids.clone();
                want.sort();
                got == want
            })
            .await
        }
    };
    member.create_record(&space, COLL, Some("1"), rec("one")).await.ok();
    owner.create_record(&space, COLL, Some("1"), rec("owner")).await.ok();
    assert!(has(vec![member.did.clone(), owner.did.clone()]).await);

    async fn remove_writer(c: &SpaceClient, space: &str, did: &str) -> Resp {
        c.post("com.atproto.space.removeWriter", json!({"space": space, "did": did})).await
    }
    let remove = |c, did| remove_writer(c, &space, did);
    remove(&other, &member.did).await.err(400, "NotSpaceOwner");
    let reader = SpaceClient::new(&s, "shz4", "space:com.example.group?action=read").await;
    let r = remove(&reader, &member.did).await;
    assert!(r.status == 403 || r.status == 400, "{r:?}");
    remove(&owner, &member.did).await.ok();
    assert!(has(vec![owner.did.clone()]).await);
    // idempotent
    remove(&owner, &member.did).await.ok();
    remove(&owner, "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa").await.ok();
    remove(&owner, &format!("at://{}/space/{TYPE}/none", owner.did)).await.err(400, "InvalidRequest");
    owner
        .post("com.atproto.space.removeWriter", json!({"space": format!("at://{}/space/{TYPE}/none", owner.did), "did": member.did}))
        .await
        .err(400, "SpaceNotFound");
    // the member's records stay on its host
    assert!(own_record(&member, &space, COLL, "1").await.is_some());
    // tracked again with its next write
    member.create_record(&space, COLL, Some("2"), rec("two")).await.ok();
    assert!(has(vec![member.did.clone(), owner.did.clone()]).await);
    // read-only: out
    put_member(&owner, &space, &member.did, true, false).await.ok();
    assert!(has(vec![owner.did.clone()]).await);
    put_member(&owner, &space, &member.did, true, true).await.ok();
    member.create_record(&space, COLL, Some("3"), rec("three")).await.ok();
    assert!(has(vec![member.did.clone(), owner.did.clone()]).await);
    // removed: out
    remove_member(&owner, &space, &member.did).await.ok();
    assert!(has(vec![owner.did.clone()]).await);
    // and its writes aren't tracked any more
    member.create_record(&space, COLL, Some("4"), rec("four")).await.ok();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(repos().await, vec![owner.did.clone()]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn credential_gates() {
    let s = spawn().await;
    let owner = SpaceClient::new(&s, "shg1", OWNER).await;
    let reader = SpaceClient::new(&s, "shg2", ANY).await;
    let writer_only = SpaceClient::new(&s, "shg3", ANY).await;
    let stranger = SpaceClient::new(&s, "shg4", ANY).await;
    let listed = created(&owner, "listed", ml()).await;
    put_member(&owner, &listed, &reader.did, true, false).await.ok();
    put_member(&owner, &listed, &writer_only.did, false, true).await.ok();
    reader.try_credential_at(&s.url, &listed, None).await.ok();
    // a refusal is SpaceNotFound, as for a space that doesn't exist
    writer_only.try_credential_at(&s.url, &listed, None).await.err(400, "SpaceNotFound");
    stranger.try_credential_at(&s.url, &listed, None).await.err(400, "SpaceNotFound");
    // the authority is always admitted, listed or not, under every policy
    owner.try_credential_at(&s.url, &listed, None).await.ok();
    let public = created(&owner, "public", public_read()).await;
    stranger.try_credential_at(&s.url, &public, None).await.ok();
    let mine = created(&owner, "mine", personal()).await;
    owner.try_credential_at(&s.url, &mine, None).await.ok();
    stranger.try_credential_at(&s.url, &mine, None).await.err(400, "SpaceNotFound");
    // a space this host doesn't govern, or that was never created
    let elsewhere = format!("at://{}/space/{TYPE}/x", dead_did().await);
    let r = stranger.try_credential_at(&s.url, &elsewhere, None).await;
    r.err(400, "SpaceNotFound");
    let uncreated = format!("at://{}/space/{TYPE}/never", owner.did);
    stranger.try_credential_at(&s.url, &uncreated, None).await.err(400, "SpaceNotFound");

    // without a delegation token: only a public-read member space issues one
    let holder = crate::common::spaces::Holder::new();
    async fn credential_without_token(url: &str, kid: &str, space: &str) -> Resp {
        let body = json!({"space": space, "credentialKid": kid});
        resp(
            reqwest::Client::new()
                .post(format!("{url}/xrpc/com.atproto.space.getSpaceCredential"))
                .json(&body)
                .send()
                .await
                .unwrap(),
        )
        .await
    }
    let tokenless = |space| credential_without_token(&s.url, &holder.did, space);
    assert!(tokenless(&public).await.ok()["credential"].is_string());
    tokenless(&listed).await.err(400, "SpaceNotFound");
    tokenless(&mine).await.err(400, "SpaceNotFound");
    let mg = created(&owner, "mg", managed("did:web:a.example#x")).await;
    tokenless(&mg).await.err(400, "SpaceNotFound");
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
    let space =
        created(&owner, "apps", members_policy(json!({"publicRead": true, "publicWrite": true, "allowedApps": [client]})))
            .await;
    let aud = format!("{}#atproto_pds", owner.did);
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
    let elsewhere = attestation(&sk, &client, "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa#atproto_pds", now, now + 60);
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
    let open = created(&owner, "open", members_policy(json!({"publicRead": true, "publicWrite": true}))).await;
    let fresh = attestation(&other_sk, &unlisted, &aud, now, now + 60);
    user.try_credential_at(&s.url, &open, Some(&fresh)).await.ok();
    // the user goes first: a non-member with a disallowed app learns only
    // that the space isn't there for it
    let closed = created(&owner, "closed", members_policy(json!({"allowedApps": [client]}))).await;
    let other = attestation(&other_sk, &unlisted, &aud, now, now + 60);
    user.try_credential_at(&s.url, &closed, Some(&other)).await.err(400, "SpaceNotFound");
    put_member(&owner, &closed, &user.did, true, false).await.ok();
    let other = attestation(&other_sk, &unlisted, &aud, now, now + 60);
    user.try_credential_at(&s.url, &closed, Some(&other)).await.err(400, "AppNotAuthorized");
    user.try_credential_at(&s.url, &closed, None).await.err(400, "AppNotAuthorized");
    let good = attestation(&sk, &client, &aud, now, now + 60);
    user.try_credential_at(&s.url, &closed, Some(&good)).await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn managing_app_decides() {
    let s = spawn().await;
    let owner = SpaceClient::new(&s, "shp1", OWNER).await;
    let user = SpaceClient::new(&s, "shp2", ANY).await;
    let app = stub("forum").await;
    let space = created(&owner, "managed", managed(&app.service("forum"))).await;
    // an attested app's client_id goes along on reads
    let (sk, jwk) = oauth::client_key();
    let client =
        oauth::serve_metadata(|id| oauth::confidential_metadata(id, "https://app.example.com/callback", &jwk)).await;
    let now = chrono::Utc::now().timestamp();
    let att = attestation(&sk, &client, &format!("{}#atproto_pds", owner.did), now, now + 60);
    user.try_credential_at(&s.url, &space, Some(&att)).await.ok();
    let calls = app.calls(CHECK);
    assert_eq!(calls.len(), 1);
    let q: std::collections::HashMap<String, String> =
        reqwest::Url::parse(&format!("http://x/?{}", calls[0].query)).unwrap().query_pairs().into_owned().collect();
    assert_eq!(
        (q["space"].as_str(), q["user"].as_str(), q["access"].as_str(), q["clientId"].as_str()),
        (space.as_str(), user.did.as_str(), "read", client.as_str())
    );
    let p = jwt_payload(&calls[0].auth);
    assert_eq!(p["iss"], json!(owner.did));
    assert_eq!(p["aud"], json!(app.service("forum")));
    assert_eq!(p["lxm"], json!("com.atproto.managedspace.checkUserAccess"));
    *app.answer.lock() = Answer::Authorized(false);
    user.try_credential_at(&s.url, &space, None).await.err(400, "SpaceNotFound");
    *app.answer.lock() = Answer::Status(500);
    user.try_credential_at(&s.url, &space, None).await.err(400, "SpaceNotFound");
    // the authority isn't asked about
    let before = app.calls(CHECK).len();
    owner.try_credential_at(&s.url, &space, None).await.ok();
    assert_eq!(app.calls(CHECK).len(), before);
    // an app that can't be resolved denies
    update(&owner, &space, managed(&format!("{}#forum", dead_did().await))).await.ok();
    user.try_credential_at(&s.url, &space, None).await.err(400, "SpaceNotFound");
    update(&owner, &space, managed(&app.service("other"))).await.ok();
    user.try_credential_at(&s.url, &space, None).await.err(400, "SpaceNotFound");
    update(&owner, &space, managed(&app.service("forum"))).await.ok();

    // writes are the app's too: a local writer's notify asks it, with no
    // clientId
    let cred = owner.credential(&space).await;
    let repos = || async {
        let r = owner.signed_get(&s.url, "com.atproto.space.listRepos", &[("space", &space)], &cred, &owner.did).await;
        r.ok()["repos"].as_array().unwrap().iter().map(|r| r["did"].as_str().unwrap().to_string()).collect::<Vec<_>>()
    };
    *app.answer.lock() = Answer::Authorized(false);
    user.create_record(&space, COLL, Some("1"), rec("refused")).await.ok();
    assert!(
        eventually(Duration::from_secs(10), || async {
            app.calls(CHECK).iter().any(|c| c.query.contains("access=write"))
        })
        .await
    );
    let write = app.calls(CHECK).into_iter().find(|c| c.query.contains("access=write")).unwrap();
    assert!(!write.query.contains("clientId"), "{}", write.query);
    assert!(repos().await.is_empty());
    *app.answer.lock() = Answer::Authorized(true);
    user.create_record(&space, COLL, Some("2"), rec("admitted")).await.ok();
    assert!(eventually(Duration::from_secs(10), || async { repos().await == vec![user.did.clone()] }).await);
    // a managed space issues nothing without a delegation token: covered in
    // credential_gates
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delete_space_tombstones_and_recreates_fresh() {
    let s = spawn().await;
    let owner = SpaceClient::new(&s, "shd1", OWNER).await;
    let member = SpaceClient::new(&s, "shd2", ANY).await;
    let syncer = stub("atproto_space_syncer").await;
    let space = created(&owner, "d", ml()).await;
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
    let r = delete_space(&member, &space).await;
    assert!(r.status == 400 || r.status == 403, "{r:?}");
    delete_space(&owner, &space).await.ok();
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
    delete_space(&owner, &space).await.ok();
    delete_space(&owner, &format!("at://{}/space/{TYPE}/never", owner.did)).await.err(400, "SpaceNotFound");

    // re-created, it starts fresh: no members, no writers, no registrations
    create(&owner, "d", ml()).await.ok();
    assert_eq!(members(&owner, &space, &[]).await.ok(), json!({"members": []}));
    member.try_credential_at(&s.url, &space, None).await.err(400, "SpaceNotFound");
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
    create(&owner, "early", ml()).await.ok();
    let cred = owner.credential(&space).await;
    let r = owner.signed_get(&s.url, "com.atproto.space.listRepos", &[("space", &space)], &cred, &owner.did).await;
    assert_eq!(r.ok()["repos"][0]["did"], json!(owner.did), "{:?}", r.json);
    let only = format!("at://{}/space/{TYPE}/written", owner.did);
    owner.create_record(&only, COLL, Some("1"), rec("only written")).await.ok();
    delete_space(&owner, &only).await.ok();
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
    let space = created(&owner, "pair", ml()).await;
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
    let aud = format!("{}#atproto_pds", owner.did);
    let body =
        |repo: &str, rev: &str| json!({"space": space, "repo": repo, "repoRev": rev, "data": b64_bytes(&[7; 32])});
    // the same repoRev with the hash held, and an older one: no-ops (the
    // same rev with another hash is a takedown's adjusted view, sequenced
    // again: spaces_side::takedowns)
    let held = repos().await[0]["data"].clone();
    let dup = json!({"space": space, "repo": member.did, "repoRev": rev2, "data": held});
    notify(&b, &a, &member.did, &aud, dup.clone()).await.ok();
    // the October 1 audience is no longer the space host's
    let old = format!("{}#atproto_space_host", owner.did);
    notify(&b, &a, &member.did, &old, dup).await.err_status(403);
    notify(&b, &a, &member.did, &owner.did, body(&member.did, &rev1)).await.ok();
    assert_eq!(repos().await[0]["spaceRev"], json!(space_rev2));
    let future = rev_at(vlatproto::tid::now_micros() + 10 * 60 * 1_000_000);
    notify(&b, &a, &member.did, &aud, body(&member.did, &future)).await.err(400, "FutureRev");
    // a writer claimed by someone else's service auth
    notify(&b, &a, &member.did, &aud, body(&stranger.did, &rev2)).await.err_status(403);
    // addressed to another authority
    notify(&b, &a, &member.did, &format!("{}#atproto_pds", stranger.did), body(&member.did, &rev2))
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
        &format!("{}#atproto_pds", member.did),
        json!({"space": foreign, "repo": member.did, "repoRev": now, "data": b64_bytes(&[7; 32])}),
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

    // a removed member leaves the writer set
    remove_member(&owner, &space, &member.did).await.ok();
    assert!(repos().await.is_empty());

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

/// getRepo: a STAR archive, the commit as its metadata (with its $type),
/// then each record in bytewise path order; the commit's MAC on request, on
/// an account's own read too.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn get_repo_star() {
    use vlpds::space::{commit, lthash::LtHash, mac, star};
    let s = spawn().await;
    let owner = SpaceClient::new(&s, "shc1", OWNER).await;
    let space = created(&owner, "car", ml()).await;
    for rkey in ["b", "aa", "a", "c"] {
        owner.create_record(&space, COLL, Some(rkey), rec(rkey)).await.ok();
    }
    owner.delete_record(&space, COLL, "c").await.ok();
    let q = [("space", space.as_str()), ("repo", owner.did.as_str())];
    let (status, ctype, body) = owner.get_raw("com.atproto.space.getRepo", &q).await;
    assert_eq!((status, ctype.as_str()), (200, "application/octet-stream"));
    assert_eq!(body[..4], star::MAGIC);
    let p = star::parse(&body).unwrap();
    let paths: Vec<&str> = p.records.iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(paths, [format!("{COLL}/a"), format!("{COLL}/aa"), format!("{COLL}/b")]);
    let mut set = LtHash::default();
    for (path, b) in &p.records {
        let (coll, rkey) = path.split_once('/').unwrap();
        set.add(&commit::element(coll, rkey, &vlatproto::cid::Cid::dag_cbor(b).to_string()));
    }
    assert!(commit::matches(&set, &p.commit), "the records fold to the commit's data");
    assert_eq!((p.commit.repo.as_str(), p.commit.space.as_str()), (owner.did.as_str(), space.as_str()));
    // an own read may ask for the MAC
    let (want, secret) =
        crate::common::spaces::want_mac(&owner.srv.http, &s.url, &owner.did, mac::COMMIT_MAC_TYPE).await;
    let url = crate::common::spaces::xrpc_url(&s.url, "com.atproto.space.getRepo", &q);
    let r = owner
        .srv
        .http
        .get(&url)
        .header("dpop", owner.key.proof("GET", &url, Some(&owner.access)))
        .header("authorization", format!("DPoP {}", owner.access))
        .header(mac::WANT_MAC_HEADER, want)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let exposed: Vec<&str> =
        r.headers().get_all("access-control-expose-headers").iter().filter_map(|v| v.to_str().ok()).collect();
    assert!(exposed.iter().any(|v| v.contains("Atproto-Space-Mac")), "{exposed:?}");
    assert!(r.headers().get_all("vary").iter().any(|v| v == "Atproto-Space-Want-Mac"));
    let m =
        mac::parse_mac(r.headers().get(mac::MAC_HEADER).and_then(|v| v.to_str().ok()), mac::COMMIT_MAC_TYPE).unwrap();
    let got = star::parse(&r.bytes().await.unwrap()).unwrap();
    assert!(commit::verify(&got.commit, &space, &owner.did, &secret, &m), "the MAC on an own read");
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

/// A shard open reads its catch-up while the shard already takes writes,
/// so a write can be sequenced and forwarded (its lane drained and gone)
/// before the catch-up reaches the dispatcher. The catch-up is then behind
/// what the service heard and is dropped: forwards stay in spaceRev order.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_catch_up_behind_a_newer_write_is_not_sent() {
    let s = spawn().await;
    let owner = SpaceClient::new(&s, "shbo", OWNER).await;
    let member = SpaceClient::new(&s, "shbm", ANY).await;
    let space = owner.create_space(TYPE, "main").await;
    put_member(&owner, &space, &member.did, true, true).await.ok();
    let syncer = stub("atproto_space_syncer").await;
    let cred = owner.credential(&space).await;
    let reg = json!({"space": space, "service": syncer.service("atproto_space_syncer")});
    owner.signed_post(&s.url, "com.atproto.space.registerNotify", reg, &cred, &owner.did).await.ok();
    let notifies = || syncer.calls("/xrpc/com.atproto.space.notifyWrite");
    let heard = |rev: String| async move {
        let hit = || notifies().into_iter().find(|n| n.body["repoRev"] == json!(rev));
        assert!(eventually(Duration::from_secs(10), || async { hit().is_some() }).await, "not forwarded");
        hit().unwrap().body
    };
    member.create_record(&space, COLL, Some("1"), rec("one")).await.ok();
    let old = heard(head(&member, &space).await).await;
    member.create_record(&space, COLL, Some("2"), rec("two")).await.ok();
    let new = heard(head(&member, &space).await).await;
    let fanout = s.app.spaces.as_ref().unwrap().fanout.clone();
    wait_until("the lane drains", Duration::from_secs(10), || fanout.lanes() == 0).await;
    let sent = notifies().len();

    // a catch-up read before the second write sequenced
    let tid = |v: &J| v.as_str().map(|t| Tid::parse(t).unwrap());
    fanout.notify(vlpds::space::fanout::Job {
        authority: owner.did.as_str().into(),
        uri: space.as_str().into(),
        sid: vlpds::state::space_id(&space),
        writer: member.did.clone(),
        repo_rev: tid(&old["repoRev"]).unwrap(),
        hash: [7; 32],
        seq: vlpds::space::repo::Sequenced {
            space_rev: tid(&old["spaceRev"]).unwrap(),
            prev: tid(&old["prevSpaceRev"]),
        },
        epoch: s.app.partition(&owner.did).ok().expect("local partition").epoch,
        catch_up: true,
    });
    // then a real one: the dispatcher takes a space's jobs in order, so once
    // it is heard the stale one was dealt with
    let p = s.app.partition(&owner.did).ok().expect("local partition");
    let table = std::sync::Arc::downgrade(&s.app.partitions);
    s.app.spaces.clone().unwrap().spawn_outbox_rescan(table, vec![(p.id, p.db.clone())], false);
    assert!(eventually(Duration::from_secs(10), || async { notifies().len() > sent }).await, "no catch-up");
    tokio::time::sleep(Duration::from_millis(200)).await;
    let late: Vec<J> = notifies()[sent..].iter().map(|n| n.body.clone()).collect();
    assert_eq!(late.len(), 1, "only the current catch-up: {late:?}");
    assert_eq!(late[0]["spaceRev"], new["spaceRev"], "{late:?}");
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
    let mut spaces = vec![];
    for k in ["a", "b"] {
        spaces.push(created(&owner, k, ml()).await);
    }
    let r = create(&owner, "c", ml()).await;
    assert!(r.status == 400 && r.text().contains("governs 2 spaces"), "{r:?}");
    // updating one isn't creating one
    update(&owner, &spaces[0], public_read()).await.ok();

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
    delete_space(&owner, &spaces[1]).await.ok();
    create(&owner, "d", ml()).await.ok();
    delete_space(&owner, &spaces[0]).await.ok();
    create(&owner, "e", ml()).await.err(429, "RateLimitExceeded");
}
