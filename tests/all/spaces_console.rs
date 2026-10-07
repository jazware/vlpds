//! The console's Spaces pages (src/xrpc/space_ops.rs): admin only, 501
//! without `--spaces`, metadata only, and the one action audited.

use crate::common::spaces::SpaceClient;
use crate::common::*;
use std::time::Duration;

const TYPE: &str = "com.example.group";
const COLL: &str = "com.example.post";
const OWNER: &str = "space:com.example.group?collection=com.example.post&action=read&action=create&action=update&action=delete&manage=create&manage=update&manage=delete";
const MEMBER: &str = "space:com.example.group?authority=*&collection=com.example.post&action=read&action=create";
/// What the records say: none of it may show up in a console answer.
const SECRET: &str = "the-quiet-part-out-loud";

fn rec(n: usize) -> J {
    json!({"$type": COLL, "text": format!("{SECRET} {n}"), "createdAt": "2026-10-01T00:00:00.000Z"})
}

async fn eventually(within: Duration, mut f: impl AsyncFnMut() -> bool) -> bool {
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

async fn put_member(owner: &SpaceClient, space: &str, did: &str) {
    let body = json!({"space": space, "did": did, "read": true, "write": true});
    owner.post("com.atproto.simplespace.putMember", body).await.ok();
}

/// A did:web syncer on loopback that takes every notify.
async fn syncer() -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let (base, did) = (format!("http://{addr}"), format!("did:web:127.0.0.1%3A{}", addr.port()));
    let d = did.clone();
    let router = axum::Router::new().fallback(move |req: axum::extract::Request| {
        let (d, b) = (d.clone(), base.clone());
        async move {
            let body = match req.uri().path() {
                "/.well-known/did.json" => {
                    json!({"id": d, "service": [{"id": "#sync", "type": "Test", "serviceEndpoint": b}]})
                }
                _ => json!({}),
            };
            axum::response::Response::builder()
                .header("content-type", "application/json")
                .body(axum::body::Body::from(body.to_string()))
                .unwrap()
        }
    });
    tokio::spawn(async move { axum::serve(l, router).await.unwrap() });
    format!("{did}#sync")
}

const READS: [&str; 4] = [
    "vlpds.admin.listSpaces",
    "vlpds.admin.getSpaceInfo",
    "vlpds.admin.getAccountSpaces",
    "vlpds.admin.getSpacesStatus",
];

/// Admin Basic only; without `--spaces` an admin gets 501 with a reason,
/// anyone else still 401.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn admin_only_and_off_without_the_flag() {
    let s = TestServer::spawn_with(|c| c.spaces = true).await;
    let a = SpaceClient::new(&s, "sca", OWNER).await;
    let space = a.create_space(TYPE, "main").await;
    let q = [("did", a.did.as_str()), ("uri", space.as_str())];
    let session = Auth::Bearer(a.session_jwt.clone());
    for m in READS {
        s.xrpc.get(m, &q, &Auth::None).await.err_status(401);
        s.xrpc.get(m, &q, &session).await.err_status(401);
        a.get(m, &q).await.err_status(401);
        s.xrpc.get(m, &q, &Auth::Admin).await.ok();
    }
    let body = json!({"did": a.did, "space": space, "service": "did:web:x.example#s", "reason": "r"});
    s.xrpc.post("vlpds.admin.removeSpaceRegistration", &body, &Auth::None).await.err_status(401);
    s.xrpc.post("vlpds.admin.removeSpaceRegistration", &body, &session).await.err_status(401);

    let off = TestServer::spawn_with(|c| c.spaces = false).await;
    let b = off.create_account("scoff").await;
    let q = [("did", b.did.as_str()), ("uri", "at://did:plc:x/space/com.example.group/main")];
    for m in READS {
        off.xrpc.get(m, &q, &Auth::None).await.err_status(401);
        let r = off.xrpc.get(m, &q, &Auth::Admin).await;
        r.err(501, "MethodNotImplemented");
        assert!(r.text().contains("--spaces"), "{m}: {}", r.text());
    }
    let body = json!({"did": b.did, "space": "at://did:plc:x/space/com.example.group/main", "service": "did:web:x#s", "reason": "r"});
    off.xrpc.post("vlpds.admin.removeSpaceRegistration", &body, &Auth::Admin).await.err(501, "MethodNotImplemented");
}

/// The overview, a space's page and an account's spaces: counts, DIDs and
/// revs, never a record's value, and no audit entry for any of it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn views_are_metadata_only() {
    let s = TestServer::spawn_with(|c| c.spaces = true).await;
    let owner = SpaceClient::new(&s, "scv", OWNER).await;
    let m = SpaceClient::new(&s, "scvm", MEMBER).await;
    let big = owner.create_space(TYPE, "big").await;
    let quiet = owner.create_space(TYPE, "quiet").await;
    put_member(&owner, &big, &m.did).await;
    for i in 0..3 {
        m.create_record(&big, COLL, Some(&format!("m{i}")), rec(i)).await.ok();
    }
    owner.create_record(&big, COLL, Some("o"), rec(9)).await.ok();
    let audit_len = async || {
        s.xrpc.get("vlpds.admin.getAuditLog", &[], &Auth::Admin).await.ok()["entries"].as_array().unwrap().len()
    };
    let before = audit_len().await;

    // both writers sequenced at the authority
    let info = async || {
        s.xrpc
            .get("vlpds.admin.getSpaceInfo", &[("did", owner.did.as_str()), ("uri", big.as_str())], &Auth::Admin)
            .await
    };
    assert!(
        eventually(Duration::from_secs(10), async || info().await.ok()["writers"].as_array().unwrap().len() == 2).await
    );

    let l = s.xrpc.get("vlpds.admin.listSpaces", &[("sort", "records")], &Auth::Admin).await.ok();
    assert!(!l.to_string().contains(SECRET), "{l}");
    let t = &l["totals"];
    assert_eq!(
        (t["spaces"].clone(), t["spaceRepos"].clone(), t["records"].clone()),
        (json!(2), json!(2), json!(4)),
        "{l}"
    );
    assert_eq!((t["members"].clone(), t["writers"].clone()), (json!(1), json!(2)), "{l}");
    let rows = l["spaces"].as_array().unwrap();
    assert_eq!(rows.iter().map(|r| r["uri"].clone()).collect::<Vec<_>>(), [json!(big), json!(quiet)]);
    let r0 = &rows[0];
    assert_eq!((r0["records"].clone(), r0["repos"].clone(), r0["writers"].clone()), (json!(4), json!(2), json!(2)));
    assert_eq!((r0["handle"].clone(), r0["readPolicy"].clone()), (json!(owner.handle), json!("member-list")));
    assert!(r0["lastSpaceRev"].is_string() && rows[1]["lastSpaceRev"].is_null(), "{l}");
    let paged = s.xrpc.get("vlpds.admin.listSpaces", &[("limit", "1")], &Auth::Admin).await.ok();
    assert_eq!((paged["spaces"].as_array().unwrap().len(), paged["cursor"].clone()), (1, json!("1")));
    let next = s.xrpc.get("vlpds.admin.listSpaces", &[("limit", "1"), ("cursor", "1")], &Auth::Admin).await.ok();
    assert!(next.get("cursor").is_none(), "{next}");
    s.xrpc.get("vlpds.admin.listSpaces", &[("sort", "values")], &Auth::Admin).await.err(400, "InvalidRequest");

    let d = info().await.ok();
    assert!(!d.to_string().contains(SECRET), "{d}");
    assert_eq!(d["space"]["uri"], json!(big));
    assert_eq!(d["members"], json!([{"did": m.did, "handle": m.handle, "read": true, "write": true}]));
    let w = d["writers"].as_array().unwrap().iter().find(|w| w["did"] == json!(m.did)).unwrap().clone();
    assert_eq!((w["records"].clone(), w["local"].clone()), (json!(3), json!(true)), "{d}");
    assert_eq!(w["hash"].as_str().unwrap().len(), 16, "a short hash: {d}");
    assert!(w["repoRev"]["at"].is_string() && w["spaceRev"]["rev"].is_string(), "{d}");
    assert_eq!(d["activity"].as_array().unwrap().len(), 2, "one sQ row per writer: {d}");
    // a space is looked up at its authority
    let q = [("did", m.did.as_str()), ("uri", big.as_str())];
    s.xrpc.get("vlpds.admin.getSpaceInfo", &q, &Auth::Admin).await.err(400, "InvalidRequest");
    let gone = format!("at://{}/space/{TYPE}/nope", owner.did);
    let q = [("did", owner.did.as_str()), ("uri", gone.as_str())];
    s.xrpc.get("vlpds.admin.getSpaceInfo", &q, &Auth::Admin).await.err(400, "SpaceNotFound");

    // a record takedown shows on the space's page, by URI
    let uri = format!("{big}/{}/{COLL}/m0", m.did);
    let body = json!({"did": m.did, "kind": "record", "uri": uri, "action": "takedown", "reason": "spam"});
    s.xrpc.post("vlpds.admin.moderate", &body, &Auth::Admin).await.ok();
    let d = info().await.ok();
    assert_eq!(d["takendownRecords"], json!([{"uri": uri, "did": m.did}]));

    let a = s.xrpc.get("vlpds.admin.getAccountSpaces", &[("did", owner.did.as_str())], &Auth::Admin).await.ok();
    let governs: Vec<&J> = a["governs"].as_array().unwrap().iter().map(|g| &g["uri"]).collect();
    assert_eq!(governs, [&json!(big), &json!(quiet)]);
    let a = s.xrpc.get("vlpds.admin.getAccountSpaces", &[("did", m.did.as_str())], &Auth::Admin).await.ok();
    assert!(!a.to_string().contains(SECRET), "{a}");
    assert_eq!(a["governs"], json!([]));
    let r = &a["repos"][0];
    assert_eq!(
        (r["space"].clone(), r["records"].clone(), r["takendownRecords"].clone()),
        (json!(big), json!(3), json!(1))
    );

    let st = s.xrpc.get("vlpds.admin.getSpacesStatus", &[], &Auth::Admin).await.ok();
    assert_eq!(st["revocations"]["loaded"], json!(true), "{st}");
    // one entry: the takedown (none for the views)
    assert_eq!(audit_len().await, before + 1);
}

/// Removing a registration is audited with its reason, and the
/// registration is gone; the space's audit filter finds it, and the reads.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn registration_removal_is_audited() {
    let s = TestServer::spawn_with(|c| c.spaces = true).await;
    let owner = SpaceClient::new(&s, "scr", OWNER).await;
    let space = owner.create_space(TYPE, "main").await;
    let other = owner.create_space(TYPE, "other").await;
    let service = syncer().await;
    let cred = owner.credential(&space).await;
    let reg = json!({"space": space, "service": service});
    owner.signed_post(&s.url, "com.atproto.space.registerNotify", reg, &cred, &owner.did).await.ok();
    let q = [("did", owner.did.as_str()), ("uri", space.as_str())];
    let d = s.xrpc.get("vlpds.admin.getSpaceInfo", &q, &Auth::Admin).await.ok();
    let regs = d["registrations"].as_array().unwrap();
    assert_eq!(
        (regs.len(), regs[0]["service"].clone(), regs[0]["host"].clone()),
        (1, json!(service), json!("127.0.0.1"))
    );
    assert!(regs[0].get("endpoint").is_none(), "the host only: {d}");

    let body = json!({"did": owner.did, "space": space, "service": service, "reason": ""});
    s.xrpc.post("vlpds.admin.removeSpaceRegistration", &body, &Auth::Admin).await.err(400, "InvalidRequest");
    let body = json!({"did": owner.did, "space": space, "service": service, "reason": "abusive syncer"});
    s.xrpc.post("vlpds.admin.removeSpaceRegistration", &body, &Auth::Admin).await.ok();
    let d = s.xrpc.get("vlpds.admin.getSpaceInfo", &q, &Auth::Admin).await.ok();
    assert_eq!(d["registrations"], json!([]));

    // a read of the other space, and an account action that isn't about a space
    let rq = [("space", other.as_str()), ("repo", owner.did.as_str()), ("reason", "report 7")];
    s.xrpc.get("vlpds.admin.getSpaceRepo", &rq, &Auth::Admin).await.err(400, "RepoNotFound");
    let body = json!({"did": owner.did, "kind": "account", "action": "takedown", "reason": "x"});
    s.xrpc.post("vlpds.admin.moderate", &body, &Auth::Admin).await.ok();

    let log = s.xrpc.get("vlpds.admin.getAuditLog", &[("space", space.as_str())], &Auth::Admin).await.ok();
    let e = log["entries"].as_array().unwrap();
    assert_eq!(e.len(), 1, "{log}");
    assert_eq!(
        (e[0]["action"].clone(), e[0]["reason"].clone()),
        (json!("space.registration.remove"), json!("abusive syncer"))
    );
    assert_eq!(e[0]["detail"]["service"], json!(service));
    assert_eq!(e[0]["subject"], json!({"kind": "space", "did": owner.did, "uri": space}));
    assert_eq!((&e[0]["actor"], &e[0]["auth"]), (&json!("admin"), &json!("token")), "{log}");
    let log = s.xrpc.get("vlpds.admin.getAuditLog", &[("space", "*")], &Auth::Admin).await.ok();
    let actions: Vec<&J> = log["entries"].as_array().unwrap().iter().map(|e| &e["action"]).collect();
    assert_eq!(actions, [&json!("space.read"), &json!("space.registration.remove")], "{log}");
}
