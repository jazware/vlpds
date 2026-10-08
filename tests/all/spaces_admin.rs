//! Spaces moderation and moving in (`--spaces`; src/xrpc/space_admin.rs,
//! src/xrpc/space_import.rs, the space takedown in src/xrpc/space.rs):
//! audited operator reads, space takedowns, no credentials for taken-down
//! accounts, blobs of taken-down records, and vlpds.space.importRepo.

use crate::common::spaces::SpaceClient;
use crate::common::*;
use std::time::Duration;
use vlatproto::cbor::Value;
use vlatproto::cid::Cid;

const TYPE: &str = "com.example.group";
const COLL: &str = "com.example.post";
const OWNER: &str = "space:com.example.group?collection=com.example.post&action=read&action=create&action=update&action=delete&manage=create&manage=update&manage=delete";
const MEMBER: &str = "space:com.example.group?authority=*&collection=com.example.post&action=read&action=create";
const CAR: &str = "application/vnd.ipld.car";
const IMPORT: &str = "vlpds.space.importRepo";

fn rec(text: &str) -> J {
    json!({"$type": COLL, "text": text, "createdAt": "2026-10-01T00:00:00.000Z"})
}

async fn spawn() -> TestServer {
    TestServer::spawn_with(|c| c.spaces = true).await
}

fn strong_ref(uri: &str) -> J {
    json!({"$type": "com.atproto.repo.strongRef", "uri": uri, "cid": "bafyreie5737gdxlw5i64vzichcalba3z2v5n6icifvx5xytvske7mr3hpm"})
}

async fn set_status(s: &TestServer, subject: J, applied: bool) {
    let body = json!({"subject": subject, "takedown": {"applied": applied, "ref": "t"}});
    s.xrpc.post("com.atproto.admin.updateSubjectStatus", &body, &Auth::Admin).await.ok();
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

/// A moderator reads space records; every read is in the audit log first,
/// naming the space and the record; a user's own tokens are refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn operator_reads_are_audited() {
    let s = spawn().await;
    let a = SpaceClient::new(&s, "sad", OWNER).await;
    let space = a.create_space(TYPE, "main").await;
    a.create_record(&space, COLL, Some("one"), rec("first")).await.ok();
    a.create_record(&space, COLL, Some("two"), rec("second")).await.ok();
    let q = [("space", space.as_str()), ("repo", a.did.as_str()), ("collection", COLL), ("rkey", "one")];
    let mut with_reason = q.to_vec();
    with_reason.push(("reason", "report 42"));

    let r = s.xrpc.get("vlpds.admin.getSpaceRecord", &with_reason, &Auth::Admin).await.ok();
    assert_eq!(r["uri"], json!(format!("{space}/{}/{COLL}/one", a.did)));
    assert_eq!(r["value"]["text"], json!("first"));
    assert_eq!(r["takendown"], json!(false));
    assert!(Cid::parse(r["cid"].as_str().unwrap()).is_ok());
    let rq = [("space", space.as_str()), ("repo", a.did.as_str())];
    let list = s.xrpc.get("vlpds.admin.listSpaceRecords", &rq, &Auth::Admin).await.ok();
    let texts: Vec<&J> = list["records"].as_array().unwrap().iter().map(|r| &r["value"]["text"]).collect();
    assert_eq!(texts, [&json!("first"), &json!("second")]);
    let repo = s.xrpc.get("vlpds.admin.getSpaceRepo", &rq, &Auth::Admin).await.ok();
    assert_eq!(repo["records"], json!(2));

    let log = s.xrpc.get("vlpds.admin.getAuditLog", &[("did", a.did.as_str())], &Auth::Admin).await.ok();
    let reads: Vec<&J> = log["entries"].as_array().unwrap().iter().filter(|e| e["action"] == "space.read").collect();
    assert_eq!(reads.len(), 3, "{log}");
    let methods: Vec<&J> = reads.iter().map(|e| &e["detail"]["method"]).collect();
    assert_eq!(methods, [&json!("getSpaceRepo"), &json!("listSpaceRecords"), &json!("getSpaceRecord")]);
    let one = reads[2];
    assert_eq!(one["reason"], json!("report 42"));
    assert_eq!(one["subject"]["uri"], r["uri"]);
    assert_eq!((one["detail"]["space"].clone(), one["detail"]["rkey"].clone()), (json!(space), json!("one")));
    assert_eq!(reads[1]["subject"], json!({"kind": "spaceRepo", "did": a.did, "uri": space}));

    // a taken-down record is still shown to the operator, flagged
    set_status(&s, strong_ref(&format!("{space}/{}/{COLL}/one", a.did)), true).await;
    let r = s.xrpc.get("vlpds.admin.getSpaceRecord", &q, &Auth::Admin).await.ok();
    assert_eq!((r["takendown"].clone(), r["value"]["text"].clone()), (json!(true), json!("first")));
    let repo = s.xrpc.get("vlpds.admin.getSpaceRepo", &rq, &Auth::Admin).await.ok();
    assert_eq!(repo["takendown"], json!([format!("{COLL}/one")]));

    // nobody else: the account's OAuth token, its password session, an app password
    let before =
        s.xrpc.get("vlpds.admin.getAuditLog", &[], &Auth::Admin).await.ok()["entries"].as_array().unwrap().len();
    a.get("vlpds.admin.getSpaceRecord", &q).await.err_status(401);
    let session = Auth::Bearer(a.session_jwt.clone());
    s.xrpc.get("vlpds.admin.getSpaceRecord", &q, &session).await.err_status(401);
    let ap = s
        .xrpc
        .post("com.atproto.server.createAppPassword", &json!({"name": "mod", "privileged": true}), &session)
        .await
        .ok();
    let ap = s.create_session(&a.handle, ap["password"].as_str().unwrap()).await.ok();
    let app_pw = Auth::Bearer(ap["accessJwt"].as_str().unwrap().into());
    s.xrpc.get("vlpds.admin.listSpaceRecords", &rq, &app_pw).await.err_status(401);
    s.xrpc.get("vlpds.admin.getSpaceRepo", &rq, &Auth::None).await.err_status(401);
    let after =
        s.xrpc.get("vlpds.admin.getAuditLog", &[], &Auth::Admin).await.ok()["entries"].as_array().unwrap().len();
    assert_eq!(after, before, "a refused read writes no audit entry");

    // what isn't there: audited all the same, then not found
    let missing = [("space", space.as_str()), ("repo", a.did.as_str()), ("collection", COLL), ("rkey", "nope")];
    s.xrpc.get("vlpds.admin.getSpaceRecord", &missing, &Auth::Admin).await.err(400, "RecordNotFound");
}

/// The console looks up space URIs: a space record by its author, a space
/// at its authority; reading the record's value is a separate audited call.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn console_lookup_takes_space_uris() {
    let s = spawn().await;
    let a = SpaceClient::new(&s, "scl", OWNER).await;
    let m = SpaceClient::new(&s, "scm", MEMBER).await;
    let space = a.create_space(TYPE, "main").await;
    put_member(&a, &space, &m.did).await;
    m.create_record(&space, COLL, Some("r"), rec("secret")).await.ok();
    let uri = format!("{space}/{}/{COLL}/r", m.did);
    let r = s.xrpc.get("vlpds.admin.resolveSubject", &[("q", uri.as_str())], &Auth::Admin).await.ok();
    assert_eq!((r["did"].clone(), r["kind"].clone(), r["uri"].clone()), (json!(m.did), json!("record"), json!(uri)));
    let d = s.xrpc.get("vlpds.admin.getSubject", &[("did", m.did.as_str()), ("uri", uri.as_str())], &Auth::Admin).await;
    let d = d.ok();
    assert_eq!(
        (d["spaceRecord"]["exists"].clone(), d["spaceRecord"]["takendown"].clone()),
        (json!(true), json!(false))
    );
    assert!(!d.to_string().contains("secret"), "the lookup never shows a space record's value: {d}");
    assert!(d["spaceRecord"].get("cid").is_none(), "nor its CID: {d}");

    let r = s.xrpc.get("vlpds.admin.resolveSubject", &[("q", space.as_str())], &Auth::Admin).await.ok();
    assert_eq!((r["did"].clone(), r["kind"].clone()), (json!(a.did), json!("space")));
    let q = [("did", a.did.as_str()), ("uri", space.as_str())];
    let d = s.xrpc.get("vlpds.admin.getSubject", &q, &Auth::Admin).await.ok();
    assert_eq!(d["space"], json!({"uri": space, "takendown": false, "exists": true, "deleted": false}));
    // the console's takedown of a space: listed, and shown on the lookup
    let body = json!({"did": a.did, "kind": "space", "uri": space, "action": "takedown", "reason": "spam ring"});
    s.xrpc.post("vlpds.admin.moderate", &body, &Auth::Admin).await.ok();
    let l = s.xrpc.get("vlpds.admin.listTakedowns", &[("kind", "space")], &Auth::Admin).await.ok();
    assert_eq!(l["takedowns"][0]["subject"]["uri"], json!(space), "{l}");
    let d = s.xrpc.get("vlpds.admin.getSubject", &q, &Auth::Admin).await.ok();
    assert_eq!(d["space"]["takendown"], json!(true));
    // a space is taken down at its authority, not at a member
    let body = json!({"did": m.did, "kind": "space", "uri": space, "action": "takedown", "reason": "x"});
    s.xrpc.post("vlpds.admin.moderate", &body, &Auth::Admin).await.err(400, "InvalidRequest");
}

/// A space takedown: no credentials, no listRepos or registrations, and
/// members' notifies dropped; a restore brings all of it back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn space_takedown_is_enforced() {
    let s = spawn().await;
    let owner = SpaceClient::new(&s, "sto", OWNER).await;
    let m = SpaceClient::new(&s, "stm", MEMBER).await;
    let space = owner.create_space(TYPE, "main").await;
    put_member(&owner, &space, &m.did).await;
    let cred = owner.credential(&space).await;
    let list_repos =
        async || owner.signed_get(&s.url, "com.atproto.space.listRepos", &[("space", &space)], &cred, &owner.did).await;
    let rev_of = async |c: &SpaceClient| {
        let q = [("space", space.as_str()), ("repo", c.did.as_str())];
        c.get("com.atproto.space.getLatestCommit", &q).await.ok()["commit"]["rev"].as_str().unwrap().to_string()
    };
    let listed_rev = async || {
        let r = list_repos().await.ok();
        r["repos"].as_array().unwrap().iter().find(|w| w["did"] == json!(m.did)).map(|w| w["repoRev"].clone())
    };
    m.create_record(&space, COLL, Some("a"), rec("one")).await.ok();
    let rev1 = rev_of(&m).await;
    assert!(eventually(Duration::from_secs(10), async || listed_rev().await == Some(json!(rev1))).await);

    set_status(&s, strong_ref(&space), true).await;
    m.try_credential_at(&s.url, &space, None).await.err(400, "NotAuthorized");
    list_repos().await.err(400, "SpaceNotFound");
    let reg = json!({"space": space, "service": "did:web:syncer.example.com"});
    owner
        .signed_post(&s.url, "com.atproto.space.registerNotify", reg.clone(), &cred, &owner.did)
        .await
        .err(400, "SpaceNotFound");
    // the member's write lands in its repo; its notify is dropped
    m.create_record(&space, COLL, Some("b"), rec("two")).await.ok();
    let sp = s.app.spaces.as_deref().unwrap();
    assert!(eventually(Duration::from_secs(10), async || sp.outbox.is_empty()).await, "the notify was answered");

    set_status(&s, strong_ref(&space), false).await;
    m.try_credential_at(&s.url, &space, None).await.ok();
    assert_eq!(listed_rev().await, Some(json!(rev1)), "the dropped notify recorded nothing");
    m.create_record(&space, COLL, Some("c"), rec("three")).await.ok();
    let rev3 = rev_of(&m).await;
    assert!(eventually(Duration::from_secs(10), async || listed_rev().await == Some(json!(rev3))).await);
}

/// No credential names a taken-down member or authority, and a taken-down
/// account mints no delegation tokens.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn taken_down_accounts_get_no_credentials() {
    let s = spawn().await;
    let owner = SpaceClient::new(&s, "sco", OWNER).await;
    let m = SpaceClient::new(&s, "scm1", MEMBER).await;
    let m2 = SpaceClient::new(&s, "scm2", MEMBER).await;
    let space = owner.create_space(TYPE, "main").await;
    put_member(&owner, &space, &m.did).await;
    put_member(&owner, &space, &m2.did).await;
    let token = async |c: &SpaceClient| c.delegation_token(&space).await.ok()["token"].as_str().unwrap().to_string();

    // a member taken down after minting its token
    let t = token(&m).await;
    set_status(&s, json!({"$type": "com.atproto.admin.defs#repoRef", "did": m.did}), true).await;
    m.exchange(&s.url, &space, &t).await.err(400, "AccountTakedown");
    m.delegation_token(&space).await.client_err();
    set_status(&s, json!({"$type": "com.atproto.admin.defs#repoRef", "did": m.did}), false).await;

    // the authority taken down
    let t2 = token(&m2).await;
    m2.exchange(&s.url, &space, &t2).await.ok();
    let t2 = token(&m2).await;
    set_status(&s, json!({"$type": "com.atproto.admin.defs#repoRef", "did": owner.did}), true).await;
    m2.exchange(&s.url, &space, &t2).await.err(400, "RepoTakendown");
    set_status(&s, json!({"$type": "com.atproto.admin.defs#repoRef", "did": owner.did}), false).await;
    let t2 = token(&m2).await;
    m2.exchange(&s.url, &space, &t2).await.ok();
}

/// A blob only taken-down records name is neither served nor listed; one
/// a visible record also names still is.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn blobs_of_taken_down_records_are_hidden() {
    let s = spawn().await;
    let a = SpaceClient::new(&s, "sbt", OWNER).await;
    let space = a.create_space(TYPE, "main").await;
    let legacy = TestAccount {
        did: a.did.clone(),
        handle: a.handle.clone(),
        password: String::new(),
        email: String::new(),
        access: a.session_jwt.clone(),
        refresh: String::new(),
    };
    let only = s.upload_blob(&legacy, &random_png(7), "image/png").await;
    let shared = s.upload_blob(&legacy, &random_png(8), "image/png").await;
    let with = |text: &str, blobs: &[&J]| json!({"$type": COLL, "text": text, "images": blobs, "createdAt": "2026-10-01T00:00:00.000Z"});
    a.create_record(&space, COLL, Some("hidden"), with("x", &[&only, &shared])).await.ok();
    a.create_record(&space, COLL, Some("shown"), with("y", &[&shared])).await.ok();
    let cid = |b: &J| b["ref"]["$link"].as_str().unwrap().to_string();
    let cred = a.credential(&space).await;
    let get = async |b: &J| {
        let c = cid(b);
        let q = [("space", space.as_str()), ("repo", a.did.as_str()), ("cid", c.as_str())];
        a.signed_get(&s.url, "com.atproto.space.getBlob", &q, &cred, &a.did).await
    };
    let listed = async || {
        let q = [("space", space.as_str()), ("repo", a.did.as_str())];
        let r = a.signed_get(&s.url, "com.atproto.space.listBlobs", &q, &cred, &a.did).await.ok();
        let mut v: Vec<String> =
            r["cids"].as_array().unwrap().iter().map(|c| c.as_str().unwrap().to_string()).collect();
        v.sort();
        v
    };
    let mut both = vec![cid(&only), cid(&shared)];
    both.sort();
    get(&only).await.ok();
    assert_eq!(listed().await, both);

    let uri = format!("{space}/{}/{COLL}/hidden", a.did);
    set_status(&s, strong_ref(&uri), true).await;
    get(&only).await.err(400, "BlobNotFound");
    get(&shared).await.ok();
    assert_eq!(listed().await, [cid(&shared)]);
    set_status(&s, strong_ref(&uri), false).await;
    get(&only).await.ok();
    assert_eq!(listed().await, both);
}

// ---------------------------------------------------------------- importRepo

use crate::spaces_side::import_repo::stub_plc;

async fn pds(plc: &str, service_did: &str) -> TestServer {
    let (plc, sd) = (plc.to_string(), service_did.to_string());
    TestServer::spawn_with(move |c| {
        c.plc_url = plc;
        c.service_did = sd;
        c.spaces = true;
    })
    .await
}

/// A 2-root CAR of `roots` and `blocks`.
fn car(roots: &[Cid], blocks: &[(Cid, Vec<u8>)]) -> Vec<u8> {
    let mut h = Vec::new();
    vlatproto::cbor::write_map_head(&mut h, 2);
    vlatproto::cbor::write_text(&mut h, "roots");
    vlatproto::cbor::write_array_head(&mut h, roots.len());
    for r in roots {
        vlatproto::cbor::write_cid(&mut h, r);
    }
    vlatproto::cbor::write_text(&mut h, "version");
    vlatproto::cbor::write_uint(&mut h, 1);
    let mut out = Vec::new();
    vlatproto::car::write_varint(&mut out, h.len() as u64);
    out.extend_from_slice(&h);
    for (c, b) in blocks {
        vlatproto::car::write_block(&mut out, c, b);
    }
    out
}

fn commit_block(c: &vlpds::space::commit::SignedCommit) -> Vec<u8> {
    use vlatproto::cbor::*;
    let mut b = Vec::new();
    write_map_head(&mut b, 6);
    for (k, v) in [("ikm", &c.ikm), ("mac", &c.mac)] {
        write_text(&mut b, k);
        write_bytes(&mut b, v);
    }
    write_text(&mut b, "rev");
    write_text(&mut b, &c.rev);
    write_text(&mut b, "sig");
    write_bytes(&mut b, &c.sig);
    write_text(&mut b, "ver");
    write_int(&mut b, c.ver);
    write_text(&mut b, "hash");
    write_bytes(&mut b, &c.hash);
    b
}

fn decode_commit(b: &[u8]) -> vlpds::space::commit::SignedCommit {
    let v = Value::decode(b).unwrap();
    let bytes = |k: &str| match v.get(k) {
        Some(Value::Bytes(b)) => b.clone(),
        _ => panic!("commit.{k}"),
    };
    let rev = match v.get("rev") {
        Some(Value::Text(t)) => t.clone(),
        _ => panic!("commit.rev"),
    };
    vlpds::space::commit::SignedCommit {
        ver: 1,
        hash: bytes("hash"),
        ikm: bytes("ikm"),
        sig: bytes("sig"),
        mac: bytes("mac"),
        rev,
    }
}

/// Export from one PDS with space.getRepo, import into another the account
/// moves to: the same signed set hash at the same rev, and the same
/// records. Tampered or mis-signed CARs are refused before anything lands.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn import_repo_round_trip_and_refusals() {
    let (plc, docs) = stub_plc().await;
    let x = pds(&plc, "did:web:x-pds.test").await;
    let y = pds(&plc, "did:web:y-pds.test").await;
    let a = SpaceClient::new(&x, "simp", OWNER).await;
    let space = a.create_space(TYPE, "main").await;
    let x_acct = TestAccount {
        did: a.did.clone(),
        handle: a.handle.clone(),
        password: String::new(),
        email: String::new(),
        access: a.session_jwt.clone(),
        refresh: String::new(),
    };
    let blob = x.upload_blob(&x_acct, &random_png(7), "image/png").await;
    let blob_cid = blob["ref"]["$link"].as_str().unwrap().to_string();
    for (k, t) in [("aa", "one"), ("bb", "two"), ("ccc", "three")] {
        let mut r = rec(t);
        if k == "aa" {
            r["image"] = blob.clone();
        }
        a.create_record(&space, COLL, Some(k), r).await.ok();
    }
    a.delete_record(&space, COLL, "bb").await.ok();
    let doc =
        x.xrpc.get("com.atproto.identity.resolveDid", &[("did", &a.did)], &Auth::None).await.ok()["didDoc"].clone();
    docs.lock().unwrap().insert(a.did.clone(), doc);
    let rq = [("space", space.as_str()), ("repo", a.did.as_str())];
    let (status, _, exported) = a.get_raw("com.atproto.space.getRepo", &rq).await;
    assert_eq!(status, 200);
    let at_x = a.get("com.atproto.space.getLatestCommit", &rq).await.ok()["commit"].clone();
    let records_x = a.get("com.atproto.space.listRecords", &rq).await.ok()["records"].clone();

    // the account on y; it moves (DID switched, activated), then imports
    // with OAuth: the CAR's commit was signed by x's key, which the DID's
    // PLC history says it held at the rev
    let handle = format!("{}.{HANDLE_DOMAIN}", unique_name("moved"));
    let token = x
        .xrpc
        .get(
            "com.atproto.server.getServiceAuth",
            &[("aud", "did:web:y-pds.test"), ("lxm", "com.atproto.server.createAccount")],
            &Auth::Bearer(a.session_jwt.clone()),
        )
        .await
        .ok()["token"]
        .as_str()
        .unwrap()
        .to_string();
    let body = json!({"handle": handle, "email": format!("{}@example.com", unique_name("m")), "password": crate::oauth::PASSWORD, "did": a.did});
    let created = y.xrpc.post("com.atproto.server.createAccount", &body, &Auth::Bearer(token)).await.ok();
    let jwt = created["accessJwt"].as_str().unwrap().to_string();
    let session = Auth::Bearer(jwt.clone());
    let path = format!("{IMPORT}?space={space}");
    let rdc = y.xrpc.get("com.atproto.identity.getRecommendedDidCredentials", &[], &session).await.ok();
    let key = rdc["verificationMethods"]["atproto"].as_str().unwrap();
    let did = a.did.clone();
    let doc = json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "alsoKnownAs": rdc["alsoKnownAs"],
        "verificationMethod": [{
            "id": format!("{did}#atproto"), "type": "Multikey", "controller": did,
            "publicKeyMultibase": key.strip_prefix("did:key:").unwrap(),
        }],
        "service": [{"id": "#atproto_pds", "type": "AtprotoPersonalDataServer", "serviceEndpoint": rdc["services"]["atproto_pds"]["endpoint"]}],
    });
    // a password session is no space access, before the move or after
    let r = y.xrpc.post_bytes(&path, exported.clone(), CAR, &session).await;
    assert_eq!(r.status, 403, "{}", r.text());
    docs.lock().unwrap().insert(did.clone(), doc);
    y.xrpc.post_empty("com.atproto.server.activateAccount", &session).await.ok();
    let r = y.xrpc.post_bytes(&path, exported.clone(), CAR, &session).await;
    r.err(403, "InsufficientScope");
    let b = SpaceClient::for_account(&y, &a.did, &handle, &jwt, OWNER).await;
    let import = async |car: Vec<u8>| b.post_bytes(IMPORT, &[("space", space.as_str())], car, CAR).await;

    let (roots, blocks) = vlatproto::car::read_car(&exported).unwrap();
    let blocks: Vec<(Cid, Vec<u8>)> = blocks.into_iter().map(|(c, b)| (c, b.to_vec())).collect();
    let (commit_cid, index_cid) = (roots[0], roots[1]);
    let commit = decode_commit(&blocks.iter().find(|(c, _)| *c == commit_cid).unwrap().1);
    let index = Value::decode(&blocks.iter().find(|(c, _)| *c == index_cid).unwrap().1).unwrap();
    let records: Vec<(Cid, Vec<u8>)> =
        blocks.iter().filter(|(c, _)| *c != commit_cid && *c != index_cid).cloned().collect();
    let with_commit = |c: &vlpds::space::commit::SignedCommit| {
        let cb = commit_block(c);
        let cc = Cid::dag_cbor(&cb);
        let mut all = vec![(cc, cb), blocks.iter().find(|(c, _)| *c == index_cid).unwrap().clone()];
        all.extend(records.iter().cloned());
        car(&[cc, index_cid], &all)
    };

    // a MAC that doesn't match
    let mut bad = commit.clone();
    *bad.mac.last_mut().unwrap() ^= 1;
    import(with_commit(&bad)).await.err(400, "InvalidCommit");
    // signed by a key the DID never had
    let Value::Map(entries) = &index else { panic!("index") };
    let mut set = vlpds::space::lthash::LtHash::default();
    for (path, v) in entries {
        let (Value::Link(c), Some((coll, rkey))) = (v, path.split_once('/')) else { panic!("index entry") };
        set.add(&vlpds::space::commit::element(coll, rkey, &c.to_string()));
    }
    let other = vlatproto::crypto::Keypair::generate();
    let ctx = vlpds::space::commit::CommitCtx { space: &space, author: &a.did, rev: &commit.rev };
    let forged = vlpds::space::commit::sign(&set, &ctx, rand::random(), |m| Ok::<_, ()>(other.sign(m))).unwrap();
    import(with_commit(&forged)).await.err(400, "InvalidCommit");
    // a rev far ahead would hold every later notify past the authority's
    // FutureRev window
    let ahead = vlatproto::tid::Tid::from_parts(vlatproto::tid::now_micros() + 3_600_000_000, 0).to_string();
    let ctx = vlpds::space::commit::CommitCtx { space: &space, author: &a.did, rev: &ahead };
    let future = vlpds::space::commit::sign(&set, &ctx, rand::random(), |m| Ok::<_, ()>(other.sign(m))).unwrap();
    import(with_commit(&future)).await.err(400, "FutureRev");
    // an index that isn't the signed set: a record left out
    let fewer = Value::Map(entries[1..].to_vec());
    let mut ib = Vec::new();
    fewer.encode(&mut ib);
    let ic = Cid::dag_cbor(&ib);
    let mut all = vec![blocks.iter().find(|(c, _)| *c == commit_cid).unwrap().clone(), (ic, ib)];
    all.extend(records.iter().cloned());
    import(car(&[commit_cid, ic], &all)).await.err(400, "DigestMismatch");
    // a record block missing
    let mut short = blocks.clone();
    short.pop();
    import(car(&roots, &short)).await.err(400, "InvalidRequest");
    // an active account's password session is no space access
    let r = x.xrpc.post_bytes(&path, exported.clone(), CAR, &Auth::Bearer(a.session_jwt.clone())).await;
    r.err(403, "InsufficientScope");

    let r = import(exported.clone()).await.ok();
    assert_eq!((r["rev"].clone(), r["records"].clone()), (at_x["rev"].clone(), json!(2)));
    // the imported record's blob hasn't come over yet
    let lm = y.xrpc.get("com.atproto.repo.listMissingBlobs", &[], &session).await.ok();
    assert_eq!(lm["blobs"], json!([{"cid": blob_cid, "recordUri": format!("{space}/{}/{COLL}/aa", a.did)}]), "{lm}");
    // the same export again is a retry: answered as before, nothing written
    let again = import(exported.clone()).await.ok();
    assert_eq!((again["rev"].clone(), again["records"].clone()), (at_x["rev"].clone(), json!(2)));

    let at_y = b.get("com.atproto.space.getLatestCommit", &rq).await.ok()["commit"].clone();
    assert_eq!((at_y["hash"].clone(), at_y["rev"].clone()), (at_x["hash"].clone(), at_x["rev"].clone()));
    assert_eq!(b.get("com.atproto.space.listRecords", &rq).await.ok()["records"], records_x);
    // the oplog starts empty; the next write follows the imported rev
    let ops = b.get("com.atproto.space.listRepoOps", &rq).await.ok();
    assert_eq!(ops["ops"], json!([]), "{ops}");
    b.create_record(&space, COLL, Some("dd"), rec("four")).await.ok();
    let next = b.get("com.atproto.space.getLatestCommit", &rq).await.ok()["commit"]["rev"].clone();
    assert!(next.as_str().unwrap() > at_x["rev"].as_str().unwrap(), "{next} after {}", at_x["rev"]);
    // check-space takes the imported base without its ops
    let chk =
        y.xrpc.get("vlpds.admin.checkSpace", &[("did", a.did.as_str()), ("space", space.as_str())], &Auth::Admin).await;
    assert_eq!(chk.ok()["ok"], json!(true), "{}", chk.json);
    assert_eq!(chk.json["records"]["count"], json!(3));
    // its report names paths: an audited operator read
    let log = y.xrpc.get("vlpds.admin.getAuditLog", &[("did", a.did.as_str())], &Auth::Admin).await.ok();
    let checks = log["entries"].as_array().unwrap().iter().filter(|e| e["detail"]["method"] == "checkSpace").count();
    assert_eq!(checks, 1, "{log}");
}

/// Rows an import staged before it stopped (no head over them) are never
/// served, and the repo's first write clears them before it lands: it's a
/// create over nothing, and the repo then holds only what was written.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rows_left_by_a_stopped_import_are_cleared_by_the_first_write() {
    let s = spawn().await;
    let a = SpaceClient::new(&s, "sun", OWNER).await;
    let m = SpaceClient::new(&s, "sum", MEMBER).await;
    let space = a.create_space(TYPE, "main").await;
    put_member(&a, &space, &m.did).await;
    let sid = vlpds::state::space_id(&space);
    let p = s.app.partition(&m.did).ok().unwrap();
    let bytes = [0xa1, 0x61, 0x61, 0x01];
    let cid = Cid::dag_cbor(&bytes);
    for rk in ["x", "y"] {
        let k = vlpds::state::space_record_key(&m.did, &sid, &format!("{COLL}/{rk}"));
        p.db.put(k, vlpds::state::record_value(&cid, 1, &bytes).to_vec()).await.unwrap();
    }
    let rq = [("space", space.as_str()), ("repo", m.did.as_str())];
    assert_eq!(m.get("com.atproto.space.listRecords", &rq).await.ok()["records"], json!([]), "no head: nothing served");

    m.create_record(&space, COLL, Some("x"), rec("new")).await.ok();
    let records = m.get("com.atproto.space.listRecords", &rq).await.ok()["records"].clone();
    let texts: Vec<&J> = records.as_array().unwrap().iter().map(|r| &r["value"]["text"]).collect();
    assert_eq!(texts, [&json!("new")], "{records}");
    let chk =
        s.xrpc.get("vlpds.admin.checkSpace", &[("did", m.did.as_str()), ("space", space.as_str())], &Auth::Admin).await;
    assert_eq!(chk.ok()["ok"], json!(true), "{}", chk.json);
    assert_eq!(chk.json["records"]["count"], json!(1));
    m.create_record(&space, COLL, Some("y"), rec("another")).await.ok();
}
