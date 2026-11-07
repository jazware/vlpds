//! `com.atproto.space.importRepo`: a space repo exported with getRepo (a
//! STAR archive) comes back in on another host, its records checked the
//! way `@atproto/space`'s `readRepoStar` checks them, at a new rev after
//! the archive's, with an empty oplog, and served as it was.
//!
//! - From the reference: testdata/spaces-alpha/export.star, written by the
//!   reference's own serializer (gen-export.mjs), imported mid-migration.
//! - vlpds to vlpds: a member's repo moves between two vlpds hosts with the
//!   account, its blobs following through listMissingBlobs.
//! - Refusals: a tampered or malformed archive, a commit naming another
//!   account, records that don't fold to the commit's data, over
//!   `--space-repo-max-records`, collections the grant doesn't name, the
//!   authority's own repo in a space it doesn't have, and anything but
//!   OAuth. A refused import into an empty repo writes nothing.
//!
//! importRepo is OAuth-only, and OAuth signs no deactivated account in, so
//! a move imports once the DID points at the new host and the account is
//! active there. The archive carries no MAC: it's the account's own data,
//! uploaded on its own grant. An import over a repo that's there replaces
//! it.

use super::phase3::*;
use super::ref_net::*;
use crate::common::spaces::{Holder, SpaceClient};
use crate::common::*;
use crate::oauth;
use axum::extract::{Path, State};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const EXPORT_STAR: &[u8] = include_bytes!("../../../testdata/spaces-alpha/export.star");
const EXPORT_JSON: &str = include_str!("../../../testdata/spaces-alpha/export.json");

pub(crate) type Docs = Arc<Mutex<DocMap>>;

/// Each DID's document.
#[derive(Default)]
pub(crate) struct DocMap {
    docs: HashMap<String, J>,
}

impl DocMap {
    pub fn get(&self, did: &str) -> Option<&J> {
        self.docs.get(did)
    }

    pub fn insert(&mut self, did: String, doc: J) -> Option<J> {
        self.docs.insert(did, doc)
    }
}

/// A PLC directory stand-in serving whatever documents a test puts in it
/// (tests/all/migration.rs's): a DID moves between hosts by a test
/// replacing its document.
pub(crate) async fn stub_plc() -> (String, Docs) {
    let docs: Docs = Arc::default();
    let app = axum::Router::new()
        .route(
            "/{did}",
            axum::routing::get(|State(d): State<Docs>, Path(did): Path<String>| async move {
                match d.lock().unwrap().get(&did) {
                    Some(doc) => Ok(axum::Json(doc.clone())),
                    None => Err(axum::http::StatusCode::NOT_FOUND),
                }
            }),
        )
        .with_state(docs.clone());
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    (url, docs)
}

/// A `--spaces` host on the stub directory.
pub(super) async fn stub_host(plc: &str, i: usize) -> TestServer {
    let plc = plc.to_string();
    TestServer::spawn_with(move |c| {
        c.plc_url = plc;
        c.service_did = format!("did:web:pds{i}.test");
        c.spaces = true;
    })
    .await
}

/// Puts `did`'s document, as `s` publishes it, in the directory.
pub(super) async fn publish(docs: &Docs, s: &TestServer, did: &str) {
    let doc = s.xrpc.get("com.atproto.identity.resolveDid", &[("did", did)], &Auth::None).await.ok()["didDoc"].clone();
    docs.lock().unwrap().insert(did.to_string(), doc);
}

/// A [`SpaceClient`] on `s` for an existing account (signed in with
/// `oauth::PASSWORD`), granted `scope`.
pub(super) async fn oauth_client(s: &TestServer, did: &str, handle: &str, jwt: &str, scope: &str) -> SpaceClient {
    let srv = oauth::Srv {
        app: s.app.clone(),
        base: s.url.clone(),
        http: reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().unwrap(),
    };
    let acct = oauth::Account { did: did.into(), handle: handle.into(), jwt: jwt.into() };
    let key = oauth::DpopKey::new();
    let scope = format!("atproto {scope}");
    let t = oauth::grant(&srv, &mut oauth::Browser::default(), &oauth::Flow::loopback(&scope, &key), &acct).await;
    SpaceClient {
        srv,
        did: did.into(),
        handle: handle.into(),
        session_jwt: jwt.into(),
        key,
        access: t.access,
        scope: t.scope,
        holder: Holder::new(),
    }
}

/// An account with an existing DID created on `new` (deactivated until the
/// DID moves), given the old host's service auth for it.
pub(super) struct Arrived {
    pub did: String,
    pub handle: String,
    /// The createAccount session: public methods (not space data).
    pub session: Auth,
}

impl Arrived {
    /// The account's OAuth grant on `new`, once it's active there.
    pub async fn oauth(&self, new: &TestServer) -> SpaceClient {
        let Auth::Bearer(jwt) = &self.session else { unreachable!() };
        oauth_client(new, &self.did, &self.handle, jwt, FULL_SCOPE).await
    }

    /// importRepo on the account's OAuth grant: once it's active.
    pub async fn import(&self, new: &TestServer, star: &[u8]) -> Resp {
        import_repo(&self.oauth(new).await, star).await
    }
}

pub(super) async fn arrive(new: &TestServer, did: &str, service_auth: String) -> Arrived {
    let handle = format!("{}.{HANDLE_DOMAIN}", unique_name("moved"));
    let body = json!({"handle": handle, "email": format!("{}@example.com", unique_name("moved")), "password": oauth::PASSWORD, "did": did});
    let created = new.xrpc.post("com.atproto.server.createAccount", &body, &Auth::Bearer(service_auth)).await.ok();
    assert_eq!(created["did"], json!(did));
    let jwt = created["accessJwt"].as_str().unwrap().to_string();
    let st = new.xrpc.get("com.atproto.server.checkAccountStatus", &[], &Auth::Bearer(jwt.clone())).await.ok();
    assert_eq!(st["activated"], json!(false), "{st}");
    Arrived { did: did.into(), handle, session: Auth::Bearer(jwt) }
}

/// A DID document's `verificationMethod`s for getRecommendedDidCredentials'
/// keys (`atproto`, and `atproto_kem` when the host holds one).
pub(crate) fn verification_methods(did: &str, recommended: &J) -> J {
    let mut out = Vec::new();
    for name in ["atproto", "atproto_kem"] {
        if let Some(key) = recommended["verificationMethods"][name].as_str() {
            out.push(json!({
                "id": format!("{did}#{name}"), "type": "Multikey", "controller": did,
                "publicKeyMultibase": key.strip_prefix("did:key:").unwrap(),
            }));
        }
    }
    J::Array(out)
}

/// Points the DID at `new` with the keys it recommends, and activates there.
pub(super) async fn complete_move(docs: &Docs, new: &TestServer, a: &Arrived) {
    let rec = new.xrpc.get("com.atproto.identity.getRecommendedDidCredentials", &[], &a.session).await.ok();
    let doc = json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": a.did,
        "alsoKnownAs": rec["alsoKnownAs"],
        "verificationMethod": verification_methods(&a.did, &rec),
        "service": [{"id": "#atproto_pds", "type": "AtprotoPersonalDataServer", "serviceEndpoint": new.url}],
    });
    docs.lock().unwrap().insert(a.did.clone(), doc);
    new.xrpc.post_empty("com.atproto.server.activateAccount", &a.session).await.ok();
}

async fn missing_blobs(s: &TestServer, auth: &Auth) -> Vec<String> {
    let r = s.xrpc.get("com.atproto.repo.listMissingBlobs", &[], auth).await.ok();
    r["blobs"].as_array().unwrap().iter().map(|b| b["cid"].as_str().unwrap().to_string()).collect()
}

/// check-space on the account's host checks the imported repo clean.
async fn check_space_ok(s: &TestServer, did: &str, space: &str) {
    let (r, out) = admin_cli(&s.url, &["--json", "check-space", did, space]).await;
    assert!(r.is_ok(), "check-space: {out}");
    let j: J = serde_json::from_str(&out).unwrap();
    assert_eq!(j["ok"], json!(true), "{j}");
}

/// The owner's view of its repo: getLatestCommit's (rev, hash).
async fn head(sc: &SpaceClient, space: &str) -> Option<(String, Vec<u8>)> {
    repo_state(sc, space).await
}

// ---------------------------------------------------------------------------
// the reference's export
// ---------------------------------------------------------------------------

struct Fixture {
    j: J,
    did: String,
    space: String,
    rev: String,
}

fn fixture() -> Fixture {
    let j: J = serde_json::from_str(EXPORT_JSON).unwrap();
    Fixture {
        did: j["did"].as_str().unwrap().into(),
        space: j["space"].as_str().unwrap().into(),
        rev: j["rev"].as_str().unwrap().into(),
        j,
    }
}

/// The reference's archive passes our port of verifyRepoStarFull, and the
/// same commit and records write back to the same bytes: the reference and
/// vlpds agree on the export format (framing, metadata encoding, bytewise
/// path order), which is what an import reads.
#[test]
fn reference_export_verifies_and_reencodes() {
    let f = fixture();
    let v = verify_repo_star(EXPORT_STAR, &f.space, &f.did)
        .unwrap_or_else(|e| panic!("the reference's export doesn't verify: {e}"));
    assert_eq!(v.commit.rev, f.rev);
    assert_eq!(hex::encode(v.commit.data), f.j["data"].as_str().unwrap());
    let want: Vec<(String, String)> = f.j["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            (
                format!("{}/{}", r["collection"].as_str().unwrap(), r["rkey"].as_str().unwrap()),
                r["cid"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    let mut sorted = want.clone();
    sorted.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    assert_eq!(want, sorted, "the reference wrote its records in bytewise path order");
    let got: Vec<(String, String)> = v.records.iter().map(|(p, c, _)| (p.clone(), c.to_string())).collect();
    assert_eq!(got, want);
    // the blob is named by a record, as a link
    let blob = f.j["blob"]["cid"].as_str().unwrap();
    assert!(v.records.iter().any(|(_, _, b)| Value::decode(b).unwrap().to_json().to_string().contains(blob)));

    let pairs: Vec<(Vec<u8>, Vec<u8>)> = v.records.iter().map(|(p, _, b)| (p.as_bytes().to_vec(), b.clone())).collect();
    assert_eq!(
        write_star(&star::repo_meta(&v.commit), &pairs, true),
        EXPORT_STAR,
        "the archive re-encodes byte for byte"
    );

    // and a commit for another repo or space is refused by the same checks
    assert!(verify_repo_star(EXPORT_STAR, &f.space, "did:plc:someoneelse2345abcdefgh").is_err());
    assert!(verify_repo_star(EXPORT_STAR, &format!("{}x", f.space), &f.did).is_err());
}

/// The reference account's document, before the move.
fn reference_doc(f: &Fixture, key: &vlatproto::crypto::Keypair) -> J {
    json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": f.did,
        "alsoKnownAs": ["at://refexport.example"],
        "verificationMethod": [{
            "id": format!("{}#atproto", f.did), "type": "Multikey", "controller": f.did,
            "publicKeyMultibase": key.did_key().strip_prefix("did:key:").unwrap(),
        }],
        "service": [{"id": "#atproto_pds", "type": "AtprotoPersonalDataServer", "serviceEndpoint": "http://127.0.0.1:9"}],
    })
}

/// A reference-hosted account (its key the test's) arrived on `new`, its
/// DID moved there and the account active.
async fn reference_arrival(f: &Fixture, docs: &Docs, new: &TestServer) -> Arrived {
    let key = vlatproto::crypto::Keypair::generate();
    docs.lock().unwrap().insert(f.did.clone(), reference_doc(f, &key));
    let new_did = new.pds_did().await;
    let sa =
        vlpds::auth::service_auth_jwt(&key, &f.did, &new_did, Some("com.atproto.server.createAccount"), 60).unwrap();
    let a = arrive(new, &f.did, sa).await;
    complete_move(docs, new, &a).await;
    a
}

/// The fixture's space, made again by its authority (the fixture account)
/// on the host it moved to.
async fn make_fixture_space(f: &Fixture, sc: &SpaceClient) {
    assert_eq!(sc.create_space(TEST_SPACE_TYPE, last_segment(&f.space)).await, f.space);
}

/// A reference-hosted account moves to vlpds with its space repo: created
/// with its DID, the DID moved and the account activated, then the
/// reference's getRepo archive imported with OAuth, the record's blob
/// listed missing until uploaded. vlpds then serves the same repo (the
/// same data and records) at a new rev after the archive's.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reference_export_imports_mid_migration() {
    let f = fixture();
    let (plc, docs) = stub_plc().await;
    let new = stub_host(&plc, 1).await;
    let a = reference_arrival(&f, &docs, &new).await;
    let oauth = a.oauth(&new).await;
    // the account governs the space: its own repo comes after the space
    import_repo(&oauth, EXPORT_STAR).await.err(400, "SpaceNotFound");
    make_fixture_space(&f, &oauth).await;

    let out = import_repo(&oauth, EXPORT_STAR).await;
    assert_eq!(out.status, 200, "{}", out.text());
    assert!(out.body.is_empty(), "importRepo answers with no body: {}", out.text());
    check_space_ok(&new, &f.did, &f.space).await;
    let (rev, data) = head(&oauth, &f.space).await.unwrap();
    assert!(rev > f.rev, "a new rev after the archive's: {rev} vs {}", f.rev);
    assert_eq!(hex::encode(data), f.j["data"].as_str().unwrap());

    // the migration copies the record's blob, which listMissingBlobs names
    let blob = f.j["blob"]["cid"].as_str().unwrap().to_string();
    assert_eq!(missing_blobs(&new, &a.session).await, vec![blob.clone()]);
    let bytes = hex::decode(f.j["blob"]["bytesHex"].as_str().unwrap()).unwrap();
    let up = new.xrpc.post_bytes("com.atproto.repo.uploadBlob", bytes, "image/png", &a.session).await.ok();
    assert_eq!(up["blob"]["ref"]["$link"], json!(blob));
    assert!(missing_blobs(&new, &a.session).await.is_empty());
    expect_set_hash_matches_store(&oauth, &f.space).await;
    let r = get_repo_self(&oauth, &f.space).await;
    assert_eq!(r.status, 200, "{}", r.text());
    let mine = verify_repo_star(&r.body, &f.space, &f.did)
        .unwrap_or_else(|e| panic!("vlpds's getRepo after the import doesn't verify: {e}"));
    let theirs = verify_repo_star(EXPORT_STAR, &f.space, &f.did).unwrap();
    assert_eq!((mine.commit.rev.as_str(), mine.commit.data), (rev.as_str(), theirs.commit.data));
    assert_eq!(mine.records, theirs.records, "the same records, in the same order");
    let b = dpop_raw(
        &oauth,
        &new.url,
        reqwest::Method::GET,
        "com.atproto.space.getBlob",
        &[("space", &f.space), ("repo", &f.did), ("cid", &blob)],
        None,
    )
    .await;
    assert_eq!((b.status, b.body.to_vec()), (200, hex::decode(f.j["blob"]["bytesHex"].as_str().unwrap()).unwrap()));

    // the oplog starts empty at the import's rev; the next write follows it
    let ops = oauth.get("com.atproto.space.listRepoOps", &[("space", &f.space), ("repo", &f.did)]).await.ok();
    assert_eq!(ops["ops"], json!([]), "{ops}");
    assert_eq!(ops["commit"]["rev"], json!(rev), "{ops}");
    let w = write(&oauth, &f.space, W::new().rkey("after-import").text("written on vlpds")).await.ok();
    let (after, _) = head(&oauth, &f.space).await.unwrap();
    assert!(after > rev, "a write after the import moves past its rev: {after} vs {rev}");
    assert!(w["uri"].as_str().unwrap().ends_with("/after-import"), "{w}");
    let ops = oauth
        .get("com.atproto.space.listRepoOps", &[("space", &f.space), ("repo", &f.did), ("since", &rev)])
        .await
        .ok();
    let mut set = LtHash::default();
    for (p, c) in theirs.set() {
        let (coll, rkey) = p.split_once('/').unwrap();
        set.add(&vlpds::space::commit::element(coll, rkey, &c));
    }
    for op in ops["ops"].as_array().unwrap() {
        super::fuzz::fold(&mut set, op);
    }
    assert!(commit_matches(&set, &ops["commit"]), "the imported set plus the new ops is the head");
    check_space_ok(&new, &f.did, &f.space).await;
}

use vlpds::space::lthash::LtHash;
use vlpds::space::star;

/// The reference export's record names a blob the new host doesn't hold
/// yet: listMissingBlobs lists it until the migration uploads it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn imported_space_blobs_are_listed_missing() {
    let f = fixture();
    let (plc, docs) = stub_plc().await;
    let new = stub_host(&plc, 1).await;
    let a = reference_arrival(&f, &docs, &new).await;
    make_fixture_space(&f, &a.oauth(&new).await).await;
    a.import(&new, EXPORT_STAR).await.ok();
    let blob = f.j["blob"]["cid"].as_str().unwrap().to_string();
    assert_eq!(missing_blobs(&new, &a.session).await, vec![blob]);
}

// ---------------------------------------------------------------------------
// vlpds to vlpds
// ---------------------------------------------------------------------------

/// Two hosts on the stub directory, bob moving from the first to the
/// second; alice governs a space on a third, bob (a member, on the first)
/// writes into it, carol (on the first) reads. The authority isn't on bob's
/// old host: these hosts run with unregistered DIDs, so that host would
/// keep verifying bob by its own document after he left, where a directory
/// host resolves the moved DID.
pub(super) struct TwoHosts {
    pub docs: Docs,
    pub a: TestServer,
    pub b: TestServer,
    /// alice's host.
    pub c: TestServer,
    pub alice: SpaceClient,
    pub bob: SpaceClient,
    pub carol: SpaceClient,
    pub space: String,
}

pub(super) async fn two_hosts() -> TwoHosts {
    let (plc, docs) = stub_plc().await;
    let (a, b, c) = (stub_host(&plc, 0).await, stub_host(&plc, 1).await, stub_host(&plc, 2).await);
    let mut who = Vec::new();
    for (name, host) in [("alice", &c), ("bob", &a), ("carol", &a)] {
        let sc = SpaceClient::new(host, &unique_name(name), FULL_SCOPE).await;
        publish(&docs, host, &sc.did).await;
        who.push(sc);
    }
    let carol = who.pop().unwrap();
    let bob = who.pop().unwrap();
    let alice = who.pop().unwrap();
    let space = format!("at://{}/space/{TEST_SPACE_TYPE}/{}", alice.did, unique_name("mv"));
    let skey = last_segment(&space).to_string();
    let r = alice
        .post(
            "com.atproto.simplespace.createSpace",
            json!({"spaceType": TEST_SPACE_TYPE, "skey": skey, "readPolicy": member_list(), "writePolicy": member_list(), "appAccess": open()}),
        )
        .await;
    assert_eq!(r.ok()["uri"], json!(space));
    for m in [&bob, &carol] {
        put_member(&alice, &space, m, true, true).await.ok();
    }
    TwoHosts { docs, a, b, c, alice, bob, carol, space }
}

/// bob's writes: creates, an update, a delete and a record naming a blob.
/// Returns the blob's CID and bytes.
pub(super) async fn fill_bob(h: &TwoHosts) -> (String, Vec<u8>) {
    for i in 0..6 {
        write(&h.bob, &h.space, W::new().rkey(&format!("r{i}")).text(&format!("bob {i}"))).await.ok();
    }
    put(&h.bob, &h.space, W::new().rkey("r1").text("bob 1, revised")).await.ok();
    del(&h.bob, &h.space, None, "r2").await.ok();
    let bytes = format!("\u{89}PNG\r\n\x1a\n bob's space image {}", unique_name("img")).into_bytes();
    let blob = upload_blob(&h.bob, &bytes).await;
    let rec = json!({"$type": TEST_COLLECTION, "text": "with an image", "image": blob});
    write(&h.bob, &h.space, W::new().rkey("img").record(rec)).await.ok();
    (blob_cid(&blob), bytes)
}

/// bob moves to host b: exported from host a, the DID switched and the
/// account activated on b, then his space repo imported there with his
/// OAuth grant (the first value) and its blobs copied as listMissingBlobs
/// asks.
pub(super) async fn move_bob(h: &TwoHosts, blob: &(String, Vec<u8>)) -> (SpaceClient, VerifiedRepo) {
    let b_did = h.b.pds_did().await;
    let sa = service_jwt(&h.bob, &b_did, "com.atproto.server.createAccount").await;
    let arrived = arrive(&h.b, &h.bob.did, sa).await;
    let r = get_repo_self(&h.bob, &h.space).await;
    assert_eq!(r.status, 200, "{}", r.text());
    let exported = verify_repo_star(&r.body, &h.space, &h.bob.did).unwrap();
    complete_move(&h.docs, &h.b, &arrived).await;
    let moved = arrived.oauth(&h.b).await;
    import_repo(&moved, &r.body).await.ok();
    // the blob from the old host's space.getBlob, as the migrate page copies it
    let (status, _, got) = h
        .bob
        .get_raw("com.atproto.space.getBlob", &[("space", &h.space), ("repo", &h.bob.did), ("cid", &blob.0)])
        .await;
    assert_eq!((status, &got), (200, &blob.1));
    assert_eq!(missing_blobs(&h.b, &arrived.session).await, vec![blob.0.clone()]);
    h.b.xrpc.post_bytes("com.atproto.repo.uploadBlob", got, "image/png", &arrived.session).await.ok();
    assert!(missing_blobs(&h.b, &arrived.session).await.is_empty());
    (moved, exported)
}

/// bob's space repo moves from one vlpds host to another with his account:
/// the head's data (at a new rev), the records, the blob refs and an empty
/// oplog; check-space passes; carol's credential reads the same records
/// from the new host; the authority hears the new host's writes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn vlpds_export_imports_on_another_vlpds() {
    let h = two_hosts().await;
    let blob = fill_bob(&h).await;
    let before = head(&h.bob, &h.space).await.unwrap();
    let cred_a = h.carol_cred().await;
    let records_a = listed(&h.a.url, &cred_a, &h.space, &h.bob.did).await;
    assert_eq!(records_a.len(), 6);

    let (moved, exported) = move_bob(&h, &blob).await;
    let moved = &moved;
    let (rev, data) = head(moved, &h.space).await.unwrap();
    assert_eq!(data, before.1, "the data moves as it was");
    assert!(rev > before.0, "at a new rev: {rev} vs {}", before.0);
    expect_set_hash_matches_store(moved, &h.space).await;
    check_space_ok(&h.b, &h.bob.did, &h.space).await;
    let ops = moved.get("com.atproto.space.listRepoOps", &[("space", &h.space), ("repo", &h.bob.did)]).await.ok();
    assert_eq!(ops["ops"], json!([]), "the oplog starts empty: {ops}");
    assert_eq!(ops["commit"]["rev"], json!(rev));
    let lb = moved.get("com.atproto.space.listBlobs", &[("space", &h.space), ("repo", &h.bob.did)]).await.ok();
    assert_eq!(lb["cids"], json!([blob.0]), "{lb}");

    h.a.xrpc
        .post("com.atproto.server.deactivateAccount", &json!({}), &Auth::Bearer(h.bob.session_jwt.clone()))
        .await
        .ok();
    let r = get_repo_self(moved, &h.space).await;
    let served = verify_repo_star(&r.body, &h.space, &h.bob.did)
        .unwrap_or_else(|e| panic!("the new host's getRepo doesn't verify: {e}"));
    assert_eq!(served.records, exported.records);
    assert_eq!((served.commit.rev, served.commit.data), (rev.clone(), exported.commit.data));

    // carol's credential (from the authority on c) reads bob at b
    let cred = h.carol_cred().await;
    assert_eq!(listed(&h.b.url, &cred, &h.space, &h.bob.did).await, records_a);
    let latest =
        cred.get(&h.b.url, "com.atproto.space.getLatestCommit", &[("space", &h.space), ("repo", &h.bob.did)]).await;
    assert_eq!(latest.ok()["commit"]["rev"], json!(rev));

    // bob writes on b: the authority on c hears the newer rev
    write(moved, &h.space, W::new().rkey("on-b").text("from the new host")).await.ok();
    let (rev, _) = head(moved, &h.space).await.unwrap();
    let mut seen = J::Null;
    for _ in 0..100 {
        seen = cred.get(&h.c.url, "com.atproto.space.listRepos", &[("space", &h.space)]).await.ok();
        let bob = seen["repos"].as_array().unwrap().iter().find(|x| x["did"] == json!(h.bob.did));
        if bob.is_some_and(|b| b["repoRev"] == json!(rev)) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let bob = seen["repos"].as_array().unwrap().iter().find(|x| x["did"] == json!(h.bob.did));
    assert_eq!(
        bob.map(|b| &b["repoRev"]),
        Some(&json!(rev)),
        "the authority's listRepos after bob wrote on the new host: {seen}"
    );
    let mut s = Syncer::new(&h.b.url, &h.space, &h.bob.did, cred);
    s.full().await;
    let now = listed(&h.b.url, &h.carol_cred().await, &h.space, &h.bob.did).await;
    assert_eq!(now.len(), records_a.len() + 1);
    assert!(records_a.iter().all(|(p, c)| now.get(p) == Some(c)), "{now:?}");
    assert_eq!(s.set, now);
}

impl TwoHosts {
    pub(super) async fn carol_cred(&self) -> Cred {
        let token = delegation_token(&self.carol, &self.space).await;
        let holder = Holder::new();
        let r = exchange(&reqwest::Client::new(), &holder, &self.c.url, &self.space, &token, None).await;
        Cred { credential: r.ok()["credential"].as_str().unwrap().to_string(), holder, http: reqwest::Client::new() }
    }
}

// ---------------------------------------------------------------------------
// imports on one host, and refusals
// ---------------------------------------------------------------------------

/// alice governs a space on one host; bob may write in it.
struct One {
    net: Net,
    alice: SpaceClient,
    bob: SpaceClient,
    space: String,
}

async fn one() -> One {
    let net = Net::new(0).await;
    let (alice, bob) = (net.actor("alice", 0).await, net.actor("bob", 0).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&bob], ..Default::default() }).await;
    One { net, alice, bob, space }
}

fn records(b: RepoBuilder, n: usize) -> RepoBuilder {
    (0..n).fold(b, |b, i| {
        b.record(TEST_COLLECTION, &format!("imp{i:04}"), record(TEST_COLLECTION, &format!("imported {i}")))
    })
}

async fn nothing_written(sc: &SpaceClient, space: &str, what: &str) {
    assert_eq!(head(sc, space).await, None, "{what}: a refused import wrote a repo");
}

/// A repo bob never wrote here (a restore from his backup): imported at a
/// new rev after the archive's, served, then written on; the authority
/// sequences it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn imports_a_restored_repo_and_takes_writes_after() {
    let o = one().await;
    let s = &o.net.pds[0];
    let rev = rev_ago(Duration::from_secs(90));
    let b = records(RepoBuilder::new(&o.space, &o.bob.did, &rev), 7);
    let built = b.build();
    let r = import_repo(&o.bob, &built.star()).await;
    assert_eq!((r.status, r.body.len()), (200, 0), "{}", r.text());
    let (at, data) = head(&o.bob, &o.space).await.unwrap();
    assert!(at > rev, "{at} after {rev}");
    assert_eq!(data, b.set().digest().to_vec());
    check_space_ok(s, &o.bob.did, &o.space).await;
    let writers = o.net.await_writer(&o.alice, &o.space, &o.bob.did).await;
    assert!(writers.contains(&o.bob.did), "the authority sequences the imported repo: {writers:?}");

    let cred = o.net.credential_for(&o.alice, &o.space).await;
    let got = listed(&s.url, &cred, &o.space, &o.bob.did).await;
    let want: std::collections::BTreeMap<String, String> =
        built.records.iter().map(|(p, c, _)| (p.clone(), c.to_string())).collect();
    assert_eq!(got, want);
    write(&o.bob, &o.space, W::new().rkey("later").text("after the restore")).await.ok();
    let (after, _) = head(&o.bob, &o.space).await.unwrap();
    assert!(after > at);
    expect_set_hash_matches_store(&o.bob, &o.space).await;
}

/// A record's map with its integer in a non-minimal encoding: valid CBOR,
/// not canonical DRISL.
fn non_canonical_record() -> Vec<u8> {
    let mut b = Vec::new();
    vlatproto::cbor::write_map_head(&mut b, 2);
    vlatproto::cbor::write_text(&mut b, "n");
    b.extend_from_slice(&[0x18, 0x01]);
    vlatproto::cbor::write_text(&mut b, "$type");
    vlatproto::cbor::write_text(&mut b, TEST_COLLECTION);
    b
}

/// The reference's readRepoStar refuses each of these, and so does the
/// import, writing nothing: a record's bytes changed, a record missing or
/// one extra (the records no longer fold to the commit's data), keys out of
/// order or a duplicate, a record that isn't canonical DRISL (even with the
/// data computed over its CID), a truncated archive (no end byte), bytes
/// after the end, an unknown control byte, a value over STAR's 1 MiB limit,
/// and something that isn't STAR at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_a_tampered_star() {
    let o = one().await;
    let rev = rev_ago(Duration::from_secs(60));
    let b = records(RepoBuilder::new(&o.space, &o.bob.did, &rev), 4);
    let built = b.build();
    assert!(verify_repo_star(&built.star(), &o.space, &o.bob.did).is_ok());

    let mut nc = RepoBuilder::new(&o.space, &o.bob.did, &rev);
    let bytes = non_canonical_record();
    nc.records.insert(format!("{TEST_COLLECTION}/nc"), (Cid::dag_cbor(&bytes), bytes));
    let mut truncated = built.star();
    truncated.pop();
    let mut trailing = built.star();
    trailing.push(0);
    let mut control = built.star();
    *control.last_mut().unwrap() = 2;
    let cases: Vec<(&str, Vec<u8>)> = vec![
        (
            "a record's bytes changed",
            built.star_with(|p| p[3].1 = record_block(&record(TEST_COLLECTION, "tampered")).1),
        ),
        ("a record missing", built.star_with(|p| drop(p.remove(2)))),
        (
            "an extra record",
            built.star_with(|p| p.push((format!("{TEST_COLLECTION}/zzz").into_bytes(), p[0].1.clone()))),
        ),
        ("records out of order", built.star_with(|p| p.swap(1, 2))),
        (
            "a duplicate key",
            built.star_with(|p| {
                let dup = p[1].clone();
                p.insert(2, dup)
            }),
        ),
        ("a record not canonical DRISL", nc.build().star()),
        ("no end byte", truncated),
        ("bytes after the end", trailing),
        ("an unknown control byte", control),
        (
            "a value over 1 MiB",
            built.star_with(|p| p.push((format!("{TEST_COLLECTION}/zzz").into_bytes(), vec![0xa0; (1 << 20) + 1]))),
        ),
        ("not STAR", b"not a star archive at all".to_vec()),
    ];
    for (what, star) in &cases {
        assert!(verify_repo_star(star, &o.space, &o.bob.did).is_err(), "{what}: the reference would accept it");
        let r = import_repo(&o.bob, star).await;
        assert_eq!(r.status, 400, "{what}: {}", r.text());
        nothing_written(&o.bob, &o.space, what).await;
    }
    import_repo(&o.bob, &built.star()).await.ok();
}

/// The commit must name the importing account, and the records must fold
/// to its data: alice's repo imported by bob, and a commit whose data was
/// rebound to another set, are refused. The archive names its space: bob's
/// repo for another space goes there, not into the one he's in.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_a_commit_for_another_account_or_data() {
    let o = one().await;
    let rev = rev_ago(Duration::from_secs(60));
    let alices = records(RepoBuilder::new(&o.space, &o.alice.did, &rev), 2).build();
    let r = import_repo(&o.bob, &alices.star()).await;
    refused_mentioning(&r, &["does not match the authenticated account"]);
    nothing_written(&o.bob, &o.space, "another DID's repo").await;

    let b = records(RepoBuilder::new(&o.space, &o.bob.did, &rev), 3);
    let mut other = b.set();
    other.add("com.example.x/y/bafyreie5737gdxlw5i64vzichcalba3z2v5n6icifvx5xytvske7mr3hpm");
    let rebound = b.build_with(&other);
    assert!(verify_repo_star(&rebound.star(), &o.space, &o.bob.did).is_err());
    let r = import_repo(&o.bob, &rebound.star()).await;
    refused_mentioning(&r, &["do not match the commit"]);
    nothing_written(&o.bob, &o.space, "a rebound data").await;

    let elsewhere = o.net.create_space(&o.alice, SpaceOpts { members: &[&o.bob], ..Default::default() }).await;
    let for_other = records(RepoBuilder::new(&elsewhere, &o.bob.did, &rev), 2).build();
    import_repo(&o.bob, &for_other.star()).await.ok();
    nothing_written(&o.bob, &o.space, "another space's repo").await;
    assert_eq!(head(&o.bob, &elsewhere).await.map(|h| h.1), Some(for_other.commit.data.to_vec()));
}

/// The authority's own repo comes after its space: an archive of alice's
/// repo in a space of hers that doesn't exist is SpaceNotFound, and once
/// she makes the space it imports. A member's repo needs no space here:
/// the authority is another host's business.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_authoritys_own_repo_needs_its_space() {
    let o = one().await;
    let rev = rev_ago(Duration::from_secs(60));
    let skey = unique_name("later");
    let space = format!("at://{}/space/{TEST_SPACE_TYPE}/{skey}", o.alice.did);
    let built = records(RepoBuilder::new(&space, &o.alice.did, &rev), 2).build();
    import_repo(&o.alice, &built.star()).await.err(400, "SpaceNotFound");
    nothing_written(&o.alice, &space, "no space").await;
    assert_eq!(o.alice.create_space(TEST_SPACE_TYPE, &skey).await, space);
    import_repo(&o.alice, &built.star()).await.ok();

    let nowhere = format!("at://did:plc:nosuchauthority2345abcd/space/{TEST_SPACE_TYPE}/x");
    let theirs = records(RepoBuilder::new(&nowhere, &o.bob.did, &rev), 1).build();
    import_repo(&o.bob, &theirs.star()).await.ok();
}

/// `--space-repo-max-records` (100k) bounds an import as it bounds writes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_a_repo_over_the_record_cap() {
    let o = one().await;
    let rev = rev_ago(Duration::from_secs(60));
    let mut b = RepoBuilder::new(&o.space, &o.bob.did, &rev);
    for i in 0..100_001u32 {
        b.records
            .insert(format!("{TEST_COLLECTION}/c{i:06}"), record_block(&json!({"$type": TEST_COLLECTION, "i": i})));
    }
    let r = import_repo(&o.bob, &b.build().star()).await;
    refused_mentioning(&r, &["limit", "max"]);
    nothing_written(&o.bob, &o.space, "over the cap").await;
    // at the cap it goes in
    b.records.pop_last();
    import_repo(&o.bob, &b.build().star()).await.ok();
}

/// Importing a repo is creating its records: the grant must allow `create`
/// in the archive's space for every collection it holds (the reference's
/// `assertSpaceRef` per collection), so a grant naming one collection
/// refuses an archive with another, and a read-only grant refuses any.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn import_needs_create_on_every_collection() {
    let o = one().await;
    let rev = rev_ago(Duration::from_secs(60));
    let both = records(RepoBuilder::new(&o.space, &o.bob.did, &rev), 2)
        .record(TEST_COLLECTION_ALT, "n1", record(TEST_COLLECTION_ALT, "a note"))
        .build();
    let one_coll = records(RepoBuilder::new(&o.space, &o.bob.did, &rev), 2).build();
    let narrow =
        regrant(&o.bob, &format!("space:{TEST_SPACE_TYPE}?authority=*&collection={TEST_COLLECTION}&action=create"))
            .await;
    let r = import_repo(&narrow, &both.star()).await;
    assert!((400..500).contains(&r.status), "a collection the grant doesn't name: {}", r.text());
    nothing_written(&o.bob, &o.space, "a collection the grant doesn't name").await;
    let read_only = regrant(&o.bob, &format!("space:{TEST_SPACE_TYPE}?authority=*&collection=*&action=read")).await;
    let r = import_repo(&read_only, &one_coll.star()).await;
    assert!((400..500).contains(&r.status), "a read-only grant: {}", r.text());
    nothing_written(&o.bob, &o.space, "a read-only grant").await;
    let other_type = regrant(&o.bob, &format!("space:{OTHER_SPACE_TYPE}?authority=*&collection=*&action=create")).await;
    let r = import_repo(&other_type, &one_coll.star()).await;
    assert!((400..500).contains(&r.status), "a grant for another space type: {}", r.text());
    nothing_written(&o.bob, &o.space, "a grant for another space type").await;
    import_repo(&narrow, &one_coll.star()).await.ok();
}

/// Space data is OAuth-only: a password session and app passwords are
/// refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn import_is_oauth_only() {
    let o = one().await;
    let s = &o.net.pds[0];
    let built = records(RepoBuilder::new(&o.space, &o.bob.did, &rev_ago(Duration::from_secs(60))), 2).build();
    let star = built.star();
    let session = Auth::Bearer(o.bob.session_jwt.clone());
    let mut auths = vec![("password session", session.clone())];
    for privileged in [false, true] {
        let ap = s
            .xrpc
            .post(
                "com.atproto.server.createAppPassword",
                &json!({"name": format!("imp-{privileged}"), "privileged": privileged}),
                &session,
            )
            .await
            .ok();
        let sess = s.create_session(&o.bob.did, ap["password"].as_str().unwrap()).await.ok();
        auths.push(("app password", Auth::Bearer(sess["accessJwt"].as_str().unwrap().into())));
    }
    auths.push(("no auth", Auth::None));
    for (what, auth) in &auths {
        let r = import_repo_as(&s.url, auth, &star).await;
        assert!(r.status == 401 || r.status == 403, "{what}: {}", r.text());
        nothing_written(&o.bob, &o.space, what).await;
    }
    import_repo(&o.bob, &star).await.ok();
}

/// An import over a repo that's there replaces it, as the reference's
/// does: the old records go, the archive's are served, check-space is
/// clean, and the head takes a new rev after both the archive's and the
/// one held (an archive older than the repo still goes in). The same
/// archive again is a replace too: a newer rev with the same data. A
/// second import while one runs is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn import_over_a_repo_replaces_it() {
    let o = one().await;
    let s = &o.net.pds[0];
    write(&o.bob, &o.space, W::new().rkey("live").text("written here")).await.ok();
    let (live_rev, _) = head(&o.bob, &o.space).await.unwrap();
    let older = rev_ago(Duration::from_secs(30));
    assert!(older < live_rev);
    let mut b = RepoBuilder::new(&o.space, &o.bob.did, &older);
    for i in 0..2 {
        b.records.insert(format!("{TEST_COLLECTION}/new{i}"), record_block(&json!({"$type": TEST_COLLECTION, "n": i})));
    }
    let built = b.build();
    // an import already running holds the space repo
    let sp = s.app.spaces.as_ref().unwrap();
    let sid = vlpds::state::space_id(&o.space);
    assert!(sp.begin_import(&o.bob.did, sid, 7));
    let r = import_repo(&o.bob, &built.star()).await;
    assert_eq!(r.status, 400, "a second import: {}", r.text());
    assert!(r.text().contains("in progress"), "{}", r.text());
    sp.end_import(&o.bob.did, sid, 7);
    assert_eq!(head(&o.bob, &o.space).await.map(|h| h.0), Some(live_rev.clone()), "a refused claim kept the repo");

    import_repo(&o.bob, &built.star()).await.ok();
    let mut got: Vec<String> =
        all_records(&o.bob, &o.space).await.iter().map(|r| r["rkey"].as_str().unwrap().to_string()).collect();
    got.sort();
    assert_eq!(got, ["new0", "new1"], "the archive replaced the repo");
    let (first, data) = head(&o.bob, &o.space).await.unwrap();
    assert!(first > live_rev, "after the held rev: {first} vs {live_rev}");
    assert_eq!(data, built.commit.data.to_vec());
    expect_set_hash_matches_store(&o.bob, &o.space).await;
    check_space_ok(s, &o.bob.did, &o.space).await;

    // the same archive again (a retry): a newer rev, the same data, and the
    // authority hears of it
    o.net.await_writer(&o.alice, &o.space, &o.bob.did).await;
    import_repo(&o.bob, &built.star()).await.ok();
    let (again, same) = head(&o.bob, &o.space).await.unwrap();
    assert!(again > first, "a retried import takes a new rev: {again} vs {first}");
    assert_eq!(same, data);
    let ops = o.bob.get("com.atproto.space.listRepoOps", &[("space", &o.space), ("repo", &o.bob.did)]).await.ok();
    assert_eq!((ops["ops"].clone(), ops["commit"]["rev"].clone()), (json!([]), json!(again)), "{ops}");
    check_space_ok(s, &o.bob.did, &o.space).await;
}

/// An import over a repo that fails part way (here: records that don't
/// fold to the commit's data, found once the archive has ended) has
/// already taken the old head away: the repo serves nothing until a retry
/// with a good archive puts it back. The reference's import is one
/// transaction and keeps the old repo.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failed_import_over_a_repo_is_retried() {
    let o = one().await;
    write(&o.bob, &o.space, W::new().rkey("live").text("written here")).await.ok();
    let b = records(RepoBuilder::new(&o.space, &o.bob.did, &rev_ago(Duration::from_secs(10))), 3);
    let mut other = b.set();
    other.add("com.example.x/y/bafyreie5737gdxlw5i64vzichcalba3z2v5n6icifvx5xytvske7mr3hpm");
    let r = import_repo(&o.bob, &b.build_with(&other).star()).await;
    refused_mentioning(&r, &["do not match the commit"]);
    let listed_now = all_records(&o.bob, &o.space).await;
    assert!(listed_now.is_empty(), "a part-way import's rows aren't served: {listed_now:?}");
    let built = b.build();
    import_repo(&o.bob, &built.star()).await.ok();
    assert_eq!(all_records(&o.bob, &o.space).await.len(), 3);
    assert_eq!(head(&o.bob, &o.space).await.map(|h| h.1), Some(built.commit.data.to_vec()));
    expect_set_hash_matches_store(&o.bob, &o.space).await;
}

/// An archive whose rev is far ahead would give the repo a rev past the
/// authority's FutureRev window, so every later notify of it would be
/// refused there: it's refused here first.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_an_archive_from_the_future() {
    let o = one().await;
    let ahead = vlatproto::tid::Tid::from_parts(vlatproto::tid::now_micros() + 3_600_000_000, 0).to_string();
    let built = records(RepoBuilder::new(&o.space, &o.bob.did, &ahead), 2).build();
    import_repo(&o.bob, &built.star()).await.err(400, "FutureRev");
    nothing_written(&o.bob, &o.space, "a rev from the future").await;
}
