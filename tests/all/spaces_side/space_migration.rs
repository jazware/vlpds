//! A space authority's account migrating with its spaces (the October 29
//! alpha, migration prompt section 5): exportSpaceMeta on the old host,
//! importSpaceMeta then com.atproto.space.importRepo on the new one.
//!
//! - Round trip: alice governs a space on host c (bob and carol members on
//!   a, bob writing); she moves to host b. Her space arrives with its policy,
//!   members and writer set (spaceRevs kept, so a syncer's listRepos cursor
//!   still works there), and her own repo at a new rev with the same data.
//!   importRepo before importSpaceMeta is SpaceNotFound; both retry.
//! - Refusals: an unknown policy, unknown policy state, keys out of order,
//!   another account's space, a grant without `manage`/`create`, and an app
//!   password; a password session may import.

use super::import_repo::*;
use super::phase3::*;
use super::ref_net::*;
use crate::common::spaces::SpaceClient;
use crate::common::*;
use std::time::Duration;
use vlpds::space::meta_archive::{self, MetaWriter, SpaceMeta};

const OCTET: &str = "application/octet-stream";
const EXPORT: &str = "com.atproto.space.exportSpaceMeta";
const IMPORT_META: &str = "com.atproto.space.importSpaceMeta";
const IMPORT: &str = "com.atproto.space.importRepo";

async fn export(sc: &SpaceClient, space: &str) -> Vec<u8> {
    let (status, ctype, body) = sc.get_raw(EXPORT, &[("space", space)]).await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    assert_eq!(ctype, OCTET);
    body
}

fn writer_of<'a>(a: &'a SpaceMeta, did: &str) -> &'a MetaWriter {
    a.writers.iter().find(|w| w.did == did).unwrap_or_else(|| panic!("no writer {did}: {a:?}"))
}

fn member_of(a: &SpaceMeta, did: &str) -> (bool, bool) {
    let key = format!("com.atproto.memberspace.member/{did}");
    let v = &a.policy_state.iter().find(|(k, _)| *k == key).unwrap_or_else(|| panic!("no {key}")).1;
    (meta_archive::bool_field(v, "read").unwrap(), meta_archive::bool_field(v, "write").unwrap())
}

/// listRepos at `host` as a syncer holding `cred` sees it: (did, spaceRev).
async fn repos(cred: &Cred, host: &str, space: &str, cursor: Option<&str>) -> Vec<(String, String)> {
    let mut q = vec![("space", space)];
    if let Some(c) = cursor {
        q.push(("cursor", c));
    }
    let r = cred.get(host, "com.atproto.space.listRepos", &q).await.ok();
    r["repos"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| (x["did"].as_str().unwrap().to_string(), x["spaceRev"].as_str().unwrap().to_string()))
        .collect()
}

async fn cred_at(h: &TwoHosts, host: &str) -> Cred {
    let token = delegation_token(&h.carol, &h.space).await;
    let holder = crate::common::spaces::Holder::new();
    let r = exchange(&reqwest::Client::new(), &holder, host, &h.space, &token, None).await;
    Cred { credential: r.ok()["credential"].as_str().unwrap().to_string(), holder, http: reqwest::Client::new() }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_authority_moves_with_its_space() {
    let h = two_hosts().await;
    fill_bob(&h).await;
    write(&h.alice, &h.space, W::new().rkey("a1").text("alice's own")).await.ok();
    put_member(&h.alice, &h.space, &h.carol, true, false).await.ok();

    // what a syncer on the old host saw: bob and alice in the writer set
    let cred_c = h.carol_cred().await;
    let mut before = Vec::new();
    for _ in 0..100 {
        before = repos(&cred_c, &h.c.url, &h.space, None).await;
        if before.iter().any(|(d, _)| *d == h.bob.did) && before.iter().any(|(d, _)| *d == h.alice.did) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(before.len(), 2, "{before:?}");

    let meta = export(&h.alice, &h.space).await;
    let exported = meta_archive::parse(&meta).unwrap();
    assert_eq!(exported.space, h.space);
    assert_eq!(member_of(&exported, &h.bob.did), (true, true));
    assert_eq!(member_of(&exported, &h.carol.did), (true, false));
    assert_eq!(
        writer_of(&exported, &h.bob.did).space_rev.to_string(),
        before.iter().find(|(d, _)| *d == h.bob.did).unwrap().1
    );
    let repo = get_repo_self(&h.alice, &h.space).await;
    assert_eq!(repo.status, 200, "{}", repo.text());
    let (old_rev, old_data) = repo_state(&h.alice, &h.space).await.unwrap();

    // alice moves to b
    let b_did = h.b.pds_did().await;
    let sa = service_jwt(&h.alice, &b_did, "com.atproto.server.createAccount").await;
    let arrived = arrive(&h.b, &h.alice.did, sa).await;
    complete_move(&h.docs, &h.b, &arrived).await;
    let moved = arrived.oauth(&h.b).await;

    // her own repo needs her space here first
    moved.post_bytes(IMPORT, &[], repo.body.to_vec(), OCTET).await.err(400, "SpaceNotFound");
    for _ in 0..2 {
        let r = moved.post_bytes(IMPORT_META, &[], meta.clone(), OCTET).await;
        assert_eq!(r.status, 200, "{}", r.text());
    }
    for _ in 0..2 {
        let r = moved.post_bytes(IMPORT, &[], repo.body.to_vec(), OCTET).await;
        assert_eq!(r.status, 200, "{}", r.text());
    }
    let (rev, data) = repo_state(&moved, &h.space).await.unwrap();
    assert_eq!(data, old_data, "the same data");
    assert!(rev > old_rev, "a new rev: {rev} after {old_rev}");
    let ops = moved.get("com.atproto.space.listRepoOps", &[("space", &h.space), ("repo", &h.alice.did)]).await.ok();
    assert_eq!(ops["ops"], json!([]), "{ops}");

    // the space, as it was
    let got = moved.get("com.atproto.space.getSpace", &[("space", &h.space)]).await.ok();
    assert_eq!(got["policy"]["$type"], json!("com.atproto.memberspace.policy"), "{got}");
    let members = moved.get("com.atproto.memberspace.listMembers", &[("space", &h.space)]).await.ok();
    let members = members["members"].as_array().unwrap();
    assert_eq!(members.len(), 2, "{members:?}");
    assert!(members.contains(&json!({"did": h.carol.did, "read": true, "write": false})));
    let again = meta_archive::parse(&export(&moved, &h.space).await).unwrap();
    assert_eq!(writer_of(&again, &h.bob.did), writer_of(&exported, &h.bob.did), "bob's writer state moves as it was");
    assert_eq!(again.policy_state, exported.policy_state);

    // a syncer at the new host: bob at the spaceRev it had, and the old
    // cursor still valid
    let cred_b = cred_at(&h, &h.b.url).await;
    let now = repos(&cred_b, &h.b.url, &h.space, None).await;
    let bob_at = |l: &[(String, String)]| l.iter().find(|(d, _)| *d == h.bob.did).map(|x| x.1.clone());
    assert_eq!(bob_at(&now), bob_at(&before), "{now:?}");
    let first = &before[0].1;
    let after: Vec<_> = repos(&cred_b, &h.b.url, &h.space, Some(first)).await;
    assert!(after.iter().all(|(_, r)| r > first), "{after:?}");
    assert!(!after.is_empty());
    // the imported writers are sequenced before her import's
    let alice_now = now.iter().find(|(d, _)| *d == h.alice.did).unwrap();
    assert!(now.iter().all(|(_, r)| r <= &alice_now.1), "{now:?}");
}

/// An archive of `policy` with `state`, framed as the reference does.
fn archive(space: &str, policy: J, state: Vec<(&str, J)>, writers: Vec<MetaWriter>) -> Vec<u8> {
    meta_archive::serialize(&SpaceMeta {
        space: space.into(),
        policy: meta_archive::from_json(&policy),
        policy_state: state.into_iter().map(|(k, v)| (k.to_string(), meta_archive::from_json(&v))).collect(),
        writers,
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn space_imports_are_checked() {
    let net = Net::new(0).await;
    let s = &net.pds[0];
    let (alice, bob) = (net.actor("alice", 0).await, net.actor("bob", 0).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&bob], ..Default::default() }).await;
    let member_policy = json!({"$type": "com.atproto.memberspace.policy"});
    let unknown = archive(&space, json!({"$type": "com.example.policy"}), vec![], vec![]);
    alice.post_bytes(IMPORT_META, &[], unknown, OCTET).await.err(400, "UnsupportedPolicy");
    let state = archive(&space, member_policy.clone(), vec![("com.example.thing/x", json!({"a": 1}))], vec![]);
    alice.post_bytes(IMPORT_META, &[], state, OCTET).await.err(400, "InvalidRequest");
    let managed = json!({"$type": "com.atproto.managedspace.policy", "managingApp": "did:web:app.example"});
    let members_elsewhere = archive(
        &space,
        managed,
        vec![("com.atproto.memberspace.member/did:plc:x", json!({"read": true, "write": true}))],
        vec![],
    );
    alice.post_bytes(IMPORT_META, &[], members_elsewhere, OCTET).await.err(400, "InvalidRequest");
    // writers out of order, framed by hand from a good archive's pairs
    let w = |d: &str| MetaWriter {
        did: d.into(),
        rev: vlatproto::tid::Tid::parse("3kbcq3p7ad42b").unwrap(),
        data: vec![7; 32],
        space_rev: vlatproto::tid::Tid::parse("3kbcq3p7ad42c").unwrap(),
    };
    let good = archive(&space, member_policy.clone(), vec![], vec![w("did:plc:aaa"), w("did:plc:bbb")]);
    let swapped = swap_last_two_pairs(&good);
    assert!(meta_archive::parse(&swapped).is_err());
    alice.post_bytes(IMPORT_META, &[], swapped, OCTET).await.err(400, "InvalidRequest");
    alice.post_bytes(IMPORT_META, &[], b"not a star".to_vec(), OCTET).await.err(400, "InvalidRequest");

    // another account's space
    bob.post_bytes(IMPORT_META, &[], export(&alice, &space).await, OCTET).await.err(400, "NotSpaceOwner");

    // a grant that can't create and update the space, an app password
    let read_only = regrant(&alice, "space:*?authority=*&collection=*&action=read_self&action=create").await;
    let r = read_only.post_bytes(IMPORT_META, &[], good.clone(), OCTET).await;
    assert_eq!(r.status, 403, "{}", r.text());
    let session = Auth::Bearer(alice.session_jwt.clone());
    let ap = s
        .xrpc
        .post("com.atproto.server.createAppPassword", &json!({"name": "meta", "privileged": true}), &session)
        .await
        .ok();
    let sess = s.create_session(&alice.did, ap["password"].as_str().unwrap()).await.ok();
    let app_pw = Auth::Bearer(sess["accessJwt"].as_str().unwrap().into());
    let r = s.xrpc.post_bytes(IMPORT_META, good.clone(), OCTET, &app_pw).await;
    assert_eq!(r.status, 403, "{}", r.text());

    // a full-access session replaces the member list (bob goes) and the
    // writer set
    let r = s.xrpc.post_bytes(IMPORT_META, good, OCTET, &session).await;
    assert_eq!(r.status, 200, "{}", r.text());
    let m = alice.get("com.atproto.memberspace.listMembers", &[("space", &space)]).await.ok();
    assert_eq!(m["members"], json!([]), "{m}");
    let now = meta_archive::parse(&export(&alice, &space).await).unwrap();
    assert_eq!(now.writers.iter().map(|w| w.did.as_str()).collect::<Vec<_>>(), ["did:plc:aaa", "did:plc:bbb"]);

    // importRepo: a grant without `create` for the archive's collection
    write(&alice, &space, W::new().rkey("r1").text("alice")).await.ok();
    let repo = get_repo_self(&alice, &space).await;
    let (rev, data) = repo_state(&alice, &space).await.unwrap();
    let no_create = regrant(&alice, "space:*?authority=*&collection=*&action=read_self").await;
    let r = no_create.post_bytes(IMPORT, &[], repo.body.to_vec(), OCTET).await;
    assert_eq!(r.status, 403, "{}", r.text());
    let r = s.xrpc.post_bytes(IMPORT, repo.body.to_vec(), OCTET, &app_pw).await;
    assert_eq!(r.status, 403, "{}", r.text());
    // another account's repo
    bob.post_bytes(IMPORT, &[], repo.body.to_vec(), OCTET).await.err(400, "InvalidRequest");
    // the session may: a new rev, the same data, over what was there
    let r = s.xrpc.post_bytes(IMPORT, repo.body.to_vec(), OCTET, &session).await;
    assert_eq!(r.status, 200, "{}", r.text());
    let (rev2, data2) = repo_state(&alice, &space).await.unwrap();
    assert!(rev2 > rev && data2 == data, "{rev} -> {rev2}");
    // published policy records travel as they are
    alice
        .post(
            "com.atproto.space.updateSpace",
            json!({"space": space, "policy": {"$type": "com.atproto.memberspace.policy", "publishPolicy": true}}),
        )
        .await
        .ok();
    let with_policy = get_repo_self(&alice, &space).await;
    let r = alice.post_bytes(IMPORT, &[], with_policy.body.to_vec(), OCTET).await;
    assert_eq!(r.status, 200, "{}", r.text());
}

/// The archive with its last two pairs swapped.
fn swap_last_two_pairs(b: &[u8]) -> Vec<u8> {
    use vlpds::space::star::read_varint;
    let mut pos = 4;
    let frame = |pos: &mut usize| {
        let (len, n) = read_varint(&b[*pos..]).unwrap().unwrap();
        let start = *pos;
        *pos += n + len as usize;
        start..*pos
    };
    frame(&mut pos);
    let mut pairs = Vec::new();
    while pos < b.len() {
        let k = frame(&mut pos);
        let v = frame(&mut pos);
        pairs.push(k.start..v.end);
    }
    let n = pairs.len();
    pairs.swap(n - 1, n - 2);
    let mut out = b[..pairs.iter().map(|r| r.start).min().unwrap()].to_vec();
    for r in pairs {
        out.extend_from_slice(&b[r]);
    }
    out
}
