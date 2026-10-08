//! Ported from the reference's `tests/space/simplespace.test.ts`
//! (5b95b2f2): `com.atproto.simplespace`, the policy layer. Each test names
//! its reference case. The client-attestation cases of "credential mint
//! gates" live in `ref_client_attestation` with the verifier's own cases.
//!
//! Adaptations: the reference's `writerDids` and storage reads become
//! listRepos (an owner's credential) and the owner's own reads, and a
//! registration's expiry (no endpoint expires one) isn't ported.

use super::ref_net::*;
use crate::common::spaces::SpaceClient;
use crate::common::*;
use std::time::Duration;

async fn get_space(owner: &SpaceClient, space: &str) -> Resp {
    owner.get("com.atproto.simplespace.getSpace", &[("space", space)]).await
}

async fn update_space(owner: &SpaceClient, space: &str, patch: J) -> Resp {
    let mut body = patch;
    body["space"] = json!(space);
    owner.post("com.atproto.simplespace.updateSpace", body).await
}

async fn list_members(owner: &SpaceClient, space: &str) -> Resp {
    owner.get("com.atproto.simplespace.listMembers", &[("space", space)]).await
}

fn uris(listed: &J) -> Vec<String> {
    listed["spaces"].as_array().unwrap().iter().filter_map(|s| s["uri"].as_str().map(String::from)).collect()
}

fn create_body(skey: &str) -> J {
    json!({"spaceType": TEST_SPACE_TYPE, "skey": skey, "readPolicy": member_list(), "writePolicy": member_list(), "appAccess": open()})
}

// ---------------------------------------------------------------------------
// lifecycle
// ---------------------------------------------------------------------------

/// lifecycle: "creates a space anchored on the caller own DID"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn creates_a_space_anchored_on_the_caller() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    let space = net.create_space(&alice, SpaceOpts::default()).await;
    assert!(space.starts_with(&format!("at://{}/space/", alice.did)));
    let listed = alice.get("com.atproto.space.listSpaces", &[]).await.ok();
    assert!(uris(&listed).contains(&space), "{listed}");
}

/// lifecycle: "refuses a duplicate space"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_a_duplicate_space() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    let space = net.create_space(&alice, SpaceOpts::default()).await;
    alice
        .post("com.atproto.simplespace.createSpace", create_body(last_segment(&space)))
        .await
        .err(400, "SpaceAlreadyExists");
}

/// lifecycle: "refuses a space key that is not a valid record key"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_a_space_key_that_is_not_a_record_key() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    let r = alice.post("com.atproto.simplespace.createSpace", create_body("not a valid rkey")).await;
    refused_mentioning(&r, &["record key"]);
}

/// lifecycle: "filters spaces by spaceType"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn filters_spaces_by_space_type() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    let space = net.create_space(&alice, SpaceOpts::default()).await;
    let other = net.create_space(&alice, SpaceOpts { space_type: Some(OTHER_SPACE_TYPE), ..Default::default() }).await;
    let listed = uris(&alice.get("com.atproto.space.listSpaces", &[("spaceType", TEST_SPACE_TYPE)]).await.ok());
    assert!(listed.contains(&space) && !listed.contains(&other), "{listed:?}");
    let listed = uris(&alice.get("com.atproto.space.listSpaces", &[("spaceType", OTHER_SPACE_TYPE)]).await.ok());
    assert_eq!(listed, [other]);
}

/// lifecycle: "governs a space written to before createSpace"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn governs_a_space_written_to_before_create_space() {
    let net = Net::new(1).await;
    let (alice, bob) = (net.actor("alice", 0).await, net.actor("bob", 1).await);
    let space = format!("at://{}/space/{TEST_SPACE_TYPE}/lazy", alice.did);
    write(&alice, &space, W::new().text("lazy space")).await.ok();
    get_space(&alice, &space).await.err(400, "SpaceNotFound");
    put_member(&alice, &space, &bob, true, true).await.err(400, "SpaceNotFound");

    net.create_space(&alice, SpaceOpts { skey: Some("lazy"), ..Default::default() }).await;
    put_member(&alice, &space, &bob, true, true).await.ok();
    let got = get_space(&alice, &space).await.ok();
    assert_eq!(got["readPolicy"]["$type"], json!(MEMBER_LIST));
    assert_eq!(got["writePolicy"]["$type"], json!(MEMBER_LIST));
    assert_eq!(all_records(&alice, &space).await.len(), 1, "the records already there stay put");
}

// ---------------------------------------------------------------------------
// members
// ---------------------------------------------------------------------------

/// members: "adds and removes members, and the owner is not one of them"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn adds_and_removes_members() {
    let net = Net::new(1).await;
    let (alice, dan, bob) = (net.actor("alice", 0).await, net.actor("dan", 0).await, net.actor("bob", 1).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&dan], ..Default::default() }).await;
    put_member(&alice, &space, &bob, true, false).await.ok();
    let members = list_members(&alice, &space).await.ok();
    let ms = members["members"].as_array().unwrap();
    let dids: Vec<&str> = ms.iter().filter_map(|m| m["did"].as_str()).collect();
    assert!(!dids.contains(&alice.did.as_str()), "the authority isn't on the member list");
    assert!(dids.contains(&dan.did.as_str()) && dids.contains(&bob.did.as_str()), "{members}");
    let b = ms.iter().find(|m| m["did"] == json!(bob.did)).unwrap();
    assert_eq!((&b["read"], &b["write"]), (&json!(true), &json!(false)));

    remove_member(&alice, &space, &bob).await.ok();
    let after = list_members(&alice, &space).await.ok();
    assert!(!after["members"].as_array().unwrap().iter().any(|m| m["did"] == json!(bob.did)));
}

/// members: "refuses membership changes from a non-owner member"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_membership_changes_from_a_non_owner() {
    let net = Net::new(2).await;
    let (alice, dan, carol) = (net.actor("alice", 0).await, net.actor("dan", 0).await, net.actor("carol", 2).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&dan], ..Default::default() }).await;
    put_member(&dan, &space, &carol, true, true).await.err(400, "NotSpaceOwner");
    remove_member(&dan, &space, &dan).await.err(400, "NotSpaceOwner");
}

/// members: "refuses listMembers to a space credential and to a non-owner
/// member"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_list_members_to_a_credential_and_a_non_owner() {
    let net = Net::new(2).await;
    let (alice, dan, carol) = (net.actor("alice", 0).await, net.actor("dan", 0).await, net.actor("carol", 2).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&carol, &dan], ..Default::default() }).await;
    let cred = net.credential_for(&carol, &space).await;
    cred.get(&net.pds[0].url, "com.atproto.simplespace.listMembers", &[("space", &space)]).await.client_err();
    list_members(&dan, &space).await.err(400, "NotSpaceOwner");
}

/// members: "putMember replaces both access values"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn put_member_replaces_both_access_values() {
    let net = Net::new(1).await;
    let (alice, bob) = (net.actor("alice", 0).await, net.actor("bob", 1).await);
    let space = net.create_space(&alice, SpaceOpts::default()).await;
    put_member(&alice, &space, &bob, true, false).await.ok();
    put_member(&alice, &space, &bob, false, true).await.ok();
    let members = list_members(&alice, &space).await.ok();
    let ms = members["members"].as_array().unwrap();
    assert_eq!(ms.iter().filter(|m| m["did"] == json!(bob.did)).count(), 1);
    assert_eq!((&ms[0]["did"], &ms[0]["read"], &ms[0]["write"]), (&json!(bob.did), &json!(false), &json!(true)));
}

// ---------------------------------------------------------------------------
// config
// ---------------------------------------------------------------------------

const FORUM: &str = "did:web:example.com#forum";

/// config: "persists what createSpace was given"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn persists_what_create_space_was_given() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    let space = net
        .create_space(
            &alice,
            SpaceOpts {
                read_policy: Some(managing_app(FORUM)),
                write_policy: Some(public()),
                app_access: Some(allow_list(&["app:one", "app:two"])),
                ..Default::default()
            },
        )
        .await;
    let got = get_space(&alice, &space).await.ok();
    assert_eq!(got["uri"], json!(space));
    assert_eq!(got["readPolicy"], managing_app(FORUM));
    assert_eq!(got["writePolicy"], public());
    assert_eq!(got["appAccess"]["$type"], json!(ALLOW_LIST));
    assert_eq!(got["appAccess"]["allowed"], json!(["app:one", "app:two"]));
}

/// config: "defaults to a member-list, open space"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn defaults_to_a_member_list_open_space() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    let space = net.create_space(&alice, SpaceOpts::default()).await;
    let got = get_space(&alice, &space).await.ok();
    assert_eq!(got["readPolicy"], member_list());
    assert_eq!(got["writePolicy"], member_list());
    assert_eq!(got["appAccess"]["$type"], json!(OPEN));
}

/// config: "patches readPolicy, writePolicy, and appAccess independently"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn patches_policies_and_app_access_independently() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    let space = net.create_space(&alice, SpaceOpts::default()).await;
    update_space(&alice, &space, json!({"readPolicy": public()})).await.ok();
    update_space(&alice, &space, json!({"writePolicy": managing_app(FORUM)})).await.ok();
    update_space(&alice, &space, json!({"appAccess": allow_list(&["app:x"])})).await.ok();
    let got = get_space(&alice, &space).await.ok();
    assert_eq!(got["readPolicy"]["$type"], json!(PUBLIC));
    assert_eq!(got["writePolicy"], managing_app(FORUM));
    assert_eq!(got["appAccess"]["allowed"], json!(["app:x"]));
}

/// config: "drops managingApp by switching policy"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn drops_managing_app_by_switching_policy() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    let space =
        net.create_space(&alice, SpaceOpts { read_policy: Some(managing_app(FORUM)), ..Default::default() }).await;
    update_space(&alice, &space, json!({"readPolicy": member_list()})).await.ok();
    assert_eq!(get_space(&alice, &space).await.ok()["readPolicy"], member_list());
}

/// config: "refuses an update from a non-owner" (bob's token, presented to
/// the authority's PDS)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_an_update_from_a_non_owner() {
    let net = Net::new(1).await;
    let (alice, bob) = (net.actor("alice", 0).await, net.actor("bob", 1).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&bob], ..Default::default() }).await;
    let body = json!({"space": space, "readPolicy": public()});
    post_at(&bob, &net.pds[0].url, "com.atproto.simplespace.updateSpace", body.clone()).await.client_err();
    bob.post("com.atproto.simplespace.updateSpace", body).await.client_err();
    assert_eq!(get_space(&alice, &space).await.ok()["readPolicy"], member_list());
}

/// config: "refuses an unrecognized appAccess variant rather than widening
/// the space"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_an_unrecognized_app_access_variant() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    let space =
        net.create_space(&alice, SpaceOpts { app_access: Some(allow_list(&["app:one"])), ..Default::default() }).await;
    update_space(&alice, &space, json!({"appAccess": {"$type": "com.example.denyEverything"}}))
        .await
        .err(400, "UnsupportedAppAccess");
    let got = get_space(&alice, &space).await.ok();
    assert_eq!((&got["appAccess"]["$type"], &got["appAccess"]["allowed"]), (&json!(ALLOW_LIST), &json!(["app:one"])));
}

/// config: "refuses an unrecognized policy variant"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_an_unrecognized_policy_variant() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    let space = net.create_space(&alice, SpaceOpts::default()).await;
    update_space(&alice, &space, json!({"writePolicy": {"$type": "com.example.whatever"}}))
        .await
        .err(400, "UnsupportedPolicy");
}

/// config: "refuses a managingApp that does not name a service"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_a_managing_app_that_is_not_a_did() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    let space = net.create_space(&alice, SpaceOpts::default()).await;
    let r = update_space(&alice, &space, json!({"readPolicy": managing_app("not-a-did-at-all")})).await;
    refused_mentioning(&r, &["must be a DID"]);
}

/// config: "serves the config to a member with a space credential"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn serves_the_config_to_a_member_credential() {
    let net = Net::new(2).await;
    let (alice, carol) = (net.actor("alice", 0).await, net.actor("carol", 2).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&carol], ..Default::default() }).await;
    let cred = net.credential_for(&carol, &space).await;
    let got = cred.get(&net.pds[0].url, "com.atproto.simplespace.getSpace", &[("space", &space)]).await.ok();
    assert_eq!((&got["uri"], &got["readPolicy"]["$type"]), (&json!(space), &json!(MEMBER_LIST)));
}

/// config: "refuses the config to a credential for another space"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_the_config_to_a_credential_for_another_space() {
    let net = Net::new(2).await;
    let (alice, carol) = (net.actor("alice", 0).await, net.actor("carol", 2).await);
    let space =
        net.create_space(&alice, SpaceOpts { skey: Some("cfg-wrong"), members: &[&carol], ..Default::default() }).await;
    let other = net
        .create_space(&alice, SpaceOpts { skey: Some("cfg-wrong-other"), members: &[&carol], ..Default::default() })
        .await;
    let cred = net.credential_for(&carol, &other).await;
    cred.get(&net.pds[0].url, "com.atproto.simplespace.getSpace", &[("space", &space)]).await.client_err();
}

/// config: "refuses the config to another account on an account credential"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_the_config_to_another_account_on_its_own_token() {
    let net = Net::new(0).await;
    let (alice, dan) = (net.actor("alice", 0).await, net.actor("dan", 0).await);
    let space = net
        .create_space(&alice, SpaceOpts { skey: Some("cfg-not-owner"), members: &[&dan], ..Default::default() })
        .await;
    get_space(&dan, &space).await.err(400, "NotSpaceOwner");
    let cred = net.credential_for(&dan, &space).await;
    let got = cred.get(&net.pds[0].url, "com.atproto.simplespace.getSpace", &[("space", &space)]).await.ok();
    assert_eq!(got["uri"], json!(space));
}

/// config: "refuses to answer for a space this host does not govern"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_to_answer_for_a_space_this_host_does_not_govern() {
    let net = Net::new(1).await;
    let (alice, bob) = (net.actor("alice", 0).await, net.actor("bob", 1).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&bob], ..Default::default() }).await;
    let cred = net.credential_for(&bob, &space).await;
    cred.get(&net.pds[1].url, "com.atproto.space.listRepos", &[("space", &space)]).await.err(400, "SpaceNotFound");
    get_space(&bob, &space).await.client_err();
}

// ---------------------------------------------------------------------------
// credential mint gates
// ---------------------------------------------------------------------------

/// credential mint gates: "mints for a non-member when the read policy is
/// public"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mints_for_a_non_member_under_a_public_read_policy() {
    let net = Net::new(2).await;
    let (alice, carol) = (net.actor("alice", 0).await, net.actor("carol", 2).await);
    let space = net.create_space(&alice, SpaceOpts { read_policy: Some(public()), ..Default::default() }).await;
    assert!(!net.credential_for(&carol, &space).await.credential.is_empty());
}

/// credential mint gates: "refuses a non-member under member-list read
/// policy"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_a_non_member_under_member_list() {
    let net = Net::new(2).await;
    let (alice, carol) = (net.actor("alice", 0).await, net.actor("carol", 2).await);
    let space = net.create_space(&alice, SpaceOpts::default()).await;
    let token = delegation_token(&carol, &space).await;
    net.mint_credential(&space, &token, None).await.0.err(400, "UserNotAuthorized");
}

/// credential mint gates: "refuses a member without read access"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_a_member_without_read_access() {
    let net = Net::new(2).await;
    let (alice, carol) = (net.actor("alice", 0).await, net.actor("carol", 2).await);
    let space = net.create_space(&alice, SpaceOpts::default()).await;
    put_member(&alice, &space, &carol, false, true).await.ok();
    let token = delegation_token(&carol, &space).await;
    net.mint_credential(&space, &token, None).await.0.err(400, "UserNotAuthorized");
}

/// credential mint gates: "always admits the authority, whatever the read
/// policy"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn always_admits_the_authority() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    let space = net
        .create_space(
            &alice,
            SpaceOpts { read_policy: Some(managing_app("did:web:unreachable.invalid#forum")), ..Default::default() },
        )
        .await;
    assert!(!net.credential_for(&alice, &space).await.credential.is_empty());
}

/// credential mint gates: "refuses when appAccess is an allowList and no
/// attestation is presented"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_an_allow_list_space_without_an_attestation() {
    let net = Net::new(2).await;
    let (alice, carol) = (net.actor("alice", 0).await, net.actor("carol", 2).await);
    let space = net
        .create_space(
            &alice,
            SpaceOpts {
                read_policy: Some(public()),
                app_access: Some(allow_list(&["https://app.example.com/client-metadata.json"])),
                ..Default::default()
            },
        )
        .await;
    let token = delegation_token(&carol, &space).await;
    net.mint_credential(&space, &token, None).await.0.err(400, "AppNotAuthorized");
}

// ---------------------------------------------------------------------------
// managing-app policy
// ---------------------------------------------------------------------------

const CHECK_ACCESS: &str = "com.atproto.simplespace.checkUserAccess";

async fn forum(authorized: Option<bool>) -> MockService {
    let app = MockService::spawn(&[("atproto_forum", "AtprotoForum")]).await;
    match authorized {
        Some(a) => app.respond(200, json!({"authorized": a})),
        None => app.respond(500, json!({"error": "InternalError"})),
    }
    app
}

async fn managed_space(net: &Net, alice: &SpaceClient, app: &str) -> String {
    let p = managing_app(app);
    net.create_space(alice, SpaceOpts { read_policy: Some(p.clone()), write_policy: Some(p), ..Default::default() })
        .await
}

/// managing-app policy: "admits a user the managing app authorizes"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn managing_app_admits_a_user_it_authorizes() {
    let net = Net::new(2).await;
    let (alice, carol) = (net.actor("alice", 0).await, net.actor("carol", 2).await);
    let app = forum(Some(true)).await;
    let space = managed_space(&net, &alice, &app.service_ref()).await;
    assert!(!net.credential_for(&carol, &space).await.credential.is_empty());
    let asked = app.calls_to(CHECK_ACCESS);
    assert_eq!(asked.len(), 1);
    assert_eq!(
        (&asked[0].body["space"], &asked[0].body["user"], &asked[0].body["access"]),
        (&json!(space), &json!(carol.did), &json!("read"))
    );
    // Service auth from the authority, so the app can tell who asks.
    let auth = asked[0].auth.as_deref().unwrap_or("");
    assert!(auth.starts_with("Bearer "), "{auth}");
    assert_eq!(jwt_claims(auth.trim_start_matches("Bearer "))["iss"], json!(alice.did));
}

/// managing-app policy: "refuses a user the managing app declines"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn managing_app_refuses_a_user_it_declines() {
    let net = Net::new(2).await;
    let (alice, carol) = (net.actor("alice", 0).await, net.actor("carol", 2).await);
    let app = forum(Some(false)).await;
    let space = managed_space(&net, &alice, &app.service_ref()).await;
    let token = delegation_token(&carol, &space).await;
    net.mint_credential(&space, &token, None).await.0.err(400, "UserNotAuthorized");
}

/// managing-app policy: "denies when the managing app errors"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn managing_app_denies_when_it_errors() {
    let net = Net::new(2).await;
    let (alice, carol) = (net.actor("alice", 0).await, net.actor("carol", 2).await);
    let app = forum(None).await;
    let space = managed_space(&net, &alice, &app.service_ref()).await;
    let token = delegation_token(&carol, &space).await;
    net.mint_credential(&space, &token, None).await.0.err(400, "UserNotAuthorized");
}

/// managing-app policy: "denies when the managing app cannot be resolved"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn managing_app_denies_when_unresolvable() {
    let net = Net::new(2).await;
    let (alice, carol) = (net.actor("alice", 0).await, net.actor("carol", 2).await);
    let space = managed_space(&net, &alice, "did:web:nonexistent.invalid#forum").await;
    let token = delegation_token(&carol, &space).await;
    net.mint_credential(&space, &token, None).await.0.err(400, "UserNotAuthorized");
}

/// managing-app policy: "records a writer the managing app admits"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn managing_app_admits_a_writer() {
    let net = Net::new(1).await;
    let (alice, bob) = (net.actor("alice", 0).await, net.actor("bob", 1).await);
    let app = forum(Some(true)).await;
    let space = managed_space(&net, &alice, &app.service_ref()).await;
    write(&bob, &space, W::new().text("admitted by the managing app")).await.ok();
    let dids = net.await_writer(&alice, &space, &bob.did).await;
    assert!(dids.contains(&bob.did), "{dids:?}");
    let asked = app.calls_to(CHECK_ACCESS);
    assert!(asked.iter().any(|c| c.body["user"] == json!(bob.did) && c.body["access"] == json!("write")), "{asked:?}");
}

// ---------------------------------------------------------------------------
// notify registration
// ---------------------------------------------------------------------------

const NOTIFY_WRITE: &str = "com.atproto.space.notifyWrite";

/// notify registration: "registers, forwards writes, and stops once
/// withdrawn"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn registers_forwards_writes_and_stops_once_withdrawn() {
    let net = Net::new(2).await;
    let (alice, bob, carol) = (net.actor("alice", 0).await, net.actor("bob", 1).await, net.actor("carol", 2).await);
    let syncer = MockService::syncer().await;
    let space = net.create_space(&alice, SpaceOpts { members: &[&bob, &carol], ..Default::default() }).await;
    let cred = net.credential_for(&carol, &space).await;
    let pds1 = &net.pds[0].url;
    let reg = json!({"space": space, "service": syncer.service_ref()});
    let r = cred.post(pds1, "com.atproto.space.registerNotify", reg.clone()).await.ok();
    assert!(r["expiresAt"].is_string(), "a registration says when it expires: {r}");

    write(&bob, &space, W::new().text("forwarded")).await.ok();
    let got = syncer.await_calls(NOTIFY_WRITE, 1, Duration::from_secs(10)).await.expect("forwarded");
    assert_eq!((&got[0].body["space"], &got[0].body["repo"]), (&json!(space), &json!(bob.did)));

    cred.post(pds1, "com.atproto.space.unregisterNotify", reg.clone()).await.ok();
    let before = syncer.calls_to(NOTIFY_WRITE).len();
    write(&bob, &space, W::new().text("not forwarded")).await.ok();
    net.await_writer(&alice, &space, &bob.did).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(syncer.calls_to(NOTIFY_WRITE).len(), before, "delivered after unregistering");
    cred.post(pds1, "com.atproto.space.unregisterNotify", reg).await.ok();
}

/// notify registration: "stops delivering to a registration past its
/// expiry, and resumes on renewal". The reference backdates the row in its
/// store; here the test hook expires it through the authority's worker.
/// vlpds prunes an expired registration rather than withholding it, and a
/// renewal registers it again either way.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stops_past_expiry_and_resumes_on_renewal() {
    let net = Net::new(2).await;
    let (alice, bob, carol) = (net.actor("alice", 0).await, net.actor("bob", 1).await, net.actor("carol", 2).await);
    let syncer = MockService::syncer().await;
    let space = net.create_space(&alice, SpaceOpts { members: &[&bob, &carol], ..Default::default() }).await;
    let cred = net.credential_for(&carol, &space).await;
    let pds1 = &net.pds[0].url;
    let reg = json!({"space": space, "service": syncer.service_ref()});
    cred.post(pds1, "com.atproto.space.registerNotify", reg.clone()).await.ok();
    let expired = vlsync_atproto::tid::now_micros() - 1_000_000;
    vlpds::xrpc::space::set_registration_expiry(&net.pds[0].app, &space, &syncer.service_ref(), expired).await.unwrap();

    write(&bob, &space, W::new().text("after expiry")).await.ok();
    net.await_writer(&alice, &space, &bob.did).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(syncer.calls_to(NOTIFY_WRITE).len(), 0, "delivered past its expiry");

    cred.post(pds1, "com.atproto.space.registerNotify", reg).await.ok();
    write(&bob, &space, W::new().text("after renewal")).await.ok();
    syncer.await_calls(NOTIFY_WRITE, 1, Duration::from_secs(10)).await.expect("forwarded after renewal");
}

/// notify registration: "refuses a service that cannot be resolved"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_a_service_that_cannot_be_resolved() {
    let net = Net::new(2).await;
    let (alice, carol) = (net.actor("alice", 0).await, net.actor("carol", 2).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&carol], ..Default::default() }).await;
    let cred = net.credential_for(&carol, &space).await;
    let body = json!({"space": space, "service": "did:web:nonexistent.invalid#syncer"});
    cred.post(&net.pds[0].url, "com.atproto.space.registerNotify", body).await.err(400, "ServiceNotResolvable");
}

// ---------------------------------------------------------------------------
// deletion
// ---------------------------------------------------------------------------

async fn delete_space(owner: &SpaceClient, space: &str) -> Resp {
    owner.post("com.atproto.simplespace.deleteSpace", json!({"space": space})).await
}

/// deletion: "purges the authority own repo and keeps a tombstone" (the
/// blob is gone once space.getBlob no longer serves it)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delete_purges_the_authority_repo_and_keeps_a_tombstone() {
    let net = Net::new(1).await;
    let (alice, bob) = (net.actor("alice", 0).await, net.actor("bob", 1).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&bob], ..Default::default() }).await;
    let blob = upload_blob(&alice, b"space blob for deletion").await;
    let cid = blob_cid(&blob);
    let rec = json!({"$type": TEST_COLLECTION, "text": "owner record", "image": blob});
    write(&alice, &space, W::new().rkey("doomed").record(rec)).await.ok();
    let cred = net.credential_for(&alice, &space).await;
    let q = [("space", space.as_str()), ("repo", alice.did.as_str()), ("cid", cid.as_str())];
    assert_eq!(cred.get(&net.pds[0].url, "com.atproto.space.getBlob", &q).await.status, 200);

    delete_space(&alice, &space).await.ok();
    get_space(&alice, &space).await.err(400, "SpaceNotFound");
    assert!(all_records(&alice, &space).await.is_empty(), "the authority's own records are gone");
    assert_eq!(repo_state(&alice, &space).await, None);
    list_members(&alice, &space).await.client_err();
    alice.get("com.atproto.space.getBlob", &q).await.client_err();
    // The tombstone keeps answering SpaceDeleted.
    let token = delegation_token(&bob, &space).await;
    net.mint_credential(&space, &token, None).await.0.err(400, "SpaceDeleted");
    // Idempotent.
    delete_space(&alice, &space).await.ok();
}

/// deletion: "answers SpaceDeleted on credential renewal"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn answers_space_deleted_on_credential_renewal() {
    let net = Net::new(2).await;
    let (alice, carol) = (net.actor("alice", 0).await, net.actor("carol", 2).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&carol], ..Default::default() }).await;
    let token = delegation_token(&carol, &space).await;
    delete_space(&alice, &space).await.ok();
    net.mint_credential(&space, &token, None).await.0.err(400, "SpaceDeleted");
}

/// deletion: "notifies registered syncers"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delete_notifies_registered_syncers() {
    let net = Net::new(2).await;
    let (alice, carol) = (net.actor("alice", 0).await, net.actor("carol", 2).await);
    let syncer = MockService::syncer().await;
    let space = net.create_space(&alice, SpaceOpts { members: &[&carol], ..Default::default() }).await;
    let cred = net.credential_for(&carol, &space).await;
    let reg = json!({"space": space, "service": syncer.service_ref()});
    cred.post(&net.pds[0].url, "com.atproto.space.registerNotify", reg).await.ok();
    delete_space(&alice, &space).await.ok();
    let got = syncer
        .await_calls("com.atproto.space.notifySpaceDeleted", 1, Duration::from_secs(10))
        .await
        .expect("notifySpaceDeleted");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(syncer.calls_to("com.atproto.space.notifySpaceDeleted").len(), 1);
    assert_eq!(got[0].body["space"], json!(space));
}

/// deletion: "leaves a member repo untouched"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delete_leaves_a_member_repo_untouched() {
    let net = Net::new(1).await;
    let (alice, bob) = (net.actor("alice", 0).await, net.actor("bob", 1).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&bob], ..Default::default() }).await;
    write(&bob, &space, W::new().text("member write")).await.ok();
    delete_space(&alice, &space).await.ok();
    assert_eq!(all_records(&bob, &space).await.len(), 1);
    let listed = bob.get("com.atproto.space.listSpaces", &[]).await.ok();
    assert!(uris(&listed).contains(&space), "{listed}");
}

/// deletion: "allows re-creating a deleted space, with fresh config"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn allows_re_creating_a_deleted_space_with_fresh_config() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    let opts = |p: bool| SpaceOpts {
        skey: Some("recreate"),
        read_policy: p.then(public),
        write_policy: p.then(public),
        ..Default::default()
    };
    let space = net.create_space(&alice, opts(true)).await;
    delete_space(&alice, &space).await.ok();
    assert_eq!(net.create_space(&alice, opts(false)).await, space);
    let got = get_space(&alice, &space).await.ok();
    assert_eq!((&got["readPolicy"]["$type"], &got["writePolicy"]["$type"]), (&json!(MEMBER_LIST), &json!(MEMBER_LIST)));
    write(&alice, &space, W::new().text("after recreation")).await.ok();
}
