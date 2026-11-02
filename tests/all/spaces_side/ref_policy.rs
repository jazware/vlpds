//! Ported from the reference's `tests/space/policy.test.ts` (5d88b414, the
//! October 29 alpha): the `com.atproto.space` lifecycle methods and the
//! baseline policies (`personalspace`, `memberspace`, `managedspace`). Each
//! test names its reference case.
//!
//! Adaptations: the reference's `writerDids` reads the authority's writer
//! set from storage (`Net::writer_dids`), and its storage reads after a
//! deletion become the owner's own reads. The "client attestation" cases
//! of "credential mint gates" are ported in `ref_client_attestation` with
//! the verifier's own cases, except the one new in this release (minting
//! without a delegation token), ported here. A registration's expiry is
//! set through the authority's worker (`xrpc::space::set_registration_expiry`)
//! where the reference backdates its row.

use super::ref_net::*;
use crate::common::spaces::{Holder, SpaceClient};
use crate::common::*;
use std::time::Duration;

const MEMBERSPACE: &str = "com.atproto.memberspace.policy";
const PERSONALSPACE: &str = "com.atproto.personalspace.policy";
const MANAGEDSPACE: &str = "com.atproto.managedspace.policy";
const POLICY: &str = "com.atproto.space.policy";
const MEMBER: &str = "com.atproto.memberspace.member";
const CHECK_ACCESS: &str = "com.atproto.managedspace.checkUserAccess";
const NOTIFY_WRITE: &str = "com.atproto.space.notifyWrite";
const FORUM: &str = "did:web:example.com#forum";
const APP: &str = "https://app.example.com/client-metadata.json";

/// `memberspace.policy.$build(fields)`.
fn memberspace(fields: J) -> J {
    let mut p = json!({"$type": MEMBERSPACE});
    for (k, v) in fields.as_object().unwrap() {
        p[k] = v.clone();
    }
    p
}

fn personalspace() -> J {
    json!({"$type": PERSONALSPACE})
}

fn managedspace(app: &str) -> J {
    json!({"$type": MANAGEDSPACE, "managingApp": app})
}

/// `sc.createSpace(owner, {policy, members, skey})`: the space's URI.
async fn space_with(owner: &SpaceClient, policy: J, members: &[&SpaceClient]) -> String {
    space_at(owner, &format!("s{}", unique_name("")), policy, members).await
}

async fn space_at(owner: &SpaceClient, skey: &str, policy: J, members: &[&SpaceClient]) -> String {
    let r = owner
        .post("com.atproto.space.createSpace", json!({"spaceType": TEST_SPACE_TYPE, "skey": skey, "policy": policy}))
        .await;
    let uri = r.ok()["uri"].as_str().unwrap().to_string();
    for m in members {
        put_member(owner, &uri, m, true, true).await.ok();
    }
    uri
}

async fn get_space(c: &SpaceClient, space: &str) -> Resp {
    c.get("com.atproto.space.getSpace", &[("space", space)]).await
}

async fn update_space(owner: &SpaceClient, space: &str, policy: J) -> Resp {
    owner.post("com.atproto.space.updateSpace", json!({"space": space, "policy": policy})).await
}

async fn list_members(c: &SpaceClient, space: &str) -> Resp {
    c.get("com.atproto.memberspace.listMembers", &[("space", space)]).await
}

async fn delete_space(owner: &SpaceClient, space: &str) -> Resp {
    owner.post("com.atproto.space.deleteSpace", json!({"space": space})).await
}

fn uris(listed: &J) -> Vec<String> {
    listed["spaces"].as_array().unwrap().iter().filter_map(|s| s["uri"].as_str().map(String::from)).collect()
}

fn member_dids(listed: &J) -> Vec<String> {
    listed["members"].as_array().unwrap().iter().filter_map(|m| m["did"].as_str().map(String::from)).collect()
}

/// `sc.publicCredential(space, {clientAttestation})`: getSpaceCredential
/// without a delegation token, at the authority's PDS.
async fn public_credential(net: &Net, space: &str, attestation: Option<&str>) -> (Resp, Holder) {
    let holder = Holder::new();
    let mut body = json!({"space": space, "credentialKid": holder.did});
    if let Some(a) = attestation {
        body["clientAttestation"] = json!(a);
    }
    let host = net.host_of(authority_of(space));
    (crate::common::spaces::get_space_credential(&reqwest::Client::new(), &host, body).await, holder)
}

/// The authority's records in `collection`, as it reads them.
async fn published(alice: &SpaceClient, space: &str, collection: &str) -> Vec<J> {
    let r = alice
        .get("com.atproto.space.listRecords", &[("space", space), ("repo", &alice.did), ("collection", collection)])
        .await;
    r.ok()["records"].as_array().unwrap().clone()
}

/// The published member records as (rkey, value), by rkey.
async fn published_members(alice: &SpaceClient, space: &str) -> Vec<(String, J)> {
    let mut v: Vec<(String, J)> = published(alice, space, MEMBER)
        .await
        .into_iter()
        .map(|r| (r["rkey"].as_str().unwrap().to_string(), r["value"].clone()))
        .collect();
    v.sort_by(|a, b| a.0.cmp(&b.0));
    v
}

// ---------------------------------------------------------------------------
// lifecycle
// ---------------------------------------------------------------------------

/// lifecycle: "creates a space anchored on the caller own DID"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn creates_a_space_anchored_on_the_caller() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    let space = space_with(&alice, memberspace(json!({})), &[]).await;
    assert!(space.starts_with(&format!("at://{}/space/", alice.did)));
    let listed = alice.get("com.atproto.space.listSpaces", &[]).await.ok();
    assert!(uris(&listed).contains(&space), "{listed}");
}

/// lifecycle: "refuses a duplicate space"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_a_duplicate_space() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    let space = space_with(&alice, memberspace(json!({})), &[]).await;
    let body = json!({"spaceType": TEST_SPACE_TYPE, "skey": last_segment(&space), "policy": memberspace(json!({}))});
    alice.post("com.atproto.space.createSpace", body).await.err(400, "SpaceAlreadyExists");
}

/// lifecycle: "refuses a space key that is not a valid record key"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_a_space_key_that_is_not_a_record_key() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    let body = json!({"spaceType": TEST_SPACE_TYPE, "skey": "not a valid rkey", "policy": memberspace(json!({}))});
    let r = alice.post("com.atproto.space.createSpace", body).await;
    refused_mentioning(&r, &["record key"]);
}

/// lifecycle: "filters spaces by spaceType"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn filters_spaces_by_space_type() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    let space = space_with(&alice, memberspace(json!({})), &[]).await;
    let other = net.create_space(&alice, SpaceOpts { space_type: Some(OTHER_SPACE_TYPE), ..Default::default() }).await;
    let listed = uris(&alice.get("com.atproto.space.listSpaces", &[("spaceType", TEST_SPACE_TYPE)]).await.ok());
    assert!(listed.contains(&space) && !listed.contains(&other), "{listed:?}");
    let listed = uris(&alice.get("com.atproto.space.listSpaces", &[("spaceType", OTHER_SPACE_TYPE)]).await.ok());
    assert_eq!(listed, [other]);
}

/// lifecycle: "refuses an owner write until createSpace". vlpds still lets
/// the authority write first and governs the space once it's created (the
/// October 1 alpha's `ensureSpace`): see `spaces_host::written_before_created`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "vlpds: an authority's write to its own never-created space is taken, not refused SpaceNotFound"]
async fn refuses_an_owner_write_until_create_space() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    let space = format!("at://{}/space/{TEST_SPACE_TYPE}/lazy", alice.did);
    write(&alice, &space, W::new().text("too early")).await.err(400, "SpaceNotFound");
    space_at(&alice, "lazy", memberspace(json!({})), &[]).await;
    write(&alice, &space, W::new().text("lazy space")).await.ok();
    assert_eq!(all_records(&alice, &space).await.len(), 1);
}

// ---------------------------------------------------------------------------
// memberspace members
// ---------------------------------------------------------------------------

/// memberspace members: "adds and removes members, and the owner is not one
/// of them"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn adds_and_removes_members() {
    let net = Net::new(1).await;
    let (alice, dan, bob) = (net.actor("alice", 0).await, net.actor("dan", 0).await, net.actor("bob", 1).await);
    let space = space_with(&alice, memberspace(json!({})), &[&dan]).await;
    put_member(&alice, &space, &bob, true, false).await.ok();
    let members = list_members(&alice, &space).await.ok();
    let dids = member_dids(&members);
    assert!(!dids.contains(&alice.did), "the authority isn't on the member list");
    assert!(dids.contains(&dan.did) && dids.contains(&bob.did), "{members}");
    let b = members["members"].as_array().unwrap().iter().find(|m| m["did"] == json!(bob.did)).unwrap().clone();
    assert_eq!((&b["read"], &b["write"]), (&json!(true), &json!(false)));

    remove_member(&alice, &space, &bob).await.ok();
    assert!(!member_dids(&list_members(&alice, &space).await.ok()).contains(&bob.did));
}

/// memberspace members: "refuses membership changes from a non-owner member"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_membership_changes_from_a_non_owner() {
    let net = Net::new(2).await;
    let (alice, dan, carol) = (net.actor("alice", 0).await, net.actor("dan", 0).await, net.actor("carol", 2).await);
    let space = space_with(&alice, memberspace(json!({})), &[&dan]).await;
    put_member(&dan, &space, &carol, true, true).await.err(400, "NotSpaceOwner");
    remove_member(&dan, &space, &dan).await.err(400, "NotSpaceOwner");
}

/// memberspace members: "refuses listMembers to a space credential and to a
/// non-owner member"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_list_members_to_a_credential_and_a_non_owner() {
    let net = Net::new(2).await;
    let (alice, dan, carol) = (net.actor("alice", 0).await, net.actor("dan", 0).await, net.actor("carol", 2).await);
    let space = space_with(&alice, memberspace(json!({})), &[&carol, &dan]).await;
    let cred = net.credential_for(&carol, &space).await;
    cred.get(&net.pds[0].url, "com.atproto.memberspace.listMembers", &[("space", &space)]).await.client_err();
    list_members(&dan, &space).await.err(400, "NotSpaceOwner");
}

/// memberspace members: "putMember replaces both access values"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn put_member_replaces_both_access_values() {
    let net = Net::new(1).await;
    let (alice, bob) = (net.actor("alice", 0).await, net.actor("bob", 1).await);
    let space = space_with(&alice, memberspace(json!({})), &[]).await;
    put_member(&alice, &space, &bob, true, false).await.ok();
    put_member(&alice, &space, &bob, false, true).await.ok();
    let members = list_members(&alice, &space).await.ok();
    let ms = members["members"].as_array().unwrap();
    assert_eq!(ms.iter().filter(|m| m["did"] == json!(bob.did)).count(), 1);
    assert_eq!((&ms[0]["did"], &ms[0]["read"], &ms[0]["write"]), (&json!(bob.did), &json!(false), &json!(true)));
}

/// memberspace members: "refuses member methods on a space under another
/// policy"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_member_methods_under_another_policy() {
    let net = Net::new(1).await;
    let (alice, bob) = (net.actor("alice", 0).await, net.actor("bob", 1).await);
    let space = space_with(&alice, personalspace(), &[]).await;
    put_member(&alice, &space, &bob, true, true).await.err(400, "PolicyMismatch");
    remove_member(&alice, &space, &bob).await.err(400, "PolicyMismatch");
    list_members(&alice, &space).await.err(400, "PolicyMismatch");
}

/// memberspace members: "removeMember drops the member from the writer set"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn remove_member_drops_the_member_from_the_writer_set() {
    let net = Net::new(0).await;
    let (alice, dan) = (net.actor("alice", 0).await, net.actor("dan", 0).await);
    let space = space_with(&alice, memberspace(json!({})), &[&dan]).await;
    write(&dan, &space, W::new().text("from a member")).await.ok();
    assert_eq!(net.await_writer(&alice, &space, &dan.did).await, [dan.did.clone()]);
    remove_member(&alice, &space, &dan).await.ok();
    assert!(net.writer_dids(&alice, &space).await.is_empty());
}

/// memberspace members: "putMember drops the member from the writer set
/// when it revokes write"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn put_member_drops_the_member_from_the_writer_set_when_it_revokes_write() {
    let net = Net::new(0).await;
    let (alice, dan) = (net.actor("alice", 0).await, net.actor("dan", 0).await);
    let space = space_with(&alice, memberspace(json!({})), &[&dan]).await;
    write(&dan, &space, W::new().text("from a member")).await.ok();
    net.await_writer(&alice, &space, &dan.did).await;
    put_member(&alice, &space, &dan, true, true).await.ok();
    assert_eq!(net.writer_dids(&alice, &space).await, [dan.did.clone()]);
    put_member(&alice, &space, &dan, true, false).await.ok();
    assert!(net.writer_dids(&alice, &space).await.is_empty());
}

// ---------------------------------------------------------------------------
// policy
// ---------------------------------------------------------------------------

/// policy: "persists what createSpace was given"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn persists_what_create_space_was_given() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    let space = space_with(&alice, managedspace(FORUM), &[]).await;
    let got = get_space(&alice, &space).await.ok();
    assert_eq!(got["uri"], json!(space));
    assert_eq!(got["policy"], json!({"$type": MANAGEDSPACE, "managingApp": FORUM, "publishPolicy": false}));
}

/// policy: "fills in the defaults of an omitted configuration"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fills_in_the_defaults_of_an_omitted_configuration() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    let space = space_with(&alice, memberspace(json!({})), &[]).await;
    assert_eq!(
        get_space(&alice, &space).await.ok()["policy"],
        json!({"$type": MEMBERSPACE, "publicRead": false, "publicWrite": false, "publishPolicy": false, "publishMembers": false})
    );
}

/// policy: "replaces the policy wholesale on update"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replaces_the_policy_wholesale_on_update() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    let space =
        space_with(&alice, memberspace(json!({"publicRead": true, "allowedApps": ["app:x"], "publishMembers": true})), &[])
            .await;
    update_space(&alice, &space, memberspace(json!({"publicWrite": true}))).await.ok();
    assert_eq!(
        get_space(&alice, &space).await.ok()["policy"],
        json!({"$type": MEMBERSPACE, "publicRead": false, "publicWrite": true, "publishPolicy": false, "publishMembers": false})
    );
}

/// policy: "keeps the member list across a configuration change"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn keeps_the_member_list_across_a_configuration_change() {
    let net = Net::new(1).await;
    let (alice, bob) = (net.actor("alice", 0).await, net.actor("bob", 1).await);
    let space = space_with(&alice, memberspace(json!({})), &[&bob]).await;
    update_space(&alice, &space, memberspace(json!({"publicRead": true}))).await.ok();
    assert_eq!(member_dids(&list_members(&alice, &space).await.ok()), [bob.did.clone()]);
}

/// policy: "refuses an update from a non-owner" (bob's token, presented to
/// the authority's PDS, and at his own)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_an_update_from_a_non_owner() {
    let net = Net::new(1).await;
    let (alice, bob) = (net.actor("alice", 0).await, net.actor("bob", 1).await);
    let space = space_with(&alice, memberspace(json!({})), &[&bob]).await;
    let body = json!({"space": space, "policy": memberspace(json!({"publicRead": true}))});
    post_at(&bob, &net.pds[0].url, "com.atproto.space.updateSpace", body.clone()).await.client_err();
    bob.post("com.atproto.space.updateSpace", body).await.client_err();
    assert_eq!(get_space(&alice, &space).await.ok()["policy"]["publicRead"], json!(false));
}

/// policy: "refuses an unrecognized policy"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_an_unrecognized_policy() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    let space = space_with(&alice, memberspace(json!({})), &[]).await;
    update_space(&alice, &space, json!({"$type": "com.example.whatever"})).await.err(400, "UnsupportedPolicy");
}

/// policy: "refuses a managingApp that does not name a service"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_a_managing_app_that_is_not_a_did() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    let space = space_with(&alice, memberspace(json!({})), &[]).await;
    let r = update_space(&alice, &space, managedspace("not-a-did-at-all")).await;
    refused_mentioning(&r, &["must be a DID"]);
}

/// policy: "refuses the policy to a member with a space credential"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_the_policy_to_a_member_credential() {
    let net = Net::new(2).await;
    let (alice, carol) = (net.actor("alice", 0).await, net.actor("carol", 2).await);
    let space = space_with(&alice, memberspace(json!({})), &[&carol]).await;
    let cred = net.credential_for(&carol, &space).await;
    cred.get(&net.pds[0].url, "com.atproto.space.getSpace", &[("space", &space)]).await.client_err();
}

/// policy: "refuses the policy to another account on an account credential"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_the_policy_to_another_account() {
    let net = Net::new(0).await;
    let (alice, dan) = (net.actor("alice", 0).await, net.actor("dan", 0).await);
    let space = space_with(&alice, memberspace(json!({})), &[&dan]).await;
    get_space(&dan, &space).await.err(400, "NotSpaceOwner");
}

/// policy: "refuses to answer for a space this host does not govern"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_to_answer_for_a_space_this_host_does_not_govern() {
    let net = Net::new(1).await;
    let (alice, bob) = (net.actor("alice", 0).await, net.actor("bob", 1).await);
    let space = space_with(&alice, memberspace(json!({})), &[&bob]).await;
    let cred = net.credential_for(&bob, &space).await;
    cred.get(&net.pds[1].url, "com.atproto.space.listRepos", &[("space", &space)]).await.err(400, "SpaceNotFound");
    get_space(&bob, &space).await.client_err();
}

// ---------------------------------------------------------------------------
// policy migration
// ---------------------------------------------------------------------------

/// policy migration: "discards the member list, and migrating back does
/// not restore it"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn migration_discards_the_member_list() {
    let net = Net::new(2).await;
    let (alice, bob, carol) = (net.actor("alice", 0).await, net.actor("bob", 1).await, net.actor("carol", 2).await);
    let space = space_with(&alice, memberspace(json!({})), &[&bob, &carol]).await;
    update_space(&alice, &space, personalspace()).await.ok();
    update_space(&alice, &space, memberspace(json!({}))).await.ok();
    assert_eq!(list_members(&alice, &space).await.ok()["members"], json!([]));
    let token = delegation_token(&bob, &space).await;
    net.mint_credential(&space, &token, None).await.0.err(400, "SpaceNotFound");
}

// ---------------------------------------------------------------------------
// publishing to readers
// ---------------------------------------------------------------------------

/// publishing to readers: "publishes the policy to readers"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn publishes_the_policy_to_readers() {
    let net = Net::new(2).await;
    let (alice, carol) = (net.actor("alice", 0).await, net.actor("carol", 2).await);
    let space = space_with(&alice, memberspace(json!({"publishPolicy": true})), &[&carol]).await;
    let policy = get_space(&alice, &space).await.ok()["policy"].clone();
    let cred = net.credential_for(&carol, &space).await;
    let q = [("space", space.as_str()), ("repo", alice.did.as_str()), ("collection", POLICY)];
    let res = cred.get(&net.pds[0].url, "com.atproto.space.listRecords", &q).await.ok();
    let records = res["records"].as_array().unwrap();
    assert_eq!(records.len(), 1, "{res}");
    assert_eq!(records[0]["rkey"], json!("self"));
    assert_eq!(records[0]["value"], json!({"$type": POLICY, "policy": policy}));
}

/// publishing to readers: "keeps the published policy in sync, and
/// withdraws it when unpublished"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn keeps_the_published_policy_in_sync() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    let mut managed = managedspace(FORUM);
    managed["publishPolicy"] = json!(true);
    let space = space_with(&alice, managed, &[]).await;
    update_space(&alice, &space, memberspace(json!({"publicRead": true, "publishPolicy": true}))).await.ok();
    let records = published(&alice, &space, POLICY).await;
    assert_eq!(records[0]["value"], json!({"$type": POLICY, "policy": get_space(&alice, &space).await.ok()["policy"]}));
    update_space(&alice, &space, memberspace(json!({}))).await.ok();
    assert!(published(&alice, &space, POLICY).await.is_empty());
}

/// publishing to readers: "publishes the member list, keyed by member DID"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn publishes_the_member_list_keyed_by_member_did() {
    let net = Net::new(2).await;
    let (alice, bob, carol) = (net.actor("alice", 0).await, net.actor("bob", 1).await, net.actor("carol", 2).await);
    let space = space_with(&alice, memberspace(json!({"publishMembers": true})), &[]).await;
    put_member(&alice, &space, &bob, true, true).await.ok();
    put_member(&alice, &space, &carol, true, true).await.ok();
    put_member(&alice, &space, &carol, true, false).await.ok();
    remove_member(&alice, &space, &bob).await.ok();
    assert_eq!(
        published_members(&alice, &space).await,
        [(carol.did.clone(), json!({"$type": MEMBER, "read": true, "write": false}))]
    );
}

/// publishing to readers: "leaves the port of a localhost did:web unencoded
/// in its record key"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn leaves_a_localhost_did_web_port_unencoded_in_its_record_key() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    let space = space_with(&alice, memberspace(json!({"publishMembers": true})), &[]).await;
    let did = "did:web:localhost%3A2583";
    let member = json!({"space": space, "did": did, "read": true, "write": true});
    alice.post("com.atproto.memberspace.putMember", member).await.ok();
    let got = published_members(&alice, &space).await;
    assert_eq!(got.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>(), ["did:web:localhost:2583"]);
    alice.post("com.atproto.memberspace.removeMember", json!({"space": space, "did": did})).await.ok();
    assert!(published_members(&alice, &space).await.is_empty());
}

/// publishing to readers: "publishes or withdraws the whole member list
/// when publishMembers changes"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn publishes_or_withdraws_the_whole_member_list() {
    let net = Net::new(2).await;
    let (alice, bob, carol) = (net.actor("alice", 0).await, net.actor("bob", 1).await, net.actor("carol", 2).await);
    let space = space_with(&alice, memberspace(json!({})), &[&bob, &carol]).await;
    assert!(published_members(&alice, &space).await.is_empty());
    update_space(&alice, &space, memberspace(json!({"publishMembers": true}))).await.ok();
    let mut want = vec![bob.did.clone(), carol.did.clone()];
    want.sort();
    let got: Vec<String> = published_members(&alice, &space).await.into_iter().map(|(k, _)| k).collect();
    assert_eq!(got, want);
    update_space(&alice, &space, memberspace(json!({}))).await.ok();
    assert!(published_members(&alice, &space).await.is_empty());
}

/// publishing to readers: "withdraws the published member list on migration"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn withdraws_the_published_member_list_on_migration() {
    let net = Net::new(1).await;
    let (alice, bob) = (net.actor("alice", 0).await, net.actor("bob", 1).await);
    let space = space_with(&alice, memberspace(json!({"publishMembers": true})), &[&bob]).await;
    assert_eq!(published_members(&alice, &space).await.len(), 1);
    update_space(&alice, &space, personalspace()).await.ok();
    assert!(published_members(&alice, &space).await.is_empty());
}

/// publishing to readers: "keeps the published records when the authority
/// clears its repo"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn keeps_the_published_records_when_the_authority_clears_its_repo() {
    let net = Net::new(1).await;
    let (alice, bob) = (net.actor("alice", 0).await, net.actor("bob", 1).await);
    let space =
        space_with(&alice, memberspace(json!({"publishPolicy": true, "publishMembers": true})), &[&bob]).await;
    write(&alice, &space, W::new().rkey("own")).await.ok();
    let clear = || alice.post("com.atproto.space.clearRecords", json!({"space": space, "repo": alice.did}));
    clear().await.ok();
    let mut collections: Vec<String> =
        all_records(&alice, &space).await.iter().map(|r| r["collection"].as_str().unwrap().to_string()).collect();
    collections.sort();
    assert_eq!(collections, [MEMBER, POLICY]);
    expect_set_hash_matches_store(&alice, &space).await;
    // With only the published records left, there is nothing more to clear.
    let cleared = repo_state(&alice, &space).await;
    clear().await.ok();
    assert_eq!(repo_state(&alice, &space).await, cleared);
}

/// publishing to readers: "notifies the space of what it publishes"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn notifies_the_space_of_what_it_publishes() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    let space = space_with(&alice, memberspace(json!({"publishPolicy": true})), &[]).await;
    assert_eq!(net.await_writer(&alice, &space, &alice.did).await, [alice.did.clone()]);
}

/// publishing to readers: "refuses direct writes of published records"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_direct_writes_of_published_records() {
    let net = Net::new(2).await;
    let (alice, bob, carol) = (net.actor("alice", 0).await, net.actor("bob", 1).await, net.actor("carol", 2).await);
    let space = space_with(&alice, memberspace(json!({"publishPolicy": true})), &[&bob]).await;
    let rec = json!({"$type": POLICY, "policy": {"$type": PERSONALSPACE}});
    let refused = ["cannot be written directly"];
    // In any repo, not only the authority's.
    refused_mentioning(&put(&alice, &space, W::new().collection(POLICY).rkey("self").record(rec.clone())).await, &refused);
    let member = json!({"$type": MEMBER, "read": true, "write": true});
    refused_mentioning(&write(&bob, &space, W::new().collection(MEMBER).rkey(&carol.did).record(member)).await, &refused);
    let writes = json!([{"$type": "com.atproto.space.applyWrites#create", "collection": POLICY, "rkey": "self", "value": rec}]);
    let r = bob.post("com.atproto.space.applyWrites", json!({"space": space, "repo": bob.did, "writes": writes})).await;
    refused_mentioning(&r, &refused);
    // Turning validation off doesn't open a way around it.
    let r = put(&alice, &space, W::new().collection(POLICY).rkey("self").record(rec).validate(false)).await;
    refused_mentioning(&r, &refused);
    // Nor can the published policy be withdrawn other than by the policy.
    refused_mentioning(&del(&alice, &space, Some(POLICY), "self").await, &refused);
    assert_eq!(published(&alice, &space, POLICY).await.len(), 1);
}

// ---------------------------------------------------------------------------
// personalspace policy
// ---------------------------------------------------------------------------

/// personalspace policy: "authorizes only the authority to read"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn personalspace_authorizes_only_the_authority_to_read() {
    let net = Net::new(2).await;
    let (alice, carol) = (net.actor("alice", 0).await, net.actor("carol", 2).await);
    let space = space_with(&alice, personalspace(), &[]).await;
    assert!(!net.credential_for(&alice, &space).await.credential.is_empty());
    let token = delegation_token(&carol, &space).await;
    net.mint_credential(&space, &token, None).await.0.err(400, "SpaceNotFound");
}

/// personalspace policy: "tracks no writer but the authority"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn personalspace_tracks_no_writer_but_the_authority() {
    let net = Net::new(1).await;
    let (alice, bob) = (net.actor("alice", 0).await, net.actor("bob", 1).await);
    let space = space_with(&alice, personalspace(), &[]).await;
    write(&alice, &space, W::new().text("my bookmark")).await.ok();
    // Bob may still write to his own repo in the space, but the authority
    // refuses his notification, so no syncer discovers it.
    write(&bob, &space, W::new().text("not tracked")).await.ok();
    net.await_writer(&alice, &space, &alice.did).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(net.writer_dids(&alice, &space).await, [alice.did.clone()]);
}

// ---------------------------------------------------------------------------
// credential mint gates
// ---------------------------------------------------------------------------

/// credential mint gates: "mints for a non-member when read access is public"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mints_for_a_non_member_when_read_access_is_public() {
    let net = Net::new(2).await;
    let (alice, carol) = (net.actor("alice", 0).await, net.actor("carol", 2).await);
    let space = space_with(&alice, memberspace(json!({"publicRead": true})), &[]).await;
    assert!(!net.credential_for(&carol, &space).await.credential.is_empty());
}

/// credential mint gates: "mints without a delegation token when read
/// access is public"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mints_without_a_delegation_token_when_read_access_is_public() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    let space = space_with(&alice, memberspace(json!({"publicRead": true})), &[]).await;
    write(&alice, &space, W::new().text("for anyone")).await.ok();
    let (r, holder) = public_credential(&net, &space, None).await;
    let credential = r.ok()["credential"].as_str().unwrap().to_string();
    let cred = Cred { credential, holder, http: reqwest::Client::new() };
    let q = [("space", space.as_str()), ("repo", alice.did.as_str())];
    let res = cred.get(&net.pds[0].url, "com.atproto.space.listRecords", &q).await.ok();
    assert_eq!(res["records"].as_array().unwrap().len(), 1, "{res}");
}

/// credential mint gates: "hides a $name space from a request without a
/// delegation token" (memberspace, personalspace, managedspace)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hides_a_space_from_a_request_without_a_delegation_token() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    for policy in [memberspace(json!({})), personalspace(), managedspace("did:web:unreachable.invalid#forum")] {
        let space = space_with(&alice, policy.clone(), &[]).await;
        let (r, _) = public_credential(&net, &space, None).await;
        assert_eq!(r.error_name(), Some("SpaceNotFound"), "{policy}: {}", r.text());
    }
}

/// credential mint gates: "hides a space from a request without a
/// delegation token before checking the app"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hides_a_tokenless_request_before_checking_the_app() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    let space = space_with(&alice, memberspace(json!({"allowedApps": [APP]})), &[]).await;
    public_credential(&net, &space, None).await.0.err(400, "SpaceNotFound");
}

/// credential mint gates: "refuses a request without a delegation token or
/// attestation when apps are restricted"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_a_tokenless_request_without_an_attestation_when_apps_are_restricted() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    let space = space_with(&alice, memberspace(json!({"publicRead": true, "allowedApps": [APP]})), &[]).await;
    public_credential(&net, &space, None).await.0.err(400, "AppNotAuthorized");
}

/// credential mint gates: "hides the space from a non-member when read
/// access is not public"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hides_the_space_from_a_non_member() {
    let net = Net::new(2).await;
    let (alice, carol) = (net.actor("alice", 0).await, net.actor("carol", 2).await);
    let space = space_with(&alice, memberspace(json!({})), &[]).await;
    let token = delegation_token(&carol, &space).await;
    net.mint_credential(&space, &token, None).await.0.err(400, "SpaceNotFound");
}

/// credential mint gates: "hides the space from a non-member before
/// checking the app"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hides_the_space_from_a_non_member_before_checking_the_app() {
    let net = Net::new(2).await;
    let (alice, carol) = (net.actor("alice", 0).await, net.actor("carol", 2).await);
    let space = space_with(&alice, memberspace(json!({"allowedApps": [APP]})), &[]).await;
    let token = delegation_token(&carol, &space).await;
    net.mint_credential(&space, &token, None).await.0.err(400, "SpaceNotFound");
}

/// credential mint gates: "hides the space from a member without read
/// access"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hides_the_space_from_a_member_without_read_access() {
    let net = Net::new(2).await;
    let (alice, carol) = (net.actor("alice", 0).await, net.actor("carol", 2).await);
    let space = space_with(&alice, memberspace(json!({})), &[]).await;
    put_member(&alice, &space, &carol, false, true).await.ok();
    let token = delegation_token(&carol, &space).await;
    net.mint_credential(&space, &token, None).await.0.err(400, "SpaceNotFound");
}

/// credential mint gates: "always admits the authority, whatever the policy"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn always_admits_the_authority() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    let space = space_with(&alice, managedspace("did:web:unreachable.invalid#forum"), &[]).await;
    assert!(!net.credential_for(&alice, &space).await.credential.is_empty());
}

/// credential mint gates: "refuses when apps are restricted and no
/// attestation is presented"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_restricted_apps_without_an_attestation() {
    let net = Net::new(2).await;
    let (alice, carol) = (net.actor("alice", 0).await, net.actor("carol", 2).await);
    let space = space_with(&alice, memberspace(json!({"publicRead": true, "allowedApps": [APP]})), &[]).await;
    let token = delegation_token(&carol, &space).await;
    net.mint_credential(&space, &token, None).await.0.err(400, "AppNotAuthorized");
}

/// credential mint gates, client attestation: "mints for an allow-listed
/// app without a delegation token"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mints_for_an_allow_listed_app_without_a_delegation_token() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    let app = MockClientApp::spawn(Keys::Uri).await;
    let space =
        space_with(&alice, memberspace(json!({"publicRead": true, "allowedApps": [app.client_id.clone()]})), &[]).await;
    let attestation = app.attest(&vlpds::space::token::space_host_aud(&alice.did), Attest::default());
    let (r, _) = public_credential(&net, &space, Some(&attestation)).await;
    assert!(r.ok()["credential"].is_string());
}

// ---------------------------------------------------------------------------
// managedspace policy
// ---------------------------------------------------------------------------

async fn forum(authorized: Option<bool>) -> MockService {
    let app = MockService::spawn(&[("atproto_forum", "AtprotoForum")]).await;
    match authorized {
        Some(a) => app.respond(200, json!({"authorized": a})),
        None => app.respond(500, json!({"error": "InternalError"})),
    }
    app
}

/// managedspace policy: "admits a user the managing app authorizes" (and
/// the service auth names the new NSID as its `lxm`)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn managing_app_admits_a_user_it_authorizes() {
    let net = Net::new(2).await;
    let (alice, carol) = (net.actor("alice", 0).await, net.actor("carol", 2).await);
    let app = forum(Some(true)).await;
    let space = space_with(&alice, managedspace(&app.service_ref()), &[]).await;
    assert!(!net.credential_for(&carol, &space).await.credential.is_empty());
    let asked = app.calls_to(CHECK_ACCESS);
    assert_eq!(asked.len(), 1);
    assert_eq!(
        (&asked[0].body["space"], &asked[0].body["user"], &asked[0].body["access"]),
        (&json!(space), &json!(carol.did), &json!("read"))
    );
    let auth = asked[0].auth.as_deref().unwrap_or("");
    assert!(auth.starts_with("Bearer "), "{auth}");
    let claims = jwt_claims(auth.trim_start_matches("Bearer "));
    assert_eq!((&claims["iss"], &claims["lxm"]), (&json!(alice.did), &json!(CHECK_ACCESS)));
}

/// managedspace policy: "refuses a user the managing app declines"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn managing_app_refuses_a_user_it_declines() {
    let net = Net::new(2).await;
    let (alice, carol) = (net.actor("alice", 0).await, net.actor("carol", 2).await);
    let app = forum(Some(false)).await;
    let space = space_with(&alice, managedspace(&app.service_ref()), &[]).await;
    let token = delegation_token(&carol, &space).await;
    net.mint_credential(&space, &token, None).await.0.err(400, "SpaceNotFound");
}

/// managedspace policy: "denies when the managing app errors"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn managing_app_denies_when_it_errors() {
    let net = Net::new(2).await;
    let (alice, carol) = (net.actor("alice", 0).await, net.actor("carol", 2).await);
    let app = forum(None).await;
    let space = space_with(&alice, managedspace(&app.service_ref()), &[]).await;
    let token = delegation_token(&carol, &space).await;
    net.mint_credential(&space, &token, None).await.0.err(400, "SpaceNotFound");
}

/// managedspace policy: "denies when the managing app cannot be resolved"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn managing_app_denies_when_unresolvable() {
    let net = Net::new(2).await;
    let (alice, carol) = (net.actor("alice", 0).await, net.actor("carol", 2).await);
    let space = space_with(&alice, managedspace("did:web:nonexistent.invalid#forum"), &[]).await;
    let token = delegation_token(&carol, &space).await;
    net.mint_credential(&space, &token, None).await.0.err(400, "SpaceNotFound");
}

/// managedspace policy: "records a writer the managing app admits" (asked
/// with `access=write` and no `clientId`)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn managing_app_admits_a_writer() {
    let net = Net::new(1).await;
    let (alice, bob) = (net.actor("alice", 0).await, net.actor("bob", 1).await);
    let app = forum(Some(true)).await;
    let space = space_with(&alice, managedspace(&app.service_ref()), &[]).await;
    write(&bob, &space, W::new().text("admitted by the managing app")).await.ok();
    let dids = net.await_writer(&alice, &space, &bob.did).await;
    assert!(dids.contains(&bob.did), "{dids:?}");
    let asked = app.calls_to(CHECK_ACCESS);
    let w = asked.iter().find(|c| c.body["user"] == json!(bob.did) && c.body["access"] == json!("write"));
    let w = w.unwrap_or_else(|| panic!("{asked:?}"));
    assert_eq!(w.body["space"], json!(space));
    assert!(w.body.get("clientId").is_none(), "{:?}", w.body);
}

// ---------------------------------------------------------------------------
// notify registration
// ---------------------------------------------------------------------------

/// notify registration: "registers, forwards writes, and stops once
/// withdrawn"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn registers_forwards_writes_and_stops_once_withdrawn() {
    let net = Net::new(2).await;
    let (alice, bob, carol) = (net.actor("alice", 0).await, net.actor("bob", 1).await, net.actor("carol", 2).await);
    let syncer = MockService::syncer().await;
    let space = space_with(&alice, memberspace(json!({})), &[&bob, &carol]).await;
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
/// expiry, and resumes on renewal". vlpds prunes an expired registration
/// rather than withholding it, and a renewal registers it again either way.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stops_past_expiry_and_resumes_on_renewal() {
    let net = Net::new(2).await;
    let (alice, bob, carol) = (net.actor("alice", 0).await, net.actor("bob", 1).await, net.actor("carol", 2).await);
    let syncer = MockService::syncer().await;
    let space = space_with(&alice, memberspace(json!({})), &[&bob, &carol]).await;
    let cred = net.credential_for(&carol, &space).await;
    let pds1 = &net.pds[0].url;
    let reg = json!({"space": space, "service": syncer.service_ref()});
    cred.post(pds1, "com.atproto.space.registerNotify", reg.clone()).await.ok();
    let expired = vlatproto::tid::now_micros() - 1_000_000;
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
    let space = space_with(&alice, memberspace(json!({})), &[&carol]).await;
    let cred = net.credential_for(&carol, &space).await;
    let body = json!({"space": space, "service": "did:web:nonexistent.invalid#syncer"});
    cred.post(&net.pds[0].url, "com.atproto.space.registerNotify", body).await.err(400, "ServiceNotResolvable");
}

// ---------------------------------------------------------------------------
// deletion
// ---------------------------------------------------------------------------

/// deletion: "purges the authority own repo and keeps a tombstone" (the
/// blob is gone once space.getBlob no longer serves it; the member list is
/// gone with the space)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delete_purges_the_authority_repo_and_keeps_a_tombstone() {
    let net = Net::new(1).await;
    let (alice, bob) = (net.actor("alice", 0).await, net.actor("bob", 1).await);
    let space = space_with(&alice, memberspace(json!({})), &[&bob]).await;
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
    let space = space_with(&alice, memberspace(json!({})), &[&carol]).await;
    let token = delegation_token(&carol, &space).await;
    delete_space(&alice, &space).await.ok();
    net.mint_credential(&space, &token, None).await.0.err(400, "SpaceDeleted");
}

/// deletion: "answers SpaceDeleted to a request without a delegation token"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn answers_space_deleted_without_a_delegation_token() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    let space = space_with(&alice, memberspace(json!({"publicRead": true})), &[]).await;
    delete_space(&alice, &space).await.ok();
    public_credential(&net, &space, None).await.0.err(400, "SpaceDeleted");
}

/// deletion: "notifies registered syncers"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delete_notifies_registered_syncers() {
    let net = Net::new(2).await;
    let (alice, carol) = (net.actor("alice", 0).await, net.actor("carol", 2).await);
    let syncer = MockService::syncer().await;
    let space = space_with(&alice, memberspace(json!({})), &[&carol]).await;
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
    let space = space_with(&alice, memberspace(json!({})), &[&bob]).await;
    write(&bob, &space, W::new().text("member write")).await.ok();
    delete_space(&alice, &space).await.ok();
    assert_eq!(all_records(&bob, &space).await.len(), 1);
    let listed = bob.get("com.atproto.space.listSpaces", &[]).await.ok();
    assert!(uris(&listed).contains(&space), "{listed}");
}

/// deletion: "allows re-creating a deleted space, with a fresh policy"
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn allows_re_creating_a_deleted_space_with_a_fresh_policy() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    let space = space_at(&alice, "recreate", memberspace(json!({"publicRead": true, "publicWrite": true})), &[]).await;
    delete_space(&alice, &space).await.ok();
    assert_eq!(space_at(&alice, "recreate", memberspace(json!({})), &[]).await, space);
    let got = get_space(&alice, &space).await.ok();
    assert_eq!((&got["policy"]["publicRead"], &got["policy"]["publicWrite"]), (&json!(false), &json!(false)));
    write(&alice, &space, W::new().text("after recreation")).await.ok();
}
