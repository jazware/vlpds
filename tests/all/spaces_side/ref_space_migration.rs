//! The reference's tests/space/migration.test.ts, for the space meta
//! archive on one host: exportSpaceMeta, then importSpaceMeta over what's
//! held. The account move itself (a second host, the PLC op, importRepo)
//! is covered by `import_repo` and the harness's migrate e2e.

use super::ref_net::*;
use crate::common::spaces::SpaceClient;
use crate::common::*;
use vlatproto::cbor::Value;
use vlpds::space::meta::{self, Archive};

async fn export(actor: &SpaceClient, space: &str) -> Vec<u8> {
    let (status, _, body) = actor.get_raw("com.atproto.space.exportSpaceMeta", &[("space", space)]).await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    body
}

async fn import(actor: &SpaceClient, archive: Vec<u8>) -> Resp {
    actor.post_bytes("com.atproto.space.importSpaceMeta", &[], archive, "application/octet-stream").await
}

async fn members(actor: &SpaceClient, space: &str) -> Vec<J> {
    let r = actor.get("com.atproto.memberspace.listMembers", &[("space", space)]).await;
    r.ok()["members"].as_array().unwrap().clone()
}

/// "moves the spaces an account is the authority of": the policy, the
/// member list and the writer set come back from the archive (here over
/// the space's own tombstone), and importing again replaces it ("replaces
/// what the new host holds when imported again").
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_space_meta_archive_round_trips() {
    let net = Net::new(1).await;
    let (alice, bob, dan) = (net.actor("alice", 0).await, net.actor("bob", 0).await, net.actor("dan", 0).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&bob], ..Default::default() }).await;
    put_member(&alice, &space, &dan, true, false).await.ok();
    write(&bob, &space, W::new().text("from bob")).await.ok();
    write(&alice, &space, W::new().text("from alice")).await.ok();
    let writers = net.writer_dids(&alice, &space).await;
    assert_eq!(writers.len(), 2);
    let archive = export(&alice, &space).await;
    let read = meta::read(&archive).unwrap();
    assert_eq!(read.space, space);
    assert_eq!(read.policy_state.len(), 2, "both members");
    assert_eq!(read.writers.len(), 2);

    alice.post("com.atproto.space.deleteSpace", json!({"space": space})).await.ok();
    import(&alice, archive.clone()).await.ok();
    let mut got: Vec<String> =
        members(&alice, &space).await.iter().map(|m| m["did"].as_str().unwrap().to_string()).collect();
    got.sort();
    let mut want = vec![bob.did.clone(), dan.did.clone()];
    want.sort();
    assert_eq!(got, want);
    assert_eq!(net.writer_dids(&alice, &space).await, writers, "the writer set, in spaceRev order");
    // the spaceRevs survive, so a listRepos cursor still works
    assert_eq!(meta::read(&export(&alice, &space).await).unwrap().writers, read.writers);

    // again, after a member left: the archive replaces the list
    alice.post("com.atproto.memberspace.removeMember", json!({"space": space, "did": dan.did})).await.ok();
    import(&alice, archive).await.ok();
    assert_eq!(members(&alice, &space).await.len(), 2);
}

/// "rejects an archive": with a policy the host doesn't implement, policy
/// state the policy doesn't define, a member list for a policy that keeps
/// none, or bytes that don't parse; and an account imports only its own
/// spaces ("imports only the account's own spaces and repos").
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rejects_an_archive() {
    let net = Net::new(1).await;
    let (alice, bob) = (net.actor("alice", 0).await, net.actor("bob", 0).await);
    let space = net.create_space(&alice, SpaceOpts::default()).await;
    let base = meta::read(&export(&alice, &space).await).unwrap();
    let with = |policy: J, state: Vec<(String, Value)>| {
        meta::write(&Archive { policy: Value::from_json(&policy).unwrap(), policy_state: state, ..base.clone() })
    };
    let member = Value::Map(vec![("read".into(), Value::Bool(true)), ("write".into(), Value::Bool(true))]);
    let key = format!("com.atproto.memberspace.member/{}", bob.did);
    import(&alice, with(json!({"$type": "com.example.policy"}), vec![])).await.err(400, "UnsupportedPolicy");
    import(&alice, with(memberspace(json!({})), vec![("com.example.thing/x".into(), member.clone())]))
        .await
        .err(400, "InvalidRequest");
    import(&alice, with(personalspace(), vec![(key, member)])).await.err(400, "InvalidRequest");
    import(&alice, b"not a star archive".to_vec()).await.err(400, "InvalidRequest");
    import(&bob, meta::write(&base)).await.err(400, "NotSpaceOwner");
}
