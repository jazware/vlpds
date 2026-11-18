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
    actor.post_bytes("com.atproto.space.importSpaceMeta", &[], archive, "application/vnd.dasl.star").await
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
    // the spaceRevs survive, so a listWriters cursor still works
    assert_eq!(meta::read(&export(&alice, &space).await).unwrap().writers, read.writers);

    // again, after a member left: the archive replaces the list
    alice.post("com.atproto.memberspace.removeMembers", json!({"space": space, "dids": [dan.did]})).await.ok();
    import(&alice, archive).await.ok();
    assert_eq!(members(&alice, &space).await.len(), 2);
}

/// "leaves a removed writer out of the archive".
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn leaves_a_removed_writer_out_of_the_archive() {
    let net = Net::new(1).await;
    let (alice, bob) = (net.actor("alice", 0).await, net.actor("bob", 0).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&bob], ..Default::default() }).await;
    write(&bob, &space, W::new()).await.ok();
    retry("bob in the writer set", || async { net.writer_dids(&alice, &space).await.contains(&bob.did).then_some(()) })
        .await;
    alice.post("com.atproto.space.removeWriter", json!({"space": space, "repo": bob.did})).await.ok();
    assert!(meta::read(&export(&alice, &space).await).unwrap().writers.is_empty());
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
    let unrecognized = |r: Resp| {
        r.err(400, "InvalidSpaceMeta");
        assert!(r.json["message"].as_str().unwrap().contains("Unrecognized policy state"), "{}", r.text());
    };
    unrecognized(
        import(&alice, with(memberspace(json!({})), vec![("com.example.thing/x".into(), member.clone())])).await,
    );
    unrecognized(import(&alice, with(personalspace(), vec![(key.clone(), member)])).await);
    let unparsed = Value::Map(vec![("read".into(), Value::Text("yes".into())), ("write".into(), Value::Bool(true))]);
    let r = import(&alice, with(memberspace(json!({})), vec![(key, unparsed)])).await;
    r.err(400, "InvalidSpaceMeta");
    assert!(r.json["message"].as_str().unwrap().contains("Invalid member"), "{}", r.text());
    import(&alice, b"not a star archive".to_vec()).await.err(400, "InvalidSpaceMeta");
    import(&bob, meta::write(&base)).await.err(400, "NotAuthorized");
}

/// "requires a grant to create and update the space to import it": the space
/// is gone from the host, so the import creates it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn import_space_meta_needs_manage_create_and_update() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    let space = net.create_space(&alice, SpaceOpts::default()).await;
    let archive = export(&alice, &space).await;
    alice.post("com.atproto.space.deleteSpace", json!({"space": space})).await.ok();
    let grant = |manage: &str| format!("space:{TEST_SPACE_TYPE}?authority={}&collection=*&{manage}", alice.did);

    let create_only = regrant(&alice, &grant("manage=create")).await;
    let r = import(&create_only, archive.clone()).await;
    r.err(403, "ScopeMissingError");
    assert!(r.json["message"].as_str().unwrap().contains("manage=update"), "{}", r.text());

    // without manage=create, refused before the body is read: a body
    // that isn't an archive gets the scope error, not InvalidSpaceMeta
    let update_only = regrant(&alice, &grant("manage=update")).await;
    let r = import(&update_only, b"not an archive".to_vec()).await;
    r.err(403, "ScopeMissingError");
    assert!(r.json["message"].as_str().unwrap().contains("manage=create"), "{}", r.text());

    // the reference's app password answer
    let s = &net.pds[0];
    let session = Auth::Bearer(alice.session_jwt.clone());
    let ap = s.xrpc.post("com.atproto.server.createAppPassword", &json!({"name": "meta"}), &session).await.ok();
    let sess = s.create_session(&alice.did, ap["password"].as_str().unwrap()).await.ok();
    let app_pw = Auth::Bearer(sess["accessJwt"].as_str().unwrap().into());
    let r = s
        .xrpc
        .post_bytes("com.atproto.space.importSpaceMeta", archive.clone(), "application/vnd.dasl.star", &app_pw)
        .await;
    r.err(400, "InvalidToken");

    let both = regrant(&alice, &grant("manage=create&manage=update")).await;
    import(&both, archive.clone()).await.ok();
    alice.get("com.atproto.space.getSpace", &[("space", &space)]).await.ok();

    // a manage-only grant, no collections, imports too
    alice.post("com.atproto.space.deleteSpace", json!({"space": space})).await.ok();
    let manage_only = regrant(
        &alice,
        &format!("space:{TEST_SPACE_TYPE}?authority={}&action=read_self&manage=create&manage=update", alice.did),
    )
    .await;
    import(&manage_only, archive).await.ok();
    alice.get("com.atproto.space.getSpace", &[("space", &space)]).await.ok();
}
