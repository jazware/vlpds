//! The reference's tests/space/notifications.test.ts "space deleted": a
//! notifySpaceDeleted that fails is kept (`sD`) and retried by the
//! authority's shard owner. Retries run here through
//! `vlpds::space::deleted::retry_due` with a clock ahead of the backoff.

use super::ref_net::*;
use crate::common::*;
use std::time::Duration;

const DELETED: &str = "com.atproto.space.notifySpaceDeleted";
const HOUR: u64 = 3_600_000_000;

async fn registered(
    net: &Net,
    owner: &crate::common::spaces::SpaceClient,
    reader: &crate::common::spaces::SpaceClient,
    skey: &str,
) -> (String, MockService) {
    let syncer = MockService::syncer().await;
    let space = net.create_space(owner, SpaceOpts { skey: Some(skey), members: &[reader], ..Default::default() }).await;
    let cred = net.credential_for(reader, &space).await;
    let reg = json!({"space": space, "service": syncer.service_ref()});
    cred.post(&net.pds[0].url, "com.atproto.space.registerNotify", reg).await.ok();
    (space, syncer)
}

async fn delete(owner: &crate::common::spaces::SpaceClient, space: &str) {
    owner.post("com.atproto.space.deleteSpace", json!({"space": space})).await.ok();
}

async fn retry(net: &Net, ahead: u64) -> usize {
    vlpds::space::deleted::retry_due(&net.pds[0].app, vlatproto::tid::now_micros() + ahead).await.unwrap()
}

/// "sends immediately without queueing a successful notification", "retries
/// a transient failure until delivered" and "does not retry a permanent
/// failure".
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn deliveries_and_retries() {
    let net = Net::new(1).await;
    let (alice, bob) = (net.actor("alice", 0).await, net.actor("bob", 1).await);

    let (space, ok) = registered(&net, &alice, &bob, "sent").await;
    delete(&alice, &space).await;
    ok.await_calls(DELETED, 1, Duration::from_secs(10)).await.expect("told at once");
    assert_eq!(retry(&net, HOUR).await, 0, "nothing queued");

    let (space, flaky) = registered(&net, &alice, &bob, "flaky").await;
    flaky.respond(503, json!({"error": "Unavailable"}));
    delete(&alice, &space).await;
    flaky.await_calls(DELETED, 1, Duration::from_secs(10)).await.expect("the first try");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(retry(&net, 0).await, 0, "not due yet");
    flaky.respond(200, json!({}));
    assert_eq!(retry(&net, 2 * HOUR).await, 1, "delivered on retry");
    assert_eq!(flaky.calls_to(DELETED).len(), 2);
    assert_eq!(retry(&net, 4 * HOUR).await, 0, "and cleared");

    let (space, gone) = registered(&net, &alice, &bob, "gone").await;
    gone.respond(400, json!({"error": "InvalidRequest"}));
    delete(&alice, &space).await;
    gone.await_calls(DELETED, 1, Duration::from_secs(10)).await.expect("the first try");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(retry(&net, 2 * HOUR).await, 0, "a permanent failure isn't kept");
    assert_eq!(gone.calls_to(DELETED).len(), 1);
}

/// "stops retrying once the registration expires" and "drops retries once
/// the space is recreated".
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn retries_end_with_the_registration_or_a_new_space() {
    let net = Net::new(1).await;
    let (alice, bob) = (net.actor("alice", 0).await, net.actor("bob", 1).await);

    let (space, down) = registered(&net, &alice, &bob, "expires").await;
    down.respond(503, json!({}));
    delete(&alice, &space).await;
    down.await_calls(DELETED, 1, Duration::from_secs(10)).await.expect("the first try");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(retry(&net, 48 * HOUR).await, 1, "dropped past the registration's expiry");
    assert_eq!(down.calls_to(DELETED).len(), 1, "without another send");

    let (space, again) = registered(&net, &alice, &bob, "again").await;
    again.respond(503, json!({}));
    delete(&alice, &space).await;
    again.await_calls(DELETED, 1, Duration::from_secs(10)).await.expect("the first try");
    tokio::time::sleep(Duration::from_millis(300)).await;
    net.create_space(&alice, SpaceOpts { skey: Some("again"), ..Default::default() }).await;
    again.respond(200, json!({}));
    assert_eq!(retry(&net, 2 * HOUR).await, 1, "dropped for the new space");
    assert_eq!(again.calls_to(DELETED).len(), 1, "the new space's syncer isn't told");
}
