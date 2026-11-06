//! The reference's October 22 alpha changes that the older ported suites
//! don't cover:
//!
//! - credential requests without a delegation token: a public space issues
//!   one, an app allow list still holds, any other space isn't there, and a
//!   deleted one answers `SpaceDeleted` either way; a valid but unrequired
//!   assertion is accepted;
//! - notifySpaceDeleted delivered until it lands: retried after a transient
//!   failure, dropped after a permanent one, cancelled by the space being
//!   made again;
//! - `#atproto_kem` keys: in a new account's DID document and the
//!   directory, listed by getRecommendedDidCredentials, required of a PLC
//!   op, and backfilled for an account made before them.

use super::ref_net::*;
use crate::common::spaces::{get_space_credential, Holder};
use crate::common::*;
use std::time::Duration;

const NOTIFY_DELETED: &str = "com.atproto.space.notifySpaceDeleted";

/// credential requests: "issues a credential for a public space without a
/// delegation token", and the other cases a token-less request meets.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn credential_requests_without_a_delegation_token() {
    let net = Net::new(1).await;
    let (alice, bob) = (net.actor("alice", 0).await, net.actor("bob", 1).await);
    let host = net.pds[0].url.clone();
    let http = reqwest::Client::new();
    let ask = |space: String, holder: &Holder| {
        let (http, host) = (http.clone(), host.clone());
        let body = json!({"space": space, "credentialKid": holder.did});
        async move { get_space_credential(&http, &host, body).await }
    };
    // a public space: a credential with no user behind it, that reads
    let public_space = net
        .create_space(&alice, SpaceOpts { read_policy: Some(public()), skey: Some("pub"), ..Default::default() })
        .await;
    write(&alice, &public_space, W::new().rkey("open").text("for anyone")).await.ok();
    let holder = Holder::new();
    let r = ask(public_space.clone(), &holder).await.ok();
    let credential = r["credential"].as_str().unwrap().to_string();
    assert_eq!(jwt_claims(&credential)["cnf"], json!({"kid": holder.did}));
    let cred = Cred { credential, holder, http: http.clone() };
    let q = [("space", public_space.as_str()), ("repo", alice.did.as_str())];
    let latest = cred.get(&host, "com.atproto.space.getLatestCommit", &q).await.ok();
    assert_eq!(latest["commit"]["repo"], json!(alice.did));
    // a valid delegation token it didn't need is accepted
    let token = delegation_token(&bob, &public_space).await;
    net.mint_credential(&public_space, &token, None).await.0.ok();

    // a members-only space isn't there without a token, whether or not it is
    let members_only = net.create_space(&alice, SpaceOpts { skey: Some("ml"), ..Default::default() }).await;
    ask(members_only.clone(), &Holder::new()).await.err(400, "SpaceNotFound");
    let never = format!("at://{}/space/{TEST_SPACE_TYPE}/never", alice.did);
    ask(never, &Holder::new()).await.err(400, "SpaceNotFound");

    // an app allow list holds without a token
    let allowed = net
        .create_space(
            &alice,
            SpaceOpts {
                read_policy: Some(public()),
                app_access: Some(allow_list(&["https://app.example/client-metadata.json"])),
                skey: Some("apps"),
                ..Default::default()
            },
        )
        .await;
    ask(allowed, &Holder::new()).await.err(400, "AppNotAuthorized");

    // a deleted space answers SpaceDeleted, with a token or without
    alice.post("com.atproto.simplespace.deleteSpace", json!({"space": public_space})).await.ok();
    ask(public_space.clone(), &Holder::new()).await.err(400, "SpaceDeleted");
    alice.post("com.atproto.simplespace.deleteSpace", json!({"space": members_only})).await.ok();
    ask(members_only.clone(), &Holder::new()).await.err(400, "SpaceDeleted");
    let token = delegation_token(&bob, &members_only).await;
    net.mint_credential(&members_only, &token, None).await.0.err(400, "SpaceDeleted");
}

/// A space with `syncer` registered for its notifies (by a member's
/// credential), and alice its authority.
async fn registered(net: &Net, syncer: &MockService, skey: &str) -> (SpaceClient, String) {
    let (alice, carol) = (net.actor("alice", 0).await, net.actor("carol", 0).await);
    let space =
        net.create_space(&alice, SpaceOpts { members: &[&carol], skey: Some(skey), ..Default::default() }).await;
    let cred = net.credential_for(&carol, &space).await;
    let reg = json!({"space": space, "service": syncer.service_ref()});
    cred.post(&net.pds[0].url, "com.atproto.space.registerNotify", reg).await.ok();
    (alice, space)
}

use crate::common::spaces::SpaceClient;
use vlpds::space::deletions::{send_due, Outcome};

/// deletion delivery: "retries notifySpaceDeleted after a transient
/// failure": the first send is refused with a 503, the row stays, and the
/// sweep delivers it once the syncer answers.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn space_deletion_is_retried_until_delivered() {
    let net = Net::new(0).await;
    let syncer = MockService::syncer().await;
    let (alice, space) = registered(&net, &syncer, "retry").await;
    syncer.respond(503, json!({"error": "Unavailable"}));
    alice.post("com.atproto.simplespace.deleteSpace", json!({"space": space})).await.ok();
    syncer.await_calls(NOTIFY_DELETED, 1, Duration::from_secs(10)).await.expect("the first send");
    tokio::time::sleep(Duration::from_millis(500)).await;
    let app = &net.pds[0].app;
    // the first send is done and rescheduled; a sweep with everything due
    // tries again, still refused
    retry("the first send is rescheduled", || async {
        let r = send_due(app, None, u64::MAX).await.unwrap();
        (r == [Outcome::Later]).then_some(())
    })
    .await;
    syncer.respond(200, json!({}));
    assert_eq!(send_due(app, None, u64::MAX).await.unwrap(), [Outcome::Delivered]);
    assert!(send_due(app, None, u64::MAX).await.unwrap().is_empty(), "delivered rows go");
    let calls = syncer.calls_to(NOTIFY_DELETED);
    assert!(calls.len() >= 3 && calls.iter().all(|c| c.body["space"] == json!(space)), "{calls:?}");
}

/// deletion delivery: "stops on a permanent HTTP error".
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn space_deletion_stops_on_a_permanent_error() {
    let net = Net::new(0).await;
    let syncer = MockService::syncer().await;
    let (alice, space) = registered(&net, &syncer, "refused").await;
    syncer.respond(400, json!({"error": "InvalidRequest"}));
    alice.post("com.atproto.simplespace.deleteSpace", json!({"space": space})).await.ok();
    syncer.await_calls(NOTIFY_DELETED, 1, Duration::from_secs(10)).await.expect("the send");
    // the immediate send settles (a sweep now would race it), dropping the row
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(send_due(&net.pds[0].app, None, u64::MAX).await.unwrap().is_empty(), "the refused row is dropped");
    assert_eq!(syncer.calls_to(NOTIFY_DELETED).len(), 1, "not retried");
}

/// deletion delivery: "cancels pending deliveries when the space is
/// recreated": telling the syncer now would purge its new copy.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn space_deletion_is_cancelled_by_recreating_the_space() {
    let net = Net::new(0).await;
    let syncer = MockService::syncer().await;
    let (alice, space) = registered(&net, &syncer, "again").await;
    syncer.respond(503, json!({"error": "Unavailable"}));
    alice.post("com.atproto.simplespace.deleteSpace", json!({"space": space})).await.ok();
    syncer.await_calls(NOTIFY_DELETED, 1, Duration::from_secs(10)).await.expect("the first send");
    // made again (a new createdAt) before the retry
    tokio::time::sleep(Duration::from_millis(5)).await;
    let skey = last_segment(&space).to_string();
    let r = alice
        .post(
            "com.atproto.simplespace.createSpace",
            json!({"spaceType": TEST_SPACE_TYPE, "skey": skey, "readPolicy": member_list(), "writePolicy": member_list(), "appAccess": open()}),
        )
        .await;
    assert_eq!(r.ok()["uri"], json!(space));
    syncer.respond(200, json!({}));
    let sent = syncer.calls_to(NOTIFY_DELETED).len();
    let r = send_due(&net.pds[0].app, None, u64::MAX).await.unwrap();
    assert!(r.iter().all(|o| *o == Outcome::Dropped("recreated")), "{r:?}");
    assert_eq!(syncer.calls_to(NOTIFY_DELETED).len(), sent, "the recreated space's syncer wasn't told");
    assert!(send_due(&net.pds[0].app, None, u64::MAX).await.unwrap().is_empty());
}

/// `#atproto_kem`: a new account's PLC genesis op names it, its DID
/// document lists it as a P-256 Multikey, and getRecommendedDidCredentials
/// carries it; submitPlcOperation refuses an op without it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn new_accounts_publish_a_kem_key() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    let s = &net.pds[0];
    let doc =
        s.xrpc.get("com.atproto.identity.resolveDid", &[("did", &alice.did)], &Auth::None).await.ok()["didDoc"].clone();
    let kem = vlpds::space::kem::kem_key_of(&doc).unwrap_or_else(|| panic!("no #atproto_kem: {doc}"));
    let acct = s.app.account(&alice.did).await.ok().unwrap();
    let row = acct.kem_key.expect("the account holds its KEM key");
    assert_eq!(kem, format!("did:key:{}", row.pubkey));
    assert!(row.published, "minted with the DID");
    assert_ne!(row.pubkey, acct.signing_pubkey, "a key of its own");
    let session = Auth::Bearer(alice.session_jwt.clone());
    let rec = s.xrpc.get("com.atproto.identity.getRecommendedDidCredentials", &[], &session).await.ok();
    assert_eq!(rec["verificationMethods"]["atproto_kem"], json!(kem), "{rec}");
    // the directory holds it too
    let data = s.app.plc.as_ref().unwrap().client.document_data(&alice.did).await.unwrap();
    assert_eq!(data["verificationMethods"]["atproto_kem"], json!(kem), "{data}");
    // the KEM key derives the secret a syncer derives
    let acct = s.app.account(&alice.did).await.ok().unwrap();
    let k = vlpds::space::kem_keys::keypair(&s.app, &acct).await.ok().flatten().expect("the KEM keypair");
    let (share, secret) = vlpds::space::kem::encapsulate(&kem).unwrap();
    assert_eq!(vlpds::space::kem::decapsulate(&k, &share).unwrap(), secret);
}

/// `#atproto_kem`: an account made before KEM keys gets one from the
/// backfill, published to the directory with an `#identity` event.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_backfill_gives_older_accounts_a_kem_key() {
    let net = Net::new(0).await;
    let alice = net.actor("alice", 0).await;
    let s = &net.pds[0];
    // as if made before KEM keys: no key on the account, none in the directory
    s.app.mutate_account(&alice.did, false, false, false, |a| Ok(a.kem_key.take().is_some())).await.ok().unwrap();
    let plc = s.app.plc.as_ref().unwrap();
    let drop_kem = |op: &mut serde_json::Map<String, J>| -> Result<(), vlpds::plc::PlcError> {
        if let Some(J::Object(vms)) = op.get_mut("verificationMethods") {
            vms.remove("atproto_kem");
        }
        Ok(())
    };
    let last = plc.client.last_op(&alice.did).await.unwrap();
    let op = plc.update_op(&last, drop_kem).unwrap();
    plc.client.send(&alice.did, &op, "test").await.unwrap();
    s.app.did_resolver.invalidate(&alice.did);
    let doc =
        s.xrpc.get("com.atproto.identity.resolveDid", &[("did", &alice.did)], &Auth::None).await.ok()["didDoc"].clone();
    assert_eq!(vlpds::space::kem::kem_key_of(&doc), None, "{doc}");

    let mut sub = s.subscribe_from_now().await;
    let (made, published, owner, failed) = vlpds::space::kem_keys::backfill(&s.app).await.unwrap();
    assert!(made >= 1 && published >= 1 && failed == 0, "{made} {published} {owner} {failed}");
    let row = s.app.account(&alice.did).await.ok().unwrap().kem_key.expect("a key now");
    assert!(row.published);
    let data = plc.client.document_data(&alice.did).await.unwrap();
    assert_eq!(data["verificationMethods"]["atproto_kem"], json!(format!("did:key:{}", row.pubkey)));
    let did = alice.did.clone();
    sub.until(Duration::from_secs(10), move |fs| {
        fs.iter().any(|f| f.kind() == "#identity" && f.did() == Some(did.as_str()))
    })
    .await;
    // once is enough
    let again = vlpds::space::kem_keys::backfill(&s.app).await.unwrap();
    assert_eq!(again, (0, 0, 0, 0));
}
