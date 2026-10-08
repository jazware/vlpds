//! Signing-key rotation (src/xrpc/key_rotation.rs, DESIGN.md "Signing-key
//! rotation"): `admin.updateAccountSigningKey` re-signs the repo with the
//! new key and emits `#identity` then `#sync`, as the reference's
//! rotate-keys; writes racing the rotation are either before it (old key)
//! or after it (new key, chained off the `#sync`); a PLC refusal changes
//! nothing; a PLC outage or a crash between the steps leaves the rotation
//! pending (writes fenced), and it is finished from durable state by a
//! retried `updateAccountSigningKey` or by the first write it fences.

use crate::common::*;
use k256::ecdsa::VerifyingKey;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use vlatproto::crypto::Keypair;
use vlpds::plc::mock::MockPlc;

async fn plc_pds(plc: &MockPlc) -> TestServer {
    TestServer::spawn_plc(&plc.url, Arc::new(Keypair::generate())).await
}

async fn rotate(s: &TestServer, did: &str) -> Resp {
    s.xrpc.post("com.atproto.admin.updateAccountSigningKey", &json!({"did": did}), &Auth::Admin).await
}

fn key_of(did_key: &str) -> VerifyingKey {
    decode_did_key_k256(did_key).unwrap()
}

async fn local_key(s: &TestServer, did: &str) -> String {
    format!("did:key:{}", s.app.account(did).await.ok().unwrap().signing_pubkey)
}

fn plc_key(plc: &MockPlc, did: &str) -> String {
    plc.data(did).unwrap()["verificationMethods"]["atproto"].as_str().unwrap().to_string()
}

async fn create(s: &TestServer, a: &TestAccount, text: &str) -> Resp {
    s.xrpc
        .post(
            "com.atproto.repo.createRecord",
            &json!({"repo": a.did, "collection": "app.bsky.feed.post", "record": post_record(text)}),
            &a.auth(),
        )
        .await
}

/// The frames of `did` after the cursor, once its `#sync` arrived.
async fn identity_then_sync(sub: &mut Sub, did: &str) -> Vec<Frame> {
    let frames = sub.until(FH_TIMEOUT, |fs| fs.iter().any(|f| f.kind() == "#sync" && f.did() == Some(did))).await;
    frames.into_iter().filter(|f| f.did() == Some(did)).collect()
}

/// Writers hammer one repo while its key rotates. Every acked write is on
/// the firehose; commits before the rotation's `#identity` verify with the
/// old key, `#sync` follows `#identity` at once with the same data root,
/// and every commit after it verifies with the new key and chains off the
/// `#sync`'s rev. No commit is signed with the old key after the rotation.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn rotation_under_concurrent_writes() {
    let plc = MockPlc::start().await;
    let s = plc_pds(&plc).await;
    let a = s.create_account("rotw").await;
    s.post(&a, "first").await;
    let old_key = key_of(&local_key(&s, &a.did).await);
    let mut sub = s.subscribe_from_now().await;

    let stop = Arc::new(AtomicBool::new(false));
    let refused = Arc::new(AtomicUsize::new(0));
    let acked = Arc::new(parking_lot::Mutex::new(Vec::<(String, String)>::new()));
    let writers: Vec<_> = (0..6)
        .map(|w| {
            let (x, a, stop, refused, acked) = (s.xrpc.clone(), a.clone(), stop.clone(), refused.clone(), acked.clone());
            tokio::spawn(async move {
                let mut i = 0;
                while !stop.load(Ordering::Relaxed) {
                    let body = json!({"repo": a.did, "collection": "app.bsky.feed.post", "record": post_record(&format!("w{w} {i}"))});
                    let r = x.post("com.atproto.repo.createRecord", &body, &a.auth()).await;
                    match r.status {
                        200 => {
                            let j = r.json;
                            acked.lock().push((j["commit"]["cid"].as_str().unwrap().to_string(), j["commit"]["rev"].as_str().unwrap().to_string()));
                            i += 1;
                        }
                        // writes wait out the rotation
                        503 if r.error_name() == Some("KeyUnavailable") => {
                            refused.fetch_add(1, Ordering::Relaxed);
                            tokio::time::sleep(Duration::from_millis(2)).await;
                        }
                        _ => panic!("write failed: {r:?}"),
                    }
                }
            })
        })
        .collect();
    let n_acked = || acked.lock().len();
    eventually(Duration::from_secs(20), || async { (n_acked() >= 40).then_some(()) }).await.expect("writes before");

    let j = rotate(&s, &a.did).await.ok();
    let new_did_key = j["signingKey"].as_str().unwrap().to_string();
    let new_key = key_of(&new_did_key);
    // acknowledged: the served head is re-signed, the DID document names the key
    let repo = s.get_repo(&a.did).await;
    repo.commit().verify(&new_key).expect("head re-signed before the ack");
    assert!(repo.commit().verify(&old_key).is_err());
    assert_eq!(plc_key(&plc, &a.did), new_did_key);
    assert_eq!(local_key(&s, &a.did).await, new_did_key);

    let at_rotation = n_acked();
    eventually(Duration::from_secs(20), || async { (n_acked() >= at_rotation + 40).then_some(()) })
        .await
        .expect("writes after");
    stop.store(true, Ordering::Relaxed);
    for w in writers {
        w.await.unwrap();
    }
    let acked = acked.lock().clone();
    eprintln!("{} writes acked, {} refused during the rotation", acked.len(), refused.load(Ordering::Relaxed));

    let want: std::collections::HashSet<Cid> = acked.iter().map(|(c, _)| Cid::parse(c).unwrap()).collect();
    let frames = sub
        .until(Duration::from_secs(30), |fs| {
            let seen: std::collections::HashSet<Cid> = fs.iter().filter_map(|f| f.commit().map(|c| c.commit)).collect();
            want.iter().all(|c| seen.contains(c))
        })
        .await;
    let frames: Vec<&Frame> = frames.iter().filter(|f| f.did() == Some(a.did.as_str())).collect();
    let ids: Vec<usize> = frames.iter().enumerate().filter(|(_, f)| f.kind() == "#identity").map(|(i, _)| i).collect();
    assert_eq!(ids.len(), 1, "one #identity: {:?}", frames.iter().map(|f| f.kind()).collect::<Vec<_>>());
    let i = ids[0];
    assert_eq!(frames[i + 1].kind(), "#sync", "#sync right after #identity");
    let sync = frames[i + 1].sync().unwrap();
    let sync_commit = sync.commit_obj();
    sync_commit.verify(&new_key).expect("#sync signed with the new key");
    assert_eq!(sync.rev, sync_commit.rev);
    let before: Vec<CommitEvt> = frames[..i].iter().filter_map(|f| f.commit()).collect();
    let after: Vec<CommitEvt> = frames[i + 2..].iter().filter_map(|f| f.commit()).collect();
    assert!(!before.is_empty() && !after.is_empty(), "{} before, {} after", before.len(), after.len());
    assert_eq!(before.len() + after.len(), frames.len() - 2, "only commits besides the rotation's events");
    let last = before.last().unwrap();
    // the empty commit: the last data root, a later rev
    assert_eq!(sync_commit.data, last.commit_obj().data);
    assert!(sync.rev > last.rev, "{} <= {}", sync.rev, last.rev);
    for c in &before {
        c.commit_obj().verify(&old_key).unwrap_or_else(|e| panic!("commit {} before the rotation: {e}", c.rev));
        assert!(c.rev < sync.rev);
    }
    // the next commit chains off the #sync
    assert_eq!(after[0].since.as_deref(), Some(sync.rev.as_str()));
    assert_eq!(after[0].prev_data, Some(sync_commit.data));
    for c in &after {
        c.commit_obj().verify(&new_key).unwrap_or_else(|e| panic!("commit {} after the rotation: {e}", c.rev));
        assert!(c.commit_obj().verify(&old_key).is_err());
        assert_eq!(c.invert().unwrap(), c.prev_data.unwrap(), "sync 1.1 inversion");
    }
    let repo = s.get_repo(&a.did).await;
    repo.commit().verify(&new_key).unwrap();
    assert_eq!(repo.entries().len(), acked.len() + 1);
}

/// A refusal by the directory changes nothing (the account keeps writing
/// with its key). An outage leaves the rotation pending: writes get a
/// retryable 503, and a retry once the directory answers finishes it with
/// the pending key; a retry naming another key finishes the pending one and
/// refuses the other (still reserved). publishIdentity with syncPlc re-signs
/// with the held key.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn plc_refusal_and_outage() {
    let plc = MockPlc::start().await;
    let s = plc_pds(&plc).await;
    let a = s.create_account("rotf").await;
    s.post(&a, "first").await;
    let before = local_key(&s, &a.did).await;
    let (head0, _) = s.latest_commit(&a.did).await;
    let mut sub = s.subscribe_from_now().await;

    plc.fail_posts(1, 400);
    let r = rotate(&s, &a.did).await;
    r.err(500, "InternalServerError");
    assert!(r.text().contains("PLC directory"), "{}", r.text());
    assert_eq!(local_key(&s, &a.did).await, before, "no local change on a PLC refusal");
    assert_eq!(plc_key(&plc, &a.did), before);
    assert!(s.app.account(&a.did).await.ok().unwrap().pending_signing_key.is_none());
    assert_eq!(s.latest_commit(&a.did).await.0, head0, "nothing re-signed");
    create(&s, &a, "after the refusal").await.ok();

    plc.set_down(true);
    let r = rotate(&s, &a.did).await;
    r.err(500, "InternalServerError");
    assert!(r.text().contains("retry updateAccountSigningKey"), "{}", r.text());
    let pending = s.app.account(&a.did).await.ok().unwrap().pending_signing_key.expect("pending");
    let new_did_key = format!("did:key:{}", pending.pubkey);
    // fenced; its kick fails against the outage too
    create(&s, &a, "during").await.err(503, "KeyUnavailable");
    rotate(&s, &a.did).await.err(500, "InternalServerError");
    assert_eq!(local_key(&s, &a.did).await, before);
    wait_until("the kick's backoff", Duration::from_secs(10), || !vlpds::xrpc::key_rotation::driving(&a.did)).await;
    assert!(s.app.account(&a.did).await.ok().unwrap().pending_signing_key.is_some());
    plc.set_down(false);
    // the retry asks for a reserved key: the pending rotation wins
    let other = s.xrpc.post("com.atproto.server.reserveSigningKey", &json!({"did": a.did}), &Auth::None).await.ok()
        ["signingKey"]
        .as_str()
        .unwrap()
        .to_string();
    let r = s
        .xrpc
        .post("com.atproto.admin.updateAccountSigningKey", &json!({"did": a.did, "signingKey": other}), &Auth::Admin)
        .await;
    r.err(400, "InvalidRequest");
    assert!(r.text().contains("now finished"), "{}", r.text());
    assert_eq!(local_key(&s, &a.did).await, new_did_key);
    assert_eq!(plc_key(&plc, &a.did), new_did_key);
    let repo = s.get_repo(&a.did).await;
    repo.commit().verify(&key_of(&new_did_key)).expect("re-signed with the pending key");
    let frames = identity_then_sync(&mut sub, &a.did).await;
    let kinds: Vec<&str> = frames.iter().map(|f| f.kind()).collect();
    assert_eq!(kinds, vec!["#commit", "#identity", "#sync"]);
    create(&s, &a, "after").await.ok();
    let st = s.xrpc.get("com.atproto.server.checkAccountStatus", &[], &a.auth()).await.ok();
    assert_eq!(st["validDid"], json!(true), "{st}");
    assert!(s.app.account(&a.did).await.ok().unwrap().pending_signing_key.is_none());

    // publishIdentity syncPlc (rotate-keys): re-signed with the held key
    let (head1, rev1) = s.latest_commit(&a.did).await;
    let mut sub = s.subscribe_from_now().await;
    let j =
        s.xrpc.post("vlpds.admin.publishIdentity", &json!({"did": a.did, "syncPlc": true}), &Auth::Admin).await.ok();
    assert_eq!(j["plcUpdated"], json!(false), "{j}");
    let frames = identity_then_sync(&mut sub, &a.did).await;
    assert_eq!(frames.iter().map(|f| f.kind()).collect::<Vec<_>>(), vec!["#identity", "#sync"]);
    let sync = frames[1].sync().unwrap();
    sync.commit_obj().verify(&key_of(&new_did_key)).unwrap();
    let (head2, rev2) = s.latest_commit(&a.did).await;
    assert_ne!(head2, head1);
    assert!(rev2 > rev1 && sync.rev == rev2);
    assert_eq!(local_key(&s, &a.did).await, new_did_key, "same key");
}

/// A deactivated account's rotation emits `#identity` only; activation
/// then announces the re-signed head with `#sync`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rotation_while_deactivated() {
    let s = TestServer::spawn().await;
    let a = s.create_account("rotd").await;
    s.post(&a, "first").await;
    s.xrpc.post("com.atproto.server.deactivateAccount", &json!({}), &a.auth()).await.ok();
    let mut sub = s.subscribe_from_now().await;
    let new_key = key_of(rotate(&s, &a.did).await.ok()["signingKey"].as_str().unwrap());
    s.xrpc.post_empty("com.atproto.server.activateAccount", &a.auth()).await.ok();
    let frames = identity_then_sync(&mut sub, &a.did).await;
    let kinds: Vec<&str> = frames.iter().map(|f| f.kind()).collect();
    assert_eq!(kinds, vec!["#identity", "#account", "#identity", "#sync"]);
    frames[3].sync().unwrap().commit_obj().verify(&new_key).expect("activation's #sync is the re-signed head");
    s.get_repo(&a.did).await.commit().verify(&new_key).unwrap();
}

async fn node(id: &str, store: &Arc<dyn object_store::ObjectStore>, plc: &MockPlc, rot: &Arc<Keypair>) -> TestServer {
    let (plc_url, rot) = (plc.url.clone(), rot.clone());
    cluster_node(id, store.clone(), 4, |c| {
        // nothing checkpointed: the survivor replays the victim's log
        c.checkpoint_every = Duration::from_secs(3600);
        use_plc(c, plc_url, rot);
        let l = lease(c);
        (l.ttl, l.renew_every, l.skew) =
            (Duration::from_secs(2), Duration::from_millis(200), Duration::from_millis(400));
    })
    .await
}

#[derive(Clone, Copy, PartialEq)]
enum FinishBy {
    /// The admin re-runs updateAccountSigningKey.
    Retry,
    /// A write is fenced and kicks the finish; it succeeds once done.
    Write,
}

/// The repo's owner dies (`Node::halt`, kill -9) mid-rotation, at `phase`:
/// "begun" (the pending key is durable, the directory not updated yet) or
/// "plc_updated" (the directory names the new key, the repo still carries
/// the old one). The survivor replays the log and finds the rotation
/// pending, its writes fenced; `by` finishes it: the directory and the
/// re-signed head agree, `#identity` then `#sync`, writes resume.
async fn crash_mid_rotation(phase: &'static str, by: FinishBy) {
    let plc = MockPlc::start().await;
    let rot = Arc::new(Keypair::generate());
    let store: Arc<dyn object_store::ObjectStore> = Arc::new(object_store::memory::InMemory::new());
    let tag = unique_name("kr");
    let a = node(&format!("{tag}-a"), &store, &plc, &rot).await;
    let b = node(&format!("{tag}-b"), &store, &plc, &rot).await;
    wait_until("both own shards", Duration::from_secs(15), || {
        owned(&a) > 0 && owned(&b) > 0 && owned(&a) + owned(&b) == 4
    })
    .await;
    // created on b: in a shard b owns
    let x = b.create_account("krx").await;
    assert!(b.app.partition(&x.did).is_ok());
    b.post(&x, "before").await;
    let old_did_key = local_key(&b, &x.did).await;
    let plc_ops = plc.ops(&x.did).len();
    let cursor = a.settled_now().await;

    let fired = Arc::new(AtomicBool::new(false));
    {
        let (fired, app) = (fired.clone(), b.app.clone());
        vlpds::xrpc::key_rotation::set_crash_hook(
            &x.did,
            Some(Arc::new(move |p: &str| {
                if p != phase || fired.swap(true, Ordering::SeqCst) {
                    return false;
                }
                app.node.halt();
                true
            })),
        );
    }
    let r = rotate(&b, &x.did).await;
    vlpds::xrpc::key_rotation::set_crash_hook(&x.did, None);
    assert!(fired.load(Ordering::SeqCst), "{phase} never reached: {r:?}");
    assert!(!r.is_ok(), "{r:?}");
    let expect_plc = if phase == "begun" { old_did_key.clone() } else { plc_key(&plc, &x.did) };
    assert_eq!(plc_key(&plc, &x.did), expect_plc);
    assert_eq!(plc.ops(&x.did).len(), plc_ops + usize::from(phase != "begun"));

    wait_until("a takes every shard", Duration::from_secs(20), || owned(&a) == 4).await;
    // replayed: the rotation is pending, the head still the old key's
    let acct = a.app.account(&x.did).await.ok().unwrap();
    let pending = acct.pending_signing_key.clone().expect("pending rotation survived the crash");
    let new_did_key = format!("did:key:{}", pending.pubkey);
    assert_eq!(format!("did:key:{}", acct.signing_pubkey), old_did_key);
    if phase == "plc_updated" {
        assert_eq!(plc_key(&plc, &x.did), new_did_key);
    }
    a.get_repo(&x.did).await.commit().verify(&key_of(&old_did_key)).unwrap();

    match by {
        FinishBy::Retry => {
            // the fenced write's kick can't finish against the outage
            plc.set_down(true);
            create(&a, &x, "fenced").await.err(503, "KeyUnavailable");
            wait_until("the kick's backoff", Duration::from_secs(10), || !vlpds::xrpc::key_rotation::driving(&x.did))
                .await;
            plc.set_down(false);
            assert!(a.app.account(&x.did).await.ok().unwrap().pending_signing_key.is_some());
            let j = rotate(&a, &x.did).await.ok();
            assert_eq!(j["signingKey"], json!(new_did_key), "the retry finished the pending rotation");
            create(&a, &x, "after").await.ok();
        }
        FinishBy::Write => {
            create(&a, &x, "fenced").await.err(503, "KeyUnavailable");
            eventually(Duration::from_secs(15), || async {
                let r = create(&a, &x, "after").await;
                if r.status == 503 && r.error_name() == Some("KeyUnavailable") {
                    return None;
                }
                r.ok();
                Some(())
            })
            .await
            .expect("the write kicked the rotation's finish");
        }
    }
    assert_eq!(plc_key(&plc, &x.did), new_did_key);
    assert_eq!(plc.ops(&x.did).len(), plc_ops + 1, "one PLC update in all");
    let acct = a.app.account(&x.did).await.ok().unwrap();
    assert!(acct.pending_signing_key.is_none());
    assert_eq!(format!("did:key:{}", acct.signing_pubkey), new_did_key);
    let new_key = key_of(&new_did_key);
    let mut sub = a.subscribe(Some(cursor)).await;
    let frames = sub.wait_for(FH_TIMEOUT, &x.did, "#commit").await;
    let frames: Vec<&Frame> = frames.iter().filter(|f| f.did() == Some(x.did.as_str())).collect();
    assert_eq!(frames.iter().map(|f| f.kind()).collect::<Vec<_>>(), vec!["#identity", "#sync", "#commit"]);
    frames[1].sync().unwrap().commit_obj().verify(&new_key).expect("re-signed with the pending key");
    frames[2].commit().unwrap().commit_obj().verify(&new_key).unwrap();
    a.get_repo(&x.did).await.commit().verify(&new_key).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn crash_after_begin_is_finished_by_a_retry() {
    crash_mid_rotation("begun", FinishBy::Retry).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn crash_after_plc_update_is_finished_by_a_retry() {
    crash_mid_rotation("plc_updated", FinishBy::Retry).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn crash_after_begin_is_finished_by_a_write() {
    crash_mid_rotation("begun", FinishBy::Write).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn crash_after_plc_update_is_finished_by_a_write() {
    crash_mid_rotation("plc_updated", FinishBy::Write).await;
}
