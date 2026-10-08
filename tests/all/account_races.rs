//! Account changes race with each other and with shard handoff:
//! - every account mutation is a read-modify-write the repo's worker applies
//!   to its current state, so a concurrent refreshIdentity / updateHandle can't
//!   write back a stale snapshot over a takedown, and changes to different
//!   fields all land;
//! - a repo load that straddles a shard close/reopen is never cached (else
//!   commits chain on the stale state, then "rebuilt MST root != head data"
//!   forever).
use crate::common::*;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use vlpds::cluster::ShardHost;

/// Hammers `nsid` as the account from 8 tasks while an admin takes it down;
/// the takedown must stick every time.
async fn takedown_survives(nsid: &'static str, body: impl Fn(&TestAccount) -> J) {
    let s = Arc::new(TestServer::spawn().await);
    for _ in 0..10 {
        let a = Arc::new(s.create_account("race").await);
        let stop = Arc::new(AtomicBool::new(false));
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let (s, a, stop, body) = (s.clone(), a.clone(), stop.clone(), body(&a));
            tasks.push(tokio::spawn(async move {
                while !stop.load(Ordering::Relaxed) {
                    let _ = s.xrpc.post(nsid, &body, &a.auth()).await;
                }
            }));
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let body = json!({"subject": repo_ref(&a.did), "takedown": {"applied": true, "ref": "race"}});
        s.xrpc.post("com.atproto.admin.updateSubjectStatus", &body, &Auth::Admin).await.ok();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        stop.store(true, Ordering::Relaxed);
        for t in tasks {
            t.await.unwrap();
        }
        let st = s.repo_status(&a.did).await.ok();
        assert_eq!(st["active"], json!(false), "takedown reverted by a concurrent {nsid}: {st}");
        assert_eq!(st["status"], json!("takendown"));
        let acct = s.app.account(&a.did).await.unwrap_or_else(|e| panic!("{}", e.message));
        assert_eq!(acct.extra.get("takedownRef"), Some(&json!("race")));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn takedown_survives_concurrent_refresh_identity() {
    takedown_survives("com.atproto.identity.refreshIdentity", |a| json!({"identifier": a.did})).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn takedown_survives_concurrent_update_handle() {
    // same handle: re-announces it (an account op every time)
    takedown_survives("com.atproto.identity.updateHandle", |a| json!({"handle": a.handle})).await;
}

/// Concurrent mutations of different fields compose: none is lost.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_account_mutations_compose() {
    let s = Arc::new(TestServer::spawn().await);
    let a = s.create_account("compose").await;
    let tasks: Vec<_> = (0..32)
        .map(|i| {
            let (s, did) = (s.clone(), a.did.clone());
            tokio::spawn(async move {
                s.app
                    .mutate_account(&did, false, false, false, move |acct| {
                        acct.extra.insert(format!("k{i}"), json!(i));
                        Ok(true)
                    })
                    .await
                    .unwrap_or_else(|e| panic!("{}", e.message));
            })
        })
        .collect();
    for t in tasks {
        t.await.unwrap();
    }
    let acct = s.app.account(&a.did).await.unwrap_or_else(|e| panic!("{}", e.message));
    for i in 0..32 {
        assert_eq!(acct.extra.get(&format!("k{i}")), Some(&json!(i)), "k{i} lost");
    }
}

/// A rejected mutation (precondition checked on the worker's state) writes
/// nothing and returns the mutation's own error.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rejected_account_mutation_writes_nothing() {
    let s = TestServer::spawn().await;
    let a = s.create_account("reject").await;
    let seq = s.current_seq().await;
    let e = s
        .app
        .mutate_account(&a.did, true, true, false, |acct| {
            acct.handle = "nope.test".into();
            Err(vlsync_atproto::xrpc::XrpcError::bad("Precondition", "no"))
        })
        .await
        .expect_err("rejected");
    assert_eq!(e.error, "Precondition");
    assert_eq!(s.app.account(&a.did).await.ok().unwrap().handle, a.handle);
    assert_eq!(s.current_seq().await, seq, "no events");
}

/// Closes and reopens shard `p`. Its history is our own closed span, which
/// the close's marker names.
async fn bounce(s: &TestServer, p: &vlpds::partition::Partition) {
    s.app.node.close(p.id).await.unwrap();
    let ours = vlpds::nodelog::Span {
        log_id: s.app.log.log_id.to_string(),
        epoch: p.epoch,
        start: 0,
        end: Some(s.app.log.next_ordinal()),
    };
    let opened = s.app.node.open_many(vec![(p.id, p.epoch, vec![ours])]).await;
    assert!(opened.iter().all(|(_, r)| r.is_ok()), "reopen failed");
}

/// A repo load in flight while its shard closes and reopens lands after the
/// reopen; it must be dropped (and the repo reloaded), not cached.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn load_straddling_shard_bounce_is_dropped() {
    let s = TestServer::spawn().await;
    let a = s.create_account("bounce").await;
    s.post(&a, "one").await;
    let old = s.app.partition(&a.did).unwrap_or_else(|e| panic!("{}", e.message));
    // the load starts under the old ownership...
    let stale = vlpds::worker::load_repo(old.clone(), a.did.as_str().into()).await.unwrap().expect("repo");
    // ...the repo moves on, the shard bounces...
    let two = s.post(&a, "two").await;
    bounce(&s, &old).await;
    assert!(!Arc::ptr_eq(&old, &s.app.partition(&a.did).unwrap_or_else(|e| panic!("{}", e.message))));
    // ...and the load completes (ahead of the next write in the worker's queue)
    s.app
        .workers
        .route(&a.did)
        .send(vlpds::worker::WorkerMsg::Loaded { did: a.did.as_str().into(), res: Box::new(Ok(Some(stale))) })
        .unwrap();
    let three = s.post(&a, "three").await;
    let rev3 = three.rev.clone().unwrap();
    let mut sub = s.subscribe(Some(0)).await;
    let frames = sub.until(FH_TIMEOUT, |fs| fs.last().and_then(|f| f.commit()).is_some_and(|c| c.rev == rev3)).await;
    let last = frames.last().and_then(|f| f.commit()).unwrap();
    assert_eq!(last.since.as_deref(), two.rev.as_deref(), "chained on the stale load");
    // durable state is consistent: another bounce forces a reload from it
    bounce(&s, &old).await;
    s.post(&a, "four").await;
    let repo = s.get_repo(&a.did).await;
    assert_eq!(repo.entries().len(), 4);
}
