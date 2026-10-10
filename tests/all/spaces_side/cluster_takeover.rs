//! Takeover in the middle of a space write burst across three nodes (plan
//! §2.6, phase 2). Two writers on the victim and one on each survivor burst
//! into a space a vlpds account governs (on the victim or a survivor) and
//! into one a remote authority governs, while the victim is killed -9 (its
//! bucket stops answering, its shards drop) and the survivors take its
//! shards over. Then:
//!
//! - every acked write is there and each repo folds and replays to its head;
//! - the vlpds authority sequenced each (repo, repoRev) once, and each
//!   repo's spaceRev only moved forward across every listRepos poll;
//! - the remote authority hears each writer's newest rev, the revs it hears
//!   per writer never go back, and the syncer gets the local space's
//!   updates in spaceRev order.
//!
//! And with no writes in flight: when the authority's shard moves, the new
//! owner sends each live registration one coalesced catch-up forward with
//! the space's current head and spaceRev (the docs-draft decision 3), so a
//! syncer whose queued forward died with the old owner hears within seconds.

use super::cluster::{client_on, settle_front, Plc};
use super::durability::{burst, by_did, consistent, create, latest, list_repos, scope, signed_post, Burst};
use super::fuzz::bytes_field;
use super::hooks::*;
use crate::common::spaces::{space_uri, SpaceClient};
use crate::common::*;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

const SHARDS: u32 = 6;
const CATCH_UP: Duration = Duration::from_secs(150);

fn tag() -> String {
    random_bytes(5).iter().map(|b| format!("{b:02x}")).collect()
}

async fn takeover_mid_burst(authority_on_victim: bool) {
    let (bucket, front, plc) = (Default::default(), Front::new().await, Plc::start().await);
    let mut nodes = Vec::new();
    for i in 1..=3 {
        nodes.push(hooked_node_with(&format!("tx-{i}"), &bucket, SHARDS, &front, |c| plc.apply(c)).await);
    }
    let [(n1, _), (n2, s2), (n3, _)] = &nodes[..] else { unreachable!() };
    balanced(&[n1, n2, n3]).await;
    let t = tag();
    let (st, coll) = (format!("com.example.tx{t}.space"), format!("com.example.tx{t}.note"));
    let sc = scope(&st, &coll);
    let mut auth = client_on(&front, if authority_on_victim { n2 } else { n1 }, "txa", &sc).await;
    let mut writers = vec![
        client_on(&front, n2, "txv", &sc).await,
        client_on(&front, n2, "txv", &sc).await,
        client_on(&front, n1, "txs", &sc).await,
        client_on(&front, n3, "txs", &sc).await,
    ];
    let mut all: Vec<&mut SpaceClient> = writers.iter_mut().collect();
    all.push(&mut auth);
    settle_front(&front, n1, &mut all);

    let local = auth.create_space(&st, "tx").await;
    for w in &writers {
        let m = json!({"space": local, "did": w.did, "read": true, "write": true});
        auth.post("com.atproto.simplespace.putMember", m).await.ok();
    }
    let (remote_auth, syncer) = (StubDid::spawn().await, StubDid::spawn().await);
    let remote = space_uri(&remote_auth.did, &st, "tx");
    let cred = auth.credential(&local).await;
    let reg = json!({"space": local, "service": format!("{}#atproto_space_syncer", syncer.did)});
    signed_post(&auth, "com.atproto.space.registerNotify", reg, &cred, &auth.did).await.ok();
    let spaces = [local.as_str(), remote.as_str()];

    let stop = AtomicBool::new(false);
    let killed_at = parking_lot::Mutex::new(None::<Instant>);
    let polls = parking_lot::Mutex::new(Vec::<Vec<J>>::new());
    let prefixes: Vec<String> = (0..writers.len()).map(|i| format!("b{i}-")).collect();
    let mut jobs = Vec::new();
    for (w, prefix) in writers.iter().zip(&prefixes) {
        for space in spaces {
            jobs.push(burst(w, space, &coll, prefix, &stop));
        }
    }
    let (bursts, _, _) = tokio::join!(
        futures::future::join_all(jobs),
        async {
            tokio::time::sleep(Duration::from_millis(1200)).await;
            kill9(n2, s2);
            *killed_at.lock() = Some(Instant::now());
            wait_until("the survivors take the victim's shards", Duration::from_secs(30), || {
                owned(n1) + owned(n3) == SHARDS as usize
            })
            .await;
            tokio::time::sleep(Duration::from_secs(2)).await;
            stop.store(true, Ordering::SeqCst);
        },
        async {
            while !stop.load(Ordering::SeqCst) {
                if let Ok(Ok(repos)) =
                    tokio::time::timeout(Duration::from_secs(5), list_repos(&auth, &local, &cred)).await
                {
                    polls.lock().push(repos);
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        },
    );
    let killed_at = killed_at.lock().unwrap();

    let mut it = bursts.iter();
    let (mut acked, mut unacked) = (0, 0);
    for (i, w) in writers.iter().enumerate() {
        for space in spaces {
            let b: &Burst = it.next().unwrap();
            (acked, unacked) = (acked + b.acked.len(), unacked + b.unacked.len());
            let ctx = format!("writer {i} in {space} after the takeover");
            let (recs, _) = consistent(n1, w, space, space == local, &ctx).await;
            for (path, cid) in &b.acked {
                assert_eq!(recs.get(path).map(|r| &r.0), Some(cid), "{ctx}: acked {path} lost");
            }
            for path in recs.keys() {
                assert!(b.acked.contains_key(path) || b.unacked.contains(path), "{ctx}: {path} was never written");
            }
            assert!(!b.acked.is_empty(), "{ctx}: the burst wrote nothing");
            // wakes the outbox past any send that failed while the shards moved
            create(w, space, &coll, &format!("w{i}-final"), "final").await.ok();
        }
    }
    eprintln!("burst: {acked} acked, {unacked} not, across the kill");

    let mut heads: BTreeMap<(String, &str), vlpds::space::commit::SignedCommit> = BTreeMap::new();
    for w in &writers {
        for space in spaces {
            heads.insert((w.did.clone(), space), latest(w, space, "final head").await);
        }
    }

    // the vlpds authority catches up with every writer's head
    let t0 = Instant::now();
    let fin = eventually(CATCH_UP, || async {
        let repos = list_repos(&auth, &local, &cred).await.ok()?;
        let rows = by_did(&repos);
        writers
            .iter()
            .all(|w| {
                let c = &heads[&(w.did.clone(), local.as_str())];
                rows.get(&w.did).is_some_and(|r| r["repoRev"] == json!(c.rev) && bytes_field(&r["hash"]) == c.hash)
            })
            .then_some(repos)
    })
    .await
    .expect("the vlpds authority never caught up");
    eprintln!("the vlpds authority caught up {:?} after the burst", t0.elapsed());
    let mut sequenced: BTreeMap<(String, String), String> = BTreeMap::new();
    let mut last: BTreeMap<String, (String, String)> = BTreeMap::new();
    let polls = std::mem::take(&mut *polls.lock());
    for repos in polls.iter().chain(std::iter::once(&fin)) {
        for (did, r) in by_did(repos) {
            let (rr, sr) = (r["repoRev"].as_str().unwrap().to_string(), r["spaceRev"].as_str().unwrap().to_string());
            if let Some(prev) = sequenced.insert((did.clone(), rr.clone()), sr.clone()) {
                assert_eq!(prev, sr, "{did} repoRev {rr} sequenced twice");
            }
            if let Some((prr, psr)) = last.insert(did.clone(), (rr.clone(), sr.clone())) {
                assert!(rr >= prr && sr >= psr, "{did} went back: ({prr}, {psr}) then ({rr}, {sr})");
            }
        }
    }
    let space_revs: BTreeSet<&str> = fin.iter().map(|r| r["spaceRev"].as_str().unwrap()).collect();
    assert_eq!(space_revs.len(), fin.len(), "two repos share a spaceRev: {fin:?}");

    // the remote authority hears every writer's newest rev, never going back
    let t0 = Instant::now();
    eventually(CATCH_UP, || async {
        let got = remote_auth.accepted();
        writers
            .iter()
            .all(|w| {
                let rev = &heads[&(w.did.clone(), remote.as_str())].rev;
                got.iter().any(|n| n.body["repo"] == json!(w.did) && n.body["repoRev"] == json!(rev))
            })
            .then_some(())
    })
    .await
    .unwrap_or_else(|| panic!("the remote authority never heard every newest rev: {:?}", remote_auth.accepted()));
    eprintln!("the remote authority caught up {:?} after the burst", t0.elapsed());
    for w in &writers {
        let revs: Vec<String> = remote_auth
            .seen()
            .iter()
            .filter(|n| n.body["repo"] == json!(w.did))
            .map(|n| n.body["repoRev"].as_str().unwrap().to_string())
            .collect();
        assert!(revs.windows(2).all(|p| p[0] <= p[1]), "{}: notifies went back: {revs:?}", w.did);
    }
    for n in remote_auth.seen() {
        assert_eq!(n.claims["aud"], json!(format!("{}#atproto_space_host", remote_auth.did)), "{n:?}");
        assert!(writers.iter().any(|w| n.claims["iss"] == json!(w.did)), "{n:?}");
    }

    // the syncer got the local space's updates in spaceRev order. The new
    // owner's catch-up forward (docs-draft decision 3) may repeat the head
    // the old owner already delivered: once, after the kill.
    syncer.assert_no_fork("the syncer");
    let got = syncer.accepted();
    let revs: Vec<&str> = got.iter().map(|n| n.body["spaceRev"].as_str().expect("spaceRev")).collect();
    assert!(revs.windows(2).all(|w| w[0] <= w[1]), "fan-out out of order: {revs:?}");
    let repeats: Vec<usize> = (1..got.len()).filter(|&i| revs[i] == revs[i - 1]).collect();
    assert!(repeats.len() <= 1, "fan-out repeated more than the one catch-up: {repeats:?} in {revs:?}");
    assert!(repeats.iter().all(|&i| got[i].at > killed_at), "a repeat before the takeover: {repeats:?} in {revs:?}");
    if authority_on_victim {
        assert!(got.iter().any(|n| n.at > killed_at), "fan-out didn't resume on the new owner");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn three_node_takeover_mid_burst_with_the_authority_on_a_survivor() {
    takeover_mid_burst(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn three_node_takeover_mid_burst_with_the_authority_on_the_victim() {
    takeover_mid_burst(true).await;
}

/// The authority's shard is on the victim; three syncers are registered and
/// have heard every write. With nothing written after it, a kill -9 moves
/// the shard and the new owner sends each registration exactly one forward
/// within a few seconds, carrying the newest sequenced (repo, repoRev,
/// spaceRev) as listRepos shows it.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn takeover_sends_each_registration_one_catch_up_forward() {
    let (bucket, front, plc) = (Default::default(), Front::new().await, Plc::start().await);
    let mut nodes = Vec::new();
    for i in 1..=3 {
        nodes.push(hooked_node_with(&format!("tc-{i}"), &bucket, SHARDS, &front, |c| plc.apply(c)).await);
    }
    let [(n1, _), (n2, s2), (n3, _)] = &nodes[..] else { unreachable!() };
    balanced(&[n1, n2, n3]).await;
    let t = tag();
    let (st, coll) = (format!("com.example.tc{t}.space"), format!("com.example.tc{t}.note"));
    let sc = scope(&st, &coll);
    let mut auth = client_on(&front, n2, "tca", &sc).await;
    let mut writers = vec![client_on(&front, n1, "tcw", &sc).await, client_on(&front, n3, "tcw", &sc).await];
    let mut all: Vec<&mut SpaceClient> = writers.iter_mut().collect();
    all.push(&mut auth);
    settle_front(&front, n1, &mut all);

    let local = auth.create_space(&st, "tc").await;
    for w in &writers {
        let m = json!({"space": local, "did": w.did, "read": true, "write": true});
        auth.post("com.atproto.simplespace.putMember", m).await.ok();
    }
    let cred = auth.credential(&local).await;
    let mut syncers = Vec::new();
    for _ in 0..3 {
        let s = StubDid::spawn().await;
        let reg = json!({"space": local, "service": format!("{}#atproto_space_syncer", s.did)});
        signed_post(&auth, "com.atproto.space.registerNotify", reg, &cred, &auth.did).await.ok();
        syncers.push(s);
    }
    for (i, w) in writers.iter().enumerate() {
        for j in 0..3 {
            create(w, &local, &coll, &format!("w{i}-{j}"), "before the kill").await.ok();
        }
    }
    let newest = |repos: &[J]| repos.iter().map(|r| r["spaceRev"].as_str().unwrap().to_string()).max();
    // a member's write reaches the authority by its PDS's notify, after the
    // write is acked: wait until every writer's last rev is sequenced
    let mut heads = Vec::new();
    for w in &writers {
        heads.push((w.did.clone(), latest(w, &local, "a writer's head before the kill").await.rev));
    }
    let before = eventually(Duration::from_secs(20), || async {
        let repos = list_repos(&auth, &local, &cred).await.ok()?;
        let rows = by_did(&repos);
        heads.iter().all(|(did, rev)| rows.get(did).is_some_and(|r| r["repoRev"] == json!(rev))).then_some(repos)
    })
    .await
    .expect("the authority never sequenced every write before the kill");
    let head = newest(&before).expect("sequenced writes");
    eventually(Duration::from_secs(20), || async {
        syncers
            .iter()
            .all(|s| s.accepted().iter().any(|n| n.body["spaceRev"].as_str() == Some(head.as_str())))
            .then_some(())
    })
    .await
    .expect("the syncers never heard the newest write before the kill");

    kill9(n2, s2);
    let killed_at = Instant::now();
    wait_until("the survivors take the victim's shards", Duration::from_secs(30), || {
        owned(n1) + owned(n3) == SHARDS as usize
    })
    .await;
    let took = killed_at.elapsed();
    let after = list_repos(&auth, &local, &cred).await.unwrap();
    assert_eq!(newest(&after), Some(head.clone()), "nothing was written after the kill");
    let row = after.iter().find(|r| r["spaceRev"].as_str() == Some(head.as_str())).unwrap().clone();

    let caught_up = eventually(took + Duration::from_secs(5), || async {
        syncers.iter().all(|s| s.accepted().iter().any(|n| n.at > killed_at)).then_some(())
    })
    .await;
    assert!(caught_up.is_some(), "a registration heard nothing within 5 s of the takeover");
    tokio::time::sleep(Duration::from_secs(2)).await;
    for (i, s) in syncers.iter().enumerate() {
        s.assert_no_fork(&format!("syncer {i}"));
        let late: Vec<Notified> = s.accepted().into_iter().filter(|n| n.at > killed_at).collect();
        assert_eq!(late.len(), 1, "syncer {i}: one catch-up forward per takeover: {late:?}");
        let b = &late[0].body;
        assert_eq!(b["space"], json!(local), "syncer {i}: {b}");
        assert_eq!(b["spaceRev"], json!(head), "syncer {i}: the current spaceRev: {b}");
        assert_eq!(
            (b["repo"].clone(), b["repoRev"].clone()),
            (row["did"].clone(), row["repoRev"].clone()),
            "syncer {i}: the head's repo and rev: {b}"
        );
    }
}
