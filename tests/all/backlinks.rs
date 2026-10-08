//! The backlink index (src/backlinks.rs, DESIGN.md "Backlinks"): the
//! reference PDS's createRecord deletes the repo's earlier like / repost /
//! follow / block of the same subject in the same commit as the new one
//! (`getBacklinkConflicts`). The `bl/` index behind it must stay exactly
//! what the repo's records say (vlpds.admin.checkRepo) through creates,
//! updates, deletes, applyWrites, imports, account deletes, concurrent
//! writes (commits in flight), replay after a kill, and reshards.

use crate::common::*;
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::sync::Arc;
use std::time::Duration;

const LIKE: &str = "app.bsky.feed.like";
const REPOST: &str = "app.bsky.feed.repost";
const FOLLOW: &str = "app.bsky.graph.follow";
const BLOCK: &str = "app.bsky.graph.block";

/// A record key (TID syntax: the linked collections' key type).
fn rk(i: usize) -> String {
    let a = b"234567abcdefghijklmnopqrstuvwxyz";
    format!("3kaaaaaaaaa{}{}", a[i / 32 % 32] as char, a[i % 32] as char)
}

fn post_uri(n: usize) -> String {
    format!("at://did:plc:bl{n:022}/app.bsky.feed.post/3jzfcijpj2z2a")
}

fn subject_did(n: usize) -> String {
    format!("did:plc:bl{n:022}")
}

/// A record of `coll` linking subject number `n`.
fn rec(coll: &str, n: usize) -> J {
    let subject = match coll {
        LIKE | REPOST => json!({"uri": post_uri(n), "cid": Cid::dag_cbor(format!("p{n}").as_bytes()).to_string()}),
        _ => json!(subject_did(n)),
    };
    json!({"$type": coll, "subject": subject, "createdAt": now_iso()})
}

/// checkRepo agrees: the `bl/` index is exactly the records' backlinks.
/// Returns its entry count.
async fn check_backlinks(s: &TestServer, did: &str) -> u64 {
    let r = s.xrpc.get("vlpds.admin.checkRepo", &[("did", did)], &Auth::Admin).await.ok();
    assert_eq!(r["indexes"]["backlinkMissing"], json!(0), "{did}: {r}");
    assert_eq!(r["indexes"]["backlinkExtra"], json!(0), "{did}: {r}");
    assert_eq!(r["ok"], json!(true), "{did}: {r}");
    r["indexes"]["backlinks"].as_u64().unwrap()
}

/// The repo's `bl/` entries, raw.
async fn scan_backlinks(s: &TestServer, did: &str) -> Vec<(Vec<u8>, Vec<u8>)> {
    let Ok(p) = s.app.partition(did) else { panic!("shard of {did} not owned") };
    let prefix = vlpds::state::backlink_prefix(did, s.app.repo_gen(did).await.ok().unwrap());
    let mut it = p.db.scan(prefix.clone()..vlsync_store::keys::prefix_end(&prefix)).await.unwrap();
    let mut out = Vec::new();
    while let Some(kv) = it.next().await.unwrap() {
        out.push((kv.key[prefix.len()..].to_vec(), kv.value.to_vec()));
    }
    out
}

async fn create(s: &TestServer, a: &TestAccount, coll: &str, record: J, validate: Option<bool>) -> RecordRef {
    let mut body = json!({"repo": a.did, "collection": coll, "record": record});
    if let Some(v) = validate {
        body["validate"] = json!(v);
    }
    RecordRef::from_json(&s.xrpc.post("com.atproto.repo.createRecord", &body, &a.auth()).await.ok())
}

/// The rkeys of `coll` records whose subject is `subject`.
async fn subject_records(s: &TestServer, did: &str, coll: &str, subject: &J) -> Vec<String> {
    let l = s.list_records(did, coll, &[("limit", "100")]).await.ok();
    l["records"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| &r["value"]["subject"] == subject)
        .map(|r| r["uri"].as_str().unwrap().rsplit('/').next().unwrap().to_string())
        .collect()
}

async fn rkeys(s: &TestServer, did: &str, coll: &str) -> Vec<String> {
    let l = s.list_records(did, coll, &[("limit", "100")]).await.ok();
    let mut v: Vec<String> = l["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["uri"].as_str().unwrap().rsplit('/').next().unwrap().to_string())
        .collect();
    v.sort();
    v
}

/// A duplicate like / repost / follow / block deletes the earlier one in
/// the new record's commit (the firehose shows both ops in one #commit);
/// other subjects, other collections and other accounts are untouched,
/// and `validate: false` skips the pruning (as the reference).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn duplicates_pruned_in_the_same_commit() {
    let s = TestServer::spawn().await;
    let a = s.create_account("bla").await;
    let b = s.create_account("blb").await;
    for coll in [LIKE, REPOST, FOLLOW, BLOCK] {
        let one = create(&s, &a, coll, rec(coll, 1), None).await;
        let two = create(&s, &a, coll, rec(coll, 2), None).await;
        let other = create(&s, &b, coll, rec(coll, 1), None).await;
        let mut sub = s.subscribe_from_now().await;
        let three = create(&s, &a, coll, rec(coll, 1), None).await;
        let frames = sub.wait_for(Duration::from_secs(10), &a.did, "#commit").await;
        let c = frames.last().unwrap().commit().unwrap();
        let mut ops: Vec<(String, String)> = c.ops.iter().map(|o| (o.action.clone(), o.path.clone())).collect();
        ops.sort();
        let mut want = vec![
            ("create".to_string(), format!("{coll}/{}", three.rkey())),
            ("delete".to_string(), format!("{coll}/{}", one.rkey())),
        ];
        want.sort();
        assert_eq!(ops, want, "{coll}: one commit with the delete and the create");
        assert_eq!(c.rev, s.latest_commit(&a.did).await.1);
        let mut left = vec![two.rkey().to_string(), three.rkey().to_string()];
        left.sort();
        assert_eq!(rkeys(&s, &a.did, coll).await, left, "{coll}");
        assert_eq!(rkeys(&s, &b.did, coll).await, vec![other.rkey().to_string()], "{coll}: another account's");
        // validate: false keeps the duplicate (the reference checks only when validating)
        let four = create(&s, &a, coll, rec(coll, 2), Some(false)).await;
        let mut left = vec![two.rkey().to_string(), three.rkey().to_string(), four.rkey().to_string()];
        left.sort();
        assert_eq!(rkeys(&s, &a.did, coll).await, left, "{coll}: validate false");
        // and the next validated create of that subject deletes both
        let five = create(&s, &a, coll, rec(coll, 2), None).await;
        let mut left = vec![three.rkey().to_string(), five.rkey().to_string()];
        left.sort();
        assert_eq!(rkeys(&s, &a.did, coll).await, left, "{coll}: both duplicates pruned");
    }
    // a like and a repost of the same post are different collections
    assert_eq!(rkeys(&s, &a.did, LIKE).await.len(), 2);
    assert_eq!(rkeys(&s, &a.did, REPOST).await.len(), 2);
    assert_eq!(check_backlinks(&s, &a.did).await, 8);
    assert_eq!(check_backlinks(&s, &b.did).await, 4);
    // the layout: bl/{did}\0 ‖ code ‖ subject -> rkey
    let like = rkeys(&s, &a.did, LIKE).await;
    let raw = scan_backlinks(&s, &a.did).await;
    let k = [b"l", post_uri(1).as_bytes()].concat();
    let v = raw.iter().find(|(key, _)| *key == k).map(|(_, v)| v.clone()).expect("like index entry");
    assert!(like.iter().any(|r| r.as_bytes() == v.as_slice()), "{like:?} {}", String::from_utf8_lossy(&v));
    // a post, or a like whose subject isn't an AT-URI, has none
    s.post(&a, "no backlink").await;
    create(&s, &a, LIKE, json!({"$type": LIKE, "subject": {"uri": "https://example.com/x", "cid": Cid::dag_cbor(b"x").to_string()}, "createdAt": now_iso()}), Some(false)).await;
    assert_eq!(check_backlinks(&s, &a.did).await, 8);
}

/// applyWrites doesn't prune (the reference checks in createRecord only):
/// duplicates in one batch are both kept and indexed under one key; a
/// createRecord of the subject then deletes them all. putRecord moving a
/// like to another subject, and deletes, keep the index exact.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn apply_writes_duplicates_and_updates() {
    let s = TestServer::spawn().await;
    let a = s.create_account("blw").await;
    let w = |coll: &str, rkey: usize, n: usize| json!({"$type": "com.atproto.repo.applyWrites#create", "collection": coll, "rkey": rk(rkey), "value": rec(coll, n)});
    s.apply_writes(&a, json!([w(LIKE, 1, 7), w(LIKE, 2, 7), w(FOLLOW, 1, 7), w(FOLLOW, 2, 7), w(LIKE, 3, 8)]))
        .await
        .ok();
    assert_eq!(rkeys(&s, &a.did, LIKE).await, vec![rk(1), rk(2), rk(3)]);
    assert_eq!(rkeys(&s, &a.did, FOLLOW).await, vec![rk(1), rk(2)]);
    assert_eq!(check_backlinks(&s, &a.did).await, 3);
    let raw = scan_backlinks(&s, &a.did).await;
    let k = [b"l", post_uri(7).as_bytes()].concat();
    assert_eq!(
        raw.iter().find(|(key, _)| *key == k).map(|(_, v)| v.clone()),
        Some(format!("{}\0{}", rk(1), rk(2)).into_bytes())
    );

    // putRecord moves rk(3) from subject 8 to 7; deleting rk(1) leaves rk(2), rk(3)
    s.put_record(&a, LIKE, &rk(3), rec(LIKE, 7)).await.ok();
    assert_eq!(check_backlinks(&s, &a.did).await, 2);
    s.delete_record(&a, LIKE, &rk(1)).await.ok();
    assert_eq!(check_backlinks(&s, &a.did).await, 2);

    let mut sub = s.subscribe_from_now().await;
    let last = create(&s, &a, LIKE, rec(LIKE, 7), None).await;
    let frames = sub.wait_for(Duration::from_secs(10), &a.did, "#commit").await;
    let ops: Vec<(String, String)> =
        frames.last().unwrap().commit().unwrap().ops.iter().map(|o| (o.action.clone(), o.path.clone())).collect();
    assert_eq!(ops.iter().filter(|(a, _)| a == "delete").count(), 2, "{ops:?}");
    assert_eq!(rkeys(&s, &a.did, LIKE).await, vec![last.rkey().to_string()]);
    create(&s, &a, FOLLOW, rec(FOLLOW, 7), None).await;
    assert_eq!(rkeys(&s, &a.did, FOLLOW).await.len(), 1);
    assert_eq!(check_backlinks(&s, &a.did).await, 2);

    // an explicit rkey naming the duplicate itself: deleted and written
    // again in one commit (the reference's delete + create), not refused
    let body = json!({"repo": a.did, "collection": LIKE, "rkey": last.rkey(), "record": rec(LIKE, 7)});
    s.xrpc.post("com.atproto.repo.createRecord", &body, &a.auth()).await.ok();
    assert_eq!(rkeys(&s, &a.did, LIKE).await, vec![last.rkey().to_string()]);
    assert_eq!(check_backlinks(&s, &a.did).await, 2);
}

/// Concurrent creates of one subject (the race the reference's check
/// guards against): each commit's check sees the ones before it, in
/// flight or not, so exactly one record per subject is left; a random
/// concurrent mix of creates, puts, deletes and batches keeps the index
/// exact.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_writes_keep_one_and_stay_exact() {
    use futures::StreamExt;
    let s = TestServer::spawn().await;
    let a = s.create_account("blc").await;
    for coll in [LIKE, FOLLOW] {
        futures::stream::iter(0..40)
            .map(|i| {
                let (s, a) = (&s, &a);
                async move { create(s, a, coll, rec(coll, 100 + i % 4), None).await }
            })
            .buffer_unordered(16)
            .collect::<Vec<_>>()
            .await;
        assert_eq!(rkeys(&s, &a.did, coll).await.len(), 4, "{coll}: one per subject");
    }
    check_backlinks(&s, &a.did).await;
    let mut rng = StdRng::seed_from_u64(5);
    let steps: Vec<(&'static str, J)> = random_steps(&mut rng, &a.did, 600);
    let (x, auth) = (s.xrpc.clone(), a.auth());
    let codes: Vec<u16> = futures::stream::iter(steps)
        .map(|(nsid, body)| {
            let (x, auth) = (x.clone(), auth.clone());
            async move { x.post(nsid, &body, &auth).await.status }
        })
        .buffer_unordered(24)
        .collect()
        .await;
    let ok = codes.iter().filter(|c| **c == 200).count();
    eprintln!("{ok} of {} writes applied", codes.len());
    assert!(ok > 200, "{codes:?}");
    assert!(check_backlinks(&s, &a.did).await > 10);
}

/// Random writes over the linked collections, a small subject pool (many
/// conflicts) and a small rkey space (updates, deletes of linked records).
fn random_steps(rng: &mut StdRng, did: &str, n: usize) -> Vec<(&'static str, J)> {
    let colls = [LIKE, REPOST, FOLLOW, BLOCK, "app.bsky.feed.post"];
    (0..n)
        .map(|_| {
            let coll = colls[rng.gen_range(0..colls.len())];
            let rkey = rk(rng.gen_range(0..30));
            let subj = rng.gen_range(0..6);
            let value = match coll {
                "app.bsky.feed.post" => json!({"$type": coll, "text": "p", "createdAt": now_iso()}),
                _ => rec(coll, subj),
            };
            match rng.gen_range(0..10) {
                0..=3 => ("com.atproto.repo.createRecord", json!({"repo": did, "collection": coll, "record": value})),
                4 => ("com.atproto.repo.createRecord", json!({"repo": did, "collection": coll, "rkey": rkey, "record": value, "validate": rng.gen_bool(0.5)})),
                5..=6 => ("com.atproto.repo.putRecord", json!({"repo": did, "collection": coll, "rkey": rkey, "record": value})),
                7 => ("com.atproto.repo.deleteRecord", json!({"repo": did, "collection": coll, "rkey": rkey})),
                _ => {
                    let writes: Vec<J> = (0..rng.gen_range(1..5))
                        .map(|i| {
                            let c = colls[rng.gen_range(0..4)];
                            match rng.gen_range(0..3) {
                                0 => json!({"$type": "com.atproto.repo.applyWrites#create", "collection": c, "value": rec(c, rng.gen_range(0..6))}),
                                1 => json!({"$type": "com.atproto.repo.applyWrites#update", "collection": c, "rkey": rk(i * 7 % 30), "value": rec(c, rng.gen_range(0..6))}),
                                _ => json!({"$type": "com.atproto.repo.applyWrites#delete", "collection": c, "rkey": rk(rng.gen_range(0..30))}),
                            }
                        })
                        .collect();
                    ("com.atproto.repo.applyWrites", json!({"repo": did, "writes": writes}))
                }
            }
        })
        .collect()
}

/// importRepo of a repo holding duplicates indexes them all (the reference
/// indexes imported records without pruning); the next createRecord of the
/// subject prunes them; a second import replaces the index; deleting the
/// account leaves no `bl/` entry.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn import_with_duplicates_then_delete() {
    let s = TestServer::spawn().await;
    let a = s.create_account("bli").await;
    let b = s.create_account("blj").await;
    // a's own index first: the import must replace it
    create(&s, &a, LIKE, rec(LIKE, 50), None).await;
    create(&s, &a, BLOCK, rec(BLOCK, 51), None).await;
    let w = |coll: &str, rkey: usize, n: usize| json!({"$type": "com.atproto.repo.applyWrites#create", "collection": coll, "rkey": rk(rkey), "value": rec(coll, n)});
    s.apply_writes(&b, json!([w(LIKE, 1, 9), w(LIKE, 2, 9), w(LIKE, 3, 9), w(REPOST, 1, 9), w(FOLLOW, 1, 3)]))
        .await
        .ok();
    let car = s.get_repo_car(&b.did).await;
    s.import_repo(&a.auth(), car.clone()).await.ok();
    assert_eq!(rkeys(&s, &a.did, LIKE).await, vec![rk(1), rk(2), rk(3)]);
    assert_eq!(check_backlinks(&s, &a.did).await, 3);
    let raw = scan_backlinks(&s, &a.did).await;
    let k = [b"l", post_uri(9).as_bytes()].concat();
    assert_eq!(
        raw.iter().find(|(key, _)| *key == k).map(|(_, v)| v.clone()),
        Some(format!("{}\0{}\0{}", rk(1), rk(2), rk(3)).into_bytes())
    );
    // right after the import (its state possibly still in flight)
    let kept = create(&s, &a, LIKE, rec(LIKE, 9), None).await;
    assert_eq!(rkeys(&s, &a.did, LIKE).await, vec![kept.rkey().to_string()]);
    create(&s, &a, FOLLOW, rec(FOLLOW, 3), None).await;
    assert_eq!(rkeys(&s, &a.did, FOLLOW).await.len(), 1);
    assert_eq!(check_backlinks(&s, &a.did).await, 3);
    // imported again: the duplicates are back, the creates' entries gone
    s.import_repo(&a.auth(), car).await.ok();
    assert_eq!(rkeys(&s, &a.did, LIKE).await, vec![rk(1), rk(2), rk(3)]);
    assert_eq!(check_backlinks(&s, &a.did).await, 3);
    // rebuildRepo re-derives it the same way
    s.xrpc.post("vlpds.admin.rebuildRepo", &json!({"did": a.did}), &Auth::Admin).await.ok();
    assert_eq!(check_backlinks(&s, &a.did).await, 3);
    s.xrpc.post("com.atproto.admin.deleteAccount", &json!({"did": a.did}), &Auth::Admin).await.ok();
    assert!(scan_backlinks(&s, &a.did).await.is_empty(), "bl/ entries left after the account delete");
    assert_eq!(check_backlinks(&s, &b.did).await, 3);
}

/// Replay rebuilds `bl/` exactly: the owner is killed (nothing
/// checkpointed) and the survivor replays its log, deriving each record's
/// put from the #commit frame and the rest from the stored muts. Then a
/// createRecord on the survivor still prunes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replay_after_kill_reproduces_the_index() {
    const SHARDS: u32 = 4;
    let store: Arc<dyn object_store::ObjectStore> = Arc::new(object_store::memory::InMemory::new());
    let node = |id: &'static str| {
        cluster_node(id, store.clone(), SHARDS, |c| {
            c.checkpoint_every = Duration::from_secs(3600);
            let l = lease(c);
            (l.ttl, l.renew_every, l.skew) =
                (Duration::from_secs(2), Duration::from_millis(200), Duration::from_millis(400));
        })
    };
    let a = node("bra").await;
    let b = node("brb").await;
    balanced(&[&a, &b]).await;
    let mut accts = Vec::new();
    for i in 0..6 {
        accts.push(a.create_account(&format!("brk{i}")).await);
    }
    let mut rng = StdRng::seed_from_u64(17);
    for x in &accts {
        for (nsid, body) in random_steps(&mut rng, &x.did, 80) {
            a.xrpc.post(nsid, &body, &x.auth()).await;
        }
    }
    let victim = if b.app.partition(&accts[0].did).is_ok() { &b } else { &a };
    let survivor = if std::ptr::eq(victim, &a) { &b } else { &a };
    let moved: Vec<&TestAccount> = accts.iter().filter(|x| victim.app.partition(&x.did).is_ok()).collect();
    assert!(!moved.is_empty(), "the victim owns some of the repos");
    let mut before = Vec::new();
    for x in &moved {
        check_backlinks(victim, &x.did).await;
        before.push(scan_backlinks(victim, &x.did).await);
    }
    victim.app.node.halt();
    wait_until("survivor takes every shard", Duration::from_secs(20), || {
        survivor.app.partitions.owned().len() == SHARDS as usize
    })
    .await;
    for (x, want) in moved.iter().zip(&before) {
        assert!(!want.is_empty());
        assert_eq!(&scan_backlinks(survivor, &x.did).await, want, "{}: replayed index", x.did);
        check_backlinks(survivor, &x.did).await;
        let one = create(survivor, x, LIKE, rec(LIKE, 0), None).await;
        let left: Vec<String> = rkeys(survivor, &x.did, LIKE).await;
        assert!(left.contains(&one.rkey().to_string()));
        check_backlinks(survivor, &x.did).await;
    }
}

/// Splits and merges carry `bl/` with the shard's slot range.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reshard_carries_the_index() {
    let s = TestServer::spawn().await;
    let mut accts = Vec::new();
    for i in 0..6 {
        accts.push(s.create_account(&format!("brs{i}")).await);
    }
    let mut rng = StdRng::seed_from_u64(29);
    for x in &accts {
        for (nsid, body) in random_steps(&mut rng, &x.did, 40) {
            s.xrpc.post(nsid, &body, &x.auth()).await;
        }
    }
    let mut before = Vec::new();
    for x in &accts {
        check_backlinks(&s, &x.did).await;
        before.push(scan_backlinks(&s, &x.did).await);
    }
    let admin = |nsid: &str, body: J| s.xrpc.post_owned(nsid, body, Auth::Admin);
    let cl = s.app.cluster.as_deref().unwrap();
    let slot = vlsync_store::slots::slot_of(&accts[0].did) as u32;
    let target = cl.layout().shards.iter().find(|r| r.lo <= slot && slot < r.hi).cloned().unwrap();
    let r =
        admin("vlpds.admin.splitShard", json!({"shard": target.id, "at": (target.lo + target.hi) / 2, "wait": true}))
            .await
            .ok();
    assert_eq!(r["done"], json!(true), "{r}");
    // `wait` returns at the flip; the children are taken after it
    balanced(&[&s]).await;
    for (x, want) in accts.iter().zip(&before) {
        assert_eq!(&scan_backlinks(&s, &x.did).await, want, "{}: after the split", x.did);
        check_backlinks(&s, &x.did).await;
    }
    let kids: Vec<vlsync_store::slots::ShardId> = r["op"]["children"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| vlsync_store::slots::ShardId(c["id"].as_u64().unwrap() as u32))
        .collect();
    for x in &accts {
        create(&s, x, FOLLOW, rec(FOLLOW, 1), None).await;
        assert!(!rkeys(&s, &x.did, FOLLOW).await.is_empty());
    }
    let r = admin("vlpds.admin.mergeShards", json!({"left": kids[0], "right": kids[1], "wait": true})).await.ok();
    assert_eq!(r["done"], json!(true), "{r}");
    balanced(&[&s]).await;
    for x in &accts {
        check_backlinks(&s, &x.did).await;
        let one = create(&s, x, FOLLOW, rec(FOLLOW, 1), None).await;
        assert_eq!(
            subject_records(&s, &x.did, FOLLOW, &json!(subject_did(1))).await,
            vec![one.rkey().to_string()],
            "{}",
            x.did
        );
        check_backlinks(&s, &x.did).await;
    }
}

/// More duplicates than one commit may hold: a create prunes as many as
/// fit (the commit stays within 200 ops, oldest first) and later creates
/// prune the rest.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn duplicate_pruning_is_capped_per_commit() {
    let s = TestServer::spawn().await;
    let a = s.create_account("blcap").await;
    let w = |rkey: usize| json!({"$type": "com.atproto.repo.applyWrites#create", "collection": LIKE, "rkey": rk(rkey), "value": rec(LIKE, 9)});
    for range in [0..200, 200..250] {
        s.apply_writes(&a, range.map(w).collect()).await.ok();
    }
    let all = || async {
        let (mut out, mut cursor) = (Vec::new(), None::<String>);
        loop {
            let mut q = vec![("limit", "100")];
            if let Some(c) = &cursor {
                q.push(("cursor", c.as_str()));
            }
            let l = s.list_records(&a.did, LIKE, &q).await.ok();
            let page: Vec<String> = l["records"]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| r["uri"].as_str().unwrap().rsplit('/').next().unwrap().to_string())
                .collect();
            let done = page.is_empty();
            out.extend(page);
            match l["cursor"].as_str() {
                Some(c) if !done => cursor = Some(c.to_string()),
                _ => return out,
            }
        }
    };
    assert_eq!(all().await.len(), 250);
    let mut sub = s.subscribe_from_now().await;
    let kept = create(&s, &a, LIKE, rec(LIKE, 9), None).await;
    let frames = sub.wait_for(Duration::from_secs(10), &a.did, "#commit").await;
    let ops = frames.iter().rev().find_map(|f| f.commit()).map(|c| c.ops.len()).unwrap();
    assert_eq!(ops, 200, "the 199 oldest duplicates deleted with the create");
    let left = all().await;
    assert_eq!(left.len(), 52);
    assert!(left.contains(&rk(249)) && !left.contains(&rk(198)), "oldest first");
    create(&s, &a, LIKE, rec(LIKE, 9), None).await;
    let left = all().await;
    assert_eq!(left.len(), 1);
    assert!(!left.contains(&kept.rkey().to_string()));
    assert_eq!(check_backlinks(&s, &a.did).await, 1);
}
