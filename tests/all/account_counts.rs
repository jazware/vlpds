//! checkAccountStatus reports counts the repo worker keeps with each
//! commit (`S/{did}`, `state::RepoStats`). After every step of random
//! histories (creates, updates, deletes, applyWrites batches, coalesced
//! concurrent writes, backlink prunes, blob refs, imports, rebuilds) they
//! equal a full walk of the repo (`repo_stats::walk`) and the tree of its
//! exported CAR; also after a kill and replay of the log.

use crate::common::*;
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

const THING: &str = "com.example.thing";
const LIKE: &str = "app.bsky.feed.like";

type Path = (String, String);

fn png(tag: u8) -> Vec<u8> {
    let mut v = b"\x89PNG\r\n\x1a\n".to_vec();
    v.extend((0..64u8).map(|i| i.wrapping_mul(tag)));
    v.push(tag);
    v
}

/// Small value ranges, so records repeat (one CID at several paths) and
/// blobs are shared across records.
fn thing(rng: &mut StdRng, blobs: &[J]) -> J {
    let media: Vec<J> = (0..rng.gen_range(0..3)).map(|_| blobs[rng.gen_range(0..blobs.len())].clone()).collect();
    json!({"$type": THING, "n": rng.gen_range(0..6), "media": media})
}

/// Few subjects: creates prune earlier likes of the same one.
fn like(rng: &mut StdRng) -> J {
    let n = rng.gen_range(0..4);
    json!({"$type": LIKE, "subject": {"uri": format!("at://did:plc:ac{n:022}/app.bsky.feed.post/3jzfcijpj2z2a"), "cid": Cid::dag_cbor(format!("p{n}").as_bytes()).to_string()}, "createdAt": "2026-10-01T00:00:00.000Z"})
}

fn tid_key(rng: &mut StdRng) -> String {
    vlsync_atproto::tid::Tid(rng.gen_range(1u64 << 50..1u64 << 52) << 10).to_string()
}

fn count(j: &J, k: &str) -> u64 {
    j[k].as_u64().unwrap_or_else(|| panic!("{k} in {j}"))
}

/// checkAccountStatus == full walk == the exported repo.
async fn check(s: &TestServer, a: &TestAccount, what: &str) {
    let st = s.xrpc.get("com.atproto.server.checkAccountStatus", &[], &a.auth()).await.ok();
    let p = s.app.partition(&a.did).unwrap_or_else(|_| panic!("shard not owned"));
    let walked = vlpds::repo_stats::walk(&*p.db, &a.did, s.app.repo_gen(&a.did).await.ok().unwrap()).await.unwrap();
    let car = s.xrpc.get("com.atproto.sync.getRepo", &[("did", &a.did)], &Auth::None).await;
    assert_eq!(car.status, 200, "{}", car.text());
    let repo = Repo::from_car(&car.body).unwrap();
    let (records, nodes) = vlpds::repo_stats::count_tree(&repo.tree()).unwrap();
    assert_eq!((walked.records, walked.nodes), (records, nodes), "{what}: walk vs exported tree");
    let got = (count(&st, "indexedRecords"), count(&st, "repoBlocks"), count(&st, "expectedBlobs"));
    assert_eq!(
        got,
        (walked.records, 1 + walked.nodes + walked.records, walked.blobs),
        "{what}: checkAccountStatus vs walk ({walked:?})"
    );
    assert_eq!(st["repoCommit"], json!(repo.root.to_string()), "{what}");
}

async fn upload_blobs(s: &TestServer, a: &TestAccount, n: u8) -> Vec<J> {
    let mut out = Vec::new();
    for t in 1..=n {
        out.push(
            s.xrpc.post_bytes("com.atproto.repo.uploadBlob", png(t), "image/png", &a.auth()).await.ok()["blob"].clone(),
        );
    }
    out
}

fn pick(rng: &mut StdRng, live: &[Path]) -> Option<Path> {
    (!live.is_empty()).then(|| live[rng.gen_range(0..live.len())].clone())
}

/// One random step against `a`; `live` tracks its paths, `cars` its exports.
async fn step(
    s: &TestServer,
    a: &TestAccount,
    rng: &mut StdRng,
    blobs: &[J],
    live: &mut Vec<Path>,
    cars: &mut Vec<Vec<u8>>,
) -> String {
    match rng.gen_range(0..100) {
        0..=24 => {
            let (coll, rec) = if rng.gen_bool(0.3) { (LIKE, like(rng)) } else { (THING, thing(rng, blobs)) };
            let rkey = tid_key(rng);
            s.xrpc
                .post(
                    "com.atproto.repo.createRecord",
                    &json!({"repo": a.did, "collection": coll, "rkey": rkey, "record": rec}),
                    &a.auth(),
                )
                .await
                .ok();
            if coll == LIKE {
                // pruned likes of the subject are gone: re-read the collection
                let listed = s.list_records(&a.did, LIKE, &[("limit", "100")]).await.ok();
                live.retain(|p| p.0 != LIKE);
                for r in listed["records"].as_array().unwrap() {
                    let uri = r["uri"].as_str().unwrap();
                    live.push((LIKE.into(), uri.rsplit('/').next().unwrap().to_string()));
                }
            } else {
                live.push((coll.into(), rkey));
            }
            format!("create {coll}")
        }
        25..=39 => {
            let (coll, rkey) = match pick(rng, live) {
                Some(p) if p.0 == THING && rng.gen_bool(0.8) => p,
                _ => (THING.to_string(), tid_key(rng)),
            };
            let rec = thing(rng, blobs);
            s.xrpc
                .post(
                    "com.atproto.repo.putRecord",
                    &json!({"repo": a.did, "collection": coll, "rkey": rkey, "record": rec}),
                    &a.auth(),
                )
                .await
                .ok();
            if !live.contains(&(coll.clone(), rkey.clone())) {
                live.push((coll, rkey));
            }
            "put".into()
        }
        40..=54 => {
            let Some((coll, rkey)) = pick(rng, live) else { return "noop".into() };
            s.xrpc
                .post(
                    "com.atproto.repo.deleteRecord",
                    &json!({"repo": a.did, "collection": coll, "rkey": rkey}),
                    &a.auth(),
                )
                .await
                .ok();
            live.retain(|p| *p != (coll.clone(), rkey.clone()));
            "delete".into()
        }
        55..=74 => {
            let mut writes = Vec::new();
            let mut touched: HashSet<Path> = HashSet::new();
            for _ in 0..rng.gen_range(1..25) {
                match rng.gen_range(0..3) {
                    0 => {
                        let rkey = tid_key(rng);
                        touched.insert((THING.to_string(), rkey.clone()));
                        writes.push(json!({"$type": "com.atproto.repo.applyWrites#create", "collection": THING, "rkey": rkey, "value": thing(rng, blobs)}));
                        live.push((THING.into(), rkey));
                    }
                    1 => {
                        let Some((coll, rkey)) = pick(rng, live).filter(|p| p.0 == THING && touched.insert(p.clone()))
                        else {
                            continue;
                        };
                        writes.push(json!({"$type": "com.atproto.repo.applyWrites#update", "collection": coll, "rkey": rkey, "value": thing(rng, blobs)}));
                    }
                    _ => {
                        let Some((coll, rkey)) = pick(rng, live).filter(|p| touched.insert(p.clone())) else {
                            continue;
                        };
                        writes.push(
                            json!({"$type": "com.atproto.repo.applyWrites#delete", "collection": coll, "rkey": rkey}),
                        );
                        live.retain(|p| *p != (coll.clone(), rkey.clone()));
                    }
                }
            }
            if writes.is_empty() {
                return "noop".into();
            }
            s.xrpc
                .post("com.atproto.repo.applyWrites", &json!({"repo": a.did, "writes": writes}), &a.auth())
                .await
                .ok();
            format!("applyWrites x{}", writes.len())
        }
        75..=84 => {
            // concurrent: coalesced into shared commits
            let n = rng.gen_range(2..12);
            let reqs: Vec<(String, J)> = (0..n).map(|_| (tid_key(rng), thing(rng, blobs))).collect();
            let auth = a.auth();
            let bodies: Vec<J> = reqs
                .iter()
                .map(|(rkey, rec)| json!({"repo": a.did, "collection": THING, "rkey": rkey, "record": rec}))
                .collect();
            let posts = bodies.iter().map(|b| s.xrpc.post("com.atproto.repo.createRecord", b, &auth));
            for r in futures::future::join_all(posts).await {
                r.ok();
            }
            live.extend(reqs.into_iter().map(|(k, _)| (THING.to_string(), k)));
            format!("{n} concurrent creates")
        }
        85..=90 => {
            cars.push(s.xrpc.get("com.atproto.sync.getRepo", &[("did", &a.did)], &Auth::None).await.body.to_vec());
            "export".into()
        }
        91..=95 => {
            if cars.is_empty() {
                return "noop".into();
            }
            let car = cars[rng.gen_range(0..cars.len())].clone();
            s.xrpc
                .post_bytes("com.atproto.repo.importRepo", car.clone(), "application/vnd.ipld.car", &a.auth())
                .await
                .ok();
            *live = Repo::from_car(&car)
                .unwrap()
                .entries()
                .into_iter()
                .map(|(p, _)| {
                    let (c, r) = p.split_once('/').unwrap();
                    (c.to_string(), r.to_string())
                })
                .collect();
            "import".into()
        }
        96..=97 => {
            s.xrpc.post("vlpds.admin.rebuildRepo", &json!({"did": a.did}), &Auth::Admin).await.ok();
            "rebuild".into()
        }
        _ => {
            // emptied, then a batch into the empty tree
            for chunk in live.chunks(100) {
                let writes: Vec<J> = chunk
                    .iter()
                    .map(|(c, r)| json!({"$type": "com.atproto.repo.applyWrites#delete", "collection": c, "rkey": r}))
                    .collect();
                s.xrpc
                    .post("com.atproto.repo.applyWrites", &json!({"repo": a.did, "writes": writes}), &a.auth())
                    .await
                    .ok();
            }
            live.clear();
            let writes: Vec<J> = (0..rng.gen_range(2..6))
                .map(|_| {
                    let rkey = tid_key(rng);
                    live.push((THING.into(), rkey.clone()));
                    json!({"$type": "com.atproto.repo.applyWrites#create", "collection": THING, "rkey": rkey, "value": thing(rng, blobs)})
                })
                .collect();
            s.xrpc
                .post("com.atproto.repo.applyWrites", &json!({"repo": a.did, "writes": writes}), &a.auth())
                .await
                .ok();
            "clear and refill".into()
        }
    }
}

async fn random_history(unload_idle: bool, seed: u64, steps: usize) {
    let s = TestServer::spawn_with(|c| {
        if unload_idle {
            c.lazy_mst_unload_idle = true;
            c.cache_per_worker = 1;
            c.workers = 1;
        }
    })
    .await;
    let a = s.create_account("acct").await;
    let other = s.create_account("acevict").await;
    check(&s, &a, "new account").await;
    let blobs = upload_blobs(&s, &a, 4).await;
    let mut rng = StdRng::seed_from_u64(seed);
    let (mut live, mut cars) = (Vec::new(), Vec::new());
    for i in 0..steps {
        let what = step(&s, &a, &mut rng, &blobs, &mut live, &mut cars).await;
        if unload_idle && i % 3 == 0 {
            // evicts the repo from the one-repo cache: its next write opens it cold
            s.post(&other, "evict").await;
        }
        check(&s, &a, &format!("step {i} ({what}, seed {seed}, unload_idle {unload_idle})")).await;
    }
    let p = s.app.partition(&a.did).unwrap_or_else(|_| panic!("shard not owned"));
    let r = s.xrpc.get("vlpds.admin.checkRepo", &[("did", &a.did)], &Auth::Admin).await.ok();
    assert_eq!(r["ok"], json!(true), "{r}");
    s.xrpc.post("com.atproto.admin.deleteAccount", &json!({"did": a.did}), &Auth::Admin).await.ok();
    assert!(
        p.db.get(vlpds::state::repo_stats_key(&a.did)).await.unwrap().is_none(),
        "S/ left after the account delete"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn counts_match_walk_after_every_step() {
    for seed in 0..env_or("VLPDS_COUNT_SEEDS", 4) {
        random_history(false, seed, 150).await;
    }
}

/// Every idle repo drops its loaded paths and blob refs after each pass,
/// and another repo's writes evict it from a one-repo cache: writes adding
/// or dropping refs read them back first, and cold opens read `S/`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn counts_match_walk_with_unloads() {
    for seed in 0..env_or("VLPDS_COUNT_SEEDS", 2) {
        random_history(true, 100 + seed, 150).await;
    }
}

/// A lost `S/` row: checkRepo reports it, and a repo opened without one
/// is counted from scratch (and the count written back).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn missing_stats_are_recounted() {
    let s = TestServer::spawn_with(|c| {
        c.cache_per_worker = 1;
        c.workers = 1;
    })
    .await;
    let a = s.create_account("acmiss").await;
    let other = s.create_account("acevict").await;
    let blobs = upload_blobs(&s, &a, 2).await;
    let mut rng = StdRng::seed_from_u64(3);
    for _ in 0..30 {
        let rec = thing(&mut rng, &blobs);
        s.xrpc
            .post(
                "com.atproto.repo.createRecord",
                &json!({"repo": a.did, "collection": THING, "record": rec}),
                &a.auth(),
            )
            .await
            .ok();
    }
    let p = s.app.partition(&a.did).unwrap_or_else(|_| panic!("shard not owned"));
    let key = vlpds::state::repo_stats_key(&a.did);
    p.db.delete(&key).await.unwrap();
    let r = s.xrpc.get("vlpds.admin.checkRepo", &[("did", &a.did)], &Auth::Admin).await.ok();
    assert_eq!(r["ok"], json!(false), "{r}");
    assert!(r["problems"].to_string().contains("repo stats (S/) missing"), "{r}");
    // the next open (after another repo took the one-repo cache) counts it
    s.post(&other, "evict").await;
    s.xrpc
        .post(
            "com.atproto.repo.createRecord",
            &json!({"repo": a.did, "collection": THING, "record": thing(&mut rng, &blobs)}),
            &a.auth(),
        )
        .await
        .ok();
    check(&s, &a, "after the recount").await;
    let r = s.xrpc.get("vlpds.admin.checkRepo", &[("did", &a.did)], &Auth::Admin).await.ok();
    assert_eq!(r["ok"], json!(true), "{r}");
}

async fn wait_until(what: &str, deadline: Duration, f: impl Fn() -> bool) {
    let t = Instant::now();
    while !f() {
        assert!(t.elapsed() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// The counts are stored muts of each commit's log entry: a node killed
/// before any checkpoint leaves them to the survivor's replay.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn counts_survive_replay() {
    const SHARDS: u32 = 4;
    let store: Arc<dyn object_store::ObjectStore> = Arc::new(object_store::memory::InMemory::new());
    let node = |id: &'static str| {
        let store = store.clone();
        TestServer::spawn_with(move |c| {
            c.memory_store = Some(store);
            c.shards = SHARDS;
            // nothing checkpointed during the test: the survivor replays it all
            c.checkpoint_every = Duration::from_secs(3600);
            c.cluster = Some(vlpds::cluster::ClusterConfig {
                node_id: id.into(),
                addr: peer_url(c),
                shards: SHARDS,
                ttl: Duration::from_secs(2),
                renew_every: Duration::from_millis(200),
                skew: Duration::from_millis(400),
                ..Default::default()
            });
        })
    };
    let a = node("cra").await;
    let b = node("crb").await;
    let owned = || a.app.partitions.owned().len() + b.app.partitions.owned().len();
    wait_until("both own shards", Duration::from_secs(15), || {
        !a.app.partitions.owned().is_empty() && !b.app.partitions.owned().is_empty() && owned() == SHARDS as usize
    })
    .await;
    let mut accts = Vec::new();
    for i in 0..6 {
        accts.push(a.create_account(&format!("crp{i}")).await);
    }
    let victim = if b.app.partition(&accts[0].did).is_ok() { &b } else { &a };
    let survivor = if std::ptr::eq(victim, &a) { &b } else { &a };
    let moved: Vec<&TestAccount> = accts.iter().filter(|x| victim.app.partition(&x.did).is_ok()).collect();
    let mut rng = StdRng::seed_from_u64(11);
    for x in &moved {
        let blobs = upload_blobs(victim, x, 3).await;
        let (mut live, mut cars) = (Vec::new(), Vec::new());
        for i in 0..40 {
            let what = step(victim, x, &mut rng, &blobs, &mut live, &mut cars).await;
            check(victim, x, &format!("step {i} ({what})")).await;
        }
        check(victim, x, "before the kill").await;
    }
    victim.app.node.halt();
    wait_until("survivor takes every shard", Duration::from_secs(20), || {
        survivor.app.partitions.owned().len() == SHARDS as usize
    })
    .await;
    for x in &moved {
        check(survivor, x, "replayed").await;
    }
}

fn env_or<T: std::str::FromStr>(k: &str, d: T) -> T {
    std::env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(d)
}

/// `VLPDS_STATUS_RECORDS=1000000 cargo test --profile dev-release --test all
/// account_counts::bench_check_account_status -- --ignored --nocapture`
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore]
async fn bench_check_account_status() {
    let n: u32 = env_or("VLPDS_STATUS_RECORDS", 1_000_000);
    let s = TestServer::spawn_with(|c| c.shards = 4).await;
    let t = Instant::now();
    let r = s
        .xrpc
        .post("vlpds.admin.bulkCreate", &json!({"indices": [0], "records": [n]}), &Auth::Bearer(ADMIN_TOKEN.into()))
        .await;
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(r.json["created"].as_u64(), Some(1), "{}", r.text());
    s.app.log.checkpoint_all().await;
    eprintln!("populated {n} records in {:.1}s", t.elapsed().as_secs_f64());
    let did = vlpds::state::bulk_did(0);
    let auth = Auth::Bearer(s.app.jwt.access(&did));
    let mut lat = Vec::new();
    for _ in 0..env_or("VLPDS_STATUS_CALLS", 5) {
        let t = Instant::now();
        let r = s.xrpc.get("com.atproto.server.checkAccountStatus", &[], &auth).await;
        lat.push(t.elapsed());
        assert_eq!(r.status, 200, "{}", r.text());
        assert_eq!(r.json["indexedRecords"].as_u64(), Some(n as u64), "{}", r.text());
    }
    lat.sort();
    let ms = |d: Duration| d.as_secs_f64() * 1e3;
    println!(
        "checkAccountStatus, {n} records: min {:.2} ms, median {:.2} ms, max {:.2} ms ({} calls)",
        ms(lat[0]),
        ms(lat[lat.len() / 2]),
        ms(lat[lat.len() - 1]),
        lat.len()
    );
}
