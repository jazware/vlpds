//! importRepo staged under a fresh repo generation (src/xrpc/staged_import.rs,
//! DESIGN.md "Staged imports"): readers, exports and the firehose see the
//! old repo or the new one, never a mix, whatever happens mid-import (a
//! crash at any phase, a shard move between batches), and the generation
//! left behind is swept until no row of it remains.

use crate::common::*;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use vlpds::xrpc::staged_import as si;
use vlsync_atproto::cbor::{key_cmp, Value};

const CAR: &str = "application/vnd.ipld.car";
/// Several of the parse's batches (4,096 records), likes of the same few
/// subjects across them (`bl/` values built over batches), blob refs.
const RECORDS: usize = 10_000;

/// (path, cid) of every record.
type Contents = BTreeMap<String, Cid>;

/// A DAG-CBOR map, keys in canonical order.
fn map(mut m: Vec<(String, Value)>) -> Value {
    m.sort_by(|a, b| key_cmp(&a.0, &b.0));
    Value::Map(m)
}

fn record(i: usize, tag: &str) -> (String, Vec<u8>) {
    let (coll, mut m) = match i % 4 {
        0 => (
            "app.bsky.feed.like",
            vec![(
                "subject".to_string(),
                map(vec![
                    ("cid".into(), Value::Text("bafyreie5737gdxlw5i64vzichcalba3z2v5n6icifvx5xytvske7mr3hpm".into())),
                    (
                        "uri".into(),
                        Value::Text(format!(
                            "at://did:plc:ewvi7nxzyoun6zhxrhs64oiz/app.bsky.feed.post/3l{:011}",
                            i % 7
                        )),
                    ),
                ]),
            )],
        ),
        1 => ("app.bsky.graph.follow", vec![("subject".to_string(), Value::Text(format!("did:plc:{:024}", i % 5)))]),
        2 => (
            "app.bsky.feed.post",
            vec![
                ("text".to_string(), Value::Text(format!("{tag} {i}"))),
                (
                    "embed".to_string(),
                    map(vec![
                        ("$type".into(), Value::Text("app.bsky.embed.images".into())),
                        (
                            "images".into(),
                            Value::Array(vec![map(vec![
                                ("alt".into(), Value::Text(String::new())),
                                (
                                    "image".into(),
                                    map(vec![
                                        ("$type".into(), Value::Text("blob".into())),
                                        ("ref".into(), Value::Link(Cid::raw(format!("blob {}", i % 13).as_bytes()))),
                                        ("mimeType".into(), Value::Text("image/png".into())),
                                        ("size".into(), Value::Int(100)),
                                    ]),
                                ),
                            ])]),
                        ),
                    ]),
                ),
            ],
        ),
        _ => ("com.example.thing", vec![("n".to_string(), Value::Text(format!("{tag} {i}")))]),
    };
    m.push(("$type".to_string(), Value::Text(coll.into())));
    m.push(("createdAt".to_string(), Value::Text("2026-01-01T00:00:00.000Z".into())));
    m.sort_by(|a, b| key_cmp(&a.0, &b.0));
    (format!("{coll}/3l{i:011}"), Value::Map(m).to_cbor())
}

/// A repo of `n` records in the streamable order, and its contents.
fn repo_car(n: usize, tag: &str) -> (Vec<u8>, Contents) {
    let mut tree = vlsync_atproto::mst::Tree::new();
    let mut blocks = Vec::new();
    let mut contents = Contents::new();
    for i in 0..n {
        let (path, rec) = record(i, tag);
        let c = Cid::dag_cbor(&rec);
        tree.insert_no_proof(path.as_bytes(), c).unwrap();
        contents.insert(path, c);
        blocks.push((c, rec));
    }
    let data = tree.write_diff_blocks(&mut blocks).unwrap();
    let mut f = vec![
        ("did".to_string(), Value::Text("did:plc:elsewhere".into())),
        ("rev".to_string(), Value::Text("3l3qo2vuowo2b".into())),
        ("data".to_string(), Value::Link(data)),
        ("prev".to_string(), Value::Null),
        ("version".to_string(), Value::Int(3)),
        ("sig".to_string(), Value::Bytes(vec![0; 64])),
    ];
    f.sort_by(|a, b| key_cmp(&a.0, &b.0));
    let commit = Value::Map(f).to_cbor();
    let map: std::collections::HashMap<Cid, Vec<u8>> = blocks.into_iter().collect();
    (vlsync_atproto::car_order::write_car((Cid::dag_cbor(&commit), &commit), data, &map).unwrap(), contents)
}

async fn import(s: &TestServer, a: &TestAccount, car: Vec<u8>) -> Resp {
    s.xrpc.post_bytes("com.atproto.repo.importRepo", car, CAR, &a.auth()).await
}

/// The exported repo's records.
async fn exported(s: &TestServer, did: &str) -> Contents {
    let car = s.xrpc.get("com.atproto.sync.getRepo", &[("did", did)], &Auth::None).await;
    assert_eq!(car.status, 200, "{}", car.text());
    let repo = Repo::from_car(&car.body).unwrap();
    repo.entries().into_iter().collect()
}

/// A few records written through the API (posts and likes).
async fn seed(s: &TestServer, a: &TestAccount) -> Contents {
    let mut writes = Vec::new();
    for i in 0..60 {
        let (coll, rec) = if i % 2 == 0 {
            ("app.bsky.feed.post", post_record(&format!("old {i}")))
        } else {
            (
                "app.bsky.feed.like",
                json!({"$type": "app.bsky.feed.like", "subject": {"uri": format!("at://did:plc:ewvi7nxzyoun6zhxrhs64oiz/app.bsky.feed.post/3l{:011}", i % 3), "cid": "bafyreie5737gdxlw5i64vzichcalba3z2v5n6icifvx5xytvske7mr3hpm"}, "createdAt": now_iso()}),
            )
        };
        writes.push(json!({"$type": "com.atproto.repo.applyWrites#create", "collection": coll, "value": rec}));
    }
    s.apply_writes(a, json!(writes)).await.ok();
    exported(s, &a.did).await
}

/// Every row of the repo's generation families: (generation's prefix
/// found, row count) by family, over all generations up to `max`.
async fn rows_by_gen(s: &TestServer, did: &str, max: u64) -> BTreeMap<u64, usize> {
    let p = s.app.partition(did).unwrap_or_else(|_| panic!("shard not owned"));
    let mut out = BTreeMap::new();
    for g in 0..=max {
        let mut n = 0;
        for fam in vlpds::state::GEN_FAMILIES {
            let prefix = vlpds::state::gen_prefix(fam, did, g);
            let mut it = p.db.scan(prefix.clone()..vlsync_store::keys::prefix_end(&prefix)).await.unwrap();
            while it.next().await.unwrap().is_some() {
                n += 1;
            }
        }
        if n > 0 {
            out.insert(g, n);
        }
    }
    out
}

async fn import_state(s: &TestServer, did: &str) -> Option<vlpds::state::ImportState> {
    let p = s.app.partition(did).unwrap_or_else(|_| panic!("shard not owned"));
    p.db.get(vlpds::state::import_key(did)).await.unwrap().map(|v| vlpds::state::ImportState::decode(&v).unwrap())
}

/// The repo is exactly `want` (export, listRecords, getRecord, counts, the
/// admin check of every index), its rows are its generation's only, and
/// nothing is left staged or to sweep.
async fn settled(s: &TestServer, a: &TestAccount, want: &Contents, what: &str) {
    assert_eq!(&exported(s, &a.did).await, want, "{what}: export");
    let (path, cid) = want.iter().next().unwrap();
    let (coll, rkey) = path.split_once('/').unwrap();
    let r = s.get_record(&a.did, coll, rkey).await.ok();
    assert_eq!(r["cid"], json!(cid.to_string()), "{what}");
    let check = s.xrpc.get("vlpds.admin.checkRepo", &[("did", &a.did)], &Auth::Admin).await.ok();
    assert_eq!(check["ok"], json!(true), "{what}: {check}");
    let st = s.xrpc.get("com.atproto.server.checkAccountStatus", &[], &a.auth()).await.ok();
    assert_eq!(st["indexedRecords"], json!(want.len()), "{what}: {st}");
    let gen = s.app.repo_gen(&a.did).await.ok().unwrap();
    let rows = rows_by_gen(s, &a.did, gen + 3).await;
    assert_eq!(rows.keys().copied().collect::<Vec<_>>(), vec![gen], "{what}: rows outside generation {gen}: {rows:?}");
    assert_eq!(import_state(s, &a.did).await, None, "{what}: G/ left");
}

/// The firehose events of `did` from `cursor` until now.
async fn events_of(s: &TestServer, did: &str, cursor: i64) -> Vec<Frame> {
    // a marker commit after everything of `did`'s
    let m = s.create_account("mark").await;
    s.post(&m, "marker").await;
    let mut sub = s.subscribe(Some(cursor)).await;
    let frames =
        sub.until(FH_TIMEOUT, |fs| fs.iter().any(|f| f.kind() == "#commit" && f.did() == Some(m.did.as_str()))).await;
    frames.into_iter().filter(|f| f.did() == Some(did)).collect()
}

/// A big import over a repo with records: the new repo whole, one `#sync`
/// (no `#commit`), the old generation swept.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn import_replaces_the_repo_and_sweeps_the_old_generation() {
    let s = TestServer::spawn().await;
    let a = s.create_account("stg").await;
    let old = seed(&s, &a).await;
    settled(&s, &a, &old, "before").await;
    let cursor = s.settled_now().await;
    let (car, new) = repo_car(RECORDS, "new");
    import(&s, &a, car).await.ok();
    // the old generation's sweep runs after the response
    wait_until("old generation swept", Duration::from_secs(20), || {
        futures::executor::block_on(async { import_state(&s, &a.did).await.is_none() })
    })
    .await;
    settled(&s, &a, &new, "after").await;
    let evs = events_of(&s, &a.did, cursor).await;
    assert_eq!(evs.iter().map(|f| f.kind()).collect::<Vec<_>>(), vec!["#sync"], "one event");
    let head = s.app.head(&a.did).await.ok().unwrap();
    assert_eq!(evs[0].str("rev"), Some(head.rev.to_string().as_str()));
    // writes continue on the new repo; a second import moves on again
    s.post(&a, "after the import").await;
    let (car, newer) = repo_car(300, "newer");
    import(&s, &a, car).await.ok();
    wait_until("swept again", Duration::from_secs(20), || {
        futures::executor::block_on(async { import_state(&s, &a.did).await.is_none() })
    })
    .await;
    settled(&s, &a, &newer, "second import").await;
    assert_eq!(s.app.repo_gen(&a.did).await.ok().unwrap(), 2);
}

/// Pauses the import of `did` at the `n`th `phase` until `go` is set.
fn pause_at(did: &str, phase: &'static str, n: usize, paused: Arc<AtomicBool>, go: Arc<AtomicBool>) {
    let seen = Arc::new(AtomicUsize::new(0));
    si::set_crash_hook(
        did,
        Some(Arc::new(move |p: &str| {
            if p == phase && seen.fetch_add(1, Ordering::SeqCst) + 1 == n {
                paused.store(true, Ordering::SeqCst);
                while !go.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
            false
        })),
    );
}

/// Readers polling throughout an import (paused between its batches) see
/// the old repo or the new one, whole; writes wait out the import.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn readers_never_see_a_partial_import() {
    let s = Arc::new(TestServer::spawn().await);
    let a = s.create_account("stgr").await;
    let old = seed(&s, &a).await;
    let (car, new) = repo_car(RECORDS, "new");
    let (paused, go) = (Arc::new(AtomicBool::new(false)), Arc::new(AtomicBool::new(false)));
    pause_at(&a.did, "staged", 2, paused.clone(), go.clone());
    let stop = Arc::new(AtomicBool::new(false));
    let seen = Arc::new(parking_lot::Mutex::new((0usize, 0usize)));
    let readers: Vec<_> = (0..3)
        .map(|r| {
            let (s, a, old, new, stop, seen) =
                (s.clone(), a.clone(), old.clone(), new.clone(), stop.clone(), seen.clone());
            tokio::spawn(async move {
                while !stop.load(Ordering::Relaxed) {
                    let (got, of_old, of_new) = match r {
                        0 => {
                            let got = exported(&s, &a.did).await;
                            let (o, n) = (got == old, got == new);
                            (format!("{} records", got.len()), o, n)
                        }
                        1 => {
                            let l = s.list_records(&a.did, "app.bsky.feed.post", &[("limit", "100")]).await.ok();
                            let got: Contents = l["records"]
                                .as_array()
                                .unwrap()
                                .iter()
                                .map(|r| {
                                    let uri = r["uri"].as_str().unwrap();
                                    (
                                        uri.splitn(4, '/').nth(3).unwrap().to_string(),
                                        Cid::parse(r["cid"].as_str().unwrap()).unwrap(),
                                    )
                                })
                                .collect();
                            let part = |c: &Contents| {
                                got.iter().all(|(p, cid)| c.get(p) == Some(cid))
                                    && got.len()
                                        == c.keys().filter(|p| p.starts_with("app.bsky.feed.post/")).count().min(100)
                            };
                            (format!("{got:?}"), part(&old), part(&new))
                        }
                        _ => {
                            let st = s.xrpc.get("com.atproto.server.checkAccountStatus", &[], &a.auth()).await.ok();
                            let n = st["indexedRecords"].as_u64().unwrap() as usize;
                            (st.to_string(), n == old.len(), n == new.len())
                        }
                    };
                    assert!(of_old || of_new, "reader {r} saw a partial import: {got}");
                    let mut g = seen.lock();
                    if of_old {
                        g.0 += 1
                    } else {
                        g.1 += 1
                    }
                }
            })
        })
        .collect();
    let imp = {
        let (s, a) = (s.clone(), a.clone());
        tokio::spawn(async move { import(&s, &a, car).await })
    };
    wait_until("import paused between batches", Duration::from_secs(20), || paused.load(Ordering::SeqCst)).await;
    // mid-import: the old repo, staged rows under another generation, and
    // writes refused until the import is done
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(exported(&s, &a.did).await, old);
    let staged = import_state(&s, &a.did).await.unwrap().staging.expect("staged");
    assert!(rows_by_gen(&s, &a.did, staged.gen).await.get(&staged.gen).is_some_and(|n| *n > 0));
    let w = s
        .xrpc
        .post(
            "com.atproto.repo.createRecord",
            &json!({"repo": a.did, "collection": "app.bsky.feed.post", "record": post_record("mid-import")}),
            &a.auth(),
        )
        .await;
    w.err(400, "InvalidRequest");
    go.store(true, Ordering::SeqCst);
    imp.await.unwrap().ok();
    si::set_crash_hook(&a.did, None);
    tokio::time::sleep(Duration::from_millis(300)).await;
    stop.store(true, Ordering::Relaxed);
    for r in readers {
        r.await.unwrap();
    }
    let (o, n) = *seen.lock();
    assert!(o > 0 && n > 0, "readers saw old {o} times, new {n} times");
    wait_until("swept", Duration::from_secs(20), || {
        futures::executor::block_on(async { import_state(&s, &a.did).await.is_none() })
    })
    .await;
    settled(&s, &a, &new, "after").await;
}

async fn crash_node(id: &str, store: &Arc<dyn object_store::ObjectStore>) -> TestServer {
    cluster_node(id, store.clone(), 4, |c| {
        // nothing checkpointed: the survivor replays the victim's log
        c.checkpoint_every = Duration::from_secs(3600);
        let l = lease(c);
        (l.ttl, l.renew_every, l.skew) =
            (Duration::from_secs(2), Duration::from_millis(200), Duration::from_millis(400));
    })
    .await
}

/// The importing node dies (kill -9) at the `n`th `phase`: the survivor
/// replays its log and has the old repo ("begun", "staged") or the new one
/// ("committed", "sweeping"), whole, with the firehose agreeing; its
/// sweeper aborts the dead import and deletes every generation left.
async fn crash_mid_import(phase: &'static str, n: usize) {
    let store: Arc<dyn object_store::ObjectStore> = Arc::new(object_store::memory::InMemory::new());
    let tag = unique_name("si");
    let a = crash_node(&format!("{tag}-a"), &store).await;
    let b = crash_node(&format!("{tag}-b"), &store).await;
    wait_until("both own shards", Duration::from_secs(15), || {
        owned(&a) > 0 && owned(&b) > 0 && owned(&a) + owned(&b) == 4
    })
    .await;
    let x = b.create_account("six").await;
    assert!(b.app.partition(&x.did).is_ok());
    let mut old = seed(&b, &x).await;
    if phase == "sweeping" {
        // an old generation big enough to take several sweep entries
        let (car, big) = repo_car(RECORDS, "old");
        import(&b, &x, car).await.ok();
        wait_until("first import swept", Duration::from_secs(20), || {
            futures::executor::block_on(async { import_state(&b, &x.did).await.is_none() })
        })
        .await;
        old = big;
    }
    let cursor = a.settled_now().await;
    let (car, new) = repo_car(RECORDS, "new");
    let fired = Arc::new(AtomicBool::new(false));
    {
        let (fired, app, seen) = (fired.clone(), b.app.clone(), Arc::new(AtomicUsize::new(0)));
        si::set_crash_hook(
            &x.did,
            Some(Arc::new(move |p: &str| {
                if p != phase || seen.fetch_add(1, Ordering::SeqCst) + 1 != n || fired.swap(true, Ordering::SeqCst) {
                    return false;
                }
                app.node.halt();
                true
            })),
        );
    }
    let r = import(&b, &x, car).await;
    if phase == "sweeping" {
        // the import itself was done: the sweep runs after the response
        r.ok();
        wait_until("hook fired", Duration::from_secs(20), || fired.load(Ordering::SeqCst)).await;
    } else {
        assert!(!r.is_ok(), "{phase}: {}", r.text());
    }
    si::set_crash_hook(&x.did, None);
    assert!(fired.load(Ordering::SeqCst), "{phase} never reached");
    wait_until("a takes every shard", Duration::from_secs(20), || owned(&a) == 4).await;
    let committed = matches!(phase, "committed" | "sweeping");
    let want = if committed { &new } else { &old };
    assert_eq!(&exported(&a, &x.did).await, want, "{phase}: after the takeover");
    let left = import_state(&a, &x.did).await.expect("G/ survives the crash");
    assert_eq!(left.staging.is_some(), !committed, "{phase}: {left:?}");
    let swept = si::sweep_pending(&a.app).await;
    assert_eq!(swept.aborted, usize::from(!committed), "{phase}: {swept:?}");
    settled(&a, &x, want, phase).await;
    let evs = events_of(&a, &x.did, cursor).await;
    let kinds: Vec<&str> = evs.iter().map(|f| f.kind()).collect();
    assert_eq!(kinds, if committed { vec!["#sync"] } else { vec![] }, "{phase}: the firehose");
    // the repo moves on: writes, and an import that finishes
    a.post(&x, "after the crash").await;
    let (car, last) = repo_car(500, "last");
    import(&a, &x, car).await.ok();
    wait_until("swept", Duration::from_secs(20), || {
        futures::executor::block_on(async { import_state(&a, &x.did).await.is_none() })
    })
    .await;
    settled(&a, &x, &last, "re-import").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn crash_after_begin_keeps_the_old_repo() {
    crash_mid_import("begun", 1).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn crash_between_batches_keeps_the_old_repo() {
    crash_mid_import("staged", 1).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn crash_after_the_last_batch_keeps_the_old_repo() {
    // 10,000 records: three batches
    crash_mid_import("staged", 3).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn crash_after_the_commit_has_the_new_repo() {
    crash_mid_import("committed", 1).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn crash_mid_sweep_has_the_new_repo_and_sweeps_on() {
    crash_mid_import("sweeping", 2).await;
}

/// The shard moves (a graceful handoff) between two of the import's
/// batches: the import fails cleanly (503 ShardMoved: retry), the new owner
/// has the old repo and sweeps the staged rows, and the retried import goes
/// through there.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn shard_move_mid_import_aborts_it() {
    let store: Arc<dyn object_store::ObjectStore> = Arc::new(object_store::memory::InMemory::new());
    let tag = unique_name("sm");
    let a = cluster_node(&format!("{tag}-a"), store.clone(), 4, |_| {}).await;
    let b = cluster_node(&format!("{tag}-b"), store.clone(), 4, |_| {}).await;
    wait_until("both own shards", Duration::from_secs(15), || {
        owned(&a) > 0 && owned(&b) > 0 && owned(&a) + owned(&b) == 4
    })
    .await;
    let x = b.create_account("smx").await;
    assert!(b.app.partition(&x.did).is_ok());
    let old = seed(&b, &x).await;
    let (car, new) = repo_car(RECORDS, "new");
    let (paused, go) = (Arc::new(AtomicBool::new(false)), Arc::new(AtomicBool::new(false)));
    pause_at(&x.did, "staged", 1, paused.clone(), go.clone());
    let imp = {
        let (xrpc, auth, car) = (b.xrpc.clone(), x.auth(), car.clone());
        tokio::spawn(async move { xrpc.post_bytes("com.atproto.repo.importRepo", car, CAR, &auth).await })
    };
    wait_until("paused", Duration::from_secs(20), || paused.load(Ordering::SeqCst)).await;
    vlpds::server::shutdown(&b.app).await;
    wait_until("a takes every shard", Duration::from_secs(20), || owned(&a) == 4).await;
    go.store(true, Ordering::SeqCst);
    let r = imp.await.unwrap();
    si::set_crash_hook(&x.did, None);
    // retryable, nothing imported
    r.err(503, "ShardMoved");
    assert_eq!(exported(&a, &x.did).await, old);
    let swept = si::sweep_pending(&a.app).await;
    assert_eq!(swept.aborted, 1, "{swept:?}");
    settled(&a, &x, &old, "after the move").await;
    import(&a, &x, car).await.ok();
    wait_until("swept", Duration::from_secs(20), || {
        futures::executor::block_on(async { import_state(&a, &x.did).await.is_none() })
    })
    .await;
    settled(&a, &x, &new, "imported on the new owner").await;
}

/// An account deleted mid-import: the import fails, its staged rows go to
/// the garbage, and the sweep (on the deleted repo, loaded as a husk)
/// clears them and the `G/` row.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn deleted_account_generations_are_swept() {
    let s = TestServer::spawn().await;
    let a = s.create_account("sgd").await;
    seed(&s, &a).await;
    let (car, _) = repo_car(RECORDS, "new");
    let (paused, go) = (Arc::new(AtomicBool::new(false)), Arc::new(AtomicBool::new(false)));
    pause_at(&a.did, "staged", 1, paused.clone(), go.clone());
    let imp = {
        let (xrpc, auth) = (s.xrpc.clone(), a.auth());
        tokio::spawn(async move { xrpc.post_bytes("com.atproto.repo.importRepo", car, CAR, &auth).await })
    };
    wait_until("paused", Duration::from_secs(20), || paused.load(Ordering::SeqCst)).await;
    let staged = import_state(&s, &a.did).await.unwrap().staging.unwrap().gen;
    s.app.account_op(&a.did, vlpds::worker::AccountOp::Delete { only_if: None }).await.ok().unwrap();
    go.store(true, Ordering::SeqCst);
    assert!(!imp.await.unwrap().is_ok());
    si::set_crash_hook(&a.did, None);
    assert!(
        import_state(&s, &a.did).await.is_none_or(|g| g.staging.is_none()),
        "the staged import went to the garbage"
    );
    si::sweep_pending(&s.app).await;
    // the aborted driver may be sweeping it too
    wait_until("swept", Duration::from_secs(20), || {
        futures::executor::block_on(async { import_state(&s, &a.did).await.is_none() })
    })
    .await;
    assert!(rows_by_gen(&s, &a.did, staged + 2).await.is_empty());
}
