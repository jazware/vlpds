//! `vlpds.space.importRepo` under hostile bodies: everything that costs
//! memory is checked before the body is read (a space write grant, the
//! account's rate limit and import slots, the import budget), and every
//! block is capped from its length before it's buffered: the commit at
//! 1 KiB, the index at `--space-repo-max-records` × 128 bytes (1 MiB at
//! least), a record at 1 MB, as a space write's.

use super::phase3::*;
use super::ref_net::*;
use crate::common::spaces::SpaceClient;
use crate::common::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

struct One {
    net: Net,
    alice: SpaceClient,
    bob: SpaceClient,
    space: String,
}

async fn one_with(f: impl Fn(usize, &mut vlpds::server::Config)) -> One {
    let net = Net::new_with(0, f).await;
    let (alice, bob) = (net.actor("alice", 0).await, net.actor("bob", 0).await);
    let space = net.create_space(&alice, SpaceOpts { members: &[&bob], ..Default::default() }).await;
    One { net, alice, bob, space }
}

/// importRepo with a body made by `body` (once per DPoP nonce attempt).
async fn import_body(sc: &SpaceClient, space: &str, body: impl Fn() -> reqwest::Body) -> Resp {
    try_import_body(sc, space, body).await.expect("the request went out")
}

/// None: the server answered and closed while the body was still going
/// out (the client sees a broken pipe instead of the answer).
async fn try_import_body(sc: &SpaceClient, space: &str, body: impl Fn() -> reqwest::Body) -> Option<Resp> {
    let url = crate::common::spaces::xrpc_url(&sc.srv.base, IMPORT_REPO, &[("space", space)]);
    for attempt in 0..2 {
        let rb = sc
            .srv
            .http
            .post(&url)
            .header("dpop", sc.key.proof("POST", &url, Some(&sc.access)))
            .header("authorization", format!("DPoP {}", sc.access))
            .header("content-type", CAR_TYPE)
            .body(body());
        let r = crate::common::spaces::resp(rb.send().await.ok()?).await;
        if let Some(n) = r.headers.get("dpop-nonce").and_then(|v| v.to_str().ok()) {
            *sc.key.nonce.lock() = Some(n.to_string());
        }
        if attempt == 0 && r.json["error"] == "use_dpop_nonce" {
            continue;
        }
        return Some(r);
    }
    unreachable!()
}

/// A body that never sends a byte nor ends.
fn hanging() -> reqwest::Body {
    reqwest::Body::wrap_stream(futures::stream::pending::<Result<bytes::Bytes, std::io::Error>>())
}

/// `car` in 64 KiB chunks, counting what the server pulled, then never
/// ending: an answer can't wait for the end.
fn counted(car: bytes::Bytes, pulled: Arc<AtomicUsize>) -> reqwest::Body {
    let chunks: Vec<bytes::Bytes> =
        (0..car.len()).step_by(64 << 10).map(|i| car.slice(i..(i + (64 << 10)).min(car.len()))).collect();
    let sent = futures::stream::iter(chunks).map(move |c| {
        pulled.fetch_add(c.len(), Ordering::Relaxed);
        Ok::<_, std::io::Error>(c)
    });
    reqwest::Body::wrap_stream(sent.chain(futures::stream::pending()))
}

use futures::StreamExt;

fn rss() -> u64 {
    let s = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    s.lines()
        .find_map(|l| l.strip_prefix("VmRSS:"))
        .and_then(|v| v.trim().trim_end_matches("kB").trim().parse::<u64>().ok())
        .map_or(0, |kb| kb << 10)
}

/// A dag-cbor array of `n` ones: ~40 bytes per byte as a decoded value.
fn ones(n: usize) -> Vec<u8> {
    let mut b = vec![0x9a];
    b.extend_from_slice(&(n as u32).to_be_bytes());
    b.resize(5 + n, 0x01);
    b
}

fn records(b: RepoBuilder, n: usize) -> RepoBuilder {
    (0..n).fold(b, |b, i| {
        b.record(TEST_COLLECTION, &format!("imp{i:04}"), record(TEST_COLLECTION, &format!("imported {i}")))
    })
}

/// A 32 MiB root block of tiny items (the commit, or the index after a
/// real commit) is refused from its length: 8 accounts at once finish fast, the
/// server pulls a fraction of each body, and the process barely grows
/// (a decode would hold ~1.3 GB each).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_huge_root_block_is_refused_cheaply() {
    let o = one_with(|_, _| {}).await;
    let s = &o.net.pds[0];
    let built = records(RepoBuilder::new(&o.space, &o.bob.did, &rev_ago(Duration::from_secs(60))), 1)
        .build(&*account_key(s, &o.bob.did).await);
    let huge = ones((32 << 20) - 64);
    let huge_cid = Cid::dag_cbor(&huge);
    let as_commit = write_car(&[huge_cid, built.index_cid], &[(huge_cid, huge.clone())]);
    let as_index =
        write_car(&[built.commit_cid, huge_cid], &[(built.commit_cid, built.commit_block.clone()), (huge_cid, huge)]);
    // one import per account: an account runs two at once
    let mut actors = vec![];
    for i in 0..8 {
        actors.push(o.net.actor(&format!("imp{i}"), 0).await);
    }
    for (what, car) in [("commit", as_commit), ("index", as_index)] {
        let car = bytes::Bytes::from(car);
        let base = rss();
        let peak = Arc::new(std::sync::atomic::AtomicU64::new(base));
        let sampling = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let sampler = {
            let (peak, sampling) = (peak.clone(), sampling.clone());
            tokio::spawn(async move {
                while sampling.load(Ordering::Relaxed) {
                    peak.fetch_max(rss(), Ordering::Relaxed);
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
        };
        let t = Instant::now();
        let pulled: Vec<Arc<AtomicUsize>> = (0..8).map(|_| Arc::default()).collect();
        let runs = pulled.iter().zip(&actors).map(|(p, sc)| {
            let (car, p) = (car.clone(), p.clone());
            let space = &o.space;
            async move { try_import_body(sc, space, || counted(car.clone(), p.clone())).await }
        });
        let rs = tokio::time::timeout(Duration::from_secs(20), futures::future::join_all(runs))
            .await
            .unwrap_or_else(|_| panic!("{what}: the imports waited for the bodies' end"));
        let took = t.elapsed();
        sampling.store(false, Ordering::Relaxed);
        sampler.await.unwrap();
        for r in rs.iter().flatten() {
            refused_mentioning(r, &["over"]);
        }
        let grew = peak.load(Ordering::Relaxed).saturating_sub(base);
        let most = pulled.iter().map(|p| p.load(Ordering::Relaxed)).max().unwrap();
        println!("{what}: 8 refused in {took:?}, RSS +{} MiB, at most {} MiB pulled", grew >> 20, most >> 20);
        assert!(took < Duration::from_secs(10), "{what}: {took:?}");
        assert!(grew < 400 << 20, "{what}: RSS grew {} MiB", grew >> 20);
        assert!(most < 24 << 20, "{what}: the server pulled {} MiB of a 32 MiB body", most >> 20);
        // the first 64 KiB (the block's length) are enough for the answer
        let prefix = car.slice(..64 << 10);
        let r = tokio::time::timeout(
            Duration::from_secs(10),
            import_body(&actors[0], &o.space, || counted(prefix.clone(), Arc::default())),
        )
        .await
        .unwrap_or_else(|_| panic!("{what}: the import waited for the block"));
        refused_mentioning(&r, &[&format!("{what} block is over")]);
    }
    nothing_written_here(&o.bob, &o.space).await;
    import_repo(&o.bob, &o.space, &built.car()).await.ok();
}

async fn nothing_written_here(sc: &SpaceClient, space: &str) {
    let r = sc.get("com.atproto.space.getLatestCommit", &[("space", space), ("repo", &sc.did)]).await;
    assert!(r.status >= 400, "a refused import wrote a repo: {}", r.text());
}

/// A grant that can't write in the space is refused before a byte of the
/// body is read: a body that would never end doesn't hold the answer up.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_grant_without_space_write_is_refused_before_the_body() {
    let o = one_with(|_, _| {}).await;
    let generic = regrant(&o.bob, "transition:generic").await;
    let read_only = regrant(&o.bob, &format!("space:{TEST_SPACE_TYPE}?authority=*&collection=*&action=read")).await;
    let other_type = regrant(&o.bob, "space:com.example.other?authority=*&collection=*&action=create").await;
    for (what, sc) in
        [("transition:generic", &generic), ("a read-only grant", &read_only), ("another type", &other_type)]
    {
        let r = tokio::time::timeout(Duration::from_secs(10), import_body(sc, &o.space, hanging))
            .await
            .unwrap_or_else(|_| panic!("{what}: the body was read before the scope check"));
        assert_eq!(r.status, 403, "{what}: {}", r.text());
    }
    // a grant that writes in the space waits for the body
    let waited = tokio::time::timeout(Duration::from_secs(2), import_body(&o.bob, &o.space, hanging)).await;
    assert!(waited.is_err(), "a write grant got an answer without a body: {:?}", waited.unwrap());
}

/// The commit over 1 KiB, the index over its cap and a record over 1 MB
/// are each refused, naming the block, and nothing is written.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn oversize_blocks_are_refused() {
    let o = one_with(|_, c| c.space_repo_max_records = 1000).await;
    let s = &o.net.pds[0];
    let key = account_key(s, &o.bob.did).await;
    let rev = rev_ago(Duration::from_secs(60));
    let built = records(RepoBuilder::new(&o.space, &o.bob.did, &rev), 2).build(&key);
    assert!(built.commit_block.len() < 512, "a real commit is {} bytes", built.commit_block.len());

    // a commit padded past 1 KiB
    let mut padded = Value::decode(&built.commit_block).unwrap();
    let Value::Map(m) = &mut padded else { unreachable!() };
    m.push(("zzzzzzzzzz".into(), Value::Bytes(vec![0; 1100])));
    let pb = padded.to_cbor();
    let pc = Cid::dag_cbor(&pb);
    let car = built.car_with(|bl| bl[0] = (pc, pb.clone()));
    let car = {
        let (_, bl) = vlatproto::car::read_car(&car).unwrap();
        let owned: Vec<(Cid, Vec<u8>)> = bl.iter().map(|(c, b)| (*c, b.to_vec())).collect();
        write_car(&[pc, built.index_cid], &owned)
    };
    refused_mentioning(&import_repo(&o.bob, &o.space, &car).await, &["commit block is over"]);

    // an index over max(1000 × 128 B, 1 MiB): 20k entries of ~60 bytes
    let fake = Cid::dag_cbor(b"x");
    let entries: Vec<(String, Cid)> = (0..20_000).map(|i| (format!("{TEST_COLLECTION}/k{i:06}"), fake)).collect();
    let ib = index_block(&entries);
    assert!(ib.len() > 1 << 20);
    let ic = Cid::dag_cbor(&ib);
    let car = write_car(&[built.commit_cid, ic], &[(built.commit_cid, built.commit_block.clone()), (ic, ib)]);
    refused_mentioning(&import_repo(&o.bob, &o.space, &car).await, &["index block is over"]);
    // under the byte cap but over the record count: refused from the map's head
    let entries: Vec<(String, Cid)> = (0..1001).map(|i| (format!("{TEST_COLLECTION}/k{i:06}"), fake)).collect();
    let ib = index_block(&entries);
    let ic = Cid::dag_cbor(&ib);
    let car = write_car(&[built.commit_cid, ic], &[(built.commit_cid, built.commit_block.clone()), (ic, ib)]);
    refused_mentioning(&import_repo(&o.bob, &o.space, &car).await, &["limit"]);

    // a record over 1 MB, which a space write refuses too
    let big = RepoBuilder::new(&o.space, &o.bob.did, &rev).record(
        TEST_COLLECTION,
        "big",
        json!({"$type": TEST_COLLECTION, "text": "x".repeat(1_000_100), "createdAt": now_iso()}),
    );
    refused_mentioning(&import_repo(&o.bob, &o.space, &big.build(&key).car()).await, &["record block is over"]);
    nothing_written_here(&o.bob, &o.space).await;
    import_repo(&o.bob, &o.space, &built.car()).await.ok();
}

/// `space-import` caps an account's imports per hour, and an account runs
/// two at once: a third waits for neither, it's refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn imports_are_rate_limited_and_capped_per_account() {
    let o = one_with(|_, c| c.rate_limits_enabled = true).await;
    let s = &o.net.pds[0];
    let built = records(RepoBuilder::new(&o.space, &o.bob.did, &rev_ago(Duration::from_secs(60))), 1)
        .build(&*account_key(s, &o.bob.did).await);

    s.xrpc
        .post(
            "vlpds.admin.updateRateLimits",
            &json!({"config": {"limiters": {"space-import": {"points": 5}}}, "ifVersion": 0, "actor": "it-test"}),
            &Auth::Admin,
        )
        .await
        .ok();
    // two hanging imports hold bob's slots
    let (bob, space) = (&o.bob, &o.space);
    let hold = || async move { tokio::time::timeout(Duration::from_secs(3), import_body(bob, space, hanging)).await };
    let (third, a, b) = tokio::join!(
        async {
            tokio::time::sleep(Duration::from_millis(1000)).await;
            import_repo(bob, space, &built.car()).await
        },
        hold(),
        hold(),
    );
    assert!(a.is_err() && b.is_err(), "the held imports answered");
    refused_mentioning(&third, &["in progress"]);
    // given back once they're gone
    import_repo(bob, space, &built.car()).await.ok();

    // 4 of 5 spent (two held, the refused one, the import)
    import_repo(bob, space, &built.car()).await.ok();
    import_repo(bob, space, &built.car()).await.err(429, "RateLimitExceeded");
    // alice has her own
    let r = import_repo(&o.alice, space, &built.car()).await;
    assert_ne!(r.status, 429, "{}", r.text());
}

/// Chunked bodies (no Content-Length) reserve an import's largest working
/// set, and a node runs no more of them than its import budget holds: on a
/// small budget several at once are each let in or refused at once with a
/// retryable 503, the budget is never overdrawn, and it's all given back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_chunked_imports_fit_the_budget() {
    let o = one_with(|_, c| {
        c.import_memory_bytes = Some(200 << 20);
        c.import_wait = Duration::from_secs(2);
    })
    .await;
    let s = &o.net.pds[0];
    let budget = s.app.imports.clone();
    let mut actors = vec![];
    for i in 0..6 {
        let sc = o.net.actor(&format!("chk{i}"), 0).await;
        put_member(&o.alice, &o.space, &sc, true, true).await.ok();
        actors.push(sc);
    }
    let mut cars = vec![];
    for sc in &actors {
        let built = records(RepoBuilder::new(&o.space, &sc.did, &rev_ago(Duration::from_secs(60))), 3)
            .build(&*account_key(s, &sc.did).await);
        cars.push(bytes::Bytes::from(built.car()));
    }
    let peak = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let sampling = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let sampler = {
        let (peak, sampling, budget) = (peak.clone(), sampling.clone(), budget.clone());
        tokio::spawn(async move {
            while sampling.load(Ordering::Relaxed) {
                peak.fetch_max(budget.reserved(), Ordering::Relaxed);
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
    };
    // each body trickles in: the header, a pause, the rest
    let runs = actors.iter().zip(&cars).map(|(sc, car)| {
        let space = &o.space;
        async move {
            import_body(sc, space, || {
                let (head, rest) = (car.slice(..64), car.slice(64..));
                let s = futures::stream::once(async move { Ok::<_, std::io::Error>(head) }).chain(
                    futures::stream::once(async move {
                        tokio::time::sleep(Duration::from_millis(400)).await;
                        Ok(rest)
                    }),
                );
                reqwest::Body::wrap_stream(s)
            })
            .await
        }
    });
    let rs = futures::future::join_all(runs).await;
    sampling.store(false, Ordering::Relaxed);
    sampler.await.unwrap();
    let ok = rs.iter().filter(|r| r.status == 200).count();
    for r in &rs {
        assert!(r.status == 200 || (r.status == 503 && r.error_name() == Some("Overloaded")), "{}", r.text());
    }
    println!("{ok} of 6 let in; peak reserved {} of {} MiB", peak.load(Ordering::Relaxed) >> 20, budget.total() >> 20);
    assert!(ok >= 1, "none let in");
    assert!(ok < 6, "a 200 MiB budget let in 6 chunked imports at their largest");
    assert!(peak.load(Ordering::Relaxed) <= budget.total());
    assert_eq!(budget.reserved(), 0);
    // one at a time, they all go in
    for (sc, car) in actors.iter().zip(&cars) {
        if rs.iter().any(|r| r.status == 503) {
            let r = import_repo(sc, &o.space, car).await;
            assert!(r.status == 200, "{}", r.text());
        }
    }
}

/// A space import whose body stalls fails once it's been idle too long,
/// giving back its slot and reservation.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stalled_space_import_body_fails() {
    let o = one_with(|_, c| c.import_body_idle = Duration::from_millis(500)).await;
    let s = &o.net.pds[0];
    let built = records(RepoBuilder::new(&o.space, &o.bob.did, &rev_ago(Duration::from_secs(60))), 3)
        .build(&*account_key(s, &o.bob.did).await);
    let car = bytes::Bytes::from(built.car());
    let t = Instant::now();
    let r = tokio::time::timeout(
        Duration::from_secs(20),
        import_body(&o.bob, &o.space, || counted(car.slice(..car.len() / 2), Arc::default())),
    )
    .await
    .expect("the import waited forever");
    refused_mentioning(&r, &["stalled"]);
    assert!(t.elapsed() < Duration::from_secs(10), "{:?}", t.elapsed());
    assert_eq!(s.app.imports.reserved(), 0);
    import_repo(&o.bob, &o.space, &built.car()).await.ok();
}
