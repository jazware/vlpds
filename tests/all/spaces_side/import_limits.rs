//! `com.atproto.space.importRepo` under hostile bodies: everything that
//! costs memory is checked before the body is read (a space write grant,
//! the account's rate limit and import slots, the import budget), and every
//! STAR frame is capped from its length before it's buffered: the metadata
//! at 64 KiB, a key at 4 KiB, a value at 1 MiB (the profile's limits), and
//! the records at `--space-repo-max-records`.

use super::phase3::*;
use super::ref_net::*;
use crate::common::spaces::SpaceClient;
use crate::common::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use vlpds::space::star;

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
async fn import_body(sc: &SpaceClient, body: impl Fn() -> reqwest::Body) -> Resp {
    try_import_body(sc, body).await.expect("the request went out")
}

/// None: the server answered and closed while the body was still going
/// out (the client sees a broken pipe instead of the answer).
async fn try_import_body(sc: &SpaceClient, body: impl Fn() -> reqwest::Body) -> Option<Resp> {
    let url = crate::common::spaces::xrpc_url(&sc.srv.base, IMPORT_REPO, &[]);
    for attempt in 0..2 {
        let rb = sc
            .srv
            .http
            .post(&url)
            .header("dpop", sc.key.proof("POST", &url, Some(&sc.access)))
            .header("authorization", format!("DPoP {}", sc.access))
            .header("content-type", STAR_TYPE)
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

/// `body` in 64 KiB chunks, counting what the server pulled, then never
/// ending: an answer can't wait for the end.
fn counted(body: bytes::Bytes, pulled: Arc<AtomicUsize>) -> reqwest::Body {
    counted_parts(vec![body], pulled)
}

/// [`counted`] over `parts` one after another (a per-account head before a
/// shared tail).
fn counted_parts(parts: Vec<bytes::Bytes>, pulled: Arc<AtomicUsize>) -> reqwest::Body {
    let chunks: Vec<bytes::Bytes> = parts
        .iter()
        .flat_map(|p| (0..p.len()).step_by(64 << 10).map(|i| p.slice(i..(i + (64 << 10)).min(p.len()))))
        .collect();
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

/// A 32 MiB metadata frame, or a 32 MiB record after real metadata (a
/// decoded array of tiny items would hold ~1.3 GB), is refused from its
/// length: 8 accounts at once finish fast, the server pulls a fraction of
/// each body, and the process barely grows.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_huge_frame_is_refused_cheaply() {
    let o = one_with(|_, _| {}).await;
    let rev = rev_ago(Duration::from_secs(60));
    let built = records(RepoBuilder::new(&o.space, &o.bob.did, &rev), 1).build();
    let huge = bytes::Bytes::from(ones((32 << 20) - 64));
    // one import per account: an account runs two at once
    let mut actors = vec![];
    for i in 0..8 {
        actors.push(o.net.actor(&format!("imp{i}"), 0).await);
    }
    let as_meta = bytes::Bytes::from(write_star(&huge, &[], true));
    // each account's own metadata, then the shared huge value
    let record_head = |did: &str| {
        let key = format!("{TEST_COLLECTION}/huge");
        let mut out = Vec::new();
        star::write_header(&mut out, &RepoBuilder::new(&o.space, did, &rev).build().meta());
        out.push(1);
        star::write_varint(&mut out, key.len() as u64);
        out.extend_from_slice(key.as_bytes());
        star::write_varint(&mut out, huge.len() as u64);
        bytes::Bytes::from(out)
    };
    let end = bytes::Bytes::from_static(&[0]);
    for what in ["metadata", "record"] {
        let parts = |did: &str| match what {
            "metadata" => vec![as_meta.clone()],
            _ => vec![record_head(did), huge.clone(), end.clone()],
        };
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
            let (parts, p) = (parts(&sc.did), p.clone());
            async move { try_import_body(sc, || counted_parts(parts.clone(), p.clone())).await }
        });
        let rs = tokio::time::timeout(Duration::from_secs(20), futures::future::join_all(runs))
            .await
            .unwrap_or_else(|_| panic!("{what}: the imports waited for the bodies' end"));
        let took = t.elapsed();
        sampling.store(false, Ordering::Relaxed);
        sampler.await.unwrap();
        for r in rs.iter().flatten() {
            refused_mentioning(r, &["exceeds limit"]);
        }
        let grew = peak.load(Ordering::Relaxed).saturating_sub(base);
        let most = pulled.iter().map(|p| p.load(Ordering::Relaxed)).max().unwrap();
        println!("{what}: 8 refused in {took:?}, RSS +{} MiB, at most {} MiB pulled", grew >> 20, most >> 20);
        assert!(took < Duration::from_secs(10), "{what}: {took:?}");
        assert!(grew < 400 << 20, "{what}: RSS grew {} MiB", grew >> 20);
        assert!(most < 24 << 20, "{what}: the server pulled {} MiB of a 32 MiB body", most >> 20);
        // the first 64 KiB (the frame's length) are enough for the answer
        let mut prefix = parts(&actors[0].did).concat();
        prefix.truncate(64 << 10);
        let prefix = bytes::Bytes::from(prefix);
        let r = tokio::time::timeout(
            Duration::from_secs(10),
            import_body(&actors[0], || counted(prefix.clone(), Arc::default())),
        )
        .await
        .unwrap_or_else(|_| panic!("{what}: the import waited for the frame"));
        refused_mentioning(&r, &["exceeds limit"]);
    }
    nothing_written_here(&o.bob, &o.space).await;
    import_repo(&o.bob, &built.star()).await.ok();
}

async fn nothing_written_here(sc: &SpaceClient, space: &str) {
    let r = sc.get("com.atproto.space.getLatestCommit", &[("space", space), ("repo", &sc.did)]).await;
    assert!(r.status >= 400, "a refused import wrote a repo: {}", r.text());
}

/// A grant that writes in no space is refused before a byte of the body
/// is read: a body that would never end doesn't hold the answer up. One
/// that writes in another type of space is refused once the metadata names
/// the space, before any record.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_grant_without_space_write_is_refused_before_the_body() {
    let o = one_with(|_, _| {}).await;
    let generic = regrant(&o.bob, "transition:generic").await;
    let read_only = regrant(&o.bob, &format!("space:{TEST_SPACE_TYPE}?authority=*&collection=*&action=read")).await;
    for (what, sc) in [("transition:generic", &generic), ("a read-only grant", &read_only)] {
        let r = tokio::time::timeout(Duration::from_secs(10), import_body(sc, hanging))
            .await
            .unwrap_or_else(|_| panic!("{what}: the body was read before the scope check"));
        assert_eq!(r.status, 403, "{what}: {}", r.text());
    }
    let other_type = regrant(&o.bob, "space:com.example.other?authority=*&collection=*&action=create").await;
    let built = records(RepoBuilder::new(&o.space, &o.bob.did, &rev_ago(Duration::from_secs(60))), 1).build();
    let header = bytes::Bytes::from(write_star(&built.meta(), &[], false));
    let r = tokio::time::timeout(
        Duration::from_secs(10),
        import_body(&other_type, || counted(header.clone(), Arc::default())),
    )
    .await
    .expect("another type: the import waited past the metadata");
    assert_eq!(r.status, 403, "another type: {}", r.text());
    // a grant that writes in the space waits for the body
    let waited = tokio::time::timeout(Duration::from_secs(2), import_body(&o.bob, hanging)).await;
    assert!(waited.is_err(), "a write grant got an answer without a body: {:?}", waited.unwrap());
}

/// Metadata over 64 KiB, a key over 4 KiB, a record over 1 MiB and more
/// records than `--space-repo-max-records` are each refused, and nothing is
/// written.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn oversize_frames_are_refused() {
    let o = one_with(|_, c| c.space_repo_max_records = 1000).await;
    let rev = rev_ago(Duration::from_secs(60));
    let built = records(RepoBuilder::new(&o.space, &o.bob.did, &rev), 2).build();
    assert!(built.meta().len() < 512, "real metadata is {} bytes", built.meta().len());

    // metadata padded past 64 KiB (a canonical map, still with its $type)
    let mut padded = Value::decode(&built.meta()).unwrap();
    let Value::Map(m) = &mut padded else { unreachable!() };
    m.push(("zzzzzzzzzz".into(), Value::Bytes(vec![0; 70 << 10])));
    let star = write_star(&padded.to_cbor(), &built.pairs(), true);
    refused_mentioning(&import_repo(&o.bob, &star).await, &["exceeds limit of 65536"]);

    let long_key = format!("{TEST_COLLECTION}/{}", "k".repeat(5000)).into_bytes();
    let star = built.star_with(|p| p.push((long_key, p[0].1.clone())));
    refused_mentioning(&import_repo(&o.bob, &star).await, &["exceeds limit of 4096"]);

    let big = RepoBuilder::new(&o.space, &o.bob.did, &rev).record(
        TEST_COLLECTION,
        "big",
        json!({"$type": TEST_COLLECTION, "text": "x".repeat((1 << 20) + 100), "createdAt": now_iso()}),
    );
    refused_mentioning(&import_repo(&o.bob, &big.build().star()).await, &["exceeds limit of 1048576"]);

    let many = records(RepoBuilder::new(&o.space, &o.bob.did, &rev), 1001).build();
    refused_mentioning(&import_repo(&o.bob, &many.star()).await, &["limit"]);
    nothing_written_here(&o.bob, &o.space).await;
    import_repo(&o.bob, &built.star()).await.ok();
}

/// `space-import` caps an account's imports per hour, and an account runs
/// two at once: a third waits for neither, it's refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn imports_are_rate_limited_and_capped_per_account() {
    let o = one_with(|_, c| c.rate_limits_enabled = true).await;
    let s = &o.net.pds[0];
    let built = records(RepoBuilder::new(&o.space, &o.bob.did, &rev_ago(Duration::from_secs(60))), 1).build();

    s.xrpc
        .post(
            "vlpds.admin.updateRateLimits",
            &json!({"config": {"limiters": {"space-import": {"points": 5}}}, "ifVersion": 0, "actor": "it-test"}),
            &Auth::Admin,
        )
        .await
        .ok();
    // two hanging imports hold bob's slots
    let bob = &o.bob;
    let hold = || async move { tokio::time::timeout(Duration::from_secs(3), import_body(bob, hanging)).await };
    let (third, a, b) = tokio::join!(
        async {
            tokio::time::sleep(Duration::from_millis(1000)).await;
            import_repo(bob, &built.star()).await
        },
        hold(),
        hold(),
    );
    assert!(a.is_err() && b.is_err(), "the held imports answered");
    refused_mentioning(&third, &["in progress"]);
    // given back once they're gone: the server drops a held import when it
    // sees the client's connection close, a moment after the client gave up
    let sp = s.app.spaces.as_ref().unwrap();
    retry("the held imports' slots came back", || async { (sp.imports_running(&bob.did) == 0).then_some(()) }).await;
    import_repo(bob, &built.star()).await.ok();

    // 4 of 5 spent (two held, the refused one, the import)
    import_repo(bob, &built.star()).await.ok();
    import_repo(bob, &built.star()).await.err(429, "RateLimitExceeded");
    // alice has her own
    let r = import_repo(&o.alice, &built.star()).await;
    assert_ne!(r.status, 429, "{}", r.text());
}

/// Chunked bodies (no Content-Length) reserve an import's largest working
/// set (~12 MiB), and a node runs no more of them than its import budget
/// holds: on a small budget several at once are each let in or refused at once with a
/// retryable 503, the budget is never overdrawn, and it's all given back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_chunked_imports_fit_the_budget() {
    let o = one_with(|_, c| {
        c.import_memory_bytes = Some(40 << 20);
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
    let mut stars = vec![];
    for sc in &actors {
        let built = records(RepoBuilder::new(&o.space, &sc.did, &rev_ago(Duration::from_secs(60))), 3).build();
        stars.push(bytes::Bytes::from(built.star()));
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
    let runs = actors.iter().zip(&stars).map(|(sc, car)| async move {
        import_body(sc, || {
            let (head, rest) = (car.slice(..64), car.slice(64..));
            let s = futures::stream::once(async move { Ok::<_, std::io::Error>(head) }).chain(futures::stream::once(
                async move {
                    tokio::time::sleep(Duration::from_millis(400)).await;
                    Ok(rest)
                },
            ));
            reqwest::Body::wrap_stream(s)
        })
        .await
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
    assert!(ok < 6, "a 40 MiB budget let in 6 chunked imports at their largest");
    assert!(peak.load(Ordering::Relaxed) <= budget.total());
    assert_eq!(budget.reserved(), 0);
    // one at a time, they all go in
    for (sc, car) in actors.iter().zip(&stars) {
        if rs.iter().any(|r| r.status == 503) {
            let r = import_repo(sc, car).await;
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
    let built = records(RepoBuilder::new(&o.space, &o.bob.did, &rev_ago(Duration::from_secs(60))), 3).build();
    let car = bytes::Bytes::from(built.star());
    let t = Instant::now();
    let r = tokio::time::timeout(
        Duration::from_secs(20),
        import_body(&o.bob, || counted(car.slice(..car.len() / 2), Arc::default())),
    )
    .await
    .expect("the import waited forever");
    refused_mentioning(&r, &["stalled"]);
    assert!(t.elapsed() < Duration::from_secs(10), "{:?}", t.elapsed());
    assert_eq!(s.app.imports.reserved(), 0);
    import_repo(&o.bob, &built.star()).await.ok();
}
