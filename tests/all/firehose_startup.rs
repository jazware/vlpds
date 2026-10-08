//! Firehose seam at a node's start (bench/ha O1): nodes join a cluster one by
//! one under write load, and every node's subscribeRepos must carry the union
//! of all node logs, each event once, in seq order, with no gaps: replayed
//! from cursor 0 afterwards, consumed from cursor 0 by a subscriber attached
//! the moment the node came up, and (from its first event on) by a cursorless
//! live subscriber attached then.

use crate::common::*;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Duration;

const SHARDS: u32 = 8;

async fn node(id: &str, store: &Arc<object_store::memory::InMemory>) -> TestServer {
    node_with(id, store, None).await
}

/// `put_ms`: every segment PUT of this node's log takes that long.
pub(crate) async fn node_with(
    id: &str,
    store: &Arc<object_store::memory::InMemory>,
    put_ms: Option<f64>,
) -> TestServer {
    cluster_node(id, store.clone(), SHARDS, |c| c.inject_latency = put_ms.map(|ms| (ms, 0.0))).await
}

/// Collects (seq, raw frame) from a subscription until `target` is set and
/// reached.
pub(crate) fn collect(mut sub: Sub, target: Arc<AtomicI64>) -> tokio::task::JoinHandle<Vec<(i64, Vec<u8>)>> {
    tokio::spawn(async move {
        let mut out: Vec<(i64, Vec<u8>)> = Vec::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
        loop {
            let t = target.load(Ordering::Acquire);
            if t > 0 && out.last().is_some_and(|(s, _)| *s >= t) {
                return out;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "subscriber never reached {t}; at {:?}",
                out.last().map(|x| x.0)
            );
            match sub.next(Duration::from_millis(200)).await {
                Some(f) => {
                    assert_ne!(f.kind(), "#info", "unexpected #info frame: {:?}", f.body);
                    if let Some(s) = f.seq() {
                        out.push((s, f.raw));
                    }
                }
                None => assert!(!sub.closed, "subscription closed"),
            }
        }
    })
}

/// Writers: each account posts as fast as it can through `via` (forwarded to
/// the owner); only acked commits count.
pub(crate) struct Writers {
    stop: Arc<AtomicBool>,
    acked: Arc<parking_lot::Mutex<Vec<String>>>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Writers {
    pub(crate) fn start(via: &TestServer, accounts: &[TestAccount]) -> Writers {
        let stop = Arc::new(AtomicBool::new(false));
        let acked: Arc<parking_lot::Mutex<Vec<String>>> = Default::default();
        let mut tasks = Vec::new();
        for acct in accounts.iter().cloned() {
            let (x, stop, acked) = (Xrpc::new(&via.url), stop.clone(), acked.clone());
            tasks.push(tokio::spawn(async move {
                let mut i = 0;
                while !stop.load(Ordering::Acquire) {
                    i += 1;
                    let body = json!({"repo": acct.did, "collection": "app.bsky.feed.post", "record": post_record(&format!("seam {i}"))});
                    let r = x.post("com.atproto.repo.createRecord", &body, &acct.auth()).await;
                    if r.is_ok() {
                        acked.lock().push(r.ok()["commit"]["cid"].as_str().expect("commit cid").to_string());
                    } else {
                        tokio::time::sleep(Duration::from_millis(5)).await; // shard moving: retry
                    }
                }
            }));
        }
        Writers { stop, acked, tasks }
    }

    /// Stops the writers; returns the acked commits' CIDs.
    pub(crate) async fn stop(self) -> Vec<String> {
        self.stop.store(true, Ordering::Release);
        for t in self.tasks {
            t.await.unwrap();
        }
        self.acked.lock().clone()
    }
}

/// Ground truth: the union of every node log in S3, merged by seq, once it
/// holds every acked commit (each exactly once).
pub(crate) async fn s3_union(s: &TestServer, acked: &[String]) -> Vec<(i64, Vec<u8>)> {
    let s3 = s.app.firehose.store.read().clone().unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let union = loop {
        let (tx, mut rx) = tokio::sync::mpsc::channel(1 << 16);
        let st = s3.clone();
        let job = tokio::spawn(async move { vlsync_firehose::backfill::backfill(&st, 0, i64::MAX, &tx).await });
        let mut all = Vec::new();
        while let Some((seq, frame)) = rx.recv().await {
            all.push((seq, frame.to_vec()));
        }
        job.await.unwrap().unwrap();
        let mut commits: HashMap<String, usize> = HashMap::new();
        for c in all.iter().filter_map(|(_, raw)| Frame::decode(raw).unwrap().commit()) {
            *commits.entry(c.commit.to_string()).or_default() += 1;
        }
        if acked.iter().all(|c| commits.contains_key(c)) {
            for c in acked {
                assert_eq!(commits[c], 1, "acked commit {c} logged more than once");
            }
            break all;
        }
        assert!(tokio::time::Instant::now() < deadline, "acked commits never all reached S3");
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    assert!(union.windows(2).all(|w| w[0].0 < w[1].0), "union of logs has duplicate seqs");
    union
}

pub(crate) fn mismatch(what: &str, got: &[(i64, Vec<u8>)], want: &[(i64, Vec<u8>)]) -> String {
    let g: Vec<i64> = got.iter().map(|x| x.0).collect();
    let w: Vec<i64> = want.iter().map(|x| x.0).collect();
    let missing: Vec<i64> = w.iter().filter(|s| !g.contains(s)).copied().take(20).collect();
    let extra: Vec<i64> = g.iter().filter(|s| !w.contains(s)).copied().take(20).collect();
    format!("{what}: got {} events, want {}; missing {missing:?} extra {extra:?}", g.len(), w.len())
}

/// A node streams only the log a follower names: a peer following a dead
/// incarnation's log at the same address must not get the new log's batches
/// (they were merged under the old log's id too: duplicate firehose events).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn log_stream_serves_only_the_named_log() {
    let store = Arc::new(object_store::memory::InMemory::new());
    let a = node("ls-a", &store).await;
    let rb = peer_client()
        .get(format!("{}/internal/v1/cluster", a.peer_url))
        .header("x-vlpds-internal", vlpds::server::DEV_INTERNAL_TOKEN);
    let log = a.xrpc.send(rb).await.ok()["log"].as_str().expect("log id").to_string();
    let connect = |log: String| {
        let url = format!("{}/internal/v1/log/stream?log={log}", a.peer_url.replacen("https", "wss", 1));
        async move {
            let mut req =
                tokio_tungstenite::tungstenite::client::IntoClientRequest::into_client_request(url.as_str()).unwrap();
            req.headers_mut().insert("x-vlpds-internal", vlpds::server::DEV_INTERNAL_TOKEN.parse().unwrap());
            tokio_tungstenite::connect_async_tls_with_config(req, None, false, peer_client().ws_connector("ls-a")).await
        }
    };
    let (mut ws, _) = connect(log.clone()).await.expect("own log streams");
    use futures::StreamExt;
    let first = tokio::time::timeout(Duration::from_secs(5), ws.next())
        .await
        .expect("a heartbeat")
        .expect("open")
        .expect("message");
    assert!(first.is_binary());
    let old = format!("{}.1", log.split('.').next().unwrap());
    assert!(connect(old).await.is_err(), "another incarnation's log must be refused");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn staggered_starts_under_load_lose_no_events() {
    let store = Arc::new(object_store::memory::InMemory::new());
    let a = node("fs-a", &store).await;
    let accounts: Vec<TestAccount> = futures::future::join_all((0..6).map(|_| a.create_account("fs"))).await;
    let writers = Writers::start(&a, &accounts);

    // nodes join one by one; each gets a cursor-0 and a live subscriber the
    // moment it is up
    let target = Arc::new(AtomicI64::new(0));
    let mut nodes = vec![a];
    let mut from_zero = vec![collect(nodes[0].subscribe(Some(0)).await, target.clone())];
    let mut live = vec![collect(nodes[0].subscribe(None).await, target.clone())];
    for id in ["fs-b", "fs-c", "fs-d"] {
        tokio::time::sleep(Duration::from_millis(400)).await;
        let n = node(id, &store).await;
        from_zero.push(collect(n.subscribe(Some(0)).await, target.clone()));
        live.push(collect(n.subscribe(None).await, target.clone()));
        nodes.push(n);
    }
    tokio::time::sleep(Duration::from_millis(600)).await;
    let acked = writers.stop().await;
    assert!(acked.len() > 200, "write load too light: {} acked", acked.len());
    let union = s3_union(&nodes[0], &acked).await;
    let seqs: Vec<i64> = union.iter().map(|x| x.0).collect();
    target.store(*seqs.last().unwrap(), Ordering::Release);

    for (i, (z, l)) in from_zero.into_iter().zip(live).enumerate() {
        let got = z.await.unwrap();
        assert!(got == union, "{}", mismatch(&format!("node {i} cursor-0 subscriber attached at start"), &got, &union));
        let got = l.await.unwrap();
        let start = seqs.iter().position(|s| *s == got[0].0).expect("live subscriber's first event is in the union");
        assert!(
            got == union[start..],
            "{}",
            mismatch(&format!("node {i} live subscriber attached at start"), &got, &union[start..])
        );
        let mut replay = collect(nodes[i].subscribe(Some(0)).await, target.clone()).await.unwrap();
        replay.truncate(union.len() + 1);
        assert!(replay == union, "{}", mismatch(&format!("node {i} replay from cursor 0"), &replay, &union));
    }
}

/// A node that starts while a peer's segments are in flight: its start floor
/// F is above seqs the peer assigned but hasn't made durable yet. A cursor-0
/// subscriber attached the moment the node is up backfills (0, F] from S3,
/// which has to wait until every peer's log is durable past F. The merger
/// drops events <= F as the backfill's, so an early backfill (say, a
/// follower's watermark starting at F before the peer reported anything)
/// loses the peer's in-flight ones for good.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn start_floor_waits_for_peers_in_flight_segments() {
    let store = Arc::new(object_store::memory::InMemory::new());
    // every segment PUT of a's log takes 300 ms: at any instant a few
    // segments' worth of its seqs are assigned but not in S3
    let a = node_with("fl-a", &store, Some(300.0)).await;
    let accounts: Vec<TestAccount> = futures::future::join_all((0..6).map(|_| a.create_account("fl"))).await;
    let writers = Writers::start(&a, &accounts);
    tokio::time::sleep(Duration::from_millis(500)).await;
    let target = Arc::new(AtomicI64::new(0));
    let b = node("fl-b", &store).await;
    let from_zero = collect(b.subscribe(Some(0)).await, target.clone());
    tokio::time::sleep(Duration::from_millis(500)).await;
    let acked = writers.stop().await;
    assert!(acked.len() >= 6, "write load too light: {} acked", acked.len());
    let union = s3_union(&a, &acked).await;
    target.store(union.last().unwrap().0, Ordering::Release);
    let got = from_zero.await.unwrap();
    assert!(got == union, "{}", mismatch("cursor-0 subscriber attached at b's start", &got, &union));
}

/// A node shut down gracefully whose server keeps answering afterwards (an
/// in-process test node, or a process hung past its shutdown): its log is
/// fenced and its lease gone. A log stream left open, heartbeating a frozen
/// watermark, would stall every peer's merger for as long as the process
/// lived. The stream must end with the log (and a follower leave a stream
/// whose lease is gone): peers drain it from S3 to the fence, retire it,
/// and their firehoses keep advancing under the writes that go on, every
/// acked event once and in order.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn stopped_node_still_serving_does_not_stall_its_peers() {
    use vlpds::cluster::ShardHost;
    let store = Arc::new(object_store::memory::InMemory::new());
    let a = node("sd-a", &store).await;
    let b = node("sd-b", &store).await;
    let c = node("sd-c", &store).await;
    wait_until("the shards spread over 3 nodes", Duration::from_secs(10), || {
        owned(&a) > 0 && owned(&b) > 0 && owned(&c) > 0 && owned(&a) + owned(&b) + owned(&c) == SHARDS as usize
    })
    .await;
    let accounts: Vec<TestAccount> = futures::future::join_all((0..8).map(|_| a.create_account("sd"))).await;
    let target = Arc::new(AtomicI64::new(0));
    let subs = vec![
        ("a live", collect(a.subscribe(None).await, target.clone())),
        ("b live", collect(b.subscribe(None).await, target.clone())),
        ("a cursor 0", collect(a.subscribe(Some(0)).await, target.clone())),
        ("b cursor 0", collect(b.subscribe(Some(0)).await, target.clone())),
    ];
    let writers = Writers::start(&a, &accounts);
    tokio::time::sleep(Duration::from_millis(400)).await;
    let c_log = c.app.log.log_id.to_string();
    vlpds::server::shutdown(&c.app).await; // and no halt: c keeps serving
    for (name, n) in [("a", &a), ("b", &b)] {
        wait_until(&format!("{name} drains c's log to its fence"), Duration::from_secs(10), || {
            !n.app.node.follow_floors().contains_key(&c_log)
        })
        .await;
    }
    // the peers' firehoses settle past now, twice over, while writes go on
    for _ in 0..2 {
        a.settled_now().await;
        b.settled_now().await;
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    let acked = writers.stop().await;
    assert!(acked.len() > 100, "write load too light: {} acked", acked.len());
    assert!(!c.app.cluster.as_ref().unwrap().halted(), "c was never halted");
    let union = s3_union(&a, &acked).await;
    let seqs: Vec<i64> = union.iter().map(|x| x.0).collect();
    target.store(*seqs.last().unwrap(), Ordering::Release);
    for (name, sub) in subs {
        let got = sub.await.unwrap();
        let start = if name.ends_with("live") {
            seqs.iter().position(|s| *s == got[0].0).expect("live subscriber's first event is in the union")
        } else {
            0
        };
        assert!(got == union[start..], "{}", mismatch(name, &got, &union[start..]));
    }
}
