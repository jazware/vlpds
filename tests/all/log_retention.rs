//! Log segment retention (src/retention.rs, DESIGN.md "Log retention"):
//! segments no replay can need and older than the window are deleted while
//! subscribers backfill, a dead log is pruned down to its fence once its
//! successors opened its shards, and a node restarts over a pruned log.
//!
//! The window is zero and passes run every 20 ms, so what holds segments
//! back is only the replay rule (checkpoints) and the fence.

use crate::common::*;
use object_store::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

fn fast() -> Option<vlpds::retention::Config> {
    Some(vlpds::retention::Config {
        window: Duration::ZERO,
        interval: Duration::from_millis(20),
        max_deletes: 3,
        ..Default::default()
    })
}

/// Ordinals of `log`'s objects in the store.
async fn ordinals(store: &vlsync_store::store::Store, log: &str) -> Vec<u64> {
    use futures::StreamExt;
    let prefix = Path::from(format!("{}/log/{log}", store.prefix));
    store
        .raw
        .list(Some(&prefix))
        .filter_map(|m| async move { m.ok()?.location.filename()?.strip_suffix(".seg")?.parse::<u64>().ok() })
        .collect()
        .await
}

/// Reads until the commit `head` of `did`, then checks what arrived: seqs
/// ascend, and `did`'s commits form one unbroken rev chain (`since` = the
/// previous rev) except right after an `OutdatedCursor` (history deleted
/// under the cursor). Returns how many OutdatedCursor infos it saw.
async fn check_stream(sub: &mut Sub, did: &str, head: &Cid) -> usize {
    let frames = sub
        .until(Duration::from_secs(20), |fs| fs.last().and_then(|f| f.commit()).is_some_and(|c| c.commit == *head))
        .await;
    let (mut outdated, mut last_seq, mut prev_rev, mut jump) = (0, 0i64, None::<String>, false);
    for f in &frames {
        if f.kind() == "#info" {
            assert_eq!(f.str("name"), Some("OutdatedCursor"));
            outdated += 1;
            jump = true;
            continue;
        }
        let seq = f.seq().expect("event seq");
        assert!(seq > last_seq, "seq {seq} after {last_seq}");
        last_seq = seq;
        if let Some(c) = f.commit().filter(|c| c.repo == did) {
            if let (Some(p), false) = (&prev_rev, jump) {
                assert_eq!(c.since.as_ref(), Some(p), "commit chain broken at seq {seq} without OutdatedCursor");
            }
            prev_rev = Some(c.rev.clone());
            jump = false;
        }
    }
    outdated
}

/// Subscribers backfill from cursor 0 (the ring holds ~2 KiB) while
/// retention deletes the log under them, a few segments per pass: each sees
/// a gap-free stream, or an OutdatedCursor where history went away. After
/// that a cursor-0 subscriber starts with OutdatedCursor, and the node
/// still serves every record.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn prune_while_subscribers_backfill() {
    let s = TestServer::spawn_with(|c| {
        c.firehose_ring_bytes = 2048;
        c.log_retention = fast();
    })
    .await;
    let a = s.create_account("ret").await;
    let mut posts = Vec::new();
    for i in 0..60 {
        posts.push(s.post(&a, &format!("retained {i} {}", "x".repeat(64))).await);
    }
    let log = s.app.log.log_id.to_string();
    let store = s.app.store.clone();
    let before = ordinals(&store, &log).await;
    assert_eq!(before.first(), Some(&0));

    // drive checkpoints (they move the replay floor) and more writes while
    // subscribers replay from 0
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let driver = {
        let (app, stop) = (s.app.clone(), stop.clone());
        tokio::spawn(async move {
            // (each checkpoint flushes a small L0 per shard: much faster
            // than this and SlateDB's L0 cap stalls flushes until compaction)
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                app.log.checkpoint_all().await;
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
    };
    let mut subs = Vec::new();
    for _ in 0..4 {
        subs.push(s.subscribe(Some(0)).await);
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    for i in 0..40 {
        posts.push(s.post(&a, &format!("during {i} {}", "y".repeat(64))).await);
    }
    let head = Cid::parse(posts.last().unwrap().commit_cid.as_deref().unwrap()).unwrap();
    let mut jumps = 0;
    for sub in &mut subs {
        jumps += check_stream(sub, &a.did, &head).await;
    }

    // wait until retention has caught up with the checkpoints
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let now = ordinals(&store, &log).await;
        if now.len() <= 2 {
            assert!(now.first() > before.first(), "the head was pruned");
            break;
        }
        assert!(Instant::now() < deadline, "retention never caught up: {} segments left", now.len());
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    driver.await.unwrap();
    eprintln!(
        "4 subscribers backfilled across pruning; {jumps} OutdatedCursor jumps; segments {} -> {:?}",
        before.len(),
        ordinals(&store, &log).await
    );

    // history before the floor is gone: OutdatedCursor first, then the rest
    let mut late = s.subscribe(Some(0)).await;
    let first = late.next(FH_TIMEOUT).await.expect("a frame");
    assert_eq!((first.kind(), first.str("name")), ("#info", Some("OutdatedCursor")));
    assert!(vlsync_firehose::log::retained_floor(&store).await.unwrap() > 0);
    // state is untouched by log retention
    for p in [&posts[0], &posts[59], posts.last().unwrap()] {
        s.get_record(&a.did, p.collection(), p.rkey()).await.ok();
    }
    s.post(&a, "after pruning").await;
}

async fn node(id: &str, store: &Arc<dyn object_store::ObjectStore>) -> TestServer {
    node_with(id, store, fast(), 64 << 20).await
}

async fn node_with(
    id: &str,
    store: &Arc<dyn object_store::ObjectStore>,
    retention: Option<vlpds::retention::Config>,
    ring_bytes: usize,
) -> TestServer {
    cluster_node(id, store.clone(), 8, |c| {
        c.log_retention = retention;
        c.firehose_ring_bytes = ring_bytes;
    })
    .await
}

/// Waits until `log` holds exactly `want` (a dead log retired to its fence).
async fn wait_for_objects(store: &vlsync_store::store::Store, log: &str, want: &[u64]) {
    let r = eventually(Duration::from_secs(15), || async { (ordinals(store, log).await == want).then_some(()) }).await;
    assert!(r.is_some(), "log {log}: {:?}, want {want:?}", ordinals(store, log).await);
}

/// Node `a` leaves (graceful: hands its shards to `b`, fences its log). Once
/// `b` has opened them, `b` (owner of the lowest shard) prunes `a`'s dead
/// log down to its fence, deletes its report, and keeps serving a's repos;
/// the firehose from 0 says OutdatedCursor and then runs gap-free.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn dead_log_pruned_after_takeover() {
    let store: Arc<dyn object_store::ObjectStore> = Arc::new(object_store::memory::InMemory::new());
    let a = node("ret-a", &store).await;
    let accounts: Vec<TestAccount> = futures::future::join_all((0..6).map(|_| a.create_account("rd"))).await;
    let mut posts = Vec::new();
    for (i, acct) in accounts.iter().enumerate() {
        posts.push((acct.did.clone(), a.post(acct, &format!("on a {i}")).await));
    }
    let b = node("ret-b", &store).await;
    let a_log = a.app.log.log_id.to_string();
    let vs = b.app.store.clone();
    vlpds::server::shutdown(&a.app).await;
    wait_until("b takes a's shards", Duration::from_secs(15), || owned(&b) >= 8).await;
    let (fence, fenced) = vlsync_firehose::log::first_free(&vs, &a_log).await.unwrap();
    assert!(fenced, "a fenced its own log on shutdown");
    wait_for_objects(&vs, &a_log, &[fence]).await;
    let reports = vlsync_firehose::log::read_reports(&vs).await.unwrap();
    assert!(!reports.contains_key(&a_log), "a's report went with its log");
    assert!(reports.get(b.app.log.log_id.as_ref()).is_some_and(|r| r.opened.len() == 8));
    // b serves everything a wrote, and keeps writing
    for (did, p) in &posts {
        b.get_record(did, p.collection(), p.rkey()).await.ok();
    }
    let last = b.post(&accounts[0], "on b").await;
    let head = Cid::parse(last.commit_cid.as_deref().unwrap()).unwrap();
    let mut sub = b.subscribe(Some(0)).await;
    assert_eq!(check_stream(&mut sub, &accounts[0].did, &head).await, 1, "one OutdatedCursor, then gap-free");
}

/// A node restarts (same node id) after its previous log was pruned: it
/// fences the fence-only log at the same place, replays nothing it lacks,
/// and serves the old records; the old log's report and segments go.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn restart_after_pruning() {
    let store: Arc<dyn object_store::ObjectStore> = Arc::new(object_store::memory::InMemory::new());
    let first = node("ret-r", &store).await;
    let acct = first.create_account("rr").await;
    let mut posts = Vec::new();
    for i in 0..20 {
        posts.push(first.post(&acct, &format!("before restart {i}")).await);
    }
    let old_log = first.app.log.log_id.to_string();
    let vs = first.app.store.clone();
    first.app.log.checkpoint_all().await;
    // pruned while alive: all but the newest durable segment
    let pruned =
        eventually(Duration::from_secs(10), || async { (ordinals(&vs, &old_log).await.len() <= 1).then_some(()) })
            .await;
    assert!(pruned.is_some(), "own log never pruned: {:?}", ordinals(&vs, &old_log).await);
    vlpds::server::shutdown(&first.app).await;
    let second = node("ret-r", &store).await;
    assert_ne!(second.app.log.log_id.as_ref(), old_log.as_str());
    assert_eq!(second.app.partitions.owned().len(), 8);
    for p in &posts {
        second.get_record(&acct.did, p.collection(), p.rkey()).await.ok();
    }
    second.post(&acct, "after restart").await;
    let (fence, fenced) = vlsync_firehose::log::first_free(&vs, &old_log).await.unwrap();
    assert!(fenced);
    wait_for_objects(&vs, &old_log, &[fence]).await;
}

/// With --fence-retention past, a dead log goes entirely: `a` leaves, `b`
/// takes its shards and prunes a's log down to its fence and then the
/// fence, so `log/` no longer lists it. Then `b` leaves too and `c` takes
/// every shard: their histories still name a's log, and replay over the
/// vanished log reads nothing (it was all applied and flushed by `b`'s
/// opens). Every record reads back.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn fence_deleted_then_takeover_replays() {
    let store: Arc<dyn object_store::ObjectStore> = Arc::new(object_store::memory::InMemory::new());
    let no_fences = || fast().map(|c| vlpds::retention::Config { fence_retention: Some(Duration::ZERO), ..c });
    let a = node_with("retf-a", &store, no_fences(), 64 << 20).await;
    let accounts: Vec<TestAccount> = futures::future::join_all((0..6).map(|_| a.create_account("rf"))).await;
    let mut posts = Vec::new();
    for (i, acct) in accounts.iter().enumerate() {
        posts.push((acct.did.clone(), a.post(acct, &format!("on a {i}")).await));
    }
    let b = node_with("retf-b", &store, no_fences(), 64 << 20).await;
    let a_log = a.app.log.log_id.to_string();
    let vs = b.app.store.clone();
    vlpds::server::shutdown(&a.app).await;
    wait_until("b takes a's shards", Duration::from_secs(15), || owned(&b) >= 8).await;
    wait_for_objects(&vs, &a_log, &[]).await;
    assert!(!vlsync_firehose::backfill::list_logs(&vs).await.unwrap().contains(&a_log), "a's log left log/");
    for (i, acct) in accounts.iter().enumerate() {
        posts.push((acct.did.clone(), b.post(acct, &format!("on b {i}")).await));
    }
    let c = node_with("retf-c", &store, no_fences(), 64 << 20).await;
    vlpds::server::shutdown(&b.app).await;
    wait_until("c takes b's shards", Duration::from_secs(15), || owned(&c) >= 8).await;
    for (did, p) in &posts {
        c.get_record(did, p.collection(), p.rkey()).await.ok();
    }
    c.post(&accounts[0], "on c").await;
}

/// Deletes a log's head the moment a reader GETs a given ordinal of it: a
/// retention pass landing between a backfill seek's LIST (which found that
/// ordinal lowest) and its header read. It raises the retained floor to the
/// last seq it deletes first, as retention does. Log reads can also be
/// slowed down (object-store latency widens every LIST-then-GET window).
#[derive(Debug, Default)]
struct PruneRace {
    inner: Option<Arc<dyn object_store::ObjectStore>>,
    armed: parking_lot::Mutex<Vec<Prune>>,
    fired: std::sync::atomic::AtomicUsize,
    log_get_delay: Duration,
}

#[derive(Debug)]
struct Prune {
    /// the GET that triggers it
    trigger: Path,
    /// the log's prefix, and the ordinals below which it deletes
    log: Path,
    below: u64,
    /// a retention report raised to `floor` before deleting
    report: Path,
    floor: i64,
}

impl std::fmt::Display for PruneRace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PruneRace")
    }
}

impl PruneRace {
    fn new(log_get_delay: Duration) -> Arc<PruneRace> {
        Arc::new(PruneRace {
            inner: Some(Arc::new(object_store::memory::InMemory::new())),
            log_get_delay,
            ..Default::default()
        })
    }

    fn inner(&self) -> &Arc<dyn object_store::ObjectStore> {
        self.inner.as_ref().unwrap()
    }

    async fn prune(&self, p: Prune) -> object_store::Result<()> {
        use futures::StreamExt;
        use object_store::ObjectStoreExt;
        let rep = vlsync_firehose::log::Report { pruned_seq: p.floor, ..Default::default() };
        self.inner().put(&p.report, serde_json::to_vec(&rep).unwrap().into()).await?;
        let doomed: Vec<Path> = self
            .inner()
            .list(Some(&p.log))
            .filter_map(|m| async move {
                let m = m.ok()?;
                let ord: u64 = m.location.filename()?.strip_suffix(".seg")?.parse().ok()?;
                (ord < p.below).then_some(m.location)
            })
            .collect()
            .await;
        for d in doomed {
            self.inner().delete(&d).await?;
        }
        self.fired.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
}

#[async_trait::async_trait]
impl object_store::ObjectStore for PruneRace {
    async fn put_opts(
        &self,
        location: &Path,
        payload: object_store::PutPayload,
        opts: object_store::PutOptions,
    ) -> object_store::Result<object_store::PutResult> {
        self.inner().put_opts(location, payload, opts).await
    }
    async fn put_multipart_opts(
        &self,
        location: &Path,
        opts: object_store::PutMultipartOptions,
    ) -> object_store::Result<Box<dyn object_store::MultipartUpload>> {
        self.inner().put_multipart_opts(location, opts).await
    }
    async fn get_opts(
        &self,
        location: &Path,
        options: object_store::GetOptions,
    ) -> object_store::Result<object_store::GetResult> {
        let hit = {
            let mut armed = self.armed.lock();
            armed.iter().position(|a| a.trigger == *location).map(|i| armed.remove(i))
        };
        if let Some(p) = hit {
            self.prune(p).await?;
        }
        if !self.log_get_delay.is_zero() && location.as_ref().contains("/log/") {
            tokio::time::sleep(self.log_get_delay).await;
        }
        self.inner().get_opts(location, options).await
    }
    fn delete_stream(
        &self,
        locations: futures::stream::BoxStream<'static, object_store::Result<Path>>,
    ) -> futures::stream::BoxStream<'static, object_store::Result<Path>> {
        self.inner().delete_stream(locations)
    }
    fn list(
        &self,
        prefix: Option<&Path>,
    ) -> futures::stream::BoxStream<'static, object_store::Result<object_store::ObjectMeta>> {
        self.inner().list(prefix)
    }
    async fn list_with_delimiter(&self, prefix: Option<&Path>) -> object_store::Result<object_store::ListResult> {
        self.inner().list_with_delimiter(prefix).await
    }
    async fn copy_opts(&self, from: &Path, to: &Path, options: object_store::CopyOptions) -> object_store::Result<()> {
        self.inner().copy_opts(from, to, options).await
    }
}

/// Firehose frames from `cursor` up to `did`'s commit `head`.
async fn frames_to(s: &TestServer, cursor: i64, did: &str, head: &Cid) -> Vec<Frame> {
    let mut sub = s.subscribe(Some(cursor)).await;
    sub.until(Duration::from_secs(20), |fs| {
        fs.last().and_then(|f| f.commit()).is_some_and(|c| c.repo == did && c.commit == *head)
    })
    .await
}

/// A cursor inside the retention window must not get OutdatedCursor when a
/// log lying wholly below it is pruned while the backfill seeks it: the seek
/// LISTs the log's lowest ordinal, retention deletes it before the header
/// read, and the reader returns `Pruned`. The retained floor is still below
/// the cursor (nothing past it was deleted), so that is not a failed
/// backfill.
///
/// Here a dead log (the node's previous incarnation, all of it below the
/// cursor) and the live log's head below the cursor are each deleted under
/// the seek, deterministically: the subscriber must get every event past its
/// cursor, in order, with no OutdatedCursor.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn pruning_below_the_cursor_under_a_seek_is_not_outdated() {
    let race = PruneRace::new(Duration::ZERO);
    let store: Arc<dyn object_store::ObjectStore> = race.clone();
    let spawn = |store: Arc<dyn object_store::ObjectStore>| {
        cluster_node("race", store, 4, |c| {
            c.firehose_ring_bytes = 2048;
            c.log_retention = None; // PruneRace is the only deleter
        })
    };
    // the previous incarnation: its log is dead (fenced) once it leaves
    let first = spawn(store.clone()).await;
    let acct = first.create_account("pr").await;
    for i in 0..20 {
        first.post(&acct, &format!("dead log {i} {}", "x".repeat(64))).await;
    }
    let dead = first.app.log.log_id.to_string();
    vlpds::server::shutdown(&first.app).await;
    let s = spawn(store.clone()).await;
    let live = s.app.log.log_id.to_string();
    assert_ne!(dead, live);
    let mut last = None;
    for i in 0..40 {
        last = Some(s.post(&acct, &format!("live log {i} {}", "y".repeat(64))).await);
    }
    let head = Cid::parse(last.unwrap().commit_cid.as_deref().unwrap()).unwrap();
    let all = frames_to(&s, 0, &acct.did, &head).await;
    assert!(all.iter().all(|f| f.kind() != "#info"), "nothing pruned yet");
    let seqs: Vec<i64> = all.iter().filter_map(|f| f.seq()).collect();
    let vs = s.app.store.clone();
    let (fence, fenced) = vlsync_firehose::log::first_free(&vs, &dead).await.unwrap();
    assert!(fenced);
    let vlsync_firehose::log::Head::Segment(h) = vlsync_firehose::log::read_head(&vs, &dead, fence - 1).await.unwrap()
    else {
        panic!("no segment before the fence")
    };
    let dead_last = h.last_seq;
    // a cursor past the whole dead log, 10 live events in (behind the ring)
    let cursor = *seqs.iter().filter(|&&q| q > dead_last).nth(10).unwrap();
    // the live log's segments wholly at or below the cursor
    let (mut below, mut live_floor) = (0, 0);
    while let vlsync_firehose::log::Head::Segment(h) = vlsync_firehose::log::read_head(&vs, &live, below).await.unwrap()
    {
        if h.last_seq > cursor {
            break;
        }
        live_floor = h.last_seq;
        below += 1;
    }
    assert!(below > 1, "the live log has segments below the cursor");
    let prune = |log: &str, below: u64, floor: i64| Prune {
        trigger: vlsync_firehose::log::segment_path(&vs, log, 0),
        log: Path::from(format!("{}/log/{log}", vs.prefix)),
        below,
        report: Path::from(format!("{}/retain/{log}-pruner", vs.prefix)),
        floor,
    };
    race.armed.lock().extend([prune(&dead, fence, dead_last), prune(&live, below, live_floor)]);

    let frames = frames_to(&s, cursor, &acct.did, &head).await;
    assert!(vlsync_firehose::log::retained_floor(&vs).await.unwrap() <= cursor);
    let kinds: Vec<&str> = frames.iter().map(|f| f.kind()).collect();
    assert!(!kinds.contains(&"#info"), "OutdatedCursor inside the window: {kinds:?}");
    assert_eq!(race.fired.load(std::sync::atomic::Ordering::SeqCst), 2, "both logs were pruned under the seek");
    let got: Vec<i64> = frames.iter().filter_map(|f| f.seq()).collect();
    let want: Vec<i64> = seqs.iter().copied().filter(|&q| q > cursor).collect();
    assert_eq!(got, want, "every event past the cursor, in order");
}

/// A node in its own runtime, so it can die like a process: every task,
/// socket and in-flight PUT of it goes at once (an in-process shutdown
/// leaves its HTTP server, and so its log streams to peers, running).
struct Proc {
    rt: Option<tokio::runtime::Runtime>,
    s: TestServer,
}

impl Proc {
    async fn spawn(
        id: &str,
        store: &Arc<dyn object_store::ObjectStore>,
        retention: Option<vlpds::retention::Config>,
    ) -> Proc {
        let (id, store) = (id.to_string(), store.clone());
        tokio::task::spawn_blocking(move || {
            let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(4).enable_all().build().unwrap();
            let s = rt.block_on(node_with(&id, &store, retention, 2048));
            Proc { rt: Some(rt), s }
        })
        .await
        .unwrap()
    }

    /// SIGTERM (a graceful shutdown first) or kill -9.
    async fn kill(mut self, graceful: bool) {
        let rt = self.rt.take().unwrap();
        if graceful {
            let app = self.s.app.clone();
            rt.spawn(async move { vlpds::server::shutdown(&app).await }).await.unwrap();
        }
        rt.shutdown_background();
    }
}

/// The soak's shape, shrunk: a 3 s window with passes every 20 ms deleting a
/// few objects each (so some log is nearly always being pruned), a ring too
/// small to serve any cursor, continuous writes, a node restarted over and
/// over (SIGTERM and kill -9 in turn; each incarnation's log goes dead and is
/// pruned to its fence) and shards split and merged, while probes subscribe
/// with cursors a quarter window old. Log GETs take 2 ms (object-store
/// latency is what opens the LIST-then-GET window the soak hit). None may get
/// OutdatedCursor, and each sees its events in seq order with every repo's
/// commits chained.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn cursors_inside_the_window_through_restarts_and_reshards() {
    const WINDOW: Duration = Duration::from_secs(3);
    // a probe's cursor age (the margin covers the probe's own backfill)
    const AGE: Duration = Duration::from_millis(750);
    let ret = Some(vlpds::retention::Config {
        window: WINDOW,
        interval: Duration::from_millis(20),
        max_deletes: 4,
        fence_retention: None,
    });
    let store: Arc<dyn object_store::ObjectStore> = PruneRace::new(Duration::from_millis(2));
    let a = node_with("win-a", &store, ret.clone(), 2048).await;
    let accts: Vec<TestAccount> = futures::future::join_all((0..6).map(|_| a.create_account("win"))).await;
    // each incarnation of b under a new node id: a restart under the same id
    // can lose a race with a peer deleting the dead incarnation's lease (a
    // startup error, retried by a process supervisor; not what this tests)
    let mut b = Some(Proc::spawn("win-b0", &store, ret.clone()).await);
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let writer = {
        let (url, accts, stop) = (a.url.clone(), accts.clone(), stop.clone());
        tokio::spawn(async move {
            let http = reqwest::Client::builder().timeout(Duration::from_secs(5)).build().unwrap();
            let (mut n, mut ok) = (0usize, 0usize);
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                let acct = &accts[n % accts.len()];
                let body = json!({"repo": acct.did, "collection": "app.bsky.feed.post", "record": post_record(&format!("w{n}"))});
                // moving shards and a dead peer's answer 503 for a moment: go on
                let r = http
                    .post(format!("{url}/xrpc/com.atproto.repo.createRecord"))
                    .bearer_auth(&acct.access)
                    .json(&body)
                    .send()
                    .await;
                ok += usize::from(r.is_ok_and(|r| r.status().is_success()));
                n += 1;
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            (n, ok)
        })
    };
    // probes against a, which stays up throughout
    let prober = {
        let (addr, stop, app) = (a.addr, stop.clone(), a.app.clone());
        tokio::spawn(async move {
            let (mut probes, mut events) = (0usize, 0usize);
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                let now = vlatproto::tid::now_micros();
                let cursor = vlsync_firehose::log::seq_floor(now - AGE.as_micros() as u64);
                let target = vlsync_firehose::log::seq_floor(now);
                let mut sub =
                    Sub::connect(&format!("ws://{addr}/xrpc/com.atproto.sync.subscribeRepos?cursor={cursor}")).await;
                let (frames, done) = sub
                    .try_until(Duration::from_secs(20), |fs| {
                        fs.last().is_some_and(|f| f.kind() == "#info" || f.seq().is_some_and(|q| q > target))
                    })
                    .await;
                assert!(
                    done,
                    "probe stuck at {:?} (target {target}, firehose at {}, closed {})",
                    frames.last().and_then(|f| f.seq()),
                    app.firehose.position(),
                    sub.closed
                );
                let mut last = cursor;
                let mut prev: std::collections::HashMap<String, String> = Default::default();
                for f in &frames {
                    if f.kind() == "#info" {
                        let floor = vlsync_firehose::log::retained_floor(&app.store).await.unwrap();
                        let age = Duration::from_micros(vlatproto::tid::now_micros() - (cursor >> 8) as u64);
                        panic!("OutdatedCursor for a cursor {AGE:?} old at connect, {age:?} now (window {WINDOW:?}); floor - cursor = {:?}", Duration::from_micros(((floor - cursor).max(0) >> 8) as u64));
                    }
                    let Some(seq) = f.seq() else { continue };
                    assert!(seq > last, "seq {seq} after {last}");
                    last = seq;
                    if let Some(c) = f.commit() {
                        if let (Some(p), Some(since)) = (prev.get(&c.repo), &c.since) {
                            assert_eq!(p, since, "chain break for {} at seq {seq}", c.repo);
                        }
                        prev.insert(c.repo.clone(), c.rev.clone());
                    }
                }
                probes += 1;
                events += frames.len();
                tokio::time::sleep(Duration::from_millis(30)).await;
            }
            (probes, events)
        })
    };
    // let the first segments age past the window
    tokio::time::sleep(WINDOW + Duration::from_millis(500)).await;
    let mut kids: Option<Vec<J>> = None;
    for round in 0..6 {
        // a reshard: split one of a's shards, or merge the last split's children back
        let r = match kids.take() {
            None => {
                let target = a.app.partitions.owned().first().expect("a owns a shard").id;
                a.xrpc.post("vlpds.admin.splitShard", &json!({"shard": target, "wait": true}), &Auth::Admin).await
            }
            Some(k) => {
                a.xrpc
                    .post(
                        "vlpds.admin.mergeShards",
                        &json!({"left": k[0]["id"], "right": k[1]["id"], "wait": true}),
                        &Auth::Admin,
                    )
                    .await
            }
        };
        if r.is_ok() {
            kids = r.ok()["op"]["children"].as_array().filter(|c| c.len() == 2).cloned();
        } else {
            eprintln!("round {round}: reshard refused: {}", r.text());
        }
        tokio::time::sleep(Duration::from_millis(700)).await;
        // restart b (SIGTERM, then kill -9): its log goes dead, a drains
        // and fences it, and retention prunes it once past the window
        b.take().unwrap().kill(round % 2 == 0).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        b = Some(Proc::spawn(&format!("win-b{}", round + 1), &store, ret.clone()).await);
        tokio::time::sleep(Duration::from_millis(1500)).await;
    }
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let (writes, acked) = writer.await.unwrap();
    let (probes, events) = prober.await.unwrap();
    b.take().unwrap().kill(true).await;
    let floor = vlsync_firehose::log::retained_floor(&a.app.store).await.unwrap();
    let retried =
        ["seek", "pruned"].map(|r| vlsync_firehose::metrics::FIREHOSE_BACKFILL_RETRIES.with_label_values(&[r]).get());
    eprintln!("{writes} writes ({acked} acked), {probes} probes ({events} frames), {retried:?} seeks/backfills overtaken by retention, retained floor {floor}");
    assert!(probes > 20 && floor > 0, "retention ran under the probes");
}
