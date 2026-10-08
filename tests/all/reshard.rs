//! Online shard split/merge (DESIGN.md "Online shard split/merge"):
//! in-process nodes sharing one in-memory object store split and merge
//! shards under write load, with the owner or driver "crashing" at each
//! phase (its object-store calls hang and its control plane stops, as if
//! the process died), concurrent with a rebalance, while a firehose
//! subscription and a listRepos enumeration span the layout change. Every
//! acked write must be readable afterwards and appear exactly once, in
//! order, on the firehose.

use crate::common::*;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use vlsync_store::slots::ShardId;

const SHARDS: u32 = 6;

/// A node's view of the shared store that can "die": every call made after
/// `kill` hangs forever (nothing it had in flight lands later either: those
/// calls already completed or hang too).
#[derive(Debug)]
pub struct Killable {
    inner: Arc<object_store::memory::InMemory>,
    dead: AtomicBool,
}

impl std::fmt::Display for Killable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Killable")
    }
}

impl Killable {
    fn kill(&self) {
        self.dead.store(true, Ordering::SeqCst);
    }

    async fn gate(&self) {
        if self.dead.load(Ordering::SeqCst) {
            futures::future::pending::<()>().await;
        }
    }
}

use object_store::path::Path;
use object_store::{
    GetOptions, GetResult, ListResult, MultipartUpload, ObjectMeta, PutMultipartOptions, PutOptions, PutPayload,
    PutResult,
};

#[async_trait::async_trait]
impl object_store::ObjectStore for Killable {
    async fn put_opts(
        &self,
        location: &Path,
        payload: PutPayload,
        opts: PutOptions,
    ) -> object_store::Result<PutResult> {
        self.gate().await;
        let r = self.inner.put_opts(location, payload, opts).await;
        self.gate().await;
        r
    }
    async fn put_multipart_opts(
        &self,
        location: &Path,
        opts: PutMultipartOptions,
    ) -> object_store::Result<Box<dyn MultipartUpload>> {
        self.gate().await;
        self.inner.put_multipart_opts(location, opts).await
    }
    async fn get_opts(&self, location: &Path, options: GetOptions) -> object_store::Result<GetResult> {
        self.gate().await;
        let r = self.inner.get_opts(location, options).await;
        self.gate().await;
        r
    }
    fn delete_stream(
        &self,
        locations: futures::stream::BoxStream<'static, object_store::Result<Path>>,
    ) -> futures::stream::BoxStream<'static, object_store::Result<Path>> {
        use futures::StreamExt;
        if self.dead.load(Ordering::SeqCst) {
            return futures::stream::pending().boxed();
        }
        self.inner.delete_stream(locations)
    }
    fn list(&self, prefix: Option<&Path>) -> futures::stream::BoxStream<'static, object_store::Result<ObjectMeta>> {
        use futures::StreamExt;
        if self.dead.load(Ordering::SeqCst) {
            return futures::stream::pending().boxed();
        }
        self.inner.list(prefix)
    }
    async fn list_with_delimiter(&self, prefix: Option<&Path>) -> object_store::Result<ListResult> {
        self.gate().await;
        self.inner.list_with_delimiter(prefix).await
    }
    async fn copy_opts(&self, from: &Path, to: &Path, options: object_store::CopyOptions) -> object_store::Result<()> {
        self.gate().await;
        self.inner.copy_opts(from, to, options).await
    }
}

pub struct Node {
    pub s: TestServer,
    pub store: Arc<Killable>,
}

impl Node {
    fn id(&self) -> String {
        cluster(&self.s).cfg.node_id.clone()
    }

    fn alive(&self) -> bool {
        !self.store.dead.load(Ordering::SeqCst)
    }
}

async fn node(id: &str, store: &Arc<object_store::memory::InMemory>) -> Node {
    node_with(id, store, |_| {}).await
}

async fn node_with(
    id: &str,
    store: &Arc<object_store::memory::InMemory>,
    f: impl FnOnce(&mut vlpds::server::Config),
) -> Node {
    let k = Arc::new(Killable { inner: store.clone(), dead: AtomicBool::new(false) });
    let (id, raw) = (id.to_string(), k.clone() as Arc<dyn object_store::ObjectStore>);
    let s = cluster_node(&id, raw, SHARDS, f).await;
    Node { s, store: k }
}

fn cluster(n: &TestServer) -> &vlpds::cluster::Cluster {
    n.app.cluster.as_deref().unwrap()
}

fn layout(n: &Node) -> Arc<vlsync_store::slots::Layout> {
    cluster(&n.s).layout()
}

fn owned(n: &Node) -> Vec<ShardId> {
    let mut v: Vec<ShardId> = n.s.app.partitions.owned().iter().map(|p| p.id).collect();
    v.sort();
    v
}

/// Until every live node routes by the same layout with no op in flight,
/// holding `want_version` or later, and its shards are each open on exactly
/// one live node. Returns that layout.
async fn settled(nodes: &[&Node], want_version: u64, timeout: Duration) -> Arc<vlsync_store::slots::Layout> {
    let deadline = Instant::now() + timeout;
    loop {
        let live: Vec<&&Node> = nodes.iter().filter(|n| n.alive()).collect();
        let l = layout(live[0]);
        let same = live.iter().all(|n| *layout(n) == *l);
        let mut seen = HashMap::new();
        let mut dup = false;
        for n in &live {
            for s in owned(n) {
                dup |= seen.insert(s, n.id()).is_some();
            }
        }
        let complete = !dup && l.ids().iter().all(|s| seen.contains_key(s)) && seen.len() == l.shards.len();
        if same && l.op.is_none() && l.version >= want_version && complete {
            return l;
        }
        assert!(
            Instant::now() < deadline,
            "never settled at v{want_version}+: layouts {:?}, owned {:?}",
            live.iter().map(|n| (n.id(), layout(n).version, layout(n).op.clone(), layout(n).ids())).collect::<Vec<_>>(),
            live.iter().map(|n| (n.id(), owned(n))).collect::<Vec<_>>()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Until the shards are spread over `n` nodes at fair share.
async fn balanced(nodes: &[&Node]) {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let l = settled(nodes, 1, Duration::from_secs(20)).await;
        let sizes: Vec<usize> = nodes.iter().filter(|n| n.alive()).map(|n| owned(n).len()).collect();
        let fair = l.shards.len().div_ceil(sizes.len());
        if sizes.iter().all(|s| *s >= 1 && *s <= fair) {
            return;
        }
        assert!(Instant::now() < deadline, "never balanced: {sizes:?}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// One acked write: repo, record uri, commit rev.
#[derive(Clone, Debug)]
struct Acked {
    did: String,
    uri: String,
    rev: String,
}

/// Writers (one per account, sequential creates) through the given nodes,
/// round-robin per attempt; failures (503 while a shard moves, a dead node)
/// are retried on the next node.
struct Load {
    stop: Arc<AtomicBool>,
    acked: Arc<parking_lot::Mutex<Vec<Acked>>>,
    failed: Arc<AtomicUsize>,
    /// Failed attempts by HTTP status (0 = no response / timed out).
    statuses: Arc<parking_lot::Mutex<HashMap<u16, usize>>>,
    /// Longest time an account went without an acked write (unavailability).
    gaps: Arc<parking_lot::Mutex<Vec<Duration>>>,
    handles: Vec<tokio::task::JoinHandle<()>>,
}

impl Load {
    fn start(urls: Vec<String>, accounts: &[TestAccount]) -> Load {
        let stop = Arc::new(AtomicBool::new(false));
        let acked = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let failed = Arc::new(AtomicUsize::new(0));
        let statuses = Arc::new(parking_lot::Mutex::new(HashMap::new()));
        let gaps = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let urls = Arc::new(parking_lot::Mutex::new(urls));
        let mut handles = Vec::new();
        for (i, acct) in accounts.iter().cloned().enumerate() {
            let (stop, acked, failed, gaps, urls, statuses) =
                (stop.clone(), acked.clone(), failed.clone(), gaps.clone(), urls.clone(), statuses.clone());
            handles.push(tokio::spawn(async move {
                // one client per node, reused (a client per attempt ran the
                // box out of ephemeral ports)
                let clients: Vec<(String, Xrpc)> = urls.lock().iter().map(|u| (u.clone(), Xrpc::new(u))).collect();
                let mut k = i;
                let mut last_ok = Instant::now();
                let mut worst = Duration::ZERO;
                while !stop.load(Ordering::Acquire) {
                    k += 1;
                    let (url, x) = &clients[k % clients.len()];
                    let body = json!({"repo": acct.did, "collection": "app.bsky.feed.post", "record": post_record(&format!("w{k}"))});
                    let r = tokio::time::timeout(Duration::from_secs(5), x.try_send(x.http.post(format!("{url}/xrpc/com.atproto.repo.createRecord")).json(&body).bearer_auth(&acct.access))).await;
                    match r {
                        Ok(Ok(r)) if r.is_ok() => {
                            let j = r.ok();
                            acked.lock().push(Acked {
                                did: acct.did.clone(),
                                uri: j["uri"].as_str().unwrap().to_string(),
                                rev: j["commit"]["rev"].as_str().unwrap().to_string(),
                            });
                            worst = worst.max(last_ok.elapsed());
                            last_ok = Instant::now();
                        }
                        other => {
                            let code = match &other {
                                Ok(Ok(r)) => r.status,
                                _ => 0,
                            };
                            *statuses.lock().entry(code).or_default() += 1;
                            failed.fetch_add(1, Ordering::Relaxed);
                            tokio::time::sleep(Duration::from_millis(20)).await;
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                gaps.lock().push(worst);
            }));
        }
        Load { stop, acked, failed, statuses, gaps, handles }
    }

    fn acked(&self) -> usize {
        self.acked.lock().len()
    }

    /// Waits for `n` more acked writes.
    async fn progress(&self, n: usize) {
        let want = self.acked() + n;
        let deadline = Instant::now() + Duration::from_secs(30);
        while self.acked() < want {
            assert!(
                Instant::now() < deadline,
                "writes stalled at {} acked ({} failed)",
                self.acked(),
                self.failed.load(Ordering::Relaxed)
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    async fn stop(self) -> (Vec<Acked>, usize, Duration) {
        self.stop.store(true, Ordering::Release);
        for h in self.handles {
            h.await.unwrap();
        }
        let statuses = self.statuses.lock().clone();
        eprintln!("failed attempts by status: {statuses:?}");
        assert!(!statuses.contains_key(&500), "a write failed with 500 (not retryable): {statuses:?}");
        let gaps = self.gaps.lock().iter().copied().max().unwrap_or_default();
        let acked = self.acked.lock().clone();
        (acked, self.failed.load(Ordering::Relaxed), gaps)
    }
}

/// Every acked record reads back through `n` (forwarded to its owner). A
/// 503 (a node whose routing hasn't caught up with a move yet) is retried,
/// as clients do.
async fn verify_readable(n: &TestServer, acked: &[Acked]) {
    use futures::StreamExt;
    futures::stream::iter(acked)
        .for_each_concurrent(16, |a| async move {
            let rkey = a.uri.rsplit('/').next().unwrap();
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                let r = n.get_record(&a.did, "app.bsky.feed.post", rkey).await;
                if r.status == 503 && Instant::now() < deadline {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
                if !r.is_ok() {
                    diagnose(n, a).await;
                }
                assert!(r.is_ok(), "acked record {} lost: {r:?}", a.uri);
                break;
            }
        })
        .await;
}

/// [`verify_readable`] through each of `nodes`, concurrently.
async fn verify_readable_on(nodes: &[&Node], acked: &[Acked]) {
    futures::future::join_all(nodes.iter().map(|n| verify_readable(&n.s, acked))).await;
}

/// On a failed read-back: where the record is. This node's routing and open
/// shards (record, head, L0 view ids that repeat), then every shard DB in the
/// bucket read directly. A record in the shard that routes it but not in its
/// open DB was lost by that shard's state, not misrouted.
async fn diagnose(n: &TestServer, a: &Acked) {
    let path = a.uri.splitn(4, '/').nth(3).unwrap().to_string();
    let rk = vlpds::state::record_key(&a.did, 0, &path);
    let l = n.app.partitions.layout();
    eprintln!(
        "DIAG {} slot {} rev {} layout v{} routes to shard {} of {:?}",
        a.uri,
        vlsync_store::slots::slot_of(&a.did),
        a.rev,
        l.version,
        l.shard_of(&a.did),
        l.ids()
    );
    for p in n.app.partitions.owned() {
        let rec = p.db.get(&rk).await.map(|v| v.is_some());
        let head = p.db.get(vlpds::state::head_key(&a.did)).await.map(|v| v.is_some());
        let m = p.db.manifest();
        let ids: Vec<_> = m.l0().iter().map(|v| v.id).collect();
        let repeats = ids.len() - ids.iter().collect::<HashSet<_>>().len();
        eprintln!(
            "DIAG open shard {}: record {rec:?} head {head:?}; L0 {} ({repeats} repeated view ids), {} sorted runs",
            p.id,
            ids.len(),
            m.compacted().len()
        );
    }
    for id in (0..l.next_id.0).map(ShardId) {
        let path = vlpds::partition::db_path(&n.app.store, id);
        let Ok(r) = slatedb::DbReader::builder(path.clone(), n.app.store.raw.clone()).build().await else { continue };
        if let Ok(Some(_)) = r.get(&rk).await {
            eprintln!("DIAG {path} holds the record");
        }
        let _ = r.close().await;
    }
}

/// The firehose from `sub` holds every acked commit exactly once, in seq
/// order, each repo's commits chained (`since` = the previous rev).
async fn verify_firehose(sub: &mut Sub, acked: &[Acked]) {
    let want: HashSet<(String, String)> = acked.iter().map(|a| (a.did.clone(), a.rev.clone())).collect();
    let dids: HashSet<&str> = acked.iter().map(|a| a.did.as_str()).collect();
    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut last_seq = 0i64;
    let mut prev_rev: HashMap<String, String> = HashMap::new();
    let deadline = Instant::now() + Duration::from_secs(60);
    while !want.is_subset(&seen) {
        let left = deadline.saturating_duration_since(Instant::now());
        let Some(f) = sub.next(left).await else {
            let missing: Vec<_> = want.difference(&seen).take(5).collect();
            panic!(
                "firehose ended or timed out: {} of {} acked commits seen; missing e.g. {missing:?}",
                want.intersection(&seen).count(),
                want.len()
            );
        };
        let Some(c) = f.commit() else { continue };
        assert!(c.seq > last_seq, "seqs out of order: {} after {last_seq}", c.seq);
        last_seq = c.seq;
        if !dids.contains(c.repo.as_str()) {
            continue;
        }
        if let (Some(prev), Some(since)) = (prev_rev.get(&c.repo), &c.since) {
            assert_eq!(prev, since, "chain break for {} at seq {}", c.repo, c.seq);
        }
        prev_rev.insert(c.repo.clone(), c.rev.clone());
        assert!(seen.insert((c.repo.clone(), c.rev.clone())), "duplicate commit {} {}", c.repo, c.rev);
    }
}

async fn accounts(n: &TestServer, k: usize) -> Vec<TestAccount> {
    futures::future::join_all((0..k).map(|_| n.create_account("rs"))).await
}

async fn admin(n: &TestServer, nsid: &str, body: J) -> J {
    n.xrpc.post(nsid, &body, &Auth::Admin).await.ok()
}

fn children(r: &J) -> Vec<ShardId> {
    r["op"]["children"].as_array().unwrap().iter().map(|c| ShardId(c["id"].as_u64().unwrap() as u32)).collect()
}

/// A split asked of `n` and waited for (`body` adds e.g. "at"); its children.
async fn split(n: &TestServer, shard: ShardId, body: J) -> Vec<ShardId> {
    let mut body = body;
    body["shard"] = json!(shard);
    body["wait"] = json!(true);
    let r = admin(n, "vlpds.admin.splitShard", body).await;
    assert_eq!(r["done"], json!(true), "{r}");
    children(&r)
}

/// A merge asked of `n` and waited for; the merged shard.
async fn merge(n: &TestServer, left: ShardId, right: ShardId) -> ShardId {
    let r = admin(n, "vlpds.admin.mergeShards", json!({"left": left, "right": right, "wait": true})).await;
    assert_eq!(r["done"], json!(true), "{r}");
    children(&r)[0]
}

/// Two adjacent shards of `l` held by different nodes.
fn cross_pair(l: &vlsync_store::slots::Layout, nodes: &[&Node]) -> (ShardId, ShardId) {
    let owner = |s: ShardId| nodes.iter().position(|n| owned(n).contains(&s));
    let pair = l.shards.windows(2).find(|w| owner(w[0].id) != owner(w[1].id)).expect("adjacent shards on two nodes");
    (pair[0].id, pair[1].id)
}

/// Splits and merges under write load across three nodes: a split of one
/// node's shard, a merge of its two children back, and a merge of two
/// shards held by different nodes. Writes keep flowing (only the moving
/// slots see a short 503 window), every acked write reads back from every
/// node and shows up exactly once, in order, on firehoses subscribed before
/// the change (live) and replayed after it (backfill), and every node routes
/// by the same layout.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn split_and_merge_under_write_load() {
    let store = Arc::new(object_store::memory::InMemory::new());
    let a = node("rsl-a", &store).await;
    let accts = accounts(&a.s, 9).await;
    let b = node("rsl-b", &store).await;
    let c = node("rsl-c", &store).await;
    balanced(&[&a, &b, &c]).await;
    let cursor = a.s.settled_now().await;
    let mut live = a.s.subscribe(Some(cursor)).await;
    let load = Load::start(vec![a.s.url.clone(), b.s.url.clone(), c.s.url.clone()], &accts);
    load.progress(30).await;

    // split a shard b owns, asked of a (the owner drives it)
    let l1 = layout(&a);
    let target = *owned(&b).first().unwrap();
    let kids = split(&a.s, target, json!({})).await;
    let l2 = settled(&[&a, &b, &c], l1.version + 1, Duration::from_secs(20)).await;
    assert!(!l2.contains(target) && kids.iter().all(|k| l2.contains(*k)), "{l2:?}");
    load.progress(30).await;

    // merge the two children back (one node holds both after the split)
    merge(&b.s, kids[0], kids[1]).await;
    let l3 = settled(&[&a, &b, &c], l2.version + 1, Duration::from_secs(20)).await;
    load.progress(30).await;

    // merge two adjacent shards held by different nodes
    let (x, y) = cross_pair(&l3, &[&a, &b, &c]);
    merge(&c.s, x, y).await;
    let l4 = settled(&[&a, &b, &c], l3.version + 1, Duration::from_secs(20)).await;
    assert_eq!(l4.shards.len(), SHARDS as usize - 1);
    load.progress(30).await;
    let (acked, failed, gap) = load.stop().await;
    eprintln!("{} acked, {failed} failed attempts, longest per-account gap {gap:?}", acked.len());
    assert!(gap < Duration::from_secs(5), "writes unavailable for {gap:?}");
    verify_readable_on(&[&a, &b, &c], &acked).await;
    verify_firehose(&mut live, &acked).await;
    let mut replay = c.s.subscribe(Some(cursor)).await;
    verify_firehose(&mut replay, &acked).await;
}

/// A single node splits and merges its own shards (no peers).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn single_node_split_and_merge() {
    let s = TestServer::spawn().await;
    let accts = accounts(&s, 6).await;
    let mut refs = Vec::new();
    for a in &accts {
        refs.push((a.did.clone(), s.post(a, "before").await));
    }
    let l = cluster(&s).layout();
    let kids = split(&s, l.shards[0].id, json!({"at": 1000})).await;
    assert_eq!(cluster(&s).layout().shards[0].hi, 1000);
    merge(&s, kids[1], l.shards[1].id).await;
    for a in &accts {
        refs.push((a.did.clone(), s.post(a, "after").await));
    }
    for (did, r) in &refs {
        assert!(s.get_record(did, "app.bsky.feed.post", r.rkey()).await.is_ok());
    }
    let l = cluster(&s).layout();
    assert_eq!((l.version, l.shards.len()), (3, 8));
    let ids: Vec<ShardId> = s.app.partitions.owned().iter().map(|p| p.id).collect();
    assert_eq!(ids.len(), 8, "every shard of the new layout open: {ids:?}");
    // bad requests are refused without changing anything
    let r = s.xrpc.post("vlpds.admin.splitShard", &json!({"shard": 999}), &Auth::Admin).await;
    r.err(400, "InvalidRequest");
    let r = s.xrpc.post("vlpds.admin.mergeShards", &json!({"left": kids[0], "right": 7}), &Auth::Admin).await;
    r.err(400, "InvalidRequest");
    s.xrpc.post("vlpds.admin.splitShard", &json!({"shard": kids[0]}), &Auth::None).await.err_status(401);
}

/// The owner (and driver) of a split's parent crashes at `phase`; the
/// survivors take over (fence + replay its log, adopt the driver role) and
/// finish the split. Every acked write survives.
async fn crash_mid_split(phase: &'static str) {
    let store = Arc::new(object_store::memory::InMemory::new());
    let tag = format!("rsc-{phase}");
    let a = node(&format!("{tag}-a"), &store).await;
    let accts = accounts(&a.s, 9).await;
    let b = node(&format!("{tag}-b"), &store).await;
    let c = node(&format!("{tag}-c"), &store).await;
    balanced(&[&a, &b, &c]).await;
    let cursor = a.s.settled_now().await;
    let mut live = a.s.subscribe(Some(cursor)).await;
    let load = Load::start(vec![a.s.url.clone(), c.s.url.clone()], &accts);
    load.progress(30).await;

    // b owns the parent, so b drives; b dies at `phase`
    let l1 = layout(&a);
    let target = *owned(&b).first().unwrap();
    let fired = Arc::new(AtomicBool::new(false));
    {
        let (fired, store, app) = (fired.clone(), b.store.clone(), b.s.app.clone());
        vlpds::reshard::set_crash_hook(
            &b.id(),
            Some(Arc::new(move |p: &str| {
                if p != phase || fired.swap(true, Ordering::SeqCst) {
                    return false;
                }
                store.kill();
                app.node.halt();
                true
            })),
        );
    }
    // "planned" fires in the planner: ask b itself (it returns at once)
    let asked = if phase == "planned" { &b } else { &a };
    let kids = children(&admin(&asked.s, "vlpds.admin.splitShard", json!({"shard": target, "wait": false})).await);
    let t = Instant::now();
    while !fired.load(Ordering::SeqCst) {
        assert!(t.elapsed() < Duration::from_secs(20), "phase {phase} never reached");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let t = Instant::now();
    let l2 = settled(&[&a, &b, &c], l1.version + 1, Duration::from_secs(30)).await;
    eprintln!("{phase}: split finished {:?} after the driver died", t.elapsed());
    assert!(!l2.contains(target) && kids.iter().all(|k| l2.contains(*k)), "{l2:?}");
    // the plan allocated the children's ids once: resuming it (a new
    // driver) neither re-allocates nor reuses any
    assert_eq!(kids, vec![l1.next_id, ShardId(l1.next_id.0 + 1)]);
    assert_eq!(l2.next_id.0, l1.next_id.0 + 2);
    load.progress(30).await;
    let (acked, failed, gap) = load.stop().await;
    eprintln!("{phase}: {} acked, {failed} failed attempts, longest gap {gap:?}", acked.len());
    vlpds::reshard::set_crash_hook(&b.id(), None);
    verify_readable_on(&[&a, &c], &acked).await;
    verify_firehose(&mut live, &acked).await;
    let fenced = cluster(&a.s).fenced_logs().len() + cluster(&c.s).fenced_logs().len();
    assert!(fenced > 0, "the dead node's log was fenced");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn crash_after_plan() {
    crash_mid_split("planned").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn crash_after_parent_closed() {
    crash_mid_split("closed").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn crash_after_freeze() {
    crash_mid_split("frozen").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn crash_after_clone() {
    crash_mid_split("cloned").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn crash_after_children_assigned() {
    crash_mid_split("children").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn crash_after_flip() {
    crash_mid_split("flipped").await;
}

/// An op stuck before its flip (its driver keeps failing after the clone)
/// is aborted: the parent unfreezes, is served again under the old layout,
/// and a later split of it succeeds.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn abort_before_flip() {
    let store = Arc::new(object_store::memory::InMemory::new());
    let a = node("rsab-a", &store).await;
    let accts = accounts(&a.s, 6).await;
    let b = node("rsab-b", &store).await;
    balanced(&[&a, &b]).await;
    let load = Load::start(vec![a.s.url.clone(), b.s.url.clone()], &accts);
    load.progress(20).await;
    let l1 = layout(&a);
    let target = *owned(&b).first().unwrap();
    let stuck = Arc::new(AtomicUsize::new(0));
    {
        let stuck = stuck.clone();
        vlpds::reshard::set_crash_hook(
            &b.id(),
            Some(Arc::new(move |p: &str| p == "cloned" && stuck.fetch_add(1, Ordering::SeqCst) < 1_000_000)),
        );
    }
    admin(&a.s, "vlpds.admin.splitShard", json!({"shard": target})).await;
    let t = Instant::now();
    while stuck.load(Ordering::SeqCst) < 3 {
        assert!(t.elapsed() < Duration::from_secs(20), "driver never got stuck after cloning");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let r = admin(&a.s, "vlpds.admin.abortReshard", json!({})).await;
    assert_eq!(r["aborted"]["parents"], json!([target]), "{r}");
    vlpds::reshard::set_crash_hook(&b.id(), None);
    let l = settled(&[&a, &b], 1, Duration::from_secs(20)).await;
    assert_eq!((l.version, l.ids()), (l1.version, l1.ids()), "nothing flipped");
    let owner = [&a, &b].into_iter().find(|n| owned(n).contains(&target)).expect("the parent is served again");
    assert!(cluster(&owner.s).assignment(target).unwrap().frozen.is_none());
    load.progress(20).await;
    // and it can be split for real now
    split(&a.s, target, json!({})).await;
    settled(&[&a, &b], l1.version + 1, Duration::from_secs(20)).await;
    load.progress(20).await;
    let (acked, ..) = load.stop().await;
    verify_readable(&a.s, &acked).await;
}

/// A node joins (and peers hand shards back to it) while a merge across two
/// nodes is in flight: everything converges and no acked write is lost.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn reshard_concurrent_with_rebalance() {
    let store = Arc::new(object_store::memory::InMemory::new());
    let a = node("rsrb-a", &store).await;
    let accts = accounts(&a.s, 9).await;
    let b = node("rsrb-b", &store).await;
    balanced(&[&a, &b]).await;
    let cursor = a.s.settled_now().await;
    let load = Load::start(vec![a.s.url.clone(), b.s.url.clone()], &accts);
    load.progress(20).await;
    let l1 = layout(&a);
    let (x, y) = cross_pair(&l1, &[&a, &b]);
    let split_of = *owned(&b).last().unwrap();
    let (c, _) = tokio::join!(node("rsrb-c", &store), merge(&a.s, x, y));
    // and a split while the joiner is still taking its share
    if layout(&a).contains(split_of) {
        split(&c.s, split_of, json!({})).await;
    }
    balanced(&[&a, &b, &c]).await;
    let l = settled(&[&a, &b, &c], l1.version + 1, Duration::from_secs(20)).await;
    assert!(!owned(&c).is_empty(), "the joiner got a share: {:?}", l.ids());
    load.progress(30).await;
    let (acked, ..) = load.stop().await;
    verify_readable_on(&[&a, &b, &c], &acked).await;
    let mut sub = c.s.subscribe(Some(cursor)).await;
    verify_firehose(&mut sub, &acked).await;
}

/// listRepos pages in (slot, DID) order with a layout-independent cursor:
/// an enumeration spanning a split and a merge lists every repo exactly once.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn list_repos_across_layout_changes() {
    let store = Arc::new(object_store::memory::InMemory::new());
    let a = node("rslr-a", &store).await;
    let b = node("rslr-b", &store).await;
    balanced(&[&a, &b]).await;
    let mut want: HashSet<String> = HashSet::new();
    for n in [&a, &b] {
        for acct in accounts(&n.s, 15).await {
            want.insert(acct.did);
        }
    }
    let mut got: Vec<String> = Vec::new();
    let mut cursor: Option<String> = None;
    let mut page = 0;
    loop {
        let mut q = vec![("limit", "4".to_string())];
        if let Some(c) = &cursor {
            q.push(("cursor", c.clone()));
        }
        let via = [&a, &b][page % 2];
        let r = via.s.xrpc.get_multi("com.atproto.sync.listRepos", &q, &Auth::None).await.ok();
        got.extend(r["repos"].as_array().unwrap().iter().map(|x| x["did"].as_str().unwrap().to_string()));
        page += 1;
        let l = layout(&a);
        if page == 2 {
            // split the shard the cursor is in
            let slot = r["cursor"].as_str().unwrap().split(':').next().unwrap().parse::<u16>().unwrap();
            split(&a.s, l.shard_of_slot(slot), json!({})).await;
            settled(&[&a, &b], l.version + 1, Duration::from_secs(20)).await;
        }
        if page == 4 {
            // merge the shard the cursor is in with the next one
            let slot = r["cursor"].as_str().unwrap().split(':').next().unwrap().parse::<u16>().unwrap();
            let i = l.index_of_slot(slot).min(l.shards.len() - 2);
            merge(&b.s, l.shards[i].id, l.shards[i + 1].id).await;
            settled(&[&a, &b], l.version + 1, Duration::from_secs(20)).await;
        }
        match r["cursor"].as_str() {
            Some(c) => cursor = Some(c.to_string()),
            None => break,
        }
        assert!(page < 100);
    }
    let set: HashSet<String> = got.iter().cloned().collect();
    assert_eq!(set.len(), got.len(), "a repo listed twice");
    assert!(want.is_subset(&set), "missing {:?}", want.difference(&set).collect::<Vec<_>>());
    let order: Vec<(u16, String)> = got.iter().map(|d| (vlsync_store::slots::slot_of(d), d.clone())).collect();
    assert!(order.windows(2).all(|w| w[0] < w[1]), "pages in (slot, DID) order");
}

/// The policy hook (off by default) splits a shard applying more writes per
/// second than its threshold, on its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn policy_splits_a_hot_shard() {
    let store = Arc::new(object_store::memory::InMemory::new());
    let n = node_with("rspol", &store, |c| {
        c.reshard_policy = vlpds::reshard::Policy { split_bytes: None, split_writes_per_sec: Some(20.0) }
    })
    .await;
    let s = &n.s;
    let acct = s.create_account("pol").await;
    let hot = s.app.partitions.shard_of(&acct.did);
    let t = Instant::now();
    let mut n = 0;
    // a write that finds its shard frozen for the split (ShardMoved) is
    // resent by the node until the children open: the client never sees it
    let post = |text: String| {
        let body = json!({"repo": acct.did, "collection": "app.bsky.feed.post", "record": post_record(&text)});
        let (x, auth) = (&s.xrpc, acct.auth());
        async move {
            let r = x.post("com.atproto.repo.createRecord", &body, &auth).await;
            assert!(r.is_ok(), "{r:?}");
        }
    };
    while cluster(s).layout().contains(hot) {
        assert!(t.elapsed() < Duration::from_secs(20), "the hot shard never split");
        post(format!("hot {n}")).await;
        n += 1;
    }
    let l = cluster(s).layout();
    assert_eq!((l.version, l.shards.len()), (2, SHARDS as usize + 1));
    // and it stops after one: the rate limit holds it for a minute
    for i in 0..50 {
        post(format!("after {i}")).await;
    }
    assert_eq!(cluster(s).layout().version, 2);
}

/// Splits and merges back to back under write load (a split, a merge of its
/// halves, a merge across nodes, a split of that), every acked write read
/// back after each op. Merging a split's halves while they still held the
/// parent's L0 SSTs lost one half's keys at the merged shard's first
/// compaction (SlateDB repeated the shared L0 view id; DESIGN.md "Patched
/// SlateDB"): without the fix this failed 9 runs in 10 (the deterministic
/// check is partition.rs `merging_a_splits_halves_keeps_their_shared_l0s`).
/// `RESHARD_CYCLES=6` for a longer run.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn repeated_splits_and_merges_under_write_load() {
    let cycles: usize = std::env::var("RESHARD_CYCLES").ok().and_then(|v| v.parse().ok()).unwrap_or(2);
    let store = Arc::new(object_store::memory::InMemory::new());
    let a = node("rss-a", &store).await;
    let accts = accounts(&a.s, 18).await;
    let b = node("rss-b", &store).await;
    let c = node("rss-c", &store).await;
    balanced(&[&a, &b, &c]).await;
    let load = Load::start(vec![a.s.url.clone(), b.s.url.clone(), c.s.url.clone()], &accts);
    load.progress(30).await;
    let nodes = [&a, &b, &c];
    // after each op: writes keep landing for a while (the new shards flush
    // L0s, run deep and compact, inherited L0s included), then every acked
    // write so far reads back
    let after_op = || async {
        tokio::time::sleep(Duration::from_millis(1500)).await;
        load.progress(20).await;
        let snap = load.acked.lock().clone();
        verify_readable(&a.s, &snap).await;
    };
    for cyc in 0..cycles {
        // split a shard of one node, asked of another
        let l = layout(&a);
        let target = *owned(nodes[cyc % 3]).first().unwrap();
        let kids = split(&nodes[(cyc + 1) % 3].s, target, json!({})).await;
        let l2 = settled(&nodes, l.version + 1, Duration::from_secs(20)).await;
        after_op().await;
        // merge its halves back, asked of a third node
        merge(&nodes[(cyc + 2) % 3].s, kids[0], kids[1]).await;
        let l3 = settled(&nodes, l2.version + 1, Duration::from_secs(20)).await;
        after_op().await;
        // a merge across nodes, then split that back
        let (x, y) = cross_pair(&l3, &nodes);
        let m = merge(&nodes[cyc % 3].s, x, y).await;
        let l4 = settled(&nodes, l3.version + 1, Duration::from_secs(20)).await;
        after_op().await;
        split(&nodes[(cyc + 1) % 3].s, m, json!({})).await;
        settled(&nodes, l4.version + 1, Duration::from_secs(20)).await;
        after_op().await;
    }
    let (acked, failed, gap) = load.stop().await;
    eprintln!("{} acked, {failed} failed attempts, longest per-account gap {gap:?}", acked.len());
    verify_readable_on(&nodes, &acked).await;
}

/// Shard ids past 16 bits work end to end: the allocator starts at 65,534
/// (a prefix whose layout already used up that many ids), so two splits
/// make shards 65,536 and 65,537. Writes land in them (log entries tagged
/// with the wide ids), their owner dies and a survivor fences and replays
/// its log into them, and a merge makes 65,538. Every acked write reads
/// back and shows up once on the firehose; the assignment and state keys
/// are the fixed-width ones, and no id was handed out twice.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn shard_ids_past_u16_end_to_end() {
    use vlsync_store::slots::{Layout, ShardId};
    let store = Arc::new(object_store::memory::InMemory::new());
    let seeded = Layout { next_id: ShardId(65_534), ..Layout::uniform(SHARDS) };
    object_store::ObjectStoreExt::put(
        &*store,
        &Path::from("vlpds/assign/layout"),
        serde_json::to_vec(&seeded).unwrap().into(),
    )
    .await
    .unwrap();
    let a = node("rsw-a", &store).await;
    let mut accts = accounts(&a.s, 9).await;
    let b = node("rsw-b", &store).await;
    let c = node("rsw-c", &store).await;
    balanced(&[&a, &b, &c]).await;
    let nodes = [&a, &b, &c];
    let mut seen: HashSet<ShardId> = layout(&a).ids().into_iter().collect();
    let mut fresh = |kids: &[ShardId]| {
        for k in kids {
            assert!(seen.insert(*k), "shard id {k} handed out twice");
        }
    };

    // split the shard holding accts[0], then the child holding it
    let probe = accts[0].did.clone();
    let l1 = layout(&a);
    let kids = split(&b.s, l1.shard_of(&probe), json!({})).await;
    assert_eq!(kids, vec![ShardId(65_534), ShardId(65_535)]);
    fresh(&kids);
    let l2 = settled(&nodes, l1.version + 1, Duration::from_secs(20)).await;
    // accounts at two distinct slots of the probe's child, split between
    // them so both wide shards get accounts and writes
    let child = l2.range_of(l2.shard_of(&probe)).unwrap();
    let slots_in = |accts: &[TestAccount]| -> std::collections::BTreeSet<u32> {
        accts
            .iter()
            .map(|x| vlsync_store::slots::slot_of(&x.did) as u32)
            .filter(|s| (child.lo..child.hi).contains(s))
            .collect()
    };
    // (a node mints DIDs in shards it owns: create through the child's owner)
    let minter = *nodes.iter().find(|n| owned(n).contains(&child.id)).expect("the child is owned");
    while slots_in(&accts).len() < 2 {
        assert!(accts.len() < 500, "no second account in {child:?}");
        accts.push(minter.s.create_account("rsw").await);
    }
    let at = *slots_in(&accts).last().unwrap();
    let wide = split(&c.s, child.id, json!({"at": at})).await;
    assert_eq!(wide, vec![ShardId(65_536), ShardId(65_537)]);
    fresh(&wide);
    let l3 = settled(&nodes, l2.version + 1, Duration::from_secs(20)).await;
    assert!(wide.contains(&l3.shard_of(&probe)), "{l3:?}");
    assert_eq!(l3.next_id, ShardId(65_538));
    assert!(wide.iter().all(|w| accts.iter().any(|x| l3.shard_of(&x.did) == *w)), "accounts in both wide shards");
    // writes to them; then the owner of the probe's shard dies under that load
    let victim = *nodes.iter().find(|n| owned(n).contains(&l3.shard_of(&probe))).expect("the probe's shard is owned");
    let survivors: Vec<&Node> = nodes.iter().copied().filter(|n| n.id() != victim.id()).collect();
    let cursor = survivors[0].s.settled_now().await;
    let mut live = survivors[0].s.subscribe(Some(cursor)).await;
    let load = Load::start(survivors.iter().map(|n| n.s.url.clone()).collect(), &accts);
    load.progress(40).await;
    victim.store.kill();
    victim.s.app.node.halt();
    let l4 = settled(&nodes, l3.version, Duration::from_secs(30)).await;
    assert!(survivors.iter().any(|n| owned(n).contains(&l4.shard_of(&probe))), "a survivor took the wide shard over");
    load.progress(40).await;
    // and merge the two wide shards (adjacent: the halves of one split)
    let merged = merge(&survivors[0].s, wide[0], wide[1]).await;
    assert_eq!(merged, ShardId(65_538));
    fresh(&[merged]);
    let l5 = settled(&nodes, l4.version + 1, Duration::from_secs(30)).await;
    assert_eq!(l5.shard_of(&probe), ShardId(65_538));
    load.progress(40).await;
    let (acked, failed, gap) = load.stop().await;
    eprintln!("{} acked, {failed} failed attempts, longest per-account gap {gap:?}", acked.len());
    verify_readable_on(&survivors, &acked).await;
    verify_firehose(&mut live, &acked).await;
    let fenced: usize = survivors.iter().map(|n| cluster(&n.s).fenced_logs().len()).sum();
    assert!(fenced > 0, "the dead owner's log was fenced");
    // object keys: 10-digit ids under assign/ and state/, every one below next_id
    let keys = keys(&store).await;
    let assigned: HashSet<ShardId> =
        keys.iter().filter_map(|k| k.strip_prefix("vlpds/assign/")).filter_map(ShardId::from_key).collect();
    for w in [65_536u32, 65_537, 65_538] {
        assert!(assigned.contains(&ShardId(w)), "assign/{} missing", ShardId(w).key());
        assert!(
            keys.iter().any(|k| k.starts_with(&format!("vlpds/state/{}/", ShardId(w).key()))),
            "state/{} missing",
            ShardId(w).key()
        );
    }
    assert!(assigned.iter().all(|s| *s < l5.next_id), "{assigned:?} vs next_id {}", l5.next_id);
    assert!(
        keys.iter()
            .filter_map(|k| k.strip_prefix("vlpds/assign/"))
            .all(|k| k == "layout" || ShardId::from_key(k).is_some()),
        "{keys:?}"
    );
}

async fn keys(store: &Arc<object_store::memory::InMemory>) -> Vec<String> {
    use futures::TryStreamExt;
    object_store::ObjectStore::list(&**store, Some(&Path::from("vlpds")))
        .map_ok(|m| m.location.to_string())
        .try_collect()
        .await
        .unwrap()
}

/// Object keys under the prefix: shard ids with a state dir, shard ids with
/// an assignment, and log ids under log/.
async fn bucket(store: &Arc<object_store::memory::InMemory>) -> (Vec<u32>, Vec<u32>, Vec<String>) {
    let keys = keys(store).await;
    let mut dirs: Vec<u32> = keys
        .iter()
        .filter_map(|k| k.strip_prefix("vlpds/state/")?.split('/').next().and_then(ShardId::from_key))
        .map(|s| s.0)
        .collect();
    dirs.dedup();
    let assigns: Vec<u32> =
        keys.iter().filter_map(|k| k.strip_prefix("vlpds/assign/").and_then(ShardId::from_key)).map(|s| s.0).collect();
    let mut logs: Vec<String> =
        keys.iter().filter_map(|k| Some(k.strip_prefix("vlpds/log/")?.split('/').next()?.to_string())).collect();
    logs.dedup();
    (dirs, assigns, logs)
}

/// Retired-state GC over a reshard history (DESIGN.md "Retired state GC"):
/// splits and merges under write load (a split's halves merged back, a
/// merge across nodes, its split) and graceful restarts in between, with
/// the grace, the log window and the fence retention all zero. Every acked
/// write reads back after every step (children detached from parents whose
/// dirs are then deleted; shards replayed over histories whose dead logs
/// are gone, fences included), and at the end the bucket holds exactly the
/// layout's state dirs and assignments and the live nodes' logs.
/// `RESHARD_GC_CYCLES=4` for a longer run.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn retired_state_gc_over_history() {
    let cycles: usize = std::env::var("RESHARD_GC_CYCLES").ok().and_then(|v| v.parse().ok()).unwrap_or(2);
    // a forced detach waits out the compactor's read guards, then SlateDB's
    // detach task releases the parent (process-wide knobs: harmless to the
    // other tests, whose SSTs are younger than the SST GC's 10 min min age)
    vlpds::partition::set_checkpoint_lifetime_unchecked(Duration::from_secs(1));
    vlpds::partition::set_detach_interval(Duration::from_millis(300));
    vlpds::partition::set_compaction_poll_interval(Duration::from_millis(500));
    // (the GC's grace is at least 3 manifest polls: a shard's owner must
    // have refreshed past a detach before the parent goes)
    vlpds::partition::set_manifest_poll_interval(Duration::from_millis(500));
    let store = Arc::new(object_store::memory::InMemory::new());
    let gc = |c: &mut vlpds::server::Config| {
        c.reshard_gc = Some(vlpds::reshard_gc::Config {
            interval: Duration::from_millis(200),
            grace: Some(Duration::ZERO),
            max_dirs: 2,
            detach_after: Some(Duration::ZERO),
            max_inflight: 2,
            full_every: None,
        });
        c.log_retention = Some(vlpds::retention::Config {
            window: Duration::ZERO,
            interval: Duration::from_millis(50),
            max_deletes: 50,
            fence_retention: Some(Duration::ZERO),
        });
    };
    let mut nodes = vec![node_with("rsgc-a", &store, gc).await];
    let accts = accounts(&nodes[0].s, 12).await;
    nodes.push(node_with("rsgc-b", &store, gc).await);
    nodes.push(node_with("rsgc-c", &store, gc).await);
    balanced(&nodes.iter().collect::<Vec<_>>()).await;
    let load = Load::start(nodes.iter().map(|n| n.s.url.clone()).collect(), &accts);
    load.progress(30).await;
    for cyc in 0..cycles {
        let refs: Vec<&Node> = nodes.iter().collect();
        // split, merge the halves back
        let l = layout(refs[0]);
        let target = *owned(refs[cyc % 3]).first().unwrap();
        let k = split(&refs[(cyc + 1) % 3].s, target, json!({})).await;
        let l2 = settled(&refs, l.version + 1, Duration::from_secs(20)).await;
        load.progress(20).await;
        check_acked(&refs[0].s, &load).await;
        merge(&refs[(cyc + 2) % 3].s, k[0], k[1]).await;
        let l3 = settled(&refs, l2.version + 1, Duration::from_secs(20)).await;
        load.progress(20).await;
        check_acked(&refs[1].s, &load).await;
        // a merge across nodes, then a split of it
        let (x, y) = cross_pair(&l3, &refs);
        let m = merge(&refs[cyc % 3].s, x, y).await;
        let l4 = settled(&refs, l3.version + 1, Duration::from_secs(20)).await;
        load.progress(20).await;
        split(&refs[(cyc + 1) % 3].s, m, json!({})).await;
        settled(&refs, l4.version + 1, Duration::from_secs(20)).await;
        load.progress(20).await;
        check_acked(&refs[2].s, &load).await;
        // a graceful restart of one node: its old log is fenced, pruned,
        // and its fence deleted; its shards' next owners replay over it
        let i = cyc % 3;
        let id = nodes[i].id();
        vlpds::server::shutdown(&nodes[i].s.app).await;
        nodes[i] = node_with(&id, &store, gc).await;
        balanced(&nodes.iter().collect::<Vec<_>>()).await;
        load.progress(20).await;
        check_acked(&nodes[i].s, &load).await;
    }
    // the bucket converges on the live layout and the live logs
    let refs: Vec<&Node> = nodes.iter().collect();
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        let l = settled(&refs, 1, Duration::from_secs(20)).await;
        let want: Vec<u32> = {
            let mut v: Vec<u32> = l.ids().iter().map(|s| s.0).collect();
            v.sort();
            v
        };
        let mut live_logs: Vec<String> = nodes.iter().map(|n| n.s.app.log.log_id.to_string()).collect();
        live_logs.sort();
        let (dirs, assigns, logs) = bucket(&store).await;
        // no dead log left. A live log may be absent: retention (window 0)
        // deletes a live log's segments once its shards checkpoint past
        // them, so a log nothing was appended to since is empty (seen ~3%
        // of loaded runs, always the last-restarted node's fresh log)
        if dirs == want && assigns == want && logs.iter().all(|l| live_logs.contains(l)) {
            eprintln!("converged: {} shards, logs {logs:?}", want.len());
            break;
        }
        if Instant::now() > deadline {
            let mut why = Vec::new();
            for d in dirs.iter().filter(|d| !want.contains(d)) {
                let path = format!("vlpds/state/{}", ShardId(*d).key());
                let admin =
                    slatedb::admin::AdminBuilder::new(path, store.clone() as Arc<dyn object_store::ObjectStore>)
                        .build();
                let cps = admin
                    .list_checkpoints(None)
                    .await
                    .map(|v| v.iter().map(|c| (c.id, c.create_time, c.expire_time, c.manifest_id)).collect::<Vec<_>>());
                let ext = admin.read_manifest(None).await.ok().flatten().map(|m| {
                    m.external_dbs()
                        .iter()
                        .map(|e| (e.path.clone(), e.source_checkpoint_id, e.final_checkpoint_id, e.sst_ids.len()))
                        .collect::<Vec<_>>()
                });
                why.push(format!("{d}: now {} checkpoints {cps:?} external {ext:?}", chrono::Utc::now()));
            }
            for d in &want {
                let path = format!("vlpds/state/{}", ShardId(*d).key());
                let admin =
                    slatedb::admin::AdminBuilder::new(path, store.clone() as Arc<dyn object_store::ObjectStore>)
                        .build();
                if let Ok(Some(m)) = admin.read_manifest(None).await {
                    why.push(format!(
                        "live {d}: external {:?}",
                        m.external_dbs()
                            .iter()
                            .map(|e| (e.path.clone(), e.sst_ids.len(), e.final_checkpoint_id.is_some()))
                            .collect::<Vec<_>>()
                    ));
                }
            }
            panic!(
                "retired state never went: dirs {dirs:?} assigns {assigns:?} (layout {want:?}); logs {logs:?} (live {live_logs:?}); inherited per node {:?}; {why:#?}",
                nodes.iter().map(|n| n.s.app.partitions.owned().iter().filter(|p| vlpds::reshard_gc::has_inherited(&p.db.manifest())).map(|p| p.id.0).collect::<Vec<_>>()).collect::<Vec<_>>()
            );
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let (acked, failed, gap) = load.stop().await;
    eprintln!("{} acked, {failed} failed attempts, longest per-account gap {gap:?}", acked.len());
    verify_readable_on(&nodes.iter().collect::<Vec<_>>(), &acked).await;
    // and a node restarted onto the collected bucket serves it all
    vlpds::server::shutdown(&nodes[0].s.app).await;
    let id = nodes[0].id();
    nodes[0] = node_with(&id, &store, gc).await;
    balanced(&nodes.iter().collect::<Vec<_>>()).await;
    verify_readable_on(&nodes.iter().collect::<Vec<_>>(), &acked).await;
}

/// Every write acked so far reads back through `n`.
async fn check_acked(n: &TestServer, load: &Load) {
    let snap = load.acked.lock().clone();
    verify_readable(n, &snap).await;
}
