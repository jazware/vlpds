use super::*;
use std::collections::{HashMap, HashSet};

pub fn routes() -> Router<Arc<App>> {
    Router::new()
        .route("/xrpc/com.atproto.sync.getLatestCommit", get(get_latest_commit))
        .route("/xrpc/com.atproto.sync.getRepoStatus", get(get_repo_status))
        .route("/xrpc/com.atproto.sync.getRepo", get(get_repo))
        .route("/xrpc/com.atproto.sync.getCheckout", get(get_checkout))
        .route("/xrpc/com.atproto.sync.getHead", get(get_head))
        .route("/xrpc/com.atproto.sync.getBlocks", get(get_blocks))
        .route("/xrpc/com.atproto.sync.getRecord", get(sync_get_record))
        .route("/xrpc/com.atproto.sync.listRepos", get(list_repos))
        .route("/xrpc/com.atproto.sync.listReposByCollection", get(list_repos_by_collection))
        .route("/xrpc/com.atproto.sync.subscribeRepos", get(subscribe_repos))
        // relay-side methods
        .route("/xrpc/com.atproto.sync.getHostStatus", get(not_implemented))
        .route("/xrpc/com.atproto.sync.listHosts", get(not_implemented))
        .route("/xrpc/com.atproto.sync.notifyOfUpdate", post(not_implemented))
        .route("/xrpc/com.atproto.sync.requestCrawl", post(not_implemented))
}

pub(super) async fn not_implemented() -> XrpcError {
    XrpcError {
        status: StatusCode::NOT_IMPLEMENTED,
        error: "MethodNotImplemented".into(),
        message: "Method Not Implemented".into(),
    }
}

/// Reference `assertRepoAvailability`: only the repo's own user or an admin
/// may read an inactive repo.
pub(super) async fn assert_available(app: &App, did: &str, creds: Option<&Credentials>) -> XResult<Account> {
    let acct = super::server::account_if_exists(app, did)
        .await?
        .ok_or_else(|| XrpcError::bad("RepoNotFound", format!("Could not find repo for DID: {did}")))?;
    let self_or_admin = match creds {
        Some(Credentials::Admin) => true,
        Some(c) => c.did() == Some(did),
        None => false,
    };
    if self_or_admin {
        return Ok(acct);
    }
    match acct.status.as_deref() {
        None => Ok(acct),
        Some("takendown") => Err(XrpcError::bad("RepoTakendown", format!("Repo has been takendown: {did}"))),
        Some("deactivated") => Err(XrpcError::bad("RepoDeactivated", format!("Repo has been deactivated: {did}"))),
        Some(st) => Err(XrpcError::bad(&inactive_error(st), format!("Repo is {st}: {did}"))),
    }
}

/// Lenient percent-decoding: a malformed escape is kept as is. `plus`:
/// form encoding, '+' is a space.
pub(super) fn pct_decode(s: &str, plus: bool) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' if plus => out.push(b' '),
            b'%' if i + 2 < b.len() && b[i + 1].is_ascii_hexdigit() && b[i + 2].is_ascii_hexdigit() => {
                out.push(u8::from_str_radix(&s[i + 1..i + 3], 16).unwrap_or(b'%'));
                i += 2;
            }
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Keeps repeated keys (`cids=a&cids=b`), which axum's `Query` can't express.
pub(super) fn query_pairs(raw: &str) -> Vec<(String, String)> {
    let decode = |s: &str| pct_decode(s, true);
    raw.split('&')
        .filter(|p| !p.is_empty())
        .map(|p| match p.split_once('=') {
            Some((k, v)) => (decode(k), decode(v)),
            None => (decode(p), String::new()),
        })
        .collect()
}

#[derive(Deserialize)]
struct DidQ {
    did: String,
}

async fn get_latest_commit(
    State(app): AppState,
    MaybeAuth(creds): MaybeAuth,
    Query(q): Query<DidQ>,
) -> XResult<Json<J>> {
    assert_available(&app, &q.did, creds.as_ref()).await?;
    let head = app.head(&q.did).await?;
    Ok(Json(json!({"cid": head.commit.to_string(), "rev": head.rev.to_string()})))
}

async fn get_head(State(app): AppState, MaybeAuth(creds): MaybeAuth, Query(q): Query<DidQ>) -> XResult<Json<J>> {
    assert_available(&app, &q.did, creds.as_ref()).await?;
    let head = app.head(&q.did).await.map_err(|e| match e.error.as_str() {
        "RepoNotFound" => XrpcError::bad("HeadNotFound", format!("Could not find root for DID: {}", q.did)),
        _ => e,
    })?;
    Ok(Json(json!({"root": head.commit.to_string()})))
}

async fn get_repo_status(State(app): AppState, Query(q): Query<DidQ>) -> XResult<Json<J>> {
    let acct = assert_available(&app, &q.did, Some(&Credentials::Admin)).await?;
    let active = acct.status.is_none();
    let mut out = json!({"did": q.did, "active": active});
    if let Some(st) = &acct.status {
        out["status"] = json!(st);
    }
    if active {
        let head = app.head(&q.did).await?;
        out["rev"] = json!(head.rev.to_string());
    }
    Ok(Json(out))
}

fn car_response(body: Vec<u8>) -> Response {
    ([(header::CONTENT_TYPE, "application/vnd.ipld.car")], Body::from(body)).into_response()
}

#[derive(Deserialize)]
struct GetRepoQ {
    did: String,
    since: Option<String>,
}

/// With `since`, only records written after that rev. MST nodes aren't
/// stored per rev, so the whole current tree is included: a superset of the
/// reference's block set that still applies cleanly for incremental sync.
async fn get_repo(State(app): AppState, MaybeAuth(creds): MaybeAuth, Query(q): Query<GetRepoQ>) -> XResult<Response> {
    let since = match &q.since {
        Some(s) => {
            Some(crate::tid::Tid::parse(s).ok_or_else(|| XrpcError::bad("InvalidRequest", "since must be a TID"))?.0)
        }
        None => None,
    };
    assert_available(&app, &q.did, creds.as_ref()).await?;
    export_repo(&app, &q.did, since).await
}

async fn get_checkout(State(app): AppState, MaybeAuth(creds): MaybeAuth, Query(q): Query<DidQ>) -> XResult<Response> {
    assert_available(&app, &q.did, creds.as_ref()).await?;
    export_repo(&app, &q.did, None).await
}

/// MiB of `M/` nodes exports may hold at once: an export reads its repo's
/// whole `M/` range with one scan (~32 B/record held), taking 1 MiB grants
/// as it goes (past them, see [`crate::mst_store::prefetch_tree`]).
static EXPORT_PREFETCH_MB: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(EXPORT_PREFETCH_POOL_MAX_MB);
const EXPORT_PREFETCH_POOL_MAX_MB: usize = 512;
const EXPORT_PREFETCH_MB_PER_SLOT: usize = 16;

fn export_prefetch_pool_mb(max_exports: usize) -> usize {
    max_exports.saturating_mul(EXPORT_PREFETCH_MB_PER_SLOT).min(EXPORT_PREFETCH_POOL_MAX_MB)
}

/// Shrinks the exports' `M/` read-ahead pool to fit `max_exports` slots.
/// Process-wide: the first call wins.
pub fn size_export_prefetch_pool(max_exports: usize) {
    static SIZED: std::sync::Once = std::sync::Once::new();
    SIZED.call_once(|| {
        EXPORT_PREFETCH_MB.forget_permits(EXPORT_PREFETCH_POOL_MAX_MB - export_prefetch_pool_mb(max_exports));
    });
}

/// Memory `max_exports` streaming exports may hold: each one's records fed
/// ahead of its walk and its queued body chunks, plus the shared `M/`
/// read-ahead pool (src/memory.rs budgets it).
pub fn export_memory_bytes(max_exports: usize) -> u64 {
    let per = EXPORT_FEED * EXPORT_BATCH_BYTES + EXPORT_QUEUE * EXPORT_CHUNK;
    (max_exports * per + (export_prefetch_pool_mb(max_exports) << 20)) as u64
}
static EXPORT_PREFETCH_MAX: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(usize::MAX);

/// Tests: caps each export's `M/` read-ahead (0: every node read one by one).
pub fn set_export_prefetch_max_bytes(n: usize) {
    EXPORT_PREFETCH_MAX.store(n, Ordering::Relaxed);
}

/// Each export holds a blocking-pool thread for its MST walk, so this also
/// bounds what slow readers can take from that pool.
pub const DEFAULT_MAX_EXPORTS: usize = 32;
pub const DEFAULT_EXPORT_STALL: std::time::Duration = std::time::Duration::from_secs(60);
const EXPORT_SLOT_WAIT: std::time::Duration = std::time::Duration::from_secs(10);
/// Body chunks queued between an export and its response body.
const EXPORT_QUEUE: usize = 4;

/// Records per batch to the walk, and their bytes past which a batch goes
/// early; with [`EXPORT_FEED`] batches queued, an export's records ahead of
/// its walk stay within ~4 MiB (and one record).
const EXPORT_BATCH: usize = 512;
const EXPORT_BATCH_BYTES: usize = 256 << 10;
const EXPORT_FEED: usize = 16;

pub(crate) const EXPORT_CHUNK: usize = 1 << 20;

/// Feeds every record to the MST walk (`tx`) in key order: its key and CID
/// (the walk rebuilds the leaves from them) and, unless `since` excludes
/// it, its block (the walk puts it by its entry).
async fn feed_records(
    snap: &slatedb::DbSnapshot,
    did: &str,
    gen: u64,
    since: Option<u64>,
    tx: tokio::sync::mpsc::Sender<crate::mst_store::RecordBatch>,
) -> anyhow::Result<()> {
    let prefix = state::record_prefix(did, gen);
    let opts = slatedb::config::ScanOptions {
        read_ahead_bytes: 4 << 20,
        max_fetch_tasks: 4,
        cache_blocks: true,
        ..Default::default()
    };
    let mut iter = match snap.scan_with_options(prefix.clone()..state::prefix_end(&prefix), &opts).await {
        Ok(it) => state::BatchedScan::new(it),
        Err(e) => {
            let _ = tx.send(Err(e.to_string())).await;
            return Err(e.into());
        }
    };
    let new_batch = || crate::mst_store::Records::with_capacity(EXPORT_BATCH);
    let mut batch = new_batch();
    loop {
        let kv = match iter.next().await {
            Ok(Some(kv)) => kv,
            Ok(None) => break,
            Err(e) => {
                let _ = tx.send(Err(e.to_string())).await;
                return Err(e.into());
            }
        };
        let (cid, bytes) = match state::record_value_parts(&kv.value) {
            Ok(v) => v,
            Err(e) => {
                let _ = tx.send(Err(e.to_string())).await;
                return Err(e);
            }
        };
        let carried = since.is_none_or(|s| state::record_value_rev(&kv.value) > s);
        batch.push(&kv.key[prefix.len()..], cid, carried.then_some(bytes));
        if (batch.len() == EXPORT_BATCH || batch.bytes() >= EXPORT_BATCH_BYTES)
            && tx.send(Ok(std::mem::replace(&mut batch, new_batch()))).await.is_err()
        {
            // the walk is gone: its result says why
            return Ok(());
        }
    }
    if !batch.is_empty() {
        let _ = tx.send(Ok(batch)).await;
    }
    Ok(())
}

pub(super) struct ExportSlot(#[allow(dead_code)] tokio::sync::OwnedSemaphorePermit);

impl Drop for ExportSlot {
    fn drop(&mut self) {
        metrics::SYNC_EXPORTS.with_label_values(&["running"]).dec();
    }
}

struct GaugeGuard(prometheus::IntGauge);

impl Drop for GaugeGuard {
    fn drop(&mut self) {
        self.0.dec();
    }
}

pub(super) async fn export_slot(app: &App) -> XResult<ExportSlot> {
    let p = match app.exports.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            let waiting = metrics::SYNC_EXPORTS.with_label_values(&["waiting"]);
            waiting.inc();
            let _w = GaugeGuard(waiting);
            match tokio::time::timeout(EXPORT_SLOT_WAIT, app.exports.clone().acquire_owned()).await {
                Ok(Ok(p)) => p,
                _ => {
                    metrics::SYNC_EXPORTS_ENDED.with_label_values(&["shed"]).inc();
                    return Err(XrpcError {
                        status: StatusCode::SERVICE_UNAVAILABLE,
                        error: "Overloaded".into(),
                        message: "too many repo exports in progress; retry shortly".into(),
                    });
                }
            }
        }
    };
    metrics::SYNC_EXPORTS.with_label_values(&["running"]).inc();
    Ok(ExportSlot(p))
}

/// A whole-tree walk's `M/` read-ahead, and its grants from
/// [`EXPORT_PREFETCH_MB`]. Walk with its `persist_min()`.
pub(crate) async fn prefetch_nodes(
    snap: &slatedb::DbSnapshot,
    did: &str,
    gen: u64,
) -> (crate::mst_store::Prefetched, Option<tokio::sync::SemaphorePermit<'static>>) {
    let (mut held, mut mb) = (None::<tokio::sync::SemaphorePermit<'static>>, 0usize);
    let max = EXPORT_PREFETCH_MAX.load(Ordering::Relaxed);
    if max == 0 {
        return (Default::default(), None);
    }
    let opts = slatedb::config::ScanOptions {
        read_ahead_bytes: 4 << 20,
        max_fetch_tasks: 4,
        cache_blocks: true,
        ..Default::default()
    };
    let r = crate::mst_store::prefetch_tree(snap, did, gen, &opts, |bytes| {
        if bytes > max {
            return false;
        }
        while mb << 20 < bytes {
            let Ok(p) = EXPORT_PREFETCH_MB.try_acquire() else { return false };
            match &mut held {
                Some(h) => h.merge(p),
                None => held = Some(p),
            }
            mb += 1;
        }
        true
    })
    .await;
    match r {
        Ok(p) => (p, held),
        Err(e) => {
            tracing::debug!(%did, "getRepo: M/ prefetch failed, reading nodes one by one: {e:#}");
            (Default::default(), None)
        }
    }
}

pub type ExportChunkTx = tokio::sync::mpsc::Sender<Result<Bytes, std::io::Error>>;
pub(super) type ChunkTx = ExportChunkTx;

/// Err: the client is gone, or took nothing for `stall` (e.g. an h2 stream
/// at a zero window).
pub(super) async fn send_chunk(tx: &ChunkTx, chunk: Vec<u8>, stall: std::time::Duration) -> Result<(), &'static str> {
    match tokio::time::timeout(stall, tx.send(Ok(Bytes::from(chunk)))).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(_)) => Err("client_gone"),
        Err(_) => Err("stalled"),
    }
}

/// An export that gives up aborts its body: the queued chunks are freed at
/// once and the body ends with an error, so the client sees a failed
/// transfer, not a short CAR that looks complete.
struct ExportBody {
    rx: parking_lot::Mutex<tokio::sync::mpsc::Receiver<Result<Bytes, std::io::Error>>>,
    aborted: std::sync::atomic::AtomicBool,
}

impl ExportBody {
    fn abort(&self) {
        self.aborted.store(true, Ordering::Release);
        let mut rx = self.rx.lock();
        rx.close();
        while rx.try_recv().is_ok() {}
    }
}

/// A source that fails once its export has ended (`stop` set by a failed
/// send), so the MST walk stops at its next read instead of walking (and
/// reading) the rest of the tree for nobody.
struct Stoppable<'a, S> {
    inner: S,
    stop: &'a std::cell::Cell<Option<&'static str>>,
}

impl<S> Stoppable<'_, S> {
    fn check(&self) -> Result<(), crate::mst::MstError> {
        match self.stop.get() {
            Some(r) => Err(crate::mst::MstError::Store(format!("export ended: {r}"))),
            None => Ok(()),
        }
    }
}

impl<S: crate::mst_lazy::Source> crate::mst_lazy::Source for Stoppable<'_, S> {
    fn cached(&self, cid: &Cid) -> Option<Arc<crate::mst::Node>> {
        self.inner.cached(cid)
    }
    fn remember(&self, n: &Arc<crate::mst::Node>) {
        self.inner.remember(n)
    }
    fn node(&self, cid: &Cid) -> Result<Option<Arc<[u8]>>, crate::mst::MstError> {
        self.check()?;
        self.inner.node(cid)
    }
    fn records(
        &self,
        lo: Option<&[u8]>,
        hi: Option<&[u8]>,
        out: &mut Vec<(crate::mst_lazy::Key, Cid)>,
    ) -> Result<(), crate::mst::MstError> {
        self.check()?;
        self.inner.records(lo, hi, out)
    }
    fn leaf_records(
        &self,
        lo: Option<&[u8]>,
        hi: Option<&[u8]>,
        enc: &mut crate::mst::LeafEncoder,
    ) -> Result<(), crate::mst::MstError> {
        self.check()?;
        self.inner.leaf_records(lo, hi, enc)
    }
    fn record_blocks(&self, upto: Option<&[u8]>, f: &mut dyn FnMut(Cid, &[u8])) -> Result<(), crate::mst::MstError> {
        self.check()?;
        self.inner.record_blocks(upto, f)
    }
}

/// Streams the repo CAR from one SlateDB snapshot in one pass, in the
/// spec's streamable order (commit, then each MST node followed by its
/// entries: see [`crate::mst_lazy::export_blocks`]). One forward `R/` scan
/// feeds the MST walk on a blocking thread both its leaves' keys and the
/// record blocks it puts by their entries. An export whose client goes away
/// or stalls for `Config::export_stall` stops at once, so slow readers
/// can't pin blocking threads, snapshots or memory.
async fn export_repo(app: &App, did: &str, since: Option<u64>) -> XResult<Response> {
    let slot = export_slot(app).await?;
    let (view, snap) = app.repo_view(did).await?;
    let (head, gen) = (view.head.clone(), view.gen);
    drop(view);
    let did: Arc<str> = did.into();
    let stall = app.config.export_stall;
    Ok(export_body(slot, "application/vnd.ipld.car", move |tx| async move {
        let r = stream_export(snap, did.clone(), gen, head, since, &tx, stall).await;
        if let Err(reason) = r {
            if reason != "client_gone" {
                tracing::debug!(%did, reason, "getRepo export ended early");
            }
        }
        r
    }))
}

/// A response streaming what `produce` sends, holding `slot` until it ends.
/// A producer that gives up (other than for a client gone) aborts the body.
pub(super) fn export_body<F, Fut>(slot: ExportSlot, content_type: &'static str, produce: F) -> Response
where
    F: FnOnce(ChunkTx) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Result<(), &'static str>> + Send + 'static,
{
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(EXPORT_QUEUE);
    let body = Arc::new(ExportBody { rx: parking_lot::Mutex::new(rx), aborted: Default::default() });
    let ours = body.clone();
    tokio::spawn(async move {
        let _slot = slot;
        let reason = match produce(tx).await {
            Ok(()) => "done",
            Err(r) => r,
        };
        metrics::SYNC_EXPORTS_ENDED.with_label_values(&[reason]).inc();
        if reason != "done" && reason != "client_gone" {
            ours.abort();
        }
    });
    // fused: body wrappers (response compression) may poll past the end
    let stream = futures::StreamExt::fuse(futures::stream::poll_fn(move |cx| match body.rx.lock().poll_recv(cx) {
        std::task::Poll::Ready(None) if body.aborted.swap(false, Ordering::AcqRel) => {
            std::task::Poll::Ready(Some(Err(std::io::Error::other("repo export aborted"))))
        }
        r => r,
    }));
    ([(header::CONTENT_TYPE, content_type)], Body::from_stream(stream)).into_response()
}

/// Err: why it ended early (`client_gone`, `stalled`, `error`). Also the
/// relay's archival getRepo, over its mirrored repos (same layout).
pub async fn stream_export(
    snap: Arc<slatedb::DbSnapshot>,
    did: Arc<str>,
    gen: u64,
    head: Head,
    since: Option<u64>,
    tx: &ChunkTx,
    stall: std::time::Duration,
) -> Result<(), &'static str> {
    const CHUNK: usize = EXPORT_CHUNK;
    let mut first = Vec::with_capacity(64 + head.commit_block.len());
    car::write_header(&mut first, &head.commit);
    car::write_block(&mut first, &head.commit, &head.commit_block);
    send_chunk(tx, first, stall).await?;
    let (ktx, krx) = tokio::sync::mpsc::channel(EXPORT_FEED);
    let walk = async {
        let (pre, budget) = prefetch_nodes(&snap, &did, gen).await;
        let (snap2, did2, root, tx2) = (snap.clone(), did.clone(), head.data, tx.clone());
        let r = tokio::task::spawn_blocking(move || {
            let rt = tokio::runtime::Handle::current();
            let stop = std::cell::Cell::new(None);
            let mut buf = Vec::with_capacity(CHUNK + 4096);
            let mut emit = |c: Cid, b: &[u8]| {
                if stop.get().is_some() {
                    return;
                }
                car::write_block(&mut buf, &c, b);
                if buf.len() >= CHUNK {
                    let chunk = std::mem::replace(&mut buf, Vec::with_capacity(CHUNK + 4096));
                    if let Err(r) = rt.block_on(send_chunk(&tx2, chunk, stall)) {
                        stop.set(Some(r));
                    }
                }
            };
            let nodes = crate::mst_store::DbSource::new(&*snap2, &did2, gen, &rt).with_prefetched(Some(&pre));
            let src = Stoppable { inner: crate::mst_store::FedSource::new(nodes, krx), stop: &stop };
            let r = crate::mst_lazy::export_blocks(root, pre.persist_min(), &src, &mut emit).map(|_| ());
            (r, stop.get(), buf)
        })
        .await;
        drop(budget);
        r
    };
    let (walked, fed) = tokio::join!(walk, feed_records(&snap, &did, gen, since, ktx));
    let buf = match walked {
        Ok((_, Some(reason), _)) => return Err(reason),
        Ok((Ok(()), None, buf)) => buf,
        Ok((Err(e), None, _)) => {
            tracing::warn!(%did, "getRepo: MST walk failed: {e}");
            return Err("error");
        }
        Err(e) => {
            tracing::warn!(%did, "getRepo: MST walk task: {e}");
            return Err("error");
        }
    };
    // a walk that ended well took every record, so the scan ended well too
    if let Err(e) = fed {
        tracing::warn!(%did, "getRepo: record scan failed: {e:#}");
        return Err("error");
    }
    if !buf.is_empty() {
        send_chunk(tx, buf, stall).await?;
    }
    Ok(())
}

/// Only the current state's blocks: ones only reachable from older revisions
/// aren't kept and report BlockNotFound.
async fn get_blocks(
    State(app): AppState,
    MaybeAuth(creds): MaybeAuth,
    axum::extract::RawQuery(raw): axum::extract::RawQuery,
) -> XResult<Response> {
    let pairs = query_pairs(raw.as_deref().unwrap_or(""));
    let did = pairs
        .iter()
        .find(|(k, _)| k == "did")
        .map(|(_, v)| v.clone())
        .ok_or_else(|| XrpcError::bad("InvalidRequest", "Error: Params must have the property \"did\""))?;
    let mut want = Vec::new();
    // a query string holds thousands of CIDs: no quadratic dedup
    let mut wanted = std::collections::HashSet::new();
    for (k, v) in &pairs {
        if k == "cids" || k == "cids[]" {
            let c = Cid::parse(v).map_err(|_| XrpcError::bad("InvalidRequest", format!("invalid cid: {v}")))?;
            if wanted.insert(c) {
                want.push(c);
            }
        }
    }
    assert_available(&app, &did, creds.as_ref()).await?;
    let (view, snap) = app.repo_view(&did).await?;
    let mut found: HashMap<Cid, Vec<u8>> = HashMap::new();
    if want.contains(&view.head.commit) {
        found.insert(view.head.commit, view.head.commit_block.to_vec());
    }
    // MST nodes, if the node index already covers this version
    let rest = |found: &HashMap<Cid, Vec<u8>>| -> Vec<Cid> {
        want.iter().filter(|c| !found.contains_key(c)).copied().collect()
    };
    let todo = rest(&found);
    if !todo.is_empty() {
        found.extend(lazy_nodes(&view, &snap, &did, todo, false).await?);
    }
    // records, by the record CID index (c/ keys) of the matching snapshot
    for c in rest(&found) {
        if c.codec == crate::cid::CODEC_DAG_CBOR {
            if let Some(b) = find_record(&snap, &did, view.gen, &c).await? {
                found.insert(c, b);
            }
        }
    }
    // the rest can only be nodes: build the index from this view if needed
    let todo = rest(&found);
    if !todo.is_empty() {
        found.extend(lazy_nodes(&view, &snap, &did, todo, true).await?);
    }
    let missing: Vec<String> = rest(&found).iter().map(|c| c.to_string()).collect();
    if !missing.is_empty() {
        return Err(XrpcError::bad("BlockNotFound", format!("Could not find cids: {}", missing.join(","))));
    }
    // CAR v1 with no roots, as the reference does
    let mut out = Vec::new();
    let mut h = Vec::with_capacity(32);
    crate::cbor::write_map_head(&mut h, 2);
    crate::cbor::write_text(&mut h, "roots");
    crate::cbor::write_array_head(&mut h, 0);
    crate::cbor::write_text(&mut h, "version");
    crate::cbor::write_uint(&mut h, 1);
    car::write_varint(&mut out, h.len() as u64);
    out.extend_from_slice(&h);
    for c in &want {
        car::write_block(&mut out, c, &found[c]);
    }
    Ok(car_response(out))
}

/// The c/ index names the paths holding that CID (or one sharing its key
/// prefix), so the record at a path must match.
pub async fn find_record(snap: &slatedb::DbSnapshot, did: &str, gen: u64, cid: &Cid) -> XResult<Option<Vec<u8>>> {
    let prefix = state::record_cid_prefix(did, gen, cid);
    let mut iter = snap.scan(prefix.clone()..state::prefix_end(&prefix)).await.map_err(XrpcError::from_err)?;
    while let Some(kv) = iter.next().await.map_err(XrpcError::from_err)? {
        let Ok(path) = std::str::from_utf8(&kv.key[prefix.len()..]) else {
            continue;
        };
        if let Some(v) = snap.get(state::record_key(did, gen, path)).await.map_err(XrpcError::from_err)? {
            let (c, bytes) = state::decode_record_value(&v).map_err(XrpcError::from_err)?;
            if c == *cid {
                return Ok(Some(bytes.to_vec()));
            }
        }
    }
    Ok(None)
}

#[derive(Deserialize)]
struct SyncRecordQ {
    did: String,
    collection: String,
    rkey: String,
}

async fn sync_get_record(
    State(app): AppState,
    MaybeAuth(creds): MaybeAuth,
    Query(q): Query<SyncRecordQ>,
) -> XResult<Response> {
    if !super::syntax::valid_nsid(&q.collection) || !super::syntax::valid_rkey(&q.rkey) {
        return Err(XrpcError::bad("InvalidRequest", "invalid collection or rkey"));
    }
    assert_available(&app, &q.did, creds.as_ref()).await?;
    let (view, snap) = app.repo_view(&q.did).await?;
    let head = view.head.clone();
    let path = format!("{}/{}", q.collection, q.rkey);
    let mut out = Vec::new();
    car::write_header(&mut out, &head.commit);
    car::write_block(&mut out, &head.commit, &head.commit_block);
    let proof = crate::mst_store::proof_blocks(&view.tree.root, &*snap, &q.did, view.gen, path.as_bytes()).await;
    for (c, b) in proof.map_err(XrpcError::from_err)? {
        car::write_block(&mut out, &c, &b);
    }
    if let Some(v) = snap.get(state::record_key(&q.did, view.gen, &path)).await.map_err(XrpcError::from_err)? {
        let (cid, bytes) = state::decode_record_value(&v).map_err(XrpcError::from_err)?;
        car::write_block(&mut out, &cid, &bytes);
    }
    Ok(car_response(out))
}

/// MST node blocks of a view by CID. First pass (`walk` false): loaded
/// nodes, leaves an index covering the view places, then `M/` point reads
/// (the snapshot holds exactly the view's interior nodes). Second pass
/// (`walk`): by the node index, built if needed with one walk of the whole
/// tree and then advanced by the worker per commit. A miss in an index
/// covering the view is final, so unknown CIDs don't walk the tree again.
async fn lazy_nodes(
    view: &Arc<crate::worker::DurableView>,
    snap: &Arc<slatedb::DbSnapshot>,
    did: &str,
    cids: Vec<Cid>,
    walk: bool,
) -> XResult<Vec<(Cid, Vec<u8>)>> {
    use crate::mst::{NodeIndex, NodeRef};
    let mut want: std::collections::HashSet<Cid> = cids.into_iter().collect();
    let mut out = Vec::new();
    let rev = view.head.rev.0;
    let lookup = |ix: &NodeIndex, want: &HashSet<Cid>| -> Vec<(Cid, NodeRef)> {
        want.iter().filter_map(|c| ix.get(c).map(|r| (*c, r.clone()))).collect()
    };
    if !walk {
        crate::mst_lazy::loaded_blocks(&view.tree.root, &want, &mut out).map_err(XrpcError::from_err)?;
        for (c, _) in &out {
            want.remove(c);
        }
        let leaves: Vec<(Cid, NodeRef)> = {
            let cell = view.nodes.lock();
            match cell.index.as_ref().filter(|ix| ix.covers(rev)) {
                Some(ix) => lookup(ix, &want).into_iter().filter(|(_, (_, h))| *h == 0).collect(),
                None => Vec::new(),
            }
        };
        for (c, (key, _)) in leaves {
            if let Some(b) = path_end_block(view, snap, did, &key, &c).await? {
                want.remove(&c);
                out.push((c, b));
            }
        }
        for c in want {
            if c.codec != crate::cid::CODEC_DAG_CBOR {
                continue;
            }
            if let Some(b) = snap.get(state::mst_node_key(did, view.gen, &c)).await.map_err(XrpcError::from_err)? {
                if Cid::dag_cbor(&b) == c {
                    out.push((c, b.to_vec()));
                }
            }
        }
        return Ok(out);
    }
    let covered = |want: &HashSet<Cid>| {
        let mut cell = view.nodes.lock();
        match cell.index.as_ref().filter(|ix| ix.covers(rev)) {
            Some(ix) => Some(lookup(ix, want)),
            None => {
                // from now on the worker reports written nodes, so the index
                // built below can catch up with commits made meanwhile
                cell.wanted = true;
                None
            }
        }
    };
    let mut refs = covered(&want);
    // One build per repo at a time (the others wait for it and use its
    // index), and a few process-wide: each walks the whole tree on a
    // blocking thread and holds a map of every leaf until it is installed.
    let _turn = match refs {
        Some(_) => None,
        None => {
            let gate = index_build_gate(&view.nodes);
            let turn = gate.lock_owned().await;
            refs = covered(&want);
            Some(turn)
        }
    };
    let refs = match refs {
        Some(r) => r,
        None => {
            let _slot = INDEX_BUILDS.acquire().await.expect("never closed");
            let (pre, _budget) = prefetch_nodes(snap, did, view.gen).await;
            let (snap, did, root, gen) = (snap.clone(), did.to_string(), view.head.data, view.gen);
            let ix = tokio::task::spawn_blocking(move || {
                let rt = tokio::runtime::Handle::current();
                let mut map = HashMap::new();
                let nodes = crate::mst_store::DbSource::new(&*snap, &did, gen, &rt).with_prefetched(Some(&pre));
                let scan = crate::mst_store::ScanSource::open(&*snap, &did, gen, nodes, &rt)?;
                crate::mst_lazy::export_blocks(root, pre.persist_min(), &scan, &mut |c, b| {
                    // nodes with keys of their own (all leaves): where they sit
                    if let Ok(n) = crate::mst::decode_node(b, c) {
                        if let Some(crate::mst::Entry::Value { key, .. }) =
                            n.entries.iter().find(|e| matches!(e, crate::mst::Entry::Value { .. }))
                        {
                            map.insert(c, (key.clone(), n.height));
                        }
                    }
                })?;
                Ok::<_, crate::mst::MstError>(NodeIndex::from_refs(map, rev))
            })
            .await
            .map_err(XrpcError::from_err)?
            .map_err(XrpcError::from_err)?;
            let r = lookup(&ix, &want);
            view.nodes.lock().install(ix);
            r
        }
    };
    for (c, (key, _)) in refs {
        if let Some(b) = path_end_block(view, snap, did, &key, &c).await? {
            out.push((c, b));
        }
    }
    Ok(out)
}

static INDEX_BUILDS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(4);

/// Keyed by the repo's shared index cell (one per cached repo).
fn index_build_gate(cell: &crate::mst::SharedNodeIndex) -> Arc<tokio::sync::Mutex<()>> {
    type Gates = HashMap<usize, std::sync::Weak<tokio::sync::Mutex<()>>>;
    static GATES: std::sync::LazyLock<parking_lot::Mutex<Gates>> = std::sync::LazyLock::new(Default::default);
    let key = Arc::as_ptr(cell) as usize;
    let mut g = GATES.lock();
    if let Some(gate) = g.get(&key).and_then(|w| w.upgrade()) {
        return gate;
    }
    if g.len() >= 1024 {
        g.retain(|_, w| w.strong_count() > 0);
    }
    let gate = Arc::new(tokio::sync::Mutex::new(()));
    g.insert(key, Arc::downgrade(&gate));
    gate
}

/// The block of node `c` if it ends `key`'s path in the view's tree (a node
/// holding its own first key does).
async fn path_end_block(
    view: &crate::worker::DurableView,
    snap: &slatedb::DbSnapshot,
    did: &str,
    key: &[u8],
    c: &Cid,
) -> XResult<Option<Vec<u8>>> {
    let n = crate::mst_store::path_end(&view.tree.root, snap, did, view.gen, key).await.map_err(XrpcError::from_err)?;
    if n.cid != Some(*c) {
        return Ok(None);
    }
    crate::mst_lazy::node_block(&n).map(Some).map_err(XrpcError::from_err)
}

#[derive(Deserialize)]
pub(super) struct ListReposQ {
    limit: Option<i64>,
    cursor: Option<String>,
}

/// A position in the global listRepos order, (slot, DID): every repo before
/// it was listed. Independent of the shard layout, so a cursor stays valid
/// across splits and merges.
#[derive(Clone, Debug, PartialEq)]
pub(super) struct RepoPos {
    pub slot: u32,
    pub after: Option<String>,
}

impl RepoPos {
    fn start() -> RepoPos {
        RepoPos { slot: 0, after: None }
    }

    fn after(did: &str) -> RepoPos {
        RepoPos { slot: crate::slots::slot_of(did) as u32, after: Some(did.to_string()) }
    }
}

/// `{slot}:{last DID}`, the DID empty at a slot's start.
pub(super) fn parse_list_cursor(c: &str) -> XResult<RepoPos> {
    let bad = || XrpcError::bad("InvalidRequest", "Malformed cursor");
    let (p, d) = c.split_once(':').ok_or_else(bad)?;
    let slot = p.parse::<u32>().map_err(|_| bad())?;
    if slot >= crate::slots::SLOTS || (!d.is_empty() && crate::slots::slot_of(d) as u32 != slot) {
        return Err(bad());
    }
    Ok(RepoPos { slot, after: (!d.is_empty()).then(|| d.to_string()) })
}

fn list_cursor(p: &RepoPos) -> String {
    format!("{}:{}", p.slot, p.after.as_deref().unwrap_or(""))
}

#[derive(serde::Serialize, Deserialize)]
pub(super) struct RepoView {
    did: String,
    head: String,
    rev: String,
    active: bool,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    status: Option<String>,
}

/// As served, and as the internal page endpoint returns it.
#[derive(serde::Serialize, Deserialize)]
pub(super) struct ReposPage {
    repos: Vec<RepoView>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    cursor: Option<String>,
}

impl ReposPage {
    pub(super) fn new(repos: Vec<RepoView>, next: Option<RepoPos>) -> ReposPage {
        ReposPage { repos, cursor: next.as_ref().map(list_cursor) }
    }
}

fn json_response(body: Vec<u8>) -> Response {
    ([(header::CONTENT_TYPE, "application/json")], Body::from(body)).into_response()
}

fn unowned(shard: crate::slots::ShardId) -> XrpcError {
    XrpcError {
        status: StatusCode::SERVICE_UNAVAILABLE,
        error: "PartitionUnavailable".into(),
        message: format!("shard {shard} has no reachable owner; retry"),
    }
}

/// Up to `limit` repos from `pos` on, through the shards this node holds
/// consecutively, and where the next page starts (None: past the last
/// slot). 503 if `pos`'s shard isn't ours. Also served to peers by
/// /internal/v1/sync/listRepos.
pub(super) async fn list_repos_local(
    app: &App,
    pos: RepoPos,
    limit: usize,
) -> XResult<(Vec<RepoView>, Option<RepoPos>)> {
    let mut repos = Vec::with_capacity(limit.min(1000));
    match list_repos_into(app, pos, limit, &mut repos).await {
        Ok(next) => Ok((repos, next)),
        Err(e) => match repos.last() {
            None => Err(e),
            // a shard read failed partway (handoff, store error): what was
            // listed stands
            Some(last) => {
                tracing::warn!("listRepos: ending the page early: {}", e.message);
                let next = RepoPos::after(&last.did);
                Ok((repos, Some(next)))
            }
        },
    }
}

/// Heads merge-joined with accounts in (slot, DID) order, each shard from
/// one snapshot.
async fn list_repos_into(app: &App, pos: RepoPos, limit: usize, repos: &mut Vec<RepoView>) -> XResult<Option<RepoPos>> {
    #[derive(Deserialize)]
    struct Status<'a> {
        #[serde(borrow, default)]
        status: Option<std::borrow::Cow<'a, str>>,
    }
    let layout = app.partitions.layout();
    let mut pos = pos;
    let mut first = true;
    let fam = state::HEAD_FAMILY.len();
    while pos.slot < crate::slots::SLOTS {
        let range = layout.shards[layout.index_of_slot(pos.slot as u16)];
        let Some(p) = app.partitions.get(range.id) else {
            if first {
                return Err(unowned(range.id));
            }
            return Ok(Some(pos));
        };
        first = false;
        let (h_lo, a_lo) = match &pos.after {
            Some(d) => ([state::head_key(d), vec![0]].concat(), [state::account_key(d), vec![0]].concat()),
            None => (
                state::slot_family(pos.slot as u16, state::HEAD_FAMILY),
                state::slot_family(pos.slot as u16, state::ACCOUNT_FAMILY),
            ),
        };
        let snap = p.db.snapshot().map_err(XrpcError::from_err)?;
        let opts = slatedb::config::ScanOptions { read_ahead_bytes: 1 << 20, max_fetch_tasks: 2, ..Default::default() };
        let mut heads = state::FamilyScan::new(snap.as_ref(), state::HEAD_FAMILY, Some(h_lo), &opts)
            .await
            .map_err(XrpcError::from_err)?;
        let mut accts = state::FamilyScan::new(snap.as_ref(), state::ACCOUNT_FAMILY, Some(a_lo), &opts)
            .await
            .map_err(XrpcError::from_err)?;
        let mut acct_peek: Option<slatedb::KeyValue> = None;
        let mut acct_done = false;
        while repos.len() < limit {
            let Some(kv) = heads.next().await.map_err(XrpcError::from_err)? else {
                break;
            };
            // a shard's DB holds only its slots; stop at its end regardless
            if state::key_slot(&kv.key).is_none_or(|s| s as u32 >= range.hi) {
                break;
            }
            let head_pos = state::slot_did(&kv.key, fam);
            let head = Head::decode(&kv.value).map_err(XrpcError::from_err)?;
            let mut status = None;
            while !acct_done {
                if acct_peek.is_none() {
                    acct_peek = accts.next().await.map_err(XrpcError::from_err)?;
                    if acct_peek.is_none() {
                        acct_done = true;
                        break;
                    }
                }
                let a = acct_peek.as_ref().unwrap();
                match state::slot_did(&a.key, fam).cmp(&head_pos) {
                    std::cmp::Ordering::Less => acct_peek = None,
                    std::cmp::Ordering::Equal => {
                        status = serde_json::from_slice::<Status>(&a.value)
                            .ok()
                            .and_then(|s| s.status.map(|s| s.into_owned()));
                        acct_peek = None;
                        break;
                    }
                    std::cmp::Ordering::Greater => break,
                }
            }
            repos.push(RepoView {
                did: String::from_utf8_lossy(head_pos.1).into_owned(),
                head: head.commit.to_string(),
                rev: head.rev.to_string(),
                active: status.is_none(),
                status,
            });
        }
        if repos.len() >= limit {
            return Ok(repos.last().map(|r| RepoPos::after(&r.did)));
        }
        pos = RepoPos { slot: range.hi, after: None };
    }
    Ok(None)
}

/// A page crossing many small or empty shards owned by different nodes
/// returns early with a cursor.
const LIST_REPOS_MAX_HOPS: usize = 16;

/// A repo that exists for the whole enumeration is listed exactly once, even
/// across shard splits and merges; one created or deleted meanwhile may or
/// may not be. An unreachable owner ends the page early with a cursor at its
/// shard (503 if nothing was listed), so a relay never skips repos.
async fn list_repos(State(app): AppState, Query(q): Query<ListReposQ>) -> XResult<Response> {
    let limit = super::extract::limit_param(q.limit, 500, 1, 1000)?;
    let mut pos = Some(match &q.cursor {
        Some(c) => parse_list_cursor(c)?,
        None => RepoPos::start(),
    });
    let mut repos: Vec<RepoView> = Vec::new();
    let mut hops = 0;
    while let Some(p) = pos.clone() {
        if repos.len() >= limit || hops == LIST_REPOS_MAX_HOPS {
            break;
        }
        hops += 1;
        let want = limit - repos.len();
        let shard = app.partitions.layout().shard_of_slot(p.slot as u16);
        if app.partitions.get(shard).is_some() || app.cluster.is_none() {
            match list_repos_local(&app, p, want).await {
                Ok((r, next)) => {
                    repos.extend(r);
                    pos = next;
                    continue;
                }
                Err(e) if repos.is_empty() => return Err(e),
                // what earlier owners listed stands: the cursor resumes here
                Err(e) => {
                    tracing::warn!(
                        shard = shard.0,
                        "listRepos: local shard failed, ending the page early: {}",
                        e.message
                    );
                    break;
                }
            }
        }
        match owner_page(&app, shard, &p, want).await {
            Ok((body, page)) => {
                // the owner's page is the whole answer: pass its bytes on
                if repos.is_empty() && (page.repos.len() == want || page.cursor.is_none()) {
                    return Ok(json_response(body.to_vec()));
                }
                repos.extend(page.repos);
                pos = page.cursor.as_deref().map(parse_list_cursor).transpose()?;
            }
            Err(e) if repos.is_empty() => return Err(e),
            Err(e) => {
                tracing::warn!(shard = shard.0, "listRepos: owner page failed, ending the page early: {}", e.message);
                break;
            }
        }
    }
    let page = ReposPage::new(repos, pos);
    Ok(json_response(serde_json::to_vec(&page).map_err(XrpcError::from_err)?))
}

async fn owner_page(
    app: &App,
    shard: crate::slots::ShardId,
    pos: &RepoPos,
    limit: usize,
) -> XResult<(Bytes, ReposPage)> {
    let c = app.cluster.as_ref().ok_or_else(|| unowned(shard))?;
    let Some((owner, addr)) = c.owner_of(shard).filter(|(id, _)| *id != c.cfg.node_id) else {
        return Err(unowned(shard));
    };
    let body = super::internal::owner_list_repos(app, &addr, &list_cursor(pos), limit).await.map_err(|e| {
        tracing::warn!(%owner, shard = shard.0, "listRepos owner page: {}", e.message);
        XrpcError { message: format!("shard {shard}: {}", e.message), ..unowned(shard) }
    })?;
    let page: ReposPage = serde_json::from_slice(&body).map_err(|e| {
        tracing::warn!(%owner, shard = shard.0, "listRepos owner page: {e}");
        unowned(shard)
    })?;
    Ok((body, page))
}

#[derive(Deserialize)]
pub(super) struct ByCollectionQ {
    collection: String,
    limit: Option<i64>,
    cursor: Option<String>,
}

/// DIDs on this node's shards, and the shards it owns. Also served to peers
/// by /internal/v1/sync/listReposByCollection.
pub(super) async fn list_repos_by_collection_local(
    app: &App,
    q: &ByCollectionQ,
) -> XResult<(Vec<String>, Vec<crate::slots::ShardId>)> {
    if !super::syntax::valid_nsid(&q.collection) {
        return Err(XrpcError::bad("InvalidRequest", "collection must be a valid nsid"));
    }
    let limit = super::extract::limit_param(q.limit, 500, 1, 2000)?;
    let fam = state::collection_family(&q.collection);
    let start = q.cursor.as_ref().map(|c| [state::collection_key(&q.collection, c), vec![0]].concat());
    let owned = app.partitions.owned();
    let ids: Vec<crate::slots::ShardId> = owned.iter().map(|p| p.id).collect();
    let mut scans = Vec::new();
    for p in owned {
        let (fam, start) = (fam.clone(), start.clone());
        scans.push(async move {
            let mut iter = state::FamilyScan::new(p.db.as_ref(), &fam, start, &Default::default())
                .await
                .map_err(XrpcError::from_err)?;
            let mut dids = Vec::new();
            while dids.len() < limit {
                let Some(kv) = iter.next().await.map_err(XrpcError::from_err)? else {
                    break;
                };
                dids.push(String::from_utf8_lossy(&state::key_body(&kv.key)[fam.len()..]).into_owned());
            }
            Ok::<_, XrpcError>(dids)
        });
    }
    let mut all = Vec::new();
    for r in futures::future::join_all(scans).await {
        all.extend(r?);
    }
    sort_slot_order(&mut all);
    all.truncate(limit);
    Ok((all, ids))
}

fn sort_slot_order(dids: &mut Vec<String>) {
    dids.sort_by_cached_key(|d| (crate::slots::slot_of(d), d.clone()));
    dids.dedup();
}

/// The (slot, DID) order spans every shard, so a shard with no answering
/// owner fails the page with 503.
async fn list_repos_by_collection(State(app): AppState, Query(q): Query<ByCollectionQ>) -> XResult<Json<J>> {
    let limit = super::extract::limit_param(q.limit, 500, 1, 2000)?;
    let (mut all, owned) = list_repos_by_collection_local(&app, &q).await?;
    let mut query = vec![("collection", q.collection.clone()), ("limit", limit.to_string())];
    if let Some(c) = &q.cursor {
        query.push(("cursor", c.clone()));
    }
    let g = super::internal::gather(&app, "/internal/v1/sync/listReposByCollection", &query).await;
    let mut covered: HashSet<crate::slots::ShardId> = owned.into_iter().collect();
    for r in g.replies {
        covered.extend(r.owned);
        all.extend(serde_json::from_value::<Vec<String>>(r.body["repos"].clone()).unwrap_or_default());
    }
    if let Some(m) = app.partitions.layout().ids().into_iter().find(|p| !covered.contains(p)) {
        return Err(unowned(m));
    }
    sort_slot_order(&mut all);
    all.truncate(limit);
    let mut out = json!({"repos": all.iter().map(|d| json!({"did": d})).collect::<Vec<_>>()});
    if all.len() == limit {
        out["cursor"] = json!(all.last());
    }
    Ok(Json(out))
}

#[derive(Deserialize)]
struct SubQ {
    cursor: Option<i64>,
    /// vlpds extension: "k/n", only events whose repo DID's hash slot is in
    /// slice k of n of the 65,536 slots (`slots::SlotRange`).
    shard: Option<String>,
}

async fn subscribe_repos(State(app): AppState, Query(q): Query<SubQ>, req: axum::extract::Request) -> Response {
    let shard = match q.shard.as_deref().map(crate::slots::SlotRange::parse) {
        None => None,
        Some(Some(r)) => Some(r),
        Some(None) => {
            return XrpcError::bad("InvalidRequest", "shard must be k/n with 0 <= k < n <= 65536").into_response();
        }
    };
    // a peer-forwarded request's vouched-for client, not the forwarding node
    let client = crate::ratelimit::request_client_ip(req.headers(), req.extensions(), &app.ratelimit.trusted);
    let ua = req.headers().get(axum::http::header::USER_AGENT).and_then(|v| v.to_str().ok()).unwrap_or("");
    // cache reads only: a miss starts a background lookup, the listing fills in later
    let ptr = client.and_then(|ip| app.ptr.get(ip));
    if let Some(ip) = client {
        app.asn.get(ip);
    }
    let verified = ptr.as_ref().filter(|p| p.verified).and_then(|p| p.name.as_deref());
    let relay = app.crawlers.relay_hint(&app.store, client, ua, verified);
    app.firehose.upgrade(req, q.cursor, shard, client, relay)
}

/// "https://pds.example.com/" -> "pds.example.com" (port kept if present).
pub(super) fn public_hostname(url: &str) -> String {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    rest.split('/').next().unwrap_or(rest).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_parsing() {
        let p = query_pairs("did=did%3Aplc%3Aabc&cids=bafy1&cids=bafy2&x=a+b&bad=%zz&t=%4");
        assert_eq!(p[0], ("did".into(), "did:plc:abc".into()));
        assert_eq!(p[1].1, "bafy1");
        assert_eq!(p[2].1, "bafy2");
        assert_eq!(p[3].1, "a b");
        assert_eq!(p[4].1, "%zz");
        assert_eq!(p[5].1, "%4");
    }

    #[test]
    fn hostnames() {
        assert_eq!(public_hostname("https://pds.example.com/"), "pds.example.com");
        assert_eq!(public_hostname("http://localhost:2583"), "localhost:2583");
    }
}
