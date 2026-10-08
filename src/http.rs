//! The PDS's outbound HTTP clients, one per role, each built once and shared
//! so connections are reused (DESIGN.md "HTTP"): [`PeerClient`] (node to
//! node), [`dedicated`] (key material), and [`proxy`] and [`h1`] (the
//! AppView proxy). vlatproto's `http` has the shared ones: `public`
//! (operator-configured upstreams) and `guarded` (URLs derived from
//! untrusted input).
//!
//! No client follows redirects: forwarded and proxied responses go back to
//! the caller as they are, and a redirect from a user-controlled host could
//! point anywhere.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock};
use std::task::{Context, Poll};
use std::time::Duration;
use vlatproto::http::{base, outbound, outbound_no_read_timeout};

/// reqwest multiplexes every request to a host over ONE h2 connection;
/// several spread the connection driver's work over threads and keep one
/// stalled connection from black-holing every forward.
pub const DEFAULT_PEER_CONNECTIONS: usize = 4;

/// An operator-configured upstream holding key material (Vault) with its
/// own pool, optionally also trusting `ca_pem` (PEM certificates) for a
/// private PKI, or only it with `ca_only`. It ignores `HTTP(S)_PROXY`: a
/// proxy set for other egress mustn't see key traffic. A pool shared across
/// tokio runtimes (tests) hands out connections whose runtime is gone, so
/// each caller builds its own.
pub fn dedicated(
    role: &'static str,
    max_idle: usize,
    ca_pem: Option<&[u8]>,
    ca_only: bool,
) -> anyhow::Result<reqwest::Client> {
    let mut b = outbound(role, max_idle).no_proxy();
    anyhow::ensure!(!ca_only || ca_pem.is_some(), "trusting only the CA bundle needs one");
    if let Some(pem) = ca_pem {
        let certs = reqwest::Certificate::from_pem_bundle(pem).map_err(|e| anyhow::anyhow!("CA bundle: {e}"))?;
        anyhow::ensure!(!certs.is_empty(), "CA bundle holds no PEM certificate");
        b = if ca_only { b.tls_certs_only(certs) } else { b.tls_certs_merge(certs) };
    }
    Ok(b.build()?)
}

/// The proxy client for `https://` upstreams (plain `http://` uses [`h1`]),
/// one per IO thread: a single pool is one mutex that every proxied request
/// takes twice (checkout, return), and that contention showed up in proxy
/// CPU profiles. The proxy bounds head and body idle time itself.
pub fn proxy() -> &'static reqwest::Client {
    static C: LazyLock<Vec<reqwest::Client>> = LazyLock::new(|| {
        let n = std::thread::available_parallelism().map_or(8, |n| n.get()).clamp(2, 64);
        (0..n).map(|_| outbound_no_read_timeout("public", 1024).build().expect("reqwest client")).collect()
    });
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    thread_local! {
        static SHARD: usize = NEXT.fetch_add(1, Ordering::Relaxed);
    }
    &C[SHARD.with(|s| *s) % C.len()]
}

/// Plain-HTTP/1.1 client for the proxy fast path (an operator-configured
/// `http://` AppView): hyper's connection API under a lock-light pool, so a
/// request normally takes only its own thread's uncontended slot lock and
/// runs no URL parsing or retry/redirect layers.
///
/// Idle connections sit in per-thread slots; a thread whose slot is empty
/// steals from another before connecting, so the connection count follows
/// concurrency rather than threads x peak when tasks hop threads. At most
/// [`MAX_CONNS`] are open per host; a request at the cap waits for one.
///
/// A connection is reused only once its response body was read to the end;
/// one dropped mid-body is closed, which also ends the upstream exchange. A
/// request that fails unwritten on a reused connection (closed while idle)
/// is retried once on a new one, like hyper-util's pool.
///
/// Hosts are never dropped: only operator-configured upstreams use this.
pub mod h1 {
    use super::*;
    use axum::body::Body;
    use bytes::Bytes;
    use hyper::client::conn::http1::SendRequest;
    use std::cell::Cell;
    use std::time::Instant;
    use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};

    use axum::http;

    pub type Response = http::Response<PooledBody>;

    pub const MAX_CONNS: usize = 1024;
    /// Below the 90-120 s idle close of common load balancers.
    pub const H1_IDLE: Duration = Duration::from_secs(60);
    const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
    /// A backstop: a returned connection or a freed permit wakes a waiter first.
    const WAIT_RECHECK: Duration = Duration::from_millis(50);

    struct Idle {
        conn: SendRequest<Body>,
        since: Instant,
    }

    /// Most recent last. Padded to its own cache lines: threads update their
    /// own slots on every request.
    #[repr(align(128))]
    struct Slot {
        idle: parking_lot::Mutex<Vec<Idle>>,
        /// `idle.len()`, readable without the lock so stealers skip empty slots
        len: AtomicUsize,
    }

    pub struct Host {
        authority: Box<str>,
        slots: Box<[Slot]>,
        /// one permit per open connection
        open: Arc<Semaphore>,
        max: usize,
        waiting: AtomicUsize,
        returned: Notify,
    }

    static HOSTS: parking_lot::RwLock<Vec<&'static Host>> = parking_lot::RwLock::new(Vec::new());
    static NEXT_SLOT: AtomicUsize = AtomicUsize::new(0);

    thread_local! {
        static SLOT: usize = NEXT_SLOT.fetch_add(1, Ordering::Relaxed);
        /// the last host this thread used (nearly always the one AppView)
        static LAST: Cell<Option<&'static Host>> = const { Cell::new(None) };
    }

    /// `max` applies only if the pool is new.
    pub(crate) fn host_with(authority: &str, max: usize) -> &'static Host {
        if let Some(h) = LAST.get().filter(|h| *h.authority == *authority) {
            return h;
        }
        let found = HOSTS.read().iter().copied().find(|h| *h.authority == *authority);
        let h = found.unwrap_or_else(|| {
            let mut hosts = HOSTS.write();
            if let Some(h) = hosts.iter().copied().find(|h| *h.authority == *authority) {
                return h;
            }
            let n = std::thread::available_parallelism().map_or(8, |n| n.get()).clamp(1, 64);
            let h: &'static Host = Box::leak(Box::new(Host {
                authority: authority.into(),
                slots: (0..n).map(|_| Slot { idle: Default::default(), len: AtomicUsize::new(0) }).collect(),
                open: Arc::new(Semaphore::new(max.max(1))),
                max: max.max(1),
                waiting: AtomicUsize::new(0),
                returned: Notify::new(),
            }));
            hosts.push(h);
            h
        });
        LAST.set(Some(h));
        h
    }

    pub fn host(authority: &str) -> &'static Host {
        host_with(authority, MAX_CONNS)
    }

    impl Host {
        /// Idle and in use.
        pub fn open_connections(&self) -> usize {
            self.max - self.open.available_permits()
        }

        pub fn idle_connections(&self) -> usize {
            self.slots.iter().map(|s| s.len.load(Ordering::Relaxed)).sum()
        }

        fn my_slot(&self) -> usize {
            SLOT.with(|s| *s) % self.slots.len()
        }

        fn take_from(&self, i: usize) -> Option<SendRequest<Body>> {
            let slot = &self.slots[i];
            let mut idle = slot.idle.lock();
            // the oldest sit at the front
            if idle.first().is_some_and(|c| c.since.elapsed() > H1_IDLE) {
                idle.retain(|c| c.since.elapsed() <= H1_IDLE);
            }
            let mut got = None;
            // (one just handed back may not be ready yet: its connection task
            // finishes the previous exchange first; `send` waits for it)
            while let Some(c) = idle.pop() {
                if !c.conn.is_closed() {
                    got = Some(c.conn);
                    break;
                }
            }
            slot.len.store(idle.len(), Ordering::SeqCst);
            got
        }

        fn take(&self) -> Option<SendRequest<Body>> {
            let mine = self.my_slot();
            if self.slots[mine].len.load(Ordering::SeqCst) > 0 {
                if let Some(c) = self.take_from(mine) {
                    return Some(c);
                }
            }
            let n = self.slots.len();
            (1..n)
                .map(|k| (mine + k) % n)
                .filter(|&i| self.slots[i].len.load(Ordering::SeqCst) > 0)
                .find_map(|i| self.take_from(i))
        }

        fn put(&self, conn: SendRequest<Body>) {
            if conn.is_closed() {
                return;
            }
            let slot = &self.slots[self.my_slot()];
            {
                let mut idle = slot.idle.lock();
                idle.push(Idle { conn, since: Instant::now() });
                slot.len.store(idle.len(), Ordering::SeqCst);
            }
            // (SeqCst on both sides: a waiter either sees this connection
            // in its re-check or is counted here)
            if self.waiting.load(Ordering::SeqCst) > 0 {
                self.returned.notify_one();
            }
        }

        /// Returns whether the connection was reused.
        async fn checkout(&'static self, role: &'static str) -> Result<(SendRequest<Body>, bool), BoxError> {
            if let Some(c) = self.take() {
                return Ok((c, true));
            }
            if let Ok(p) = self.open.clone().try_acquire_owned() {
                return Ok((connect(role, self, p).await?, false));
            }
            crate::metrics::HTTP_CLIENT_POOL_WAITS.with_label_values(&[role]).inc();
            struct Waiting<'a>(&'a AtomicUsize);
            impl Drop for Waiting<'_> {
                fn drop(&mut self) {
                    self.0.fetch_sub(1, Ordering::SeqCst);
                }
            }
            self.waiting.fetch_add(1, Ordering::SeqCst);
            let _waiting = Waiting(&self.waiting);
            loop {
                let returned = self.returned.notified();
                tokio::pin!(returned);
                returned.as_mut().enable();
                if let Some(c) = self.take() {
                    return Ok((c, true));
                }
                tokio::select! {
                    p = self.open.clone().acquire_owned() => {
                        let p = p.map_err(|_| "pool closed")?;
                        return Ok((connect(role, self, p).await?, false));
                    }
                    _ = &mut returned => {}
                    _ = tokio::time::sleep(WAIT_RECHECK) => {}
                }
            }
        }

        async fn fresh(&'static self, role: &'static str) -> Result<SendRequest<Body>, BoxError> {
            let p = match self.open.clone().try_acquire_owned() {
                Ok(p) => p,
                Err(_) => self.open.clone().acquire_owned().await.map_err(|_| "pool closed")?,
            };
            connect(role, self, p).await
        }
    }

    /// The connection's task holds `permit` until the connection closes.
    async fn connect(
        role: &'static str,
        host: &Host,
        permit: OwnedSemaphorePermit,
    ) -> Result<SendRequest<Body>, BoxError> {
        vlatproto::http::HTTP_CLIENT_CONNECTS.with_label_values(&[role]).inc();
        let authority = &*host.authority;
        let connect = async {
            let mut last = None;
            for addr in tokio::net::lookup_host(authority).await? {
                let sock =
                    if addr.is_ipv4() { tokio::net::TcpSocket::new_v4()? } else { tokio::net::TcpSocket::new_v6()? };
                sock.set_keepalive(true)?;
                sock.set_nodelay(true)?;
                match sock.connect(addr).await {
                    Ok(s) => return Ok(s),
                    Err(e) => last = Some(e),
                }
            }
            Err(last.unwrap_or_else(|| std::io::Error::other("no address")))
        };
        let tcp = tokio::time::timeout(CONNECT_TIMEOUT, connect).await.map_err(|_| "connect timeout")??;
        let (send, conn) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tcp)).await?;
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                tracing::debug!("upstream connection: {e}");
            }
            drop(permit);
        });
        Ok(send)
    }

    type BoxError = Box<dyn std::error::Error + Send + Sync>;

    /// `req` has an origin-form URI; Host is set here from `authority`.
    pub async fn send(role: &'static str, authority: &str, mut req: http::Request<Body>) -> Result<Response, BoxError> {
        let host = self::host(authority);
        let h = req.headers_mut();
        h.insert(http::header::HOST, http::HeaderValue::from_str(authority)?);
        h.entry(http::header::USER_AGENT).or_insert(http::HeaderValue::from_static(vlatproto::http::user_agent()));
        h.entry(http::header::ACCEPT).or_insert(http::HeaderValue::from_static("*/*"));
        // a request body still uploading when the response ends keeps its
        // connection busy: such a connection is not pooled (PooledBody)
        let req_done = match hyper::body::Body::size_hint(req.body()).exact() {
            Some(0) => None,
            _ => {
                let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
                let body = std::mem::take(req.body_mut());
                *req.body_mut() = Body::new(TrackEnd { body, done: done.clone() });
                Some(done)
            }
        };
        let (mut conn, mut reused) = host.checkout(role).await?;
        if conn.ready().await.is_err() {
            drop(conn);
            (conn, reused) = (host.fresh(role).await?, false);
        }
        let resp = match conn.try_send_request(req).await {
            Ok(r) => r,
            Err(mut e) => match e.take_message() {
                // never written: the idle connection was closed under us
                Some(req) if reused => {
                    drop(conn);
                    conn = host.fresh(role).await?;
                    conn.send_request(req).await?
                }
                _ => return Err(e.into_error().into()),
            },
        };
        let (parts, body) = resp.into_parts();
        let body = PooledBody { body, conn: Some(conn), host, req_done };
        Ok(http::Response::from_parts(parts, body))
    }

    struct TrackEnd {
        body: Body,
        done: Arc<std::sync::atomic::AtomicBool>,
    }

    impl hyper::body::Body for TrackEnd {
        type Data = Bytes;
        type Error = axum::Error;

        fn poll_frame(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Option<Result<hyper::body::Frame<Bytes>, axum::Error>>> {
            let r = std::pin::Pin::new(&mut self.body).poll_frame(cx);
            if matches!(r, Poll::Ready(None)) || (matches!(r, Poll::Ready(Some(Ok(_)))) && self.body.is_end_stream()) {
                self.done.store(true, Ordering::Release);
            }
            r
        }

        fn is_end_stream(&self) -> bool {
            self.body.is_end_stream()
        }

        fn size_hint(&self) -> hyper::body::SizeHint {
            self.body.size_hint()
        }
    }

    pub struct PooledBody {
        body: hyper::body::Incoming,
        conn: Option<SendRequest<Body>>,
        host: &'static Host,
        /// None: no request body
        req_done: Option<Arc<std::sync::atomic::AtomicBool>>,
    }

    impl PooledBody {
        /// One whose upload is still going (the upstream answered early) is
        /// not pooled: the next request on it would wait for that upload.
        fn release(&mut self) {
            if hyper::body::Body::is_end_stream(&self.body) {
                if let Some(c) = self.conn.take() {
                    if self.req_done.as_ref().is_none_or(|d| d.load(Ordering::Acquire)) {
                        self.host.put(c);
                    }
                }
            }
        }
    }

    impl Drop for PooledBody {
        fn drop(&mut self) {
            // an empty body may never be polled
            self.release();
        }
    }

    impl hyper::body::Body for PooledBody {
        type Data = Bytes;
        type Error = hyper::Error;

        fn poll_frame(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Option<Result<hyper::body::Frame<Bytes>, hyper::Error>>> {
            let r = std::pin::Pin::new(&mut self.body).poll_frame(cx);
            // readers stop at `is_end_stream` (a known length), before None
            if matches!(r, Poll::Ready(None)) || self.body.is_end_stream() {
                self.release();
            }
            r
        }

        fn is_end_stream(&self) -> bool {
            self.body.is_end_stream()
        }

        fn size_hint(&self) -> hyper::body::SizeHint {
            self.body.size_hint()
        }
    }
}

/// Write-progress deadlines for response bodies streamed from an upstream to
/// a client.
///
/// The server polls a response body only when it can send more, so a client
/// that stops reading leaves the upstream busy as long as it likes: a peer
/// h2 stream holds its unread bytes out of the connection's flow-control
/// window (enough of them stall every forward on that connection), and a
/// pooled AppView connection is never returned. The upstream calls' own
/// deadlines don't see this.
///
/// A sweeper thread drops the upstream body of every [`Watched`] body not
/// polled within [`WRITE_STALL`] of handing out a chunk (or the head); a
/// later poll errors, which resets the client's stream. An upstream that
/// keeps the body waiting is not a stall.
pub mod stall {
    use super::*;
    use bytes::Bytes;
    use std::sync::atomic::AtomicU64;
    use std::sync::Weak;
    use std::time::Instant;

    /// Generous: a client reading at all is polled far more often.
    pub const WRITE_STALL: Duration = Duration::from_secs(30);
    const SWEEP: Duration = Duration::from_secs(1);
    const SHARDS: usize = 16;

    static LIMIT_MS: AtomicU64 = AtomicU64::new(WRITE_STALL.as_millis() as u64);
    static EPOCH: LazyLock<Instant> = LazyLock::new(Instant::now);
    static STALLED: AtomicU64 = AtomicU64::new(0);

    /// Tests.
    pub fn set_limit(d: Duration) {
        LIMIT_MS.store(d.as_millis().max(1) as u64, Ordering::Relaxed);
    }

    pub fn stalled_total() -> u64 {
        STALLED.load(Ordering::Relaxed)
    }

    /// Never 0.
    fn now_ms() -> u64 {
        EPOCH.elapsed().as_millis() as u64 + 1
    }

    type BoxError = Box<dyn std::error::Error + Send + Sync>;

    trait Reap: Send + Sync {
        fn stalled(&self, now: u64, limit: u64) -> bool;
        /// Drops the upstream body if it is (still) stalled at `now`.
        fn reap(&self, now: u64, limit: u64) -> bool;
    }

    struct Registry {
        shards: Vec<parking_lot::Mutex<Vec<Weak<dyn Reap>>>>,
        next: AtomicUsize,
    }

    static REG: LazyLock<Registry> = LazyLock::new(|| {
        std::thread::Builder::new()
            .name("vlpds-stall-sweep".into())
            .spawn(|| loop {
                std::thread::sleep(SWEEP);
                sweep();
            })
            .expect("stall sweeper thread");
        Registry { shards: (0..SHARDS).map(|_| Default::default()).collect(), next: AtomicUsize::new(0) }
    });

    thread_local! {
        static SHARD: usize = REG.next.fetch_add(1, Ordering::Relaxed) % SHARDS;
    }

    fn register(w: Weak<dyn Reap>) {
        let i = SHARD.with(|s| *s);
        REG.shards[i].lock().push(w);
    }

    fn sweep() -> usize {
        let (now, limit) = (now_ms(), LIMIT_MS.load(Ordering::Relaxed));
        let mut stalled = Vec::new();
        for s in &REG.shards {
            s.lock().retain(|w| match w.upgrade() {
                None => false,
                Some(e) if e.stalled(now, limit) => {
                    stalled.push(e);
                    false
                }
                Some(_) => true,
            });
        }
        // (dropped outside the shard locks)
        let mut n = 0;
        for e in stalled {
            if e.reap(now, limit) {
                n += 1;
            } else {
                // polled as we looked: back on the list
                register(Arc::downgrade(&e));
            }
        }
        if n > 0 {
            STALLED.fetch_add(n as u64, Ordering::Relaxed);
            crate::metrics::HTTP_STALLED_BODIES.inc_by(n as u64);
            tracing::info!("dropped {n} upstream response bodies whose clients stopped reading");
        }
        n
    }

    struct Shared<B> {
        /// None once dropped for a stall.
        body: parking_lot::Mutex<Option<B>>,
        /// When a chunk (not the last) was handed out with no poll since; 0 =
        /// not waiting on the client. Written under `body`'s lock.
        waiting: AtomicU64,
    }

    impl<B: Send> Reap for Shared<B> {
        fn stalled(&self, now: u64, limit: u64) -> bool {
            let w = self.waiting.load(Ordering::Relaxed);
            w != 0 && now.saturating_sub(w) >= limit
        }

        fn reap(&self, now: u64, limit: u64) -> bool {
            // a body being polled right now is not stalled
            let Some(mut g) = self.body.try_lock() else { return false };
            if !self.stalled(now, limit) {
                return false;
            }
            let b = g.take();
            drop(g);
            drop(b);
            true
        }
    }

    enum State<B> {
        Own(B),
        Shared(Arc<Shared<B>>),
    }

    /// `H` is held until the body is dropped (e.g. an admission slot).
    pub struct Watched<B, H = ()> {
        state: State<B>,
        _hold: H,
    }

    impl<B: hyper::body::Body + Send + 'static> Watched<B, ()> {
        pub fn new(body: B) -> Self {
            Self::with_hold(body, ())
        }
    }

    impl<B: hyper::body::Body + Send + 'static, H> Watched<B, H> {
        /// Watched from now on: a client whose h2 window is zero from the
        /// start never polls the body at all.
        fn with_hold(body: B, hold: H) -> Self {
            let waiting = if body.is_end_stream() { 0 } else { now_ms() };
            let s = Arc::new(Shared { body: parking_lot::Mutex::new(Some(body)), waiting: AtomicU64::new(waiting) });
            register(Arc::downgrade(&s) as Weak<dyn Reap>);
            Watched { state: State::Shared(s), _hold: hold }
        }

        /// For a body that holds no upstream.
        pub fn unwatched(body: B, hold: H) -> Self {
            Watched { state: State::Own(body), _hold: hold }
        }
    }

    fn stalled_error() -> BoxError {
        "client stopped reading the response".into()
    }

    impl<B, H> hyper::body::Body for Watched<B, H>
    where
        B: hyper::body::Body<Data = Bytes> + Send + Unpin + 'static,
        B::Error: Into<BoxError>,
        H: Unpin,
    {
        type Data = Bytes;
        type Error = BoxError;

        fn poll_frame(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Option<Result<hyper::body::Frame<Bytes>, BoxError>>> {
            match &mut self.state {
                State::Own(b) => std::pin::Pin::new(b).poll_frame(cx).map(|o| o.map(|r| r.map_err(Into::into))),
                State::Shared(s) => {
                    let mut g = s.body.lock();
                    s.waiting.store(0, Ordering::Relaxed);
                    let Some(b) = g.as_mut() else { return Poll::Ready(Some(Err(stalled_error()))) };
                    let r = std::pin::Pin::new(&mut *b).poll_frame(cx);
                    // handed a chunk with more to come: the client's turn
                    // (pending: the upstream's, which has its own deadlines)
                    if matches!(r, Poll::Ready(Some(Ok(_)))) && !b.is_end_stream() {
                        s.waiting.store(now_ms(), Ordering::Relaxed);
                    }
                    r.map(|o| o.map(|r| r.map_err(Into::into)))
                }
            }
        }

        fn is_end_stream(&self) -> bool {
            match &self.state {
                State::Own(b) => b.is_end_stream(),
                State::Shared(s) => s.body.lock().as_ref().is_some_and(|b| b.is_end_stream()),
            }
        }

        fn size_hint(&self) -> hyper::body::SizeHint {
            match &self.state {
                State::Own(b) => b.size_hint(),
                State::Shared(s) => s.body.lock().as_ref().map(|b| b.size_hint()).unwrap_or_default(),
            }
        }
    }

    /// Tests.
    pub fn sweep_now() -> usize {
        sweep()
    }
}

/// Node-to-node client: h2 over peer mTLS, `n` clients (one connection
/// each) per peer origin, picked round-robin. Each origin's TLS config checks
/// that the server's certificate names the node the cluster expects there.
///
/// Bulk downloads (`is_bulk`) go over `n` other connections: clients that
/// read them slowly fill only those connections' flow-control windows, never
/// the ones every other forward shares.
#[derive(Clone)]
pub struct PeerClient(Arc<PeerInner>);

struct PeerInner {
    n: usize,
    /// None: a lone node, whose requests all fail.
    tls: Option<Arc<crate::peer_tls::PeerTls>>,
    registry: Arc<std::sync::OnceLock<Registry>>,
    /// A handful of peers, so a scan.
    origins: parking_lot::RwLock<Vec<(Arc<str>, Arc<Pool>)>>,
}

struct Pool {
    clients: Vec<reqwest::Client>,
    bulk: Vec<reqwest::Client>,
    next: AtomicUsize,
}

impl Pool {
    fn build(n: usize, b: impl Fn() -> reqwest::ClientBuilder) -> reqwest::Result<Pool> {
        let clients = (0..n.max(1)).map(|_| b().build()).collect::<Result<_, _>>()?;
        let bulk = (0..n.max(1)).map(|_| b().build()).collect::<Result<_, _>>()?;
        Ok(Pool { clients, bulk, next: AtomicUsize::new(0) })
    }

    fn pick(&self, path: &str) -> &reqwest::Client {
        let c = if is_bulk(path) { &self.bulk } else { &self.clients };
        if c.len() == 1 {
            return &c[0];
        }
        &c[self.next.fetch_add(1, Ordering::Relaxed) % c.len()]
    }
}

/// Node ids the cluster expects at an origin (`https://host:port`).
pub type Registry = Arc<dyn Fn(&str) -> Vec<String> + Send + Sync>;

const MAX_ORIGINS: usize = 256;

fn is_bulk(path: &str) -> bool {
    matches!(
        path.strip_prefix("/xrpc/"),
        Some("com.atproto.sync.getRepo" | "com.atproto.sync.getBlob" | "com.atproto.sync.getBlocks")
    )
}

pub fn split_origin(url: &str) -> (&str, &str) {
    let start = url.find("://").map_or(0, |i| i + 3);
    match url[start..].find(['/', '?']) {
        Some(i) => url.split_at(start + i),
        None => (url, ""),
    }
}

/// Trusts no CA, so every request fails.
fn refusing() -> &'static reqwest::Client {
    static C: LazyLock<reqwest::Client> = LazyLock::new(|| {
        let tls = rustls::ClientConfig::builder_with_provider(vlatproto::http::tls_provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("TLS 1.3 with the ring provider")
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        base("peer").https_only(true).tls_backend_preconfigured(tls).build().expect("reqwest client")
    });
    &C
}

impl PeerClient {
    /// Until [`PeerClient::set_registry`], any node of the cluster CA is
    /// accepted at any origin.
    pub fn new(n: usize, tls: Arc<crate::peer_tls::PeerTls>) -> PeerClient {
        PeerClient(Arc::new(PeerInner { n, tls: Some(tls), registry: Default::default(), origins: Default::default() }))
    }

    pub fn lone() -> PeerClient {
        PeerClient(Arc::new(PeerInner { n: 1, tls: None, registry: Default::default(), origins: Default::default() }))
    }

    /// Set once, right after the cluster is joined. An origin it names no
    /// node for is refused.
    pub fn set_registry(&self, r: Registry) {
        let _ = self.0.registry.set(r);
    }

    fn client_for(&self, url: &str) -> reqwest::Client {
        let Some(tls) = &self.0.tls else { return refusing().clone() };
        let (origin, rest) = split_origin(url);
        let path = rest.split_once('?').map_or(rest, |(p, _)| p);
        self.origin_pool(tls, origin).pick(path).clone()
    }

    fn origin_pool(&self, tls: &Arc<crate::peer_tls::PeerTls>, origin: &str) -> Arc<Pool> {
        let inner = &self.0;
        if let Some((_, p)) = inner.origins.read().iter().find(|(o, _)| **o == *origin) {
            return p.clone();
        }
        let mut origins = inner.origins.write();
        if let Some((_, p)) = origins.iter().find(|(o, _)| **o == *origin) {
            return p.clone();
        }
        if origins.len() >= MAX_ORIGINS {
            // addresses churn (new IPs per restart): keep the live ones
            if let Some(r) = inner.registry.get() {
                origins.retain(|(o, _)| !r(o).is_empty());
            }
        }
        let o: Arc<str> = origin.into();
        let (reg, key) = (inner.registry.clone(), o.clone());
        let expect = crate::peer_tls::Expect::Lookup(Arc::new(move || reg.get().map(|r| r(&key))));
        let config = tls.client_config(expect, &[b"h2"]);
        let pool = Pool::build(inner.n, || peer_builder().https_only(true).tls_backend_preconfigured(config.clone()))
            .map(Arc::new)
            .unwrap_or_else(|e| {
                tracing::error!(origin, "peer TLS client: {e}");
                Arc::new(Pool {
                    clients: vec![refusing().clone()],
                    bulk: vec![refusing().clone()],
                    next: AtomicUsize::new(0),
                })
            });
        origins.push((o, pool.clone()));
        pool
    }

    pub fn get(&self, url: impl AsRef<str>) -> reqwest::RequestBuilder {
        let u = url.as_ref();
        self.client_for(u).get(u)
    }

    pub fn post(&self, url: impl AsRef<str>) -> reqwest::RequestBuilder {
        let u = url.as_ref();
        self.client_for(u).post(u)
    }

    pub fn request(&self, method: reqwest::Method, url: impl AsRef<str>) -> reqwest::RequestBuilder {
        let u = url.as_ref();
        self.client_for(u).request(method, u)
    }

    /// For a log stream (`wss://`) from `node`; HTTP/1.1 by ALPN since the
    /// stream is an upgrade. None on a lone node.
    pub fn ws_connector(&self, node: &str) -> Option<tokio_tungstenite::Connector> {
        let tls = self.0.tls.as_ref()?;
        let config = tls.client_config(crate::peer_tls::Expect::Node(node.to_string()), &[b"http/1.1"]);
        Some(tokio_tungstenite::Connector::Rustls(Arc::new(config)))
    }
}

/// Peer h2 receive windows. A response the entry node's client doesn't read
/// keeps up to one stream window out of the connection window until
/// [`stall::Watched`] drops it: 64 such responses are needed to stall a
/// connection, while one stream still moves ~5 GB/s at LAN RTTs.
pub const PEER_STREAM_WINDOW: u32 = 1 << 20;
pub const PEER_CONNECTION_WINDOW: u32 = 64 << 20;

/// h2, not HTTP/1.1: forwarding at load needs ~1k concurrent requests per
/// peer, and HTTP/1.1 beyond the pooled connections opens and closes a TCP
/// connection per request.
fn peer_builder() -> reqwest::ClientBuilder {
    base("peer")
        .http2_prior_knowledge()
        .http2_initial_stream_window_size(PEER_STREAM_WINDOW)
        .http2_initial_connection_window_size(PEER_CONNECTION_WINDOW)
        // a half-open connection would otherwise black-hole every forward on
        // it until each one's TTFB deadline: PING every 10 s, idle or not,
        // and drop the connection after 5 s without an answer
        .http2_keep_alive_interval(Duration::from_secs(10))
        .http2_keep_alive_timeout(Duration::from_secs(5))
        .http2_keep_alive_while_idle(true)
        .connect_timeout(Duration::from_secs(1))
        .timeout(Duration::from_secs(15))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn origins_and_bulk_paths() {
        assert_eq!(split_origin("https://10.0.0.1:2584/xrpc/a?b=c"), ("https://10.0.0.1:2584", "/xrpc/a?b=c"));
        assert_eq!(split_origin("http://h:1?x"), ("http://h:1", "?x"));
        assert_eq!(split_origin("http://h:1"), ("http://h:1", ""));
    }

    /// A TLS peer listener of `ca` serving `router`; returns its base URL.
    pub(crate) async fn tls_peer(ca: &crate::peer_tls::tests::TestCa, id: &str, router: axum::Router) -> String {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("https://{}", l.local_addr().unwrap());
        let opts = crate::server::ServeOptions { tls: Some(ca.node(id).server_config()), ..Default::default() };
        tokio::spawn(crate::server::serve_with(l, router, opts));
        url
    }

    #[tokio::test]
    async fn peer_connections_are_reused() {
        let ca = crate::peer_tls::tests::TestCa::new();
        let router = axum::Router::new().route("/", axum::routing::get(|| async { "ok" }));
        let url = format!("{}/", tls_peer(&ca, "server", router).await);
        let peers = PeerClient::new(3, ca.node("client"));
        let count = || vlatproto::http::HTTP_CLIENT_CONNECTS.with_label_values(&["peer"]).get();
        let before = count();
        for _ in 0..60 {
            let r = peers.get(&url).send().await.unwrap();
            assert_eq!(r.version(), reqwest::Version::HTTP_2);
            assert_eq!(r.text().await.unwrap(), "ok");
        }
        // one connection per client (other tests may connect concurrently)
        let opened = count() - before;
        assert!((3..10).contains(&opened), "{opened} connections for 60 requests");
        // never cleartext
        assert!(peers.get(url.replace("https://", "http://")).send().await.is_err());
    }

    #[tokio::test]
    async fn a_node_refuses_origins_the_cluster_doesnt_name() {
        let ca = crate::peer_tls::tests::TestCa::new();
        let router = axum::Router::new().route("/", axum::routing::get(|| async { "ok" }));
        let url = tls_peer(&ca, "server", router).await;
        let peers = PeerClient::new(1, ca.node("client"));
        let known = url.clone();
        peers.set_registry(Arc::new(move |o: &str| if o == known { vec!["server".to_string()] } else { Vec::new() }));
        assert_eq!(peers.get(format!("{url}/")).send().await.unwrap().status(), 200);
        // the same server at an origin no lease or route names
        let alias = url.replace("127.0.0.1", "localhost");
        assert!(peers.get(format!("{alias}/")).send().await.is_err());
        // a lone node reaches no one
        assert!(PeerClient::lone().get(format!("{url}/")).send().await.is_err());
    }

    /// An upstream answering every request with 3,000 bytes after `delay`;
    /// returns its `host:port`.
    async fn h1_upstream(delay: Duration) -> String {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let authority = l.local_addr().unwrap().to_string();
        let router = axum::Router::new().fallback(move || async move {
            tokio::time::sleep(delay).await;
            "x".repeat(3000)
        });
        tokio::spawn(crate::server::serve(l, router));
        authority
    }

    fn h1_get(path: &str) -> axum::http::Request<axum::body::Body> {
        let mut r = axum::http::Request::new(axum::body::Body::empty());
        *r.uri_mut() = path.parse().unwrap();
        r
    }

    fn h1_connects(role: &str) -> u64 {
        vlatproto::http::HTTP_CLIENT_CONNECTS.with_label_values(&[role]).get()
    }

    /// Sends a GET on a new OS thread and reads its body to the end on
    /// another: the request runs on a thread whose own slot is empty, and
    /// the connection goes back to a slot the next request doesn't use first.
    fn h1_hop(rt: &tokio::runtime::Handle, role: &'static str, authority: &str) {
        let (h, a) = (rt.clone(), authority.to_string());
        let resp = std::thread::spawn(move || h.block_on(h1::send(role, &a, h1_get("/hop"))).unwrap()).join().unwrap();
        let h = rt.clone();
        let len = std::thread::spawn(move || {
            h.block_on(axum::body::to_bytes(axum::body::Body::new(resp.into_body()), usize::MAX)).unwrap().len()
        })
        .join()
        .unwrap();
        assert_eq!(len, 3000);
    }

    /// Requests and bodies on ever-new threads: per-thread pools connected
    /// once per hop; the shared slots keep it to one connection per request
    /// in flight (vlpds_http_client_connects_total).
    #[test]
    fn h1_pool_survives_thread_hops() {
        const ROLE: &str = "test-h1-hops";
        let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(4).enable_all().build().unwrap();
        let authority = rt.block_on(h1_upstream(Duration::ZERO));
        for _ in 0..64 {
            h1_hop(rt.handle(), ROLE, &authority);
        }
        assert_eq!(h1_connects(ROLE), 1, "sequential requests hopping threads");
        let host = h1::host(&authority);
        assert_eq!((host.open_connections(), host.idle_connections()), (1, 1));

        // 8 concurrent chains of hopping requests: at most 8 connections
        let chains: Vec<_> = (0..8)
            .map(|_| {
                let (h, a) = (rt.handle().clone(), authority.clone());
                std::thread::spawn(move || {
                    for _ in 0..24 {
                        h1_hop(&h, ROLE, &a);
                    }
                })
            })
            .collect();
        for c in chains {
            c.join().unwrap();
        }
        let n = h1_connects(ROLE);
        assert!(n <= 8, "{n} connections for 8 chains of thread-hopping requests");
        assert_eq!(host.open_connections() as u64, n);
    }

    /// At most `max` connections per host: requests beyond it wait for one
    /// to come back instead of connecting.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn h1_pool_is_capped() {
        const ROLE: &str = "test-h1-cap";
        let authority = h1_upstream(Duration::from_millis(20)).await;
        let host = h1::host_with(&authority, 4);
        let tasks: Vec<_> = (0..32)
            .map(|_| {
                let a = authority.clone();
                tokio::spawn(async move {
                    for _ in 0..4 {
                        let r = h1::send(ROLE, &a, h1_get("/cap")).await.unwrap();
                        let b = axum::body::to_bytes(axum::body::Body::new(r.into_body()), usize::MAX).await.unwrap();
                        assert_eq!(b.len(), 3000);
                    }
                })
            })
            .collect();
        let mut max_open = 0;
        while !tasks.iter().all(|t| t.is_finished()) {
            max_open = max_open.max(host.open_connections());
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        for t in tasks {
            t.await.unwrap();
        }
        assert!(max_open <= 4, "{max_open} open");
        assert!(h1_connects(ROLE) <= 4, "{} connects", h1_connects(ROLE));
        let waits = crate::metrics::HTTP_CLIENT_POOL_WAITS.with_label_values(&[ROLE]).get();
        assert!(waits > 0, "128 requests over 4 connections waited");
    }

    /// An upstream that answers before the request body is uploaded: the
    /// connection is not pooled (the next request on it would wait behind
    /// that upload), and it closes once the upload ends.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn h1_early_answer_during_upload_is_not_pooled() {
        use futures::StreamExt;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        const ROLE: &str = "test-h1-early";
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let authority = l.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 64 << 10];
                    let _ = s.read(&mut buf).await; // the head (and whatever came with it)
                    let _ = s.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok").await;
                    while s.read(&mut buf).await.is_ok_and(|n| n > 0) {}
                });
            }
        });
        let (go, wait) = tokio::sync::oneshot::channel::<()>();
        let upload = futures::stream::once(async { Ok::<_, std::io::Error>(bytes::Bytes::from_static(b"part one")) })
            .chain(futures::stream::once(async move {
                let _ = wait.await;
                Ok(bytes::Bytes::from_static(b"part two"))
            }));
        let mut req = axum::http::Request::new(axum::body::Body::from_stream(upload));
        *req.method_mut() = axum::http::Method::POST;
        *req.uri_mut() = "/upload".parse().unwrap();
        let r = h1::send(ROLE, &authority, req).await.unwrap();
        let b = axum::body::to_bytes(axum::body::Body::new(r.into_body()), usize::MAX).await.unwrap();
        assert_eq!(&b[..], b"ok");
        let host = h1::host(&authority);
        assert_eq!(host.idle_connections(), 0, "pooled while its upload is still going");
        // a new request gets a connection of its own at once
        let r = tokio::time::timeout(Duration::from_secs(2), h1::send(ROLE, &authority, h1_get("/next"))).await;
        assert!(r.expect("waited behind the upload").is_ok());
        drop(go);
    }

    /// A body dropped part-way (the client went away) closes its connection,
    /// which ends the upstream exchange and frees the permit, instead of
    /// pooling it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn h1_dropped_body_closes_its_connection() {
        const ROLE: &str = "test-h1-drop";
        struct OnDrop(Option<tokio::sync::oneshot::Sender<()>>);
        impl Drop for OnDrop {
            fn drop(&mut self) {
                if let Some(t) = self.0.take() {
                    let _ = t.send(());
                }
            }
        }
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let authority = l.local_addr().unwrap().to_string();
        let (closed_tx, closed_rx) = tokio::sync::oneshot::channel::<()>();
        let closed_tx = Arc::new(parking_lot::Mutex::new(Some(closed_tx)));
        // a body that never ends; its stream is dropped when the connection closes
        let router = axum::Router::new().fallback(move || {
            let guard = OnDrop(closed_tx.lock().take());
            async move {
                let s = futures::stream::unfold(guard, |g| async move {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    Some((Ok::<_, std::io::Error>(bytes::Bytes::from_static(b"chunk")), g))
                });
                axum::body::Body::from_stream(s)
            }
        });
        tokio::spawn(crate::server::serve(l, router));
        let r = h1::send(ROLE, &authority, h1_get("/stream")).await.unwrap();
        let mut body = axum::body::Body::new(r.into_body()).into_data_stream();
        let first = futures::StreamExt::next(&mut body).await.unwrap().unwrap();
        assert_eq!(first.as_ref(), b"chunk");
        drop(body);
        tokio::time::timeout(Duration::from_secs(5), closed_rx).await.expect("upstream saw the close").unwrap();
        let host = h1::host(&authority);
        let t = std::time::Instant::now();
        while host.open_connections() > 0 {
            assert!(t.elapsed() < Duration::from_secs(5), "permit not freed");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(host.idle_connections(), 0);
    }
}
