//! XRPC HTTP surface (axum). One module per lexicon namespace; each exposes
//! `routes()`. Shared state, errors and auth helpers live here.

mod account_stats;
mod admin;
pub mod admin_audit;
mod admin_tools;
pub mod authn;
mod blob_quota;
pub mod blobs;
pub mod cas;
pub mod changes;
mod console;
mod console_accounts;
mod console_storage;
pub mod crawlers;
mod ctl_load;
mod email2fa;
pub mod extract;
mod feature_level;
pub mod firehose_subs;
mod handle_domains;
mod identity;
pub mod import_budget;
pub mod import_stream;
pub mod internal;
pub mod key_rotation;
pub mod mfa;
pub mod moderation;
pub mod oauth;
pub mod passkeys;
#[doc(hidden)]
pub mod private_rows;
pub(crate) mod proxy;
mod ratelimits;
mod repo;
pub mod scheduled_deletion;
mod server;
mod signin;
mod simplespace;
pub mod space;
mod space_admin;
mod space_import;
mod space_ops;
pub mod staged_import;
mod sync;
mod webui;
pub use account_stats::{export_account_totals, scan_totals, totals, totals_loading};
pub use blobs::spawn_blob_gc;
pub use import_budget::ImportBudget;
pub use repo::DEFAULT_MAX_IMPORT_BYTES;
pub use repo::{parse_import, ImportedRecord};
pub(crate) use server::SEC;
pub use server::{auth_epoch, auth_epoch_cond, epoch_for_login, new_auth_epoch_op, AUTH_EPOCH};
pub use server::{
    drop_revocation, reset_token_did, revocation_expired, set_delete_crash_hook, set_stale_claim_grace,
    spawn_reserved_key_gc, sweep_reserved_keys,
};
pub use server::{LogMailer, Mail, Mailer};
pub use signin::{trust_expired, ALERTS_PER_DAY, DEFAULT_TRUST_DAYS, TRUST as TRUST_PREFIX};
pub use staged_import::import_rows;
pub(crate) use sync::EXPORT_CHUNK;
pub use sync::{
    export_memory_bytes, find_record, set_export_prefetch_max_bytes, size_export_prefetch_pool, stream_export,
    ExportChunkTx, DEFAULT_EXPORT_STALL, DEFAULT_MAX_EXPORTS,
};
use vlatproto::cbor::blob_refs;
use vlatproto::xrpc::{XrpcError, SIGNATURE_FAULT};
pub use webui::WebUi;

#[allow(unused_imports)]
mod prelude {
    pub(crate) use crate::auth::Jwt;
    pub(crate) use crate::metrics;
    pub(crate) use crate::partition::Partition;
    pub(crate) use crate::state::{self, Account, Head};
    pub(crate) use crate::stats::STATS;
    pub(crate) use crate::worker::{
        CommitAck, CreateRepoReq, WorkerMsg, Workers, Write, WriteError, WriteOutcome, WriteReq,
    };
    pub(crate) use axum::body::{Body, Bytes as AxBytes};
    pub(crate) use axum::extract::{State, WebSocketUpgrade};
    pub(crate) use vlatproto::car;
    pub(crate) use vlatproto::cbor::Value;
    pub(crate) use vlatproto::cid::Cid;
    pub(crate) use vlatproto::crypto::{self, Keypair};
    pub(crate) use vlatproto::tid::TidClock;
    pub(crate) use vlsync_firehose::firehose::Firehose;
    pub(crate) use vlsync_store::store::Store;
    // XRPC-envelope rejections (400 InvalidRequest / 413) instead of axum's.
    pub(crate) use super::extract::{Json, Query};
    pub(crate) use axum::http::{header, HeaderMap, StatusCode};
    pub(crate) use axum::response::{IntoResponse, Response};
    pub(crate) use axum::routing::{get, post};
    pub(crate) use axum::Router;
    pub(crate) use bytes::Bytes;
    pub(crate) use object_store::{ObjectStoreExt, PutMode, PutOptions, PutPayload};
    pub(crate) use serde::Deserialize;
    pub(crate) use serde_json::{json, Value as J};
    pub(crate) use std::sync::atomic::Ordering;
    pub(crate) use std::sync::Arc;
    pub(crate) use std::time::Instant;
    pub(crate) use tokio::sync::oneshot;
}
pub(crate) use prelude::*;
pub struct App {
    pub jwt: Jwt,
    pub store: Store,
    pub workers: Workers,
    pub partitions: Arc<crate::partitions::PartitionTable>,
    pub firehose: Arc<Firehose>,
    pub tids: TidClock,
    pub public_url: String,
    /// `--handle-domain` and the domains added at runtime.
    pub handle_domains: Arc<crate::handle_domains::HandleDomains>,
    /// Writes beyond this many in flight get a fast 503. A write's permit
    /// travels with its queued message, so it is held until its worker takes
    /// it, even if the handler is gone.
    pub write_permits: Arc<tokio::sync::Semaphore>,
    /// Repo-view reads queued at the workers, held the same way.
    pub read_permits: Arc<tokio::sync::Semaphore>,
    pub exports: Arc<tokio::sync::Semaphore>,
    /// importRepo admission (`import_budget`).
    pub imports: Arc<import_budget::ImportBudget>,
    pub admin_token: String,
    pub config: Arc<crate::server::Config>,
    pub did_resolver: Arc<vlatproto::did_resolver::DidResolver>,
    /// None = single node owning every partition.
    pub cluster: Option<Arc<crate::cluster::Cluster>>,
    pub http: crate::http::PeerClient,
    pub log: Arc<crate::nodelog::NodeLog>,
    pub node: Arc<crate::node::Node>,
    pub ratelimit: Arc<crate::ratelimit::Limiter>,
    pub crawlers: Arc<crawlers::Crawlers>,
    /// Firehose subscribers' reverse DNS and origin AS, for the console.
    pub ptr: Arc<crate::ptr::PtrCache>,
    pub asn: Arc<crate::asn::AsnCache>,
    pub secrets: Arc<crate::secrets::Secrets>,
    /// None = DIDs minted locally and never registered (dev only).
    pub plc: Option<Arc<crate::plc::Plc>>,
    pub ui: Arc<WebUi>,
    /// Objects and bytes in the bucket by component (vlsync_store::store_stats).
    pub store_stats: Arc<vlsync_store::store_stats::StoreStats>,
    /// `--spaces` (src/space): space repo heads, the notifyWrite outbox,
    /// revocations. None without the flag.
    pub spaces: Option<Arc<crate::space::Spaces>>,
    pub space_blob_accounts: blobs::SpaceBlobAccounts,
    /// Ends the node's listeners at shutdown.
    pub http_drain: crate::server::Drain,
    /// What the console shows that changed (`vlpds.admin.subscribeChanges`).
    pub changes: Arc<changes::Changes>,
}

type AppState = State<Arc<App>>;

impl App {
    pub fn partition(&self, did: &str) -> Result<Arc<Partition>, XrpcError> {
        let p = self.partitions.shard_of(did);
        // moving or not reopened yet: nothing was done, so the entry node
        // resends writes (crate::forward)
        self.partitions.get(p).ok_or_else(|| {
            XrpcError::unavailable(crate::forward::SHARD_MOVED, format!("partition {p} is not owned by this node"))
        })
    }

    pub async fn resolve_handle(&self, handle: &str) -> Result<Option<String>, XrpcError> {
        let path = object_store::path::Path::from(format!("{}/handle/{}", self.store.prefix, handle));
        match self.store.raw.get(&path).await {
            Ok(r) => Ok(Some(String::from_utf8_lossy(&r.bytes().await.map_err(XrpcError::from_err)?).to_string())),
            Err(object_store::Error::NotFound { .. }) => Ok(None),
            Err(e) => Err(XrpcError::from_err(e)),
        }
    }

    pub async fn resolve_repo(&self, repo: &str) -> Result<Arc<str>, XrpcError> {
        if repo.starts_with("did:") {
            return Ok(repo.into());
        }
        self.resolve_handle(&repo.to_ascii_lowercase())
            .await?
            .map(Into::into)
            .ok_or_else(|| XrpcError::bad("RepoNotFound", format!("could not find repo: {repo}")))
    }

    pub async fn head(&self, did: &str) -> Result<Head, XrpcError> {
        let p = self.partition(did)?;
        let v = p.db.get(state::head_key(did)).await.map_err(XrpcError::from_err)?;
        let v = v.ok_or_else(|| XrpcError::bad("RepoNotFound", format!("could not find repo: {did}")))?;
        Head::decode(&v).map_err(XrpcError::from_err)
    }

    pub async fn account(&self, did: &str) -> Result<Account, XrpcError> {
        let p = self.partition(did)?;
        let v = p.db.get(state::account_key(did)).await.map_err(XrpcError::from_err)?;
        let v = v.ok_or_else(|| XrpcError::bad("AccountNotFound", format!("no account {did}")))?;
        serde_json::from_slice(&v).map_err(XrpcError::from_err)
    }

    /// The generation the repo's rows are under (0 without an account).
    pub async fn repo_gen(&self, did: &str) -> Result<u64, XrpcError> {
        match self.account(did).await {
            Ok(a) => Ok(a.repo_gen),
            Err(e) if e.error == "AccountNotFound" => Ok(0),
            Err(e) => Err(e),
        }
    }

    /// A record's `R/` value, at generation `gen` (None: the account's).
    /// The generation and the row aren't read from one snapshot, so a
    /// reader could read the generation just before an import commits and
    /// the row once the old generation is swept: a miss re-reads the
    /// generation and tries again if it moved. (It moves only with the
    /// commit, and no row of the generation it left is swept before that
    /// commit is applied, so a miss at an unchanged generation is real.)
    pub async fn record_value(&self, did: &str, gen: Option<u64>, path: &str) -> Result<Option<Bytes>, XrpcError> {
        let p = self.partition(did)?;
        let mut gen = match gen {
            Some(g) => g,
            None => self.repo_gen(did).await?,
        };
        loop {
            let v = p.db.get(state::record_key(did, gen, path)).await.map_err(XrpcError::from_err)?;
            if v.is_some() {
                return Ok(v);
            }
            let now = self.repo_gen(did).await?;
            if now == gen {
                return Ok(None);
            }
            gen = now;
        }
    }
}

impl From<WriteError> for XrpcError {
    fn from(e: WriteError) -> XrpcError {
        match e {
            WriteError::RepoNotFound => XrpcError::bad("RepoNotFound", "repo not found"),
            WriteError::RepoInactive(status) => inactive_account_error(&status),
            WriteError::InvalidSwap(m) => XrpcError::bad("InvalidSwap", m),
            WriteError::Invalid(m) => XrpcError::bad("InvalidRequest", m),
            WriteError::Internal(m) => XrpcError::internal(m),
            // none of these applied anything; the entry node resends a write
            // whose shard moved (crate::forward)
            WriteError::Unavailable(m) => XrpcError::unavailable(crate::forward::SHARD_MOVED, m),
            WriteError::KeyUnavailable(m) => XrpcError::unavailable(KEY_UNAVAILABLE, m),
            WriteError::SignatureFault(m) => XrpcError::unavailable(SIGNATURE_FAULT, m),
        }
    }
}

pub const KEY_UNAVAILABLE: &str = "KeyUnavailable";

/// Shed with a 503 rather than queue behind a login/sign-up flood.
impl From<crate::state::Argon2Busy> for XrpcError {
    fn from(e: crate::state::Argon2Busy) -> XrpcError {
        crate::metrics::ARGON2_SHED.inc();
        XrpcError::unavailable("Overloaded", e.to_string())
    }
}

impl From<crate::secrets::SecretError> for XrpcError {
    fn from(e: crate::secrets::SecretError) -> XrpcError {
        if e.retryable() {
            XrpcError::unavailable(KEY_UNAVAILABLE, e.to_string())
        } else {
            tracing::error!("secret unwrap failed: {e}");
            XrpcError::internal(e.to_string())
        }
    }
}

pub type XResult<T> = Result<T, XrpcError>;

fn no_partitions() -> XrpcError {
    XrpcError::unavailable("PartitionUnavailable", "this node owns no partitions yet")
}

pub fn router(app: Arc<App>) -> Router {
    let r = Router::new()
        .route("/xrpc/_health", get(|| async { Json(json!({"version": crate::build::version()})) }))
        .route("/metrics", get(|| async { metrics::render() }))
        // locally served XRPC methods; debug builds check their output schemas
        .merge(extract::debug_output_layer(
            Router::new()
                .merge(server::routes())
                .merge(signin::routes())
                .merge(passkeys::routes())
                .merge(mfa::routes())
                .merge(identity::routes())
                .merge(repo::routes())
                .merge(sync::routes())
                .merge(blobs::routes())
                .merge(admin::routes())
                .merge(admin_tools::routes())
                .merge(crawlers::routes())
                .merge(handle_domains::routes())
                .merge(space_ops::routes())
                .merge(match app.config.spaces {
                    true => space::routes()
                        .merge(simplespace::routes())
                        .merge(space_admin::routes())
                        .merge(space_import::routes())
                        .merge(admin_tools::space_routes()),
                    false => Router::new(),
                }),
        ))
        .merge(proxy::routes())
        .merge(oauth::routes())
        .merge(internal::routes())
        .merge(space_ops::internal_routes())
        .merge(match app.config.spaces {
            true => space::internal_routes(),
            false => Router::new(),
        })
        .merge(crate::profiling::routes())
        .merge(ratelimits::routes())
        .merge(firehose_subs::routes())
        .merge(changes::routes())
        .merge(console::routes())
        .merge(console_accounts::routes())
        .merge(console_storage::routes())
        .merge(moderation::routes())
        .merge(feature_level::routes())
        .merge(webui::routes())
        // Local routes only (their extractors bound the decoded size): the
        // proxy fallback, added after this layer, forwards bodies as the
        // client encoded them, like the reference; decoding there was
        // unbounded (~1000:1) and refused codings the upstream may take.
        .layer(tower_http::decompression::RequestDecompressionLayer::new())
        .fallback(proxy::fallback);
    ratelimits::start(&app);
    crawlers::start(&app);
    handle_domains::start(&app);
    let r = oauth::with_dpop_layer(r, &app);
    let r = if app.config.rate_limits_enabled {
        let limiter = app.ratelimit.clone();
        r.layer(axum::middleware::from_fn_with_state(limiter, crate::ratelimit::layer))
    } else {
        r.layer(axum::middleware::from_fn(crate::ratelimit::unlimited))
    };
    r.layer(axum::middleware::from_fn(incorrect_method))
        .layer(axum::middleware::from_fn(track_http))
        .layer(tower_http::compression::CompressionLayer::new().compress_when(tower_http::compression::Predicate::and(
            tower_http::compression::predicate::SizeAbove::new(1024),
            JsonOrCar,
        )))
        .layer(axum::middleware::from_fn(cors))
        .with_state(app)
}

/// Compress only JSON and CAR bodies (reference `compression()` filter with
/// its CAR special case, packages/pds/src/util/compression.ts).
#[derive(Clone, Copy)]
struct JsonOrCar;

impl tower_http::compression::predicate::Predicate for JsonOrCar {
    fn should_compress<B>(&self, response: &axum::http::Response<B>) -> bool
    where
        B: axum::body::HttpBody,
    {
        let ct = response.headers().get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("");
        let ct = ct.split(';').next().unwrap_or("").trim();
        ct == "application/json" || ct == "application/vnd.ipld.car"
    }
}

const CORS_EXPOSE: &str = "DPoP-Nonce, WWW-Authenticate, atproto-repo-rev, atproto-content-labelers, \
RateLimit-Limit, RateLimit-Remaining, RateLimit-Reset, RateLimit-Policy, Retry-After";
/// When a preflight doesn't name any.
const CORS_ALLOW_HEADERS: &str = "Authorization, Content-Type, DPoP, atproto-proxy, \
atproto-accept-labelers, atproto-content-labelers";

/// Server-wide CORS, like the reference's `cors({ maxAge: DAY / SECOND })`:
/// any origin; preflights (for routes without their own OPTIONS handler)
/// allow any method and mirror the requested headers; every response
/// exposes [`CORS_EXPOSE`] (added next to any value a handler set).
async fn cors(req: axum::extract::Request, next: axum::middleware::Next) -> Response {
    use header::HeaderValue;
    let preflight = req.method() == axum::http::Method::OPTIONS;
    let req_headers = req.headers().get(header::ACCESS_CONTROL_REQUEST_HEADERS).cloned();
    // XRPC preflights (incl. proxied methods) are answered here; other
    // routes (OAuth endpoints) may have their own OPTIONS handlers.
    let mut resp = if preflight && req.uri().path().starts_with("/xrpc/") {
        StatusCode::NOT_FOUND.into_response()
    } else {
        next.run(req).await
    };
    if preflight && matches!(resp.status(), StatusCode::METHOD_NOT_ALLOWED | StatusCode::NOT_FOUND) {
        resp = StatusCode::NO_CONTENT.into_response();
        let h = resp.headers_mut();
        h.insert(header::ACCESS_CONTROL_ALLOW_METHODS, HeaderValue::from_static("GET,HEAD,PUT,PATCH,POST,DELETE"));
        h.insert(
            header::ACCESS_CONTROL_ALLOW_HEADERS,
            req_headers.unwrap_or(HeaderValue::from_static(CORS_ALLOW_HEADERS)),
        );
        h.insert(header::ACCESS_CONTROL_MAX_AGE, HeaderValue::from_static("86400"));
    }
    let h = resp.headers_mut();
    h.entry(header::ACCESS_CONTROL_ALLOW_ORIGIN).or_insert(HeaderValue::from_static("*"));
    h.append(header::ACCESS_CONTROL_EXPOSE_HEADERS, HeaderValue::from_static(CORS_EXPOSE));
    resp
}

/// A local XRPC route called with the wrong HTTP method: 400 InvalidRequest
/// as the reference's xrpc-server ("Incorrect HTTP method (POST) expected
/// GET") instead of axum's bare 405. Local routes are GET or POST only, so
/// the expected method is the other one (axum adds its Allow header outside
/// route layers, too late to read here). Preflights are left to [`cors`].
async fn incorrect_method(req: axum::extract::Request, next: axum::middleware::Next) -> Response {
    use axum::http::Method;
    let method = req.method().clone();
    let xrpc = req.uri().path().starts_with("/xrpc/");
    let resp = next.run(req).await;
    if !xrpc || method == Method::OPTIONS || resp.status() != StatusCode::METHOD_NOT_ALLOWED {
        return resp;
    }
    let message = match method {
        Method::POST => "Incorrect HTTP method (POST) expected GET".to_string(),
        Method::GET | Method::HEAD => format!("Incorrect HTTP method ({method}) expected POST"),
        _ => "XRPC requests only supports GET and POST".to_string(),
    };
    XrpcError::bad("InvalidRequest", message).into_response()
}

async fn track_http(req: axum::extract::Request, next: axum::middleware::Next) -> Response {
    // Label by matched route only: proxied/fallback paths are attacker-chosen,
    // so they share one label to keep metric cardinality bounded.
    let method = match req.extensions().get::<axum::extract::MatchedPath>() {
        Some(m) => metrics::method_label(m.as_str()).to_string(),
        None => "_proxy_or_unmatched".to_string(),
    };
    let start = Instant::now();
    metrics::HTTP_INFLIGHT.inc();
    let resp = next.run(req).await;
    metrics::HTTP_INFLIGHT.dec();
    metrics::HTTP_DURATION.with_label_values(&[&method]).observe(start.elapsed().as_secs_f64());
    metrics::HTTP_REQUESTS.with_label_values(&[&method, resp.status().as_str()]).inc();
    resp
}

#[allow(unused_imports)]
pub(crate) use authn::{authed_repo, Auth, Credentials, MaybeAuth};

/// As the reference's findAccount with checkTakedown/checkDeactivated.
pub fn inactive_account_error(status: &str) -> XrpcError {
    match status {
        "takendown" | "suspended" => takedown_error(),
        "deactivated" => XrpcError {
            status: StatusCode::UNAUTHORIZED,
            error: "AccountDeactivated".into(),
            message: "Account is deactivated".into(),
        },
        st => XrpcError::bad(&inactive_error(st), format!("repo is {st}")),
    }
}

pub(crate) fn takedown_error() -> XrpcError {
    XrpcError {
        status: StatusCode::UNAUTHORIZED,
        error: "AccountTakedown".into(),
        message: "Account has been taken down".into(),
    }
}

/// RepoDeactivated, RepoTakendown, ...
pub fn inactive_error(status: &str) -> String {
    let mut c = status.chars();
    match c.next() {
        Some(f) => format!("Repo{}{}", f.to_ascii_uppercase(), c.as_str()),
        None => "RepoInactive".into(),
    }
}

/// Private rows through `p`'s log, never forwarded. A shard that closed
/// between the caller's lookup and the enqueue is refused by the log with
/// nothing written: ShardMoved, so the entry node resends the request to the
/// new owner (which re-runs any conditional write's checks).
pub(crate) async fn write_private_local(
    p: &crate::partition::Partition,
    muts: Vec<vlsync_store::segment::Mutation>,
) -> Result<(), XrpcError> {
    let (tx, rx) = oneshot::channel();
    let entry = crate::partition::LogEntry {
        shard: p.id,
        frames: Vec::new(),
        muts,
        ack: Some(Box::new(move |r| {
            let _ = tx.send(r);
        })),
        pending: None,
        enqueued: Instant::now(),
        totals: None,
    };
    p.tx.send(entry).await.map_err(|_| XrpcError::internal("partition sequencer gone"))?;
    rx.await.map_err(|_| XrpcError::internal("log dropped write"))?.map_err(|e| {
        if e.to_string() == crate::nodelog::NOT_HELD {
            return XrpcError::unavailable(
                crate::forward::SHARD_MOVED,
                format!("partition {} closed under this write", p.id),
            );
        }
        XrpcError::internal(e.to_string())
    })
}

impl App {
    /// Base URL of `routing_key`'s owner, if that is not us.
    pub fn remote_owner(&self, routing_key: &str) -> Option<String> {
        let cluster = self.cluster.as_ref()?;
        let p = self.partitions.shard_of(routing_key);
        if self.partitions.get(p).is_some() {
            return None;
        }
        cluster.owner_of(p).filter(|(id, _)| *id != cluster.cfg.node_id).map(|(_, addr)| addr)
    }

    /// Drops `did`'s signing key from every cache that holds it, so its next
    /// use unwraps it again (the cold-key path the Spaces bench measures).
    #[doc(hidden)]
    pub fn forget_signing_key(&self, did: &str) {
        proxy::account_changed(did);
        self.secrets.forget(did);
    }

    /// A DID in a partition this node owns, so account creation never needs
    /// forwarding.
    pub fn mint_local_did(&self) -> Result<String, XrpcError> {
        if self.cluster.is_none() {
            return Ok(crypto::random_plc_did());
        }
        (0..10_000)
            .map(|_| crypto::random_plc_did())
            .find(|did| self.partitions.for_key(did).is_some())
            .ok_or_else(no_partitions)
    }

    /// (did, genesis op), re-signed until the DID lands in a partition this
    /// node owns (the hedged signature makes every attempt a new DID).
    pub fn mint_plc_did(
        &self,
        plc: &crate::plc::Plc,
        signing_did_key: &str,
        handle: &str,
        recovery_key: Option<&str>,
    ) -> Result<(String, serde_json::Value), XrpcError> {
        for _ in 0..10_000 {
            let (did, op) = plc.genesis(signing_did_key, handle, &self.public_url, recovery_key)?;
            if self.cluster.is_none() || self.partitions.for_key(&did).is_some() {
                return Ok((did, op));
            }
        }
        Err(no_partitions())
    }

    /// A repo's latest durable (head, MST) plus a SlateDB snapshot consistent
    /// with it. O(1): the MST is the worker's copy-on-write tree.
    pub async fn repo_view(
        &self,
        did: &str,
    ) -> Result<(Arc<crate::worker::DurableView>, Arc<slatedb::DbSnapshot>), XrpcError> {
        let Ok(permit) = self.read_permits.clone().try_acquire_owned() else {
            return Err(XrpcError::unavailable("Overloaded", "too many reads queued; retry with backoff"));
        };
        let (tx, rx) = oneshot::channel();
        self.workers
            .route(did)
            .send(WorkerMsg::Snapshot(crate::worker::SnapshotReq { did: did.into(), reply: tx, permit: Some(permit) }))
            .map_err(XrpcError::from_err)?;
        let cell = rx.await.map_err(|_| XrpcError::internal("worker dropped request"))??;
        let p = self.partition(did)?;
        let _g = p.apply_lock.read().await;
        let view = cell.read().clone();
        let snap = p.db.snapshot().map_err(XrpcError::from_err)?;
        Ok((view, snap))
    }

    pub async fn ensure_active(&self, did: &str) -> Result<Account, XrpcError> {
        let a = self
            .account(did)
            .await
            .map_err(|_| XrpcError::bad("RepoNotFound", format!("could not find repo: {did}")))?;
        match &a.status {
            Some(st) => Err(inactive_account_error(st)),
            None => Ok(a),
        }
    }

    /// Private (non-repo) state, through the partition log without firehose
    /// events.
    pub async fn put_private(&self, did: &str, muts: Vec<vlsync_store::segment::Mutation>) -> Result<(), XrpcError> {
        if let Some(owner) = self.remote_owner(did) {
            return internal::forward_put_private(self, &owner, did, muts).await;
        }
        let p = self.partition(did)?;
        write_private_local(&p, muts).await
    }

    pub async fn get_private(&self, did: &str, name: &str) -> Result<Option<Bytes>, XrpcError> {
        if let Some(owner) = self.remote_owner(did) {
            return internal::forward_get_private(self, &owner, did, name).await;
        }
        let p = self.partition(did)?;
        p.db.get(state::private_key(did, name)).await.map_err(XrpcError::from_err)
    }

    /// Ordered with the repo's commits.
    pub async fn account_op(&self, did: &str, op: crate::worker::AccountOp) -> Result<Head, XrpcError> {
        let (tx, rx) = oneshot::channel();
        self.workers
            .route(did)
            .send(WorkerMsg::Account(crate::worker::AccountReq { did: did.into(), op, reply: tx }))
            .map_err(XrpcError::from_err)?;
        let head = rx.await.map_err(|_| XrpcError::internal("worker dropped request"))??;
        self.changes.account(did);
        Ok(head)
    }

    /// Read-modify-write of an account on the worker's current state (a
    /// snapshot read here could be outdated by a concurrent change). `f`
    /// checks its preconditions and returns whether anything changed (false:
    /// no write, no events). Returns (before, after).
    pub async fn mutate_account<F>(
        &self,
        did: &str,
        identity_event: bool,
        account_event: bool,
        activate: bool,
        f: F,
    ) -> Result<(Account, Account), XrpcError>
    where
        F: FnOnce(&mut Account) -> Result<bool, XrpcError> + Send + 'static,
    {
        // f's own error and the accounts come back through `out`; the worker
        // only learns that the op was rejected
        let (out_tx, mut out_rx) = oneshot::channel();
        let mutate: crate::worker::AccountMutation = Box::new(move |a: &mut Account| {
            let before = a.clone();
            match f(a) {
                Ok(changed) => {
                    let _ = out_tx.send(Ok((before, a.clone())));
                    Ok(changed)
                }
                Err(e) => {
                    let msg = e.message.clone();
                    let _ = out_tx.send(Err(e));
                    Err(WriteError::Invalid(msg))
                }
            }
        });
        let op = if activate {
            crate::worker::AccountOp::Activate { mutate }
        } else {
            crate::worker::AccountOp::Update { mutate, identity_event, account_event }
        };
        let res = self.account_op(did, op).await;
        match (out_rx.try_recv(), res) {
            (Ok(Err(e)), _) => Err(e),
            (_, Err(e)) => Err(e),
            (Ok(Ok(accts)), Ok(_)) => {
                // notifies that waited out a takedown or deactivation
                if let (Some(sp), Some(_), None) = (&self.spaces, &accts.0.status, &accts.1.status) {
                    sp.outbox.resume(did);
                }
                Ok(accts)
            }
            (Err(_), Ok(_)) => Err(XrpcError::internal("account mutation did not run")),
        }
    }
}
