//! Server assembly, used by the binary and by in-process integration tests.
//! A single node is simply a one-node cluster.

use crate::cluster::{Cluster, ClusterConfig, ShardHost};
use crate::firehose::Firehose;
use crate::nodelog::{NodeLog, NodeLogConfig};
use crate::store::{S3Config, Store};
use crate::{auth, stats, worker, xrpc};
use axum::response::IntoResponse;
use std::sync::Arc;
use std::time::Duration;

/// No Debug: it holds secrets (tokens, S3/SMTP credentials, KEK config).
#[derive(Clone)]
pub struct Config {
    pub public_url: String,
    pub handle_domain: String,
    pub service_did: String,
    pub jwt_secret: String,
    pub admin_token: String,
    /// Distinct from the admin token so a leaked node credential isn't an
    /// admin credential.
    pub internal_token: String,
    /// None: in-memory object store.
    pub s3: Option<S3Config>,
    pub prefix: String,
    /// (median ms, lognormal sigma) injected on segment PUTs.
    pub inject_latency: Option<(f64, f64)>,
    pub store_inflight: usize,
    pub log_store_inflight: usize,
    /// The initial layout of a new prefix; the stored layout wins after.
    pub shards: u32,
    pub workers: usize,
    pub cache_per_worker: usize,
    /// The memory budget and the SST metadata, SST block and repo caches'
    /// sizes (default: automatic, src/memory.rs).
    pub memory: crate::memory::Settings,
    pub lazy_mst_prefetch_bytes: usize,
    /// Tests: drop every idle repo's loaded paths after each worker pass, so
    /// every write and read walks from the root through the store.
    pub lazy_mst_unload_idle: bool,
    pub lazy_mst_node_cache_bytes: usize,
    pub max_segment_bytes: usize,
    pub log_inflight: usize,
    pub live_ring_bytes: usize,
    pub firehose_merge_queue_bytes: usize,
    pub firehose_ring_bytes: usize,
    /// 0: serve subscribeRepos on the request runtime.
    pub firehose_threads: usize,
    pub firehose_max_lag_bytes: usize,
    pub backfill_readahead_bytes: usize,
    pub backfill_cache_bytes: usize,
    pub firehose_max_backfills: usize,
    /// 0: no cap.
    pub firehose_max_per_ip: usize,
    pub hedge_after: Duration,
    pub max_inflight_writes: usize,
    pub max_queued_reads: usize,
    pub max_exports: usize,
    pub export_stall: Duration,
    /// Per listener; 0: no cap.
    pub max_connections: usize,
    pub cache_dir: Option<std::path::PathBuf>,
    /// Split over the layout's shards. None: SlateDB's 16 GiB per shard.
    pub disk_cache_bytes: Option<u64>,
    pub disk_cache_shard_bytes: Option<u64>,
    /// (url, service DID)
    pub appview: Option<(String, String)>,
    /// (url, service DID)
    pub report_service: Option<(String, String)>,
    /// None: the PDS's own getBlob URL.
    pub appview_cdn_url_pattern: Option<String>,
    /// Relays told to crawl us (`xrpc::crawlers`) while the bucket's
    /// `config/crawlers.json` sets none.
    pub crawlers: Vec<String>,
    pub crawl_interval: Duration,
    pub dev_mode: bool,
    pub allow_bulk_create: bool,
    /// Empty: the dev KEK, dev mode only.
    pub kek: crate::secrets::KekConfig,
    /// None: the process-wide mailer (logs only, unless `xrpc::set_mailer`).
    pub mailer: Option<crate::mail::SharedMailer>,
    /// None: `mailer`.
    pub moderation_mailer: Option<crate::mail::SharedMailer>,
    pub email_branding: crate::mail::Branding,
    pub max_blob_size: u64,
    pub privacy_policy_url: Option<String>,
    pub terms_of_service_url: Option<String>,
    pub contact_email_address: Option<String>,
    pub blob_gc_grace: Duration,
    /// Per-account stored blob bytes; 0: unlimited. Overridable per DID.
    pub blob_quota_bytes: u64,
    /// Per-account uploadBlob calls per UTC day; 0: unlimited.
    pub blob_uploads_per_day: u32,
    /// How long a taken-down blob's bytes stay in quarantine.
    pub blob_quarantine: Duration,
    /// Deactivated accounts with a `deleteAfter` are deleted once it has
    /// passed and they have been deactivated at least this long. None: kept.
    pub delete_after_min_hold: Option<Duration>,
    pub plc_url: String,
    /// Default: registration off, which only dev mode accepts.
    pub plc: crate::plc::PlcConfig,
    pub invite_required: bool,
    /// None: accounts never earn codes.
    pub invite_interval: Option<Duration>,
    /// 0: from account creation.
    pub invite_epoch_ms: i64,
    /// None: admin Basic auth only.
    pub mod_service_did: Option<String>,
    /// None: the system resolver; tests inject a stub.
    pub txt_resolver: Option<crate::handle_resolver::TxtResolverRef>,
    /// Firehose subscribers' reverse DNS. None: the system resolver; tests
    /// inject a stub.
    pub ptr_resolver: Option<crate::ptr::PtrResolverRef>,
    /// The whois server (`host:port`) asked for firehose subscribers' AS.
    /// None: no lookups.
    pub asn_whois: Option<String>,
    /// How long ASN misses gather before one batched query.
    pub asn_debounce: Duration,
    /// None: the SSRF-guarded HTTPS fetch; tests inject a stub.
    pub well_known_fetcher: Option<crate::handle_resolver::WellKnownRef>,
    /// None: node id "single", addr = public_url.
    pub cluster: Option<ClusterConfig>,
    pub rate_limits_enabled: bool,
    pub trusted_proxies: Vec<String>,
    pub peer_connections: usize,
    /// None: a lone node, with no peer listener, no `/internal/*`, and peer
    /// calls that fail.
    pub peer_tls: Option<Arc<crate::peer_tls::PeerTls>>,
    pub rate_limit_bypass_key: Option<String>,
    /// `mail-cluster-day`'s default points.
    pub mail_daily_budget: u32,
    /// How long "trust this browser" skips the second factor; 0: not offered.
    pub trusted_device_days: u32,
    /// How long a write waits for a lexicon resolution. None: off.
    pub resolve_lexicons: Option<Duration>,
    /// AT Protocol Spaces (`--spaces`; src/space). Their NSIDs are never
    /// proxied: one without a handler answers 501.
    pub spaces: bool,
    /// Most records an account's repo in one space holds.
    pub space_repo_max_records: u64,
    /// How long space oplog rows are kept. None: forever.
    pub space_oplog_retention: Option<Duration>,
    /// Largest importRepo body.
    pub max_import_bytes: usize,
    /// The import budget (`xrpc::import_budget`). None: the memory plan's
    /// `import` part.
    pub import_memory_bytes: Option<u64>,
    /// How long an import waits for the budget to admit it (then 503); a
    /// running one waits at most 10 s of it to grow.
    pub import_wait: Duration,
    /// How long an importRepo body (public or space) may go without a byte,
    /// and how long it may take in all; then it fails.
    pub import_body_idle: Duration,
    pub import_body_deadline: Duration,
    /// With `s3: None`: share this store so several in-process nodes form
    /// one cluster (tests).
    pub memory_store: Option<Arc<dyn object_store::ObjectStore>>,
    /// Serve /metrics and /debug/pprof there instead of the app port.
    pub metrics_listen: Option<String>,
    /// None: keep every segment forever.
    pub log_retention: Option<crate::retention::Config>,
    /// None: 10% of the memory budget.
    pub cache_budget_bytes: Option<u64>,
    pub cache_entries: Vec<(crate::caches::Cache, usize)>,
    pub reshard_policy: crate::reshard::Policy,
    /// The built web UI (`xrpc::WebUi::load`). None: the source tree's.
    pub ui_dir: Option<std::path::PathBuf>,
    /// None: keep retired parents' state forever.
    pub reshard_gc: Option<crate::reshard_gc::Config>,
    pub checkpoint_every: Duration,
    pub checkpoint_stagger: bool,
    /// 0: off.
    pub preload_recent: usize,
    /// None: wait for the write to start.
    pub forwarded_write_start: Option<Duration>,
    pub retry_unapplied_writes: bool,
}

/// Well-known secrets, accepted only with `dev_mode`.
pub const DEV_S3_CREDENTIAL: &str = "minioadmin";
pub const DEFAULT_BLOB_QUOTA_GB: u64 = 25;
pub const DEFAULT_BLOB_UPLOADS_PER_DAY: u32 = 500;
pub const DEFAULT_BLOB_QUARANTINE_DAYS: u64 = 30;
pub const DEFAULT_DELETE_AFTER_MIN_HOLD_DAYS: u64 = 3;
pub const DEV_JWT_SECRET: &str = "dev-secret-change-me";
pub const DEV_ADMIN_TOKEN: &str = "dev-admin-token";
pub const DEV_INTERNAL_TOKEN: &str = "dev-internal-token";
const MIN_SECRET_LEN: usize = 32;

impl Config {
    /// The binary calls it; in-process tests may skip it. Secrets are never
    /// empty, and outside dev mode they must be real, at least
    /// 32 bytes, and pairwise distinct.
    pub fn check_secrets(&self) -> anyhow::Result<()> {
        let secrets = [
            ("VLPDS_JWT_SECRET", &self.jwt_secret, DEV_JWT_SECRET),
            ("VLPDS_ADMIN_TOKEN", &self.admin_token, DEV_ADMIN_TOKEN),
            ("VLPDS_INTERNAL_TOKEN", &self.internal_token, DEV_INTERNAL_TOKEN),
        ];
        for (name, v, dev) in secrets {
            anyhow::ensure!(!v.is_empty(), "{name} must be set (non-empty)");
            if self.dev_mode {
                continue;
            }
            anyhow::ensure!(v != dev, "{name} is the dev default; set a real secret (or run with --dev-mode)");
            anyhow::ensure!(v.len() >= MIN_SECRET_LEN, "{name} must be at least {MIN_SECRET_LEN} bytes");
        }
        self.kek.check(self.dev_mode)?;
        self.plc.check(self.dev_mode, &self.plc_url)?;
        if let (Some(s3), false) = (&self.s3, self.dev_mode) {
            anyhow::ensure!(
                s3.access_key != DEV_S3_CREDENTIAL && s3.secret_key != DEV_S3_CREDENTIAL,
                "VLPDS_S3_ACCESS_KEY / VLPDS_S3_SECRET_KEY are the MinIO defaults ({DEV_S3_CREDENTIAL}); set real credentials (or run with --dev-mode)"
            );
        }
        if !self.dev_mode {
            for (i, (a, va, _)) in secrets.iter().enumerate() {
                for (b, vb, _) in &secrets[i + 1..] {
                    anyhow::ensure!(va != vb, "{a} and {b} must differ");
                }
            }
        }
        Ok(())
    }
}

impl Config {
    /// The memory plan's fixed costs.
    pub fn memory_fixed(&self) -> crate::memory::Fixed {
        crate::memory::Fixed {
            in_memory_caches: self.cache_budget_bytes,
            mst_node_cache: self.lazy_mst_node_cache_bytes as u64,
            firehose_ring: self.firehose_ring_bytes as u64,
            live_ring: self.live_ring_bytes as u64,
            merge_queue: self.firehose_merge_queue_bytes as u64,
            backfill_cache: self.backfill_cache_bytes as u64,
            backfill_readahead: self.backfill_readahead_bytes as u64,
            max_backfills: self.firehose_max_backfills as u64,
            max_exports: self.max_exports as u64,
            import_memory: self.import_memory_bytes,
            space_exports: match self.spaces {
                true => crate::space::export_budget_bytes(self.space_repo_max_records),
                false => 0,
            },
        }
    }

    /// Refuses sizes that don't fit the memory budget.
    pub fn memory_plan(&self) -> anyhow::Result<crate::memory::Plan> {
        let mut s = self.memory.clone();
        s.block = s.block.or(crate::partition::pinned_block_cache_bytes());
        crate::memory::plan(&s, &self.memory_fixed(), crate::memory::limit_bytes())
    }
}

impl Default for Config {
    fn default() -> Self {
        Config {
            public_url: "http://localhost:2583".into(),
            handle_domain: "vlpds.test".into(),
            service_did: "did:web:localhost".into(),
            jwt_secret: DEV_JWT_SECRET.into(),
            admin_token: DEV_ADMIN_TOKEN.into(),
            internal_token: DEV_INTERNAL_TOKEN.into(),
            s3: None,
            prefix: "vlpds".into(),
            inject_latency: None,
            store_inflight: crate::objlimit::DEFAULT_STATE_INFLIGHT,
            log_store_inflight: crate::objlimit::DEFAULT_LOG_INFLIGHT,
            shards: 8,
            workers: 2,
            cache_per_worker: 10_000,
            memory: Default::default(),
            lazy_mst_prefetch_bytes: crate::worker::DEFAULT_PREFETCH_BYTES,
            lazy_mst_unload_idle: std::env::var("VLPDS_LAZY_MST_UNLOAD_IDLE").is_ok_and(|v| v == "1"),
            lazy_mst_node_cache_bytes: crate::mst_store::DEFAULT_NODE_CACHE_BYTES,
            max_segment_bytes: 8 << 20,
            log_inflight: crate::nodelog::DEFAULT_LOG_INFLIGHT,
            live_ring_bytes: crate::nodelog::DEFAULT_LIVE_RING_BYTES,
            firehose_merge_queue_bytes: crate::firehose::DEFAULT_MERGE_QUEUE_BYTES,
            firehose_ring_bytes: 64 << 20,
            firehose_threads: 2,
            firehose_max_lag_bytes: crate::firehose::DEFAULT_MAX_LAG_BYTES,
            backfill_readahead_bytes: crate::backfill::DEFAULT_READAHEAD_BYTES,
            backfill_cache_bytes: crate::backfill::DEFAULT_CACHE_BYTES,
            firehose_max_backfills: crate::firehose::DEFAULT_MAX_BACKFILLS,
            firehose_max_per_ip: crate::firehose::DEFAULT_MAX_PER_IP,
            hedge_after: Duration::from_millis(100),
            max_inflight_writes: 20_000,
            max_queued_reads: 20_000,
            max_exports: crate::xrpc::DEFAULT_MAX_EXPORTS,
            export_stall: crate::xrpc::DEFAULT_EXPORT_STALL,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            cache_dir: None,
            disk_cache_bytes: None,
            disk_cache_shard_bytes: None,
            appview: None,
            report_service: None,
            appview_cdn_url_pattern: None,
            crawlers: Vec::new(),
            crawl_interval: xrpc::crawlers::DEFAULT_INTERVAL,
            dev_mode: true,
            allow_bulk_create: false,
            kek: Default::default(),
            mailer: None,
            moderation_mailer: None,
            email_branding: Default::default(),
            cluster: None,
            max_blob_size: 100 << 20,
            privacy_policy_url: None,
            terms_of_service_url: None,
            contact_email_address: None,
            blob_gc_grace: Duration::from_secs(6 * 3600),
            blob_quota_bytes: DEFAULT_BLOB_QUOTA_GB * 1_000_000_000,
            blob_uploads_per_day: DEFAULT_BLOB_UPLOADS_PER_DAY,
            blob_quarantine: Duration::from_secs(DEFAULT_BLOB_QUARANTINE_DAYS * 86_400),
            delete_after_min_hold: Some(Duration::from_secs(DEFAULT_DELETE_AFTER_MIN_HOLD_DAYS * 86_400)),
            plc_url: crate::plc::DEFAULT_PLC_URL.into(),
            plc: Default::default(),
            invite_required: false,
            invite_interval: None,
            invite_epoch_ms: 0,
            mod_service_did: None,
            txt_resolver: None,
            ptr_resolver: None,
            asn_whois: None,
            asn_debounce: crate::asn::DEBOUNCE,
            well_known_fetcher: None,
            rate_limits_enabled: true,
            trusted_proxies: Vec::new(),
            peer_connections: crate::http::DEFAULT_PEER_CONNECTIONS,
            peer_tls: None,
            rate_limit_bypass_key: None,
            mail_daily_budget: crate::ratelimit::DEFAULT_MAIL_DAILY_BUDGET,
            trusted_device_days: crate::xrpc::DEFAULT_TRUST_DAYS,
            resolve_lexicons: None,
            spaces: false,
            space_repo_max_records: crate::space::DEFAULT_MAX_RECORDS,
            space_oplog_retention: Some(crate::space::retention::DEFAULT_RETENTION),
            max_import_bytes: crate::xrpc::DEFAULT_MAX_IMPORT_BYTES,
            import_memory_bytes: None,
            import_wait: crate::xrpc::import_budget::ADMIT_WAIT,
            import_body_idle: crate::xrpc::import_stream::BODY_IDLE,
            import_body_deadline: crate::xrpc::import_stream::BODY_DEADLINE,
            memory_store: None,
            metrics_listen: None,
            log_retention: Some(crate::retention::Config::default()),
            cache_budget_bytes: None,
            cache_entries: Vec::new(),
            reshard_policy: Default::default(),
            ui_dir: None,
            reshard_gc: Some(Default::default()),
            checkpoint_every: Duration::from_secs(10),
            checkpoint_stagger: true,
            preload_recent: crate::partition::DEFAULT_RECENT_REPOS,
            forwarded_write_start: Some(crate::forward::FORWARDED_WRITE_START),
            retry_unapplied_writes: true,
        }
    }
}

pub async fn build(cfg: Config) -> anyhow::Result<Arc<xrpc::App>> {
    let ui = Arc::new(xrpc::WebUi::load(cfg.ui_dir.as_deref())?);
    let plan = crate::memory::init(cfg.memory_plan()?);
    let (caps, budget) = crate::caches::resolve(
        Some(cfg.cache_budget_bytes.unwrap_or(plan.part("in_memory_caches"))),
        &cfg.cache_entries,
    );
    crate::caches::apply(&caps);
    if let Some(m) = plan.limit {
        crate::metrics::MEMORY_LIMIT.set(m as i64);
    }
    crate::xrpc::size_export_prefetch_pool(cfg.max_exports);
    tracing::info!(budget_mb = budget >> 20, full_mb = caps.total_bytes() >> 20, "in-memory cache caps: {caps}");
    // Separate connection pools for the commit log, the control plane and
    // everything else, each bounded (objlimit.rs), so a takeover's burst
    // can't starve lease renewals or exhaust ephemeral ports.
    use crate::objlimit::{Limits, Reserve};
    let log_limits = Limits::new(cfg.log_store_inflight)
        .with_reserved(Reserve::Writes, crate::objlimit::log_write_permits(cfg.log_inflight));
    let state_limits = Limits::new(cfg.store_inflight);
    let ctl_limits =
        Limits::new(crate::objlimit::CTL_PERMITS).with_reserved(Reserve::LeaseWrites, crate::objlimit::LEASE_PERMITS);
    let (store, state_store, ctl_store) = match &cfg.s3 {
        None => {
            let m = match &cfg.memory_store {
                Some(raw) => Store { raw: raw.clone(), ..Store::memory(cfg.inject_latency) },
                None => Store::memory(cfg.inject_latency),
            };
            let plain = Store { latency: None, ..m.clone() };
            (m.counted("log"), plain.clone().counted("state"), plain.counted("ctl"))
        }
        Some(s3) => (
            Store::s3(s3, &cfg.prefix, cfg.inject_latency, log_limits.connections())?.counted("log"),
            Store::s3(s3, &cfg.prefix, None, state_limits.connections())?.counted("state"),
            Store::s3_ctl(
                s3,
                &cfg.prefix,
                ctl_limits.connections(),
                cfg.cluster.as_ref().map_or_else(|| ClusterConfig::default().renew_every, |c| c.renew_every),
            )?
            .counted("ctl"),
        ),
    };
    let (store, state_store, ctl_store) = (
        store.limited("log", log_limits),
        state_store.limited("state", state_limits),
        ctl_store.limited("ctl", ctl_limits),
    );
    let firehose = Firehose::new(crate::firehose::Options {
        ring_bytes: cfg.firehose_ring_bytes,
        max_lag_bytes: cfg.firehose_max_lag_bytes,
        readahead_bytes: cfg.backfill_readahead_bytes,
        backfill_cache_bytes: cfg.backfill_cache_bytes,
        max_backfills: cfg.firehose_max_backfills,
        max_per_ip: cfg.firehose_max_per_ip,
        write_idle: crate::firehose::DEFAULT_WRITE_IDLE,
        runtime: (cfg.firehose_threads > 0).then(|| crate::firehose::runtime(cfg.firehose_threads)),
        max_labelled: crate::firehose::DEFAULT_MAX_LABELLED,
        start_floor: None,
    });
    firehose.set_max_queue_bytes(cfg.firehose_merge_queue_bytes.max(1));
    let (merger_tx, merger_rx) = tokio::sync::mpsc::unbounded_channel();
    let n = cfg.shards;
    let table = crate::partitions::PartitionTable::new(n);
    let lookup_parts = table.clone();
    let lookup: worker::PartitionLookup = Arc::new(move |did: &str| lookup_parts.for_key(did));
    let repo_bytes = crate::memory::current().map_or(0, |s| s.repo) as usize;
    let limits = worker::CacheLimits {
        entries: cfg.cache_per_worker,
        bytes: repo_bytes / cfg.workers.max(1),
        prefetch_bytes: cfg.lazy_mst_prefetch_bytes,
        unload_idle: cfg.lazy_mst_unload_idle,
    };
    crate::mst_store::NODE_CACHE.set_bytes(cfg.lazy_mst_node_cache_bytes);
    let secrets = Arc::new(crate::secrets::Secrets::from_config(&cfg.kek, cfg.dev_mode)?);
    tracing::info!(kek = secrets.current_kid(), unwrap_keks = ?secrets.kids(), dev = secrets.is_dev(), "secrets at rest");
    secrets.check_key_service().await?;
    let workers =
        worker::spawn_with_secrets(cfg.workers, limits, lookup, tokio::runtime::Handle::current(), secrets.clone());
    let plc = crate::plc::Plc::from_config(&cfg.plc, &cfg.plc_url, cfg.dev_mode, &secrets).await?;

    let mut cc = cfg.cluster.clone().unwrap_or_else(|| ClusterConfig {
        node_id: "single".into(),
        addr: cfg.public_url.clone(),
        ..Default::default()
    });
    cc.shards = n;
    crate::version::init_metrics();
    // before the join, which may fence our own previous incarnation's log
    crate::metrics::init_counters();
    let started = std::time::Instant::now();
    let cluster = Cluster::join(cc, ctl_store).await?;
    // route by this prefix's layout (it may differ from --shards: splits,
    // merges, or a different count at creation)
    table.replace_layout(cluster.layout());
    cluster.set_reshard_policy(cfg.reshard_policy.clone());
    let lease = cluster.clone();
    let log = NodeLog::start_with_inflight(
        store.clone(),
        NodeLogConfig {
            log_id: cluster.log_id.clone(),
            writer: cluster.writer,
            max_segment_bytes: cfg.max_segment_bytes,
            hedge_after: cfg.hedge_after,
            lease_ok: Some(Arc::new(move || lease.lease_valid())),
        },
        cfg.log_inflight,
        merger_tx.clone(),
    );
    log.live.set_max_bytes(cfg.live_ring_bytes);
    firehose.set_source(&log.log_id, Some(crate::firehose::Source::Local(log.wm.clone())));
    *firehose.store.write() = Some(store.clone());
    {
        // never announce a watermark beyond our node lease
        let (c, wm) = (cluster.clone(), log.wm.clone());
        tokio::spawn(async move {
            loop {
                wm.set_lease_expiry(c.lease_expiry_us());
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        });
        log.spawn_checkpoints(cfg.checkpoint_every, cfg.checkpoint_stagger);
    }
    let http = match &cfg.peer_tls {
        Some(t) => {
            anyhow::ensure!(
                t.node_id() == cluster.cfg.node_id,
                "the peer TLS certificate names node {:?} but this node is {:?} (--node-id)",
                t.node_id(),
                cluster.cfg.node_id
            );
            anyhow::ensure!(
                cluster.cfg.addr.starts_with("https://"),
                "with peer TLS the advertised address must be https:// (got {:?})",
                cluster.cfg.addr
            );
            let http = crate::http::PeerClient::new(cfg.peer_connections, t.clone());
            let c = cluster.clone();
            http.set_registry(Arc::new(move |origin: &str| {
                let at = |addr: &str| crate::http::split_origin(addr.trim_end_matches('/')).0 == origin;
                let mut ids: Vec<String> = c.peers().into_iter().filter(|l| at(&l.addr)).map(|l| l.node_id).collect();
                for r in c.layout().shards.iter() {
                    if let Some((id, addr)) = c.owner_of(r.id) {
                        if at(&addr) && !ids.contains(&id) {
                            ids.push(id);
                        }
                    }
                }
                ids
            }));
            http
        }
        None => crate::http::PeerClient::lone(),
    };
    let spaces = cfg.spaces.then(|| {
        Arc::new(crate::space::Spaces::new(crate::space::Limits {
            max_records: cfg.space_repo_max_records,
            oplog_retention: cfg.space_oplog_retention,
        }))
    });
    let node = Arc::new(crate::node::Node {
        cluster: cluster.clone(),
        log: log.clone(),
        store: store.clone(),
        state_store: state_store.clone(),
        table: table.clone(),
        firehose: firehose.clone(),
        merger_tx,
        workers: workers.clone(),
        disk_cache: cfg.cache_dir.clone().map(|dir| crate::partition::DiskCacheConfig {
            dir,
            node_bytes: cfg.disk_cache_bytes,
            shard_bytes: cfg.disk_cache_shard_bytes,
        }),
        internal_token: cfg.internal_token.clone(),
        http: http.clone(),
        recent_cap: cfg.preload_recent,
        followers: Default::default(),
        spaces: spaces.clone(),
    });
    crate::node::export_sst_meta_bytes(&table);
    crate::memory::register(&table, &cluster, &workers);
    let host: Arc<dyn ShardHost> = node.clone();
    let node_handle = node.clone();
    // first membership step inline, so a lone node serves with all its shards
    cluster.first_step(&host).await?;
    // Only now merge: the step registered a follower for every live peer, so
    // the merger never settles past the start floor on our own log's
    // watermark alone (a peer followed after that would owe only its events
    // above the new position; the ones below it would be lost).
    firehose.spawn_merger(merger_rx);
    cluster.spawn(host);
    if let Some(rc) = cfg.log_retention.clone() {
        let (c, l) = (cluster.clone(), cluster.clone());
        let members = crate::retention::Membership {
            live_logs: Box::new(move || c.peers().into_iter().map(|p| p.log_id).chain([c.log_id.clone()]).collect()),
            leader: Box::new(move || l.leads_slot0()),
        };
        crate::retention::Retention::new(store.clone(), log.clone(), rc, members).spawn();
    }
    if let Some(gc) = cfg.reshard_gc.clone() {
        let (l, v, t) = (cluster.clone(), cluster.clone(), table.clone());
        let hooks = crate::reshard_gc::Hooks {
            leader: Box::new(move || l.leads_slot0()),
            lease_ok: Box::new(move || v.lease_valid()),
            owned: Box::new(move || t.owned().into_iter().map(|p| (p.id, p.db.clone())).collect()),
            crash_at: None,
        };
        crate::reshard_gc::ReshardGc::new(state_store.clone(), gc, hooks).spawn();
    }
    tracing::info!(
        node = %cluster.cfg.node_id, log = %cluster.log_id, writer = cluster.writer, shards = cluster.layout().shards.len(),
        owned = cluster.owned().len(), elapsed_ms = started.elapsed().as_millis() as u64, "node ready"
    );

    let app = Arc::new(xrpc::App {
        spaces,
        space_blob_accounts: Default::default(),
        http_drain: Default::default(),
        jwt: auth::Jwt::new(&cfg.jwt_secret, &cfg.service_did),
        store: state_store,
        workers,
        partitions: table,
        firehose,
        tids: crate::tid::TidClock::new(),
        public_url: cfg.public_url.clone(),
        handle_domains: Arc::new(crate::handle_domains::HandleDomains::new(&cfg.handle_domain)),
        write_permits: Arc::new(tokio::sync::Semaphore::new(cfg.max_inflight_writes)),
        read_permits: Arc::new(tokio::sync::Semaphore::new(cfg.max_queued_reads.max(1))),
        exports: Arc::new(tokio::sync::Semaphore::new(cfg.max_exports.max(1))),
        imports: xrpc::ImportBudget::new(cfg.import_memory_bytes.unwrap_or(plan.part("import")), cfg.import_wait),
        admin_token: cfg.admin_token.clone(),
        did_resolver: Arc::new(crate::did_resolver::DidResolver::new(&cfg.plc_url, cfg.dev_mode)),
        http,
        ratelimit: Arc::new(crate::ratelimit::Limiter::new(&cfg)),
        crawlers: Arc::new(xrpc::crawlers::Crawlers::new(&cfg.crawlers, cfg.crawl_interval)),
        ptr: crate::ptr::PtrCache::new(cfg.ptr_resolver.as_ref()),
        asn: crate::asn::AsnCache::with(cfg.asn_whois.clone(), cfg.asn_debounce, crate::asn::MAX_ENTRIES),
        secrets,
        plc,
        config: Arc::new(cfg),
        cluster: Some(cluster),
        log,
        node: node_handle,
        ui,
    });
    if let Some(s) = &app.spaces {
        crate::metrics::init_space_counters();
        s.outbox.start(Arc::downgrade(&app));
        s.fanout.start(Arc::downgrade(&app));
        crate::space::retention::start(&app);
        s.start_revocations(app.store.clone()).await;
    }
    Ok(app)
}

pub fn spawn_reporters(app: &Arc<xrpc::App>) {
    stats::spawn_reporter(Duration::from_secs(5));
    let parts = app.partitions.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        loop {
            tick.tick().await;
            let now = crate::nodelog::seq_floor(crate::tid::now_micros());
            // one node log: report its watermark lag once
            if let Some(p) = parts.owned().first() {
                let lag_us = (now - p.wm.get()).max(0) >> 8;
                crate::metrics::WATERMARK_LAG.with_label_values(&["node"]).set(lag_us);
            }
        }
    });
    stats::spawn_stall_detector();
}

/// Builds the app and serves it in background tasks. Returns the public
/// address (tests bind 127.0.0.1:0).
pub async fn spawn(
    cfg: Config,
    public: tokio::net::TcpListener,
    peer: Option<tokio::net::TcpListener>,
) -> anyhow::Result<(Arc<xrpc::App>, std::net::SocketAddr)> {
    anyhow::ensure!(
        peer.is_some() == cfg.peer_tls.is_some(),
        "a peer listener goes with peer TLS, and peer TLS with a peer listener"
    );
    let app = build(cfg).await?;
    let addr = public.local_addr()?;
    if let Some(peer) = peer {
        spawn_peer_listener(&app, peer)?;
    }
    let router = public_router(&app);
    let opts = public_serve_options(&app);
    tokio::spawn(async move {
        if let Err(e) = serve_with(public, router, opts).await {
            tracing::error!("server exited: {e:#}");
        }
    });
    if let Some(m) = &app.config.metrics_listen {
        spawn_metrics_listener(&app, tokio::net::TcpListener::bind(m).await?);
    }
    Ok((app, addr))
}

pub fn spawn_metrics_listener(app: &Arc<xrpc::App>, listener: tokio::net::TcpListener) {
    let r = metrics_router(app);
    tokio::spawn(async move {
        if let Err(e) = serve(listener, r).await {
            tracing::error!("metrics server exited: {e:#}");
        }
    });
}

/// The full [`router`] over mTLS, with the peer HTTP/2 profile.
pub fn spawn_peer_listener(app: &Arc<xrpc::App>, listener: tokio::net::TcpListener) -> anyhow::Result<()> {
    let tls = app.config.peer_tls.as_ref().ok_or_else(|| anyhow::anyhow!("a peer listener needs peer TLS"))?;
    let opts = ServeOptions {
        h2: H2Profile::Peer,
        max_connections: app.config.max_connections,
        tls: Some(tls.server_config()),
        drain: Some(app.http_drain.clone()),
    };
    let router = router(app);
    tokio::spawn(async move {
        if let Err(e) = serve_with(listener, router, opts).await {
            tracing::error!("peer server exited: {e:#}");
        }
    });
    Ok(())
}

/// Stripped on [`public_router`], so a client's copy means nothing.
const PEER_ONLY_HEADERS: [&str; 4] = [
    crate::forward::FORWARDED_HEADER,
    "x-vlpds-internal",
    crate::ratelimit::CLIENT_IP_HEADER,
    crate::forward::RESEND_HEADER,
];

/// [`router`] without `/internal/*`, and with the peer-only headers dropped
/// before anything reads them: a forwarded marker is served as the client
/// request it is, and `x-vlpds-internal` doesn't skip rate limits.
pub fn public_router(app: &Arc<xrpc::App>) -> axum::Router {
    router(app).layer(axum::middleware::from_fn(
        |mut req: axum::extract::Request, next: axum::middleware::Next| async move {
            let p = req.uri().path();
            if p == "/internal" || p.starts_with("/internal/") {
                return axum::http::StatusCode::NOT_FOUND.into_response();
            }
            for h in PEER_ONLY_HEADERS {
                req.headers_mut().remove(h);
            }
            next.run(req).await
        },
    ))
}

const METRICS_PATHS: [&str; 2] = ["/metrics", "/debug/pprof/"];

/// The peer listener's router, and the base of [`public_router`].
pub fn router(app: &Arc<xrpc::App>) -> axum::Router {
    let r = with_forwarding(app, xrpc::router(app.clone()));
    if app.config.metrics_listen.is_none() {
        return r;
    }
    r.layer(axum::middleware::from_fn(|req: axum::extract::Request, next: axum::middleware::Next| async move {
        let p = req.uri().path();
        if METRICS_PATHS.iter().any(|m| p == *m || (m.ends_with('/') && p.starts_with(m))) {
            return axum::http::StatusCode::NOT_FOUND.into_response();
        }
        next.run(req).await
    }))
}

fn metrics_router(app: &Arc<xrpc::App>) -> axum::Router {
    axum::Router::new()
        .route("/metrics", axum::routing::get(|| async { crate::metrics::render() }))
        .merge(crate::profiling::routes())
        .with_state(app.clone())
}

/// DESIGN.md "HTTP".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum H2Profile {
    Peer,
    /// Smaller: what one client connection can make the server buffer, and
    /// how many requests it can start at once, scale with these.
    Public,
}

#[derive(Clone, Debug)]
pub struct ServeOptions {
    pub h2: H2Profile,
    /// At the cap new connections wait in the kernel's accept queue. 0: no cap.
    pub max_connections: usize,
    pub tls: Option<Arc<rustls::ServerConfig>>,
    /// None: served until the process exits.
    pub drain: Option<Drain>,
}

impl Default for ServeOptions {
    fn default() -> Self {
        ServeOptions { h2: H2Profile::Peer, max_connections: DEFAULT_MAX_CONNECTIONS, tls: None, drain: None }
    }
}

/// The public listener's options.
pub fn public_serve_options(app: &xrpc::App) -> ServeOptions {
    ServeOptions {
        h2: H2Profile::Public,
        max_connections: app.config.max_connections,
        tls: None,
        drain: Some(app.http_drain.clone()),
    }
}

const SERVING: u8 = 0;
const DRAINING: u8 = 1;
const CUT: u8 = 2;

/// Ends a node's public and peer listeners at shutdown. Exiting with
/// requests in flight would drop answers the node may already have acted
/// on (a forwarded write applied at its owner): the client could only take
/// that as unknown, and a load balancer that resends a request whose
/// connection failed resends it with its spent DPoP proof, which is then
/// refused, a definite 401 for an applied write.
#[derive(Clone, Debug)]
pub struct Drain(Arc<tokio::sync::watch::Sender<u8>>);

impl Default for Drain {
    fn default() -> Self {
        Drain(Arc::new(tokio::sync::watch::channel(SERVING).0))
    }
}

impl Drain {
    fn subscribe(&self) -> tokio::sync::watch::Receiver<u8> {
        self.0.subscribe()
    }

    /// Stops accepting connections, closes idle ones and lets every request
    /// in flight be answered (HTTP/1 closes after it, HTTP/2 sends GOAWAY)
    /// for up to `grace`; then cuts what is left. True: nothing was cut.
    pub async fn run(&self, grace: Duration) -> bool {
        self.0.send_replace(DRAINING);
        if tokio::time::timeout(grace, self.0.closed()).await.is_ok() {
            return true;
        }
        self.0.send_replace(CUT);
        false
    }
}

/// Resolves once `rx` reaches `level`; never if its [`Drain`] is gone.
async fn reached(rx: &mut tokio::sync::watch::Receiver<u8>, level: u8) {
    if rx.wait_for(|s| *s >= level).await.is_err() {
        std::future::pending::<()>().await;
    }
}

/// Serves `$conn` (a hyper connection) to its end, or until its drain cuts it.
macro_rules! serve_drained {
    ($conn:expr, $stop:expr) => {{
        let conn = $conn;
        tokio::pin!(conn);
        match $stop {
            None => {
                let _ = conn.await;
            }
            Some(mut stop) => {
                tokio::select! {
                    _ = conn.as_mut() => {}
                    _ = reached(&mut stop, DRAINING) => {
                        conn.as_mut().graceful_shutdown();
                        tokio::select! {
                            _ = conn.as_mut() => {}
                            _ = reached(&mut stop, CUT) => {}
                        }
                    }
                }
            }
        }
    }};
}

pub const DEFAULT_MAX_CONNECTIONS: usize = 50_000;

/// Tests inject failing listeners.
pub trait Accept: Send + 'static {
    fn poll_accept(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<(tokio::net::TcpStream, std::net::SocketAddr)>>;
}

impl Accept for tokio::net::TcpListener {
    fn poll_accept(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<(tokio::net::TcpStream, std::net::SocketAddr)>> {
        tokio::net::TcpListener::poll_accept(self, cx)
    }
}

pub async fn serve(listener: tokio::net::TcpListener, router: axum::Router) -> anyhow::Result<()> {
    serve_with(listener, router, ServeOptions::default()).await
}

/// Not axum::serve: it doesn't expose HTTP/2 settings, and hyper's default
/// 64KB connection window chops request bodies on busy connections into
/// tiny DATA frames, which trips h2's small-frame flood guard (DESIGN.md
/// "HTTP").
///
/// An accept error (EMFILE and the like) is retried after a short pause, as
/// axum::serve does, instead of ending the server and the process without
/// a graceful handoff.
pub async fn serve_with<A: Accept>(mut listener: A, router: axum::Router, opts: ServeOptions) -> anyhow::Result<()> {
    use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
    use hyper_util::server::conn::auto::Builder;
    use hyper_util::service::TowerToHyperService;
    let (stream_window, conn_window, streams) = match opts.h2 {
        H2Profile::Peer => (4 << 20, 64 << 20, 1024),
        H2Profile::Public => (1 << 20, 8 << 20, 256),
    };
    let mut builder = Builder::new(TokioExecutor::new());
    builder
        .http1()
        // the timer enables hyper's header read timeout (slowloris): a
        // client gets 30 s to send a request head, which also bounds an idle
        // keep-alive connection waiting for its next request
        .timer(TokioTimer::new())
        .header_read_timeout(Duration::from_secs(30))
        .keep_alive(true);
    builder
        .http2()
        .timer(TokioTimer::new())
        .initial_stream_window_size(stream_window)
        .initial_connection_window_size(conn_window)
        .max_frame_size(256 << 10)
        // per connection; the load generator spreads its requests over 64
        // connections, peers over --peer-connections
        .max_concurrent_streams(streams)
        // atproto heads (DPoP proof + access token) are a few KiB
        .max_header_list_size(32 << 10)
        // PING idle clients; drop the connection after 10 s without a PONG
        .keep_alive_interval(Duration::from_secs(20))
        .keep_alive_timeout(Duration::from_secs(10))
        // rapid-reset (CVE-2023-44487) and local-error-reset floods: hyper/h2's
        // defaults, stated so a change is a decision
        .max_pending_accept_reset_streams(20)
        .max_local_error_reset_streams(1024);
    let active = ActiveRequests {
        h1: crate::metrics::HTTP_SERVER_ACTIVE.with_label_values(&["h1"]),
        h2: crate::metrics::HTTP_SERVER_ACTIVE.with_label_values(&["h2"]),
    };
    let slots = (opts.max_connections > 0).then(|| Arc::new(tokio::sync::Semaphore::new(opts.max_connections)));
    let acceptor = opts.tls.clone().map(tokio_rustls::TlsAcceptor::from);
    let mut stop = opts.drain.as_ref().map(Drain::subscribe);
    loop {
        let next = async {
            // a slot first: at the cap, connections wait in the accept queue
            let slot = match &slots {
                Some(s) => Some(s.clone().acquire_owned().await.expect("never closed")),
                None => None,
            };
            (slot, std::future::poll_fn(|cx| listener.poll_accept(cx)).await)
        };
        let (slot, accepted) = match stop.as_mut() {
            None => next.await,
            Some(rx) => tokio::select! {
                n = next => n,
                // the listener closes with this: new connections are refused
                _ = reached(rx, DRAINING) => return Ok(()),
            },
        };
        let (sock, peer) = match accepted {
            Ok(c) => c,
            Err(e) => {
                crate::metrics::HTTP_SERVER_ACCEPT_ERRORS.inc();
                tracing::warn!("accept failed (retrying): {e}");
                // EMFILE and friends last until something closes: don't spin
                tokio::time::sleep(ACCEPT_ERROR_PAUSE).await;
                continue;
            }
        };
        let _ = sock.set_nodelay(true);
        crate::metrics::HTTP_SERVER_CONNECTIONS.inc();
        let (acceptor, builder, stop) = (acceptor.clone(), builder.clone(), stop.clone());
        // set once the handshake has verified the client certificate
        let identity: Arc<std::sync::OnceLock<crate::peer_tls::PeerIdentity>> = Arc::default();
        let id = identity.clone();
        let svc = TowerToHyperService::new(Track {
            inner: tower::ServiceExt::map_request(
                router.clone(),
                move |mut req: axum::http::Request<hyper::body::Incoming>| {
                    req.extensions_mut().insert(axum::extract::ConnectInfo(peer));
                    if let Some(id) = id.get() {
                        req.extensions_mut().insert(id.clone());
                    }
                    req
                },
            ),
            active: active.clone(),
        });
        tokio::spawn(async move {
            match acceptor {
                None => {
                    crate::metrics::HTTP_SERVER_OPEN.inc();
                    serve_drained!(builder.serve_connection_with_upgrades(TokioIo::new(sock), svc), stop);
                }
                Some(acceptor) => {
                    // on the connection's task: a slow or silent client
                    // holds only its own slot
                    let tls =
                        match tokio::time::timeout(crate::peer_tls::HANDSHAKE_TIMEOUT, acceptor.accept(sock)).await {
                            Ok(Ok(s)) => s,
                            Ok(Err(e)) => {
                                crate::peer_tls::server_handshake_failed();
                                tracing::warn!(%peer, "peer TLS handshake failed: {e}");
                                return;
                            }
                            Err(_) => {
                                crate::peer_tls::server_handshake_failed();
                                tracing::warn!(%peer, "peer TLS handshake timed out");
                                return;
                            }
                        };
                    if let Some(id) = crate::peer_tls::PeerIdentity::of(tls.get_ref().1) {
                        let _ = identity.set(id);
                    }
                    crate::metrics::HTTP_SERVER_OPEN.inc();
                    serve_drained!(builder.serve_connection_with_upgrades(TokioIo::new(tls), svc), stop);
                }
            }
            crate::metrics::HTTP_SERVER_OPEN.dec();
            // an upgraded connection (subscribeRepos) lives on past this
            // without a slot: the firehose caps its subscribers itself
            drop(slot);
        });
    }
}

const ACCEPT_ERROR_PAUSE: Duration = Duration::from_millis(50);

#[derive(Clone)]
struct ActiveRequests {
    h1: prometheus::IntGauge,
    h2: prometheus::IntGauge,
}

/// Counts requests (h2: streams) until their response head.
#[derive(Clone)]
struct Track<S> {
    inner: S,
    active: ActiveRequests,
}

/// Decrements on drop, so a reset stream (future dropped) is counted out.
struct ActiveGuard(prometheus::IntGauge);

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.dec();
    }
}

impl<S, B> tower::Service<axum::http::Request<B>> for Track<S>
where
    S: tower::Service<axum::http::Request<B>>,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = futures::future::BoxFuture<'static, Result<S::Response, S::Error>>;

    fn poll_ready(&mut self, cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), S::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: axum::http::Request<B>) -> Self::Future {
        let g = if req.version() == axum::http::Version::HTTP_2 { &self.active.h2 } else { &self.active.h1 };
        g.inc();
        let guard = ActiveGuard(g.clone());
        let f = self.inner.call(req);
        Box::pin(async move {
            let r = f.await;
            drop(guard);
            r
        })
    }
}

struct ClusterRouter {
    app: Arc<xrpc::App>,
}

#[async_trait::async_trait]
impl crate::forward::Router for ClusterRouter {
    fn remote_owner(&self, did: &str) -> Option<String> {
        self.app.remote_owner(did)
    }
    async fn resolve_handle(&self, handle: &str) -> Option<String> {
        self.app.resolve_handle(handle).await.ok().flatten()
    }
    fn app(&self) -> Option<&xrpc::App> {
        Some(&self.app)
    }
    fn alone(&self) -> bool {
        self.app.cluster.as_ref().is_some_and(|c| c.alone())
    }
    fn stopping_alone(&self) -> bool {
        self.app.cluster.as_ref().is_some_and(|c| c.stopping() && c.peers().is_empty())
    }
}

fn with_forwarding(app: &Arc<xrpc::App>, router: axum::Router) -> axum::Router {
    if app.cluster.is_none() {
        return router;
    }
    // one Arc clone per request (router and client together)
    let ctx = Arc::new((ClusterRouter { app: app.clone() }, app.http.clone()));
    router.layer(axum::middleware::from_fn(move |req, next| {
        let ctx = ctx.clone();
        async move { crate::forward::route(&ctx.0, &ctx.1, req, next).await }
    }))
}

/// Serving on after the handoff: peers' routing follows it while we still
/// accept (and forward).
pub const SHUTDOWN_SETTLE: Duration = Duration::from_millis(500);
/// Bounds the wait for requests in flight at shutdown: a resent write's
/// budget (`forward::RETRY_BUDGET`) plus a forward's deadline, within the
/// deploy's 60 s minimum stop grace.
pub const SHUTDOWN_GRACE: Duration = Duration::from_secs(30);

/// SIGTERM: [`shutdown`], [`settle_for`] more of serving, then the
/// listeners drain ([`Drain::run`] for `grace`) while firehose subscribers
/// are told we are going away. False: requests still in flight were cut.
pub async fn shutdown_gracefully(app: &Arc<xrpc::App>, grace: Duration) -> bool {
    shutdown(app).await;
    tokio::time::sleep(settle_for(app)).await;
    // they resume from their cursors elsewhere, or here after the restart,
    // and see a going-away close instead of their socket dropping at exit
    app.firehose.close_subscribers();
    app.http_drain.run(grace).await
}

/// [`SHUTDOWN_SETTLE`] with peers; none for a node without any, whose
/// routing nobody follows.
pub fn settle_for(app: &xrpc::App) -> Duration {
    match &app.cluster {
        Some(c) if !c.peers().is_empty() => SHUTDOWN_SETTLE,
        _ => Duration::ZERO,
    }
}

/// Hands every shard back and drops the node lease, so successors take over
/// immediately instead of waiting out the lease TTL.
pub async fn shutdown(app: &Arc<xrpc::App>) {
    if let Some(c) = &app.cluster {
        let host: Arc<dyn ShardHost> = app.node.clone();
        tracing::info!(shards = c.owned().len(), "graceful shutdown: releasing shards");
        if let Err(e) = c.shutdown(&host).await {
            // Our lease stays (renewals stopped): peers presume us dead and
            // fence our log, as does our own restart (it reads our lease).
            tracing::error!("{e:#}: exiting nonzero without dropping our lease (peers or our restart fence the log)");
            crate::lifecycle::fail_stop(8, "shutdown_fence");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_fail_closed_outside_dev_mode() {
        let dev = Config::default();
        assert!(dev.dev_mode);
        dev.check_secrets().expect("dev defaults are fine in dev mode");
        let empty_admin = Config { admin_token: String::new(), ..Config::default() };
        assert!(empty_admin.check_secrets().is_err(), "empty admin token refused even in dev mode");

        let prod = |jwt: &str, admin: &str, internal: &str| Config {
            dev_mode: false,
            jwt_secret: jwt.into(),
            admin_token: admin.into(),
            internal_token: internal.into(),
            kek: crate::secrets::KekConfig { local: Some(crate::secrets::KekBytes::random()), ..Default::default() },
            plc: crate::plc::PlcConfig {
                rotation_key: Some(crate::plc::RotationKey::Key(Arc::new(crate::crypto::Keypair::generate()))),
                ..Default::default()
            },
            ..Config::default()
        };
        let (a, b, c) = ("a".repeat(32), "b".repeat(32), "c".repeat(32));
        prod(&a, &b, &c).check_secrets().expect("strong distinct secrets");
        // a PLC rotation key is required (DIDs are registered), and the
        // unregistered dev mode is refused
        let e = Config { plc: Default::default(), ..prod(&a, &b, &c) }.check_secrets().unwrap_err();
        assert!(e.to_string().contains("PLC rotation key"), "{e}");
        let unreg = crate::plc::PlcConfig { mode: crate::plc::PlcMode::Unregistered, ..prod(&a, &b, &c).plc };
        assert!(Config { plc: unreg, ..prod(&a, &b, &c) }.check_secrets().is_err());
        // a KEK is required, and not the dev one
        let e = Config { kek: Default::default(), ..prod(&a, &b, &c) }.check_secrets().unwrap_err();
        assert!(e.to_string().contains("key-encryption key"), "{e}");
        let dev_kek = crate::secrets::KekConfig { local: Some(crate::secrets::dev_kek()), ..Default::default() };
        assert!(Config { kek: dev_kek, ..prod(&a, &b, &c) }.check_secrets().is_err());
        // dev defaults
        let e = Config { dev_mode: false, ..Config::default() }.check_secrets().unwrap_err();
        assert!(e.to_string().contains("VLPDS_JWT_SECRET"), "{e}");
        assert!(prod(&a, DEV_ADMIN_TOKEN, &c).check_secrets().is_err());
        assert!(prod(&a, &b, DEV_INTERNAL_TOKEN).check_secrets().is_err());
        // unset / short / shared
        assert!(prod("", &b, &c).check_secrets().is_err());
        assert!(prod(&a, &"b".repeat(31), &c).check_secrets().is_err());
        let e = prod(&a, &b, &b).check_secrets().unwrap_err();
        assert!(e.to_string().contains("must differ"), "{e}");
        // the MinIO default S3 credentials, and their Debug is redacted
        let s3 = |k: &str| crate::store::S3Config {
            endpoint: "http://s3".into(),
            bucket: "b".into(),
            access_key: k.into(),
            secret_key: format!("{k}-secret"),
            region: "r".into(),
        };
        prod(&a, &b, &c).check_secrets().expect("no S3 (memory store)");
        Config { s3: Some(s3("AKIAREAL")), ..prod(&a, &b, &c) }.check_secrets().expect("real S3 credentials");
        let e = Config { s3: Some(s3(DEV_S3_CREDENTIAL)), ..prod(&a, &b, &c) }.check_secrets().unwrap_err();
        assert!(e.to_string().contains("MinIO defaults"), "{e}");
        Config { s3: Some(s3(DEV_S3_CREDENTIAL)), ..Config::default() }.check_secrets().expect("dev mode allows them");
        let dbg = format!("{:?}", s3("AKIAREAL"));
        assert!(!dbg.contains("AKIAREAL"), "{dbg}");
    }

    /// Accept errors (EMFILE and the like) are retried, not fatal: the
    /// server keeps serving; and at the connection cap a new connection
    /// waits until one closes.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn accept_errors_are_retried_and_connections_capped() {
        struct Flaky {
            inner: tokio::net::TcpListener,
            fail: usize,
        }
        impl Accept for Flaky {
            fn poll_accept(
                &mut self,
                cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<std::io::Result<(tokio::net::TcpStream, std::net::SocketAddr)>> {
                if self.fail > 0 {
                    self.fail -= 1;
                    return std::task::Poll::Ready(Err(std::io::Error::from_raw_os_error(24)));
                    // EMFILE
                }
                self.inner.poll_accept(cx)
            }
        }
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let before = crate::metrics::HTTP_SERVER_ACCEPT_ERRORS.get();
        let router = axum::Router::new().route("/ok", axum::routing::get(|| async { "ok" }));
        let server = tokio::spawn(serve_with(
            Flaky { inner: l, fail: 3 },
            router,
            ServeOptions { max_connections: 1, ..Default::default() },
        ));
        let get = || async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
            c.write_all(b"GET /ok HTTP/1.1\r\nhost: x\r\n\r\n").await.unwrap();
            let mut buf = [0u8; 256];
            let n = c.read(&mut buf).await.unwrap();
            (String::from_utf8_lossy(&buf[..n]).into_owned(), c)
        };
        let (first, held) =
            tokio::time::timeout(Duration::from_secs(5), get()).await.expect("served after accept errors");
        assert!(first.starts_with("HTTP/1.1 200"), "{first}");
        assert!(crate::metrics::HTTP_SERVER_ACCEPT_ERRORS.get() >= before + 3);
        assert!(!server.is_finished(), "accept errors don't end the server");
        // the one slot is held by `held` (keep-alive): the next connection waits
        let second = tokio::spawn(get());
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!second.is_finished(), "served past the connection cap");
        drop(held);
        let (r, _) =
            tokio::time::timeout(Duration::from_secs(5), second).await.expect("served once a slot freed").unwrap();
        assert!(r.starts_with("HTTP/1.1 200"), "{r}");
        server.abort();
    }

    /// `metrics_listen` moves /metrics and /debug/pprof off the app port.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn metrics_listen_splits_routes() {
        use tower::ServiceExt;
        let status = |r: axum::Router, path: &'static str| async move {
            let req = axum::http::Request::get(path)
                .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 1))))
                .body(axum::body::Body::empty())
                .unwrap();
            r.oneshot(req).await.unwrap().status().as_u16()
        };
        let app = build(Config::default()).await.unwrap();
        assert_eq!(status(router(&app), "/metrics").await, 200, "default: on the app port");
        let app = build(Config { metrics_listen: Some("127.0.0.1:0".into()), ..Config::default() }).await.unwrap();
        assert_eq!(status(router(&app), "/metrics").await, 404);
        assert_eq!(status(router(&app), "/debug/pprof/profile").await, 404);
        assert_eq!(status(router(&app), "/xrpc/_health").await, 200);
        assert_eq!(status(metrics_router(&app), "/metrics").await, 200);
        assert_ne!(status(metrics_router(&app), "/debug/pprof/profile").await, 404);
    }
}
