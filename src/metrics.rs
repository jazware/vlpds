//! Prometheus metrics, exposed at /metrics.

use prometheus::{
    exponential_buckets, register_gauge, register_gauge_vec, register_histogram, register_histogram_vec,
    register_int_counter, register_int_counter_vec, register_int_gauge, register_int_gauge_vec, Gauge, GaugeVec,
    Histogram, HistogramVec, IntCounter, IntCounterVec, IntGauge, IntGaugeVec,
};
use std::sync::LazyLock;

fn latency_buckets() -> Vec<f64> {
    exponential_buckets(0.0001, 2.0, 20).unwrap()
}

macro_rules! lazy {
    ($name:ident: $t:ty = $e:expr) => {
        pub static $name: LazyLock<$t> = LazyLock::new(|| $e.unwrap());
    };
}

lazy!(RUNTIME_LATE: Histogram = register_histogram!("vlpds_runtime_tick_late_seconds", "How late a 10 ms ticker on the tokio runtime wakes (runtime threads blocked or starved)", exponential_buckets(0.001, 2.0, 12).unwrap()));
lazy!(RUNTIME_LATE_TOTAL: prometheus::Counter = prometheus::register_counter!("vlpds_runtime_late_seconds_total", "Sum of the 10 ms ticker's lateness: time the runtime could not run a ready task promptly"));

lazy!(HTTP_REQUESTS: IntCounterVec = register_int_counter_vec!("vlpds_http_requests_total", "XRPC requests by method and status", &["method", "status"]));
lazy!(HTTP_DURATION: HistogramVec = register_histogram_vec!("vlpds_http_request_duration_seconds", "XRPC request latency", &["method"], latency_buckets()));
lazy!(HTTP_INFLIGHT: IntGauge = register_int_gauge!("vlpds_http_requests_inflight", "XRPC requests in flight"));
lazy!(HTTP_CLIENT_POOL_WAITS: IntCounterVec = register_int_counter_vec!("vlpds_http_client_pool_waits_total", "Proxy requests that waited for an upstream connection at the per-host cap (src/http.rs h1::MAX_CONNS)", &["role"]));
lazy!(HTTP_SERVER_CONNECTIONS: IntCounter = register_int_counter!("vlpds_http_server_connections_total", "Accepted inbound TCP connections"));
lazy!(HTTP_SERVER_OPEN: IntGauge = register_int_gauge!("vlpds_http_server_connections_open", "Inbound connections open"));
lazy!(HTTP_SERVER_ACCEPT_ERRORS: IntCounter = register_int_counter!("vlpds_http_server_accept_errors_total", "Failed accepts on a listener (retried after 50 ms; e.g. out of file descriptors)"));
lazy!(HTTP_SERVER_ACTIVE: IntGaugeVec = register_int_gauge_vec!("vlpds_http_server_active_requests", "Inbound requests (h2: streams) awaiting their response head, by HTTP version", &["version"]));
lazy!(RATE_LIMITED: IntCounter = register_int_counter!("vlpds_rate_limited_total", "Requests rejected with 429 RateLimitExceeded"));
lazy!(WRITES_SHED: IntCounter = register_int_counter!("vlpds_writes_shed_total", "Write requests rejected by admission control (503)"));
lazy!(ARGON2_SHED: IntCounter = register_int_counter!("vlpds_argon2_shed_total", "Password checks/hashes (createSession, createAccount, OAuth sign-in, password changes) answered 503 Overloaded: every Argon2 permit stayed busy for 2 s"));
lazy!(PROXY_REJECTED: IntCounterVec = register_int_counter_vec!("vlpds_proxy_rejected_total", "Proxied (AppView/service) requests refused before forwarding, by reason (account_cap: 429 at 64 in flight for one account on its owner)", &["reason"]));
lazy!(HTTP_STALLED_BODIES: IntCounter = register_int_counter!("vlpds_http_stalled_bodies_total", "Proxied/forwarded response bodies dropped because the client stopped reading for 30 s (write-progress deadline, src/http.rs stall)"));

lazy!(COMMITS: IntCounter = register_int_counter!("vlpds_commits_total", "Commits built"));
lazy!(OPS: IntCounterVec = register_int_counter_vec!("vlpds_ops_total", "Record ops committed by action", &["action"]));
lazy!(COMMIT_OPS: Histogram = register_histogram!("vlpds_commit_ops", "Ops per commit (write coalescing)", vec![1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0, 128.0, 200.0]));
lazy!(COMMIT_REQUESTS: Histogram = register_histogram!("vlpds_commit_requests", "Write requests coalesced per commit", vec![1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0, 128.0]));
lazy!(COMMIT_BUILD: Histogram = register_histogram!("vlpds_commit_build_seconds", "CPU time to build+sign a commit", exponential_buckets(0.000005, 2.0, 16).unwrap()));
lazy!(COMMIT_BLOCKS_BYTES: Histogram = register_histogram!("vlpds_commit_car_bytes", "Size of a commit's block CAR", exponential_buckets(256.0, 2.0, 14).unwrap()));
lazy!(WRITE_ERRORS: IntCounterVec = register_int_counter_vec!("vlpds_write_errors_total", "Rejected writes by kind", &["kind"]));
lazy!(WORKER_BATCH: Histogram = register_histogram!("vlpds_worker_batch_messages", "Messages drained per worker loop iteration", exponential_buckets(1.0, 2.0, 14).unwrap()));
lazy!(WORKER_QUEUE: IntGaugeVec = register_int_gauge_vec!("vlpds_worker_queue_depth", "Messages queued per worker", &["worker"]));
lazy!(CACHED_REPOS: IntGaugeVec = register_int_gauge_vec!("vlpds_cached_repos", "Repos held in memory per worker", &["worker"]));
lazy!(LOADING_REPOS: IntGauge = register_int_gauge!("vlpds_repos_loading", "Cold repo loads in progress"));
lazy!(REPO_LOADS: IntCounterVec = register_int_counter_vec!("vlpds_repo_loads_total", "Cold repo loads by result", &["result"]));
lazy!(REPO_LOAD_DURATION: Histogram = register_histogram!("vlpds_repo_load_seconds", "Cold repo load latency (head, account, M/ prefetch, MST root + the first request's paths, blob refs)", latency_buckets()));
lazy!(REPO_EVICTIONS: IntCounter = register_int_counter!("vlpds_repo_evictions_total", "Repos evicted from worker caches"));
lazy!(REPO_CACHE_BYTES: IntGaugeVec = register_int_gauge_vec!("vlpds_repo_cache_bytes", "Approximate heap of the repos a worker holds (their loaded MST paths)", &["worker"]));
lazy!(REPO_PRELOADS: IntCounterVec = register_int_counter_vec!("vlpds_repo_preloads_total", "Preloads of recently written repos after a shard open, by result", &["result"]));
lazy!(LAZY_MST_READS: IntCounterVec = register_int_counter_vec!("vlpds_lazy_mst_reads_total", "Lazy MST store reads by kind (node: M/ point read; leaf: R/ range scan), outside a prefetch", &["kind"]));
lazy!(LAZY_MST_PREFETCH_BYTES: Histogram = register_histogram!("vlpds_lazy_mst_prefetch_bytes", "Bytes of a repo's M/ range read ahead by one scan on a lazy cold open", exponential_buckets(1024.0, 4.0, 10).unwrap()));
lazy!(LAZY_MST_FETCHES: IntCounterVec = register_int_counter_vec!("vlpds_lazy_mst_fetches_total", "Path loads a repo worker handed to the blocking pool before applying writes (lazy MSTs), by result", &["result"]));
lazy!(LAZY_MST_FALLBACKS: IntCounterVec = register_int_counter_vec!("vlpds_lazy_mst_fallbacks_total", "Lazy MST opens rebuilt from all of the repo's records, by reason (missing: no persisted root; invalid: a node or rebuilt subtree didn't match its link)", &["reason"]));
lazy!(LAZY_MST_UNLOADS: IntCounter = register_int_counter!("vlpds_lazy_mst_unloads_total", "Repos whose loaded MST paths were dropped (back to the root) to keep the worker's path cache in its byte budget"));
lazy!(WRITES_ABANDONED: IntCounter = register_int_counter!("vlpds_writes_abandoned_total", "Forwarded writes answered 503 RepoLoading before their worker started them (never applied; the forwarding node retries)"));

lazy!(CHECKPOINT_SHARD: Histogram = register_histogram!("vlpds_checkpoint_shard_seconds", "One shard's checkpoint (applied marker + memtable flush)", latency_buckets()));
lazy!(SEQ_QUEUE: IntGaugeVec = register_int_gauge_vec!("vlpds_sequencer_queue_depth", "Log entries waiting for the sequencer", &["partition"]));
lazy!(SEGMENTS: IntCounterVec = register_int_counter_vec!("vlpds_segments_total", "Segments made durable", &["partition"]));
lazy!(SEGMENT_BYTES: Histogram = register_histogram!("vlpds_segment_bytes", "Segment object size", exponential_buckets(1024.0, 2.0, 14).unwrap()));
lazy!(SEGMENT_EVENTS: Histogram = register_histogram!("vlpds_segment_events", "Firehose events per segment", exponential_buckets(1.0, 2.0, 16).unwrap()));
lazy!(SEGMENT_ENTRIES: Histogram = register_histogram!("vlpds_segment_entries", "Sequenced log entries per segment: firehose events plus private-state writes (OAuth, Spaces, GC), which take a seq but no firehose frame", exponential_buckets(1.0, 2.0, 16).unwrap()));
lazy!(SEGMENT_BYTES_TOTAL: IntCounter = register_int_counter!("vlpds_segment_bytes_total", "Bytes written to the log (uncompressed segments)"));
lazy!(SEGMENT_STALL_SEALS: IntCounter = register_int_counter!("vlpds_segment_stall_seals_total", "Segments sealed early because the oldest PUT in flight stalled (over 2x the recent PUT latency)"));
lazy!(SEGMENT_STORED_BYTES_TOTAL: IntCounter = register_int_counter!("vlpds_segment_stored_bytes_total", "Bytes of segment objects PUT (after compression)"));
lazy!(SEGMENT_COMPRESS: Histogram = register_histogram!("vlpds_segment_compress_seconds", "CPU time to zstd one segment body before its PUT", latency_buckets()));
lazy!(PUT_DURATION: HistogramVec = register_histogram_vec!("vlpds_segment_put_seconds", "Segment PUT latency until durable (incl. hedges/retries)", &["partition"], latency_buckets()));
lazy!(PUT_ATTEMPTS: IntCounterVec = register_int_counter_vec!("vlpds_segment_put_attempts_total", "Segment PUT attempts by result", &["result"]));
lazy!(PUT_HEDGES: IntCounter = register_int_counter!("vlpds_segment_put_hedges_total", "Hedged (duplicate) segment PUTs started"));
lazy!(APPLY_DURATION: Histogram = register_histogram!("vlpds_state_apply_seconds", "SlateDB batch apply latency per segment", latency_buckets()));
lazy!(COMMIT_LATENCY: Histogram = register_histogram!("vlpds_commit_durable_seconds", "Commit enqueue -> durable+applied+acked", latency_buckets()));
lazy!(WATERMARK_LAG: IntGaugeVec = register_int_gauge_vec!("vlpds_watermark_lag_microseconds", "now - partition watermark", &["partition"]));
lazy!(REPLAYED_SEGMENTS: IntCounter = register_int_counter!("vlpds_recovery_replayed_segments_total", "Log segments replayed when opening shards (previous owners' log tails after a crash or takeover)"));

lazy!(SYNC_EXPORTS: IntGaugeVec = register_int_gauge_vec!("vlpds_sync_exports", "getRepo exports streaming, and waiting for a slot (--max-exports)", &["state"]));
lazy!(SYNC_EXPORTS_ENDED: IntCounterVec = register_int_counter_vec!("vlpds_sync_exports_ended_total", "getRepo exports by how they ended: done, client_gone, stalled (the client read nothing for --export-stall-secs), error, shed (no slot within 10 s: 503)", &["reason"]));
lazy!(IMPORTS: IntGaugeVec = register_int_gauge_vec!("vlpds_imports", "importRepo calls running (admitted by the import budget), and waiting for it", &["state"]));
lazy!(IMPORT_RESERVED_BYTES: IntGauge = register_int_gauge!("vlpds_import_reserved_bytes", "Import budget reserved by running importRepo calls (their estimated working sets)"));
lazy!(IMPORT_BUDGET_BYTES: IntGauge = register_int_gauge!("vlpds_import_budget_bytes", "The import budget (--import-memory-mb, or 1/16 of the memory budget within 192 MiB-1 GiB)"));
lazy!(IMPORT_ADMISSIONS: IntCounterVec = register_int_counter_vec!("vlpds_import_admissions_total", "importRepo admissions by the import budget: admitted (at once), waited (admitted after queueing), rejected (no room in time: 503)", &["result"]));
lazy!(IMPORT_GROWTHS: IntCounterVec = register_int_counter_vec!("vlpds_import_growths_total", "Running imports' reservations grown past their estimate (no or wrong Content-Length, the buffered fallback): granted, waited, rejected (503)", &["result"]));
lazy!(IMPORT_WAIT_SECONDS: HistogramVec = register_histogram_vec!("vlpds_import_wait_seconds", "Time importRepo calls queued for the import budget, by kind: admit, grow", &["kind"], latency_buckets()));
lazy!(IMPORT_REPO_PARSES: IntCounterVec = register_int_counter_vec!("vlpds_import_repo_parses_total", "importRepo bodies parsed, by path: stream (one pass over a CAR in the streamable block order) or buffered (any other order, or a CAR refused)", &["path"]));
lazy!(LOG_LIVE_BYTES: IntGauge = register_int_gauge!("vlpds_log_live_ring_bytes", "Segment bytes pinned by the node log's live ring (peer streams)"));
lazy!(LOG_STREAM_LAGGED: IntCounter = register_int_counter!("vlpds_log_stream_lagged_total", "Peer log streams dropped for falling behind the live ring (they catch up from S3)"));

lazy!(RETENTION_DELETED_OBJECTS: IntCounterVec = register_int_counter_vec!("vlpds_retention_deleted_objects_total", "Log objects deleted by retention, by log (own, dead) or fence (a dead log's fence past --fence-retention)", &["log"]));
lazy!(RETENTION_DELETED_BYTES: IntCounterVec = register_int_counter_vec!("vlpds_retention_deleted_bytes_total", "Log bytes deleted by retention, by log (own, dead)", &["log"]));
lazy!(RETENTION_PRUNED_SEQ: IntGauge = register_int_gauge!("vlpds_retention_pruned_seq", "Highest seq this node has deleted from any log (older cursors get OutdatedCursor)"));
lazy!(RETENTION_REPLAY_HOLD: IntGauge = register_int_gauge!("vlpds_retention_replay_hold_segments", "Segments of our log kept only because a crash replay could still need them (durable ordinal - replay floor)"));
lazy!(RETENTION_LISTS_SKIPPED: IntCounterVec = register_int_counter_vec!("vlpds_retention_lists_skipped_total", "Retention LISTs a pass skipped because nothing could be due yet (own: our log's first segment is inside the window or held by the replay floor; dead: no dead logs but retired ones whose fences aren't due, live set unchanged); each still runs at least hourly", &["list"]));
lazy!(RETENTION_TICKS: IntCounterVec = register_int_counter_vec!("vlpds_retention_ticks_total", "Retention passes by result", &["result"]));

lazy!(PROXY_CACHE: IntCounterVec = register_int_counter_vec!("vlpds_proxy_cache_total", "Proxy fast-path cache lookups", &["result"]));
lazy!(READ_AFTER_WRITE: IntCounterVec = register_int_counter_vec!("vlpds_proxy_read_after_write_total", "Proxied reads with an AppView rev: how the requester's records since it were found (log_nothing, log_records, store_read) and what was returned (munged, unchanged, failed)", &["result"]));

lazy!(CACHE_ENTRIES: IntGaugeVec = register_int_gauge_vec!("vlpds_cache_entries", "Entries held per in-memory cache", &["cache"]));
lazy!(CACHE_BYTES: IntGaugeVec = register_int_gauge_vec!("vlpds_cache_bytes", "Approximate bytes held per in-memory cache (entries x estimated entry size)", &["cache"]));
lazy!(META_CACHE_BYTES: IntGauge = register_int_gauge!("vlpds_meta_cache_bytes", "Bytes of SST filters, indexes and stats held by the shared SlateDB metadata cache (partition.rs MetaCache)"));
lazy!(META_CACHE_CAPACITY: IntGauge = register_int_gauge!("vlpds_meta_cache_capacity_bytes", "Capacity of the shared SlateDB metadata cache (--meta-cache-mb; default sized by the memory budget to the owned SSTs' metadata, src/memory.rs)"));
lazy!(META_CACHE_LOADS: IntCounterVec = register_int_counter_vec!("vlpds_meta_cache_loads_total", "Metadata cache misses by kind (filter, index, stats) and outcome: fetched (read and decoded from the store) or shared (waited for a concurrent read's fetch of the same entry)", &["kind", "result"]));
lazy!(SST_META_BYTES: IntGaugeVec = register_int_gauge_vec!("vlpds_sst_meta_bytes", "Encoded filter and index bytes of every SST in the shards this node owns (the metadata cache's working set under uniform reads), by kind", &["kind"]));
lazy!(CACHE_CAPACITY: IntGaugeVec = register_int_gauge_vec!("vlpds_cache_capacity_entries", "Entry cap per in-memory cache (--cache-budget-mb, --cache-entries)", &["cache"]));

lazy!(FORWARDED: IntCounter = register_int_counter!("vlpds_requests_forwarded_total", "Requests proxied to the partition owner"));
lazy!(CTL_LOADS: IntCounterVec = register_int_counter_vec!("vlpds_security_ctl_loads_total", "Reads of an account's revocations/takedowns past its cached view, by result (loaded; coalesced: shared another request's read; stale_moving / stale_unreachable: a view <= 300 s old stood in while the shard moved / the owner failed; moved / unavailable: 503)", &["result"]));
lazy!(WRITE_RETRIES: IntCounterVec = register_int_counter_vec!("vlpds_write_retries_total", "Repo writes the entry node resent after a not-applied 503, by reason (loading: RepoLoading; moved: ShardMoved)", &["reason"]));
lazy!(READ_RETRIES: IntCounterVec = register_int_counter_vec!("vlpds_read_retries_total", "XRPC queries the entry node resent after a 503 that did nothing, by reason (unreachable: owner refused the connection; loading: RepoLoading; moved: ShardMoved, also from a security-controls check waiting out a move)", &["reason"]));
lazy!(OWNED_PARTITIONS: IntGauge = register_int_gauge!("vlpds_owned_partitions", "Partitions this node owns"));
lazy!(LEASE_EVENTS: IntCounterVec = register_int_counter_vec!("vlpds_lease_events_total", "Partition lease transitions", &["event"]));
lazy!(CLUSTER_STORE_REQUESTS: IntCounterVec = register_int_counter_vec!("vlpds_cluster_store_requests_total", "Control-plane object-store requests (leases, assignments, writer claims, fences) by op", &["op"]));
lazy!(CLUSTER_NUDGES: IntCounterVec = register_int_counter_vec!("vlpds_cluster_nudges_total", "Early control-plane steps asked of peers after a release (sent, failed) or by peers (received)", &["dir"]));
lazy!(CLUSTER_LONE_SKIPS: IntCounterVec = register_int_counter_vec!("vlpds_cluster_lone_skips_total", "Control-plane LISTs a lone node skipped (nodes: membership reused, listed at least once per TTL; assign: assignments unchanged but by our own writes, listed every 25 steps)", &["list"]));
lazy!(CLUSTER_STORE_TIMEOUTS: IntCounterVec = register_int_counter_vec!("vlpds_cluster_store_timeouts_total", "Control-plane object-store calls a step gave up on at their deadline (min(TTL, 5 s)); the step retries next tick", &["op"]));
lazy!(COMPACTION_POLL_MODE: IntCounterVec = register_int_counter_vec!("vlpds_compaction_poll_switches_total", "Shard compactors switched to fast polls (deep L0) or back to slow (--compaction-polling adaptive)", &["mode"]));
lazy!(LAYOUT_VERSION: IntGauge = register_int_gauge!("vlpds_shard_layout_version", "Version of the shard layout this node routes by (grows with each split/merge)"));
lazy!(RESHARD_EVENTS: IntCounterVec = register_int_counter_vec!("vlpds_reshard_events_total", "Shard split/merge steps this node performed: planned, frozen (parents closed), split / merged (layout flipped), aborted", &["event"]));
lazy!(RESHARD_SECONDS: Histogram = register_histogram!("vlpds_reshard_drive_seconds", "Driver time from every parent frozen to the children open (clone, assignments, flip, open)", exponential_buckets(0.01, 2.0, 14).unwrap()));
lazy!(RESHARD_GC_PASSES: IntCounterVec = register_int_counter_vec!("vlpds_reshard_gc_passes_total", "Retired-state GC passes (src/reshard_gc.rs) by result (ok, error), skipped ones not counted (vlpds_reshard_gc_skipped_passes_total); the dir/assign half runs on the owner of slot 0's shard only", &["result"]));
lazy!(RESHARD_GC_DELETED: IntCounterVec = register_int_counter_vec!("vlpds_reshard_gc_deleted_total", "Retired-state GC deletes: state_dirs (retired split/merge parents, aborted ops' clones), state_objects (their objects), assign_records", &["kind"]));
lazy!(RESHARD_GC_RETIRED: IntGaugeVec = register_int_gauge_vec!("vlpds_reshard_gc_retired_dirs", "State dirs of shards no longer in the layout, as of the last GC pass (leader only): total, and the ones checked this pass by state: deletable, checkpoint (a clone, reader or backup still holds a checkpoint in it), grace (changed within --reshard-gc-grace), referenced (a manifest lists its SSTs although it holds no checkpoint: never deleted, investigate), other (no manifest, or an owner)", &["state"]));
lazy!(RESHARD_GC_SKIPPED: IntCounter = register_int_counter!("vlpds_reshard_gc_skipped_passes_total", "Retired-state GC dir passes skipped after the layout GET (no LISTs) because the layout is unchanged since a full pass that found no dir or assign/ record out of the layout; a full pass still runs at least hourly, and at once after any layout change. Not counted in vlpds_reshard_gc_passes_total"));
lazy!(RESHARD_GC_ORPHAN_ASSIGNS: IntGauge = register_int_gauge!("vlpds_reshard_gc_orphan_assign_records", "assign/ records of shards out of the layout whose state dir is gone, as of the last GC pass (deleted by it, bounded per pass)"));
lazy!(FORCED_COMPACTIONS: IntCounterVec = register_int_counter_vec!("vlpds_forced_compactions_total", "Compactions this node submitted for its shards, by kind (detach: rewrite SSTs inherited from a split/merge parent; full: --full-compaction-every) and result (submitted, completed, failed: retried next pass)", &["kind", "result"]));
lazy!(SHARDS_INHERITED: IntGauge = register_int_gauge!("vlpds_shards_with_inherited_ssts", "Shards open here still reading SSTs of a split/merge parent (external SSTs): each pins its parent's state dir until a forced compaction rewrites them"));

lazy!(COMMIT_STAGE: HistogramVec = register_histogram_vec!("vlpds_commit_stage_seconds", "Per-segment commit pipeline stages: seal_wait (oldest entry's enqueue -> PUT start), put (-> durable), apply_lock (finalizer waiting for shard apply locks), apply (SlateDB batches), ack (acks + repo views published)", &["stage"], latency_buckets()));
lazy!(PUTS_INFLIGHT: IntGauge = register_int_gauge!("vlpds_segment_puts_inflight", "Segment PUT attempts in flight (hedges included)"));
lazy!(REPO_CACHE: IntCounterVec = register_int_counter_vec!("vlpds_repo_cache_lookups_total", "Worker repo lookups for queued requests: hit (cached), miss (starts a cold load), loading (joins one in flight)", &["result"]));
lazy!(FORWARDS: IntCounterVec = register_int_counter_vec!("vlpds_forwards_total", "Forwarded requests by the owner's status class (5xx includes owner unreachable / past its TTFB deadline)", &["result"]));
lazy!(FORWARD_DURATION: Histogram = register_histogram!("vlpds_forward_seconds", "Forwarded request time to the owner's response head", latency_buckets()));
lazy!(BUILD_INFO: IntGaugeVec = register_int_gauge_vec!("vlpds_build_info", "1, labeled with node id, git revision and whether the profiling feature is built in", &["node_id", "rev", "profiling"]));

// The prometheus crate's process collector is Linux-only, so these are ours.

/// Also records the round trip as a fraction of the lease TTL, so alert
/// thresholds work at any --lease-ttl-ms.
pub struct LeaseRenewHistogram {
    secs: Histogram,
    ttl_ratio: Histogram,
}

impl LeaseRenewHistogram {
    pub fn observe(&self, secs: f64) {
        self.secs.observe(secs);
        let ttl = LEASE_TTL.get();
        if ttl > 0.0 {
            self.ttl_ratio.observe(secs / ttl);
        }
    }

    pub fn get_sample_count(&self) -> u64 {
        self.secs.get_sample_count()
    }
}

pub static LEASE_RENEW_SECONDS: LazyLock<LeaseRenewHistogram> = LazyLock::new(|| {
    LeaseRenewHistogram {
    secs: register_histogram!("vlpds_lease_renew_seconds", "Node lease renewal round trip (the CAS PUT of nodes/{node_id}), answered or failed. Validity ends TTL - skew after a renewal's send time, so round trips over 0.4 x TTL (4 s at the default TTL) open a gap and the node fail-stops", exponential_buckets(0.001, 2.0, 14).unwrap()).unwrap(),
    ttl_ratio: register_histogram!("vlpds_lease_renew_ttl_ratio", "Node lease renewal round trip as a fraction of the lease TTL (vlpds_lease_renew_seconds / vlpds_lease_ttl_seconds). Over 0.4 the node's validity gaps and it fail-stops", vec![0.01, 0.025, 0.05, 0.1, 0.15, 0.2, 0.3, 0.4, 0.5, 0.6, 0.8, 1.0]).unwrap(),
}
});
lazy!(LEASE_TTL: Gauge = register_gauge!("vlpds_lease_ttl_seconds", "Configured node lease TTL (--lease-ttl-ms). Renewal ceiling = 0.4 x TTL; a crashed node's shards are taken over after about TTL + skew"));
lazy!(LEASE_RENEW_INTERVAL: Gauge = register_gauge!("vlpds_lease_renew_interval_seconds", "Configured node lease renewal interval (TTL / 5)"));
lazy!(LEASE_SKEW: Gauge = register_gauge!("vlpds_lease_skew_seconds", "Configured clock-skew margin of the node lease (TTL / 5): validity ends TTL - skew after a renewal's send time"));
lazy!(LEASE_RENEW_ERRORS: IntCounterVec = register_int_counter_vec!("vlpds_lease_renew_errors_total", "Failed node lease renewals by kind: timeout / error (retried next interval), conflict (someone rewrote our lease: fail-stop), lapsed (validity ended before the renewal: fail-stop)", &["kind"]));
lazy!(LEASE_VALIDITY: GaugeVec = register_gauge_vec!("vlpds_lease_validity_seconds", "Seconds until this node's own lease validity ends (TTL - skew after the send time of its last successful renewal), computed at scrape. Normally between TTL - skew - one renew interval and TTL - skew; negative = lapsed", &["node_id"]));
lazy!(PEER_TAKEOVERS: IntCounterVec = register_int_counter_vec!("vlpds_peer_takeovers_total", "Log incarnations this node fenced because they ended without fencing themselves (crash, kill, fail-stop, partition): peer = a dead peer's log, before taking its shards; restart = our own previous incarnation's, at startup. A graceful stop fences its own log and is not counted", &["reason"]));

lazy!(SHARDS_OPENED: IntCounterVec = register_int_counter_vec!("vlpds_shards_opened_total", "Shard opens (acquire, adopt, takeover, reshard children) by result", &["result"]));
lazy!(SHARD_OPEN_SECONDS: HistogramVec = register_histogram_vec!("vlpds_shard_open_seconds", "One batch of shard opens until served (SlateDB open + log replay + flush), by kind: replay (it replayed segments: a takeover after a crash) or clean (nothing to replay: a handback)", &["kind"], exponential_buckets(0.01, 2.0, 14).unwrap()));
lazy!(SHARD_OPEN_PHASE_SECONDS: HistogramVec = register_histogram_vec!("vlpds_shard_open_phase_seconds", "One batch of shard opens, by phase: open (SlateDB opens), replay (log tails), flush (memtables after a replay), warm_wait (the rest of the warm-up, capped)", &["phase"], exponential_buckets(0.001, 2.0, 18).unwrap()));
lazy!(TOTALS_LOAD_SECONDS: Histogram = register_histogram!("vlpds_account_totals_load_seconds", "Opening a shard until its account totals are loaded (in the background: the shard serves meanwhile, and is left out of vlpds_accounts and vlpds_repos_written_within until then)", exponential_buckets(0.01, 2.0, 14).unwrap()));
lazy!(TOTALS_LOADING: IntGauge = register_int_gauge!("vlpds_account_totals_loading_shards", "Shards open here whose account totals are still loading, left out of vlpds_accounts and vlpds_repos_written_within"));
lazy!(SHARD_WARM_SECONDS: Histogram = register_histogram!("vlpds_shard_warm_seconds", "One batch of shard opens: fetching every SST's filters and index (and the newest L0s whole) into the caches before serving (partition::warm)", exponential_buckets(0.01, 2.0, 14).unwrap()));
lazy!(SHARD_WARM_SSTS: IntCounterVec = register_int_counter_vec!("vlpds_shard_warm_ssts_total", "SSTs warmed before a newly opened shard served, by result", &["result"]));
lazy!(SHARD_PREWARMS: IntCounterVec = register_int_counter_vec!("vlpds_shard_prewarm_total", "Shards handed to a peer, by whether the peer warmed its caches for them first (ok) or the prewarm request failed and the peer starts them cold (failed)", &["result"]));
lazy!(REPLAY_SECONDS: Histogram = register_histogram!("vlpds_recovery_replay_seconds", "Replay step of a shard-open batch that replayed at least one segment (previous owners' log tails)", exponential_buckets(0.01, 2.0, 14).unwrap()));
lazy!(LAYOUT_SHARDS: IntGauge = register_int_gauge!("vlpds_shard_layout_shards", "Shards in the layout this node routes by (changes with each split/merge)"));

lazy!(MEMORY_LIMIT: IntGauge = register_int_gauge!("vlpds_memory_limit_bytes", "Memory this process may use: physical RAM, or the cgroup limit when lower (memory.rs; absent if neither is readable)"));
lazy!(REPO_CACHE_CAPACITY: IntGauge = register_int_gauge!("vlpds_repo_cache_capacity_bytes", "Byte budget of the repo workers' caches, all workers together (--repo-cache-mb, default sized by the memory budget); compare with sum(vlpds_repo_cache_bytes)"));
lazy!(MEMORY_BUDGET: IntGaugeVec = register_int_gauge_vec!("vlpds_memory_budget_bytes", "The memory plan (src/memory.rs): budget (the limit or --memory-budget-mb), the fixed costs taken off it (runtime, in_memory_caches, mst_node_cache, firehose, backfill, exports, import, headroom), and the pool left for the SST metadata, SST block and repo caches", &["part"]));
lazy!(MEMORY_CACHE: IntGaugeVec = register_int_gauge_vec!("vlpds_memory_cache_bytes", "The pool's caches (meta: SST filters + indexes, block: SST blocks, repo: loaded MSTs) by kind: target (meta: the owned SSTs' decoded metadata with failover and compaction headroom; block, repo: their share of the pool), capacity (applied), used (meta and block; the repo cache's is sum(vlpds_repo_cache_bytes))", &["cache", "kind"]));
lazy!(SST_META_NEED: IntGauge = register_int_gauge!("vlpds_sst_meta_need_bytes", "Decoded size of the owned SSTs' filters and indexes: vlpds_sst_meta_bytes x vlpds_sst_meta_decode_ratio (what the metadata cache must hold under uniform reads)"));
lazy!(SST_META_DECODE_RATIO: Gauge = register_gauge!("vlpds_sst_meta_decode_ratio", "Decoded / encoded size of SST filters and indexes, measured from the metadata cache while it neither loads nor evicts (1.3 until measured)"));
lazy!(META_CACHE_SHORTFALL: IntGauge = register_int_gauge!("vlpds_meta_cache_shortfall_bytes", "How far the metadata cache's capacity is below its target (the memory pool can't fit the owned SSTs' metadata with headroom, or --meta-cache-mb is too small); 0 when it fits"));

lazy!(RETENTION_PASS_SECONDS: Histogram = register_histogram!("vlpds_retention_pass_seconds", "One log retention pass, ok or failed", exponential_buckets(0.01, 2.0, 14).unwrap()));
lazy!(RETENTION_DEAD_SEGMENTS: IntGauge = register_int_gauge!("vlpds_retention_dead_log_segments", "Log objects left below the end of dead (writer gone) logs, as of the last pass that checked them all; only the dead-log pruner (owner of slot 0's shard) reports non-zero"));
lazy!(RETENTION_DEAD_LOGS: IntGaugeVec = register_int_gauge_vec!("vlpds_retention_dead_logs", "Dead logs by state as of the last pass that checked them all: unfenced (no successor fenced it yet), needed (a shard's replay may still read it), pruning (segments inside the window, or deleting), fenced (pruned to its fence, which goes after --fence-retention)", &["state"]));

lazy!(SIGNUPS: IntCounterVec = register_int_counter_vec!("vlpds_signups_total", "Sign-up attempts (createAccount, the OAuth sign-up form) by result: created, or refused for invite (missing or unusable invite code), email_policy (unsupported or disposable address), handle_policy (reserved or inappropriate handle), taken (handle or email already in use), invalid (other bad input), error (server-side failure)", &["result"]));
lazy!(ACCOUNT_EVENTS: IntCounterVec = register_int_counter_vec!("vlpds_account_events_total", "Account lifecycle events: created (sign-ups and migrations in; not vlpds.admin.bulkCreate), deleted, deactivated, reactivated", &["event"]));
lazy!(ACCOUNT_DELETIONS: IntCounterVec = register_int_counter_vec!("vlpds_account_deletions_total", "Accounts deleted, by reason: user (deleteAccount with an emailed token), admin (com.atproto.admin.deleteAccount), delete_after (the sweep, once a deactivated account's deleteAfter passed)", &["reason"]));
lazy!(SCHEDULED_DELETION_PASSES: IntCounterVec = register_int_counter_vec!("vlpds_scheduled_deletion_passes_total", "Scheduled-deletion sweeps (deactivated accounts whose deleteAfter passed; every node, every 10 min, over its own shards) by result: ok, or error (a shard's scan or an account's deletion failed)", &["result"]));
lazy!(SCHEDULED_DELETION_PASS_SECONDS: Histogram = register_histogram!("vlpds_scheduled_deletion_pass_seconds", "One scheduled-deletion sweep, ok or failed", exponential_buckets(0.01, 2.0, 14).unwrap()));
lazy!(SCHEDULED_DELETION_ACCOUNTS: IntCounterVec = register_int_counter_vec!("vlpds_scheduled_deletion_accounts_total", "Accounts the scheduled-deletion sweep acted on, by result: deleted, finished (a deletion that had stopped partway, completed), raced (reactivated as the sweep deleted it; kept), failed (retried next sweep)", &["result"]));
lazy!(SCHEDULED_DELETION_STATE: IntGaugeVec = register_int_gauge_vec!("vlpds_scheduled_deletion_accounts", "Accounts with a deleteAfter on this node's shards as of its last sweep, by state: scheduled (all of them), held (due but taken down or suspended: never deleted while so), deferred (left for the next sweep by its per-pass cap); sum over nodes", &["state"]));
lazy!(OAUTH_CONSENTS: IntCounterVec = register_int_counter_vec!("vlpds_oauth_consents_total", "OAuth consent page answers by result: full (every requested scope granted), narrowed (the user unticked some), denied (the user refused), refused (a required scope was unticked: access_denied)", &["result"]));
lazy!(SCOPE_REJECTIONS: IntCounterVec = register_int_counter_vec!("vlpds_scope_rejections_total", "Requests refused 403 ScopeMissingError, by credential (oauth: an OAuth token; app_password: a scoped app password) and the missing scope's kind (repo, rpc, blob, account, identity)", &["credential", "kind"]));
lazy!(SIGN_IN_FACTORS: IntCounterVec = register_int_counter_vec!("vlpds_sign_in_factors_total", "Successful sign-ins by method (password, app_password, oauth, passkey: passwordless with a passkey, on the OAuth page or the account page) and second factor (none, totp, email, passkey, recovery: a recovery code, trusted: a trusted browser skipped it; a passwordless sign-in counts as passkey)", &["method", "factor"]));
lazy!(SIGN_IN_ALERTS: IntCounterVec = register_int_counter_vec!("vlpds_sign_in_alerts_total", "Sign-ins from a new device, by what became of their alert mail: mailed (handed to the mailer), budget (a mail budget refused it: vlpds_mail_suppressed_total{purpose=\"sign_in_alert\"}), account_limit (the account's 3 alerts a day are spent), muted (the owner turned alerts off), no_email, email_code (an emailed code just went to the same inbox), baseline (the account's first recorded sign-in)", &["result"]));
lazy!(SIGN_IN_SETTINGS: IntCounterVec = register_int_counter_vec!("vlpds_sign_in_settings_total", "Sign-in security settings changed by account owners, by setting (oauth_only, block_app_passwords, password_alerts, app_password_alerts) and new value (on, off)", &["setting", "value"]));
lazy!(PASSKEYS: IntCounterVec = register_int_counter_vec!("vlpds_passkeys_total", "Passkey changes by event: registered (an owner added one on the Security page), removed (an owner removed one), reset (the operator's resetSecondFactors removed them; counts accounts)", &["event"]));
lazy!(PASSKEY_FAILURES: IntCounterVec = register_int_counter_vec!("vlpds_passkey_failures_total", "Passkey registrations and assertions refused, by the check that failed: malformed, too_large, type, challenge (wrong, expired or bound to another flow), origin, cross_origin, rp_id, user_present, user_verified (passwordless without a PIN or biometric), algorithm, key, signature, credential_id, counter (a hardware key's counter went backwards, or it was flagged for that), unknown_credential (not one of the account's), replay (its challenge was already used)", &["reason"]));
lazy!(PASSKEY_COUNTER_REGRESSIONS: IntCounterVec = register_int_counter_vec!("vlpds_passkey_counter_regressions_total", "Passkey sign-ins whose signature counter went backwards, by result: refused (a key that can't be synced: flagged and the owner mailed), accepted (a synced passkey, whose copies are expected)", &["result"]));
lazy!(TRUSTED_BROWSERS: IntCounterVec = register_int_counter_vec!("vlpds_trusted_browsers_total", "Trusted browsers (skip the second factor for --trusted-device-days): granted (\"trust this browser\" after a code), revoked (one, or all, from the account page)", &["event"]));
lazy!(HANDLE_CHECKS: IntCounterVec = register_int_counter_vec!("vlpds_handle_checks_total", "vlpds.identity.checkHandle answers by kind (service: a name under the handle domain; external: the caller's own domain) and status (invalid, reserved, current, taken, available, verified, unverified)", &["kind", "status"]));
lazy!(MODERATION_ACTIONS: IntCounterVec = register_int_counter_vec!("vlpds_moderation_actions_total", "Takedowns applied or reversed (com.atproto.admin.updateSubjectStatus), by subject (account, record, blob) and action (takedown, reversed)", &["subject", "action"]));
lazy!(LOGINS: IntCounterVec = register_int_counter_vec!("vlpds_logins_total", "Sign-ins by method (password: createSession with the account password; app_password: createSession with an app password; oauth: the OAuth sign-in page; passkey: a passkey in place of the password, on the OAuth page or the account page) and result: success, failed (wrong identifier or password, or a timed-out step), second_factor_required (a 2FA code was asked for or mailed), second_factor_failed (wrong or locked-out 2FA code), inactive (a taken-down or suspended account; on the OAuth sign-in page also a deactivated one), oauth_required (the account's OAuth-only switch refused its main password), app_passwords_blocked (the account turned app passwords off), passkey_required (a passkey is the account's only strong factor: createSession refused its main password outside this server's own pages), rate_limited, error (server-side failure)", &["method", "result"]));
lazy!(PASSWORD_RESETS: IntCounterVec = register_int_counter_vec!("vlpds_password_resets_total", "Password resets: requested (a reset email asked for), unknown_email (asked for an address with no account; answered the same), completed (a new password set with its token)", &["step"]));
lazy!(INVITE_CODES: IntCounterVec = register_int_counter_vec!("vlpds_invite_codes_total", "Invite codes: created (admin or earned), used (by a sign-up)", &["event"]));
lazy!(RECORDS_WRITTEN: IntCounterVec = register_int_counter_vec!("vlpds_records_written_total", "Record ops committed by collection (the well-known app.bsky / chat.bsky collections; any other is `other`) and action (create, update, delete)", &["collection", "action"]));
lazy!(BLOB_UPLOADS: IntCounterVec = register_int_counter_vec!("vlpds_blob_uploads_total", "Blobs stored by uploadBlob, by kind (image, video, other: from the stored MIME type)", &["kind"]));
lazy!(BLOB_QUOTA_REJECTIONS: IntCounterVec = register_int_counter_vec!("vlpds_blob_quota_rejections_total", "uploadBlob calls refused by the per-account quotas: bytes (413 BlobQuotaExceeded, stored bytes over --blob-quota-gb or the account override), uploads (429, over --blob-uploads-per-day)", &["reason"]));
lazy!(BLOB_QUARANTINE: IntCounterVec = register_int_counter_vec!("vlpds_blob_quarantine_total", "Taken-down blobs: quarantined (bytes moved to blob-quarantine/ by a takedown), restored (moved back by a reversal), purged (deleted after --blob-quarantine-days)", &["event"]));
lazy!(BLOB_UPLOAD_BYTES: IntCounter = register_int_counter!("vlpds_blob_upload_bytes_total", "Bytes of blobs stored by uploadBlob"));
lazy!(REPORTS: IntCounterVec = register_int_counter_vec!("vlpds_reports_total", "Moderation reports (com.atproto.moderation.createReport) passed on to the moderation service, by result (ok; failed: the service refused it or was unreachable)", &["result"]));
lazy!(UPSTREAM_REQUESTS: IntCounterVec = register_int_counter_vec!("vlpds_upstream_requests_total", "Requests proxied for users to other services, by service (appview: the Bluesky AppView, chat, moderation, other) and result (ok: 2xx/3xx; client_error: 4xx; server_error: 5xx; unreachable: connection failure or timeout)", &["service", "result"]));
lazy!(UPSTREAM_DURATION: HistogramVec = register_histogram_vec!("vlpds_upstream_request_seconds", "Proxied request time until the upstream service's response head, by service (unreachable ones included)", &["service"], latency_buckets()));
lazy!(HANDLE_RESOLUTIONS: IntCounterVec = register_int_counter_vec!("vlpds_handle_resolutions_total", "Custom-domain handle lookups by result (dns: TXT _atproto record; http: /.well-known/atproto-did; not_found: neither answered with a DID)", &["result"]));
lazy!(REQUEST_CRAWL: IntCounterVec = register_int_counter_vec!("vlpds_request_crawl_total", "requestCrawl calls to relays (the slot-0 leader's startup/after-activity asks, and vlpds.admin.requestCrawl) by relay and result (ok; rejected: non-2xx answer; failed: unreachable)", &["relay", "result"]));
lazy!(REQUEST_CRAWL_LAST_OK: GaugeVec = register_gauge_vec!("vlpds_request_crawl_last_success_time_seconds", "Unix time of this node's last requestCrawl the relay accepted (0: none since the process started)", &["relay"]));
lazy!(ACCOUNTS: IntGaugeVec = register_int_gauge_vec!("vlpds_accounts", "Accounts on the shards this node has open, by status (active, deactivated, takendown, suspended, other); exact, kept per slot with every account change (crate::totals); sum over nodes for the PDS", &["status"]));
lazy!(REPOS_WRITTEN_WITHIN: IntGaugeVec = register_int_gauge_vec!("vlpds_repos_written_within", "Repos on the shards this node has open whose latest commit's UTC day is within the window of today's (1d: yesterday or today; 7d, 30d), and all of them (all); exact, kept per slot with every commit", &["window"]));
lazy!(CPU_CORES: Gauge = register_gauge!("vlpds_cpu_cores", "CPU cores available to this process (std::thread::available_parallelism: affinity and cgroup quota aware)"));
lazy!(DISK_CACHE_BYTES: IntGaugeVec = register_int_gauge_vec!("vlpds_disk_cache_bytes", "SST disk cache (--cache-dir): used (bytes of the open shards' cache files, as SlateDB's evictor tracks them) and capacity (configured)", &["kind"]));

/// The last entry, `other`, takes every collection not listed.
const KNOWN_COLLECTIONS: [&str; 18] = [
    "app.bsky.feed.post",
    "app.bsky.feed.like",
    "app.bsky.feed.repost",
    "app.bsky.graph.follow",
    "app.bsky.graph.block",
    "app.bsky.graph.list",
    "app.bsky.graph.listitem",
    "app.bsky.graph.listblock",
    "app.bsky.graph.starterpack",
    "app.bsky.graph.verification",
    "app.bsky.actor.profile",
    "app.bsky.actor.status",
    "app.bsky.feed.threadgate",
    "app.bsky.feed.postgate",
    "app.bsky.feed.generator",
    "app.bsky.labeler.service",
    "chat.bsky.actor.declaration",
    "other",
];
const RECORD_ACTIONS: [&str; 3] = ["create", "update", "delete"];

static RECORD_COUNTERS: LazyLock<Vec<[IntCounter; 3]>> = LazyLock::new(|| {
    KNOWN_COLLECTIONS.iter().map(|c| RECORD_ACTIONS.map(|a| RECORDS_WRITTEN.with_label_values(&[c, a]))).collect()
});

pub fn record_written(path: &str, action: &str) {
    let coll = path.split_once('/').map_or(path, |(c, _)| c);
    let ci = KNOWN_COLLECTIONS[..KNOWN_COLLECTIONS.len() - 1]
        .iter()
        .position(|k| *k == coll)
        .unwrap_or(KNOWN_COLLECTIONS.len() - 1);
    let ai = match action {
        "create" => 0,
        "update" => 1,
        _ => 2,
    };
    RECORD_COUNTERS[ci][ai].inc();
}

pub fn blob_kind(mime: &str) -> &'static str {
    if mime.starts_with("image/") {
        "image"
    } else if mime.starts_with("video/") {
        "video"
    } else {
        "other"
    }
}

pub fn upstream_service(service_id: &str) -> &'static str {
    match service_id {
        "bsky_appview" => "appview",
        "bsky_chat" => "chat",
        "atproto_labeler" | "bsky_moderation" => "moderation",
        _ => "other",
    }
}

/// Exports counters at 0 before their first event: a series that first
/// appears at 1 has no earlier sample, so `rate()` and `increase()` never see
/// that event and alerts like `VlpdsUncleanNodeExit` don't fire. Startup
/// calls this before joining the cluster, so a restart's own takeover counts.
/// Per-route and per-object-store-op families are not pre-created
/// (unbounded); a few others are pre-created where their loops start.
pub fn init_counters() {
    static DONE: std::sync::Once = std::sync::Once::new();
    DONE.call_once(|| {
        for c in UNLABELLED_COUNTERS {
            LazyLock::force(c);
        }
        LazyLock::force(&RUNTIME_LATE_TOTAL);
        for h in ALERT_HISTOGRAMS {
            LazyLock::force(h);
        }
        for (vec, values) in LABELLED_COUNTERS {
            for v in *values {
                vec.with_label_values(&[v]);
            }
        }
        for kind in ["replay", "clean"] {
            SHARD_OPEN_SECONDS.with_label_values(&[kind]);
        }
        for phase in ["open", "replay", "flush", "warm_wait"] {
            SHARD_OPEN_PHASE_SECONDS.with_label_values(&[phase]);
        }
        for kind in ["filter", "index", "stats"] {
            for r in ["fetched", "shared"] {
                META_CACHE_LOADS.with_label_values(&[kind, r]);
            }
        }
        LazyLock::force(&RECORD_COUNTERS);
        for state in ["running", "waiting"] {
            IMPORTS.with_label_values(&[state]);
        }
        for kind in ["admit", "grow"] {
            IMPORT_WAIT_SECONDS.with_label_values(&[kind]);
        }
        LazyLock::force(&IMPORT_RESERVED_BYTES);
        LazyLock::force(&BLOB_UPLOAD_BYTES);
        CPU_CORES.set(std::thread::available_parallelism().map_or(0, |n| n.get()) as f64);
        for method in ["password", "app_password", "oauth", "passkey"] {
            for r in LOGIN_RESULTS {
                LOGINS.with_label_values(&[method, r]);
            }
        }
        for method in ["password", "app_password", "oauth", "passkey"] {
            for factor in ["none", "totp", "email", "passkey", "recovery", "trusted"] {
                SIGN_IN_FACTORS.with_label_values(&[method, factor]);
            }
        }
        for credential in ["oauth", "app_password"] {
            for kind in SCOPE_KINDS {
                SCOPE_REJECTIONS.with_label_values(&[credential, kind]);
            }
        }
        for setting in ["oauth_only", "block_app_passwords", "password_alerts", "app_password_alerts"] {
            for value in ["on", "off"] {
                SIGN_IN_SETTINGS.with_label_values(&[setting, value]);
            }
        }
        for status in ["invalid", "reserved", "current", "taken", "available"] {
            HANDLE_CHECKS.with_label_values(&["service", status]);
        }
        for status in ["invalid", "current", "taken", "verified", "unverified"] {
            HANDLE_CHECKS.with_label_values(&["external", status]);
        }
        for subject in ["account", "record", "blob"] {
            for action in ["takedown", "reversed"] {
                MODERATION_ACTIONS.with_label_values(&[subject, action]);
            }
        }
        for service in ["appview", "chat", "moderation", "other"] {
            for r in ["ok", "client_error", "server_error", "unreachable"] {
                UPSTREAM_REQUESTS.with_label_values(&[service, r]);
            }
            UPSTREAM_DURATION.with_label_values(&[service]);
        }
        for purpose in [
            "reset_password",
            "delete_account",
            "confirm_email",
            "update_email",
            "plc_operation",
            "auth_factor",
            "sign_in_alert",
            "security_change",
        ] {
            for r in ["sent", "failed", "dropped"] {
                crate::mail::MAIL_MESSAGES.with_label_values(&[r, purpose]);
            }
            for reason in ["recipient_limit", "node_limit", "cluster_limit"] {
                crate::mail::MAIL_SUPPRESSED.with_label_values(&[purpose, reason]);
            }
        }
        crate::mail::MAIL_SUPPRESSED.with_label_values(&["reset_password", "account_limit"]);
        crate::mail::MAIL_SUPPRESSED.with_label_values(&["auth_factor", "dedup"]);
    });
}

/// At 0 for each configured relay, so an alert sees its first failure.
pub fn init_request_crawl(relays: &[String]) {
    for relay in relays {
        for r in ["ok", "rejected", "failed"] {
            REQUEST_CRAWL.with_label_values(&[relay.as_str(), r]);
        }
        REQUEST_CRAWL_LAST_OK.with_label_values(&[relay]);
    }
}

pub fn request_crawl(relay: &str, result: &str) {
    REQUEST_CRAWL.with_label_values(&[relay, result]).inc();
    if result == "ok" {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0.0, |d| d.as_secs_f64());
        REQUEST_CRAWL_LAST_OK.with_label_values(&[relay]).set(now);
    }
}

const LOGIN_RESULTS: [&str; 10] = [
    "success",
    "failed",
    "second_factor_required",
    "second_factor_failed",
    "inactive",
    "oauth_required",
    "app_passwords_blocked",
    "passkey_required",
    "rate_limited",
    "error",
];

pub fn login(method: &str, result: &str) {
    LOGINS.with_label_values(&[method, result]).inc();
}

static UNLABELLED_COUNTERS: &[&LazyLock<IntCounter>] = &[
    &HTTP_SERVER_CONNECTIONS,
    &HTTP_SERVER_ACCEPT_ERRORS,
    &RATE_LIMITED,
    &WRITES_SHED,
    &ARGON2_SHED,
    &HTTP_STALLED_BODIES,
    &COMMITS,
    &REPO_EVICTIONS,
    &LAZY_MST_UNLOADS,
    &WRITES_ABANDONED,
    &SEGMENT_BYTES_TOTAL,
    &SEGMENT_STALL_SEALS,
    &SEGMENT_STORED_BYTES_TOTAL,
    &vlsync_store::metrics::SEGMENT_DECODES,
    &PUT_HEDGES,
    &REPLAYED_SEGMENTS,
    &vlsync_firehose::metrics::FIREHOSE_EVENTS,
    &vlsync_firehose::metrics::FIREHOSE_SENT,
    &vlsync_firehose::metrics::FIREHOSE_SPILLS,
    &vlsync_firehose::metrics::FIREHOSE_SPILL_SEGMENTS,
    &vlsync_firehose::metrics::FIREHOSE_SENT_BYTES,
    &vlsync_firehose::metrics::FIREHOSE_BACKFILL_GETS,
    &vlsync_firehose::metrics::FIREHOSE_BACKFILL_EVENTS,
    &LOG_STREAM_LAGGED,
    &FORWARDED,
    &RESHARD_GC_SKIPPED,
];

/// Histograms whose `_count` an alert rates.
static ALERT_HISTOGRAMS: &[&LazyLock<Histogram>] = &[
    &COMMIT_LATENCY,
    &CHECKPOINT_SHARD,
    &FORWARD_DURATION,
    &vlsync_firehose::metrics::FIREHOSE_EMIT_DELAY,
    &REPLAY_SECONDS,
];

#[allow(clippy::type_complexity)]
static LABELLED_COUNTERS: &[(&LazyLock<IntCounterVec>, &[&str])] = &[
    (&PEER_TAKEOVERS, &["peer", "restart"]),
    (
        &LEASE_EVENTS,
        &[
            "opened",
            "closed",
            "lost",
            "peer_refused",
            "lease_recreated",
            "history_full",
            "join_lease_moved",
            "shutdown_fence_failed",
        ],
    ),
    (&LEASE_RENEW_ERRORS, &["timeout", "error", "conflict", "lapsed"]),
    (&CLUSTER_STORE_TIMEOUTS, &["get", "put", "list", "delete", "fence", "fence-scan"]),
    (&SHARDS_OPENED, &["ok", "error"]),
    (&SHARD_WARM_SSTS, &["ok", "error"]),
    (&SHARD_PREWARMS, &["ok", "failed"]),
    (&PUT_ATTEMPTS, &["ok", "already_exists", "error"]),
    (
        &WRITE_ERRORS,
        &[
            "repo_not_found",
            "repo_inactive",
            "invalid_swap",
            "invalid",
            "internal",
            "unavailable",
            "key_unavailable",
            "signature_fault",
            "not_started",
        ],
    ),
    (&WRITE_RETRIES, &["unreachable", "loading", "moved"]),
    (&READ_RETRIES, &["unreachable", "loading", "moved"]),
    (&FORWARDS, &["2xx", "3xx", "4xx", "5xx"]),
    (&PROXY_REJECTED, &["account_cap"]),
    (&REPO_CACHE, &["hit", "miss", "loading"]),
    (&REPO_LOADS, &["ok", "error", "not_found", "stale"]),
    (&LAZY_MST_FALLBACKS, &["missing", "missing_node", "invalid"]),
    (&vlsync_firehose::metrics::FIREHOSE_DISCONNECTS, &["too_slow"]),
    (&vlsync_firehose::metrics::FIREHOSE_REJECTED, &["per_ip"]),
    (&SYNC_EXPORTS_ENDED, &["done", "client_gone", "stalled", "error", "shed"]),
    (&IMPORT_REPO_PARSES, &["stream", "buffered"]),
    (&IMPORT_ADMISSIONS, &["admitted", "waited", "rejected"]),
    (&IMPORT_GROWTHS, &["granted", "waited", "rejected"]),
    (&SIGNUPS, &["created", "invite", "email_policy", "handle_policy", "taken", "invalid", "error"]),
    (&ACCOUNT_EVENTS, &["created", "deleted", "deactivated", "reactivated"]),
    (&ACCOUNT_DELETIONS, &["user", "admin", "delete_after"]),
    (&OAUTH_CONSENTS, &["full", "narrowed", "denied", "refused"]),
    (&SIGN_IN_ALERTS, &["mailed", "budget", "account_limit", "muted", "no_email", "email_code", "baseline"]),
    (&TRUSTED_BROWSERS, &["granted", "revoked"]),
    (&PASSKEYS, &["registered", "removed", "reset"]),
    (
        &PASSKEY_FAILURES,
        &[
            "malformed",
            "too_large",
            "type",
            "challenge",
            "origin",
            "cross_origin",
            "rp_id",
            "user_present",
            "user_verified",
            "algorithm",
            "key",
            "signature",
            "credential_id",
            "counter",
            "unknown_credential",
            "replay",
        ],
    ),
    (&PASSKEY_COUNTER_REGRESSIONS, &["refused", "accepted"]),
    (&PASSWORD_RESETS, &["requested", "unknown_email", "completed"]),
    (&INVITE_CODES, &["created", "used"]),
    (&BLOB_UPLOADS, &["image", "video", "other"]),
    (&BLOB_QUOTA_REJECTIONS, &["bytes", "uploads"]),
    (&BLOB_QUARANTINE, &["quarantined", "restored", "purged"]),
    (&REPORTS, &["ok", "failed"]),
    (&HANDLE_RESOLUTIONS, &["dns", "http", "not_found"]),
    (&vlsync_atproto::events::IDENTITY_EVENTS, &["identity", "account"]),
];

/// Only nodes that run retention, so `VlpdsRetentionNotRunning` stays quiet
/// elsewhere.
pub fn init_retention_counters() {
    for r in ["ok", "error"] {
        RETENTION_TICKS.with_label_values(&[r]);
    }
}

/// Only nodes that run the scheduled-deletion sweep (--delete-after).
pub fn init_scheduled_deletion_counters() {
    for r in ["ok", "error"] {
        SCHEDULED_DELETION_PASSES.with_label_values(&[r]);
    }
    for r in ["deleted", "finished", "raced", "failed"] {
        SCHEDULED_DELETION_ACCOUNTS.with_label_values(&[r]);
    }
    LazyLock::force(&SCHEDULED_DELETION_PASS_SECONDS);
}

pub const SCOPE_KINDS: [&str; 5] = ["repo", "rpc", "blob", "account", "identity"];

/// `scope`: the missing one (`repo:...`, `rpc:...`); labelled by its kind.
/// `space` (`--spaces` only) isn't pre-registered.
pub fn scope_rejected(credential: &str, scope: &str) {
    let kind = scope.split(':').next().unwrap_or("");
    if let Some(kind) = SCOPE_KINDS.iter().chain(&["space"]).find(|k| **k == kind) {
        SCOPE_REJECTIONS.with_label_values(&[credential, kind]).inc();
    }
}

// Spaces (`--spaces`, src/space). Registered on first use, so a node
// without the flag exports none of them.
lazy!(SPACE_WRITES: IntCounterVec = register_int_counter_vec!("vlpds_space_writes_total", "Space record write requests (createRecord, putRecord, deleteRecord, applyWrites) by method and result", &["op", "result"]));
lazy!(SPACE_READS: IntCounterVec = register_int_counter_vec!("vlpds_space_reads_total", "Space repo reads by method and auth (credential: a space credential; oauth: the account's own read)", &["method", "auth"]));
lazy!(SPACE_LIST_REPO_OPS: IntCounterVec = register_int_counter_vec!("vlpds_space_list_repo_ops_total", "listRepoOps answered by path (noop: since was the head, served from memory; scan: an oplog range scan)", &["path"]));
lazy!(SPACE_LIST_REPO_OPS_SECONDS: HistogramVec = register_histogram_vec!("vlpds_space_list_repo_ops_seconds", "listRepoOps server time by path, auth excluded", &["path"], latency_buckets()));
lazy!(SPACE_NOTIFY: IntCounterVec = register_int_counter_vec!("vlpds_space_notify_total", "notifyWrite hops by direction (out: this node's writes to their authorities; in: received as an authority; fanout: forwarded to syncers) and result", &["hop", "result"]));
lazy!(SPACE_NOTIFY_ACK: Histogram = register_histogram!("vlpds_space_notify_ack_seconds", "A space write's ack to its authority's acknowledgement of the notify", exponential_buckets(0.001, 2.0, 24).unwrap()));
lazy!(SPACE_OUTBOX_ROWS: IntGauge = register_int_gauge!("vlpds_space_outbox_rows", "notifyWrite outbox rows this node owes (one per repo and space)"));
lazy!(SPACE_OUTBOX_OLDEST: Gauge = register_gauge!("vlpds_space_outbox_oldest_seconds", "Age of the oldest notifyWrite outbox row, leaving out rows held for an inactive writer"));
lazy!(SPACE_DELEGATIONS: IntCounter = register_int_counter!("vlpds_space_delegations_total", "Delegation tokens minted (getDelegationToken)"));
lazy!(SPACE_CREDENTIAL_CACHE: IntCounterVec = register_int_counter_vec!("vlpds_space_credential_cache_total", "Space credential verifications by cache result (hit: a verified credential, only the request signature checked; miss: the whole chain)", &["result"]));
lazy!(SPACE_CREDENTIAL_CHECKS: IntCounterVec = register_int_counter_vec!("vlpds_space_credential_checks_total", "Space credential checks by result (ok, bad_sig, expired, revoked, audience, space)", &["result"]));
lazy!(SPACE_REVOCATIONS: IntGauge = register_int_gauge!("vlpds_space_revocations", "Revoked space credentials this node enforces (until they would have expired)"));
lazy!(SPACE_REVOCATIONS_SATURATED: IntGauge = register_int_gauge!("vlpds_space_revocations_saturated", "1 while the revocation blocks are saturated: every remote space authority's credentials are refused (local ones keep working)"));
lazy!(SPACE_REVOCATION_BLOCKS: IntGaugeVec = register_int_gauge_vec!("vlpds_space_revocation_blocks", "Spaces and authorities whose credentials are refused because a revocation of theirs couldn't be stored, by kind (space, authority)", &["kind"]));
lazy!(SPACE_FANOUT_DEPTH: IntGauge = register_int_gauge!("vlpds_space_fanout_queue_depth", "Write notifications waiting to be forwarded to registered services, across lanes"));
lazy!(SPACE_FANOUT_DROPPED: IntCounterVec = register_int_counter_vec!("vlpds_space_fanout_dropped_total", "Write notifications not forwarded to a registered service, by reason (queue_full: the dispatcher's queue; lane_full: the oldest of a (space, service) lane; host_full: the service host's queue; all_full: every lane's queues together; lanes_full: no room for another lane; gave_up: retries ran out; expired: the registration expired while failing; takendown: the space is taken down). The service sees a prevSpaceRev gap and catches up with listRepos", &["reason"]));
lazy!(SPACE_FANOUT_COALESCED: IntCounter = register_int_counter!("vlpds_space_fanout_coalesced_total", "Write notifications replaced before they were sent by a newer one of the same writer to the same service"));
lazy!(SPACE_OUTBOX_OVERFLOW: IntCounter = register_int_counter!("vlpds_space_outbox_overflow_total", "notifyWrite outbox rows left in the bucket because the in-memory outbox was full (picked up by a rescan once it drains)"));
lazy!(SPACE_EXPORT_BYTES: Histogram = register_histogram!("vlpds_space_export_bytes", "Memory a space getRepo export holds: its paths and CIDs (pass 1) and the chunk it fills", exponential_buckets(65536.0, 2.0, 16).unwrap()));
lazy!(SPACE_OPLOG_PRUNED: IntCounter = register_int_counter!("vlpds_space_oplog_pruned_total", "Space oplog ops deleted past --space-oplog-retention"));
lazy!(SPACE_CREDENTIALS_ISSUED: IntCounterVec = register_int_counter_vec!("vlpds_space_credentials_issued_total", "getSpaceCredential answers as a space authority, by result", &["result"]));

pub fn space_write(op: &str, result: &str) {
    SPACE_WRITES.with_label_values(&[op, result]).inc();
}

pub fn space_read(method: &str, auth: &str) {
    SPACE_READS.with_label_values(&[method, auth]).inc();
}

pub fn space_list_repo_ops(path: &str, took: std::time::Duration) {
    SPACE_LIST_REPO_OPS.with_label_values(&[path]).inc();
    SPACE_LIST_REPO_OPS_SECONDS.with_label_values(&[path]).observe(took.as_secs_f64());
}

pub fn space_notify(hop: &str, result: &str) {
    SPACE_NOTIFY.with_label_values(&[hop, result]).inc();
}

pub fn space_notify_ack(took: std::time::Duration) {
    SPACE_NOTIFY_ACK.observe(took.as_secs_f64());
}

pub fn space_outbox_gauges(rows: usize, oldest_secs: f64) {
    SPACE_OUTBOX_ROWS.set(rows as i64);
    SPACE_OUTBOX_OLDEST.set(oldest_secs);
}

pub fn space_delegation() {
    SPACE_DELEGATIONS.inc();
}

pub fn space_credential_cache(hit: bool) {
    SPACE_CREDENTIAL_CACHE.with_label_values(&[if hit { "hit" } else { "miss" }]).inc();
}

pub fn space_credential_check(result: &str) {
    SPACE_CREDENTIAL_CHECKS.with_label_values(&[result]).inc();
}

pub fn space_revocations(n: usize) {
    SPACE_REVOCATIONS.set(n as i64);
}

pub fn space_revocation_blocks(saturated: bool, spaces: usize, authorities: usize) {
    SPACE_REVOCATIONS_SATURATED.set(saturated as i64);
    SPACE_REVOCATION_BLOCKS.with_label_values(&["space"]).set(spaces as i64);
    SPACE_REVOCATION_BLOCKS.with_label_values(&["authority"]).set(authorities as i64);
}

pub fn space_fanout_depth(delta: i64) {
    SPACE_FANOUT_DEPTH.add(delta);
}

pub fn space_fanout_dropped(reason: &str) {
    SPACE_FANOUT_DROPPED.with_label_values(&[reason]).inc();
}

pub fn space_fanout_coalesced() {
    SPACE_FANOUT_COALESCED.inc();
}

pub fn space_outbox_overflow() {
    SPACE_OUTBOX_OVERFLOW.inc();
}

pub fn space_export_bytes(n: usize) {
    SPACE_EXPORT_BYTES.observe(n as f64);
}

pub fn space_oplog_pruned(n: usize) {
    SPACE_OPLOG_PRUNED.inc_by(n as u64);
}

pub fn space_credential_issued(result: &str) {
    SPACE_CREDENTIALS_ISSUED.with_label_values(&[result]).inc();
}

lazy!(SPACE_SIGN_SECONDS: Histogram = register_histogram!("vlpds_space_sign_seconds", "Signing one space commit for a reader (getLatestCommit, listRepoOps, getRepo: a fresh ikm per response)", exponential_buckets(0.000_005, 2.0, 16).unwrap()));
lazy!(SPACE_DIGEST_MISMATCH: IntCounter = register_int_counter!("vlpds_space_digest_mismatch_total", "Space repos whose stored head disagreed with the set hash recomputed from their records (vlpds.admin.checkSpace): an integrity bug, never load"));
lazy!(SPACE_REPOS: IntGauge = register_int_gauge!("vlpds_space_repos", "Space repos (an account's repo in one space) in the shards this node owns, counted by the oplog retention sweep (every ~6 h)"));
lazy!(SPACE_IMPORTS: IntCounterVec = register_int_counter_vec!("vlpds_space_imports_total", "vlpds.space.importRepo calls by result (ok; refused: a bad CAR, signature, MAC or set hash, or a repo already there; error)", &["result"]));
lazy!(SPACE_OPERATOR_READS: IntCounterVec = register_int_counter_vec!("vlpds_space_operator_reads_total", "Audited operator reads of space data (vlpds.admin.getSpaceRepo, listSpaceRecords, getSpaceRecord) by method", &["method"]));

pub fn space_sign(took: std::time::Duration) {
    SPACE_SIGN_SECONDS.observe(took.as_secs_f64());
}

pub fn space_digest_mismatch() {
    SPACE_DIGEST_MISMATCH.inc();
}

pub fn space_repos(n: usize) {
    SPACE_REPOS.set(n as i64);
}

pub fn space_import(result: &str) {
    SPACE_IMPORTS.with_label_values(&[result]).inc();
}

pub fn space_operator_read(method: &str) {
    SPACE_OPERATOR_READS.with_label_values(&[method]).inc();
}

/// With `--spaces`: the series its alerts and dashboard row read, at 0
/// before their first event (a node without the flag exports none).
pub fn init_space_counters() {
    for hop in ["out", "in", "fanout"] {
        let results: &[&str] = match hop {
            "out" => &["ok", "refused", "gone", "expired", "retry", "wait"],
            "in" => &["ok", "noop", "refused", "error", "same_rev_capped", "same_rev_unverified"],
            _ => &["ok", "refused", "error"],
        };
        for r in results {
            SPACE_NOTIFY.with_label_values(&[hop, r]);
        }
    }
    for r in ["ok", "bad_sig", "expired", "revoked", "audience", "space"] {
        SPACE_CREDENTIAL_CHECKS.with_label_values(&[r]);
    }
    for r in ["hit", "miss"] {
        SPACE_CREDENTIAL_CACHE.with_label_values(&[r]);
    }
    for path in ["noop", "scan"] {
        SPACE_LIST_REPO_OPS.with_label_values(&[path]);
        SPACE_LIST_REPO_OPS_SECONDS.with_label_values(&[path]);
    }
    for r in ["queue_full", "lane_full", "host_full", "all_full", "lanes_full", "gave_up", "expired", "takendown"] {
        SPACE_FANOUT_DROPPED.with_label_values(&[r]);
    }
    for r in ["ok", "bad_token", "refused", "error"] {
        SPACE_CREDENTIALS_ISSUED.with_label_values(&[r]);
    }
    for r in ["ok", "refused", "error"] {
        SPACE_IMPORTS.with_label_values(&[r]);
    }
    for c in [
        &SPACE_DELEGATIONS,
        &SPACE_DIGEST_MISMATCH,
        &SPACE_FANOUT_COALESCED,
        &SPACE_OUTBOX_OVERFLOW,
        &SPACE_OPLOG_PRUNED,
    ] {
        LazyLock::force(c);
    }
    for g in [&SPACE_OUTBOX_ROWS, &SPACE_FANOUT_DEPTH, &SPACE_REVOCATIONS, &SPACE_REVOCATIONS_SATURATED] {
        LazyLock::force(g);
    }
    for k in ["space", "authority"] {
        SPACE_REVOCATION_BLOCKS.with_label_values(&[k]);
    }
    LazyLock::force(&SPACE_OUTBOX_OLDEST);
    LazyLock::force(&SPACE_NOTIFY_ACK);
    LazyLock::force(&SPACE_SIGN_SECONDS);
}

pub fn init_reshard_gc_counters() {
    for r in ["ok", "error"] {
        RESHARD_GC_PASSES.with_label_values(&[r]);
    }
    for kind in ["detach", "full"] {
        for r in ["submitted", "completed", "failed"] {
            FORCED_COMPACTIONS.with_label_values(&[kind, r]);
        }
    }
}

/// Survives cancellation, unlike an inc/dec pair around an await.
pub struct InflightGuard(&'static IntGauge);

impl InflightGuard {
    pub fn new(g: &'static LazyLock<IntGauge>) -> InflightGuard {
        g.inc();
        InflightGuard(g)
    }
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        self.0.dec();
    }
}

/// Alert thresholds scale with these; also enables `vlpds_lease_renew_ttl_ratio`.
pub fn export_lease_config(ttl: std::time::Duration, renew_every: std::time::Duration, skew: std::time::Duration) {
    LEASE_TTL.set(ttl.as_secs_f64());
    LEASE_RENEW_INTERVAL.set(renew_every.as_secs_f64());
    LEASE_SKEW.set(skew.as_secs_f64());
}

pub fn observe_forward(status: u16, start: std::time::Instant) {
    FORWARD_DURATION.observe(start.elapsed().as_secs_f64());
    let class = match status {
        200..=299 => "2xx",
        300..=399 => "3xx",
        400..=499 => "4xx",
        _ => "5xx",
    };
    FORWARDS.with_label_values(&[class]).inc();
}

/// The whole /metrics text: vlpds's series and every vlsync one.
pub fn render() -> String {
    init_counters();
    vlsync_atproto::crypto::touch_metrics();
    crate::caches::refresh_metrics();
    vlsync_store::metrics::render()
}

/// The `db` label of a shard's SlateDB series (its read-only warm-up
/// handle adds `_reader`).
pub fn slatedb_label(shard: vlsync_store::slots::ShardId) -> String {
    format!("shard_{}", shard.0)
}

pub fn with_slatedb_metrics<P: Into<slatedb::object_store::path::Path>>(
    b: slatedb::DbBuilder<P>,
    db: &str,
) -> slatedb::DbBuilder<P> {
    #[cfg(feature = "slatedb-metrics")]
    let b = b.with_metrics_recorder(slate_metrics::recorder(db));
    #[cfg(not(feature = "slatedb-metrics"))]
    let _ = db;
    b
}

/// Adds an open shard DB to the `slatedb_lsm_*` series and `slate_metrics::shapes()`.
pub fn register_slatedb(db: &str, handle: &slatedb::Db) {
    #[cfg(feature = "slatedb-metrics")]
    slate_metrics::register(db, handle);
    #[cfg(not(feature = "slatedb-metrics"))]
    let _ = (db, handle);
}

pub fn register_slatedb_reader(db: &str, handle: &slatedb::DbReader) {
    #[cfg(feature = "slatedb-metrics")]
    slate_metrics::register_reader(db, handle);
    #[cfg(not(feature = "slatedb-metrics"))]
    let _ = (db, handle);
}

/// A SlateDB gauge (its dotted name) summed over this node's open DBs;
/// None if no DB registered it.
pub fn slatedb_gauge(name: &str) -> Option<i64> {
    #[cfg(feature = "slatedb-metrics")]
    return slate_metrics::gauge_sum(name);
    #[allow(unreachable_code)]
    {
        let _ = name;
        None
    }
}

#[cfg(feature = "slatedb-metrics")]
pub fn slatedb_recorder(db: &str) -> std::sync::Arc<dyn slate_metrics::MetricsRecorder> {
    slate_metrics::recorder(db)
}

pub fn method_label(path: &str) -> &str {
    match path.strip_prefix("/xrpc/") {
        Some(m) if !m.is_empty() => m,
        _ => "other",
    }
}
