//! A fresh node's /metrics exports the counters ops/alerts.yml and the
//! dashboard rely on at 0 (metrics::init_counters), before their first
//! event. A series that first appears already at 1 has no earlier sample,
//! so `rate()` / `increase()` never see that event: a kill -9 survivor once
//! showed `vlpds_peer_takeovers_total{reason="peer"} 1` and
//! `VlpdsUncleanNodeExit` never fired.
//!
//! Its own binary because metrics are process-wide: in tests/all other
//! tests' nodes move them.

macro_rules! suite_only {
    ($($i:item)*) => {};
}

#[path = "all/common/mod.rs"]
mod common;

use common::*;
use std::collections::HashMap;

/// Exposition lines as series (name plus labels, as printed) -> value.
fn parse(text: &str) -> HashMap<String, f64> {
    text.lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .filter_map(|l| {
            let (series, v) = l.rsplit_once(' ')?;
            Some((series.to_string(), v.parse().ok()?))
        })
        .collect()
}

/// Rare events: exported, and at 0 on a fresh idle node.
const AT_ZERO: &[&str] = &[
    r#"vlpds_peer_takeovers_total{reason="peer"}"#,
    r#"vlpds_peer_takeovers_total{reason="restart"}"#,
    r#"vlpds_lease_events_total{event="peer_refused"}"#,
    r#"vlpds_lease_events_total{event="lost"}"#,
    r#"vlpds_lease_events_total{event="renewal_landed"}"#,
    r#"vlpds_lease_events_total{event="join_landed"}"#,
    r#"vlpds_lease_events_total{event="revalidated"}"#,
    r#"vlpds_lease_renew_errors_total{kind="timeout"}"#,
    r#"vlpds_lease_renew_errors_total{kind="error"}"#,
    r#"vlpds_lease_renew_errors_total{kind="conflict"}"#,
    r#"vlpds_lease_renew_errors_total{kind="lapsed"}"#,
    r#"vlpds_cluster_store_timeouts_total{op="get"}"#,
    r#"vlpds_cluster_store_timeouts_total{op="put"}"#,
    r#"vlpds_cluster_store_timeouts_total{op="list"}"#,
    r#"vlpds_cluster_store_timeouts_total{op="fence"}"#,
    r#"vlpds_cluster_store_timeouts_total{op="fence-scan"}"#,
    r#"vlpds_object_store_throttled_total{kind="lease"}"#,
    r#"vlpds_object_store_throttled_total{kind="segment"}"#,
    r#"vlpds_object_store_throttled_total{kind="other"}"#,
    "vlpds_object_store_lease_resends_total",
    r#"vlpds_shards_opened_total{result="error"}"#,
    r#"vlpds_segment_put_attempts_total{result="error"}"#,
    r#"vlpds_write_errors_total{kind="internal"}"#,
    r#"vlpds_write_errors_total{kind="unavailable"}"#,
    r#"vlpds_write_retries_total{reason="loading"}"#,
    r#"vlpds_write_retries_total{reason="moved"}"#,
    r#"vlpds_read_retries_total{reason="moved"}"#,
    r#"vlpds_shard_prewarm_total{result="failed"}"#,
    r#"vlpds_forwards_total{result="5xx"}"#,
    r#"vlpds_proxy_rejected_total{reason="account_cap"}"#,
    r#"vlpds_repo_loads_total{result="error"}"#,
    r#"vlpds_lazy_mst_fallbacks_total{reason="invalid"}"#,
    r#"vlpds_firehose_disconnects_total{reason="too_slow"}"#,
    r#"vlpds_retention_ticks_total{result="error"}"#,
    r#"vlpds_reshard_gc_passes_total{result="error"}"#,
    r#"vlpds_forced_compactions_total{kind="detach",result="failed"}"#,
    r#"vlpds_forced_compactions_total{kind="detach",result="completed"}"#,
    r#"vlpds_format_errors_total{format="segment"}"#,
    r#"vlpds_format_errors_total{format="log_stream"}"#,
    r#"vlpds_format_errors_total{format="applied_marker"}"#,
    r#"vlpds_format_errors_total{format="cluster_version"}"#,
    r#"vlpds_format_errors_total{format="control_object"}"#,
    r#"vlpds_signature_verify_failures_total{purpose="commit"}"#,
    r#"vlpds_kms_requests_total{backend="local",op="unwrap",result="rejected"}"#,
    r#"vlpds_kms_requests_total{backend="local",op="unwrap",result="unavailable"}"#,
    r#"vlpds_shard_open_seconds_count{kind="replay"}"#,
    "vlpds_recovery_replay_seconds_count",
    "vlpds_recovery_replayed_segments_total",
    "vlpds_writes_shed_total",
    "vlpds_argon2_shed_total",
    "vlpds_rate_limited_total",
    "vlpds_firehose_merge_spills_total",
    "vlpds_log_stream_lagged_total",
    "vlpds_http_server_accept_errors_total",
    "vlpds_forward_seconds_count",
    // the operator dashboard's user, content and network counters
    r#"vlpds_signups_total{result="created"}"#,
    r#"vlpds_signups_total{result="email_policy"}"#,
    r#"vlpds_account_events_total{event="deleted"}"#,
    r#"vlpds_logins_total{method="password",result="success"}"#,
    r#"vlpds_logins_total{method="oauth",result="second_factor_failed"}"#,
    r#"vlpds_logins_total{method="password",result="oauth_required"}"#,
    r#"vlpds_logins_total{method="app_password",result="app_passwords_blocked"}"#,
    r#"vlpds_sign_in_factors_total{factor="trusted",method="oauth"}"#,
    r#"vlpds_sign_in_alerts_total{result="budget"}"#,
    r#"vlpds_sign_in_settings_total{setting="oauth_only",value="on"}"#,
    r#"vlpds_trusted_browsers_total{event="granted"}"#,
    r#"vlpds_oauth_consents_total{result="narrowed"}"#,
    r#"vlpds_scope_rejections_total{credential="app_password",kind="repo"}"#,
    r#"vlpds_handle_checks_total{kind="external",status="verified"}"#,
    r#"vlpds_mail_suppressed_total{purpose="sign_in_alert",reason="recipient_limit"}"#,
    r#"vlpds_moderation_actions_total{action="takedown",subject="account"}"#,
    r#"vlpds_password_resets_total{step="requested"}"#,
    r#"vlpds_invite_codes_total{event="used"}"#,
    r#"vlpds_records_written_total{action="create",collection="app.bsky.feed.post"}"#,
    r#"vlpds_records_written_total{action="delete",collection="other"}"#,
    r#"vlpds_blob_uploads_total{kind="image"}"#,
    "vlpds_blob_upload_bytes_total",
    r#"vlpds_reports_total{result="ok"}"#,
    r#"vlpds_upstream_requests_total{result="server_error",service="appview"}"#,
    r#"vlpds_upstream_request_seconds_count{service="appview"}"#,
    r#"vlpds_handle_resolutions_total{result="not_found"}"#,
    r#"vlpds_import_admissions_total{result="rejected"}"#,
    r#"vlpds_import_growths_total{result="rejected"}"#,
    r#"vlpds_import_wait_seconds_count{kind="admit"}"#,
    r#"vlpds_imports{state="running"}"#,
    "vlpds_import_reserved_bytes",
    r#"vlpds_mail_messages_total{purpose="reset_password",result="failed"}"#,
    r#"vlpds_mail_suppressed_total{purpose="auth_factor",reason="recipient_limit"}"#,
    r#"vlpds_mail_suppressed_total{purpose="confirm_email",reason="node_limit"}"#,
    r#"vlpds_mail_suppressed_total{purpose="confirm_email",reason="cluster_limit"}"#,
    "vlpds_mail_budget_errors_total",
    r#"vlpds_mail_suppressed_total{purpose="reset_password",reason="account_limit"}"#,
    r#"vlpds_mail_suppressed_total{purpose="auth_factor",reason="dedup"}"#,
];

/// With `--spaces`: what its alerts (ops/alerts.yml vlpds-spaces) and the
/// dashboard's Spaces row read, at 0 on a fresh node.
const SPACES_AT_ZERO: &[&str] = &[
    "vlpds_space_digest_mismatch_total",
    "vlpds_space_outbox_oldest_seconds",
    "vlpds_space_outbox_rows",
    "vlpds_space_notify_ack_seconds_count",
    r#"vlpds_space_notify_total{hop="fanout",result="ok"}"#,
    r#"vlpds_space_notify_total{hop="fanout",result="error"}"#,
    r#"vlpds_space_notify_total{hop="fanout",result="refused"}"#,
    r#"vlpds_space_notify_total{hop="out",result="ok"}"#,
    r#"vlpds_space_notify_total{hop="out",result="retry"}"#,
    r#"vlpds_space_notify_total{hop="in",result="ok"}"#,
    r#"vlpds_space_notify_total{hop="in",result="same_rev_capped"}"#,
    r#"vlpds_space_notify_total{hop="in",result="same_rev_unverified"}"#,
    r#"vlpds_space_credential_checks_total{result="ok"}"#,
    r#"vlpds_space_credential_checks_total{result="bad_sig"}"#,
    r#"vlpds_space_credential_checks_total{result="expired"}"#,
    r#"vlpds_space_credential_checks_total{result="revoked"}"#,
    r#"vlpds_space_credential_checks_total{result="audience"}"#,
    r#"vlpds_space_credential_checks_total{result="space"}"#,
    r#"vlpds_space_credential_cache_total{result="hit"}"#,
    r#"vlpds_space_credential_cache_total{result="miss"}"#,
    r#"vlpds_space_list_repo_ops_total{path="noop"}"#,
    r#"vlpds_space_list_repo_ops_total{path="scan"}"#,
    r#"vlpds_space_fanout_dropped_total{reason="queue_full"}"#,
    r#"vlpds_space_fanout_dropped_total{reason="gave_up"}"#,
    "vlpds_space_fanout_queue_depth",
    "vlpds_space_revocations",
    "vlpds_space_revocations_saturated",
    r#"vlpds_space_revocation_blocks{kind="space"}"#,
    r#"vlpds_space_revocation_blocks{kind="authority"}"#,
    r#"vlpds_space_imports_total{result="refused"}"#,
];

/// Exported from the start; startup itself may move them.
const PRESENT: &[&str] = &[
    r#"vlpds_lease_events_total{event="opened"}"#,
    r#"vlpds_shards_opened_total{result="ok"}"#,
    r#"vlpds_segment_put_attempts_total{result="ok"}"#,
    r#"vlpds_repo_cache_lookups_total{result="miss"}"#,
    r#"vlpds_forwards_total{result="2xx"}"#,
    r#"vlpds_retention_ticks_total{result="ok"}"#,
    r#"vlpds_reshard_gc_passes_total{result="ok"}"#,
    "vlpds_commits_total",
    "vlpds_firehose_events_total",
    "vlpds_checkpoint_shard_seconds_count",
    "vlpds_commit_durable_seconds_count",
    "vlpds_firehose_emit_delay_seconds_count",
    "vlpds_runtime_late_seconds_total",
    r#"vlpds_meta_cache_loads_total{kind="filter",result="fetched"}"#,
    r#"vlpds_meta_cache_loads_total{kind="index",result="shared"}"#,
    r#"vlpds_sst_meta_bytes{kind="filter"}"#,
    "vlpds_meta_cache_capacity_bytes",
];

/// Gauges an alert compares, at their values on a fresh node.
const AT_VALUE: &[(&str, f64)] = &[
    (r#"vlpds_mail_budget_remaining{window="day"}"#, vlpds::ratelimit::DEFAULT_MAIL_DAILY_BUDGET as f64),
    (r#"vlpds_mail_budget_limit{window="day"}"#, vlpds::ratelimit::DEFAULT_MAIL_DAILY_BUDGET as f64),
];

/// A local relay stand-in that accepts every requestCrawl.
async fn accepting_relay() -> String {
    let app = axum::Router::new().route(
        "/xrpc/com.atproto.sync.requestCrawl",
        axum::routing::post(|| async { axum::Json(serde_json::json!({})) }),
    );
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    url
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fresh_node_exports_alerting_counters_at_zero() {
    let relay = accepting_relay().await;
    let r = relay.clone();
    let s = TestServer::spawn_with(move |c| c.crawlers = vec![r]).await;
    let text = reqwest::get(format!("{}/metrics", s.url)).await.unwrap().text().await.unwrap();
    // without --spaces, none of its series (a node with it starts below)
    assert!(!text.contains("vlpds_space_"), "space series without --spaces");
    let series = parse(&text);
    // per configured relay; the startup ask may already have counted "ok"
    for result in ["failed", "rejected"] {
        let name = format!(r#"vlpds_request_crawl_total{{relay="{relay}",result="{result}"}}"#);
        assert_eq!(series.get(&name), Some(&0.0), "{name} at 0 on a fresh node");
    }
    assert!(series.contains_key(&format!(r#"vlpds_request_crawl_last_success_time_seconds{{relay="{relay}"}}"#)));
    for name in AT_ZERO {
        assert_eq!(series.get(*name), Some(&0.0), "{name} at 0 on a fresh node");
    }
    for name in PRESENT {
        assert!(series.contains_key(*name), "{name} exported on a fresh node");
    }
    for (name, v) in AT_VALUE {
        assert_eq!(series.get(*name), Some(v), "{name} on a fresh node");
    }
    // cumulative CPU / busy time are counters (rate() over a gauge warns
    // and misreads resets)
    for name in ["vlpds_process_cpu_seconds_total", "vlpds_tokio_busy_seconds_total"] {
        assert!(text.contains(&format!("# TYPE {name} counter")), "{name} is a counter");
    }
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    assert!(series.get(r#"vlpds_process_cpu_seconds_total{mode="user"}"#).is_some_and(|v| *v > 0.0), "user CPU");

    let s = TestServer::spawn_with(|c| c.spaces = true).await;
    let text = reqwest::get(format!("{}/metrics", s.url)).await.unwrap().text().await.unwrap();
    let series = parse(&text);
    for name in SPACES_AT_ZERO {
        assert_eq!(series.get(*name), Some(&0.0), "{name} at 0 on a fresh --spaces node");
    }
}
