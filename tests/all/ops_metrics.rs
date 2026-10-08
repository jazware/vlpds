//! The operational metrics ops/alerts.yml relies on move when their events
//! happen (ops/RUNBOOK.md): a 2-node cluster where one node dies (kill -9,
//! `Node::halt`) with un-checkpointed writes; the survivor fences its log
//! (`vlpds_peer_takeovers_total`), replays it (`..._replayed_segments_total`,
//! replay / open histograms) and opens its shards; renewals are timed and
//! the lease validity gauge is exported per node. Metrics are process-wide
//! and other tests run alongside, so counters are checked for growth.

use crate::common::*;
use std::sync::Arc;
use std::time::Duration;
use vlpds::metrics as m;

const SHARDS: u32 = 8;

/// The value of the first exposition line starting with `series`.
fn scraped(text: &str, series: &str) -> Option<f64> {
    text.lines().find(|l| l.starts_with(series)).and_then(|l| l.rsplit(' ').next()?.parse().ok())
}

async fn node(id: &str, store: &Arc<dyn object_store::ObjectStore>, advertise: Option<String>) -> TestServer {
    cluster_node(id, store.clone(), SHARDS, |c| {
        // no checkpoints: a takeover replays everything the dead node wrote
        c.checkpoint_every = Duration::from_secs(3600);
        let l = lease(c);
        (l.ttl, l.renew_every, l.skew) =
            (Duration::from_secs(6), Duration::from_millis(200), Duration::from_millis(1200));
        if let Some(a) = advertise {
            l.addr = a;
        }
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn takeover_replay_and_lease_metrics_move() {
    let store: Arc<dyn object_store::ObjectStore> = Arc::new(object_store::memory::InMemory::new());
    let (ida, idb) = (unique_name("opsm-a"), unique_name("opsm-b"));
    let renewals0 = m::LEASE_RENEW_SECONDS.get_sample_count();
    let a = node(&ida, &store, None).await;
    // b advertises an address that refuses connections, so a presumes it
    // dead as soon as it misses a renewal
    let refusing = {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        format!("https://{}", l.local_addr().unwrap())
    };
    let b = node(&idb, &store, Some(refusing)).await;
    wait_until("b gets its share", Duration::from_secs(10), || {
        owned(&b) > 0 && owned(&a) + owned(&b) == SHARDS as usize
    })
    .await;

    // writes in b's shards (a node creates accounts in shards it owns),
    // never checkpointed
    let b_shards: Vec<vlsync_store::slots::ShardId> = b.app.partitions.owned().iter().map(|p| p.id).collect();
    let layout = b.app.cluster.as_ref().unwrap().layout();
    let mut in_b = 0;
    for _ in 0..40 {
        let acct = b.create_account("opsm").await;
        b.post(&acct, "before the crash").await;
        if b_shards.contains(&layout.shard_of(&acct.did)) {
            in_b += 1;
        }
        if in_b >= 3 {
            break;
        }
    }
    assert!(in_b >= 3, "accounts in b's shards {b_shards:?}: {in_b}");

    // lease renewals are timed; validity is exported per node at scrape
    assert!(m::LEASE_RENEW_SECONDS.get_sample_count() > renewals0);
    let text = m::render();
    let valid =
        scraped(&text, &format!("vlpds_lease_validity_seconds{{node_id=\"{ida}\"}}")).expect("validity gauge for a");
    assert!(valid > 0.0 && valid <= 6.0 - 1.2, "a's lease validity left: {valid}");
    // process-wide: the last layout any in-process test node installed
    assert!(scraped(&text, "vlpds_shard_layout_shards").is_some_and(|v| v >= 1.0));
    assert!(scraped(&text, "process_start_time_seconds").is_some_and(|v| v > 1.7e9));
    assert!(scraped(&text, "vlpds_memory_limit_bytes").is_some_and(|v| v > 0.0));
    assert!(
        text.lines().any(|l| l.starts_with("vlpds_object_store_requests_total{")
            && l.contains("component=\"ctl_lease\"")
            && l.contains("op=\"put_cas\"")
            && l.contains("result=\"ok\"")),
        "lease CAS PUTs counted with their result"
    );
    assert!(
        text.contains("vlpds_object_store_request_seconds_bucket{component=\"ctl_lease\""),
        "control-plane latency histogram"
    );

    let replayed0 = m::REPLAYED_SEGMENTS.get();
    let takeovers0 = m::PEER_TAKEOVERS.with_label_values(&["peer"]).get();
    let opened0 = m::SHARDS_OPENED.with_label_values(&["ok"]).get();
    let replay_opens0 = m::SHARD_OPEN_SECONDS.with_label_values(&["replay"]).get_sample_count();
    let replay_secs0 = m::REPLAY_SECONDS.get_sample_count();

    b.app.node.halt(); // kill -9
    wait_until("a takes b's shards", Duration::from_secs(10), || owned(&a) == SHARDS as usize).await;

    assert!(m::PEER_TAKEOVERS.with_label_values(&["peer"]).get() > takeovers0, "a fenced b's log as a dead peer's");
    assert!(m::REPLAYED_SEGMENTS.get() > replayed0, "a replayed b's log tail");
    assert!(m::SHARDS_OPENED.with_label_values(&["ok"]).get() >= opened0 + b_shards.len() as u64);
    assert!(m::SHARD_OPEN_SECONDS.with_label_values(&["replay"]).get_sample_count() > replay_opens0);
    assert!(m::REPLAY_SECONDS.get_sample_count() > replay_secs0);
    // b's halted lease runs out
    wait_until("b's validity goes negative", Duration::from_secs(10), || {
        scraped(&m::render(), &format!("vlpds_lease_validity_seconds{{node_id=\"{idb}\"}}")).is_some_and(|v| v < 0.0)
    })
    .await;
}
