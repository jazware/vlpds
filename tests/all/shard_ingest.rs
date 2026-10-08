//! Single-shard ingest: a whole repo lives in one shard, so a huge import
//! pushes all of its state through one SlateDB, where memtable backpressure
//! (L0 full until the compactor and the writer's manifest poll catch up) can
//! stall writes for seconds (the tuning in `partition::open_db`).
//!
//! This drives one shard DB the way the node log's finalizer does (one
//! `WriteBatch` per segment, `db.write`), with the rows a createRecord
//! produces (a time-ordered `R/` record row with its bytes, and a `C/` CID
//! index row in hash order), paced at a target rate, and records the longest
//! single write. Ignored by default (it moves GBs); run with e.g.
//! `INGEST_RECORDS=2000000 INGEST_RATE=50000 INGEST_LATENCY_MS=10 cargo test
//! --test all shard_ingest -- --ignored --nocapture`.

use object_store::throttle::{ThrottleConfig, ThrottledStore};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn env(name: &str, default: u64) -> u64 {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore]
async fn one_shard_sustains_bulk_ingest() {
    let records = env("INGEST_RECORDS", 2_000_000);
    let rate = env("INGEST_RATE", 50_000); // records/s, 0 = unpaced
    let per_batch = env("INGEST_BATCH", 1_000) as usize; // records per segment
    let latency = Duration::from_millis(env("INGEST_LATENCY_MS", 10));
    let raw: Arc<dyn object_store::ObjectStore> = if latency.is_zero() {
        Arc::new(object_store::memory::InMemory::new())
    } else {
        let cfg = ThrottleConfig {
            wait_get_per_call: latency,
            wait_put_per_call: latency,
            wait_list_per_call: latency,
            wait_delete_per_call: latency,
            ..Default::default()
        };
        Arc::new(ThrottledStore::new(object_store::memory::InMemory::new(), cfg))
    };
    let store = vlsync_store::store::Store { raw, ..vlsync_store::store::Store::memory(None) };
    let db = vlpds::partition::open_db(&store, vlsync_store::slots::ShardId(0), None).await.unwrap();

    let did = "did:plc:ingestingestingestingest";
    let record = vec![0xa5u8; 260]; // a typical post's DAG-CBOR
    let started = Instant::now();
    let (mut worst, mut slow, mut stalled) = (Duration::ZERO, 0u64, Duration::ZERO);
    let mut written = 0u64;
    let mut last_report = Instant::now();
    while written < records {
        if rate > 0 {
            // pace: don't run ahead of `rate` (a stall is not made up later
            // by an unbounded burst, as with a client's bounded concurrency)
            let due = started + Duration::from_secs_f64(written as f64 / rate as f64);
            tokio::time::sleep_until(due.into()).await;
        }
        let mut wb = slatedb::WriteBatch::new();
        for i in 0..per_batch as u64 {
            let n = written + i;
            let rkey = format!("{:013}", n); // TID-like, time ordered
            let path = format!("app.bsky.feed.post/{rkey}");
            let cid: [u8; 32] = <sha2::Sha256 as sha2::Digest>::digest(n.to_le_bytes()).into();
            let mut val = cid.to_vec();
            val.extend_from_slice(&record);
            wb.put(vlpds::state::record_key(did, 0, &path), val);
            let mut ck = b"C/".to_vec();
            ck.extend_from_slice(did.as_bytes());
            ck.push(0);
            ck.extend_from_slice(&cid);
            ck.extend_from_slice(path.as_bytes());
            wb.put(ck, b"");
        }
        let t = Instant::now();
        db.write(wb).await.unwrap();
        let took = t.elapsed();
        worst = worst.max(took);
        if took > Duration::from_millis(250) {
            slow += 1;
            stalled += took;
        }
        written += per_batch as u64;
        if last_report.elapsed() > Duration::from_secs(5) {
            last_report = Instant::now();
            eprintln!(
                "ingest: {written} records, {:.0}/s, worst write {worst:?}",
                written as f64 / started.elapsed().as_secs_f64()
            );
        }
    }
    let secs = started.elapsed().as_secs_f64();
    eprintln!(
        "ingest done: {records} records in {secs:.1} s ({:.0}/s, target {rate}/s), worst write {worst:?}, {slow} writes > 250 ms ({stalled:?} total)",
        records as f64 / secs
    );
    db.close().await.unwrap();
    assert!(worst < Duration::from_secs(1), "a single-shard write stalled {worst:?}");
}
