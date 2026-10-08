//! Pipelined node-log PUTs (K segments in flight, finalized in ordinal
//! order; DESIGN.md "Pipelined segment PUTs"). Tiny segments plus a wide
//! injected PUT latency make several PUTs overlap and complete out of order.
//! Acks, the firehose and a graceful handoff (close barrier behind in-flight
//! segments, replay of the releaser's span) must all see the same gap-free
//! prefix.

use crate::common::*;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use vlsync_firehose::log::{read_head, Head};
use vlsync_store::store::Store;

const SHARDS: u32 = 8;
const POST: &str = "app.bsky.feed.post";

async fn node(id: &str, store: &Arc<object_store::memory::InMemory>) -> TestServer {
    cluster_node(id, store.clone(), SHARDS, |c| {
        // one commit is ~3.5 KB: past max / K, so every commit may start its
        // own PUT while others are in flight
        c.max_segment_bytes = 4096;
        // median 8 ms, sigma 1: PUTs routinely finish out of order
        c.inject_latency = Some((8.0, 1.0));
    })
    .await
}

/// Concurrent posts; a 503 while shards move (not owned here yet / any
/// more) is retried: it was never acked.
async fn writes(s: &TestServer, accts: &[TestAccount], per_acct: usize) -> Vec<RecordRef> {
    let futs = accts.iter().flat_map(|a| {
        (0..per_acct).map(move |i| async move {
            let body = json!({"repo": a.did, "collection": POST, "record": post_record(&format!("p{i}"))});
            for _ in 0..100 {
                let r = s.xrpc.post("com.atproto.repo.createRecord", &body, &a.auth()).await;
                if r.status == 503 {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
                return RecordRef::from_json(&r.ok());
            }
            panic!("createRecord kept failing with 503");
        })
    });
    futures::future::join_all(futs).await
}

fn ops(frames: &[Frame]) -> usize {
    frames.iter().filter_map(|f| f.commit()).map(|c| c.ops.len()).sum()
}

/// Seqs strictly increase and every acked commit is on the stream once
/// (concurrent writes to one repo may share a commit).
fn check_stream(frames: &[Frame], acked: &[RecordRef]) {
    let seqs: Vec<i64> = frames.iter().filter_map(|f| f.seq()).collect();
    for w in seqs.windows(2) {
        assert!(w[0] < w[1], "seq {} followed by {}", w[0], w[1]);
    }
    let mut commits = HashSet::new();
    for c in frames.iter().filter_map(|f| f.commit()) {
        assert!(commits.insert(c.commit.to_string()), "commit {} twice", c.commit);
    }
    for r in acked {
        let c = r.commit_cid.as_ref().unwrap();
        assert!(commits.contains(c), "acked commit {c} ({}) not on the firehose", r.uri);
    }
}

/// Segments of `log_id` that were sealed while an earlier one was in flight.
async fn overlapped(raw: &Arc<object_store::memory::InMemory>, log_id: &str) -> usize {
    let store = Store { raw: raw.clone(), ..Store::memory(None) };
    let (end, _) = vlsync_firehose::log::first_free(&store, log_id).await.unwrap();
    let mut n = 0;
    for o in 0..end {
        match read_head(&store, log_id, o).await.unwrap() {
            Head::Segment(h) => n += usize::from(h.prefix_end < o),
            other => panic!("{log_id}/{o} inside the durable prefix is {other:?}"),
        }
    }
    n
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pipelined_log_keeps_acks_and_firehose_in_order() {
    let raw = Arc::new(object_store::memory::InMemory::new());
    let s = node("pipe-a", &raw).await;
    let mut accts = Vec::new();
    for n in ["alice", "bob", "carol", "dan"] {
        accts.push(s.create_account(n).await);
    }
    let mut live = s.subscribe(Some(0)).await;
    let acked = writes(&s, &accts, 30).await;
    assert!(overlapped(&raw, &s.app.log.log_id).await > 0, "no segment was sealed with another in flight");
    let n = acked.len();
    let mut frames = live.until(FH_TIMEOUT, |fs| ops(fs) >= n).await;
    frames.extend(live.drain(Duration::from_millis(300)).await);
    check_stream(&frames, &acked);
    // a cursor replay (ring) matches the live stream
    let replay = s.subscribe(Some(0)).await.drain(Duration::from_millis(500)).await;
    assert_eq!(replay.iter().map(|f| &f.raw).collect::<Vec<_>>(), frames.iter().map(|f| &f.raw).collect::<Vec<_>>());
}

/// b joins while a's log has PUTs in flight: a closes the shards it gives up
/// (barrier queued behind in-flight segments), b replays a's span. Every
/// acked write is readable on both nodes and on b's merged firehose.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn handoff_from_a_pipelined_log() {
    let raw = Arc::new(object_store::memory::InMemory::new());
    let a = node("pipe-h-a", &raw).await;
    let mut accts = Vec::new();
    for n in ["erin", "frank", "gina", "hal", "ivy", "jon"] {
        accts.push(a.create_account(n).await);
    }
    let mut acked = writes(&a, &accts, 10).await;
    // keep writing through the join and rebalance
    let b_fut = node("pipe-h-b", &raw);
    let (b, more) = tokio::join!(b_fut, writes(&a, &accts, 10));
    acked.extend(more);
    wait_until("b takes shards", Duration::from_secs(10), || owned(&b) > 0).await;
    acked.extend(writes(&a, &accts, 5).await);
    for r in &acked {
        let (did, rkey) = (r.did(), r.rkey());
        for s in [&a, &b] {
            let got = s.get_record(did, POST, rkey).await;
            assert!(got.is_ok(), "{} missing on {}: {}", r.uri, s.url, got.text());
        }
    }
    assert!(overlapped(&raw, &a.app.log.log_id).await > 0);
    let frames = b.subscribe(Some(0)).await.drain(Duration::from_millis(800)).await;
    check_stream(&frames, &acked);
    assert_eq!(ops(&frames), acked.len(), "no ops beyond the acked writes");
}
