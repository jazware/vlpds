//! Sharded firehose subscriptions (vlpds extension):
//! `subscribeRepos?cursor=..&shard=k/n` carries only the events whose repo
//! DID hashes into slice k of n of the 65,536 hash slots, with the full
//! stream's seqs, order and cursor semantics (DESIGN.md §5).
use crate::common::*;
use std::time::Duration;
use vlsync_store::slots::{slot_of, SlotRange};

const IDLE: Duration = Duration::from_millis(600);

async fn sub_shard(s: &TestServer, cursor: i64, k: u32, n: u32) -> Sub {
    Sub::connect(&format!("ws://{}/xrpc/com.atproto.sync.subscribeRepos?cursor={cursor}&shard={k}/{n}", s.addr)).await
}

/// Reads `sub` up to the event `last` (None: the stream carries nothing, so
/// it's drained until idle). Waiting for a known last event rather than for
/// idleness: under load the first frame of a replay can trail by more than
/// any idle gap.
async fn read_to(mut sub: Sub, last: Option<i64>) -> Vec<Frame> {
    match last {
        Some(last) => sub.until(FH_TIMEOUT, |fs| fs.last().and_then(|f| f.seq()).is_some_and(|q| q >= last)).await,
        None => sub.drain(IDLE).await,
    }
}

/// The last event of `full` in `range`.
fn last_in(full: &[(i64, Vec<u8>)], range: SlotRange) -> Option<i64> {
    full.iter()
        .rev()
        .find(|(_, raw)| {
            Frame::decode(raw).ok().and_then(|f| f.did().map(|d| range.contains(slot_of(d)))).unwrap_or(false)
        })
        .map(|e| e.0)
}

/// (seq, raw frame) of the message frames.
fn events(fs: &[Frame]) -> Vec<(i64, Vec<u8>)> {
    fs.iter().filter_map(|f| f.seq().map(|q| (q, f.raw.clone()))).collect()
}

/// Every frame of a k/n stream is for a repo in that slice, seqs strictly
/// increase, and the n streams together are exactly `full`.
fn check_partition(full: &[(i64, Vec<u8>)], shards: &[Vec<Frame>], n: u32) {
    let mut union = Vec::new();
    for (k, fs) in shards.iter().enumerate() {
        let range = SlotRange::new(k as u32, n).unwrap();
        for f in fs {
            assert_eq!(f.op, 1, "shard {k}/{n}: unexpected frame {:?}", f.body);
            let did = f.did().expect("event names its repo");
            assert!(range.contains(slot_of(did)), "shard {k}/{n} carried {did} (slot {})", slot_of(did));
        }
        let ev = events(fs);
        for w in ev.windows(2) {
            assert!(w[0].0 < w[1].0, "shard {k}/{n}: seqs out of order");
        }
        union.extend(ev);
    }
    union.sort_by_key(|e| e.0);
    assert_eq!(union.len(), full.len(), "{n} shards carry {} events, the full stream {}", union.len(), full.len());
    assert!(union == full, "the union of the {n} sharded streams is the full stream, byte for byte");
}

async fn activity(s: &TestServer, accounts: usize, posts: usize) -> Vec<TestAccount> {
    let mut accts = Vec::new();
    for _ in 0..accounts {
        let a = s.create_account("fs").await;
        for i in 0..posts {
            s.post(&a, &format!("sharded {i}")).await;
        }
        accts.push(a);
    }
    accts
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sharded_streams_partition_the_full_stream() {
    let s = TestServer::spawn().await;
    activity(&s, 10, 3).await;
    s.settled_now().await;
    let head = s.app.firehose.last_emitted.load(std::sync::atomic::Ordering::Acquire);
    let full_frames = read_to(s.subscribe(Some(0)).await, Some(head)).await;
    let full = events(&full_frames);
    assert!(full.len() >= 40, "{} events", full.len());
    let mut used: Vec<u32> = full_frames.iter().filter_map(|f| f.did().map(|d| slot_of(d) as u32)).collect();
    used.sort();
    used.dedup();
    for n in [1u32, 3, 4, 65_536] {
        let mut shards = Vec::new();
        // at n = 65,536 (one slot each) subscribe to the slots in use plus a
        // few empty ones; the rest carry nothing
        let ks: Vec<u32> = if n > 16 { used.iter().copied().chain([0, 1, 65_535]).collect() } else { (0..n).collect() };
        let drained = futures::future::join_all(ks.iter().map(|k| async {
            read_to(sub_shard(&s, 0, *k, n).await, last_in(&full, SlotRange::new(*k, n).unwrap())).await
        }))
        .await;
        for k in 0..n {
            match ks.iter().position(|x| *x == k) {
                Some(i) => shards.push(drained[i].clone()),
                None => shards.push(Vec::new()),
            }
        }
        check_partition(&full, &shards, n);
    }
    // a cursor from the full stream: exactly the slice's events after it, in
    // both halves (which half has any depends on the random DIDs; together
    // they carry everything after the cursor)
    let mid = full[full.len() / 2].0;
    let after: Vec<Frame> = read_to(s.subscribe(Some(mid)).await, Some(head)).await;
    let mut carried = 0;
    for k in 0..2 {
        let range = SlotRange::new(k, 2).unwrap();
        let got = events(&read_to(sub_shard(&s, mid, k, 2).await, last_in(&full, range).filter(|q| *q > mid)).await);
        let want: Vec<(i64, Vec<u8>)> = after
            .iter()
            .filter(|f| f.did().is_some_and(|d| range.contains(slot_of(d))))
            .filter_map(|f| f.seq().map(|q| (q, f.raw.clone())))
            .collect();
        assert_eq!(got, want, "shard {k}/2 from cursor {mid}");
        carried += want.len();
    }
    assert_eq!(carried, events(&after).len());
    assert!(carried > 0);
}

/// A cursor older than a tiny ring is backfilled from the S3 segments with
/// the shard filter, then handed to the live ring; writes made while the
/// subscribers are connected arrive live, still filtered and in order.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sharded_backfill_hands_off_to_live() {
    let s = TestServer::spawn_with(|c| c.firehose_ring_bytes = 2048).await;
    let accts = activity(&s, 6, 4).await;
    s.settled_now().await;
    let n = 3;
    let mut subs = Vec::new();
    for k in 0..n {
        subs.push(sub_shard(&s, 0, k, n).await);
    }
    let mut full_sub = s.subscribe(Some(0)).await;
    // live writes while subscribed
    let mut last = None;
    for (i, a) in accts.iter().enumerate() {
        last = Some(s.post(a, &format!("live {i} {}", "y".repeat(200))).await);
    }
    let head = Cid::parse(last.unwrap().commit_cid.as_deref().unwrap()).unwrap();
    let full_frames = full_sub
        .until(FH_TIMEOUT, |fs| {
            fs.last().is_some_and(|f| matches!(f.body.get("commit"), Some(Value::Link(c)) if *c == head))
        })
        .await;
    let full = events(&full_frames);
    assert!(full.len() >= 6 * 7 + 6, "{} events", full.len());
    let shards = futures::future::join_all(subs.iter_mut().map(|sub| sub.drain(IDLE))).await;
    check_partition(&full, &shards, n);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn invalid_shard_params_are_rejected() {
    let s = TestServer::spawn().await;
    for bad in ["", "4/4", "1", "a/b", "0/0", "0/65537", "-1/2", "1/2/3", " 0/2"] {
        let r = s.xrpc.get("com.atproto.sync.subscribeRepos", &[("shard", bad)], &Auth::None).await;
        assert_eq!((r.status, r.json["error"].as_str()), (400, Some("InvalidRequest")), "shard={bad:?}");
    }
    // a valid one gets to the websocket handshake
    let r = s.xrpc.get("com.atproto.sync.subscribeRepos", &[("shard", "65535/65536")], &Auth::None).await;
    assert_eq!(r.status, 400);
    assert_ne!(r.json["error"].as_str(), Some("InvalidRequest"));
}
