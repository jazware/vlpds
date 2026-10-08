//! Cross-node log streams (merged firehose).
//!
//! Each node serves its own log at `/internal/v1/log/stream`, a websocket of
//! binary messages:
//!   0x00 | ordinal u64 | count u32 | (seq i64 | len u32 | frame)*   durable batch
//!   0x01 | watermark i64                                            heartbeat
//! A watermark promises every event with seq <= it has been sent. A message
//! of any other type is skipped (and counted in
//! `vlpds_format_errors_total{format="log_stream"}`): a newer build sends one
//! only to peers whose lease advertises a level that has it (DESIGN.md
//! "Rolling upgrades and format versioning").
//!
//! Every node follows every peer's log. A follower owes the merger every
//! event of the log above its floor (the merger's position when it started),
//! in ordinal order with no gaps. On every (re)connect, once the owner has
//! subscribed us, it catches up from S3 after the last ordinal it delivered,
//! then dedupes against the stream. When the peer dies, the follower drains
//! the log from S3 up to its fence and retires. The follower leaves a stream
//! as soon as the log's lease is no longer live, whatever the owner still
//! sends: a process outliving its lease must not hold every merger at its
//! frozen watermark. S3 reads stop at the first missing ordinal or the
//! fence, so they only deliver the log's gap-free durable prefix.

use crate::nodelog::{LiveRecv, NodeLog};
use axum::extract::ws::{Message, WebSocket};
use bytes::{Buf, BufMut, Bytes};
use futures::{SinkExt, StreamExt};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use vlsync_firehose::firehose::Firehose;
use vlsync_firehose::log::{read_object, LogBatch};
use vlsync_store::segment::{self, LogObject};
use vlsync_store::store::Store;

const HEARTBEAT: Duration = Duration::from_millis(5);
/// A live log stream (or its connect) silent this long is presumed dead: a
/// half-open connection to a dead peer never delivers a FIN or RST.
const STREAM_IDLE_TIMEOUT: Duration = Duration::from_secs(2);
/// Owner side: the follower presumed a stuck stream dead long before this
/// and reconnected; a stuck socket mustn't pin the task and its live-ring
/// subscription.
const STREAM_SEND_TIMEOUT: Duration = Duration::from_secs(10);
const LEASE_CHECK: Duration = Duration::from_millis(50);

/// False = drop the stream.
async fn send_bounded(ws: &mut WebSocket, m: Message) -> bool {
    matches!(tokio::time::timeout(STREAM_SEND_TIMEOUT, ws.send(m)).await, Ok(Ok(())))
}

async fn close_bounded(ws: &mut WebSocket) {
    let _ = tokio::time::timeout(STREAM_SEND_TIMEOUT, ws.close()).await;
}

pub fn encode_batch(b: &LogBatch) -> Bytes {
    let size: usize = b.events.iter().map(|(_, f)| f.len() + 12).sum();
    let mut out = Vec::with_capacity(13 + size);
    out.put_u8(0);
    out.put_u64(b.ordinal);
    out.put_u32(b.events.len() as u32);
    for (seq, f) in &b.events {
        out.put_i64(*seq);
        out.put_u32(f.len() as u32);
        out.put_slice(f);
    }
    out.into()
}

pub fn encode_watermark(w: i64) -> Bytes {
    let mut m = Vec::with_capacity(9);
    m.put_u8(1);
    m.put_i64(w);
    m.into()
}

pub enum StreamMsg {
    Batch(LogBatch),
    Watermark(i64),
    Unknown(u8),
}

pub fn decode(log_id: &Arc<str>, data: Bytes) -> anyhow::Result<StreamMsg> {
    let mut r = data.clone();
    anyhow::ensure!(r.has_remaining(), "empty message");
    match r.get_u8() {
        0 => {
            anyhow::ensure!(r.remaining() >= 12, "short batch");
            let ordinal = r.get_u64();
            let n = r.get_u32() as usize;
            // a count from the wire: each event takes at least 12 bytes
            let mut events = Vec::with_capacity(n.min(r.remaining() / 12));
            for _ in 0..n {
                anyhow::ensure!(r.remaining() >= 12, "short event");
                let seq = r.get_i64();
                let len = r.get_u32() as usize;
                anyhow::ensure!(r.remaining() >= len, "short frame");
                let off = data.len() - r.remaining();
                events.push((seq, data.slice(off..off + len)));
                r.advance(len);
            }
            Ok(StreamMsg::Batch(LogBatch { log_id: log_id.clone(), ordinal, events }))
        }
        1 => {
            anyhow::ensure!(r.remaining() >= 8, "short watermark");
            Ok(StreamMsg::Watermark(r.get_i64()))
        }
        t => Ok(StreamMsg::Unknown(t)),
    }
}

/// Owner side: stream our log's durable batches and watermark heartbeats.
pub async fn serve_stream(mut ws: WebSocket, log: Arc<NodeLog>) {
    let mut rx = log.live.subscribe();
    let mut tick = tokio::time::interval(HEARTBEAT);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        if log.closed.load(Ordering::Acquire) {
            close_bounded(&mut ws).await;
            return;
        }
        // Read the watermark *before* draining: batches covered by it were
        // broadcast before it advanced, so they are already in our queue.
        let w = log.wm.get();
        loop {
            match rx.try_recv() {
                LiveRecv::Batch(b) => {
                    if !send_bounded(&mut ws, Message::Binary(encode_batch(&b))).await {
                        return;
                    }
                }
                LiveRecv::Empty => break,
                LiveRecv::Lagged => {
                    crate::metrics::LOG_STREAM_LAGGED.inc();
                    tracing::warn!(log_id = %log.log_id, "peer fell behind our live ring: dropping its stream (it catches up from S3)");
                    close_bounded(&mut ws).await;
                    return;
                }
            }
        }
        if !send_bounded(&mut ws, Message::Binary(encode_watermark(w))).await {
            return;
        }
    }
}

/// A follower of one peer log feeding our merger.
pub struct Follower {
    pub log_id: Arc<str>,
    /// Every event of the log above this is delivered to the merger.
    pub floor: i64,
    pub watermark: Arc<AtomicI64>,
    pub stop: Arc<AtomicBool>,
    /// Set once a dead log has been drained up to its fence.
    pub done: Arc<AtomicBool>,
}

/// Registers the log as a firehose source of `fh` and follows it. `addr`
/// returns the peer's base URL while it is alive, None once it's dead.
/// `tls`: peer mTLS (None on a lone node: nothing streams).
pub fn follow_log(
    log_id: &str,
    fh: &Firehose,
    store: Store,
    addr: Arc<dyn Fn() -> Option<String> + Send + Sync>,
    token: String,
    merger_tx: mpsc::UnboundedSender<LogBatch>,
    tls: Option<tokio_tungstenite::Connector>,
) -> Follower {
    let log_id: Arc<str> = log_id.into();
    let (floor, watermark) = fh.add_remote(&log_id);
    let f = Follower {
        log_id: log_id.clone(),
        floor,
        watermark,
        stop: Arc::new(AtomicBool::new(false)),
        done: Arc::new(AtomicBool::new(false)),
    };
    let (wm, stop, done) = (f.watermark.clone(), f.stop.clone(), f.done.clone());
    tokio::spawn(async move {
        // next ordinal to deliver to the merger (None until found in S3)
        let mut next: Option<u64> = None;
        while !stop.load(Ordering::Acquire) {
            match addr() {
                Some(base) => {
                    if let Err(e) = stream_live(
                        &log_id,
                        &store,
                        floor,
                        &base,
                        &token,
                        &merger_tx,
                        &wm,
                        &mut next,
                        &stop,
                        &*addr,
                        tls.clone(),
                    )
                    .await
                    {
                        tracing::debug!(%log_id, "log stream from {base} ended: {e:#}");
                    }
                }
                None => match catch_up(&log_id, &store, floor, &merger_tx, &wm, &mut next).await {
                    Ok(true) => {
                        done.store(true, Ordering::Release);
                        return;
                    }
                    Ok(false) => {} // not fenced yet: keep waiting
                    Err(e) => tracing::warn!(%log_id, "draining dead log: {e:#}"),
                },
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    });
    f
}

/// Delivers segments from `next` (first resolved as the first segment past
/// `floor`) from S3 until the first missing one. Ok(true) = reached the fence.
async fn catch_up(
    log_id: &Arc<str>,
    store: &Store,
    floor: i64,
    merger_tx: &mpsc::UnboundedSender<LogBatch>,
    wm: &AtomicI64,
    next: &mut Option<u64>,
) -> anyhow::Result<bool> {
    let next = match next {
        Some(n) => n,
        None => next.insert(vlsync_firehose::backfill::seek(store, log_id, floor).await?),
    };
    loop {
        match read_object(store, log_id, *next).await? {
            None => match vlsync_firehose::backfill::first_ordinal(store, log_id).await? {
                // log retention deleted it (we are a whole window behind)
                Some(first) if first > *next => {
                    tracing::warn!(%log_id, from = *next, to = first, "log pruned ahead of its follower; skipping");
                    *next = first;
                }
                _ => return Ok(false),
            },
            Some(LogObject::Fence { .. }) => return Ok(true),
            Some(LogObject::Segment(h, entries)) => {
                let _ = merger_tx.send(LogBatch {
                    log_id: log_id.clone(),
                    ordinal: *next,
                    events: segment::events(entries),
                });
                wm.fetch_max(h.last_seq, Ordering::AcqRel);
                *next += 1;
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn stream_live(
    log_id: &Arc<str>,
    store: &Store,
    floor: i64,
    base: &str,
    token: &str,
    merger_tx: &mpsc::UnboundedSender<LogBatch>,
    wm: &AtomicI64,
    next: &mut Option<u64>,
    stop: &AtomicBool,
    addr: &(dyn Fn() -> Option<String> + Send + Sync),
    tls: Option<tokio_tungstenite::Connector>,
) -> anyhow::Result<()> {
    let tls =
        tls.ok_or_else(|| anyhow::anyhow!("no peer TLS on this node (a lone node): can't stream {base}'s log"))?;
    let Some(rest) = base.strip_prefix("https://") else {
        anyhow::bail!("peer address {base:?} isn't https:// (peers talk mTLS only)");
    };
    // name the log: the address may already serve a later incarnation's log
    let url = format!("wss://{rest}/internal/v1/log/stream?log={log_id}");
    let mut req = tokio_tungstenite::tungstenite::client::IntoClientRequest::into_client_request(url.as_str())?;
    req.headers_mut().insert("x-vlpds-internal", token.parse()?);
    let connect = tokio_tungstenite::connect_async_tls_with_config(req, None, false, Some(tls));
    let (mut ws, _) = tokio::time::timeout(STREAM_IDLE_TIMEOUT, connect)
        .await
        .map_err(|_| anyhow::anyhow!("log stream connect to {base} timed out"))??;
    // The owner subscribes to its log only after the upgrade, so wait for its
    // first message before the S3 catch-up: every batch it won't send us was
    // broadcast, so PUT, before that. Catching up any earlier could miss a
    // batch landing in between, which the first heartbeat already covers.
    let Some(first) = next_msg(&mut ws, log_id, base).await? else { return Ok(()) };
    let mut first = Some(first);
    if catch_up(log_id, store, floor, merger_tx, wm, next).await? {
        // fenced: whatever this address streams now isn't this log
        return Ok(());
    }
    let n = next.as_mut().expect("resolved by catch_up");
    let mut checked = Instant::now();
    loop {
        let msg = match first.take() {
            Some(m) => m,
            None => match next_msg(&mut ws, log_id, base).await? {
                Some(m) => m,
                None => break,
            },
        };
        if stop.load(Ordering::Acquire) {
            return Ok(());
        }
        // The stream is trusted only while the log's lease is live: a zombie
        // whose server still answers would heartbeat a frozen watermark
        // forever and stall our merger. Drain the log from S3 instead.
        if checked.elapsed() >= LEASE_CHECK {
            checked = Instant::now();
            if addr().is_none() {
                tracing::info!(%log_id, "log's lease is gone: leaving its stream to drain it from S3");
                let _ = ws.close(None).await;
                return Ok(());
            }
        }
        let Some(data) = msg else { continue };
        match decode(log_id, data)? {
            StreamMsg::Batch(b) => {
                if b.ordinal < *n {
                    continue; // already delivered via S3 catch-up
                }
                anyhow::ensure!(b.ordinal == *n, "log {log_id} stream gap: {} while expecting {n}", b.ordinal);
                *n += 1;
                let _ = merger_tx.send(b);
            }
            StreamMsg::Watermark(w) => {
                wm.fetch_max(w, Ordering::AcqRel);
            }
            StreamMsg::Unknown(t) => skip_unknown(log_id, t),
        }
    }
    let _ = ws.close(None).await;
    Ok(())
}

/// Skipped rather than failing the stream: a reconnect would only meet it
/// again.
fn skip_unknown(log_id: &str, t: u8) {
    vlsync_store::version::format_error("log_stream");
    tracing::warn!(%log_id, message_type = t, "skipping a log stream message of an unknown type (a peer of a newer feature level?)");
}

type Ws = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// The next message of a log stream: None at its end, Some(None) for a
/// non-binary message.
async fn next_msg(ws: &mut Ws, log_id: &str, base: &str) -> anyhow::Result<Option<Option<Bytes>>> {
    match tokio::time::timeout(STREAM_IDLE_TIMEOUT, ws.next()).await {
        Ok(Some(m)) => Ok(Some(match m? {
            tokio_tungstenite::tungstenite::Message::Binary(data) => Some(data),
            _ => None,
        })),
        Ok(None) => Ok(None),
        Err(_) => anyhow::bail!("log {log_id} stream from {base} idle for {STREAM_IDLE_TIMEOUT:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use object_store::{ObjectStoreExt, PutPayload};
    use vlsync_firehose::log::segment_path;
    use vlsync_store::segment::SegmentBuilder;

    /// A batch claiming 4G events in a few bytes is an error, without
    /// reserving room for them first; a real one round-trips.
    #[test]
    fn decode_caps_the_claimed_count() {
        let log: Arc<str> = "A".into();
        let mut m = vec![0u8];
        m.extend_from_slice(&7u64.to_be_bytes());
        m.extend_from_slice(&u32::MAX.to_be_bytes());
        m.extend_from_slice(&[0u8; 12]);
        assert!(decode(&log, Bytes::from(m)).is_err());
        let b = LogBatch {
            log_id: log.clone(),
            ordinal: 3,
            events: vec![(5, Bytes::from_static(b"xy")), (9, Bytes::new())],
        };
        match decode(&log, encode_batch(&b)).unwrap() {
            StreamMsg::Batch(got) => assert_eq!((got.ordinal, got.events), (3, b.events)),
            _ => panic!("not a batch"),
        }
    }

    async fn put(store: &Store, ord: u64, prefix_end: u64) {
        let mut b = SegmentBuilder::new();
        b.push(1000 + ord as i64, vlsync_store::slots::ShardId(0), 1, |o| o.extend_from_slice(b"f"), &[]);
        let mut obj = b.sealed_header("A", ord, prefix_end);
        obj.extend_from_slice(&b.body);
        store.raw.put(&segment_path(store, "A", ord), PutPayload::from(obj)).await.unwrap();
    }

    /// Messages of an unknown type decode as `Unknown` (followers skip them)
    /// instead of failing the stream; known ones round-trip.
    #[test]
    fn unknown_message_types_are_skipped() {
        let log_id: Arc<str> = "A".into();
        let before = vlsync_store::metrics::FORMAT_ERRORS.with_label_values(&["log_stream"]).get();
        assert!(matches!(decode(&log_id, Bytes::from_static(&[7, 1, 2, 3])).unwrap(), StreamMsg::Unknown(7)));
        skip_unknown("A", 7);
        assert_eq!(vlsync_store::metrics::FORMAT_ERRORS.with_label_values(&["log_stream"]).get(), before + 1);
        assert!(matches!(decode(&log_id, encode_watermark(42)).unwrap(), StreamMsg::Watermark(42)));
        let b = LogBatch { log_id: log_id.clone(), ordinal: 9, events: vec![(5, Bytes::from_static(b"f"))] };
        let StreamMsg::Batch(back) = decode(&log_id, encode_batch(&b)).unwrap() else { panic!() };
        assert_eq!((back.ordinal, back.events.len(), &back.events[0].1[..]), (9, 1, &b"f"[..]));
        // malformed known messages and empty ones are still errors
        assert!(decode(&log_id, Bytes::new()).is_err());
        assert!(decode(&log_id, Bytes::from_static(&[1, 0])).is_err());
    }

    /// Draining a dead log delivers its gap-free prefix up to the fence and
    /// nothing past it (segments a crash left beyond the hole).
    #[tokio::test]
    async fn catch_up_stops_at_the_fence_before_garbage() {
        let store = Store::memory(None);
        put(&store, 0, 0).await;
        put(&store, 1, 0).await;
        put(&store, 3, 2).await; // landed while 2 was in flight; 2 never did
        let log_id: Arc<str> = "A".into();
        let (tx, mut rx) = mpsc::unbounded_channel();
        let wm = AtomicI64::new(0);
        let mut next = None;
        // not fenced yet: delivers 0, 1 and waits at the hole
        assert!(!catch_up(&log_id, &store, 0, &tx, &wm, &mut next).await.unwrap());
        assert_eq!(next, Some(2));
        store.raw.put(&segment_path(&store, "A", 2), PutPayload::from_bytes(segment::fence_object("B"))).await.unwrap();
        assert!(catch_up(&log_id, &store, 0, &tx, &wm, &mut next).await.unwrap());
        drop(tx);
        let mut ords = Vec::new();
        while let Some(b) = rx.recv().await {
            ords.push(b.ordinal);
        }
        assert_eq!(ords, vec![0, 1]);
        assert_eq!(wm.load(Ordering::Acquire), 1001);
        // a follower starting late seeks into the prefix, never past the fence
        let mut next = None;
        let (tx, _rx) = mpsc::unbounded_channel();
        assert!(catch_up(&log_id, &store, 1002, &tx, &wm, &mut next).await.unwrap());
        assert_eq!(next, Some(2));
    }
}
