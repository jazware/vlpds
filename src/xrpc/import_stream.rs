//! importRepo's body, parsed as it arrives when the CAR is in the
//! streamable block order (vlsync-atproto/src/car_order.rs): one pass verifies the commit
//! block, every node's and record's CID, and key order, holding only the
//! nodes on the path from the root, and hands the records out in batches as
//! they arrive (to `staged_import`, which stages them), with the canonical
//! tree rebuilt alongside by a [`StreamBuilder`] (one open node per height).
//! The rebuilt root must be the commit's `data`, which proves every node
//! streamed was the canonical one. Anything else (another order, a
//! malformed or refused CAR) voids what was handed out ([`Item::Restart`])
//! and falls back to the buffered [`parse_import`] of the whole body, which
//! reports the error or hands the records out again. So both paths accept
//! exactly the same CARs with the same records and tree.
//!
//! The body is kept for that fallback: in memory up to [`SPILL_AFTER`],
//! then in a temporary file, so a big streamed import holds only what its
//! batches in flight reference.

use super::import_budget::Reservation;
use super::repo::{imported_record_blobs, parse_import, ImportedRecord};
use super::*;
use crate::mst_lazy::StreamBuilder;
use futures::StreamExt;
use std::io::{Read, Write as _};
use std::time::Duration;
use tokio::sync::mpsc;
use vlsync_atproto::car_order::{Next, Walk};
use vlsync_atproto::mst::{self, Node};

/// Chunks queued for the parser: hyper's are up to a few hundred KB.
const QUEUE: usize = 32;
/// A batch is handed out at this many records, or at the import's batch
/// bytes (`import_budget::sizing`).
pub(super) const BATCH_RECORDS: usize = 4096;
/// Batches parsed ahead of the one being staged.
pub(super) const ITEMS_AHEAD: usize = 2;
/// Bodies up to this size stay in memory for the fallback.
pub(super) const SPILL_AFTER: usize = 16 << 20;

pub(super) fn too_large(max: usize) -> XrpcError {
    XrpcError {
        status: StatusCode::PAYLOAD_TOO_LARGE,
        error: "PayloadTooLarge".into(),
        message: format!("request entity too large (max {max} bytes)"),
    }
}

/// What the parse hands out, in order; an error ends it.
pub(super) enum Item {
    /// Records in key order, and the tree's persisted nodes (height >= 1)
    /// finished meanwhile.
    Batch { records: Vec<ImportedRecord>, nodes: Vec<(Cid, Arc<[u8]>)> },
    /// Everything handed out so far is void: the buffered parse follows.
    Restart,
    /// The whole repo was handed out: the root's block (its CID is the
    /// commit's `data`), the counts and bytes, and which parse took it.
    Done { root: Bytes, records: u64, nodes: u64, bytes: crate::state::RepoBytes, path: &'static str },
}

enum Chunk {
    Data(Bytes),
    End,
    Fail(XrpcError),
}

/// An import body that sends nothing for this long fails: it holds an
/// import slot and its reservation, which other imports wait for.
pub const BODY_IDLE: Duration = Duration::from_secs(30);
/// And one that takes longer than this in all (a 1 GiB CAR at ~0.3 MB/s).
pub const BODY_DEADLINE: Duration = Duration::from_secs(3600);

/// A body's chunks, each within `idle` of the last and all by `deadline`;
/// past either, an error.
pub struct TimedBody {
    stream: axum::body::BodyDataStream,
    idle: Duration,
    deadline: tokio::time::Instant,
}

impl TimedBody {
    pub(super) fn new(body: Body, idle: Duration, total: Duration) -> TimedBody {
        TimedBody { stream: body.into_data_stream(), idle, deadline: tokio::time::Instant::now() + total }
    }

    pub(super) async fn next(&mut self) -> Option<XResult<Bytes>> {
        let by = (tokio::time::Instant::now() + self.idle).min(self.deadline);
        match tokio::time::timeout_at(by, self.stream.next()).await {
            Ok(Some(Ok(c))) => Some(Ok(c)),
            Ok(Some(Err(e))) => Some(Err(XrpcError::bad("InvalidRequest", format!("error reading body: {e}")))),
            Ok(None) => None,
            Err(_) => Some(Err(XrpcError::bad("InvalidRequest", "the request body stalled or took too long"))),
        }
    }
}

/// Reads the body (at most `max` bytes) and parses it on the blocking pool;
/// the items arrive on the receiver, at most [`ITEMS_AHEAD`] ahead. The
/// reservation grows as the body passes what it covers.
pub(super) fn start(body: TimedBody, max: usize, res: Arc<Reservation>) -> mpsc::Receiver<XResult<Item>> {
    let (tx, rx) = mpsc::channel::<Chunk>(QUEUE);
    let (items_tx, items_rx) = mpsc::channel(ITEMS_AHEAD);
    let parse_res = res.clone();
    tokio::task::spawn_blocking(move || parse(rx, items_tx, &parse_res));
    tokio::spawn(async move {
        let mut stream = body;
        let mut total = 0usize;
        while let Some(chunk) = stream.next().await {
            let chunk = match chunk {
                Ok(c) => c,
                Err(e) => {
                    let _ = tx.send(Chunk::Fail(e)).await;
                    return;
                }
            };
            total += chunk.len();
            if total > max {
                let _ = tx.send(Chunk::Fail(too_large(max))).await;
                return;
            }
            if let Err(e) = res.cover(total as u64).await {
                let _ = tx.send(Chunk::Fail(e)).await;
                return;
            }
            if !chunk.is_empty() && tx.send(Chunk::Data(chunk)).await.is_err() {
                return;
            }
        }
        let _ = tx.send(Chunk::End).await;
    });
    items_rx
}

/// Why the single pass stopped early.
enum Stop {
    /// A departure from the order, or anything the buffered parse would
    /// refuse (it then reports why).
    Depart,
    /// The receiver is gone (the import failed).
    Gone,
}

/// Batches records and builds the tree as they come.
struct Sink<'a> {
    tx: &'a mpsc::Sender<XResult<Item>>,
    res: &'a Reservation,
    builder: StreamBuilder,
    records: Vec<ImportedRecord>,
    nodes: Vec<(Cid, Arc<[u8]>)>,
    bytes: usize,
    /// Of every record so far.
    record_bytes: u64,
    sent: bool,
}

impl<'a> Sink<'a> {
    fn new(tx: &'a mpsc::Sender<XResult<Item>>, res: &'a Reservation) -> Self {
        Sink {
            tx,
            res,
            builder: StreamBuilder::default(),
            records: Vec::new(),
            nodes: Vec::new(),
            bytes: 0,
            record_bytes: 0,
            sent: false,
        }
    }

    fn record(&mut self, r: ImportedRecord) -> Result<(), Stop> {
        let key: crate::mst_lazy::Key = Arc::from(r.0.as_bytes());
        self.builder.push(key, r.1, &mut self.nodes).map_err(|_| Stop::Depart)?;
        self.bytes += r.2.len();
        self.record_bytes += r.2.len() as u64;
        self.records.push(r);
        if self.records.len() >= BATCH_RECORDS || self.bytes >= self.res.sizing().batch_bytes {
            self.flush()?;
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), Stop> {
        if self.records.is_empty() && self.nodes.is_empty() {
            return Ok(());
        }
        let item = Item::Batch { records: std::mem::take(&mut self.records), nodes: std::mem::take(&mut self.nodes) };
        self.bytes = 0;
        self.sent = true;
        self.tx.blocking_send(Ok(item)).map_err(|_| Stop::Gone)
    }
}

/// The parse thread: the single pass, else the buffered parse.
fn parse(rx: mpsc::Receiver<Chunk>, tx: mpsc::Sender<XResult<Item>>, res: &Reservation) {
    let mut input = Input::new(rx);
    let mut sink = Sink::new(&tx, res);
    let sent = match stream(&mut input, &mut sink) {
        Ok((root, records, nodes, bytes)) => {
            let _ = tx.blocking_send(Ok(Item::Done { root, records, nodes, bytes, path: "stream" }));
            return;
        }
        Err(Stop::Gone) => return,
        Err(Stop::Depart) => sink.sent,
    };
    if sent && tx.blocking_send(Ok(Item::Restart)).is_err() {
        return;
    }
    if input.end == End::Aborted {
        if let Err(e) = input.rest() {
            let _ = tx.blocking_send(Err(e));
        }
        return;
    }
    let _one = futures::executor::block_on(res.budget().buffered.acquire()).expect("never closed");
    // the whole body and its parse, counted before reading the rest
    if let Err(e) = futures::executor::block_on(res.buffered(input.received as u64)) {
        let _ = tx.blocking_send(Err(e));
        return;
    }
    let r = input.rest().and_then(|body| {
        let (records, tree) = parse_import(&body)?;
        drop(tree);
        Ok(records)
    });
    let records = match r {
        Ok(r) => r,
        Err(e) => {
            let _ = tx.blocking_send(Err(e));
            return;
        }
    };
    let mut sink = Sink::new(&tx, res);
    for r in records {
        if sink.record(r).is_err() {
            return;
        }
    }
    // the buffered parse checked the tree: this rebuilds the same root
    let records = sink.builder.records;
    let (root, nodes, node_bytes) = match std::mem::take(&mut sink.builder).finish(&mut sink.nodes) {
        Ok(v) => v,
        Err(e) => {
            let _ = tx.blocking_send(Err(XrpcError::from_err(e)));
            return;
        }
    };
    if sink.flush().is_err() {
        return;
    }
    let root = root.bytes.as_deref().map(Bytes::copy_from_slice).unwrap_or_default();
    let bytes = crate::state::RepoBytes { records: sink.record_bytes, nodes: node_bytes };
    let _ = tx.blocking_send(Ok(Item::Done { root, records, nodes, bytes, path: "buffered" }));
}

/// The single pass, handing records to `sink`.
fn stream(input: &mut Input, sink: &mut Sink) -> Result<(Bytes, u64, u64, crate::state::RepoBytes), Stop> {
    let hlen = input.varint().ok_or(Stop::Depart)?;
    let header = input.take(usize::try_from(hlen).map_err(|_| Stop::Depart)?).ok_or(Stop::Depart)?;
    let roots = car::read_header(&header).map_err(|_| Stop::Depart)?;
    let [root] = roots[..] else { return Err(Stop::Depart) };
    let (c, commit) = input.block().ok_or(Stop::Depart)?;
    if c != root || root.codec != vlsync_atproto::cid::CODEC_DAG_CBOR {
        return Err(Stop::Depart);
    }
    let commit = Value::decode(&commit).map_err(|_| Stop::Depart)?;
    if !matches!(commit.get("version"), Some(Value::Int(2 | 3))) {
        return Err(Stop::Depart);
    }
    let Some(Value::Link(data)) = commit.get("data") else { return Err(Stop::Depart) };
    let data = *data;
    let mut walk = Walk::new(data);
    let mut prev: Option<Arc<[u8]>> = None;
    loop {
        match walk.next() {
            Next::Node(want) => {
                let (c, b) = input.block().ok_or(Stop::Depart)?;
                if c != want {
                    return Err(Stop::Depart);
                }
                let n: Node = mst::decode_node(&b, c).map_err(|_| Stop::Depart)?;
                walk.enter(n).map_err(|_| Stop::Depart)?;
            }
            Next::Record { key, cid } => {
                if prev.as_ref().is_some_and(|p| key <= *p) {
                    return Err(Stop::Depart);
                }
                let path = std::str::from_utf8(&key).map_err(|_| Stop::Depart)?;
                if !vlsync_atproto::syntax::valid_record_path(path) || cid.codec != vlsync_atproto::cid::CODEC_DAG_CBOR
                {
                    return Err(Stop::Depart);
                }
                let (c, b) = input.block().ok_or(Stop::Depart)?;
                if c != cid {
                    return Err(Stop::Depart);
                }
                let blobs = imported_record_blobs(path, &b).map_err(|_| Stop::Depart)?;
                sink.record((path.to_string(), cid, b, blobs))?;
                prev = Some(key);
            }
            Next::Done => break,
        }
    }
    // The tree rebuilt from the records reproduces `data` only if every node
    // streamed was the canonical one: the same tree the buffered parse loads.
    let builder = std::mem::take(&mut sink.builder);
    let records = builder.records;
    let (root, nodes, node_bytes) = builder.finish(&mut sink.nodes).map_err(|_| Stop::Depart)?;
    if root.cid != Some(data) {
        return Err(Stop::Depart);
    }
    // further blocks are only checked against their CIDs, as there
    while !input.at_end() {
        input.block().ok_or(Stop::Depart)?;
    }
    // a body cut short (or refused by the pump) fails as the buffered parse
    // would, even after a whole CAR
    if input.end == End::Aborted {
        return Err(Stop::Depart);
    }
    sink.flush()?;
    let block = root.bytes.as_deref().map(Bytes::copy_from_slice).ok_or(Stop::Depart)?;
    Ok((block, records, nodes, crate::state::RepoBytes { records: sink.record_bytes, nodes: node_bytes }))
}

#[derive(PartialEq)]
enum End {
    Open,
    Done,
    Aborted,
}

/// The body as received so far, kept whole for a fallback: in memory (a
/// block within one chunk is a slice of it), or once over [`SPILL_AFTER`]
/// in a temporary file, the chunks read past dropped.
struct Input {
    rx: mpsc::Receiver<Chunk>,
    chunks: Vec<Bytes>,
    /// Read position: chunk index and offset in it.
    at: usize,
    off: usize,
    /// Bytes received past the read position.
    avail: usize,
    received: usize,
    end: End,
    /// Why the body ended early (the pump's error).
    fail: Option<XrpcError>,
    spill: Option<Spill>,
}

/// An unlinked-on-drop temporary file holding the body.
struct Spill {
    file: std::fs::File,
    path: std::path::PathBuf,
}

impl Drop for Spill {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

impl Input {
    fn new(rx: mpsc::Receiver<Chunk>) -> Input {
        Input { rx, chunks: Vec::new(), at: 0, off: 0, avail: 0, received: 0, end: End::Open, fail: None, spill: None }
    }

    fn recv(&mut self) -> bool {
        if self.end != End::Open {
            return false;
        }
        match self.rx.blocking_recv() {
            Some(Chunk::Data(c)) => {
                self.avail += c.len();
                self.received += c.len();
                if let Some(s) = &mut self.spill {
                    if s.file.write_all(&c).is_err() {
                        self.spill_failed();
                        return false;
                    }
                }
                self.chunks.push(c);
                if self.spill.is_none() && self.received > SPILL_AFTER {
                    self.start_spill();
                }
                self.drop_read();
                true
            }
            Some(Chunk::End) => {
                self.end = End::Done;
                false
            }
            Some(Chunk::Fail(e)) => {
                self.fail = Some(e);
                self.end = End::Aborted;
                false
            }
            None => {
                self.end = End::Aborted;
                false
            }
        }
    }

    fn start_spill(&mut self) {
        let path = std::env::temp_dir().join(format!("vlpds-import-{:016x}.car", rand::random::<u64>()));
        let opened = std::fs::OpenOptions::new().read(true).write(true).create_new(true).open(&path);
        let Ok(file) = opened else { return self.spill_failed() };
        let mut s = Spill { file, path };
        for c in &self.chunks {
            if s.file.write_all(c).is_err() {
                return self.spill_failed();
            }
        }
        self.spill = Some(s);
    }

    /// Without a file the body can't be kept for a fallback past the
    /// memory bound: the import fails rather than hold it.
    fn spill_failed(&mut self) {
        self.spill = None;
        self.fail = Some(XrpcError::internal("could not buffer the import body"));
        self.end = End::Aborted;
    }

    /// Spilled: the chunks before the read position are in the file only.
    fn drop_read(&mut self) {
        if self.spill.is_some() {
            for c in &mut self.chunks[..self.at] {
                *c = Bytes::new();
            }
        }
    }

    fn fill(&mut self, n: usize) -> bool {
        while self.avail < n {
            if !self.recv() {
                return false;
            }
        }
        true
    }

    fn at_end(&mut self) -> bool {
        !self.fill(1)
    }

    /// The next `n` bytes, or None if the body ends first.
    fn take(&mut self, n: usize) -> Option<Bytes> {
        if !self.fill(n) {
            return None;
        }
        self.avail -= n;
        while self.at < self.chunks.len() && self.off == self.chunks[self.at].len() {
            self.at += 1;
            self.off = 0;
        }
        if n == 0 {
            return Some(Bytes::new());
        }
        let c = &self.chunks[self.at];
        if c.len() - self.off >= n {
            let b = c.slice(self.off..self.off + n);
            self.off += n;
            return Some(b);
        }
        let mut out = Vec::with_capacity(n);
        while out.len() < n {
            let c = &self.chunks[self.at];
            let k = (c.len() - self.off).min(n - out.len());
            out.extend_from_slice(&c[self.off..self.off + k]);
            self.off += k;
            if self.off == c.len() {
                self.at += 1;
                self.off = 0;
            }
        }
        Some(Bytes::from(out))
    }

    /// As [`car::read_varint`].
    fn varint(&mut self) -> Option<u64> {
        let mut n = 0u64;
        for i in 0..10 {
            let b = self.take(1)?[0];
            n |= ((b & 0x7f) as u64) << (7 * i);
            if b & 0x80 == 0 {
                return Some(n);
            }
        }
        None
    }

    /// A block whose bytes match its CID.
    fn block(&mut self) -> Option<(Cid, Bytes)> {
        let len = self.varint()?;
        let b = self.take(usize::try_from(len).ok()?)?;
        let (c, cl) = Cid::read_prefix(&b).ok()?;
        let data = b.slice(cl..);
        car::block_matches(&c, &data).then_some((c, data))
    }

    /// The whole body.
    fn rest(mut self) -> XResult<Bytes> {
        while self.recv() {}
        if self.end == End::Aborted {
            return Err(self.fail.take().unwrap_or_else(|| XrpcError::bad("InvalidRequest", "request body aborted")));
        }
        if let Some(mut s) = self.spill.take() {
            let mut out = Vec::with_capacity(self.received);
            let read = std::io::Seek::rewind(&mut s.file).and_then(|_| s.file.read_to_end(&mut out));
            read.map_err(|e| XrpcError::internal(format!("reading back the import body: {e}")))?;
            return Ok(Bytes::from(out));
        }
        if self.chunks.len() == 1 {
            return Ok(self.chunks.pop().expect("one chunk"));
        }
        let mut out = Vec::with_capacity(self.received);
        // freed as copied, so the copy adds little
        for c in self.chunks.drain(..) {
            out.extend_from_slice(&c);
        }
        Ok(Bytes::from(out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use vlsync_atproto::cbor::key_cmp;
    use vlsync_atproto::mst::Tree;

    struct Repo {
        commit: (Cid, Vec<u8>),
        data: Cid,
        blocks: HashMap<Cid, Vec<u8>>,
    }

    fn record(path: &str) -> Vec<u8> {
        let mut m = vec![
            ("$type".to_string(), Value::Text(crate::worker::collection_of(path).into())),
            ("k".to_string(), Value::Text(path.into())),
        ];
        m.sort_by(|a, b| key_cmp(&a.0, &b.0));
        Value::Map(m).to_cbor()
    }

    fn commit(data: Cid) -> (Cid, Vec<u8>) {
        let mut f = vec![
            ("did".to_string(), Value::Text("did:plc:abc".into())),
            ("rev".to_string(), Value::Text("3l3qo2vuowo2b".into())),
            ("data".to_string(), Value::Link(data)),
            ("prev".to_string(), Value::Null),
            ("version".to_string(), Value::Int(3)),
            ("sig".to_string(), Value::Bytes(vec![0; 64])),
        ];
        f.sort_by(|a, b| key_cmp(&a.0, &b.0));
        let b = Value::Map(f).to_cbor();
        (Cid::dag_cbor(&b), b)
    }

    fn repo_of(records: &[(String, Vec<u8>)]) -> Repo {
        let mut tree = Tree::new();
        let mut blocks = Vec::new();
        for (p, r) in records {
            let c = Cid::dag_cbor(r);
            tree.insert_no_proof(p.as_bytes(), c).unwrap();
            blocks.push((c, r.clone()));
        }
        let data = tree.write_diff_blocks(&mut blocks).unwrap();
        Repo { commit: commit(data), data, blocks: blocks.into_iter().collect() }
    }

    fn repo(n: usize) -> Repo {
        let recs: Vec<(String, Vec<u8>)> = (0..n)
            .map(|i| {
                let p = format!("com.example.{}/{i:06}", ["a", "b", "c"][i % 3]);
                let r = record(&p);
                (p, r)
            })
            .collect();
        repo_of(&recs)
    }

    impl Repo {
        fn streamed(&self) -> Vec<u8> {
            vlsync_atproto::car_order::write_car((self.commit.0, &self.commit.1), self.data, &self.blocks).unwrap()
        }

        /// Commit, then the other blocks by CID.
        fn cid_ordered(&self) -> Vec<u8> {
            let mut out = Vec::new();
            car::write_header(&mut out, &self.commit.0);
            car::write_block(&mut out, &self.commit.0, &self.commit.1);
            let mut cs: Vec<&Cid> = self.blocks.keys().collect();
            cs.sort_by_key(|c| c.to_bytes());
            for c in cs {
                car::write_block(&mut out, c, &self.blocks[c]);
            }
            out
        }
    }

    type Parsed = XResult<(Vec<ImportedRecord>, Cid)>;

    fn unbounded() -> Arc<Reservation> {
        futures::executor::block_on(
            super::super::import_budget::ImportBudget::new(1 << 40, std::time::Duration::ZERO).admit(None),
        )
        .ok()
        .expect("room")
    }

    /// Feeds `car` in chunks of `chunk` bytes, as a request body would, and
    /// collects what the parse hands out: the records (those before a
    /// restart dropped), the root, the path. Also checks the batches' nodes
    /// are the persisted nodes of the tree.
    fn run(car: &[u8], chunk: usize) -> (Parsed, &'static str) {
        let (tx, rx) = mpsc::channel(car.len() / chunk + 2);
        for c in car.chunks(chunk) {
            tx.try_send(Chunk::Data(Bytes::copy_from_slice(c))).ok().unwrap();
        }
        tx.try_send(Chunk::End).ok().unwrap();
        let (itx, mut irx) = mpsc::channel(1 << 16);
        parse(rx, itx, &unbounded());
        let (mut recs, mut nodes) = (Vec::new(), HashMap::new());
        loop {
            match irx.try_recv().expect("an item") {
                Ok(Item::Batch { records, nodes: n }) => {
                    recs.extend(records);
                    nodes.extend(n);
                }
                Ok(Item::Restart) => {
                    recs.clear();
                    nodes.clear();
                }
                Ok(Item::Done { root, records, nodes: count, bytes, path }) => {
                    let root_cid = Cid::dag_cbor(&root);
                    assert_eq!(records as usize, recs.len());
                    let mut t = Tree::new();
                    for (p, c, ..) in &recs {
                        t.insert_no_proof(p.as_bytes(), *c).unwrap();
                    }
                    assert_eq!(t.root_cid().unwrap(), root_cid);
                    assert_eq!(count, crate::repo_stats::count_tree(&t).unwrap().1);
                    assert_eq!(bytes.nodes, crate::repo_stats::tree_bytes(&t).unwrap());
                    assert_eq!(bytes.records, recs.iter().map(|r| r.2.len() as u64).sum::<u64>());

                    let want = crate::mst_lazy::persisted_nodes(&t, 1);
                    assert_eq!(nodes.len(), want.len());
                    assert!(want.keys().all(|c| nodes.contains_key(c)));
                    return (Ok((recs, root_cid)), path);
                }
                Err(e) => return (Err(e), "buffered"),
            }
        }
    }

    fn summary(r: &Parsed) -> Result<(Vec<ImportedRecord>, Cid), String> {
        match r {
            Ok(v) => Ok(v.clone()),
            Err(e) => Err(format!("{} {}: {}", e.status, e.error, e.message)),
        }
    }

    fn buffered(car: &[u8]) -> Result<(Vec<ImportedRecord>, Cid), String> {
        summary(&parse_import(&Bytes::copy_from_slice(car)).map(|(r, mut t)| (r, t.root_cid().unwrap())))
    }

    /// A streamed CAR takes the fast path at any chunking (blocks split
    /// across chunks included), with the buffered parse's result.
    #[test]
    fn streamed_car_takes_the_fast_path() {
        for n in [0, 1, 7, 500] {
            let r = repo(n);
            let car = r.streamed();
            let want = buffered(&car);
            assert!(want.is_ok());
            for chunk in [1, 3, 64, 4096, car.len()] {
                let (got, path) = run(&car, chunk);
                assert_eq!(path, "stream", "n={n} chunk={chunk}");
                assert_eq!(summary(&got), want, "n={n} chunk={chunk}");
            }
        }
    }

    /// A body past its Content-Length's estimate grows the reservation as
    /// it arrives; with no room to grow the import fails with a retryable
    /// 503 and holds nothing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bodies_past_their_estimate_grow_the_reservation() {
        use super::super::import_budget::{sizing, ImportBudget};
        let car = repo(20_000).streamed();
        let chunked = |car: Vec<u8>| {
            Body::from_stream(futures::stream::iter(
                car.chunks(8192).map(|c| Ok::<_, std::io::Error>(Bytes::copy_from_slice(c))).collect::<Vec<_>>(),
            ))
        };
        let budget = ImportBudget::new(64 << 20, std::time::Duration::from_millis(100));
        let res = budget.admit(Some(100)).await.ok().expect("room");
        let before = res.held();
        let mut items = start(TimedBody::new(chunked(car.clone()), BODY_IDLE, BODY_DEADLINE), usize::MAX, res.clone());
        loop {
            match items.recv().await.expect("an item") {
                Ok(Item::Batch { .. }) => {}
                Ok(Item::Done { records, path, .. }) => {
                    assert_eq!((records, path), (20_000, "stream"));
                    break;
                }
                Ok(Item::Restart) => panic!("restart"),
                Err(e) => panic!("{}", e.message),
            }
        }
        assert!(res.car() >= car.len() as u64 && res.held() > before);
        assert_eq!(res.held(), sizing(res.car()).working_set);
        drop((items, res));
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(budget.reserved(), 0);

        // no room to grow: 503, nothing left reserved
        let budget = ImportBudget::new(2 << 20, std::time::Duration::from_millis(100));
        let other = budget.admit(Some(100)).await.ok().expect("room");
        let res = budget.admit(Some(100)).await.ok().expect("room");
        let mut items = start(TimedBody::new(chunked(car), BODY_IDLE, BODY_DEADLINE), usize::MAX, res);
        let e = loop {
            match items.recv().await.expect("an item") {
                Err(e) => break e,
                Ok(Item::Done { .. }) => panic!("imported past the budget"),
                Ok(_) => {}
            }
        };
        assert_eq!((e.status, e.error.as_str()), (StatusCode::SERVICE_UNAVAILABLE, "Overloaded"));
        drop((items, other));
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(budget.reserved(), 0);
    }

    /// Other orders fall back, with the same result.
    #[test]
    fn other_orders_fall_back() {
        let r = repo(300);
        let car = r.cid_ordered();
        let (got, path) = run(&car, 1000);
        assert_eq!(path, "buffered");
        assert_eq!(summary(&got), buffered(&r.streamed()));
        // a streamed CAR with two blocks swapped
        let streamed = r.streamed();
        let (_, blocks) = car::read_car(&streamed).unwrap();
        let mut blocks: Vec<(Cid, Vec<u8>)> = blocks.into_iter().map(|(c, b)| (c, b.to_vec())).collect();
        let k = blocks.len() / 2;
        blocks.swap(k, k + 1);
        let mut car = Vec::new();
        car::write_header(&mut car, &r.commit.0);
        for (c, b) in &blocks {
            car::write_block(&mut car, c, b);
        }
        let (got, path) = run(&car, 1000);
        assert_eq!(path, "buffered");
        assert_eq!(summary(&got), buffered(&r.streamed()));
    }

    /// Extra blocks after the tree are only hash-checked; a record under two
    /// keys is repeated at each, or (deduplicated) falls back.
    #[test]
    fn trailing_blocks_and_shared_records() {
        let r = repo(50);
        let mut car = r.streamed();
        car::write_block(&mut car, &Cid::raw(b"extra"), b"extra");
        let (got, path) = run(&car, 100);
        assert_eq!(path, "stream");
        assert_eq!(summary(&got), buffered(&car));
        let mut bad = r.streamed();
        car::write_block(&mut bad, &Cid::raw(b"extra"), b"other");
        let (got, path) = run(&bad, 100);
        assert_eq!(path, "buffered");
        assert!(summary(&got).unwrap_err().contains("block does not match its cid"));

        let same = record("com.example.a/x");
        let recs: Vec<(String, Vec<u8>)> = (0..40)
            .map(|i| {
                (
                    format!("com.example.a/{i:03}"),
                    if i % 10 == 0 { same.clone() } else { record(&format!("com.example.a/{i:03}")) },
                )
            })
            .collect();
        let r = repo_of(&recs);
        let car = r.streamed();
        let (got, path) = run(&car, 100);
        assert_eq!(path, "stream");
        assert_eq!(summary(&got), buffered(&car));
        assert_eq!(summary(&got).unwrap().0.len(), 40);
        let (_, blocks) = car::read_car(&car).unwrap();
        let mut seen = std::collections::HashSet::new();
        let mut dedup = Vec::new();
        car::write_header(&mut dedup, &r.commit.0);
        for (c, b) in blocks {
            if seen.insert(c) {
                car::write_block(&mut dedup, &c, b);
            }
        }
        let (got, path) = run(&dedup, 100);
        assert_eq!(path, "buffered");
        assert_eq!(summary(&got), buffered(&car));
    }

    /// Refused CARs fail with the buffered parse's error.
    #[test]
    fn refusals_match_the_buffered_parse() {
        let r = repo(200);
        let good = r.streamed();
        let (_, blocks) = car::read_car(&good).unwrap();
        let blocks: Vec<(Cid, Vec<u8>)> = blocks.into_iter().map(|(c, b)| (c, b.to_vec())).collect();
        let build = |bs: &[(Cid, Vec<u8>)]| {
            let mut car = Vec::new();
            car::write_header(&mut car, &r.commit.0);
            for (c, b) in bs {
                car::write_block(&mut car, c, b);
            }
            car
        };
        let rec_at = blocks.iter().position(|(c, b)| *c != r.commit.0 && mst::decode_node(b, *c).is_err()).unwrap();
        let mut cases: Vec<(&str, Vec<u8>)> = Vec::new();
        // a record block replaced by another record (wrong CID for its leaf)
        let mut bs = blocks.clone();
        let other = record("com.example.zzz/x");
        bs[rec_at] = (Cid::dag_cbor(&other), other);
        cases.push(("wrong record cid", build(&bs)));
        // a record's bytes changed under its CID
        let mut bs = blocks.clone();
        bs[rec_at].1.push(0);
        cases.push(("bad record bytes", build(&bs)));
        // a missing record block, and a missing node
        let mut bs = blocks.clone();
        bs.remove(rec_at);
        cases.push(("missing record", build(&bs)));
        let mut bs = blocks.clone();
        let node_at = blocks.iter().rposition(|(c, b)| mst::decode_node(b, *c).is_ok()).unwrap();
        bs.remove(node_at);
        cases.push(("missing node", build(&bs)));
        // truncated mid-block, and at a block boundary
        cases.push(("truncated", good[..good.len() - 7].to_vec()));
        cases.push(("truncated at a block", build(&blocks[..blocks.len() - 1])));
        // a record too big, and not CBOR
        let mut tree = Tree::new();
        let big = {
            let m = vec![
                ("$type".to_string(), Value::Text("com.example.a".into())),
                ("b".to_string(), Value::Bytes(vec![1; (2 << 20) + 1])),
            ];
            Value::Map(m).to_cbor()
        };
        let junk = b"\xff\xff".to_vec();
        for (name, rec) in [("record too large", big), ("record not cbor", junk)] {
            let c = Cid::dag_cbor(&rec);
            tree.insert_no_proof(b"com.example.a/x", c).unwrap();
            let mut bs = vec![(c, rec)];
            let data = tree.write_diff_blocks(&mut bs).unwrap();
            let map: HashMap<Cid, Vec<u8>> = bs.into_iter().collect();
            let cm = commit(data);
            cases.push((name, vlsync_atproto::car_order::write_car((cm.0, &cm.1), data, &map).unwrap()));
        }
        // a header with two roots, and garbage
        let mut two = Vec::new();
        let mut h = Vec::new();
        vlsync_atproto::cbor::write_map_head(&mut h, 2);
        vlsync_atproto::cbor::write_text(&mut h, "roots");
        vlsync_atproto::cbor::write_array_head(&mut h, 2);
        vlsync_atproto::cbor::write_cid(&mut h, &r.commit.0);
        vlsync_atproto::cbor::write_cid(&mut h, &r.commit.0);
        vlsync_atproto::cbor::write_text(&mut h, "version");
        vlsync_atproto::cbor::write_uint(&mut h, 1);
        car::write_varint(&mut two, h.len() as u64);
        two.extend_from_slice(&h);
        for (c, b) in &blocks {
            car::write_block(&mut two, c, b);
        }
        cases.push(("two roots", two));
        cases.push(("garbage", vec![0xff; 20]));
        cases.push(("empty", Vec::new()));
        for (name, car) in cases {
            let want = buffered(&car);
            assert!(want.is_err(), "{name}: {want:?}");
            for chunk in [1, 100, car.len().max(1)] {
                let (got, path) = run(&car, chunk);
                assert_eq!(path, "buffered", "{name}");
                assert_eq!(summary(&got).map(|_| ()), want.clone().map(|_| ()), "{name}");
            }
        }
    }

    /// A node linking one child twice: the stream has to send the child again
    /// for the second link (work stays linear in the body), so one sent once
    /// is a departure, and the buffered parse refuses the DAG.
    #[test]
    fn dag_mst_falls_back_and_is_refused() {
        let k1 = (0..).map(|i| format!("com.example.a/{i}")).find(|k| mst::height_for_key(k.as_bytes()) == 1).unwrap();
        let rec = record("com.example.a/x");
        let rc = Cid::dag_cbor(&rec);
        let mut leaf = Vec::new();
        let n = mst::Node::clean(0, vec![mst::Entry::Value { key: Arc::from(&b"com.example.a/x"[..]), val: rc }], None);
        mst::encode_node(&n, &mut leaf).unwrap();
        let lc = Cid::dag_cbor(&leaf);
        let child = || mst::Entry::Child { node: None, cid: Some(lc) };
        let entries = vec![child(), mst::Entry::Value { key: Arc::from(k1.as_bytes()), val: rc }, child()];
        let mut parent = Vec::new();
        mst::encode_node(&mst::Node::clean(1, entries, None), &mut parent).unwrap();
        let pc = Cid::dag_cbor(&parent);
        let cm = commit(pc);
        let mut car = Vec::new();
        car::write_header(&mut car, &cm.0);
        for (c, b) in [(cm.0, &cm.1), (pc, &parent), (lc, &leaf), (rc, &rec), (rc, &rec)] {
            car::write_block(&mut car, &c, b);
        }
        let (got, path) = run(&car, 50);
        assert_eq!(path, "buffered");
        let want = buffered(&car);
        assert!(want.as_ref().unwrap_err().contains("could not load MST"), "{want:?}");
        assert_eq!(summary(&got).map(|_| ()), want.map(|_| ()));
    }

    /// A well-formed stream of a non-canonical tree (a key-less root over the
    /// one leaf) falls back and is refused.
    #[test]
    fn non_canonical_tree_falls_back_and_is_refused() {
        let leaf_rec = record("com.example.a/x");
        let rc = Cid::dag_cbor(&leaf_rec);
        let mut leaf = Vec::new();
        let n = mst::Node::clean(0, vec![mst::Entry::Value { key: Arc::from(&b"com.example.a/x"[..]), val: rc }], None);
        mst::encode_node(&n, &mut leaf).unwrap();
        let lc = Cid::dag_cbor(&leaf);
        let entries = vec![mst::Entry::Child { node: None, cid: Some(lc) }];
        let mut parent = Vec::new();
        mst::encode_node(&mst::Node::clean(1, entries, None), &mut parent).unwrap();
        let pc = Cid::dag_cbor(&parent);
        let cm = commit(pc);
        let mut car = Vec::new();
        car::write_header(&mut car, &cm.0);
        for (c, b) in [(cm.0, &cm.1), (pc, &parent), (lc, &leaf), (rc, &leaf_rec)] {
            car::write_block(&mut car, &c, b);
        }
        let (got, path) = run(&car, 50);
        assert_eq!(path, "buffered");
        assert_eq!(summary(&got).map(|_| ()), buffered(&car).map(|_| ()));
        assert!(got.is_err());
    }

    /// A node block from raw parts, canonical or not: `l`, then entries of
    /// (prefix length, key suffix, right subtree, value).
    fn raw_node(l: Option<Cid>, es: &[(usize, &[u8], Option<Cid>, Cid)]) -> (Cid, Vec<u8>) {
        let link = |c: Option<Cid>| c.map_or(Value::Null, Value::Link);
        let e = es
            .iter()
            .map(|(p, k, t, v)| {
                Value::Map(vec![
                    ("k".into(), Value::Bytes(k.to_vec())),
                    ("p".into(), Value::Int(*p as i64)),
                    ("t".into(), link(*t)),
                    ("v".into(), Value::Link(*v)),
                ])
            })
            .collect();
        let b = Value::Map(vec![("e".into(), Value::Array(e)), ("l".into(), link(l))]).to_cbor();
        (Cid::dag_cbor(&b), b)
    }

    /// A CAR of a commit over `data`, then `blocks` in the given order.
    fn car_over(root: Option<(Cid, Vec<u8>)>, data: Cid, blocks: &[(Cid, &[u8])]) -> Vec<u8> {
        let cm = root.unwrap_or_else(|| commit(data));
        let mut car = Vec::new();
        car::write_header(&mut car, &cm.0);
        car::write_block(&mut car, &cm.0, &cm.1);
        for (c, b) in blocks {
            car::write_block(&mut car, c, b);
        }
        car
    }

    fn key_at(h: i32, n: usize) -> Vec<String> {
        let mut ks: Vec<String> = (0..)
            .map(|i| format!("com.example.a/k{i}"))
            .filter(|k| mst::height_for_key(k.as_bytes()) == h)
            .take(n)
            .collect();
        ks.sort();
        ks
    }

    /// Non-canonical trees and non-dag-cbor links are refused by both
    /// parses with the same error: duplicate or unordered keys in a node, a
    /// key at the wrong layer, a node reached through a raw-codec link, a
    /// record or commit under a raw-codec CID.
    #[test]
    fn non_canonical_trees_and_codecs_refused() {
        let rec = record("com.example.a/x");
        let rc = Cid::dag_cbor(&rec);
        let [k0, k1] = <[String; 2]>::try_from(key_at(0, 2)).unwrap();
        let (k0, k1) = (k0.as_bytes(), k1.as_bytes());
        let mut cases: Vec<(&str, Vec<u8>)> = Vec::new();

        // control: the canonical one-node tree imports
        let (good, gb) =
            raw_node(None, &[(0, k0, None, rc), (count_prefix(k0, k1), &k1[count_prefix(k0, k1)..], None, rc)]);
        let ok = car_over(None, good, &[(good, &gb), (rc, &rec), (rc, &rec)]);
        assert_eq!(buffered(&ok).unwrap().0.len(), 2);
        assert_eq!(run(&ok, 64).1, "stream");

        let (dup, b) = raw_node(None, &[(0, k0, None, rc), (k0.len(), b"", None, rc)]);
        cases.push(("duplicate key", car_over(None, dup, &[(dup, &b), (rc, &rec), (rc, &rec)])));
        let (unordered, b) = raw_node(None, &[(0, k1, None, rc), (0, k0, None, rc)]);
        cases.push(("keys out of order", car_over(None, unordered, &[(unordered, &b), (rc, &rec), (rc, &rec)])));

        // a height-1 key over a leaf holding another height-1 key
        let [h1a, h1b] = <[String; 2]>::try_from(key_at(1, 2)).unwrap();
        let (leaf, lb) = raw_node(None, &[(0, h1a.as_bytes(), None, rc)]);
        let (top, tb) = raw_node(Some(leaf), &[(0, h1b.as_bytes(), None, rc)]);
        cases.push(("key at the wrong layer", car_over(None, top, &[(top, &tb), (leaf, &lb), (rc, &rec), (rc, &rec)])));

        // the canonical tree of k0 and h1a, its leaf linked as raw
        let (leaf, lb) = raw_node(None, &[(0, k0, None, rc)]);
        let raw_leaf = Cid::raw(&lb);
        let over = |child: Cid| match k0 < h1a.as_bytes() {
            true => raw_node(Some(child), &[(0, h1a.as_bytes(), None, rc)]),
            false => raw_node(None, &[(0, h1a.as_bytes(), Some(child), rc)]),
        };
        let (top, tb) = over(raw_leaf);
        let (canon, cb) = over(leaf);
        assert!(buffered(&car_over(None, canon, &[(canon, &cb), (leaf, &lb), (rc, &rec), (rc, &rec)])).is_ok());
        cases
            .push(("raw-codec node link", car_over(None, top, &[(top, &tb), (raw_leaf, &lb), (rc, &rec), (rc, &rec)])));

        // a record under a raw-codec CID (the tree itself is canonical)
        let raw_rec = Cid::raw(&rec);
        let (one, ob) = raw_node(None, &[(0, k0, None, raw_rec)]);
        cases.push(("raw-codec record", car_over(None, one, &[(one, &ob), (raw_rec, &rec)])));

        // the commit under a raw-codec CID
        let (one, ob) = raw_node(None, &[(0, k0, None, rc)]);
        let cm = commit(one);
        let raw_commit = (Cid::raw(&cm.1), cm.1.clone());
        cases.push(("raw-codec commit", car_over(Some(raw_commit), one, &[(one, &ob), (rc, &rec)])));

        for (name, car) in cases {
            let want = buffered(&car);
            let why = match name {
                "duplicate key" | "keys out of order" => "keys not in ascending order",
                "key at the wrong layer" => "child height is not parent height - 1",
                "raw-codec node link" => "CAR does not contain the complete MST",
                "raw-codec record" => "record CID at com.example.a/",
                _ => "commit CID is not dag-cbor",
            };
            assert!(want.as_ref().is_err_and(|e| e.contains(why)), "{name}: {want:?}");
            for chunk in [1, 64, car.len()] {
                let (got, path) = run(&car, chunk);
                assert_eq!(path, "buffered", "{name}");
                assert_eq!(summary(&got).map(|_| ()), want.clone().map(|_| ()), "{name}");
            }
        }
    }

    fn count_prefix(a: &[u8], b: &[u8]) -> usize {
        a.iter().zip(b).take_while(|(x, y)| x == y).count()
    }

    /// Duplicate blocks (same CID, same bytes) anywhere in the body are
    /// tolerated by both parses: content addressing makes them identical.
    #[test]
    fn duplicate_blocks_tolerated() {
        let r = repo(60);
        let ordered = r.cid_ordered();
        let (_, blocks) = car::read_car(&ordered).unwrap();
        let mut car = Vec::new();
        car::write_header(&mut car, &r.commit.0);
        for (c, b) in blocks.iter().chain(blocks.iter()) {
            car::write_block(&mut car, c, b);
        }
        assert_eq!(buffered(&car), buffered(&r.streamed()));
        let once = r.streamed();
        let mut streamed = once.clone();
        let (_, sblocks) = car::read_car(&once).unwrap();
        for (c, b) in &sblocks {
            car::write_block(&mut streamed, c, b);
        }
        let (got, path) = run(&streamed, 100);
        assert_eq!(path, "stream");
        assert_eq!(summary(&got), buffered(&r.streamed()));
    }
}
