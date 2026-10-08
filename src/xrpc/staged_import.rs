//! importRepo, staged under a fresh repo generation (DESIGN.md "Staged
//! imports"). The parse (`import_stream`) hands out the records in key order
//! in batches; each becomes a log entry of rows under the new generation
//! (`R/ c/ b/ bl/ M/`), which no reader looks at: readers key by the
//! account's generation. One small entry then commits: the account moves to
//! the new generation with the new head, `S/`, the collection index and
//! #sync, and the old generation goes to the garbage (`G/`), whose rows are
//! deleted in batches afterwards. Memory is a few batches whatever the
//! repo's size.
//!
//! A crash or a shard move mid-import leaves the staged rows unreachable;
//! the sweeper ([`sweep_pending`], on the shard's owner) aborts an import
//! whose driver is gone and deletes every garbage generation.

use super::import_budget::Reservation;
use super::import_stream::{self, Item};
use super::repo::ImportedRecord;
use super::*;
use crate::worker::{AccountOp, AccountReq, ImportStep, ImportTicket};
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::time::Duration;
use tokio::sync::oneshot;

/// Batches staged ahead of their acks.
pub(super) const IN_FLIGHT: usize = 2;
/// Keys deleted per sweep entry.
const SWEEP_KEYS: usize = 8192;
pub const SWEEP_INTERVAL: Duration = Duration::from_secs(60);
const INTERRUPTED: &str = "ImportInterrupted";

/// DID -> nonce of the import this node is driving. The repo's worker
/// refuses other commits while it stages ([`driving`]); a staged import
/// that isn't here (a crash, a move) is the sweeper's to abort.
static DRIVING: parking_lot::Mutex<Option<HashMap<String, u64>>> = parking_lot::Mutex::new(None);

pub fn driving(did: &str, nonce: u64) -> bool {
    DRIVING.lock().as_ref().and_then(|m| m.get(did)).is_some_and(|n| *n == nonce)
}

struct Driver {
    did: String,
    nonce: u64,
}

impl Driver {
    fn start(did: &str) -> XResult<Driver> {
        let nonce = rand::random::<u64>();
        let mut g = DRIVING.lock();
        let m = g.get_or_insert_with(HashMap::new);
        if m.contains_key(did) {
            return Err(XrpcError::from(WriteError::Invalid(
                "a repo import is in progress; retry once it is done".into(),
            )));
        }
        m.insert(did.to_string(), nonce);
        Ok(Driver { did: did.to_string(), nonce })
    }
}

impl Drop for Driver {
    fn drop(&mut self) {
        if let Some(m) = DRIVING.lock().as_mut() {
            if m.get(&self.did) == Some(&self.nonce) {
                m.remove(&self.did);
            }
        }
    }
}

/// (DID, generation) sweeps running on this node.
static SWEEPING: parking_lot::Mutex<Option<HashSet<(String, u64)>>> = parking_lot::Mutex::new(None);

struct Sweeping((String, u64));

impl Sweeping {
    fn take(did: &str, gen: u64) -> Option<Sweeping> {
        let k = (did.to_string(), gen);
        let fresh = SWEEPING.lock().get_or_insert_with(HashSet::new).insert(k.clone());
        fresh.then(|| Sweeping(k))
    }
}

impl Drop for Sweeping {
    fn drop(&mut self) {
        if let Some(s) = SWEEPING.lock().as_mut() {
            s.remove(&self.0);
        }
    }
}

/// Phases: "begun" (the generation is reserved), "staged" (after each
/// batch's entry), "committed" (the commit is durable, the old generation
/// not swept) and "sweeping" (before each sweep entry). A firing hook stops
/// the work there with nothing undone, as a crash would; the test halts
/// the node in it.
static CRASH_HOOKS: vlsync_store::lifecycle::CrashHooks = vlsync_store::lifecycle::CrashHooks::new();

pub fn set_crash_hook(did: &str, h: Option<vlsync_store::lifecycle::CrashHook>) {
    CRASH_HOOKS.set(did, h)
}

fn crash_at(did: &str, phase: &str) -> XResult<()> {
    // a test's hook may block (to pause the import there): off the worker,
    // so the tasks queued behind it run meanwhile
    let multi = tokio::runtime::Handle::try_current()
        .is_ok_and(|h| h.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread);
    let fires = match multi {
        true => tokio::task::block_in_place(|| CRASH_HOOKS.fires(did, phase)),
        false => CRASH_HOOKS.fires(did, phase),
    };
    match fires {
        true => Err(XrpcError::unavailable(INTERRUPTED, format!("import of {did} stopped at {phase} (crash hook)"))),
        false => Ok(()),
    }
}

fn crashed(e: &XrpcError) -> bool {
    e.error == INTERRUPTED
}

type Reply = oneshot::Receiver<Result<Head, WriteError>>;

/// Queues an import step on the repo's worker; steps reach it in the order
/// queued.
fn queue(app: &App, did: &str, step: ImportStep) -> XResult<Reply> {
    let (tx, rx) = oneshot::channel();
    app.workers
        .route(did)
        .send(WorkerMsg::Account(AccountReq { did: did.into(), op: AccountOp::Import(step), reply: tx }))
        .map_err(XrpcError::from_err)?;
    Ok(rx)
}

async fn settle(rx: Reply) -> XResult<Head> {
    Ok(rx.await.map_err(|_| XrpcError::internal("worker dropped request"))??)
}

async fn step(app: &App, did: &str, step: ImportStep) -> XResult<Head> {
    settle(queue(app, did, step)?).await
}

/// The import of `body` into `did`'s repo, once the node's import budget
/// admits it (`import_budget`).
pub(super) async fn import(app: &Arc<App>, did: &str, body: Body, headers: &HeaderMap) -> XResult<()> {
    let max = app.config.max_import_bytes;
    let declared =
        headers.get(header::CONTENT_LENGTH).and_then(|v| v.to_str().ok()).and_then(|v| v.parse::<u64>().ok());
    if declared.is_some_and(|n| n > max as u64) {
        return Err(import_stream::too_large(max));
    }
    let res = app.imports.admit(declared).await?;
    let driver = Driver::start(did)?;
    let body = import_stream::TimedBody::new(body, app.config.import_body_idle, app.config.import_body_deadline);
    let mut items = import_stream::start(body, max, res.clone());
    let mut st = Stage { did: did.to_string(), nonce: driver.nonce, ..Default::default() };
    let r = st.run(app, &mut items, &res).await;
    if let Err(e) = &r {
        if !crashed(e) {
            st.abort(app).await;
        }
    }
    r
}

/// One import's staging.
#[derive(Default)]
struct Stage {
    did: String,
    nonce: u64,
    ticket: Option<ImportTicket>,
    /// Entries queued and not acked yet, oldest first, by batch number.
    inflight: VecDeque<(u64, Reply)>,
    batch: u64,
    /// Backlink values written by batches not acked yet, with the batch
    /// that wrote them; acked ones are read back from the store.
    recent: HashMap<Vec<u8>, (u64, crate::backlinks::Rkeys)>,
    /// Links staged so far: a miss needs no read.
    seen: Bloom,
    colls: BTreeSet<String>,
}

impl Stage {
    async fn run(
        &mut self,
        app: &Arc<App>,
        items: &mut tokio::sync::mpsc::Receiver<XResult<Item>>,
        res: &Reservation,
    ) -> XResult<()> {
        loop {
            let item = items.recv().await.ok_or_else(|| XrpcError::internal("import parse ended early"))??;
            match item {
                Item::Batch { records, nodes } => self.stage(app, records, nodes, res.sizing().bloom_words).await?,
                Item::Restart => {
                    self.drain().await?;
                    // a Begin with the same nonce sends the staged
                    // generation to the garbage and reserves another
                    if self.ticket.is_some() {
                        self.begin(app).await?;
                    }
                    *self = Stage {
                        did: std::mem::take(&mut self.did),
                        nonce: self.nonce,
                        ticket: self.ticket,
                        ..Default::default()
                    };
                }
                Item::Done { root, records, nodes, bytes, path } => {
                    metrics::IMPORT_REPO_PARSES.with_label_values(&[path]).inc();
                    return self.commit(app, root, records, nodes, bytes).await;
                }
            }
        }
    }

    async fn begin(&mut self, app: &Arc<App>) -> XResult<ImportTicket> {
        let (tx, rx) = oneshot::channel();
        step(app, &self.did, ImportStep::Begin { nonce: self.nonce, ticket: tx }).await?;
        let t = rx.await.map_err(|_| XrpcError::internal("import ticket dropped"))?;
        self.ticket = Some(t);
        if let Some(g) = t.stale {
            spawn_sweep(app.clone(), self.did.clone(), g);
        }
        crash_at(&self.did, "begun")?;
        Ok(t)
    }

    async fn ticket(&mut self, app: &Arc<App>) -> XResult<ImportTicket> {
        match self.ticket {
            Some(t) => Ok(t),
            None => self.begin(app).await,
        }
    }

    async fn stage(
        &mut self,
        app: &Arc<App>,
        records: Vec<ImportedRecord>,
        nodes: Vec<(Cid, Arc<[u8]>)>,
        bloom_words: usize,
    ) -> XResult<()> {
        let t = self.ticket(app).await?;
        let did = self.did.clone();
        let (mut muts, links, colls) =
            tokio::task::spawn_blocking(move || rows(&did, t, records, nodes)).await.map_err(XrpcError::from_err)?;
        self.colls.extend(colls);
        while self.inflight.len() >= IN_FLIGHT {
            self.ack_oldest().await?;
        }
        self.batch += 1;
        self.backlinks(app, t.gen, links, &mut muts, bloom_words).await?;
        let rx = queue(app, &self.did, ImportStep::Rows { nonce: self.nonce, epoch: t.epoch, muts })?;
        self.inflight.push_back((self.batch, rx));
        Ok(())
    }

    async fn ack_oldest(&mut self) -> XResult<()> {
        let Some((n, rx)) = self.inflight.pop_front() else { return Ok(()) };
        settle(rx).await?;
        self.recent.retain(|_, (b, _)| *b > n);
        crash_at(&self.did, "staged")
    }

    async fn drain(&mut self) -> XResult<()> {
        while !self.inflight.is_empty() {
            self.ack_oldest().await?;
        }
        Ok(())
    }

    /// The `bl/` values of a batch's links: its rkeys added to what earlier
    /// batches wrote (records come in key order, so a collection's rkeys
    /// only ever append).
    async fn backlinks(
        &mut self,
        app: &App,
        gen: u64,
        links: Vec<(Vec<u8>, Box<str>)>,
        muts: &mut Vec<vlsync_store::segment::Mutation>,
        bloom_words: usize,
    ) -> XResult<()> {
        let mut by_link: std::collections::BTreeMap<Vec<u8>, crate::backlinks::Rkeys> = Default::default();
        for (l, rkey) in links {
            by_link.entry(l).or_default().push(rkey);
        }
        let p = (!by_link.is_empty()).then(|| app.partition(&self.did)).transpose()?;
        for (l, rkeys) in by_link {
            let mut v = match self.recent.get(&l) {
                Some((_, v)) => v.clone(),
                None if self.seen.maybe(&l) => {
                    let p = p.as_ref().expect("a link");
                    let got = p.db.get(state::backlink_key(&self.did, gen, &l)).await.map_err(XrpcError::from_err)?;
                    got.map(|v| crate::backlinks::decode(&v)).unwrap_or_default()
                }
                None => Vec::new(),
            };
            v.extend(rkeys);
            v.sort();
            v.dedup();
            self.seen.insert(&l, bloom_words);
            muts.push(vlsync_store::segment::Mutation {
                key: state::backlink_key(&self.did, gen, &l).into(),
                val: Some(crate::backlinks::encode(&v)),
            });
            self.recent.insert(l, (self.batch, v));
        }
        Ok(())
    }

    async fn commit(
        &mut self,
        app: &Arc<App>,
        root: Bytes,
        records: u64,
        nodes: u64,
        bytes: state::RepoBytes,
    ) -> XResult<()> {
        let t = self.ticket(app).await?;
        self.drain().await?;
        let p = app.partition(&self.did)?;
        let blobs = distinct_blobs(&*p.db, &self.did, t.gen).await.map_err(XrpcError::from_err)?;
        let old: BTreeSet<String> =
            collections(&*p.db, &self.did, t.old_gen).await.map_err(XrpcError::from_err)?.into_iter().collect();
        let colls_add = self.colls.difference(&old).cloned().collect();
        let colls_del = old.difference(&self.colls).cloned().collect();
        let root = (!root.is_empty()).then_some(root);
        let stats = state::RepoStats { records, nodes, blobs, bytes: Some(bytes) };

        step(
            app,
            &self.did,
            ImportStep::Commit { nonce: self.nonce, epoch: t.epoch, root, stats, colls_add, colls_del },
        )
        .await?;
        self.ticket = None;
        crash_at(&self.did, "committed")?;
        spawn_sweep(app.clone(), self.did.clone(), t.old_gen);
        Ok(())
    }

    /// Best effort: whatever it can't do, the sweeper does.
    async fn abort(&mut self, app: &Arc<App>) {
        let Some(t) = self.ticket.take() else { return };
        let _ = self.drain().await;
        if step(app, &self.did, ImportStep::Abort { nonce: self.nonce }).await.is_ok() {
            spawn_sweep(app.clone(), self.did.clone(), t.gen);
        }
    }
}

/// A batch's rows under the staged generation, its links (for `bl/`) and
/// its collections.
#[allow(clippy::type_complexity)]
fn rows(
    did: &str,
    t: ImportTicket,
    records: Vec<ImportedRecord>,
    nodes: Vec<(Cid, Arc<[u8]>)>,
) -> (Vec<vlsync_store::segment::Mutation>, Vec<(Vec<u8>, Box<str>)>, Vec<String>) {
    import_rows(did, t.gen, t.rev, records, nodes)
}

/// [`rows`] for a generation and rev of the caller's (the relay's archival
/// bootstrap stages a fetched repo with it).
#[allow(clippy::type_complexity)]
pub fn import_rows(
    did: &str,
    gen: u64,
    rev: vlatproto::tid::Tid,
    records: Vec<ImportedRecord>,
    nodes: Vec<(Cid, Arc<[u8]>)>,
) -> (Vec<vlsync_store::segment::Mutation>, Vec<(Vec<u8>, Box<str>)>, Vec<String>) {
    use vlsync_store::segment::Mutation;
    let rev_t = rev;
    let rev = rev_t.0.to_be_bytes();
    let mut muts = Vec::with_capacity(records.len() * 3 + nodes.len());
    let mut links = Vec::new();
    let mut colls: Vec<String> = Vec::new();
    for (path, cid, bytes, mut blobs) in records {
        let coll = crate::worker::collection_of(&path);
        if colls.last().is_none_or(|c| c != coll) {
            colls.push(coll.to_string());
        }
        if crate::backlinks::linked(coll) {
            if let Some(l) = crate::backlinks::link(coll, &bytes) {
                links.push((l, path[coll.len() + 1..].into()));
            }
        }
        muts.push(Mutation {
            key: state::record_key(did, gen, &path).into(),
            val: Some(state::record_value(&cid, rev_t.0, &bytes)),
        });
        muts.push(Mutation { key: state::record_cid_key(did, gen, &cid, &path).into(), val: Some(Bytes::new()) });
        blobs.sort();
        blobs.dedup();
        for b in &blobs {
            muts.push(Mutation {
                key: state::blob_ref_key(did, gen, b, &path).into(),
                val: Some(Bytes::copy_from_slice(&rev)),
            });
        }
    }
    for (c, b) in nodes {
        muts.push(Mutation { key: state::mst_node_key(did, gen, &c).into(), val: Some(Bytes::copy_from_slice(&b)) });
    }
    (muts, links, colls)
}

/// Distinct blob CIDs among a generation's refs: `b/` keys sort by CID.
async fn distinct_blobs<R: slatedb::DbReadOps + Sync + ?Sized>(db: &R, did: &str, gen: u64) -> anyhow::Result<u64> {
    let prefix = state::blob_ref_prefix(did, gen);
    let mut it =
        vlsync_store::keys::BatchedScan::new(db.scan(prefix.clone()..vlsync_store::keys::prefix_end(&prefix)).await?);
    let (mut n, mut last) = (0u64, Vec::new());
    while let Some(kv) = it.next().await? {
        let cid = kv.key[prefix.len()..].split(|b| *b == 0).next().unwrap_or_default();
        if cid != &last[..] {
            n += 1;
            last = cid.to_vec();
        }
    }
    Ok(n)
}

/// A generation's collections: one seek per collection.
async fn collections<R: slatedb::DbReadOps + Sync + ?Sized>(
    db: &R,
    did: &str,
    gen: u64,
) -> anyhow::Result<Vec<String>> {
    let prefix = state::record_prefix(did, gen);
    let end = vlsync_store::keys::prefix_end(&prefix);
    let mut lo = prefix.clone();
    let mut out = Vec::new();
    loop {
        let mut it = db.scan(lo.clone()..end.clone()).await?;
        let Some(kv) = it.next().await? else { return Ok(out) };
        let path = String::from_utf8_lossy(&kv.key[prefix.len()..]).into_owned();
        let coll = crate::worker::collection_of(&path).to_string();
        lo = vlsync_store::keys::prefix_end(&[&prefix[..], coll.as_bytes(), b"/"].concat());
        out.push(coll);
    }
}

/// Links staged so far, as bloom filters sized to the repo: the first at
/// the reservation's estimate when the first link comes, then each 4x the
/// last once it holds its share (a body larger than estimated), up to 4 MiB
/// each (~6% false positives at 5M links; each costs one point read).
#[derive(Default)]
struct Bloom {
    layers: Vec<BloomLayer>,
    hasher: std::collections::hash_map::RandomState,
}

struct BloomLayer {
    bits: Vec<u64>,
    keys: usize,
}

impl BloomLayer {
    fn probes(&self, h: u64) -> [usize; 3] {
        let h2 = h.rotate_left(32) | 1;
        let bits = (self.bits.len() * 64) as u64;
        [0u64, 1, 2].map(|i| (h.wrapping_add(i.wrapping_mul(h2)) % bits) as usize)
    }

    fn full(&self) -> bool {
        self.bits.len() < super::import_budget::MAX_BLOOM_WORDS
            && self.keys * super::import_budget::BLOOM_BITS_PER_LINK as usize >= self.bits.len() * 64
    }
}

impl Bloom {
    fn hash(&self, k: &[u8]) -> u64 {
        use std::hash::BuildHasher;
        self.hasher.hash_one(k)
    }

    fn insert(&mut self, k: &[u8], words: usize) {
        let h = self.hash(k);
        let words = match self.layers.last() {
            None => words,
            Some(l) if l.full() => (l.bits.len() * 4).min(super::import_budget::MAX_BLOOM_WORDS),
            Some(_) => 0,
        };
        if words > 0 {
            self.layers.push(BloomLayer { bits: vec![0; words.max(1)], keys: 0 });
        }
        let l = self.layers.last_mut().expect("a layer");
        for b in l.probes(h) {
            l.bits[b / 64] |= 1 << (b % 64);
        }
        l.keys += 1;
    }

    fn maybe(&self, k: &[u8]) -> bool {
        let h = self.hash(k);
        self.layers.iter().any(|l| l.probes(h).iter().all(|b| l.bits[b / 64] & (1 << (b % 64)) != 0))
    }

    #[cfg(test)]
    fn words(&self) -> usize {
        self.layers.iter().map(|l| l.bits.len()).sum()
    }
}

fn spawn_sweep(app: Arc<App>, did: String, gen: u64) {
    tokio::spawn(async move {
        if let Err(e) = sweep_gen(&app, &did, gen).await {
            if !crashed(&e) {
                tracing::warn!(%did, gen, "repo generation sweep left to the sweeper: {}", e.message);
            }
        }
    });
}

/// Deletes a garbage generation's rows, then forgets it. Skipped when a
/// sweep of it already runs here.
pub async fn sweep_gen(app: &App, did: &str, gen: u64) -> XResult<()> {
    let Some(_s) = Sweeping::take(did, gen) else { return Ok(()) };
    let p = app.partition(did)?;
    for fam in state::GEN_FAMILIES {
        let prefix = state::gen_prefix(fam, did, gen);
        let end = vlsync_store::keys::prefix_end(&prefix);
        let mut lo = prefix.clone();
        loop {
            let mut it = vlsync_store::keys::BatchedScan::new(
                p.db.scan(lo.clone()..end.clone()).await.map_err(XrpcError::from_err)?,
            );
            let mut dels = Vec::new();
            while dels.len() < SWEEP_KEYS {
                let Some(kv) = it.next().await.map_err(XrpcError::from_err)? else { break };
                dels.push(vlsync_store::segment::Mutation { key: kv.key, val: None });
            }
            drop(it);
            let Some(last) = dels.last() else { break };
            lo = [&last.key[..], &[0]].concat();
            crash_at(did, "sweeping")?;
            step(app, did, ImportStep::Sweep { gen, muts: dels }).await?;
        }
    }
    step(app, did, ImportStep::Swept { gen }).await?;
    Ok(())
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Swept {
    /// Staged imports whose driver was gone.
    pub aborted: usize,
    pub generations: usize,
}

/// One pass over the `G/` rows of this node's shards: aborts staged
/// imports no driver here is running (crashed or moved away), and sweeps
/// every garbage generation.
pub async fn sweep_pending(app: &Arc<App>) -> Swept {
    let mut found = Vec::new();
    for p in app.partitions.owned() {
        let fam = state::IMPORT_FAMILY;
        let scan = async {
            let mut it = state::FamilyScan::new(p.db.as_ref(), fam, None, &Default::default()).await?;
            while let Some(kv) = it.next().await? {
                let did = String::from_utf8_lossy(&vlsync_store::keys::key_body(&kv.key)[fam.len()..]).into_owned();
                if let Ok(s) = state::ImportState::decode(&kv.value) {
                    found.push((did, s));
                }
            }
            Ok::<_, slatedb::Error>(())
        };
        if let Err(e) = scan.await {
            tracing::warn!(shard = %p.id, "staged imports: scan failed: {e}");
        }
    }
    let mut out = Swept::default();
    for (did, mut s) in found {
        if let Some(st) = s.staging.filter(|st| !driving(&did, st.nonce)) {
            match step(app, &did, ImportStep::Abort { nonce: st.nonce }).await {
                Ok(_) => {
                    out.aborted += 1;
                    s.garbage.push(st.gen);
                }
                Err(e) => tracing::warn!(%did, "aborting a stale import: {}", e.message),
            }
        }
        for g in s.garbage {
            match sweep_gen(app, &did, g).await {
                Ok(()) => out.generations += 1,
                Err(e) => tracing::warn!(%did, gen = g, "sweeping a repo generation: {}", e.message),
            }
        }
    }
    if out != Swept::default() {
        tracing::info!(aborted = out.aborted, generations = out.generations, "staged imports swept");
    }
    out
}

pub fn spawn_import_gc(app: Arc<App>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(SWEEP_INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            sweep_pending(&app).await;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sized from the estimate, grown in layers past it, never a false
    /// negative.
    #[test]
    fn bloom_grows_past_its_estimate() {
        let mut b = Bloom::default();
        let key = |i: u32| format!("at://did:plc:x/app.bsky.feed.post/{i}").into_bytes();
        assert!(!b.maybe(&key(0)));
        for i in 0..100_000 {
            b.insert(&key(i), 16);
        }
        assert!((0..100_000).all(|i| b.maybe(&key(i))));
        assert!(b.layers.len() > 1 && b.words() < 1 << 18, "{} layers, {} words", b.layers.len(), b.words());
        let fp = (100_000..110_000).filter(|i| b.maybe(&key(*i))).count();
        assert!(fp < 1000, "{fp} false positives in 10,000");
    }
}
