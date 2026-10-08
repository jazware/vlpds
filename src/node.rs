//! The [`ShardHost`]: opens and closes the shards the cluster assigns to
//! this node, and follows every peer's log for the merged firehose.

use crate::cluster::{Cluster, ShardHost};
use crate::nodelog::{self, NodeLog, ShardSink, Span};
use crate::partition::{self, Partition};
use crate::partitions::PartitionTable;
use crate::remote::{self, Follower};
use crate::worker::{WorkerMsg, Workers};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use vlsync_firehose::firehose::Firehose;
use vlsync_firehose::log::LogBatch;
use vlsync_store::slots::ShardId;
use vlsync_store::store::Store;

const SEQ_FLOOR_MAX_WAIT: Duration = Duration::from_secs(30);
/// How long newly opened shards wait for `partition::warm` before serving,
/// counted from the start of the open. Writes for them meanwhile are
/// answered `ShardMoved` and resent by their entry node.
const WARM_MAX: Duration = Duration::from_secs(5);
/// How long a handoff's recipient warms before answering (the sender waits
/// a little longer for the answer, then hands over anyway).
const HANDOFF_WARM_MAX: Duration = Duration::from_secs(8);
const HANDOFF_WAIT: Duration = Duration::from_secs(10);
const HANDOFF_WARM_REPOS: usize = 128;

pub struct Node {
    pub cluster: Arc<Cluster>,
    pub log: Arc<NodeLog>,
    pub store: Store,
    pub state_store: Store,
    pub table: Arc<PartitionTable>,
    pub firehose: Arc<Firehose>,
    pub merger_tx: mpsc::UnboundedSender<LogBatch>,
    pub workers: Workers,
    pub disk_cache: Option<partition::DiskCacheConfig>,
    pub internal_token: String,
    pub http: crate::http::PeerClient,
    /// 0 = off.
    pub recent_cap: usize,
    pub(crate) followers: Mutex<HashMap<String, Follower>>,
    /// `--spaces`: its heads leave with a shard, its outbox resumes with one.
    pub spaces: Option<Arc<crate::space::Spaces>>,
}

/// Exports `vlpds_sst_meta_bytes` at every render: the encoded filters and
/// indexes of every SST in the shards this node owns.
pub fn export_sst_meta_bytes(table: &Arc<PartitionTable>) {
    let weak = Arc::downgrade(table);
    vlsync_store::metrics::on_render(move || {
        let Some(table) = weak.upgrade() else { return false };
        let owned = table.owned();
        let (filter, index) = crate::memory::sst_meta_bytes(owned.iter().map(|p| &*p.db));
        crate::metrics::SST_META_BYTES.with_label_values(&["filter"]).set(filter as i64);
        crate::metrics::SST_META_BYTES.with_label_values(&["index"]).set(index as i64);
        true
    });
}

impl Node {
    /// Retires followers of dead logs once drained to their fence.
    pub fn sync_followers(&self) {
        let peers = self.cluster.peers();
        let mut f = self.followers.lock();
        for p in &peers {
            if p.log_id == self.cluster.log_id || f.contains_key(&p.log_id) {
                continue;
            }
            let cluster = self.cluster.clone();
            let log_id = p.log_id.clone();
            let addr = Arc::new(move || cluster.peers().into_iter().find(|l| l.log_id == log_id).map(|l| l.addr));
            let tls = self.http.ws_connector(&p.node_id);
            let fl = remote::follow_log(
                &p.log_id,
                &self.firehose,
                self.store.clone(),
                addr,
                self.internal_token.clone(),
                self.merger_tx.clone(),
                tls,
            );
            tracing::info!(log_id = %p.log_id, node = %p.node_id, "following peer log");
            f.insert(p.log_id.clone(), fl);
        }
        let done: Vec<String> =
            f.iter().filter(|(_, fl)| fl.done.load(Ordering::Acquire)).map(|(k, _)| k.clone()).collect();
        for log_id in done {
            self.firehose.set_source(&log_id, None);
            f.remove(&log_id);
            tracing::info!(%log_id, "dead peer log drained to its fence");
        }
    }

    /// The node budget split over every shard of the layout plus a
    /// split/merge's children, so the caps fit the budget even if this node
    /// comes to hold them all.
    pub fn shard_disk_cache(&self) -> Option<partition::DiskCache> {
        let c = self.disk_cache.as_ref()?;
        let layout = self.cluster.layout();
        let shards = layout.shards.len() + layout.op.as_ref().map_or(0, |op| op.children.len());
        Some(c.for_shards(shards))
    }

    /// Tests only: drops every shard from routing and the workers' caches
    /// without closing anything, as a crash would (see `Cluster::halt`).
    pub fn halt(&self) {
        self.cluster.halt();
        self.log.closed.store(true, Ordering::Release);
        for p in self.table.owned() {
            self.table.set(p.id, None);
            if let Some(s) = &self.spaces {
                s.heads.drop_shard(p.id);
            }
            for w in self.workers.senders.iter() {
                let (tx, _rx) = tokio::sync::oneshot::channel();
                let _ = w.send(WorkerMsg::DropPartition(p.id, tx));
            }
        }
    }

    pub async fn close(&self, shard: ShardId) -> anyhow::Result<()> {
        self.close_many(vec![shard]).await.pop().map_or(Ok(()), |(_, r)| r)
    }

    /// Before a peer hands us `shards`: reads them through read-only views
    /// into the block cache their `Db`s will share, every SST's filters and
    /// index, the newest L0s whole, then the blocks of the repos the peer
    /// wrote most recently (newest first, across shards), until
    /// [`HANDOFF_WARM_MAX`]. The peer serves them meanwhile.
    pub async fn warm_handoff(&self, shards: Vec<crate::xrpc::internal::PrewarmShard>) {
        use futures::StreamExt;
        let started = Instant::now();
        let deadline = tokio::time::Instant::now() + HANDOFF_WARM_MAX;
        let opened: Vec<(Arc<slatedb::DbReader>, Vec<String>)> = futures::stream::iter(shards)
            .map(|s| async move {
                match partition::open_reader(&self.state_store, s.shard).await {
                    Ok(r) => Some((Arc::new(r), s.recent)),
                    Err(e) => {
                        tracing::warn!(shard = s.shard.0, "handoff prewarm: open failed: {e:#}");
                        None
                    }
                }
            })
            .buffer_unordered(32)
            .filter_map(std::future::ready)
            .collect()
            .await;
        let readers: Vec<Arc<slatedb::DbReader>> = opened.iter().map(|(r, _)| r.clone()).collect();
        let _ = tokio::time::timeout_at(deadline, partition::warm(&readers)).await;
        let mut order = Vec::new();
        for k in 0..opened.iter().map(|(_, v)| v.len()).max().unwrap_or(0) {
            order.extend(opened.iter().filter_map(|(r, v)| v.get(k).map(|d| (r.clone(), d.clone()))));
        }
        let n = order.len();
        let warmed = futures::stream::iter(order)
            .map(|(r, did)| async move { crate::worker::warm_repo(&*r, &did).await.is_ok() })
            .buffer_unordered(HANDOFF_WARM_REPOS)
            .take_until(tokio::time::sleep_until(deadline))
            .filter(|ok| std::future::ready(*ok))
            .count()
            .await;
        for r in readers {
            if let Err(e) = r.close().await {
                tracing::debug!("handoff prewarm: reader close: {e}");
            }
        }
        tracing::info!(
            shards = opened.len(),
            recent = n,
            warmed,
            elapsed_ms = started.elapsed().as_millis() as u64,
            "handoff prewarmed"
        );
    }

    async fn purge_worker_caches(&self, shards: &[ShardId]) {
        if let Some(s) = &self.spaces {
            for &shard in shards {
                s.heads.drop_shard(shard);
            }
        }
        let mut acks = Vec::new();
        for w in self.workers.senders.iter() {
            for &shard in shards {
                let (tx, rx) = tokio::sync::oneshot::channel();
                let _ = w.send(WorkerMsg::DropPartition(shard, tx));
                acks.push(rx);
            }
        }
        for a in acks {
            let _ = a.await;
        }
    }
}

#[async_trait::async_trait]
impl ShardHost for Node {
    fn next_ordinal(&self) -> u64 {
        self.log.next_ordinal()
    }

    fn durable_end(&self) -> u64 {
        self.log.durable_ordinal.load(Ordering::Acquire).wrapping_add(1)
    }

    async fn open_many(&self, shards: Vec<(ShardId, u64, Vec<Span>)>) -> Vec<(ShardId, anyhow::Result<()>)> {
        use futures::StreamExt;
        if shards.is_empty() {
            return Vec::new();
        }
        let started = Instant::now();
        let n = shards.len();
        let cache = self.shard_disk_cache();
        let cache = cache.as_ref();
        let opened: Vec<(ShardId, u64, Vec<Span>, anyhow::Result<Arc<slatedb::Db>>)> = futures::stream::iter(shards)
            .map(|(s, e, h)| async move {
                let db = partition::open_db(&self.state_store, s, cache).await.map(Arc::new);
                (s, e, h, db)
            })
            .buffer_unordered(32)
            .collect()
            .await;
        let mut results = Vec::with_capacity(n);
        let mut ready = Vec::new();
        for (s, e, h, db) in opened {
            match db {
                Ok(db) => ready.push((s, e, h, db)),
                Err(e) => results.push((s, Err(e))),
            }
        }
        let opened_ms = started.elapsed().as_millis() as u64;
        let warm = {
            let dbs: Vec<Arc<slatedb::Db>> = ready.iter().map(|r| r.3.clone()).collect();
            tokio::spawn(async move { partition::warm(&dbs).await })
        };
        let plan: Vec<(ShardId, &slatedb::Db, &[Span])> =
            ready.iter().map(|(s, _, h, db)| (*s, db.as_ref(), h.as_slice())).collect();
        let replay_started = Instant::now();
        let replayed = match nodelog::replay_many(&self.store, &plan).await {
            Ok(r) => r,
            Err(e) => {
                let msg = format!("{e:#}");
                for (s, ..) in ready {
                    results.push((s, Err(anyhow::anyhow!("replay failed: {msg}"))));
                }
                crate::metrics::SHARDS_OPENED.with_label_values(&["error"]).inc_by(results.len() as u64);
                return results;
            }
        };
        if replayed > 0 {
            crate::metrics::REPLAYED_SEGMENTS.inc_by(replayed);
            crate::metrics::REPLAY_SECONDS.observe(replay_started.elapsed().as_secs_f64());
        }
        let replayed_ms = started.elapsed().as_millis() as u64;
        let phase = |name: &str, t: Instant| {
            crate::metrics::SHARD_OPEN_PHASE_SECONDS.with_label_values(&[name]).observe(t.elapsed().as_secs_f64())
        };
        crate::metrics::SHARD_OPEN_PHASE_SECONDS.with_label_values(&["open"]).observe(opened_ms as f64 / 1000.0);
        phase("replay", replay_started);
        // make replayed state durable before serving, and before the totals
        // load reads it
        let flush_started = Instant::now();
        let flushed: Vec<(ShardId, u64, Arc<slatedb::Db>, anyhow::Result<()>)> = futures::stream::iter(ready)
            .map(|(s, e, _, db)| async move {
                let r = match replayed > 0 {
                    true => db
                        .flush_with_options(slatedb::config::FlushOptions {
                            flush_type: slatedb::config::FlushType::MemTable,
                        })
                        .await
                        .map_err(Into::into),
                    false => Ok(()),
                };
                (s, e, db, r)
            })
            .buffer_unordered(32)
            .collect()
            .await;
        phase("flush", flush_started);
        // past the cap the warm-up goes on behind the first requests
        let warm_wait = Instant::now();
        let _ = tokio::time::timeout_at((started + WARM_MAX).into(), warm).await;
        phase("warm_wait", warm_wait);
        let mut preload = Vec::new();
        for (shard, epoch, db, r) in flushed {
            if let Err(e) = r {
                results.push((shard, Err(e)));
                continue;
            }
            let recent = Arc::new(partition::RecentRepos::new(self.recent_cap));
            preload.push((shard, db.clone(), recent.clone()));
            let apply_lock = Arc::new(tokio::sync::RwLock::new(()));
            let sink = Arc::new(ShardSink {
                id: shard,
                epoch,
                db: db.clone(),
                apply_lock: apply_lock.clone(),
                applied: Default::default(),
                recent: recent.clone(),
                barrier: Default::default(),
                totals: Mutex::new(crate::totals::ShardTotals::unloaded()),
            });
            crate::totals::spawn_load(&sink, &self.cluster.cfg.node_id, self.log.tx.clone());
            self.log.sinks.insert(sink);
            self.table.set(
                shard,
                Some(Arc::new(Partition {
                    id: shard,
                    epoch,
                    db,
                    apply_lock,
                    tx: self.log.tx.clone(),
                    wm: self.log.wm.clone(),
                    log: self.log.clone(),
                    recent,
                })),
            );
            crate::metrics::LEASE_EVENTS.with_label_values(&["opened"]).inc();
            results.push((shard, Ok(())));
        }
        crate::metrics::OWNED_PARTITIONS.set(self.table.owned().len() as i64);
        let ok = results.iter().filter(|(_, r)| r.is_ok()).count() as u64;
        crate::metrics::SHARDS_OPENED.with_label_values(&["ok"]).inc_by(ok);
        crate::metrics::SHARDS_OPENED.with_label_values(&["error"]).inc_by(results.len() as u64 - ok);
        crate::metrics::SHARD_OPEN_SECONDS
            .with_label_values(&[if replayed > 0 { "replay" } else { "clean" }])
            .observe(started.elapsed().as_secs_f64());
        tracing::info!(
            shards = n,
            segments_replayed = replayed,
            opened_ms,
            replayed_ms,
            elapsed_ms = started.elapsed().as_millis() as u64,
            "shards opened"
        );
        if let Some(s) = &self.spaces {
            let shards = preload.iter().map(|(shard, db, _)| (*shard, db.clone())).collect();
            s.clone().spawn_outbox_rescan(Arc::downgrade(&self.table), shards, false);
        }
        crate::worker::spawn_preload(&self.workers, preload);
        results
    }

    fn seq_high(&self) -> i64 {
        self.log.wm.get()
    }

    async fn wait_seq_floor(&self, seq: i64) {
        // Commit-wait: otherwise a repo's commits could sort out of order on
        // the firehose. Bounded, so a wildly wrong clock costs order, not
        // availability.
        let started = Instant::now();
        if !crate::cluster::wait_clock_past(seq, SEQ_FLOOR_MAX_WAIT).await {
            tracing::error!(
                seq,
                "previous owner's clock is more than {SEQ_FLOOR_MAX_WAIT:?} ahead of ours: serving anyway"
            );
            return;
        }
        if started.elapsed() > Duration::from_millis(1) {
            tracing::warn!(
                waited_ms = started.elapsed().as_millis() as u64,
                "waited for our clock to pass the previous owner's last seq"
            );
        }
    }

    async fn close_many(&self, shards: Vec<ShardId>) -> Vec<(ShardId, anyhow::Result<()>)> {
        use futures::StreamExt;
        let started = Instant::now();
        let mut results = Vec::with_capacity(shards.len());
        // Keyed off the sink, not the routing table: a shard whose earlier
        // close failed half-way (already unrouted) is still drained.
        let mut sinks = Vec::new();
        for s in shards {
            match self.log.sinks.get(s) {
                Some(k) => sinks.push(k),
                None => results.push((s, Ok(()))),
            }
        }
        if sinks.is_empty() {
            return results;
        }
        let ids: Vec<ShardId> = sinks.iter().map(|k| k.id).collect();
        for &s in &ids {
            self.table.set(s, None);
        }
        // no worker may keep building commits for them (a load in flight is
        // cached only while its Partition is still the routed one)
        self.purge_worker_caches(&ids).await;
        // Once a shard's barrier is durable, every earlier entry for it is
        // durable and applied (the log is FIFO), and the log refuses any
        // later one (it would land past the span end we publish). Queued back
        // to back, they share one segment.
        let mut acks = Vec::with_capacity(sinks.len());
        for k in &sinks {
            let (tx, rx) = tokio::sync::oneshot::channel();
            let sent = self
                .log
                .tx
                .send(k.barrier_entry(Box::new(move |r| {
                    let _ = tx.send(r);
                })))
                .await;
            acks.push(sent.map(|_| rx));
        }
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        let mut drained = Vec::with_capacity(sinks.len());
        for (k, ack) in sinks.into_iter().zip(acks) {
            let r: anyhow::Result<()> = async {
                let rx = ack.map_err(|_| anyhow::anyhow!("node log gone"))?;
                tokio::time::timeout_at(deadline, rx)
                    .await
                    .map_err(|_| anyhow::anyhow!("barrier not durable within 30 s"))??
                    .map_err(|e| anyhow::anyhow!("{e}"))
            }
            .await;
            match r {
                Ok(()) => drained.push(k),
                Err(e) => results.push((k.id, Err(e))),
            }
        }
        let drained_ms = started.elapsed().as_millis() as u64;
        // checkpoint so the successor replays nothing
        let ord = self.log.durable_ordinal.load(Ordering::Acquire);
        let closed: Vec<(ShardId, anyhow::Result<()>)> = futures::stream::iter(drained)
            .map(|k| async move {
                let r = async {
                    {
                        let _g = k.apply_lock.write().await;
                        let mut wb = slatedb::WriteBatch::new();
                        wb.put(nodelog::META_APPLIED, nodelog::encode_marker(&self.log.log_id, ord));
                        if let Some(r) = k.recent.take_dirty() {
                            wb.put(nodelog::META_RECENT, r);
                        }
                        k.db.write(wb).await?;
                    }
                    // the shard's replay floor holds until the close flushed
                    self.log.sinks.remove(k.id);
                    k.db.close().await?;
                    self.log.sinks.retire(k.id);
                    crate::metrics::LEASE_EVENTS.with_label_values(&["closed"]).inc();
                    anyhow::Ok(())
                }
                .await;
                (k.id, r)
            })
            .buffer_unordered(32)
            .collect()
            .await;
        results.extend(closed);
        crate::metrics::OWNED_PARTITIONS.set(self.table.owned().len() as i64);
        tracing::info!(
            shards = results.len(),
            drained_ms,
            elapsed_ms = started.elapsed().as_millis() as u64,
            "shards closed"
        );
        results
    }

    async fn quiesce(&self) -> bool {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !self.log.wm.idle() {
            if Instant::now() > deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        true
    }

    fn lost(&self) {
        if self.cluster.halted() {
            return; // an in-process test node "crashed": already inert
        }
        crate::metrics::LEASE_EVENTS.with_label_values(&["lost"]).inc();
        tracing::error!("node lease lost unexpectedly: fail-stop");
        vlsync_store::lifecycle::fail_stop(5, "lease_lost");
    }

    fn on_membership(&self) {
        self.sync_followers();
    }

    async fn nudge(&self, nudges: Vec<(String, Vec<crate::cluster::Handoff>)>) {
        crate::xrpc::internal::nudge_peers(&self.http, &self.internal_token, nudges).await;
    }

    async fn prewarm(&self, plan: Vec<(String, Vec<ShardId>)>) {
        let plan = plan
            .into_iter()
            .map(|(addr, shards)| {
                let shards = shards
                    .into_iter()
                    .map(|s| {
                        (
                            s,
                            self.table
                                .get(s)
                                .map(|p| p.recent.snapshot().iter().map(|d| d.to_string()).collect())
                                .unwrap_or_default(),
                        )
                    })
                    .collect();
                (addr, crate::xrpc::internal::prewarm_request(shards))
            })
            .collect();
        crate::xrpc::internal::prewarm_peers(&self.http, &self.internal_token, plan, HANDOFF_WAIT).await;
    }

    async fn greet(&self, peers: Vec<crate::cluster::NodeLease>) -> Vec<Option<i64>> {
        let addrs = peers.into_iter().map(|l| l.addr).collect();
        crate::xrpc::internal::hello_peers(
            &self.http,
            &self.internal_token,
            &self.cluster.cfg.node_id,
            self.cluster.cfg.levels,
            addrs,
        )
        .await
    }

    fn leaving(&self) {
        self.firehose.freeze();
        // peers drain our fenced log from S3 instead of trusting our frozen
        // watermark for as long as this process keeps serving
        self.log.closed.store(true, Ordering::Release);
    }

    fn follow_floors(&self) -> std::collections::BTreeMap<String, i64> {
        self.followers.lock().iter().map(|(log_id, f)| (log_id.clone(), f.floor)).collect()
    }

    async fn refused(&self, addr: &str) -> bool {
        let Some(authority) = reqwest::Url::parse(addr)
            .ok()
            .and_then(|u| Some(format!("{}:{}", u.host_str()?, u.port_or_known_default()?)))
        else {
            return false;
        };
        match tokio::time::timeout(Duration::from_millis(500), tokio::net::TcpStream::connect(&authority)).await {
            Ok(Err(e)) => e.kind() == std::io::ErrorKind::ConnectionRefused,
            _ => false,
        }
    }

    fn on_layout(&self, layout: Arc<vlsync_store::slots::Layout>) {
        self.table.set_layout(layout);
    }

    async fn clone_shards(
        &self,
        layout: &vlsync_store::slots::Layout,
        op: &vlsync_store::slots::Reshard,
    ) -> anyhow::Result<()> {
        use futures::StreamExt;
        let started = Instant::now();
        let parents: Vec<vlsync_store::slots::ShardRange> = op
            .parents
            .iter()
            .map(|p| layout.range_of(*p).ok_or_else(|| anyhow::anyhow!("parent {p} not in layout v{}", layout.version)))
            .collect::<anyhow::Result<_>>()?;
        // each child takes the slots it shares with every parent it overlaps
        let plans: Vec<(ShardId, Vec<(ShardId, u32, u32)>)> = op
            .children
            .iter()
            .map(|c| {
                (
                    c.id,
                    parents
                        .iter()
                        .filter(|p| p.lo < c.hi && c.lo < p.hi)
                        .map(|p| (p.id, p.lo.max(c.lo), p.hi.min(c.hi)))
                        .collect(),
                )
            })
            .collect();
        let results: Vec<anyhow::Result<()>> = futures::stream::iter(plans)
            .map(|(c, srcs)| async move {
                partition::clone_db(&self.state_store, c, &srcs)
                    .await
                    .map_err(|e| e.context(format!("cloning shard {c} from {srcs:?}")))
            })
            .buffer_unordered(4)
            .collect()
            .await;
        results.into_iter().collect::<anyhow::Result<Vec<()>>>()?;
        tracing::info!(op = op.id, children = ?op.children.iter().map(|c| c.id).collect::<Vec<_>>(), elapsed_ms = started.elapsed().as_millis() as u64, "cloned reshard children");
        Ok(())
    }

    fn shard_stats(&self) -> Vec<(ShardId, u64, u64)> {
        self.table
            .owned()
            .iter()
            .map(|p| {
                let m = p.db.manifest();
                let bytes: u64 = m.l0().iter().map(|t| t.estimate_size()).sum::<u64>()
                    + m.compacted().iter().map(|r| r.estimate_size()).sum::<u64>();
                (p.id, bytes, self.log.sinks.applied_entries(p.id))
            })
            .collect()
    }
}
