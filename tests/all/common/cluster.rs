//! In-process clusters: nodes sharing one object store form a real cluster
//! (leases, shard handoff, forwarding over peer mTLS).

use super::*;
use std::collections::HashSet;
use std::time::Instant;
use vlsync_store::slots::ShardId;

/// Cluster node `id` on `store` with `shards` shards and fast leases (1.5 s
/// TTL, 100 ms renewals, 200 ms skew); `f` adjusts the config afterwards.
pub async fn cluster_node(
    id: &str,
    store: Arc<dyn object_store::ObjectStore>,
    shards: u32,
    f: impl FnOnce(&mut vlpds::server::Config),
) -> TestServer {
    let id = id.to_string();
    TestServer::spawn_with(move |c| {
        c.memory_store = Some(store);
        c.shards = shards;
        c.cluster = Some(vlpds::cluster::ClusterConfig {
            node_id: id,
            addr: peer_url(c),
            shards,
            ttl: Duration::from_millis(1500),
            renew_every: Duration::from_millis(100),
            skew: Duration::from_millis(200),
            ..Default::default()
        });
        f(c);
    })
    .await
}

/// The cluster config of a [`cluster_node`] config, for `f` to adjust.
pub fn lease(c: &mut vlpds::server::Config) -> &mut vlpds::cluster::ClusterConfig {
    c.cluster.as_mut().expect("cluster node")
}

pub fn cluster(n: &TestServer) -> &vlpds::cluster::Cluster {
    n.app.cluster.as_ref().expect("cluster node")
}

/// How many shards `n` has open.
pub fn owned(n: &TestServer) -> usize {
    n.app.partitions.owned().len()
}

/// The shards `n` has open, sorted.
fn owned_shards(n: &TestServer) -> Vec<ShardId> {
    let mut v: Vec<ShardId> = n.app.partitions.owned().iter().map(|p| p.id).collect();
    v.sort();
    v
}

/// The node in `nodes` that has `key`'s shard open.
pub fn owner_of<'a>(nodes: &[&'a TestServer], key: &str) -> &'a TestServer {
    let p = nodes[0].app.partitions.shard_of(key);
    nodes.iter().find(|n| n.app.partitions.get(p).is_some()).copied().unwrap_or_else(|| panic!("nobody owns {p:?}"))
}

/// Waits until `nodes` own every shard of the layout exactly once, none
/// empty and none over ceil(shards / nodes) (the cluster's fair-share rule,
/// so 6/6/4 counts), every node's routing names those owners, and that has
/// held still for 500 ms. "Each node owns some" can still be mid-rebalance
/// (e.g. 6/1/1): the hand-backs that follow move accounts off their node
/// and answer 503 PartitionUnavailable while a shard moves.
pub async fn balanced(nodes: &[&TestServer]) {
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut stable_since: Option<(Vec<Vec<ShardId>>, Instant)> = None;
    loop {
        let shards: HashSet<ShardId> = nodes[0].app.partitions.layout().shards.iter().map(|r| r.id).collect();
        let owned: Vec<Vec<ShardId>> = nodes.iter().map(|n| owned_shards(n)).collect();
        let all: HashSet<ShardId> = owned.iter().flatten().copied().collect();
        let sizes: Vec<usize> = owned.iter().map(Vec::len).collect();
        let fair = owned.iter().all(|o| !o.is_empty() && o.len() <= shards.len().div_ceil(nodes.len()));
        let once = all == shards && sizes.iter().sum::<usize>() == shards.len();
        let routed = nodes.iter().all(|n| {
            owned.iter().zip(nodes).all(|(ss, o)| {
                let id = &cluster(o).cfg.node_id;
                ss.iter().all(|p| cluster(n).owner_of(*p).is_some_and(|(owner, _)| &owner == id))
            })
        });
        if fair && once && routed {
            match &stable_since {
                Some((prev, at)) if *prev == owned => {
                    if at.elapsed() >= Duration::from_millis(500) {
                        return;
                    }
                }
                _ => stable_since = Some((owned, Instant::now())),
            }
        } else {
            stable_since = None;
        }
        assert!(Instant::now() < deadline, "cluster never balanced: {sizes:?}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn in_a_minute_ms() -> u64 {
    (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() + 60_000) as u64
}

/// A live-looking lease for a node that isn't one: `id` at `addr`, valid a
/// minute from each renewal, level 1.
pub fn ghost_lease(id: &str, addr: String) -> vlpds::cluster::NodeLease {
    vlpds::cluster::NodeLease {
        node_id: id.into(),
        log_id: format!("{id}.0"),
        addr,
        writer: 254,
        expires_ms: in_a_minute_ms(),
        renewals: 0,
        next_ordinal: 0,
        draining: false,
        joined: false,
        follows: Default::default(),
        wm_cap: 0,
        rev: "ghost-rev".into(),
        min_level: 1,
        max_level: 1,
        seen_level: 1,
        pending_age_ms: None,
    }
}

/// Renews `lease` in `store` every 25 ms until aborted (a lease that goes
/// quiet is presumed dead within a couple of renew intervals).
pub fn spawn_ghost(
    store: Arc<dyn object_store::ObjectStore>,
    mut lease: vlpds::cluster::NodeLease,
) -> tokio::task::JoinHandle<()> {
    use object_store::ObjectStoreExt;
    tokio::spawn(async move {
        let path = object_store::path::Path::from(format!("vlpds/nodes/{}", lease.node_id));
        loop {
            lease.renewals += 1;
            if lease.expires_ms != 0 {
                lease.expires_ms = in_a_minute_ms();
            }
            store.put(&path, serde_json::to_vec(&lease).unwrap().into()).await.unwrap();
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
}
