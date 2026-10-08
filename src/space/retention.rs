//! Oplog retention (`--space-oplog-retention`). The spec lets a host drop
//! oplog ops: a syncer whose `since` is older than what's kept gets the ops
//! from the window's start, its replayed hash doesn't match the commit, and
//! it falls back to getRepo (the reference keeps every op; DESIGN.md
//! "Spaces" divergences).
//!
//! Each node sweeps the shards it owns now and then, never per write: per
//! space repo (`sH`) one range scan over its ops older than the window, and
//! their deletes in frameless entries of a bounded size. A repo created
//! inside the window has nothing to prune and isn't scanned.

use crate::state::{self, SpaceId};
use crate::xrpc::App;
use std::sync::Arc;
use std::time::Duration;
use vlatproto::tid::Tid;

pub const DEFAULT_RETENTION: Duration = Duration::from_secs(7 * 24 * 3600);
/// Between sweeps: a sweep reads every space head of the node's shards.
const EVERY: Duration = Duration::from_secs(6 * 3600);
/// Deletes per entry.
const BATCH: usize = 500;

/// Starts the node's sweeps (with `--spaces`): the first a few minutes
/// after start, so a node restarted more often than [`EVERY`] still sweeps.
/// Without a retention window a sweep only counts the space repos
/// (`vlpds_space_repos`).
pub fn start(app: &Arc<App>) {
    let Some(sp) = app.spaces.as_ref() else { return };
    let window = sp.limits.oplog_retention;
    let weak = Arc::downgrade(app);
    tokio::spawn(async move {
        let mut wait = Duration::from_secs(60).mul_f64(1.0 + 9.0 * rand::random::<f64>());
        loop {
            tokio::time::sleep(wait).await;
            let Some(app) = weak.upgrade() else { return };
            let cutoff = window.map_or(0, |w| vlatproto::tid::now_micros().saturating_sub(w.as_micros() as u64));
            match prune_before(&app, cutoff).await {
                Ok(0) => {}
                Ok(n) => tracing::info!(ops = n, "space oplog retention pruned ops"),
                Err(e) => tracing::warn!("space oplog retention sweep failed: {e:#}"),
            }
            wait = EVERY.mul_f64(0.9 + 0.2 * rand::random::<f64>());
        }
    });
}

/// Deletes the oplog ops older than `cutoff` (unix µs) of every space repo
/// in the shards this node owns. Returns how many went.
pub async fn prune_before(app: &App, cutoff: u64) -> anyhow::Result<usize> {
    let below = Tid::from_parts(cutoff, 0).0.to_be_bytes();
    let (mut pruned, mut repos_seen) = (0, 0);
    for p in app.partitions.owned() {
        let opts = slatedb::config::ScanOptions::default();
        let mut heads = state::FamilyScan::new(&*p.db, state::SPACE_HEAD_FAMILY, None, &opts).await?;
        let mut repos: Vec<(String, SpaceId)> = Vec::new();
        while let Some(kv) = heads.next().await? {
            let Some((did, sid)) = super::rows::did_sid(&kv.key) else { continue };
            repos_seen += 1;
            if super::rows::HeadRow::decode(&kv.value)?.created < cutoff {
                repos.push((did.to_string(), sid));
            }
        }
        drop(heads);
        let mut muts = Vec::new();
        for (did, sid) in repos {
            let prefix = state::space_prefix(state::SPACE_OPLOG_FAMILY, &did, &sid);
            let hi = [&prefix[..], &below].concat();
            let mut it = vlsync_store::keys::BatchedScan::new(p.db.scan_with_options(prefix..hi, &opts).await?);
            while let Some(kv) = it.next().await? {
                muts.push(vlsync_store::segment::Mutation { key: kv.key, val: None });
                if muts.len() == BATCH {
                    pruned += flush(&p, &mut muts).await?;
                }
            }
        }
        pruned += flush(&p, &mut muts).await?;
    }
    crate::metrics::space_repos(repos_seen);
    Ok(pruned)
}

async fn flush(
    p: &crate::partition::Partition,
    muts: &mut Vec<vlsync_store::segment::Mutation>,
) -> anyhow::Result<usize> {
    if muts.is_empty() {
        return Ok(0);
    }
    let n = muts.len();
    crate::xrpc::write_private_local(p, std::mem::take(muts)).await.map_err(|e| anyhow::anyhow!("{}", e.message))?;
    crate::metrics::space_oplog_pruned(n);
    Ok(n)
}
