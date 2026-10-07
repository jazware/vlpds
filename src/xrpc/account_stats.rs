//! Totals for the operator dashboard: accounts by status, repos written
//! recently, and the SST disk cache's size. The account totals are kept by
//! the shards themselves (crate::totals) and summed over this node's shards
//! at scrape; the dashboard sums the nodes. A shard counts on the node that
//! has it open, so its totals move with it.

use super::*;
use crate::totals::{self, Totals};

/// The totals of the shards this node has open and whose totals are
/// loaded, as of the last entry each one's sequencer took, and how many
/// are still loading (left out: a shard counts whole or not at all).
pub fn totals_loading(app: &App) -> (Totals, usize) {
    sum_shards(app, true)
}

/// Scrapes skip the suffixes: only the handle domains page reads them.
fn sum_shards(app: &App, suffixes: bool) -> (Totals, usize) {
    let (mut t, mut loading) = (Totals::default(), 0);
    for s in app.log.sinks.all() {
        match s.totals.lock().sum() {
            Some(sum) if suffixes => t.merge(sum),
            Some(sum) => t.merge_counts(sum),
            None => loading += 1,
        }
    }
    (t, loading)
}

pub fn totals(app: &App) -> Totals {
    totals_loading(app).0
}

fn export(app: &App) {
    let (t, loading) = sum_shards(app, false);
    metrics::TOTALS_LOADING.set(loading as i64);
    for (i, s) in totals::STATUSES.iter().enumerate() {
        metrics::ACCOUNTS.with_label_values(&[s]).set(t.accounts[i]);
    }
    let today = totals::today();
    for (w, days) in totals::WINDOWS {
        metrics::REPOS_WRITTEN_WITHIN.with_label_values(&[w]).set(t.written_within(days, today));
    }
    metrics::REPOS_WRITTEN_WITHIN.with_label_values(&["all"]).set(t.repos());
    if let Some(cfg) = &app.node.disk_cache {
        let owned = app.partitions.owned().len().max(1) as u64;
        let capacity =
            cfg.node_bytes.unwrap_or_else(|| app.node.shard_disk_cache().map_or(0, |c| c.shard_bytes) * owned);
        metrics::DISK_CACHE_BYTES.with_label_values(&["capacity"]).set(capacity as i64);
        if let Some(used) = metrics::slatedb_gauge("slatedb.object_store_cache.cache_bytes") {
            metrics::DISK_CACHE_BYTES.with_label_values(&["used"]).set(used);
        }
    }
}

/// Exports at every scrape while the app lives.
pub fn export_account_totals(app: &Arc<App>) {
    let app = Arc::downgrade(app);
    metrics::on_render(move || match app.upgrade() {
        Some(a) => {
            export(&a);
            true
        }
        None => false,
    });
}

/// The same totals counted from scratch, suffixes too: every account and
/// head row of this node's shards, from a snapshot each. Costs a read of
/// every account; for checking the kept totals (tests, debugging), never on
/// a schedule.
/// Its `days` are uncut: compare windows, not the vector.
#[doc(hidden)]
pub async fn scan_totals(app: &App) -> anyhow::Result<Totals> {
    #[derive(serde::Deserialize)]
    struct Status<'a> {
        #[serde(borrow)]
        handle: std::borrow::Cow<'a, str>,
        #[serde(borrow, default)]
        status: Option<std::borrow::Cow<'a, str>>,
        #[serde(default)]
        email_confirmed: bool,
        #[serde(flatten)]
        extra: serde_json::Map<String, serde_json::Value>,
    }
    let layout = app.partitions.layout();
    let mut t = Totals::default();
    let mut days = std::collections::BTreeMap::<u32, i64>::new();
    let opts = slatedb::config::ScanOptions { read_ahead_bytes: 1 << 20, max_fetch_tasks: 2, ..Default::default() };
    for range in &layout.shards {
        let Some(p) = app.partitions.get(range.id) else { continue };
        let snap = p.db.snapshot()?;
        let lo = range.lo as u16;
        let in_range = |key: &[u8]| state::key_slot(key).is_some_and(|s| (s as u32) < range.hi);
        let mut accts = state::FamilyScan::new(
            snap.as_ref(),
            state::ACCOUNT_FAMILY,
            Some(state::slot_family(lo, state::ACCOUNT_FAMILY)),
            &opts,
        )
        .await?;
        while let Some(kv) = accts.next().await? {
            if !in_range(&kv.key) {
                break;
            }
            let Ok(a) = serde_json::from_slice::<Status>(&kv.value) else {
                t.accounts[totals::status_index(None) as usize] += 1;
                continue;
            };
            t.accounts[totals::status_index(a.status.as_deref()) as usize] += 1;
            let f = totals::flags(a.status.as_deref(), a.email_confirmed, &a.extra);
            t.unconfirmed += i64::from(f & totals::UNCONFIRMED != 0);
            t.no2fa += i64::from(f & totals::NO_2FA != 0);

            if a.status.is_none() {
                if let Some(s) = crate::handle_domains::handle_suffix(&a.handle) {
                    *t.suffixes.entry(s).or_default() += 1;
                }
            }
        }
        let mut heads = state::FamilyScan::new(
            snap.as_ref(),
            state::HEAD_FAMILY,
            Some(state::slot_family(lo, state::HEAD_FAMILY)),
            &opts,
        )
        .await?;
        while let Some(kv) = heads.next().await? {
            if !in_range(&kv.key) {
                break;
            }
            let head = state::Head::decode(&kv.value)?;
            *days.entry(totals::day_of(head.rev)).or_default() += 1;
        }
    }
    t.days = days.into_iter().collect();
    Ok(t)
}
