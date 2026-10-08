//! The cluster's mail budget (`mail-cluster-day`): one counter for the
//! whole cluster in the bucket object `{prefix}/budget/mail.json`, spent
//! with a compare-and-swap by whichever node mails. No owner or leader
//! holds it, so it keeps counting through a node's loss or restart and
//! through shard moves (an in-memory counter on one owner would start over
//! at each). The price is one store write per account mail, plus a read
//! when another node wrote since: nothing at mail's rate.
//!
//! Windows are aligned to the epoch (a day is the UTC day), so nodes agree
//! on when one ends without talking. Only mail that goes out is counted.
//!
//! A store error lets the mail through (counted, logged): the provider
//! refusing mail past its quota is no worse than refusing all mail while
//! the store is unreachable, and `mail-node-hour` still bounds each node.

use object_store::{GetOptions, ObjectStore, PutMode, PutOptions, PutPayload};
use prometheus::{IntCounter, IntGaugeVec};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use vlsync_store::store::Store;

const STORE_TIMEOUT: Duration = Duration::from_secs(5);
const CAS_RETRIES: usize = 8;
/// Keeps the gauge and the console current on nodes that aren't mailing.
pub const REFRESH_EVERY: Duration = Duration::from_secs(60);

pub(crate) static REMAINING: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    prometheus::register_int_gauge_vec!(
        "vlpds_mail_budget_remaining",
        "Account mails the cluster may still send in the current window of its mail budget (window=day: mail-cluster-day), as this node last read it",
        &["window"]
    )
    .unwrap()
});
pub(crate) static LIMIT: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    prometheus::register_int_gauge_vec!(
        "vlpds_mail_budget_limit",
        "The cluster's mail budget per window (window=day: mail-cluster-day)",
        &["window"]
    )
    .unwrap()
});
pub(crate) static ERRORS: LazyLock<IntCounter> = LazyLock::new(|| {
    prometheus::register_int_counter!(
        "vlpds_mail_budget_errors_total",
        "Account mails sent without spending the cluster mail budget because its bucket object couldn't be read or written"
    )
    .unwrap()
});

pub(crate) fn set_gauges(limit: u32, used: u32) {
    LIMIT.with_label_values(&["day"]).set(limit as i64);
    REMAINING.with_label_values(&["day"]).set(limit.saturating_sub(used) as i64);
}

pub fn path(store: &Store) -> object_store::path::Path {
    object_store::path::Path::from(format!("{}/budget/mail.json", store.prefix))
}

pub fn window_start(window_ms: u64, now_ms: u64) -> u64 {
    let w = window_ms.max(1);
    now_ms / w * w
}

/// The stored object.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct State {
    pub window_start_ms: u64,
    pub window_ms: u64,
    pub used: u32,
}

impl State {
    /// A new window length starts afresh, as for the per-node counters.
    pub fn used_in(&self, window_ms: u64, now_ms: u64) -> u32 {
        if self.window_ms == window_ms && self.window_start_ms == window_start(window_ms, now_ms) {
            self.used
        } else {
            0
        }
    }
}

struct Seen {
    state: State,
    /// None: no object.
    etag: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Spend {
    Spent(u32),
    /// Nothing written.
    Exhausted(u32),
}

impl Spend {
    pub fn used(self) -> u32 {
        match self {
            Spend::Spent(u) | Spend::Exhausted(u) => u,
        }
    }
}

#[derive(Default)]
pub struct Budget {
    /// The object as last read or written. The lock serializes this node's
    /// spends, which would otherwise only conflict with each other.
    io: tokio::sync::Mutex<Option<Seen>>,
    last: parking_lot::Mutex<Option<State>>,
}

async fn bounded<T>(f: impl std::future::Future<Output = object_store::Result<T>>) -> object_store::Result<T> {
    match tokio::time::timeout(STORE_TIMEOUT, f).await {
        Ok(r) => r,
        Err(_) => {
            Err(object_store::Error::Generic { store: "mail-budget", source: "mail budget call timed out".into() })
        }
    }
}

async fn fetch(raw: &Arc<dyn ObjectStore>, path: &object_store::path::Path) -> object_store::Result<Seen> {
    let got = bounded(async {
        let r = raw.get_opts(path, GetOptions::default()).await?;
        let e = r.meta.e_tag.clone();
        Ok((r.bytes().await?, e))
    })
    .await;
    match got {
        // unreadable: overwritten by the next spend
        Ok((b, etag)) => Ok(Seen { state: serde_json::from_slice(&b).unwrap_or_default(), etag }),
        Err(object_store::Error::NotFound { .. }) => Ok(Seen { state: State::default(), etag: None }),
        Err(e) => Err(e),
    }
}

/// S3 answers an If-Match PUT of a deleted key 404.
fn lost_race(e: &object_store::Error) -> bool {
    crate::cluster::is_conflict(e) || matches!(e, object_store::Error::NotFound { .. })
}

impl Budget {
    pub fn last(&self) -> Option<State> {
        *self.last.lock()
    }

    fn keep(&self, io: &mut Option<Seen>, seen: Seen) {
        *self.last.lock() = Some(seen.state);
        *io = Some(seen);
    }

    /// Spends one mail of `limit` per `window_ms`.
    pub async fn spend(&self, store: &Store, limit: u32, window_ms: u64, now_ms: u64) -> object_store::Result<Spend> {
        let path = path(store);
        let mut io = self.io.lock().await;
        for _ in 0..CAS_RETRIES {
            let (seen, fresh) = match io.take() {
                Some(s) => (s, false),
                None => (fetch(&store.raw, &path).await?, true),
            };
            let used = seen.state.used_in(window_ms, now_ms);
            if used >= limit {
                // a cached copy only undercounts, unless an operator reset
                // the object; a refusal is worth a read to be sure
                if !fresh {
                    continue;
                }
                self.keep(&mut io, seen);
                return Ok(Spend::Exhausted(used));
            }
            let next = State { window_start_ms: window_start(window_ms, now_ms), window_ms, used: used + 1 };
            let mode = match seen.etag {
                Some(e) => crate::cluster::if_match(Some(e)),
                None => PutMode::Create,
            };
            let body = PutPayload::from(serde_json::to_vec(&next).expect("serializable"));
            match bounded(store.raw.put_opts(&path, body, PutOptions { mode, ..Default::default() })).await {
                Ok(r) => {
                    *self.last.lock() = Some(next);
                    // without an ETag the next spend reads first
                    if let Some(etag) = r.e_tag {
                        *io = Some(Seen { state: next, etag: Some(etag) });
                    }
                    return Ok(Spend::Spent(next.used));
                }
                Err(e) if lost_race(&e) => continue,
                Err(e) => return Err(e),
            }
        }
        Err(object_store::Error::Generic {
            store: "mail-budget",
            source: format!("mail budget still contended after {CAS_RETRIES} tries").into(),
        })
    }

    /// Re-reads the object unless a spend is under way (it reads or writes
    /// it anyway).
    pub async fn refresh(&self, store: &Store) -> object_store::Result<()> {
        let Ok(mut io) = self.io.try_lock() else { return Ok(()) };
        let seen = fetch(&store.raw, &path(store)).await?;
        self.keep(&mut io, seen);
        Ok(())
    }
}

/// Once per limiter; stops when it is dropped. Idle under
/// `--no-rate-limits`, where nothing is counted.
pub fn spawn_refresher(limiter: &Arc<super::Limiter>, store: Store) {
    if !limiter.enabled_by_flag || limiter.mail_budget_started.swap(true, std::sync::atomic::Ordering::AcqRel) {
        return;
    }
    let weak = Arc::downgrade(limiter);
    tokio::spawn(async move {
        loop {
            let Some(l) = weak.upgrade() else { return };
            match l.mail_budget.refresh(&store).await {
                Ok(()) => l.publish_mail_budget(),
                Err(e) => tracing::warn!("mail budget refresh failed (retrying): {e}"),
            }
            drop(l);
            tokio::time::sleep(REFRESH_EVERY).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use object_store::ObjectStoreExt;

    const DAY: u64 = 86_400_000;

    #[tokio::test]
    async fn shared_between_budgets_and_windows_roll() {
        let store = Store::memory(None);
        let (a, b) = (Budget::default(), Budget::default());
        let t = 10 * DAY + 5;
        for i in 1..=3 {
            assert_eq!(a.spend(&store, 5, DAY, t).await.unwrap(), Spend::Spent(i));
        }
        // b reads a's count; a's cached ETag is then stale and it re-reads
        assert_eq!(b.spend(&store, 5, DAY, t).await.unwrap(), Spend::Spent(4));
        assert_eq!(a.spend(&store, 5, DAY, t).await.unwrap(), Spend::Spent(5));
        assert_eq!(b.spend(&store, 5, DAY, t).await.unwrap(), Spend::Exhausted(5));
        assert_eq!(a.spend(&store, 5, DAY, t).await.unwrap(), Spend::Exhausted(5));
        // a raised limit counts on; the next UTC day starts at 0
        assert_eq!(a.spend(&store, 6, DAY, t).await.unwrap(), Spend::Spent(6));
        assert_eq!(b.spend(&store, 6, DAY, 11 * DAY).await.unwrap(), Spend::Spent(1));
        // a new window length starts afresh
        assert_eq!(a.spend(&store, 6, 3_600_000, 11 * DAY).await.unwrap(), Spend::Spent(1));
        // an operator deleting the object resets it, even for a node that
        // last saw it exhausted
        let c = Budget::default();
        assert_eq!(c.spend(&store, 1, DAY, 11 * DAY).await.unwrap(), Spend::Spent(1));
        assert_eq!(c.spend(&store, 1, DAY, 11 * DAY).await.unwrap(), Spend::Exhausted(1));
        store.raw.delete(&path(&store)).await.unwrap();
        assert_eq!(c.spend(&store, 1, DAY, 11 * DAY).await.unwrap(), Spend::Spent(1));
        b.refresh(&store).await.unwrap();
        assert_eq!(b.last().unwrap().used_in(DAY, 11 * DAY), 1);
    }

    #[tokio::test]
    async fn concurrent_spends_never_overshoot() {
        let store = Store::memory(None);
        let budgets: Vec<Arc<Budget>> = (0..4).map(|_| Arc::new(Budget::default())).collect();
        let mut tasks = Vec::new();
        for b in &budgets {
            for _ in 0..10 {
                let (b, store) = (b.clone(), store.clone());
                tasks.push(tokio::spawn(async move { b.spend(&store, 25, DAY, DAY).await }));
            }
        }
        let mut spent = 0;
        for t in tasks {
            match t.await.unwrap() {
                Ok(Spend::Spent(_)) => spent += 1,
                Ok(Spend::Exhausted(_)) => {}
                // heavy contention may exhaust the retries: counted nowhere
                Err(_) => {}
            }
        }
        assert!(spent <= 25, "{spent} spent");
        let raw = store.raw.get(&path(&store)).await.unwrap().bytes().await.unwrap();
        let st: State = serde_json::from_slice(&raw).unwrap();
        assert_eq!(st.used, spent);
    }
}
