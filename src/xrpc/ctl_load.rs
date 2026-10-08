//! Coalesced loads of an account's security controls (`super::server::ctl`):
//! one load per DID at a time, and while a shard is in flight (moving,
//! reopening) one probe per shard instead of one failing read per request.

use super::XrpcError;
use parking_lot::Mutex as PMutex;
use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};
use vlsync_store::slots::ShardId;

const PROBE_PAUSE_MIN: Duration = Duration::from_millis(20);
const PROBE_PAUSE_MAX: Duration = Duration::from_millis(200);

/// The account's shard is in flight: nothing was read or done, a retry
/// after the move succeeds.
pub(super) fn in_flight(e: &XrpcError) -> bool {
    e.status == axum::http::StatusCode::SERVICE_UNAVAILABLE
        && (e.error == crate::forward::SHARD_MOVED || e.error == crate::forward::REPO_LOADING)
}

struct Flight<T> {
    gen: u64,
    cell: tokio::sync::OnceCell<Result<Arc<T>, XrpcError>>,
}

struct GateState {
    probing: bool,
    not_before: Instant,
    pause: Duration,
}

#[derive(Default)]
struct Gate {
    state: PMutex<Option<GateState>>,
    reachable: tokio::sync::Notify,
}

pub(super) struct Loads<T> {
    flights: PMutex<HashMap<String, Arc<Flight<T>>>>,
    gates: PMutex<HashMap<ShardId, Arc<Gate>>>,
}

impl<T> Default for Loads<T> {
    fn default() -> Self {
        Loads { flights: Default::default(), gates: Default::default() }
    }
}

pub(super) enum Attempt {
    Go(Probe),
    /// Another load is probing the shard (or it failed moments ago).
    Wait(Duration),
}

/// The right to probe a shard seen in flight; dropping it unanswered (a
/// cancelled request) lets the next load probe at once.
pub(super) struct Probe(Option<Arc<Gate>>);

impl Drop for Probe {
    fn drop(&mut self) {
        if let Some(g) = &self.0 {
            if let Some(s) = g.state.lock().as_mut() {
                s.probing = false;
            }
        }
    }
}

impl<T> Loads<T> {
    /// Runs `load` for `key` unless one started at the same change
    /// generation is running, whose result is shared. A load that began
    /// before a change (`gen` differs) is never joined: a request arriving
    /// after a revocation must not get a view read before it.
    pub(super) async fn single_flight<F, Fut>(&self, key: &str, gen: u64, load: F) -> (Result<Arc<T>, XrpcError>, bool)
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<Arc<T>, XrpcError>>,
    {
        let (flight, joined) = {
            let mut m = self.flights.lock();
            match m.get(key) {
                Some(f) if f.gen == gen => (f.clone(), true),
                _ => {
                    let f = Arc::new(Flight { gen, cell: tokio::sync::OnceCell::new() });
                    m.insert(key.to_string(), f.clone());
                    (f, false)
                }
            }
        };
        struct Leave<'a, T>(&'a Loads<T>, &'a str, &'a Arc<Flight<T>>);
        impl<T> Drop for Leave<'_, T> {
            fn drop(&mut self) {
                let mut m = self.0.flights.lock();
                if m.get(self.1).is_some_and(|f| Arc::ptr_eq(f, self.2)) {
                    m.remove(self.1);
                }
            }
        }
        let _leave = Leave(self, key, &flight);
        let r = flight.cell.get_or_init(load).await.clone();
        (r, joined)
    }

    /// Whether a load in `shard` may read now.
    pub(super) fn attempt(&self, shard: ShardId) -> Attempt {
        let Some(g) = self.gates.lock().get(&shard).cloned() else {
            return Attempt::Go(Probe(None));
        };
        let now = Instant::now();
        let mut st = g.state.lock();
        match st.as_mut() {
            None => Attempt::Go(Probe(None)),
            Some(s) if s.probing => Attempt::Wait(s.pause.min(PROBE_PAUSE_MAX)),
            Some(s) if now < s.not_before => Attempt::Wait(s.not_before - now),
            Some(s) => {
                s.probing = true;
                drop(st);
                Attempt::Go(Probe(Some(g)))
            }
        }
    }

    /// Waits up to `d` for `shard` to be found reachable.
    pub(super) async fn wait(&self, shard: ShardId, d: Duration) {
        let Some(g) = self.gates.lock().get(&shard).cloned() else { return };
        let n = g.reachable.notified();
        tokio::pin!(n);
        n.as_mut().enable();
        if g.state.lock().is_none() {
            return;
        }
        let _ = tokio::time::timeout(d, n).await;
    }

    /// `shard` answered: loads there read freely again.
    pub(super) fn reachable(&self, shard: ShardId, _probe: Probe) {
        if let Some(g) = self.gates.lock().remove(&shard) {
            *g.state.lock() = None;
            g.reachable.notify_waiters();
        }
    }

    /// `shard` is in flight: the next probe waits a pause (doubling).
    pub(super) fn moving(&self, shard: ShardId, probe: Probe) {
        let prober = probe.0.is_some();
        let g = self.gates.lock().entry(shard).or_default().clone();
        let mut st = g.state.lock();
        let (pause, probing) = match st.as_ref() {
            Some(s) if prober => ((s.pause * 2).min(PROBE_PAUSE_MAX), false),
            Some(s) => (s.pause, s.probing),
            None => (PROBE_PAUSE_MIN, false),
        };
        *st = Some(GateState { probing, not_before: Instant::now() + pause, pause });
        drop(st);
        drop(probe);
    }

    #[cfg(test)]
    fn gated(&self, shard: ShardId) -> bool {
        self.gates.lock().contains_key(&shard)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn moved() -> XrpcError {
        XrpcError::unavailable(crate::forward::SHARD_MOVED, "partition 1 is not owned by this node")
    }

    /// Concurrent loads of one DID share one read; a load from before a
    /// change is not joined.
    #[tokio::test]
    async fn one_read_per_did_and_generation() {
        let loads: Arc<Loads<u32>> = Default::default();
        let reads = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(tokio::sync::Notify::new());
        let run = |gen: u64| {
            let (loads, reads, gate) = (loads.clone(), reads.clone(), gate.clone());
            tokio::spawn(async move {
                loads
                    .single_flight("did:plc:a", gen, || async move {
                        reads.fetch_add(1, Ordering::SeqCst);
                        gate.notified().await;
                        Ok(Arc::new(gen as u32))
                    })
                    .await
            })
        };
        let same: Vec<_> = (0..50).map(|_| run(7)).collect();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(reads.load(Ordering::SeqCst), 1);
        let later = run(8);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(reads.load(Ordering::SeqCst), 2, "a change since the first read started: a read of its own");
        gate.notify_waiters();
        let mut joined = 0;
        for h in same {
            let (r, j) = h.await.unwrap();
            assert_eq!(*r.ok().unwrap(), 7);
            joined += j as usize;
        }
        assert_eq!(joined, 49);
        assert_eq!(*later.await.unwrap().0.ok().unwrap(), 8);
        assert!(loads.flights.lock().is_empty());
    }

    /// A shard seen in flight is probed by one load at a time, spaced by a
    /// pause; once it answers, every load reads at once.
    #[tokio::test]
    async fn one_probe_per_moving_shard() {
        let loads: Loads<()> = Default::default();
        let s = ShardId(3);
        let Attempt::Go(p) = loads.attempt(s) else { panic!("open shard") };
        assert!(in_flight(&moved()));
        loads.moving(s, p);
        assert!(loads.gated(s));
        assert!(matches!(loads.attempt(s), Attempt::Wait(_)), "within the pause");
        tokio::time::sleep(PROBE_PAUSE_MIN + Duration::from_millis(5)).await;
        let Attempt::Go(p) = loads.attempt(s) else { panic!("pause over: probe") };
        assert!(matches!(loads.attempt(s), Attempt::Wait(_)), "one prober");
        drop(p);
        let Attempt::Go(p) = loads.attempt(s) else { panic!("a dropped probe frees the shard") };
        let waiter = {
            let (t, loads) = (Instant::now(), &loads);
            async move {
                loads.wait(s, Duration::from_secs(5)).await;
                t.elapsed()
            }
        };
        let (waited, ()) = tokio::join!(waiter, async {
            tokio::time::sleep(Duration::from_millis(30)).await;
            loads.reachable(s, p);
        });
        assert!(waited < Duration::from_secs(1), "woken when the shard answered: {waited:?}");
        assert!(!loads.gated(s));
        assert!(matches!(loads.attempt(s), Attempt::Go(Probe(None))));
    }

    #[test]
    fn other_errors_are_not_moves() {
        assert!(!in_flight(&XrpcError::unavailable("PartitionUnavailable", "partition owner: timeout")));
        assert!(!in_flight(&XrpcError::internal("boom")));
        assert!(in_flight(&XrpcError::unavailable(crate::forward::REPO_LOADING, "loading")));
    }
}
