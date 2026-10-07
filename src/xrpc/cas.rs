//! Conditional writes of private (`p/{routing}\0...`) state, correct across
//! nodes: [`App::private_cas`] (DESIGN.md "Auth state under concurrency").
//!
//! The conditions are checked and the write made at the routing key's
//! owner, under a lock every conditional write of that key takes, with the
//! write applied before the lock is released. Only conditional writes
//! serialize with each other: a blind `put_private` of the same rows can
//! still slip between a check and its write, so rows that need the
//! guarantee are written only through here.
//!
//! An ownership move between the check and the write is safe: the old
//! owner's log refuses an entry for a shard it no longer holds, so the write
//! fails rather than landing after the new owner's writes.

use super::*;
use crate::segment::Mutation;
use std::collections::HashMap;

#[derive(Clone, Debug)]
pub enum Cond {
    /// The row `name` holds exactly `val` (None = absent).
    Eq { name: String, val: Option<Bytes> },
}

impl Cond {
    pub fn eq(name: impl Into<String>, val: Option<Bytes>) -> Cond {
        Cond::Eq { name: name.into(), val }
    }
}

#[derive(Clone, Debug)]
pub enum Op {
    /// None deletes.
    Put { name: String, val: Option<Bytes> },
    /// Listed at the owner under the lock, so no row created by an earlier
    /// conditional write is missed.
    DeletePrefix { prefix: String },
}

impl Op {
    pub fn put(name: impl Into<String>, val: Option<Bytes>) -> Op {
        Op::Put { name: name.into(), val }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Outcome {
    /// False: a condition failed and nothing was written.
    pub applied: bool,
    /// (name, value) of the rows removed by [`Op::DeletePrefix`].
    pub deleted: Vec<(String, Bytes)>,
}

/// Per-routing-key locks of one node.
#[derive(Default)]
pub(super) struct Locks {
    m: parking_lot::Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

const LOCKS_PRUNE_AT: usize = 4096;

impl Locks {
    fn get(&self, key: &str) -> Arc<tokio::sync::Mutex<()>> {
        let mut m = self.m.lock();
        if m.len() >= LOCKS_PRUNE_AT {
            // a held lock (or one being waited on) has another reference
            m.retain(|_, l| Arc::strong_count(l) > 1);
        }
        m.entry(key.to_string()).or_default().clone()
    }
}

/// Test hook: awaited at a named point of a read-modify-write (e.g.
/// `oauth_refresh`, right before its conditional write) for one routing key,
/// so a test can hold a request there while it races something against it.
pub type PauseHook = Arc<dyn Fn(&str) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> + Send + Sync>;

static PAUSE_HOOKS: parking_lot::Mutex<Option<HashMap<String, PauseHook>>> = parking_lot::Mutex::new(None);
static ANY_PAUSE_HOOK: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub fn set_pause_hook(routing: &str, h: Option<PauseHook>) {
    let mut g = PAUSE_HOOKS.lock();
    let m = g.get_or_insert_with(HashMap::new);
    match h {
        Some(h) => m.insert(routing.to_string(), h),
        None => m.remove(routing),
    };
    ANY_PAUSE_HOOK.store(!m.is_empty(), std::sync::atomic::Ordering::Release);
}

pub async fn pause_point(point: &str, routing: &str) {
    if !ANY_PAUSE_HOOK.load(std::sync::atomic::Ordering::Acquire) {
        return;
    }
    let h = PAUSE_HOOKS.lock().as_ref().and_then(|m| m.get(routing).cloned());
    if let Some(h) = h {
        h(point).await;
    }
}

impl App {
    /// Checks `conds` and, if they all hold, applies `ops` in one log write.
    pub async fn private_cas(&self, routing: &str, conds: Vec<Cond>, ops: Vec<Op>) -> Result<Outcome, XrpcError> {
        if let Some(owner) = self.remote_owner(routing) {
            let touches_sec =
                ops.iter().any(|o| matches!(o, Op::Put { name, .. } if name.starts_with(super::server::SEC)));
            let r = internal::forward_private_cas(self, &owner, routing, conds, ops).await;
            if touches_sec {
                // the owner dropped its view; so does this node (as put_sec)
                super::server::ctl_changed(self, routing);
            }
            return r;
        }
        private_cas_local(self, routing, conds, ops).await
    }
}

/// Never forwarded again.
pub(super) async fn private_cas_local(
    app: &App,
    routing: &str,
    conds: Vec<Cond>,
    ops: Vec<Op>,
) -> Result<Outcome, XrpcError> {
    let lock = super::server::ext(app).cas_locks.get(routing);
    let _g = lock.lock().await;
    let p = app.partition(routing)?;
    for c in &conds {
        let Cond::Eq { name, val } = c;
        let cur = p.db.get(state::private_key(routing, name)).await.map_err(XrpcError::from_err)?;
        if cur.as_deref() != val.as_deref() {
            return Ok(Outcome::default());
        }
    }
    let mut muts: Vec<Mutation> = Vec::new();
    let mut deleted = Vec::new();
    let put_names: Vec<&str> = ops
        .iter()
        .filter_map(|op| match op {
            Op::Put { name, .. } => Some(name.as_str()),
            Op::DeletePrefix { .. } => None,
        })
        .collect();
    let mut lockout = false;
    for op in &ops {
        match op {
            Op::Put { name, val } => {
                muts.push(Mutation { key: state::private_key(routing, name).into(), val: val.clone() });
                let idx = super::mfa::lockout_index(routing, name, val.as_ref());
                lockout |= idx.is_some();
                muts.extend(idx);
            }

            Op::DeletePrefix { prefix } => {
                for (name, v) in super::server::scan_private(app, routing, prefix).await? {
                    if !put_names.contains(&name.as_str()) {
                        muts.push(Mutation { key: state::private_key(routing, &name).into(), val: None });
                    }
                    deleted.push((name, v));
                }
            }
        }
    }
    if !muts.is_empty() {
        let sec = state::private_key(routing, super::server::SEC);
        let touches_sec = muts.iter().any(|m| m.key.starts_with(&sec));
        let r = super::write_private_local(&p, muts).await;
        if touches_sec {
            super::server::ctl_changed(app, routing);
        }
        r?;
        if lockout {
            app.changes.emit("lockout", routing, super::changes::now_ms());
            app.changes.account(routing);
        }
    }
    Ok(Outcome { applied: true, deleted })
}
