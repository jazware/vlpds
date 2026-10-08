//! Keeps every node's [`Policy`] in step with the config object
//! (`{prefix}/config/ratelimits.json`): a conditional GET every
//! [`REFRESH_EVERY`], at startup, and when a peer nudges after a change.
//! Saves check the caller edited the version it read and write version + 1
//! with CAS on the ETag, so concurrent admins on different nodes can't
//! overwrite each other. An invalid object never takes a node down: it keeps
//! its last good policy and reports the error.
//!
//! Loads and saves on a node are serialized, so a slow load can never
//! install an older version over a newer one.

use super::config::{self, Audit, Doc};
use super::Limiter;
use object_store::{GetOptions, ObjectStore, PutMode, PutOptions, PutPayload};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use vlsync_store::store::Store;

/// Peers are nudged on every change, so this only bounds staleness after a
/// lost nudge.
pub const REFRESH_EVERY: Duration = Duration::from_secs(10);
const CALL_DEADLINE: Duration = Duration::from_secs(5);

pub fn config_path(store: &Store) -> object_store::path::Path {
    object_store::path::Path::from(format!("{}/config/ratelimits.json", store.prefix))
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ConfigError {
    /// If that much could be read.
    pub version: Option<u64>,
    pub message: String,
    pub at_ms: u64,
}

#[derive(Clone, Debug, Default)]
pub struct RtStatus {
    /// None: no object, flag defaults.
    pub doc: Option<Doc>,
    /// Of the last object fetched, good or not.
    seen_etag: Option<String>,
    pub loaded_at_ms: Option<u64>,
    pub checked_at_ms: Option<u64>,
    /// Set while the newest object is rejected.
    pub error: Option<ConfigError>,
}

#[derive(Default)]
pub struct Runtime {
    status: Mutex<RtStatus>,
    io: tokio::sync::Mutex<()>,
    wake: tokio::sync::Notify,
    started: AtomicBool,
}

impl Runtime {
    pub fn status(&self) -> RtStatus {
        self.status.lock().clone()
    }
}

#[derive(Debug)]
pub enum SaveError {
    Invalid(Vec<String>),
    Conflict { expected: u64, current: Option<u64> },
    Store(String),
}

impl std::fmt::Display for SaveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SaveError::Invalid(e) => write!(f, "invalid config: {}", e.join("; ")),
            SaveError::Conflict { expected, current: Some(c) } => {
                write!(f, "the config changed since version {expected} (now version {c}); reload and reapply your edit")
            }
            SaveError::Conflict { expected, current: None } => {
                write!(f, "the config changed since version {expected}; reload and reapply your edit")
            }
            SaveError::Store(e) => write!(f, "config store error: {e}"),
        }
    }
}

pub struct SaveReq {
    /// Metadata fields are ignored.
    pub doc: Doc,
    /// 0: none stored.
    pub if_version: u64,
    pub actor: String,
    pub ip: Option<String>,
    pub node: String,
    pub note: Option<String>,
}

async fn bounded<T>(f: impl std::future::Future<Output = object_store::Result<T>>) -> object_store::Result<T> {
    match tokio::time::timeout(CALL_DEADLINE, f).await {
        Ok(r) => r,
        Err(_) => Err(object_store::Error::Generic { store: "ratelimits", source: "config call timed out".into() }),
    }
}

/// None when absent.
async fn fetch(store: &Store, etag: Option<String>) -> object_store::Result<Option<(bytes::Bytes, Option<String>)>> {
    let path = config_path(store);
    let got = bounded(async {
        let r = store.raw.get_opts(&path, GetOptions { if_none_match: etag, ..Default::default() }).await?;
        let e = r.meta.e_tag.clone();
        Ok((r.bytes().await?, e))
    })
    .await;
    match got {
        Ok(x) => Ok(Some(x)),
        Err(object_store::Error::NotFound { .. }) => Ok(None),
        Err(e) => Err(e),
    }
}

impl Limiter {
    /// Validates and installs `doc` (None: flag defaults). On failure the
    /// policy in force stays and the error is recorded.
    fn apply(&self, doc: Option<Doc>, etag: Option<String>) -> Result<(), Vec<String>> {
        let now = super::now_ms();
        let compiled = config::compile_with(doc.as_ref(), self.mail_daily_budget);
        let mut st = self.runtime.status.lock();
        st.seen_etag = etag;
        st.checked_at_ms = Some(now);
        match compiled {
            Ok(p) => {
                let changed = st.doc != doc;
                self.install(p);
                st.doc = doc;
                st.error = None;
                if changed {
                    st.loaded_at_ms = Some(now);
                }
                Ok(())
            }
            Err(errs) => {
                super::CONFIG_ERRORS.inc();
                st.error = Some(ConfigError { version: doc.map(|d| d.version), message: errs.join("; "), at_ms: now });
                Err(errs)
            }
        }
    }

    fn reject(&self, version: Option<u64>, message: String, etag: Option<String>) {
        super::CONFIG_ERRORS.inc();
        let now = super::now_ms();
        let mut st = self.runtime.status.lock();
        st.seen_etag = etag;
        st.checked_at_ms = Some(now);
        st.error = Some(ConfigError { version, message, at_ms: now });
    }

    /// Asks the refresher to re-read the object now.
    pub fn wake(&self) {
        self.runtime.wake.notify_one();
    }
}

/// Re-reads the object (conditional on the last ETag) and installs it if it
/// changed and validates. Returns whether a new policy was installed.
pub async fn refresh(limiter: &Limiter, store: &Store) -> anyhow::Result<bool> {
    let _io = limiter.runtime.io.lock().await;
    let (seen, had_doc) = {
        let st = limiter.runtime.status.lock();
        (st.seen_etag.clone(), st.doc.is_some() || st.error.is_some())
    };
    let label = |r: &str| super::CONFIG_LOADS.with_label_values(&[r]).inc();
    let got = match fetch(store, seen).await {
        Ok(g) => g,
        Err(object_store::Error::NotModified { .. }) => {
            limiter.runtime.status.lock().checked_at_ms = Some(super::now_ms());
            label("unchanged");
            return Ok(false);
        }
        Err(e) => {
            label("error");
            return Err(e.into());
        }
    };
    let Some((bytes, etag)) = got else {
        // no object (never written): flag defaults
        if !had_doc {
            limiter.runtime.status.lock().checked_at_ms = Some(super::now_ms());
            label("unchanged");
            return Ok(false);
        }
        let _ = limiter.apply(None, None);
        label("applied");
        return Ok(true);
    };
    match config::parse_stored(&bytes).map(|(doc, dropped)| {
        if !dropped.is_empty() {
            tracing::warn!(
                ?dropped,
                "rate-limit config has fields this build doesn't know (a newer feature level's): ignored"
            );
        }
        doc
    }) {
        Err(msg) => {
            let version = serde_json::from_slice::<serde_json::Value>(&bytes).ok().and_then(|v| v["version"].as_u64());
            tracing::warn!(?version, "rate-limit config object rejected (keeping the last good config): {msg}");
            limiter.reject(version, msg, etag);
            label("invalid");
            Ok(false)
        }
        Ok(doc) => {
            let version = doc.version;
            match limiter.apply(Some(doc), etag) {
                Ok(()) => {
                    tracing::info!(version, "rate-limit config applied");
                    label("applied");
                    Ok(true)
                }
                Err(errs) => {
                    tracing::warn!(
                        version,
                        "rate-limit config object rejected (keeping the last good config): {}",
                        errs.join("; ")
                    );
                    label("invalid");
                    Ok(false)
                }
            }
        }
    }
}

/// Starts this node's refresher (once per limiter): a load now, then every
/// [`REFRESH_EVERY`] or when woken. Stops when the limiter is dropped.
pub fn spawn_refresher(limiter: &Arc<Limiter>, store: Store) {
    if limiter.runtime.started.swap(true, Ordering::AcqRel) {
        return;
    }
    let weak = Arc::downgrade(limiter);
    tokio::spawn(async move {
        loop {
            let Some(l) = weak.upgrade() else { return };
            if let Err(e) = refresh(&l, &store).await {
                tracing::warn!("rate-limit config refresh failed (retrying): {e:#}");
            }
            tokio::select! {
                _ = tokio::time::sleep(REFRESH_EVERY) => {}
                _ = l.runtime.wake.notified() => {}
            }
        }
    });
}

fn is_conflict(e: &object_store::Error) -> bool {
    matches!(e, object_store::Error::Precondition { .. } | object_store::Error::AlreadyExists { .. })
}

/// Validates and stores `req.doc` as the next version (CAS), installs it on
/// this node and writes the audit log line. Returns the stored object.
pub async fn save(limiter: &Limiter, store: &Store, req: SaveReq) -> Result<Doc, SaveError> {
    let _io = limiter.runtime.io.lock().await;
    let cur = fetch(store, None).await.map_err(|e| SaveError::Store(e.to_string()))?;
    let (cur_doc, cur_version, etag) = match &cur {
        None => (None, 0, None),
        Some((b, e)) => {
            // an unreadable object can still be replaced: its version (if
            // any) is what the caller must have seen
            let raw: Option<serde_json::Value> = serde_json::from_slice(b).ok();
            let v = raw.as_ref().and_then(|v| v["version"].as_u64()).unwrap_or(0);
            (config::parse_stored(b).ok().map(|(d, _)| d), v, e.clone())
        }
    };
    if cur_version != req.if_version {
        return Err(SaveError::Conflict { expected: req.if_version, current: Some(cur_version) });
    }
    let mut doc = req.doc.editable();
    doc.version = cur_version + 1;
    if let Err(errs) = config::compile(Some(&doc)) {
        return Err(SaveError::Invalid(errs));
    }
    let changes = config::changes(cur_doc.as_ref(), &doc, limiter.mail_daily_budget);
    let at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let note = req.note.filter(|n| !n.trim().is_empty());
    if note.as_ref().is_some_and(|n| n.chars().count() > 280) {
        return Err(SaveError::Invalid(vec!["note: longer than 280 characters".into()]));
    }
    doc.updated_at = Some(at.clone());
    doc.updated_by = Some(req.actor.clone());
    doc.note = note.clone();
    let mut history = cur_doc.map(|d| d.history).unwrap_or_default();
    history.push(Audit {
        version: doc.version,
        at,
        by: req.actor.clone(),
        ip: req.ip.clone(),
        node: req.node.clone(),
        note,
        changes: if changes.is_empty() { vec!["no changes".into()] } else { changes.clone() },
    });
    let drop = history.len().saturating_sub(config::HISTORY);
    history.drain(..drop);
    doc.history = history;
    let body = serde_json::to_vec_pretty(&doc).map_err(|e| SaveError::Store(e.to_string()))?;
    let mode = match etag {
        Some(e) => crate::cluster::if_match(Some(e)),
        None => PutMode::Create,
    };
    let put = bounded(store.raw.put_opts(
        &config_path(store),
        PutPayload::from(body),
        PutOptions { mode, ..Default::default() },
    ))
    .await;
    let new_etag = match put {
        Ok(r) => r.e_tag,
        Err(e) if is_conflict(&e) => return Err(SaveError::Conflict { expected: req.if_version, current: None }),
        Err(e) => return Err(SaveError::Store(e.to_string())),
    };
    if let Err(errs) = limiter.apply(Some(doc.clone()), new_etag) {
        // compile() passed above; unreachable unless validation is not pure
        return Err(SaveError::Invalid(errs));
    }
    // the vlpds::audit line is the handler's audit entry's
    tracing::info!(
        version = doc.version,
        by = %req.actor,
        ip = req.ip.as_deref().unwrap_or("-"),
        node = %req.node,
        changes = %changes.join("; "),
        "rate-limit config updated"
    );
    Ok(doc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use object_store::ObjectStoreExt;

    fn limiter() -> Arc<Limiter> {
        Arc::new(Limiter::new(&crate::server::Config::default()))
    }

    fn req(doc: serde_json::Value, if_version: u64) -> SaveReq {
        SaveReq {
            doc: serde_json::from_value(doc).unwrap(),
            if_version,
            actor: "tester".into(),
            ip: Some("127.0.0.1".into()),
            node: "n1".into(),
            note: Some("why".into()),
        }
    }

    #[tokio::test]
    async fn save_swaps_and_peers_pick_it_up() {
        let store = Store::memory(None);
        let (a, b) = (limiter(), limiter());
        assert!(!refresh(&b, &store).await.unwrap(), "no object: defaults");
        let d = save(&a, &store, req(serde_json::json!({"limiters": {"global-ip": {"points": 7}}}), 0)).await.unwrap();
        assert_eq!(d.version, 1);
        assert_eq!(d.history.len(), 1);
        assert_eq!(d.history[0].changes, vec!["global-ip: points 3000→7"]);
        // installed on the writer at once
        assert_eq!(a.policy().version, 1);
        assert_eq!(a.policy().builtin(&super::super::GLOBAL_IP).points, 7);
        // the peer on its next refresh; then 304s
        assert!(refresh(&b, &store).await.unwrap());
        assert_eq!(b.policy().builtin(&super::super::GLOBAL_IP).points, 7);
        assert!(!refresh(&b, &store).await.unwrap());
        // a stale edit is refused; a fresh one lands as version 2
        assert!(matches!(save(&b, &store, req(serde_json::json!({}), 0)).await, Err(SaveError::Conflict { .. })));
        let d = save(&b, &store, req(serde_json::json!({}), 1)).await.unwrap();
        assert_eq!((d.version, d.history.len()), (2, 2));
        assert_eq!(b.policy().builtin(&super::super::GLOBAL_IP).points, 3000);
    }

    #[tokio::test]
    async fn invalid_saves_are_refused_and_invalid_objects_keep_the_last_good_policy() {
        let store = Store::memory(None);
        let a = limiter();
        let bad = save(&a, &store, req(serde_json::json!({"limiters": {"global-ip": {"points": 0}}}), 0)).await;
        assert!(matches!(bad, Err(SaveError::Invalid(_))));
        save(&a, &store, req(serde_json::json!({"limiters": {"global-ip": {"points": 9}}}), 0)).await.unwrap();
        // someone writes garbage by hand
        store
            .raw
            .put(&config_path(&store), PutPayload::from_static(br#"{"version": 5, "limiters": {"nope": {}}}"#))
            .await
            .unwrap();
        let b = limiter();
        assert!(!refresh(&a, &store).await.unwrap());
        assert!(!refresh(&b, &store).await.unwrap());
        for l in [&a, &b] {
            let st = l.runtime.status();
            let e = st.error.expect("error surfaced");
            assert_eq!(e.version, Some(5));
            assert!(e.message.contains("unknown limiter"), "{}", e.message);
        }
        // a keeps its last good policy; b (never had one) stays on defaults
        assert_eq!(a.policy().builtin(&super::super::GLOBAL_IP).points, 9);
        assert_eq!(b.policy().version, 0);
        // the broken object can be replaced through the API (version 5 seen)
        let d = save(&a, &store, req(serde_json::json!({}), 5)).await.unwrap();
        assert_eq!(d.version, 6);
        assert!(refresh(&b, &store).await.unwrap());
        assert!(b.runtime.status().error.is_none());
        // not JSON at all
        store.raw.put(&config_path(&store), PutPayload::from_static(b"{{")).await.unwrap();
        assert!(!refresh(&b, &store).await.unwrap());
        assert_eq!(b.policy().version, 6);
        assert_eq!(b.runtime.status().error.unwrap().version, None);
    }
}
