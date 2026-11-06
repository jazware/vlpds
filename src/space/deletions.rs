//! notifySpaceDeleted, delivered until it lands (reference
//! `space-notifications.ts` `notifySpaceDeleted`). deleteSpace records one
//! `sD` row per service registered at the time, in the authority's shard,
//! before the space becomes a tombstone; each is sent at once and then by
//! the node's sweep until one of:
//!
//! - delivered (2xx), or refused with a status not worth retrying;
//! - the registration it was owed under expires (a syncer that still holds
//!   a copy learns of the deletion when its credential renewal answers
//!   `SpaceDeleted`);
//! - the space was made again since (sending it now would purge the
//!   syncer's new copy), or the authority's account is gone (syncers learn
//!   of that from the account event).
//!
//! A deactivated or taken-down authority's rows wait. Rows sit beside the
//! tombstone, so a deletion whose own op never applied is found out by its
//! space still being live under the same `createdAt`, and waits too, until
//! its registration's expiry.

use crate::state::{self, SpaceId};
use crate::xrpc::App;
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;

/// Between sweeps of a node's shards for due rows.
const EVERY: Duration = Duration::from_secs(30);
const RETRY_BASE_MICROS: u64 = 10_000_000;
const RETRY_MAX_MICROS: u64 = 30 * 60 * 1_000_000;
/// Rows sent at once per sweep (a deletion is rare; a space has at most
/// [`super::host::MAX_REGISTRATIONS`]).
const SWEEP_MAX: usize = 1024;

/// `sD`: a notifySpaceDeleted owed to a service.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeletedRow {
    pub uri: String,
    pub endpoint: String,
    /// The registration's expiry, unix µs: no retries past it.
    pub expires: u64,
    /// The deleted incarnation's `createdAt`.
    pub created_at: String,
    pub attempts: u32,
    /// Unix µs.
    pub next_at: u64,
}

impl DeletedRow {
    pub fn encode(&self) -> bytes::Bytes {
        serde_json::to_vec(self).expect("deletion rows serialize").into()
    }

    pub fn decode(v: &[u8]) -> anyhow::Result<DeletedRow> {
        Ok(serde_json::from_slice(v)?)
    }
}

fn backoff(attempts: u32) -> u64 {
    RETRY_BASE_MICROS.saturating_mul(1 << attempts.min(20)).min(RETRY_MAX_MICROS)
}

/// The rows a deletion of the space `uri` (live, made at `created_at`)
/// owes its live registrations, written in the authority's shard (this
/// node's). Before the tombstone, so a crash between the two leaves rows
/// that wait for it rather than a deletion no one hears of.
pub async fn record(
    app: &App,
    authority: &str,
    sid: &SpaceId,
    uri: &str,
    created_at: &str,
    regs: &[(String, super::rows::NotifyRow)],
) -> Result<(), vlatproto::xrpc::XrpcError> {
    if regs.is_empty() {
        return Ok(());
    }
    let p = app.partition(authority)?;
    let now = vlatproto::tid::now_micros();
    let muts = regs
        .iter()
        .map(|(service, reg)| {
            let row = DeletedRow {
                uri: uri.into(),
                endpoint: reg.endpoint.clone(),
                expires: reg.expires,
                created_at: created_at.into(),
                attempts: 0,
                next_at: now,
            };
            vlsync_store::segment::Mutation {
                key: state::space_deleted_key(authority, sid, service).into(),
                val: Some(row.encode()),
            }
        })
        .collect();
    crate::xrpc::write_private_local(&p, muts).await
}

/// Sends a space's rows now, in the background.
pub fn send_now(app: &Arc<App>, authority: &str, sid: SpaceId) {
    let (app, authority) = (app.clone(), authority.to_string());
    tokio::spawn(async move {
        if let Err(e) = send_due(&app, Some((&authority, &sid)), u64::MAX).await {
            tracing::info!(space = %hex::encode(sid), "notifySpaceDeleted send failed (the sweep retries): {e:#}");
        }
    });
}

/// Starts the node's sweeps (with `--spaces`).
pub fn start(app: &Arc<App>) {
    let weak = Arc::downgrade(app);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(EVERY.mul_f64(0.8 + 0.4 * rand::random::<f64>())).await;
            let Some(app) = weak.upgrade() else { return };
            if let Err(e) = send_due(&app, None, vlatproto::tid::now_micros()).await {
                tracing::warn!("notifySpaceDeleted sweep failed: {e:#}");
            }
        }
    });
}

/// What became of one row.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Delivered,
    /// Refused for good, expired, recreated or the authority gone: dropped.
    Dropped(&'static str),
    /// Tried again later.
    Later,
}

/// Every row due by `due` (unix µs) in the shards this node owns (or one
/// space's), each sent and then cleared or rescheduled. Returns them.
pub async fn send_due(app: &App, only: Option<(&str, &SpaceId)>, due: u64) -> anyhow::Result<Vec<Outcome>> {
    let mut rows = Vec::new();
    let opts = slatedb::config::ScanOptions::default();
    let parts = match only {
        Some((authority, _)) => app.partition(authority).map(|p| vec![p]).unwrap_or_default(),
        None => app.partitions.owned(),
    };
    for p in parts {
        let mut it = match only {
            Some((authority, sid)) => {
                let prefix = state::space_prefix(state::SPACE_DELETED_FAMILY, authority, sid);
                let iter =
                    p.db.scan_with_options(prefix.clone()..vlsync_store::keys::prefix_end(&prefix), &opts).await?;
                Scan::Range(iter)
            }
            None => Scan::Family(state::FamilyScan::new(&*p.db, state::SPACE_DELETED_FAMILY, None, &opts).await?),
        };
        while let Some(kv) = it.next().await? {
            let row = match DeletedRow::decode(&kv.value) {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!("undecodable space deletion row dropped: {e:#}");
                    rows.push((p.clone(), kv.key, None));
                    continue;
                }
            };
            if row.next_at <= due && rows.len() < SWEEP_MAX {
                rows.push((p.clone(), kv.key, Some(row)));
            }
        }
    }
    let sends = rows.into_iter().map(|(p, key, row)| async move {
        let Some(row) = row else {
            write(&p, key, None).await?;
            return Ok(Outcome::Dropped("undecodable"));
        };
        let outcome = attempt(app, &key, &row).await;
        match &outcome {
            Outcome::Later => {
                let attempts = row.attempts + 1;
                let next_at = (vlatproto::tid::now_micros() + backoff(attempts)).min(row.expires);
                write(&p, key, Some(DeletedRow { attempts, next_at, ..row })).await?;
            }
            _ => write(&p, key, None).await?,
        }
        anyhow::Ok(outcome)
    });
    futures::future::join_all(sends).await.into_iter().collect()
}

enum Scan {
    Range(slatedb::DbIterator),
    Family(state::FamilyScan),
}

impl Scan {
    async fn next(&mut self) -> anyhow::Result<Option<slatedb::KeyValue>> {
        Ok(match self {
            Scan::Range(i) => i.next().await?,
            Scan::Family(f) => f.next().await?,
        })
    }
}

async fn write(p: &crate::partition::Partition, key: bytes::Bytes, row: Option<DeletedRow>) -> anyhow::Result<()> {
    let m = vlsync_store::segment::Mutation { key, val: row.map(|r| r.encode()) };
    crate::xrpc::write_private_local(p, vec![m]).await.map_err(|e| anyhow::anyhow!("{}", e.message))
}

async fn attempt(app: &App, key: &[u8], row: &DeletedRow) -> Outcome {
    let log_id = state::space_log_id(&row.uri);
    if row.expires <= vlatproto::tid::now_micros() {
        tracing::info!(space = %log_id, "notifySpaceDeleted expired with its registration");
        return Outcome::Dropped("expired");
    }
    let (Some((authority, sid)), Some(service)) = (super::rows::did_sid_head(key), service_of(key)) else {
        return Outcome::Dropped("malformed");
    };
    let account = match app.account(authority).await {
        Ok(a) => Some(a),
        Err(e) if e.error == "AccountNotFound" => None,
        Err(_) => return Outcome::Later,
    };
    let Some(account) = account else { return Outcome::Dropped("authority gone") };
    if account.status.is_some() {
        return Outcome::Later;
    }
    let p = match app.partition(authority) {
        Ok(p) => p,
        Err(_) => return Outcome::Later,
    };
    let space = match p.db.get(state::space_key(authority, &sid)).await {
        Ok(Some(v)) => match super::rows::SpaceRow::decode(&v) {
            Ok(s) => s,
            Err(_) => return Outcome::Later,
        },
        Ok(None) => return Outcome::Dropped("authority gone"),
        Err(_) => return Outcome::Later,
    };
    if space.live() {
        if space.created_at != row.created_at {
            return Outcome::Dropped("recreated");
        }
        // the deletion's own op hasn't applied (yet)
        return Outcome::Later;
    }
    let lxm = "com.atproto.space.notifySpaceDeleted";
    let body = json!({"space": row.uri});
    let client = vlatproto::http::guarded_fanout(app.config.dev_mode);
    let post = reqwest::Method::POST;
    match super::host::call(app, client, authority, service, &row.endpoint, lxm, post, &[], Some(&body)).await {
        Ok((s, _)) if (200..300).contains(&s) => Outcome::Delivered,
        Ok((s, _)) if crate::xrpc::space::retryable_status(s) => {
            tracing::info!(space = %log_id, service, status = s, "notifySpaceDeleted failed, will retry");
            Outcome::Later
        }
        Ok((s, _)) => {
            tracing::info!(space = %log_id, service, status = s, "notifySpaceDeleted refused, not retried");
            Outcome::Dropped("refused")
        }
        Err(e) => {
            tracing::info!(space = %log_id, service, "notifySpaceDeleted failed, will retry: {e}");
            Outcome::Later
        }
    }
}

/// The service an `sD` key names (after the space id).
fn service_of(key: &[u8]) -> Option<&str> {
    let body = vlsync_store::keys::key_body(key).get(3..)?;
    let at = body.iter().position(|b| *b == 0)?;
    std::str::from_utf8(body.get(at + 1 + state::SPACE_ID_LEN..)?).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rows_and_keys() {
        let row = DeletedRow {
            uri: "at://did:plc:a/space/a.b.c/k".into(),
            endpoint: "https://syncer.example".into(),
            expires: 5,
            created_at: "2026-10-22T00:00:00.000Z".into(),
            attempts: 2,
            next_at: 3,
        };
        assert_eq!(DeletedRow::decode(&row.encode()).unwrap(), row);
        let sid = state::space_id(&row.uri);
        let key = state::space_deleted_key("did:plc:a", &sid, "did:web:syncer.example#sync");
        assert_eq!(super::super::rows::did_sid_head(&key), Some(("did:plc:a", sid)));
        assert_eq!(service_of(&key), Some("did:web:syncer.example#sync"));
        assert!(state::is_space_key(&key));
    }

    #[test]
    fn backoff_grows_to_a_cap() {
        assert_eq!(backoff(0), RETRY_BASE_MICROS);
        assert_eq!(backoff(1), 2 * RETRY_BASE_MICROS);
        assert_eq!(backoff(40), RETRY_MAX_MICROS);
    }
}
