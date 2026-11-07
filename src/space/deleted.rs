//! notifySpaceDeleted, delivered reliably (reference `space-notifications.ts`):
//! each service registered when a space is deleted is told at once, and a
//! send that fails for a reason worth retrying leaves an `sD` row in the
//! authority's shard that the shard's owner retries, backing off from a
//! minute to an hour, until it's delivered, refused for good, or the
//! service's registration would have expired.
//!
//! A retry is dropped once the space has been created again (telling the
//! service then would purge its copy of the new space) or the authority's
//! account is gone (its deletion sweeps `sD` with its other rows), and
//! waits while the authority is inactive. A deletion of the space made
//! again overwrites the row; a retry clears a row only when it's still the
//! one it read, so an older delivery finishing never drops a newer one.

use super::rows::NotifyRow;
use crate::state::{self, SpaceId};
use crate::xrpc::App;
use std::sync::Arc;
use std::time::Duration;

const EVERY: Duration = Duration::from_secs(30);
const BASE: Duration = Duration::from_secs(60);
const MAX: Duration = Duration::from_secs(3600);

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeletedRow {
    pub uri: String,
    pub endpoint: String,
    /// When the registration expires (unix µs): no retry after it.
    pub expires: u64,
    pub attempts: u32,
    /// Unix µs.
    pub retry_at: u64,
}

fn next_retry(attempts: u32, now: u64) -> u64 {
    let d = BASE.saturating_mul(1 << attempts.saturating_sub(1).min(10)).min(MAX);
    now + d.mul_f64(0.75 + 0.5 * rand::random::<f64>()).as_micros() as u64
}

enum Sent {
    Delivered,
    Refused(String),
    Retry(String),
}

async fn send(app: &App, authority: &str, uri: &str, service: &str, endpoint: &str) -> Sent {
    let lxm = "com.atproto.space.notifySpaceDeleted";
    let body = serde_json::json!({"space": uri});
    let client = vlatproto::http::guarded_fanout(app.config.dev_mode);
    match super::host::call(app, client, authority, service, endpoint, lxm, reqwest::Method::POST, &[], Some(&body))
        .await
    {
        Ok((s, _)) if (200..300).contains(&s) => Sent::Delivered,
        Ok((s, _)) if crate::xrpc::space::retryable_status(s) => Sent::Retry(format!("status {s}")),
        Ok((s, _)) => Sent::Refused(format!("status {s}")),
        Err(e) => Sent::Retry(e),
    }
}

/// Tells each of `services` that `space` is gone, leaving an `sD` row for
/// each send worth retrying.
pub async fn notify(app: &App, authority: &str, space: &str, sid: SpaceId, services: Vec<(String, NotifyRow)>) {
    let log_id = state::space_log_id(space);
    for (service, reg) in services {
        match send(app, authority, space, &service, &reg.endpoint).await {
            Sent::Delivered => {}
            Sent::Refused(e) => {
                tracing::info!(space = %log_id, service, "notifySpaceDeleted refused, not retried: {e}")
            }
            Sent::Retry(e) => {
                let now = vlatproto::tid::now_micros();
                let row = DeletedRow {
                    uri: space.to_string(),
                    endpoint: reg.endpoint,
                    expires: reg.expires,
                    attempts: 1,
                    retry_at: next_retry(1, now).min(reg.expires),
                };
                tracing::info!(space = %log_id, service, "notifySpaceDeleted queued for retry: {e}");
                if let Err(e) = put(app, authority, &sid, &service, Some(&row)).await {
                    tracing::warn!(space = %log_id, service, "notifySpaceDeleted retry not stored: {}", e.message);
                }
            }
        }
    }
}

async fn put(
    app: &App,
    authority: &str,
    sid: &SpaceId,
    service: &str,
    row: Option<&DeletedRow>,
) -> crate::xrpc::XResult<()> {
    let p = app.partition(authority)?;
    let key = state::space_deleted_key(authority, sid, service);
    let val = row.map(|r| bytes::Bytes::from(serde_json::to_vec(r).expect("serializes")));
    crate::xrpc::write_private_local(&p, vec![vlsync_store::segment::Mutation { key: key.into(), val }]).await
}

/// Starts the retries of the shards this node owns (with `--spaces`).
pub fn start(app: &Arc<App>) {
    if app.spaces.is_none() {
        return;
    }
    let weak = Arc::downgrade(app);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(EVERY.mul_f64(0.8 + 0.4 * rand::random::<f64>())).await;
            let Some(app) = weak.upgrade() else { return };
            if let Err(e) = retry_due(&app, vlatproto::tid::now_micros()).await {
                tracing::warn!("space deletion notify retries failed: {e:#}");
            }
        }
    });
}

/// One pass over the `sD` rows of the owned shards due at `now` (unix µs).
/// Returns how many rows it settled (delivered, refused or dropped).
pub async fn retry_due(app: &App, now: u64) -> anyhow::Result<usize> {
    let mut settled = 0;
    for p in app.partitions.owned() {
        let opts = slatedb::config::ScanOptions::default();
        let mut scan = state::FamilyScan::new(&*p.db, state::SPACE_DELETED_FAMILY, None, &opts).await?;
        let mut due = Vec::new();
        while let Some(kv) = scan.next().await? {
            let Some((authority, sid)) = super::rows::did_sid_head(&kv.key) else { continue };
            let service = std::str::from_utf8(&kv.key[kv.key.len() - service_len(&kv.key, authority)..])?.to_string();
            let row: DeletedRow = serde_json::from_slice(&kv.value)?;
            if row.retry_at <= now || row.expires <= now {
                due.push((authority.to_string(), sid, service, row));
            }
        }
        drop(scan);
        for (authority, sid, service, row) in due {
            settled += retry_one(app, &authority, sid, &service, row, now).await? as usize;
        }
    }
    Ok(settled)
}

/// The service's length at the end of an `sD` key.
fn service_len(key: &[u8], authority: &str) -> usize {
    let body = vlsync_store::keys::key_body(key);
    body.len() - (state::SPACE_DELETED_FAMILY.len() + authority.len() + 1 + state::SPACE_ID_LEN)
}

/// Ok(true) when the row is settled and cleared.
async fn retry_one(
    app: &App,
    authority: &str,
    sid: SpaceId,
    service: &str,
    row: DeletedRow,
    now: u64,
) -> anyhow::Result<bool> {
    let log_id = state::space_log_id(&row.uri);
    let clear = |why: &str| tracing::info!(space = %log_id, service, "notifySpaceDeleted retry dropped: {why}");
    if row.expires <= now {
        clear("the registration expired");
        return clear_if_same(app, authority, &sid, service, &row).await;
    }
    let account = match app.account(authority).await {
        Ok(a) if a.status.as_deref() != Some("deleted") => a,
        Ok(_) => {
            clear("the authority's account is gone");
            return clear_if_same(app, authority, &sid, service, &row).await;
        }
        Err(e) if e.error == "AccountNotFound" => {
            clear("the authority's account is gone");
            return clear_if_same(app, authority, &sid, service, &row).await;
        }
        Err(e) => anyhow::bail!("{}", e.message),
    };
    if account.status.is_some() {
        let next = DeletedRow {
            attempts: row.attempts + 1,
            retry_at: next_retry(row.attempts + 1, now).min(row.expires),
            ..row.clone()
        };
        return replace_if_same(app, authority, &sid, service, &row, &next).await.map(|_| false);
    }
    let p = app.partition(authority).map_err(|e| anyhow::anyhow!("{}", e.message))?;
    let live = match p.db.get(state::space_key(authority, &sid)).await? {
        Some(v) => super::rows::SpaceRow::decode(&v)?.live(),
        None => false,
    };
    if live {
        clear("the space was created again");
        return clear_if_same(app, authority, &sid, service, &row).await;
    }
    match send(app, authority, &row.uri, service, &row.endpoint).await {
        Sent::Delivered => clear_if_same(app, authority, &sid, service, &row).await,
        Sent::Refused(e) => {
            clear(&e);
            clear_if_same(app, authority, &sid, service, &row).await
        }
        Sent::Retry(e) => {
            tracing::info!(space = %log_id, service, attempts = row.attempts, "notifySpaceDeleted retry failed: {e}");
            let next = DeletedRow {
                attempts: row.attempts + 1,
                retry_at: next_retry(row.attempts + 1, now).min(row.expires),
                ..row.clone()
            };
            replace_if_same(app, authority, &sid, service, &row, &next).await.map(|_| false)
        }
    }
}

async fn current(app: &App, authority: &str, sid: &SpaceId, service: &str) -> anyhow::Result<Option<DeletedRow>> {
    let p = app.partition(authority).map_err(|e| anyhow::anyhow!("{}", e.message))?;
    match p.db.get(state::space_deleted_key(authority, sid, service)).await? {
        Some(v) => Ok(Some(serde_json::from_slice(&v)?)),
        None => Ok(None),
    }
}

async fn clear_if_same(
    app: &App,
    authority: &str,
    sid: &SpaceId,
    service: &str,
    read: &DeletedRow,
) -> anyhow::Result<bool> {
    if current(app, authority, sid, service).await?.as_ref() != Some(read) {
        return Ok(false);
    }
    put(app, authority, sid, service, None).await.map_err(|e| anyhow::anyhow!("{}", e.message))?;
    Ok(true)
}

async fn replace_if_same(
    app: &App,
    authority: &str,
    sid: &SpaceId,
    service: &str,
    read: &DeletedRow,
    next: &DeletedRow,
) -> anyhow::Result<()> {
    if current(app, authority, sid, service).await?.as_ref() == Some(read) {
        put(app, authority, sid, service, Some(next)).await.map_err(|e| anyhow::anyhow!("{}", e.message))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_to_an_hour() {
        let now = 1_000_000_000;
        let d = |a| next_retry(a, now) - now;
        assert!((45_000_000..=75_000_000).contains(&d(1)), "{}", d(1));
        assert!((90_000_000..=150_000_000).contains(&d(2)));
        assert!(d(30) <= 4_500_000_000);
    }

    #[test]
    fn rows_round_trip() {
        let r = DeletedRow {
            uri: "at://did:plc:a/space/t.t/k".into(),
            endpoint: "https://s".into(),
            expires: 9,
            attempts: 2,
            retry_at: 5,
        };
        assert_eq!(serde_json::from_slice::<DeletedRow>(&serde_json::to_vec(&r).unwrap()).unwrap(), r);
    }
}
