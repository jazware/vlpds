//! Notices to syncers, delivered reliably (reference
//! `space-notifications.ts`): a space's deletion, to every registration it
//! had (lapsed ones too), and a lapsed registration's expiry, in place of
//! the first update after it lapsed. Each is sent at once, and a send that
//! fails for a reason worth retrying leaves an `sE` row in the authority's
//! shard that the shard's owner retries after 1 min, 10 min, 1 h, 6 h and
//! then every 12 h, until it's delivered or refused for good, or a retry
//! fails once 72 hours have passed.
//!
//! A syncer that refuses its expiry notice, or can't be reached within the
//! window, is unregistered (unless it has authorized again since). A
//! notice that no longer applies is dropped rather than sent: an expiry
//! notice once the registration is renewed, a deletion notice once the
//! space is created again. A retry waits while the authority is inactive,
//! and is dropped once its account is gone (its deletion sweeps `sE` with
//! its other rows). A deletion notice replaces a pending expiry notice, and
//! an expiry notice never replaces a pending notice. A retry clears a row
//! only when it's still the one it read, so an older delivery finishing
//! never drops a newer one.

use super::host::{Registration, Sent};
use crate::state::{self, SpaceId};
use crate::xrpc::App;
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;
use vlatproto::tid::Tid;

const EVERY: Duration = Duration::from_secs(30);
const DELAYS: [Duration; 5] = [
    Duration::from_secs(60),
    Duration::from_secs(600),
    Duration::from_secs(3600),
    Duration::from_secs(6 * 3600),
    Duration::from_secs(12 * 3600),
];
pub const WINDOW: Duration = Duration::from_secs(72 * 3600);

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum Notice {
    SpaceDeleted,
    #[serde(rename_all = "camelCase")]
    RegistrationExpired {
        space_rev: String,
    },
}

impl Notice {
    fn update(&self) -> serde_json::Value {
        match self {
            Notice::SpaceDeleted => json!({"$type": "com.atproto.space.notifySpaceUpdate#spaceDeleted"}),
            Notice::RegistrationExpired { space_rev } => {
                json!({"$type": "com.atproto.space.notifySpaceUpdate#registrationExpired", "spaceRev": space_rev})
            }
        }
    }

    fn name(&self) -> &'static str {
        match self {
            Notice::SpaceDeleted => "spaceDeleted",
            Notice::RegistrationExpired { .. } => "registrationExpired",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NoticeRow {
    #[serde(with = "crate::state::stored_uri")]
    pub uri: String,
    pub endpoint: String,
    pub token: String,
    pub notice: Notice,
    pub attempts: u32,
    /// Unix µs.
    pub retry_at: u64,
    /// The end of the retry window (unix µs): a retry failing after it is
    /// the last.
    pub expires: u64,
}

/// An `sD` row from before notices named a registration
/// (notifySpaceDeleted to a service): it's dropped at the expiry it
/// carries, as it was then.
#[derive(serde::Deserialize)]
struct LegacyRow {
    expires: u64,
}

fn next_retry(attempts: u32, now: u64) -> u64 {
    let d = DELAYS[(attempts.max(1) as usize - 1).min(DELAYS.len() - 1)];
    now + d.mul_f64(0.5 + rand::random::<f64>() / 2.0).as_micros() as u64
}

/// Sends `notice` to each of `regs`, leaving an `sE` row for each send
/// worth retrying.
pub async fn notify(app: &App, authority: &str, space: &str, sid: SpaceId, regs: Vec<Registration>, notice: Notice) {
    let log_id = state::space_log_id(space);
    for reg in regs {
        let sent =
            super::host::notify_space_update(app, space, &reg.row.endpoint, &reg.row.token, notice.update()).await;
        crate::metrics::space_notify("notice", sent_label(&sent));
        match sent {
            Sent::Delivered => {}
            Sent::Refused(e) => {
                tracing::info!(space = %log_id, notice = notice.name(), "syncer notice refused, not retried: {e}");
                abandon(app, space, &reg.id, &notice).await;
            }
            Sent::Retry(e) => {
                let now = vlatproto::tid::now_micros();
                let row = NoticeRow {
                    uri: space.to_string(),
                    endpoint: reg.row.endpoint,
                    token: reg.row.token,
                    notice: notice.clone(),
                    attempts: 1,
                    retry_at: next_retry(1, now),
                    expires: now + WINDOW.as_micros() as u64,
                };
                tracing::info!(space = %log_id, notice = notice.name(), "syncer notice queued for retry: {e}");
                if let Err(e) = queue(app, authority, &sid, &reg.id, row).await {
                    tracing::warn!(space = %log_id, "syncer notice retry not stored: {e:#}");
                }
            }
        }
    }
}

fn sent_label(s: &Sent) -> &'static str {
    match s {
        Sent::Delivered => "ok",
        Sent::Refused(_) => "refused",
        Sent::Retry(_) => "error",
    }
}

/// A deletion notice replaces whatever is pending; an expiry notice never
/// replaces a pending notice, so a deletion notice is never lost.
async fn queue(app: &App, authority: &str, sid: &SpaceId, id: &[u8; 32], row: NoticeRow) -> anyhow::Result<()> {
    if matches!(row.notice, Notice::RegistrationExpired { .. }) && current(app, authority, sid, id).await?.is_some() {
        return Ok(());
    }
    put(app, authority, sid, id, Some(&row)).await
}

/// Gives up on a notice: a lapsed registration that refuses its expiry
/// notice, or can't be reached, is unregistered unless it has authorized
/// again since. A deleted space's registrations went with it.
async fn abandon(app: &App, space: &str, id: &[u8; 32], notice: &Notice) {
    if !matches!(notice, Notice::RegistrationExpired { .. }) {
        return;
    }
    let now = vlatproto::tid::now_micros();
    if let Err(e) = crate::xrpc::space::unregister_lapsed(app, space, id, now).await {
        tracing::info!(space = %state::space_log_id(space), "lapsed registration not dropped: {e:#}");
    }
}

async fn put(app: &App, authority: &str, sid: &SpaceId, id: &[u8; 32], row: Option<&NoticeRow>) -> anyhow::Result<()> {
    let p = app.partition(authority).map_err(|e| anyhow::anyhow!("{}", e.message))?;
    let key = state::space_notice_key(authority, sid, id);
    let val = row.map(|r| bytes::Bytes::from(serde_json::to_vec(r).expect("serializes")));
    crate::xrpc::write_private_local(&p, vec![vlsync_store::segment::Mutation { key: key.into(), val }])
        .await
        .map_err(|e| anyhow::anyhow!("{}", e.message))
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
                tracing::warn!("syncer notice retries failed: {e:#}");
            }
        }
    });
}

/// One pass over the `sE` rows of the owned shards due at `now` (unix µs),
/// and the `sD` rows that have expired. Returns how many rows it settled
/// (delivered, refused or dropped).
pub async fn retry_due(app: &App, now: u64) -> anyhow::Result<usize> {
    let mut settled = 0;
    for p in app.partitions.owned() {
        let opts = slatedb::config::ScanOptions::default();
        let mut scan = state::FamilyScan::new(&*p.db, state::SPACE_NOTICE_FAMILY, None, &opts).await?;
        let (mut due, mut legacy) = (Vec::new(), Vec::new());
        while let Some(kv) = scan.next().await? {
            let Some((authority, sid)) = super::rows::did_sid_head(&kv.key) else { continue };
            let Some(id) = super::rows::after_sid(&kv.key).and_then(|r| <[u8; 32]>::try_from(r).ok()) else {
                continue;
            };
            // one bad row mustn't stall every other notice on the shard
            let Ok(row) = serde_json::from_slice::<NoticeRow>(&kv.value) else {
                tracing::warn!(space = %hex::encode(sid), "undecodable syncer notice dropped");
                crate::metrics::space_notify("notice", "undecodable");
                legacy.push(kv.key.clone());
                continue;
            };
            if row.retry_at <= now {
                due.push((authority.to_string(), sid, id, row));
            }
        }
        drop(scan);
        let mut scan = state::FamilyScan::new(&*p.db, state::SPACE_DELETED_FAMILY, None, &opts).await?;
        while let Some(kv) = scan.next().await? {
            if serde_json::from_slice::<LegacyRow>(&kv.value).map_or(true, |r| r.expires <= now) {
                legacy.push(kv.key.clone());
            }
        }
        drop(scan);
        if !legacy.is_empty() {
            settled += legacy.len();
            let muts = legacy.into_iter().map(|k| vlsync_store::segment::Mutation { key: k, val: None }).collect();
            crate::xrpc::write_private_local(&p, muts).await.map_err(|e| anyhow::anyhow!("{}", e.message))?;
        }
        for (authority, sid, id, row) in due {
            settled += retry_one(app, &authority, sid, &id, row, now).await? as usize;
        }
    }
    Ok(settled)
}

/// Ok(true) when the row is settled and cleared.
async fn retry_one(
    app: &App,
    authority: &str,
    sid: SpaceId,
    id: &[u8; 32],
    row: NoticeRow,
    now: u64,
) -> anyhow::Result<bool> {
    let log_id = state::space_log_id(&row.uri);
    let notice = row.notice.name();
    let dropped = |why: &str| tracing::info!(space = %log_id, notice, "syncer notice dropped: {why}");
    let account = match app.account(authority).await {
        Ok(a) if a.status.as_deref() != Some("deleted") => a,
        Ok(_) => {
            dropped("the authority's account is gone");
            return clear_if_same(app, authority, &sid, id, &row).await;
        }
        Err(e) if e.error == "AccountNotFound" => {
            dropped("the authority's account is gone");
            return clear_if_same(app, authority, &sid, id, &row).await;
        }
        Err(e) => anyhow::bail!("{}", e.message),
    };
    if account.status.is_some() {
        return reschedule(app, authority, &sid, id, &row, now).await;
    }
    if !owed(app, authority, &sid, id, &row).await? {
        dropped("it no longer applies");
        return clear_if_same(app, authority, &sid, id, &row).await;
    }
    let sent = super::host::notify_space_update(app, &row.uri, &row.endpoint, &row.token, row.notice.update()).await;
    crate::metrics::space_notify("notice", sent_label(&sent));
    match sent {
        Sent::Delivered => clear_if_same(app, authority, &sid, id, &row).await,
        Sent::Refused(e) => {
            dropped(&e);
            let cleared = clear_if_same(app, authority, &sid, id, &row).await?;
            abandon(app, &row.uri, id, &row.notice).await;
            Ok(cleared)
        }
        Sent::Retry(e) => {
            tracing::info!(space = %log_id, notice, attempts = row.attempts, "syncer notice retry failed: {e}");
            reschedule(app, authority, &sid, id, &row, now).await
        }
    }
}

/// Retries aren't scheduled to stop at the window's end, so the last one
/// lands after it; once that one has failed too, the notice is abandoned.
async fn reschedule(
    app: &App,
    authority: &str,
    sid: &SpaceId,
    id: &[u8; 32],
    row: &NoticeRow,
    now: u64,
) -> anyhow::Result<bool> {
    if row.expires <= now {
        tracing::info!(space = %state::space_log_id(&row.uri), notice = row.notice.name(), "syncer notice expired after 72 hours");
        let cleared = clear_if_same(app, authority, sid, id, row).await?;
        abandon(app, &row.uri, id, &row.notice).await;
        return Ok(cleared);
    }
    let next = NoticeRow { attempts: row.attempts + 1, retry_at: next_retry(row.attempts + 1, now), ..row.clone() };
    if current(app, authority, sid, id).await?.as_ref() == Some(row) {
        put(app, authority, sid, id, Some(&next)).await?;
    }
    Ok(false)
}

/// An expiry notice is owed while the registration is still lapsed; a
/// deletion notice while the space isn't live again.
async fn owed(app: &App, authority: &str, sid: &SpaceId, id: &[u8; 32], row: &NoticeRow) -> anyhow::Result<bool> {
    let p = app.partition(authority).map_err(|e| anyhow::anyhow!("{}", e.message))?;
    Ok(match &row.notice {
        Notice::RegistrationExpired { .. } => {
            match p.db.get(state::space_registration_key(authority, sid, id)).await? {
                Some(v) => super::rows::RegRow::decode(&v)?.lapsed(vlatproto::tid::now_micros()),
                None => false,
            }
        }
        Notice::SpaceDeleted => match p.db.get(state::space_key(authority, sid)).await? {
            Some(v) => !super::rows::SpaceRow::decode(&v)?.live(),
            None => true,
        },
    })
}

async fn current(app: &App, authority: &str, sid: &SpaceId, id: &[u8; 32]) -> anyhow::Result<Option<NoticeRow>> {
    let p = app.partition(authority).map_err(|e| anyhow::anyhow!("{}", e.message))?;
    match p.db.get(state::space_notice_key(authority, sid, id)).await? {
        Some(v) => Ok(Some(serde_json::from_slice(&v)?)),
        None => Ok(None),
    }
}

async fn clear_if_same(
    app: &App,
    authority: &str,
    sid: &SpaceId,
    id: &[u8; 32],
    read: &NoticeRow,
) -> anyhow::Result<bool> {
    if current(app, authority, sid, id).await?.as_ref() != Some(read) {
        return Ok(false);
    }
    put(app, authority, sid, id, None).await?;
    Ok(true)
}

/// The expiry notice for a registration that lapsed before the update at
/// `space_rev`.
pub fn expired(space_rev: Tid) -> Notice {
    Notice::RegistrationExpired { space_rev: space_rev.to_string() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_follows_the_schedule() {
        let now = 1_000_000_000;
        let d = |a| next_retry(a, now) - now;
        let within = |a: u32, secs: u64| {
            let v = d(a);
            assert!((secs * 500_000..=secs * 1_000_000).contains(&v), "attempt {a}: {v}");
        };
        within(1, 60);
        within(2, 600);
        within(3, 3600);
        within(4, 6 * 3600);
        within(5, 12 * 3600);
        within(30, 12 * 3600);
    }

    #[test]
    fn rows_round_trip() {
        for notice in [Notice::SpaceDeleted, expired(Tid(77))] {
            let r = NoticeRow {
                uri: "at:space/did:plc:a/t.t/k".into(),
                endpoint: "https://s".into(),
                token: "tok".into(),
                notice,
                attempts: 2,
                retry_at: 5,
                expires: 9,
            };
            let stored = serde_json::to_vec(&r).unwrap();
            assert_eq!(serde_json::from_slice::<NoticeRow>(&stored).unwrap(), r);
            // stored in the form before Nov 24, which an older build reads
            assert!(String::from_utf8(stored).unwrap().contains(r#""uri":"at://did:plc:a/space/t.t/k""#));
        }
        // a row as notifySpaceDeleted's retries wrote it
        let old =
            br#"{"uri":"at://did:plc:a/space/t.t/k","endpoint":"https://s","expires":9,"attempts":2,"retryAt":5}"#;
        assert!(serde_json::from_slice::<NoticeRow>(old).is_err());
        assert_eq!(serde_json::from_slice::<LegacyRow>(old).unwrap().expires, 9);
    }

    #[test]
    fn updates() {
        assert_eq!(Notice::SpaceDeleted.update(), json!({"$type": "com.atproto.space.notifySpaceUpdate#spaceDeleted"}));
        assert_eq!(expired(Tid(1)).update()["$type"], json!("com.atproto.space.notifySpaceUpdate#registrationExpired"));
    }
}
