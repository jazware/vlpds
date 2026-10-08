//! Per-account blob quotas: stored bytes (`--blob-quota-gb`) and uploads
//! per UTC day (`--blob-uploads-per-day`), overridable per DID from the
//! console.
//!
//!   p/{did}\0bq/use     [`Usage`]: running byte total of the account's
//!                       stored blobs (`blobs::STORED` rows) + today's uploads
//!   p/{did}\0bq/limit   [`Limits`]: the operator's per-account override
//!   {prefix}/moderation/over-quota/{did}.json
//!                       marker for the console while an account is over its
//!                       byte quota (only blobs of a repo moving in can put
//!                       it there)
//!
//! The total moves with the stored rows: +size when uploadBlob adds a row,
//! -size when the blob GC or a quarantine purge drops one. A missing `bq/use`
//! (accounts from before quotas) is rebuilt once by listing the account's
//! objects. Updates are serialized per DID on the node ([`lock`]): uploads
//! and the GC run on the account's owner, so the count is exact unless an
//! ownership move splits one account's writes across nodes.

use super::server::{get_json, pmut, to_json_bytes};
use super::*;
use futures::StreamExt;
use object_store::ObjectStore;

pub(super) const USAGE: &str = "bq/use";
pub(super) const LIMITS: &str = "bq/limit";

#[derive(Clone, Debug, Default, PartialEq, serde::Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Usage {
    pub bytes: u64,
    /// UTC day (days since the epoch) `uploads` counts.
    pub day: u32,
    pub uploads: u32,
    /// Over the byte quota (a migration brought more than it allows).
    #[serde(default)]
    pub over: bool,
}

/// None: the flag's default. Some(0): unlimited.
#[derive(Clone, Debug, Default, PartialEq, serde::Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Limits {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uploads_per_day: Option<u32>,
}

/// What a blob upload is let off.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Exempt {
    pub daily: bool,
    pub bytes: bool,
}

fn today() -> u32 {
    (super::server::now_secs() / 86_400) as u32
}

/// (bytes, uploads per day) in force; 0 = unlimited.
pub(super) fn effective(app: &App, l: &Limits) -> (u64, u32) {
    (l.bytes.unwrap_or(app.config.blob_quota_bytes), l.uploads_per_day.unwrap_or(app.config.blob_uploads_per_day))
}

static LOCKS: std::sync::LazyLock<Vec<tokio::sync::Mutex<()>>> =
    std::sync::LazyLock::new(|| (0..256).map(|_| tokio::sync::Mutex::new(())).collect());

pub(super) async fn lock(did: &str) -> tokio::sync::MutexGuard<'static, ()> {
    LOCKS[(state::did_hash(did) % LOCKS.len() as u64) as usize].lock().await
}

fn marker_path(app: &App, did: &str) -> object_store::path::Path {
    object_store::path::Path::from(format!("{}/moderation/over-quota/{}.json", app.store.prefix, did))
}

/// Sum of the account's blob objects (live and quarantined by a takedown).
async fn rebuild(app: &App, did: &str) -> XResult<u64> {
    let mut total = 0;
    for root in ["blob", super::moderation::QUARANTINE] {
        let prefix = object_store::path::Path::from(format!("{}/{root}/{did}", app.store.prefix));
        let mut list = app.store.raw.list(Some(&prefix));
        while let Some(m) = list.next().await {
            total += m.map_err(XrpcError::from_err)?.size;
        }
    }
    Ok(total)
}

pub(super) async fn limits(app: &App, did: &str) -> XResult<Limits> {
    Ok(get_json::<Limits>(app, did, LIMITS).await?.unwrap_or_default())
}

/// The stored usage, rebuilt (not written) when missing; today's count reset
/// on a new day.
pub(super) async fn usage(app: &App, did: &str) -> XResult<Usage> {
    let mut u = match get_json::<Usage>(app, did, USAGE).await? {
        Some(u) => u,
        None => Usage { bytes: rebuild(app, did).await?, ..Default::default() },
    };
    let d = today();
    if u.day != d {
        u.day = d;
        u.uploads = 0;
    }
    Ok(u)
}

fn gib(b: u64) -> String {
    match b {
        0..1_000_000 => format!("{b} bytes"),
        1_000_000..1_000_000_000 => format!("{:.1} MB", b as f64 / 1e6),
        _ => format!("{:.2} GB", b as f64 / 1e9),
    }
}

fn bytes_exceeded(used: u64, size: u64, limit: u64) -> XrpcError {
    crate::metrics::BLOB_QUOTA_REJECTIONS.with_label_values(&["bytes"]).inc();
    XrpcError {
        status: StatusCode::PAYLOAD_TOO_LARGE,
        error: "BlobQuotaExceeded".into(),
        message: format!(
            "this account's blob storage quota is full: {} of {} used, this blob is {} bytes. Delete posts with media you no longer need, or ask the server's operator for more space",
            gib(used),
            gib(limit),
            size
        ),
    }
}

fn daily_exceeded(limit: u32) -> XrpcError {
    crate::metrics::BLOB_QUOTA_REJECTIONS.with_label_values(&["uploads"]).inc();
    XrpcError {
        status: StatusCode::TOO_MANY_REQUESTS,
        error: "RateLimitExceeded".into(),
        message: format!("this account has uploaded {limit} blobs today, its daily limit; try again after 00:00 UTC"),
    }
}

/// Cheap early refusal before the body is read (no lock, no writes):
/// today's upload count, and `declared` bytes against the byte quota.
pub(super) async fn precheck(app: &App, did: &str, declared: Option<u64>, moving_in: bool) -> XResult<()> {
    if moving_in {
        // checked once the CID shows whether the imported repo references it
        return Ok(());
    }
    let (u, l) = tokio::try_join!(usage(app, did), limits(app, did))?;
    let (max_bytes, per_day) = effective(app, &l);
    if per_day > 0 && u.uploads >= per_day {
        return Err(daily_exceeded(per_day));
    }
    // only a full quota: the body may be a blob the account already stores,
    // which adds nothing ([`commit`] decides exactly)
    if max_bytes > 0 && u.bytes >= max_bytes {
        return Err(bytes_exceeded(u.bytes, declared.unwrap_or(0), max_bytes));
    }
    Ok(())
}

/// Checks the quotas for a received blob, runs `write` (which stores its
/// bytes), then records the stored row and the new usage in one log write.
/// A CID the account already stores adds no bytes.
pub(super) async fn commit<F>(app: &App, did: &str, cid: &str, size: u64, exempt: Exempt, write: F) -> XResult<()>
where
    F: std::future::Future<Output = XResult<()>>,
{
    let _g = lock(did).await;
    let row = format!("{}{cid}", super::blobs::STORED);
    let (u, l, had) = tokio::try_join!(usage(app, did), limits(app, did), app.get_private(did, &row))?;
    let (max_bytes, per_day) = effective(app, &l);
    let mut u = u;
    if !exempt.daily && per_day > 0 && u.uploads >= per_day {
        return Err(daily_exceeded(per_day));
    }
    let added = if had.is_some() { 0 } else { size };
    if !exempt.bytes && max_bytes > 0 && added > 0 && u.bytes.saturating_add(added) > max_bytes {
        return Err(bytes_exceeded(u.bytes, size, max_bytes));
    }
    write.await?;
    u.bytes = u.bytes.saturating_add(added);
    if !exempt.daily {
        u.uploads += 1;
    }
    let was_over = u.over;
    u.over = max_bytes > 0 && u.bytes > max_bytes;
    let muts = vec![super::blobs::stored(did, cid, true), pmut(did, USAGE, Some(to_json_bytes(&u)))];
    app.put_private(did, muts).await?;
    sync_marker(app, did, was_over, &u, max_bytes).await;
    Ok(())
}

/// Drops the account's stored row for `cid` (the GC deleted the bytes, or a
/// quarantine purge did) and takes `size` off the total. No row: nothing.
pub(super) async fn drop_stored(app: &App, did: &str, cid: &str, size: u64) -> XResult<()> {
    adjust_stored(app, did, cid, size, false).await
}

/// The GC put a blob back.
pub(super) async fn restore_stored(app: &App, did: &str, cid: &str, size: u64) -> XResult<()> {
    adjust_stored(app, did, cid, size, true).await
}

async fn adjust_stored(app: &App, did: &str, cid: &str, size: u64, present: bool) -> XResult<()> {
    let _g = lock(did).await;
    let had = app.get_private(did, &format!("{}{cid}", super::blobs::STORED)).await?.is_some();
    if had == present {
        return Ok(());
    }
    let (mut u, l) = tokio::try_join!(usage(app, did), limits(app, did))?;
    u.bytes = if present { u.bytes.saturating_add(size) } else { u.bytes.saturating_sub(size) };
    let was_over = u.over;
    let (max_bytes, _) = effective(app, &l);
    u.over = max_bytes > 0 && u.bytes > max_bytes;
    let muts = vec![super::blobs::stored(did, cid, present), pmut(did, USAGE, Some(to_json_bytes(&u)))];
    app.put_private(did, muts).await?;
    sync_marker(app, did, was_over, &u, max_bytes).await;
    Ok(())
}

/// Best effort: the marker only feeds the console's list.
async fn sync_marker(app: &App, did: &str, was_over: bool, u: &Usage, max_bytes: u64) {
    if u.over == was_over {
        return;
    }
    let path = marker_path(app, did);
    let r = if u.over {
        let body = json!({"did": did, "bytes": u.bytes, "limit": max_bytes, "at": vlatproto::events::now_rfc3339()});
        app.store.raw.put(&path, PutPayload::from(to_json_bytes(&body))).await.map(|_| ())
    } else {
        match app.store.raw.delete(&path).await {
            Err(object_store::Error::NotFound { .. }) => Ok(()),
            r => r,
        }
    };
    if let Err(e) = r {
        tracing::warn!(%did, "over-quota marker: {e}");
    }
}

/// The console's view of an account's quota.
pub(super) async fn view(app: &App, did: &str) -> XResult<J> {
    let (u, l) = tokio::try_join!(usage(app, did), limits(app, did))?;
    let (max_bytes, per_day) = effective(app, &l);
    Ok(json!({
        "bytes": u.bytes,
        "uploadsToday": u.uploads,
        "limitBytes": max_bytes,
        "limitUploadsPerDay": per_day,
        "override": l,
        "defaults": {"bytes": app.config.blob_quota_bytes, "uploadsPerDay": app.config.blob_uploads_per_day},
        "over": max_bytes > 0 && u.bytes > max_bytes,
    }))
}

/// Writes the override (both None: back to the defaults) and re-evaluates
/// the over-quota flag.
pub(super) async fn set_limits(app: &App, did: &str, l: Limits) -> XResult<()> {
    let _g = lock(did).await;
    let mut u = usage(app, did).await?;
    let was_over = u.over;
    let (max_bytes, _) = effective(app, &l);
    u.over = max_bytes > 0 && u.bytes > max_bytes;
    let lim = (l != Limits::default()).then(|| to_json_bytes(&l));
    app.put_private(did, vec![pmut(did, LIMITS, lim), pmut(did, USAGE, Some(to_json_bytes(&u)))]).await?;
    sync_marker(app, did, was_over, &u, max_bytes).await;
    Ok(())
}

/// Accounts flagged over their byte quota.
pub(super) async fn over_quota(app: &App) -> XResult<Vec<J>> {
    let root = object_store::path::Path::from(format!("{}/moderation/over-quota", app.store.prefix));
    let metas: Vec<object_store::ObjectMeta> = app
        .store
        .raw
        .list(Some(&root))
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .collect::<Result<_, _>>()
        .map_err(XrpcError::from_err)?;
    let mut out = Vec::new();
    for m in metas {
        if let Ok(r) = app.store.raw.get(&m.location).await {
            if let Ok(v) = serde_json::from_slice::<J>(&r.bytes().await.map_err(XrpcError::from_err)?) {
                out.push(v);
            }
        }
    }
    Ok(out)
}

pub(super) fn fixture_rows(did: &str) -> Vec<super::private_rows::PrivateRow> {
    let u = Usage { bytes: 1_234_567, day: 20_729, uploads: 3, over: false };
    let l = Limits { bytes: Some(50_000_000_000), uploads_per_day: Some(1000) };
    vec![
        (did.into(), USAGE.into(), super::private_rows::enc(&u)),
        (did.into(), LIMITS.into(), super::private_rows::enc(&l)),
    ]
}

pub(super) fn check_row(_routing: &str, name: &str, val: &[u8]) -> Option<anyhow::Result<&'static str>> {
    match name {
        USAGE => Some(super::private_rows::typed_row::<Usage>("blob quota usage", val)),
        LIMITS => Some(super::private_rows::typed_row::<Limits>("blob quota override", val)),
        _ => None,
    }
}
