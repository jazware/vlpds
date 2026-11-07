//! Gives each account made before `#atproto_kem` keys one (with `--spaces`),
//! once, in the background after startup: the reference PDS's KEM key
//! backfill. Until an account has a published key, syncers can't derive
//! MAC secrets for its space repos.
//!
//! Each node backfills the shards it owns, so every account is handled by
//! its own worker and no node needs a lease. An account is done once its row
//! holds a key, which a run cut short skips. A shard is done once a pass over
//! it had no failures: `kem-backfill/{shard}` in the bucket records that, so
//! no node scans it again. Shard ids are never reused, so a reshard's
//! children scan once and find every account done. A node without Spaces
//! deletes the records at startup: accounts it creates get no key, and a
//! later `--spaces` start must look again.
//!
//! Where this PDS may change the account's did:plc (it lists one of our
//! rotation keys and names us as its PDS), the key is published and
//! `#identity` sequenced. Otherwise (did:web, a rotation key removed,
//! migrated away) the key is stored for the owner to publish, and logged.

use crate::state;
use crate::xrpc::App;
use futures::StreamExt;
use object_store::path::Path;
use object_store::{ObjectStoreExt, PutPayload};
use prometheus::{register_int_counter_vec, IntCounterVec};
use std::collections::HashSet;
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use vlatproto::xrpc::XrpcError;
use vlsync_store::slots::ShardId;

/// After startup, so the node's shards are open and warm first.
const START_DELAY: Duration = Duration::from_secs(30);
/// Between looks for shards this node took over since.
const RECHECK: Duration = Duration::from_secs(600);
const RETRY_MIN: Duration = Duration::from_secs(30);
/// The directory rate-limits writes (as `ROTATE_PLC_CONCURRENCY`).
const CONCURRENCY: usize = 4;

static ACCOUNTS: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "vlpds_kem_backfill_accounts_total",
        "Accounts given a #atproto_kem key by the backfill, by result (published: on PLC with #identity; unpublished: stored, the owner must publish it; failed: retried)",
        &["result"]
    )
    .unwrap()
});

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Pass {
    pub published: usize,
    pub unpublished: usize,
    pub failed: usize,
    /// Scanned and recorded done in this pass.
    pub shards_done: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Published,
    /// Stored; the owner must publish it.
    Unpublished,
    /// Has a key already, or is deleted.
    Skipped,
}

pub fn start(app: &Arc<App>) {
    for r in ["published", "unpublished", "failed"] {
        ACCOUNTS.with_label_values(&[r]);
    }
    let weak = Arc::downgrade(app);
    tokio::spawn(async move {
        let mut done = HashSet::new();
        let (mut wait, mut retry, mut logged) = (START_DELAY, RETRY_MIN, false);
        loop {
            tokio::time::sleep(wait).await;
            let Some(app) = weak.upgrade() else { return };
            let p = pass(&app, &mut done).await;
            if p.failed > 0 {
                tracing::warn!(failed = p.failed, retry_in_s = retry.as_secs(), "kem key backfill will retry");
                wait = retry;
                retry = (retry * 2).min(RECHECK);
                continue;
            }
            (wait, retry) = (RECHECK, RETRY_MIN);
            if p.shards_done > 0 || !logged {
                tracing::info!(
                    published = p.published,
                    unpublished = p.unpublished,
                    shards = p.shards_done,
                    "kem key backfill complete"
                );
                logged = true;
            }
        }
    });
}

fn record_path(app: &App, shard: ShardId) -> Path {
    Path::from(format!("{}/kem-backfill/{}", app.store.prefix, shard.key()))
}

/// One pass over the shards this node owns that aren't in `done` (shards
/// known complete; filled in here).
pub async fn pass(app: &App, done: &mut HashSet<ShardId>) -> Pass {
    let mut out = Pass::default();
    for p in app.partitions.owned() {
        if done.contains(&p.id) {
            continue;
        }
        let path = record_path(app, p.id);
        match app.store.raw.head(&path).await {
            Ok(_) => {
                done.insert(p.id);
                continue;
            }
            Err(object_store::Error::NotFound { .. }) => {}
            Err(e) => {
                tracing::warn!(shard = %p.id, "kem key backfill: reading the shard's record failed: {e}");
                out.failed += 1;
                continue;
            }
        }
        let dids = match missing(&p).await {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!(shard = %p.id, "kem key backfill: scanning the shard's accounts failed: {e}");
                out.failed += 1;
                continue;
            }
        };
        let failed_before = out.failed;
        let mut results = futures::stream::iter(dids)
            .map(|did| async move { (backfill_account(app, &did).await, did) })
            .buffer_unordered(CONCURRENCY);
        while let Some((r, did)) = results.next().await {
            let result = match r {
                Ok(Outcome::Published) => {
                    out.published += 1;
                    "published"
                }
                Ok(Outcome::Unpublished) => {
                    out.unpublished += 1;
                    "unpublished"
                }
                Ok(Outcome::Skipped) => continue,
                Err(e) => {
                    tracing::warn!(%did, "failed to backfill kem key: {}", e.message);
                    out.failed += 1;
                    "failed"
                }
            };
            ACCOUNTS.with_label_values(&[result]).inc();
        }
        if out.failed > failed_before {
            continue;
        }
        let body = PutPayload::from(serde_json::to_vec(&serde_json::json!({"completedAt": now()})).unwrap());
        match app.store.raw.put(&path, body).await {
            Ok(_) => {
                done.insert(p.id);
                out.shards_done += 1;
            }
            Err(e) => {
                tracing::warn!(shard = %p.id, "kem key backfill: recording the shard done failed: {e}");
                out.failed += 1;
            }
        }
    }
    out
}

fn now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// The shard's accounts without a KEM key.
async fn missing(p: &crate::partition::Partition) -> Result<Vec<String>, slatedb::Error> {
    #[derive(serde::Deserialize)]
    struct Row {
        did: String,
        #[serde(default)]
        status: Option<String>,
        #[serde(default)]
        kem_pubkey: Option<String>,
    }
    let mut out = Vec::new();
    let mut it = state::FamilyScan::new(p.db.as_ref(), state::ACCOUNT_FAMILY, None, &Default::default()).await?;
    while let Some(kv) = it.next().await? {
        let Ok(a) = serde_json::from_slice::<Row>(&kv.value) else { continue };
        if a.kem_pubkey.is_none() && a.status.as_deref() != Some("deleted") {
            out.push(a.did);
        }
    }
    Ok(out)
}

/// Gives `did` (on this node) a KEM key if it has none. The key is stored
/// only after it is published, so a failed publish leaves the account to
/// the next pass.
pub async fn backfill_account(app: &App, did: &str) -> Result<Outcome, XrpcError> {
    let acct = app.account(did).await?;
    if acct.kem_pubkey.is_some() || acct.status.as_deref() == Some("deleted") {
        return Ok(Outcome::Skipped);
    }
    let key = crate::secrets::generate_kem_key();
    let (wrapped, pubkey) = app.secrets.wrap_kem_key(did, &key).await?;
    let did_key = format!("did:key:{pubkey}");
    let published = match &app.plc {
        Some(plc) => plc.publish_kem_key(did, &did_key, &app.public_url).await?,
        // the document of a DID minted here is the one this node generates
        None => !crate::xrpc::server::has_external_did(&acct),
    };
    // (submitPlcOperation's rule: no #identity for a taken-down account)
    let identity = published && acct.status.as_deref() != Some("takendown");
    let stored = pubkey.clone();
    let (_, after) = app
        .mutate_account(did, identity, false, false, move |a| {
            if a.kem_pubkey.is_some() {
                return Ok(false);
            }
            a.wrapped_kem_key = Some(wrapped);
            a.kem_pubkey = Some(stored);
            Ok(true)
        })
        .await?;
    app.did_resolver.invalidate(did);
    match after.kem_pubkey {
        Some(k) if k == pubkey => {}
        // another run stored its key between our read and our write
        Some(k) => {
            if let (Some(plc), true) = (&app.plc, published) {
                plc.publish_kem_key(did, &format!("did:key:{k}"), &app.public_url).await?;
            }
            return Ok(Outcome::Skipped);
        }
        None => return Err(XrpcError::internal("the KEM key was not stored")),
    }
    if !published {
        tracing::warn!(%did, kem_key = %did_key, "cannot publish kem key, account must update its did doc");
        return Ok(Outcome::Unpublished);
    }
    Ok(Outcome::Published)
}

/// With Spaces off: the accounts this node creates get no key, so the
/// records go and a later `--spaces` start scans again.
pub fn reset(app: &Arc<App>) {
    let app = app.clone();
    tokio::spawn(async move {
        let prefix = Path::from(format!("{}/kem-backfill", app.store.prefix));
        let listed: Vec<_> = app.store.raw.list(Some(&prefix)).collect().await;
        for m in listed {
            let r = match m {
                Ok(m) => app.store.raw.delete(&m.location).await,
                Err(e) => Err(e),
            };
            if let Err(e) = r {
                tracing::warn!("kem key backfill: clearing the shard records failed: {e}");
                return;
            }
        }
    });
}
