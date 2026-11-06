//! Accounts' `#atproto_kem` keys (reference `kem-key-backfill.ts` and
//! createAccount): the dedicated P-256 key a syncer establishes a MAC
//! secret against ([`super::kem`]). This PDS holds the private half, wrapped
//! under the KEK (`Purpose::KemKey`) on the account (`Account::kem_key`).
//!
//! - A new account gets one at creation, in its PLC genesis op when this
//!   PDS mints the DID; otherwise (a DID minted ahead, a DID brought in) it
//!   is published afterwards, or by its owner.
//! - Accounts from before KEM keys get one from the backfill each node runs
//!   over its shards at start (`--spaces`). Where a server rotation key can
//!   still sign the account's PLC ops and its PDS is this one, the key is
//!   published and the account gets an `#identity` event; otherwise
//!   (did:web, a removed rotation key, migrated away) the key is kept and
//!   `cannot publish kem key, account must update its did doc` is logged.
//! - getRecommendedDidCredentials lists it, and submitPlcOperation refuses
//!   an op that doesn't (`Incorrect KEM key`), so a migration in carries it.
//!
//! An account without a published key can't serve MAC-bearing reads to a
//! syncer: there is nothing to derive a secret against.

use super::kem::KemKey;
use crate::state::{Account, KemKeyRow};
use crate::xrpc::App;
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use vlatproto::xrpc::XrpcError;

/// Accounts the backfill starts per second (each a directory read, and a
/// submit when it publishes).
const BACKFILL_PER_SECOND: f64 = 4.0;
const CACHE_ENTRIES: usize = 4096;

/// did -> (public multibase, key): an unwrap is a KMS call.
static CACHE: LazyLock<parking_lot::Mutex<lru::LruCache<String, (String, Arc<KemKey>)>>> = LazyLock::new(|| {
    parking_lot::Mutex::new(lru::LruCache::new(std::num::NonZeroUsize::new(CACHE_ENTRIES).expect("nonzero")))
});

/// A new key, wrapped for `did` (cached, so a new account never unwraps).
pub async fn make(app: &App, did: &str) -> Result<KemKeyRow, crate::secrets::SecretError> {
    wrap(app, did, KemKey::generate()).await
}

/// `key` wrapped for `did`, and cached.
pub async fn wrap(app: &App, did: &str, key: KemKey) -> Result<KemKeyRow, crate::secrets::SecretError> {
    let wrapped = app.secrets.wrap(crate::secrets::Purpose::KemKey, did, &key.to_bytes()).await?;
    let pubkey = key.public_multibase();
    CACHE.lock().put(did.to_string(), (pubkey.clone(), Arc::new(key)));
    Ok(KemKeyRow { wrapped, pubkey, published: false })
}

/// The account's KEM keypair (None: it has none yet), checked against its
/// public key.
pub async fn keypair(app: &App, acct: &Account) -> Result<Option<Arc<KemKey>>, XrpcError> {
    let Some(row) = &acct.kem_key else { return Ok(None) };
    if let Some((pk, k)) = CACHE.lock().get(&acct.did) {
        if *pk == row.pubkey {
            return Ok(Some(k.clone()));
        }
    }
    let u = app.secrets.unwrap(crate::secrets::Purpose::KemKey, &acct.did, &row.wrapped).await?;
    let key = KemKey::from_bytes(&u.plaintext)
        .filter(|k| k.public_multibase() == row.pubkey)
        .ok_or_else(|| XrpcError::internal(format!("the KEM key of {} does not match its public key", acct.did)))?;
    let key = Arc::new(key);
    CACHE.lock().put(acct.did.clone(), (row.pubkey.clone(), key.clone()));
    Ok(Some(key))
}

/// The account's key, made (and stored) if it has none. A key made by
/// another call meanwhile is the one kept.
pub async fn ensure_key(app: &App, did: &str) -> Result<KemKeyRow, XrpcError> {
    if let Some(k) = app.account(did).await?.kem_key {
        return Ok(k);
    }
    let made = make(app, did).await?;
    let (_, after) = app
        .mutate_account(did, false, false, false, move |a| {
            if a.kem_key.is_some() {
                return Ok(false);
            }
            a.kem_key = Some(made);
            Ok(true)
        })
        .await?;
    after.kem_key.ok_or_else(|| XrpcError::internal("the KEM key was not stored"))
}

/// What [`ensure_published`] found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Published {
    /// Listed before this call.
    Already,
    /// Listed by this call (an `#identity` event went out).
    Now,
    /// Not ours to list: the owner must.
    Owner,
    /// The account isn't active here (yet): not tried.
    Inactive,
}

/// The account's key made if needed, and listed in its DID document where
/// this PDS can list it.
pub async fn ensure_published(app: &App, did: &str) -> Result<Published, XrpcError> {
    let row = ensure_key(app, did).await?;
    if row.published {
        return Ok(Published::Already);
    }
    let acct = app.account(did).await?;
    if acct.status.is_some() {
        return Ok(Published::Inactive);
    }
    let did_key = format!("did:key:{}", row.pubkey);
    let outcome = match &app.plc {
        // no directory: the document generated here is the account's
        None => Some(Published::Now),
        Some(_) if !did.starts_with("did:plc:") => None,
        Some(plc) => match plc.update_kem_key(did, &did_key, &app.public_url).await {
            Ok(crate::plc::KemPublish::Published) => Some(Published::Now),
            Ok(crate::plc::KemPublish::Already) => Some(Published::Already),
            Ok(crate::plc::KemPublish::Foreign | crate::plc::KemPublish::Elsewhere) => None,
            Err(crate::plc::PlcError::NotFound(_) | crate::plc::PlcError::Tombstoned) => None,
            Err(e) => return Err(e.into()),
        },
    };
    let Some(outcome) = outcome else {
        tracing::warn!(%did, "cannot publish kem key, account must update its did doc");
        return Ok(Published::Owner);
    };
    app.did_resolver.invalidate(did);
    let pubkey = row.pubkey.clone();
    app.mutate_account(did, outcome == Published::Now, false, false, move |a| match &mut a.kem_key {
        Some(k) if k.pubkey == pubkey && !k.published => {
            k.published = true;
            Ok(true)
        }
        _ => Ok(false),
    })
    .await?;
    Ok(outcome)
}

/// [`ensure_published`] in the background (an account just made, or just
/// activated), logged when it fails: the next backfill tries again.
pub fn spawn_ensure(app: &Arc<App>, did: &str) {
    if app.spaces.is_none() {
        return;
    }
    let (app, did) = (app.clone(), did.to_string());
    tokio::spawn(async move {
        if let Err(e) = ensure_published(&app, &did).await {
            tracing::info!(%did, "kem key not published yet (the backfill retries): {}", e.message);
        }
    });
}

/// The node's backfill (with `--spaces`): every account of its shards
/// without a published key, a few per second, once per start.
pub fn start_backfill(app: &Arc<App>) {
    let weak = Arc::downgrade(app);
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(5)).await;
        let Some(app) = weak.upgrade() else { return };
        match backfill(&app).await {
            Ok((made, published, owner, failed)) => {
                if made + published + owner + failed > 0 {
                    tracing::info!(made, published, owner, failed, "kem key backfill complete");
                }
            }
            Err(e) => tracing::warn!("kem key backfill failed: {e:#}"),
        }
    });
}

/// (keys made, published, left to their owners, failed).
pub async fn backfill(app: &App) -> anyhow::Result<(u64, u64, u64, u64)> {
    let mut todo = Vec::new();
    for p in app.partitions.owned() {
        let opts = slatedb::config::ScanOptions::default();
        let mut it = crate::state::FamilyScan::new(&*p.db, crate::state::ACCOUNT_FAMILY, None, &opts).await?;
        while let Some(kv) = it.next().await? {
            let Ok(a) = serde_json::from_slice::<Account>(&kv.value) else { continue };
            if matches!(a.status.as_deref(), Some("deleted")) || a.kem_key.as_ref().is_some_and(|k| k.published) {
                continue;
            }
            todo.push((a.did, a.kem_key.is_none()));
        }
    }
    let period = Duration::from_secs_f64(1.0 / BACKFILL_PER_SECOND);
    let (mut made, mut published, mut owner, mut failed) = (0, 0, 0, 0);
    for (did, new) in todo {
        tokio::time::sleep(period).await;
        match ensure_published(app, &did).await {
            Ok(p) => {
                made += new as u64;
                match p {
                    Published::Now | Published::Already => published += 1,
                    Published::Owner => owner += 1,
                    Published::Inactive => {}
                }
            }
            Err(e) => {
                failed += 1;
                tracing::warn!(%did, "kem key backfill of an account failed: {}", e.message);
            }
        }
    }
    Ok((made, published, owner, failed))
}
