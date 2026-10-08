//! Signing-key rotation (DESIGN.md "Signing-key rotation"): `Begin` records
//! the new key as pending (before any directory can name it, and repo
//! writes are refused from then on), the PLC directory is updated, `Finish`
//! re-signs the head. A rotation stopped in between stays pending until
//! [`complete`] drives it to its end from durable state alone: the admin
//! re-running `updateAccountSigningKey`, or the first write it fences
//! ([`kick`]). Only a definite refusal by a directory that doesn't name the
//! key abandons it.

use super::*;
use crate::plc::PlcError;
use crate::state::PendingSigningKey;
use crate::worker::{AccountOp, KeyStep};
use std::collections::HashSet;
use std::time::Duration;

/// A failed kick holds its slot this long, so writers retrying against a
/// directory outage don't each start a PLC round trip.
const KICK_BACKOFF: Duration = Duration::from_secs(1);

const INTERRUPTED: &str = "KeyRotationInterrupted";

pub use vlsync_store::lifecycle::CrashHook;

/// Phases of a DID's rotation: "begun" (the pending key is durable) and
/// "plc_updated" (the directory names it, the repo isn't re-signed yet).
/// The test halts the node in the hook.
static CRASH_HOOKS: vlsync_store::lifecycle::CrashHooks = vlsync_store::lifecycle::CrashHooks::new();

pub fn set_crash_hook(did: &str, h: Option<CrashHook>) {
    CRASH_HOOKS.set(did, h)
}

fn crash_at(did: &str, phase: &str) -> Result<(), XrpcError> {
    match CRASH_HOOKS.fires(did, phase) {
        true => Err(XrpcError::bad(INTERRUPTED, format!("key rotation of {did} stopped at {phase} (crash hook)"))),
        false => Ok(()),
    }
}

/// DIDs whose rotation this node is driving. Kicks skip a held DID; the
/// admin path drives regardless. Only an economy: every step is safe to
/// repeat or race.
static DRIVING: parking_lot::Mutex<Option<HashSet<String>>> = parking_lot::Mutex::new(None);

struct Driving(String);

impl Driving {
    fn take(did: &str) -> Option<Driving> {
        DRIVING.lock().get_or_insert_with(HashSet::new).insert(did.to_string()).then(|| Driving(did.to_string()))
    }
}

impl Drop for Driving {
    fn drop(&mut self) {
        if let Some(s) = DRIVING.lock().as_mut() {
            s.remove(&self.0);
        }
    }
}

/// Whether a driver (an admin call or a kick, incl. a failed kick's
/// backoff) holds `did` on this node.
pub fn driving(did: &str) -> bool {
    DRIVING.lock().as_ref().is_some_and(|s| s.contains(did))
}

pub enum Done {
    Finished(Head),
    /// The directory refused the new key and doesn't name it.
    Aborted(XrpcError),
}

/// Whether the directory names `did_key` as the `atproto` key.
async fn plc_names(plc: &crate::plc::Plc, did: &str, did_key: &str) -> Result<bool, PlcError> {
    match plc.last_op(did).await {
        Ok(last) => Ok(crate::plc::normalize(&last)["verificationMethods"]["atproto"] == did_key),
        Err(PlcError::Tombstoned) => Ok(false),
        Err(e) => Err(e),
    }
}

/// Idempotent: once the rotation finished, a repeat changes nothing (Finish
/// of the current key is a no-op). `key`: the new key, if the caller holds
/// it (else unwrapped from `p`). Err: undecided; the rotation is still
/// pending.
pub async fn complete(
    app: &App,
    did: &str,
    p: &PendingSigningKey,
    key: Option<Arc<Keypair>>,
) -> Result<Done, XrpcError> {
    let did_key = format!("did:key:{}", p.pubkey);
    if let (Some(plc), true) = (&app.plc, did.starts_with("did:plc:")) {
        match plc.update_signing_key(did, &did_key).await {
            Ok(_) => {}
            // maybe applied: decided on a later attempt
            Err(e @ PlcError::Unavailable(_)) => return Err(e.into()),
            // refused; the key stays unless an earlier attempt (a racing
            // driver) already made it the document's
            Err(e) => {
                if !plc_names(plc, did, &did_key).await? {
                    tracing::warn!(%did, key = %did_key, "signing key rotation abandoned: PLC refused the new key: {e}");
                    app.account_op(did, AccountOp::SigningKey(KeyStep::Abort { pubkey: p.pubkey.clone() })).await?;
                    return Ok(Done::Aborted(e.into()));
                }
            }
        }
    }
    crash_at(did, "plc_updated")?;
    let key = match key {
        Some(k) => k,
        None => app.secrets.signing_key(did, &p.wrapped, &p.pubkey).await?,
    };
    let head = app.account_op(did, AccountOp::SigningKey(KeyStep::Finish { key })).await?;
    app.did_resolver.invalidate(did);
    tracing::info!(%did, key = %did_key, rev = %head.rev, "signing key rotated, repo re-signed");
    Ok(Done::Finished(head))
}

fn pending_hint(mut e: XrpcError) -> XrpcError {
    if e.status.is_server_error() {
        e.message = format!(
            "{}; the rotation is pending (writes are refused): retry updateAccountSigningKey to finish it",
            e.message
        );
    }
    e
}

/// The new key's did:key once the repo is re-signed with it. On an
/// undecided failure the rotation stays pending: a retry finishes it
/// ([`finish_pending`]), as does the next write it fences ([`kick`]).
pub(super) async fn rotate(app: &App, did: &str, key: Keypair) -> XResult<String> {
    let key = Arc::new(key);
    let did_key = key.did_key();
    // wrapped for the row; cached unwrapped too (the re-sign needs no unwrap)
    let (wrapped, pubkey) = app.secrets.wrap_signing_key(did, &key).await?;
    let p = PendingSigningKey { wrapped, pubkey };
    let _driving = Driving::take(did);
    app.account_op(did, AccountOp::SigningKey(KeyStep::Begin(p.clone()))).await?;
    crash_at(did, "begun")?;
    match complete(app, did, &p, Some(key)).await.map_err(pending_hint)? {
        Done::Finished(_) => Ok(did_key),
        Done::Aborted(e) => Err(e),
    }
}

/// A retried `updateAccountSigningKey` on an account with a rotation
/// pending finishes that rotation. `requested`: the did:key the retry
/// asked for, if any; a different one than the pending key is refused once
/// the pending rotation is finished (left reserved, for the next call).
pub(super) async fn finish_pending(
    app: &App,
    did: &str,
    p: &PendingSigningKey,
    requested: Option<&str>,
) -> XResult<String> {
    let did_key = format!("did:key:{}", p.pubkey);
    let _driving = Driving::take(did);
    match complete(app, did, p, None).await.map_err(pending_hint)? {
        Done::Finished(_) => {}
        Done::Aborted(e) => return Err(e),
    }
    match requested {
        Some(r) if r != did_key => Err(XrpcError::bad(
            "InvalidRequest",
            format!("an interrupted rotation to {did_key} was pending and is now finished; {r} was not used (still reserved): retry to rotate to it"),
        )),
        _ => Ok(did_key),
    }
}

/// A write fenced by a pending rotation: finish it in the background, one
/// driver per DID. A DID whose key is merely unavailable (key service
/// down) has nothing pending, and the kick ends at the account read.
pub(super) fn kick(app: &Arc<App>, did: &str) {
    let Some(driving) = Driving::take(did) else { return };
    let (app, did) = (app.clone(), did.to_string());
    tokio::spawn(async move {
        let r = match app.account(&did).await {
            Ok(acct) => match acct.pending_signing_key {
                Some(p) => complete(&app, &did, &p, None).await.map(|_| ()),
                None => Ok(()),
            },
            Err(e) => Err(e),
        };
        if let Err(e) = r {
            tracing::warn!(%did, "pending signing key rotation not finished yet: {}", e.message);
            tokio::time::sleep(KICK_BACKOFF).await;
        }
        drop(driving);
    });
}
