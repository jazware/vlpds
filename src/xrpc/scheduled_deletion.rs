//! Deletes deactivated accounts whose `deleteAfter` has passed.
//!
//! `com.atproto.server.deactivateAccount` takes an optional `deleteAfter`:
//! the client's suggestion of how long to keep the deactivated account. The
//! worker mirrors it into `D/{did}` in the account's slot (state.rs), so each
//! node's sweep finds the scheduled accounts of the shards it owns with one
//! family scan, and a shard move carries the rows along with the accounts.
//!
//! An account is due once `deleteAfter` has passed and it has been
//! deactivated for at least `Config::delete_after_min_hold`. Taken-down and
//! suspended accounts are held (moderation keeps them); reactivating clears
//! `deleteAfter`. The deletion is the deleteAccount path, with the repo
//! delete refused in the worker unless the account is still due, so a
//! reactivation racing the sweep wins. `D/` outlives the repo delete: a
//! deletion that stopped partway is finished by the next pass.

use super::server::{delete_from, finish_delete, DeleteFrom};
use super::*;
use chrono::{DateTime, Utc};
use std::time::Duration;

pub const INTERVAL: Duration = Duration::from_secs(600);
/// Deletions per pass, all shards together.
pub const MAX_PER_PASS: usize = 100;

/// When `a` gets deleted. None: never (no `deleteAfter`, not deactivated,
/// or taken down / suspended).
pub fn due_at(a: &Account, min_hold: Duration) -> Option<DateTime<Utc>> {
    if a.status.as_deref() != Some("deactivated") || a.extra.get("takedownRef").is_some_and(|v| !v.is_null()) {
        return None;
    }
    let at = |k: &str| {
        a.extra.get(k).and_then(|v| v.as_str()).and_then(|t| DateTime::parse_from_rfc3339(t).ok()).map(|t| t.to_utc())
    };
    let delete_after = at("deleteAfter")?;
    let hold = chrono::Duration::from_std(min_hold).unwrap_or(chrono::Duration::MAX);
    let held_until = at("deactivatedAt").and_then(|t| t.checked_add_signed(hold)).unwrap_or(DateTime::<Utc>::MAX_UTC);
    Some(delete_after.max(held_until))
}

/// `deletionScheduledAt` for getSession and the admin account view: when
/// the sweep deletes `a`, if it will.
pub fn scheduled_at(app: &App, a: &Account) -> Option<String> {
    let t = due_at(a, app.config.delete_after_min_hold?)?;
    Some(t.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Swept {
    pub deleted: usize,
    /// Deletions that had stopped partway, finished.
    pub finished: usize,
    /// Due but taken down or suspended.
    pub held: usize,
    /// Reactivated while being deleted: kept.
    pub raced: usize,
    pub failed: usize,
}

enum Outcome {
    Deleted,
    Finished,
    Held,
    Raced,
    Kept,
}

/// One pass over the `D/` rows of this node's shards, as of `now`.
pub async fn sweep(app: &App, now: DateTime<Utc>, max: usize) -> Swept {
    let mut out = Swept::default();
    let Some(min_hold) = app.config.delete_after_min_hold else { return out };
    let started = std::time::Instant::now();
    let fam = state::DELETE_AFTER_FAMILY;
    let mut found = Vec::new();
    let mut scan_failed = false;
    for p in app.partitions.owned() {
        let scan = async {
            let mut it = state::FamilyScan::new(p.db.as_ref(), fam, None, &Default::default()).await?;
            while let Some(kv) = it.next().await? {
                found.push(String::from_utf8_lossy(&vlsync_store::keys::key_body(&kv.key)[fam.len()..]).into_owned());
            }
            Ok::<_, slatedb::Error>(())
        };
        if let Err(e) = scan.await {
            scan_failed = true;
            tracing::warn!(shard = %p.id, error = %e, "scheduled deletions: scan failed");
        }
    }
    let scheduled = found.len();
    let mut visited = 0;
    for did in found {
        if out.deleted + out.finished >= max {
            break;
        }
        visited += 1;
        match sweep_one(app, &did, now, min_hold).await {
            Ok(Outcome::Deleted) => {
                out.deleted += 1;
                tracing::info!(%did, "scheduled deletion: account deleted");
            }
            Ok(Outcome::Finished) => out.finished += 1,
            Ok(Outcome::Held) => out.held += 1,
            Ok(Outcome::Raced) => {
                out.raced += 1;
                tracing::info!(%did, "scheduled deletion: reactivated first, kept");
            }
            Ok(Outcome::Kept) => {}
            Err(e) => {
                out.failed += 1;
                tracing::warn!(%did, error = %e.message, "scheduled deletion failed (retried next sweep)");
            }
        }
    }
    if out.deleted + out.finished + out.raced + out.failed > 0 {
        tracing::info!(
            deleted = out.deleted,
            finished = out.finished,
            held = out.held,
            raced = out.raced,
            failed = out.failed,
            "scheduled deletions"
        );
    }
    use crate::metrics as m;
    for (r, n) in [("deleted", out.deleted), ("finished", out.finished), ("raced", out.raced), ("failed", out.failed)] {
        m::SCHEDULED_DELETION_ACCOUNTS.with_label_values(&[r]).inc_by(n as u64);
    }
    for (state, n) in [("scheduled", scheduled), ("held", out.held), ("deferred", scheduled - visited)] {
        m::SCHEDULED_DELETION_STATE.with_label_values(&[state]).set(n as i64);
    }
    let result = if scan_failed || out.failed > 0 { "error" } else { "ok" };
    m::SCHEDULED_DELETION_PASSES.with_label_values(&[result]).inc();
    m::SCHEDULED_DELETION_PASS_SECONDS.observe(started.elapsed().as_secs_f64());
    out
}

async fn sweep_one(app: &App, did: &str, now: DateTime<Utc>, min_hold: Duration) -> XResult<Outcome> {
    // moved away since the scan: its new owner sweeps it
    app.partition(did)?;
    let from = match delete_from(app, did).await {
        Ok(f) => f,
        Err(e) if e.error == "AccountNotFound" => {
            // deleted by other means
            drop_row(app, did).await?;
            return Ok(Outcome::Kept);
        }
        Err(e) => return Err(e),
    };
    match from {
        DeleteFrom::Leftovers(_) => {
            finish_delete(app, did, from, "delete_after", None).await?;
            drop_row(app, did).await?;
            Ok(Outcome::Finished)
        }
        DeleteFrom::Unreadable => Err(XrpcError::internal("account row unreadable")),
        DeleteFrom::Account(_) => {
            let a = app.account(did).await?;
            if a.extra.get("deleteAfter").is_none_or(|v| v.is_null()) {
                // a row left by a deletion of an earlier account of this DID:
                // rewriting the account rewrites its row
                app.mutate_account(did, false, false, false, |_| Ok(true)).await?;
                return Ok(Outcome::Kept);
            }
            if !due_at(&a, min_hold).is_some_and(|t| t <= now) {
                let held = super::server::is_takendown_account(&a) || a.extra.get("takedownRef").is_some();
                return Ok(if held { Outcome::Held } else { Outcome::Kept });
            }
            let check: crate::worker::AccountCheck = Box::new(move |a| match due_at(a, min_hold) {
                Some(t) if t <= now => Ok(()),
                _ => Err(WriteError::Invalid("no longer scheduled for deletion".into())),
            });
            match finish_delete(app, did, from, "delete_after", Some(check)).await {
                Err(e) if e.error == "InvalidRequest" => return Ok(Outcome::Raced),
                r => r?,
            }
            drop_row(app, did).await?;
            Ok(Outcome::Deleted)
        }
    }
}

/// Local only: `/internal` writes take private rows alone, so a shard
/// that moved fails this and its new owner drops the row.
async fn drop_row(app: &App, did: &str) -> XResult<()> {
    let p = app.partition(did)?;
    write_private_local(
        &p,
        vec![vlsync_store::segment::Mutation { key: state::delete_after_key(did).into(), val: None }],
    )
    .await
}

pub fn spawn(app: Arc<App>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if app.config.delete_after_min_hold.is_none() {
            return;
        }
        crate::metrics::init_scheduled_deletion_counters();
        let mut tick = tokio::time::interval(INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            sweep(&app, Utc::now(), MAX_PER_PASS).await;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account(extra: &[(&str, &str)], status: Option<&str>) -> Account {
        let mut a: Account = serde_json::from_value(json!({
            "did": "did:plc:x", "handle": "x.test", "signing_pubkey": "", "password_hash": "", "created_at": ""
        }))
        .unwrap_or_default();
        a.status = status.map(String::from);
        for (k, v) in extra {
            a.extra.insert((*k).into(), json!(v));
        }
        a
    }

    fn t(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().to_utc()
    }

    #[test]
    fn due_is_the_later_of_delete_after_and_the_hold() {
        let day = Duration::from_secs(86_400);
        let a = account(
            &[("deactivatedAt", "2026-01-01T00:00:00Z"), ("deleteAfter", "2026-01-02T00:00:00Z")],
            Some("deactivated"),
        );
        assert_eq!(due_at(&a, Duration::ZERO), Some(t("2026-01-02T00:00:00Z")));
        assert_eq!(due_at(&a, 3 * day), Some(t("2026-01-04T00:00:00Z")));
        let past = account(
            &[("deactivatedAt", "2026-01-01T00:00:00Z"), ("deleteAfter", "2000-01-01T00:00:00Z")],
            Some("deactivated"),
        );
        assert_eq!(due_at(&past, 3 * day), Some(t("2026-01-04T00:00:00Z")));
    }

    #[test]
    fn never_due_unless_deactivated_with_delete_after() {
        let both = [("deactivatedAt", "2026-01-01T00:00:00Z"), ("deleteAfter", "2026-01-02T00:00:00Z")];
        assert_eq!(due_at(&account(&both, None), Duration::ZERO), None);
        assert_eq!(due_at(&account(&both, Some("takendown")), Duration::ZERO), None);
        assert_eq!(due_at(&account(&both, Some("suspended")), Duration::ZERO), None);
        let mut td = account(&both, Some("deactivated"));
        td.extra.insert("takedownRef".into(), json!("r"));
        assert_eq!(due_at(&td, Duration::ZERO), None);
        assert_eq!(due_at(&account(&both[..1], Some("deactivated")), Duration::ZERO), None);
        let bad = [("deactivatedAt", "2026-01-01T00:00:00Z"), ("deleteAfter", "soon")];
        assert_eq!(due_at(&account(&bad, Some("deactivated")), Duration::ZERO), None);
    }
}
