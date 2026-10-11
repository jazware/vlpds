//! Expiry sweep for owner-auth rows.
//!
//! Transactions and grants carry their own routing key (`auth:…`), so the
//! sweep finds them the way the OAuth GC finds request rows: one scan of the
//! local partitions by routing prefix. A row is deleted only if it is still
//! the one that was read, so a sweep racing a live login loses.

use super::store;
use super::*;

/// How often to sweep. Rows are short-lived and harmless when late.
const SWEEP_EVERY: std::time::Duration = std::time::Duration::from_secs(300);

/// Delete this node's expired transactions and grants. Returns how many.
pub async fn sweep(app: &App) -> XResult<usize> {
    let now = now_secs();
    let mut removed = 0;
    for (routing, name, val) in super::server::scan_private_routing(app, "auth:").await? {
        let dead = if name == store::TXN_ROW {
            serde_json::from_slice::<store::Txn>(&val).map(|t| t.expired(now)).unwrap_or(true)
        } else if name == "g" {
            serde_json::from_slice::<store::Grant>(&val).map(|g| g.exp < now).unwrap_or(true)
        } else {
            false
        };
        if !dead {
            continue;
        }
        let out = app
            .private_cas(&routing, vec![cas::Cond::eq(&name, Some(val.clone()))], vec![cas::Op::put(&name, None)])
            .await?;
        if out.applied {
            removed += 1;
        }
    }
    Ok(removed)
}

pub fn spawn(app: Arc<App>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(SWEEP_EVERY);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            match sweep(&app).await {
                Ok(0) => {}
                Ok(n) => tracing::debug!(removed = n, "owner-auth sweep removed expired rows"),
                Err(e) => tracing::debug!("owner-auth sweep failed: {}", e.message),
            }
        }
    });
}
