//! `vlpds.admin.setFeatureLevel` (DESIGN.md "Rolling upgrades and format
//! versioning").

use super::*;
use crate::cluster::FinalizeError;

pub fn routes() -> Router<Arc<App>> {
    Router::new().route("/xrpc/vlpds.admin.setFeatureLevel", post(set_feature_level))
}

#[derive(Deserialize)]
struct SetIn {
    level: u32,
    /// Only past levels that gate wire behavior (non-persistent ones).
    #[serde(default)]
    lower: bool,
    actor: Option<String>,
}

/// 200 with the new `cluster/version`; 400 `InvalidRequest` (a raise not
/// above the active level or past this node's build; a lower past a
/// persistent level or during a raise); 409 `IncompatibleNodes` (live nodes
/// whose builds can't run it: nothing changed); 503 on a store error or a
/// concurrent change (retry).
async fn set_feature_level(
    State(app): AppState,
    Auth(creds): Auth,
    super::moderation::ClientIp(ip): super::moderation::ClientIp,
    Json(inp): Json<SetIn>,
) -> XResult<Json<J>> {
    use super::moderation::{audit, SubjectRef, Who};
    super::admin::require_admin(&creds)?;
    let Some(c) = &app.cluster else {
        return Err(XrpcError::bad("InvalidRequest", "not running as a cluster node"));
    };
    let by = format!("admin@{}", c.cfg.node_id);
    let r = if inp.lower { c.lower_level(inp.level, &by).await } else { c.finalize_level(inp.level, &by).await };
    match r {
        Ok(v) => {
            let detail = json!({"level": inp.level, "lower": inp.lower, "active": v.active});
            let who = Who::of(&creds, inp.actor.as_deref(), ip);
            let subject = SubjectRef::other("config", "featureLevel");
            audit(&app, &who, "feature_level.set", Some(&subject), None, None, Some(detail)).await?;
            Ok(Json(json!({"active": v.active, "target": v.target, "history": v.history})))
        }
        Err(FinalizeError::Invalid(m)) => Err(XrpcError::bad("InvalidRequest", m)),
        Err(e @ FinalizeError::Incompatible { .. }) => {
            Err(XrpcError { status: StatusCode::CONFLICT, error: "IncompatibleNodes".into(), message: e.to_string() })
        }
        Err(e @ FinalizeError::Store(_)) => Err(XrpcError::unavailable("Unavailable", e.to_string())),
    }
}
