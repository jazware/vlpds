//! Operator reads of space data (`--spaces`; DESIGN.md "Spaces", Q6): an
//! account's repo in a space, its records and one record, for moderation.
//! Admin or the moderation service only. Every call writes an entry to the
//! moderation audit log (`vlpds.admin.getAuditLog`) before anything is
//! read, so no read happens without its trail; the console asks for a
//! reason. Taken-down records are shown, flagged.

use super::admin::require_moderator;
use super::moderation::{audit, ClientIp, SubjectRef, Who};
use super::space::{hidden_paths, load_head, spaces, takedown_name, Space};
use super::*;

pub fn routes() -> Router<Arc<App>> {
    Router::new()
        .route("/xrpc/vlpds.admin.getSpaceRepo", get(get_space_repo))
        .route("/xrpc/vlpds.admin.listSpaceRecords", get(list_space_records))
        .route("/xrpc/vlpds.admin.getSpaceRecord", get(get_space_record))
}

const MAX_REASON: usize = 2000;

fn reason(r: Option<&str>) -> XResult<Option<&str>> {
    let r = r.map(str::trim).filter(|r| !r.is_empty());
    if r.is_some_and(|r| r.chars().count() > MAX_REASON) {
        return Err(XrpcError::bad("InvalidRequest", format!("reason: longer than {MAX_REASON} characters")));
    }
    Ok(r)
}

/// The audit entry of one read, written before the read.
async fn audited(
    app: &App,
    creds: &Credentials,
    who: &Who,
    method: &str,
    subject: SubjectRef,
    reason: Option<&str>,
    detail: J,
) -> XResult<()> {
    require_moderator(creds)?;
    spaces(app)?;
    let mut detail = detail;
    detail["method"] = json!(method);
    audit(app, who, "space.read", Some(&subject), reason, None, Some(detail)).await?;
    crate::metrics::space_operator_read(method);
    Ok(())
}

fn record_json(uri: &str, v: &[u8], takendown: bool) -> XResult<J> {
    let (cid, bytes) = state::record_value_parts(v).map_err(XrpcError::from_err)?;
    let value = Value::decode(bytes).map_err(XrpcError::from_err)?;
    Ok(json!({"uri": uri, "cid": cid.to_string(), "value": value.to_json(), "takendown": takendown}))
}

#[derive(Deserialize)]
struct RepoQ {
    space: String,
    repo: String,
    reason: Option<String>,
    actor: Option<String>,
}

/// The account's repo in the space: its head and the records taken down.
async fn get_space_repo(
    State(app): AppState,
    Auth(creds): Auth,
    ClientIp(ip): ClientIp,
    Query(q): Query<RepoQ>,
) -> XResult<Json<J>> {
    let space = Space::parse(&q.space)?;
    let who = Who::of(&creds, q.actor.as_deref(), ip);
    let subject = SubjectRef::space_repo(&space.uri, &q.repo);
    let detail = json!({"space": space.uri, "repo": q.repo});
    audited(&app, &creds, &who, "getSpaceRepo", subject, reason(q.reason.as_deref())?, detail).await?;
    let p = app.partition(&q.repo)?;
    let head = load_head(spaces(&app)?, &p, &q.repo, &space)
        .await?
        .ok_or_else(|| XrpcError::bad("RepoNotFound", format!("{} has no repo in {}", q.repo, space.uri)))?;
    let created = (head.created != 0)
        .then(|| chrono::DateTime::from_timestamp_micros(head.created as i64))
        .flatten()
        .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Millis, true));
    Ok(Json(json!({
        "space": space.uri,
        "repo": q.repo,
        "rev": head.rev.to_string(),
        "records": head.records,
        "createdAt": created,
        "takendown": hidden_paths(&app, &q.repo, &space.sid).await?,
    })))
}

#[derive(Deserialize)]
struct ListQ {
    space: String,
    repo: String,
    collection: Option<String>,
    limit: Option<i64>,
    cursor: Option<String>,
    reason: Option<String>,
    actor: Option<String>,
}

/// Records in path order after `cursor` (a path), values included.
async fn list_space_records(
    State(app): AppState,
    Auth(creds): Auth,
    ClientIp(ip): ClientIp,
    Query(q): Query<ListQ>,
) -> XResult<Json<J>> {
    let space = Space::parse(&q.space)?;
    if let Some(c) = &q.collection {
        super::repo::check_path(c, None)?;
    }
    let limit = super::extract::limit_param(q.limit, 50, 1, 100)?;
    let who = Who::of(&creds, q.actor.as_deref(), ip);
    let subject = SubjectRef::space_repo(&space.uri, &q.repo);
    let detail = json!({"space": space.uri, "repo": q.repo, "collection": q.collection, "cursor": q.cursor});
    audited(&app, &creds, &who, "listSpaceRecords", subject, reason(q.reason.as_deref())?, detail).await?;
    let p = app.partition(&q.repo)?;
    if load_head(spaces(&app)?, &p, &q.repo, &space).await?.is_none() {
        return Ok(Json(json!({"records": []})));
    }
    let base = state::space_prefix(state::SPACE_RECORD_FAMILY, &q.repo, &space.sid);
    let prefix = match &q.collection {
        Some(c) => [&base[..], c.as_bytes(), b"/"].concat(),
        None => base.clone(),
    };
    let lo = match &q.cursor {
        Some(c) => [&base[..], c.as_bytes(), &[0]].concat().max(prefix.clone()),
        None => prefix.clone(),
    };
    let end = vlsync_store::keys::prefix_end(&prefix);
    let ctl = super::server::ctl(&app, &q.repo).await?;
    let mut records = Vec::new();
    let mut last = None;
    if lo < end {
        let mut iter = p.db.scan(lo..end).await.map_err(XrpcError::from_err)?;
        let rows = iter.next_batch(limit).await.map_err(XrpcError::from_err)?;
        for kv in rows {
            let path = std::str::from_utf8(&kv.key[base.len()..]).map_err(XrpcError::from_err)?;
            let hidden = ctl.has_takedown(&takedown_name(&space.sid, path));
            records.push(record_json(&format!("{}/{}/{path}", space.uri, q.repo), &kv.value, hidden)?);
            last = Some(path.to_string());
        }
    }
    let full = records.len() == limit;
    let mut out = json!({"records": records});
    if let (true, Some(path)) = (full, last) {
        out["cursor"] = json!(path);
    }
    Ok(Json(out))
}

#[derive(Deserialize)]
struct RecordQ {
    space: String,
    repo: String,
    collection: String,
    rkey: String,
    reason: Option<String>,
    actor: Option<String>,
}

/// One record, `{uri, cid, value}` as space.getRecord answers, plus whether
/// it is taken down.
async fn get_space_record(
    State(app): AppState,
    Auth(creds): Auth,
    ClientIp(ip): ClientIp,
    Query(q): Query<RecordQ>,
) -> XResult<Json<J>> {
    let space = Space::parse(&q.space)?;
    super::repo::check_path(&q.collection, Some(&q.rkey))?;
    let path = format!("{}/{}", q.collection, q.rkey);
    let uri = format!("{}/{}/{path}", space.uri, q.repo);
    let who = Who::of(&creds, q.actor.as_deref(), ip);
    let subject = SubjectRef::record(&uri, &q.repo);
    let detail = json!({"space": space.uri, "repo": q.repo, "collection": q.collection, "rkey": q.rkey});
    audited(&app, &creds, &who, "getSpaceRecord", subject, reason(q.reason.as_deref())?, detail).await?;
    let p = app.partition(&q.repo)?;
    let not_found = || XrpcError::bad("RecordNotFound", format!("Could not locate record: {uri}"));
    // the head names the space: a space id shared with another fails here
    if load_head(spaces(&app)?, &p, &q.repo, &space).await?.is_none() {
        return Err(not_found());
    }
    let v = p.db.get(state::space_record_key(&q.repo, &space.sid, &path)).await.map_err(XrpcError::from_err)?;
    let hidden = super::server::ctl(&app, &q.repo).await?.has_takedown(&takedown_name(&space.sid, &path));
    Ok(Json(record_json(&uri, &v.ok_or_else(not_found)?, hidden)?))
}
