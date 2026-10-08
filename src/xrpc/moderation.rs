//! Operator moderation (docs/operations/email-and-moderation.md): takedowns and
//! restores with a reason and an audit trail, blob quarantine, a case queue
//! and subject lookup for the console's Moderation page.
//!
//! Takedown state itself stays where enforcement reads it (`sec/td/` rows
//! and the account's `takedownRef`, admin.rs). The operator's records are
//! control-plane objects in the bucket, like `config/ratelimits.json`:
//! low-volume, read from any node, and independent of which node owns an
//! account's shard (they outlive a shard move or the account itself).
//!
//!   {prefix}/moderation/audit/{micros:016x}-{rand}.json  one immutable entry
//!                                                        per action
//!   {prefix}/moderation/cases/{id}.json                  a case (ETag CAS)
//!   {prefix}/moderation/takedowns/{kind}/{key}.json      index of active
//!                                                        takedowns
//!   {prefix}/blob-quarantine/{did}/{cid}                 a taken-down blob's
//!                                                        bytes until purged
//!
//! One object per entry rather than one document: concurrent actions never
//! contend, and the audit log is append-only.

use super::admin::require_admin;
use super::server::{get_json, now_ms};
use super::*;
use futures::StreamExt;
use object_store::ObjectStore;
use sha2::{Digest, Sha256};
use std::time::Duration;

/// Bucket prefix of quarantined blob bytes (beside `blob/`, never served).
pub(super) const QUARANTINE: &str = "blob-quarantine";
const MAX_REASON: usize = 2000;
const MAX_NOTE: usize = 4000;
const CASE_CAS_RETRIES: usize = 8;
const AUDIT_PAGE: usize = 200;
const STATUSES: [&str; 4] = ["open", "actioned", "dismissed", "restored"];

pub fn routes() -> Router<Arc<App>> {
    Router::new()
        .route("/xrpc/vlpds.admin.resolveSubject", get(resolve_subject))
        .route("/xrpc/vlpds.admin.getSubject", get(get_subject))
        .route("/xrpc/vlpds.admin.moderate", post(moderate))
        .route("/xrpc/vlpds.admin.listTakedowns", get(list_takedowns))
        .route("/xrpc/vlpds.admin.getAuditLog", get(get_audit_log))
        .route("/xrpc/vlpds.admin.listCases", get(list_cases))
        .route("/xrpc/vlpds.admin.getCase", get(get_case))
        .route("/xrpc/vlpds.admin.createCase", post(create_case))
        .route("/xrpc/vlpds.admin.updateCase", post(update_case))
        .route("/xrpc/vlpds.admin.setBlobQuota", post(set_blob_quota))
        .route("/xrpc/vlpds.admin.listOverQuota", get(list_over_quota))
        .route("/xrpc/vlpds.admin.resetSecondFactors", post(reset_second_factors))
}

/// The client address for audit entries (as the rate-limit config's).
pub struct ClientIp(pub Option<std::net::IpAddr>);

impl axum::extract::FromRequestParts<Arc<App>> for ClientIp {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        app: &Arc<App>,
    ) -> Result<Self, Self::Rejection> {
        Ok(ClientIp(crate::ratelimit::request_client_ip(&parts.headers, &parts.extensions, &app.ratelimit.trusted)))
    }
}

/// Who acted: the operator a proxy named, "admin" (or a name the console
/// sends with the admin token), the moderation service's DID, or "system"
/// (quarantine expiry).
pub struct Who {
    pub actor: String,
    pub ip: Option<String>,
    /// How the actor got in: `proxy` (the login was verified by the admin
    /// listener's proxy), `token` (the admin token: `actor` is only what the
    /// caller typed) or `service` (the moderation service's JWT). None: vlpds
    /// itself.
    pub auth: Option<&'static str>,
}

impl Who {
    /// An operator call's actor. A proxy-named operator is who the proxy
    /// said, whatever `actor` the body claims; the token can't tell people
    /// apart, so the name the console sends stands for it.
    pub fn of(creds: &Credentials, actor: Option<&str>, ip: Option<std::net::IpAddr>) -> Who {
        let (actor, auth) = match creds {
            Credentials::ModService { iss } => (iss.clone(), "service"),
            _ => match creds.operator() {
                Some(login) => (login.to_string(), "proxy"),
                None => (actor_of(actor), "token"),
            },
        };
        Who { actor, ip: ip.map(|i| i.to_string()), auth: Some(auth) }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubjectRef {
    /// account, record, blob, space or spaceRepo. Audit entries of operator
    /// changes can also name a shard, node, domain (a served handle domain)
    /// or config (a cluster-wide setting) by `id`, with an empty `did`.
    pub kind: String,
    /// Always written, empty or not, so a build without `id` still reads
    /// every entry.
    pub did: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

impl SubjectRef {
    pub fn account(did: &str) -> SubjectRef {
        SubjectRef { kind: "account".into(), did: did.into(), uri: None, cid: None, id: None }
    }

    pub fn blob(did: &str, cid: &str) -> SubjectRef {
        SubjectRef { kind: "blob".into(), did: did.into(), uri: None, cid: Some(cid.into()), id: None }
    }

    pub fn record(uri: &str, did: &str) -> SubjectRef {
        SubjectRef { kind: "record".into(), did: did.into(), uri: Some(uri.into()), cid: None, id: None }
    }

    /// `did`'s repo in the space `uri` (operator reads; never taken down).
    pub fn space_repo(uri: &str, did: &str) -> SubjectRef {
        SubjectRef { kind: "spaceRepo".into(), did: did.into(), uri: Some(uri.into()), cid: None, id: None }
    }

    /// A space (`uri`) at its authority `did`.
    pub fn space(uri: &str, did: &str) -> SubjectRef {
        SubjectRef { kind: "space".into(), did: did.into(), uri: Some(uri.into()), cid: None, id: None }
    }

    /// The subject of an operator change that has no account: `kind` is
    /// shard, node, domain or config.
    pub fn other(kind: &str, id: impl ToString) -> SubjectRef {
        SubjectRef { kind: kind.into(), did: String::new(), uri: None, cid: None, id: Some(id.to_string()) }
    }

    /// Distinguishes the subject within its kind (index key, case de-dup).
    fn key(&self) -> String {
        if let Some(id) = &self.id {
            return id.clone();
        }
        match self.kind.as_str() {
            "record" | "space" => self.uri.clone().unwrap_or_default(),
            "spaceRepo" => format!("{} {}", self.uri.as_deref().unwrap_or(""), self.did),
            "blob" => format!("{}/{}", self.did, self.cid.as_deref().unwrap_or("")),
            _ => self.did.clone(),
        }
    }

    fn same(&self, o: &SubjectRef) -> bool {
        self.kind == o.kind && self.key() == o.key()
    }
}

pub struct Action {
    pub applied: bool,
    pub reason: Option<String>,
    pub r#ref: Option<String>,
    pub case_id: Option<String>,
}

#[derive(Clone, Debug, serde::Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditEntry {
    pub id: String,
    pub at: String,
    pub actor: String,
    /// [`Who::auth`]: `proxy`, `token` or `service`; absent for vlpds's own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    pub node: String,
    /// takedown, restore, blob.purge, case.create, case.update, quota.set,
    /// second_factors.reset, and every other operator write
    /// ([`super::admin_audit::AUDITED`])
    pub action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<SubjectRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub case_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<J>,
}

pub(super) fn node_id(app: &App) -> String {
    app.cluster.as_ref().map(|c| c.cfg.node_id.clone()).unwrap_or_else(|| "single".into())
}

fn path(app: &App, rel: &str) -> object_store::path::Path {
    object_store::path::Path::from(format!("{}/moderation/{rel}", app.store.prefix))
}

pub(super) fn quarantine_path(app: &App, did: &str, cid: impl std::fmt::Display) -> object_store::path::Path {
    object_store::path::Path::from(format!("{}/{QUARANTINE}/{did}/{cid}", app.store.prefix))
}

fn index_path(app: &App, s: &SubjectRef) -> object_store::path::Path {
    let h = hex::encode(&Sha256::digest(s.key().as_bytes())[..16]);
    path(app, &format!("takedowns/{}/{h}.json", s.kind))
}

fn store_err(e: object_store::Error) -> XrpcError {
    XrpcError::unavailable("Unavailable", format!("moderation store: {e}"))
}

async fn get_obj<T: serde::de::DeserializeOwned>(
    app: &App,
    p: &object_store::path::Path,
) -> XResult<Option<(T, Option<String>)>> {
    match app.store.raw.get(p).await {
        Ok(r) => {
            let etag = r.meta.e_tag.clone();
            let b = r.bytes().await.map_err(store_err)?;
            Ok(Some((serde_json::from_slice(&b).map_err(XrpcError::from_err)?, etag)))
        }
        Err(object_store::Error::NotFound { .. }) => Ok(None),
        Err(e) => Err(store_err(e)),
    }
}

async fn put_obj<T: serde::Serialize>(
    app: &App,
    p: &object_store::path::Path,
    v: &T,
    mode: PutMode,
) -> Result<(), object_store::Error> {
    let body = serde_json::to_vec_pretty(v).expect("serializable");
    app.store.raw.put_opts(p, PutPayload::from(body), PutOptions { mode, ..Default::default() }).await.map(|_| ())
}

async fn delete_obj(app: &App, p: &object_store::path::Path) -> XResult<()> {
    match app.store.raw.delete(p).await {
        Ok(()) | Err(object_store::Error::NotFound { .. }) => Ok(()),
        Err(e) => Err(store_err(e)),
    }
}

async fn list_metas(app: &App, rel: &str) -> XResult<Vec<object_store::ObjectMeta>> {
    let root = path(app, rel);
    app.store.raw.list(Some(&root)).collect::<Vec<_>>().await.into_iter().collect::<Result<_, _>>().map_err(store_err)
}

/// Writes the audit entry and its `vlpds::audit` log line.
pub(super) async fn audit(
    app: &App,
    who: &Who,
    action: &str,
    subject: Option<&SubjectRef>,
    reason: Option<&str>,
    case_id: Option<&str>,
    detail: Option<J>,
) -> XResult<AuditEntry> {
    let id = format!("{:016x}-{}", vlsync_atproto::tid::now_micros(), hex::encode(rand::random::<[u8; 4]>()));
    let e = AuditEntry {
        id: id.clone(),
        at: vlsync_atproto::events::now_rfc3339(),
        actor: who.actor.clone(),
        auth: who.auth.map(str::to_string),
        ip: who.ip.clone(),
        node: node_id(app),
        action: action.into(),
        subject: subject.cloned(),
        reason: reason.map(str::to_string),
        case_id: case_id.map(str::to_string),
        detail,
    };
    put_obj(app, &path(app, &format!("audit/{id}.json")), &e, PutMode::Create).await.map_err(store_err)?;
    tracing::info!(
        target: "vlpds::audit",
        action,
        id = %id,
        by = %who.actor,
        auth = who.auth.unwrap_or("-"),
        ip = who.ip.as_deref().unwrap_or("-"),
        subject = subject.map(|s| format!("{} {}", s.kind, s.key())).unwrap_or_default(),
        reason = reason.unwrap_or(""),
        case = case_id.unwrap_or(""),
        "moderation"
    );
    app.changes.audited(&e);
    Ok(e)
}

fn takedown_name(s: &SubjectRef) -> XResult<String> {
    match s.kind.as_str() {
        "record" => {
            let uri = s.uri.as_deref().ok_or_else(|| XrpcError::bad("InvalidRequest", "a record subject needs uri"))?;
            super::admin::record_takedown_name(uri, &s.did)
        }
        "blob" => Ok(format!(
            "blob/{}",
            s.cid.as_deref().ok_or_else(|| XrpcError::bad("InvalidRequest", "a blob subject needs cid"))?
        )),
        "space" => {
            let uri = s.uri.as_deref().ok_or_else(|| XrpcError::bad("InvalidRequest", "a space subject needs uri"))?;
            let space = super::space::Space::parse(uri)?;
            if space.authority != s.did {
                return Err(XrpcError::bad("InvalidRequest", "a space is taken down at its authority"));
            }
            Ok(super::space::space_takedown_name(&space.sid))
        }
        k => Err(XrpcError::bad("InvalidRequest", format!("no takedown row for kind {k}"))),
    }
}

/// Applies or lifts a takedown, keeps the index of active takedowns, writes
/// the audit entry and links it to the case. The single path for the console
/// and `com.atproto.admin.updateSubjectStatus`.
pub(super) async fn apply(app: &App, s: &SubjectRef, act: &Action, who: &Who) -> XResult<J> {
    let mut detail = json!({});
    let r = act.r#ref.clone().or_else(|| act.case_id.clone().map(|c| format!("case:{c}")));
    match s.kind.as_str() {
        "account" => {
            let r = act.applied.then(|| r.clone().unwrap_or_else(vlsync_atproto::events::now_rfc3339));
            super::admin::takedown_account(app, &s.did, r).await?;
        }
        "record" | "space" => {
            let name = takedown_name(s)?;
            let v = act.applied.then(|| json!({"uri": s.uri, "did": s.did, "cid": s.cid, "ref": r}));
            super::admin::set_subject_takedown(app, &s.did, &name, v).await?;
        }
        "blob" => {
            let cid = s.cid.as_deref().unwrap_or_default();
            let c = Cid::parse(cid).map_err(|_| XrpcError::bad("InvalidRequest", "Invalid cid"))?;
            detail = blob_takedown(app, &s.did, c, act.applied, r.clone()).await?;
        }
        k => return Err(XrpcError::bad("InvalidRequest", format!("unknown subject kind {k}"))),
    }
    crate::metrics::MODERATION_ACTIONS
        .with_label_values(&[s.kind.as_str(), if act.applied { "takedown" } else { "reversed" }])
        .inc();
    let action = if act.applied { "takedown" } else { "restore" };
    let e =
        audit(app, who, action, Some(s), act.reason.as_deref(), act.case_id.as_deref(), Some(detail.clone())).await?;
    let idx = index_path(app, s);
    if act.applied {
        let mut entry = json!({
            "subject": s, "ref": r, "reason": act.reason, "caseId": act.case_id,
            "at": e.at, "actor": who.actor, "auditId": e.id,
        });
        if let Some(o) = detail.as_object() {
            for (k, v) in o {
                entry[k] = v.clone();
            }
        }
        put_obj(app, &idx, &entry, PutMode::Overwrite).await.map_err(store_err)?;
    } else {
        delete_obj(app, &idx).await?;
    }
    if let Some(id) = &act.case_id {
        link_case(app, id, s, &e).await?;
    }
    detail["auditId"] = json!(e.id);
    detail["ref"] = json!(r);
    Ok(detail)
}

/// Takedown: the row first (serving stops at once), then the bytes move to
/// quarantine. Restore: the bytes move back first, then the row goes. A
/// crash between steps leaves state that a retry or [`sweep_quarantine`]
/// finishes.
async fn blob_takedown(app: &App, did: &str, cid: Cid, applied: bool, r: Option<String>) -> XResult<J> {
    let name = format!("blob/{cid}");
    let row_name = format!("{}{name}", super::server::TAKEDOWN);
    let store = &app.store.raw;
    let live = super::blobs::blob_path(app, did, cid);
    let q = quarantine_path(app, did, cid);
    if applied {
        let prev: Option<J> = get_json(app, did, &row_name).await?;
        let q_at = prev.as_ref().and_then(|p| p["quarantinedAt"].as_u64()).unwrap_or_else(now_ms);
        let row = json!({"did": did, "cid": cid.to_string(), "ref": r, "quarantinedAt": q_at});
        super::admin::set_subject_takedown(app, did, &name, Some(row)).await?;
        let quarantined = match store.copy(&live, &q).await {
            Ok(()) => {
                delete_obj(app, &live).await?;
                crate::metrics::BLOB_QUARANTINE.with_label_values(&["quarantined"]).inc();
                true
            }
            Err(object_store::Error::NotFound { .. }) => store.head(&q).await.is_ok(),
            Err(e) => return Err(store_err(e)),
        };
        let purge_after = q_at + app.config.blob_quarantine.as_millis() as u64;
        Ok(json!({"quarantined": quarantined, "quarantinedAtMs": q_at, "purgeAfterMs": purge_after}))
    } else {
        let restored = match store.copy(&q, &live).await {
            Ok(()) => true,
            Err(object_store::Error::NotFound { .. }) => false,
            Err(e) => return Err(store_err(e)),
        };
        super::admin::set_subject_takedown(app, did, &name, None).await?;
        if restored {
            delete_obj(app, &q).await?;
            crate::metrics::BLOB_QUARANTINE.with_label_values(&["restored"]).inc();
        }
        Ok(json!({"bytesRestored": restored}))
    }
}

/// Deletes quarantined blobs whose takedown is older than `keep`, and
/// tidies what an interrupted takedown or restore left. Only accounts on
/// shards this node owns. Returns the number purged.
pub async fn sweep_quarantine(app: &App, keep: Duration) -> anyhow::Result<usize> {
    let store = app.store.raw.clone();
    let root = object_store::path::Path::from(format!("{}/{QUARANTINE}", app.store.prefix));
    let metas: Vec<object_store::ObjectMeta> =
        store.list(Some(&root)).collect::<Vec<_>>().await.into_iter().collect::<Result<_, _>>()?;
    let now = now_ms();
    let keep_ms = keep.as_millis() as u64;
    let mut purged = 0;
    for meta in metas {
        let Some((did, cid)) = super::blobs::did_cid(&meta.location) else { continue };
        let Ok(c) = Cid::parse(&cid) else { continue };
        if app.partition(&did).is_err() {
            continue;
        }
        let row_name = format!("{}blob/{cid}", super::server::TAKEDOWN);
        let row: Option<J> = get_json(app, &did, &row_name).await.map_err(|e| anyhow::anyhow!(e.message))?;
        let live = super::blobs::blob_path(app, &did, c);
        let modified = meta.last_modified.timestamp_millis().max(0) as u64;
        match row {
            Some(mut row) => {
                // an interrupted takedown's live copy
                if let Err(e) = store.delete(&live).await {
                    if !matches!(e, object_store::Error::NotFound { .. }) {
                        tracing::warn!(%did, %cid, "quarantine: removing the live copy: {e}");
                    }
                }
                let q_at = row["quarantinedAt"].as_u64().unwrap_or(modified);
                if now.saturating_sub(q_at) < keep_ms {
                    continue;
                }
                super::blob_quota::drop_stored(app, &did, &cid, meta.size)
                    .await
                    .map_err(|e| anyhow::anyhow!(e.message))?;
                store.delete(&meta.location).await?;
                row["purgedAtMs"] = json!(now);
                super::admin::set_subject_takedown(app, &did, &format!("blob/{cid}"), Some(row))
                    .await
                    .map_err(|e| anyhow::anyhow!(e.message))?;
                let s = SubjectRef::blob(&did, &cid);
                if let Ok(Some((mut entry, _))) = get_obj::<J>(app, &index_path(app, &s)).await {
                    entry["purgedAtMs"] = json!(now);
                    entry["quarantined"] = json!(false);
                    let _ = put_obj(app, &index_path(app, &s), &entry, PutMode::Overwrite).await;
                }
                let who = Who { actor: "system".into(), ip: None, auth: None };
                let _ = audit(
                    app,
                    &who,
                    "blob.purge",
                    Some(&s),
                    Some("quarantine period over"),
                    None,
                    Some(json!({"bytes": meta.size})),
                )
                .await;
                crate::metrics::BLOB_QUARANTINE.with_label_values(&["purged"]).inc();
                purged += 1;
            }
            None => match app.account(&did).await {
                // evidence of a deleted account is kept for the same period
                Err(e) if e.error == "AccountNotFound" => {
                    if now.saturating_sub(modified) >= keep_ms {
                        store.delete(&meta.location).await?;
                        purged += 1;
                    }
                }
                Err(e) => return Err(anyhow::anyhow!(e.message)),
                // an interrupted restore
                Ok(_) => {
                    if store.head(&live).await.is_err() {
                        store.copy(&meta.location, &live).await?;
                    }
                    store.delete(&meta.location).await?;
                }
            },
        }
    }
    Ok(purged)
}

// ---------------------------------------------------------------- cases

#[derive(Clone, Debug, serde::Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Note {
    pub at: String,
    pub actor: String,
    /// As [`AuditEntry::auth`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    pub text: String,
}

#[derive(Clone, Debug, serde::Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CaseAction {
    pub at: String,
    pub audit_id: String,
    pub action: String,
    pub subject: SubjectRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub actor: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<String>,
}

#[derive(Clone, Debug, serde::Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Case {
    pub id: String,
    pub created_at: String,
    pub updated_at: String,
    pub status: String,
    /// Where it came from, e.g. "DMCA notice from X, received by email".
    pub source: String,
    #[serde(default)]
    pub subjects: Vec<SubjectRef>,
    #[serde(default)]
    pub notes: Vec<Note>,
    #[serde(default)]
    pub actions: Vec<CaseAction>,
}

fn case_path(app: &App, id: &str) -> XResult<object_store::path::Path> {
    if id.is_empty() || id.len() > 64 || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        return Err(XrpcError::bad("InvalidRequest", "invalid case id"));
    }
    Ok(path(app, &format!("cases/{id}.json")))
}

fn case_not_found(id: &str) -> XrpcError {
    XrpcError::bad("CaseNotFound", format!("no case {id}"))
}

/// Read-modify-write under the object's ETag; `f` may run more than once.
async fn edit_case(app: &App, id: &str, f: impl Fn(&mut Case) -> XResult<()>) -> XResult<Case> {
    let p = case_path(app, id)?;
    for _ in 0..CASE_CAS_RETRIES {
        let (mut c, etag) = get_obj::<Case>(app, &p).await?.ok_or_else(|| case_not_found(id))?;
        f(&mut c)?;
        c.updated_at = vlsync_atproto::events::now_rfc3339();
        match put_obj(app, &p, &c, crate::cluster::if_match(etag)).await {
            Ok(()) => return Ok(c),
            Err(object_store::Error::Precondition { .. }) | Err(object_store::Error::AlreadyExists { .. }) => continue,
            Err(e) => return Err(store_err(e)),
        }
    }
    Err(XrpcError::unavailable("Unavailable", "the case kept changing under this edit; retry"))
}

/// Records the action on the case, adds the subject, and moves an open case
/// (or a restored one) to actioned on a takedown, an actioned one to restored
/// on a restore.
async fn link_case(app: &App, id: &str, s: &SubjectRef, e: &AuditEntry) -> XResult<()> {
    edit_case(app, id, |c| {
        if !c.subjects.iter().any(|x| x.same(s)) {
            c.subjects.push(s.clone());
        }
        if !c.actions.iter().any(|a| a.audit_id == e.id) {
            c.actions.push(CaseAction {
                at: e.at.clone(),
                audit_id: e.id.clone(),
                action: e.action.clone(),
                subject: s.clone(),
                reason: e.reason.clone(),
                actor: e.actor.clone(),
                auth: e.auth.clone(),
            });
        }
        match (e.action.as_str(), c.status.as_str()) {
            ("takedown", "open" | "restored") => c.status = "actioned".into(),
            ("restore", "actioned") => c.status = "restored".into(),
            _ => {}
        }
        Ok(())
    })
    .await
    .map(|_| ())
}

// ---------------------------------------------------------------- lookup

/// What an operator pasted, before handle resolution.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Parsed {
    /// A handle or a DID.
    pub actor: Option<String>,
    pub collection: Option<String>,
    pub rkey: Option<String>,
    pub cid: Option<String>,
}

fn looks_like_cid(s: &str) -> bool {
    s.len() > 40 && s.starts_with("baf") && Cid::parse(s).is_ok()
}

fn is_actor(s: &str) -> bool {
    s.starts_with("did:") || (s.contains('.') && !s.contains('/') && !s.contains('@') && !s.contains(':'))
}

/// bsky.app (and look-alike app) URLs, at:// URIs, handles, DIDs, CIDs
/// (with a DID beside them), getBlob URLs and Bluesky CDN/video URLs.
pub fn parse_input(input: &str) -> Result<Parsed, String> {
    let t = input.trim();
    if t.is_empty() {
        return Err("paste a bsky.app URL, an at:// URI, a handle, a DID, or a blob CID with its DID".into());
    }
    if let Some(rest) = t.strip_prefix("at://") {
        let mut it = rest.split(['?', '#']).next().unwrap_or("").split('/').filter(|p| !p.is_empty());
        let actor = it.next().ok_or("at:// URI without an authority")?;
        return Ok(Parsed {
            actor: Some(super::sync::pct_decode(actor, false).trim_start_matches('@').to_string()),
            collection: it.next().map(str::to_string),
            rkey: it.next().map(str::to_string),
            cid: None,
        });
    }
    if t.starts_with("https://") || t.starts_with("http://") {
        return parse_url(t);
    }
    let mut p = Parsed::default();
    for tok in t.split(|c: char| c.is_whitespace() || c == ',') {
        let tok = tok.trim_start_matches('@');
        if tok.is_empty() {
            continue;
        }
        if looks_like_cid(tok) {
            p.cid = Some(tok.to_string());
        } else if is_actor(tok) {
            p.actor = Some(if tok.starts_with("did:") { tok.to_string() } else { tok.to_ascii_lowercase() });
        } else {
            return Err(format!("not a handle, DID or CID: {tok}"));
        }
    }
    if p.actor.is_none() {
        return Err(if p.cid.is_some() {
            "a blob CID needs the DID of the account that stores it (paste both)".into()
        } else {
            "nothing to look up".into()
        });
    }
    Ok(p)
}

fn parse_url(u: &str) -> Result<Parsed, String> {
    let after = u.split_once("://").map(|x| x.1).unwrap_or(u);
    let (host_path, query) = after.split_once('?').map_or((after, ""), |(a, b)| (a, b));
    let host_path = host_path.split('#').next().unwrap_or("");
    let segs: Vec<String> =
        host_path.split('/').skip(1).filter(|s| !s.is_empty()).map(|s| super::sync::pct_decode(s, false)).collect();
    let q: Vec<(String, String)> = query
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (k.to_string(), super::sync::pct_decode(v, true)))
        .collect();
    let qget = |k: &str| q.iter().find(|(qk, _)| qk == k).map(|(_, v)| v.clone());
    // .../xrpc/com.atproto.sync.getBlob?did=&cid= (any PDS or AppView proxy)
    if let (Some(did), Some(cid)) = (qget("did"), qget("cid")) {
        return Ok(Parsed { actor: Some(did), cid: Some(cid), ..Default::default() });
    }
    if segs.first().map(String::as_str) == Some("profile") {
        let actor = segs.get(1).ok_or("profile URL without a handle or DID")?.trim_start_matches('@').to_string();
        let collection = match segs.get(2).map(String::as_str) {
            None => None,
            Some("post") => Some("app.bsky.feed.post"),
            Some("feed") => Some("app.bsky.feed.generator"),
            Some("lists") => Some("app.bsky.graph.list"),
            Some(other) => return Err(format!("unrecognized profile URL part /{other}/")),
        };
        let rkey = collection.and(segs.get(3)).cloned();
        if collection.is_some() && rkey.is_none() {
            return Err("URL names a collection but no record key".into());
        }
        return Ok(Parsed { actor: Some(actor), collection: collection.map(str::to_string), rkey, cid: None });
    }
    if segs.first().map(String::as_str) == Some("starter-pack") {
        let actor = segs.get(1).ok_or("starter-pack URL without a handle")?.clone();
        let rkey = segs.get(2).ok_or("starter-pack URL without a record key")?.clone();
        return Ok(Parsed {
            actor: Some(actor),
            collection: Some("app.bsky.graph.starterpack".into()),
            rkey: Some(rkey),
            cid: None,
        });
    }
    // CDN and video URLs: .../{did}/{cid}[@jpeg][/...]
    if let Some(i) = segs.iter().position(|s| s.starts_with("did:")) {
        if let Some(cid) =
            segs.get(i + 1).map(|c| c.split('@').next().unwrap_or("").to_string()).filter(|c| looks_like_cid(c))
        {
            return Ok(Parsed { actor: Some(segs[i].clone()), cid: Some(cid), ..Default::default() });
        }
        return Ok(Parsed { actor: Some(segs[i].clone()), ..Default::default() });
    }
    Err("unrecognized URL: expected a bsky.app profile or post URL, a getBlob URL or a CDN image/video URL".into())
}

#[derive(Deserialize)]
struct ResolveQ {
    q: String,
}

fn not_here(m: impl Into<String>) -> XrpcError {
    XrpcError::bad("NotHostedHere", m)
}

/// Turns pasted input into a subject on this PDS (routing-free: answers on
/// any node); the console then reads it with getSubject.
async fn resolve_subject(State(app): AppState, Auth(creds): Auth, Query(q): Query<ResolveQ>) -> XResult<Json<J>> {
    require_admin(&creds)?;
    if let Some(u) = vlsync_atproto::syntax::parse_space_uri(q.q.trim()) {
        let space = format!("at://{}/space/{}/{}", u.authority, u.space_type, u.skey);
        let (did, kind, uri) = match u.record {
            Some((author, c, r)) => (author, "record", format!("{space}/{author}/{c}/{r}")),
            None => (u.authority, "space", space),
        };
        let acct = super::internal::account_anywhere(&app, did).await.map_err(|e| {
            if e.error == "AccountNotFound" {
                not_here(format!(
                    "{did} has no account on this PDS: only spaces and space records stored here can be acted on here"
                ))
            } else {
                e
            }
        })?;
        return Ok(Json(json!({"did": did, "handle": acct.handle, "kind": kind, "uri": uri})));
    }
    let p = parse_input(&q.q).map_err(|m| XrpcError::bad("InvalidRequest", m))?;
    let actor = p.actor.clone().unwrap_or_default();
    let did = if actor.starts_with("did:") {
        actor.clone()
    } else {
        let h = actor.to_ascii_lowercase();
        app.resolve_handle(&h)
            .await?
            .ok_or_else(|| not_here(format!("@{h} is not an account on this PDS: only content stored here can be taken down here (report other content to its PDS or to Bluesky)")))?
    };
    let acct = super::internal::account_anywhere(&app, &did).await.map_err(|e| {
        if e.error == "AccountNotFound" {
            not_here(format!("{did} has no account on this PDS: only content stored here can be taken down here (report other content to its PDS or to Bluesky)"))
        } else {
            e
        }
    })?;
    let mut out = json!({"did": did, "handle": acct.handle, "kind": "account"});
    if let Some(cid) = &p.cid {
        Cid::parse(cid).map_err(|_| XrpcError::bad("InvalidRequest", "Invalid cid"))?;
        out["kind"] = json!("blob");
        out["cid"] = json!(cid);
    } else if let (Some(c), Some(r)) = (&p.collection, &p.rkey) {
        out["kind"] = json!("record");
        out["uri"] = json!(format!("at://{did}/{c}/{r}"));
    }
    Ok(Json(out))
}

#[derive(Deserialize)]
struct SubjectQ {
    did: String,
    uri: Option<String>,
    cid: Option<String>,
}

async fn blob_view(app: &App, did: &str, cid: &str, ctl: &super::server::Ctl) -> XResult<J> {
    let c = Cid::parse(cid).map_err(|_| XrpcError::bad("InvalidRequest", "Invalid cid"))?;
    let store = &app.store.raw;
    let opts = || object_store::GetOptions { head: true, ..Default::default() };
    let takendown = ctl.has_takedown(&format!("blob/{cid}"));
    let (lp, qp) = (super::blobs::blob_path(app, did, c), quarantine_path(app, did, c));
    let (live, quarantined) = tokio::join!(store.get_opts(&lp, opts()), store.get_opts(&qp, opts()));
    let found = live.as_ref().ok().or(quarantined.as_ref().ok());
    let mut v = json!({
        "cid": cid,
        "takendown": takendown,
        "stored": live.is_ok(),
        "quarantined": quarantined.is_ok(),
    });
    if let Some(r) = found {
        v["mimeType"] = json!(super::blobs::stored_mime(&r.attributes));
        v["size"] = json!(r.meta.size);
    }
    if takendown {
        let row: Option<J> = get_json(app, did, &format!("{}blob/{cid}", super::server::TAKEDOWN)).await?;
        if let Some(r) = row {
            v["takedown"] = r.clone();
            if let Some(q_at) = r["quarantinedAt"].as_u64() {
                v["purgeAfterMs"] = json!(q_at + app.config.blob_quarantine.as_millis() as u64);
            }
        }
    }
    Ok(v)
}

/// The account, record and blob(s) a subject names, for the console.
/// Routes to the account's owner (by `did`).
async fn get_subject(State(app): AppState, Auth(creds): Auth, Query(q): Query<SubjectQ>) -> XResult<Json<J>> {
    require_admin(&creds)?;
    let acct = app.account(&q.did).await.map_err(|e| {
        if e.error == "AccountNotFound" {
            not_here(format!("{} has no account on this PDS", q.did))
        } else {
            e
        }
    })?;
    let ctl = super::server::ctl(&app, &q.did).await?;
    let tref = acct.extra.get("takedownRef").and_then(|v| v.as_str());
    let mut out = json!({
        "account": {
            "did": acct.did, "handle": acct.handle, "email": acct.email, "createdAt": acct.created_at,
            "status": acct.status, "takedown": {"applied": tref.is_some(), "ref": tref},
        },
        "quota": super::blob_quota::view(&app, &q.did).await?,
    });
    if let Some(u) = q.uri.as_deref().and_then(vlsync_atproto::syntax::parse_space_uri) {
        let uri = q.uri.as_deref().unwrap_or_default();
        let space = super::space::Space::parse(&format!("at://{}/space/{}/{}", u.authority, u.space_type, u.skey))?;
        let p = app.partition(&q.did)?;
        match u.record {
            // what a space record is, never what it says (nor its CID, which
            // would confirm a guessed value): reading it is
            // vlpds.admin.getSpaceRecord, with a reason and an audit entry
            Some((_, c, r)) => {
                let name = super::admin::record_takedown_name(uri, &q.did)?;
                let path = format!("{c}/{r}");
                let v =
                    p.db.get(state::space_record_key(&q.did, &space.sid, &path)).await.map_err(XrpcError::from_err)?;
                out["spaceRecord"] = json!({"uri": uri, "space": space.uri, "takendown": ctl.has_takedown(&name), "exists": v.is_some()});
            }
            None => {
                if space.authority != q.did {
                    return Err(XrpcError::bad("InvalidRequest", "a space is looked up at its authority"));
                }
                let row = p.db.get(state::space_key(&q.did, &space.sid)).await.map_err(XrpcError::from_err)?;
                let row =
                    row.map(|v| crate::space::rows::SpaceRow::decode(&v)).transpose().map_err(XrpcError::from_err)?;
                out["space"] = json!({
                    "uri": space.uri,
                    "takendown": ctl.has_takedown(&super::space::space_takedown_name(&space.sid)),
                    "exists": row.is_some(),
                    "deleted": row.as_ref().is_some_and(|r| !r.live()),
                });
            }
        }
    } else if let Some(uri) = &q.uri {
        let rpath = super::admin::record_path(uri, &q.did)?;
        let takendown = ctl.has_takedown(&format!("rec/{rpath}"));
        let mut rec = json!({"uri": uri, "takendown": takendown, "exists": false});
        if let Some(v) = app.record_value(&q.did, Some(acct.repo_gen), rpath).await? {
            let (cid, bytes) = state::decode_record_value(&v).map_err(XrpcError::from_err)?;
            let value = Value::decode(&bytes).map_err(XrpcError::from_err)?;
            let mut cids = Vec::new();
            super::blob_refs(&value, &mut cids);
            let mut blobs = Vec::new();
            for c in cids {
                blobs.push(blob_view(&app, &q.did, &c.to_string(), &ctl).await?);
            }
            rec["exists"] = json!(true);
            rec["cid"] = json!(cid.to_string());
            rec["value"] = value.to_json();
            rec["blobs"] = json!(blobs);
        }
        out["record"] = rec;
    }
    if let Some(cid) = &q.cid {
        out["blob"] = blob_view(&app, &q.did, cid, &ctl).await?;
    }
    Ok(Json(out))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ModerateIn {
    /// The account (routes the call to its owner).
    did: String,
    kind: String,
    uri: Option<String>,
    cid: Option<String>,
    /// takedown | restore
    action: String,
    reason: String,
    case_id: Option<String>,
    actor: Option<String>,
}

/// A console-sent name, or "admin".
pub(super) fn actor_of(a: Option<&str>) -> String {
    a.map(|a| a.trim().chars().take(64).collect::<String>()).filter(|a| !a.is_empty()).unwrap_or_else(|| "admin".into())
}

fn bounded_text(field: &str, s: &str, max: usize) -> XResult<String> {
    let t = s.trim();
    if t.chars().count() > max {
        return Err(XrpcError::bad("InvalidRequest", format!("{field}: longer than {max} characters")));
    }
    Ok(t.to_string())
}

/// One-step takedown or restore from the console: a reason is required.
async fn moderate(
    State(app): AppState,
    Auth(creds): Auth,
    ClientIp(ip): ClientIp,
    Json(inp): Json<ModerateIn>,
) -> XResult<Json<J>> {
    require_admin(&creds)?;
    let reason = bounded_text("reason", &inp.reason, MAX_REASON)?;
    if reason.is_empty() {
        return Err(XrpcError::bad("InvalidRequest", "a reason is required"));
    }
    let applied = match inp.action.as_str() {
        "takedown" => true,
        "restore" => false,
        a => return Err(XrpcError::bad("InvalidRequest", format!("action must be takedown or restore, not {a}"))),
    };
    let s = match inp.kind.as_str() {
        "account" => SubjectRef::account(&inp.did),
        "record" => {
            let uri = inp.uri.ok_or_else(|| XrpcError::bad("InvalidRequest", "uri required"))?;
            super::admin::record_takedown_name(&uri, &inp.did)?;
            SubjectRef { kind: "record".into(), did: inp.did.clone(), uri: Some(uri), cid: inp.cid, id: None }
        }
        "blob" => SubjectRef::blob(
            &inp.did,
            inp.cid.as_deref().ok_or_else(|| XrpcError::bad("InvalidRequest", "cid required"))?,
        ),
        "space" => {
            let uri = inp.uri.ok_or_else(|| XrpcError::bad("InvalidRequest", "uri required"))?;
            let s = SubjectRef::space(&super::space::Space::parse(&uri)?.uri, &inp.did);
            takedown_name(&s)?;
            s
        }
        k => {
            return Err(XrpcError::bad(
                "InvalidRequest",
                format!("kind must be account, record, blob or space, not {k}"),
            ))
        }
    };
    app.account(&inp.did).await.map_err(|e| {
        if e.error == "AccountNotFound" {
            not_here(format!("{} has no account on this PDS", inp.did))
        } else {
            e
        }
    })?;
    let case_id = inp.case_id.filter(|c| !c.trim().is_empty());
    if let Some(c) = &case_id {
        get_obj::<Case>(&app, &case_path(&app, c)?).await?.ok_or_else(|| case_not_found(c))?;
    }
    let who = Who::of(&creds, inp.actor.as_deref(), ip);
    let act = Action { applied, reason: Some(reason), r#ref: None, case_id };
    let detail = apply(&app, &s, &act, &who).await?;
    Ok(Json(json!({"subject": s, "applied": applied, "result": detail})))
}

#[derive(Deserialize)]
struct KindQ {
    kind: Option<String>,
}

async fn list_takedowns(State(app): AppState, Auth(creds): Auth, Query(q): Query<KindQ>) -> XResult<Json<J>> {
    require_admin(&creds)?;
    let kinds: Vec<&str> = match q.kind.as_deref().filter(|k| !k.is_empty()) {
        Some(k @ ("account" | "record" | "blob" | "space")) => vec![k],
        Some(k) => return Err(XrpcError::bad("InvalidRequest", format!("unknown kind {k}"))),
        None => vec!["account", "record", "blob", "space"],
    };
    let mut out = Vec::new();
    for k in kinds {
        for m in list_metas(&app, &format!("takedowns/{k}")).await? {
            if let Some((v, _)) = get_obj::<J>(&app, &m.location).await? {
                out.push(v);
            }
        }
    }
    out.sort_by(|a, b| b["at"].as_str().cmp(&a["at"].as_str()));
    Ok(Json(json!({"takedowns": out})))
}

#[derive(Deserialize)]
struct AuditQ {
    limit: Option<usize>,
    did: Option<String>,
    /// `*`: entries about any space; a space URI: about that space, its
    /// records and its repos.
    space: Option<String>,
}

/// The space an entry is about, if any: its subject's, or the space a read
/// or a registration removal names.
fn entry_space(e: &AuditEntry) -> Option<String> {
    let of = |u: &str| {
        vlsync_atproto::syntax::parse_space_uri(u)
            .map(|s| format!("at://{}/space/{}/{}", s.authority, s.space_type, s.skey))
    };
    e.subject
        .as_ref()
        .and_then(|s| s.uri.as_deref())
        .and_then(of)
        .or_else(|| e.detail.as_ref().and_then(|d| d["space"].as_str()).and_then(of))
}

/// Newest first.
async fn get_audit_log(State(app): AppState, Auth(creds): Auth, Query(q): Query<AuditQ>) -> XResult<Json<J>> {
    require_admin(&creds)?;
    let limit = q.limit.unwrap_or(100).clamp(1, AUDIT_PAGE);
    let mut metas = list_metas(&app, "audit").await?;
    metas.sort_by(|a, b| b.location.as_ref().cmp(a.location.as_ref()));
    let mut out = Vec::new();
    for m in metas {
        if out.len() >= limit {
            break;
        }
        if let Some((e, _)) = get_obj::<AuditEntry>(&app, &m.location).await? {
            if q.did.as_deref().is_some_and(|d| e.subject.as_ref().is_none_or(|s| s.did != d)) {
                continue;
            }
            match q.space.as_deref().filter(|s| !s.is_empty()) {
                Some("*") if entry_space(&e).is_none() => continue,
                Some(u) if u != "*" && entry_space(&e).as_deref() != Some(u) => continue,
                _ => {}
            }
            out.push(e);
        }
    }
    Ok(Json(json!({"entries": out})))
}

#[derive(Deserialize)]
struct CasesQ {
    status: Option<String>,
    /// Cases with a subject of this account (any kind).
    did: Option<String>,
    /// Narrows `did` to one record (its at:// URI) or blob (its CID).
    subject: Option<String>,
}

/// Every case is read and filtered here: cases are few (one object each,
/// opened by hand). Past a few thousand a subject index (`cases/by-did/…`
/// written with the case) would replace the scan.
async fn list_cases(State(app): AppState, Auth(creds): Auth, Query(q): Query<CasesQ>) -> XResult<Json<J>> {
    require_admin(&creds)?;
    let did = q.did.as_deref().map(str::trim).filter(|d| !d.is_empty());
    let subject = q.subject.as_deref().map(str::trim).filter(|s| !s.is_empty());
    if subject.is_some() && did.is_none() {
        return Err(XrpcError::bad("InvalidRequest", "subject needs did"));
    }
    let about = |c: &Case| {
        did.is_none_or(|d| {
            c.subjects.iter().any(|s| {
                s.did == d && subject.is_none_or(|x| s.uri.as_deref() == Some(x) || s.cid.as_deref() == Some(x))
            })
        })
    };
    let mut out: Vec<Case> = Vec::new();
    for m in list_metas(&app, "cases").await? {
        if let Some((c, _)) = get_obj::<Case>(&app, &m.location).await? {
            if q.status.as_deref().is_none_or(|s| s.is_empty() || s == c.status) && about(&c) {
                out.push(c);
            }
        }
    }

    out.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    Ok(Json(json!({"cases": out})))
}

#[derive(Deserialize)]
struct IdQ {
    id: String,
}

async fn get_case(State(app): AppState, Auth(creds): Auth, Query(q): Query<IdQ>) -> XResult<Json<Case>> {
    require_admin(&creds)?;
    let (c, _) = get_obj::<Case>(&app, &case_path(&app, &q.id)?).await?.ok_or_else(|| case_not_found(&q.id))?;
    Ok(Json(c))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateCaseIn {
    source: String,
    #[serde(default)]
    subjects: Vec<SubjectRef>,
    note: Option<String>,
    actor: Option<String>,
}

fn check_subject(s: &SubjectRef) -> XResult<()> {
    match s.kind.as_str() {
        "account" => {}
        "record" => {
            super::admin::record_takedown_name(s.uri.as_deref().unwrap_or(""), &s.did)?;
        }
        "blob" => {
            Cid::parse(s.cid.as_deref().unwrap_or("")).map_err(|_| XrpcError::bad("InvalidRequest", "Invalid cid"))?;
        }
        k => return Err(XrpcError::bad("InvalidRequest", format!("unknown subject kind {k}"))),
    }
    if !s.did.starts_with("did:") {
        return Err(XrpcError::bad("InvalidRequest", "subject did must be a DID"));
    }
    if s.id.is_some() {
        return Err(XrpcError::bad("InvalidRequest", "a case subject has no id"));
    }
    Ok(())
}

async fn create_case(
    State(app): AppState,
    Auth(creds): Auth,
    ClientIp(ip): ClientIp,
    Json(inp): Json<CreateCaseIn>,
) -> XResult<Json<Case>> {
    require_admin(&creds)?;
    let source = bounded_text("source", &inp.source, MAX_REASON)?;
    if source.is_empty() {
        return Err(XrpcError::bad("InvalidRequest", "describe the case's source (e.g. who sent the notice)"));
    }
    inp.subjects.iter().try_for_each(check_subject)?;
    let who = Who::of(&creds, inp.actor.as_deref(), ip);
    let now = vlsync_atproto::events::now_rfc3339();
    let mut notes = Vec::new();
    if let Some(n) =
        inp.note.as_deref().map(|n| bounded_text("note", n, MAX_NOTE)).transpose()?.filter(|n| !n.is_empty())
    {
        notes.push(Note {
            at: now.clone(),
            actor: who.actor.clone(),
            auth: who.auth.map(str::to_string),
            ip: who.ip.clone(),
            text: n,
        });
    }
    let mut subjects: Vec<SubjectRef> = Vec::new();
    for s in inp.subjects {
        if !subjects.iter().any(|x| x.same(&s)) {
            subjects.push(s);
        }
    }
    let c = Case {
        id: app.tids.next().to_string(),
        created_at: now.clone(),
        updated_at: now,
        status: "open".into(),
        source,
        subjects,
        notes,
        actions: Vec::new(),
    };
    put_obj(&app, &case_path(&app, &c.id)?, &c, PutMode::Create).await.map_err(store_err)?;
    audit(&app, &who, "case.create", None, Some(&c.source), Some(&c.id), None).await?;
    Ok(Json(c))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateCaseIn {
    id: String,
    status: Option<String>,
    source: Option<String>,
    note: Option<String>,
    add_subject: Option<SubjectRef>,
    remove_subject: Option<SubjectRef>,
    actor: Option<String>,
}

async fn update_case(
    State(app): AppState,
    Auth(creds): Auth,
    ClientIp(ip): ClientIp,
    Json(inp): Json<UpdateCaseIn>,
) -> XResult<Json<Case>> {
    require_admin(&creds)?;
    if let Some(s) = inp.status.as_deref().filter(|s| !STATUSES.contains(s)) {
        return Err(XrpcError::bad(
            "InvalidRequest",
            format!("status must be one of {}, not {s}", STATUSES.join(", ")),
        ));
    }
    if let Some(s) = &inp.add_subject {
        check_subject(s)?;
    }
    let source =
        inp.source.as_deref().map(|s| bounded_text("source", s, MAX_REASON)).transpose()?.filter(|s| !s.is_empty());
    let note = inp.note.as_deref().map(|n| bounded_text("note", n, MAX_NOTE)).transpose()?.filter(|n| !n.is_empty());
    let who = Who::of(&creds, inp.actor.as_deref(), ip);
    let at = vlsync_atproto::events::now_rfc3339();
    let mut changes = Vec::new();
    if let Some(s) = &inp.status {
        changes.push(format!("status → {s}"));
    }
    if source.is_some() {
        changes.push("source edited".to_string());
    }
    if note.is_some() {
        changes.push("note added".to_string());
    }
    if let Some(s) = &inp.add_subject {
        changes.push(format!("subject added: {} {}", s.kind, s.key()));
    }
    if let Some(s) = &inp.remove_subject {
        changes.push(format!("subject removed: {} {}", s.kind, s.key()));
    }
    let c = edit_case(&app, &inp.id, |c| {
        if let Some(s) = &inp.status {
            c.status = s.clone();
        }
        if let Some(s) = &source {
            c.source = s.clone();
        }
        if let Some(n) = &note {
            if !c.notes.iter().any(|x| x.at == at && x.text == *n) {
                c.notes.push(Note {
                    at: at.clone(),
                    actor: who.actor.clone(),
                    auth: who.auth.map(str::to_string),
                    ip: who.ip.clone(),
                    text: n.clone(),
                });
            }
        }
        if let Some(s) = &inp.add_subject {
            if !c.subjects.iter().any(|x| x.same(s)) {
                c.subjects.push(s.clone());
            }
        }
        if let Some(s) = &inp.remove_subject {
            c.subjects.retain(|x| !x.same(s));
        }
        Ok(())
    })
    .await?;
    audit(
        &app,
        &who,
        "case.update",
        inp.add_subject.as_ref(),
        note.as_deref(),
        Some(&c.id),
        Some(json!({"changes": changes})),
    )
    .await?;
    Ok(Json(c))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ResetFactorsIn {
    did: String,
    reason: String,
    actor: Option<String>,
    /// Also sign out everywhere (a revoke-all): for when whoever has the
    /// account now may not be its owner.
    #[serde(default)]
    revoke_sessions: bool,
}

/// For a user who lost every factor: removes their passkeys, TOTP,
/// recovery codes and trusted browsers (the password and the email factor
/// stay). A reason is required; it's audited and the user is mailed, since
/// whoever talks the operator into it still needs the password.
async fn reset_second_factors(
    State(app): AppState,
    Auth(creds): Auth,
    ClientIp(ip): ClientIp,
    Json(inp): Json<ResetFactorsIn>,
) -> XResult<Json<J>> {
    require_admin(&creds)?;
    let reason = bounded_text("reason", &inp.reason, MAX_REASON)?;
    if reason.is_empty() {
        return Err(XrpcError::bad("InvalidRequest", "a reason is required"));
    }
    app.account(&inp.did).await.map_err(|e| {
        if e.error == "AccountNotFound" {
            not_here(format!("{} has no account on this PDS", inp.did))
        } else {
            e
        }
    })?;
    let who = Who::of(&creds, inp.actor.as_deref(), ip);
    let subject = SubjectRef::account(&inp.did);
    // recorded before anything changes: no reset without its audit entry
    let started = audit(
        &app,
        &who,
        "second_factors.reset",
        Some(&subject),
        Some(&reason),
        None,
        Some(json!({"status": "started", "revokeSessions": inp.revoke_sessions})),
    )
    .await?;
    let r = super::server::reset_second_factors(&app, &inp.did, inp.revoke_sessions).await;
    let mut detail = match &r {
        Ok(result) => json!({"status": "done", "result": result}),
        Err(e) => json!({"status": "failed", "error": e.message}),
    };
    detail["started"] = json!(started.id);
    detail["revokeSessions"] = json!(inp.revoke_sessions);
    let e = audit(&app, &who, "second_factors.reset", Some(&subject), Some(&reason), None, Some(detail)).await?;
    let result = r?;
    Ok(Json(json!({"did": inp.did, "result": result, "auditId": e.id})))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SetQuotaIn {
    did: String,
    /// null: the default; 0: unlimited.
    bytes: Option<u64>,
    uploads_per_day: Option<u32>,
    reason: Option<String>,
    actor: Option<String>,
}

/// Per-account override of the blob quotas (routes to the owner by `did`).
async fn set_blob_quota(
    State(app): AppState,
    Auth(creds): Auth,
    ClientIp(ip): ClientIp,
    Json(inp): Json<SetQuotaIn>,
) -> XResult<Json<J>> {
    require_admin(&creds)?;
    app.account(&inp.did).await.map_err(|e| {
        if e.error == "AccountNotFound" {
            not_here(format!("{} has no account on this PDS", inp.did))
        } else {
            e
        }
    })?;
    let reason = inp.reason.as_deref().map(|r| bounded_text("reason", r, MAX_REASON)).transpose()?;
    let l = super::blob_quota::Limits { bytes: inp.bytes, uploads_per_day: inp.uploads_per_day };
    super::blob_quota::set_limits(&app, &inp.did, l.clone()).await?;
    let who = Who::of(&creds, inp.actor.as_deref(), ip);
    audit(
        &app,
        &who,
        "quota.set",
        Some(&SubjectRef::account(&inp.did)),
        reason.as_deref(),
        None,
        Some(serde_json::to_value(&l).unwrap()),
    )
    .await?;
    Ok(Json(super::blob_quota::view(&app, &inp.did).await?))
}

async fn list_over_quota(State(app): AppState, Auth(creds): Auth) -> XResult<Json<J>> {
    require_admin(&creds)?;
    Ok(Json(json!({"accounts": super::blob_quota::over_quota(&app).await?})))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(actor: &str, coll: Option<&str>, rkey: Option<&str>, cid: Option<&str>) -> Parsed {
        Parsed {
            actor: Some(actor.into()),
            collection: coll.map(Into::into),
            rkey: rkey.map(Into::into),
            cid: cid.map(Into::into),
        }
    }

    const CID: &str = "bafkreie5737gdxlw5i64vzichcalba3z2v5n6icifvx5xytvske7mr3hpm";

    #[test]
    fn parses_bsky_urls() {
        assert_eq!(
            parse_input("https://bsky.app/profile/alice.pds.example.com").unwrap(),
            p("alice.pds.example.com", None, None, None)
        );
        assert_eq!(
            parse_input(" https://bsky.app/profile/did:plc:abc123/post/3kabc ").unwrap(),
            p("did:plc:abc123", Some("app.bsky.feed.post"), Some("3kabc"), None)
        );
        assert_eq!(
            parse_input("https://bsky.app/profile/did%3Aplc%3Aabc123/post/3kabc?ref=x#y").unwrap(),
            p("did:plc:abc123", Some("app.bsky.feed.post"), Some("3kabc"), None)
        );
        assert_eq!(
            parse_input("https://bsky.app/profile/alice.test/post/3kabc/quotes").unwrap(),
            p("alice.test", Some("app.bsky.feed.post"), Some("3kabc"), None)
        );
        assert_eq!(
            parse_input("https://bsky.app/profile/alice.test/feed/hot").unwrap(),
            p("alice.test", Some("app.bsky.feed.generator"), Some("hot"), None)
        );
        assert_eq!(
            parse_input("https://bsky.app/profile/alice.test/lists/3l").unwrap(),
            p("alice.test", Some("app.bsky.graph.list"), Some("3l"), None)
        );
        assert_eq!(
            parse_input("https://bsky.app/starter-pack/alice.test/3s").unwrap(),
            p("alice.test", Some("app.bsky.graph.starterpack"), Some("3s"), None)
        );
        assert!(parse_input("https://bsky.app/profile/alice.test/post").is_err());
        assert!(parse_input("https://bsky.app/search?q=x").is_err());
    }

    #[test]
    fn parses_at_uris_handles_dids() {
        assert_eq!(
            parse_input("at://did:plc:abc/app.bsky.feed.post/3k").unwrap(),
            p("did:plc:abc", Some("app.bsky.feed.post"), Some("3k"), None)
        );
        assert_eq!(parse_input("at://alice.test").unwrap(), p("alice.test", None, None, None));
        assert_eq!(parse_input("@Alice.Test").unwrap(), p("alice.test", None, None, None));
        assert_eq!(parse_input("did:web:example.com").unwrap(), p("did:web:example.com", None, None, None));
        assert!(parse_input("").is_err());
        assert!(parse_input("hello").is_err());
    }

    #[test]
    fn parses_blob_forms() {
        assert_eq!(parse_input(&format!("did:plc:abc {CID}")).unwrap(), p("did:plc:abc", None, None, Some(CID)));
        assert_eq!(parse_input(&format!("{CID}, did:plc:abc")).unwrap(), p("did:plc:abc", None, None, Some(CID)));
        assert!(parse_input(CID).unwrap_err().contains("DID"));
        let get_blob = format!("https://pds.example.com/xrpc/com.atproto.sync.getBlob?did=did%3Aplc%3Aabc&cid={CID}");
        assert_eq!(parse_input(&get_blob).unwrap(), p("did:plc:abc", None, None, Some(CID)));
        let cdn = format!("https://cdn.bsky.app/img/feed_fullsize/plain/did:plc:abc/{CID}@jpeg");
        assert_eq!(parse_input(&cdn).unwrap(), p("did:plc:abc", None, None, Some(CID)));
        let video = format!("https://video.bsky.app/watch/did%3Aplc%3Aabc/{CID}/playlist.m3u8");
        assert_eq!(parse_input(&video).unwrap(), p("did:plc:abc", None, None, Some(CID)));
    }
}
