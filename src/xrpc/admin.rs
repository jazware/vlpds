//! com.atproto.admin.*, vlpds.admin.* operator methods, invite-code storage
//! and subject takedowns (kept in the account's partition under `sec/td/`).

use super::admin_audit::{bounded_note, node_subject, ActorIn};
use super::authn::Credentials;
use super::moderation::{audit, ClientIp, SubjectRef, Who};
use super::server::{
    ctl, delete_from, ext, finish_delete, get_json, invalid_request, normalize_handle, pmut, put_sec, recompute_status,
    scan_private_routing, set_deactivated, set_email, set_extra, to_json_bytes, update_account, DeleteFrom,
    NEW_PASSWORD_MAX_LENGTH, TAKEDOWN,
};
use super::*;

pub fn routes() -> Router<Arc<App>> {
    Router::new()
        .route("/xrpc/vlpds.admin.bulkCreate", post(bulk_create))
        .route("/xrpc/vlpds.admin.rewrapSecrets", post(rewrap_secrets))
        .route("/xrpc/vlpds.admin.rotatePlcKeys", post(rotate_plc_keys))
        .route("/xrpc/vlpds.admin.ensureRecoveryKey", post(ensure_recovery_key))
        .route("/xrpc/vlpds.admin.getDevMail", get(get_dev_mail))
        .route("/xrpc/vlpds.admin.getGrafanaDashboard", get(get_grafana_dashboard))
        .route("/xrpc/com.atproto.admin.getAccountInfo", get(get_account_info))
        .route("/xrpc/com.atproto.admin.getAccountInfos", get(get_account_infos))
        .route("/xrpc/com.atproto.admin.searchAccounts", get(search_accounts))
        .route("/xrpc/com.atproto.admin.updateAccountHandle", post(update_account_handle))
        .route("/xrpc/com.atproto.admin.updateAccountEmail", post(update_account_email))
        .route("/xrpc/com.atproto.admin.updateAccountPassword", post(update_account_password))
        .route("/xrpc/com.atproto.admin.updateAccountSigningKey", post(update_account_signing_key))
        .route("/xrpc/com.atproto.admin.updateSubjectStatus", post(update_subject_status))
        .route("/xrpc/com.atproto.admin.getSubjectStatus", get(get_subject_status))
        .route("/xrpc/com.atproto.admin.deleteAccount", post(delete_account))
        .route("/xrpc/com.atproto.admin.disableAccountInvites", post(disable_account_invites))
        .route("/xrpc/com.atproto.admin.enableAccountInvites", post(enable_account_invites))
        .route("/xrpc/com.atproto.admin.disableInviteCodes", post(disable_invite_codes))
        .route("/xrpc/com.atproto.admin.getInviteCodes", get(get_invite_codes))
        .route("/xrpc/com.atproto.admin.sendEmail", post(send_email))
        .route("/xrpc/vlpds.admin.getShardLayout", get(get_shard_layout))
        .route("/xrpc/vlpds.admin.splitShard", post(split_shard))
        .route("/xrpc/vlpds.admin.mergeShards", post(merge_shards))
        .route("/xrpc/vlpds.admin.abortReshard", post(abort_reshard))
}

fn cluster_of(app: &App) -> XResult<&Arc<crate::cluster::Cluster>> {
    app.cluster.as_ref().ok_or_else(|| invalid_request("no cluster"))
}

fn layout_json(app: &App) -> XResult<J> {
    let c = cluster_of(app)?;
    let l = c.layout();
    let shards: Vec<J> = l
        .shards
        .iter()
        .map(|r| json!({"id": r.id, "lo": r.lo, "hi": r.hi, "owner": c.owner_of(r.id).map(|o| o.0)}))
        .collect();
    Ok(json!({"version": l.version, "shards": shards, "nextId": l.next_id, "op": l.op}))
}

async fn get_shard_layout(State(app): AppState, Auth(creds): Auth) -> XResult<Json<J>> {
    require_admin(&creds)?;
    Ok(Json(layout_json(&app)?))
}

#[derive(Deserialize)]
struct SplitIn {
    shard: crate::slots::ShardId,
    at: Option<u32>,
    #[serde(default)]
    wait: bool,
    actor: Option<String>,
}

#[derive(Deserialize)]
struct MergeIn {
    left: crate::slots::ShardId,
    right: crate::slots::ShardId,
    #[serde(default)]
    wait: bool,
    actor: Option<String>,
}

/// With `wait`, returns once the op flipped or was aborted. Audited before
/// it's planned (the planner may die right after), and again if the plan is
/// refused.
async fn reshard(app: &Arc<App>, plan: crate::reshard::Plan, wait: bool, who: &Who) -> XResult<Json<J>> {
    use crate::reshard::Plan;
    let c = cluster_of(app)?;
    let host: Arc<dyn crate::cluster::ShardHost> = app.node.clone();
    let before = c.layout().version;
    let (action, shard, detail) = match &plan {
        Plan::Split { shard, at } => ("shard.split", *shard, json!({"at": at})),
        Plan::Merge { left, right } => ("shard.merge", *left, json!({"right": right})),
    };
    let subject = SubjectRef::other("shard", shard);
    let started = audit(app, who, action, Some(&subject), None, None, Some(detail)).await?;
    let op = match c.plan_reshard(&host, plan).await {
        Ok(op) => op,
        Err(e) => {
            let message = format!("{e:#}");
            let detail = json!({"failed": message, "started": started.id});
            audit(app, who, action, Some(&subject), None, None, Some(detail)).await?;
            return Err(invalid_request(message));
        }
    };
    let mut out = json!({"op": op});
    if wait {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
        loop {
            let l = c.layout();
            if l.version > before && l.op.as_ref().is_none_or(|o| o.id != op.id) {
                out["done"] = json!(l.shards.iter().any(|r| op.children.iter().any(|ch| ch.id == r.id)));
                break;
            }
            if l.op.is_none() && l.version == before {
                out["done"] = json!(false); // aborted
                break;
            }
            if std::time::Instant::now() > deadline {
                return Err(XrpcError {
                    status: StatusCode::GATEWAY_TIMEOUT,
                    error: "Timeout".into(),
                    message: format!("op {} still in progress", op.id),
                });
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    }
    out["layout"] = layout_json(app)?;
    Ok(Json(out))
}

async fn split_shard(
    State(app): AppState,
    Auth(creds): Auth,
    ClientIp(ip): ClientIp,
    Json(inp): Json<SplitIn>,
) -> XResult<Json<J>> {
    require_admin(&creds)?;
    let who = Who::of(&creds, inp.actor.as_deref(), ip);
    reshard(&app, crate::reshard::Plan::Split { shard: inp.shard, at: inp.at }, inp.wait, &who).await
}

async fn merge_shards(
    State(app): AppState,
    Auth(creds): Auth,
    ClientIp(ip): ClientIp,
    Json(inp): Json<MergeIn>,
) -> XResult<Json<J>> {
    require_admin(&creds)?;
    let who = Who::of(&creds, inp.actor.as_deref(), ip);
    reshard(&app, crate::reshard::Plan::Merge { left: inp.left, right: inp.right }, inp.wait, &who).await
}

/// Only before it flips. Audited when there was an op to abort.
async fn abort_reshard(
    State(app): AppState,
    Auth(creds): Auth,
    ClientIp(ip): ClientIp,
    body: Option<Json<ActorIn>>,
) -> XResult<Json<J>> {
    require_admin(&creds)?;
    let c = cluster_of(&app)?;
    let host: Arc<dyn crate::cluster::ShardHost> = app.node.clone();
    let op = c.abort_reshard(&host).await.map_err(XrpcError::from_err)?;
    if let Some(o) = &op {
        let actor = body.as_ref().and_then(|Json(b)| b.actor.as_deref());
        let detail = json!({"op": o.id, "parents": o.parents});
        let subject = o.parents.first().map(|p| SubjectRef::other("shard", p));
        audit(&app, &Who::of(&creds, actor, ip), "shard.abort", subject.as_ref(), None, None, Some(detail)).await?;
    }
    Ok(Json(json!({"aborted": op, "layout": layout_json(&app)?})))
}

/// The reference's `authVerifier.moderator`: admin Basic auth, or a service
/// JWT from the configured moderation service (`--mod-service-did`; verified
/// in `authn::authenticate` for [`super::authn::MODERATOR_METHODS`]).
pub(super) fn require_moderator(creds: &Credentials) -> XResult<()> {
    match creds {
        Credentials::ModService { .. } => Ok(()),
        _ => require_admin(creds),
    }
}

/// The reference's `authVerifier.adminToken`.
pub(super) fn require_admin(creds: &Credentials) -> XResult<()> {
    match creds {
        Credentials::Admin { .. } => Ok(()),
        _ => Err(XrpcError::auth("admin credentials required")),
    }
}

fn not_found(message: &str) -> XrpcError {
    XrpcError::bad("NotFound", message)
}

fn not_implemented(message: &str) -> XrpcError {
    XrpcError { status: StatusCode::NOT_FOUND, error: "MethodNotImplemented".into(), message: message.into() }
}

async fn ensure_account(app: &App, did: &str) -> XResult<Account> {
    app.account(did).await.map_err(|_| invalid_request(format!("Account not found: {did}")))
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct InviteUse {
    pub used_by: String,
    pub used_at: String,
}

/// Stored at p/_invite:{code}\0c in the reference's CodeDetail shape.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct InviteCode {
    pub code: String,
    pub available: i64,
    pub disabled: bool,
    pub for_account: String,
    pub created_by: String,
    pub created_at: String,
    #[serde(default)]
    pub uses: Vec<InviteUse>,
    /// vlpds: only for handles under this served domain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle_domain: Option<String>,
}

fn invite_routing(code: &str) -> String {
    format!("_invite:{code}")
}

/// Golden fixtures (`super::private_rows`).
pub(super) fn fixture_rows(did: &str) -> Vec<super::private_rows::PrivateRow> {
    let code = "pds-test-abcde-fghij";
    let inv = InviteCode {
        code: code.into(),
        available: 2,
        disabled: false,
        for_account: did.into(),
        created_by: "admin".into(),
        created_at: "2026-10-01T00:00:00.000Z".into(),
        uses: vec![InviteUse {
            used_by: "did:plc:invitee000000000000000".into(),
            used_at: "2026-10-01T00:01:00.000Z".into(),
        }],
        handle_domain: None,
    };
    vec![
        (invite_routing(code), "c".into(), super::private_rows::enc(&inv)),
        (did.into(), format!("invite/{code}"), Vec::new()),
    ]
}

pub(super) fn check_row(routing: &str, name: &str, val: &[u8]) -> Option<anyhow::Result<&'static str>> {
    if routing.starts_with("_invite:") && name == "c" {
        return Some(super::private_rows::typed_row::<InviteCode>("invite code", val));
    }
    if name.starts_with("invite/") {
        return Some(if val.is_empty() {
            Ok("invite code index")
        } else {
            Err(anyhow::anyhow!("invite index row with a value"))
        });
    }
    None
}

/// `{hostname with . -> -}-xxxxx-xxxxx`
pub(super) fn gen_invite_code(app: &App) -> String {
    format!("{}-{}", super::server::public_host(app).replace('.', "-"), super::server::random_token())
}

async fn get_invite(app: &App, code: &str) -> XResult<Option<InviteCode>> {
    get_json(app, &invite_routing(code), "c").await
}

async fn put_invite(app: &App, inv: &InviteCode) -> XResult<()> {
    let r = invite_routing(&inv.code);
    app.put_private(&r, vec![pmut(&r, "c", Some(to_json_bytes(inv)))]).await
}

/// Read-modify-write of a code, conditional on the row read: signups record
/// their uses from whichever node owns the new account, and a node-local lock
/// let two nodes each write back a copy missing the other's use. `f` returns
/// whether it changed anything. Ok(false): no such code.
async fn update_invite(app: &App, code: &str, mut f: impl FnMut(&mut InviteCode) -> bool) -> XResult<bool> {
    use super::cas::{Cond, Op};
    let r = invite_routing(code);
    for _ in 0..64 {
        let Some(raw) = app.get_private(&r, "c").await? else {
            return Ok(false);
        };
        let mut inv: InviteCode = serde_json::from_slice(&raw).map_err(XrpcError::from_err)?;
        if !f(&mut inv) {
            return Ok(true);
        }
        let val = Bytes::from(to_json_bytes(&inv));
        if app.private_cas(&r, vec![Cond::eq("c", Some(raw))], vec![Op::put("c", Some(val))]).await?.applied {
            return Ok(true);
        }
    }
    Err(super::server::cas_conflict())
}

/// `account`: a DID or "admin". `created_by`: "admin", or the account itself
/// for codes earned with `--invite-interval`. `handle_domain`: a served
/// domain the codes are limited to.
pub(super) async fn create_invites(
    app: &App,
    account: &str,
    codes: &[String],
    use_count: i64,
    disabled: bool,
    created_by: &str,
    handle_domain: Option<&str>,
) -> XResult<()> {
    if let Some(d) = handle_domain {
        if !app.handle_domains.names().iter().any(|n| n == d) {
            return Err(invalid_request(format!("{d} is not a served handle domain")));
        }
    }
    let now = crate::events::now_rfc3339();
    for code in codes {
        let inv = InviteCode {
            code: code.clone(),
            available: use_count,
            disabled,
            for_account: account.to_string(),
            created_by: created_by.into(),
            created_at: now.clone(),
            uses: Vec::new(),
            handle_domain: handle_domain.map(str::to_string),
        };
        put_invite(app, &inv).await?;
    }
    let muts = codes.iter().map(|c| pmut(account, &format!("invite/{c}"), Some(Vec::new()))).collect();
    app.put_private(account, muts).await?;
    crate::metrics::INVITE_CODES.with_label_values(&["created"]).inc_by(codes.len() as u64);
    Ok(())
}

/// `account`: a DID or "admin".
pub(super) async fn account_invites(app: &App, account: &str) -> XResult<Vec<InviteCode>> {
    let mut out = Vec::new();
    // `account` may be owned elsewhere (getAccountInfos, disableInviteCodes)
    for (name, _) in super::internal::scan_private_anywhere(app, account, "invite/").await? {
        if let Some(inv) = get_invite(app, &name["invite/".len()..]).await? {
            out.push(inv);
        }
    }
    out.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    Ok(out)
}

fn invite_slot_path(app: &App, code: &str, slot: i64) -> object_store::path::Path {
    object_store::path::Path::from(format!("{}/invite-use/{}/{slot}", app.store.prefix, hex::encode(code.as_bytes())))
}

pub(super) struct InviteClaim {
    code: String,
    slot: i64,
}

/// The code's uses are slots `0..available`, each claimed by a conditional
/// create of `invite-use/{code}/{slot}`, so concurrent signups on any node
/// can't over-use it. Released ([`release_invite_use`]) if account creation
/// then fails, else recorded ([`record_invite_use`]).
pub(super) async fn claim_invite_use(app: &App, code: &str, did: &str, handle: &str) -> XResult<InviteClaim> {
    let unavailable = || XrpcError::bad("InvalidInviteCode", "Provided invite code not available");
    let inv = get_invite(app, code).await?.ok_or_else(unavailable)?;
    if inv.disabled || inv.available <= inv.uses.len() as i64 {
        return Err(unavailable());
    }
    if let Some(d) = &inv.handle_domain {
        if app.handle_domains.under(handle).is_none_or(|(_, under)| under != *d) {
            return Err(XrpcError::bad("InvalidInviteCode", format!("This invite code is for handles under .{d}")));
        }
    }
    if inv.for_account.starts_with("did:") {
        if let Ok(a) = app.account(&inv.for_account).await {
            if a.status.as_deref() == Some("takendown") {
                return Err(unavailable());
            }
        }
    }
    // recorded uses fill the low slots; a released claim can leave a gap
    let used = (inv.uses.len() as i64).min(inv.available);
    for slot in (used..inv.available).chain(0..used) {
        let opts = PutOptions { mode: PutMode::Create, ..Default::default() };
        let payload = PutPayload::from(did.as_bytes().to_vec());
        match app.store.raw.put_opts(&invite_slot_path(app, code, slot), payload, opts).await {
            Ok(_) => return Ok(InviteClaim { code: code.to_string(), slot }),
            Err(object_store::Error::AlreadyExists { .. }) => continue,
            Err(e) => return Err(XrpcError::from_err(e)),
        }
    }
    Err(unavailable())
}

pub(super) async fn release_invite_use(app: &App, claim: InviteClaim) {
    if let Err(e) = app.store.raw.delete(&invite_slot_path(app, &claim.code, claim.slot)).await {
        tracing::warn!(code = %claim.code, "failed to release invite claim: {e}");
    }
}

pub(super) async fn record_invite_use(app: &App, claim: &InviteClaim, did: &str) -> XResult<()> {
    let used_at = crate::events::now_rfc3339();
    let found = update_invite(app, &claim.code, |inv| {
        // a retried request mustn't list the account twice
        if inv.uses.iter().any(|u| u.used_by == did) {
            return false;
        }
        inv.uses.push(InviteUse { used_by: did.to_string(), used_at: used_at.clone() });
        true
    })
    .await?;
    if !found {
        return Err(XrpcError::bad("InvalidInviteCode", "Provided invite code not available"));
    }
    crate::metrics::INVITE_CODES.with_label_values(&["used"]).inc();
    Ok(())
}

async fn set_invites_disabled(app: &App, codes: &[String], disabled: bool) -> XResult<()> {
    for code in codes {
        update_invite(app, code, |inv| {
            let changed = inv.disabled != disabled;
            inv.disabled = disabled;
            changed
        })
        .await?;
    }
    Ok(())
}

/// `path`: `{collection}/{rkey}`.
pub async fn is_record_takendown(app: &App, did: &str, path: &str) -> XResult<bool> {
    Ok(ctl(app, did).await?.has_takedown(&format!("rec/{path}")))
}

pub async fn is_blob_takendown(app: &App, did: &str, cid: &str) -> XResult<bool> {
    Ok(ctl(app, did).await?.has_takedown(&format!("blob/{cid}")))
}

/// `r` Some takes the account down with that ref, None reverses it. As the
/// reference's takedownAccount (revokeRefreshTokensByDid, token.removeByDid),
/// a takedown revokes refresh and OAuth tokens; legacy access tokens stay
/// valid until they expire.
pub(super) async fn takedown_account(app: &App, did: &str, r: Option<String>) -> XResult<()> {
    let applied = r.is_some();
    update_account(app, did, false, true, move |a| {
        set_extra(a, "takedownRef", r.map_or(J::Null, |r| json!(r)));
        recompute_status(a);
        Ok(())
    })
    .await
    .map_err(|_| invalid_request(format!("Account not found: {did}")))?;
    if applied {
        super::server::revoke_refresh_tokens(app, did).await?;
        revoke_oauth_sessions(app, did).await?;
    }
    Ok(())
}

/// `val` None lifts it; `name` is relative to [`TAKEDOWN`].
pub(super) async fn set_subject_takedown(app: &App, did: &str, name: &str, val: Option<J>) -> XResult<()> {
    put_sec(app, did, vec![pmut(did, &format!("{TAKEDOWN}{name}"), val.map(|v| to_json_bytes(&v)))]).await
}

/// `{collection}/{rkey}` of an at:// URI naming a record of `did`.
/// A record takedown's name below `sec/td/`, in `did`'s account: a repo
/// record's `rec/{collection}/{rkey}`, or a space record's
/// (`at://{authority}/space/{type}/{skey}/{did}/{collection}/{rkey}`)
/// `space/{sid}/{collection}/{rkey}`.
pub(super) fn record_takedown_name(uri: &str, did: &str) -> XResult<String> {
    if let Some(u) = super::syntax::parse_space_uri(uri) {
        let (author, collection, rkey) = u.record.ok_or_else(|| invalid_request("not a space record uri"))?;
        if author != did {
            return Err(invalid_request("invalid at-uri"));
        }
        let sid = state::space_id(&format!("at://{}/space/{}/{}", u.authority, u.space_type, u.skey));
        return Ok(super::space::takedown_name(&sid, &format!("{collection}/{rkey}")));
    }
    Ok(format!("rec/{}", record_path(uri, did)?))
}

/// The account a record subject's URI names: a space record's author.
fn record_uri_did(uri: &str) -> Option<&str> {
    if let Some(u) = super::syntax::parse_space_uri(uri) {
        return u.record.map(|(author, _, _)| author);
    }
    uri.strip_prefix("at://").and_then(|r| r.split('/').next()).filter(|d| d.starts_with("did:"))
}

pub(super) fn record_path<'a>(uri: &'a str, did: &str) -> XResult<&'a str> {
    uri.strip_prefix("at://")
        .and_then(|r| r.strip_prefix(did))
        .and_then(|r| r.strip_prefix('/'))
        .filter(|p| p.split('/').count() == 2 && !p.split('/').any(str::is_empty))
        .ok_or_else(|| invalid_request("invalid at-uri"))
}

async fn account_view(app: &App, a: &Account) -> XResult<J> {
    let invites: Vec<J> =
        account_invites(app, &a.did).await?.into_iter().map(|c| serde_json::to_value(c).unwrap()).collect();
    let mut v = json!({
        "did": a.did,
        "handle": a.handle,
        "indexedAt": a.created_at,
        "invites": invites,
        "invitesDisabled": a.extra.get("invitesDisabled").and_then(|v| v.as_bool()).unwrap_or(false),
    });
    if let Some(e) = &a.email {
        v["email"] = json!(e);
    }
    if let Some(t) = super::scheduled_deletion::scheduled_at(app, a) {
        v["deletionScheduledAt"] = json!(t);
    }
    for k in ["emailConfirmedAt", "deactivatedAt", "deleteAfter"] {
        if let Some(s) = a.extra.get(k).and_then(|v| v.as_str()) {
            v[k] = json!(s);
        }
    }
    if a.email_confirmed && v.get("emailConfirmedAt").is_none() {
        v["emailConfirmedAt"] = json!(a.created_at);
    }
    if let Some(code) = a.extra.get("invitedBy").and_then(|v| v.as_str()) {
        if let Some(inv) = get_invite(app, code).await? {
            v["invitedBy"] = serde_json::to_value(inv).unwrap();
        }
    }
    Ok(v)
}

#[derive(Deserialize)]
struct DidQ {
    did: String,
}

async fn get_account_info(State(app): AppState, Auth(creds): Auth, Query(q): Query<DidQ>) -> XResult<Json<J>> {
    require_moderator(&creds)?;
    let a = app.account(&q.did).await.map_err(|_| not_found("Account not found"))?;
    Ok(Json(account_view(&app, &a).await?))
}

async fn get_account_infos(
    State(app): AppState,
    Auth(creds): Auth,
    axum::extract::RawQuery(raw): axum::extract::RawQuery,
) -> XResult<Json<J>> {
    require_moderator(&creds)?;
    let mut infos = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for (k, did) in super::sync::query_pairs(raw.as_deref().unwrap_or("")) {
        if (k == "dids" || k == "dids[]") && seen.insert(did.clone()) {
            // the DIDs live on any node's shards (the request routes by none)
            if let Ok(a) = super::internal::account_anywhere(&app, &did).await {
                infos.push(account_view(&app, &a).await?);
            }
        }
    }
    Ok(Json(json!({"infos": infos})))
}

#[derive(Deserialize)]
pub(super) struct SearchQ {
    email: Option<String>,
    cursor: Option<String>,
    limit: Option<usize>,
}

/// One searchAccounts hit, keyed by the global sort key (slot, did).
#[derive(serde::Serialize, Deserialize)]
pub(super) struct AccountHit {
    slot: u32,
    did: String,
    view: J,
}

/// (limit, lowercased email prefix, resume after this DID)
type SearchParams = (usize, Option<String>, Option<String>);

impl SearchQ {
    fn parsed(&self) -> XResult<SearchParams> {
        let limit = self.limit.unwrap_or(50).clamp(1, 100);
        let email = self.email.as_deref().map(|e| e.trim().to_ascii_lowercase()).filter(|e| !e.is_empty());
        let after = match self.cursor.as_deref().filter(|c| !c.is_empty()) {
            Some(c) => {
                let (p, d) = c.split_once(':').ok_or_else(|| invalid_request("Malformed cursor"))?;
                let slot = p.parse::<u32>().map_err(|_| invalid_request("Malformed cursor"))?;
                if d.is_empty() || crate::slots::slot_of(d) as u32 != slot {
                    return Err(invalid_request("Malformed cursor"));
                }
                Some(d.to_string())
            }
            None => None,
        };
        Ok((limit, email, after))
    }
}

/// The local half of searchAccounts: (hits in (slot, did) order after the
/// cursor, the shards scanned).
pub(super) async fn search_accounts_local(
    app: &App,
    q: &SearchQ,
) -> XResult<(Vec<AccountHit>, Vec<crate::slots::ShardId>)> {
    let (limit, email, after) = q.parsed()?;
    let layout = app.partitions.layout();
    let mut owned = app.partitions.owned();
    owned.sort_by_key(|p| layout.range_of(p.id).map_or(u32::MAX, |r| r.lo));
    let ids: Vec<crate::slots::ShardId> = owned.iter().map(|p| p.id).collect();
    let start = after.as_deref().map(|d| [state::account_key(d), vec![0]].concat());
    let mut out = Vec::new();
    for p in owned {
        if out.len() >= limit {
            break;
        }
        let mut iter = state::FamilyScan::new(p.db.as_ref(), state::ACCOUNT_FAMILY, start.clone(), &Default::default())
            .await
            .map_err(XrpcError::from_err)?;
        while out.len() < limit {
            let Some(kv) = iter.next().await.map_err(XrpcError::from_err)? else { break };
            let Ok(a) = serde_json::from_slice::<Account>(&kv.value) else { continue };
            if email.as_ref().is_some_and(|e| !a.email.as_deref().is_some_and(|ae| ae.starts_with(e.as_str()))) {
                continue;
            }
            let (slot, did) = state::slot_did(&kv.key, state::ACCOUNT_FAMILY.len());
            let slot = u16::from_be_bytes([slot[0], slot[1]]) as u32;
            let did = String::from_utf8_lossy(did).to_string();
            out.push(AccountHit { slot, did, view: account_view(app, &a).await? });
        }
    }
    Ok((out, ids))
}

/// Cluster-wide, merged in (slot, did) order, which is independent of the
/// shard layout, so a `{slot}:{did}` cursor resumes on every node. Gaps are
/// reported ([`partial_fields`]) instead of silently dropped.
async fn search_accounts(State(app): AppState, Auth(creds): Auth, Query(q): Query<SearchQ>) -> XResult<Json<J>> {
    require_admin(&creds)?;
    let (limit, _, after) = q.parsed()?;
    let (mut hits, owned) = search_accounts_local(&app, &q).await?;
    let mut query = vec![("limit", limit.to_string())];
    if let Some(e) = &q.email {
        query.push(("email", e.clone()));
    }
    if let Some(c) = &q.cursor {
        query.push(("cursor", c.clone()));
    }
    let g = super::internal::gather(&app, "/internal/v1/admin/searchAccounts", &query).await;
    let mut covered: std::collections::HashSet<crate::slots::ShardId> = owned.into_iter().collect();
    for r in g.replies {
        covered.extend(r.owned);
        hits.extend(serde_json::from_value::<Vec<AccountHit>>(r.body["accounts"].clone()).unwrap_or_default());
    }
    hits.sort_by(|a, b| (a.slot, &a.did).cmp(&(b.slot, &b.did)));
    hits.dedup_by(|a, b| a.did == b.did);
    hits.truncate(limit);
    let cursor = (hits.len() == limit).then(|| hits.last().map(|h| format!("{}:{}", h.slot, h.did))).flatten();
    // slots before the cursor's are done; only shards past it can be missing
    let from = after.map(|d| crate::slots::slot_of(&d) as u32).unwrap_or(0);
    let mut res = json!({"accounts": hits.into_iter().map(|h| h.view).collect::<Vec<_>>()});
    if let Some(c) = cursor {
        res["cursor"] = json!(c);
    }
    partial_fields(&app, &mut res, g.unreachable, g.unsupported, &covered, from);
    Ok(Json(res))
}

/// Marks a scatter-gather result incomplete: `unsupportedNodes` lack the
/// endpoint (a rolling deploy), `missingShards` hold slots >= `from` but no
/// answering node owned them (e.g. mid-move).
pub(super) fn partial_fields(
    app: &App,
    res: &mut J,
    unreachable: Vec<String>,
    unsupported: Vec<String>,
    covered: &std::collections::HashSet<crate::slots::ShardId>,
    from: u32,
) {
    let missing: Vec<crate::slots::ShardId> = app
        .partitions
        .layout()
        .shards
        .iter()
        .filter(|r| r.hi > from && !covered.contains(&r.id))
        .map(|r| r.id)
        .collect();
    if !unreachable.is_empty() {
        res["unreachableNodes"] = json!(unreachable);
    }
    if !unsupported.is_empty() {
        res["unsupportedNodes"] = json!(unsupported);
    }
    if !missing.is_empty() {
        res["missingShards"] = json!(missing);
    }
}

#[derive(Deserialize)]
struct UpdateHandleIn {
    did: String,
    handle: String,
    actor: Option<String>,
}

async fn update_account_handle(
    State(app): AppState,
    Auth(creds): Auth,
    ClientIp(ip): ClientIp,
    Json(inp): Json<UpdateHandleIn>,
) -> XResult<StatusCode> {
    require_admin(&creds)?;
    let handle = normalize_handle(&inp.handle)?;
    // reference allowAnyValid: no slur or reserved-name checks, but a
    // service-domain handle still has to be one 3-18 char label
    if app.handle_domains.under(&handle).is_some() {
        super::server::ensure_service_handle(&app, &handle, true)?;
    }
    let before = ensure_account(&app, &inp.did).await?;
    super::identity::set_handle(&app, &inp.did, &handle, false).await?;
    let detail = json!({"handle": handle, "previous": before.handle});
    let who = Who::of(&creds, inp.actor.as_deref(), ip);
    audit(&app, &who, "account.handle", Some(&SubjectRef::account(&inp.did)), None, None, Some(detail)).await?;
    Ok(StatusCode::OK)
}

#[derive(Deserialize)]
struct UpdateEmailIn {
    account: String,
    email: String,
    actor: Option<String>,
}

/// Audited with the old and new addresses' domains only, as the mail log
/// keeps them.
async fn update_account_email(
    State(app): AppState,
    Auth(creds): Auth,
    ClientIp(ip): ClientIp,
    Json(inp): Json<UpdateEmailIn>,
) -> XResult<StatusCode> {
    require_admin(&creds)?;
    let missing = || invalid_request(format!("Account does not exist: {}", inp.account));
    let did = app.resolve_repo(&inp.account).await.map_err(|_| missing())?;
    let before = app.account(&did).await.map_err(|_| missing())?;
    set_email(&app, &did, &inp.email).await?;
    let domain = crate::mail::recipient_domain;
    let detail = json!({"domain": domain(&inp.email), "previousDomain": before.email.as_deref().map(domain)});
    let who = Who::of(&creds, inp.actor.as_deref(), ip);
    audit(&app, &who, "account.email", Some(&SubjectRef::account(&did)), None, None, Some(detail)).await?;
    Ok(StatusCode::OK)
}

#[derive(Deserialize)]
struct UpdatePasswordIn {
    did: String,
    password: String,
    actor: Option<String>,
}

async fn update_account_password(
    State(app): AppState,
    Auth(creds): Auth,
    ClientIp(ip): ClientIp,
    Json(inp): Json<UpdatePasswordIn>,
) -> XResult<StatusCode> {
    require_admin(&creds)?;
    if inp.password.len() > NEW_PASSWORD_MAX_LENGTH {
        return Err(invalid_request("Invalid password length."));
    }
    ensure_account(&app, &inp.did).await?;
    super::server::change_password(&app, &inp.did, &inp.password).await?;
    let who = Who::of(&creds, inp.actor.as_deref(), ip);
    audit(&app, &who, "account.password", Some(&SubjectRef::account(&inp.did)), None, None, None).await?;
    Ok(StatusCode::OK)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateSigningKeyIn {
    did: String,
    signing_key: Option<String>,
    actor: Option<String>,
}

/// The PDS signs commits, so it must hold the private key: `signingKey` is
/// a did:key reserved with server.reserveSigningKey, or omitted/"generate"
/// for a fresh key (src/xrpc/key_rotation.rs). With a rotation pending (an
/// earlier call failed midway), the call finishes that one instead. The
/// audit entry has the new public did:key and where the key came from.
async fn update_account_signing_key(
    State(app): AppState,
    Auth(creds): Auth,
    ClientIp(ip): ClientIp,
    Json(inp): Json<UpdateSigningKeyIn>,
) -> XResult<Json<J>> {
    require_admin(&creds)?;
    let acct = app.account(&inp.did).await.map_err(|_| invalid_request(format!("Account not found: {}", inp.did)))?;
    let requested = inp.signing_key.as_deref().filter(|k| !k.is_empty() && *k != "generate");
    let audited = |did_key: String, source: &'static str| {
        let (app, who) = (app.clone(), Who::of(&creds, inp.actor.as_deref(), ip));
        let subject = SubjectRef::account(&inp.did);
        async move {
            let detail = json!({"publicKey": did_key, "source": source});
            audit(&app, &who, "account.signing_key", Some(&subject), None, None, Some(detail)).await?;
            Ok::<_, XrpcError>(Json(json!({"signingKey": did_key})))
        }
    };
    if let Some(p) = &acct.pending_signing_key {
        let did_key = super::key_rotation::finish_pending(&app, &inp.did, p, requested).await?;
        return audited(did_key, "pending").await;
    }
    let source = if requested.is_some() { "reserved" } else { "generated" };
    let key = match requested {
        Some(dk) => {
            if !dk.starts_with("did:key:") {
                return Err(invalid_request("signingKey must be a did:key"));
            }
            super::server::take_reserved_key(&app, dk).await?.ok_or_else(|| {
                invalid_request(
                    "signingKey is not a key reserved on this PDS (use com.atproto.server.reserveSigningKey)",
                )
            })?
        }
        None => Keypair::generate(),
    };
    let did_key = super::key_rotation::rotate(&app, &inp.did, key).await?;
    audited(did_key, source).await
}

#[derive(Deserialize)]
struct StatusAttr {
    applied: bool,
    #[serde(rename = "ref")]
    r#ref: Option<String>,
}

#[derive(Deserialize)]
struct UpdateSubjectStatusIn {
    subject: J,
    takedown: Option<StatusAttr>,
    deactivated: Option<StatusAttr>,
    actor: Option<String>,
}

enum Subject {
    Repo(String),
    Record {
        uri: String,
        did: String,
        cid: Option<String>,
    },
    Blob {
        did: String,
        cid: String,
    },
    /// A whole space, at its authority (a vlpds extension).
    Space {
        uri: String,
        did: String,
    },
}

fn parse_subject(s: &J) -> XResult<Subject> {
    let field =
        |k: &str| s[k].as_str().map(str::to_string).ok_or_else(|| invalid_request(format!("subject.{k} required")));
    let t = s["$type"].as_str().unwrap_or("");
    match t {
        "com.atproto.admin.defs#repoRef" => Ok(Subject::Repo(field("did")?)),
        "com.atproto.repo.strongRef" => {
            let uri = field("uri")?;
            if let Some(u) = super::syntax::parse_space_uri(&uri).filter(|u| u.record.is_none()) {
                let did = u.authority.to_string();
                return Ok(Subject::Space { uri: format!("at://{did}/space/{}/{}", u.space_type, u.skey), did });
            }
            let did = record_uri_did(&uri).ok_or_else(|| invalid_request("invalid at-uri"))?.to_string();
            Ok(Subject::Record { uri, did, cid: s["cid"].as_str().map(str::to_string) })
        }
        "com.atproto.admin.defs#repoBlobRef" => Ok(Subject::Blob { did: field("did")?, cid: field("cid")? }),
        _ => Err(invalid_request(format!("Invalid subject ({t})"))),
    }
}

/// So the account's DPoP access tokens stop verifying and can't be
/// refreshed. A failure fails the takedown request (already applied, so a
/// retry is idempotent).
async fn revoke_oauth_sessions(app: &App, did: &str) -> XResult<()> {
    crate::oauth::store::revoke_all_sessions(app, did).await.map(|_| ()).map_err(|e| {
        tracing::warn!(%did, "takedown: revoking OAuth sessions failed: {}", e.description);
        XrpcError::internal(format!("takedown applied but revoking OAuth sessions failed (retry): {}", e.description))
    })
}

async fn update_subject_status(
    State(app): AppState,
    Auth(creds): Auth,
    super::moderation::ClientIp(peer): super::moderation::ClientIp,
    Json(inp): Json<UpdateSubjectStatusIn>,
) -> XResult<Json<J>> {
    require_moderator(&creds)?;
    if inp.takedown.as_ref().is_some_and(|t| t.applied) && inp.deactivated.as_ref().is_some_and(|d| !d.applied) {
        return Err(invalid_request("Cannot activate and takedown an account at the same time"));
    }
    let subject = parse_subject(&inp.subject)?;
    let who = Who::of(&creds, inp.actor.as_deref(), peer);
    if let Some(td) = &inp.takedown {
        let s = match &subject {
            Subject::Repo(did) => SubjectRef::account(did),
            Subject::Record { uri, did, cid } => SubjectRef {
                kind: "record".into(),
                did: did.clone(),
                uri: Some(uri.clone()),
                cid: cid.clone(),
                id: None,
            },
            Subject::Blob { did, cid } => SubjectRef::blob(did, cid),
            Subject::Space { uri, did } => SubjectRef::space(uri, did),
        };
        let act =
            super::moderation::Action { applied: td.applied, reason: None, r#ref: td.r#ref.clone(), case_id: None };
        super::moderation::apply(&app, &s, &act, &who).await?;
    }
    if let (Some(d), Subject::Repo(did)) = (&inp.deactivated, &subject) {
        set_deactivated(&app, did, d.applied, None).await?;
        let action = if d.applied { "account.deactivate" } else { "account.activate" };
        audit(&app, &who, action, Some(&SubjectRef::account(did)), None, None, None).await?;
    }
    if inp.takedown.is_none() && inp.deactivated.is_none() {
        if let Subject::Repo(did) = &subject {
            // re-announce the current status
            update_account(&app, did, false, true, |_| Ok(())).await?;
        }
    }
    let mut out = json!({"subject": inp.subject});
    if let Some(td) = &inp.takedown {
        out["takedown"] = json!({"applied": td.applied});
        if let Some(r) = &td.r#ref {
            out["takedown"]["ref"] = json!(r);
        }
    }
    Ok(Json(out))
}

#[derive(Deserialize)]
struct SubjectStatusQ {
    did: Option<String>,
    uri: Option<String>,
    blob: Option<String>,
}

async fn get_subject_status(
    State(app): AppState,
    Auth(creds): Auth,
    Query(q): Query<SubjectStatusQ>,
) -> XResult<Json<J>> {
    require_moderator(&creds)?;
    let body = if let Some(blob) = &q.blob {
        let did = q.did.as_deref().ok_or_else(|| invalid_request("Must provide a did to request blob state"))?;
        get_json::<J>(&app, did, &format!("{TAKEDOWN}blob/{blob}")).await?.map(|t| {
            json!({
                "subject": {"$type": "com.atproto.admin.defs#repoBlobRef", "did": did, "cid": blob},
                "takedown": status_attr(true, t["ref"].as_str()),
            })
        })
    } else if let Some(uri) = &q.uri {
        let did = uri
            .strip_prefix("at://")
            .and_then(|r| r.split('/').next())
            .ok_or_else(|| invalid_request("invalid at-uri"))?;
        let td = get_json::<J>(&app, did, &format!("{TAKEDOWN}rec/{}", record_path(uri, did)?)).await?;
        let cid = current_record_cid(&app, uri).await;
        match (td, cid) {
            (Some(t), Some(cid)) => Some(json!({
                "subject": {"$type": "com.atproto.repo.strongRef", "uri": uri, "cid": cid},
                "takedown": status_attr(true, t["ref"].as_str()),
            })),
            _ => None,
        }
    } else if let Some(did) = &q.did {
        app.account(did).await.ok().map(|a| {
            let tref = a.extra.get("takedownRef").and_then(|v| v.as_str());
            json!({
                "subject": {"$type": "com.atproto.admin.defs#repoRef", "did": did},
                "takedown": status_attr(tref.is_some(), tref),
                "deactivated": {"applied": a.extra.get("deactivatedAt").is_some_and(|v| !v.is_null())},
            })
        })
    } else {
        return Err(invalid_request("No provided subject"));
    };
    body.map(Json).ok_or_else(|| not_found("Subject not found"))
}

fn status_attr(applied: bool, r: Option<&str>) -> J {
    let mut v = json!({"applied": applied});
    if let Some(r) = r {
        v["ref"] = json!(r);
    }
    v
}

async fn current_record_cid(app: &App, uri: &str) -> Option<String> {
    let rest = uri.strip_prefix("at://")?;
    let (did, path) = rest.split_once('/')?;
    let v = app.record_value(did, None, path).await.ok()??;
    let (cid, _) = state::decode_record_value(&v).ok()?;
    Some(cid.to_string())
}

#[derive(Deserialize)]
struct DeleteAccountIn {
    did: String,
    actor: Option<String>,
}

/// Audited before anything is deleted, and again if the deletion fails
/// (a retry finishes it, and is audited as another deletion).
async fn delete_account(
    State(app): AppState,
    Auth(creds): Auth,
    ClientIp(ip): ClientIp,
    Json(inp): Json<DeleteAccountIn>,
) -> XResult<StatusCode> {
    require_admin(&creds)?;
    let did = inp.did.as_str();
    let from = delete_from(&app, did).await.map_err(|e| match e.error.as_str() {
        "AccountNotFound" => invalid_request(format!("Account not found: {did}")),
        _ => e,
    })?;
    let (handle, retry) = match &from {
        DeleteFrom::Account(d) => (Some(d.handle.clone()), false),
        DeleteFrom::Leftovers(d) => (Some(d.handle.clone()), true),
        DeleteFrom::Unreadable => (None, false),
    };
    let (who, subject) = (Who::of(&creds, inp.actor.as_deref(), ip), SubjectRef::account(did));
    let detail = json!({"handle": handle, "retry": retry});
    let started = audit(&app, &who, "account.delete", Some(&subject), None, None, Some(detail)).await?;
    if let Err(e) = finish_delete(&app, did, from, "admin", None).await {
        let detail = json!({"handle": handle, "failed": e.message, "started": started.id});
        audit(&app, &who, "account.delete", Some(&subject), None, None, Some(detail)).await?;
        return Err(e);
    }
    Ok(StatusCode::OK)
}

#[derive(Deserialize)]
struct AccountIn {
    account: String,
    note: Option<String>,
    actor: Option<String>,
}

/// The account's DID and how many of its codes there are.
async fn set_account_invites_disabled(app: &App, account: &str, disabled: bool) -> XResult<(String, usize)> {
    let did = app.resolve_repo(account).await?;
    update_account(app, &did, false, false, move |a| {
        set_extra(a, "invitesDisabled", json!(disabled));
        Ok(())
    })
    .await?;
    let codes: Vec<String> = account_invites(app, &did).await?.into_iter().map(|c| c.code).collect();
    set_invites_disabled(app, &codes, disabled).await?;
    Ok((did.to_string(), codes.len()))
}

async fn account_invites_toggle(
    app: &App,
    creds: &Credentials,
    ip: Option<std::net::IpAddr>,
    inp: AccountIn,
    disabled: bool,
) -> XResult<StatusCode> {
    require_moderator(creds)?;
    let (did, codes) = set_account_invites_disabled(app, &inp.account, disabled).await?;
    let action = if disabled { "invites.disable_account" } else { "invites.enable_account" };
    let who = Who::of(creds, inp.actor.as_deref(), ip);
    let note = bounded_note(inp.note.as_deref());
    let detail = json!({"codes": codes});
    audit(app, &who, action, Some(&SubjectRef::account(&did)), note.as_deref(), None, Some(detail)).await?;
    Ok(StatusCode::OK)
}

async fn disable_account_invites(
    State(app): AppState,
    Auth(creds): Auth,
    ClientIp(ip): ClientIp,
    Json(inp): Json<AccountIn>,
) -> XResult<StatusCode> {
    account_invites_toggle(&app, &creds, ip, inp, true).await
}

async fn enable_account_invites(
    State(app): AppState,
    Auth(creds): Auth,
    ClientIp(ip): ClientIp,
    Json(inp): Json<AccountIn>,
) -> XResult<StatusCode> {
    account_invites_toggle(&app, &creds, ip, inp, false).await
}

#[derive(Deserialize, Default)]
struct DisableCodesIn {
    #[serde(default)]
    codes: Vec<String>,
    #[serde(default)]
    accounts: Vec<String>,
    note: Option<String>,
    actor: Option<String>,
}

/// Audited with how many codes and which accounts, never the codes.
async fn disable_invite_codes(
    State(app): AppState,
    Auth(creds): Auth,
    ClientIp(ip): ClientIp,
    Json(inp): Json<DisableCodesIn>,
) -> XResult<StatusCode> {
    require_moderator(&creds)?;
    if inp.accounts.iter().any(|a| a == "admin") {
        return Err(invalid_request("cannot disable admin invite codes"));
    }
    let mut codes = inp.codes.clone();
    for a in &inp.accounts {
        codes.extend(account_invites(&app, a).await?.into_iter().map(|c| c.code));
    }
    set_invites_disabled(&app, &codes, true).await?;
    let subject = match inp.accounts.as_slice() {
        [one] if inp.codes.is_empty() && one.starts_with("did:") => Some(SubjectRef::account(one)),
        _ => None,
    };
    let detail = json!({"codes": codes.len(), "accounts": inp.accounts.iter().take(50).collect::<Vec<_>>()});
    let (who, note) = (Who::of(&creds, inp.actor.as_deref(), ip), bounded_note(inp.note.as_deref()));
    audit(&app, &who, "invites.disable_codes", subject.as_ref(), note.as_deref(), None, Some(detail)).await?;
    Ok(StatusCode::OK)
}

#[derive(Deserialize)]
pub(super) struct InviteCodesQ {
    sort: Option<String>,
    limit: Option<i64>,
    cursor: Option<String>,
}

/// Listed descending.
#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum InviteKey {
    Recent(String, String),
    Usage(usize, String),
}

impl InviteKey {
    fn of(usage: bool, c: &InviteCode) -> InviteKey {
        if usage {
            InviteKey::Usage(c.uses.len(), c.code.clone())
        } else {
            InviteKey::Recent(c.created_at.clone(), c.code.clone())
        }
    }

    /// `{createdAt|uses}/{code}` (codes and timestamps never contain '/').
    fn cursor(&self) -> String {
        match self {
            InviteKey::Recent(t, c) => format!("{t}/{c}"),
            InviteKey::Usage(n, c) => format!("{n}/{c}"),
        }
    }

    fn parse(usage: bool, s: &str) -> XResult<InviteKey> {
        let bad = || invalid_request("Malformed cursor");
        let (k, c) = s.split_once('/').ok_or_else(bad)?;
        Ok(if usage {
            InviteKey::Usage(k.parse().map_err(|_| bad())?, c.to_string())
        } else {
            InviteKey::Recent(k.to_string(), c.to_string())
        })
    }
}

impl InviteCodesQ {
    /// (usage sort, limit, resume-after key)
    fn parsed(&self) -> XResult<(bool, usize, Option<InviteKey>)> {
        let sort = self.sort.as_deref().unwrap_or("recent");
        if sort != "recent" && sort != "usage" {
            return Err(invalid_request(format!("unknown sort method: {sort}")));
        }
        let usage = sort == "usage";
        let limit = super::extract::limit_param(self.limit, 100, 1, 500)?;
        let after = self.cursor.as_deref().filter(|c| !c.is_empty()).map(|c| InviteKey::parse(usage, c)).transpose()?;
        Ok((usage, limit, after))
    }
}

/// The local half of getInviteCodes: (at most `limit + 1` codes after the
/// cursor, so the merger knows whether more exist; the shards scanned).
pub(super) async fn invite_codes_local(
    app: &App,
    q: &InviteCodesQ,
) -> XResult<(Vec<InviteCode>, Vec<crate::slots::ShardId>)> {
    let (usage, limit, after) = q.parsed()?;
    let owned: Vec<crate::slots::ShardId> = app.partitions.owned().iter().map(|p| p.id).collect();
    let mut all: Vec<(InviteKey, InviteCode)> = scan_private_routing(app, "_invite:")
        .await?
        .into_iter()
        .filter(|(_, name, _)| name == "c")
        .filter_map(|(_, _, v)| serde_json::from_slice::<InviteCode>(&v).ok())
        .map(|c| (InviteKey::of(usage, &c), c))
        .filter(|(k, _)| after.as_ref().is_none_or(|a| k < a))
        .collect();
    all.sort_by(|a, b| b.0.cmp(&a.0));
    all.truncate(limit + 1);
    Ok((all.into_iter().map(|(_, c)| c).collect(), owned))
}

/// Cluster-wide, like searchAccounts: the cursor is the last code's sort key.
async fn get_invite_codes(State(app): AppState, Auth(creds): Auth, Query(q): Query<InviteCodesQ>) -> XResult<Json<J>> {
    require_moderator(&creds)?;
    let (usage, limit, _) = q.parsed()?;
    let (codes, owned) = invite_codes_local(&app, &q).await?;
    let mut all: Vec<(InviteKey, InviteCode)> = codes.into_iter().map(|c| (InviteKey::of(usage, &c), c)).collect();
    let mut query = vec![("limit", limit.to_string()), ("sort", (if usage { "usage" } else { "recent" }).to_string())];
    if let Some(c) = &q.cursor {
        query.push(("cursor", c.clone()));
    }
    let g = super::internal::gather(&app, "/internal/v1/admin/inviteCodes", &query).await;
    let mut covered: std::collections::HashSet<crate::slots::ShardId> = owned.into_iter().collect();
    for r in g.replies {
        covered.extend(r.owned);
        let codes = serde_json::from_value::<Vec<InviteCode>>(r.body["codes"].clone()).unwrap_or_default();
        all.extend(codes.into_iter().map(|c| (InviteKey::of(usage, &c), c)));
    }
    all.sort_by(|a, b| b.0.cmp(&a.0));
    all.dedup_by(|a, b| a.1.code == b.1.code);
    let more = all.len() > limit;
    all.truncate(limit);
    let mut out = json!({"codes": all.iter().map(|(_, c)| serde_json::to_value(c).unwrap()).collect::<Vec<_>>()});
    if more {
        out["cursor"] = json!(all.last().map(|(k, _)| k.cursor()));
    }
    partial_fields(&app, &mut out, g.unreachable, g.unsupported, &covered, 0);
    Ok(Json(out))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SendEmailIn {
    recipient_did: String,
    content: String,
    subject: Option<String>,
    #[allow(dead_code)]
    sender_did: Option<String>,
    comment: Option<String>,
    actor: Option<String>,
}

/// Audited with the recipient's domain and the comment, never the address
/// or the message. The mail itself is in the mail log (purpose `admin`).
async fn send_email(
    State(app): AppState,
    Auth(creds): Auth,
    ClientIp(ip): ClientIp,
    Json(inp): Json<SendEmailIn>,
) -> XResult<Json<J>> {
    require_moderator(&creds)?;
    let a = app.account(&inp.recipient_did).await.map_err(|_| invalid_request("Recipient not found"))?;
    let to = a.email.ok_or_else(|| invalid_request("account does not have an email address"))?;
    let subject = inp.subject.unwrap_or_else(|| "Message via your PDS".into());
    super::server::deliver_moderation(&app, &a.did, &to, &subject, &inp.content);
    let (who, comment) = (Who::of(&creds, inp.actor.as_deref(), ip), bounded_note(inp.comment.as_deref()));
    let detail = json!({"toDomain": crate::mail::recipient_domain(&to), "purpose": "admin"});
    audit(&app, &who, "mail.send", Some(&SubjectRef::account(&a.did)), comment.as_deref(), None, Some(detail)).await?;
    Ok(Json(json!({"sent": true})))
}

#[derive(Deserialize)]
struct DashboardQ {
    name: String,
}

/// The import-ready Grafana dashboard `vlpds dashboards --name` prints, for
/// the console's Live metrics page.
async fn get_grafana_dashboard(Auth(creds): Auth, Query(q): Query<DashboardQ>) -> XResult<axum::response::Response> {
    use axum::response::IntoResponse;
    require_admin(&creds)?;
    let (_, _, body) = crate::cli::dashboards::DASHBOARDS
        .iter()
        .find(|(n, _, _)| *n == q.name)
        .ok_or_else(|| invalid_request("name: vlpds or internals"))?;
    Ok(([(axum::http::header::CONTENT_TYPE, "application/json")], *body).into_response())
}

#[derive(Deserialize)]
struct DevMailQ {
    email: String,
}

async fn get_dev_mail(State(app): AppState, Auth(creds): Auth, Query(q): Query<DevMailQ>) -> XResult<Json<J>> {
    require_admin(&creds)?;
    if !app.config.dev_mode {
        return Err(not_implemented("dev mail is only available in dev mode"));
    }
    let email = q.email.trim().to_ascii_lowercase();
    let e = ext(&app);
    let msgs = e.dev_mail.lock().get(&email).cloned().unwrap_or_default();
    let token = msgs.iter().rev().find_map(|m| m.token.clone());
    let latest = msgs.last().cloned();
    Ok(Json(json!({"email": email, "token": token, "latest": latest, "messages": msgs})))
}

#[derive(Deserialize)]
struct BulkCreateIn {
    #[serde(default)]
    start: u64,
    #[serde(default)]
    count: u64,
    /// Instead of `start..start+count`, so a load generator can send each
    /// node only the DIDs it owns.
    #[serde(default)]
    indices: Option<Vec<u64>>,
    records: BulkRecords,
    /// Unset: a random one nobody knows.
    #[serde(default)]
    password: Option<String>,
}

/// Genesis records: one count for every account, or one per account.
#[derive(Deserialize)]
#[serde(untagged)]
enum BulkRecords {
    All(u32),
    Each(Vec<u32>),
}

const BULK_MAX_ACCOUNTS: usize = 100_000;
const BULK_MAX_RECORDS: u64 = 1_000_000;
const BULK_EXISTS_CONCURRENCY: usize = 64;

/// Simulation only: accounts with deterministic DIDs (`state::bulk_did`)
/// and genesis posts. Emits the normal events but skips the handle claims
/// and never touches the PLC directory (benchmarks must not hammer a real
/// one). Idempotent, so a resumed range is safe.
async fn bulk_create(State(app): AppState, headers: HeaderMap, Json(inp): Json<BulkCreateIn>) -> XResult<Json<J>> {
    use futures::StreamExt;
    let tok = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).and_then(|v| v.strip_prefix("Bearer "));
    if !tok.is_some_and(|t| crate::auth::token_eq(&app.admin_token, t)) {
        return Err(XrpcError::auth("admin token required"));
    }
    if !(app.config.dev_mode || app.config.allow_bulk_create) {
        return Err(not_implemented("bulkCreate needs --dev-mode or --allow-bulk-create"));
    }
    let password_hash = bulk_password_hash(inp.password).await?;
    let idx: Vec<u64> = match inp.indices {
        Some(v) => v,
        None => {
            if inp.count as usize > BULK_MAX_ACCOUNTS {
                return Err(invalid_request(format!("at most {BULK_MAX_ACCOUNTS} accounts per request")));
            }
            (inp.start..inp.start.saturating_add(inp.count)).collect()
        }
    };
    if idx.len() > BULK_MAX_ACCOUNTS {
        return Err(invalid_request(format!("at most {BULK_MAX_ACCOUNTS} accounts per request")));
    }
    let records: Vec<u32> = match inp.records {
        BulkRecords::All(n) => vec![n; idx.len()],
        BulkRecords::Each(v) if v.len() == idx.len() => v,
        BulkRecords::Each(v) => {
            return Err(invalid_request(format!("records has {} entries for {} accounts", v.len(), idx.len())));
        }
    };
    if records.iter().map(|&n| n as u64).sum::<u64>() > BULK_MAX_RECORDS {
        return Err(invalid_request(format!("at most {BULK_MAX_RECORDS} genesis records per request")));
    }
    let mut not_owned = 0u64;
    let mut owned = Vec::with_capacity(idx.len());
    for (&i, &n) in idx.iter().zip(&records) {
        let did = state::bulk_did(i);
        match app.partitions.for_key(&did) {
            Some(p) => owned.push((i, n, did, p)),
            None => not_owned += 1,
        }
    }
    let checked: Vec<_> = futures::stream::iter(owned)
        .map(|(i, n, did, p)| async move {
            let exists = p.db.get(state::head_key(&did)).await.map(|h| h.is_some());
            (i, n, did, exists)
        })
        .buffered(BULK_EXISTS_CONCURRENCY)
        .collect()
        .await;
    let mut waits = Vec::with_capacity(checked.len());
    let mut existing = 0u64;
    for (i, n, did, exists) in checked {
        if exists.map_err(XrpcError::from_err)? {
            existing += 1;
            continue;
        }
        let handle = state::bulk_handle(i);
        let key = Arc::new(Keypair::generate());
        let (wrapped_signing_key, signing_pubkey) = app.secrets.wrap_signing_key(&did, &key).await?;
        let acct = Account {
            did: did.clone(),
            handle: handle.clone(),
            wrapped_signing_key,
            signing_pubkey,
            // a request's accounts share one hash (Argon2id is ~20 ms each)
            password_hash: password_hash.clone(),
            created_at: crate::events::now_rfc3339(),
            ..Default::default()
        };
        let mut recs = Vec::with_capacity(n as usize);
        for r in 0..n {
            let v = Value::from_json(&json!({
                "$type": "app.bsky.feed.post",
                "text": format!("genesis post {r} of account {i}"),
                "createdAt": "2026-09-30T00:00:00.000Z",
            }))
            .map_err(XrpcError::from_err)?;
            let bytes = v.to_cbor();
            let path = format!("app.bsky.feed.post/{}", app.tids.next());
            recs.push((path, Cid::dag_cbor(&bytes), Bytes::from(bytes)));
        }
        let (tx, rx) = oneshot::channel();
        app.workers
            .route(&did)
            .send(WorkerMsg::CreateRepo(CreateRepoReq {
                did: did.into(),
                handle,
                key,
                account_json: Bytes::from(serde_json::to_vec(&acct).unwrap()),
                records: recs,
                reply: tx,
            }))
            .map_err(XrpcError::from_err)?;
        waits.push((n, rx));
    }
    let (mut created, mut created_records, mut failed) = (0u64, 0u64, 0u64);
    for (n, w) in waits {
        match w.await {
            Ok(Ok(_)) => {
                created += 1;
                created_records += n as u64;
            }
            // created by a concurrent request since the head check (the
            // worker still holds it)
            Ok(Err(WriteError::Invalid(m))) if m == crate::worker::REPO_EXISTS => existing += 1,
            _ => failed += 1,
        }
    }
    Ok(Json(json!({
        "created": created, "records": created_records, "existing": existing,
        "notOwned": not_owned, "failed": failed,
    })))
}

/// The last password's hash is reused: a load generator sends the same one
/// on every request.
async fn bulk_password_hash(password: Option<String>) -> XResult<String> {
    static LAST: parking_lot::Mutex<Option<(String, String)>> = parking_lot::Mutex::new(None);
    let pw = match password {
        Some(p) if p.is_empty() => return Err(invalid_request("password must not be empty")),
        Some(p) => p,
        None => return Ok(BULK_RANDOM_PASSWORD_HASH.clone()),
    };
    if let Some((p, h)) = LAST.lock().as_ref() {
        if crate::auth::token_eq(p, &pw) {
            return Ok(h.clone());
        }
    }
    let p = pw.clone();
    let h =
        tokio::task::spawn_blocking(move || state::hash_password_blocking(&p)).await.map_err(XrpcError::from_err)?;
    *LAST.lock() = Some((pw, h.clone()));
    Ok(h)
}

static BULK_RANDOM_PASSWORD_HASH: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| state::hash_password_blocking(&hex::encode(rand::random::<[u8; 32]>())));

/// The shards a per-node maintenance call scans: those this node owns, or
/// of them only `only` (the CLI rerunning shards a move made it miss).
/// Answers carry `scanned` and `layoutVersion`, so the CLI can check that
/// the union of the nodes' answers covers the layout (a shard moving
/// between two nodes' calls is otherwise skipped by both).
fn scan_set(app: &App, only: &Option<Vec<crate::slots::ShardId>>) -> (Vec<Arc<Partition>>, J) {
    let mut parts = app.partitions.owned();
    if let Some(only) = only {
        parts.retain(|p| only.contains(&p.id));
    }
    parts.sort_by_key(|p| p.id);
    let ids: Vec<crate::slots::ShardId> = parts.iter().map(|p| p.id).collect();
    (parts, json!({"scanned": ids, "layoutVersion": app.partitions.layout().version}))
}

/// Every account of `parts`.
async fn accounts_of(parts: &[Arc<Partition>]) -> XResult<Vec<Account>> {
    let mut out = Vec::new();
    for p in parts {
        let mut it = state::FamilyScan::new(p.db.as_ref(), state::ACCOUNT_FAMILY, None, &Default::default())
            .await
            .map_err(XrpcError::from_err)?;
        while let Some(kv) = it.next().await.map_err(XrpcError::from_err)? {
            out.push(serde_json::from_slice(&kv.value).map_err(XrpcError::from_err)?);
        }
    }
    Ok(out)
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct RotatePlcIn {
    #[serde(default)]
    dry_run: bool,
    shards: Option<Vec<crate::slots::ShardId>>,
    actor: Option<String>,
}

/// The directory rate-limits.
const ROTATE_PLC_CONCURRENCY: usize = 4;

/// Moves this node's did:plc accounts off a retired server rotation key
/// (DESIGN.md "PLC identity"). Idempotent. `foreign`: DIDs that list none of
/// our keys (migrated away). Audited per node unless a dry run.
async fn rotate_plc_keys(
    State(app): AppState,
    Auth(creds): Auth,
    ClientIp(ip): ClientIp,
    body: Option<Json<RotatePlcIn>>,
) -> XResult<Json<J>> {
    use futures::StreamExt;
    require_admin(&creds)?;
    let plc = app.plc.clone().ok_or_else(|| invalid_request("PLC registration is off on this PDS"))?;
    let inp = body.map(|Json(b)| b).unwrap_or_default();
    let dry = inp.dry_run;
    let (parts, coverage) = scan_set(&app, &inp.shards);
    let dids: Vec<String> =
        accounts_of(&parts).await?.into_iter().map(|a| a.did).filter(|d| crate::plc::valid_plc_did(d)).collect();
    let accounts = dids.len();
    let results: Vec<(String, Result<crate::plc::KeyRotation, crate::plc::PlcError>)> = futures::stream::iter(dids)
        .map(|did| {
            let plc = plc.clone();
            async move {
                let r = plc.rotate_server_key(&did, dry).await;
                (did, r)
            }
        })
        .buffer_unordered(ROTATE_PLC_CONCURRENCY)
        .collect()
        .await;
    let (mut current, mut rotated, mut foreign) = (0u64, 0u64, 0u64);
    let mut errors = Vec::new();
    for (did, r) in results {
        match r {
            Ok(crate::plc::KeyRotation::Current) => current += 1,
            Ok(crate::plc::KeyRotation::Rotated) => rotated += 1,
            Ok(crate::plc::KeyRotation::Foreign) => foreign += 1,
            // synthetic (bulkCreate) DIDs were never registered
            Err(crate::plc::PlcError::NotFound(_)) => foreign += 1,
            Err(e) => errors.push(format!("{did}: {e}")),
        }
    }
    tracing::info!(
        accounts,
        current,
        rotated,
        foreign,
        errors = errors.len(),
        dry_run = dry,
        rotation_key = plc.rotation_did_key(),
        "rotate PLC keys"
    );
    let failed = errors.len();
    errors.truncate(20);
    if !dry {
        let detail = json!({
            "rotationKey": plc.rotation_did_key(), "accounts": accounts, "rotated": rotated,
            "current": current, "foreign": foreign, "failed": failed, "shards": coverage["scanned"].as_array().map_or(0, Vec::len),
        });
        let who = Who::of(&creds, inp.actor.as_deref(), ip);
        audit(&app, &who, "plc.rotate_keys", Some(&node_subject(&app)), None, None, Some(detail)).await?;
    }
    Ok(Json(with_coverage(
        coverage,
        json!({
            "rotationKey": plc.rotation_did_key(),
            "dryRun": dry,
            "accounts": accounts,
            "current": current,
            "rotated": rotated,
            "foreign": foreign,
            "failed": failed,
            "errors": errors,
        }),
    )))
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct EnsureRecoveryIn {
    #[serde(default)]
    dry_run: bool,
    shards: Option<Vec<crate::slots::ShardId>>,
    /// DIDs started per second (each is a directory read, plus a submit
    /// when the key is added).
    per_second: Option<f64>,
    actor: Option<String>,
}

const ENSURE_RECOVERY_PER_SECOND: f64 = 4.0;
const ENSURE_RECOVERY_CHANGES_SHOWN: usize = 50;

/// Lists `--plc-recovery-did-key` in the rotation keys of this node's
/// did:plc accounts that lack it (accounts made before it was set, or that
/// arrived with other keys), just ahead of the server key so keys the user
/// added stay first. Idempotent. Audited per node unless a dry run.
async fn ensure_recovery_key(
    State(app): AppState,
    Auth(creds): Auth,
    ClientIp(ip): ClientIp,
    body: Option<Json<EnsureRecoveryIn>>,
) -> XResult<Json<J>> {
    use crate::plc::RecoveryKeyOutcome as O;
    use futures::StreamExt;
    require_admin(&creds)?;
    let plc = app.plc.clone().ok_or_else(|| invalid_request("PLC registration is off on this PDS"))?;
    let recovery = plc
        .recovery_did_key()
        .map(str::to_string)
        .ok_or_else(|| invalid_request("no operator recovery key configured: set --plc-recovery-did-key"))?;
    let inp = body.map(|Json(b)| b).unwrap_or_default();
    let dry = inp.dry_run;
    let per_second = inp.per_second.unwrap_or(ENSURE_RECOVERY_PER_SECOND);
    if !(per_second > 0.0 && per_second <= 1000.0) {
        return Err(invalid_request("perSecond must be within (0, 1000]"));
    }
    let period = std::time::Duration::from_secs_f64(1.0 / per_second);
    let next = Arc::new(tokio::sync::Mutex::new(tokio::time::Instant::now()));
    let (parts, coverage) = scan_set(&app, &inp.shards);
    let dids: Vec<String> =
        accounts_of(&parts).await?.into_iter().map(|a| a.did).filter(|d| crate::plc::valid_plc_did(d)).collect();
    let accounts = dids.len();
    let results: Vec<(String, Result<crate::plc::RecoveryKeyChange, crate::plc::PlcError>)> =
        futures::stream::iter(dids)
            .map(|did| {
                let (plc, next) = (plc.clone(), next.clone());
                async move {
                    let at = {
                        let mut n = next.lock().await;
                        let at = (*n).max(tokio::time::Instant::now());
                        *n = at + period;
                        at
                    };
                    tokio::time::sleep_until(at).await;
                    let r = plc.ensure_recovery_key(&did, dry).await;
                    (did, r)
                }
            })
            .buffer_unordered(ROTATE_PLC_CONCURRENCY)
            .collect()
            .await;
    let (mut present, mut added, mut foreign, mut full) = (0u64, 0u64, 0u64, 0u64);
    let (mut errors, mut changes) = (Vec::new(), Vec::new());
    for (did, r) in results {
        match r {
            Ok(c) => match c.outcome {
                O::Present => present += 1,
                O::Foreign => foreign += 1,
                O::Full => {
                    full += 1;
                    errors.push(format!("{did}: rotation keys full, nothing added"));
                }
                O::Added => {
                    added += 1;
                    if changes.len() < ENSURE_RECOVERY_CHANGES_SHOWN {
                        changes.push(json!({"did": did, "before": c.before, "after": c.after}));
                    }
                }
            },
            Err(crate::plc::PlcError::NotFound(_)) => foreign += 1,
            Err(e) => errors.push(format!("{did}: {e}")),
        }
    }
    let failed = errors.len() as u64 - full;
    tracing::info!(accounts, present, added, foreign, full, failed, dry_run = dry, recovery_key = %recovery, "ensure PLC recovery key");
    errors.truncate(20);
    if !dry {
        let detail = json!({
            "recoveryKey": recovery, "accounts": accounts, "added": added, "present": present,
            "foreign": foreign, "full": full, "failed": failed, "shards": coverage["scanned"].as_array().map_or(0, Vec::len),
        });
        let who = Who::of(&creds, inp.actor.as_deref(), ip);
        audit(&app, &who, "plc.recovery_key", Some(&node_subject(&app)), None, None, Some(detail)).await?;
    }
    Ok(Json(with_coverage(
        coverage,
        json!({
            "recoveryKey": recovery,
            "dryRun": dry,
            "accounts": accounts,
            "present": present,
            "added": added,
            "foreign": foreign,
            "full": full,
            "failed": failed,
            "errors": errors,
            "changes": changes,
        }),
    )))
}

fn with_coverage(coverage: J, mut res: J) -> J {
    if let (Some(r), J::Object(c)) = (res.as_object_mut(), coverage) {
        r.extend(c);
    }
    res
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct RewrapIn {
    #[serde(default)]
    dry_run: bool,
    /// Also unwrap blobs already under the current KEK's id, to find ones
    /// under an older version of a Cloud KMS or Vault Transit key (one
    /// decrypt each).
    #[serde(default)]
    check_versions: bool,
    shards: Option<Vec<crate::slots::ShardId>>,
    actor: Option<String>,
}

/// Rewraps this node's secrets at rest (signing keys, reserved keys, TOTP)
/// under the current KEK (DESIGN.md "Secrets at rest"). Idempotent. Audited
/// per node with the counts and the KEK's id unless a dry run.
async fn rewrap_secrets(
    State(app): AppState,
    Auth(creds): Auth,
    ClientIp(ip): ClientIp,
    body: Option<Json<RewrapIn>>,
) -> XResult<Json<J>> {
    use crate::secrets::Purpose;
    use futures::StreamExt;
    require_admin(&creds)?;
    let inp = body.map(|Json(b)| b).unwrap_or_default();
    // a version rotation the node hasn't seen yet would count as current
    app.secrets.refresh_versions().await?;
    let started = std::time::Instant::now();
    let (parts, coverage) = scan_set(&app, &inp.shards);
    let dids: Vec<(String, String)> =
        accounts_of(&parts).await?.into_iter().map(|a| (a.did, a.wrapped_signing_key)).collect();
    let (accounts, check, dry) = (dids.len(), inp.check_versions, inp.dry_run);
    let app2 = app.clone();
    // (stale signing key, stale TOTP, error, blobs stored afterwards)
    let results: Vec<(bool, bool, Option<String>, Vec<String>)> = futures::stream::iter(dids)
        .map(|(did, blob)| {
            let app = app2.clone();
            async move {
                let mut kept = vec![blob.clone()];
                let r: XResult<(bool, bool)> = async {
                    let key_stale = if !check && app.secrets.is_current(&blob) {
                        false
                    } else if dry {
                        app.secrets.unwrap(Purpose::SigningKey, &did, &blob).await?.stale
                    } else {
                        match app.secrets.rewrap(Purpose::SigningKey, &did, &blob).await? {
                            None => false,
                            Some(new) => {
                                kept = vec![new.clone()];
                                update_account(&app, &did, false, false, move |a| {
                                    // unless rotated meanwhile
                                    if a.wrapped_signing_key == blob {
                                        a.wrapped_signing_key = new;
                                    }
                                    Ok(())
                                })
                                .await?;
                                true
                            }
                        }
                    };
                    let (totp_stale, totp_blobs) = crate::totp::rewrap(&app, &did, check, dry).await?;
                    // rewritten ones are under the latest version
                    if !totp_stale || dry {
                        kept.extend(totp_blobs);
                    }
                    Ok((key_stale, totp_stale))
                }
                .await;
                match r {
                    Ok((k, t)) => (k, t, None, kept),
                    Err(e) => (false, false, Some(format!("{did}: {}", e.message)), kept),
                }
            }
        })
        .buffer_unordered(16)
        .collect()
        .await;
    let mut errors: Vec<String> = Vec::new();
    let (mut keys, mut totp) = (0u64, 0u64);
    // kid -> the lowest key version still stored, for min_decryption_version
    let mut min_versions: std::collections::BTreeMap<String, u64> = Default::default();
    let mut note_version = |blob: &str| {
        if let Some((kid, v)) = app.secrets.blob_version(blob) {
            min_versions.entry(kid).and_modify(|m| *m = (*m).min(v)).or_insert(v);
        }
    };
    for (k, t, e, kept) in results {
        keys += k as u64;
        totp += t as u64;
        errors.extend(e);
        kept.iter().for_each(|b| note_version(b));
    }
    // the did:key-indexed rows carry the wrapped key
    let mut reserved = 0u64;
    for (routing, name, val) in super::server::scan_private_routing_in(&parts, "_reserved:").await? {
        let Some(did_key) = routing.strip_prefix("_reserved:").filter(|r| r.starts_with("did:key:") && name == "k")
        else {
            continue;
        };
        let Ok(mut rec) = serde_json::from_slice::<J>(&val) else { continue };
        let Some(blob) = rec["key"].as_str().map(str::to_string) else { continue };
        if !check && app.secrets.is_current(&blob) {
            continue;
        }
        let r = if dry {
            app.secrets.unwrap(Purpose::ReservedKey, did_key, &blob).await.map(|u| u.stale.then_some(String::new()))
        } else {
            app.secrets.rewrap(Purpose::ReservedKey, did_key, &blob).await
        };
        match r {
            Ok(None) => note_version(&blob),
            Ok(Some(_)) if dry => {
                note_version(&blob);
                reserved += 1
            }
            Ok(Some(new)) => {
                note_version(&new);
                rec["key"] = json!(new);
                app.put_private(&routing, vec![pmut(&routing, "k", Some(to_json_bytes(&rec)))]).await?;
                reserved += 1;
            }
            Err(e) => {
                note_version(&blob);
                errors.push(format!("{did_key}: {e}"))
            }
        }
    }
    let stale = keys + totp + reserved;
    tracing::info!(
        accounts,
        signing_keys = keys,
        totp,
        reserved,
        errors = errors.len(),
        dry_run = dry,
        kek = app.secrets.current_kid(),
        elapsed_ms = started.elapsed().as_millis() as u64,
        "rewrap secrets"
    );
    let failed = errors.len();
    errors.truncate(20);
    if !dry {
        let detail = json!({
            "kek": app.secrets.current_kid(), "accounts": accounts, "signingKeys": keys, "totpSecrets": totp,
            "reservedKeys": reserved, "failed": failed, "shards": coverage["scanned"].as_array().map_or(0, Vec::len),
        });
        let who = Who::of(&creds, inp.actor.as_deref(), ip);
        audit(&app, &who, "secrets.rewrap", Some(&node_subject(&app)), None, None, Some(detail)).await?;
    }
    Ok(Json(with_coverage(
        coverage,
        json!({
            "kek": app.secrets.current_kid(),
            "dryRun": dry,
            "accounts": accounts,
            // stale secrets found (dry run) or rewrapped
            "stale": stale,
            "signingKeys": keys,
            "totpSecrets": totp,
            "reservedKeys": reserved,
            "failed": failed,
            "errors": errors,
            // per kid with readable versions (Vault): the lowest still stored
            "minKeyVersions": min_versions,
        }),
    )))
}
