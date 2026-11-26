//! The space host's calls out (reference `space-policy/manager.ts`,
//! `space-notifications.ts` and `api/com/atproto/space/util.ts`): asking a
//! managing app for an account's access (service auth from the authority,
//! `aud` the `did#serviceId` reference as published), and the calls to a
//! syncer's registered endpoint: confirming a registration, and
//! notifySpaceUpdate (no auth: the registration's token is in the body).
//! Every call goes through the SSRF-guarded client with a 10 s timeout and
//! a small response cap.

use super::rows::{LegacyNotifyRow, RegRow};
use crate::state::{self, SpaceId};
use crate::xrpc::App;
use serde_json::{json, Value as J};
use std::time::Duration;
use vlatproto::tid::Tid;

pub const CALL_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_RESPONSE: usize = 64 << 10;
/// A registered endpoint (`sG` rows hold u16-length strings).
pub const MAX_ENDPOINT: usize = 2048;
/// A registration's token (the lexicon's maxLength).
pub const MAX_TOKEN: usize = 512;

/// Reference `resolveServiceEndpoint`: a `did#serviceId` reference's
/// service entry.
pub async fn resolve_service_endpoint(app: &App, service: &str) -> Option<String> {
    let (did, id) = service.split_once('#')?;
    if !vlatproto::syntax::valid_did(did) || id.is_empty() {
        return None;
    }
    let doc = match app.did_resolver.resolve(did).await {
        Ok(d) => d,
        Err(e) => {
            tracing::info!(service, "could not resolve service did: {e:?}");
            return None;
        }
    };
    vlatproto::did_resolver::service_endpoint(&doc, id).filter(|e| e.len() <= MAX_ENDPOINT)
}

/// A send's error for the logs, without its URL: a query names the space
/// and its members, which the logs must not (privacy.md).
pub(crate) fn http_error(what: &str, e: reqwest::Error) -> String {
    format!("{what}: {}", e.without_url())
}

/// A call to `service` at `endpoint` as `iss` (an account hosted here):
/// Ok(status, JSON body) once it answered.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn call(
    app: &App,
    client: vlatproto::http::Guarded,
    iss: &str,
    service: &str,
    endpoint: &str,
    lxm: &str,
    method: reqwest::Method,
    query: &[(&str, &str)],
    body: Option<&J>,
) -> Result<(u16, J), String> {
    let (key, _) = crate::xrpc::proxy::account_key_status(app, iss).await.map_err(|e| e.message)?;
    let jwt = crate::auth::service_auth_jwt(&key, iss, service, Some(lxm), 60).map_err(|e| e.to_string())?;
    let url = format!("{}/xrpc/{lxm}", endpoint.trim_end_matches('/'));
    let mut rb = client.request(method, &url)?.bearer_auth(jwt).timeout(CALL_TIMEOUT);
    if !query.is_empty() {
        rb = rb.query(query);
    }
    if let Some(b) = body {
        rb = rb.json(b);
    }
    let mut r = rb.send().await.map_err(|e| http_error(&url, e))?;
    let status = r.status().as_u16();
    let mut buf = Vec::new();
    while let Some(c) = r.chunk().await.map_err(|e| http_error(&url, e))? {
        if buf.len() + c.len() > MAX_RESPONSE {
            return Err(format!("{url}: response too large"));
        }
        buf.extend_from_slice(&c);
    }
    Ok((status, serde_json::from_slice(&buf).unwrap_or(J::Null)))
}

/// Reference `checkAccess`: the managing app's (read, write) for `repo`
/// (None: a read without a delegation token) and the attested client.
/// Err when it can't be had (unresolvable, unreachable, any error or a
/// malformed answer): failing open would hand credentials out for the
/// spaces that asked for the strictest gate, and denying would be taken as
/// a loss of access (a registration withdrawn, a repo host's notify
/// dropped rather than retried).
pub async fn check_access(
    app: &App,
    space: &str,
    authority: &str,
    managing_app: &str,
    repo: Option<&str>,
    client_id: Option<&str>,
) -> Result<(bool, bool), String> {
    let lxm = "com.atproto.managedspace.checkAccess";
    let log_id = crate::state::space_log_id(space);
    let Some(endpoint) = resolve_service_endpoint(app, managing_app).await else {
        tracing::info!(space = %log_id, managing_app, "could not resolve managing app");
        return Err("could not resolve the managing app".into());
    };
    let mut q = vec![("space", space)];
    if let Some(r) = repo {
        q.push(("repo", r));
    }
    if let Some(c) = client_id {
        q.push(("clientId", c));
    }
    let client = vlatproto::http::guarded(app.config.dev_mode);
    match call(app, client, authority, managing_app, &endpoint, lxm, reqwest::Method::GET, &q, None).await {
        Ok((200, body)) => match (body["read"].as_bool(), body["write"].as_bool()) {
            (Some(read), Some(write)) => Ok((read, write)),
            _ => {
                tracing::info!(space = %log_id, managing_app, "managing app check: malformed answer");
                Err("the managing app's answer is malformed".into())
            }
        },
        Ok((status, _)) => {
            tracing::info!(space = %log_id, managing_app, status, "managing app check failed");
            Err(format!("the managing app answered {status}"))
        }
        Err(e) => {
            tracing::info!(space = %log_id, managing_app, "managing app check failed: {e}");
            Err("the managing app did not answer".into())
        }
    }
}

/// Registrations (live or lapsed) a space may hold.
pub const MAX_REGISTRATIONS: usize = 256;

/// Registrations across one authority's spaces: each space's cap alone
/// would let one account's spaces register without end.
pub const MAX_REGISTRATIONS_PER_AUTHORITY: usize = 1024;

/// Registrations across `authority`'s spaces, counted up to `stop_at`.
pub async fn authority_registrations(app: &App, authority: &str, stop_at: usize) -> anyhow::Result<usize> {
    let p = app.partition(authority).map_err(|e| anyhow::anyhow!("{}", e.message))?;
    let prefix = state::space_did_prefix(state::SPACE_REG_FAMILY, authority);
    let mut it = p.db.scan(prefix.clone()..vlsync_store::keys::prefix_end(&prefix)).await?;
    let mut n = 0;
    while it.next().await?.is_some() {
        n += 1;
        if n >= stop_at {
            break;
        }
    }
    Ok(n)
}

/// One registration of a space.
#[derive(Clone, Debug)]
pub struct Registration {
    pub id: [u8; 32],
    pub row: RegRow,
}

/// A space's registrations (`sG`) from the authority's shard, active and
/// lapsed, and the keys of its registerNotify rows (`sN`) that have
/// expired.
#[derive(Default, Debug)]
pub struct Registrations {
    pub active: Vec<Registration>,
    pub lapsed: Vec<Registration>,
    pub legacy_expired: Vec<Vec<u8>>,
}

impl Registrations {
    pub fn all(&self) -> impl Iterator<Item = &Registration> {
        self.active.iter().chain(&self.lapsed)
    }
}

pub async fn registrations(app: &App, authority: &str, sid: &SpaceId) -> anyhow::Result<Registrations> {
    let p = app.partition(authority).map_err(|e| anyhow::anyhow!("{}", e.message))?;
    let opts = slatedb::config::ScanOptions::default();
    let now = vlatproto::tid::now_micros();
    let mut out = Registrations::default();
    let prefix = state::space_prefix(state::SPACE_REG_FAMILY, authority, sid);
    let mut it = p.db.scan_with_options(prefix.clone()..vlsync_store::keys::prefix_end(&prefix), &opts).await?;
    while let Some(kv) = it.next().await? {
        let id: [u8; 32] = kv.key[prefix.len()..].try_into().map_err(|_| anyhow::anyhow!("bad registration key"))?;
        let row = RegRow::decode(&kv.value)?;
        match row.lapsed(now) {
            false => out.active.push(Registration { id, row }),
            true => out.lapsed.push(Registration { id, row }),
        }
    }
    let prefix = state::space_prefix(state::SPACE_NOTIFY_FAMILY, authority, sid);
    let mut it = p.db.scan_with_options(prefix.clone()..vlsync_store::keys::prefix_end(&prefix), &opts).await?;
    while let Some(kv) = it.next().await? {
        if LegacyNotifyRow::decode(&kv.value).map_or(true, |r| r.expires <= now) {
            out.legacy_expired.push(kv.key.to_vec());
        }
    }
    Ok(out)
}

/// What a forward tells a syncer of: a writer's new state, or its removal
/// from the writer set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Update {
    Write { repo_rev: Tid, hash: [u8; 32] },
    Removed,
}

/// One forward of a sequenced change to a registered endpoint.
#[derive(Clone, Debug)]
pub struct Forward {
    pub authority: std::sync::Arc<str>,
    pub uri: std::sync::Arc<str>,
    pub reg: [u8; 32],
    pub endpoint: String,
    pub token: String,
    pub writer: String,
    pub update: Update,
    pub space_rev: Tid,
    pub prev_space_rev: Option<Tid>,
    /// The registration's expiry (unix µs).
    pub expires: u64,
}

fn b64(b: &[u8]) -> J {
    use base64::Engine;
    json!({"$bytes": base64::engine::general_purpose::STANDARD_NO_PAD.encode(b)})
}

/// How a call to a syncer's endpoint ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sent {
    Delivered,
    /// A status not worth retrying.
    Refused(String),
    Retry(String),
}

/// A POST of `body` to `{endpoint}/xrpc/{lxm}` with no auth, as the
/// reference's `xrpc` over `safeFetch` calls an endpoint a syncer chose:
/// (status, JSON body).
async fn post_endpoint(app: &App, endpoint: &str, lxm: &str, body: &J) -> Result<(u16, J), String> {
    let url = format!("{}/xrpc/{lxm}", endpoint.trim_end_matches('/'));
    let client = vlatproto::http::guarded_fanout(app.config.dev_mode);
    let mut r =
        client.request(reqwest::Method::POST, &url)?.timeout(CALL_TIMEOUT).json(body).send().await.map_err(|e| {
            // the endpoint is the syncer's; the logs keep its host only
            http_error(lxm, e)
        })?;
    let status = r.status().as_u16();
    let mut buf = Vec::new();
    while let Some(c) = r.chunk().await.map_err(|e| http_error(lxm, e))? {
        if buf.len() + c.len() > MAX_RESPONSE {
            return Err(format!("{lxm}: response too large"));
        }
        buf.extend_from_slice(&c);
    }
    Ok((status, serde_json::from_slice(&buf).unwrap_or(J::Null)))
}

fn outcome(r: Result<(u16, J), String>) -> Sent {
    match r {
        Ok((s, _)) if (200..300).contains(&s) => Sent::Delivered,
        Ok((s, b)) if crate::xrpc::space::retryable_status(s) => Sent::Retry(describe(s, &b)),
        Ok((s, b)) => Sent::Refused(describe(s, &b)),
        Err(e) => Sent::Retry(e),
    }
}

/// A failed XRPC answer for the logs: `status {s}: {error}: {message}`. The
/// logs name spaces by id only, so a word of the message naming a DID or
/// an AT URI is left out, and the message is cut at 200 chars.
pub fn describe(status: u16, body: &J) -> String {
    let mut out = format!("status {status}");
    if let Some(e) = body["error"].as_str() {
        out += &format!(": {}", scrub(e));
    }
    if let Some(m) = body["message"].as_str() {
        out += &format!(": {}", scrub(m));
    }
    out
}

fn scrub(s: &str) -> String {
    let words: Vec<&str> =
        s.split_whitespace().map(|w| if w.contains("did:") || w.contains("at:") { "…" } else { w }).collect();
    let s: String = words.join(" ").chars().filter(|c| !c.is_control()).collect();
    match s.char_indices().nth(200) {
        Some((i, _)) => format!("{}…", &s[..i]),
        None => s,
    }
}

/// [`describe`] of a response, reading at most 4 KiB of its body.
pub async fn describe_response(mut r: reqwest::Response) -> String {
    let status = r.status().as_u16();
    let mut buf = Vec::new();
    while let Ok(Some(c)) = r.chunk().await {
        buf.extend_from_slice(&c);
        if buf.len() > 4 << 10 {
            break;
        }
    }
    describe(status, &serde_json::from_slice(&buf).unwrap_or(J::Null))
}

/// Reference `confirmRegistration`: before a registration is made, its
/// endpoint must know the token as one it issued for this space and echo a
/// random challenge.
pub async fn confirm_registration(app: &App, space: &str, endpoint: &str, token: &str) -> Result<(), String> {
    let challenge = super::token::new_jti();
    let body = json!({"space": space, "token": token, "challenge": challenge});
    match post_endpoint(app, endpoint, "com.atproto.space.confirmRegistration", &body).await {
        Ok((200, b)) if b["challenge"].as_str() == Some(challenge.as_str()) => Ok(()),
        Ok((s, _)) => Err(format!("status {s}")),
        Err(e) => Err(e),
    }
}

/// notifySpaceUpdate with `update` (a `$type`d union member).
pub async fn notify_space_update(app: &App, space: &str, endpoint: &str, token: &str, update: J) -> Sent {
    let body = json!({"space": space, "token": token, "update": update});
    outcome(post_endpoint(app, endpoint, "com.atproto.space.notifySpaceUpdate", &body).await)
}

/// A forward, naming `prev` as the spaceRev before it: "ok", "refused" or
/// "error".
pub async fn forward(app: &App, f: &Forward, prev: Option<Tid>) -> &'static str {
    let mut update = match &f.update {
        Update::Write { repo_rev, hash } => json!({
            "$type": "com.atproto.space.defs#repoWrite",
            "repo": f.writer,
            "repoRev": repo_rev.to_string(),
            "data": b64(hash),
            "spaceRev": f.space_rev.to_string(),
        }),
        Update::Removed => json!({
            "$type": "com.atproto.space.defs#repoRemoved",
            "repo": f.writer,
            "spaceRev": f.space_rev.to_string(),
        }),
    };
    if let Some(p) = prev {
        update["prevSpaceRev"] = json!(p.to_string());
    }
    let log_id = crate::state::space_log_id(&f.uri);
    match notify_space_update(app, &f.uri, &f.endpoint, &f.token, update).await {
        Sent::Delivered => "ok",
        Sent::Retry(e) => {
            tracing::info!(space = %log_id, "space notify forward failed: {e}");
            "error"
        }
        Sent::Refused(e) => {
            tracing::info!(space = %log_id, "space notify forward refused: {e}");
            "refused"
        }
    }
}

/// How long the authority waits on a writer's host to confirm a same-rev
/// hash: well inside the writer's own 10 s notify timeout.
const CHECK_TIMEOUT: Duration = Duration::from_secs(5);

/// Ok when `writer`'s host serves `hash` at `rev` in `space` now: its
/// getLatestCommit, read as a syncer reads it with a credential `authority`
/// issues itself, its MAC keyed against `writer`'s `#atproto_kem` key. A
/// commit's hash is the author's claim only when it comes from the author's
/// host, MACed for this request, which is what this asks for.
pub async fn check_served_hash(
    app: &App,
    space: &str,
    authority: &str,
    writer: &str,
    rev: Tid,
    hash: &[u8; 32],
) -> Result<(), String> {
    let doc = app.did_resolver.resolve(writer).await.map_err(|e| format!("could not resolve the writer: {e:?}"))?;
    match served_commit(app, &doc, space, authority, writer).await {
        Err(e) if e == MAC_MISMATCH => {
            // the KEM key may have rotated since the document was cached
            if !app.did_resolver.refresh(writer) {
                return Err(e);
            }
            let doc =
                app.did_resolver.resolve(writer).await.map_err(|e| format!("could not resolve the writer: {e:?}"))?;
            check_commit(served_commit(app, &doc, space, authority, writer).await?, rev, hash)
        }
        r => check_commit(r?, rev, hash),
    }
}

const MAC_MISMATCH: &str = "the commit's MAC doesn't verify against the writer's KEM key";

fn check_commit(c: super::commit::Commit, rev: Tid, hash: &[u8; 32]) -> Result<(), String> {
    if c.rev != rev.to_string() {
        return Err(format!("the writer's host is at {}", c.rev));
    }
    if c.data != *hash {
        return Err("the writer's host serves another hash".into());
    }
    Ok(())
}

/// The writer's getLatestCommit, its MAC verified.
async fn served_commit(
    app: &App,
    doc: &J,
    space: &str,
    authority: &str,
    writer: &str,
) -> Result<super::commit::Commit, String> {
    use p256::ecdsa::signature::Signer;
    let endpoint = vlatproto::did_resolver::service_endpoint(doc, "atproto_pds").ok_or("the writer names no PDS")?;
    let kem = super::mac::kem_key_of(doc).ok_or("the writer publishes no KEM key")?;
    let (share, secret) = super::mac::encapsulate(&kem).map_err(|e| e.0.to_string())?;
    let (key, _) = crate::xrpc::proxy::account_key_status(app, authority).await.map_err(|e| e.message)?;
    let holder = <p256::ecdsa::SigningKey as p256::elliptic_curve::Generate>::generate();
    let mut mk = vec![0x80, 0x24];
    mk.extend_from_slice(holder.verifying_key().to_sec1_point(true).as_bytes());
    let holder_did = format!("did:key:z{}", bs58::encode(mk).into_string());
    let mint = super::token::Mint {
        iss: authority,
        sub: space,
        key_id: Some(&holder_did),
        expires_in_secs: Some(60),
        ..Default::default()
    };
    let now = vlatproto::tid::now_micros() as i64 / 1_000_000;
    let jti = super::token::new_jti();
    let cred = super::token::encode(super::token::TokenType::Credential, &mint, "ES256K", now, &jti, |b| {
        Ok::<_, std::convert::Infallible>(key.sign(b))
    })
    .map_err(|e| format!("credential: {e:?}"))?;
    let signed = super::httpsig::headers(&cred, writer, |b| {
        let sig: p256::ecdsa::Signature = holder.sign(b);
        sig.to_bytes().into()
    });
    let url = format!("{}/xrpc/com.atproto.space.getLatestCommit", endpoint.trim_end_matches('/'));
    let mut req = vlatproto::http::guarded(app.config.dev_mode)
        .request(reqwest::Method::GET, &url)?
        .query(&[("space", space), ("repo", writer)])
        .header(super::mac::ACCEPT_SIGNATURE, super::mac::format_request(super::mac::Profile::Commit, &share));
    for (k, v) in signed {
        req = req.header(k, v);
    }
    let mut r = req.timeout(CHECK_TIMEOUT).send().await.map_err(|e| http_error("getLatestCommit", e))?;
    if !r.status().is_success() {
        return Err(format!("getLatestCommit: {}", r.status()));
    }
    let headers = r.headers().clone();
    let mut buf = Vec::new();
    while let Some(c) = r.chunk().await.map_err(|e| http_error("getLatestCommit", e))? {
        if buf.len() + c.len() > MAX_RESPONSE {
            return Err("getLatestCommit: response too large".into());
        }
        buf.extend_from_slice(&c);
    }
    let body: J = serde_json::from_slice(&buf).map_err(|_| "getLatestCommit: not JSON")?;
    let commit = super::commit::Commit::from_json(&body["commit"]).ok_or("getLatestCommit: malformed commit")?;
    let header = |name: &str| {
        let lines: Vec<&str> = headers.get_all(name).iter().filter_map(|v| v.to_str().ok()).collect();
        (!lines.is_empty()).then(|| lines.join(", "))
    };
    if commit.repo != writer || commit.space != space {
        return Err("getLatestCommit: a commit for another repo".into());
    }
    if super::mac::verify_commit(&commit, &share, &secret, &header).is_err() {
        return Err(MAC_MISMATCH.into());
    }
    Ok(commit)
}

#[cfg(test)]
mod tests {
    /// An unreachable endpoint's error names neither the space nor the
    /// member its query carried.
    #[tokio::test]
    async fn send_errors_leave_the_url_out() {
        let space = "at:space/did:plc:secretauthority0000000000/com.example.group/skey";
        let e = reqwest::Client::new()
            .get("http://127.0.0.1:1/xrpc/com.atproto.space.getLatestCommit")
            .query(&[("space", space), ("repo", "did:plc:secretmember")])
            .send()
            .await
            .unwrap_err();
        assert!(e.to_string().contains("secret"), "reqwest names the URL: {e}");
        let logged = super::http_error("getLatestCommit", e);
        assert!(!logged.contains("secret") && !logged.contains("did:plc"), "{logged}");
    }

    /// A refusal's error and message reach the logs, without the space or
    /// member they may echo.
    #[test]
    fn refusals_name_the_error() {
        let body = serde_json::json!({
            "error": "InvalidRequest",
            "message": "Invalid space-ref: at:space/did:plc:secretauthority/com.example.group/skey (from did:plc:secretmember)",
        });
        let d = super::describe(400, &body);
        assert_eq!(d, "status 400: InvalidRequest: Invalid space-ref: … (from …");
        assert_eq!(super::describe(502, &serde_json::Value::Null), "status 502");
        let long = super::describe(400, &serde_json::json!({"message": "x".repeat(300)}));
        assert_eq!(long.chars().count(), "status 400: ".len() + 201);
    }
}
