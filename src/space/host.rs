//! The space host's calls out (reference `simplespace/manager.ts` and
//! `api/com/atproto/space/util.ts`): resolving a service identifier,
//! asking a managing app whether a user may read or write, and forwarding
//! a sequenced write to a registered service (notifySpaceDeleted is
//! [`super::deletions`]'s). Every call goes through the SSRF-guarded
//! client with service auth from the authority (`aud` = the service
//! identifier as published), a 10 s timeout and a small response cap.

use super::rows::NotifyRow;
use crate::state::{self, SpaceId};
use crate::xrpc::App;
use serde_json::{json, Value as J};
use std::time::Duration;
use vlatproto::tid::Tid;

pub const CALL_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_RESPONSE: usize = 64 << 10;
/// Endpoints are kept in `sN` rows (u16-length strings).
const MAX_ENDPOINT: usize = 2048;

/// How long a notify registration lasts (the reference's
/// `REGISTRATION_TTL_MS`).
pub const REGISTRATION_TTL: Duration = Duration::from_secs(24 * 3600);

/// Reference `resolveServiceEndpoint`: `did#fragment` names that service
/// entry; a bare DID its PDS.
pub async fn resolve_service_endpoint(app: &App, service: &str) -> Option<String> {
    let (did, fragment) = match service.split_once('#') {
        Some((d, f)) => (d, Some(f)),
        None => (service, None),
    };
    if !vlatproto::syntax::valid_did(did) {
        return None;
    }
    let doc = match app.did_resolver.resolve(did).await {
        Ok(d) => d,
        Err(e) => {
            tracing::info!(service, "could not resolve service did: {e:?}");
            return None;
        }
    };
    let ep = match fragment {
        Some(f) => vlatproto::did_resolver::service_endpoint(&doc, f),
        None => vlatproto::did_resolver::service_endpoint(&doc, "atproto_pds"),
    };
    ep.filter(|e| e.len() <= MAX_ENDPOINT)
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

/// Reference `checkManagingApp`: the managing app's answer, and a denial
/// whenever it can't be had (unresolvable, unreachable, any error), since
/// failing open would hand credentials out for the spaces that asked for
/// the strictest gate.
pub async fn check_user_access(
    app: &App,
    space: &str,
    authority: &str,
    managing_app: &str,
    user: &str,
    access: &str,
    client_id: Option<&str>,
) -> bool {
    let lxm = "com.atproto.managedspace.checkUserAccess";
    let Some(endpoint) = resolve_service_endpoint(app, managing_app).await else {
        tracing::info!(space = %crate::state::space_log_id(space), managing_app, "could not resolve managing app");
        return false;
    };
    let mut q = vec![("space", space), ("user", user), ("access", access)];
    if let Some(c) = client_id {
        q.push(("clientId", c));
    }
    let client = vlatproto::http::guarded(app.config.dev_mode);
    match call(app, client, authority, managing_app, &endpoint, lxm, reqwest::Method::GET, &q, None).await {
        Ok((200, body)) => body["authorized"] == J::Bool(true),
        Ok((status, _)) => {
            tracing::info!(space = %crate::state::space_log_id(space), managing_app, status, "managing app check failed");
            false
        }
        Err(e) => {
            tracing::info!(space = %crate::state::space_log_id(space), managing_app, "managing app check failed: {e}");
            false
        }
    }
}

/// Live notify registrations a space may hold.
pub const MAX_REGISTRATIONS: usize = 256;
/// A registered service identifier (a DID and an optional fragment).
pub const MAX_SERVICE_LEN: usize = 512;

/// Live notify registrations across one authority's spaces: each space's
/// cap alone would let one account's spaces register without end.
pub const MAX_REGISTRATIONS_PER_AUTHORITY: usize = 1024;

/// Live registrations across `authority`'s spaces, counted up to `stop_at`.
pub async fn authority_registrations(app: &App, authority: &str, stop_at: usize) -> anyhow::Result<usize> {
    let p = app.partition(authority).map_err(|e| anyhow::anyhow!("{}", e.message))?;
    let prefix = state::space_did_prefix(state::SPACE_NOTIFY_FAMILY, authority);
    let mut it = p.db.scan(prefix.clone()..vlsync_store::keys::prefix_end(&prefix)).await?;
    let now = vlatproto::tid::now_micros();
    let mut n = 0;
    while let Some(kv) = it.next().await? {
        if NotifyRow::decode(&kv.value)?.expires > now {
            n += 1;
            if n >= stop_at {
                break;
            }
        }
    }
    Ok(n)
}

/// A space's registrations (`sN`) from the authority's shard: the live
/// ones, and the services of expired ones.
pub async fn registrations(
    app: &App,
    authority: &str,
    sid: &SpaceId,
) -> anyhow::Result<(Vec<(String, NotifyRow)>, Vec<String>)> {
    let p = app.partition(authority).map_err(|e| anyhow::anyhow!("{}", e.message))?;
    let prefix = state::space_prefix(state::SPACE_NOTIFY_FAMILY, authority, sid);
    let opts = slatedb::config::ScanOptions::default();
    let mut it = p.db.scan_with_options(prefix.clone()..vlsync_store::keys::prefix_end(&prefix), &opts).await?;
    let now = vlatproto::tid::now_micros();
    let (mut live, mut expired) = (Vec::new(), Vec::new());
    while let Some(kv) = it.next().await? {
        let service = std::str::from_utf8(&kv.key[prefix.len()..])?.to_string();
        let row = NotifyRow::decode(&kv.value)?;
        match row.expires > now {
            true => live.push((service, row)),
            false => expired.push(service),
        }
    }
    Ok((live, expired))
}

/// One forward of a sequenced write to a registered service.
pub struct Forward {
    pub authority: std::sync::Arc<str>,
    pub uri: std::sync::Arc<str>,
    pub service: String,
    pub endpoint: String,
    pub writer: String,
    pub repo_rev: Tid,
    pub hash: [u8; 32],
    pub space_rev: Tid,
    pub prev_space_rev: Option<Tid>,
    /// The registration's expiry (unix µs).
    pub expires: u64,
}

fn b64(b: &[u8]) -> J {
    use base64::Engine;
    json!({"$bytes": base64::engine::general_purpose::STANDARD_NO_PAD.encode(b)})
}

/// notifyWrite to a registered service, as the reference forwards it (the
/// writer's notify plus the spaceRevs), naming `prev` as the spaceRev
/// before it: "ok", "refused" (a status not worth retrying) or "error".
pub async fn forward(app: &App, f: &Forward, prev: Option<Tid>) -> &'static str {
    let lxm = "com.atproto.space.notifyWrite";
    let mut body = json!({
        "space": &*f.uri,
        "repo": f.writer,
        "repoRev": f.repo_rev.to_string(),
        "data": b64(&f.hash),
        "spaceRev": f.space_rev.to_string(),
    });
    if let Some(p) = prev {
        body["prevSpaceRev"] = json!(p.to_string());
    }
    let client = vlatproto::http::guarded_fanout(app.config.dev_mode);
    let post = reqwest::Method::POST;
    match call(app, client, &f.authority, &f.service, &f.endpoint, lxm, post, &[], Some(&body)).await {
        Ok((s, _)) if (200..300).contains(&s) => "ok",
        Ok((s, _)) if crate::xrpc::space::retryable_status(s) => {
            tracing::info!(space = %crate::state::space_log_id(&f.uri), service = f.service, status = s, "space notify forward failed");
            "error"
        }
        Ok((s, _)) => {
            tracing::info!(space = %crate::state::space_log_id(&f.uri), service = f.service, status = s, "space notify forward refused");
            "refused"
        }
        Err(e) => {
            tracing::info!(space = %crate::state::space_log_id(&f.uri), service = f.service, "space notify forward failed: {e}");
            "error"
        }
    }
}

/// How long the authority waits on a writer's host to confirm a same-rev
/// hash: well inside the writer's own 10 s notify timeout.
const CHECK_TIMEOUT: Duration = Duration::from_secs(5);

/// Ok when `writer`'s host serves `hash` at `rev` in `space` now: its
/// getLatestCommit, read as a syncer reads it, with a credential
/// `authority` issues itself and a MAC against `writer`'s `#atproto_kem`
/// key. A commit's data is the author's host's claim only under a MAC its
/// response carried, which is what this checks. A MAC that fails is asked
/// for once more after the writer's document is refetched (its KEM key may
/// have rotated).
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
        Err(Checked::Mac(_)) if app.did_resolver.refresh(writer) => {
            let doc =
                app.did_resolver.resolve(writer).await.map_err(|e| format!("could not resolve the writer: {e:?}"))?;
            served_commit(app, &doc, space, authority, writer).await
        }
        r => r,
    }
    .map_err(|e| match e {
        Checked::Mac(m) | Checked::Other(m) => m,
    })
    .and_then(|c| {
        if c.rev != rev.to_string() {
            return Err(format!("the writer's host is at {}", c.rev));
        }
        if c.data[..] != hash[..] {
            return Err("the writer's host serves another hash".into());
        }
        Ok(())
    })
}

enum Checked {
    /// The MAC didn't verify (or the writer has no usable KEM key).
    Mac(String),
    Other(String),
}

/// One getLatestCommit at the writer's host, its MAC verified.
async fn served_commit(
    app: &App,
    doc: &J,
    space: &str,
    authority: &str,
    writer: &str,
) -> Result<super::commit::Commit, Checked> {
    use p256::ecdsa::signature::Signer;
    let other = Checked::Other;
    let endpoint = vlatproto::did_resolver::service_endpoint(doc, "atproto_pds")
        .ok_or_else(|| other("the writer names no PDS".into()))?;
    let kem_key =
        super::kem::kem_key_of(doc).ok_or_else(|| Checked::Mac("the writer has no #atproto_kem key".into()))?;
    let (key, _) = crate::xrpc::proxy::account_key_status(app, authority).await.map_err(|e| other(e.message))?;
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
    .map_err(|e| other(format!("credential: {e:?}")))?;
    let (share, secret) = super::kem::encapsulate(&kem_key).map_err(|e| Checked::Mac(e.to_string()))?;
    let url = format!("{}/xrpc/com.atproto.space.getLatestCommit", endpoint.trim_end_matches('/'));
    let mut rb = vlatproto::http::guarded(app.config.dev_mode)
        .request(reqwest::Method::GET, &url)
        .map_err(other)?
        .query(&[("space", space), ("repo", writer)])
        .header(super::mac::WANT_MAC_HEADER, super::mac::format_want_mac(super::mac::COMMIT_MAC_TYPE, &share))
        .timeout(CHECK_TIMEOUT);
    let signed = super::httpsig::sign_headers(&cred, writer, |b| {
        let sig: p256::ecdsa::Signature = holder.sign(b);
        sig.to_bytes().into()
    });
    for (k, v) in signed {
        rb = rb.header(k, v);
    }
    let mut r = rb.send().await.map_err(|e| other(http_error("getLatestCommit", e)))?;
    if !r.status().is_success() {
        return Err(other(format!("getLatestCommit: {}", r.status())));
    }
    let mac_value = r.headers().get(super::mac::MAC_HEADER).and_then(|v| v.to_str().ok()).map(String::from);
    let mut buf = Vec::new();
    while let Some(c) = r.chunk().await.map_err(|e| other(http_error("getLatestCommit", e)))? {
        if buf.len() + c.len() > MAX_RESPONSE {
            return Err(other("getLatestCommit: response too large".into()));
        }
        buf.extend_from_slice(&c);
    }
    let body: J = serde_json::from_slice(&buf).map_err(|_| other("getLatestCommit: not JSON".into()))?;
    let commit = super::commit::Commit::from_json(&body["commit"]).map_err(other)?;
    let mac = super::mac::parse_mac(mac_value.as_deref(), super::mac::COMMIT_MAC_TYPE)
        .map_err(|e| Checked::Mac(format!("getLatestCommit: {e}")))?;
    if !super::commit::verify(&commit, space, writer, &secret, &mac) {
        return Err(Checked::Mac("the commit doesn't verify against its MAC".into()));
    }
    Ok(commit)
}

#[cfg(test)]
mod tests {
    /// An unreachable endpoint's error names neither the space nor the
    /// member its query carried.
    #[tokio::test]
    async fn send_errors_leave_the_url_out() {
        let space = "at://did:plc:secretauthority0000000000/space/com.example.group/skey";
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
}
