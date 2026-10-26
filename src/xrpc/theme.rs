//! The theme's API (docs/operations/theming.md): `vlpds.admin.getTheme` /
//! `putTheme` for the operator, `vlpds.server.describeTheme` for anyone
//! (apps that want to match this server's look), and the stylesheet and
//! images the pages load. Storage and rendering are `crate::theme`.

use super::admin::require_admin;
use super::moderation::{audit, ClientIp, SubjectRef, Who};
use super::*;
use crate::theme::{self as th, Colors, Compiled, Font, ImageKind, Links, SaveError};
use axum::extract::DefaultBodyLimit;
use serde::Deserializer;
use std::time::Duration;

const RELOAD_TIMEOUT: Duration = Duration::from_secs(2);
/// A logo and a favicon as base64 in JSON, with room for the rest (the
/// `Json` extractor's 150 KiB is too little).
const PUT_BODY_MAX: usize = 1024 * 1024;

pub fn xrpc_routes() -> Router<Arc<App>> {
    Router::new()
        .route("/xrpc/vlpds.admin.getTheme", get(get_theme))
        .route("/xrpc/vlpds.admin.putTheme", post(put_theme).layer(DefaultBodyLimit::max(PUT_BODY_MAX)))
        .route("/xrpc/vlpds.server.describeTheme", get(describe_theme))
}

/// What the pages load.
pub fn routes() -> Router<Arc<App>> {
    Router::new()
        .route(th::CSS_PATH, get(stylesheet))
        .route(th::LOGO_PATH, get(logo))
        .route(th::FAVICON_PATH, get(favicon))
}

pub fn internal_routes() -> Router<Arc<App>> {
    Router::new().route("/internal/v1/theme/reload", post(internal_reload))
}

/// Idempotent.
pub fn start(app: &Arc<App>) {
    th::spawn_refresher(&app.theme, app.store.clone());
}

fn node_id(app: &App) -> String {
    app.cluster.as_ref().map(|c| c.cfg.node_id.clone()).unwrap_or_else(|| "single".into())
}

fn absolute(app: &App, path: &str) -> String {
    format!("{}{path}", app.public_url.trim_end_matches('/'))
}

fn image_view(app: &App, s: &Option<th::Served>, kind: ImageKind, url: &Option<String>) -> J {
    match (s, url) {
        (Some(s), Some(u)) => json!({
            "mime": s.mime,
            "sha256": s.sha256,
            "bytes": s.bytes.len(),
            "url": absolute(app, u),
            "kind": kind.as_str(),
        }),
        _ => J::Null,
    }
}

/// The admin view: the settings (images by hash and URL, never inline),
/// the contrast warnings, and what fills in where the theme sets nothing.
fn admin_view(app: &App, c: &Compiled) -> J {
    let t = &c.doc.theme;
    let cfg = &app.config;
    let b = &cfg.email_branding;
    json!({
        "theme": {
            "name": t.name,
            "logoIsWordmark": t.logo_is_wordmark,
            "colors": t.colors,
            "font": t.font,
            "links": t.links,
            "logo": image_view(app, &c.logo, ImageKind::Logo, &c.brand.logo),
            "favicon": image_view(app, &c.favicon, ImageKind::Favicon, &c.brand.favicon),
        },
        "version": c.doc.version,
        "updatedAt": c.doc.updated_at,
        "updatedBy": c.doc.updated_by,
        "warnings": th::warnings(t),
        "resolved": {"light": th::resolve(&t.colors.light, &th::LIGHT), "dark": th::resolve(&t.colors.dark, &th::DARK)},
        "defaults": {"light": th::resolve(&Default::default(), &th::LIGHT), "dark": th::resolve(&Default::default(), &th::DARK)},
        "stylesheet": c.css,
        // the boot-time settings the theme takes over field by field
        "fallbacks": {
            "emailName": b.name,
            "emailHomeUrl": b.home_url,
            "emailLogoUrl": b.logo_url,
            "emailPrimaryColor": b.primary_color,
            "termsOfService": cfg.terms_of_service_url,
            "privacyPolicy": cfg.privacy_policy_url,
        },
        "limits": {
            "nameChars": th::MAX_NAME,
            "urlChars": th::MAX_URL,
            "logoBytes": th::MAX_LOGO_BYTES,
            "faviconBytes": th::MAX_FAVICON_BYTES,
            "logoTypes": ["image/png", "image/jpeg", "image/webp"],
            "faviconTypes": ["image/png", "image/x-icon"],
            "fonts": ["default", "system", "serif", "rounded", "mono"],
        },
    })
}

async fn get_theme(State(app): AppState, Auth(creds): Auth) -> XResult<Json<J>> {
    require_admin(&creds)?;
    Ok(Json(admin_view(&app, &app.theme.current())))
}

/// Absent: keep the stored image; null: remove it; a string: a `data:` URI
/// to replace it with.
fn present<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Option<String>>, D::Error> {
    Ok(Some(Option::deserialize(d)?))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ThemeIn {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    logo_is_wordmark: bool,
    #[serde(default)]
    colors: Colors,
    #[serde(default)]
    font: Font,
    #[serde(default)]
    links: Links,
    #[serde(default, deserialize_with = "present")]
    logo: Option<Option<String>>,
    #[serde(default, deserialize_with = "present")]
    favicon: Option<Option<String>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PutIn {
    /// The whole theme: a field left out is unset (vlpds's), except the
    /// images (see [`ThemeIn`]).
    theme: ThemeIn,
    #[serde(default)]
    if_version: Option<u64>,
    /// The audit entry's reason.
    #[serde(default)]
    note: Option<String>,
    #[serde(default)]
    actor: Option<String>,
}

fn save_error(e: SaveError) -> XrpcError {
    let message = e.to_string();
    match e {
        SaveError::Invalid(_) => XrpcError::bad("InvalidTheme", message),
        SaveError::Conflict(_) => XrpcError { status: StatusCode::CONFLICT, error: "VersionMismatch".into(), message },
        SaveError::Store(_) => XrpcError { status: StatusCode::BAD_GATEWAY, error: "UpstreamFailure".into(), message },
    }
}

fn image_in(v: &Option<Option<String>>, kind: ImageKind) -> XResult<Option<Option<th::Image>>> {
    match v {
        None => Ok(None),
        Some(None) => Ok(Some(None)),
        Some(Some(uri)) => {
            th::image_from_data_uri(uri, kind).map(|i| Some(Some(i))).map_err(|m| XrpcError::bad("InvalidTheme", m))
        }
    }
}

async fn put_theme(State(app): AppState, Auth(creds): Auth, ClientIp(ip): ClientIp, body: AxBytes) -> XResult<Json<J>> {
    require_admin(&creds)?;
    // read here, not by `Json`: a logo as base64 is over its 150 KiB
    let inp: PutIn = serde_json::from_slice(&body)
        .map_err(|e| XrpcError::bad("InvalidRequest", format!("Invalid JSON body: {e}")))?;
    let t = inp.theme;
    let (logo, favicon) = (image_in(&t.logo, ImageKind::Logo)?, image_in(&t.favicon, ImageKind::Favicon)?);
    let wordmark = t.logo_is_wordmark;
    let mut settings = th::Theme {
        name: t.name,
        logo_is_wordmark: t.logo_is_wordmark,
        colors: t.colors,
        font: t.font,
        links: t.links,
        logo: None,
        favicon: None,
    };
    // the settings are checked before the store is read; the images again
    // with them once merged
    th::normalize(&mut settings, app.config.dev_mode).map_err(|m| XrpcError::bad("InvalidTheme", m))?;
    let by = creds.operator().unwrap_or("admin").to_string();
    let dev = app.config.dev_mode;
    let (old, doc) = th::update(&app.theme, &app.store, inp.if_version, &by, |stored| {
        let mut next = settings.clone();
        next.logo = logo.clone().unwrap_or_else(|| stored.logo.clone());
        next.favicon = favicon.clone().unwrap_or_else(|| stored.favicon.clone());
        // dropped again without a logo
        next.logo_is_wordmark = wordmark;
        th::normalize(&mut next, dev).map_err(SaveError::Invalid)?;
        *stored = next;
        Ok(())
    })
    .await
    .map_err(save_error)?;
    let changed = th::changes(&old.theme, &doc.theme);
    let who = Who::of(&creds, inp.actor.as_deref(), ip);
    let subject = SubjectRef::other("config", "theme");
    let note = super::admin_audit::bounded_note(inp.note.as_deref());
    let detail = json!({"version": doc.version, "changes": changed});
    audit(&app, &who, "theme.put", Some(&subject), note.as_deref(), None, Some(detail)).await?;
    app.changes.emit("config", "theme", super::changes::now_ms());
    let nodes = nudge_peers(&app).await;
    let mut out = admin_view(&app, &app.theme.current());
    out["changes"] = json!(changed);
    out["nodes"] = json!(nodes);
    Ok(Json(out))
}

async fn nudge_peers(app: &Arc<App>) -> Vec<J> {
    let me = node_id(app);
    let mut applied = vec![json!({"node": me, "ok": true})];
    let Some(c) = &app.cluster else { return applied };
    let peers: Vec<_> = c.peers().into_iter().filter(|l| l.node_id != me).collect();
    let sends = peers.into_iter().map(|l| {
        let app = app.clone();
        async move {
            let r = app
                .http
                .post(format!("{}/internal/v1/theme/reload", l.addr.trim_end_matches('/')))
                .header(super::internal::HDR, &app.config.internal_token)
                .timeout(RELOAD_TIMEOUT)
                .send()
                .await
                .and_then(|r| r.error_for_status());
            match r {
                Ok(_) => json!({"node": l.node_id, "ok": true}),
                Err(e) => {
                    tracing::warn!(peer = %l.node_id, "theme reload nudge failed (it re-reads on its own): {e}");
                    json!({"node": l.node_id, "ok": false, "error": e.to_string()})
                }
            }
        }
    });
    applied.extend(futures::future::join_all(sends).await);
    applied
}

async fn internal_reload(State(app): AppState, headers: HeaderMap) -> XResult<Json<J>> {
    super::internal::check(&app, &headers)?;
    th::refresh(&app.theme, &app.store).await.map_err(|e| XrpcError {
        status: StatusCode::BAD_GATEWAY,
        error: "UpstreamFailure".into(),
        message: format!("{e:#}"),
    })?;
    Ok(Json(json!({"node": node_id(&app), "version": app.theme.current().doc.version})))
}

/// For apps matching this server's look: every color resolved (vlpds's
/// where the theme sets none), absolute URLs. Public, cached a minute.
async fn describe_theme(State(app): AppState) -> Response {
    let c = app.theme.current();
    let t = &c.doc.theme;
    let b = &c.brand;
    let body = json!({
        "name": b.display_name(),
        "custom": !b.is_default() || t.font != Font::Default,
        "logo": b.logo.as_deref().map(|p| absolute(&app, p)),
        "logoIsWordmark": b.wordmark,
        "favicon": b.favicon.as_deref().map(|p| absolute(&app, p)),
        "font": t.font,
        "colors": {"light": th::resolve(&t.colors.light, &th::LIGHT), "dark": th::resolve(&t.colors.dark, &th::DARK)},
        "links": t.links,
        "stylesheet": (!c.css.is_empty()).then(|| absolute(&app, &format!("{}?v={}", th::CSS_PATH, b.css_tag))),
        "version": c.doc.version,
    });
    let mut r = Json(body).into_response();
    r.headers_mut().insert(header::CACHE_CONTROL, header::HeaderValue::from_static("public, max-age=60"));
    r
}

/// Immutable under the `?v=` the pages use; a minute otherwise.
fn cache_control(q: Option<&str>, tag: &str) -> &'static str {
    if q.is_some_and(|q| q.split('&').any(|kv| kv == format!("v={tag}"))) {
        "public, max-age=31536000, immutable"
    } else {
        "public, max-age=60"
    }
}

async fn stylesheet(State(app): AppState, uri: axum::http::Uri) -> Response {
    let c = app.theme.current();
    let cache = cache_control(uri.query(), &c.brand.css_tag);
    (
        [
            (header::CONTENT_TYPE, "text/css; charset=utf-8"),
            (header::CACHE_CONTROL, cache),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            (header::HeaderName::from_static("cross-origin-resource-policy"), "cross-origin"),
        ],
        c.css.clone(),
    )
        .into_response()
}

fn image(app: &App, kind: ImageKind, uri: &axum::http::Uri, headers: &HeaderMap) -> Response {
    let c = app.theme.current();
    let s = match kind {
        ImageKind::Logo => &c.logo,
        ImageKind::Favicon => &c.favicon,
    };
    let Some(s) = s else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let etag = format!("\"{}\"", s.sha256);
    let cache = cache_control(uri.query(), s.tag());
    let mut h = HeaderMap::new();
    h.insert(header::CONTENT_TYPE, header::HeaderValue::from_static(s.mime));
    h.insert(header::CACHE_CONTROL, header::HeaderValue::from_static(cache));
    h.insert(header::ETAG, header::HeaderValue::from_str(&etag).unwrap());
    h.insert(header::X_CONTENT_TYPE_OPTIONS, header::HeaderValue::from_static("nosniff"));
    // opened directly it is still only an image; other sites may embed it
    h.insert(header::CONTENT_SECURITY_POLICY, header::HeaderValue::from_static("default-src 'none'; sandbox"));
    h.insert(
        header::HeaderName::from_static("cross-origin-resource-policy"),
        header::HeaderValue::from_static("cross-origin"),
    );
    if headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.split(',').any(|t| t.trim() == etag))
    {
        return (StatusCode::NOT_MODIFIED, h).into_response();
    }
    (h, s.bytes.clone()).into_response()
}

async fn logo(State(app): AppState, uri: axum::http::Uri, headers: HeaderMap) -> Response {
    image(&app, ImageKind::Logo, &uri, &headers)
}

async fn favicon(State(app): AppState, uri: axum::http::Uri, headers: HeaderMap) -> Response {
    image(&app, ImageKind::Favicon, &uri, &headers)
}
