//! The operator's theme (src/theme.rs, src/xrpc/theme.rs,
//! docs/operations/theming.md): unconfigured is vlpds's look; getTheme /
//! putTheme with ifVersion; image limits; the theme on the OAuth pages
//! (with its stylesheet allowed by hash), the SPA shells, describeTheme,
//! describeServer and account email; and `vlpds admin theme`.

use crate::common::*;
use base64::Engine;
use sha2::{Digest, Sha256};
use std::time::Duration;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

fn png(extra: usize) -> Vec<u8> {
    let mut b = b"\x89PNG\r\n\x1a\n".to_vec();
    b.extend(std::iter::repeat_n(3u8, extra));
    b
}

fn data_uri(mime: &str, b: &[u8]) -> String {
    format!("data:{mime};base64,{}", B64.encode(b))
}

async fn get_page(s: &TestServer, path: &str) -> (u16, reqwest::header::HeaderMap, Vec<u8>) {
    let r = reqwest::Client::new().get(format!("{}{path}", s.url)).send().await.unwrap();
    let (status, headers) = (r.status().as_u16(), r.headers().clone());
    (status, headers, r.bytes().await.unwrap().to_vec())
}

async fn html(s: &TestServer, path: &str) -> (String, String) {
    let (status, h, body) = get_page(s, path).await;
    assert_eq!(status, 200, "{path}");
    let csp = h.get("content-security-policy").map(|v| v.to_str().unwrap().to_string()).unwrap_or_default();
    (String::from_utf8(body).unwrap(), csp)
}

fn style_hashes(csp: &str) -> Vec<String> {
    let d = csp.split(';').map(str::trim).find(|d| d.starts_with("style-src")).unwrap_or("");
    d.split_whitespace()
        .filter_map(|s| s.strip_prefix("'sha256-"))
        .map(|s| s.trim_end_matches('\'').to_string())
        .collect()
}

async fn get_theme(s: &TestServer) -> J {
    s.xrpc.get("vlpds.admin.getTheme", &[], &Auth::Admin).await.ok()
}

async fn put(s: &TestServer, body: J) -> Resp {
    s.xrpc.post("vlpds.admin.putTheme", &body, &Auth::Admin).await
}

fn cavu(logo: &[u8]) -> J {
    json!({
        "name": "cavu",
        "colors": {
            "light": {"primary": "#0F766E", "secondary": "#f59e0b"},
            "dark": {"primary": "#2dd4bf"},
        },
        "font": "system",
        "links": {"home": "https://cavu.example", "terms": "https://cavu.example/terms", "support": "mailto:help@cavu.example"},
        "logo": data_uri("image/png", logo),
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unconfigured_is_vlpds() {
    let s = TestServer::spawn().await;
    let t = get_theme(&s).await;
    assert_eq!(t["version"], 0);
    assert_eq!(t["theme"]["name"], J::Null);
    assert_eq!(t["warnings"], json!([]));
    assert_eq!(t["stylesheet"], "");

    let (page, csp) = html(&s, "/oauth/account").await;
    assert!(page.contains("</svg>vlpds<span>account security</span>"), "{page}");
    assert!(!page.contains("/theme") && !page.contains("<nav class=\"links\""), "{page}");
    assert_eq!(page.matches("<style>").count(), 1);
    assert_eq!(style_hashes(&csp).len(), 1, "{csp}");
    assert!(page.contains("<title>Sign in</title>"), "{page}");

    let d = s.xrpc.get("vlpds.server.describeTheme", &[], &Auth::None).await.ok();
    assert_eq!(
        (&d["name"], &d["custom"], &d["logo"], &d["stylesheet"]),
        (&json!("vlpds"), &json!(false), &J::Null, &J::Null)
    );
    assert_eq!(d["colors"]["light"]["primary"], "#17705f");
    assert_eq!(get_page(&s, "/theme/logo").await.0, 404);
    assert_eq!(get_page(&s, "/theme/favicon").await.0, 404);
    let (status, _, css) = get_page(&s, "/theme.css").await;
    assert_eq!((status, css.len()), (200, 0));

    let (shell, _) = html(&s, "/account").await;
    assert!(shell.contains("<title>Account · vlpds</title>"), "{shell}");
    assert!(!shell.contains("vlpds-brand") && !shell.contains("/theme.css"), "{shell}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn put_get_round_trip_with_if_version() {
    let s = TestServer::spawn().await;
    let logo = png(200);
    let r = put(&s, json!({"theme": cavu(&logo), "ifVersion": 0, "note": "launch"})).await.ok();
    assert_eq!(r["version"], 1);
    assert_eq!(r["changes"], json!(["name", "colors.light", "colors.dark", "font", "links", "logo"]));
    assert_eq!(r["warnings"], json!([]), "a readable teal");
    let t = get_theme(&s).await;
    assert_eq!(t["theme"]["name"], "cavu");
    assert_eq!(t["theme"]["colors"]["light"]["primary"], "#0f766e", "normalized");
    assert_eq!(t["theme"]["font"], "system");
    assert_eq!(t["theme"]["logo"]["mime"], "image/png");
    assert_eq!(t["theme"]["logo"]["bytes"], logo.len());
    assert_eq!(t["theme"]["logo"]["sha256"], hex::encode(Sha256::digest(&logo)));
    assert!(t["theme"]["logo"].get("data").is_none(), "never inline in the view");
    assert_eq!(t["updatedBy"], "admin");

    // a stale version is refused; nothing changes
    put(&s, json!({"theme": {"name": "other"}, "ifVersion": 0})).await.err(409, "VersionMismatch");
    assert_eq!(get_theme(&s).await["theme"]["name"], "cavu");

    // the images: left out kept, null removed
    let mut keep = cavu(&logo);
    keep.as_object_mut().unwrap().remove("logo");
    keep["name"] = json!("cavu social");
    let r = put(&s, json!({"theme": keep, "ifVersion": 1})).await.ok();
    assert_eq!((r["version"].clone(), r["changes"].clone()), (json!(2), json!(["name"])));
    assert_eq!(r["theme"]["logo"]["bytes"], logo.len());
    let r = put(&s, json!({"theme": {"name": "cavu", "logo": null, "logoIsWordmark": true}})).await.ok();
    assert_eq!(r["theme"]["logo"], J::Null);
    assert_eq!(r["theme"]["logoIsWordmark"], false, "no logo, no wordmark");
    assert_eq!(r["theme"]["colors"], json!({"light": {}, "dark": {}}), "a put replaces the settings");

    // a contrast problem is a warning, not a refusal
    let r =
        put(&s, json!({"theme": {"colors": {"light": {"primary": "#a7f3d0", "primaryText": "#ffffff"}}}})).await.ok();
    let checks: Vec<&str> = r["warnings"].as_array().unwrap().iter().map(|w| w["check"].as_str().unwrap()).collect();
    assert_eq!(checks, ["primaryText", "primaryOnSurface"], "{}", r["warnings"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bad_themes_and_images_are_refused() {
    let s = TestServer::spawn().await;
    for (theme, what) in [
        (json!({"colors": {"light": {"primary": "teal"}}}), "colors.light.primary"),
        (json!({"colors": {"dark": {"accent": "#12345"}}}), "colors.dark.accent"),
        (json!({"name": "x".repeat(49)}), "name"),
        (json!({"links": {"terms": "javascript:alert(1)"}}), "links.terms"),
        (json!({"links": {"home": "http://cavu.example"}}), "links.home"),
        (json!({"logo": data_uri("image/png", &png(256 * 1024))}), "logo"),
        (json!({"favicon": data_uri("image/png", &png(64 * 1024))}), "favicon"),
        (json!({"logo": data_uri("image/svg+xml", b"<svg onload='x'/>")}), "logo"),
        (json!({"logo": "https://cavu.example/logo.png"}), "logo"),
    ] {
        let r = put(&s, json!({"theme": theme})).await;
        r.err(400, "InvalidTheme");
        assert!(r.json["message"].as_str().unwrap().contains(what), "{what}: {}", r.json);
    }
    put(&s, json!({"theme": {"css": "body{display:none}"}})).await.client_err();
    s.xrpc.post("vlpds.admin.putTheme", &json!({"theme": {}}), &Auth::None).await.err_status(401);
    assert_eq!(get_theme(&s).await["version"], 0, "nothing was saved");
    // at the limit is fine
    put(&s, json!({"theme": {"logo": data_uri("image/png", &png(256 * 1024 - 8))}})).await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_theme_reaches_every_page() {
    let s = TestServer::spawn().await;
    let logo = png(64);
    let ico = [0u8, 0, 1, 0, 1, 0, 16, 16];
    let mut theme = cavu(&logo);
    theme["favicon"] = json!(data_uri("image/x-icon", &ico));
    put(&s, json!({"theme": theme})).await.ok();
    let tag = &hex::encode(Sha256::digest(&logo))[..16];

    // the OAuth pages: name, logo, links, and a stylesheet the CSP allows by hash
    let (page, csp) = html(&s, "/oauth/account").await;
    assert!(
        page.contains(&format!("<img src=\"/theme/logo?v={tag}\" alt=\"\">cavu<span>account security</span>")),
        "{page}"
    );
    assert!(page.contains("<title>Sign in · cavu</title>"), "{page}");
    assert!(page.contains("<link rel=\"icon\" href=\"/theme/favicon?v="), "{page}");
    assert!(page.contains("<a href=\"https://cavu.example/terms\">Terms</a>"), "{page}");
    assert!(page.contains("<a href=\"mailto:help@cavu.example\">Support</a>"), "{page}");
    let css = page.split("<style>").nth(2).and_then(|s| s.split("</style>").next()).expect("the theme's own <style>");
    assert!(css.starts_with(":root:root{--accent:#0f766e;--accent-ink:#ffffff;"), "{css}");
    assert!(css.contains("--brand2:#f59e0b") && css.contains("--sans:ui-sans-serif"), "{css}");
    let hashes = style_hashes(&csp);
    assert_eq!(hashes.len(), 2, "{csp}");
    assert_eq!(hashes[1], B64.encode(Sha256::digest(css.as_bytes())), "{csp}");

    // the images: sniffed type, immutable under ?v=, revalidated otherwise
    let (status, h, body) = get_page(&s, &format!("/theme/logo?v={tag}")).await;
    assert_eq!((status, body.as_slice()), (200, logo.as_slice()));
    assert_eq!(h["content-type"], "image/png");
    assert_eq!(h["cache-control"], "public, max-age=31536000, immutable");
    assert_eq!(h["x-content-type-options"], "nosniff");
    assert!(h["content-security-policy"].to_str().unwrap().contains("sandbox"));
    let (_, h, _) = get_page(&s, "/theme/logo").await;
    assert_eq!(h["cache-control"], "public, max-age=60");
    let etag = h["etag"].to_str().unwrap().to_string();
    let r = reqwest::Client::new()
        .get(format!("{}/theme/logo", s.url))
        .header("if-none-match", &etag)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 304);
    let (_, h, body) = get_page(&s, "/theme/favicon").await;
    assert_eq!((h["content-type"].to_str().unwrap(), body.as_slice()), ("image/x-icon", &ico[..]));
    let (_, h, body) = get_page(&s, "/theme.css").await;
    assert_eq!(h["content-type"], "text/css; charset=utf-8");
    assert_eq!(String::from_utf8(body).unwrap(), css);

    // the SPA shells users see; the console stays vlpds's
    let (shell, shell_csp) = html(&s, "/account").await;
    assert!(shell.contains("<title>Account · cavu</title>"), "{shell}");
    assert!(shell.contains("<link rel=\"stylesheet\" href=\"/theme.css?v="), "{shell}");
    assert!(shell.contains("<script type=\"application/json\" id=\"vlpds-brand\">{"), "{shell}");
    assert!(shell.contains("\"name\":\"cavu\""), "{shell}");
    assert!(shell_csp.contains("style-src 'self'"), "the SPA's CSP is unchanged: {shell_csp}");
    assert!(shell.contains("<link rel=\"icon\" href=\"/theme/favicon?v="), "{shell}");
    assert!(!shell.contains("/favicon.svg"), "the themed favicon replaces vlpds's: {shell}");
    let (m, _) = html(&s, "/migrate").await;
    assert!(m.contains("/theme.css?v="), "{m}");
    let (admin, _) = html(&s, "/admin").await;
    assert!(admin.contains("<title>Console · vlpds</title>") && !admin.contains("/theme.css"), "{admin}");

    // describeTheme and describeServer
    let d = s.xrpc.get("vlpds.server.describeTheme", &[], &Auth::None).await.ok();
    assert_eq!(d["name"], "cavu");
    assert_eq!(d["custom"], true);
    assert_eq!(d["logo"], json!(format!("{}/theme/logo?v={tag}", s.url)));
    assert_eq!(d["colors"]["light"]["primary"], "#0f766e");
    assert_eq!(d["colors"]["light"]["primaryText"], "#ffffff");
    assert_eq!(d["colors"]["dark"]["secondary"], "#e3a43a", "unset: vlpds's");
    assert!(d["stylesheet"].as_str().unwrap().starts_with(&format!("{}/theme.css?v=", s.url)));
    let ds = s.xrpc.get("com.atproto.server.describeServer", &[], &Auth::None).await.ok();
    assert_eq!(ds["links"]["termsOfService"], "https://cavu.example/terms");

    // account email: the name, the logo (absolute), the home link
    let a = s.create_account("themed").await;
    s.xrpc.post("com.atproto.server.requestPasswordReset", &json!({"email": a.email}), &Auth::None).await.ok();
    let mail = eventually(Duration::from_secs(5), || async {
        let m = s.dev_mail(&a.email).await.ok();
        m["messages"].as_array()?.iter().rev().find(|m| m["subject"] == "Password Reset Requested").cloned()
    })
    .await
    .expect("the reset mail");
    let body = mail["html"].as_str().unwrap();
    assert!(body.contains(&format!("src='{}/theme/logo?v={tag}'", s.url)), "{body}");
    assert!(body.contains("alt='cavu'") && body.contains(">cavu</a>"), "{body}");
    assert!(body.contains("href='https://cavu.example'"), "{body}");
    assert!(mail["body"].as_str().unwrap().contains("cavu (https://cavu.example)"), "{}", mail["body"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn admin_cli_theme() {
    let s = TestServer::spawn().await;
    let u = s.url.as_str();
    let dir = std::env::temp_dir().join(unique_name("theme-cli"));
    std::fs::create_dir_all(&dir).unwrap();
    let logo = dir.join("logo.png");
    std::fs::write(&logo, png(32)).unwrap();
    let (r, out) = admin_cli(
        u,
        &[
            "theme",
            "set",
            "--name",
            "cavu",
            "--primary",
            "#0f766e",
            "--logo",
            logo.to_str().unwrap(),
            "--terms",
            "https://cavu.example/t",
        ],
    )
    .await;
    r.unwrap();
    assert!(out.contains("version 1 by admin"), "{out}");
    assert!(out.contains("changed: name, colors.light, links, logo"), "{out}");
    // a second set keeps what it doesn't name, clears what is ""
    let (r, out) = admin_cli(u, &["theme", "set", "--terms", "", "--primary-dark", "#2dd4bf"]).await;
    r.unwrap();
    assert!(out.contains("changed: colors.dark, links"), "{out}");
    let (r, out) = admin_cli(u, &["--json", "theme", "show"]).await;
    r.unwrap();
    let j: J = serde_json::from_str(&out).unwrap();
    assert_eq!(j["theme"]["name"], "cavu");
    assert_eq!(j["theme"]["colors"]["light"]["primary"], "#0f766e");
    assert_eq!(j["theme"]["links"]["terms"], J::Null);
    assert_eq!(j["theme"]["logo"]["mime"], "image/png");
    let (r, _) = admin_cli(u, &["theme", "reset", "--yes"]).await;
    r.unwrap();
    let t = get_theme(&s).await;
    assert_eq!(
        (t["theme"]["name"].clone(), t["theme"]["logo"].clone(), t["version"].clone()),
        (J::Null, J::Null, json!(3))
    );
    let (r, _) = admin_cli(u, &["theme", "set", "--primary", "nope"]).await;
    assert!(format!("{:#}", r.unwrap_err()).contains("InvalidTheme"));
    std::fs::remove_dir_all(&dir).ok();
}
