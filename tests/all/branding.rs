//! Operator branding (docs/operations/branding.md): the OAuth pages' header
//! and links, the served logo, favicon and stylesheet, the SPA shells' head,
//! describeServer and email. Unbranded, all of it is vlpds's own.

use crate::common::{latest_mail, TestServer};
use crate::oauth::{create_account, csrf_of, pkce, spawn_with, Browser, DpopKey, Flow, Srv, PASSWORD};
use base64::Engine;
use serde_json::json;
use sha2::Digest;

fn sample(public_url: &str) -> vlpds::brand::Brand {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/brand");
    let parts = vlpds::brand::Parts {
        name: Some("Tidepool Social".into()),
        logo: Some(std::fs::read(dir.join("logo.png")).unwrap()),
        favicon: Some(std::fs::read(dir.join("favicon.png")).unwrap()),
        primary_color: Some("#c2410c".into()),
        primary_color_dark: Some("#fb923c".into()),
        home_url: Some("https://tidepool.example".into()),
        support_url: Some("mailto:help@tidepool.example".into()),
        terms_of_service_url: Some("https://tidepool.example/terms".into()),
        privacy_policy_url: Some("https://tidepool.example/privacy".into()),
    };
    vlpds::brand::Brand::new(parts, public_url).unwrap()
}

async fn branded() -> Srv {
    spawn_with(|c| c.brand = sample(&c.public_url)).await
}

/// The consent page for a fresh account, and its CSP.
async fn consent_page(s: &Srv) -> (String, String) {
    let acct = create_account(s, "brand").await;
    let key = DpopKey::new();
    let f = Flow::loopback("atproto repo:app.bsky.feed.post", &key);
    let mut b = Browser::default();
    let ru = f.request_uri(s, &pkce(), "st").await;
    let (st, _, html) = b.authorize(s, &f, &ru).await;
    assert_eq!(st, 200, "{html}");
    let (st, h, html) = b.sign_in(s, &ru, &csrf_of(&html), &acct.handle, PASSWORD).await;
    assert_eq!(st, 200, "{html}");
    assert!(html.contains("<h1>Authorize access</h1>"), "{html}");
    (html, h.get("content-security-policy").unwrap().to_str().unwrap().to_string())
}

fn styles(html: &str) -> Vec<&str> {
    html.split("<style>").skip(1).map(|s| &s[..s.find("</style>").unwrap()]).collect()
}

fn sha(s: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(sha2::Sha256::digest(s.as_bytes()))
}

fn style_src(csp: &str) -> &str {
    csp.split("; ").find(|d| d.starts_with("style-src")).unwrap()
}

const CLIENT: &str = "<div class=\"client\">A development app running on your own computer (http://localhost)</div>";
const BUTTONS: &str = "<div class=\"row\"><button type=\"submit\" name=\"action\" value=\"deny\">Deny</button><button type=\"submit\" class=\"primary\" name=\"action\" value=\"allow\" autofocus>Allow</button></div></form>";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn branded_consent_page() {
    let s = branded().await;
    let (html, csp) = consent_page(&s).await;
    let brand = &s.app.config.brand;
    let logo = brand.logo_src().unwrap();
    assert!(
        html.contains(&format!("<div class=\"brand\"><img src=\"{logo}\" alt=\"\" height=\"24\">Tidepool Social<span>account security</span>")),
        "{html}"
    );
    assert!(html.contains(CLIENT) && html.contains(BUTTONS), "{html}");
    assert!(
        html.contains("<nav class=\"bl\" aria-label=\"Tidepool Social\"><a href=\"https://tidepool.example\">Home</a>"),
        "{html}"
    );
    assert!(html.contains("<a href=\"mailto:help@tidepool.example\">Support</a></nav></main>"), "{html}");
    let st = styles(&html);
    assert_eq!(st.len(), 2, "{html}");
    assert_eq!(style_src(&csp), format!("style-src 'sha256-{}' 'sha256-{}'", sha(st[0]), sha(st[1])));
    assert!(!csp.contains("unsafe-inline") && !csp.contains("unsafe-eval"), "{csp}");
    assert!(st[1].contains("--accent:#c2410c;--accent-ink:#ffffff"), "{}", st[1]);
    assert!(!st[1].contains("--danger") && !st[1].contains("--amber"), "{}", st[1]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unbranded_consent_page_is_vlpds() {
    let s = spawn_with(|_| {}).await;
    let (html, csp) = consent_page(&s).await;
    assert!(html.contains("<main><div class=\"brand\"><svg width=\"22\""), "{html}");
    assert!(html.contains("</svg>vlpds<span>account security</span>"), "{html}");
    assert!(html.contains(CLIENT) && html.contains(BUTTONS), "{html}");
    assert!(html.ends_with("</form></div></main></body></html>"), "{html}");
    assert!(!html.contains("/brand/") && !html.contains("<nav") && !html.contains("rel=\"icon\""), "{html}");
    let st = styles(&html);
    assert_eq!(st.len(), 1);
    assert_eq!(style_src(&csp), format!("style-src 'sha256-{}'", sha(st[0])));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn brand_files_are_served_with_safe_headers() {
    let s = branded().await;
    let brand = &s.app.config.brand;
    let get = |path: String, etag: Option<String>| {
        let mut r = s.http.get(format!("{}{path}", s.base));
        if let Some(e) = etag {
            r = r.header("if-none-match", e);
        }
        async move { r.send().await.unwrap() }
    };
    for (path, src, mime, len) in [
        ("/brand/logo", brand.logo_src().unwrap(), "image/png", brand.logo.as_ref().unwrap().bytes.len()),
        ("/brand/favicon", brand.favicon_src().unwrap(), "image/png", brand.favicon.as_ref().unwrap().bytes.len()),
    ] {
        let r = get(path.to_string(), None).await;
        assert_eq!(r.status(), 200);
        let h = r.headers().clone();
        assert_eq!(h["content-type"], mime);
        assert_eq!(h["x-content-type-options"], "nosniff");
        assert_eq!(h["content-security-policy"], "default-src 'none'; sandbox");
        assert_eq!(h["cache-control"], "public, max-age=3600");
        assert_eq!(r.bytes().await.unwrap().len(), len);
        let r = get(src, None).await;
        assert_eq!(r.headers()["cache-control"], "public, max-age=31536000, immutable");
        let etag = r.headers()["etag"].to_str().unwrap().to_string();
        assert_eq!(get(path.to_string(), Some(etag)).await.status(), 304);
    }
    let r = get("/brand/brand.css".into(), None).await;
    assert_eq!(r.status(), 200);
    assert_eq!(r.headers()["content-type"], "text/css; charset=utf-8");
    assert_eq!(r.headers()["x-content-type-options"], "nosniff");
    assert!(r.text().await.unwrap().contains(":root:root{--accent:#c2410c"));

    let plain = spawn_with(|_| {}).await;
    for p in ["/brand/logo", "/brand/favicon", "/brand/brand.css"] {
        let r = plain.http.get(format!("{}{p}", plain.base)).send().await.unwrap();
        assert_eq!(r.status(), 404, "{p}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn spa_shells_carry_the_brand_but_console_and_docs_dont() {
    let s = branded().await;
    let brand = &s.app.config.brand;
    let shell = |p: &'static str| {
        let r = s.http.get(format!("{}{p}", s.base));
        async move { r.send().await.unwrap().text().await.unwrap() }
    };
    for p in ["/", "/account", "/account/signup", "/migrate"] {
        let html = shell(p).await;
        assert!(
            html.contains(&format!(
                "<link rel=\"icon\" type=\"image/png\" href=\"{}\" />",
                brand.favicon_src().unwrap()
            )),
            "{p}: {html}"
        );
        assert!(!html.contains("href=\"/favicon.svg\""), "{p}: one icon only");
        assert!(html.contains("<link rel=\"stylesheet\" href=\"/brand/brand.css?v="), "{p}");
        let data = html.split("<script type=\"application/json\" id=\"vlpds-brand\">").nth(1).unwrap();
        let j: serde_json::Value = serde_json::from_str(&data[..data.find("</script>").unwrap()]).unwrap();
        assert_eq!(j["name"], "Tidepool Social", "{p}");
        assert_eq!(j["logo"], json!(brand.logo_src()));
        assert_eq!(j["links"].as_array().unwrap().len(), 4);
    }
    assert!(shell("/").await.contains("<title>Tidepool Social</title>"));
    assert!(shell("/account").await.contains("<title>Account · Tidepool Social</title>"));
    for p in ["/admin", "/docs"] {
        let html = shell(p).await;
        assert!(!html.contains("vlpds-brand") && !html.contains("/brand/"), "{p}: {html}");
        assert!(html.contains(vlpds::brand::DEFAULT_ICON), "{p}");
    }
    let plain = spawn_with(|_| {}).await;
    let html = plain.http.get(format!("{}/", plain.base)).send().await.unwrap().text().await.unwrap();
    assert!(!html.contains("vlpds-brand") && !html.contains("/brand/"), "{html}");
    assert_eq!(html.matches("rel=\"icon\"").count(), 1, "{html}");
    assert!(html.contains(vlpds::brand::DEFAULT_ICON));
    assert!(html.contains("· vlpds</title>"), "{html}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn describe_server_and_email_use_the_brand() {
    let s = TestServer::spawn_with(|c| c.brand = sample(&c.public_url)).await;
    let j = s.xrpc.get("com.atproto.server.describeServer", &[], &crate::common::Auth::None).await.ok();
    assert_eq!(
        j["links"],
        json!({"privacyPolicy": "https://tidepool.example/privacy", "termsOfService": "https://tidepool.example/terms"})
    );
    assert!(j.get("name").is_none(), "no field the lexicon lacks: {j}");
    let a = s.create_account("mail").await;
    s.xrpc
        .post("com.atproto.server.requestPasswordReset", &json!({"email": a.email}), &crate::common::Auth::None)
        .await
        .ok();
    let m = latest_mail(&s, &a.email).await;
    let html = m["html"].as_str().unwrap();
    let logo = format!("{}{}", s.url.trim_end_matches('/'), s.app.config.brand.logo_src().unwrap());
    assert!(html.contains(&format!("src='{logo}'")), "{html}");
    assert!(html.contains("alt='Tidepool Social'") && html.contains("href='https://tidepool.example'"), "{html}");
    assert!(html.contains("color:#c2410c"), "{html}");
    assert!(html.contains("href='mailto:help@tidepool.example'"), "{html}");
}
