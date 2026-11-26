//! Public pages carry server-rendered `<head>` tags (title, description,
//! canonical, Open Graph, Twitter) so link-preview fetchers, which don't run
//! the SPA, can build a card; the card images are PNGs from the UI build.
//! Signed-in areas are noindex.

use crate::common::*;

fn body(r: &Resp) -> String {
    String::from_utf8_lossy(&r.body).into_owned()
}

/// `content` of the first `<meta {attr}="{key}" content="…">`.
fn meta(html: &str, attr: &str, key: &str) -> Option<String> {
    let pat = format!("<meta {attr}=\"{key}\" content=\"");
    let at = html.find(&pat)? + pat.len();
    Some(html[at..at + html[at..].find('"')?].to_string())
}

fn canonical(html: &str) -> Option<String> {
    let pat = "<link rel=\"canonical\" href=\"";
    let at = html.find(pat)? + pat.len();
    Some(html[at..at + html[at..].find('"')?].to_string())
}

fn title(html: &str) -> Option<String> {
    let at = html.find("<title>")? + "<title>".len();
    Some(html[at..at + html[at..].find("</title>")?].to_string())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn public_pages_have_link_preview_tags() {
    let s = TestServer::spawn().await;
    let get = |path: &str| {
        let x = s.xrpc.clone();
        let url = format!("{}{path}", s.url);
        async move { x.send(x.http.get(url)).await }
    };
    let origin = s.url.trim_end_matches('/').to_string();
    let host = origin.split_once("://").unwrap().1.to_string();

    let landing = body(&get("/").await);
    let built = !landing.contains("without its web UI");
    assert_eq!(title(&landing).unwrap(), format!("{host} · vlpds"));
    assert_eq!(canonical(&landing).unwrap(), format!("{origin}/"));
    assert_eq!(meta(&landing, "property", "og:url").unwrap(), format!("{origin}/"));
    assert_eq!(meta(&landing, "property", "og:site_name").unwrap(), host);
    assert!(meta(&landing, "name", "description").unwrap().contains("personal data server for the AT Protocol"));
    assert!(landing.matches("<title>").count() == 1, "the shell's own title is replaced");
    assert!(meta(&landing, "name", "robots").is_none());

    let migrate = get("/migrate").await;
    assert!(
        migrate.header("content-security-policy").unwrap().contains("connect-src 'self' https:"),
        "migrate keeps its CSP"
    );
    let migrate = body(&migrate);
    assert_eq!(meta(&migrate, "property", "og:title").unwrap(), format!("Move your Bluesky account to {host}"));
    assert_eq!(canonical(&migrate).unwrap(), format!("{origin}/migrate"));

    for (path, noindex) in
        [("/account", true), ("/account/security", true), ("/admin", true), ("/admin/cluster", true), ("/", false)]
    {
        let html = body(&get(path).await);
        assert_eq!(meta(&html, "name", "robots").as_deref() == Some("noindex, nofollow"), noindex, "{path}");
    }
    let admin = body(&get("/admin").await);
    assert!(meta(&admin, "property", "og:image").is_none(), "no card for the console");

    let robots = get("/robots.txt").await;
    assert_eq!(robots.status, 200);
    let robots = body(&robots);
    for l in [
        "Disallow: /admin",
        "Disallow: /account",
        "Disallow: /xrpc/",
        "Disallow: /oauth/",
        &format!("Sitemap: {origin}/sitemap.xml"),
    ] {
        assert!(robots.lines().any(|x| x == l), "robots.txt has {l:?}:\n{robots}");
    }

    if !built {
        eprintln!("ui/dist is the placeholder (run `just ui`): skipping docs pages and card images");
        return;
    }

    let r = get("/docs/overview").await;
    assert_eq!(r.status, 200);
    let doc = body(&r);
    assert_eq!(title(&doc).unwrap(), "Overview · vlpds docs");
    assert_eq!(canonical(&doc).unwrap(), format!("{origin}/docs/overview"));
    assert_eq!(meta(&doc, "property", "og:type").unwrap(), "article");
    assert!(meta(&doc, "property", "og:description")
        .unwrap()
        .starts_with("An atproto PDS whose only durable storage is an object store."));
    assert_eq!(meta(&doc, "name", "twitter:card").unwrap(), "summary_large_image");
    assert_eq!(meta(&doc, "property", "og:image:width").unwrap(), "1200");
    assert_eq!(meta(&doc, "property", "og:image:height").unwrap(), "630");
    // /docs is the overview, under one canonical URL
    assert_eq!(canonical(&body(&get("/docs").await)).unwrap(), format!("{origin}/docs/overview"));
    let deploy = body(&get("/docs/operations/deploy").await);
    assert_eq!(canonical(&deploy).unwrap(), format!("{origin}/docs/operations/deploy"));
    assert_ne!(meta(&deploy, "property", "og:image"), meta(&doc, "property", "og:image"), "each page has its own card");

    let missing = get("/docs/no-such-page").await;
    assert_eq!(missing.status, 404);
    assert_eq!(meta(&body(&missing), "name", "robots").unwrap(), "noindex, nofollow");

    for html in [&landing, &migrate, &doc] {
        let img = meta(html, "property", "og:image").unwrap();
        assert_eq!(meta(html, "name", "twitter:image").unwrap(), img);
        assert!(!meta(html, "property", "og:image:alt").unwrap().is_empty());
        let path = img.strip_prefix(&origin).unwrap_or_else(|| panic!("og:image is absolute on this host: {img}"));
        let r = get(path).await;
        assert_eq!(r.status, 200, "{img}");
        assert_eq!(r.header("content-type").unwrap(), "image/png");
        assert!(r.header("cache-control").unwrap().contains("immutable"));
        assert!(r.body.starts_with(b"\x89PNG\r\n\x1a\n"), "{img} is a PNG");
        // IHDR width and height
        assert_eq!(&r.body[16..24], &[0, 0, 0x04, 0xb0, 0, 0, 0x02, 0x76], "{img} is 1200×630");
        assert!(r.body.len() < 150_000, "{img}: {} bytes", r.body.len());
    }

    let sitemap = get("/sitemap.xml").await;
    assert_eq!(sitemap.status, 200);
    let sitemap = body(&sitemap);
    for p in ["/", "/migrate", "/docs/overview", "/docs/operations/deploy"] {
        assert!(sitemap.contains(&format!("<loc>{origin}{p}</loc>")), "sitemap lists {p}");
    }
    assert!(!sitemap.contains(&format!("{origin}/admin")) && !sitemap.contains(&format!("{origin}/account")));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn head_values_are_escaped() {
    let s = TestServer::spawn_with(|c| {
        let parts = vlpds::brand::Parts { name: Some("Tom & Jerry's \"PDS\" <b>".into()), ..Default::default() };
        c.brand = vlpds::brand::Brand::new(parts, &c.public_url).unwrap();
    })
    .await;
    let r = s.xrpc.send(s.xrpc.http.get(format!("{}/", s.url))).await;
    let html = body(&r);
    assert_eq!(meta(&html, "property", "og:site_name").unwrap(), "Tom &amp; Jerry&#39;s &quot;PDS&quot; &lt;b&gt;");
    assert!(!html.contains("<b>"));
}
