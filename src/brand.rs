//! Operator branding (docs/operations/branding.md): a name, a logo and a
//! favicon, an accent color and a few links, all boot flags. Read and
//! checked once at startup, so a bad value stops the node instead of
//! reaching a page; nothing is stored. Unset, every page is vlpds's own.
//!
//! The image sniffing and WCAG contrast math follow chris-pardy's theming
//! work (jazware/vlpds#15).

use axum::body::Bytes;
use base64::Engine;
use std::path::PathBuf;

pub const MAX_IMAGE_BYTES: usize = 256 * 1024;
pub const MAX_NAME_CHARS: usize = 64;
pub const MAX_URL: usize = 512;
pub const LOGO_PATH: &str = "/brand/logo";
pub const FAVICON_PATH: &str = "/brand/favicon";
pub const CSS_PATH: &str = "/brand/brand.css";

/// The page backgrounds the accent sits on (the UI's `--sheet`).
const LIGHT_SHEET: &str = "#f8f9f6";
const DARK_SHEET: &str = "#19212b";
/// WCAG AA for text: the accent colors links.
const AA_TEXT: f64 = 4.5;

/// What the flags gave, before any check: each is the flag's value or the
/// first non-empty fallback variable.
#[derive(Clone, Debug, Default)]
pub struct Settings {
    pub name: Option<String>,
    pub logo_file: Option<PathBuf>,
    pub favicon_file: Option<PathBuf>,
    pub primary_color: Option<String>,
    pub primary_color_dark: Option<String>,
    pub home_url: Option<String>,
    pub support_url: Option<String>,
    pub terms_of_service_url: Option<String>,
    pub privacy_policy_url: Option<String>,
}

/// Each setting's fallback variables, in order, after its own flag and
/// `VLPDS_` variable: the email-only names it replaced, then the reference
/// PDS's.
pub const FALLBACKS: &[(&str, &[&str])] = &[
    ("name", &["VLPDS_EMAIL_BRAND_NAME", "PDS_SERVICE_NAME"]),
    ("primary_color", &["VLPDS_EMAIL_PRIMARY_COLOR", "PDS_PRIMARY_COLOR"]),
    ("home_url", &["VLPDS_EMAIL_HOME_URL", "PDS_HOME_URL"]),
    ("support_url", &["PDS_SUPPORT_URL"]),
    ("terms_of_service_url", &["PDS_TERMS_OF_SERVICE_URL"]),
    ("privacy_policy_url", &["PDS_PRIVACY_POLICY_URL"]),
];

fn fallback(key: &str, flag: Option<String>, env: &impl Fn(&str) -> Option<String>) -> Option<String> {
    let nonempty = |v: Option<String>| v.filter(|v| !v.trim().is_empty());
    nonempty(flag).or_else(|| {
        FALLBACKS
            .iter()
            .find(|(k, _)| *k == key)
            .into_iter()
            .flat_map(|(_, vars)| vars.iter())
            .find_map(|v| nonempty(env(v)))
    })
}

impl Settings {
    /// Fills unset settings from [`FALLBACKS`] through `env` (the process
    /// environment in `main`, a map in tests).
    pub fn with_fallbacks(self, env: impl Fn(&str) -> Option<String>) -> Settings {
        let path = |p: Option<PathBuf>| p.filter(|p| !p.as_os_str().is_empty());
        Settings {
            name: fallback("name", self.name, &env),
            logo_file: path(self.logo_file),
            favicon_file: path(self.favicon_file),
            primary_color: fallback("primary_color", self.primary_color, &env),
            primary_color_dark: fallback("primary_color_dark", self.primary_color_dark, &env),
            home_url: fallback("home_url", self.home_url, &env),
            support_url: fallback("support_url", self.support_url, &env),
            terms_of_service_url: fallback("terms_of_service_url", self.terms_of_service_url, &env),
            privacy_policy_url: fallback("privacy_policy_url", self.privacy_policy_url, &env),
        }
    }

    /// Reads the images and checks everything; the error names the flag.
    pub fn load(self, public_url: &str) -> anyhow::Result<Brand> {
        let read = |flag: &str, p: &Option<PathBuf>| -> anyhow::Result<Option<Vec<u8>>> {
            let Some(p) = p else { return Ok(None) };
            let meta = std::fs::metadata(p).map_err(|e| anyhow::anyhow!("{flag} {}: {e}", p.display()))?;
            // checked before reading so a wrong path to something huge fails fast
            if meta.len() > MAX_IMAGE_BYTES as u64 {
                anyhow::bail!(
                    "{flag} {}: {} bytes, larger than {} KiB",
                    p.display(),
                    meta.len(),
                    MAX_IMAGE_BYTES / 1024
                );
            }
            std::fs::read(p).map(Some).map_err(|e| anyhow::anyhow!("{flag} {}: {e}", p.display()))
        };
        let parts = Parts {
            name: self.name,
            logo: read("--logo-file", &self.logo_file)?,
            favicon: read("--favicon-file", &self.favicon_file)?,
            primary_color: self.primary_color,
            primary_color_dark: self.primary_color_dark,
            home_url: self.home_url,
            support_url: self.support_url,
            terms_of_service_url: self.terms_of_service_url,
            privacy_policy_url: self.privacy_policy_url,
        };
        let b = Brand::new(parts, public_url).map_err(|e| anyhow::anyhow!(e))?;
        for w in b.contrast_warnings() {
            tracing::warn!("branding: {w}");
        }
        Ok(b)
    }
}

/// [`Settings`] with the images read.
#[derive(Clone, Debug, Default)]
pub struct Parts {
    pub name: Option<String>,
    pub logo: Option<Vec<u8>>,
    pub favicon: Option<Vec<u8>>,
    pub primary_color: Option<String>,
    pub primary_color_dark: Option<String>,
    pub home_url: Option<String>,
    pub support_url: Option<String>,
    pub terms_of_service_url: Option<String>,
    pub privacy_policy_url: Option<String>,
}

#[derive(Clone, Debug)]
pub struct Image {
    pub bytes: Bytes,
    pub mime: &'static str,
    /// The first 16 hex digits of its SHA-256: the ETag, and the `?v=` that
    /// makes a page's reference cacheable for good.
    pub tag: String,
}

/// A validated accent and the ink for text on it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Accent {
    /// Lowercase `#rrggbb`.
    pub color: String,
    /// `#000000` or `#ffffff`.
    pub ink: &'static str,
}

#[derive(Clone, Debug, Default)]
pub struct Brand {
    pub name: Option<String>,
    /// The name, else the public host: the logo's alt text.
    pub label: String,
    pub logo: Option<Image>,
    pub favicon: Option<Image>,
    pub accent: Option<Accent>,
    /// `--primary-color-dark`, else the light one.
    pub accent_dark: Option<Accent>,
    pub home_url: Option<String>,
    pub support_url: Option<String>,
    pub terms_of_service_url: Option<String>,
    pub privacy_policy_url: Option<String>,
    /// The OAuth pages' extra stylesheet and its CSP hash.
    oauth_style: Option<(String, String)>,
    spa_css: Option<Bytes>,
    css_tag: String,
}

/// By magic number.
pub fn sniff(b: &[u8]) -> Option<&'static str> {
    if b.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some("image/png")
    } else if b.starts_with(&[0xff, 0xd8, 0xff]) {
        Some("image/jpeg")
    } else if b.len() >= 12 && &b[..4] == b"RIFF" && &b[8..12] == b"WEBP" {
        Some("image/webp")
    } else {
        None
    }
}

/// Only for a clearer error: SVG is refused whatever it looks like, since
/// one opened from this origin could run script and most mail clients
/// don't show it.
fn looks_like_svg(b: &[u8]) -> bool {
    let head = &b[..b.len().min(1024)];
    let s = String::from_utf8_lossy(head).to_ascii_lowercase();
    s.trim_start_matches('\u{feff}').trim_start().starts_with('<') && s.contains("<svg")
}

pub fn image(flag: &str, bytes: Vec<u8>) -> Result<Image, String> {
    if bytes.is_empty() {
        return Err(format!("{flag}: the file is empty"));
    }
    if bytes.len() > MAX_IMAGE_BYTES {
        return Err(format!("{flag}: {} bytes, larger than {} KiB", bytes.len(), MAX_IMAGE_BYTES / 1024));
    }
    let Some(mime) = sniff(&bytes) else {
        return Err(if looks_like_svg(&bytes) {
            format!("{flag}: SVG isn't accepted; use a PNG, JPEG or WebP")
        } else {
            format!("{flag}: not a PNG, JPEG or WebP image (by its bytes)")
        });
    };
    let tag = hex::encode(&crate::oauth::util::sha256(&bytes)[..8]);
    Ok(Image { bytes: bytes.into(), mime, tag })
}

/// Exactly `#rrggbb`, any case, as lowercase.
pub fn color(flag: &str, s: &str) -> Result<String, String> {
    let s = s.trim();
    match s.strip_prefix('#') {
        Some(h) if h.len() == 6 && h.chars().all(|c| c.is_ascii_hexdigit()) => {
            Ok(format!("#{}", h.to_ascii_lowercase()))
        }
        _ => Err(format!("{flag}: {s:?} isn't a #rrggbb color")),
    }
}

/// https only (and `mailto:` where `mailto`), no credentials, no spaces or
/// quotes, so it can go in an attribute after escaping and in a JSON block.
pub fn link(flag: &str, s: &str, mailto: bool) -> Result<String, String> {
    let s = s.trim();
    let bad = |why: &str| Err(format!("{flag}: {s:?} {why}"));
    if s.len() > MAX_URL {
        return bad(&format!("is longer than {MAX_URL} characters"));
    }
    if s.chars().any(|c| c.is_whitespace() || c.is_control() || matches!(c, '"' | '\'' | '<' | '>' | '\\' | '`')) {
        return bad("has spaces, quotes or angle brackets in it");
    }
    if mailto {
        if let Some(addr) = s.strip_prefix("mailto:") {
            let (local, domain) = addr.split('?').next().unwrap_or_default().split_once('@').unwrap_or_default();
            return if !local.is_empty() && domain.contains('.') {
                Ok(s.to_string())
            } else {
                bad("isn't a mailto: address")
            };
        }
    }
    let u = match reqwest::Url::parse(s) {
        Ok(u) => u,
        Err(e) => return bad(&format!("isn't a URL ({e})")),
    };
    if u.scheme() != "https" || u.host_str().is_none_or(str::is_empty) {
        return bad(if mailto { "isn't an https: or mailto: link" } else { "isn't an https: link" });
    }
    if !u.username().is_empty() || u.password().is_some() {
        return bad("has credentials in it");
    }
    Ok(s.to_string())
}

fn rgb(hex: &str) -> (f64, f64, f64) {
    let h = hex.trim_start_matches('#');
    let c = |i: usize| u8::from_str_radix(h.get(i..i + 2).unwrap_or("00"), 16).unwrap_or(0) as f64;
    (c(0), c(2), c(4))
}

/// WCAG 2.x relative luminance.
fn luminance(hex: &str) -> f64 {
    let (r, g, b) = rgb(hex);
    let ch = |v: f64| {
        let s = v / 255.0;
        if s <= 0.04045 {
            s / 12.92
        } else {
            ((s + 0.055) / 1.055).powf(2.4)
        }
    };
    0.2126 * ch(r) + 0.7152 * ch(g) + 0.0722 * ch(b)
}

pub fn contrast(a: &str, b: &str) -> f64 {
    let (x, y) = (luminance(a), luminance(b));
    let (hi, lo) = if x > y { (x, y) } else { (y, x) };
    (hi + 0.05) / (lo + 0.05)
}

/// Black or white, whichever contrasts more with `bg`, as the reference
/// picks the primary's foreground.
pub fn ink(bg: &str) -> &'static str {
    if contrast("#000000", bg) > contrast("#ffffff", bg) {
        "#000000"
    } else {
        "#ffffff"
    }
}

/// `a` over `b` at `t` (0..1).
fn mix(a: &str, b: &str, t: f64) -> String {
    let ((ar, ag, ab), (br, bg, bb)) = (rgb(a), rgb(b));
    let m = |x: f64, y: f64| (x * t + y * (1.0 - t)).round().clamp(0.0, 255.0) as u8;
    format!("#{:02x}{:02x}{:02x}", m(ar, br), m(ag, bg), m(ab, bb))
}

/// The host of `public_url`, port kept.
fn host_of(public_url: &str) -> String {
    reqwest::Url::parse(public_url)
        .ok()
        .and_then(|u| {
            u.host_str().map(|h| match u.port() {
                Some(p) => format!("{h}:{p}"),
                None => h.to_string(),
            })
        })
        .unwrap_or_else(|| public_url.to_string())
}

impl Brand {
    pub fn new(p: Parts, public_url: &str) -> Result<Brand, String> {
        let name = match p.name.as_deref().map(str::trim) {
            None | Some("") => None,
            Some(n) if n.chars().count() > MAX_NAME_CHARS || n.chars().any(char::is_control) => {
                return Err(format!("--brand-name: 1 to {MAX_NAME_CHARS} characters, no control characters"))
            }
            Some(n) => Some(n.to_string()),
        };
        let accent_of = |flag: &str, c: &Option<String>| -> Result<Option<Accent>, String> {
            c.as_deref().map(|c| color(flag, c).map(|color| Accent { ink: ink(&color), color })).transpose()
        };
        let accent = accent_of("--primary-color", &p.primary_color)?;
        let dark = accent_of("--primary-color-dark", &p.primary_color_dark)?;
        if dark.is_some() && accent.is_none() {
            return Err("--primary-color-dark needs --primary-color".into());
        }
        let url =
            |flag: &str, u: &Option<String>, mailto: bool| u.as_deref().map(|u| link(flag, u, mailto)).transpose();
        let mut b = Brand {
            label: name.clone().unwrap_or_else(|| host_of(public_url)),
            name,
            logo: p.logo.map(|b| image("--logo-file", b)).transpose()?,
            favicon: p.favicon.map(|b| image("--favicon-file", b)).transpose()?,
            accent_dark: dark.or_else(|| accent.clone()),
            accent,
            home_url: url("--home-url", &p.home_url, false)?,
            support_url: url("--support-url", &p.support_url, true)?,
            terms_of_service_url: url("--terms-of-service-url", &p.terms_of_service_url, false)?,
            privacy_policy_url: url("--privacy-policy-url", &p.privacy_policy_url, false)?,
            ..Default::default()
        };
        b.oauth_style = b.build_oauth_style().map(|css| {
            let hash = base64::engine::general_purpose::STANDARD.encode(crate::oauth::util::sha256(&css));
            (css, hash)
        });
        if let Some(css) = b.build_spa_css() {
            b.css_tag = hex::encode(&crate::oauth::util::sha256(&css)[..8]);
            b.spa_css = Some(css.into());
        }
        Ok(b)
    }

    /// Nothing set: every page is vlpds's own.
    pub fn is_default(&self) -> bool {
        self.name.is_none()
            && self.logo.is_none()
            && self.favicon.is_none()
            && self.accent.is_none()
            && self.links().is_empty()
    }

    /// (title, url), in the reference's order.
    pub fn links(&self) -> Vec<(&'static str, &str)> {
        [
            ("Home", &self.home_url),
            ("Terms of Service", &self.terms_of_service_url),
            ("Privacy Policy", &self.privacy_policy_url),
            ("Support", &self.support_url),
        ]
        .into_iter()
        .filter_map(|(t, u)| u.as_deref().map(|u| (t, u)))
        .collect()
    }

    pub fn logo_src(&self) -> Option<String> {
        self.logo.as_ref().map(|i| format!("{LOGO_PATH}?v={}", i.tag))
    }

    pub fn favicon_src(&self) -> Option<String> {
        self.favicon.as_ref().map(|i| format!("{FAVICON_PATH}?v={}", i.tag))
    }

    /// Accents below AA for text on the page background, where links in
    /// that color would be hard to read.
    pub fn contrast_warnings(&self) -> Vec<String> {
        let mut out = Vec::new();
        let one_color = self.accent == self.accent_dark;
        for (flag, a, bg, mode) in [
            ("--primary-color", &self.accent, LIGHT_SHEET, "light"),
            (if one_color { "--primary-color" } else { "--primary-color-dark" }, &self.accent_dark, DARK_SHEET, "dark"),
        ] {
            let Some(a) = a else { continue };
            let r = contrast(&a.color, bg);
            if r < AA_TEXT {
                let hint = if mode == "dark" && one_color { "; set --primary-color-dark" } else { "" };
                out.push(format!(
                    "{flag} {} has a contrast of {r:.1}:1 with the {mode} page background ({bg}), under {AA_TEXT}:1: links in it will be hard to read{hint}",
                    a.color
                ));
            }
        }
        out
    }

    /// Accent tokens, the header logo and the link row under the card. All
    /// values are validated colors; nothing else is interpolated.
    fn build_oauth_style(&self) -> Option<String> {
        if self.is_default() {
            return None;
        }
        let mut s = String::from(
            ".brand img{display:block;height:24px;width:auto;max-width:180px;object-fit:contain}\
nav.bl{display:flex;flex-wrap:wrap;justify-content:center;gap:6px 18px;margin:14px 0 0;font-size:13px}\
nav.bl a{color:var(--ink2)}",
        );
        if let (Some(l), Some(d)) = (&self.accent, &self.accent_dark) {
            s.push_str(&format!(
                ":root{{--accent:{};--accent-ink:{}}}@media (prefers-color-scheme:dark){{:root{{--accent:{};--accent-ink:{}}}}}",
                l.color, l.ink, d.color, d.ink
            ));
        }
        Some(s)
    }

    /// The SPA's accent tokens for each of its theme selectors, one step
    /// more specific than styles.css's so load order doesn't matter.
    fn build_spa_css(&self) -> Option<String> {
        let (l, d) = (self.accent.as_ref()?, self.accent_dark.as_ref()?);
        let vars = |a: &Accent, sheet: &str, t: f64| {
            format!("--accent:{};--accent-ink:{};--accent-wash:{}", a.color, a.ink, mix(&a.color, sheet, t))
        };
        let (lv, dv) = (vars(l, LIGHT_SHEET, 0.15), vars(d, DARK_SHEET, 0.2));
        Some(format!(
            ":root:root{{{lv}}}\n@media (prefers-color-scheme: dark){{:root:root:not([data-theme='light']){{{dv}}}}}\n:root:root[data-theme='dark']{{{dv}}}\n"
        ))
    }

    /// The `<style>` the OAuth pages add, and its CSP source.
    pub fn oauth_style(&self) -> Option<(&str, &str)> {
        self.oauth_style.as_ref().map(|(c, h)| (c.as_str(), h.as_str()))
    }

    pub fn spa_css(&self) -> Option<&Bytes> {
        self.spa_css.as_ref()
    }

    pub fn css_tag(&self) -> &str {
        &self.css_tag
    }

    /// What a user-facing SPA shell adds to its `<head>`: the icon, the
    /// accent stylesheet, and a JSON data block for the header and links
    /// (not script, so `script-src 'self'` doesn't apply). Unbranded: only
    /// vlpds's icon.
    pub fn spa_head(&self) -> String {
        let mut h = match self.favicon_src() {
            Some(src) => {
                format!(
                    "<link rel=\"icon\" type=\"{}\" href=\"{src}\" />",
                    self.favicon.as_ref().map_or("", |f| f.mime)
                )
            }
            None => DEFAULT_ICON.to_string(),
        };
        if self.spa_css.is_some() {
            h.push_str(&format!("\n    <link rel=\"stylesheet\" href=\"{CSS_PATH}?v={}\" />", self.css_tag));
        }
        if !self.is_default() {
            h.push_str(&format!(
                "\n    <script type=\"application/json\" id=\"vlpds-brand\">{}</script>",
                json_for_html(&self.spa_config())
            ));
        }
        h
    }

    pub fn spa_config(&self) -> serde_json::Value {
        serde_json::json!({
            "name": self.name,
            "label": self.label,
            "logo": self.logo_src(),
            "links": self.links().iter().map(|(t, u)| serde_json::json!({"label": t, "url": u})).collect::<Vec<_>>(),
        })
    }

    /// Email's settings: `--email-logo-url` wins, then the served logo's
    /// absolute URL, then the reference's default.
    pub fn email(
        &self,
        logo_url: Option<String>,
        disable_confirmation_link: bool,
        public_url: &str,
    ) -> crate::mail::Branding {
        let served = self.logo_src().map(|p| format!("{}{p}", public_url.trim_end_matches('/')));
        crate::mail::Branding {
            name: self.name.clone(),
            home_url: self.home_url.clone(),
            logo_url: logo_url.filter(|u| !u.is_empty()).or(served),
            primary_color: self.accent.as_ref().map(|a| a.color.clone()),
            disable_confirmation_link,
            links: self
                .links()
                .into_iter()
                .filter(|(t, _)| *t != "Home")
                .map(|(t, u)| (t.to_string(), u.to_string()))
                .collect(),
        }
    }
}

/// index.html's own icon link, which the server renders with the rest of
/// the head (see `xrpc::webui`).
pub const DEFAULT_ICON: &str = "<link rel=\"icon\" type=\"image/svg+xml\" href=\"/favicon.svg\" />";

/// JSON that can't end its `<script>` element or start a comment.
pub fn json_for_html(v: &serde_json::Value) -> String {
    v.to_string().replace('<', "\\u003c").replace('>', "\\u003e").replace('&', "\\u0026")
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::collections::HashMap;

    pub(crate) fn png(extra: usize) -> Vec<u8> {
        let mut b = b"\x89PNG\r\n\x1a\n".to_vec();
        b.resize(8 + extra, 0);
        b
    }

    const URL: &str = "https://pds.example.com";

    fn env(m: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let m: HashMap<String, String> = m.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        move |k| m.get(k).cloned()
    }

    #[test]
    fn flags_beat_old_names_which_beat_the_reference() {
        let all = env(&[
            ("VLPDS_EMAIL_BRAND_NAME", "old"),
            ("PDS_SERVICE_NAME", "ref"),
            ("PDS_PRIMARY_COLOR", "#111111"),
            ("VLPDS_EMAIL_HOME_URL", "https://old.example"),
            ("PDS_HOME_URL", "https://ref.example"),
            ("PDS_SUPPORT_URL", "mailto:help@example.com"),
            ("PDS_TERMS_OF_SERVICE_URL", "https://ref.example/tos"),
        ]);
        let s = Settings { name: Some("flag".into()), ..Default::default() }.with_fallbacks(&all);
        assert_eq!(s.name.as_deref(), Some("flag"));
        assert_eq!(s.primary_color.as_deref(), Some("#111111"));
        assert_eq!(s.home_url.as_deref(), Some("https://old.example"));
        assert_eq!(s.support_url.as_deref(), Some("mailto:help@example.com"));
        assert_eq!(s.terms_of_service_url.as_deref(), Some("https://ref.example/tos"));
        assert_eq!(s.privacy_policy_url, None);
        let s = Settings::default().with_fallbacks(&all);
        assert_eq!(s.name.as_deref(), Some("old"));
        // empty values (an ansible template's unset var) are unset
        let s = Settings { name: Some("".into()), ..Default::default() }
            .with_fallbacks(env(&[("VLPDS_EMAIL_BRAND_NAME", ""), ("PDS_SERVICE_NAME", "ref")]));
        assert_eq!(s.name.as_deref(), Some("ref"));
        let s = Settings::default().with_fallbacks(env(&[]));
        assert!(s.name.is_none() && s.primary_color.is_none() && s.home_url.is_none());
    }

    #[test]
    fn every_bad_value_is_refused() {
        let bad = |p: Parts| Brand::new(p, URL).unwrap_err();
        for c in ["red", "#fff", "#12345", "#1234567", "#gggggg", "rgb(1,2,3)", "#12345g", "'#123456'"] {
            let e = bad(Parts { primary_color: Some(c.into()), ..Default::default() });
            assert!(e.starts_with("--primary-color:"), "{c}: {e}");
        }
        let e = bad(Parts {
            primary_color: Some("#123456".into()),
            primary_color_dark: Some("blue".into()),
            ..Default::default()
        });
        assert!(e.starts_with("--primary-color-dark:"), "{e}");
        assert!(bad(Parts { primary_color_dark: Some("#123456".into()), ..Default::default() }).contains("needs"));
        for u in [
            "http://example.com",
            "javascript:alert(1)",
            "example.com",
            "https://user:pw@example.com",
            "https://example.com/\"onclick=x",
            "https://example.com/a b",
            "https://example.com/<x>",
            "mailto:help@example.com",
            "data:text/html,x",
        ] {
            let e = bad(Parts { home_url: Some(u.into()), ..Default::default() });
            assert!(e.starts_with("--home-url:"), "{u}: {e}");
        }
        let long = format!("https://example.com/{}", "a".repeat(MAX_URL));
        assert!(bad(Parts { terms_of_service_url: Some(long), ..Default::default() }).contains("longer"));
        assert!(bad(Parts { privacy_policy_url: Some("ftp://x.example".into()), ..Default::default() })
            .starts_with("--privacy-policy-url:"));
        for u in ["mailto:", "mailto:nobody", "mailto:a@b", "http://help.example"] {
            let e = bad(Parts { support_url: Some(u.into()), ..Default::default() });
            assert!(e.starts_with("--support-url:"), "{u}: {e}");
        }
        assert!(bad(Parts { name: Some("a\u{7}b".into()), ..Default::default() }).starts_with("--brand-name:"));
        assert!(bad(Parts { name: Some("x".repeat(MAX_NAME_CHARS + 1)), ..Default::default() })
            .starts_with("--brand-name:"));
        assert!(bad(Parts { logo: Some(vec![]), ..Default::default() }).contains("empty"));
        assert!(bad(Parts { favicon: Some(b"GIF89a....".to_vec()), ..Default::default() })
            .starts_with("--favicon-file: not a PNG"));
    }

    #[test]
    fn good_values_are_normalized() {
        let b = Brand::new(
            Parts {
                name: Some("  Tidepool  ".into()),
                primary_color: Some("#D9480F".into()),
                support_url: Some("mailto:help@tidepool.example".into()),
                home_url: Some("https://tidepool.example/".into()),
                ..Default::default()
            },
            URL,
        )
        .unwrap();
        assert_eq!(b.name.as_deref(), Some("Tidepool"));
        assert_eq!(b.accent.as_ref().unwrap().color, "#d9480f");
        assert_eq!(b.accent_dark, b.accent, "dark falls back to the light accent");
        assert_eq!(b.links(), [("Home", "https://tidepool.example/"), ("Support", "mailto:help@tidepool.example")]);
        let b =
            Brand::new(Parts { logo: Some(png(10)), ..Default::default() }, "https://pds.example.com:8443").unwrap();
        assert_eq!(b.label, "pds.example.com:8443");
    }

    #[test]
    fn images_are_sniffed_capped_and_svg_refused() {
        assert_eq!(image("f", png(10)).unwrap().mime, "image/png");
        assert_eq!(image("f", vec![0xff, 0xd8, 0xff, 0xe0, 0, 0]).unwrap().mime, "image/jpeg");
        assert_eq!(image("f", b"RIFF\0\0\0\0WEBPVP8 ".to_vec()).unwrap().mime, "image/webp");
        assert!(image("f", b"RIFF\0\0\0\0WEB".to_vec()).is_err(), "too short for WebP");
        assert!(image("f", png(MAX_IMAGE_BYTES - 8)).is_ok());
        assert!(image("f", png(MAX_IMAGE_BYTES - 7)).unwrap_err().contains("larger than 256 KiB"));
        for svg in [
            &b"<svg xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>"[..],
            b"\xef\xbb\xbf  <?xml version='1.0'?>\n<svg/>",
            b"<!DOCTYPE svg><SVG onload=x>",
        ] {
            let e = image("--logo-file", svg.to_vec()).unwrap_err();
            assert!(e.contains("SVG isn't accepted"), "{e}");
        }
        // a .png that is really HTML, or an ICO, is refused by its bytes
        assert!(image("f", b"<html><script>x</script>".to_vec()).unwrap_err().contains("not a PNG"));
        assert!(image("f", vec![0, 0, 1, 0, 1, 0]).unwrap_err().contains("not a PNG"));
        let a = image("f", png(1)).unwrap();
        assert_eq!(a.tag.len(), 16);
        assert_ne!(a.tag, image("f", png(2)).unwrap().tag);
    }

    #[test]
    fn load_reads_and_checks_files() {
        let dir = std::env::temp_dir().join(format!("vlpds-brand-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (ok, big, svg) = (dir.join("ok.png"), dir.join("big.png"), dir.join("spoof.png"));
        std::fs::write(&ok, png(100)).unwrap();
        std::fs::write(&big, png(MAX_IMAGE_BYTES)).unwrap();
        std::fs::write(&svg, b"<svg onload=alert(1)/>").unwrap();
        let load = |p: &std::path::Path| Settings { logo_file: Some(p.into()), ..Default::default() }.load(URL);
        assert_eq!(load(&ok).unwrap().logo.unwrap().bytes.len(), 108);
        assert!(format!("{:#}", load(&big).unwrap_err()).contains("larger than 256 KiB"));
        assert!(format!("{:#}", load(&svg).unwrap_err()).contains("SVG"));
        let e = format!("{:#}", load(&dir.join("missing.png")).unwrap_err());
        assert!(e.starts_with("--logo-file ") && e.contains("missing.png"), "{e}");
        for f in [&ok, &big, &svg] {
            std::fs::remove_file(f).unwrap();
        }
        std::fs::remove_dir(&dir).unwrap();
    }

    #[test]
    fn ink_is_black_or_white_by_contrast() {
        assert_eq!(ink("#ffffff"), "#000000");
        assert_eq!(ink("#000000"), "#ffffff");
        assert_eq!(ink("#17705f"), "#ffffff");
        assert_eq!(ink("#4fbf9f"), "#000000");
        assert_eq!(ink("#ffd400"), "#000000");
        assert_eq!(ink("#0b3d91"), "#ffffff");
        // mid grey: black has 5.3:1, white 3.9:1
        assert_eq!(ink("#808080"), "#000000");
        assert!((contrast("#000000", "#ffffff") - 21.0).abs() < 1e-9);
        assert!((contrast("#777777", "#ffffff") - 4.48).abs() < 0.01);
    }

    #[test]
    fn poor_contrast_only_warns() {
        let b = Brand::new(Parts { primary_color: Some("#ffd400".into()), ..Default::default() }, URL).unwrap();
        let w = b.contrast_warnings();
        assert_eq!(w.len(), 1, "{w:?}");
        assert!(w[0].contains("light page background"), "{w:?}");
        let b = Brand::new(Parts { primary_color: Some("#0b3d91".into()), ..Default::default() }, URL).unwrap();
        let w = b.contrast_warnings();
        assert!(w.len() == 1 && w[0].contains("set --primary-color-dark"), "{w:?}");
        let b = Brand::new(
            Parts {
                primary_color: Some("#0b3d91".into()),
                primary_color_dark: Some("#8fb0ff".into()),
                ..Default::default()
            },
            URL,
        )
        .unwrap();
        assert!(b.contrast_warnings().is_empty());
    }

    #[test]
    fn unbranded_adds_nothing() {
        let b = Brand::new(Parts::default(), URL).unwrap();
        assert!(b.is_default());
        assert!(b.oauth_style().is_none() && b.spa_css().is_none());
        assert_eq!(b.spa_head(), DEFAULT_ICON);
        let m = b.email(None, false, URL);
        assert!(m.name.is_none() && m.logo_url.is_none() && m.primary_color.is_none() && m.links.is_empty());
    }

    #[test]
    fn styles_and_head_carry_only_checked_values() {
        let b = Brand::new(
            Parts {
                name: Some("Tom & Jerry's </script><b>".into()),
                logo: Some(png(4)),
                primary_color: Some("#d9480f".into()),
                primary_color_dark: Some("#ff8a4c".into()),
                home_url: Some("https://tidepool.example/?a=1&b=2".into()),
                ..Default::default()
            },
            URL,
        )
        .unwrap();
        let (css, hash) = b.oauth_style().unwrap();
        assert!(css.contains(":root{--accent:#d9480f;--accent-ink:#000000}"), "{css}");
        assert!(
            css.contains("@media (prefers-color-scheme:dark){:root{--accent:#ff8a4c;--accent-ink:#000000}}"),
            "{css}"
        );
        assert!(!css.contains("--danger") && !css.contains("--amber"), "{css}");
        assert_eq!(hash.len(), 44);
        let spa = String::from_utf8(b.spa_css().unwrap().to_vec()).unwrap();
        assert!(spa.contains(":root:root{--accent:#d9480f;--accent-ink:#000000;--accent-wash:"), "{spa}");
        assert!(spa.contains(":root:root[data-theme='dark']{--accent:#ff8a4c"), "{spa}");
        let head = b.spa_head();
        assert!(!head.contains("</script><b>") && !head.contains("&b=2"), "{head}");
        let data = head.split("id=\"vlpds-brand\">").nth(1).unwrap().strip_suffix("</script>").unwrap();
        let j: serde_json::Value = serde_json::from_str(data).unwrap();
        assert_eq!(j["name"], "Tom & Jerry's </script><b>");
        assert_eq!(j["links"][0]["url"], "https://tidepool.example/?a=1&b=2");
        assert!(j["logo"].as_str().unwrap().starts_with("/brand/logo?v="));
        assert!(head.starts_with(DEFAULT_ICON), "{head}");
        let m = b.email(None, false, "https://pds.example.com/");
        assert!(m.logo_url.unwrap().starts_with("https://pds.example.com/brand/logo?v="));
        assert_eq!(
            b.email(Some("https://cdn.example/l.png".into()), false, URL).logo_url.as_deref(),
            Some("https://cdn.example/l.png")
        );
    }

    /// `VLPDS_BRAND_DUMP=<dir>` writes a made-up brand's SPA head, stylesheet,
    /// images and OAuth pages, for `npm run shots` and `consent-shots`.
    #[test]
    fn dump_brand() {
        let Ok(dir) = std::env::var("VLPDS_BRAND_DUMP") else { return };
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/brand");
        let b = Brand::new(sample_parts(&root), "https://pds.tidepool.example").unwrap();
        let dir = std::path::Path::new(&dir);
        std::fs::create_dir_all(dir.join("brand")).unwrap();
        std::fs::write(dir.join("brand/head.txt"), b.spa_head()).unwrap();
        std::fs::write(dir.join("brand/brand.css"), b.spa_css().unwrap()).unwrap();
        std::fs::write(dir.join("brand/logo"), &b.logo.as_ref().unwrap().bytes).unwrap();
        std::fs::write(dir.join("brand/favicon"), &b.favicon.as_ref().unwrap().bytes).unwrap();
        crate::oauth::ui::tests::dump_branded(&b, dir);
    }

    /// The made-up brand the screenshots use.
    pub(crate) fn sample_parts(root: &std::path::Path) -> Parts {
        Parts {
            name: Some("Tidepool Social".into()),
            logo: Some(std::fs::read(root.join("logo.png")).unwrap()),
            favicon: Some(std::fs::read(root.join("favicon.png")).unwrap()),
            primary_color: Some("#c2410c".into()),
            primary_color_dark: Some("#fb923c".into()),
            home_url: Some("https://tidepool.example".into()),
            support_url: Some("mailto:help@tidepool.example".into()),
            terms_of_service_url: Some("https://tidepool.example/terms".into()),
            privacy_policy_url: Some("https://tidepool.example/privacy".into()),
        }
    }
}
