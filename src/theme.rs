//! The operator's theme (docs/operations/theming.md): a display name, a
//! logo and favicon, light and dark colors, a font and a few links, applied
//! to every page a user sees (the OAuth pages, the account app, /migrate,
//! the landing page) and to account email. The operator console and the
//! docs stay vlpds's own.
//!
//! Stored for the cluster in `{prefix}/config/theme.json` (images inline,
//! base64) and kept in memory on every node the way
//! `crate::federated::config` keeps the sign-in providers: a conditional GET
//! at startup, every [`REFRESH_EVERY`] and on a peer's nudge; an unreadable
//! object keeps the last good theme. Nothing configured is the vlpds look,
//! byte for byte on the OAuth pages.
//!
//! Only design tokens are themable, never free-form CSS: the pages' CSP
//! allows their one stylesheet by hash, and a stylesheet an admin login
//! could write would be able to restyle the consent page into saying
//! something else (and would break on every vlpds release, having no stable
//! selectors to aim at). The generated stylesheet sets CSS custom
//! properties only, from validated `#rrggbb` values and a fixed font list.

use base64::Engine;
use object_store::{GetOptions, PutMode, PutOptions, PutPayload};
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use vlsync_store::store::Store;

pub const REFRESH_EVERY: Duration = Duration::from_secs(10);
const CALL_DEADLINE: Duration = Duration::from_secs(5);
const CAS_RETRIES: usize = 5;
pub const MAX_NAME: usize = 48;
pub const MAX_URL: usize = 512;
pub const MAX_LOGO_BYTES: usize = 256 * 1024;
pub const MAX_FAVICON_BYTES: usize = 64 * 1024;
/// WCAG 2.x AA: body text, and non-text UI (a focus ring).
pub const AA_TEXT: f64 = 4.5;
pub const AA_UI: f64 = 3.0;

/// Where the images are served (`crate::xrpc::theme`).
pub const LOGO_PATH: &str = "/theme/logo";
pub const FAVICON_PATH: &str = "/theme/favicon";
pub const CSS_PATH: &str = "/theme.css";

pub fn config_path(store: &Store) -> object_store::path::Path {
    object_store::path::Path::from(format!("{}/config/theme.json", store.prefix))
}

// ---------------------------------------------------------------- the stored form

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Doc {
    #[serde(default)]
    pub theme: Theme,
    /// Bumped by every save: `ifVersion` on the admin API.
    #[serde(default)]
    pub version: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Theme {
    /// Replaces "vlpds" in the pages' headers and titles, and the service
    /// name in email.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The logo already spells the name: the pages show it alone.
    #[serde(default, skip_serializing_if = "is_false")]
    pub logo_is_wordmark: bool,
    #[serde(default)]
    pub colors: Colors,
    #[serde(default)]
    pub font: Font,
    #[serde(default)]
    pub links: Links,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logo: Option<Image>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub favicon: Option<Image>,
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// Each mode on its own: a color left out of one keeps vlpds's color for
/// that mode (a light primary is rarely readable on the dark pages).
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Colors {
    #[serde(default)]
    pub light: Palette,
    #[serde(default)]
    pub dark: Palette,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Palette {
    /// Buttons, links, checkboxes, the selected item (`--accent`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary: Option<String>,
    /// Text on a primary button (`--accent-ink`); left out, white or near
    /// black, whichever reads better on the primary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary_text: Option<String>,
    /// The second band of the stripe under the header (`--brand2`; vlpds's
    /// amber). Warnings keep their amber.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secondary: Option<String>,
    /// Focus rings (`--focus`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accent: Option<String>,
}

/// Fonts the pages can use without loading anything from another host
/// (their CSP allows fonts from this server only).
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Font {
    /// Schibsted Grotesk, served by vlpds.
    #[default]
    Default,
    /// The device's UI font.
    System,
    Serif,
    Rounded,
    /// JetBrains Mono, served by vlpds.
    Mono,
}

impl Font {
    fn stack(self) -> Option<&'static str> {
        match self {
            Font::Default => None,
            Font::System => Some("ui-sans-serif,system-ui,-apple-system,\"Segoe UI\",Roboto,sans-serif"),
            Font::Serif => Some("ui-serif,Georgia,Cambria,\"Times New Roman\",serif"),
            Font::Rounded => Some("ui-rounded,\"SF Pro Rounded\",system-ui,sans-serif"),
            Font::Mono => Some("\"JetBrains Mono\",ui-monospace,Menlo,monospace"),
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Links {
    /// The footer link in email, and "Home" under the pages.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub home: Option<String>,
    /// Also describeServer's `links.termsOfService`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terms: Option<String>,
    /// Also describeServer's `links.privacyPolicy`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privacy: Option<String>,
    /// An https: or mailto: link.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub support: Option<String>,
}

impl Links {
    /// (label, url), in footer order.
    pub fn listed(&self) -> Vec<(&'static str, &str)> {
        [("Home", &self.home), ("Terms", &self.terms), ("Privacy", &self.privacy), ("Support", &self.support)]
            .into_iter()
            .filter_map(|(l, u)| u.as_deref().map(|u| (l, u)))
            .collect()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Image {
    /// Sniffed from the bytes, never the uploader's claim.
    pub mime: String,
    /// Hex: the URL's cache key and the ETag.
    pub sha256: String,
    /// Base64 (standard).
    pub data: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImageKind {
    Logo,
    Favicon,
}

impl ImageKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ImageKind::Logo => "logo",
            ImageKind::Favicon => "favicon",
        }
    }

    pub fn max_bytes(self) -> usize {
        match self {
            ImageKind::Logo => MAX_LOGO_BYTES,
            ImageKind::Favicon => MAX_FAVICON_BYTES,
        }
    }

    fn allowed(self) -> &'static [&'static str] {
        match self {
            ImageKind::Logo => &["image/png", "image/jpeg", "image/webp"],
            ImageKind::Favicon => &["image/png", "image/x-icon"],
        }
    }

    fn path(self) -> &'static str {
        match self {
            ImageKind::Logo => LOGO_PATH,
            ImageKind::Favicon => FAVICON_PATH,
        }
    }
}

/// By magic number. SVG is refused: an SVG opened from this origin could
/// run script, and most mail clients don't show it.
pub fn sniff(b: &[u8]) -> Option<&'static str> {
    if b.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some("image/png")
    } else if b.starts_with(&[0xff, 0xd8, 0xff]) {
        Some("image/jpeg")
    } else if b.len() >= 12 && &b[..4] == b"RIFF" && &b[8..12] == b"WEBP" {
        Some("image/webp")
    } else if b.starts_with(&[0, 0, 1, 0]) {
        Some("image/x-icon")
    } else {
        None
    }
}

/// A `data:` URI (the admin API's form) or raw bytes, checked for `kind`.
pub fn image_from_data_uri(uri: &str, kind: ImageKind) -> Result<Image, String> {
    let what = kind.as_str();
    let rest = uri.strip_prefix("data:").ok_or_else(|| format!("{what}: expected a data: URI"))?;
    let (meta, b64) = rest.split_once(',').ok_or_else(|| format!("{what}: malformed data: URI"))?;
    if !meta.ends_with(";base64") {
        return Err(format!("{what}: the data: URI must be base64"));
    }
    // a size check before decoding anything large
    if b64.len() > kind.max_bytes().div_ceil(3) * 4 + 4 {
        return Err(format!("{what}: larger than {} KiB", kind.max_bytes() / 1024));
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|e| format!("{what}: bad base64 ({e})"))?;
    image_from_bytes(&bytes, kind)
}

pub fn image_from_bytes(bytes: &[u8], kind: ImageKind) -> Result<Image, String> {
    let what = kind.as_str();
    if bytes.is_empty() {
        return Err(format!("{what}: empty"));
    }
    if bytes.len() > kind.max_bytes() {
        return Err(format!("{what}: {} bytes, larger than {} KiB", bytes.len(), kind.max_bytes() / 1024));
    }
    let mime = sniff(bytes).filter(|m| kind.allowed().contains(m)).ok_or_else(|| {
        format!("{what}: not a {} image (by its bytes)", kind.allowed().join(", ").replace("image/", ""))
    })?;
    Ok(Image {
        mime: mime.into(),
        sha256: hex::encode(crate::oauth::util::sha256(bytes)),
        data: base64::engine::general_purpose::STANDARD.encode(bytes),
    })
}

// ---------------------------------------------------------------- validation

/// `#rgb` or `#rrggbb`, any case, as lowercase `#rrggbb`.
pub fn normalize_color(s: &str) -> Option<String> {
    let h = s.trim().strip_prefix('#')?;
    if !h.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let h = h.to_ascii_lowercase();
    match h.len() {
        6 => Some(format!("#{h}")),
        3 => Some(format!("#{}", h.chars().flat_map(|c| [c, c]).collect::<String>())),
        _ => None,
    }
}

fn url_ok(s: &str, mailto: bool, dev_mode: bool) -> Result<(), String> {
    if s.len() > MAX_URL {
        return Err(format!("longer than {MAX_URL} characters"));
    }
    if mailto {
        if let Some(addr) = s.strip_prefix("mailto:") {
            return if addr.contains('@') && !addr.contains(['<', '>', '"', ' ']) {
                Ok(())
            } else {
                Err("not a mailto: address".into())
            };
        }
    }
    let u = reqwest::Url::parse(s).map_err(|e| e.to_string())?;
    let loopback = u.scheme() == "http" && matches!(u.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    if u.scheme() != "https" && !(dev_mode && loopback) {
        return Err(if mailto { "not an https: or mailto: URL".into() } else { "not an https: URL".into() });
    }
    if !u.username().is_empty() || u.password().is_some() {
        return Err("has credentials in it".into());
    }
    Ok(())
}

/// Normalizes in place (trims, lowercases colors); the first problem.
pub fn normalize(t: &mut Theme, dev_mode: bool) -> Result<(), String> {
    if let Some(n) = &t.name {
        let n = n.trim();
        if n.is_empty() {
            t.name = None;
        } else if n.chars().count() > MAX_NAME || n.chars().any(char::is_control) {
            return Err(format!("name: 1 to {MAX_NAME} characters, no control characters"));
        } else {
            t.name = Some(n.to_string());
        }
    }
    for (mode, p) in [("light", &mut t.colors.light), ("dark", &mut t.colors.dark)] {
        for (field, v) in [
            ("primary", &mut p.primary),
            ("primaryText", &mut p.primary_text),
            ("secondary", &mut p.secondary),
            ("accent", &mut p.accent),
        ] {
            if let Some(c) = v.as_deref() {
                if c.trim().is_empty() {
                    *v = None;
                    continue;
                }
                *v = Some(normalize_color(c).ok_or_else(|| format!("colors.{mode}.{field}: {c:?} is not #rrggbb"))?);
            }
        }
        if p.primary_text.is_some() && p.primary.is_none() {
            return Err(format!("colors.{mode}.primaryText needs colors.{mode}.primary"));
        }
    }
    let l = &mut t.links;
    for (field, v, mailto) in [
        ("home", &mut l.home, false),
        ("terms", &mut l.terms, false),
        ("privacy", &mut l.privacy, false),
        ("support", &mut l.support, true),
    ] {
        if let Some(u) = v.as_deref() {
            let u = u.trim();
            if u.is_empty() {
                *v = None;
                continue;
            }
            url_ok(u, mailto, dev_mode).map_err(|e| format!("links.{field}: {e}"))?;
            *v = Some(u.to_string());
        }
    }
    for (kind, img) in [(ImageKind::Logo, &t.logo), (ImageKind::Favicon, &t.favicon)] {
        if let Some(i) = img {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(&i.data)
                .map_err(|e| format!("{}: bad base64 ({e})", kind.as_str()))?;
            let checked = image_from_bytes(&bytes, kind)?;
            if checked != *i {
                return Err(format!("{}: mime or sha256 doesn't match its bytes", kind.as_str()));
            }
        }
    }
    if t.logo_is_wordmark && t.logo.is_none() {
        t.logo_is_wordmark = false;
    }
    Ok(())
}

// ---------------------------------------------------------------- colors and contrast

/// vlpds's own values for the tokens a theme can set (ui/src/styles.css,
/// src/oauth/ui.rs), light then dark.
pub struct Defaults {
    pub primary: &'static str,
    pub primary_text: &'static str,
    pub secondary: &'static str,
    pub accent: &'static str,
    pub paper: &'static str,
    pub sheet: &'static str,
    pub wash: &'static str,
}

pub const LIGHT: Defaults = Defaults {
    primary: "#17705f",
    primary_text: "#ffffff",
    secondary: "#a86d0a",
    accent: "#3561c9",
    paper: "#edefea",
    sheet: "#f8f9f6",
    wash: "#d9e9e3",
};
pub const DARK: Defaults = Defaults {
    primary: "#4fbf9f",
    primary_text: "#0b1a15",
    secondary: "#e3a43a",
    accent: "#8fb0ff",
    paper: "#121820",
    sheet: "#19212b",
    wash: "#173129",
};

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

/// White or near black, whichever reads better on `bg`.
pub fn auto_text(bg: &str) -> &'static str {
    const DARK_TEXT: &str = "#101418";
    if contrast("#ffffff", bg) >= contrast(DARK_TEXT, bg) {
        "#ffffff"
    } else {
        DARK_TEXT
    }
}

/// `a` over `b` at `t` (0..1), as `#rrggbb`.
fn mix(a: &str, b: &str, t: f64) -> String {
    let ((ar, ag, ab), (br, bg, bb)) = (rgb(a), rgb(b));
    let m = |x: f64, y: f64| (x * t + y * (1.0 - t)).round().clamp(0.0, 255.0) as u8;
    format!("#{:02x}{:02x}{:02x}", m(ar, br), m(ag, bg), m(ab, bb))
}

/// One mode's values with vlpds's filling the gaps.
#[derive(Clone, Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Resolved {
    pub primary: String,
    pub primary_text: String,
    pub secondary: String,
    pub accent: String,
    pub background: String,
    pub surface: String,
}

pub fn resolve(p: &Palette, d: &Defaults) -> Resolved {
    let primary = p.primary.clone().unwrap_or_else(|| d.primary.into());
    let primary_text = match (&p.primary_text, &p.primary) {
        (Some(t), _) => t.clone(),
        (None, Some(pr)) => auto_text(pr).into(),
        (None, None) => d.primary_text.into(),
    };
    Resolved {
        primary,
        primary_text,
        secondary: p.secondary.clone().unwrap_or_else(|| d.secondary.into()),
        accent: p.accent.clone().unwrap_or_else(|| d.accent.into()),
        background: d.paper.into(),
        surface: d.sheet.into(),
    }
}

#[derive(Clone, Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Warning {
    pub mode: &'static str,
    pub check: &'static str,
    /// Rounded to two decimals.
    pub ratio: f64,
    pub min: f64,
    pub message: String,
}

/// WCAG AA checks on what the theme set (vlpds's own colors pass). Saving
/// is not refused over them: the console shows them.
pub fn warnings(t: &Theme) -> Vec<Warning> {
    let mut out = Vec::new();
    for (mode, p, d) in [("light", &t.colors.light, &LIGHT), ("dark", &t.colors.dark, &DARK)] {
        let r = resolve(p, d);
        let mut check = |check: &'static str, fg: &str, bg: &str, min: f64, what: String| {
            let ratio = contrast(fg, bg);
            if ratio < min {
                out.push(Warning {
                    mode,
                    check,
                    ratio: (ratio * 100.0).round() / 100.0,
                    min,
                    message: format!("{mode}: {what} is {ratio:.2}:1, under WCAG AA's {min}:1"),
                });
            }
        };
        if p.primary.is_some() {
            check(
                "primaryText",
                &r.primary_text,
                &r.primary,
                AA_TEXT,
                format!("text {} on primary {}", r.primary_text, r.primary),
            );
            check(
                "primaryOnSurface",
                &r.primary,
                d.sheet,
                AA_TEXT,
                format!("primary {} as link text on {}", r.primary, d.sheet),
            );
        }
        if p.accent.is_some() {
            check("accent", &r.accent, d.paper, AA_UI, format!("the focus ring {} on {}", r.accent, d.paper));
        }
    }
    out
}

/// The custom properties one mode sets: empty when the theme sets none.
fn mode_vars(p: &Palette, d: &Defaults) -> String {
    let mut s = String::new();
    if let Some(pr) = &p.primary {
        let text = p.primary_text.clone().unwrap_or_else(|| auto_text(pr).into());
        s.push_str(&format!("--accent:{pr};--accent-ink:{text};--accent-wash:{};", mix(pr, d.paper, 0.16)));
    }
    if let Some(c) = &p.secondary {
        s.push_str(&format!("--brand2:{c};"));
    }
    if let Some(c) = &p.accent {
        s.push_str(&format!("--focus:{c};"));
    }
    s
}

/// vlpds's own value for each property the other mode sets: the light
/// rule (`:root:root`) otherwise wins in dark mode on the OAuth pages,
/// whose dark rule is a plain `:root` in a media query.
fn defaults_for(other: &Palette, d: &Defaults) -> String {
    let mut s = String::new();
    if other.primary.is_some() {
        s.push_str(&format!("--accent:{};--accent-ink:{};--accent-wash:{};", d.primary, d.primary_text, d.wash));
    }
    if other.secondary.is_some() {
        s.push_str("--brand2:var(--amber);");
    }
    if other.accent.is_some() {
        s.push_str(&format!("--focus:{};", d.accent));
    }
    s
}

/// The theme's stylesheet: custom properties only, empty when nothing is
/// set. `:root:root` outranks the pages' own `:root` rules wherever this
/// sheet lands, and the dark rules follow the pages' switcher
/// (`data-theme`) as ui/src/styles.css does.
pub fn css(t: &Theme) -> String {
    let (lp, dp) = (&t.colors.light, &t.colors.dark);
    let mut light = mode_vars(lp, &LIGHT);
    if let Some(stack) = t.font.stack() {
        light.push_str(&format!("--sans:{stack};"));
    }
    let mut dark = mode_vars(dp, &DARK);
    // set for light only: vlpds's dark values for those
    let missing = Palette {
        primary: lp.primary.clone().filter(|_| dp.primary.is_none()),
        primary_text: None,
        secondary: lp.secondary.clone().filter(|_| dp.secondary.is_none()),
        accent: lp.accent.clone().filter(|_| dp.accent.is_none()),
    };
    dark.push_str(&defaults_for(&missing, &DARK));
    let mut s = String::new();
    if !light.is_empty() {
        s.push_str(&format!(":root:root{{{light}}}"));
    }
    if !dark.is_empty() {
        s.push_str(&format!(
            "@media (prefers-color-scheme:dark){{:root:root:not([data-theme=light]){{{dark}}}}}:root:root[data-theme=dark]{{{dark}}}"
        ));
    }
    s
}

// ---------------------------------------------------------------- what the pages use

/// The theme as the pages and email use it, built once per saved version.
#[derive(Clone, Debug, Default)]
pub struct Brand {
    /// None: "vlpds".
    pub name: Option<String>,
    /// Same-origin paths with the image's hash as `?v=`.
    pub logo: Option<String>,
    pub favicon: Option<String>,
    pub wordmark: bool,
    /// The stylesheet and its CSP hash (`sha256-…` without quotes); None
    /// when the theme sets no token.
    pub style: Option<(String, String)>,
    pub links: Vec<(&'static str, String)>,
    /// `?v=` of [`CSS_PATH`].
    pub css_tag: String,
}

impl Brand {
    pub fn display_name(&self) -> &str {
        self.name.as_deref().unwrap_or("vlpds")
    }

    pub fn is_default(&self) -> bool {
        self.name.is_none()
            && self.logo.is_none()
            && self.favicon.is_none()
            && self.style.is_none()
            && self.links.is_empty()
    }
}

/// An image ready to serve.
#[derive(Clone, Debug)]
pub struct Served {
    pub mime: &'static str,
    pub sha256: String,
    pub bytes: bytes::Bytes,
}

impl Served {
    /// The `?v=` the pages use.
    pub fn tag(&self) -> &str {
        &self.sha256[..16.min(self.sha256.len())]
    }
}

#[derive(Clone, Debug, Default)]
pub struct Compiled {
    pub doc: Doc,
    pub brand: Brand,
    pub logo: Option<Served>,
    pub favicon: Option<Served>,
    pub css: String,
}

fn served(i: &Option<Image>) -> Option<Served> {
    let i = i.as_ref()?;
    let bytes = base64::engine::general_purpose::STANDARD.decode(&i.data).ok()?;
    let mime = sniff(&bytes)?;
    Some(Served { mime, sha256: i.sha256.clone(), bytes: bytes.into() })
}

pub fn compile(doc: Doc) -> Compiled {
    let t = &doc.theme;
    let (logo, favicon) = (served(&t.logo), served(&t.favicon));
    let css = css(t);
    let at = |kind: ImageKind, s: &Option<Served>| s.as_ref().map(|s| format!("{}?v={}", kind.path(), s.tag()));
    let style = (!css.is_empty()).then(|| {
        let hash = base64::engine::general_purpose::STANDARD.encode(crate::oauth::util::sha256(&css));
        (css.clone(), hash)
    });
    let css_tag = hex::encode(&crate::oauth::util::sha256(&css)[..8]);
    let brand = Brand {
        name: t.name.clone(),
        logo: at(ImageKind::Logo, &logo),
        favicon: at(ImageKind::Favicon, &favicon),
        wordmark: t.logo_is_wordmark && logo.is_some(),
        style,
        links: t.links.listed().into_iter().map(|(l, u)| (l, u.to_string())).collect(),
        css_tag,
    };
    Compiled { doc, brand, logo, favicon, css }
}

/// Account email's branding: the theme where it sets something, else the
/// `--email-*` flags (and their `PDS_*` fallbacks), else the reference's
/// defaults.
pub fn email_branding(flags: &crate::mail::Branding, c: &Compiled, public_url: &str) -> crate::mail::Branding {
    let t = &c.doc.theme;
    let origin = public_url.trim_end_matches('/');
    crate::mail::Branding {
        name: t.name.clone().or_else(|| flags.name.clone()),
        home_url: t.links.home.clone().or_else(|| flags.home_url.clone()),
        logo_url: c.brand.logo.as_ref().map(|p| format!("{origin}{p}")).or_else(|| flags.logo_url.clone()),
        primary_color: t.colors.light.primary.clone().or_else(|| flags.primary_color.clone()),
        disable_confirmation_link: flags.disable_confirmation_link,
    }
}

// ---------------------------------------------------------------- the runtime copy

pub struct Themes {
    stored: RwLock<Arc<Compiled>>,
    seen_etag: Mutex<Option<String>>,
    io: tokio::sync::Mutex<()>,
    wake: tokio::sync::Notify,
    started: AtomicBool,
}

impl Default for Themes {
    fn default() -> Self {
        Themes {
            stored: RwLock::new(Arc::new(compile(Doc::default()))),
            seen_etag: Default::default(),
            io: Default::default(),
            wake: Default::default(),
            started: AtomicBool::new(false),
        }
    }
}

impl std::fmt::Debug for Themes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Themes").field("version", &self.stored.read().doc.version).finish()
    }
}

impl Themes {
    pub fn current(&self) -> Arc<Compiled> {
        self.stored.read().clone()
    }

    fn install(&self, doc: Doc, etag: Option<String>) {
        *self.stored.write() = Arc::new(compile(doc));
        *self.seen_etag.lock() = etag;
    }

    pub fn wake(&self) {
        self.wake.notify_one();
    }
}

#[derive(Debug)]
pub enum SaveError {
    Invalid(String),
    Conflict(u64),
    Store(String),
}

impl std::fmt::Display for SaveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SaveError::Invalid(m) => write!(f, "{m}"),
            SaveError::Conflict(v) => write!(f, "the theme changed (now version {v}): reload and retry"),
            SaveError::Store(e) => write!(f, "config store error: {e}"),
        }
    }
}

async fn bounded<T>(f: impl std::future::Future<Output = object_store::Result<T>>) -> object_store::Result<T> {
    match tokio::time::timeout(CALL_DEADLINE, f).await {
        Ok(r) => r,
        Err(_) => Err(object_store::Error::Generic { store: "theme", source: "config call timed out".into() }),
    }
}

async fn fetch(store: &Store, etag: Option<String>) -> object_store::Result<Option<(bytes::Bytes, Option<String>)>> {
    let path = config_path(store);
    let got = bounded(async {
        let r = store.raw.get_opts(&path, GetOptions { if_none_match: etag, ..Default::default() }).await?;
        let e = r.meta.e_tag.clone();
        Ok((r.bytes().await?, e))
    })
    .await;
    match got {
        Ok(x) => Ok(Some(x)),
        Err(object_store::Error::NotFound { .. }) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Returns whether the theme was replaced.
pub async fn refresh(d: &Themes, store: &Store) -> anyhow::Result<bool> {
    let _io = d.io.lock().await;
    let seen = d.seen_etag.lock().clone();
    let got = match fetch(store, seen.clone()).await {
        Ok(g) => g,
        Err(object_store::Error::NotModified { .. }) => return Ok(false),
        Err(e) => return Err(e.into()),
    };
    let Some((bytes, etag)) = got else {
        if seen.is_none() && d.stored.read().doc == Doc::default() {
            return Ok(false);
        }
        d.install(Doc::default(), None);
        return Ok(true);
    };
    match serde_json::from_slice::<Doc>(&bytes) {
        Ok(doc) => {
            let v = doc.version;
            d.install(doc, etag);
            tracing::info!(version = v, "theme loaded");
            Ok(true)
        }
        Err(e) => {
            *d.seen_etag.lock() = etag;
            tracing::warn!("theme.json unreadable (keeping the last good theme): {e}");
            Ok(false)
        }
    }
}

pub fn spawn_refresher(d: &Arc<Themes>, store: Store) {
    if d.started.swap(true, Ordering::AcqRel) {
        return;
    }
    let weak = Arc::downgrade(d);
    tokio::spawn(async move {
        loop {
            let Some(d) = weak.upgrade() else { return };
            if let Err(e) = refresh(&d, &store).await {
                tracing::warn!("theme refresh failed (retrying): {e:#}");
            }
            tokio::select! {
                _ = tokio::time::sleep(REFRESH_EVERY) => {}
                _ = d.wake.notified() => {}
            }
        }
    });
}

fn is_conflict(e: &object_store::Error) -> bool {
    matches!(e, object_store::Error::Precondition { .. } | object_store::Error::AlreadyExists { .. })
}

/// Read-modify-write under CAS; installs the result on this node. `f` may
/// be called more than once. Returns the stored doc before and after.
pub async fn update(
    d: &Themes,
    store: &Store,
    if_version: Option<u64>,
    by: &str,
    f: impl Fn(&mut Theme) -> Result<(), SaveError>,
) -> Result<(Doc, Doc), SaveError> {
    let _io = d.io.lock().await;
    let store_err = |e: object_store::Error| SaveError::Store(e.to_string());
    for _ in 0..CAS_RETRIES {
        let (old, etag) = match fetch(store, None).await.map_err(store_err)? {
            None => (Doc::default(), None),
            Some((b, e)) => (serde_json::from_slice(&b).unwrap_or_else(|_| d.stored.read().doc.clone()), e),
        };
        if if_version.is_some_and(|v| v != old.version) {
            return Err(SaveError::Conflict(old.version));
        }
        let mut doc = old.clone();
        f(&mut doc.theme)?;
        doc.version += 1;
        doc.updated_at = Some(vlatproto::events::now_rfc3339());
        doc.updated_by = Some(by.to_string());
        let mode = match etag {
            Some(e) => crate::cluster::if_match(Some(e)),
            None => PutMode::Create,
        };
        let body = serde_json::to_vec_pretty(&doc).map_err(|e| SaveError::Store(e.to_string()))?;
        let put = bounded(store.raw.put_opts(
            &config_path(store),
            PutPayload::from(body),
            PutOptions { mode, ..Default::default() },
        ))
        .await;
        match put {
            Ok(r) => {
                d.install(doc.clone(), r.e_tag);
                return Ok((old, doc));
            }
            Err(e) if is_conflict(&e) => continue,
            Err(e) => return Err(store_err(e)),
        }
    }
    Err(SaveError::Store("theme.json kept changing under the update".into()))
}

/// What a save changed, by field, for the audit entry.
pub fn changes(old: &Theme, new: &Theme) -> Vec<&'static str> {
    let mut out = Vec::new();
    let mut diff = |name: &'static str, same: bool| {
        if !same {
            out.push(name);
        }
    };
    diff("name", old.name == new.name);
    diff("logoIsWordmark", old.logo_is_wordmark == new.logo_is_wordmark);
    diff("colors.light", old.colors.light == new.colors.light);
    diff("colors.dark", old.colors.dark == new.colors.dark);
    diff("font", old.font == new.font);
    diff("links", old.links == new.links);
    diff("logo", old.logo.as_ref().map(|i| &i.sha256) == new.logo.as_ref().map(|i| &i.sha256));
    diff("favicon", old.favicon.as_ref().map(|i| &i.sha256) == new.favicon.as_ref().map(|i| &i.sha256));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use object_store::ObjectStoreExt;

    pub(crate) fn png(extra: usize) -> Vec<u8> {
        let mut b = b"\x89PNG\r\n\x1a\n".to_vec();
        b.extend(std::iter::repeat_n(7u8, extra));
        b
    }

    fn data_uri(mime: &str, b: &[u8]) -> String {
        format!("data:{mime};base64,{}", base64::engine::general_purpose::STANDARD.encode(b))
    }

    fn sample() -> Theme {
        let mut t = Theme {
            name: Some("  cavu ".into()),
            colors: Colors {
                light: Palette { primary: Some("#0F766E".into()), ..Default::default() },
                dark: Palette { primary: Some("#2dd4bf".into()), secondary: Some("#fa0".into()), ..Default::default() },
            },
            font: Font::System,
            links: Links { terms: Some("https://cavu.example/terms".into()), ..Default::default() },
            ..Default::default()
        };
        normalize(&mut t, false).unwrap();
        t
    }

    #[test]
    fn colors_normalize_and_bad_ones_are_refused() {
        assert_eq!(normalize_color("#ABC").as_deref(), Some("#aabbcc"));
        assert_eq!(normalize_color(" #0f766E ").as_deref(), Some("#0f766e"));
        for bad in ["0f766e", "#0f766", "#0f766e00", "red", "#ggg", "#12345;", "#123}body{x:y"] {
            assert_eq!(normalize_color(bad), None, "{bad}");
        }
        let t = sample();
        assert_eq!(t.name.as_deref(), Some("cavu"));
        assert_eq!(t.colors.light.primary.as_deref(), Some("#0f766e"));
        assert_eq!(t.colors.dark.secondary.as_deref(), Some("#ffaa00"));
        let bad = |f: &dyn Fn(&mut Theme)| {
            let mut t = sample();
            f(&mut t);
            normalize(&mut t, false).err()
        };
        assert!(bad(&|t| t.colors.light.accent = Some("blue".into())).unwrap().contains("colors.light.accent"));
        assert!(bad(&|t| t.colors.dark.primary_text = Some("#fff".into())).is_none());
        assert!(bad(&|t| {
            t.colors.dark.primary = None;
            t.colors.dark.primary_text = Some("#fff".into());
        })
        .is_some());
        assert!(bad(&|t| t.name = Some("x".repeat(MAX_NAME + 1))).is_some());
        assert!(bad(&|t| t.name = Some("a\nb".into())).is_some());
        assert!(bad(&|t| t.links.home = Some("http://cavu.example".into())).is_some());
        assert!(bad(&|t| t.links.home = Some("javascript:alert(1)".into())).is_some());
        assert!(bad(&|t| t.links.home = Some("https://u:p@cavu.example".into())).is_some());
        assert!(bad(&|t| t.links.terms = Some("mailto:a@b.example".into())).is_some(), "mailto is for support only");
        assert!(bad(&|t| t.links.support = Some("mailto:help@cavu.example".into())).is_none());
        assert!(bad(&|t| t.links.support = Some("mailto:<x>".into())).is_some());
        let mut t = sample();
        t.links.home = Some("http://127.0.0.1:2583/".into());
        assert!(normalize(&mut t, false).is_err());
        assert!(normalize(&mut t, true).is_ok(), "loopback http in dev mode");
        // empty strings clear
        let mut t = Theme {
            name: Some(" ".into()),
            links: Links { home: Some("".into()), ..Default::default() },
            ..Default::default()
        };
        normalize(&mut t, false).unwrap();
        assert_eq!(t, Theme::default());
    }

    #[test]
    fn images_are_sniffed_and_capped() {
        let ok = image_from_data_uri(&data_uri("image/png", &png(100)), ImageKind::Logo).unwrap();
        assert_eq!(ok.mime, "image/png");
        // the claim is ignored, the bytes decide
        let i = image_from_data_uri(&data_uri("image/gif", &png(10)), ImageKind::Favicon).unwrap();
        assert_eq!(i.mime, "image/png");
        let svg = data_uri("image/svg+xml", b"<svg xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>");
        assert!(image_from_data_uri(&svg, ImageKind::Logo).unwrap_err().contains("not a"));
        let jpeg = [0xff, 0xd8, 0xff, 0xe0, 0, 0];
        assert!(image_from_bytes(&jpeg, ImageKind::Logo).is_ok());
        assert!(image_from_bytes(&jpeg, ImageKind::Favicon).is_err(), "favicons: png or ico");
        assert!(image_from_bytes(&[0, 0, 1, 0, 1, 0], ImageKind::Favicon).is_ok());
        let big = data_uri("image/png", &png(MAX_LOGO_BYTES));
        assert!(image_from_data_uri(&big, ImageKind::Logo).unwrap_err().contains("KiB"));
        assert!(image_from_data_uri(&data_uri("image/png", &png(MAX_LOGO_BYTES - 8)), ImageKind::Logo).is_ok());
        assert!(image_from_data_uri(&data_uri("image/png", &png(MAX_FAVICON_BYTES)), ImageKind::Favicon).is_err());
        assert!(image_from_data_uri("https://x.example/logo.png", ImageKind::Logo).is_err());
        assert!(image_from_data_uri("data:image/png,rawtext", ImageKind::Logo).is_err());
        // a stored image whose hash doesn't match is refused
        let mut t = Theme { logo: Some(Image { sha256: "00".into(), ..ok.clone() }), ..Default::default() };
        assert!(normalize(&mut t, false).is_err());
        let mut t = Theme { logo: Some(ok), logo_is_wordmark: true, ..Default::default() };
        normalize(&mut t, false).unwrap();
        assert!(t.logo_is_wordmark);
        let mut t = Theme { logo_is_wordmark: true, ..Default::default() };
        normalize(&mut t, false).unwrap();
        assert!(!t.logo_is_wordmark, "no logo, no wordmark");
    }

    #[test]
    fn contrast_matches_wcag() {
        assert!((contrast("#000000", "#ffffff") - 21.0).abs() < 1e-9);
        assert!((contrast("#ffffff", "#ffffff") - 1.0).abs() < 1e-9);
        // vlpds's own pairs pass
        assert!(contrast(LIGHT.primary_text, LIGHT.primary) >= AA_TEXT);
        assert!(contrast(DARK.primary_text, DARK.primary) >= AA_TEXT);
        assert_eq!(auto_text("#0f766e"), "#ffffff");
        assert_eq!(auto_text("#2dd4bf"), "#101418");
        assert!(warnings(&Theme::default()).is_empty());
        assert!(warnings(&sample()).is_empty(), "{:?}", warnings(&sample()));
        let mut t = Theme::default();
        t.colors.light.primary = Some("#7dd3c0".into());
        t.colors.light.primary_text = Some("#ffffff".into());
        t.colors.dark.accent = Some("#1a2030".into());
        let w = warnings(&t);
        let checks: Vec<_> = w.iter().map(|w| (w.mode, w.check)).collect();
        assert_eq!(checks, vec![("light", "primaryText"), ("light", "primaryOnSurface"), ("dark", "accent")], "{w:?}");
        assert!(w[0].message.contains("WCAG AA"), "{}", w[0].message);
    }

    #[test]
    fn unconfigured_is_vlpds() {
        let c = compile(Doc::default());
        assert!(c.css.is_empty());
        assert!(c.brand.is_default());
        assert_eq!(c.brand.display_name(), "vlpds");
        // email: the flags and the reference's defaults, untouched
        let flags = crate::mail::Branding { name: Some("Flag".into()), ..Default::default() };
        let b = email_branding(&flags, &c, "https://pds.example");
        assert_eq!(b.name.as_deref(), Some("Flag"));
        assert_eq!((b.logo_url, b.home_url, b.primary_color), (None, None, None));
    }

    #[test]
    fn the_stylesheet_sets_tokens_only() {
        let t = sample();
        let s = css(&t);
        assert!(s.starts_with(":root:root{--accent:#0f766e;--accent-ink:#ffffff;--accent-wash:"), "{s}");
        assert!(s.contains("--sans:ui-sans-serif"), "{s}");
        assert!(s.contains("@media (prefers-color-scheme:dark){:root:root:not([data-theme=light]){--accent:#2dd4bf;--accent-ink:#101418;"), "{s}");
        assert!(s.contains(":root:root[data-theme=dark]{"), "{s}");
        assert!(s.contains("--brand2:#ffaa00"));
        assert!(!s.contains('<') && !s.contains("url("), "{s}");
        // light only: dark mode gets vlpds's dark values back
        let mut t = Theme::default();
        t.colors.light.primary = Some("#0f766e".into());
        let s = css(&t);
        assert!(s.contains(&format!(":root:root[data-theme=dark]{{--accent:{};", DARK.primary)), "{s}");
        // dark only: no light rule
        let mut t = Theme::default();
        t.colors.dark.accent = Some("#ffffff".into());
        assert!(css(&t).starts_with("@media"), "{}", css(&t));
        // font only
        let t = Theme { font: Font::Serif, ..Default::default() };
        assert_eq!(css(&t), ":root:root{--sans:ui-serif,Georgia,Cambria,\"Times New Roman\",serif;}");
    }

    #[test]
    fn brand_and_email() {
        let mut t = sample();
        t.logo = Some(image_from_bytes(&png(40), ImageKind::Logo).unwrap());
        t.links.home = Some("https://cavu.example".into());
        let c = compile(Doc { theme: t.clone(), version: 3, ..Default::default() });
        assert_eq!(c.brand.display_name(), "cavu");
        let logo = c.brand.logo.clone().unwrap();
        assert!(logo.starts_with("/theme/logo?v=") && logo.len() == "/theme/logo?v=".len() + 16, "{logo}");
        assert_eq!(c.logo.as_ref().unwrap().bytes.len(), 48);
        assert_eq!(
            c.brand.links,
            vec![("Home", "https://cavu.example".into()), ("Terms", "https://cavu.example/terms".into())]
        );
        let (css, hash) = c.brand.style.clone().unwrap();
        assert_eq!(hash, base64::engine::general_purpose::STANDARD.encode(crate::oauth::util::sha256(&css)));
        let flags = crate::mail::Branding {
            name: Some("Flag".into()),
            home_url: Some("https://flag.example".into()),
            primary_color: Some("#123456".into()),
            disable_confirmation_link: true,
            ..Default::default()
        };
        let b = email_branding(&flags, &c, "https://pds.example/");
        assert_eq!(b.name.as_deref(), Some("cavu"));
        assert_eq!(b.home_url.as_deref(), Some("https://cavu.example"));
        assert_eq!(b.logo_url, Some(format!("https://pds.example{logo}")));
        assert_eq!(b.primary_color.as_deref(), Some("#0f766e"));
        assert!(b.disable_confirmation_link);
        assert_eq!(
            changes(&Theme::default(), &t),
            vec!["name", "colors.light", "colors.dark", "font", "links", "logo"]
        );
    }

    #[tokio::test]
    async fn put_conflict_and_peers_pick_it_up() {
        let store = Store::memory(None);
        let (a, b) = (Themes::default(), Themes::default());
        assert!(!refresh(&b, &store).await.unwrap());
        let (old, doc) = update(&a, &store, Some(0), "admin", |t| {
            *t = sample();
            Ok(())
        })
        .await
        .unwrap();
        assert_eq!((old.version, doc.version), (0, 1));
        assert_eq!(a.current().brand.display_name(), "cavu");
        assert_eq!(b.current().brand.display_name(), "vlpds");
        assert!(refresh(&b, &store).await.unwrap());
        assert_eq!(b.current().brand.display_name(), "cavu");
        assert_eq!(b.current().doc.updated_by.as_deref(), Some("admin"));
        assert!(matches!(update(&b, &store, Some(0), "x", |_| Ok(())).await, Err(SaveError::Conflict(1))));
        let (_, doc) = update(&b, &store, Some(1), "x", |t| {
            t.name = None;
            Ok(())
        })
        .await
        .unwrap();
        assert_eq!(doc.version, 2);
        assert!(refresh(&a, &store).await.unwrap());
        assert_eq!(a.current().brand.display_name(), "vlpds");
        store.raw.put(&config_path(&store), PutPayload::from_static(b"{{")).await.unwrap();
        assert!(!refresh(&a, &store).await.unwrap());
        assert_eq!(a.current().doc.version, 2, "garbage keeps the last good theme");
    }
}
