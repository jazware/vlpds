//! Server-rendered pages for the authorization flow and session management.
//! No external assets: one inline stylesheet allowed by hash in the
//! Content-Security-Policy. Two fixed scripts, each allowed by hash and
//! only on its pages: the auto-submit of the `response_mode=form_post`
//! page, and the passkey ceremony on the sign-in pages ([`PASSKEY_JS`]).
//! Operator branding ([`Brand`]) adds a second stylesheet, also by hash,
//! and changes only the header and the links under the card.

use super::rollup::{self, Line, Row, Tier};
use super::util::{html_escape as e, sha256};
use crate::brand::Brand;
use base64::Engine;
use std::sync::LazyLock;

const STYLE: &str = r#"
.u{position:absolute;left:-9999px;width:1px;height:1px;overflow:hidden}
@font-face{font-family:"Schibsted Grotesk";src:url(/fonts/schibsted-grotesk.woff2) format("woff2");font-weight:400 900;font-display:swap}
@font-face{font-family:"JetBrains Mono";src:url(/fonts/jetbrains-mono.woff2) format("woff2");font-weight:100 800;font-display:swap}
:root{--paper:#edefea;--sheet:#f8f9f6;--ink:#18222d;--ink2:#4d5966;--ink3:#7a858f;--rule:#c9cfc8;--accent:#17705f;--accent-ink:#fff;--amber:#b9770e;--danger:#a93a24;--focus:#3561c9;color-scheme:light}
@media (prefers-color-scheme:dark){:root{--paper:#121820;--sheet:#19212b;--ink:#dce4e3;--ink2:#93a0a8;--ink3:#6b7884;--rule:#2a3542;--accent:#4fbf9f;--accent-ink:#0c1a16;--amber:#e3a43a;--danger:#f0806a;--focus:#8fb0ff;color-scheme:dark}}
*{box-sizing:border-box}
body{margin:0;background:var(--paper);color:var(--ink);font:15px/1.55 "Schibsted Grotesk",ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;-webkit-font-smoothing:antialiased}
main{max-width:480px;margin:6vh auto 8vh;padding:0 16px}
.brand{display:flex;align-items:center;gap:10px;margin:0 0 18px;font-weight:800;font-size:17px;letter-spacing:-.01em}
.brand svg{display:block}
.brand span{color:var(--ink2);font-weight:500;font-size:14px}
.gh{margin-left:auto;display:flex;padding:6px;border-radius:6px;color:var(--ink2)}
.gh:hover{color:var(--ink);background:var(--sheet)}
.card{background:var(--sheet);border:1px solid var(--rule);border-radius:8px;padding:26px 24px 22px;box-shadow:0 1px 0 var(--rule)}
.strata{height:5px;margin:-26px -24px 22px;border-radius:7px 7px 0 0;background:linear-gradient(var(--accent) 0 2px,transparent 2px 3px,var(--amber) 3px 4px,transparent 4px)}
h1{font-size:24px;line-height:1.2;letter-spacing:-.015em;margin:0 0 6px;font-weight:750}
p{margin:8px 0}
b{font-weight:650}
a{color:var(--accent);text-underline-offset:3px}
.muted{color:var(--ink2);font-size:13.5px}
.client{display:flex;flex-direction:column;gap:2px;min-width:0;overflow-wrap:anywhere;font-size:14px;background:var(--paper);border:1px solid var(--rule);border-left:3px solid var(--accent);border-radius:4px;padding:9px 11px;margin:10px 0}
.client b{font-size:16px}
.client code{font:12.5px/1.45 "JetBrains Mono",ui-monospace,Menlo,monospace;color:var(--ink2);overflow-wrap:anywhere}
label{display:block;font-size:13.5px;font-weight:600;margin:16px 0 5px}
input[type=text],input[type=password],input[type=email]{width:100%;padding:10px 12px;border:1px solid var(--rule);border-radius:5px;background:var(--paper);color:var(--ink);font:inherit;font-size:15px}
.affix{display:flex;align-items:stretch}
.affix input{border-radius:5px 0 0 5px;min-width:0}
.affix span,.affix select{display:flex;align-items:center;padding:0 11px;border:1px solid var(--rule);border-left:0;border-radius:0 5px 5px 0;background:var(--sheet);color:var(--ink2);font-family:"JetBrains Mono",ui-monospace,Menlo,monospace;font-size:13px;white-space:nowrap}
.hint{color:var(--ink2);font-size:12.5px;margin:5px 0 0}
.alt{margin:18px 0 0;padding-top:14px;border-top:1px solid var(--rule);font-size:14px;color:var(--ink2)}
input:focus-visible,button:focus-visible,a:focus-visible{outline:2px solid var(--focus);outline-offset:2px}
button{font:inherit;font-weight:600;border-radius:5px;padding:9px 16px;border:1px solid var(--rule);background:var(--sheet);color:var(--ink);cursor:pointer}
button:hover{border-color:var(--ink2)}
button.primary{background:var(--accent);border-color:var(--accent);color:var(--accent-ink)}
button.primary:hover{filter:brightness(1.08)}
button.danger{color:var(--danger)}
button.danger:hover{border-color:var(--danger)}
.row{display:flex;gap:10px;justify-content:flex-end;margin-top:22px;flex-wrap:wrap}
.row .back{order:-1}
.err{color:var(--danger);margin:12px 0;padding:8px 11px;border:1px solid var(--danger);border-radius:5px;font-size:14px}
.acct{display:flex;align-items:center;justify-content:space-between;gap:10px;border:1px solid var(--rule);border-radius:6px;padding:10px 12px;margin:8px 0;background:var(--paper)}
.acct form{margin:0}
.acct .who{min-width:0;overflow-wrap:anywhere}
.acct .who .muted{font-family:"JetBrains Mono",ui-monospace,Menlo,monospace;font-size:12px}
table{width:100%;border-collapse:collapse;font-size:13.5px}
td{border-top:1px solid var(--rule);padding:10px 4px;vertical-align:top;overflow-wrap:anywhere}
td:last-child{text-align:right;width:1%;white-space:nowrap;overflow-wrap:normal;padding-left:10px}
footer{margin-top:14px;text-align:center}
p.lead{font-weight:650;margin:14px 0 6px}
ul.rows{list-style:none;margin:0;padding:0;border-top:1px solid var(--rule)}
ul.rows>li{display:flex;gap:11px;align-items:flex-start;padding:11px 0;border-bottom:1px solid var(--rule)}
ul.rows>li>input[type=checkbox]{flex:none;width:17px;height:17px;margin:3px 0 0;accent-color:var(--accent)}
.cb{flex:none;width:17px;height:17px;margin:3px 0 0;border-radius:3px;background:var(--ink3);display:grid;place-items:center}
.cb:after{content:"";width:5px;height:9px;border:solid var(--sheet);border-width:0 2px 2px 0;transform:translate(0,-1px) rotate(45deg)}
.rb{min-width:0;flex:1}
details.r>summary{list-style:none;cursor:pointer;display:block;position:relative;padding-right:22px}
details.r>summary::-webkit-details-marker{display:none}
details.r>summary:after{content:"";position:absolute;right:4px;top:6px;width:7px;height:7px;border:solid var(--ink2);border-width:0 2px 2px 0;transform:rotate(45deg)}
details.r[open]>summary:after{transform:rotate(-135deg);top:10px}
details.r>summary:hover .rl{color:var(--accent)}
summary:focus-visible{outline:2px solid var(--focus);outline-offset:2px;border-radius:3px}
.rl{font-weight:650;overflow-wrap:anywhere}
.rs{display:block;color:var(--ink2);font-size:13.5px;margin-top:1px}
.tag{display:inline-block;margin-left:6px;padding:0 6px;border-radius:3px;font-size:11px;font-weight:600;line-height:1.6;vertical-align:1px;border:1px solid currentColor}
.tag.t1{color:var(--danger)}
.tag.t2{color:var(--amber)}
.src{display:inline-block;margin:6px 6px 0 0;padding:1px 7px;border-radius:3px;font-size:12px;font-weight:600;background:var(--paper);border:1px solid var(--rule);color:var(--ink2)}
ul.dl{margin:8px 0 2px;padding:0;list-style:none;font-size:13.5px}
ul.dl>li{padding:6px 0;border-top:1px dashed var(--rule)}
ul.dl .v{display:block;font-weight:600;font-size:13px}
ul.dl .o{display:block;color:var(--ink2)}
ul.dl code,ul.raw li{font:11.5px/1.5 "JetBrains Mono",ui-monospace,Menlo,monospace;overflow-wrap:anywhere}
ul.dl code{display:block;color:var(--ink3)}
.rn{display:block;font-size:12.5px;color:var(--ink2);margin-top:6px}
.quote{display:block;font-size:13px;color:var(--ink2);border-left:2px solid var(--rule);padding-left:8px;margin:6px 0 0}
details.raw{margin:12px 0 0;font-size:13.5px}
details.raw summary{cursor:pointer;color:var(--accent)}
ul.raw{list-style:none;margin:6px 0 0;padding:8px 10px;background:var(--paper);border:1px solid var(--rule);border-radius:4px;color:var(--ink2)}
ul.raw li.gh{font:600 12px/1.5 "Schibsted Grotesk",ui-sans-serif,system-ui,sans-serif;color:var(--ink);margin-top:6px}
ul.raw li.gh:first-child{margin-top:0}
ul.raw li.ig{font-family:inherit;font-style:italic}
.warn{display:block;margin:6px 0 0;padding:6px 9px;border-left:3px solid var(--amber);background:var(--paper);font-size:13.5px;font-weight:400;color:var(--ink)}
label.check{display:flex;gap:8px;align-items:center;font-weight:500}
.wide{width:100%}
form.pk{margin:14px 0 4px}
.sep{border-top:1px solid var(--rule);margin:18px 0 0}
.or{text-align:center;margin:14px 0 0}
details.alt-code{margin:16px 0 0}
details.alt-code summary{cursor:pointer;color:var(--accent);font-size:14px}
.fed{display:grid;gap:8px;margin:14px 0 0}
a.fedbtn{display:flex;align-items:center;justify-content:center;gap:9px;padding:9px 16px;border:1px solid var(--rule);border-radius:5px;background:var(--sheet);color:var(--ink);font-weight:600;text-decoration:none}
a.fedbtn:hover{border-color:var(--ink2)}
a.fedbtn img{width:18px;height:18px}
.note{margin:12px 0;padding:8px 11px;border:1px solid var(--accent);border-radius:5px;font-size:14px}
h2{font-size:15px;margin:16px 0 4px}
"#;

static STYLE_HASH: LazyLock<String> = LazyLock::new(|| base64::engine::general_purpose::STANDARD.encode(sha256(STYLE)));

/// `form_action`: extra sources. Browsers apply form-action to the redirect
/// that follows a form post, so the consent page must allow the client's
/// redirect_uri origin/scheme.
pub fn csp(b: &Brand, form_action: &[String]) -> String {
    let mut fa = String::from("'self'");
    for s in form_action {
        fa.push(' ');
        fa.push_str(s);
    }
    let brand = b.oauth_style().map(|(_, h)| format!(" 'sha256-{h}'")).unwrap_or_default();
    format!(
        "default-src 'none'; style-src 'sha256-{}'{brand}; font-src 'self'; img-src 'self' data:; form-action {fa}; frame-ancestors 'none'; base-uri 'none'",
        *STYLE_HASH
    )
}

/// The guard keeps a page restored from history from posting the code again.
const AUTO_SUBMIT: &str = "var f=document.forms[0],done=false;\
f.addEventListener('submit',function(e){if(done){e.preventDefault()}done=true});\
setTimeout(function(){if(!done){done=true;f.submit()}},1);";

static AUTO_SUBMIT_HASH: LazyLock<String> =
    LazyLock::new(|| base64::engine::general_purpose::STANDARD.encode(sha256(AUTO_SUBMIT)));

pub fn csp_form_post(b: &Brand, form_action: &[String]) -> String {
    format!("{}; script-src 'sha256-{}'", csp(b, form_action), *AUTO_SUBMIT_HASH)
}

/// `response_mode=form_post`. The button is the no-script fallback.
pub fn form_post(b: &Brand, redirect_uri: &str, params: &[(String, String)]) -> String {
    let mut fields = String::new();
    for (k, v) in params {
        fields.push_str(&format!("<input type=\"hidden\" name=\"{}\" value=\"{}\">", e(k), e(v)));
    }
    let body = format!(
        "<h1>Returning to the app</h1><form method=\"post\" action=\"{}\">{fields}<div class=\"row\">\
<button type=\"submit\" class=\"primary\">Continue</button></div></form>",
        e(redirect_uri)
    );
    page_with_script(b, "Returning to the app", &body, AUTO_SUBMIT)
}

/// Three strata: log segments settling into state.
const MARK: &str = "<svg width=\"22\" height=\"18\" viewBox=\"0 0 22 18\" aria-hidden=\"true\">\
<rect x=\"0\" y=\"0\" width=\"22\" height=\"4\" rx=\"1\" fill=\"currentColor\"/>\
<rect x=\"3\" y=\"7\" width=\"16\" height=\"4\" rx=\"1\" fill=\"currentColor\" opacity=\".6\"/>\
<rect x=\"6\" y=\"14\" width=\"10\" height=\"4\" rx=\"1\" fill=\"currentColor\" opacity=\".35\"/></svg>";

/// GitHub's mark, linking the source as the web UI's top bar does.
const SOURCE_LINK: &str = "<a class=\"gh\" href=\"https://github.com/jazware/vlpds\" aria-label=\"Source on GitHub\" title=\"Source on GitHub\">\
<svg width=\"18\" height=\"18\" viewBox=\"0 0 16 16\" fill=\"currentColor\" aria-hidden=\"true\"><path d=\"M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8Z\"/></svg></a>";

pub fn page(b: &Brand, title: &str, body: &str) -> String {
    page_with_script(b, title, body, "")
}

/// vlpds's mark and name, or the operator's logo and name.
fn header(b: &Brand) -> String {
    if b.name.is_none() && b.logo.is_none() {
        return format!("<div class=\"brand\">{MARK}vlpds<span>account security</span>{SOURCE_LINK}</div>");
    }
    // the name follows the logo when set, so the image is decorative then
    let logo = b
        .logo_src()
        .map(|src| {
            let alt = if b.name.is_some() { String::new() } else { e(&b.label) };
            format!("<img src=\"{}\" alt=\"{alt}\" height=\"24\">", e(&src))
        })
        .unwrap_or_default();
    let name = b.name.as_deref().map(e).unwrap_or_default();
    format!("<div class=\"brand\">{logo}{name}<span>account security</span>{SOURCE_LINK}</div>")
}

fn brand_links(b: &Brand) -> String {
    let links = b.links();
    if links.is_empty() {
        return String::new();
    }
    let mut s = format!("<nav class=\"bl\" aria-label=\"{}\">", e(&b.label));
    for (t, u) in links {
        s.push_str(&format!("<a href=\"{}\">{t}</a>", e(u)));
    }
    s.push_str("</nav>");
    s
}

fn page_with_script(b: &Brand, title: &str, body: &str, script: &str) -> String {
    let script = if script.is_empty() { String::new() } else { format!("<script>{script}</script>") };
    let mut head = String::new();
    if let Some(src) = b.favicon_src() {
        head.push_str(&format!("<link rel=\"icon\" href=\"{}\">", e(&src)));
    }
    if let Some((css, _)) = b.oauth_style() {
        head.push_str(&format!("<style>{css}</style>"));
    }
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
<meta name=\"referrer\" content=\"no-referrer\"><title>{}</title><style>{STYLE}</style>{head}</head><body><main>\
{}<div class=\"card\"><div class=\"strata\"></div>{body}</div>{}</main>{script}</body></html>",
        e(title),
        header(b),
        brand_links(b)
    )
}

pub struct Ctx<'a> {
    pub request_uri: &'a str,
    pub csrf: &'a str,
    pub client_id: &'a str,
    pub loopback: bool,
    pub server_name: &'a str,
}

fn hidden(ctx: &Ctx) -> String {
    format!(
        "<input type=\"hidden\" name=\"request_uri\" value=\"{}\"><input type=\"hidden\" name=\"csrf\" value=\"{}\">",
        e(ctx.request_uri),
        e(ctx.csrf)
    )
}

fn client_block(ctx: &Ctx) -> String {
    if ctx.loopback {
        "<div class=\"client\">A development app running on your own computer (http://localhost)</div>".into()
    } else {
        format!(
            "<div class=\"client\"><b>{}</b><code>{}</code></div>",
            e(&rollup::client_label(ctx.client_id, false)),
            e(ctx.client_id)
        )
    }
}

pub struct LoginForm<'a> {
    pub action: &'a str,
    pub identifier: &'a str,
    pub error: Option<&'a str>,
    /// Password accepted: the second-factor step.
    pub second: Option<Second<'a>>,
    /// The password step: also offer a passkey instead of the password.
    pub passkey: Option<PasskeyUi<'a>>,
    /// The password step: sign-in providers (GET links, so the page's
    /// form-action needn't allow the provider).
    pub providers: &'a [ProviderLink],
    /// `/oauth/account` only: signing in to change sign-in methods.
    pub step_up: Option<StepUp<'a>>,
}

/// `/oauth/account` asking for the sign-in that adding or removing a
/// sign-in method needs, then back to that section.
pub struct StepUp<'a> {
    /// The hinted account's own handle.
    pub handle: Option<&'a str>,
    /// The hinted account's DID, posted back so a failed sign-in's page
    /// keeps it.
    pub hint: Option<&'a str>,
}

/// The `return` value, on `/oauth/account` and its sign-in forms, that
/// lands a sign-in on the account's sign-in methods.
pub const METHODS_RETURN: &str = "sign-in-methods";

pub struct ProviderLink {
    pub name: String,
    /// A `data:image/…` URI (checked when the provider was saved).
    pub icon: Option<String>,
    pub href: String,
}

fn provider_links(links: &[ProviderLink], verb: &str) -> String {
    if links.is_empty() {
        return String::new();
    }
    let mut b = String::from("<div class=\"fed\">");
    for l in links {
        let icon = l.icon.as_deref().map(|i| format!("<img src=\"{}\" alt=\"\">", e(i))).unwrap_or_default();
        b.push_str(&format!(
            "<a class=\"fedbtn\" href=\"{}\">{icon}<span>{verb} {}</span></a>",
            e(&l.href),
            e(&l.name)
        ));
    }
    b.push_str("</div>");
    b
}

/// What the second-factor step offers.
pub struct Second<'a> {
    /// The code was emailed to this (obfuscated) address: the only factor.
    pub email_hint: Option<&'a str>,
    pub totp: bool,
    /// Offer to trust this browser for this many days (0: don't).
    pub trust_days: u32,
    /// The account's passkeys.
    pub passkey: Option<PasskeyUi<'a>>,
    /// The account has passkeys, but every one is flagged as copied.
    pub flagged: bool,
}

/// What [`PASSKEY_JS`] reads from the passkey form's `data-*` attributes.
pub struct PasskeyUi<'a> {
    /// base64url
    pub challenge: &'a str,
    pub rp_id: &'a str,
    /// `allowCredentials` as JSON (empty for passwordless).
    pub allow: &'a str,
}

/// The passkey ceremony on the sign-in and second-factor pages. Fixed bytes
/// (allowed by hash, like the style), reading everything from the `#pk`
/// form's data attributes, posting the assertion as hidden fields: no
/// fetch, so no connect-src. Conditional UI (autofill) on the password step.
/// On a host that isn't the RP ID (an IP address never is) every request
/// would fail, so the button stays hidden and autofill never starts.
pub const PASSKEY_JS: &str = "(function(){var f=document.getElementById('pk');if(!f||!window.PublicKeyCredential)return;\
var d=f.dataset,E=f.elements,ctl,h=location.hostname;if(h!==d.rp||/^[\\d.]+$/.test(h)||h.indexOf(':')>=0)return;\
function b(s){var r=atob(s.replace(/-/g,'+').replace(/_/g,'/')),u=new Uint8Array(r.length);for(var i=0;i<r.length;i++)u[i]=r.charCodeAt(i);return u}\
function e(a){var u=new Uint8Array(a),s='';for(var i=0;i<u.length;i++)s+=String.fromCharCode(u[i]);return btoa(s).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'')}\
var o={challenge:b(d.challenge),rpId:d.rp,timeout:300000,userVerification:d.uv,\
allowCredentials:JSON.parse(d.allow||'[]').map(function(c){return{type:'public-key',id:b(c.id),transports:c.transports}})};\
function go(m){if(ctl)ctl.abort();ctl=new AbortController();var q={publicKey:o,signal:ctl.signal};if(m)q.mediation=m;\
navigator.credentials.get(q).then(function(c){var r=c.response,t=document.querySelector('input[type=checkbox][name=trust]');\
E.passkey_id.value=e(c.rawId);E.client_data.value=e(r.clientDataJSON);E.auth_data.value=e(r.authenticatorData);\
E.signature.value=e(r.signature);E.user_handle.value=r.userHandle?e(r.userHandle):'';\
if(t&&t.checked&&E.trust)E.trust.value='1';f.submit()},\
function(x){if(!m&&x&&x.name!=='AbortError'){var p=document.getElementById('pk-err');if(p)p.hidden=false}})}\
var g=document.getElementById('pk-go');if(g){g.hidden=false;g.addEventListener('click',function(){go()})}\
if(d.mode==='signin'&&PublicKeyCredential.isConditionalMediationAvailable)\
PublicKeyCredential.isConditionalMediationAvailable().then(function(a){if(a)go('conditional')})})();";

static PASSKEY_JS_HASH: LazyLock<String> =
    LazyLock::new(|| base64::engine::general_purpose::STANDARD.encode(sha256(PASSKEY_JS)));

/// [`csp`] plus the passkey script, on the sign-in and second-factor pages.
pub fn csp_passkey(b: &Brand, form_action: &[String]) -> String {
    format!("{}; script-src 'sha256-{}'", csp(b, form_action), *PASSKEY_JS_HASH)
}

/// The second-factor step's "trust this browser" choice, whatever the factor.
fn trust_choice(days: u32) -> String {
    if days == 0 {
        return String::new();
    }
    let n = if days == 1 { "1 day".to_string() } else { format!("{days} days") };
    format!(
        "<label class=\"check\"><input type=\"checkbox\" name=\"trust\" value=\"1\">Trust this browser for {n}</label>\
<p class=\"muted\">You won't be asked for a code on this browser until then. Leave it unticked on a shared computer.</p>"
    )
}

/// The hidden form the script fills and posts; its button stays hidden
/// without the script.
fn passkey_form(hidden: &str, action: &str, pk: &PasskeyUi, second: bool) -> String {
    let (mode, step, uv, label, err) = if second {
        ("2fa", "2fa", "preferred", "Use your passkey", "That passkey wasn't used. Try again, or use a code.")
    } else {
        (
            "signin",
            "passkey",
            "required",
            "Sign in with a passkey",
            "No passkey was used. Try again, or use your password.",
        )
    };
    format!(
        "<form method=\"post\" action=\"{}\" id=\"pk\" class=\"pk\" data-mode=\"{mode}\" data-challenge=\"{}\" data-rp=\"{}\" data-uv=\"{uv}\" data-allow=\"{}\">{hidden}\
<input type=\"hidden\" name=\"step\" value=\"{step}\"><input type=\"hidden\" name=\"action\" value=\"sign-in\">\
<input type=\"hidden\" name=\"passkey_id\"><input type=\"hidden\" name=\"client_data\"><input type=\"hidden\" name=\"auth_data\">\
<input type=\"hidden\" name=\"signature\"><input type=\"hidden\" name=\"user_handle\"><input type=\"hidden\" name=\"trust\">\
<button type=\"button\" id=\"pk-go\" class=\"{}\" hidden>{label}</button>\
<p class=\"err\" id=\"pk-err\" role=\"alert\" hidden>{err}</p></form>",
        e(action),
        e(pk.challenge),
        e(pk.rp_id),
        e(pk.allow),
        if second { "primary wide" } else { "wide" },
    )
}

pub fn login(br: &Brand, ctx: Option<&Ctx>, f: &LoginForm, csrf_only: &str) -> String {
    let mut b = String::new();
    match ctx {
        Some(c) => {
            b.push_str(&format!(
                "<h1>Sign in to {}</h1><p class=\"muted\">to continue to</p>{}",
                e(c.server_name),
                client_block(c)
            ));
        }
        None => match &f.step_up {
            Some(su) => {
                let whose = su.handle.map(|h| format!(" for <b>@{}</b>", e(h))).unwrap_or_default();
                b.push_str(&format!(
                    "<h1>Confirm it's you</h1><p class=\"muted\">Sign in again to add or remove sign-in methods{whose}. \
This browser hasn't signed in here yet, or it was more than 10 minutes ago.</p>"
                ));
            }
            None => b.push_str("<h1>Sign in</h1><p class=\"muted\">Manage the apps connected to your account.</p>"),
        },
    }
    if let Some(err) = f.error {
        b.push_str(&format!("<p class=\"err\" role=\"alert\">{}</p>", e(err)));
    }
    let hidden_fields = match ctx {
        Some(c) => hidden(c),
        None => format!(
            "<input type=\"hidden\" name=\"csrf\" value=\"{}\">{}",
            e(csrf_only),
            match &f.step_up {
                Some(su) => format!(
                    "<input type=\"hidden\" name=\"return\" value=\"{METHODS_RETURN}\">{}",
                    su.hint
                        .map(|d| format!("<input type=\"hidden\" name=\"login_hint\" value=\"{}\">", e(d)))
                        .unwrap_or_default()
                ),
                None => String::new(),
            }
        ),
    };
    let username = format!(
        "<input type=\"text\" class=\"u\" autocomplete=\"username\" value=\"{}\" readonly tabindex=\"-1\" aria-hidden=\"true\">",
        e(f.identifier)
    );
    let mut script = false;
    // a passkey-only second factor: the code form is only for recovery codes
    let mut recovery_only = false;
    if let Some(s) = &f.second {
        b.push_str(&format!("<p>Two-factor authentication is enabled for <b>{}</b>.</p>", e(f.identifier)));
        recovery_only = !s.totp && s.email_hint.is_none() && (s.passkey.is_some() || s.flagged);
        if s.flagged {
            b.push_str(
                "<p class=\"warn\">Your passkey was refused because it may have been copied. Sign in with a recovery code, then remove it on the Security page.</p>",
            );
        }
        if let Some(pk) = &s.passkey {
            script = true;
            b.push_str(&passkey_form(&hidden_fields, f.action, pk, true));
            b.push_str("<noscript><p class=\"muted\">Turn on JavaScript to use your passkey.</p></noscript>");
        }
    }
    b.push_str(&format!("<form method=\"post\" action=\"{}\">", e(f.action)));
    b.push_str(&hidden_fields);
    match &f.second {
        Some(Second { email_hint: Some(hint), trust_days, .. }) => b.push_str(&format!(
            "<p>We sent a sign-in code to <b>{}</b>.</p>{username}\
<label for=\"code\">Sign-in code from your email</label>\
<input type=\"text\" id=\"code\" name=\"code\" autocomplete=\"one-time-code\" autocapitalize=\"characters\" spellcheck=\"false\" required autofocus>\
{}<input type=\"hidden\" name=\"step\" value=\"2fa\">",
            e(hint),
            trust_choice(*trust_days)
        )),
        Some(s) if recovery_only => b.push_str(&format!(
            "{username}{}<input type=\"hidden\" name=\"step\" value=\"2fa\">\
<details class=\"alt-code\"{}><summary>Use a recovery code instead</summary>\
<label for=\"code\">Recovery code</label>\
<input type=\"text\" id=\"code\" name=\"code\" autocomplete=\"one-time-code\" autocapitalize=\"none\" spellcheck=\"false\" required>\
<div class=\"row\"><button type=\"submit\" class=\"primary\" name=\"action\" value=\"sign-in\">Sign in</button></div></details>",
            trust_choice(s.trust_days),
            if s.passkey.is_none() { " open" } else { "" }
        )),
        Some(s) => b.push_str(&format!(
            "{}{username}\
<label for=\"code\">Authenticator code (or a recovery code)</label>\
<input type=\"text\" id=\"code\" name=\"code\" inputmode=\"numeric\" autocomplete=\"one-time-code\" required{}>\
{}<input type=\"hidden\" name=\"step\" value=\"2fa\">",
            if s.passkey.is_some() { "<p class=\"muted or\">or enter a code</p>" } else { "" },
            if s.passkey.is_some() { "" } else { " autofocus" },
            trust_choice(s.trust_days)
        )),
        None => b.push_str(&format!(
            "<label for=\"identifier\">Handle or DID</label>\
<input type=\"text\" id=\"identifier\" name=\"identifier\" value=\"{}\" autocomplete=\"username{}\" autocapitalize=\"none\" spellcheck=\"false\" required{}>\
<label for=\"password\">Password</label>\
<input type=\"password\" id=\"password\" name=\"password\" autocomplete=\"current-password\" required{}>",
            e(f.identifier),
            if f.passkey.is_some() { " webauthn" } else { "" },
            if f.identifier.is_empty() { " autofocus" } else { "" },
            if f.identifier.is_empty() { "" } else { " autofocus" }
        )),
    }
    b.push_str("<div class=\"row\">");
    // Enter submits with the form's first submit button: Sign in, not Cancel
    if !recovery_only {
        b.push_str("<button type=\"submit\" class=\"primary\" name=\"action\" value=\"sign-in\">Sign in</button>");
    }
    if ctx.is_some() {
        b.push_str(
            "<button type=\"submit\" class=\"back\" name=\"action\" value=\"deny\" formnovalidate>Cancel</button>",
        );
    }
    b.push_str("</div></form>");
    if let (None, Some(pk)) = (&f.second, &f.passkey) {
        script = true;
        b.push_str("<div class=\"sep\" aria-hidden=\"true\"></div>");
        b.push_str(&passkey_form(&hidden_fields, f.action, pk, false));
    }
    if f.second.is_none() && !f.providers.is_empty() {
        if f.passkey.is_none() {
            b.push_str("<div class=\"sep\" aria-hidden=\"true\"></div>");
        }
        b.push_str(&provider_links(f.providers, "Continue with"));
    }
    if let (Some(c), None) = (ctx, &f.second) {
        b.push_str(&format!(
            "<p class=\"alt\">New to {}? <a href=\"{}\">Create an account</a></p>",
            e(c.server_name),
            e(&screen_url(c, "sign-up"))
        ));
    }
    page_with_script(br, "Sign in", &b, if script { PASSKEY_JS } else { "" })
}

fn screen_url(c: &Ctx, screen: &str) -> String {
    format!(
        "/oauth/authorize?client_id={}&request_uri={}&screen={screen}",
        super::util::encode_uri_component(c.client_id),
        super::util::encode_uri_component(c.request_uri)
    )
}

pub struct SignupForm<'a> {
    /// The first label.
    pub handle: &'a str,
    /// The one picked of `domains` (primary first).
    pub domain: &'a str,
    pub domains: &'a [String],
    pub email: &'a str,
    pub invite_code: &'a str,
    pub invite_required: bool,
    pub error: Option<&'a str>,
}

fn domain_affix(f: &SignupForm) -> String {
    if f.domains.len() < 2 {
        return format!("<span>.{}</span>", e(f.domain));
    }
    let mut s = String::from("<select name=\"domain\" aria-label=\"Domain\">");
    for d in f.domains {
        let sel = if d == f.domain { " selected" } else { "" };
        s.push_str(&format!("<option value=\"{}\"{sel}>.{}</option>", e(d), e(d)));
    }
    s.push_str("</select>");
    s
}

pub fn signup(br: &Brand, ctx: &Ctx, f: &SignupForm) -> String {
    let mut b = format!(
        "<h1>Create an account on {}</h1><p class=\"muted\">to continue to</p>{}",
        e(ctx.server_name),
        client_block(ctx)
    );
    if let Some(err) = f.error {
        b.push_str(&format!("<p class=\"err\" role=\"alert\">{}</p>", e(err)));
    }
    b.push_str("<form method=\"post\" action=\"/oauth/authorize/sign-up\">");
    b.push_str(&hidden(ctx));
    b.push_str(&format!(
        "<label for=\"handle\">Handle</label>\
<div class=\"affix\"><input type=\"text\" id=\"handle\" name=\"handle\" value=\"{}\" autocomplete=\"username\" autocapitalize=\"none\" spellcheck=\"false\" minlength=\"3\" maxlength=\"18\" required autofocus>{}</div>\
<p class=\"hint\">3 to 18 letters, digits or hyphens. You can switch to your own domain later.</p>\
<label for=\"email\">Email</label>\
<input type=\"email\" id=\"email\" name=\"email\" value=\"{}\" autocomplete=\"email\" required>\
<label for=\"password\">Password</label>\
<input type=\"password\" id=\"password\" name=\"password\" autocomplete=\"new-password\" minlength=\"8\" maxlength=\"256\" required>",
        e(f.handle),
        domain_affix(f),
        e(f.email)
    ));
    if f.invite_required {
        b.push_str(&format!(
            "<label for=\"invite\">Invite code</label>\
<input type=\"text\" id=\"invite\" name=\"invite_code\" value=\"{}\" autocapitalize=\"none\" spellcheck=\"false\" required>",
            e(f.invite_code)
        ));
    }
    b.push_str(
        "<div class=\"row\"><button type=\"submit\" class=\"primary\" name=\"action\" value=\"sign-up\">Create account</button>\
<button type=\"submit\" class=\"back\" name=\"action\" value=\"deny\" formnovalidate>Cancel</button></div></form>",
    );
    b.push_str(&format!(
        "<p class=\"alt\">Already have an account? <a href=\"{}\">Sign in</a></p>",
        e(&screen_url(ctx, "sign-in"))
    ));
    page(br, "Create an account", &b)
}

/// Account creation with a sign-in provider's identity: no password.
pub struct FederatedSignup<'a> {
    pub ticket: &'a str,
    pub csrf: &'a str,
    pub provider: &'a str,
    pub form: SignupForm<'a>,
    /// The provider vouched for the address it gave.
    pub email_verified: bool,
}

pub fn federated_signup(br: &Brand, ctx: Option<&Ctx>, f: &FederatedSignup) -> String {
    let s = &f.form;
    let mut b = match ctx {
        Some(c) => format!(
            "<h1>Create an account on {}</h1><p class=\"muted\">with {}, to continue to</p>{}",
            e(c.server_name),
            e(f.provider),
            client_block(c)
        ),
        None => format!("<h1>Create an account</h1><p class=\"muted\">with {}</p>", e(f.provider)),
    };
    b.push_str(&format!(
        "<p>No account here uses this {} sign-in yet. Pick a handle to create one, or <a href=\"/oauth/account?add=1\">sign in another way</a> and add it to your account.</p>",
        e(f.provider)
    ));
    if let Some(err) = s.error {
        b.push_str(&format!("<p class=\"err\" role=\"alert\">{}</p>", e(err)));
    }
    b.push_str(&format!(
        "<form method=\"post\" action=\"/oauth/federated/signup\"><input type=\"hidden\" name=\"ticket\" value=\"{}\"><input type=\"hidden\" name=\"csrf\" value=\"{}\">\
<label for=\"handle\">Handle</label>\
<div class=\"affix\"><input type=\"text\" id=\"handle\" name=\"handle\" value=\"{}\" autocomplete=\"username\" autocapitalize=\"none\" spellcheck=\"false\" minlength=\"3\" maxlength=\"18\" required autofocus>{}</div>\
<p class=\"hint\">3 to 18 letters, digits or hyphens. You can switch to your own domain later.</p>\
<label for=\"email\">Email</label>\
<input type=\"email\" id=\"email\" name=\"email\" value=\"{}\" autocomplete=\"email\" required>\
<p class=\"hint\">{}</p>",
        e(f.ticket),
        e(f.csrf),
        e(s.handle),
        domain_affix(s),
        e(s.email),
        if f.email_verified {
            "Already confirmed by your sign-in. Change it and you'll confirm the new one by email."
        } else {
            "Required: the server sends account and security mail here."
        }
    ));
    if s.invite_required {
        b.push_str(&format!(
            "<label for=\"invite\">Invite code</label>\
<input type=\"text\" id=\"invite\" name=\"invite_code\" value=\"{}\" autocapitalize=\"none\" spellcheck=\"false\" required>",
            e(s.invite_code)
        ));
    }
    b.push_str(
        "<div class=\"row\"><button type=\"submit\" class=\"primary\" name=\"action\" value=\"sign-up\">Create account</button>\
<button type=\"submit\" class=\"back\" name=\"action\" value=\"deny\" formnovalidate>Cancel</button></div></form>",
    );
    page(br, "Create an account", &b)
}

pub fn chooser(br: &Brand, ctx: &Ctx, accounts: &[(String, String)]) -> String {
    let mut b = format!("<h1>Choose an account</h1><p class=\"muted\">to continue to</p>{}", client_block(ctx));
    for (did, handle) in accounts {
        b.push_str(&format!(
            "<div class=\"acct\"><div class=\"who\"><b>@{}</b><div class=\"muted\">{}</div></div>\
<form method=\"post\" action=\"/oauth/authorize/select\">{}<input type=\"hidden\" name=\"did\" value=\"{}\"><button type=\"submit\" class=\"primary\">Continue</button></form></div>",
            e(handle),
            e(did),
            hidden(ctx),
            e(did)
        ));
    }
    b.push_str(&format!(
        "<div class=\"row\"><form method=\"post\" action=\"/oauth/authorize/select\">{}<input type=\"hidden\" name=\"did\" value=\"\"><button type=\"submit\">Use another account</button></form>\
<form method=\"post\" action=\"/oauth/authorize/consent\">{}<button type=\"submit\" name=\"action\" value=\"deny\">Cancel</button></form></div>",
        hidden(ctx),
        hidden(ctx)
    ));
    page(br, "Choose an account", &b)
}

fn lines_html(lines: &[Line]) -> String {
    if lines.is_empty() {
        return String::new();
    }
    let mut b = String::from("<ul class=\"dl\">");
    for l in lines {
        b.push_str("<li>");
        if !l.verb.is_empty() {
            b.push_str(&format!("<span class=\"v\">{}</span>", e(&l.verb)));
        }
        if !l.objects.is_empty() {
            b.push_str(&format!("<span class=\"o\">{}</span>", e(&l.objects)));
        }
        if !l.code.is_empty() {
            b.push_str(&format!("<code>{}</code>", e(&l.code)));
        }
        b.push_str("</li>");
    }
    b.push_str("</ul>");
    b
}

/// One row: its checkbox (a hidden field when it has none), label, tier
/// tag, summary and set chips. A row that isn't account control opens to
/// its lines; an account-control row shows everything at once.
fn row_html(i: usize, r: &Row) -> String {
    let id = format!("r{i}");
    let grants = e(&r.grants.join(" "));
    let described = if r.summary.is_empty() { String::new() } else { format!(" aria-describedby=\"{id}s\"") };
    let input = match r.fixed {
        true => format!("<input type=\"hidden\" name=\"row\" value=\"{grants}\"><span class=\"cb\" aria-hidden=\"true\"></span>"),
        false => format!(
            "<input type=\"checkbox\" id=\"{id}\" name=\"row\" value=\"{grants}\"{} aria-labelledby=\"{id}l\"{described}>",
            if r.checked { " checked" } else { "" }
        ),
    };
    let tag = match (r.key.as_str(), r.tier.tag()) {
        ("identity", _) | (_, None) => String::new(),
        (_, Some(t)) => format!("<span class=\"tag {}\">{t}</span>", r.tier.class()),
    };
    let summary = if r.summary.is_empty() {
        String::new()
    } else {
        format!("<span class=\"rs\" id=\"{id}s\">{}</span>", e(&r.summary))
    };
    let head = format!("<span class=\"rl\" id=\"{id}l\">{}</span>{tag}{summary}", e(&r.label));
    let chips: String = r
        .sets
        .iter()
        .filter_map(|s| s.title.as_ref())
        .map(|t| format!("<span class=\"src\">{}</span>", e(t)))
        .collect();
    let mut inner = String::new();
    for s in &r.sets {
        if let Some(d) = &s.detail {
            inner.push_str(&format!("<span class=\"quote\">{}</span>", e(d)));
        }
        inner.push_str(&format!("<span class=\"rn\">{}</span>", e(&rollup::set_note(s))));
    }
    inner.push_str(&lines_html(&r.lines));
    if !r.not_in_set.is_empty() {
        inner.push_str("<span class=\"rn\"><b>Not in the set</b></span>");
        inner.push_str(&lines_html(&r.not_in_set));
    }
    if !r.includes.is_empty() {
        inner.push_str(&format!("<span class=\"rn\">Also covers: {}</span>", e(&r.includes.join(" · "))));
    }
    let warns: String = r.warnings.iter().map(|w| format!("<span class=\"warn\">{}</span>", e(w))).collect();
    let openable = r.tier != Tier::Control && !inner.is_empty();
    let body = match openable {
        true => format!("<details class=\"r\"><summary>{head}{chips}</summary>{inner}</details>{warns}"),
        false => format!("{head}{chips}{inner}{warns}"),
    };
    format!("<li>{input}<div class=\"rb\">{body}</div></li>")
}

/// One checkbox per row, ticked unless nothing on screen describes it,
/// posted as repeated `row` fields so the page needs no script. A row's
/// value is its grant keys ([`rollup::grant_key`]); a row without a
/// checkbox posts them in a hidden field. The requested scopes, grouped
/// by row, are at the bottom.
pub fn consent(br: &Brand, ctx: &Ctx, did: &str, handle: &str, rows: &[Row]) -> String {
    let mut b = format!(
        "<h1>Authorize access</h1><p class=\"muted\">Signed in as <b>@{}</b></p>{}\
<form method=\"post\" action=\"/oauth/authorize/consent\">{}<input type=\"hidden\" name=\"did\" value=\"{}\">\
<p class=\"lead\">It will be able to:</p><ul class=\"rows\">",
        e(handle),
        client_block(ctx),
        hidden(ctx),
        e(did)
    );
    for (i, r) in rows.iter().enumerate() {
        b.push_str(&row_html(i, r));
    }
    let n: usize = rows.iter().map(|r| r.scopes.len()).sum();
    b.push_str(&format!("</ul><details class=\"raw\"><summary>Requested scopes ({n})</summary><ul class=\"raw\">"));
    for (label, scopes, notes) in rollup::raw_groups(rows) {
        b.push_str(&format!("<li class=\"gh\">{}</li>", e(&label)));
        for s in scopes {
            b.push_str(&format!("<li>{}</li>", e(&s)));
        }
        for n in notes {
            b.push_str(&format!("<li class=\"ig\">{}</li>", e(&n)));
        }
    }
    b.push_str(
        "</ul></details><p class=\"muted\">You can revoke this under <b>Connected apps</b> in your account.</p>\
<div class=\"row\"><button type=\"submit\" name=\"action\" value=\"deny\">Deny</button><button type=\"submit\" class=\"primary\" name=\"action\" value=\"allow\" autofocus>Allow</button></div></form>",
    );
    page(br, "Authorize access", &b)
}

pub fn error(br: &Brand, title: &str, msg: &str) -> String {
    page(br, title, &format!("<h1>{}</h1><p>{}</p>", e(title), e(msg)))
}

pub struct SessionRow {
    pub id: String,
    pub client_id: String,
    pub scope: String,
    pub created_at: String,
    pub updated_at: String,
}

/// One signed-in account on `/oauth/account`.
pub struct AccountRow {
    pub did: String,
    pub handle: String,
    pub sessions: Vec<SessionRow>,
    /// None when the server offers no sign-in providers and the account has
    /// no identity.
    pub methods: Option<Methods>,
}

pub struct Methods {
    pub identities: Vec<IdentityRow>,
    pub add: Vec<ProviderLink>,
    /// Signed in recently enough on this browser to change them.
    pub fresh: bool,
}

pub struct IdentityRow {
    /// `fed:…`
    pub r: String,
    /// The provider's name, or its issuer once the provider is gone.
    pub label: String,
    pub display: Option<String>,
    pub dormant: bool,
}

/// `anchor`: the block a step-up sign-in lands on.
fn methods_block(csrf: &str, did: &str, m: &Methods, anchor: bool) -> String {
    let mut b = format!("<h2{}>Sign-in methods</h2>", if anchor { " id=\"sign-in-methods\"" } else { "" });
    if m.identities.is_empty() {
        b.push_str("<p class=\"muted\">Only your password and passkeys.</p>");
    }
    for i in &m.identities {
        let sub = match (&i.display, i.dormant) {
            (_, true) => "no longer offered here".to_string(),
            (Some(d), false) => d.clone(),
            (None, false) => String::new(),
        };
        // without a fresh sign-in, Remove would only be refused
        let remove = if m.fresh {
            format!(
                "<form method=\"post\" action=\"/oauth/account/unlink\"><input type=\"hidden\" name=\"csrf\" value=\"{}\"><input type=\"hidden\" name=\"did\" value=\"{}\"><input type=\"hidden\" name=\"ref\" value=\"{}\"><button type=\"submit\" class=\"danger\">Remove</button></form>",
                e(csrf),
                e(did),
                e(&i.r)
            )
        } else {
            String::new()
        };
        b.push_str(&format!(
            "<div class=\"acct\"><div class=\"who\"><b>{}</b><div class=\"muted\">{}</div></div>{remove}</div>",
            e(&i.label),
            e(&sub)
        ));
    }
    if m.fresh {
        b.push_str(&provider_links(&m.add, "Add"));
    } else if !m.add.is_empty() || !m.identities.is_empty() {
        b.push_str(&format!(
            "<p class=\"muted\">To add or remove one, sign in again on this browser. Changing these needs a sign-in here in the last 10 minutes.</p>\
<div class=\"fed\"><a class=\"fedbtn\" href=\"/oauth/account?login_hint={}&amp;return={METHODS_RETURN}\"><span>Sign in again to change these</span></a></div>",
            e(&super::util::encode_uri_component(did))
        ));
    }
    b
}

/// `notice`: (message, an error). `anchor`: the account whose sign-in
/// methods a step-up sign-in lands on (else the first shown).
pub fn account_page(
    br: &Brand,
    csrf: &str,
    accounts: &[AccountRow],
    notice: Option<(&str, bool)>,
    anchor: Option<&str>,
) -> String {
    let anchor = anchor.or_else(|| accounts.iter().find(|a| a.methods.is_some()).map(|a| a.did.as_str()));
    let mut b = String::from("<h1>Connected apps</h1><p class=\"muted\">Apps you have authorized with OAuth. Revoking access signs the app out immediately.</p>");
    if let Some((m, error)) = notice {
        b.push_str(&format!("<p class=\"{}\" role=\"status\">{}</p>", if error { "err" } else { "note" }, e(m)));
    }
    for a in accounts {
        let (did, handle, sessions) = (&a.did, &a.handle, &a.sessions);
        b.push_str(&format!(
            "<div class=\"acct\"><div class=\"who\"><b>@{}</b><div class=\"muted\">{}</div></div>\
<form method=\"post\" action=\"/oauth/account/sign-out\"><input type=\"hidden\" name=\"csrf\" value=\"{}\"><input type=\"hidden\" name=\"did\" value=\"{}\"><button type=\"submit\">Sign out</button></form></div>",
            e(handle),
            e(did),
            e(csrf),
            e(did)
        ));
        if sessions.is_empty() {
            b.push_str("<p class=\"muted\">No connected apps.</p>");
        } else {
            b.push_str("<table>");
            for s in sessions {
                b.push_str(&format!(
                    "<tr><td><div class=\"client\">{}</div><div class=\"muted\">{}</div><div class=\"muted\">authorized {} &middot; last used {}</div></td>\
<td><form method=\"post\" action=\"/oauth/account/revoke\"><input type=\"hidden\" name=\"csrf\" value=\"{}\"><input type=\"hidden\" name=\"did\" value=\"{}\"><input type=\"hidden\" name=\"session\" value=\"{}\"><button type=\"submit\" class=\"danger\">Revoke</button></form></td></tr>",
                    e(&s.client_id),
                    e(&s.scope),
                    e(&s.created_at),
                    e(&s.updated_at),
                    e(csrf),
                    e(did),
                    e(&s.id)
                ));
            }
            b.push_str("</table>");
        }
        if let Some(m) = &a.methods {
            b.push_str(&methods_block(csrf, did, m, anchor == Some(did.as_str())));
        }
    }
    b.push_str("<div class=\"row\"><a href=\"/oauth/account?add=1\">Add another account</a></div><footer class=\"muted\"><a href=\"/account\">Open account settings</a></footer>");
    page(br, "Connected apps", &b)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::rollup::{Request, SpaceNames};
    use super::*;
    use crate::oauth::scopes::IncludeScope;
    use serde_json::{json, Value as J};

    const BOARDS: &str = "space:dev.example.boards.board?authority=*&collection=dev.example.boards.post&collection=dev.example.boards.comment&collection=dev.example.boards.vote&action=read&action=create&action=update&action=delete";
    const BOARDS_SET: &str = "include:dev.example.boards.basePermissions?aud=did:web:boards.example%23boards";

    fn boards_names(name: &str) -> SpaceNames {
        let decl = crate::lexicon::SpaceDecl {
            name: name.into(),
            name_lang: vec![],
            description: None,
            key: None,
            collections: ["post", "comment", "vote"].map(|c| format!("dev.example.boards.{c}")).to_vec(),
        };
        SpaceNames { decls: [("dev.example.boards.board".to_string(), decl)].into(), handles: Default::default() }
    }

    fn boards_set(title: &str, detail: &str) -> Vec<(IncludeScope, Result<J, String>)> {
        let set = json!({
            "type": "permission-set",
            "title": title,
            "detail": detail,
            "permissions": [
                {"type": "permission", "resource": "repo", "collection": ["dev.example.boards.profile"]},
                {"type": "permission", "resource": "rpc", "lxm": ["dev.example.boards.getBoard", "dev.example.boards.listPosts"], "inheritAud": true},
                {"type": "permission", "resource": "space", "spaceType": "dev.example.boards.board", "action": ["read", "create", "update", "delete"]},
            ],
        });
        vec![(IncludeScope::parse(BOARDS_SET).unwrap(), Ok(set))]
    }

    fn page_for(scope: &str, sets: &[(IncludeScope, Result<J, String>)], names: Option<&SpaceNames>) -> String {
        let client_id = "https://app.example/client-metadata.json";
        let ctx = Ctx {
            request_uri: "urn:ietf:params:oauth:request_uri:req-x",
            csrf: "c",
            client_id,
            loopback: false,
            server_name: "vlpds",
        };
        let rows = rollup::rows(&Request { scope, sets, client_id, loopback: false, names });
        consent(&Brand::default(), &ctx, "did:plc:abc", "alice.test", &rows)
    }

    fn posted(html: &str) -> Vec<String> {
        html.split("name=\"row\" value=\"").skip(1).map(|r| r[..r.find('"').unwrap()].replace("&amp;", "&")).collect()
    }

    /// `VLPDS_CONSENT_DUMP=<dir>` writes the pages, for screenshots.
    fn dump(name: &str, html: &str) {
        if let Ok(dir) = std::env::var("VLPDS_CONSENT_DUMP") {
            std::fs::write(format!("{dir}/{name}.html"), html).unwrap();
        }
    }

    #[test]
    fn rows_post_their_grant_keys_and_identity_is_hidden() {
        let html = page_for("atproto account:email repo:app.bsky.feed.post blob:image/*", &[], None);
        assert!(html.contains("<input type=\"hidden\" name=\"row\" value=\"identity\"><span class=\"cb\""), "{html}");
        let mut p = posted(&html);
        p.sort();
        assert_eq!(p, ["email", "identity", "ns:app.bsky", "uploads"]);
        assert_eq!(html.matches("type=\"checkbox\"").count(), 3, "{html}");
        let bsky = "<span class=\"rl\" id=\"r2l\">Bluesky</span><span class=\"tag t2\">As you</span><span class=\"rs\" id=\"r2s\">Change posts</span>";
        assert!(html.contains(bsky), "{html}");
        assert!(html.contains("id=\"r2\" name=\"row\" value=\"ns:app.bsky\" checked aria-labelledby=\"r2l\" aria-describedby=\"r2s\">"), "{html}");
        assert!(!html.contains("<script"), "{html}");
        assert!(
            html.contains(
                "<div class=\"client\"><b>app.example</b><code>https://app.example/client-metadata.json</code></div>"
            ),
            "{html}"
        );
    }

    #[test]
    fn account_control_rows_show_in_full() {
        let html = page_for("atproto identity:handle transition:generic transition:chat.bsky", &[], None);
        dump("control", &html);
        assert!(!html.contains("<details class=\"r\">"), "nothing to open: {html}");
        assert_eq!(html.matches("<span class=\"tag t1\">Account control</span>").count(), 3, "{html}");
        assert!(html.contains("Read and send Bluesky private messages · Needs Full access"), "{html}");
    }

    #[test]
    fn warnings_stay_on_their_row() {
        let names = SpaceNames::default();
        let html =
            page_for("atproto space:*?authority=*&action=read space:*?authority=*&action=read_self", &[], Some(&names));
        assert!(html.contains("asking to read every space on the network"), "{html}");
        assert_eq!(html.matches("class=\"warn\"").count(), 1, "{html}");
        assert!(html.contains(">Every space</span><span class=\"tag t1\">"), "{html}");
    }

    /// The account page's owner grant manages only the user's own spaces,
    /// and the consent says so rather than "manage in every space".
    #[test]
    fn self_bound_management_says_whose() {
        let names = SpaceNames::default();
        let html = page_for(
            "atproto space:*?authority=*&action=read_self space:*?action=read_self&manage=update&manage=delete",
            &[],
            Some(&names),
        );
        assert!(
            html.contains(
                "All spaces on your account: read your own space repos and change and delete spaces and their members"
            ),
            "{html}"
        );
        assert!(!html.contains("manage in every space"), "{html}");
    }

    #[test]
    fn a_space_grant_lists_its_type_and_collections() {
        let names = boards_names("Boards");
        let html = page_for(&format!("atproto {BOARDS}"), &[], Some(&names));
        dump("boards", &html);
        assert!(html.contains("Boards spaces: read what members share with you and write records in dev.example.boards.post, dev.example.boards.comment and dev.example.boards.vote"), "{html}");
        assert!(html.contains(">Boards spaces</span>"), "{html}");
        assert!(!html.contains("class=\"warn\""), "{html}");
    }

    #[test]
    fn a_permission_set_is_one_row_with_its_title_as_a_chip() {
        let names = boards_names("Boards");
        let html = page_for(
            &format!("atproto {BOARDS_SET}"),
            &boards_set("Boards", "Post, comment and vote on boards"),
            Some(&names),
        );
        dump("include", &html);
        assert_eq!(posted(&html), ["identity", "set:dev.example.boards.basePermissions"]);
        assert!(html.contains("<span class=\"src\">Boards</span>"), "{html}");
        assert!(html.contains("<span class=\"quote\">Post, comment and vote on boards</span>"), "{html}");
        assert!(html.contains(". Can add dev.example.boards permissions later.</span>"), "{html}");
        assert_eq!(html.matches("type=\"checkbox\"").count(), 1, "the set is granted whole: {html}");
    }

    #[test]
    fn hostile_names_are_escaped() {
        let x = "<img src=x onerror=alert(1)>";
        let names = boards_names(x);
        let html = page_for(&format!("atproto {BOARDS} {BOARDS_SET}"), &boards_set(x, x), Some(&names));
        assert!(!html.contains("<img"), "{html}");
        assert!(html.contains("&lt;img src=x onerror=alert(1)&gt; spaces: read"), "{html}");
        let row = Row {
            key: "ns:a.<zb>".into(),
            grants: vec!["\"><zg>".into()],
            label: "<zi>t</zi>".into(),
            tier: Tier::AsYou,
            summary: "<zs>x</zs>".into(),
            chip: String::new(),
            lines: vec![Line { verb: "<zu>do</zu>".into(), objects: "<zo>".into(), code: "a.<zb>.c".into() }],
            not_in_set: vec![],
            sets: vec![rollup::SetInfo {
                nsid: "a.b.c".into(),
                title: Some("<zt>".into()),
                detail: Some("<zp>d".into()),
                publisher: "<zw>".into(),
                group: "a.b".into(),
                ignored: 0,
                unavailable: false,
            }],
            includes: vec![],
            scopes: vec!["repo:\"><zb>x".into()],
            fixed: false,
            checked: true,
            warnings: vec!["<zx>".into()],
        };
        let ctx = Ctx { request_uri: "r", csrf: "c", client_id: "x", loopback: true, server_name: "s" };
        let html = consent(&Brand::default(), &ctx, "d", "h", &[row]);
        for bad in ["<zb>", "<zi>", "<zu>", "<zs>", "<zp>d", "<zt>", "<zw>", "<zx>", "<zo>", "<zg>"] {
            assert!(!html.contains(bad), "{bad}: {html}");
        }
        assert!(html.contains("value=\"&quot;&gt;&lt;zg&gt;\""), "{html}");
    }

    #[test]
    fn the_raw_scopes_are_at_the_bottom_grouped_by_row() {
        let scope = format!("atproto {BOARDS} blob:image/*");
        let html = page_for(&scope, &[], Some(&boards_names("Boards")));
        let raw = &html[html.find("<details class=\"raw\">").unwrap()..];
        assert!(raw.starts_with("<details class=\"raw\"><summary>Requested scopes (3)</summary>"), "{raw}");
        assert!(raw.contains("<li class=\"gh\">Who you are</li><li>atproto</li>"), "{raw}");
        assert!(raw.contains(&format!("<li class=\"gh\">Boards spaces</li><li>{}</li>", e(BOARDS))), "{raw}");
        assert!(!raw.contains("name=\"row\""), "{raw}");
        assert!(raw.find("</details>").unwrap() < raw.find("Allow</button>").unwrap(), "{raw}");
    }

    #[test]
    fn signup_offers_a_domain_select_only_with_several() {
        let ctx = Ctx { request_uri: "r", csrf: "c", client_id: "x", loopback: true, server_name: "s" };
        let one = ["pds.test".to_string()];
        let f = |domain, domains| SignupForm {
            handle: "al",
            domain,
            domains,
            email: "",
            invite_code: "",
            invite_required: false,
            error: None,
        };
        let html = signup(&Brand::default(), &ctx, &f("pds.test", &one));
        assert!(html.contains("<span>.pds.test</span>") && !html.contains("<select"), "{html}");
        let two = ["pds.test".to_string(), "group-a.test".to_string()];
        let html = signup(&Brand::default(), &ctx, &f("group-a.test", &two));
        assert!(html.contains("<select name=\"domain\""), "{html}");
        assert!(html.contains("<option value=\"group-a.test\" selected>.group-a.test</option>"), "{html}");
        assert!(html.contains("<option value=\"pds.test\">.pds.test</option>"), "{html}");
    }

    fn branded() -> Brand {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/brand");
        Brand::new(crate::brand::tests::sample_parts(&root), "https://pds.tidepool.example").unwrap()
    }

    /// Everything from the card on, links excepted.
    fn card(html: &str) -> &str {
        let at = html.find("<div class=\"card\">").unwrap();
        let rest = &html[at..];
        &rest[..rest.find("<nav class=\"bl\"").or_else(|| rest.find("</main>")).unwrap()]
    }

    fn styles(html: &str) -> Vec<&str> {
        html.split("<style>").skip(1).map(|s| &s[..s.find("</style>").unwrap()]).collect()
    }

    fn sha(s: &str) -> String {
        base64::engine::general_purpose::STANDARD.encode(sha256(s))
    }

    #[test]
    fn unbranded_pages_are_vlpds() {
        let html = page_for("atproto repo:app.bsky.feed.post", &[], None);
        assert!(html.contains(&format!("<main><div class=\"brand\">{MARK}vlpds<span>account security</span>{SOURCE_LINK}</div><div class=\"card\">")), "{html}");
        assert!(html.ends_with("</form></div></main></body></html>"), "{html}");
        assert!(!html.contains("/brand/") && !html.contains("<nav") && !html.contains("rel=\"icon\""), "{html}");
        assert_eq!(styles(&html), [STYLE]);
        assert_eq!(
            csp(&Brand::default(), &[]),
            format!("default-src 'none'; style-src 'sha256-{}'; font-src 'self'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'", sha(STYLE))
        );
    }

    #[test]
    fn branding_changes_only_the_header_links_and_accent() {
        let br = branded();
        let scope = "atproto account:email repo:app.bsky.feed.post blob:image/*";
        let ctx = Ctx {
            request_uri: "urn:x",
            csrf: "c",
            client_id: "https://app.example/client-metadata.json",
            loopback: false,
            server_name: "pds.tidepool.example",
        };
        let rows = rollup::rows(&Request { scope, sets: &[], client_id: ctx.client_id, loopback: false, names: None });
        let plain = consent(&Brand::default(), &ctx, "did:plc:abc", "alice.test", &rows);
        let html = consent(&br, &ctx, "did:plc:abc", "alice.test", &rows);
        assert_eq!(card(&html), card(&plain), "the client block, rows and buttons are untouched");
        assert!(card(&html).contains(
            "<div class=\"client\"><b>app.example</b><code>https://app.example/client-metadata.json</code></div>"
        ));
        assert!(card(&html).contains("<button type=\"submit\" name=\"action\" value=\"deny\">Deny</button><button type=\"submit\" class=\"primary\" name=\"action\" value=\"allow\" autofocus>Allow</button>"));
        let logo = br.logo_src().unwrap();
        assert!(html.contains(&format!("<div class=\"brand\"><img src=\"{logo}\" alt=\"\" height=\"24\">Tidepool Social<span>account security</span>")), "{html}");
        assert!(!html.contains(MARK), "{html}");
        assert!(html.contains("<nav class=\"bl\" aria-label=\"Tidepool Social\"><a href=\"https://tidepool.example\">Home</a><a href=\"https://tidepool.example/terms\">Terms of Service</a><a href=\"https://tidepool.example/privacy\">Privacy Policy</a><a href=\"mailto:help@tidepool.example\">Support</a></nav></main>"), "{html}");
        assert!(html.contains(&format!("<link rel=\"icon\" href=\"{}\">", br.favicon_src().unwrap())), "{html}");
        // every <style> is allowed by its hash, and nothing else
        let st = styles(&html);
        assert_eq!(st.len(), 2);
        let policy = csp(&br, &[]);
        let style_src = policy.split("; ").find(|d| d.starts_with("style-src")).unwrap();
        assert_eq!(style_src, format!("style-src 'sha256-{}' 'sha256-{}'", sha(st[0]), sha(st[1])));
        assert!(!policy.contains("unsafe"), "{policy}");
        assert!(st[1].contains("--accent:#c2410c;--accent-ink:#ffffff") && !st[1].contains("--danger"), "{}", st[1]);
    }

    #[test]
    fn a_logo_without_a_name_is_labelled_by_the_host() {
        let br = Brand::new(
            crate::brand::Parts { logo: Some(crate::brand::tests::png(4)), ..Default::default() },
            "https://pds.example.com",
        )
        .unwrap();
        let html = error(&br, "Oops", "x");
        assert!(html.contains("alt=\"pds.example.com\" height=\"24\"><span>account security</span>"), "{html}");
        // a color alone keeps vlpds's header
        let br = Brand::new(
            crate::brand::Parts { primary_color: Some("#123456".into()), ..Default::default() },
            "https://x.example",
        )
        .unwrap();
        let html = error(&br, "Oops", "x");
        assert!(html.contains(&format!("<div class=\"brand\">{MARK}vlpds")) && !html.contains("<nav"), "{html}");
        assert_eq!(styles(&html).len(), 2);
    }

    #[test]
    fn hostile_brand_names_are_escaped() {
        let br = Brand::new(
            crate::brand::Parts {
                name: Some("<img src=x onerror=alert(1)>".into()),
                home_url: Some("https://h.example/?a=1&b=2".into()),
                ..Default::default()
            },
            "https://x.example",
        )
        .unwrap();
        let html = error(&br, "Oops", "x");
        assert!(!html.contains("<img"), "{html}");
        assert!(
            html.contains("&lt;img src=x onerror=alert(1)&gt;<span>")
                && html.contains("href=\"https://h.example/?a=1&amp;b=2\""),
            "{html}"
        );
    }

    /// The branded pages `brand::tests::dump_brand` writes for `consent-shots`.
    pub(crate) fn dump_branded(br: &Brand, dir: &std::path::Path) {
        let client_id = "https://app.example/client-metadata.json";
        let ctx =
            Ctx { request_uri: "urn:x", csrf: "c", client_id, loopback: false, server_name: "pds.tidepool.example" };
        let scope = "atproto account:email repo:app.bsky.feed.post repo:app.bsky.feed.like blob:image/*";
        let rows = rollup::rows(&Request { scope, sets: &[], client_id, loopback: false, names: None });
        let pages = [
            ("consent", consent(br, &ctx, "did:plc:abc", "alice.tidepool.example", &rows)),
            (
                "sign-in",
                login(
                    br,
                    Some(&ctx),
                    &LoginForm {
                        action: "/oauth/authorize/sign-in",
                        identifier: "",
                        error: None,
                        second: None,
                        passkey: None,
                        providers: &[],
                        step_up: None,
                    },
                    "",
                ),
            ),
        ];
        for (name, html) in pages {
            std::fs::write(dir.join(format!("{name}.html")), html).unwrap();
        }
    }
}
