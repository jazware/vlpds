//! Server-rendered pages for the authorization flow and session management.
//! No external assets: one inline stylesheet allowed by hash in the
//! Content-Security-Policy. Two fixed scripts, each allowed by hash and
//! only on its pages: the auto-submit of the `response_mode=form_post`
//! page, and the passkey ceremony on the sign-in pages ([`PASSKEY_JS`]).

use super::scopes::{IncludeScope, Permission, SpacePermission};
use super::util::{html_escape as e, sha256};
use base64::Engine;
use serde_json::Value as J;
use std::sync::LazyLock;

const STYLE: &str = r#"
.u{position:absolute;left:-9999px;width:1px;height:1px;overflow:hidden}
@font-face{font-family:"Schibsted Grotesk";src:url(/fonts/schibsted-grotesk.woff2) format("woff2");font-weight:400 900;font-display:swap}
@font-face{font-family:"JetBrains Mono";src:url(/fonts/jetbrains-mono.woff2) format("woff2");font-weight:100 800;font-display:swap}
:root{--paper:#edefea;--sheet:#f8f9f6;--ink:#18222d;--ink2:#4d5966;--rule:#c9cfc8;--accent:#17705f;--accent-ink:#fff;--amber:#b9770e;--danger:#a93a24;--focus:#3561c9;color-scheme:light}
@media (prefers-color-scheme:dark){:root{--paper:#121820;--sheet:#19212b;--ink:#dce4e3;--ink2:#93a0a8;--rule:#2a3542;--accent:#4fbf9f;--accent-ink:#0c1a16;--amber:#e3a43a;--danger:#f0806a;--focus:#8fb0ff;color-scheme:dark}}
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
.client{font-family:"JetBrains Mono",ui-monospace,Menlo,monospace;font-size:12.5px;overflow-wrap:anywhere;background:var(--paper);border:1px solid var(--rule);border-left:3px solid var(--accent);border-radius:4px;padding:9px 11px;margin:10px 0}
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
fieldset{border:0;margin:14px 0 0;padding:0;min-width:0}
legend{padding:0;font-weight:600}
ul.scopes,ul.ents,ul.ns{list-style:none;padding:0;margin:0}
ul.scopes{margin:8px 0 12px}
ul.scopes>li{border-top:1px solid var(--rule)}
li.ent{display:flex;gap:11px;align-items:flex-start;padding:10px 0}
li.ent>input[type=checkbox]{flex:none;width:17px;height:17px;margin:3px 0 0;accent-color:var(--accent)}
li.ent>div{min-width:0;flex:1}
li.ent label,li.ent .et{display:inline;margin:0;font-size:15px;font-weight:600;cursor:pointer;overflow-wrap:anywhere}
li.ent .et{cursor:default;font-size:14px}
li.ent input:disabled+div label{cursor:default}
details.grp>summary{display:block;cursor:pointer;padding:10px 0 10px 24px;position:relative;list-style:none}
details.grp>summary::-webkit-details-marker{display:none}
details.grp>summary:before{content:"";position:absolute;left:5px;top:17px;width:7px;height:7px;border:solid var(--ink2);border-width:0 2px 2px 0;transform:rotate(-45deg)}
details.grp[open]>summary:before{transform:rotate(45deg);top:14px}
details.grp>summary:hover .gl{color:var(--accent)}
summary:focus-visible{outline:2px solid var(--focus);outline-offset:2px;border-radius:3px}
.gl{font-weight:650;overflow-wrap:anywhere}
code.gp,ul.ns code,ul.raw code{font:12px/1.5 "JetBrains Mono",ui-monospace,Menlo,monospace;overflow-wrap:anywhere}
ul.ns code{overflow-wrap:break-word}
code.gp{color:var(--ink2);margin-left:6px}
.gl code.gp{margin-left:0;color:inherit;font-size:13px}
.gs{display:block;color:var(--ink2);font-size:13.5px;margin-top:1px}
summary .warn{display:block}
ul.ents{margin:0 0 6px 24px}
ul.ents>li{border-top:1px dashed var(--rule)}
ul.ents>li.ent{padding:8px 0}
li.sg>.sgh{padding:9px 0 2px;font-size:13.5px}
li.sg>.sgh .gl{font-weight:600}
li.sg>.sgh .gs{margin:0}
li.sg>ul.ents{margin:0 0 4px 12px}
li.sg>ul.ents>li{border-top:0}
ul.ns{margin-top:3px;color:var(--ink2);font-size:12.5px}
ul.ns li{padding:1px 0}
ul.ns span{overflow-wrap:break-word}
ul.ns code{color:var(--ink);margin-right:2px}
ul.scopes.inner{margin:8px 0 2px}
ul.scopes.inner>li{border-top-style:dashed}
details.raw{margin:12px 0 0}
details.raw summary{cursor:pointer;color:var(--accent);font-size:13.5px}
ul.raw{list-style:none;margin:6px 0 0;padding:8px 10px;background:var(--paper);border:1px solid var(--rule);border-radius:4px;color:var(--ink2)}
.req{display:inline-block;margin-left:7px;padding:0 5px;border:1px solid var(--rule);border-radius:3px;color:var(--ink2);font-size:11.5px;font-weight:600;vertical-align:1px}
.sd{margin:4px 0 0;color:var(--ink2);font-size:13.5px}
.warn{margin:6px 0 0;padding:6px 9px;border-left:3px solid var(--amber);background:var(--paper);font-size:13.5px;font-weight:400;color:var(--ink)}
label.check{display:flex;gap:8px;align-items:center;font-weight:500}
.wide{width:100%}
form.pk{margin:14px 0 4px}
.sep{border-top:1px solid var(--rule);margin:18px 0 0}
.or{text-align:center;margin:14px 0 0}
details.alt-code{margin:16px 0 0}
details.alt-code summary{cursor:pointer;color:var(--accent);font-size:14px}
"#;

static STYLE_HASH: LazyLock<String> = LazyLock::new(|| base64::engine::general_purpose::STANDARD.encode(sha256(STYLE)));

/// `form_action`: extra sources. Browsers apply form-action to the redirect
/// that follows a form post, so the consent page must allow the client's
/// redirect_uri origin/scheme.
pub fn csp(form_action: &[String]) -> String {
    let mut fa = String::from("'self'");
    for s in form_action {
        fa.push(' ');
        fa.push_str(s);
    }
    format!(
        "default-src 'none'; style-src 'sha256-{}'; font-src 'self'; img-src 'self' data:; form-action {fa}; frame-ancestors 'none'; base-uri 'none'",
        *STYLE_HASH
    )
}

/// The guard keeps a page restored from history from posting the code again.
const AUTO_SUBMIT: &str = "var f=document.forms[0],done=false;\
f.addEventListener('submit',function(e){if(done){e.preventDefault()}done=true});\
setTimeout(function(){if(!done){done=true;f.submit()}},1);";

static AUTO_SUBMIT_HASH: LazyLock<String> =
    LazyLock::new(|| base64::engine::general_purpose::STANDARD.encode(sha256(AUTO_SUBMIT)));

pub fn csp_form_post(form_action: &[String]) -> String {
    format!("{}; script-src 'sha256-{}'", csp(form_action), *AUTO_SUBMIT_HASH)
}

/// The Sign-In with Ethereum ceremony on the server-rendered page. It asks the
/// wallet for its account, takes a challenge from this server, signs it, and
/// lets the server finish; both calls are same-origin, hence `connect-src`.
pub const WALLET_JS: &str = "(function(){\
var btn=document.getElementById('vlpds-wallet');\
if(!btn){return}\
var eth=window.ethereum;\
if(!eth){btn.disabled=true;btn.textContent='No Ethereum wallet found in this browser';return}\
btn.addEventListener('click',async function(ev){\
ev.preventDefault();\
try{\
var accounts=await eth.request({method:'eth_requestAccounts'});\
var address=accounts&&accounts[0];\
if(!address){throw new Error('no account')}\
var started=await fetch('/auth/start',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({provider:'siwe',intent:'sign_in',address:address,requestUri:btn.dataset.requestUri,csrf:btn.dataset.csrf})});\
var s=await started.json();\
if(!started.ok||!s.challenge||s.challenge.kind!=='siwe'){throw new Error('start')}\
var signature=await eth.request({method:'personal_sign',params:[s.challenge.message,address]});\
var out=await fetch('/auth/continue?form=1',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({txn:s.txnId,step:'siwe',message:s.challenge.message,signature:signature})});\
window.location.href=(out.url&&out.url.indexOf('/auth/')>=0)?out.url:'/account?auth=unfinished';\
}catch(e){\
window.location.href='/account?auth=cancelled';\
}\
});\
})();";

static WALLET_JS_HASH: LazyLock<String> =
    LazyLock::new(|| base64::engine::general_purpose::STANDARD.encode(sha256(WALLET_JS)));

/// A page whose only script runs the wallet ceremony.
pub fn csp_wallet(form_action: &[String]) -> String {
    format!("{}; connect-src 'self'; script-src 'sha256-{}'", csp(form_action), *WALLET_JS_HASH)
}

pub fn wallet_page(title: &str, body: &str) -> String {
    page_with_script(title, body, WALLET_JS)
}

/// `response_mode=form_post`. The button is the no-script fallback.
pub fn form_post(redirect_uri: &str, params: &[(String, String)]) -> String {
    let mut fields = String::new();
    for (k, v) in params {
        fields.push_str(&format!("<input type=\"hidden\" name=\"{}\" value=\"{}\">", e(k), e(v)));
    }
    let body = format!(
        "<h1>Returning to the app</h1><form method=\"post\" action=\"{}\">{fields}<div class=\"row\">\
<button type=\"submit\" class=\"primary\">Continue</button></div></form>",
        e(redirect_uri)
    );
    page_with_script("Returning to the app", &body, AUTO_SUBMIT)
}

/// Three strata: log segments settling into state.
const MARK: &str = "<svg width=\"22\" height=\"18\" viewBox=\"0 0 22 18\" aria-hidden=\"true\">\
<rect x=\"0\" y=\"0\" width=\"22\" height=\"4\" rx=\"1\" fill=\"currentColor\"/>\
<rect x=\"3\" y=\"7\" width=\"16\" height=\"4\" rx=\"1\" fill=\"currentColor\" opacity=\".6\"/>\
<rect x=\"6\" y=\"14\" width=\"10\" height=\"4\" rx=\"1\" fill=\"currentColor\" opacity=\".35\"/></svg>";

/// GitHub's mark, linking the source as the web UI's top bar does.
const SOURCE_LINK: &str = "<a class=\"gh\" href=\"https://github.com/jazware/vlpds\" aria-label=\"Source on GitHub\" title=\"Source on GitHub\">\
<svg width=\"18\" height=\"18\" viewBox=\"0 0 16 16\" fill=\"currentColor\" aria-hidden=\"true\"><path d=\"M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8Z\"/></svg></a>";

pub fn page(title: &str, body: &str) -> String {
    page_with_script(title, body, "")
}

fn page_with_script(title: &str, body: &str, script: &str) -> String {
    let script = if script.is_empty() { String::new() } else { format!("<script>{script}</script>") };
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
<meta name=\"referrer\" content=\"no-referrer\"><title>{}</title><style>{STYLE}</style></head><body><main>\
<div class=\"brand\">{MARK}vlpds<span>account security</span>{SOURCE_LINK}</div>\
<div class=\"card\"><div class=\"strata\"></div>{body}</div></main>{script}</body></html>",
        e(title)
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
        format!("<div class=\"client\">{}</div>", e(ctx.client_id))
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
    /// Configured owner-auth methods, offered beside the password form.
    pub providers: &'a [ProviderBtn<'a>],
}

/// One configured owner-auth method on a server-rendered page. A wallet needs
/// its own page (and its own script); the rest are plain form posts.
pub struct ProviderBtn<'a> {
    pub id: &'a str,
    pub label: &'a str,
    pub wallet: bool,
}

/// The provider block, appended after the password form so it can use its own
/// `<form>` elements.
fn provider_buttons(ctx: &Ctx, providers: &[ProviderBtn]) -> String {
    if providers.is_empty() {
        return String::new();
    }
    let mut b = String::from("<div class=\"sep\" aria-hidden=\"true\"></div><p class=\"muted\">Or continue with</p>");
    for p in providers {
        if p.wallet {
            b.push_str(&format!(
                "<a class=\"btn wide\" href=\"/oauth/authorize/wallet?client_id={}&request_uri={}&csrf={}\">Continue with {}</a>",
                e(&crate::oauth::util::encode_uri_component(ctx.client_id)),
                e(&crate::oauth::util::encode_uri_component(ctx.request_uri)),
                e(ctx.csrf),
                e(p.label)
            ));
        } else {
            b.push_str(&format!(
                "<form method=\"post\" action=\"/oauth/authorize/sign-in\">{}\
<input type=\"hidden\" name=\"provider\" value=\"{}\">\
<button type=\"submit\" class=\"btn wide\">Continue with {}</button></form>",
                hidden(ctx),
                e(p.id),
                e(p.label)
            ));
        }
    }
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
pub fn csp_passkey(form_action: &[String]) -> String {
    format!("{}; script-src 'sha256-{}'", csp(form_action), *PASSKEY_JS_HASH)
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

pub fn login(ctx: Option<&Ctx>, f: &LoginForm, csrf_only: &str) -> String {
    let mut b = String::new();
    match ctx {
        Some(c) => {
            b.push_str(&format!(
                "<h1>Sign in to {}</h1><p class=\"muted\">to continue to</p>{}",
                e(c.server_name),
                client_block(c)
            ));
        }
        None => b.push_str("<h1>Sign in</h1><p class=\"muted\">Manage the apps connected to your account.</p>"),
    }
    if let Some(err) = f.error {
        b.push_str(&format!("<p class=\"err\" role=\"alert\">{}</p>", e(err)));
    }
    let hidden_fields = match ctx {
        Some(c) => hidden(c),
        None => format!("<input type=\"hidden\" name=\"csrf\" value=\"{}\">", e(csrf_only)),
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
    if let (Some(c), None) = (ctx, &f.second) {
        b.push_str(&provider_buttons(c, f.providers));
        b.push_str(&format!(
            "<p class=\"alt\">New to {}? <a href=\"{}\">Create an account</a></p>",
            e(c.server_name),
            e(&screen_url(c, "sign-up"))
        ));
    }
    page_with_script("Sign in", &b, if script { PASSKEY_JS } else { "" })
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

pub fn signup(ctx: &Ctx, f: &SignupForm) -> String {
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
    page("Create an account", &b)
}

pub fn chooser(ctx: &Ctx, accounts: &[(String, String)]) -> String {
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
    page("Choose an account", &b)
}

/// Where a permission sits on the consent screen.
#[derive(Clone, Debug, PartialEq)]
pub enum Place {
    /// An NSID authority: the NSID minus its last segment.
    Nsid(String),
    /// A group of its own: a key and its label.
    Fixed(&'static str, &'static str),
    /// Never grouped: a permission set, which lists its own permissions.
    Alone,
}

/// What a group's summary line counts.
#[derive(Clone, Debug, Default)]
pub struct Tally {
    repo: Vec<&'static str>,
    collections: Vec<String>,
    lxms: Vec<String>,
    space: Vec<&'static str>,
    types: Vec<String>,
    /// Phrases for permissions that name no NSID ("upload images").
    other: Vec<String>,
}

const VERB_ORDER: [&str; 6] = ["read", "read your own", "create", "update", "delete", "manage"];

fn push_unique<T: PartialEq + Clone>(v: &mut Vec<T>, x: &[T]) {
    for x in x {
        if !v.contains(x) {
            v.push(x.clone());
        }
    }
}

fn count(n: usize, one: &str) -> String {
    if n == 1 {
        format!("1 {one}")
    } else {
        format!("{n} {one}s")
    }
}

impl Tally {
    fn add(&mut self, o: &Tally) {
        push_unique(&mut self.repo, &o.repo);
        push_unique(&mut self.collections, &o.collections);
        push_unique(&mut self.lxms, &o.lxms);
        push_unique(&mut self.space, &o.space);
        push_unique(&mut self.types, &o.types);
        push_unique(&mut self.other, &o.other);
    }

    /// "Create and delete in 4 collections · call 2 methods".
    fn summary(&self) -> String {
        let verbs = |v: &[&'static str]| {
            let mut v = v.to_vec();
            if v.contains(&"read") {
                v.retain(|x| *x != "read your own");
            }
            v.sort_by_key(|x| VERB_ORDER.iter().position(|o| o == x));
            join_and(&v)
        };
        let mut parts = Vec::new();
        if !self.collections.is_empty() {
            let r#where = match self.collections.iter().any(|c| c == "*") {
                true => "any collection".to_string(),
                false => count(self.collections.len(), "collection"),
            };
            parts.push(format!("{} in {where}", verbs(&self.repo)));
        }
        if !self.lxms.is_empty() {
            parts.push(match self.lxms.iter().any(|l| l == "*") {
                true => "make any request".to_string(),
                false => format!("call {}", count(self.lxms.len(), "method")),
            });
        }
        if !self.types.is_empty() {
            let r#where = match self.types.iter().any(|t| t == "*") {
                true => "every space".to_string(),
                false => count(self.types.len(), "space type"),
            };
            parts.push(match self.space.is_empty() {
                true => format!("no access in {where}"),
                false => format!("{} in {where}", verbs(&self.space)),
            });
        }
        parts.extend(self.other.iter().cloned());
        capitalize(&parts.join(" · "))
    }
}

/// One permission as the consent screen shows it: plain text, escaped
/// when rendered.
#[derive(Clone, Debug)]
pub struct Item {
    pub title: String,
    pub place: Place,
    /// The NSIDs it covers, each with its actions.
    pub lines: Vec<(String, String)>,
    pub warning: Option<&'static str>,
    pub tally: Tally,
}

impl Item {
    fn fixed(title: &str, key: &'static str, label: &'static str, warning: Option<&'static str>) -> Item {
        Item {
            title: title.to_string(),
            place: Place::Fixed(key, label),
            lines: Vec::new(),
            warning,
            tally: Tally { other: vec![decapitalize(title)], ..Default::default() },
        }
    }
}

/// One requested scope: one checkbox.
pub struct ScopeRow {
    pub scope: String,
    pub required: bool,
    pub item: Item,
    /// A permission set's description.
    pub detail: Option<String>,
    /// A permission set's permissions.
    pub inner: Vec<Item>,
}

/// atproto has no client-declared "required" scopes; only `atproto` itself,
/// without which the token grants nothing.
pub const REQUIRED_SCOPES: [&str; 1] = ["atproto"];

const GENERIC_WARNING: &str = "A broad grant: it covers everything except private messages and account settings, \
and it can't be narrowed. Untick it to refuse it entirely.";
const CHAT_WARNING: &str =
    "A broad grant covering all of your private messages. It only works together with full access to your account.";

const SPACE_UNIVERSAL_READ_WARNING: &str = "This app is asking to read every space on the network: whatever anyone \
shares with you in a space, anywhere. That's a very broad grant. Only allow it for an app you trust completely.";
const SPACE_UNIVERSAL_WRITE_WARNING: &str = "This app is asking to write in every space on the network you're a \
member of, as you. That's a very broad grant. Only allow it for an app you trust completely.";
const SPACE_UNIVERSAL_READ_WRITE_WARNING: &str = "This app is asking to read whatever anyone shares with you in a \
space, anywhere on the network, and to write in every space you're a member of, as you. That's a very broad grant. \
Only allow it for an app you trust completely.";

/// A `space:*?authority=*` grant that reads what others share or writes
/// anything. One that only reads your own space repos gets no warning.
fn space_warning(p: &SpacePermission) -> Option<&'static str> {
    if p.space_type != "*" || p.authority != "*" {
        return None;
    }
    let reads = p.action.iter().any(|a| a == "read");
    let writes = p.writes() || p.manage.as_ref().is_some_and(|m| !m.is_empty());
    match (reads, writes) {
        (true, true) => Some(SPACE_UNIVERSAL_READ_WRITE_WARNING),
        (true, false) => Some(SPACE_UNIVERSAL_READ_WARNING),
        (false, true) => Some(SPACE_UNIVERSAL_WRITE_WARNING),
        (false, false) => None,
    }
}

/// Names for `space:` grants on the consent screen (`--spaces`): type
/// declarations by NSID and the handles of authority DIDs that resolve back
/// to them. A missing one shows the NSID or the DID.
#[derive(Debug, Default)]
pub struct SpaceNames {
    pub decls: std::collections::HashMap<String, crate::lexicon::SpaceDecl>,
    pub handles: std::collections::HashMap<String, String>,
}

/// One row per requested scope, in request order. `names`: Some with
/// `--spaces`.
pub fn describe_scopes(scope: &str, sets: &[(IncludeScope, J)], names: Option<&SpaceNames>) -> Vec<ScopeRow> {
    let mut out = Vec::new();
    for s in scope.split(' ').filter(|s| !s.is_empty()) {
        let row = |item| ScopeRow {
            scope: s.to_string(),
            required: REQUIRED_SCOPES.contains(&s),
            item,
            detail: None,
            inner: Vec::new(),
        };
        match s {
            "atproto" => out.push(row(Item::fixed(
                "Know who you are: your account identifier (DID) and handle",
                "atproto",
                "Who you are",
                None,
            ))),
            "transition:generic" => out.push(row(Item::fixed(
                "Full access to your account: create, change and delete any of your public data, upload media, and use other services on your behalf",
                "generic",
                "Full access",
                Some(GENERIC_WARNING),
            ))),
            "transition:chat.bsky" => {
                let mut i = Item::fixed("Read and send your Bluesky private messages", "", "", Some(CHAT_WARNING));
                i.place = Place::Nsid("chat.bsky".into());
                out.push(row(i))
            }
            "transition:email" => {
                out.push(row(Item::fixed("Read your email address", "account", "Your account settings", None)))
            }
            _ => {
                if let Some(p) = Permission::parse(s) {
                    out.push(row(item(&p, names)));
                } else if let Some(inc) = IncludeScope::parse(s) {
                    let set = sets.iter().find(|(i, _)| i == &inc).map(|(_, j)| j);
                    let title = set.and_then(|j| j.get("title")).and_then(|t| t.as_str()).unwrap_or(&inc.nsid);
                    let mut r = row(Item {
                        title: title.to_string(),
                        place: Place::Alone,
                        lines: vec![(inc.nsid.clone(), "permission set".into())],
                        warning: None,
                        tally: Tally::default(),
                    });
                    r.detail = set.and_then(|j| j.get("detail")).and_then(|t| t.as_str()).map(String::from);
                    if let Some(set) = set {
                        r.inner = inc.to_permissions(set, names.is_some()).iter().map(|p| item(p, names)).collect();
                    }
                    out.push(r);
                }
            }
        }
    }
    out
}

/// The NSID minus its last segment.
fn authority(nsid: &str) -> &str {
    nsid.rsplit_once('.').map_or(nsid, |(a, _)| a)
}

/// The longest authority every NSID shares, if it's a real one (two
/// segments at least); `any`: the group for a `*`.
fn place_of(nsids: &[String], any: (&'static str, &'static str)) -> Place {
    if nsids.iter().any(|n| n == "*") {
        return Place::Fixed(any.0, any.1);
    }
    let mut common: Option<Vec<&str>> = None;
    for n in nsids {
        let segs: Vec<&str> = authority(n).split('.').collect();
        common = Some(match common {
            None => segs,
            Some(c) => c.iter().zip(&segs).take_while(|(a, b)| a == b).map(|(a, _)| *a).collect(),
        });
    }
    match common {
        Some(c) if c.len() >= 2 => Place::Nsid(c.join(".")),
        _ => Place::Fixed("several", "Several apps"),
    }
}

/// create, update, delete: in that order.
fn write_verbs(action: &[String]) -> Vec<&'static str> {
    ["create", "update", "delete"].into_iter().filter(|v| action.iter().any(|a| a == v)).collect()
}

fn item(p: &Permission, names: Option<&SpaceNames>) -> Item {
    let title = match (p, names) {
        (Permission::Space(s), Some(n)) => describe_space(s, n),
        _ => describe_permission(p),
    };
    match p {
        Permission::Repo { collection, action } => {
            let verbs = write_verbs(action);
            Item {
                place: place_of(collection, ("any-collection", "Any collection")),
                lines: collection.iter().map(|c| (c.clone(), join_and(&verbs))).collect(),
                warning: None,
                tally: Tally { repo: verbs, collections: collection.clone(), ..Default::default() },
                title,
            }
        }
        Permission::Rpc { aud, lxm } => {
            let via = if aud == "*" { "call on any service".to_string() } else { format!("call on {aud}") };
            Item {
                place: place_of(lxm, ("any-request", "Any request")),
                lines: lxm.iter().map(|l| (l.clone(), via.clone())).collect(),
                warning: None,
                tally: Tally { lxms: lxm.clone(), ..Default::default() },
                title,
            }
        }
        Permission::Blob { .. } => Item::fixed(&title, "blob", "Uploads", None),
        Permission::Account { .. } | Permission::Identity { .. } => {
            Item::fixed(&title, "account", "Your account settings", None)
        }
        Permission::Space(s) => {
            let s = match names.and_then(|n| n.decls.get(&s.space_type)) {
                Some(d) if s.space_type != "*" => s.clone().with_default_collections(&d.collections),
                _ => s.clone(),
            };
            let mut verbs: Vec<&'static str> = Vec::new();
            if s.action.iter().any(|a| a == "read") {
                verbs.push("read");
            } else if s.action.iter().any(|a| a == "read_self") {
                verbs.push("read your own");
            }
            let writes = write_verbs(&s.action);
            verbs.extend(&writes);
            let mut on_type: Vec<String> =
                verbs.first().filter(|v| v.starts_with("read")).map(|v| v.to_string()).into_iter().collect();
            let mut other = Vec::new();
            if let Some(m) = s.manage.as_ref().filter(|m| !m.is_empty()) {
                let ops: Vec<&str> = m
                    .iter()
                    .map(|op| match op.as_str() {
                        "create" => "create",
                        "update" => "change",
                        _ => "delete",
                    })
                    .collect();
                // management bound to one account isn't "in every space"
                // the type covers: the summary says whose
                let whose = match s.authority.as_str() {
                    "*" => None,
                    "self" => Some("your".to_string()),
                    did => Some(format!("{did}'s")),
                };
                match whose {
                    None => {
                        verbs.push("manage");
                        on_type.push(format!("{} spaces", join_and(&ops)));
                    }
                    Some(w) => {
                        other.push(format!("manage {w} spaces"));
                        on_type.push(format!("{} {w} spaces", join_and(&ops)));
                    }
                }
            }
            let mut lines = vec![(
                s.space_type.clone(),
                if on_type.is_empty() {
                    "space type".into()
                } else {
                    join_and(&on_type.iter().map(String::as_str).collect::<Vec<_>>())
                },
            )];
            if let Some(c) = s.collection.as_ref().filter(|_| !writes.is_empty()) {
                lines.extend(c.iter().map(|c| (c.clone(), join_and(&writes))));
            }
            Item {
                place: place_of(std::slice::from_ref(&s.space_type), ("all-spaces", "Every space")),
                lines,
                warning: names.and_then(|_| space_warning(&s)),
                tally: Tally { space: verbs, types: vec![s.space_type.clone()], other, ..Default::default() },
                title,
            }
        }
    }
}

/// A small map of well-known NSID authorities; anything else shows its prefix.
fn group_label(prefix: &str) -> Option<&'static str> {
    Some(match prefix {
        "app.bsky" => "Bluesky",
        "app.bsky.feed" => "Bluesky posts and feeds",
        "app.bsky.graph" => "Bluesky follows and lists",
        "app.bsky.actor" => "Bluesky profile",
        "app.bsky.notification" => "Bluesky notifications",
        "chat.bsky" => "Bluesky chat",
        "chat.bsky.convo" => "Bluesky chat conversations",
        "chat.bsky.actor" => "Bluesky chat settings",
        "com.atproto" => "Your atproto account",
        "com.atproto.repo" => "Your repository",
        "com.atproto.server" => "Your account and sessions",
        "com.atproto.identity" => "Your handle and identity",
        "com.atproto.sync" => "Repository sync",
        _ => return None,
    })
}

/// A group's heading: its label, then its prefix in code; a prefix without
/// a label is the label.
fn group_head(place: &Place, prefix: &str) -> String {
    match (place, group_label(prefix)) {
        (Place::Fixed(_, label), _) => format!("<span class=\"gl\">{}</span>", e(label)),
        (_, Some(label)) => format!("<span class=\"gl\">{}</span><code class=\"gp\">{}</code>", e(label), e(prefix)),
        (_, None) => format!("<span class=\"gl\"><code class=\"gp\">{}</code></span>", e(prefix)),
    }
}

enum Node<'a, E> {
    One(&'a E),
    /// A sub-authority with two or more entries.
    Sub(String, Vec<&'a E>),
}

struct Group<'a, E> {
    place: Place,
    prefix: String,
    entries: Vec<&'a E>,
}

/// Groups by NSID authority, two segments at the top (`app.bsky`), in
/// order of first appearance. A group whose entries share one authority
/// takes that authority's name, so `app.bsky.feed` alone doesn't nest under
/// `app.bsky`.
fn groups<'a, E>(entries: &'a [E], item: &impl Fn(&E) -> &Item) -> Vec<Group<'a, E>> {
    let mut out: Vec<Group<'a, E>> = Vec::new();
    for (i, en) in entries.iter().enumerate() {
        let place = item(en).place.clone();
        let key = match &place {
            Place::Nsid(a) => format!("n:{}", a.split('.').take(2).collect::<Vec<_>>().join(".")),
            Place::Fixed(k, _) => format!("f:{k}"),
            Place::Alone => format!("a:{i}"),
        };
        match out.iter_mut().find(|g| g.prefix == key) {
            Some(g) => g.entries.push(en),
            None => out.push(Group { place, prefix: key, entries: vec![en] }),
        }
    }
    for g in &mut out {
        g.prefix = match &g.place {
            Place::Nsid(_) => {
                let auths: Vec<&str> = g
                    .entries
                    .iter()
                    .filter_map(|en| match &item(en).place {
                        Place::Nsid(a) => Some(a.as_str()),
                        _ => None,
                    })
                    .collect();
                match auths.iter().all(|a| *a == auths[0]) {
                    true => auths[0].to_string(),
                    false => g.prefix[2..].to_string(),
                }
            }
            _ => String::new(),
        };
    }
    out
}

/// A group's entries under its prefix: an authority with two or more
/// entries nests one level, and one with a single entry doesn't.
fn nodes<'a, E>(g: &Group<'a, E>, item: &impl Fn(&E) -> &Item) -> Vec<Node<'a, E>> {
    let auth = |en: &E| match &item(en).place {
        Place::Nsid(a) => a.clone(),
        _ => String::new(),
    };
    let mut out: Vec<Node<'a, E>> = Vec::new();
    for en in &g.entries {
        let a = auth(en);
        if a == g.prefix || g.entries.iter().filter(|x| auth(x) == a).count() < 2 {
            out.push(Node::One(en));
        } else if let Some(Node::Sub(_, v)) = out.iter_mut().find(|n| matches!(n, Node::Sub(s, _) if *s == a)) {
            v.push(en);
        } else {
            out.push(Node::Sub(a, vec![en]));
        }
    }
    out
}

/// `<li>`s for a `ul.scopes`: a group with one entry is that entry, shown
/// flat with its warning. A larger one is a `<details>`, open when it
/// carries a warning, whose summary has the label, the combined verbs and
/// counts, and every warning (entries inside don't repeat them).
fn render_groups<E>(entries: &[E], item: impl Fn(&E) -> &Item, entry: impl Fn(&E, bool) -> String) -> String {
    let mut b = String::new();
    for g in groups(entries, &item) {
        if let [one] = g.entries[..] {
            b.push_str(&entry(one, true));
            continue;
        }
        let mut tally = Tally::default();
        let mut warnings: Vec<&str> = Vec::new();
        for en in &g.entries {
            tally.add(&item(en).tally);
            push_unique(&mut warnings, &item(en).warning.into_iter().collect::<Vec<_>>());
        }
        b.push_str(&format!(
            "<li class=\"grp\"><details class=\"grp\"{}><summary>{}<span class=\"gs\">{}</span>",
            if warnings.is_empty() { "" } else { " open" },
            group_head(&g.place, &g.prefix),
            e(&tally.summary())
        ));
        for w in warnings {
            b.push_str(&format!("<span class=\"warn\">{}</span>", e(w)));
        }
        b.push_str("</summary><ul class=\"ents\">");
        for n in nodes(&g, &item) {
            match n {
                Node::One(en) => b.push_str(&entry(en, false)),
                Node::Sub(a, v) => {
                    let mut t = Tally::default();
                    for en in &v {
                        t.add(&item(en).tally);
                    }
                    b.push_str(&format!(
                        "<li class=\"sg\"><div class=\"sgh\">{}<span class=\"gs\">{}</span></div><ul class=\"ents\">",
                        group_head(&Place::Nsid(a.clone()), &a),
                        e(&t.summary())
                    ));
                    for en in v {
                        b.push_str(&entry(en, false));
                    }
                    b.push_str("</ul></li>");
                }
            }
        }
        b.push_str("</ul></details></li>");
    }
    b
}

fn lines_html(it: &Item) -> String {
    if it.lines.is_empty() {
        return String::new();
    }
    let mut b = String::from("<ul class=\"ns\">");
    for (nsid, actions) in &it.lines {
        b.push_str(&format!("<li><code>{}</code> <span>{}</span></li>", e(nsid), e(actions)));
    }
    b.push_str("</ul>");
    b
}

fn warn_html(it: &Item, show: bool) -> String {
    it.warning.filter(|_| show).map(|w| format!("<p class=\"warn\">{}</p>", e(w))).unwrap_or_default()
}

/// A permission set's permissions, grouped, without checkboxes: the set is
/// granted or refused whole.
fn inner_html(items: &[Item]) -> String {
    if items.is_empty() {
        return String::new();
    }
    let rows = render_groups(
        items,
        |i| i,
        |it, warn| {
            format!(
                "<li class=\"ent\"><div><span class=\"et\">{}</span>{}{}</div></li>",
                e(&it.title),
                lines_html(it),
                warn_html(it, warn)
            )
        },
    );
    format!("<ul class=\"scopes inner\">{rows}</ul>")
}

/// "a, b and c".
fn join_and(v: &[&str]) -> String {
    match v {
        [] => String::new(),
        [one] => one.to_string(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

fn collection_name(nsid: &str) -> Option<&'static str> {
    Some(match nsid {
        "app.bsky.feed.post" => "posts",
        "app.bsky.feed.like" => "likes",
        "app.bsky.feed.repost" => "reposts",
        "app.bsky.graph.follow" => "follows",
        "app.bsky.graph.block" => "blocks",
        "app.bsky.graph.list" => "lists",
        "app.bsky.graph.listitem" => "list members",
        "app.bsky.graph.starterpack" => "starter packs",
        "app.bsky.actor.profile" => "profile",
        "app.bsky.feed.threadgate" => "reply settings",
        "app.bsky.feed.postgate" => "quote settings",
        "app.bsky.feed.generator" => "feeds",
        _ => return None,
    })
}

pub fn describe_permission(p: &Permission) -> String {
    match p {
        Permission::Repo { collection, action } => {
            let verbs: Vec<&str> = action
                .iter()
                .map(|a| match a.as_str() {
                    "create" => "create",
                    "update" => "update",
                    _ => "delete",
                })
                .collect();
            let verbs = capitalize(&join_and(&verbs));
            let names: Option<Vec<&str>> = collection.iter().map(|c| collection_name(c)).collect();
            match names {
                Some(n) if !n.is_empty() => format!("{verbs} your {}", join_and(&n)),
                _ if collection.iter().any(|c| c == "*") => format!("{verbs} records in any collection"),
                _ => format!("{verbs} records in {}", collection.join(", ")),
            }
        }
        Permission::Rpc { aud, lxm } => {
            let svc = if aud == "*" { "any service".to_string() } else { aud.clone() };
            if !lxm.is_empty() && lxm.iter().all(|l| l.starts_with("chat.bsky.")) {
                if aud == "did:web:api.bsky.chat#bsky_chat" {
                    "Read and send your Bluesky private messages".to_string()
                } else {
                    format!("Read and send your Bluesky private messages (through {svc})")
                }
            } else if lxm.iter().any(|l| l == "*") {
                format!("Make any request on your behalf to {svc}")
            } else {
                format!("Make requests on your behalf to {svc} ({})", lxm.join(", "))
            }
        }
        Permission::Blob { accept } => {
            let kinds: Vec<&str> = accept
                .iter()
                .map(|a| match a.as_str() {
                    "*/*" => "files of any type",
                    "image/*" => "images",
                    "video/*" => "video",
                    "audio/*" => "audio",
                    other => other,
                })
                .collect();
            format!("Upload {}", join_and(&kinds))
        }
        Permission::Account { attr, action } => {
            let manage = action.iter().any(|a| a == "manage");
            let what = match attr.as_str() {
                "email" => "your email address",
                "repo" => "your repository (import/export)",
                _ => "your account status (activate/deactivate)",
            };
            format!("{} {what}", if manage { "Read and change" } else { "Read" })
        }
        Permission::Identity { attr } => {
            if attr == "handle" {
                "Change your handle".into()
            } else {
                "Manage your identity (handle and DID document)".into()
            }
        }
        Permission::Space(p) => describe_space(p, &SpaceNames::default()),
    }
}

/// Reference consent `SpaceRow`: the declaration's name for the type, the
/// authority's verified handle (else its DID), and a bare grant's writes as
/// its declaration's collections, which is what the token will carry.
pub fn describe_space(p: &SpacePermission, names: &SpaceNames) -> String {
    let decl = names.decls.get(&p.space_type);
    let p = match decl {
        Some(d) if p.space_type != "*" => p.clone().with_default_collections(&d.collections),
        _ => p.clone(),
    };
    let owner = match p.authority.as_str() {
        "self" => "your account".to_string(),
        did => names.handles.get(did).map(|h| format!("@{h}")).unwrap_or_else(|| did.to_string()),
    };
    let kind = decl.map(|d| d.name.clone()).unwrap_or_else(|| p.space_type.clone());
    let what = match (p.space_type.as_str(), p.authority.as_str()) {
        ("*", "*") => "All spaces on the network".to_string(),
        ("*", _) => format!("All spaces on {owner}"),
        (_, "*") => format!("{kind} spaces"),
        _ => format!("{kind} spaces on {owner}"),
    };
    let mut parts: Vec<String> = Vec::new();
    if p.action.iter().any(|a| a == "read") {
        parts.push("read what members share with you".into());
    } else if p.action.iter().any(|a| a == "read_self") {
        parts.push("read your own space repos".into());
    }
    let verbs: Vec<&str> =
        p.action.iter().map(String::as_str).filter(|a| ["create", "update", "delete"].contains(a)).collect();
    let write = match verbs.len() {
        3 => "write".to_string(),
        _ => join_and(&verbs),
    };
    if let Some(c) = p.collection.as_ref().filter(|_| !verbs.is_empty()) {
        let colls = match c.iter().any(|c| c == "*") {
            true => "any collection".to_string(),
            false => join_and(&c.iter().map(String::as_str).collect::<Vec<_>>()),
        };
        parts.push(format!("{write} records in {colls}"));
    }
    // the token request fails rather than guess at what was meant
    let unresolved =
        (p.collection.is_none() && !verbs.is_empty() && decl.is_none() && p.space_type != "*").then(|| {
            format!(
                "{write} records in the collections {} declares, which could not be looked up, so approving this will fail",
                p.space_type
            )
        });
    if let Some(m) = p.manage.as_ref().filter(|m| !m.is_empty()) {
        let ops: Vec<&str> = m
            .iter()
            .map(|op| match op.as_str() {
                "create" => "create",
                "update" => "change",
                _ => "delete",
            })
            .collect();
        let members = if m.iter().any(|op| op == "update") { " and their members" } else { "" };
        parts.push(format!("{} spaces{members}", join_and(&ops)));
    }
    let parts: Vec<&str> = parts.iter().map(String::as_str).collect();
    match (parts.is_empty(), unresolved) {
        (true, None) => format!("{what}: no access"),
        (true, Some(u)) => format!("{what}: {u}"),
        (false, None) => format!("{what}: {}", join_and(&parts)),
        (false, Some(u)) => format!("{what}: {}. It also asks to {u}", join_and(&parts)),
    }
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}

fn decapitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_lowercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}

/// One checkbox per scope, all ticked, posted as repeated `scope` fields so
/// the page needs no script. Disabled inputs aren't submitted, so a hidden
/// field carries each required scope. Scopes are grouped by NSID authority
/// in native `<details>`, so a checkbox can sit in a closed group.
/// `scope`: as requested, shown raw at the bottom.
pub fn consent(ctx: &Ctx, did: &str, handle: &str, scope: &str, rows: &[ScopeRow]) -> String {
    let mut b = format!(
        "<h1>Authorize access</h1><p class=\"muted\">Signed in as <b>@{}</b></p><p>This app wants access to your account:</p>{}\
<form method=\"post\" action=\"/oauth/authorize/consent\">{}<input type=\"hidden\" name=\"did\" value=\"{}\">\
<fieldset><legend>It will be able to:</legend><p class=\"hint\">Open a group to see each permission. Untick anything you don't want to allow. The app might not work fully without it.</p><ul class=\"scopes\">",
        e(handle),
        client_block(ctx),
        hidden(ctx),
        e(did)
    );
    let entries: Vec<(usize, &ScopeRow)> = rows.iter().enumerate().collect();
    b.push_str(&render_groups(&entries, |(_, r)| &r.item, |&(i, r), warn| {
        let sc = e(&r.scope);
        let input = if r.required {
            format!("<input type=\"hidden\" name=\"scope\" value=\"{sc}\"><input type=\"checkbox\" id=\"s{i}\" checked disabled aria-describedby=\"s{i}d\">")
        } else {
            format!("<input type=\"checkbox\" id=\"s{i}\" name=\"scope\" value=\"{sc}\" checked aria-describedby=\"s{i}d\">")
        };
        let req = if r.required { "<span class=\"req\">Required</span>" } else { "" };
        let detail = r.detail.as_ref().map(|d| format!("<p class=\"sd\">{}</p>", e(d))).unwrap_or_default();
        format!(
            "<li class=\"ent\">{input}<div><label for=\"s{i}\">{}{req}</label><div id=\"s{i}d\">{}{}{detail}{}</div></div></li>",
            e(&r.item.title),
            lines_html(&r.item),
            warn_html(&r.item, warn),
            inner_html(&r.inner)
        )
    }));
    b.push_str("</ul></fieldset><details class=\"raw\"><summary>Show requested scopes</summary><ul class=\"raw\">");
    for s in scope.split(' ').filter(|s| !s.is_empty()) {
        b.push_str(&format!("<li><code>{}</code></li>", e(s)));
    }
    b.push_str(
        "</ul></details><p class=\"muted\">You can revoke this access at any time under <b>Connected apps</b> in your account settings on this server.</p>\
<div class=\"row\"><button type=\"submit\" name=\"action\" value=\"deny\">Deny</button><button type=\"submit\" class=\"primary\" name=\"action\" value=\"allow\" autofocus>Allow</button></div></form>",
    );
    page("Authorize access", &b)
}

pub fn error(title: &str, msg: &str) -> String {
    page(title, &format!("<h1>{}</h1><p>{}</p>", e(title), e(msg)))
}

pub struct SessionRow {
    pub id: String,
    pub client_id: String,
    pub scope: String,
    pub created_at: String,
    pub updated_at: String,
}

pub fn account_page(csrf: &str, accounts: &[(String, String, Vec<SessionRow>)]) -> String {
    let mut b = String::from("<h1>Connected apps</h1><p class=\"muted\">Apps you have authorized with OAuth. Revoking access signs the app out immediately.</p>");
    for (did, handle, sessions) in accounts {
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
            continue;
        }
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
    b.push_str("<div class=\"row\"><a href=\"/oauth/account?add=1\">Add another account</a></div><footer class=\"muted\"><a href=\"/account\">Open account settings</a></footer>");
    page("Connected apps", &b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const APPVIEW: &str = "did:web:api.bsky.app%23bsky_appview";
    const CHAT: &str = "did:web:api.bsky.chat%23bsky_chat";
    const BOARDS: &str = "space:dev.example.boards.board?authority=*&collection=dev.example.boards.post&collection=dev.example.boards.comment&collection=dev.example.boards.vote&action=read&action=create&action=update&action=delete";
    const BOARDS_SET: &str = "include:dev.example.boards.basePermissions?aud=did:web:boards.example%23boards";

    fn big() -> String {
        [
            "atproto".to_string(),
            "transition:generic".into(),
            "repo:app.bsky.feed.post".into(),
            "repo:app.bsky.feed.like?action=create&action=delete".into(),
            "repo:app.bsky.feed.repost?action=create&action=delete".into(),
            "repo:app.bsky.graph.follow?action=create&action=delete".into(),
            "repo:app.bsky.graph.block?action=create&action=delete".into(),
            "repo:app.bsky.graph.list".into(),
            "repo:app.bsky.actor.profile?action=update".into(),
            format!("rpc:app.bsky.feed.getTimeline?aud={APPVIEW}"),
            format!("rpc:app.bsky.feed.getFeed?aud={APPVIEW}"),
            format!("rpc:app.bsky.actor.getPreferences?aud={APPVIEW}"),
            "transition:chat.bsky".into(),
            format!("rpc:chat.bsky.convo.sendMessage?aud={CHAT}"),
            format!("rpc:chat.bsky.convo.getLog?aud={CHAT}"),
            format!("rpc:chat.bsky.actor.exportAccountData?aud={CHAT}"),
            "blob:image/*".into(),
            "blob:video/*".into(),
            "account:email".into(),
            "identity:handle".into(),
        ]
        .join(" ")
    }

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

    fn boards_set(title: &str, detail: &str) -> Vec<(IncludeScope, J)> {
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
        vec![(IncludeScope::parse(BOARDS_SET).unwrap(), set)]
    }

    fn page_for(scope: &str, sets: &[(IncludeScope, J)], names: Option<&SpaceNames>) -> String {
        let ctx = Ctx {
            request_uri: "urn:ietf:params:oauth:request_uri:req-x",
            csrf: "c",
            client_id: "https://app.example/client-metadata.json",
            loopback: false,
            server_name: "vlpds",
        };
        consent(&ctx, "did:plc:abc", "alice.test", scope, &describe_scopes(scope, sets, names))
    }

    fn summary_of<'a>(html: &'a str, head: &str) -> &'a str {
        let at = html.find(head).unwrap_or_else(|| panic!("no {head}: {html}"));
        let start = html[..at].rfind("<details").unwrap();
        &html[start..at + html[at..].find("</summary>").unwrap()]
    }

    fn scopes_posted(html: &str) -> Vec<String> {
        html.split("name=\"scope\" value=\"").skip(1).map(|r| r[..r.find('"').unwrap()].replace("&amp;", "&")).collect()
    }

    /// `VLPDS_CONSENT_DUMP=<dir>` writes the pages, for screenshots.
    fn dump(name: &str, html: &str) {
        if let Ok(dir) = std::env::var("VLPDS_CONSENT_DUMP") {
            std::fs::write(format!("{dir}/{name}.html"), html).unwrap();
        }
    }

    #[test]
    fn a_lone_authority_takes_its_own_name() {
        let html = page_for("atproto repo:app.bsky.feed.post repo:app.bsky.feed.like", &[], None);
        let s = summary_of(&html, "Bluesky posts and feeds");
        assert!(s.contains("<code class=\"gp\">app.bsky.feed</code>"), "{s}");
        assert!(s.contains("Create, update and delete in 2 collections"), "{s}");
        assert!(!html.contains(">Bluesky<"), "app.bsky.feed alone doesn't nest under app.bsky: {html}");
        assert!(!html.contains("class=\"sg\""), "{html}");
        // a group of one is just its row
        assert!(!html.contains("Who you are"), "{html}");
    }

    #[test]
    fn authorities_nest_one_level_and_single_children_merge_up() {
        let html = page_for(&big(), &[], None);
        dump("big", &html);
        let s = summary_of(&html, "<span class=\"gl\">Bluesky</span>");
        assert!(s.contains("<code class=\"gp\">app.bsky</code>"), "{s}");
        assert!(s.contains("Create, update and delete in 7 collections · call 3 methods"), "{s}");
        // feed and graph have several entries each; actor's profile and
        // getPreferences make two as well
        for sub in ["Bluesky posts and feeds", "Bluesky follows and lists", "Bluesky profile"] {
            assert!(html.contains(&format!("<div class=\"sgh\"><span class=\"gl\">{sub}</span>")), "{sub}: {html}");
        }
        assert!(html.contains("<span class=\"gl\">Bluesky follows and lists</span><code class=\"gp\">app.bsky.graph</code><span class=\"gs\">Create, update and delete in 3 collections</span>"), "{html}");
        // chat: transition:chat.bsky sits at chat.bsky itself, convo nests,
        // and actor's single method merges up
        let s = summary_of(&html, "<span class=\"gl\">Bluesky chat</span>");
        assert!(s.contains("Call 3 methods · read and send your Bluesky private messages"), "{s}");
        assert!(html.contains("<span class=\"gl\">Bluesky chat conversations</span>"), "{html}");
        assert!(!html.contains("<span class=\"gl\">Bluesky chat settings</span>"), "{html}");
        let s = summary_of(&html, "<span class=\"gl\">Uploads</span>");
        assert!(s.contains("Upload images · upload video"), "{s}");
        let s = summary_of(&html, "<span class=\"gl\">Your account settings</span>");
        assert!(s.contains("Read your email address · change your handle"), "{s}");
        // every scope keeps its checkbox, in request order
        let mut posted = scopes_posted(&html);
        posted.sort();
        let mut want: Vec<String> = big().split(' ').map(String::from).collect();
        want.sort();
        assert_eq!(posted, want);
        assert!(!html.contains("<script"), "{html}");
    }

    #[test]
    fn warnings_stay_at_the_summary_and_open_their_group() {
        let html = page_for(&big(), &[], None);
        // generic is a group of one: its row carries the warning
        assert_eq!(html.matches("class=\"warn\"").count(), 2, "{html}");
        let s = summary_of(&html, "<span class=\"gl\">Bluesky chat</span>");
        assert!(s.starts_with("<details class=\"grp\" open>"), "{s}");
        assert!(s.contains("<span class=\"warn\">A broad grant covering all of your private messages."), "{s}");
        let s = summary_of(&html, "<span class=\"gl\">Bluesky</span>");
        assert!(s.starts_with("<details class=\"grp\">"), "collapsed without a warning: {s}");

        // a universal space read in a group of two: the warning is in the summary
        let names = SpaceNames::default();
        let html =
            page_for("atproto space:*?authority=*&action=read space:*?authority=*&action=read_self", &[], Some(&names));
        let s = summary_of(&html, "<span class=\"gl\">Every space</span>");
        assert!(s.starts_with("<details class=\"grp\" open>"), "{s}");
        assert!(s.contains("Read in every space"), "{s}");
        assert!(s.contains("asking to read every space on the network"), "{s}");
        assert_eq!(html.matches("class=\"warn\"").count(), 1, "{html}");
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
        let s = summary_of(&html, "<span class=\"gl\">Every space</span>");
        assert!(s.contains("Read your own in every space · manage your spaces"), "{s}");
        assert!(!s.contains("manage in every space"), "{s}");
        assert!(html.contains("read your own and change and delete your spaces"), "{html}");
    }

    #[test]
    fn a_space_grant_lists_its_type_and_collections() {
        let names = boards_names("Boards");
        let html = page_for(&format!("atproto {BOARDS}"), &[], Some(&names));
        dump("boards", &html);
        assert!(html.contains("Boards spaces: read what members share with you and write records in dev.example.boards.post, dev.example.boards.comment and dev.example.boards.vote"), "{html}");
        assert!(html.contains("<li><code>dev.example.boards.board</code> <span>read</span></li><li><code>dev.example.boards.post</code> <span>create, update and delete</span></li>"), "{html}");
        assert!(!html.contains("class=\"warn\""), "{html}");
        // two space types under one authority: grouped, counted
        let html =
            page_for(&format!("atproto {BOARDS} space:dev.example.boards.archive?action=read_self"), &[], Some(&names));
        let s = summary_of(&html, "<code class=\"gp\">dev.example.boards</code>");
        assert!(s.contains("Read, create, update and delete in 2 space types"), "{s}");
    }

    #[test]
    fn a_permission_set_groups_its_permissions() {
        let names = boards_names("Boards");
        let html = page_for(
            &format!("atproto {BOARDS_SET}"),
            &boards_set("Boards", "Post, comment and vote on boards"),
            Some(&names),
        );
        dump("include", &html);
        assert_eq!(scopes_posted(&html), ["atproto", BOARDS_SET]);
        assert!(html.contains("<label for=\"s1\">Boards</label>"), "{html}");
        assert!(html.contains("<p class=\"sd\">Post, comment and vote on boards</p>"), "{html}");
        let s = summary_of(&html, "<span class=\"gl\"><code class=\"gp\">dev.example.boards</code></span>");
        assert!(s.contains("Create, update and delete in 1 collection · call 2 methods · read, create, update and delete in 1 space type"), "{s}");
        // the set is granted whole: one checkbox
        assert_eq!(html.matches("type=\"checkbox\"").count(), 2, "{html}");
    }

    #[test]
    fn hostile_names_are_escaped() {
        let x = "<img src=x onerror=alert(1)>";
        let names = boards_names(x);
        let html = page_for(&format!("atproto {BOARDS} {BOARDS_SET}"), &boards_set(x, x), Some(&names));
        assert!(!html.contains("<img"), "{html}");
        assert!(html.contains("&lt;img src=x onerror=alert(1)&gt; spaces: read"), "{html}");
        // NSIDs and actions are escaped too, wherever they come from
        let row = |scope: &str| ScopeRow {
            scope: scope.into(),
            required: false,
            item: Item {
                title: "<zi>t</zi>".into(),
                place: Place::Nsid("a.<zb>".into()),
                lines: vec![("a.<zb>.c".into(), "<zu>do</zu>".into())],
                warning: None,
                tally: Tally { other: vec!["<zs>x</zs>".into()], ..Default::default() },
            },
            detail: Some("<zp>d".into()),
            inner: vec![],
        };
        let two = [row("repo:\"><zb>x"), row("y")];
        let ctx = Ctx { request_uri: "r", csrf: "c", client_id: "x", loopback: true, server_name: "s" };
        let html = consent(&ctx, "d", "h", "repo:\"><zb>x y", &two);
        for bad in ["<zb>", "<zi>", "<zu>", "<zs>", "<zp>d"] {
            assert!(!html.contains(bad), "{bad}: {html}");
        }
        assert!(html.contains("<code class=\"gp\">a.&lt;zb&gt;</code>"), "{html}");
        assert!(html.contains("value=\"repo:&quot;&gt;&lt;zb&gt;x\""), "{html}");
    }

    #[test]
    fn the_raw_scopes_are_at_the_bottom() {
        let scope = format!("atproto {BOARDS}");
        let html = page_for(&scope, &[], Some(&boards_names("Boards")));
        let raw = &html[html.find("<details class=\"raw\">").unwrap()..];
        assert!(raw.starts_with("<details class=\"raw\"><summary>Show requested scopes</summary>"), "{raw}");
        assert!(raw.contains("<li><code>atproto</code></li>"), "{raw}");
        assert!(raw.contains(&format!("<li><code>{}</code></li>", e(BOARDS))), "{raw}");
        assert!(!raw.contains("name=\"scope\""), "{raw}");
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
        let html = signup(&ctx, &f("pds.test", &one));
        assert!(html.contains("<span>.pds.test</span>") && !html.contains("<select"), "{html}");
        let two = ["pds.test".to_string(), "group-a.test".to_string()];
        let html = signup(&ctx, &f("group-a.test", &two));
        assert!(html.contains("<select name=\"domain\""), "{html}");
        assert!(html.contains("<option value=\"group-a.test\" selected>.group-a.test</option>"), "{html}");
        assert!(html.contains("<option value=\"pds.test\">.pds.test</option>"), "{html}");
    }
}
