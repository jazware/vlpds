//! atproto OAuth: end-to-end client flows driven from Rust against an
//! in-process PDS (dev mode). A real client is simulated: P-256 DPoP key,
//! PAR, the browser's login + consent form posts, code exchange, DPoP-bound
//! XRPC calls, refresh rotation, revocation, loopback and confidential
//! (private_key_jwt) clients, TOTP and include: permission sets.

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::elliptic_curve::Generate;
use reqwest::header::HeaderMap;
use serde_json::{json, Value as J};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;

pub(crate) const PASSWORD: &str = "correct horse battery staple";
pub(crate) const REDIRECT: &str = "http://127.0.0.1/cb";
pub(crate) const JWT_BEARER: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const FORM: &str = "application/x-www-form-urlencoded";

fn b64(b: impl AsRef<[u8]>) -> String {
    B64.encode(b)
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn rand_str(n: usize) -> String {
    b64((0..n).map(|_| rand::random::<u8>()).collect::<Vec<u8>>())
}

pub(crate) fn enc(s: &str) -> String {
    vlpds::oauth::util::form_encode_component(s)
}

pub(crate) fn form(pairs: &[(&str, &str)]) -> String {
    pairs.iter().map(|(k, v)| format!("{}={}", enc(k), enc(v))).collect::<Vec<_>>().join("&")
}

pub(crate) struct Srv {
    pub(crate) app: Arc<vlpds::xrpc::App>,
    pub(crate) base: String,
    pub(crate) http: reqwest::Client,
}

pub(crate) async fn spawn() -> Srv {
    spawn_with(|_| {}).await
}

pub(crate) async fn spawn_with(f: impl FnOnce(&mut vlpds::server::Config)) -> Srv {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let mut cfg = vlpds::server::Config { dev_mode: true, public_url: base.clone(), ..Default::default() };
    f(&mut cfg);
    let (app, _) = vlpds::server::spawn(cfg, listener, None).await.unwrap();
    let http = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().unwrap();
    Srv { app, base, http }
}

impl Srv {
    pub(crate) async fn get_json(&self, path: &str) -> J {
        self.http.get(format!("{}{path}", self.base)).send().await.unwrap().json().await.unwrap()
    }

    /// An XRPC call with a password session's access JWT (POST when `body`
    /// is given or `post` is set).
    pub(crate) async fn bearer(&self, jwt: &str, nsid: &str, post: bool, body: Option<J>) -> (u16, J) {
        let url = format!("{}/xrpc/{nsid}", self.base);
        let mut rb = if post || body.is_some() { self.http.post(url) } else { self.http.get(url) }.bearer_auth(jwt);
        if let Some(b) = &body {
            rb = rb.json(b);
        }
        let r = rb.send().await.unwrap();
        (r.status().as_u16(), r.json().await.unwrap_or(J::Null))
    }
}

pub(crate) struct Account {
    pub(crate) did: String,
    pub(crate) handle: String,
    pub(crate) jwt: String,
}

pub(crate) async fn create_account(s: &Srv, name: &str) -> Account {
    let handle = format!("{name}{}.vlpds.test", rand::random::<u32>() % 100000);
    let r = s
        .http
        .post(format!("{}/xrpc/com.atproto.server.createAccount", s.base))
        .json(&json!({"handle": handle, "password": PASSWORD, "email": format!("{name}@example.com")}))
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success(), "createAccount: {}", r.text().await.unwrap());
    let j: J = r.json().await.unwrap();
    Account { did: j["did"].as_str().unwrap().into(), handle, jwt: j["accessJwt"].as_str().unwrap().into() }
}

// ---------- DPoP client ----------

pub(crate) struct DpopKey {
    sk: SigningKey,
    pub(crate) nonce: parking_lot::Mutex<Option<String>>,
}

impl DpopKey {
    pub(crate) fn new() -> DpopKey {
        DpopKey { sk: SigningKey::generate(), nonce: Default::default() }
    }

    fn jwk(&self) -> J {
        let pt = self.sk.verifying_key().to_sec1_point(false);
        json!({"kty": "EC", "crv": "P-256", "x": b64(pt.x().unwrap()), "y": b64(pt.y().unwrap())})
    }

    /// RFC 7638 thumbprint.
    pub(crate) fn jkt(&self) -> String {
        let j = self.jwk();
        let canon = format!(
            r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
            j["x"].as_str().unwrap(),
            j["y"].as_str().unwrap()
        );
        b64(Sha256::digest(canon))
    }

    fn proof_with(&self, htm: &str, htu: &str, ath: Option<&str>, nonce: Option<&str>) -> String {
        let header = json!({"typ": "dpop+jwt", "alg": "ES256", "jwk": self.jwk()});
        let mut payload = json!({"jti": rand_str(16), "htm": htm, "htu": htu, "iat": now()});
        if let Some(n) = nonce {
            payload["nonce"] = json!(n);
        }
        if let Some(t) = ath {
            payload["ath"] = json!(b64(Sha256::digest(t)));
        }
        sign_jwt(&self.sk, &header, &payload)
    }

    pub(crate) fn proof(&self, htm: &str, htu: &str, ath: Option<&str>) -> String {
        let n = self.nonce.lock().clone();
        self.proof_with(htm, htu, ath, n.as_deref())
    }

    pub(crate) fn update_nonce(&self, h: &HeaderMap) {
        if let Some(n) = h.get("dpop-nonce").and_then(|v| v.to_str().ok()) {
            *self.nonce.lock() = Some(n.to_string());
        }
    }
}

pub(crate) fn sign_jwt(sk: &SigningKey, header: &J, payload: &J) -> String {
    let input = format!("{}.{}", b64(serde_json::to_vec(header).unwrap()), b64(serde_json::to_vec(payload).unwrap()));
    let sig: Signature = sk.sign(input.as_bytes());
    format!("{input}.{}", b64(sig.to_bytes()))
}

/// A client signing key and its public JWK (kid "k1").
pub(crate) fn client_key() -> (SigningKey, J) {
    let sk = SigningKey::generate();
    let pt = sk.verifying_key().to_sec1_point(false);
    let jwk = json!({"kty": "EC", "crv": "P-256", "x": b64(pt.x().unwrap()), "y": b64(pt.y().unwrap()), "kid": "k1", "alg": "ES256", "use": "sig"});
    (sk, jwk)
}

/// A private_key_jwt client assertion for `aud`.
pub(crate) fn client_assertion(sk: &SigningKey, client_id: &str, aud: &str) -> String {
    let payload =
        json!({"iss": client_id, "sub": client_id, "aud": aud, "jti": rand_str(12), "iat": now(), "exp": now() + 60});
    sign_jwt(sk, &json!({"alg": "ES256", "kid": "k1", "typ": "JWT"}), &payload)
}

pub(crate) struct Resp {
    pub(crate) status: u16,
    pub(crate) headers: HeaderMap,
    pub(crate) body: J,
}

/// A DPoP request, retried once on use_dpop_nonce (as real clients do).
async fn dpop_send(
    s: &Srv,
    key: &DpopKey,
    method: reqwest::Method,
    url: &str,
    token: Option<&str>,
    build: impl Fn(reqwest::RequestBuilder) -> reqwest::RequestBuilder,
) -> Resp {
    for attempt in 0..2 {
        let mut rb = build(s.http.request(method.clone(), url)).header("dpop", key.proof(method.as_str(), url, token));
        if let Some(t) = token {
            rb = rb.header("authorization", format!("DPoP {t}"));
        }
        let r = match rb.send().await {
            Ok(r) => r,
            // a pooled connection the server closed after refusing a large
            // body early (importRepo over its caps): a GET goes again
            Err(e) if attempt == 0 && method == reqwest::Method::GET && e.is_request() => continue,
            Err(e) => panic!("{url}: {e:?}"),
        };
        let (status, headers) = (r.status().as_u16(), r.headers().clone());
        key.update_nonce(&headers);
        let body: J = r.json().await.unwrap_or(J::Null);
        if attempt == 0 && body["error"] == "use_dpop_nonce" {
            assert!(headers.get("dpop-nonce").is_some(), "use_dpop_nonce without DPoP-Nonce header");
            continue;
        }
        return Resp { status, headers, body };
    }
    unreachable!()
}

/// POST a form to an AS endpoint with DPoP.
pub(crate) async fn as_post(s: &Srv, key: &DpopKey, path: &str, pairs: &[(&str, &str)]) -> Resp {
    let body = form(pairs);
    dpop_send(s, key, reqwest::Method::POST, &format!("{}{path}", s.base), None, |rb| {
        rb.header("content-type", FORM).body(body.clone())
    })
    .await
}

/// DPoP-authenticated XRPC call.
pub(crate) async fn xrpc_dpop(s: &Srv, key: &DpopKey, token: &str, method: &str, nsid: &str, body: Option<J>) -> Resp {
    let m = if method == "GET" { reqwest::Method::GET } else { reqwest::Method::POST };
    dpop_send(s, key, m, &format!("{}/xrpc/{nsid}", s.base), Some(token), |rb| match &body {
        Some(b) => rb.json(b),
        None => rb,
    })
    .await
}

async fn create_post(s: &Srv, key: &DpopKey, token: &str, did: &str, collection: &str) -> Resp {
    let record = match collection {
        "app.bsky.feed.like" => {
            json!({"$type": collection, "subject": {"uri": format!("at://{did}/app.bsky.feed.post/3k2a"), "cid": "bafyreie5737gdxlw5i64vzichcalba3z2v5n6icifvx5xytvske7mr3hpm"}, "createdAt": "2024-01-01T00:00:00.000Z"})
        }
        _ => json!({"$type": collection, "text": "hello from oauth", "createdAt": "2024-01-01T00:00:00.000Z"}),
    };
    xrpc_dpop(
        s,
        key,
        token,
        "POST",
        "com.atproto.repo.createRecord",
        Some(json!({"repo": did, "collection": collection, "record": record})),
    )
    .await
}

// ---------- client + browser simulation ----------

pub(crate) struct Pkce {
    pub(crate) verifier: String,
    pub(crate) challenge: String,
}

pub(crate) fn pkce() -> Pkce {
    let verifier = rand_str(32);
    let challenge = b64(Sha256::digest(&verifier));
    Pkce { verifier, challenge }
}

pub(crate) fn loopback_client_id(scope: &str, redirect: &str) -> String {
    format!("http://localhost?scope={}&redirect_uri={}", enc(scope), enc(redirect))
}

pub(crate) fn hidden_field(html: &str, name: &str) -> Option<String> {
    let pat = format!("name=\"{name}\" value=\"");
    let i = html.find(&pat)? + pat.len();
    Some(html[i..i + html[i..].find('"').unwrap()].replace("&amp;", "&"))
}

pub(crate) fn csrf_of(html: &str) -> String {
    hidden_field(html, "csrf").expect("csrf field")
}

pub(crate) type Page = (u16, HeaderMap, String);

/// Minimal cookie-jar browser.
#[derive(Default)]
pub(crate) struct Browser {
    pub(crate) cookie: Option<String>,
}

impl Browser {
    pub(crate) async fn get(&mut self, s: &Srv, url: &str) -> Page {
        let mut rb = s.http.get(url);
        if let Some(c) = &self.cookie {
            rb = rb.header("cookie", c);
        }
        self.absorb(rb.send().await.unwrap()).await
    }

    pub(crate) async fn post(&mut self, s: &Srv, path: &str, pairs: &[(&str, &str)]) -> Page {
        let mut rb = s.http.post(format!("{}{path}", s.base)).header("content-type", FORM).body(form(pairs));
        if let Some(c) = &self.cookie {
            rb = rb.header("cookie", c);
        }
        self.absorb(rb.send().await.unwrap()).await
    }

    pub(crate) async fn absorb(&mut self, r: reqwest::Response) -> Page {
        let status = r.status().as_u16();
        let headers = r.headers().clone();
        for sc in headers.get_all("set-cookie") {
            let c = sc.to_str().unwrap().split(';').next().unwrap();
            if c.starts_with("vlpds-device=") {
                self.cookie = Some(c.to_string());
            }
        }
        (status, headers, r.text().await.unwrap())
    }

    /// Opens the authorization page of a pushed request.
    pub(crate) async fn authorize(&mut self, s: &Srv, f: &Flow<'_>, request_uri: &str) -> Page {
        self.get(s, &f.authorize_url(s, request_uri)).await
    }

    /// The authorization page's password step.
    pub(crate) async fn sign_in(&mut self, s: &Srv, ru: &str, csrf: &str, identifier: &str, password: &str) -> Page {
        self.post(
            s,
            "/oauth/authorize/sign-in",
            &[
                ("request_uri", ru),
                ("csrf", csrf),
                ("identifier", identifier),
                ("password", password),
                ("action", "sign-in"),
            ],
        )
        .await
    }

    /// The authorization page's second-factor (authenticator or email) step.
    pub(crate) async fn second_factor(&mut self, s: &Srv, ru: &str, csrf: &str, code: &str) -> (u16, String) {
        let (st, _, html) = self
            .post(
                s,
                "/oauth/authorize/sign-in",
                &[("request_uri", ru), ("csrf", csrf), ("step", "2fa"), ("code", code), ("action", "sign-in")],
            )
            .await;
        (st, html)
    }
}

pub(crate) fn location_params(h: &HeaderMap) -> (String, HashMap<String, String>) {
    let loc = h.get("location").expect("location").to_str().unwrap().to_string();
    let (base, q) = loc.split_once(['?', '#']).unwrap_or((&loc, ""));
    (base.to_string(), vlpds::oauth::util::parse_form(q).into_iter().collect())
}

pub(crate) struct Tokens {
    pub(crate) access: String,
    pub(crate) refresh: Option<String>,
    pub(crate) scope: String,
}

pub(crate) struct Flow<'a> {
    pub(crate) client_id: String,
    pub(crate) redirect_uri: String,
    pub(crate) scope: String,
    pub(crate) key: &'a DpopKey,
    pub(crate) extra: Vec<(String, String)>,
}

impl<'a> Flow<'a> {
    pub(crate) fn new(client_id: &str, redirect_uri: &str, scope: &str, key: &'a DpopKey) -> Self {
        Flow { client_id: client_id.into(), redirect_uri: redirect_uri.into(), scope: scope.into(), key, extra: vec![] }
    }

    /// A loopback client (redirect [`REDIRECT`]) declaring and requesting `scope`.
    pub(crate) fn loopback(scope: &str, key: &'a DpopKey) -> Self {
        Flow::new(&loopback_client_id(scope, REDIRECT), REDIRECT, scope, key)
    }

    pub(crate) fn with(mut self, k: &str, v: &str) -> Self {
        self.extra.push((k.into(), v.into()));
        self
    }

    pub(crate) async fn par(&self, s: &Srv, p: &Pkce, state: &str) -> Resp {
        let mut pairs: Vec<(&str, &str)> = vec![
            ("client_id", &self.client_id),
            ("response_type", "code"),
            ("redirect_uri", &self.redirect_uri),
            ("scope", &self.scope),
            ("state", state),
            ("code_challenge", &p.challenge),
            ("code_challenge_method", "S256"),
        ];
        pairs.extend(self.extra.iter().map(|(k, v)| (k.as_str(), v.as_str())));
        as_post(s, self.key, "/oauth/par", &pairs).await
    }

    /// A PAR that must succeed; its request_uri.
    pub(crate) async fn request_uri(&self, s: &Srv, p: &Pkce, state: &str) -> String {
        let par = self.par(s, p, state).await;
        assert_eq!(par.status, 201, "PAR: {}", par.body);
        par.body["request_uri"].as_str().unwrap().to_string()
    }

    pub(crate) fn authorize_url(&self, s: &Srv, request_uri: &str) -> String {
        format!("{}/oauth/authorize?client_id={}&request_uri={}", s.base, enc(&self.client_id), enc(request_uri))
    }
}

/// Full interactive flow: PAR, login, consent; returns the code.
pub(crate) async fn authorize_interactive(s: &Srv, b: &mut Browser, f: &Flow<'_>, acct: &Account, p: &Pkce) -> String {
    let state = rand_str(8);
    let request_uri = f.request_uri(s, p, &state).await;
    let (st, h, body) = browser_consent(s, b, f, acct, &request_uri, &[]).await;
    assert_eq!(st, 303, "{body}");
    let (base, q) = location_params(&h);
    assert_eq!(base, f.redirect_uri.split('?').next().unwrap());
    assert_eq!(q.get("state"), Some(&state));
    assert_eq!(q.get("iss"), Some(&s.base));
    q.get("code").expect("code").clone()
}

/// [`authorize_interactive`] then the code exchange.
pub(crate) async fn grant(s: &Srv, b: &mut Browser, f: &Flow<'_>, acct: &Account) -> Tokens {
    let p = pkce();
    let code = authorize_interactive(s, b, f, acct, &p).await;
    tokens(&exchange(s, f, &code, &p, &[]).await)
}

/// A loopback client authorized for `scope` by `acct`; returns the DPoP key
/// and the access token.
async fn login(s: &Srv, acct: &Account, scope: &str) -> (DpopKey, String) {
    let key = DpopKey::new();
    let t = grant(s, &mut Browser::default(), &Flow::loopback(scope, &key), acct).await;
    assert_eq!(t.scope, scope);
    (key, t.access)
}

/// Browser side of a pushed request: open the authorization page, pick or
/// sign in to `acct`, and post "allow" on the consent page (with `extra`
/// form fields). Returns the consent POST's response.
pub(crate) async fn browser_consent(
    s: &Srv,
    b: &mut Browser,
    f: &Flow<'_>,
    acct: &Account,
    ru: &str,
    extra: &[(&str, &str)],
) -> Page {
    let (st, h, mut html) = b.authorize(s, f, ru).await;
    assert_eq!(st, 200, "{html}");
    let csp = h.get("content-security-policy").unwrap().to_str().unwrap();
    assert!(csp.contains("default-src 'none'") && csp.contains("frame-ancestors 'none'"), "{csp}");
    if html.contains("Choose an account") {
        let did = if html.contains(&acct.did) { acct.did.as_str() } else { "" };
        let (st, _, next) =
            b.post(s, "/oauth/authorize/select", &[("request_uri", ru), ("csrf", &csrf_of(&html)), ("did", did)]).await;
        assert_eq!(st, 200, "{next}");
        html = next;
    }
    if html.contains("name=\"password\"") {
        let (st, _, next) = b.sign_in(s, ru, &csrf_of(&html), &acct.handle, PASSWORD).await;
        assert_eq!(st, 200, "{next}");
        html = next;
    }
    assert!(html.contains("Authorize access"), "expected consent page: {html}");
    let csrf = csrf_of(&html);
    let mut pairs: Vec<(&str, &str)> =
        vec![("request_uri", ru), ("csrf", &csrf), ("did", &acct.did), ("action", "allow")];
    pairs.extend_from_slice(extra);
    b.post(s, "/oauth/authorize/consent", &pairs).await
}

pub(crate) async fn exchange(s: &Srv, f: &Flow<'_>, code: &str, p: &Pkce, extra: &[(&str, &str)]) -> Resp {
    let mut pairs = vec![
        ("grant_type", "authorization_code"),
        ("client_id", f.client_id.as_str()),
        ("code", code),
        ("redirect_uri", f.redirect_uri.as_str()),
        ("code_verifier", p.verifier.as_str()),
    ];
    pairs.extend_from_slice(extra);
    as_post(s, f.key, "/oauth/token", &pairs).await
}

pub(crate) fn tokens(r: &Resp) -> Tokens {
    assert_eq!(r.status, 200, "token: {}", r.body);
    assert_eq!(r.body["token_type"], "DPoP");
    assert!(r.headers.get("dpop-nonce").is_some());
    assert_eq!(r.headers.get("cache-control").unwrap(), "no-store");
    Tokens {
        access: r.body["access_token"].as_str().unwrap().into(),
        refresh: r.body["refresh_token"].as_str().map(String::from),
        scope: r.body["scope"].as_str().unwrap().into(),
    }
}

pub(crate) async fn refresh(s: &Srv, f: &Flow<'_>, rt: &str, extra: &[(&str, &str)]) -> Resp {
    let mut pairs = vec![("grant_type", "refresh_token"), ("client_id", f.client_id.as_str()), ("refresh_token", rt)];
    pairs.extend_from_slice(extra);
    as_post(s, f.key, "/oauth/token", &pairs).await
}

/// Serves a client metadata document built from its own client_id.
pub(crate) async fn serve_metadata(build: impl FnOnce(&str) -> J) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client_id = format!("http://{}/client-metadata.json", listener.local_addr().unwrap());
    let md = build(&client_id);
    let router = axum::Router::new()
        .route("/client-metadata.json", axum::routing::get(move || std::future::ready(axum::Json(md.clone()))));
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    client_id
}

/// Metadata of a confidential web client authenticating with `jwk`.
pub(crate) fn confidential_metadata(id: &str, redirect: &str, jwk: &J) -> J {
    json!({
        "client_id": id,
        "client_name": "Test App",
        "redirect_uris": [redirect],
        "scope": "atproto transition:generic",
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "private_key_jwt",
        "token_endpoint_auth_signing_alg": "ES256",
        "application_type": "web",
        "dpop_bound_access_tokens": true,
        "jwks": {"keys": [jwk]},
    })
}

fn unsecured_jwt(payload: &J) -> String {
    format!(
        "{}.{}.",
        b64(serde_json::to_vec(&json!({"alg": "none"})).unwrap()),
        b64(serde_json::to_vec(payload).unwrap())
    )
}

/// Enables TOTP for `acct`; returns the secret and the step the confirm code
/// spent.
pub(crate) async fn enable_totp(s: &Srv, acct: &Account) -> (Vec<u8>, u64) {
    let (_, setup) = s.bearer(&acct.jwt, "vlpds.server.setupTotp", true, None).await;
    let secret = vlpds::totp::base32_decode(setup["secret"].as_str().unwrap()).unwrap();
    let step = vlpds::totp::step_at(vlpds::totp::now_secs());
    let (st, j) = s
        .bearer(
            &acct.jwt,
            "vlpds.server.confirmTotp",
            true,
            Some(json!({"code": vlpds::totp::code_for_step(&secret, step)})),
        )
        .await;
    assert_eq!(st, 200, "{j}");
    (secret, step)
}

/// Newest dev-mode mail token of `purpose` sent to `email`.
pub(crate) async fn dev_mail_token(s: &Srv, email: &str, purpose: &str) -> String {
    let v: J = s
        .http
        .get(format!("{}/xrpc/vlpds.admin.getDevMail?email={}", s.base, enc(email)))
        .basic_auth("admin", Some("dev-admin-token"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let m = v["messages"].as_array().unwrap().iter().rev().find(|m| m["purpose"] == purpose);
    m.unwrap_or_else(|| panic!("no {purpose} mail to {email}: {v}"))["token"].as_str().unwrap().into()
}

/// The sign-up page's form.
fn sign_up_form<'a>(
    ru: &'a str,
    csrf: &'a str,
    handle: &'a str,
    email: &'a str,
    invite: Option<&'a str>,
) -> Vec<(&'a str, &'a str)> {
    let mut v = vec![
        ("request_uri", ru),
        ("csrf", csrf),
        ("handle", handle),
        ("email", email),
        ("password", PASSWORD),
        ("action", "sign-up"),
    ];
    v.extend(invite.map(|c| ("invite_code", c)));
    v
}

// ---------- tests ----------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn metadata_documents() {
    let s = spawn().await;
    let r = s.http.get(format!("{}/.well-known/oauth-authorization-server", s.base)).send().await.unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(r.headers().get("access-control-allow-origin").unwrap(), "*");
    let m: J = r.json().await.unwrap();
    let has = |k: &str, v: &str| m[k].as_array().unwrap().contains(&json!(v));
    assert_eq!(m["issuer"], s.base);
    assert_eq!(m["require_pushed_authorization_requests"], true);
    assert_eq!(m["authorization_response_iss_parameter_supported"], true);
    assert_eq!(m["client_id_metadata_document_supported"], true);
    assert_eq!(m["pushed_authorization_request_endpoint"], format!("{}/oauth/par", s.base));
    assert!(has("dpop_signing_alg_values_supported", "ES256"));
    assert!(has("token_endpoint_auth_methods_supported", "private_key_jwt"));
    assert!(has("token_endpoint_auth_methods_supported", "none"));
    assert!(has("token_endpoint_auth_signing_alg_values_supported", "ES256"));
    assert!(has("scopes_supported", "atproto"));
    assert_eq!(m["code_challenge_methods_supported"], json!(["S256"]));
    assert_eq!(m["require_request_uri_registration"], true);
    assert_eq!(s.get_json("/.well-known/oauth-protected-resource").await["authorization_servers"], json!([s.base]));
    let jwks = s.get_json("/oauth/jwks").await;
    assert_eq!(jwks["keys"][0]["crv"], "P-256");
    assert!(jwks["keys"][0].get("d").is_none());
    // CORS preflight on the token endpoint
    let r = s.http.request(reqwest::Method::OPTIONS, format!("{}/oauth/token", s.base)).send().await.unwrap();
    assert!(r.headers().get("access-control-allow-headers").unwrap().to_str().unwrap().contains("DPoP"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn full_flow_create_record_refresh_and_revoke() {
    let s = spawn().await;
    let acct = create_account(&s, "alice").await;
    let key = DpopKey::new();
    let scope = "atproto transition:generic";
    let f = Flow::loopback(scope, &key);
    let mut b = Browser::default();
    let p = pkce();
    let code = authorize_interactive(&s, &mut b, &f, &acct, &p).await;
    let post = |tok: String| {
        let (s, key, did) = (&s, &key, acct.did.clone());
        async move { create_post(s, key, &tok, &did, "app.bsky.feed.post").await }
    };

    // wrong verifier fails (and does not burn the code: PKCE checked first)
    let bad = exchange(&s, &f, &code, &pkce(), &[]).await;
    assert_eq!(bad.status, 400);
    assert_eq!(bad.body["error"], "invalid_grant");

    let r = exchange(&s, &f, &code, &p, &[]).await;
    let t = tokens(&r);
    assert_eq!(r.body["sub"], acct.did);
    assert!(t.scope.split(' ').any(|x| x == "atproto"));
    let rt = t.refresh.clone().expect("refresh token");

    // access token is a JWT with the documented claims, bound to our key
    let payload: J = serde_json::from_slice(&B64.decode(t.access.split('.').nth(1).unwrap()).unwrap()).unwrap();
    assert_eq!(payload["sub"], acct.did);
    assert_eq!(payload["cnf"]["jkt"], key.jkt());
    assert_eq!(payload["client_id"], f.client_id);
    assert!(payload["exp"].as_i64().unwrap() - payload["iat"].as_i64().unwrap() <= 1800);
    for c in ["aud", "jti", "scope", "iat"] {
        assert!(payload.get(c).is_some(), "missing {c}");
    }

    let r = post(t.access.clone()).await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert!(r.body["uri"].as_str().unwrap().starts_with(&format!("at://{}/app.bsky.feed.post/", acct.did)));
    assert!(r.headers.get("dpop-nonce").is_some());

    // a Bearer presentation of a DPoP token is rejected
    let r = s
        .http
        .post(format!("{}/xrpc/com.atproto.repo.createRecord", s.base))
        .bearer_auth(&t.access)
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert!(matches!(r.status().as_u16(), 400 | 401), "{}", r.status());

    // code reuse is rejected and revokes the session issued from it
    let replay = exchange(&s, &f, &code, &p, &[]).await;
    assert_eq!(replay.body["error"], "invalid_grant", "{}", replay.body);
    let r = post(t.access.clone()).await;
    assert_eq!(r.status, 401);
    assert_eq!(r.body["error"], "invalid_token");
    assert!(r.headers.get("www-authenticate").unwrap().to_str().unwrap().contains("invalid_token"));
    assert_eq!(refresh(&s, &f, &rt, &[]).await.body["error"], "invalid_grant");

    // new grant: refresh rotation + replay detection
    let t1 = grant(&s, &mut b, &f, &acct).await;
    let rt1 = t1.refresh.clone().unwrap();
    let t2 = tokens(&refresh(&s, &f, &rt1, &[]).await);
    let rt2 = t2.refresh.clone().unwrap();
    assert_ne!(rt1, rt2);
    // the rotated-out access token no longer works; the new one does
    assert_eq!(post(t1.access.clone()).await.status, 401);
    assert_eq!(post(t2.access.clone()).await.status, 200);
    // replaying the old refresh token revokes the whole session
    let replay = refresh(&s, &f, &rt1, &[]).await;
    assert_eq!(replay.body["error"], "invalid_grant");
    assert!(replay.body["error_description"].as_str().unwrap().contains("replayed"));
    assert_eq!(refresh(&s, &f, &rt2, &[]).await.body["error"], "invalid_grant");
    assert_eq!(post(t2.access.clone()).await.status, 401);

    // refresh with a different DPoP key is refused, and so is using the
    // access token with it
    let t3 = grant(&s, &mut b, &f, &acct).await;
    let rt3 = t3.refresh.as_deref().unwrap();
    let other = DpopKey::new();
    assert_eq!(refresh(&s, &Flow::loopback(scope, &other), rt3, &[]).await.status, 400);
    assert_eq!(create_post(&s, &other, &t3.access, &acct.did, "app.bsky.feed.post").await.status, 401);

    // revocation endpoint: revoking the refresh token kills the access token
    assert_eq!(as_post(&s, &key, "/oauth/revoke", &[("client_id", &f.client_id), ("token", rt3)]).await.status, 200);
    assert_eq!(post(t3.access.clone()).await.status, 401);
    // unknown tokens are fine (RFC 7009)
    assert_eq!(
        as_post(&s, &key, "/oauth/revoke", &[("client_id", &f.client_id), ("token", "garbage")]).await.status,
        200
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scope_enforcement() {
    let s = spawn().await;
    let acct = create_account(&s, "bob").await;
    let scope = "atproto repo:app.bsky.feed.like";
    let (key, access) = login(&s, &acct, scope).await;
    let r = create_post(&s, &key, &access, &acct.did, "app.bsky.feed.post").await;
    assert_eq!(r.status, 403, "{}", r.body);
    // the reference's ScopeMissingError, naming the missing scope
    assert_eq!(r.body["error"], "ScopeMissingError");
    assert_eq!(r.body["message"], "Missing required scope \"repo:app.bsky.feed.post?action=create\"");
    let r = create_post(&s, &key, &access, &acct.did, "app.bsky.feed.like").await;
    assert_eq!(r.status, 200, "{}", r.body);

    // scopes not declared by the client are refused at PAR, and "atproto"
    // is required
    for requested in ["atproto transition:generic", "repo:app.bsky.feed.like"] {
        let mut f = Flow::loopback(scope, &key);
        f.scope = requested.into();
        assert_eq!(f.par(&s, &pkce(), "x").await.body["error"], "invalid_scope", "{requested}");
    }
}

/// app.bsky.notification.{register,unregister}Push over OAuth (reference
/// registerPush.ts): the token needs `rpc:{lxm}?aud={serviceDid}#bsky_notif`;
/// without it, 403 ScopeMissingError naming that scope, and nothing is sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn push_registration_rpc_scope() {
    const APPVIEW: &str = "did:web:appview.test";
    const REGISTER: &str = "app.bsky.notification.registerPush";
    const UNREGISTER: &str = "app.bsky.notification.unregisterPush";
    let hits = Arc::new(parking_lot::Mutex::new(Vec::<String>::new()));
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let appview = format!("http://{}", l.local_addr().unwrap());
    let h = hits.clone();
    let router = axum::Router::new().fallback(move |req: axum::extract::Request| {
        h.lock().push(req.uri().path().to_string());
        std::future::ready(axum::http::StatusCode::OK)
    });
    tokio::spawn(async move { axum::serve(l, router).await.unwrap() });
    let s = spawn_with(|c| c.appview = Some((appview, APPVIEW.into()))).await;
    let acct = create_account(&s, "pushy").await;
    let input = |service_did: &str| {
        Some(json!({"serviceDid": service_did, "token": "device-1", "platform": "ios", "appId": "xyz.blueskyweb.app"}))
    };
    let scope_missing = |r: &Resp, scope: &str| {
        assert_eq!(r.status, 403, "{}", r.body);
        assert_eq!(r.body["error"], "ScopeMissingError");
        assert_eq!(r.body["message"], format!("Missing required scope \"{scope}\""));
    };

    // granted for registerPush at the AppView's #bsky_notif only
    let (key, tok) =
        login(&s, &acct, "atproto rpc:app.bsky.notification.registerPush?aud=did:web:appview.test%23bsky_notif").await;
    let r = xrpc_dpop(&s, &key, &tok, "POST", REGISTER, input(APPVIEW)).await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(hits.lock().drain(..).collect::<Vec<_>>(), [format!("/xrpc/{REGISTER}")]);
    let r = xrpc_dpop(&s, &key, &tok, "POST", UNREGISTER, input(APPVIEW)).await;
    scope_missing(&r, "rpc:app.bsky.notification.unregisterPush?aud=did:web:appview.test%23bsky_notif");
    // another service DID is another audience
    let r = xrpc_dpop(&s, &key, &tok, "POST", REGISTER, input("did:web:push.example.com")).await;
    scope_missing(&r, "rpc:app.bsky.notification.registerPush?aud=did:web:push.example.com%23bsky_notif");
    assert!(hits.lock().is_empty());

    // an unrelated scope set allows neither; transition:generic allows both
    let (key, tok) = login(&s, &acct, "atproto repo:app.bsky.feed.like").await;
    for lxm in [REGISTER, UNREGISTER] {
        let r = xrpc_dpop(&s, &key, &tok, "POST", lxm, input(APPVIEW)).await;
        assert_eq!(r.status, 403, "{lxm}: {}", r.body);
        assert_eq!(r.body["error"], "ScopeMissingError");
    }
    assert!(hits.lock().is_empty());
    let (key, tok) = login(&s, &acct, "atproto transition:generic").await;
    for lxm in [REGISTER, UNREGISTER] {
        let r = xrpc_dpop(&s, &key, &tok, "POST", lxm, input(APPVIEW)).await;
        assert_eq!(r.status, 200, "{lxm}: {}", r.body);
    }
    assert_eq!(hits.lock().len(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn par_validation_and_nonces() {
    let s = spawn().await;
    let key = DpopKey::new();
    let cid = loopback_client_id("atproto", REDIRECT);
    let htu = format!("{}/oauth/par", s.base);
    let p = pkce();
    let body = form(&[
        ("client_id", &cid),
        ("response_type", "code"),
        ("redirect_uri", REDIRECT),
        ("scope", "atproto"),
        ("code_challenge", &p.challenge),
        ("code_challenge_method", "S256"),
    ]);
    // (status, DPoP-Nonce, body) of a PAR with this proof
    let raw = |proof: Option<String>, body: String| {
        let mut rb = s.http.post(&htu).header("content-type", FORM).body(body);
        if let Some(p) = proof {
            rb = rb.header("dpop", p);
        }
        async move {
            let r = rb.send().await.unwrap();
            let nonce = r.headers().get("dpop-nonce").map(|v| v.to_str().unwrap().to_string());
            (r.status().as_u16(), nonce, r.json::<J>().await.unwrap())
        }
    };
    let (st, _, j) = raw(None, body.clone()).await;
    assert_eq!((st, j["error"].as_str()), (400, Some("invalid_dpop_proof")), "no DPoP proof");
    // proof without nonce -> use_dpop_nonce + DPoP-Nonce header
    let (st, nonce, j) = raw(Some(key.proof_with("POST", &htu, None, None)), body.clone()).await;
    assert_eq!((st, j["error"].as_str()), (400, Some("use_dpop_nonce")));
    let nonce = nonce.expect("nonce");
    let (_, _, j) = raw(Some(key.proof_with("POST", &htu, None, Some("nope"))), body.clone()).await;
    assert_eq!(j["error"], "use_dpop_nonce", "bogus nonce");
    let (_, _, j) =
        raw(Some(key.proof_with("POST", &format!("{}/oauth/token", s.base), None, Some(&nonce))), body.clone()).await;
    assert_eq!(j["error"], "invalid_dpop_proof", "proof for the wrong URL");
    // good proof; then replaying the exact same proof is rejected
    let proof = key.proof_with("POST", &htu, None, Some(&nonce));
    let (st, _, j) = raw(Some(proof.clone()), body.clone()).await;
    assert_eq!(st, 201);
    assert!(j["request_uri"].as_str().unwrap().starts_with("urn:ietf:params:oauth:request_uri:"));
    assert!(j["expires_in"].as_i64().unwrap() > 0);
    let (_, _, j) = raw(Some(proof), body.replace(&enc(&p.challenge), &enc(&pkce().challenge))).await;
    assert_eq!(j["error"], "invalid_dpop_proof");

    // code_challenge reuse is refused
    *key.nonce.lock() = Some(nonce.clone());
    let f = Flow::loopback("atproto", &key);
    assert_eq!(f.par(&s, &p, "x").await.body["error"], "invalid_request");
    // PKCE required, S256 only
    let base =
        [("client_id", cid.as_str()), ("response_type", "code"), ("redirect_uri", REDIRECT), ("scope", "atproto")];
    assert_eq!(as_post(&s, &key, "/oauth/par", &base).await.body["error"], "invalid_request");
    let p3 = pkce();
    let plain =
        [&base[..], &[("code_challenge", p3.challenge.as_str()), ("code_challenge_method", "plain")][..]].concat();
    assert_eq!(as_post(&s, &key, "/oauth/par", &plain).await.body["error"], "invalid_request");
    // unregistered redirect_uri
    let mut f = Flow::loopback("atproto", &key);
    f.redirect_uri = "http://127.0.0.1/elsewhere".into();
    assert_eq!(f.par(&s, &pkce(), "x").await.body["error"], "invalid_request");
    // invalid login_hint
    let f = Flow::loopback("atproto", &key).with("login_hint", "not a handle!");
    assert_eq!(f.par(&s, &pkce(), "x").await.body["error"], "invalid_request");
    // invalid client ids
    let f = Flow::new("http://localhost/path", REDIRECT, "atproto", &key);
    assert_eq!(f.par(&s, &pkce(), "x").await.body["error"], "invalid_client_metadata");

    // the authorization endpoint refuses requests that skip PAR
    let (st, _, _) = Browser::default()
        .get(&s, &format!("{}/oauth/authorize?client_id={}&response_type=code", s.base, enc(&cid)))
        .await;
    assert_eq!(st, 400);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn resource_dpop_checks() {
    let s = spawn().await;
    let acct = create_account(&s, "carol").await;
    let (key, access) = login(&s, &acct, "atproto transition:generic").await;
    let url = format!("{}/xrpc/com.atproto.repo.createRecord", s.base);
    let rec = json!({"repo": acct.did, "collection": "app.bsky.feed.post", "record": {"$type": "app.bsky.feed.post", "text": "x", "createdAt": "2024-01-01T00:00:00.000Z"}});
    let send = |proof: Option<String>| {
        let mut rb = s.http.post(&url).header("authorization", format!("DPoP {access}")).json(&rec);
        if let Some(p) = proof {
            rb = rb.header("dpop", p);
        }
        async move { rb.send().await.unwrap() }
    };
    let www = |r: &reqwest::Response| r.headers().get("www-authenticate").unwrap().to_str().unwrap().to_string();
    // missing proof
    let r = send(None).await;
    assert_eq!(r.status(), 401);
    assert!(www(&r).starts_with("DPoP"));
    // no nonce -> 401 use_dpop_nonce with WWW-Authenticate + DPoP-Nonce
    let r = send(Some(key.proof_with("POST", &url, Some(&access), None))).await;
    assert_eq!(r.status(), 401);
    assert!(www(&r).contains("error=\"use_dpop_nonce\""), "{}", www(&r));
    let nonce = r.headers().get("dpop-nonce").unwrap().to_str().unwrap().to_string();
    assert!(r.headers().get("access-control-expose-headers").unwrap().to_str().unwrap().contains("DPoP-Nonce"));
    let n = Some(nonce.as_str());
    // wrong ath
    let r = send(Some(key.proof_with("POST", &url, Some("other-token"), n))).await;
    assert_eq!(r.status(), 401);
    assert!(www(&r).contains("invalid_dpop_proof"));
    // wrong htm
    assert_eq!(send(Some(key.proof_with("GET", &url, Some(&access), n))).await.status(), 401);
    // htu with a query string is accepted (legacy), different path is not
    assert_eq!(send(Some(key.proof_with("POST", &format!("{url}?x=1"), Some(&access), n))).await.status(), 200);
    assert_eq!(
        send(Some(key.proof_with("POST", &format!("{}/xrpc/other", s.base), Some(&access), n))).await.status(),
        401
    );
    // replayed proof
    let proof = key.proof_with("POST", &url, Some(&access), n);
    assert_eq!(send(Some(proof.clone())).await.status(), 200);
    assert_eq!(send(Some(proof)).await.status(), 401);
    // resource-request claims live in the owner's memory only (no log write
    // per request; HA notes in src/oauth/mod.rs)
    let part = s.app.partition(&acct.did).ok().unwrap();
    let prefix = vlpds::state::private_key(&acct.did, vlpds::oauth::util::REPLAY_ROW);
    let mut rows = part.db.scan(prefix.clone()..vlsync_store::keys::prefix_end(&prefix)).await.unwrap();
    assert!(rows.next().await.unwrap().is_none(), "resource-request DPoP claim persisted");
    // stale iat, wrong typ
    let ath = b64(Sha256::digest(&access));
    for (typ, iat) in [("dpop+jwt", now() - 3600), ("JWT", now())] {
        let header = json!({"typ": typ, "alg": "ES256", "jwk": key.jwk()});
        let payload = json!({"jti": rand_str(8), "htm": "POST", "htu": url, "iat": iat, "nonce": nonce, "ath": ath});
        assert_eq!(send(Some(sign_jwt(&key.sk, &header, &payload))).await.status(), 401, "{typ} {iat}");
    }
    // tampered access token
    let mut parts: Vec<String> = access.split('.').map(String::from).collect();
    let mut claims: J = serde_json::from_slice(&B64.decode(&parts[1]).unwrap()).unwrap();
    claims["scope"] = json!("atproto transition:generic transition:chat.bsky");
    parts[1] = b64(serde_json::to_vec(&claims).unwrap());
    let r = xrpc_dpop(&s, &key, &parts.join("."), "POST", "com.atproto.repo.createRecord", Some(rec.clone())).await;
    assert_eq!(r.status, 401);
    assert_eq!(r.body["error"], "invalid_token");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn account_chooser_prompts_and_denial() {
    let s = spawn().await;
    let a1 = create_account(&s, "dave").await;
    let a2 = create_account(&s, "erin").await;
    let key = DpopKey::new();
    let f = Flow::loopback("atproto", &key);
    let mut b = Browser::default();
    authorize_interactive(&s, &mut b, &f, &a1, &pkce()).await;
    // next time the device remembers a1: the chooser is shown
    let ru = f.request_uri(&s, &pkce(), "s").await;
    let (st, _, html) = b.authorize(&s, &f, &ru).await;
    assert_eq!(st, 200);
    assert!(html.contains("Choose an account") && html.contains(&a1.handle), "{html}");
    let csrf = csrf_of(&html);
    // CSRF: a post without the token is refused
    let (st, _, _) = b.post(&s, "/oauth/authorize/select", &[("request_uri", &ru), ("did", &a1.did)]).await;
    assert_eq!(st, 403);
    // choose "another account" -> login form -> sign in as a2 -> consent
    let (st, _, html) =
        b.post(&s, "/oauth/authorize/select", &[("request_uri", &ru), ("csrf", &csrf), ("did", "")]).await;
    assert_eq!(st, 200);
    assert!(html.contains("name=\"password\""));
    let (st, _, html) = b.sign_in(&s, &ru, &csrf, &a2.handle, "wrong").await;
    assert_eq!(st, 401);
    assert!(html.contains("Invalid handle or password"));
    let (_, _, html) = b.sign_in(&s, &ru, &csrf, &a2.handle, PASSWORD).await;
    assert!(html.contains("Authorize access") && html.contains(&a2.handle));
    // deny -> access_denied redirect with state + iss
    let (st, h, _) = b
        .post(
            &s,
            "/oauth/authorize/consent",
            &[("request_uri", &ru), ("csrf", &csrf), ("did", &a2.did), ("action", "deny")],
        )
        .await;
    assert_eq!(st, 303);
    let (_, q) = location_params(&h);
    assert_eq!(q["error"], "access_denied");
    assert_eq!(q["state"], "s");
    assert_eq!(q["iss"], s.base);
    // the request is gone afterwards
    let (st, _, html) = b.authorize(&s, &f, &ru).await;
    assert_ne!(st, 200, "{html}");

    // login_hint selects the matching signed-in account directly (consent page)
    let f = Flow::loopback("atproto", &key).with("login_hint", &a2.handle);
    let ru = f.request_uri(&s, &pkce(), "s2").await;
    let (_, _, html) = b.authorize(&s, &f, &ru).await;
    assert!(html.contains("Authorize access") && html.contains(&a2.handle), "{html}");

    // public clients are forced to prompt=consent, so prompt=login is
    // overridden; the chooser is shown instead (as in the reference AS)
    let f = Flow::loopback("atproto", &key).with("prompt", "login");
    let ru = f.request_uri(&s, &pkce(), "s3").await;
    assert_eq!(b.authorize(&s, &f, &ru).await.0, 200);

    // prompt=none is not allowed for public clients
    let f = Flow::loopback("atproto", &key).with("prompt", "none");
    assert_eq!(f.par(&s, &pkce(), "s4").await.body["error"], "consent_required");

    // a request started on one device can't be continued on another
    let f = Flow::loopback("atproto", &key);
    let ru = f.request_uri(&s, &pkce(), "s5").await;
    b.authorize(&s, &f, &ru).await;
    let (st, h, _) = Browser::default().authorize(&s, &f, &ru).await;
    assert_eq!(st, 303);
    assert_eq!(location_params(&h).1["error"], "access_denied");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn totp_prompt_on_login() {
    let s = spawn().await;
    let acct = create_account(&s, "frank").await;
    let (secret, step) = enable_totp(&s, &acct).await;
    let key = DpopKey::new();
    let f = Flow::loopback("atproto", &key);
    let mut b = Browser::default();
    let ru = f.request_uri(&s, &pkce(), "t").await;
    let csrf = csrf_of(&b.authorize(&s, &f, &ru).await.2);
    let (st, _, html) = b.sign_in(&s, &ru, &csrf, &acct.handle, PASSWORD).await;
    assert_eq!(st, 200);
    assert!(html.contains("name=\"code\"") && html.contains("Two-factor"), "expected TOTP prompt: {html}");
    let (st, html) = b.second_factor(&s, &ru, &csrf, "000000").await;
    assert_eq!(st, 401);
    assert!(html.contains("Invalid authenticator code"));
    // right code (next step: the confirm step's code is spent)
    let (st, html) = b.second_factor(&s, &ru, &csrf, &vlpds::totp::code_for_step(&secret, step + 1)).await;
    assert_eq!(st, 200, "{html}");
    assert!(html.contains("Authorize access"), "{html}");
}

/// The reference's email factor on the sign-in page
/// (SecondAuthenticationFactorRequiredError 'emailOtp'): the password step
/// mails a code and asks for it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn email_code_prompt_on_login() {
    let s = spawn().await;
    let acct = create_account(&s, "emma").await;
    let email = "emma@example.com";
    let (st, _) = s.bearer(&acct.jwt, "com.atproto.server.requestEmailConfirmation", true, Some(json!({}))).await;
    assert_eq!(st, 200);
    let tok = dev_mail_token(&s, email, "confirm_email").await;
    let (st, j) =
        s.bearer(&acct.jwt, "com.atproto.server.confirmEmail", true, Some(json!({"email": email, "token": tok}))).await;
    assert_eq!(st, 200, "{j}");
    let (st, j) = s
        .bearer(
            &acct.jwt,
            "com.atproto.server.updateEmail",
            true,
            Some(json!({"email": email, "emailAuthFactor": true})),
        )
        .await;
    assert_eq!(st, 200, "{j}");

    let key = DpopKey::new();
    let f = Flow::loopback("atproto", &key);
    let mut b = Browser::default();
    let ru = f.request_uri(&s, &pkce(), "t").await;
    let csrf = csrf_of(&b.authorize(&s, &f, &ru).await.2);
    let (st, _, html) = b.sign_in(&s, &ru, &csrf, &acct.handle, PASSWORD).await;
    assert_eq!(st, 200);
    assert!(
        html.contains("name=\"code\"") && html.contains("We sent a sign-in code to <b>e***a@e***m</b>"),
        "expected email code prompt: {html}"
    );
    let code = dev_mail_token(&s, email, "auth_factor").await;
    let (st, html) = b.second_factor(&s, &ru, &csrf, "AAAAA-AAAAA").await;
    assert_eq!(st, 401);
    assert!(html.contains("Invalid sign-in code") && html.contains("name=\"code\""), "{html}");
    let (st, html) = b.second_factor(&s, &ru, &csrf, &code).await;
    assert_eq!(st, 200, "{html}");
    assert!(html.contains("Authorize access"), "{html}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn session_management() {
    let s = spawn().await;
    let acct = create_account(&s, "grace").await;
    let key = DpopKey::new();
    let f = Flow::loopback("atproto transition:generic", &key);
    let mut b = Browser::default();
    let t = grant(&s, &mut b, &f, &acct).await;

    // XRPC: list + revoke (full account session required)
    let (_, list) = s.bearer(&acct.jwt, "vlpds.oauth.listSessions", false, None).await;
    let sessions = list["sessions"].as_array().unwrap();
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0]["clientId"], f.client_id);
    // an OAuth token can't list/revoke grants
    assert_eq!(xrpc_dpop(&s, &key, &t.access, "GET", "vlpds.oauth.listSessions", None).await.status, 403);
    let (st, _) = s.bearer(&acct.jwt, "vlpds.oauth.revokeSession", true, Some(json!({"id": sessions[0]["id"]}))).await;
    assert_eq!(st, 200);
    assert_eq!(create_post(&s, &key, &t.access, &acct.did, "app.bsky.feed.post").await.status, 401);

    // UI: /oauth/account lists the grant and revokes it
    let t = grant(&s, &mut b, &f, &acct).await;
    let (st, h, html) = b.get(&s, &format!("{}/oauth/account", s.base)).await;
    assert_eq!(st, 200);
    assert!(h.get("content-security-policy").is_some());
    assert!(html.contains("Connected apps") && html.contains(&acct.handle), "{html}");
    let sid = hidden_field(&html, "session").unwrap();
    let csrf = csrf_of(&html);
    let (st, _, _) = b.post(&s, "/oauth/account/revoke", &[("did", &acct.did), ("session", &sid)]).await;
    assert_eq!(st, 403, "csrf required");
    let (st, h, _) =
        b.post(&s, "/oauth/account/revoke", &[("csrf", &csrf), ("did", &acct.did), ("session", &sid)]).await;
    assert_eq!(st, 303);
    assert_eq!(h.get("location").unwrap(), "/oauth/account");
    assert_eq!(create_post(&s, &key, &t.access, &acct.did, "app.bsky.feed.post").await.status, 401);

    // a fresh browser has to sign in on /oauth/account
    let mut b2 = Browser::default();
    let (_, _, html) = b2.get(&s, &format!("{}/oauth/account", s.base)).await;
    assert!(html.contains("name=\"password\""));
    let (st, h, _) = b2
        .post(
            &s,
            "/oauth/account/sign-in",
            &[("csrf", &csrf_of(&html)), ("identifier", &acct.handle), ("password", PASSWORD)],
        )
        .await;
    assert_eq!(st, 303);
    assert_eq!(h.get("location").unwrap(), "/oauth/account");
    let (_, _, html) = b2.get(&s, &format!("{}/oauth/account", s.base)).await;
    assert!(html.contains("Connected apps"));
}

/// Confidential client: discoverable client metadata served over http by a
/// local server (dev mode allows http + private addresses), private_key_jwt
/// client authentication, remembered consent and prompt=none.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn confidential_client_private_key_jwt() {
    let s = spawn().await;
    let acct = create_account(&s, "heidi").await;
    let (client_sk, jwk) = client_key();
    let redirect = "https://app.example.com/callback";
    let client_id = serve_metadata(|id| confidential_metadata(id, redirect, &jwk)).await;
    let assertion = |aud: &str| client_assertion(&client_sk, &client_id, aud);
    let key = DpopKey::new();
    let mut f = Flow::new(&client_id, redirect, "atproto transition:generic", &key)
        .with("client_assertion_type", JWT_BEARER)
        .with("client_assertion", &assertion(&s.base));
    let mut b = Browser::default();
    let p = pkce();
    let code = authorize_interactive(&s, &mut b, &f, &acct, &p).await;

    // token request without client authentication is refused
    assert_eq!(exchange(&s, &f, &code, &p, &[]).await.status, 400);
    let bad = assertion("https://elsewhere.example");
    let r = exchange(&s, &f, &code, &p, &[("client_assertion_type", JWT_BEARER), ("client_assertion", &bad)]).await;
    assert_eq!(r.body["error"], "invalid_client", "wrong audience");
    let good = assertion(&s.base);
    let auth = [("client_assertion_type", JWT_BEARER), ("client_assertion", good.as_str())];
    let t = tokens(&exchange(&s, &f, &code, &p, &auth).await);
    let rt = t.refresh.as_deref().unwrap();
    // assertion jti replay is refused
    assert_eq!(refresh(&s, &f, rt, &auth).await.body["error"], "invalid_client");
    let a2 = assertion(&s.base);
    let t2 = tokens(&refresh(&s, &f, rt, &[("client_assertion_type", JWT_BEARER), ("client_assertion", &a2)]).await);
    assert_eq!(create_post(&s, &key, &t2.access, &acct.did, "app.bsky.feed.post").await.status, 200);

    // consent is remembered for confidential clients: prompt=none issues a
    // code without any UI
    f.extra[1].1 = assertion(&s.base);
    f.extra.push(("prompt".into(), "none".into()));
    let ru = f.request_uri(&s, &pkce(), "silent").await;
    let (st, h, _) = b.authorize(&s, &f, &ru).await;
    assert_eq!(st, 303);
    let (_, q) = location_params(&h);
    assert!(q.contains_key("code"), "{q:?}");
    assert_eq!(q["state"], "silent");
    // prompt=none from a fresh device: login_required
    f.extra[1].1 = assertion(&s.base);
    let ru = f.request_uri(&s, &pkce(), "silent2").await;
    let (st, h, _) = Browser::default().authorize(&s, &f, &ru).await;
    assert_eq!(st, 303);
    assert_eq!(location_params(&h).1["error"], "login_required");
}

/// include: scopes resolve a permission-set lexicon (published by an account
/// on this PDS; the NSID authority's DNS lookup is pinned) and are expanded
/// into granular repo permissions in the token.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn include_permission_set() {
    let s = spawn().await;
    let publisher = create_account(&s, "lexpub").await;
    let user = create_account(&s, "ivan").await;
    let nsid = "com.example.vlpdstest.basicPerms";
    let lex = json!({
        "$type": "com.atproto.lexicon.schema",
        "lexicon": 1,
        "id": nsid,
        "defs": {"main": {
            "type": "permission-set",
            "title": "Basic test permissions",
            "detail": "Create things",
            "permissions": [
                {"type": "permission", "resource": "repo", "collection": ["com.example.vlpdstest.thing"]},
                {"type": "permission", "resource": "repo", "collection": ["app.bsky.feed.post"]},
            ],
        }},
    });
    let body = json!({"repo": publisher.did, "collection": "com.atproto.lexicon.schema", "rkey": nsid, "record": lex, "validate": false});
    let (st, j) = s.bearer(&publisher.jwt, "com.atproto.repo.createRecord", true, Some(body)).await;
    assert_eq!(st, 200, "{j}");
    vlpds::oauth::lexicon::override_authority(&vlpds::oauth::lexicon::nsid_authority(nsid), &publisher.did);

    // the published record verifies through the network proof path too
    let car = s
        .http
        .get(format!(
            "{}/xrpc/com.atproto.sync.getRecord?did={}&collection=com.atproto.lexicon.schema&rkey={nsid}",
            s.base, publisher.did
        ))
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    let path = format!("com.atproto.lexicon.schema/{nsid}");
    let acct = s.app.account(&publisher.did).await.ok().unwrap();
    let rec = vlpds::oauth::lexicon::verify_record_proof(&car, &publisher.did, &acct.signing_pubkey, &path).unwrap();
    assert_eq!(rec["id"], nsid);
    let other = vlsync_atproto::crypto::Keypair::generate();
    assert!(vlpds::oauth::lexicon::verify_record_proof(&car, &publisher.did, &other.public_multibase(), &path).is_err());

    let key = DpopKey::new();
    let f = Flow::loopback(&format!("atproto include:{nsid}"), &key);
    let mut b = Browser::default();
    let p = pkce();
    let ru = f.request_uri(&s, &p, "inc").await;
    let csrf = csrf_of(&b.authorize(&s, &f, &ru).await.2);
    let (_, _, html) = b.sign_in(&s, &ru, &csrf, &user.handle, PASSWORD).await;
    assert!(html.contains("Basic test permissions"), "consent should show the permission set: {html}");
    let (_, h, _) = b
        .post(
            &s,
            "/oauth/authorize/consent",
            &[("request_uri", &ru), ("csrf", &csrf), ("did", &user.did), ("action", "allow")],
        )
        .await;
    let t = tokens(&exchange(&s, &f, &location_params(&h).1["code"], &p, &[]).await);
    // only the permission under the set's own NSID group is granted
    assert_eq!(t.scope, "repo:com.example.vlpdstest.thing atproto");
    assert_eq!(create_post(&s, &key, &t.access, &user.did, "app.bsky.feed.post").await.status, 403);
    assert_eq!(create_post(&s, &key, &t.access, &user.did, "com.example.vlpdstest.thing").await.status, 200);

    // an include: that does not resolve is refused at PAR
    let f2 = Flow::loopback("atproto include:com.example.vlpdstest.missing", &key);
    assert_eq!(f2.par(&s, &pkce(), "x").await.body["error"], "invalid_scope");
}

/// Wrong authenticator codes: a few are fine, three drop the pending sign-in
/// (password again), and five in a row lock the account's factor for both
/// OAuth and createSession, persisted in its TOTP state.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn totp_brute_force_lockout() {
    let s = spawn().await;
    let acct = create_account(&s, "mallory").await;
    let (secret, step) = enable_totp(&s, &acct).await;
    let key = DpopKey::new();
    let f = Flow::loopback("atproto", &key);
    let mut b = Browser::default();
    let ru = f.request_uri(&s, &pkce(), "t").await;
    let csrf = csrf_of(&b.authorize(&s, &f, &ru).await.2);

    let (st, _, html) = b.sign_in(&s, &ru, &csrf, &acct.handle, PASSWORD).await;
    assert_eq!(st, 200, "{html}");
    for _ in 0..2 {
        let (st, html) = b.second_factor(&s, &ru, &csrf, "000000").await;
        assert_eq!(st, 401);
        assert!(html.contains("Invalid authenticator code") && html.contains("name=\"code\""), "{html}");
    }
    // third wrong code on this pending sign-in: back to the password step
    let (st, html) = b.second_factor(&s, &ru, &csrf, "000000").await;
    assert_eq!(st, 429, "{html}");
    assert!(html.contains("Too many invalid authenticator codes"), "{html}");
    assert!(!html.contains("name=\"code\""), "{html}");
    // the pending step is gone: a right code alone no longer signs in
    let good = vlpds::totp::code_for_step(&secret, step + 1);
    let (st, html) = b.second_factor(&s, &ru, &csrf, &good).await;
    assert_eq!(st, 401);
    assert!(html.contains("timed out"), "{html}");

    // password again; the account counter is at 3, two more lock it
    assert_eq!(b.sign_in(&s, &ru, &csrf, &acct.handle, PASSWORD).await.0, 200);
    assert_eq!(b.second_factor(&s, &ru, &csrf, "111111").await.0, 401);
    let (st, html) = b.second_factor(&s, &ru, &csrf, "222222").await;
    assert_eq!(st, 429, "{html}");
    let Ok(st) = vlpds::xrpc::mfa::load(&s.app, &acct.did).await else { panic!("load the lockout") };
    assert_eq!(st.failures, vlpds::totp::MAX_FAILURES);
    assert!(st.locked_until > vlpds::totp::now_secs(), "lockout persisted");

    // locked: the password step itself is refused, and so is createSession
    // with a right code (shared counter)
    let (st, _, html) = b.sign_in(&s, &ru, &csrf, &acct.handle, PASSWORD).await;
    assert_eq!(st, 429, "{html}");
    let r = s
        .http
        .post(format!("{}/xrpc/com.atproto.server.createSession", s.base))
        .json(&json!({"identifier": acct.handle, "password": PASSWORD, "authFactorToken": good}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 429);
    assert_eq!(r.json::<J>().await.unwrap()["error"], "RateLimitExceeded");
}

/// `/oauth/account?error=` only maps fixed codes to fixed messages; sign-in
/// failures redirect with a code.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn account_page_error_codes() {
    let s = spawn().await;
    let acct = create_account(&s, "ivan").await;
    let mut b = Browser::default();
    let evil = enc("<b>Your account is compromised, call 555-0100</b>");
    let (_, _, html) = b.get(&s, &format!("{}/oauth/account?add=1&error={evil}", s.base)).await;
    assert!(!html.contains("compromised") && !html.contains("555-0100"), "{html}");
    let (_, _, html) = b.get(&s, &format!("{}/oauth/account?add=1&error=bad_code", s.base)).await;
    assert!(html.contains("Invalid authenticator code"), "{html}");

    let (st, h, _) = b
        .post(
            &s,
            "/oauth/account/sign-in",
            &[("csrf", &csrf_of(&html)), ("identifier", &acct.handle), ("password", "wrong")],
        )
        .await;
    assert_eq!(st, 303);
    assert_eq!(h.get("location").unwrap(), "/oauth/account?add=1&error=invalid");
    let (_, _, html) = b.get(&s, &format!("{}/oauth/account?add=1&error=invalid", s.base)).await;
    assert!(html.contains("Invalid handle or password"), "{html}");
}

/// OAuth sign-in posts share createSession's identifier + IP buckets (30 per
/// 5 min), checked before any password hashing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sign_in_rate_limited() {
    let s = spawn().await;
    let mut b = Browser::default();
    let (_, _, html) = b.get(&s, &format!("{}/oauth/account", s.base)).await;
    let csrf = csrf_of(&html);
    let form = [("csrf", csrf.as_str()), ("identifier", "ghost.vlpds.test"), ("password", "x")];
    for _ in 0..30 {
        let (_, h, _) = b.post(&s, "/oauth/account/sign-in", &form).await;
        assert_eq!(h.get("location").unwrap(), "/oauth/account?add=1&error=invalid");
    }
    let (_, h, _) = b.post(&s, "/oauth/account/sign-in", &form).await;
    assert_eq!(h.get("location").unwrap(), "/oauth/account?add=1&error=rate_limited");
    let (_, _, html) = b.get(&s, &format!("{}/oauth/account?add=1&error=rate_limited", s.base)).await;
    assert!(html.contains("Too many sign-in attempts"), "{html}");
}

/// OAuth sign-up posts spend createAccount's per-IP bucket, as the XRPC does.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sign_up_rate_limited() {
    let s = spawn().await;
    let d: vlpds::ratelimit::config::Doc =
        serde_json::from_value(json!({"limiters": {"com.atproto.server.createAccount-0": {"points": 3}}})).unwrap();
    s.app.ratelimit.install(vlpds::ratelimit::config::compile(Some(&d)).unwrap());
    let key = DpopKey::new();
    let f = Flow::loopback("atproto", &key).with("prompt", "create");
    let mut b = Browser::default();
    let ru = f.request_uri(&s, &pkce(), "su").await;
    let csrf = csrf_of(&b.authorize(&s, &f, &ru).await.2);
    let form = sign_up_form(&ru, &csrf, "no spaces", "x@example.com", None);
    for _ in 0..3 {
        let (st, _, html) = b.post(&s, "/oauth/authorize/sign-up", &form).await;
        assert_eq!(st, 400, "{html}");
    }
    let (st, _, html) = b.post(&s, "/oauth/authorize/sign-up", &form).await;
    assert_eq!(st, 429, "{html}");
    assert!(html.contains("Too many sign-up attempts"), "{html}");
}

/// The email factor over its recipient's mail budget: rate_limited, not a
/// prompt for a code that never comes (nor a wrong-code strike).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn email_code_over_mail_budget_is_rate_limited() {
    let s = spawn().await;
    let acct = create_account(&s, "emil").await;
    let email = "emil@example.com";
    s.bearer(&acct.jwt, "com.atproto.server.requestEmailConfirmation", true, Some(json!({}))).await;
    let tok = dev_mail_token(&s, email, "confirm_email").await;
    let (st, j) =
        s.bearer(&acct.jwt, "com.atproto.server.confirmEmail", true, Some(json!({"email": email, "token": tok}))).await;
    assert_eq!(st, 200, "{j}");
    let (st, j) = s
        .bearer(
            &acct.jwt,
            "com.atproto.server.updateEmail",
            true,
            Some(json!({"email": email, "emailAuthFactor": true})),
        )
        .await;
    assert_eq!(st, 200, "{j}");
    // the confirmation mail spent the hour's budget
    let d: vlpds::ratelimit::config::Doc =
        serde_json::from_value(json!({"limiters": {"mail-recipient-hour": {"points": 1}}})).unwrap();
    s.app.ratelimit.install(vlpds::ratelimit::config::compile(Some(&d)).unwrap());

    let mut b = Browser::default();
    let (_, _, html) = b.get(&s, &format!("{}/oauth/account", s.base)).await;
    let form = [("csrf", csrf_of(&html)), ("identifier", acct.handle.clone()), ("password", PASSWORD.to_string())];
    let form: Vec<(&str, &str)> = form.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let (_, h, _) = b.post(&s, "/oauth/account/sign-in", &form).await;
    assert_eq!(h.get("location").unwrap(), "/oauth/account?add=1&error=rate_limited");
}

// ---------- JAR, response modes, prompt=create, scope narrowing, GC ----------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn jar_request_objects() {
    let s = spawn().await;
    let acct = create_account(&s, "jar").await;
    let (client_sk, jwk) = client_key();
    let redirect = "https://app.example.com/callback";
    let client_id = serve_metadata(|id| confidential_metadata(id, redirect, &jwk)).await;
    let key = DpopKey::new();
    let p = pkce();
    let claims = || {
        json!({
            "iss": client_id, "aud": s.base, "iat": now(), "jti": rand_str(12),
            "client_id": client_id, "response_type": "code", "redirect_uri": redirect,
            "scope": "atproto transition:generic", "state": "inner",
            "code_challenge": p.challenge, "code_challenge_method": "S256",
        })
    };
    let jar_header = json!({"alg": "ES256", "kid": "k1", "typ": "oauth-authz-req+jwt"});
    let jar = |payload: &J| sign_jwt(&client_sk, &jar_header, payload);
    let par = |request: String| {
        let a = client_assertion(&client_sk, &client_id, &s.base);
        let (s, key, client_id) = (&s, &key, client_id.clone());
        async move {
            // "state" is ignored: only the request object's parameters count
            as_post(
                s,
                key,
                "/oauth/par",
                &[
                    ("client_id", &client_id),
                    ("client_assertion_type", JWT_BEARER),
                    ("client_assertion", &a),
                    ("request", &request),
                    ("state", "outer"),
                ],
            )
            .await
        }
    };
    let expect_invalid = |r: Resp, needle: &str| {
        assert_eq!(r.status, 400, "{}", r.body);
        assert_eq!(r.body["error"], "invalid_request", "{}", r.body);
        let d = r.body["error_description"].as_str().unwrap();
        assert!(d.contains(needle), "{needle:?} not in {d:?}");
    };
    let with = |k: &str, v: Option<J>| {
        let mut c = claims();
        match v {
            Some(v) => c[k] = v,
            None => drop(c.as_object_mut().unwrap().remove(k)),
        }
        jar(&c)
    };

    expect_invalid(par(with("aud", Some(json!("https://elsewhere.example")))).await, "\"aud\"");
    expect_invalid(par(with("iat", Some(json!(now() - 120)))).await, "\"iat\"");
    expect_invalid(par(with("jti", None)).await, "\"jti\"");
    expect_invalid(par(with("iss", Some(json!("https://someone.else/client.json")))).await, "\"iss\"");
    let other = SigningKey::generate();
    expect_invalid(par(sign_jwt(&other, &jar_header, &claims())).await, "signature verification failed");
    expect_invalid(par(unsecured_jwt(&claims())).await, "unsecured");
    expect_invalid(par(with("client_id", Some(json!("http://localhost")))).await, "does not match");
    expect_invalid(par(with("client_id", None)).await, "client_id");
    expect_invalid(par("not-a-jwt".into()).await, "Invalid \"request\" object");

    // a valid request object; its parameters (state=inner) win
    let good = jar(&claims());
    let r = par(good.clone()).await;
    assert_eq!(r.status, 201, "{}", r.body);
    let ru = r.body["request_uri"].as_str().unwrap().to_string();
    expect_invalid(par(good).await, "replayed");

    let f = Flow::new(&client_id, redirect, "atproto transition:generic", &key);
    let (st, h, body) = browser_consent(&s, &mut Browser::default(), &f, &acct, &ru, &[]).await;
    assert_eq!(st, 303, "{body}");
    let (_, q) = location_params(&h);
    assert_eq!(q["state"], "inner");
    let a = client_assertion(&client_sk, &client_id, &s.base);
    let t = tokens(
        &exchange(&s, &f, &q["code"], &p, &[("client_assertion_type", JWT_BEARER), ("client_assertion", &a)]).await,
    );
    assert_eq!(t.scope, "atproto transition:generic");
}

/// A public client that registered `request_object_signing_alg: none` sends
/// unsecured request objects (iss/aud optional); signed ones are refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn jar_unsecured_request_objects() {
    let s = spawn().await;
    let redirect = "https://app.example.com/callback";
    let client_id = serve_metadata(|id| {
        json!({
            "client_id": id,
            "redirect_uris": [redirect],
            "scope": "atproto",
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
            "request_object_signing_alg": "none",
            "application_type": "web",
            "dpop_bound_access_tokens": true,
        })
    })
    .await;
    let key = DpopKey::new();
    let payload = || {
        json!({
            "iat": now(), "jti": rand_str(12), "client_id": client_id,
            "response_type": "code", "redirect_uri": redirect, "scope": "atproto",
            "code_challenge": pkce().challenge, "code_challenge_method": "S256",
        })
    };
    let r =
        as_post(&s, &key, "/oauth/par", &[("client_id", &client_id), ("request", &unsecured_jwt(&payload()))]).await;
    assert_eq!(r.status, 201, "{}", r.body);
    let signed = sign_jwt(&SigningKey::generate(), &json!({"alg": "ES256"}), &payload());
    let r = as_post(&s, &key, "/oauth/par", &[("client_id", &client_id), ("request", &signed)]).await;
    assert_eq!(r.status, 400, "{}", r.body);
    assert!(r.body["error_description"].as_str().unwrap().contains("unsecured"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn response_modes_form_post_and_fragment() {
    use base64::engine::general_purpose::STANDARD;
    let s = spawn().await;
    let acct = create_account(&s, "formpost").await;
    let m = s.get_json("/.well-known/oauth-authorization-server").await;
    assert_eq!(m["response_modes_supported"], json!(["query", "fragment", "form_post"]));
    assert_eq!(m["request_parameter_supported"], true);
    assert!(m["request_object_signing_alg_values_supported"].as_array().unwrap().contains(&json!("none")));

    let key = DpopKey::new();
    let scope = "atproto transition:generic";
    let f = Flow::loopback(scope, &key).with("response_mode", "form_post");
    let p = pkce();
    let ru = f.request_uri(&s, &p, "fp-state").await;
    let mut b = Browser::default();
    let (st, h, body) = browser_consent(&s, &mut b, &f, &acct, &ru, &[]).await;
    assert_eq!(st, 200, "{body}");
    assert!(h.get("location").is_none());
    assert_eq!(h.get("cache-control").unwrap(), "no-store");
    assert!(body.contains(&format!("<form method=\"post\" action=\"{REDIRECT}\">")), "{body}");
    assert_eq!(hidden_field(&body, "state").as_deref(), Some("fp-state"));
    assert_eq!(hidden_field(&body, "iss"), Some(s.base.clone()));
    let code = hidden_field(&body, "code").expect("code field");
    // CSP: only the inline auto-submit script (by hash), and the form may
    // post to the client's redirect origin
    let csp = h.get("content-security-policy").unwrap().to_str().unwrap();
    let i = body.find("<script>").unwrap() + "<script>".len();
    let script = &body[i..i + body[i..].find("</script>").unwrap()];
    let hash = STANDARD.encode(Sha256::digest(script));
    assert!(csp.contains(&format!("script-src 'sha256-{hash}'")), "{csp}");
    assert!(csp.contains("form-action 'self' http://127.0.0.1"), "{csp}");
    assert!(csp.contains("default-src 'none'"), "{csp}");
    tokens(&exchange(&s, &f, &code, &p, &[]).await);

    // errors use the same response mode
    let ru = f.request_uri(&s, &pkce(), "fp-deny").await;
    let csrf = csrf_of(&b.authorize(&s, &f, &ru).await.2);
    let (st, _, body) =
        b.post(&s, "/oauth/authorize/consent", &[("request_uri", &ru), ("csrf", &csrf), ("action", "deny")]).await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(hidden_field(&body, "error").as_deref(), Some("access_denied"));
    assert_eq!(hidden_field(&body, "state").as_deref(), Some("fp-deny"));

    // fragment: the response is in the redirect's fragment
    let f = Flow::loopback(scope, &key).with("response_mode", "fragment");
    let p = pkce();
    let ru = f.request_uri(&s, &p, "frag").await;
    let (st, h, body) = browser_consent(&s, &mut b, &f, &acct, &ru, &[]).await;
    assert_eq!(st, 303, "{body}");
    let loc = h.get("location").unwrap().to_str().unwrap();
    assert!(loc.starts_with(&format!("{REDIRECT}#")), "{loc}");
    let (_, q) = location_params(&h);
    assert_eq!(q["state"], "frag");
    tokens(&exchange(&s, &f, &q["code"], &p, &[]).await);

    // unknown response modes are refused at PAR
    let r = Flow::loopback(scope, &key).with("response_mode", "web_message").par(&s, &pkce(), "x").await;
    assert_eq!(r.status, 400, "{}", r.body);
}

/// prompt=create: the sign-up page. Creating an account there signs it in
/// on the device and continues to consent; the two pages link to each
/// other; form errors keep the values entered.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn prompt_create_signs_up() {
    let s = spawn().await;
    let taken = create_account(&s, "taken").await;
    let m = s.get_json("/.well-known/oauth-authorization-server").await;
    assert!(m["prompt_values_supported"].as_array().unwrap().contains(&json!("create")));
    let key = DpopKey::new();
    let f = Flow::loopback("atproto transition:generic", &key).with("prompt", "create");
    let mut b = Browser::default();
    let p = pkce();
    let ru = f.request_uri(&s, &p, "c1").await;
    let (st, _, html) = b.authorize(&s, &f, &ru).await;
    assert_eq!(st, 200);
    assert!(html.contains("Create an account") && html.contains("name=\"email\""), "sign-up expected: {html}");
    assert!(!html.contains("name=\"invite_code\""), "invites are optional here: {html}");
    // the "Sign in" link shows the sign-in page, which links back
    let link = |html: &str, screen: &str| {
        let at = html.find(&format!("screen={screen}")).expect("screen link");
        let start = html[..at].rfind("href=\"").unwrap() + 6;
        format!("{}{}", s.base, html[start..at + 7 + screen.len()].replace("&amp;", "&"))
    };
    let (st, _, signin) = b.get(&s, &link(&html, "sign-in")).await;
    assert_eq!(st, 200);
    assert!(signin.contains("name=\"identifier\""), "{signin}");
    let (_, _, html) = b.get(&s, &link(&signin, "sign-up")).await;
    assert!(html.contains("name=\"email\""), "{html}");

    // a taken handle: the form again, with the error and the values kept
    let name = format!("new{}", rand::random::<u32>() % 100000);
    let email = format!("{name}@example.com");
    let taken_label = taken.handle.split('.').next().unwrap();
    let csrf = csrf_of(&html);
    let (st, _, html) =
        b.post(&s, "/oauth/authorize/sign-up", &sign_up_form(&ru, &csrf, taken_label, &email, None)).await;
    assert_eq!(st, 400, "{html}");
    assert!(html.contains("Handle already taken") && html.contains(&email), "{html}");
    let (st, _, _) = b.post(&s, "/oauth/authorize/sign-up", &sign_up_form(&ru, "bogus", &name, &email, None)).await;
    assert_eq!(st, 403, "a CSRF token is required");

    // success: signed in on the device, then consent (public client)
    let (st, _, html) =
        b.post(&s, "/oauth/authorize/sign-up", &sign_up_form(&ru, &csrf_of(&html), &name, &email, None)).await;
    assert_eq!(st, 200, "{html}");
    assert!(html.contains("Authorize access"), "consent expected: {html}");
    let did = hidden_field(&html, "did").expect("did on the consent form");
    let (st, h, body) = b
        .post(
            &s,
            "/oauth/authorize/consent",
            &[("request_uri", &ru), ("csrf", &csrf_of(&html)), ("did", &did), ("action", "allow")],
        )
        .await;
    assert_eq!(st, 303, "{body}");
    let t = tokens(&exchange(&s, &f, &location_params(&h).1["code"], &p, &[]).await);
    let r = create_post(&s, &key, &t.access, &did, "app.bsky.feed.post").await;
    assert_eq!(r.status, 200, "{}", r.body);
    // a real account: the password works for createSession too
    let r = s
        .http
        .post(format!("{}/xrpc/com.atproto.server.createSession", s.base))
        .json(&json!({"identifier": format!("{name}.vlpds.test"), "password": PASSWORD}))
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success());

    // the device now knows the account: a later prompt=create still offers
    // sign-up, and the sign-in page offers it as well
    let ru = f.request_uri(&s, &pkce(), "c2").await;
    assert!(b.authorize(&s, &f, &ru).await.2.contains("name=\"email\""));
    let f = Flow::loopback("atproto transition:generic", &key);
    let ru = f.request_uri(&s, &pkce(), "c3").await;
    let (_, _, html) = b.get(&s, &format!("{}&screen=sign-in", f.authorize_url(&s, &ru))).await;
    assert!(html.contains("Create an account"), "{html}");
}

/// With several handle domains the sign-up page offers them all, and the
/// one picked is the new handle's.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sign_up_under_an_added_domain() {
    let s = spawn().await;
    vlpds::handle_domains::add(&s.app.handle_domains, &s.app.store, "group-a.test", "test").await.unwrap();
    let key = DpopKey::new();
    let f = Flow::loopback("atproto transition:generic", &key).with("prompt", "create");
    let mut b = Browser::default();
    let ru = f.request_uri(&s, &pkce(), "c1").await;
    let (_, _, html) = b.authorize(&s, &f, &ru).await;
    assert!(html.contains("<option value=\"group-a.test\">.group-a.test</option>"), "{html}");
    let name = format!("grp{}", rand::random::<u32>() % 100000);
    let email = format!("{name}@example.com");
    let mut form = sign_up_form(&ru, "", &name, &email, None);
    let csrf = csrf_of(&html);
    form[1].1 = &csrf;
    form.push(("domain", "group-a.test"));
    let (st, _, html) = b.post(&s, "/oauth/authorize/sign-up", &form).await;
    assert_eq!(st, 200, "{html}");
    let did = hidden_field(&html, "did").expect("did on the consent form");
    assert_eq!(s.app.account(&did).await.ok().unwrap().handle, format!("{name}.group-a.test"));
}

/// With invites required, the sign-up page asks for a code and enforces it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sign_up_page_with_required_invites() {
    let s = spawn_with(|c| c.invite_required = true).await;
    let key = DpopKey::new();
    let f = Flow::loopback("atproto", &key).with("prompt", "create");
    let mut b = Browser::default();
    let ru = f.request_uri(&s, &pkce(), "i1").await;
    let (_, _, html) = b.authorize(&s, &f, &ru).await;
    assert!(html.contains("name=\"invite_code\""), "{html}");
    let name = format!("inv{}", rand::random::<u32>() % 100000);
    let email = format!("{name}@example.com");
    let (st, _, html) =
        b.post(&s, "/oauth/authorize/sign-up", &sign_up_form(&ru, &csrf_of(&html), &name, &email, Some(""))).await;
    assert_eq!(st, 400, "{html}");
    assert!(html.contains("No invite code provided"), "{html}");
    let (st, _, html) = b
        .post(&s, "/oauth/authorize/sign-up", &sign_up_form(&ru, &csrf_of(&html), &name, &email, Some("bogus-code")))
        .await;
    assert_eq!(st, 400, "{html}");
    assert!(html.contains("invite code not available"), "{html}");

    // a real code: the sign-up uses it, listed like a createAccount's use
    let admin = |r: reqwest::RequestBuilder| async move {
        let v: J = r.basic_auth("admin", Some("dev-admin-token")).send().await.unwrap().json().await.unwrap();
        v
    };
    let code = admin(
        s.http.post(format!("{}/xrpc/com.atproto.server.createInviteCode", s.base)).json(&json!({"useCount": 2})),
    )
    .await["code"]
        .as_str()
        .unwrap()
        .to_string();
    let (st, _, html) =
        b.post(&s, "/oauth/authorize/sign-up", &sign_up_form(&ru, &csrf_of(&html), &name, &email, Some(&code))).await;
    assert_eq!(st, 200, "{html}");
    let did = hidden_field(&html, "did").expect("did on the consent form");
    let all = admin(s.http.get(format!("{}/xrpc/com.atproto.admin.getInviteCodes?limit=500", s.base))).await;
    let v = all["codes"].as_array().unwrap().iter().find(|c| c["code"] == code.as_str()).unwrap();
    assert_eq!(v["available"], json!(2), "{v}");
    assert_eq!(v["uses"].as_array().unwrap().iter().map(|u| u["usedBy"].clone()).collect::<Vec<_>>(), vec![json!(did)]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn consent_scope_narrowing() {
    let s = spawn().await;
    let acct = create_account(&s, "narrow").await;
    let key = DpopKey::new();
    let scope = "atproto account:email repo:app.bsky.feed.post";
    let f = Flow::loopback(scope, &key);
    let mut b = Browser::default();
    // one flow: the redirect's parameters and the granted token scope (if a
    // code was issued)
    async fn consent(
        s: &Srv,
        b: &mut Browser,
        f: &Flow<'_>,
        acct: &Account,
        extra: &[(&str, &str)],
    ) -> (HashMap<String, String>, Option<String>) {
        let p = pkce();
        let ru = f.request_uri(s, &p, "n").await;
        let (st, h, body) = browser_consent(s, b, f, acct, &ru, extra).await;
        assert_eq!(st, 303, "{body}");
        let (_, q) = location_params(&h);
        let scope = match q.get("code") {
            Some(code) => Some(tokens(&exchange(s, f, code, &p, &[]).await).scope),
            None => None,
        };
        (q, scope)
    }

    // what a browser posts for the page's `scope` fields with every box
    // left ticked: the hidden required ones and each enabled checkbox
    fn page_scopes(html: &str) -> Vec<String> {
        html.split("name=\"scope\" value=\"").skip(1).map(|r| r[..r.find('"').unwrap()].replace("&amp;", "&")).collect()
    }
    fn scope_pairs(v: &[&str]) -> Vec<(&'static str, String)> {
        v.iter().map(|x| ("scope", x.to_string())).collect()
    }
    async fn post(
        s: &Srv,
        b: &mut Browser,
        f: &Flow<'_>,
        acct: &Account,
        scopes: &[&str],
    ) -> (HashMap<String, String>, Option<String>) {
        let pairs = scope_pairs(scopes);
        let extra: Vec<(&str, &str)> = pairs.iter().map(|(k, v)| (*k, v.as_str())).collect();
        consent(s, b, f, acct, &extra).await
    }

    // process-wide counters other tests move too: check growth
    let consents = |r: &str| vlpds::metrics::OAUTH_CONSENTS.with_label_values(&[r]).get();
    let before = ["full", "narrowed", "refused"].map(consents);

    // no scope field: allowed as requested
    assert_eq!(consent(&s, &mut b, &f, &acct, &[]).await.1.as_deref(), Some(scope));

    // one checkbox per requested scope; atproto is ticked, disabled and
    // carried by a hidden field
    let f = f.with("login_hint", &acct.handle);
    let ru = f.request_uri(&s, &pkce(), "page").await;
    let (_, _, html) = b.authorize(&s, &f, &ru).await;
    assert_eq!(page_scopes(&html), scope.split(' ').collect::<Vec<_>>(), "{html}");
    assert!(html.contains("<input type=\"hidden\" name=\"scope\" value=\"atproto\"><input type=\"checkbox\" id=\"s0\" checked disabled"), "{html}");
    assert!(html.contains("Required</span>"), "{html}");
    assert!(html.contains("Read your email address"), "{html}");
    assert!(html.contains("Create, update and delete your posts"), "{html}");
    assert!(!html.contains("<script"), "the consent page works without script: {html}");
    assert_eq!(html.matches("type=\"checkbox\"").count(), 3, "{html}");

    // everything left ticked: unchanged
    let all = page_scopes(&html);
    let all: Vec<&str> = all.iter().map(String::as_str).collect();
    assert_eq!(post(&s, &mut b, &f, &acct, &all).await.1.as_deref(), Some(scope));
    // email unticked: the token's scope is exactly the narrowed set
    let (_, sc) = post(&s, &mut b, &f, &acct, &["atproto", "repo:app.bsky.feed.post"]).await;
    assert_eq!(sc.as_deref(), Some("atproto repo:app.bsky.feed.post"));
    // the narrowed grant is what the session holds
    let sessions = vlpds::oauth::store::list_sessions(&s.app, &acct.did).await.unwrap();
    assert!(sessions.iter().any(|x| x.scope == "atproto repo:app.bsky.feed.post"));
    // every optional box unticked
    assert_eq!(post(&s, &mut b, &f, &acct, &["atproto"]).await.1.as_deref(), Some("atproto"));
    // a space-separated override works too, and is an intersection only
    // (nothing can be added)
    let (_, sc) =
        consent(&s, &mut b, &f, &acct, &[("scope", "atproto transition:generic repo:app.bsky.feed.post")]).await;
    assert_eq!(sc.as_deref(), Some("atproto repo:app.bsky.feed.post"));
    // a forged post without the required scope is refused, not granted
    // without it
    for forged in [&["repo:app.bsky.feed.post", "account:email"][..], &[""][..], &["transition:generic"][..]] {
        let (q, sc) = post(&s, &mut b, &f, &acct, forged).await;
        assert_eq!(sc, None, "{forged:?}");
        assert_eq!(q["error"], "access_denied", "{forged:?}");
    }
    for ((r, n), b) in [("full", 2), ("narrowed", 3), ("refused", 3)].into_iter().zip(before) {
        assert!(consents(r) >= b + n, "vlpds_oauth_consents_total{{result={r}}} grew by {n}");
    }

    // transition scopes: broad grants with a warning, each droppable whole;
    // chat.bsky doesn't work without generic, so it goes with it
    let ts = "atproto transition:generic transition:chat.bsky transition:email";
    let f2 = Flow::loopback(ts, &key).with("login_hint", &acct.handle);
    let ru = f2.request_uri(&s, &pkce(), "page2").await;
    let (_, _, html) = b.authorize(&s, &f2, &ru).await;
    assert_eq!(page_scopes(&html), ts.split(' ').collect::<Vec<_>>(), "{html}");
    assert_eq!(html.matches("class=\"warn\"").count(), 2, "{html}");
    assert_eq!(post(&s, &mut b, &f2, &acct, &ts.split(' ').collect::<Vec<_>>()).await.1.as_deref(), Some(ts));
    let (_, sc) = post(&s, &mut b, &f2, &acct, &["atproto", "transition:generic", "transition:email"]).await;
    assert_eq!(sc.as_deref(), Some("atproto transition:generic transition:email"));
    let (_, sc) = post(&s, &mut b, &f2, &acct, &["atproto", "transition:chat.bsky", "transition:email"]).await;
    assert_eq!(sc.as_deref(), Some("atproto transition:email"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gc_sweeps_expired_rows() {
    use vlpds::oauth::gc::Sweeper;
    use vlpds::oauth::store;
    let s = spawn().await;
    let acct = create_account(&s, "gc").await;
    let key = DpopKey::new();
    let f = Flow::loopback("atproto transition:generic", &key);
    let mut b = Browser::default();
    // a full grant: consumed request, code challenge, device, session
    let p = pkce();
    let code = authorize_interactive(&s, &mut b, &f, &acct, &p).await;
    let t = tokens(&exchange(&s, &f, &code, &p, &[]).await);
    let consumed_rid = store::code_request_id(&code).unwrap();
    let device_id = b.cookie.clone().unwrap().split_once('=').unwrap().1.to_string();
    // a pending (unauthorized) request
    let p2 = pkce();
    let pending_uri = f.request_uri(&s, &p2, "pending").await;
    let pending_rid = store::request_id_from_uri(&pending_uri).unwrap().to_string();

    let mut sw = Sweeper::new();
    let now = now();
    // nothing is expired yet
    let st = sw.tick(&s.app, now, 10_000, 10_000).await.unwrap();
    assert_eq!(st.removed, 0, "{st:?}");
    assert!(st.scanned > 0);
    // past the PAR lifetime: only the pending request goes; the consumed
    // request stays as a code-reuse tombstone
    let st = sw.tick(&s.app, now + 6 * 60, 10_000, 10_000).await.unwrap();
    assert_eq!(st.removed, 1, "{st:?}");
    assert!(store::get_request(&s.app, &pending_rid).await.unwrap().is_none());
    assert!(store::get_request(&s.app, &consumed_rid).await.unwrap().is_some());
    let (st_code, _, html) = b.authorize(&s, &f, &pending_uri).await;
    assert_eq!(st_code, 400);
    assert!(html.contains("Unknown request_uri"), "{html}");
    // code challenges are claimed for 24 h
    let r = f.par(&s, &p2, "again").await;
    assert_eq!(r.status, 400, "{}", r.body);
    let st = sw.tick(&s.app, now + 86_400 + 60, 10_000, 10_000).await.unwrap();
    assert_eq!(st.removed, 2, "two code challenges: {st:?}");
    f.request_uri(&s, &p2, "again").await;
    // 15 days on: the public client's session, the idle device and the
    // tombstone are gone (the new PAR request too)
    assert_eq!(store::list_sessions(&s.app, &acct.did).await.unwrap().len(), 1);
    let st = sw.tick(&s.app, now + 15 * 86_400, 10_000, 10_000).await.unwrap();
    assert!(st.removed >= 4, "{st:?}");
    assert!(store::list_sessions(&s.app, &acct.did).await.unwrap().is_empty());
    assert!(store::get_device(&s.app, &device_id).await.unwrap().is_none());
    assert!(store::get_request(&s.app, &consumed_rid).await.unwrap().is_none());
    let r = refresh(&s, &f, t.refresh.as_ref().unwrap(), &[]).await;
    assert_eq!(r.body["error"], "invalid_grant", "{}", r.body);
}

/// Each tick does bounded work and resumes where it stopped.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gc_work_is_bounded_per_tick() {
    use vlpds::oauth::gc::Sweeper;
    let s = spawn().await;
    let key = DpopKey::new();
    let f = Flow::loopback("atproto", &key);
    for i in 0..3 {
        f.request_uri(&s, &pkce(), &format!("s{i}")).await;
    }
    let later = now() + 6 * 60;
    // delete budget 1: one request per tick
    let mut sw = Sweeper::new();
    for _ in 0..3 {
        let st = sw.tick(&s.app, later, 10_000, 1).await.unwrap();
        assert_eq!(st.removed, 1, "{st:?}");
    }
    assert_eq!(sw.tick(&s.app, later, 10_000, 1).await.unwrap().removed, 0);
    // scan budget 1: one key examined per partition per tick, the cursor
    // carries on, and everything is found within a bounded number of ticks
    for i in 0..3 {
        f.request_uri(&s, &pkce(), &format!("t{i}")).await;
    }
    let mut sw = Sweeper::new();
    let parts = s.app.partitions.owned().len();
    let mut removed = 0;
    for _ in 0..200 {
        let st = sw.tick(&s.app, later, 1, 10_000).await.unwrap();
        assert!(st.scanned <= parts, "{st:?}");
        removed += st.removed;
        if removed == 3 {
            break;
        }
    }
    assert_eq!(removed, 3);
}

/// Latency of DPoP-authenticated resource requests (the proof's replay
/// claim is on this path):
/// `cargo test --profile dev-release --test all oauth::bench_dpop_resource_requests -- --ignored --nocapture`
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn bench_dpop_resource_requests() {
    // BENCH_INJECT_MS: segment PUT latency (S3-like), e.g. 25
    let inject = std::env::var("BENCH_INJECT_MS").ok().and_then(|v| v.parse::<f64>().ok());
    let s = spawn_with(|c| c.inject_latency = inject.map(|ms| (ms, 0.0))).await;
    let acct = create_account(&s, "benchy").await;
    let (key, access) = login(&s, &acct, "atproto transition:generic").await;
    let nsid = "app.bsky.actor.getPreferences";
    assert_eq!(xrpc_dpop(&s, &key, &access, "GET", nsid, None).await.status, 200);
    let url = format!("{}/xrpc/{nsid}", s.base);
    let n = if inject.is_some() { 200 } else { 2000 };
    // proofs are signed up front: only the server's work is timed
    let proofs: Vec<String> = (0..n).map(|_| key.proof("GET", &url, Some(&access))).collect();
    let send = |proof: String| {
        let rb = s.http.get(&url).header("authorization", format!("DPoP {access}")).header("dpop", proof);
        async move {
            let r = rb.send().await.unwrap();
            assert_eq!(r.status(), 200);
            r.bytes().await.unwrap();
        }
    };
    let t0 = std::time::Instant::now();
    for p in proofs[..n / 2].iter().cloned() {
        send(p).await;
    }
    let seq = t0.elapsed().as_secs_f64() * 1e6 / (n / 2) as f64;
    let t0 = std::time::Instant::now();
    use futures::StreamExt;
    futures::stream::iter(proofs[n / 2..].iter().cloned().map(send)).buffer_unordered(16).collect::<Vec<_>>().await;
    let par = t0.elapsed().as_secs_f64() * 1e6 / (n / 2) as f64;
    println!("DPoP resource request: {seq:.0} us sequential, {par:.0} us/request at 16 in flight");
}

/// Re-opening an authorized request's page (anyone holding its request_uri,
/// from any device) is refused but doesn't delete the request: the client's
/// code exchange still works.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reopened_authorized_request_keeps_code() {
    let s = spawn().await;
    let acct = create_account(&s, "reopen").await;
    let key = DpopKey::new();
    let f = Flow::loopback("atproto transition:generic", &key);
    let mut b = Browser::default();
    let p = pkce();
    let ru = f.request_uri(&s, &p, "st").await;
    let (st, h, body) = browser_consent(&s, &mut b, &f, &acct, &ru, &[]).await;
    assert_eq!(st, 303, "{body}");
    let code = location_params(&h).1.get("code").expect("code").clone();
    // another device, and the same browser, open it again
    let (st, _, body) = Browser::default().authorize(&s, &f, &ru).await;
    assert_ne!(st, 200, "{body}");
    let (st, _, body) = b.authorize(&s, &f, &ru).await;
    assert_ne!(st, 200, "{body}");
    tokens(&exchange(&s, &f, &code, &p, &[]).await);
}

/// Outside dev mode (the SSRF policy on): a loopback development client
/// (`http://localhost?...`, whose metadata comes from the client_id and is
/// never fetched) still completes the whole flow with an
/// `http://127.0.0.1:<port>` redirect, which the browser follows, not the
/// server. Client metadata the server would fetch from a loopback or
/// private address, or over http, is refused before anything connects.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn loopback_clients_work_and_metadata_fetches_are_guarded_outside_dev_mode() {
    let s = spawn_with(|c| c.dev_mode = false).await;
    let acct = create_account(&s, "loopy").await;
    let key = DpopKey::new();
    let scope = "atproto transition:generic";
    for redirect in ["http://127.0.0.1:43123/callback", "http://[::1]:43123/callback"] {
        let f = Flow::new(&loopback_client_id(scope, redirect), redirect, scope, &key);
        let t = grant(&s, &mut Browser::default(), &f, &acct).await;
        assert_eq!(t.scope, scope);
    }
    // the bare loopback client id: its default redirects http://127.0.0.1/
    // and http://[::1]/ match any port (RFC 8252 §7.3), not another path
    for redirect in ["http://127.0.0.1:43123/", "http://[::1]:43124/"] {
        let f = Flow::new("http://localhost", redirect, "atproto", &key);
        grant(&s, &mut Browser::default(), &f, &acct).await;
    }
    let f = Flow::new("http://localhost", "http://127.0.0.1:43123/callback", "atproto", &key);
    assert_eq!(f.par(&s, &pkce(), "x").await.body["error"], "invalid_request");

    let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = hits.clone();
    tokio::spawn(async move {
        while let Ok((c, _)) = listener.accept().await {
            seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            drop(c);
        }
    });
    for client_id in [
        format!("http://127.0.0.1:{port}/client-metadata.json"),
        format!("https://127.0.0.1:{port}/client-metadata.json"),
        format!("https://localhost:{port}/client-metadata.json"),
        format!("https://app.localhost:{port}/client-metadata.json"),
        format!("https://[::ffff:127.0.0.1]:{port}/client-metadata.json"),
        "https://169.254.169.254/latest/meta-data".to_string(),
        "https://2130706433/client-metadata.json".to_string(),
    ] {
        let f = Flow::new(&client_id, "https://app.example.com/cb", "atproto", &key);
        let r = f.par(&s, &pkce(), "x").await;
        assert_eq!(
            (r.status, r.body["error"].as_str()),
            (400, Some("invalid_client_metadata")),
            "{client_id}: {}",
            r.body
        );
    }
    assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 0, "a metadata fetch reached a loopback address");
}

// Reference-suite ports that reuse this file's client simulation.
#[path = "ref_oauth.rs"]
mod ref_oauth;

/// A new pushed request in browser `b`, signed in with the password only:
/// the page that follows.
pub(crate) async fn password_step(s: &Srv, b: &mut Browser, f: &Flow<'_>, acct: &Account) -> String {
    let ru = f.request_uri(s, &pkce(), "t").await;
    let (_, _, html) = b.authorize(s, f, &ru).await;
    let (st, _, html) = b.sign_in(s, &ru, &csrf_of(&html), &acct.handle, PASSWORD).await;
    assert_eq!(st, 200, "{html}");
    html
}

/// "Trust this browser" on the sign-in page's second-factor step
/// (src/xrpc/signin.rs): that browser skips the code until a password
/// change; the OAuth-only switch leaves this page alone; each sign-in is
/// logged with its client.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn trusted_browser_skips_the_second_factor() {
    let s = spawn().await;
    let acct = create_account(&s, "tess").await;
    let (secret, step) = enable_totp(&s, &acct).await;
    let key = DpopKey::new();
    let f = Flow::loopback("atproto", &key).with("prompt", "login");
    let mut b = Browser::default();
    let ru = f.request_uri(&s, &pkce(), "t").await;
    let (_, _, html) = b.authorize(&s, &f, &ru).await;
    let csrf = csrf_of(&html);
    let (_, _, html) = b.sign_in(&s, &ru, &csrf, &acct.handle, PASSWORD).await;
    assert!(html.contains("name=\"trust\"") && html.contains("Trust this browser for 30 days"), "{html}");
    let code = vlpds::totp::code_for_step(&secret, step + 1);
    let pairs = [
        ("request_uri", ru.as_str()),
        ("csrf", csrf.as_str()),
        ("step", "2fa"),
        ("code", code.as_str()),
        ("trust", "1"),
        ("action", "sign-in"),
    ];
    let (st, _, html) = b.post(&s, "/oauth/authorize/sign-in", &pairs).await;
    assert_eq!(st, 200, "{html}");
    assert!(html.contains("Authorize access"), "{html}");

    // the same browser: password only, straight to consent
    let html = password_step(&s, &mut b, &f, &acct).await;
    assert!(html.contains("Authorize access"), "trusted browser asked for a code: {html}");
    // another browser is asked
    let html = password_step(&s, &mut Browser::default(), &f, &acct).await;
    assert!(html.contains("name=\"code\""), "{html}");

    // OAuth-only doesn't touch this page
    let (st, j) =
        s.bearer(&acct.jwt, "vlpds.server.updateSignInSecurity", true, Some(json!({"oauthOnly": true}))).await;
    assert_eq!(st, 200, "{j}");
    let html = password_step(&s, &mut b, &f, &acct).await;
    assert!(html.contains("Authorize access"), "{html}");

    // the log: OAuth sign-ins with their client and factor
    let (_, j) = s.bearer(&acct.jwt, "vlpds.server.getSignInSecurity", false, None).await;
    let recent = j["recentSignIns"].as_array().unwrap();
    assert_eq!(recent.len(), 3, "{j}");
    assert!(recent.iter().all(|e| e["method"] == "oauth" && e["clientId"] == json!(f.client_id)), "{j}");
    let factors: Vec<&str> = recent.iter().map(|e| e["factor"].as_str().unwrap()).collect();
    assert_eq!(factors, ["trusted", "trusted", "totp"]);
    assert_eq!(j["trustedBrowsers"].as_array().unwrap().len(), 1);

    // a password change: the code is asked for again
    let r = s
        .http
        .post(format!("{}/xrpc/com.atproto.server.requestPasswordReset", s.base))
        .json(&json!({"email": "tess@example.com"}))
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success());
    let tok = dev_mail_token(&s, "tess@example.com", "reset_password").await;
    let r = s
        .http
        .post(format!("{}/xrpc/com.atproto.server.resetPassword", s.base))
        .json(&json!({"token": tok, "password": PASSWORD}))
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success(), "{}", r.text().await.unwrap());
    let html = password_step(&s, &mut b, &f, &acct).await;
    assert!(html.contains("name=\"code\""), "trust survived a password change: {html}");
}
