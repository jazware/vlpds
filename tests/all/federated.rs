//! Third-party sign-in (docs/federated-sign-in.html) against an in-process
//! mock OpenID provider: provider config through the admin API, linking on
//! `/oauth/account`, sign-in on the OAuth page through to a code exchange,
//! the form_post handoff, every id_token check, state binding, unlink and
//! its revocations, second factors, and the feature-level gate.

use crate::oauth::*;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::elliptic_curve::Generate;
use parking_lot::Mutex;
use serde_json::{json, Value as J};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

const CLIENT_ID: &str = "vlpds-test-client";
const CLIENT_SECRET: &str = "shh-its-a-secret";

fn b64(b: impl AsRef<[u8]>) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

type Tweak = Arc<dyn Fn(&mut J, &mut J) + Send + Sync>;

struct Code {
    nonce: String,
    challenge: String,
    redirect_uri: String,
    /// A SIWE sign-in's subject (the wallet), else `IdpState::sub`.
    sub: Option<String>,
}

/// An authorization a wallet has yet to sign for (the SIWE adapter mode).
struct SiweRequest {
    code: Code,
    state: String,
    siwe_nonce: String,
}

/// What the mock provider does: who signs in, and how to misbehave.
pub(crate) struct IdpState {
    pub(crate) sub: String,
    pub(crate) email: Option<String>,
    key: SigningKey,
    kid: String,
    /// Signs with this key and kid instead (not published unless `publish_alt`).
    alt: Option<(SigningKey, String)>,
    publish_alt: bool,
    tweak: Option<Tweak>,
    /// "basic", "post", "jwt" (private_key_jwt) or "signed" (a client
    /// secret that is an ES256 JWT): how the client must authenticate.
    pub(crate) auth: &'static str,
    /// The client's public key, for "jwt" and "signed".
    pub(crate) client_key: Option<p256::ecdsa::VerifyingKey>,
    /// Send the iss parameter on the authorization response.
    pub(crate) send_iss: Option<String>,
    codes: HashMap<String, Code>,
    /// Act as a Sign-In with Ethereum adapter: `/authorize` asks the wallet
    /// to sign an EIP-4361 message, `/siwe` checks it and issues the code.
    pub(crate) siwe: bool,
    siwe_requests: HashMap<String, SiweRequest>,
}

pub(crate) struct Idp {
    pub(crate) issuer: String,
    pub(crate) state: Arc<Mutex<IdpState>>,
    pub(crate) jwks_hits: Arc<AtomicUsize>,
}

fn sign(key: &SigningKey, header: &J, claims: &J) -> String {
    let input = format!("{}.{}", b64(serde_json::to_vec(header).unwrap()), b64(serde_json::to_vec(claims).unwrap()));
    let sig: Signature = key.sign(input.as_bytes());
    format!("{input}.{}", b64(sig.to_bytes()))
}

fn jwk(key: &SigningKey, kid: &str) -> J {
    let pt = key.verifying_key().to_sec1_point(false);
    json!({"kty": "EC", "crv": "P-256", "x": b64(pt.x().unwrap()), "y": b64(pt.y().unwrap()), "kid": kid, "use": "sig", "alg": "ES256"})
}

fn form_page(action: &str, pairs: &[(&str, &str)]) -> String {
    let mut f = format!("<form method=\"post\" action=\"{action}\">");
    for (k, v) in pairs {
        f.push_str(&format!("<input type=\"hidden\" name=\"{k}\" value=\"{v}\">"));
    }
    f + "</form>"
}

/// An ES256 JWT from the client: signed by its key, for this client and
/// audience, current.
fn client_jwt(st: &IdpState, jwt: Option<&String>, iss: &str, aud: &str) -> bool {
    use p256::ecdsa::signature::Verifier;
    let (Some(jwt), Some(vk)) = (jwt, &st.client_key) else { return false };
    let Ok(d) = vlpds::oauth::jose::DecodedJwt::decode(jwt) else { return false };
    let (input, sig) = jwt.rsplit_once('.').unwrap();
    let Some(sig) = vlpds::oauth::util::b64u_decode(sig).and_then(|b| Signature::from_slice(&b).ok()) else {
        return false;
    };
    let c = &d.payload;
    vk.verify(input.as_bytes(), &sig).is_ok()
        && d.header["kid"] == "client-key-1"
        && c["iss"] == iss
        && c["sub"] == CLIENT_ID
        && c["aud"] == aud
        && c["exp"].as_i64().is_some_and(|e| e > now())
}

impl Idp {
    pub(crate) async fn start() -> Idp {
        use axum::extract::{Form, Query, State};
        use axum::response::{Html, IntoResponse, Response};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer = format!("http://{}", listener.local_addr().unwrap());
        let state = Arc::new(Mutex::new(IdpState {
            sub: "user-1".into(),
            email: Some("person@example.com".into()),
            key: SigningKey::generate(),
            kid: "k1".into(),
            alt: None,
            publish_alt: false,
            tweak: None,
            auth: "basic",
            client_key: None,
            send_iss: None,
            codes: HashMap::new(),
            siwe: false,
            siwe_requests: HashMap::new(),
        }));
        let jwks_hits = Arc::new(AtomicUsize::new(0));
        #[derive(Clone)]
        struct S {
            issuer: String,
            st: Arc<Mutex<IdpState>>,
            hits: Arc<AtomicUsize>,
        }
        let s = S { issuer: issuer.clone(), st: state.clone(), hits: jwks_hits.clone() };
        async fn discovery(State(s): State<S>) -> axum::Json<J> {
            axum::Json(json!({
                "issuer": s.issuer,
                "authorization_endpoint": format!("{}/authorize", s.issuer),
                "token_endpoint": format!("{}/token", s.issuer),
                "jwks_uri": format!("{}/jwks", s.issuer),
                "response_types_supported": ["code"],
            }))
        }
        async fn jwks(State(s): State<S>) -> axum::Json<J> {
            s.hits.fetch_add(1, Ordering::SeqCst);
            let st = s.st.lock();
            let mut keys = vec![jwk(&st.key, &st.kid)];
            if let (Some((k, kid)), true) = (&st.alt, st.publish_alt) {
                keys.push(jwk(k, kid));
            }
            axum::Json(json!({"keys": keys}))
        }
        async fn authorize(State(s): State<S>, Query(q): Query<HashMap<String, String>>) -> Response {
            let code = format!("code-{}", rand::random::<u64>());
            let mut st = s.st.lock();
            assert_eq!(q.get("client_id").map(String::as_str), Some(CLIENT_ID));
            assert_eq!(q.get("code_challenge_method").map(String::as_str), Some("S256"));
            assert!(q["scope"].split(' ').any(|x| x == "openid"), "{q:?}");
            let pending = Code {
                nonce: q["nonce"].clone(),
                challenge: q["code_challenge"].clone(),
                redirect_uri: q["redirect_uri"].clone(),
                sub: None,
            };
            if st.siwe {
                let request = format!("req-{}", rand::random::<u64>());
                let siwe_nonce = format!("{:016x}", rand::random::<u64>());
                st.siwe_requests.insert(
                    request.clone(),
                    SiweRequest { code: pending, state: q["state"].clone(), siwe_nonce: siwe_nonce.clone() },
                );
                let domain = s.issuer.trim_start_matches("http://").to_string();
                return axum::Json(json!({"request": request, "nonce": siwe_nonce, "domain": domain, "uri": s.issuer}))
                    .into_response();
            }
            st.codes.insert(code.clone(), pending);
            let mut pairs = vec![("code", code.clone()), ("state", q["state"].clone())];
            if let Some(i) = &st.send_iss {
                pairs.push(("iss", i.clone()));
            }
            if q.get("response_mode").map(String::as_str) == Some("form_post") {
                let p: Vec<(&str, &str)> = pairs.iter().map(|(k, v)| (*k, v.as_str())).collect();
                return Html(form_page(&q["redirect_uri"], &p)).into_response();
            }
            let qs: Vec<String> =
                pairs.iter().map(|(k, v)| format!("{k}={}", vlpds::oauth::util::form_encode_component(v))).collect();
            let mut r = axum::http::StatusCode::SEE_OTHER.into_response();
            r.headers_mut().insert("location", format!("{}?{}", q["redirect_uri"], qs.join("&")).parse().unwrap());
            r
        }
        async fn token(
            State(s): State<S>,
            headers: axum::http::HeaderMap,
            Form(f): Form<HashMap<String, String>>,
        ) -> Response {
            let bad = |e: &str| (axum::http::StatusCode::BAD_REQUEST, axum::Json(json!({"error": e}))).into_response();
            let mut st = s.st.lock();
            let authed = match st.auth {
                "basic" => headers.get("authorization").and_then(|v| v.to_str().ok()).is_some_and(|v| {
                    use base64::Engine;
                    v == format!(
                        "Basic {}",
                        base64::engine::general_purpose::STANDARD.encode(format!("{CLIENT_ID}:{CLIENT_SECRET}"))
                    )
                }),
                "jwt" => {
                    f.get("client_assertion_type").map(String::as_str)
                        == Some("urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
                        && client_jwt(&st, f.get("client_assertion"), CLIENT_ID, &format!("{}/token", s.issuer))
                }
                "signed" => client_jwt(&st, f.get("client_secret"), "TEAM", &s.issuer),
                _ => {
                    f.get("client_id").map(String::as_str) == Some(CLIENT_ID)
                        && f.get("client_secret").map(String::as_str) == Some(CLIENT_SECRET)
                }
            };
            if !authed {
                return bad("invalid_client");
            }
            let Some(c) = st.codes.remove(f.get("code").map(String::as_str).unwrap_or("")) else {
                return bad("invalid_grant");
            };
            if f.get("redirect_uri") != Some(&c.redirect_uri)
                || b64(Sha256::digest(f.get("code_verifier").map(String::as_str).unwrap_or(""))) != c.challenge
            {
                return bad("invalid_grant");
            }
            let t = now();
            let sub = c.sub.clone().unwrap_or_else(|| st.sub.clone());
            let mut claims =
                json!({"iss": s.issuer, "aud": CLIENT_ID, "sub": sub, "iat": t, "exp": t + 300, "nonce": c.nonce});
            if let (Some(e), None) = (&st.email, &c.sub) {
                claims["email"] = json!(e);
                claims["email_verified"] = json!(true);
            }
            let (key, kid) = match &st.alt {
                Some((k, kid)) => (k.clone(), kid.clone()),
                None => (st.key.clone(), st.kid.clone()),
            };
            let mut header = json!({"alg": "ES256", "kid": kid, "typ": "JWT"});
            if let Some(t) = &st.tweak {
                t(&mut header, &mut claims);
            }
            let id_token = sign(&key, &header, &claims);
            axum::Json(json!({"access_token": "at", "token_type": "Bearer", "id_token": id_token})).into_response()
        }
        /// The wallet's signed message: the adapter checks it names this
        /// adapter and the request's nonce, recovers the signer, and issues
        /// a code whose subject is the wallet's address.
        async fn siwe(State(s): State<S>, Form(f): Form<HashMap<String, String>>) -> Response {
            let bad = |e: &str| (axum::http::StatusCode::BAD_REQUEST, e.to_string()).into_response();
            let mut st = s.st.lock();
            let Some(req) = st.siwe_requests.remove(f.get("request").map(String::as_str).unwrap_or("")) else {
                return bad("unknown request");
            };
            let msg = f.get("message").cloned().unwrap_or_default();
            let domain = s.issuer.trim_start_matches("http://");
            let lines: Vec<&str> = msg.lines().collect();
            let header = format!("{domain} wants you to sign in with your Ethereum account:");
            let field = |k: &str| lines.iter().find_map(|l| l.strip_prefix(k)).map(str::to_string);
            if lines.first() != Some(&header.as_str())
                || field("Nonce: ").as_deref() != Some(req.siwe_nonce.as_str())
                || field("Chain ID: ").as_deref() != Some("1")
                || field("URI: ").as_deref() != Some(s.issuer.as_str())
            {
                return bad("message doesn't match the request");
            }
            let Some(claimed) = lines.get(1).map(|a| a.to_ascii_lowercase()) else { return bad("no address") };
            match siwe_signer(&msg, f.get("signature").map(String::as_str).unwrap_or("")) {
                Some(addr) if addr == claimed => {}
                _ => return bad("signature isn't by the address in the message"),
            }
            let code = format!("code-{}", rand::random::<u64>());
            let mut c = req.code;
            c.sub = Some(format!("eip155:1:{claimed}"));
            let redirect = format!(
                "{}?code={code}&state={}",
                c.redirect_uri,
                vlpds::oauth::util::form_encode_component(&req.state)
            );
            st.codes.insert(code, c);
            let mut r = axum::http::StatusCode::SEE_OTHER.into_response();
            r.headers_mut().insert("location", redirect.parse().unwrap());
            r
        }
        let router = axum::Router::new()
            .route("/siwe", axum::routing::post(siwe))
            .route("/.well-known/openid-configuration", axum::routing::get(discovery))
            .route("/jwks", axum::routing::get(jwks))
            .route("/authorize", axum::routing::get(authorize))
            .route("/token", axum::routing::post(token))
            .with_state(s);
        tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        Idp { issuer, state, jwks_hits }
    }

    pub(crate) fn tweak(&self, f: impl Fn(&mut J, &mut J) + Send + Sync + 'static) {
        self.state.lock().tweak = Some(Arc::new(f));
    }

    pub(crate) fn untweak(&self) {
        let mut st = self.state.lock();
        st.tweak = None;
        st.alt = None;
    }
}

fn admin(s: &Srv) -> String {
    use base64::Engine;
    let _ = s;
    format!("Basic {}", base64::engine::general_purpose::STANDARD.encode("admin:dev-admin-token"))
}

pub(crate) async fn admin_post(s: &Srv, nsid: &str, body: J) -> (u16, J) {
    let r = s
        .http
        .post(format!("{}/xrpc/{nsid}", s.base))
        .header("authorization", admin(s))
        .json(&body)
        .send()
        .await
        .unwrap();
    (r.status().as_u16(), r.json().await.unwrap_or(J::Null))
}

pub(crate) async fn admin_get(s: &Srv, nsid: &str) -> (u16, J) {
    let r = s.http.get(format!("{}/xrpc/{nsid}", s.base)).header("authorization", admin(s)).send().await.unwrap();
    (r.status().as_u16(), r.json().await.unwrap_or(J::Null))
}

pub(crate) async fn add_provider(s: &Srv, idp: &Idp, id: &str, extra: J) {
    let mut p = json!({
        "id": id,
        "name": "Example",
        "issuer": idp.issuer,
        "clientId": CLIENT_ID,
        "clientAuth": {"method": "client_secret_basic", "secret": {"value": CLIENT_SECRET}},
    });
    for (k, v) in extra.as_object().unwrap() {
        p[k] = v.clone();
    }
    let (st, j) = admin_post(s, "vlpds.admin.putSignInProvider", json!({"provider": p})).await;
    assert_eq!(st, 200, "{j}");
}

fn unescape(s: &str) -> String {
    s.replace("&amp;", "&")
}

/// The href of the first link starting with `prefix`.
pub(crate) fn href(html: &str, prefix: &str) -> Option<String> {
    let pat = format!("href=\"{prefix}");
    let i = html.find(&pat)? + 6;
    Some(unescape(&html[i..i + html[i..].find('"').unwrap()]))
}

pub(crate) fn location(h: &reqwest::header::HeaderMap) -> String {
    h.get("location").expect("location").to_str().unwrap().to_string()
}

/// Follows a start link to the provider and back: the callback's response
/// in `b`. form_post responses are posted cross-site (no cookie) and the
/// handoff followed with the cookie.
pub(crate) async fn through_idp(s: &Srv, b: &mut Browser, start: &str) -> Page {
    let (st, h, body) = b.get(s, &format!("{}{start}", s.base)).await;
    assert_eq!(st, 303, "start: {body}");
    let to_idp = location(&h);
    let r = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().unwrap();
    let resp = r.get(&to_idp).send().await.unwrap();
    if resp.status().as_u16() == 303 {
        let back = location(resp.headers());
        return b.get(s, &back).await;
    }
    let html = resp.text().await.unwrap();
    let action = html.split("action=\"").nth(1).unwrap().split('"').next().unwrap().to_string();
    let mut pairs = Vec::new();
    for part in html.split("<input type=\"hidden\" name=\"").skip(1) {
        let name = part.split('"').next().unwrap().to_string();
        let value = part.split("value=\"").nth(1).unwrap().split('"').next().unwrap().to_string();
        pairs.push((name, value));
    }
    let body = pairs
        .iter()
        .map(|(k, v)| format!("{k}={}", vlpds::oauth::util::form_encode_component(v)))
        .collect::<Vec<_>>()
        .join("&");
    let post = r
        .post(&action)
        .header("content-type", "application/x-www-form-urlencoded")
        .header("sec-fetch-site", "cross-site")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(post.status().as_u16(), 303, "form_post: {}", post.text().await.unwrap());
    let handoff = location(post.headers());
    assert!(handoff.starts_with("/oauth/federated/callback/") && handoff.contains("?handoff="), "{handoff}");
    b.get(s, &format!("{}{handoff}", s.base)).await
}

/// Signs `acct` in on `/oauth/account` with the password.
pub(crate) async fn device_sign_in(s: &Srv, b: &mut Browser, acct: &Account) {
    let (_, _, html) = b.get(s, &format!("{}/oauth/account", s.base)).await;
    let csrf = csrf_of(&html);
    let (st, h, body) = b
        .post(
            s,
            "/oauth/account/sign-in",
            &[("csrf", &csrf), ("identifier", &acct.handle), ("password", PASSWORD), ("action", "sign-in")],
        )
        .await;
    assert_eq!((st, location(&h)), (303, "/oauth/account".to_string()), "{body}");
}

/// Links the provider's current user to `acct` from `/oauth/account`.
pub(crate) async fn link(s: &Srv, b: &mut Browser, acct: &Account) -> String {
    device_sign_in(s, b, acct).await;
    let (_, _, html) = b.get(s, &format!("{}/oauth/account", s.base)).await;
    assert!(html.contains("Sign-in methods"), "{html}");
    let add = href(&html, "/oauth/federated/start?provider=").expect("an Add link");
    let (st, h, body) = through_idp(s, b, &add).await;
    assert_eq!(st, 303, "{body}");
    location(&h)
}

struct Setup {
    s: Srv,
    idp: Idp,
    acct: Account,
}

async fn setup(provider_extra: J) -> Setup {
    let s = spawn().await;
    let idp = Idp::start().await;
    add_provider(&s, &idp, "example", provider_extra).await;
    let acct = create_account(&s, "fed").await;
    Setup { s, idp, acct }
}

/// PAR + the authorization page, then the provider's start link: the
/// callback's response.
async fn oauth_via_provider(s: &Srv, b: &mut Browser, f: &Flow<'_>, p: &Pkce) -> (String, Page) {
    let ru = f.request_uri(s, p, "st-1").await;
    let (st, _, html) = b.authorize(s, f, &ru).await;
    assert_eq!(st, 200, "{html}");
    let start = href(&html, "/oauth/federated/start?provider=").expect("a provider button on the sign-in page");
    (ru, through_idp(s, b, &start).await)
}

async fn consent_and_token(
    s: &Srv,
    b: &mut Browser,
    f: &Flow<'_>,
    p: &Pkce,
    ru: &str,
    html: &str,
    did: &str,
) -> Tokens {
    assert!(html.contains("Authorize access"), "expected consent: {html}");
    let csrf = csrf_of(html);
    let (st, h, body) = b
        .post(s, "/oauth/authorize/consent", &[("request_uri", ru), ("csrf", &csrf), ("did", did), ("action", "allow")])
        .await;
    assert_eq!(st, 303, "{body}");
    let (_, q) = location_params(&h);
    tokens(&exchange(s, f, &q["code"], p, &[]).await)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn link_then_sign_in_through_to_tokens() {
    let Setup { s, idp, acct } = setup(json!({})).await;
    let (st, list) = admin_get(&s, "vlpds.admin.listSignInProviders").await;
    assert_eq!(st, 200);
    assert_eq!(list["providers"][0]["clientAuth"]["secret"], json!({"stored": "wrapped"}), "{list}");
    assert!(!list.to_string().contains(CLIENT_SECRET), "the secret never comes back");
    assert_eq!(
        (list["available"].as_bool(), &list["providers"][0]["callbackUrl"]),
        (Some(true), &json!(format!("{}/oauth/federated/callback/example", s.base)))
    );

    let mut b = Browser::default();
    assert_eq!(link(&s, &mut b, &acct).await, "/oauth/account?notice=linked");
    let (_, ids) = s.bearer(&acct.jwt, "vlpds.server.listFederatedIdentities", false, None).await;
    assert_eq!(ids["identities"][0]["display"], "person@example.com", "{ids}");
    assert_eq!(ids["identities"][0]["provider"], "example");
    let mail = latest_mail(&s, "fed@example.com").await;
    assert!(mail.contains("You can now sign in to your account with Example"), "{mail}");

    // a fresh browser signs in with the provider alone (no TOTP here)
    let key = DpopKey::new();
    let f = Flow::loopback("atproto transition:generic", &key);
    let p = pkce();
    let mut b2 = Browser::default();
    let (ru, (st, _, html)) = oauth_via_provider(&s, &mut b2, &f, &p).await;
    assert_eq!(st, 200, "{html}");
    let t = consent_and_token(&s, &mut b2, &f, &p, &ru, &html, &acct.did).await;
    let r = xrpc_dpop(&s, &key, &t.access, "GET", "com.atproto.server.getSession", None).await;
    assert_eq!((r.status, &r.body["did"]), (200, &json!(acct.did)), "{}", r.body);

    // the sign-in log names the provider
    let (_, sec) = s.bearer(&acct.jwt, "vlpds.server.getSignInSecurity", false, None).await;
    let recent = sec["recentSignIns"].as_array().unwrap();
    assert!(recent.iter().any(|e| e["method"] == "federated" && e["provider"] == "Example"), "{sec}");
    let _ = idp;
}

async fn latest_mail(s: &Srv, email: &str) -> String {
    let r = s
        .http
        .get(format!("{}/xrpc/vlpds.admin.getDevMail?email={email}", s.base))
        .header("authorization", admin(s))
        .send()
        .await
        .unwrap();
    let j: J = r.json().await.unwrap_or(J::Null);
    j["messages"].as_array().and_then(|m| m.last()).map(|m| m.to_string()).unwrap_or_default()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn form_post_hands_off_to_a_same_origin_get_once() {
    let Setup { s, idp, acct } = setup(json!({"responseMode": "form_post", "clientAuth": {"method": "client_secret_post", "secret": {"value": CLIENT_SECRET}}})).await;
    idp.state.lock().auth = "post";
    let mut b = Browser::default();
    assert_eq!(link(&s, &mut b, &acct).await, "/oauth/account?notice=linked");

    // a sign-in whose handoff is replayed afterwards
    let mut b2 = Browser::default();
    let (_, _, html) = b2.get(&s, &format!("{}/oauth/account", s.base)).await;
    let start = href(&html, "/oauth/federated/start?provider=").expect("provider button");
    let (st, h, _) = b2.get(&s, &format!("{}{start}", s.base)).await;
    assert_eq!(st, 303);
    let r = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().unwrap();
    let html = r.get(location(&h)).send().await.unwrap().text().await.unwrap();
    let field =
        |n: &str| html.split(&format!("name=\"{n}\" value=\"")).nth(1).unwrap().split('"').next().unwrap().to_string();
    let body = format!("code={}&state={}", field("code"), field("state"));
    let post = |body: String| {
        r.post(format!("{}/oauth/federated/callback/example", s.base))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(body)
            .send()
    };
    let first = post(body.clone()).await.unwrap();
    assert_eq!(first.status().as_u16(), 303);
    let handoff = location(first.headers());
    // a second post for the same state is refused: one handoff per state
    assert_eq!(post(body).await.unwrap().status().as_u16(), 400);
    // the handoff without the browser's cookie is refused (and not used up)
    let other = r.get(format!("{}{handoff}", s.base)).send().await.unwrap();
    assert_eq!(other.status().as_u16(), 400);
    let (st, h, body) = b2.get(&s, &format!("{}{handoff}", s.base)).await;
    assert_eq!((st, location(&h)), (303, "/oauth/account".to_string()), "{body}");
    let (st, _, again) = b2.get(&s, &format!("{}{handoff}", s.base)).await;
    assert_eq!(st, 400, "a handoff works once: {again}");
    assert!(again.contains("expired or was already used"), "{again}");
}

/// One provider sign-in from a fresh browser on `/oauth/account`: the
/// callback's response.
async fn account_page_sign_in(s: &Srv) -> Page {
    let mut b = Browser::default();
    let (_, _, html) = b.get(s, &format!("{}/oauth/account", s.base)).await;
    let start = href(&html, "/oauth/federated/start?provider=").expect("provider button");
    through_idp(s, &mut b, &start).await
}

fn signed_in(p: &Page) -> bool {
    p.0 == 303 && location(&p.1) == "/oauth/account"
}

fn refused(p: &Page) -> bool {
    p.0 == 303 && location(&p.1) == "/oauth/account?add=1&error=federated"
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_id_token_check_refuses() {
    let Setup { s, idp, acct } = setup(json!({})).await;
    link(&s, &mut Browser::default(), &acct).await;
    assert!(signed_in(&account_page_sign_in(&s).await));
    let iss = idp.issuer.clone();
    type T = fn(&mut J, &mut J, &str);
    let cases: Vec<(&str, T)> = vec![
        ("wrong iss", |_, c, i| c["iss"] = json!(format!("{i}/other"))),
        ("wrong aud", |_, c, _| c["aud"] = json!("someone-else")),
        ("several aud without azp", |_, c, _| c["aud"] = json!([CLIENT_ID, "other"])),
        ("wrong azp", |_, c, _| c["azp"] = json!("other")),
        ("wrong nonce", |_, c, _| c["nonce"] = json!("not-it")),
        ("no nonce", |_, c, _| {
            c.as_object_mut().unwrap().remove("nonce");
        }),
        ("expired", |_, c, _| c["exp"] = json!(now() - 120)),
        ("issued in the future", |_, c, _| c["iat"] = json!(now() + 600)),
        ("issued long ago", |_, c, _| c["iat"] = json!(now() - 3600)),
        ("no kid", |h, _, _| {
            h.as_object_mut().unwrap().remove("kid");
        }),
        ("alg none", |h, _, _| h["alg"] = json!("none")),
        ("alg HS256", |h, _, _| h["alg"] = json!("HS256")),
        ("alg RS256 on an EC key", |h, _, _| h["alg"] = json!("RS256")),
        ("no sub", |_, c, _| c["sub"] = json!("")),
    ];
    for (what, t) in cases {
        let i = iss.clone();
        idp.tweak(move |h, c| t(h, c, &i));
        assert!(refused(&account_page_sign_in(&s).await), "{what} was accepted");
    }
    idp.untweak();
    // a signature by a key the provider never published
    idp.state.lock().alt = Some((SigningKey::generate(), "k1".into()));
    assert!(refused(&account_page_sign_in(&s).await), "forged signature accepted");
    idp.untweak();
    // required claims
    let (st, _) = admin_post(
        &s,
        "vlpds.admin.putSignInProvider",
        json!({"provider": {"id": "example", "name": "Example", "issuer": idp.issuer, "clientId": CLIENT_ID,
               "clientAuth": {"method": "client_secret_basic"}, "requiredClaims": {"hd": "example.com"}}}),
    )
    .await;
    assert_eq!(st, 200, "the stored secret is kept when left out");
    assert!(refused(&account_page_sign_in(&s).await), "missing hd accepted");
    idp.tweak(|_, c| c["hd"] = json!("example.com"));
    assert!(signed_in(&account_page_sign_in(&s).await));
    // a provider that sends iss on the response must send ours
    idp.state.lock().send_iss = Some("https://evil.example".into());
    assert!(refused(&account_page_sign_in(&s).await), "mix-up iss accepted");
    idp.state.lock().send_iss = Some(idp.issuer.clone());
    assert!(signed_in(&account_page_sign_in(&s).await));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unknown_kid_refetches_at_most_once_a_minute() {
    let Setup { s, idp, acct } = setup(json!({})).await;
    link(&s, &mut Browser::default(), &acct).await;
    let hits = idp.jwks_hits.load(Ordering::SeqCst);
    assert!(hits >= 1);
    // the provider rotates to a new key: one refetch finds it
    {
        let mut st = idp.state.lock();
        st.key = SigningKey::generate();
        st.kid = "k2".into();
    }
    assert!(signed_in(&account_page_sign_in(&s).await), "rotated key");
    let after_rotation = idp.jwks_hits.load(Ordering::SeqCst);
    assert_eq!(after_rotation, hits + 1);
    // made-up kids: no refetch inside the window
    idp.state.lock().alt = Some((SigningKey::generate(), "made-up".into()));
    assert!(refused(&account_page_sign_in(&s).await));
    assert!(refused(&account_page_sign_in(&s).await));
    assert_eq!(idp.jwks_hits.load(Ordering::SeqCst), after_rotation, "unknown kids don't refetch within a minute");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn state_is_bound_to_the_browser_and_used_once() {
    let Setup { s, idp, acct } = setup(json!({})).await;
    link(&s, &mut Browser::default(), &acct).await;
    let mut b = Browser::default();
    let (_, _, html) = b.get(&s, &format!("{}/oauth/account", s.base)).await;
    let start = href(&html, "/oauth/federated/start?provider=").unwrap();
    let (_, h, _) = b.get(&s, &format!("{}{start}", s.base)).await;
    let r = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().unwrap();
    let back = location(r.get(location(&h)).send().await.unwrap().headers());
    // an attacker's browser (another cookie, or none) can't finish it
    let mut attacker = Browser::default();
    let _ = attacker.get(&s, &format!("{}/oauth/account", s.base)).await;
    let (st, _, body) = attacker.get(&s, &back).await;
    assert_eq!(st, 400, "{body}");
    assert!(body.contains("another browser"), "{body}");
    // the right browser still can, once
    assert!(signed_in(&b.get(&s, &back).await));
    let (st, _, body) = b.get(&s, &back).await;
    assert_eq!(st, 400, "replayed callback: {body}");
    assert!(body.contains("expired or was already used"));
    let _ = idp;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn identities_are_never_matched_by_email_and_belong_to_one_account() {
    let Setup { s, idp, acct } = setup(json!({})).await;
    // the provider's email is the account's: still no sign-in without a link
    idp.state.lock().email = Some("fed@example.com".into());
    let p = account_page_sign_in(&s).await;
    assert_eq!(location(&p.1), "/oauth/account?add=1&error=unknown_identity");
    link(&s, &mut Browser::default(), &acct).await;
    // another account can't take it
    let other = create_account(&s, "fed2").await;
    assert_eq!(link(&s, &mut Browser::default(), &other).await, "/oauth/account?notice=taken");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn linking_needs_a_fresh_sign_in_and_a_csrf_token() {
    let Setup { s, idp, acct } = setup(json!({})).await;
    let mut b = Browser::default();
    device_sign_in(&s, &mut b, &acct).await;
    let (_, _, html) = b.get(&s, &format!("{}/oauth/account", s.base)).await;
    let add = href(&html, "/oauth/federated/start?provider=").unwrap();
    // no csrf, or another device's link
    let bare = add.split("&csrf=").next().unwrap().to_string();
    let (st, _, _) = b.get(&s, &format!("{}{bare}", s.base)).await;
    assert_eq!(st, 403);
    let (st, _, _) = Browser::default().get(&s, &format!("{}{add}", s.base)).await;
    assert_eq!(st, 403);
    // a sign-in older than the step-up window: sign in again first
    let dev = b.cookie.clone().unwrap();
    let dev_id = dev.trim_start_matches("vlpds-device=").to_string();
    let mut d = vlpds::oauth::store::get_device(&s.app, &dev_id).await.unwrap().unwrap();
    for a in &mut d.accounts {
        a.authenticated_at -= 3600;
    }
    vlpds::oauth::store::put_device(&s.app, &d).await.unwrap();
    let (st, h, _) = b.get(&s, &format!("{}{add}", s.base)).await;
    assert_eq!((st, location(&h)), (303, "/oauth/account?notice=stale".to_string()));
    let (_, _, html) = b.get(&s, &format!("{}/oauth/account", s.base)).await;
    assert!(html.contains("sign in again"), "{html}");
    let _ = idp;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn totp_still_applies_after_a_provider_sign_in() {
    let Setup { s, idp, acct } = setup(json!({})).await;
    link(&s, &mut Browser::default(), &acct).await;
    let (secret, step) = enable_totp(&s, &acct).await;
    let key = DpopKey::new();
    let f = Flow::loopback("atproto", &key);
    let p = pkce();
    let mut b = Browser::default();
    let (ru, (st, _, html)) = oauth_via_provider(&s, &mut b, &f, &p).await;
    assert_eq!(st, 200, "{html}");
    assert!(html.contains("Authenticator code"), "the second factor is asked: {html}");
    assert!(!html.contains("Authorize access"));
    let code = vlpds::totp::code_for_step(&secret, step + 1);
    let (st, html) = b.second_factor(&s, &ru, &csrf_of(&html), &code).await;
    assert_eq!(st, 200, "{html}");
    let t = consent_and_token(&s, &mut b, &f, &p, &ru, &html, &acct.did).await;
    assert!(!t.access.is_empty());
    let _ = idp;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unlink_revokes_and_never_leaves_an_account_without_a_way_in() {
    let Setup { s, idp, acct } = setup(json!({})).await;
    let mut b = Browser::default();
    link(&s, &mut b, &acct).await;
    // an OAuth session signed in with the provider
    let key = DpopKey::new();
    let f = Flow::loopback("atproto", &key);
    let p = pkce();
    let mut b2 = Browser::default();
    let (ru, (_, _, html)) = oauth_via_provider(&s, &mut b2, &f, &p).await;
    let t = consent_and_token(&s, &mut b2, &f, &p, &ru, &html, &acct.did).await;
    let ok = xrpc_dpop(&s, &key, &t.access, "GET", "com.atproto.server.getSession", None).await;
    assert_eq!(ok.status, 200);

    // the account without its password: the identity is its only way in
    let saved = s.app.account(&acct.did).await.ok().unwrap().password_hash;
    s.app
        .mutate_account(&acct.did, false, false, false, |a| {
            a.password_hash = String::new();
            Ok(true)
        })
        .await
        .ok()
        .unwrap();
    let (_, _, html) = b.get(&s, &format!("{}/oauth/account", s.base)).await;
    let csrf = csrf_of(&html);
    let r = hidden_field(&html, "ref").expect("a Remove form");
    let (st, h, _) = b.post(&s, "/oauth/account/unlink", &[("csrf", &csrf), ("did", &acct.did), ("ref", &r)]).await;
    assert_eq!((st, location(&h)), (303, "/oauth/account?notice=last".to_string()));
    s.app
        .mutate_account(&acct.did, false, false, false, move |a| {
            a.password_hash = saved.clone();
            Ok(true)
        })
        .await
        .ok()
        .unwrap();

    let (st, h, _) = b.post(&s, "/oauth/account/unlink", &[("csrf", &csrf), ("did", &acct.did), ("ref", &r)]).await;
    assert_eq!((st, location(&h)), (303, "/oauth/account?notice=unlinked".to_string()));
    let gone = xrpc_dpop(&s, &key, &t.access, "GET", "com.atproto.server.getSession", None).await;
    assert_eq!(gone.status, 401, "the session it signed in ended: {}", gone.body);
    // b2's device sign-in is void too, and the identity signs in nowhere
    let (_, _, html) = b2.get(&s, &format!("{}/oauth/account", s.base)).await;
    assert!(!html.contains(&acct.did), "{html}");
    assert_eq!(location(&account_page_sign_in(&s).await.1), "/oauth/account?add=1&error=unknown_identity");
    // the claim went with it: another account may link it now
    let other = create_account(&s, "fed3").await;
    assert_eq!(link(&s, &mut Browser::default(), &other).await, "/oauth/account?notice=linked");
    let _ = idp;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_removed_provider_leaves_its_identities_dormant() {
    let Setup { s, idp, acct } = setup(json!({})).await;
    link(&s, &mut Browser::default(), &acct).await;
    let (st, _) = admin_post(&s, "vlpds.admin.removeSignInProvider", json!({"id": "example"})).await;
    assert_eq!(st, 200);
    let (_, ids) = s.bearer(&acct.jwt, "vlpds.server.listFederatedIdentities", false, None).await;
    assert_eq!(
        (ids["identities"][0]["dormant"].as_bool(), ids["providers"].as_array().map(Vec::len)),
        (Some(true), Some(0)),
        "{ids}"
    );
    let r = s.http.get(format!("{}/oauth/federated/start?provider=example&account=1", s.base)).send().await.unwrap();
    assert_eq!(r.status().as_u16(), 404);
    let (_, _, html) = Browser::default().get(&s, &format!("{}/oauth/account", s.base)).await;
    assert!(!html.contains("/oauth/federated/start"), "no buttons");
    // added back with the same issuer: it works again
    add_provider(&s, &idp, "renamed", json!({})).await;
    assert!(signed_in(&account_page_sign_in(&s).await));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn provider_config_is_validated_and_audited() {
    let s = spawn().await;
    let idp = Idp::start().await;
    let put = |p: J| admin_post(&s, "vlpds.admin.putSignInProvider", json!({"provider": p}));
    let base = json!({"id": "x", "name": "X", "issuer": idp.issuer, "clientId": CLIENT_ID,
                      "clientAuth": {"method": "client_secret_basic", "secret": {"value": CLIENT_SECRET}}});
    let with = |k: &str, v: J| {
        let mut p = base.clone();
        p[k] = v;
        p
    };
    assert_eq!(put(with("id", json!("Bad Id"))).await.0, 400);
    assert_eq!(put(with("idTokenAlgs", json!(["HS256"]))).await.0, 400);
    assert_eq!(put(with("icon", json!("https://evil.example/x.png"))).await.0, 400);
    assert_eq!(put(with("issuer", json!("http://127.0.0.1:1"))).await.1["error"], "ProviderUnreachable");
    let mut keyed = base.clone();
    keyed["clientAuth"] = json!({"method": "private_key_jwt", "key": {"value": "not a key"}, "keyId": "k"});
    assert_eq!(put(keyed).await.0, 400);
    let (st, j) = put(base.clone()).await;
    assert_eq!(st, 200, "{j}");
    // stored wrapped, never in the clear
    use object_store::ObjectStoreExt;
    let path = vlpds::federated::config::config_path(&s.app.store);
    let stored = s.app.store.raw.get(&path).await.unwrap().bytes().await.unwrap();
    let stored = String::from_utf8_lossy(&stored);
    assert!(stored.contains("\"wrapped\": \"vw1.") && !stored.contains(CLIENT_SECRET), "{stored}");
    let (st, j) = admin_post(&s, "vlpds.admin.rewrapSecrets", json!({"dryRun": true, "checkVersions": true})).await;
    assert_eq!((st, &j["providerSecrets"]), (200, &json!(0)), "{j}");
    let (st, j) = admin_post(&s, "vlpds.admin.putSignInProvider", json!({"provider": base, "ifVersion": 0})).await;
    assert_eq!((st, &j["error"]), (409, &json!("VersionMismatch")));
    // unauthenticated callers get nothing
    let r = s.http.get(format!("{}/xrpc/vlpds.admin.listSignInProviders", s.base)).send().await.unwrap();
    assert_eq!(r.status().as_u16(), 401);
    let (_, d) = {
        let r = s.http.get(format!("{}/xrpc/vlpds.server.describeSignInProviders", s.base)).send().await.unwrap();
        (r.status().as_u16(), r.json::<J>().await.unwrap())
    };
    assert_eq!(d["providers"][0]["id"], "x", "{d}");
}

/// A node whose cluster runs level 1 offers nothing, even with providers
/// saved; level 2 is what turns it on.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn level_one_offers_nothing() {
    use crate::common::{cluster_node, lease, Auth, TestServer};
    let store = Arc::new(object_store::memory::InMemory::new());
    let old: TestServer = cluster_node("fed-old", store.clone(), 2, |c| {
        lease(c).levels = vlsync_store::version::Window { min: 1, max: 1 }
    })
    .await;
    let new: TestServer = cluster_node("fed-new", store.clone(), 2, |_| {}).await;
    let idp = Idp::start().await;
    let p = json!({"provider": {"id": "example", "name": "Example", "issuer": idp.issuer, "clientId": CLIENT_ID,
                                 "clientAuth": {"method": "client_secret_basic", "secret": {"value": CLIENT_SECRET}}}});
    // nothing is written below the level
    new.xrpc.post("vlpds.admin.putSignInProvider", &p, &Auth::Admin).await.err(400, "FeatureLevelRequired");
    new.xrpc
        .post("vlpds.admin.removeSignInProvider", &json!({"id": "example"}), &Auth::Admin)
        .await
        .err(400, "FeatureLevelRequired");
    // a provider in the bucket all the same (a level-2 build that ran here) isn't offered
    let mut stored: vlpds::federated::config::Provider = serde_json::from_value(json!({
        "id": "example", "name": "Example", "issuer": idp.issuer, "clientId": CLIENT_ID,
        "clientAuth": {"method": "client_secret_basic", "secret": {"wrapped": "vw1.x.eA"}}}))
    .unwrap();
    stored.scopes = vec!["openid".into()];
    vlpds::federated::config::put(&new.app.federated.providers, &new.app.store, stored, None).await.unwrap();
    let list = new.xrpc.get("vlpds.admin.listSignInProviders", &[], &Auth::Admin).await.ok();
    assert_eq!((list["available"].as_bool(), &list["featureLevel"]["active"]), (Some(false), &json!(1)), "{list}");
    assert!(list["reason"].as_str().unwrap().contains("level 2"));
    let d = new.xrpc.get("vlpds.server.describeSignInProviders", &[], &Auth::None).await.ok();
    assert_eq!(d["providers"], json!([]));
    let http = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().unwrap();
    for path in [
        "/oauth/federated/start?provider=example&account=1",
        "/oauth/federated/callback/example?state=aaaaaaaaaaaaaaaaaaaa",
    ] {
        let r = http.get(format!("{}{path}", new.url)).send().await.unwrap();
        assert_eq!(r.status().as_u16(), 404, "{path}");
    }
    let page = http.get(format!("{}/oauth/account", new.url)).send().await.unwrap().text().await.unwrap();
    assert!(!page.contains("/oauth/federated/start"), "no buttons at level 1");
    drop(old);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_admin_cli_puts_lists_and_removes() {
    use crate::common::admin_cli;
    let s = spawn().await;
    let idp = Idp::start().await;
    let dir = std::env::temp_dir().join(format!("vlpds-fed-cli-{}", rand::random::<u64>()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("provider.json");
    let p = json!({"id": "cli", "name": "From the CLI", "issuer": idp.issuer, "clientId": CLIENT_ID,
                   "clientAuth": {"method": "client_secret_post", "secret": {"value": CLIENT_SECRET}}});
    std::fs::write(&file, p.to_string()).unwrap();
    let (r, out) = admin_cli(&s.base, &["signin-provider", "put", file.to_str().unwrap()]).await;
    r.unwrap();
    assert!(out.contains("saved cli"), "{out}");
    let (r, out) = admin_cli(&s.base, &["signin-provider", "list"]).await;
    r.unwrap();
    assert!(
        out.contains("From the CLI") && out.contains("client_secret_post") && !out.contains(CLIENT_SECRET),
        "{out}"
    );
    assert!(out.contains("/oauth/federated/callback/cli"), "{out}");
    let (r, out) = admin_cli(&s.base, &["signin-provider", "remove", "cli"]).await;
    r.unwrap();
    assert!(out.contains("removed cli"), "{out}");
    let (r, _) = admin_cli(&s.base, &["signin-provider", "remove", "cli"]).await;
    assert!(r.is_err());
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn private_key_jwt_and_signed_client_secrets() {
    use p256::pkcs8::EncodePrivateKey;
    let sk = p256::SecretKey::generate();
    let pem = sk.to_pkcs8_pem(Default::default()).unwrap().to_string();
    let vk = *p256::ecdsa::SigningKey::from(&sk).verifying_key();
    for (mode, auth) in [
        ("jwt", json!({"method": "private_key_jwt", "key": {"value": pem}, "keyId": "client-key-1"})),
        (
            "signed",
            json!({"method": "client_secret_post", "key": {"value": pem}, "keyId": "client-key-1",
                   "signedSecret": {"issuer": "TEAM", "lifetimeSecs": 600}}),
        ),
    ] {
        let Setup { s, idp, acct } = setup(json!({"clientAuth": auth})).await;
        {
            let mut st = idp.state.lock();
            st.auth = mode;
            st.client_key = Some(vk);
        }
        assert_eq!(link(&s, &mut Browser::default(), &acct).await, "/oauth/account?notice=linked", "{mode}");
        assert!(signed_in(&account_page_sign_in(&s).await), "{mode}: the cached secret again");
        idp.state.lock().client_key = Some(*p256::ecdsa::SigningKey::generate().verifying_key());
        assert!(refused(&account_page_sign_in(&s).await), "{mode}: the provider no longer knows the key");
        let (_, list) = admin_get(&s, "vlpds.admin.listSignInProviders").await;
        assert!(!list.to_string().contains("PRIVATE"), "{list}");
    }
    // a key without its id is refused
    let s = spawn().await;
    let idp = Idp::start().await;
    let (st, j) = admin_post(
        &s,
        "vlpds.admin.putSignInProvider",
        json!({"provider": {"id": "k", "name": "K", "issuer": idp.issuer, "clientId": CLIENT_ID,
               "clientAuth": {"method": "private_key_jwt", "key": {"value": pem}}}}),
    )
    .await;
    assert_eq!((st, &j["error"]), (400, &json!("InvalidProvider")), "{j}");
}

// ---------------------------------------------------------------- review fixes

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn secrets_are_values_only_and_an_issuer_change_needs_them_again() {
    let s = spawn().await;
    let idp = Idp::start().await;
    let other = Idp::start().await;
    let put = |p: J| admin_post(&s, "vlpds.admin.putSignInProvider", json!({"provider": p}));
    // no file form: an admin API naming files would read anything on the node
    for auth in [
        json!({"method": "client_secret_basic", "secret": {"file": "/proc/self/environ"}}),
        json!({"method": "private_key_jwt", "key": {"file": "/etc/passwd"}, "keyId": "k"}),
    ] {
        let (st, j) =
            put(json!({"id": "x", "name": "X", "issuer": idp.issuer, "clientId": CLIENT_ID, "clientAuth": auth})).await;
        assert_eq!(st, 400, "{j}");
    }
    // a padded id is refused before anything is wrapped under it
    let (st, j) = put(json!({"id": " x", "name": "X", "issuer": idp.issuer, "clientId": CLIENT_ID,
                             "clientAuth": {"method": "client_secret_basic", "secret": {"value": CLIENT_SECRET}}}))
    .await;
    assert_eq!((st, &j["error"]), (400, &json!("InvalidProvider")), "{j}");
    let base = json!({"id": "x", "name": "X", "issuer": idp.issuer, "clientId": CLIENT_ID,
                      "clientAuth": {"method": "client_secret_basic", "secret": {"value": CLIENT_SECRET}}});
    assert_eq!(put(base).await.0, 200);
    // the same issuer keeps the stored secret; another issuer doesn't
    let keep = json!({"id": "x", "name": "Renamed", "issuer": idp.issuer, "clientId": CLIENT_ID,
                      "clientAuth": {"method": "client_secret_basic"}});
    assert_eq!(put(keep).await.0, 200);
    let moved = json!({"id": "x", "name": "X", "issuer": other.issuer, "clientId": CLIENT_ID,
                       "clientAuth": {"method": "client_secret_basic"}});
    let (st, j) = put(moved).await;
    assert_eq!((st, &j["error"]), (400, &json!("InvalidProvider")), "the secret must be given again: {j}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_callback_for_another_provider_is_refused() {
    let Setup { s, idp, acct } = setup(json!({})).await;
    add_provider(&s, &idp, "second", json!({"issuer": Idp::start().await.issuer})).await;
    link(&s, &mut Browser::default(), &acct).await;
    let mut b = Browser::default();
    let _ = b.get(&s, &format!("{}/oauth/account", s.base)).await;
    let (_, h, _) = b.get(&s, &format!("{}/oauth/federated/start?provider=example&account=1", s.base)).await;
    let r = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().unwrap();
    let back = location(r.get(location(&h)).send().await.unwrap().headers());
    assert!(back.contains("/oauth/federated/callback/example?"), "{back}");
    let mixed = back.replace("/callback/example?", "/callback/second?");
    let (st, _, body) = b.get(&s, &mixed).await;
    assert_eq!(st, 400, "{body}");
    // refused without using the state up: the right callback still works
    assert!(signed_in(&b.get(&s, &back).await));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_link_asks_for_an_account_and_its_token_expires() {
    let Setup { s, idp, acct } = setup(json!({})).await;
    let mut b = Browser::default();
    device_sign_in(&s, &mut b, &acct).await;
    let (_, _, html) = b.get(&s, &format!("{}/oauth/account", s.base)).await;
    let add = href(&html, "/oauth/federated/start?provider=").unwrap();
    let (st, h, _) = b.get(&s, &format!("{}{add}", s.base)).await;
    assert_eq!(st, 303);
    assert!(location(&h).contains("prompt=select_account"), "{}", location(&h));
    // the token carries its issue time and is good for the step-up window
    let csrf = add.split("&csrf=").nth(1).unwrap().to_string();
    let decoded = vlpds::oauth::util::percent_decode_strict(&csrf).unwrap();
    let (at, mac) = decoded.split_once('.').unwrap();
    let old = format!("{}.{mac}", at.parse::<i64>().unwrap() - 3600);
    let stale = add.replace(&csrf, &vlpds::oauth::util::encode_uri_component(&old));
    let (st, _, _) = b.get(&s, &format!("{}{stale}", s.base)).await;
    assert_eq!(st, 403, "an old (or forged) issue time");
    // the mail names the identity that was added
    let p = through_idp(&s, &mut b, &add).await;
    assert_eq!(location(&p.1), "/oauth/account?notice=linked");
    let mail = latest_mail(&s, "fed@example.com").await;
    assert!(mail.contains("with Example (person@example.com)"), "{mail}");
    let _ = idp;
}

// ---------------------------------------------------------------- P2: signup and the account page app

/// The signup form's fields from its page.
fn signup_fields(html: &str) -> (String, String) {
    (hidden_field(html, "ticket").expect("ticket"), csrf_of(html))
}

async fn post_signup(s: &Srv, b: &mut Browser, html: &str, handle: &str, email: &str, invite: &str) -> Page {
    let (ticket, csrf) = signup_fields(html);
    b.post(
        s,
        "/oauth/federated/signup",
        &[
            ("ticket", &ticket),
            ("csrf", &csrf),
            ("handle", handle),
            ("email", email),
            ("invite_code", invite),
            ("action", "sign-up"),
        ],
    )
    .await
}

async fn session_of(s: &Srv, key: &DpopKey, t: &Tokens) -> J {
    let r = xrpc_dpop(s, key, &t.access, "GET", "com.atproto.server.getSession", None).await;
    assert_eq!(r.status, 200, "{}", r.body);
    r.body
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn signup_with_a_provider_on_the_oauth_page() {
    let s = spawn().await;
    let idp = Idp::start().await;
    add_provider(&s, &idp, "example", json!({"signup": "open", "trustEmail": true})).await;
    idp.state.lock().email = Some("newcomer@example.com".into());
    let key = DpopKey::new();
    let f = Flow::loopback("atproto transition:email", &key);
    let p = pkce();
    let mut b = Browser::default();
    let (ru, (st, _, html)) = oauth_via_provider(&s, &mut b, &f, &p).await;
    assert_eq!(st, 200, "{html}");
    assert!(html.contains("Create an account") && html.contains("newcomer@example.com"), "{html}");
    // the OAuth request lives as long as the signup ticket
    let rid = vlpds::oauth::store::request_id_from_uri(&ru).unwrap().to_string();
    let req = vlpds::oauth::store::get_request(&s.app, &rid).await.unwrap().unwrap();
    assert!(req.expires_at - chrono::Utc::now().timestamp() > 14 * 60, "{}", req.expires_at);
    assert!(html.contains("Already confirmed") && !html.contains("name=\"password\""), "{html}");
    // another browser can't use the ticket
    let (st, _, other) = post_signup(&s, &mut Browser::default(), &html, "intruder1", "x@example.com", "").await;
    assert_eq!(st, 400, "{other}");
    // a taken handle: the same ticket again with another
    let taken = create_account(&s, "taken").await;
    let first_label = taken.handle.split('.').next().unwrap().to_string();
    let (st, _, again) = post_signup(&s, &mut b, &html, &first_label, "newcomer@example.com", "").await;
    assert_eq!(st, 400, "{again}");
    assert!(again.contains("already taken") || again.contains("Handle"), "{again}");
    let handle = format!("nc{}", rand::random::<u32>() % 100000);
    let (st, _, consent) = post_signup(&s, &mut b, &again, &handle, "newcomer@example.com", "").await;
    assert_eq!(st, 200, "{consent}");
    let did = hidden_field(&consent, "did").expect("consent names the new account");
    let t = consent_and_token(&s, &mut b, &f, &p, &ru, &consent, &did).await;
    let sess = session_of(&s, &key, &t).await;
    assert_eq!((&sess["did"], &sess["emailConfirmed"]), (&json!(did), &json!(true)), "{sess}");
    // the ticket is spent
    let (st, _, _) = post_signup(&s, &mut b, &again, "another1", "newcomer@example.com", "").await;
    assert_eq!(st, 400);
    // no password: createSession never works, the provider does
    let r = s
        .http
        .post(format!("{}/xrpc/com.atproto.server.createSession", s.base))
        .json(&json!({"identifier": format!("{handle}.vlpds.test"), "password": ""}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 401);
    assert!(signed_in(&account_page_sign_in(&s).await));
    // the identity is its only way in: unlinking it is refused
    let mut b2 = Browser::default();
    let (_, _, html) = b2.get(&s, &format!("{}/oauth/account", s.base)).await;
    let start = href(&html, "/oauth/federated/start?provider=").unwrap();
    assert!(signed_in(&through_idp(&s, &mut b2, &start).await));
    let (_, _, html) = b2.get(&s, &format!("{}/oauth/account", s.base)).await;
    let r = hidden_field(&html, "ref").expect("a Remove form");
    let (_, h, _) =
        b2.post(&s, "/oauth/account/unlink", &[("csrf", &csrf_of(&html)), ("did", &did), ("ref", &r)]).await;
    assert_eq!(location(&h), "/oauth/account?notice=last");
    // the email reset sets a password; then the identity may go
    let r = s
        .http
        .post(format!("{}/xrpc/com.atproto.server.requestPasswordReset", s.base))
        .json(&json!({"email": "newcomer@example.com"}))
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success());
    let tok = dev_mail_token(&s, "newcomer@example.com", "reset_password").await;
    let r = s
        .http
        .post(format!("{}/xrpc/com.atproto.server.resetPassword", s.base))
        .json(&json!({"token": tok, "password": PASSWORD}))
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success(), "{}", r.text().await.unwrap());
    let r = s
        .http
        .post(format!("{}/xrpc/com.atproto.server.createSession", s.base))
        .json(&json!({"identifier": format!("{handle}.vlpds.test"), "password": PASSWORD}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    // the reset signed everything out, so sign in again before changing methods
    let acct = Account { did: did.clone(), handle: format!("{handle}.vlpds.test"), jwt: String::new() };
    let mut b3 = Browser::default();
    device_sign_in(&s, &mut b3, &acct).await;
    let (_, _, html) = b3.get(&s, &format!("{}/oauth/account", s.base)).await;
    let r = hidden_field(&html, "ref").unwrap();
    let (_, h, _) =
        b3.post(&s, "/oauth/account/unlink", &[("csrf", &csrf_of(&html)), ("did", &did), ("ref", &r)]).await;
    assert_eq!(location(&h), "/oauth/account?notice=unlinked");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn signup_policies_and_unverified_email() {
    let s = spawn().await;
    let idp = Idp::start().await;
    add_provider(&s, &idp, "example", json!({"signup": "invite"})).await;
    idp.state.lock().email = Some("invited@example.com".into());
    let mut b = Browser::default();
    let (_, _, html) = b.get(&s, &format!("{}/oauth/account", s.base)).await;
    let start = href(&html, "/oauth/federated/start?provider=").unwrap();
    let (st, _, form) = through_idp(&s, &mut b, &start).await;
    assert_eq!(st, 200, "{form}");
    assert!(form.contains("name=\"invite_code\"") && !form.contains("Already confirmed"), "{form}");
    let handle = format!("inv{}", rand::random::<u32>() % 100000);
    let (st, _, again) = post_signup(&s, &mut b, &form, &handle, "invited@example.com", "").await;
    assert_eq!(st, 400, "{again}");
    assert!(again.contains("invite code is required"), "{again}");
    let (st, _, again) = post_signup(&s, &mut b, &again, &handle, "invited@example.com", "nope-nope").await;
    assert_eq!(st, 400, "{again}");
    let (_, code) = admin_post(&s, "com.atproto.server.createInviteCode", json!({"useCount": 1})).await;
    let code = code["code"].as_str().unwrap().to_string();
    let (st, h, body) = post_signup(&s, &mut b, &again, &handle, "invited@example.com", &code).await;
    assert_eq!((st, location(&h)), (303, "/oauth/account".to_string()), "{body}");
    // without trustEmail the address isn't confirmed
    let did = s.app.resolve_handle(&format!("{handle}.vlpds.test")).await.ok().flatten().unwrap();
    assert!(!s.app.account(&did).await.ok().unwrap().email_confirmed);
    // signup off: the unknown identity is just unknown
    add_provider(&s, &idp, "example", json!({"signup": "off"})).await;
    idp.state.lock().sub = "user-2".into();
    assert_eq!(location(&account_page_sign_in(&s).await.1), "/oauth/account?add=1&error=unknown_identity");
}

/// The account page app's provider sign-in: the server pages do it, then
/// the app trades it once for a session.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_account_page_app_gets_a_session_once() {
    let Setup { s, idp, acct } = setup(json!({})).await;
    link(&s, &mut Browser::default(), &acct).await;
    let trade = |b: &Browser, same_origin: bool| {
        let mut rb = s.http.post(format!("{}/xrpc/vlpds.server.createFederatedSession", s.base));
        if let Some(c) = &b.cookie {
            rb = rb.header("cookie", c);
        }
        if same_origin {
            rb = rb.header("sec-fetch-site", "same-origin");
        }
        rb.send()
    };
    let mut b = Browser::default();
    let (_, _, _) = b.get(&s, &format!("{}/oauth/account", s.base)).await;
    let p = through_idp(&s, &mut b, "/oauth/federated/start?provider=example&account=1&app=1").await;
    assert_eq!((p.0, location(&p.1)), (303, "/account?signin=device".to_string()));
    assert_eq!(trade(&b, false).await.unwrap().status().as_u16(), 401, "same-origin only");
    // two pickups at once: one session
    let (r1, r2) = tokio::join!(trade(&b, true), trade(&b, true));
    let (r1, r2) = (r1.unwrap(), r2.unwrap());
    let mut codes = [r1.status().as_u16(), r2.status().as_u16()];
    codes.sort();
    assert_eq!(codes, [200, 401], "one of two concurrent pickups");
    let r = if r1.status().as_u16() == 200 { r1 } else { r2 };
    let j: J = r.json().await.unwrap();
    assert_eq!(j["did"], json!(acct.did));
    let (st, me) = s.bearer(j["accessJwt"].as_str().unwrap(), "com.atproto.server.getSession", false, None).await;
    assert_eq!((st, &me["did"]), (200, &json!(acct.did)));
    assert_eq!(trade(&b, true).await.unwrap().status().as_u16(), 401, "once");
    // with TOTP the second step happens on the server page first
    let (secret, step) = enable_totp(&s, &acct).await;
    let mut b = Browser::default();
    let _ = b.get(&s, &format!("{}/oauth/account", s.base)).await;
    let p = through_idp(&s, &mut b, "/oauth/federated/start?provider=example&account=1&app=1").await;
    assert_eq!(location(&p.1), "/oauth/account?add=1&2fa=1");
    assert_eq!(trade(&b, true).await.unwrap().status().as_u16(), 401, "nothing to trade before the code");
    let (_, _, html) = b.get(&s, &format!("{}/oauth/account?add=1&2fa=1", s.base)).await;
    let code = vlpds::totp::code_for_step(&secret, step + 1);
    let (st, h, body) = b
        .post(
            &s,
            "/oauth/account/sign-in",
            &[("csrf", &csrf_of(&html)), ("step", "2fa"), ("code", &code), ("action", "sign-in")],
        )
        .await;
    assert_eq!((st, location(&h)), (303, "/account?signin=device".to_string()), "{body}");
    let r = trade(&b, true).await.unwrap();
    assert_eq!(r.status().as_u16(), 200);
    let _ = idp;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_empty_password_is_no_password() {
    let s = spawn().await;
    for pw in ["", "   "] {
        let r = s
            .http
            .post(format!("{}/xrpc/com.atproto.server.createAccount", s.base))
            .json(&json!({"handle": format!("np{}.vlpds.test", rand::random::<u32>() % 100000), "password": pw,
                          "email": format!("np{}@example.com", rand::random::<u32>())}))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 400, "{pw:?}");
        let j: J = r.json().await.unwrap();
        assert_eq!(j["message"], "Password is required", "{j}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dormant_identity_is_no_way_in() {
    let Setup { s, idp, acct } = setup(json!({})).await;
    let mut b = Browser::default();
    link(&s, &mut b, &acct).await;
    let other = Idp::start().await;
    add_provider(&s, &other, "second", json!({})).await;
    let (_, _, html) = b.get(&s, &format!("{}/oauth/account", s.base)).await;
    let add = href(&html, "/oauth/federated/start?provider=second").unwrap();
    assert_eq!(location(&through_idp(&s, &mut b, &add).await.1), "/oauth/account?notice=linked");
    let (st, _) = admin_post(&s, "vlpds.admin.removeSignInProvider", json!({"id": "second"})).await;
    assert_eq!(st, 200);
    s.app
        .mutate_account(&acct.did, false, false, false, |a| {
            a.password_hash = String::new();
            Ok(true)
        })
        .await
        .ok()
        .unwrap();
    let (_, _, html) = b.get(&s, &format!("{}/oauth/account", s.base)).await;
    let live = vlpds::federated::auth_ref(&idp.issuer, "user-1");
    let (_, h, _) =
        b.post(&s, "/oauth/account/unlink", &[("csrf", &csrf_of(&html)), ("did", &acct.did), ("ref", &live)]).await;
    assert_eq!(location(&h), "/oauth/account?notice=last", "the dormant identity can't sign in, so the live one stays");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn signups_per_provider_are_capped_per_day() {
    let s = spawn().await;
    let idp = Idp::start().await;
    add_provider(&s, &idp, "example", json!({"signup": "open", "signupsPerDay": 1})).await;
    let (_, list) = admin_get(&s, "vlpds.admin.listSignInProviders").await;
    assert_eq!(list["providers"][0]["signupsPerDay"], 1);
    for (i, sub) in ["first", "second"].into_iter().enumerate() {
        idp.state.lock().sub = sub.into();
        let mut b = Browser::default();
        let (_, _, html) = b.get(&s, &format!("{}/oauth/account", s.base)).await;
        let start = href(&html, "/oauth/federated/start?provider=").unwrap();
        let (_, _, form) = through_idp(&s, &mut b, &start).await;
        let handle = format!("cap{}", rand::random::<u32>() % 100000);
        if i == 0 {
            // a refused form doesn't use up the day's only signup
            let (st, _, body) = post_signup(&s, &mut b, &form, "a", &format!("{sub}@example.com"), "").await;
            assert_eq!(st, 400, "{body}");
        }
        let (st, _, body) = post_signup(&s, &mut b, &form, &handle, &format!("{sub}@example.com"), "").await;
        match i {
            0 => assert_eq!(st, 303, "{body}"),
            _ => {
                assert_eq!(st, 429, "{body}");
                assert!(body.contains("today"), "{body}");
            }
        }
    }
}

// ---------------------------------------------------------------- P3: SIWE through an OIDC adapter

fn keccak(b: &[u8]) -> [u8; 32] {
    use sha3::Digest as _;
    sha3::Keccak256::digest(b).into()
}

/// EIP-191 `personal_sign` hash.
fn eip191(msg: &str) -> [u8; 32] {
    keccak(format!("\x19Ethereum Signed Message:\n{}{msg}", msg.len()).as_bytes())
}

fn eth_address(vk: &k256::ecdsa::VerifyingKey) -> String {
    let pt = vk.to_sec1_point(false);
    format!("0x{}", hex::encode(&keccak(&pt.as_bytes()[1..])[12..]))
}

/// The signer of a `personal_sign` signature (65 bytes: r, s, v), as a
/// lowercase address.
fn siwe_signer(msg: &str, sig_hex: &str) -> Option<String> {
    let sig = hex::decode(sig_hex.trim_start_matches("0x")).ok()?;
    if sig.len() != 65 {
        return None;
    }
    let rec = k256::ecdsa::RecoveryId::from_byte(sig[64].checked_sub(27)?)?;
    let s = k256::ecdsa::Signature::from_slice(&sig[..64]).ok()?;
    let vk = k256::ecdsa::VerifyingKey::recover_from_prehash(&eip191(msg), &s, rec).ok()?;
    Some(eth_address(&vk))
}

struct Wallet {
    sk: k256::ecdsa::SigningKey,
}

impl Wallet {
    fn new() -> Wallet {
        Wallet { sk: k256::ecdsa::SigningKey::generate() }
    }

    fn address(&self) -> String {
        eth_address(self.sk.verifying_key())
    }

    fn sign(&self, msg: &str) -> String {
        let (sig, rec) = self.sk.sign_prehash_recoverable(&eip191(msg));
        format!("0x{}{:02x}", hex::encode(sig.to_bytes()), 27 + rec.to_byte())
    }

    /// The EIP-4361 message for the adapter's challenge, as `address`.
    fn message(challenge: &J, address: &str) -> String {
        format!(
            "{} wants you to sign in with your Ethereum account:\n{address}\n\nSign in to the PDS.\n\nURI: {}\nVersion: 1\nChain ID: 1\nNonce: {}\nIssued At: {}",
            challenge["domain"].as_str().unwrap(),
            challenge["uri"].as_str().unwrap(),
            challenge["nonce"].as_str().unwrap(),
            chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        )
    }
}

/// A start link through the adapter: the wallet signs the challenge (as
/// `claim`, its own address by default) and the browser comes back. The
/// adapter's answer when it refuses.
async fn through_wallet(
    s: &Srv,
    b: &mut Browser,
    start: &str,
    w: &Wallet,
    claim: Option<&str>,
) -> Result<Page, String> {
    let (st, h, body) = b.get(s, &format!("{}{start}", s.base)).await;
    assert_eq!(st, 303, "start: {body}");
    let to_adapter = location(&h);
    let r = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().unwrap();
    let challenge: J = r.get(&to_adapter).send().await.unwrap().json().await.unwrap();
    let issuer = to_adapter.split("/authorize").next().unwrap().to_string();
    let msg = Wallet::message(&challenge, claim.unwrap_or(&w.address()));
    let resp = r
        .post(format!("{issuer}/siwe"))
        .form(&[("request", challenge["request"].as_str().unwrap()), ("message", &msg), ("signature", &w.sign(&msg))])
        .send()
        .await
        .unwrap();
    if resp.status().as_u16() != 303 {
        return Err(resp.text().await.unwrap());
    }
    Ok(b.get(s, &location(resp.headers())).await)
}

/// A wallet signs up and signs in through an operator-run SIWE adapter,
/// which is just another OpenID provider to the PDS: the identity is the
/// adapter's issuer and the wallet's `eip155:1:0x…` subject.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn siwe_through_an_oidc_adapter() {
    let s = spawn().await;
    let adapter = Idp::start().await;
    {
        let mut st = adapter.state.lock();
        st.siwe = true;
        st.email = None;
    }
    add_provider(
        &s,
        &adapter,
        "wallet",
        json!({"name": "Ethereum", "signup": "open", "scopes": ["openid", "profile"]}),
    )
    .await;
    let w = Wallet::new();

    // signup on the OAuth page: no email from a wallet, so it's asked for and not confirmed
    let key = DpopKey::new();
    let f = Flow::loopback("atproto transition:email", &key);
    let p = pkce();
    let mut b = Browser::default();
    let ru = f.request_uri(&s, &p, "st-siwe").await;
    let (_, _, html) = b.authorize(&s, &f, &ru).await;
    assert!(html.contains("Continue with Ethereum"), "{html}");
    let start = href(&html, "/oauth/federated/start?provider=wallet").unwrap();
    let (st, _, form) = through_wallet(&s, &mut b, &start, &w, None).await.unwrap();
    assert_eq!(st, 200, "{form}");
    assert!(form.contains("Create an account") && form.contains("name=\"email\" value=\"\""), "{form}");
    let handle = format!("eth{}", rand::random::<u32>() % 100000);
    let (st, _, consent) = post_signup(&s, &mut b, &form, &handle, "wallet-owner@example.com", "").await;
    assert_eq!(st, 200, "{consent}");
    let did = hidden_field(&consent, "did").unwrap();
    let t = consent_and_token(&s, &mut b, &f, &p, &ru, &consent, &did).await;
    let sess = session_of(&s, &key, &t).await;
    assert_eq!((&sess["did"], &sess["emailConfirmed"]), (&json!(did), &json!(false)), "{sess}");

    // the identity is the adapter's issuer and the wallet's address
    let ids = s.app.get_private(&did, "fedid").await.ok().flatten().unwrap();
    let ids: J = serde_json::from_slice(&ids).unwrap();
    assert_eq!(ids["identities"][0]["sub"], json!(format!("eip155:1:{}", w.address())), "{ids}");
    assert_eq!(ids["identities"][0]["iss"], json!(adapter.issuer));

    // the same wallet signs in again from a fresh browser
    let mut b2 = Browser::default();
    let _ = b2.get(&s, &format!("{}/oauth/account", s.base)).await;
    let p2 = through_wallet(&s, &mut b2, "/oauth/federated/start?provider=wallet&account=1", &w, None).await.unwrap();
    assert!(signed_in(&p2), "{:?}", p2.0);

    // a wallet claiming another's address never gets past the adapter
    let thief = Wallet::new();
    let start = "/oauth/federated/start?provider=wallet&account=1";
    let refused = through_wallet(&s, &mut Browser::default(), start, &thief, Some(&w.address())).await;
    assert!(refused.is_err(), "a signature by another key was accepted");
    // and another wallet is another identity: a new signup, never this account
    let mut b3 = Browser::default();
    let _ = b3.get(&s, &format!("{}/oauth/account", s.base)).await;
    let (st, _, other) = through_wallet(&s, &mut b3, start, &thief, None).await.unwrap();
    assert_eq!(st, 200);
    assert!(other.contains("Create an account"), "{other}");
}

/// A password account adds its wallet, then signs in with it alone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_wallet_linked_to_an_existing_account() {
    let s = spawn().await;
    let adapter = Idp::start().await;
    adapter.state.lock().siwe = true;
    add_provider(&s, &adapter, "wallet", json!({"name": "Ethereum"})).await;
    let acct = create_account(&s, "walletfan").await;
    let w = Wallet::new();
    let mut b = Browser::default();
    device_sign_in(&s, &mut b, &acct).await;
    let (_, _, html) = b.get(&s, &format!("{}/oauth/account", s.base)).await;
    let add = href(&html, "/oauth/federated/start?provider=wallet").unwrap();
    let (st, h, body) = through_wallet(&s, &mut b, &add, &w, None).await.unwrap();
    assert_eq!((st, location(&h)), (303, "/oauth/account?notice=linked".to_string()), "{body}");
    let mut b2 = Browser::default();
    let _ = b2.get(&s, &format!("{}/oauth/account", s.base)).await;
    let p = through_wallet(&s, &mut b2, "/oauth/federated/start?provider=wallet&account=1", &w, None).await.unwrap();
    assert!(signed_in(&p));
    let (_, _, page) = b2.get(&s, &format!("{}/oauth/account", s.base)).await;
    assert!(page.contains(&acct.did), "signed in as the account: {page}");
}

/// The mock adapter's EIP-191 recovery against web3.js's documented vector
/// (`web3.eth.accounts.sign('Some data', …)`), so the test speaks real SIWE.
#[test]
fn eip191_matches_web3() {
    let sig = "0xb91467e570a6466aa9e9876cbcd013baba02900b8979d43fe208a4a4f339f5fd6007e74cd82e037b800186422fc2da167c747ef045e5d18a5f5d4300f8e1a0291c";
    assert_eq!(siwe_signer("Some data", sig).as_deref(), Some("0x2c7536e3605d9c16a7a3d7b1898e529396a65c23"));
    let sk = k256::ecdsa::SigningKey::from_slice(
        &hex::decode("4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318").unwrap(),
    )
    .unwrap();
    assert_eq!(eth_address(sk.verifying_key()), "0x2c7536e3605d9c16a7a3d7b1898e529396a65c23");
}

// ---------------------------------------------------------------- the step-up page (jazware/vlpds#10)

/// The account page app's Manage link, as `SignInMethods.tsx` builds it.
fn step_up_url(s: &Srv, hint: &str) -> String {
    format!(
        "{}/oauth/account?login_hint={}&return=sign-in-methods",
        s.base,
        vlpds::oauth::util::form_encode_component(hint)
    )
}

fn methods_return(did: &str) -> String {
    format!("/oauth/account?login_hint={}#sign-in-methods", vlpds::oauth::util::encode_uri_component(did))
}

/// Ages every sign-in on `b`'s device past the step-up window.
async fn age_sign_ins(s: &Srv, b: &Browser) {
    let id = b.cookie.as_deref().unwrap().trim_start_matches("vlpds-device=").to_string();
    let mut d = vlpds::oauth::store::get_device(&s.app, &id).await.unwrap().unwrap();
    for a in &mut d.accounts {
        a.authenticated_at -= 3600;
    }
    vlpds::oauth::store::put_device(&s.app, &d).await.unwrap();
}

/// The page's password form as a browser posts it, its hidden `login_hint`
/// included when it has one.
async fn step_up_post(s: &Srv, b: &mut Browser, html: &str, ident: &str, password: &str, ret: &str) -> Page {
    let hint = hidden_field(html, "login_hint");
    let csrf = csrf_of(html);
    let mut pairs = vec![
        ("csrf", csrf.as_str()),
        ("identifier", ident),
        ("password", password),
        ("return", ret),
        ("action", "sign-in"),
    ];
    if let Some(h) = &hint {
        pairs.push(("login_hint", h));
    }
    b.post(s, "/oauth/account/sign-in", &pairs).await
}

async fn step_up_sign_in(s: &Srv, b: &mut Browser, html: &str, acct: &Account, ret: &str) -> Page {
    step_up_post(s, b, html, &acct.handle, PASSWORD, ret).await
}

fn hint_q(did: &str) -> String {
    format!("&login_hint={}", vlpds::oauth::util::encode_uri_component(did))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn manage_from_the_app_asks_to_confirm_and_returns_to_sign_in_methods() {
    let Setup { s, idp, acct } = setup(json!({})).await;
    // a browser that never signed in here: the step-up copy, the handle filled in
    let mut b = Browser::default();
    let (st, _, html) = b.get(&s, &step_up_url(&s, &acct.did)).await;
    assert_eq!(st, 200);
    assert!(html.contains("Confirm it's you"), "{html}");
    assert!(html.contains(&format!("for <b>@{}</b>", acct.handle)), "{html}");
    assert!(html.contains(&format!("name=\"identifier\" value=\"{}\"", acct.handle)), "{html}");
    assert!(!html.contains("Manage the apps"), "{html}");
    assert_eq!(hidden_field(&html, "return").as_deref(), Some("sign-in-methods"));
    let (_, _, plain) = Browser::default().get(&s, &format!("{}/oauth/account", s.base)).await;
    assert_eq!(html.contains("id=\"pk\""), plain.contains("id=\"pk\""), "the passkey form as on the plain page");
    let start = href(&html, "/oauth/federated/start?provider=").unwrap();
    assert!(start.ends_with("&account=1&return=sign-in-methods"), "{start}");
    assert_eq!(hidden_field(&html, "login_hint").as_deref(), Some(acct.did.as_str()));
    // the app sends a DID; a handle isn't taken, so the page never says
    // "for @" with text it was handed
    let (_, _, by_handle) = Browser::default().get(&s, &step_up_url(&s, &format!("@{}", acct.handle))).await;
    assert!(by_handle.contains("Confirm it's you") && !by_handle.contains(" for <b>@"), "{by_handle}");
    assert!(!by_handle.contains(&acct.handle), "{by_handle}");

    // a wrong password comes back with the page's hint, so the handle stays
    let (st, h, _) = step_up_post(&s, &mut b, &html, &acct.handle, "wrong-password", "sign-in-methods").await;
    assert_eq!(st, 303);
    let back = location(&h);
    assert!(
        back.starts_with("/oauth/account?add=1&error=")
            && back.ends_with(&format!("&return=sign-in-methods{}", hint_q(&acct.did))),
        "{back}"
    );
    let (_, _, retry) = b.get(&s, &format!("{}{back}", s.base)).await;
    assert!(retry.contains(&format!("for <b>@{}</b>", acct.handle)) && retry.contains("role=\"alert\""), "{retry}");
    assert!(retry.contains(&format!("name=\"identifier\" value=\"{}\"", acct.handle)), "{retry}");
    // with no hint on the page, nothing is derived from what was typed
    let mut b3 = Browser::default();
    let (_, _, nohint) = b3.get(&s, &format!("{}/oauth/account?add=1&return=sign-in-methods", s.base)).await;
    assert!(hidden_field(&nohint, "login_hint").is_none(), "{nohint}");
    let (_, h, _) = step_up_post(&s, &mut b3, &nohint, &acct.handle, "wrong-password", "sign-in-methods").await;
    assert!(!location(&h).contains("login_hint"), "{}", location(&h));

    // signing in lands on the sign-in methods, which it may change now
    let (st, h, body) = step_up_sign_in(&s, &mut b, &html, &acct, "sign-in-methods").await;
    assert_eq!((st, location(&h)), (303, methods_return(&acct.did)), "{body}");
    let (st, _, page) = b.get(&s, &format!("{}{}", s.base, methods_return(&acct.did))).await;
    assert_eq!(st, 200);
    assert!(page.contains("<h2 id=\"sign-in-methods\">Sign-in methods</h2>"), "{page}");
    assert!(page.contains("&amp;link="), "an Add link: {page}");
    // fresh, the same link goes straight to the page
    let (_, _, again) = b.get(&s, &step_up_url(&s, &acct.did)).await;
    assert!(again.contains("id=\"sign-in-methods\"") && !again.contains("Confirm it's you"), "{again}");

    // a provider sign-in from the step-up page returns there too
    let add = href(&page, "/oauth/federated/start?provider=").unwrap();
    assert_eq!(location(&through_idp(&s, &mut b, &add).await.1), "/oauth/account?notice=linked");
    let mut b2 = Browser::default();
    let (_, _, html) = b2.get(&s, &step_up_url(&s, &acct.did)).await;
    let start = href(&html, "/oauth/federated/start?provider=").unwrap();
    let p = through_idp(&s, &mut b2, &start).await;
    assert_eq!((p.0, location(&p.1)), (303, methods_return(&acct.did)));
    let _ = idp;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_step_up_hint_and_return_take_only_what_they_expect() {
    let Setup { s, idp, acct } = setup(json!({})).await;
    for bad in ["<script>alert(1)</script>", "not a handle", "did:plc:\"><b>x", "https://evil.example/"] {
        let (st, _, html) = Browser::default().get(&s, &step_up_url(&s, bad)).await;
        assert_eq!(st, 200, "{bad}");
        assert!(html.contains("Confirm it's you"), "{html}");
        assert!(!html.contains(" for <b>@"), "{bad}: {html}");
        assert!(
            !html.contains("alert(1)") && !html.contains("evil.example") && !html.contains("<b>x"),
            "{bad}: {html}"
        );
        assert!(html.contains("name=\"identifier\" value=\"\""), "{bad}: {html}");
    }
    // a DID with no account here is no hint
    let (_, _, html) = Browser::default().get(&s, &step_up_url(&s, "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa")).await;
    assert!(!html.contains(" for <b>@"), "{html}");
    // nor is an inactive account, whose handle describeRepo and
    // resolveHandle hide; nor any handle
    let gone = create_account(&s, "fedgone").await;
    let (st, j) = s.bearer(&gone.jwt, "com.atproto.server.deactivateAccount", true, Some(json!({}))).await;
    assert_eq!(st, 200, "{j}");
    let down = create_account(&s, "feddown").await;
    let body =
        json!({"subject": {"$type": "com.atproto.admin.defs#repoRef", "did": down.did}, "takedown": {"applied": true}});
    let (st, j) = admin_post(&s, "com.atproto.admin.updateSubjectStatus", body).await;
    assert_eq!(st, 200, "{j}");
    for (hint, handle) in [
        (gone.did.clone(), &gone.handle),
        (down.did.clone(), &down.handle),
        (acct.handle.clone(), &acct.handle),
        (format!("@{}", acct.handle), &acct.handle),
    ] {
        let (st, _, html) = Browser::default().get(&s, &step_up_url(&s, &hint)).await;
        assert_eq!(st, 200, "{hint}");
        assert!(!html.contains(" for <b>@") && !html.contains(handle.as_str()), "{hint}: {html}");
        assert!(hidden_field(&html, "login_hint").is_none(), "{hint}: {html}");
    }
    // any other return is the plain page, and its sign-ins stay on it
    for ret in ["https://evil.example/", "//evil.example", "/account", "sign-in-methods#x"] {
        let mut b = Browser::default();
        let q = vlpds::oauth::util::form_encode_component(ret);
        let (_, _, html) = b.get(&s, &format!("{}/oauth/account?return={q}", s.base)).await;
        assert!(html.contains("Manage the apps") && hidden_field(&html, "return").is_none(), "{ret}: {html}");
        let (st, h, body) = step_up_sign_in(&s, &mut b, &html, &acct, ret).await;
        assert_eq!((st, location(&h)), (303, "/oauth/account".to_string()), "{ret}: {body}");
        let start = format!("/oauth/federated/start?provider=example&account=1&return={q}");
        let (st, h, _) = b.get(&s, &format!("{}{start}", s.base)).await;
        assert_eq!(st, 303);
        assert!(!location(&h).contains("evil"), "only the provider: {}", location(&h));
    }
    let _ = idp;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stale_sign_in_says_to_sign_in_again_and_offers_the_step_up() {
    let Setup { s, idp, acct } = setup(json!({})).await;
    let mut b = Browser::default();
    link(&s, &mut b, &acct).await;
    age_sign_ins(&s, &b).await;
    let (_, _, html) = b.get(&s, &format!("{}/oauth/account", s.base)).await;
    assert!(html.contains("<h2 id=\"sign-in-methods\">"), "{html}");
    assert!(html.contains("Sign in again to change these"), "{html}");
    assert!(hidden_field(&html, "ref").is_none(), "no Remove that would only be refused: {html}");
    assert!(href(&html, "/oauth/federated/start?").is_none(), "no Add either: {html}");
    let again = href(&html, "/oauth/account?login_hint=").expect("a sign-in-again link");
    assert_eq!(
        again,
        format!(
            "/oauth/account?login_hint={}&return=sign-in-methods",
            vlpds::oauth::util::encode_uri_component(&acct.did)
        )
    );
    let (_, _, html) = b.get(&s, &format!("{}{again}", s.base)).await;
    assert!(html.contains("Confirm it's you") && html.contains(&format!("@{}", acct.handle)), "{html}");
    let (st, h, _) = step_up_sign_in(&s, &mut b, &html, &acct, "sign-in-methods").await;
    assert_eq!((st, location(&h)), (303, methods_return(&acct.did)));
    let (_, _, html) = b.get(&s, &format!("{}{}", s.base, methods_return(&acct.did))).await;
    assert!(hidden_field(&html, "ref").is_some(), "Remove is back: {html}");
    let _ = idp;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_step_up_adds_the_apps_account_beside_another() {
    let Setup { s, idp, acct } = setup(json!({})).await;
    let other = create_account(&s, "fedother").await;
    let mut b = Browser::default();
    device_sign_in(&s, &mut b, &other).await;
    // signed in here as someone else: the hint asks for the app's account
    let (_, _, html) = b.get(&s, &step_up_url(&s, &acct.did)).await;
    assert!(html.contains("Confirm it's you") && html.contains(&format!("@{}", acct.handle)), "{html}");
    assert!(!html.contains(&other.did), "nothing of the other account: {html}");
    let (st, h, _) = step_up_sign_in(&s, &mut b, &html, &acct, "sign-in-methods").await;
    assert_eq!((st, location(&h)), (303, methods_return(&acct.did)));
    let (_, _, page) = b.get(&s, &format!("{}{}", s.base, methods_return(&acct.did))).await;
    assert!(page.contains(&other.did) && page.contains(&acct.did), "both signed in: {page}");
    assert_eq!(page.matches("id=\"sign-in-methods\"").count(), 1, "{page}");
    let anchor = page.find("id=\"sign-in-methods\"").unwrap();
    let last_account = page[..anchor].rfind("<div class=\"who\"><b>@").unwrap();
    assert!(page[last_account..anchor].contains(&acct.handle), "the anchor is the app account's: {page}");
    let _ = idp;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_step_up_keeps_its_return_through_the_second_factor() {
    let Setup { s, idp, acct } = setup(json!({})).await;
    let (secret, step) = enable_totp(&s, &acct).await;
    let mut b = Browser::default();
    let (_, _, html) = b.get(&s, &step_up_url(&s, &acct.did)).await;
    let (st, h, _) = step_up_sign_in(&s, &mut b, &html, &acct, "sign-in-methods").await;
    assert_eq!(
        (st, location(&h)),
        (303, format!("/oauth/account?add=1&2fa=1&return=sign-in-methods{}", hint_q(&acct.did)))
    );
    let (_, _, html) = b.get(&s, &format!("{}{}", s.base, location(&h))).await;
    assert!(html.contains("Confirm it's you") && html.contains("Authenticator code"), "{html}");
    assert_eq!(hidden_field(&html, "return").as_deref(), Some("sign-in-methods"));
    let code = vlpds::totp::code_for_step(&secret, step + 1);
    let (st, h, body) = b
        .post(
            &s,
            "/oauth/account/sign-in",
            &[
                ("csrf", &csrf_of(&html)),
                ("step", "2fa"),
                ("code", &code),
                ("return", "sign-in-methods"),
                ("action", "sign-in"),
            ],
        )
        .await;
    assert_eq!((st, location(&h)), (303, methods_return(&acct.did)), "{body}");
    let _ = idp;
}
