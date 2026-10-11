//! The OIDC providers — Google and Apple
//! (src/xrpc/owner_auth/providers/{google,apple}.rs) — end to end against a
//! stub issuer that signs real RS256 ID tokens.
//!
//! Only the network is stubbed. The JWKS, the signature, the issuer, the
//! audience, the nonce and the expiry are all checked by the provider's own
//! code, and the callback → resume → link/sign-in plumbing is exercised for
//! real — including that a redirect provider's proof is consumed at its
//! callback, so the client's later step carries no proof of its own. Apple is
//! driven through its `form_post` callback, and its client secret is checked
//! as the ES256 assertion it has to be.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use futures::future::BoxFuture;
use parking_lot::Mutex;
use ring::signature::{RsaKeyPair, RSA_PKCS1_SHA256};

use crate::common::*;
use vlpds::xrpc::owner_auth::{Config, GoogleConfig, HttpFetch};

const CLIENT_ID: &str = "test-client.apps.googleusercontent.com";
const ISSUER: &str = "https://issuer.test";
const KID: &str = "test-key";
const SUBJECT: &str = "google-subject-1";
/// The modulus of `testdata/oidc-test-key.pem`, as the JWKS serves it.
const N_HEX: &str = "E5CA379997C6F79262B28BDBDFD99E7AF9B08E408AB390DB07D850C441E9D26AED1F1D7713FA869772885655B5ABBBA8C074BD8999433153891CA21A252D5EDEE3235592F4412D3B405B4F8C36D6755233A9208986C47B2C1A16EA73B7A4A339FC5B9A769400CA59269CDDDF3B4B1D361FD4297B7C615D0F0452D7E2CE5D1DBE7BFFA7B72FB02FF5AD47FECD4F0525B46A09654C242F4DBCFB222DDE9D226FE9E000250A01194DBA85670A78FC7C27CDA3027591E32868B164E911553F744FC3F5AA74EB37229E11DE1B3E84BAE7F4C627F57E015BDBFFF3E987BB0C2C46441C4A85D3110841A6065F6C45A11BCB89DAD57B5F37244D5FFACFEDED168CCA6DA1";
const KEY_PEM: &str = include_str!("../../testdata/oidc-test-key.pem");

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// A stand-in for Google's endpoints: it serves the JWKS for the test key and
/// signs whatever ID token the test asks for.
struct StubIssuer {
    key: RsaKeyPair,
    /// The nonce the sign-in page was handed, echoed into the token.
    nonce: Mutex<String>,
    /// Likewise for the audience the test wants a token for.
    aud: Mutex<Option<String>>,
    /// The issuer to sign for (Google by default; Apple sets its own).
    iss: Mutex<String>,
    /// Sign without an email claim, as Apple's first authorization can be
    /// relied on only through its `user` object.
    omit_email: Mutex<bool>,
    /// The last token request's form, so the test can assert PKCE was used.
    last_form: Mutex<Vec<(String, String)>>,
}

impl StubIssuer {
    fn new() -> Arc<StubIssuer> {
        let der = vlpds::xrpc::owner_auth::jwt::pem_to_der(KEY_PEM).expect("the test key is PKCS#8 PEM");
        let key = RsaKeyPair::from_pkcs8(&der).expect("a 2048-bit RSA key");
        Arc::new(StubIssuer {
            key,
            nonce: Mutex::new(String::new()),
            aud: Mutex::new(None),
            iss: Mutex::new(ISSUER.to_string()),
            omit_email: Mutex::new(false),
            last_form: Mutex::new(Vec::new()),
        })
    }

    fn jwks(&self) -> J {
        json!({"keys": [{
            "kty": "RSA", "kid": KID, "use": "sig", "alg": "RS256",
            "n": b64(&hex::decode(N_HEX).expect("modulus hex")),
            "e": b64(&[1, 0, 1]),
        }]})
    }

    /// Sign `claims` with the test key (RS256), as Google would.
    fn sign(&self, claims: J) -> String {
        let header = b64(&serde_json::to_vec(&json!({"alg": "RS256", "kid": KID, "typ": "JWT"})).unwrap());
        let payload = b64(&serde_json::to_vec(&claims).unwrap());
        let input = format!("{header}.{payload}");
        let rng = ring::rand::SystemRandom::new();
        let mut sig = vec![0u8; self.key.public().modulus_len()];
        self.key.sign(&RSA_PKCS1_SHA256, &rng, input.as_bytes(), &mut sig).expect("sign");
        format!("{input}.{}", b64(&sig))
    }

    /// The ID token the token endpoint returns, with `nonce` (default: the one
    /// the page was given) and `aud`.
    fn id_token(&self, aud: &str, nonce: &str) -> String {
        let t = now();
        let mut claims = json!({
            "iss": self.iss.lock().clone(), "aud": aud, "sub": SUBJECT,
            "iat": t, "exp": t + 3600, "nonce": nonce,
        });
        if !*self.omit_email.lock() {
            claims["email"] = json!("guser@example.com");
            claims["email_verified"] = json!(true);
            claims["hd"] = json!("example.com");
        }
        self.sign(claims)
    }
}

impl HttpFetch for StubIssuer {
    fn get_json<'a>(&'a self, _url: &'a str, _max: usize) -> BoxFuture<'a, Result<J, String>> {
        Box::pin(async move {
            // The only GET a provider makes is its JWKS, whatever path its
            // configuration gives it; the token request is asserted instead.
            Ok(self.jwks())
        })
    }

    fn post_form<'a>(
        &'a self,
        url: &'a str,
        form: &'a [(String, String)],
        _max: usize,
    ) -> BoxFuture<'a, Result<J, String>> {
        Box::pin(async move {
            if !url.ends_with("/token") {
                return Err(format!("unexpected POST {url}"));
            }
            *self.last_form.lock() = form.to_vec();
            let nonce = self.nonce.lock().clone();
            let aud = self.aud.lock().clone().unwrap_or_else(|| CLIENT_ID.to_string());
            Ok(json!({"id_token": self.id_token(&aud, &nonce)}))
        })
    }
}

/// A browser that follows no redirects, so a 303 and its Location are visible.
struct Browser {
    http: reqwest::Client,
    base: String,
    cookie: Option<String>,
}

impl Browser {
    fn new(base: &str) -> Browser {
        let http = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().expect("client");
        Browser { http, base: base.to_string(), cookie: None }
    }

    fn absorb(&mut self, r: &reqwest::Response) {
        for v in r.headers().get_all(reqwest::header::SET_COOKIE) {
            if let Ok(s) = v.to_str() {
                if let Some(c) = s.split(';').next() {
                    if c.starts_with("vlpds-device=") {
                        self.cookie = Some(c.to_string());
                    }
                }
            }
        }
    }

    async fn post(&mut self, path: &str, body: J, bearer: Option<&str>) -> (reqwest::StatusCode, J) {
        let mut rb = self.http.post(format!("{}{}", self.base, path)).json(&body);
        if let Some(c) = &self.cookie {
            rb = rb.header("cookie", c.as_str());
        }
        if let Some(t) = bearer {
            rb = rb.bearer_auth(t);
        }
        let r = rb.send().await.expect("request");
        self.absorb(&r);
        let status = r.status();
        (status, r.json().await.unwrap_or(J::Null))
    }

    /// A GET returning (status, Location, body).
    async fn get(&mut self, path: &str) -> (reqwest::StatusCode, Option<String>, String) {
        let mut rb = self.http.get(format!("{}{}", self.base, path));
        if let Some(c) = &self.cookie {
            rb = rb.header("cookie", c.as_str());
        }
        let r = rb.send().await.expect("request");
        self.absorb(&r);
        let status = r.status();
        let loc = r.headers().get(reqwest::header::LOCATION).and_then(|v| v.to_str().ok()).map(String::from);
        (status, loc, r.text().await.unwrap_or_default())
    }

    /// A form POST returning (status, Location, body) — Apple's callback.
    async fn post_form(
        &mut self,
        path: &str,
        pairs: &[(String, String)],
    ) -> (reqwest::StatusCode, Option<String>, String) {
        let mut rb = self.http.post(format!("{}{}", self.base, path)).form(pairs);
        if let Some(c) = &self.cookie {
            rb = rb.header("cookie", c.as_str());
        }
        let r = rb.send().await.expect("request");
        self.absorb(&r);
        let status = r.status();
        let loc = r.headers().get(reqwest::header::LOCATION).and_then(|v| v.to_str().ok()).map(String::from);
        (status, loc, r.text().await.unwrap_or_default())
    }
}

fn query(url: &str, key: &str) -> String {
    reqwest::Url::parse(url)
        .ok()
        .and_then(|u| u.query_pairs().find(|(k, _)| k == key).map(|(_, v)| v.into_owned()))
        .unwrap_or_default()
}

/// Follow the provider round trip for `txn`'s challenge: the callback, then
/// the same-origin landing. Returns the landing's Location.
async fn round_trip(
    b: &mut Browser,
    stub: &Arc<StubIssuer>,
    authorize_url: &str,
) -> (reqwest::StatusCode, Option<String>) {
    *stub.nonce.lock() = query(authorize_url, "nonce");
    let state = query(authorize_url, "state");
    let (st, loc, body) = b.get(&format!("/auth/callback/google?code=a-one-time-code&state={state}")).await;
    assert_eq!(st, 303, "callback should redirect: {body}");
    let resume = loc.expect("callback Location");
    assert!(resume.starts_with("/auth/resume?t="), "{resume}");
    let (st, loc, body) = b.get(&resume).await;
    assert_eq!(st, 303, "resume should redirect: {body}");
    (st, loc)
}

fn google_config(stub: Arc<StubIssuer>) -> Config {
    Config {
        google: Some(GoogleConfig {
            client_id: CLIENT_ID.into(),
            client_secret: "test-secret".into(),
            issuer: ISSUER.into(),
            authorization_endpoint: format!("{ISSUER}/authorize"),
            token_endpoint: format!("{ISSUER}/token"),
            jwks_uri: format!("{ISSUER}/jwks"),
        }),
        fetch: Some(stub),
        ..Default::default()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_new_google_identity_signs_up_without_a_password() {
    let stub = StubIssuer::new();
    let s = TestServer::spawn_with(|c| c.owner_auth = google_config(stub.clone())).await;
    let mut b = Browser::new(&s.url);

    // An identity nobody has linked: ask to sign up with it.
    let (st, v) = b.post("/auth/start", json!({"provider": "google", "intent": "sign_up"}), None).await;
    assert_eq!(st, 200, "{v}");
    let auth_url = v["challenge"]["url"].as_str().expect("authorize URL").to_string();
    let txn = v["txnId"].as_str().expect("txn").to_string();
    let (st, loc) = round_trip(&mut b, &stub, &auth_url).await;
    assert_eq!(st, 303);
    let loc = loc.expect("landing Location");
    assert!(loc.starts_with("/account?auth=signup"), "an unknown identity is offered a sign-up: {loc}");
    assert!(loc.contains("t=txn-"), "the verified transaction rides along: {loc}");

    // The account page finishes it: the identity was already proved, so only
    // the account's own fields are collected.
    let (st, v) = b
        .post(
            "/auth/continue",
            json!({"txn": txn, "step": "signup", "handle": "gnew", "email": "gnew@example.com"}),
            None,
        )
        .await;
    assert_eq!(st, 200, "{v}");
    assert_eq!(v["status"], "done", "{v}");
    assert_eq!(v["handle"], "gnew.vlpds.test");

    // The browser can redeem a session, and no local password was invented.
    let (st, v) = b.post("/auth/complete", json!({}), None).await;
    assert_eq!(st, 200, "{v}");
    assert_eq!(v["handle"], "gnew.vlpds.test");
    s.xrpc
        .post(
            "com.atproto.server.createSession",
            &json!({"identifier": "gnew.vlpds.test", "password": ""}),
            &Auth::None,
        )
        .await
        .err_status(401);

    // Signing in with the same Google identity now resolves to that account.
    let (st, v) = b.post("/auth/start", json!({"provider": "google", "intent": "sign_in"}), None).await;
    assert_eq!(st, 200, "{v}");
    let auth_url = v["challenge"]["url"].as_str().expect("authorize URL").to_string();
    let (st, loc) = round_trip(&mut b, &stub, &auth_url).await;
    assert_eq!(st, 303);
    assert!(loc.unwrap_or_default().contains("auth=complete"));
    let (st, v) = b.post("/auth/complete", json!({}), None).await;
    assert_eq!(st, 200, "{v}");
    assert_eq!(v["handle"], "gnew.vlpds.test");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn google_link_then_sign_in() {
    let stub = StubIssuer::new();
    let s = TestServer::spawn_with(|c| c.owner_auth = google_config(stub.clone())).await;
    let a = s.create_account("guser").await;
    let mut b = Browser::new(&s.url);

    // The method is offered, and never enumerates accounts.
    let m = s.xrpc.http.get(format!("{}/auth/methods", s.url)).send().await.unwrap().json::<J>().await.unwrap();
    assert_eq!(m["providers"][0]["id"], "google", "{m}");

    // Link it, confirming with the account's password.
    let (st, v) =
        b.post("/auth/link", json!({"provider": "google", "password": a.password}), Some(a.access.as_str())).await;
    assert_eq!(st, 200, "{v}");
    assert_eq!(v["challenge"]["kind"], "redirect", "{v}");
    let auth_url = v["challenge"]["url"].as_str().expect("authorize URL").to_string();
    assert_eq!(query(&auth_url, "client_id"), CLIENT_ID);
    assert_eq!(query(&auth_url, "code_challenge_method"), "S256", "PKCE is required");

    let txn = v["txnId"].as_str().expect("txn").to_string();
    let (st, loc) = round_trip(&mut b, &stub, &auth_url).await;
    assert_eq!(st, 303);
    let loc = loc.expect("landing Location");
    assert!(loc.contains("step=link"), "a link is handed back to the app: {loc}");

    // The token request carried PKCE and the code.
    let form = stub.last_form.lock().clone();
    let field = |k: &str| form.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone()).unwrap_or_default();
    assert_eq!(field("grant_type"), "authorization_code");
    assert_eq!(field("code"), "a-one-time-code");
    assert!(!field("code_verifier").is_empty(), "a PKCE verifier must be sent");

    // The app finishes the link — with no proof of its own, because the
    // callback already consumed one.
    let (st, v) = b.post("/auth/continue", json!({"txn": txn, "step": "link"}), None).await;
    assert_eq!(st, 200, "{v}");
    assert_eq!(v["status"], "linked", "{v}");
    assert_eq!(v["credential"]["provider"], "google", "{v}");

    let list = s.xrpc.get("vlpds.auth.listCredentials", &[], &a.auth()).await.ok();
    assert_eq!(list["credentials"].as_array().map(|a| a.len()), Some(1), "{list}");
    assert_eq!(list["credentials"][0]["provider"], "google");
    assert_eq!(list["credentials"][0]["label"], "guser@example.com", "{list}");

    // Now sign in with it: the account is signed in on this browser.
    let (st, v) = b.post("/auth/start", json!({"provider": "google", "intent": "sign_in"}), None).await;
    assert_eq!(st, 200, "{v}");
    let auth_url = v["challenge"]["url"].as_str().expect("authorize URL").to_string();
    let (st, loc) = round_trip(&mut b, &stub, &auth_url).await;
    assert_eq!(st, 303);
    assert!(loc.unwrap_or_default().contains("auth=complete"), "a finished sign-in returns to the app");

    let (st, v) = b.post("/auth/complete", json!({}), None).await;
    assert_eq!(st, 200, "{v}");
    assert_eq!(v["did"], a.did);
    assert_eq!(v["handle"], a.handle);
    assert!(v["accessJwt"].as_str().is_some_and(|t| !t.is_empty()), "a session is issued");

    // The session records the credential that signed it, so removing that
    // credential ends it.
    let cred_id = list["credentials"][0]["id"].as_str().unwrap().to_string();
    let grant = {
        let (st, v) = b
            .post(
                "/auth/reauth",
                json!({"provider": "google", "action": "unlink", "target": cred_id}),
                Some(v["accessJwt"].as_str().unwrap()),
            )
            .await;
        assert_eq!(st, 200, "{v}");
        let auth_url = v["challenge"]["url"].as_str().expect("authorize URL").to_string();
        let txn = v["txnId"].as_str().unwrap().to_string();
        let (st, loc) = round_trip(&mut b, &stub, &auth_url).await;
        assert_eq!(st, 303);
        assert!(loc.unwrap_or_default().contains("step=reauth"), "a confirmation comes back as one");
        let (st, v) = b.post("/auth/continue", json!({"txn": txn, "step": "reauth"}), None).await;
        assert_eq!(st, 200, "{v}");
        assert_eq!(v["status"], "confirmed", "{v}");
        v["grant"].as_str().unwrap().to_string()
    };
    let (st, v) = b.post("/auth/complete", json!({}), None).await;
    assert_eq!(st, 200, "{v}");
    let token = v["accessJwt"].as_str().unwrap().to_string();
    let ok = s
        .xrpc
        .post("vlpds.auth.unlinkCredential", &json!({"id": cred_id, "grant": grant}), &Auth::Bearer(token.clone()))
        .await
        .ok();
    assert_eq!(ok["removed"], true, "{ok}");
    // The credential that approved the session is gone, so the session is too.
    s.xrpc.get("com.atproto.server.getSession", &[], &Auth::Bearer(token)).await.err(400, "ExpiredToken");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn google_rejects_proofs_that_are_not_ours() {
    let stub = StubIssuer::new();
    let s = TestServer::spawn_with(|c| c.owner_auth = google_config(stub.clone())).await;
    let mut b = Browser::new(&s.url);

    /// Start a sign-in, hand the stub its nonce, and report where to send the
    /// callback.
    async fn begin(b: &mut Browser, stub: &Arc<StubIssuer>) -> String {
        let (st, v) = b.post("/auth/start", json!({"provider": "google", "intent": "sign_in"}), None).await;
        assert_eq!(st, 200, "{v}");
        let auth_url = v["challenge"]["url"].as_str().expect("authorize URL").to_string();
        *stub.nonce.lock() = query(&auth_url, "nonce");
        query(&auth_url, "state")
    }

    // A token minted for another audience.
    let state = begin(&mut b, &stub).await;
    *stub.aud.lock() = Some("someone-else.apps.googleusercontent.com".into());
    let (st, loc, body) = b.get(&format!("/auth/callback/google?code=c&state={state}")).await;
    assert_eq!(st, 400, "a token for another audience must be refused: {loc:?} {body}");
    assert!(loc.is_none(), "a refused proof must not redirect");
    *stub.aud.lock() = None;

    // A token whose nonce is not the one we sent.
    let state = begin(&mut b, &stub).await;
    *stub.nonce.lock() = "not-the-nonce-we-sent".to_string();
    let (st, loc, body) = b.get(&format!("/auth/callback/google?code=c&state={state}")).await;
    assert_eq!(st, 400, "a token with the wrong nonce must be refused: {loc:?} {body}");
    assert!(loc.is_none());

    // State that names no live transaction.
    let (st, _, _) = b.get("/auth/callback/google?code=c&state=txn-does-not-exist").await;
    assert_eq!(st, 400);

    // And none of it signed anybody in.
    let (st, _) = b.post("/auth/complete", json!({}), None).await;
    assert_ne!(st, 200, "no session may exist after only refused proofs");
}

// ------------------------------------------------------------------- Apple

const APPLE_CLIENT_ID: &str = "place.stream.signin";
const APPLE_TEAM_ID: &str = "TEAM123456";
const APPLE_KEY_ID: &str = "KEY1234567";
const APPLE_ISSUER: &str = "https://appleid.test";
const EC_KEY_PEM: &str = include_str!("../../testdata/oidc-test-ec-key.pem");

fn apple_config(stub: Arc<StubIssuer>) -> Config {
    // Apple's client id is not Google's: sign the ID tokens for it.
    *stub.aud.lock() = Some(APPLE_CLIENT_ID.to_string());
    Config {
        apple: Some(vlpds::xrpc::owner_auth::AppleConfig {
            client_id: APPLE_CLIENT_ID.into(),
            team_id: APPLE_TEAM_ID.into(),
            key_id: APPLE_KEY_ID.into(),
            private_key_pem: EC_KEY_PEM.into(),
            issuer: APPLE_ISSUER.into(),
            authorization_endpoint: format!("{APPLE_ISSUER}/auth/authorize"),
            token_endpoint: format!("{APPLE_ISSUER}/auth/token"),
            jwks_uri: format!("{APPLE_ISSUER}/auth/keys"),
        }),
        fetch: Some(stub),
        ..Default::default()
    }
}

/// The first-authorization profile, as Apple's form body carries it.
fn apple_user() -> String {
    json!({"name": {"firstName": "Ada", "lastName": "Lovelace"}, "email": "ada@example.com"}).to_string()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn apple_link_and_sign_in_via_form_post() {
    let stub = StubIssuer::new();
    *stub.iss.lock() = APPLE_ISSUER.to_string();
    // Apple's first authorization may carry the address only in `user`, so the
    // token need not have an email claim at all.
    *stub.omit_email.lock() = true;
    let s = TestServer::spawn_with(|c| c.owner_auth = apple_config(stub.clone())).await;
    let a = s.create_account("auser").await;
    let mut b = Browser::new(&s.url);

    // Link it. The authorize URL is Apple's form_post form.
    let (st, v) =
        b.post("/auth/link", json!({"provider": "apple", "password": a.password}), Some(a.access.as_str())).await;
    assert_eq!(st, 200, "{v}");
    let auth_url = v["challenge"]["url"].as_str().expect("authorize URL").to_string();
    assert_eq!(query(&auth_url, "response_mode"), "form_post", "{auth_url}");
    assert_eq!(query(&auth_url, "scope"), "name email");
    assert_eq!(query(&auth_url, "client_id"), APPLE_CLIENT_ID);
    let txn = v["txnId"].as_str().expect("txn").to_string();
    let state = query(&auth_url, "state");
    *stub.nonce.lock() = query(&auth_url, "nonce");

    // The callback arrives as a cross-site form POST, profile included.
    let (st, loc, body) = b
        .post_form(
            "/auth/callback/apple",
            &[("code".into(), "apple-one-time-code".into()), ("state".into(), state), ("user".into(), apple_user())],
        )
        .await;
    assert_eq!(st, 303, "Apple's callback should redirect: {body}");
    let (st, loc, body) = b.get(&loc.expect("callback Location")).await;
    assert_eq!(st, 303, "resume should redirect: {body}");
    assert!(loc.unwrap_or_default().contains("step=link"), "a link comes back to the app");

    // The client secret is an ES256 assertion aimed at Apple, not at us.
    let form = stub.last_form.lock().clone();
    let field = |k: &str| form.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone()).unwrap_or_default();
    assert_eq!(field("grant_type"), "authorization_code");
    assert_eq!(field("code"), "apple-one-time-code");
    let secret = field("client_secret");
    let jwt = vlpds::xrpc::owner_auth::jwt::Jwt::decode(&secret).expect("a JWT client secret");
    assert_eq!(jwt.alg(), "ES256", "Apple requires an ES256 assertion");
    assert_eq!(jwt.kid(), Some(APPLE_KEY_ID));
    assert_eq!(jwt.claim_str("iss"), Some(APPLE_TEAM_ID));
    assert_eq!(jwt.claim_str("sub"), Some(APPLE_CLIENT_ID));
    assert_eq!(jwt.claim_str("aud"), Some(APPLE_ISSUER), "the audience is Apple's issuer, not the client id");

    // The app finishes the link; the label is the profile Apple sent.
    let (st, v) = b.post("/auth/continue", json!({"txn": txn, "step": "link"}), None).await;
    assert_eq!(st, 200, "{v}");
    assert_eq!(v["status"], "linked", "{v}");
    assert_eq!(v["credential"]["provider"], "apple");
    assert_eq!(v["credential"]["label"], "ada@example.com", "{v}");

    // Sign in with Apple.
    let (st, v) = b.post("/auth/start", json!({"provider": "apple", "intent": "sign_in"}), None).await;
    assert_eq!(st, 200, "{v}");
    let auth_url = v["challenge"]["url"].as_str().expect("authorize URL").to_string();
    *stub.nonce.lock() = query(&auth_url, "nonce");
    let (st, _, body) = b
        .post_form("/auth/callback/apple", &[("code".into(), "c".into()), ("state".into(), query(&auth_url, "state"))])
        .await;
    assert_eq!(st, 303, "{body}");
    let (st, loc, _) = b.get(&format!("/auth/resume?t={}", v["txnId"].as_str().expect("txn"))).await;
    assert_eq!(st, 303);
    assert!(loc.unwrap_or_default().contains("auth=complete"), "a finished sign-in returns to the app");
    let (st, v) = b.post("/auth/complete", json!({}), None).await;
    assert_eq!(st, 200, "{v}");
    assert_eq!(v["did"], a.did);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn apple_rejects_a_token_from_another_issuer() {
    let stub = StubIssuer::new();
    *stub.iss.lock() = "https://evil.test".to_string();
    let s = TestServer::spawn_with(|c| c.owner_auth = apple_config(stub.clone())).await;
    let mut b = Browser::new(&s.url);

    let (st, v) = b.post("/auth/start", json!({"provider": "apple", "intent": "sign_in"}), None).await;
    assert_eq!(st, 200, "{v}");
    let auth_url = v["challenge"]["url"].as_str().expect("authorize URL").to_string();
    *stub.nonce.lock() = query(&auth_url, "nonce");
    let (st, loc, body) = b
        .post_form("/auth/callback/apple", &[("code".into(), "c".into()), ("state".into(), query(&auth_url, "state"))])
        .await;
    assert_eq!(st, 400, "a token from another issuer must be refused: {loc:?} {body}");
    assert!(loc.is_none(), "a refused proof must not redirect");
}
