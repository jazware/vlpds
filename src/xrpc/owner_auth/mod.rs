//! Pluggable owner authentication: Google, Apple and Sign-In with Ethereum
//! behind one coordinator, alongside password and passkey.
//!
//! Layering: [`types`] is the vocabulary, [`store`] the durable rows,
//! [`provider`] the proof boundary, [`providers`] the three implementations,
//! [`flow`] the coordinator (resolve/link/signup/second factors/completion)
//! and [`web`] the HTTP surface. A provider never creates an account, issues
//! a session or decides that a second factor is unnecessary.

pub mod flow;
pub mod gc;
pub mod jwt;
pub mod provider;
pub mod providers;
pub mod store;
pub mod types;
pub mod web;

pub use provider::{AuthProvider, Begin, BeginOut, CallbackOut, SiweProof};
pub use store::{Continuation, Cred, Creds, Grant, Txn};
pub use types::{Challenge, Intent, Presentation, ProviderId, VerifiedEmail, VerifiedIdentity};

use futures::future::BoxFuture;

use super::*;

/// The built provider registry and the configuration it was built from,
/// fixed at startup: adding a provider is a restart, not a runtime change.
pub struct Runtime {
    pub cfg: Config,
    providers: Vec<Arc<dyn AuthProvider>>,
}

impl Runtime {
    pub fn new(cfg: Config) -> Runtime {
        let providers = cfg.registry();
        Runtime { cfg, providers }
    }

    pub fn provider(&self, id: ProviderId) -> Option<Arc<dyn AuthProvider>> {
        self.providers.iter().find(|p| p.id() == id).cloned()
    }

    /// Providers this node runs, in display order.
    pub fn enabled(&self) -> Vec<ProviderId> {
        self.cfg.enabled()
    }
}

/// Everything the provider subsystem needs from configuration. A provider
/// with no configuration is compiled in but disabled.
#[derive(Clone, Default)]
pub struct Config {
    pub google: Option<GoogleConfig>,
    pub apple: Option<AppleConfig>,
    pub siwe: Option<SiweConfig>,
    /// Outbound HTTP for provider metadata and token endpoints. None: the
    /// SSRF-guarded client. Tests inject a stub.
    pub fetch: Option<Arc<dyn HttpFetch>>,
    /// Passed to the guarded client (dev mode allows loopback).
    pub dev_mode: bool,
}

impl Config {
    /// The providers this node runs, in a fixed display order.
    pub fn enabled(&self) -> Vec<ProviderId> {
        let mut out = Vec::new();
        if self.google.is_some() {
            out.push(ProviderId::Google);
        }
        if self.apple.is_some() {
            out.push(ProviderId::Apple);
        }
        if self.siwe.is_some() {
            out.push(ProviderId::Siwe);
        }
        out
    }

    pub fn is_enabled(&self, id: ProviderId) -> bool {
        self.enabled().contains(&id)
    }

    /// The providers to run, built once at startup.
    pub fn registry(&self) -> Vec<Arc<dyn AuthProvider>> {
        let mut out: Vec<Arc<dyn AuthProvider>> = Vec::new();
        if let Some(c) = &self.google {
            out.push(Arc::new(providers::google::GoogleProvider::new(c.clone())));
        }
        if let Some(c) = &self.apple {
            match providers::apple::AppleProvider::new(c.clone()) {
                Ok(p) => out.push(Arc::new(p)),
                Err(e) => tracing::error!("Apple provider disabled: {e}"),
            }
        }
        if let Some(c) = &self.siwe {
            out.push(Arc::new(providers::siwe::SiweProvider::new(c.clone())));
        }
        out
    }

    /// Refuse to start when a configured provider is unusable.
    pub fn validate(&self, public_url: &str) -> anyhow::Result<()> {
        if self.enabled().is_empty() {
            return Ok(());
        }
        let url = reqwest::Url::parse(public_url)
            .map_err(|e| anyhow::anyhow!("--public-url is not a URL, but an auth provider is configured: {e}"))?;
        if url.scheme() != "https" && !self.dev_mode {
            anyhow::bail!("auth providers need an https --public-url (except in dev mode): {public_url}");
        }
        if url.host_str().is_none() {
            anyhow::bail!("--public-url has no host, but an auth provider is configured");
        }
        if let Some(g) = &self.google {
            anyhow::ensure!(!g.client_id.trim().is_empty(), "--auth-google-client-id is empty");
            anyhow::ensure!(!g.client_secret.trim().is_empty(), "--auth-google-client-secret is empty");
        }
        if let Some(a) = &self.apple {
            anyhow::ensure!(!a.client_id.trim().is_empty(), "--auth-apple-client-id is empty");
            anyhow::ensure!(a.team_id.len() == 10, "--auth-apple-team-id must be Apple's 10-character Team ID");
            anyhow::ensure!(!a.key_id.trim().is_empty(), "--auth-apple-key-id is empty");
            anyhow::ensure!(
                a.private_key_pem.contains("PRIVATE KEY"),
                "--auth-apple-private-key-file is not a PEM key"
            );
        }
        if let Some(s) = &self.siwe {
            anyhow::ensure!(s.chain_id > 0, "--auth-siwe-chain-id must be a positive EIP-155 chain id");
        }
        Ok(())
    }

    /// The callback URL registered with each provider.
    pub fn redirect_uri(public_url: &str, id: ProviderId) -> String {
        format!("{}/auth/callback/{}", public_url.trim_end_matches('/'), id.as_str())
    }
}

/// Google (OIDC). Endpoints are configurable so a self-hosted or test issuer
/// can stand in; the defaults are Google's.
#[derive(Clone, Debug)]
pub struct GoogleConfig {
    pub client_id: String,
    pub client_secret: String,
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
}

impl GoogleConfig {
    pub fn with_defaults(client_id: String, client_secret: String) -> Self {
        GoogleConfig {
            client_id,
            client_secret,
            issuer: "https://accounts.google.com".into(),
            authorization_endpoint: "https://accounts.google.com/o/oauth2/v2/auth".into(),
            token_endpoint: "https://oauth2.googleapis.com/token".into(),
            jwks_uri: "https://www.googleapis.com/oauth2/v3/certs".into(),
        }
    }
}

/// Apple. The client secret is an ES256 JWT this node mints from the signing
/// key, so no long-lived secret is stored.
#[derive(Clone, Debug)]
pub struct AppleConfig {
    /// The Services ID.
    pub client_id: String,
    pub team_id: String,
    pub key_id: String,
    /// PEM of the ES256 `.p8` key.
    pub private_key_pem: String,
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
}

impl AppleConfig {
    pub fn with_defaults(client_id: String, team_id: String, key_id: String, private_key_pem: String) -> Self {
        AppleConfig {
            client_id,
            team_id,
            key_id,
            private_key_pem,
            issuer: "https://appleid.apple.com".into(),
            authorization_endpoint: "https://appleid.apple.com/auth/authorize".into(),
            token_endpoint: "https://appleid.apple.com/auth/token".into(),
            jwks_uri: "https://appleid.apple.com/auth/keys".into(),
        }
    }
}

/// Sign-In with Ethereum. No client credentials: the wallet signs a
/// server-issued EIP-4361 message.
#[derive(Clone, Debug)]
pub struct SiweConfig {
    pub chain_id: u64,
    /// The EIP-4361 `domain`. None: the public URL's host.
    pub domain: Option<String>,
    /// The EIP-4361 `uri`. None: `<public_url>/auth/siwe`.
    pub uri: Option<String>,
}

/// Outbound HTTP for provider endpoints. Split out so tests can stand in for
/// Google's and Apple's servers without real network access.
pub trait HttpFetch: Send + Sync {
    fn get_json<'a>(&'a self, url: &'a str, max: usize) -> BoxFuture<'a, Result<J, String>>;
    fn post_form<'a>(
        &'a self,
        url: &'a str,
        form: &'a [(String, String)],
        max: usize,
    ) -> BoxFuture<'a, Result<J, String>>;
}

/// The production fetcher: the SSRF-guarded client (`vlatproto::http`),
/// no redirects, size-capped, 10 s.
pub struct GuardedFetch {
    pub dev_mode: bool,
}

const FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// One guarded request, response read under a byte cap and parsed as JSON.
async fn guarded_json(dev_mode: bool, url: &str, form: Option<&[(String, String)]>, max: usize) -> Result<J, String> {
    use futures::StreamExt;
    let g = vlatproto::http::guarded(dev_mode);
    let rb = match form {
        Some(f) => g
            .request(reqwest::Method::POST, url)?
            .header("content-type", "application/x-www-form-urlencoded")
            .body(crate::oauth::util::form_encode(f)),
        None => g.get(url)?,
    };
    let resp = rb
        .header("accept", "application/json")
        .timeout(FETCH_TIMEOUT)
        .send()
        .await
        .map_err(|e| format!("fetch failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("unexpected HTTP status {}", resp.status().as_u16()));
    }
    if resp.content_length().is_some_and(|l| l as usize > max) {
        return Err("response too large".into());
    }
    let mut buf: Vec<u8> = Vec::new();
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| e.to_string())?;
        if buf.len() + chunk.len() > max {
            return Err("response too large".into());
        }
        buf.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&buf).map_err(|e| format!("invalid JSON: {e}"))
}

impl HttpFetch for GuardedFetch {
    fn get_json<'a>(&'a self, url: &'a str, max: usize) -> BoxFuture<'a, Result<J, String>> {
        Box::pin(guarded_json(self.dev_mode, url, None, max))
    }

    fn post_form<'a>(
        &'a self,
        url: &'a str,
        form: &'a [(String, String)],
        max: usize,
    ) -> BoxFuture<'a, Result<J, String>> {
        Box::pin(guarded_json(self.dev_mode, url, Some(form), max))
    }
}

/// The fetcher this node uses: the injected stub, else the guarded client.
pub fn fetcher(cfg: &Config) -> Arc<dyn HttpFetch> {
    cfg.fetch.clone().unwrap_or_else(|| Arc::new(GuardedFetch { dev_mode: cfg.dev_mode }))
}

/// The largest provider JSON body we accept (JWKS, token, userinfo).
pub const MAX_PROVIDER_BODY: usize = 64 * 1024;

pub fn now_secs() -> i64 {
    crate::oauth::util::now_secs()
}
