//! Google: authorization-code flow with PKCE and a server-generated nonce,
//! then a validated RS256 ID token. The userinfo endpoint is never used to
//! rescue a token that failed validation — a bad proof is terminal.

use async_trait::async_trait;

use super::super::jwt::{self, Jwks, Jwt};
use super::super::provider::{Begin, BeginOut, CallbackOut};
use super::super::store::Txn;
use super::super::types::*;
use super::super::*;
use crate::oauth::util::random_id;
use crate::xrpc::owner_auth::GoogleConfig;

pub struct GoogleProvider {
    cfg: GoogleConfig,
    jwks: Jwks,
}

fn param<'a>(q: &'a [(String, String)], k: &str) -> Option<&'a str> {
    q.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str())
}

fn b64u(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

impl GoogleProvider {
    pub fn new(cfg: GoogleConfig) -> GoogleProvider {
        let jwks = Jwks::new(&cfg.jwks_uri);
        GoogleProvider { cfg, jwks }
    }
}

#[async_trait]
impl AuthProvider for GoogleProvider {
    fn id(&self) -> ProviderId {
        ProviderId::Google
    }

    async fn begin(&self, _app: &App, b: &Begin<'_>) -> Result<BeginOut, XrpcError> {
        // The provider's `state` is the transaction id: it is the only thing
        // the callback is given to find the login it belongs to, and it is
        // unguessable. The nonce and PKCE verifier stay independent.
        let state = b.txn_id.to_string();
        let nonce = random_id("n-", 16);
        let verifier = random_id("v-", 32);
        let challenge = b64u(&crate::oauth::util::sha256(verifier.as_bytes()));
        let url = format!(
            "{}?{}",
            self.cfg.authorization_endpoint,
            crate::oauth::util::form_encode(&[
                ("client_id".into(), self.cfg.client_id.clone()),
                ("redirect_uri".into(), b.redirect_uri.to_string()),
                ("response_type".into(), "code".into()),
                ("scope".into(), "openid email profile".into()),
                ("state".into(), state.clone()),
                ("nonce".into(), nonce.clone()),
                ("code_challenge".into(), challenge),
                ("code_challenge_method".into(), "S256".into()),
                ("prompt".into(), "select_account".into()),
            ])
        );
        let st = json!({"state": state, "nonce": nonce, "verifier": verifier});
        Ok(BeginOut::Redirect { url, state: st })
    }

    async fn callback(&self, app: &App, txn: &Txn, q: &[(String, String)]) -> Result<CallbackOut, XrpcError> {
        if param(q, "error").is_some() {
            return Ok(CallbackOut::Cancelled);
        }
        let st = txn.state.as_ref().ok_or_else(|| bad_request("transaction has no provider state"))?;
        let expect_state = st.get("state").and_then(J::as_str).ok_or_else(|| XrpcError::internal("no state"))?;
        let got_state = param(q, "state").ok_or_else(|| bad_request("callback has no state"))?;
        if got_state != expect_state {
            return Err(proof_rejected("state mismatch"));
        }
        let code = param(q, "code").ok_or_else(|| bad_request("callback has no code"))?;
        let verifier = st.get("verifier").and_then(J::as_str).ok_or_else(|| XrpcError::internal("no PKCE verifier"))?;
        let nonce = st.get("nonce").and_then(J::as_str).ok_or_else(|| XrpcError::internal("no nonce"))?;

        let f = fetcher(&app.config.owner_auth);
        let redirect = Config::redirect_uri(&app.public_url, ProviderId::Google);
        let body = f
            .post_form(
                &self.cfg.token_endpoint,
                &[
                    ("grant_type".into(), "authorization_code".into()),
                    ("code".into(), code.to_string()),
                    ("redirect_uri".into(), redirect),
                    ("client_id".into(), self.cfg.client_id.clone()),
                    ("client_secret".into(), self.cfg.client_secret.clone()),
                    ("code_verifier".into(), verifier.to_string()),
                ],
                MAX_PROVIDER_BODY,
            )
            .await
            .map_err(|e| provider_unavailable(&format!("Google token exchange failed: {e}")))?;
        let id_token = body.get("id_token").and_then(J::as_str).ok_or_else(|| proof_rejected("no id_token"))?;

        let jwt = Jwt::decode(id_token).map_err(|e| proof_rejected(&e))?;
        jwt::check_common(&jwt, &self.cfg.issuer, &self.cfg.client_id, now_secs()).map_err(|e| proof_rejected(&e))?;
        match jwt.claim_str("nonce") {
            Some(n) if n == nonce => {}
            _ => return Err(proof_rejected("id_token nonce mismatch")),
        }
        self.jwks.verify(app, &jwt).await.map_err(|e| proof_rejected(&e))?;

        let c = jwt::claims(&jwt).map_err(|e| proof_rejected(&e))?;
        // Google is authoritative for the address only for Gmail or a hosted
        // (Workspace) domain whose hd claim is present.
        let hd = jwt.claim_str("hd");
        let gmail = c.email.as_deref().is_some_and(|e| e.to_ascii_lowercase().ends_with("@gmail.com"));
        let authoritative = c.email_verified && (gmail || hd.is_some());
        Ok(CallbackOut::Verified(Box::new(VerifiedIdentity {
            provider: ProviderId::Google,
            subject: c.sub,
            email: c.email.clone().map(|address| VerifiedEmail { address, authoritative }),
            label: c.email.clone().or(c.name.clone()),
            verified_at: now_secs(),
            sealed_token: None,
        })))
    }
}
