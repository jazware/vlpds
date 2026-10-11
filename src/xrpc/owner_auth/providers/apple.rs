//! Apple: `response_mode=form_post` authorization, a client secret minted as
//! an ES256 assertion from the configured `.p8` key, and a validated RS256 ID
//! token.
//!
//! The callback is a cross-site POST, so the browser's SameSite=Lax device
//! cookie is not sent with it; the coordinator therefore stages the verified
//! identity on the transaction and finishes on a same-origin landing request.

use async_trait::async_trait;

use super::super::jwt::{self, Jwks, Jwt};
use super::super::provider::{Begin, BeginOut, CallbackOut};
use super::super::store::Txn;
use super::super::types::*;
use super::super::*;
use crate::oauth::util::random_id;
use crate::xrpc::owner_auth::AppleConfig;

/// Apple rejects client-secret assertions valid for more than six months;
/// stay well inside that.
const CLIENT_SECRET_TTL_SECS: i64 = 150 * 24 * 3600;

pub struct AppleProvider {
    cfg: AppleConfig,
    jwks: Jwks,
}

fn param<'a>(q: &'a [(String, String)], k: &str) -> Option<&'a str> {
    q.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str())
}

impl AppleProvider {
    pub fn new(cfg: AppleConfig) -> Result<AppleProvider, String> {
        // Fail at startup, not at the first login.
        jwt::pem_to_der(&cfg.private_key_pem).map_err(|e| format!("Apple private key: {e}"))?;
        let jwks = Jwks::new(&cfg.jwks_uri);
        Ok(AppleProvider { cfg, jwks })
    }

    fn client_secret(&self) -> Result<String, XrpcError> {
        let now = now_secs();
        let claims = json!({
            "iss": self.cfg.team_id,
            "iat": now,
            "exp": now + CLIENT_SECRET_TTL_SECS,
            // Apple wants its own issuer as the audience here, not the
            // Services ID.
            "aud": self.cfg.issuer,
            "sub": self.cfg.client_id,
        });
        jwt::sign_es256_pem(&self.cfg.private_key_pem, &self.cfg.key_id, &claims)
            .map_err(|e| XrpcError::internal(format!("Apple client secret: {e}")))
    }

    /// The first-authorization `user` object (name/email). Present only the
    /// first time; must not be treated as proof.
    fn user_profile(user: Option<&str>) -> (Option<String>, Option<String>) {
        let Some(raw) = user else { return (None, None) };
        let Ok(v) = serde_json::from_str::<J>(raw) else { return (None, None) };
        let email = v.get("email").and_then(J::as_str).map(String::from);
        let name = v.get("name").and_then(|n| {
            let first = n.get("firstName").and_then(J::as_str).unwrap_or("");
            let last = n.get("lastName").and_then(J::as_str).unwrap_or("");
            let full = format!("{first} {last}").trim().to_string();
            (!full.is_empty()).then_some(full)
        });
        (email, name)
    }
}

#[async_trait]
impl AuthProvider for AppleProvider {
    fn id(&self) -> ProviderId {
        ProviderId::Apple
    }

    async fn begin(&self, _app: &App, b: &Begin<'_>) -> Result<BeginOut, XrpcError> {
        // As for Google: the state the callback comes back with is the
        // transaction id.
        let state = b.txn_id.to_string();
        let nonce = random_id("n-", 16);
        let url = format!(
            "{}?{}",
            self.cfg.authorization_endpoint,
            crate::oauth::util::form_encode(&[
                ("client_id".into(), self.cfg.client_id.clone()),
                ("redirect_uri".into(), b.redirect_uri.to_string()),
                ("response_type".into(), "code".into()),
                ("scope".into(), "name email".into()),
                ("response_mode".into(), "form_post".into()),
                ("state".into(), state.clone()),
                ("nonce".into(), nonce.clone()),
            ])
        );
        let st = json!({"state": state, "nonce": nonce});
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
        let nonce = st.get("nonce").and_then(J::as_str).ok_or_else(|| XrpcError::internal("no nonce"))?;
        let (user_email, user_name) = Self::user_profile(param(q, "user"));

        let f = fetcher(&app.config.owner_auth);
        let redirect = Config::redirect_uri(&app.public_url, ProviderId::Apple);
        let secret = self.client_secret()?;
        let body = f
            .post_form(
                &self.cfg.token_endpoint,
                &[
                    ("grant_type".into(), "authorization_code".into()),
                    ("code".into(), code.to_string()),
                    ("redirect_uri".into(), redirect),
                    ("client_id".into(), self.cfg.client_id.clone()),
                    ("client_secret".into(), secret),
                ],
                MAX_PROVIDER_BODY,
            )
            .await
            .map_err(|e| provider_unavailable(&format!("Apple token exchange failed: {e}")))?;
        let id_token = body.get("id_token").and_then(J::as_str).ok_or_else(|| proof_rejected("no id_token"))?;

        let jwt = Jwt::decode(id_token).map_err(|e| proof_rejected(&e))?;
        jwt::check_common(&jwt, &self.cfg.issuer, &self.cfg.client_id, now_secs()).map_err(|e| proof_rejected(&e))?;
        match jwt.claim_str("nonce") {
            Some(n) if n == nonce => {}
            _ => return Err(proof_rejected("id_token nonce mismatch")),
        }
        self.jwks.verify(app, &jwt).await.map_err(|e| proof_rejected(&e))?;

        let c = jwt::claims(&jwt).map_err(|e| proof_rejected(&e))?;
        // Apple is authoritative only for a non-relay, verified address.
        let relay = c.email.as_deref().is_some_and(|e| e.to_ascii_lowercase().ends_with("@privaterelay.appleid.com"))
            || jwt.claim_bool("is_private_email").unwrap_or(false)
            || jwt.claim_str("is_private_email") == Some("true");
        let email = c
            .email
            .clone()
            .or(user_email)
            .map(|address| VerifiedEmail { address, authoritative: c.email_verified && !relay });
        Ok(CallbackOut::Verified(Box::new(VerifiedIdentity {
            provider: ProviderId::Apple,
            subject: c.sub,
            label: email.as_ref().map(|e| e.address.clone()).or(user_name),
            email,
            verified_at: now_secs(),
            // Apple's refresh token would be needed to call Apple's
            // `/auth/revoke` on unlink; that lifecycle call is not wired in
            // this pass, so no provider token is retained at all rather than
            // storing one we never use.
            sealed_token: None,
        })))
    }
}
