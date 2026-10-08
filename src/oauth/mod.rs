//! atproto OAuth authorization server building blocks; the HTTP surface is
//! `xrpc/oauth.rs`.
//!
//! Access tokens are ES256 JWTs under a P-256 key derived from `jwt_secret`,
//! as are the DPoP nonce, CSRF and refresh-token MAC keys, so every node can
//! issue and verify with no shared mutable state (rotating `jwt_secret`
//! invalidates every OAuth token). Durable rows go through `put_private`:
//! - `oauth:req:{id}` / `oauth/req`: PAR requests, then the issued code; a
//!   consumed one stays as a tombstone so code reuse can revoke its session.
//!   The id is minted to land on a partition of the node that ran PAR.
//! - `oauth:cc:{hash}` / `oauth/cc`: PKCE `code_challenge` reuse markers.
//! - `oauth:dev:{id}` / `oauth/dev`: browser device sessions.
//! - `{did}` / `oauth/ses/{id}`, `oauth/authz/{hash(client_id)}`: sessions
//!   and remembered consent.
//! - `oauth:lex:{nsid}` / `oauth/lex`: last good permission-set lexicons.
//!
//! Refresh tokens and codes embed their routing key (DID + session id,
//! request id), so lookups need no index and `crate::forward` can route
//! `/oauth/*` statelessly (`xrpc::oauth::route_key`) to the row's owner.
//!
//! Single use, cluster-wide:
//! - Code exchange and refresh rotation run only on the owner of the row
//!   (`require_owner`; 503 mid-handoff), under `store::lock`, and write the
//!   session conditionally (`store::put_session_if`; DESIGN.md "Auth state
//!   under concurrency"), so a revoke-all from any node is never undone by
//!   an exchange or refresh in flight.
//! - DPoP proof, client-assertion and request-object `jti`s are claimed at
//!   the owner of a routing key (`xrpc::internal::claim_replay_anywhere`).
//!   Authorization-server claims are also persisted (`oauth/replay/{hash}`)
//!   before they count, so a new owner after a failover still refuses a
//!   proof its predecessor accepted.
//! - Resource-request proofs are claimed in memory only, like the
//!   reference: a durable claim would put a log write on every authenticated
//!   request. Residual risk: right after a failover, a captured proof could
//!   be replayed once, within its `iat` window and nonce lifetime, and only
//!   with the (short-lived, revocable) access token it is bound to.
//! - A resource request answered ShardMoved / RepoLoading (nothing done)
//!   gives its proof's claim back, so the entry node's resend of the same
//!   proof is served (`xrpc::oauth::dpop_layer`; DESIGN.md "Forwarding
//!   deadlines and not-applied writes").

pub mod client;
pub mod gc;
pub mod jose;
pub mod lexicon;
pub mod scopes;
pub mod store;
pub mod ui;
pub mod util;

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;

pub use scopes::ScopeSet;

/// Spec: < 30 min when individually revocable, as ours are.
pub const ACCESS_TOKEN_TTL: i64 = 15 * 60;
pub const PAR_EXPIRES_IN: i64 = 5 * 60;
/// On the authorization page, and an issued code's lifetime.
pub const AUTHORIZATION_INACTIVITY_TIMEOUT: i64 = 5 * 60;
pub const AUTHENTICATION_MAX_AGE: i64 = 7 * 86_400;
pub const CODE_CHALLENGE_REPLAY_TIMEFRAME: i64 = 86_400;

#[derive(Debug, Clone)]
pub struct OAuthError {
    pub status: StatusCode,
    pub error: String,
    pub description: String,
}

impl OAuthError {
    pub fn new(status: StatusCode, error: &str, description: &str) -> OAuthError {
        OAuthError { status, error: error.into(), description: description.into() }
    }
    pub fn invalid_request(d: &str) -> OAuthError {
        Self::new(StatusCode::BAD_REQUEST, "invalid_request", d)
    }
    pub fn invalid_client(d: &str) -> OAuthError {
        Self::new(StatusCode::BAD_REQUEST, "invalid_client", d)
    }
    pub fn invalid_client_metadata(d: &str) -> OAuthError {
        Self::new(StatusCode::BAD_REQUEST, "invalid_client_metadata", d)
    }
    pub fn invalid_redirect_uri(d: &str) -> OAuthError {
        Self::new(StatusCode::BAD_REQUEST, "invalid_redirect_uri", d)
    }
    pub fn invalid_grant(d: &str) -> OAuthError {
        Self::new(StatusCode::BAD_REQUEST, "invalid_grant", d)
    }
    pub fn invalid_scope(d: &str) -> OAuthError {
        Self::new(StatusCode::BAD_REQUEST, "invalid_scope", d)
    }
    pub fn unauthorized_client(d: &str) -> OAuthError {
        Self::new(StatusCode::BAD_REQUEST, "unauthorized_client", d)
    }
    pub fn unsupported_grant_type(d: &str) -> OAuthError {
        Self::new(StatusCode::BAD_REQUEST, "unsupported_grant_type", d)
    }
    pub fn use_dpop_nonce(d: &str) -> OAuthError {
        Self::new(StatusCode::BAD_REQUEST, "use_dpop_nonce", d)
    }
    pub fn invalid_dpop_proof(d: &str) -> OAuthError {
        Self::new(StatusCode::BAD_REQUEST, "invalid_dpop_proof", d)
    }
    pub fn server_error(d: &str) -> OAuthError {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "server_error", d)
    }
}

impl From<vlsync_atproto::xrpc::XrpcError> for OAuthError {
    fn from(e: vlsync_atproto::xrpc::XrpcError) -> OAuthError {
        // transient 503s (shard moving, Argon2 shed, KMS down) stay
        // retryable: RFC 6749 temporarily_unavailable, not server_error
        if e.status == StatusCode::SERVICE_UNAVAILABLE {
            return OAuthError::new(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable", &e.message);
        }
        OAuthError::server_error(&e.message)
    }
}

impl IntoResponse for OAuthError {
    fn into_response(self) -> Response {
        let mut r =
            (self.status, Json(serde_json::json!({"error": self.error, "error_description": self.description})))
                .into_response();
        r.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        if self.status == StatusCode::SERVICE_UNAVAILABLE {
            r.headers_mut().insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
        }
        r
    }
}
