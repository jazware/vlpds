//! The provider boundary: a provider proves who the person is and nothing
//! else. Account resolution, linking, signup, local second factors and
//! session issuance all live in the coordinator, so every provider gets the
//! same policy.

use async_trait::async_trait;

use super::types::*;
use super::*;

/// What a provider needs to start a login.
pub struct Begin<'a> {
    pub txn_id: &'a str,
    pub intent: Intent,
    /// This server's canonical origin (`scheme://host[:port]`), taken from
    /// `--public-url`, never from the request's Host header.
    pub origin: &'a str,
    /// Where the provider sends the browser back: `<origin>/auth/callback/<id>`.
    pub redirect_uri: &'a str,
    /// Whether the browser is already signed in as some account (link/reauth).
    pub owner: Option<&'a str>,
    /// A client-supplied hint the provider needs before it can build the
    /// challenge (the wallet address for SIWE). Ignored by redirect
    /// providers, which learn nothing from the browser up front.
    pub address: Option<&'a str>,
}

/// What the browser must do next.
pub enum BeginOut {
    /// Send the browser here; `state` is persisted on the transaction.
    Redirect { url: String, state: J },
    /// Have the wallet sign `message`; `state` is persisted on the transaction.
    Siwe { message: String, state: J },
}

/// The result of a provider callback.
pub enum CallbackOut {
    /// The proof is good.
    Verified(Box<VerifiedIdentity>),
    /// The user backed out at the provider (no error page needed).
    Cancelled,
}

/// A browser-submitted proof (a SIWE signature).
#[derive(Clone, Debug, Default, Deserialize)]
pub struct SiweProof {
    #[serde(default)]
    pub message: String,
    #[serde(default)]
    pub signature: String,
    /// Optional: the page the signature should report; checked against the
    /// configured one.
    #[serde(default)]
    pub address: Option<String>,
}

#[async_trait]
pub trait AuthProvider: Send + Sync {
    fn id(&self) -> ProviderId;

    /// Create the challenge for a started transaction.
    async fn begin(&self, app: &App, b: &Begin<'_>) -> Result<BeginOut, XrpcError>;

    /// Consume the provider's callback (query params for Google, a form body
    /// for Apple). Only redirect-based providers use this.
    async fn callback(&self, app: &App, txn: &Txn, q: &[(String, String)]) -> Result<CallbackOut, XrpcError>;

    /// Verify a proof the browser submitted directly (SIWE). Default: the
    /// provider has no direct-proof path.
    async fn verify(&self, _app: &App, _txn: &Txn, _proof: &SiweProof) -> Result<VerifiedIdentity, XrpcError> {
        Err(bad_request("this method does not take a direct proof"))
    }
}
