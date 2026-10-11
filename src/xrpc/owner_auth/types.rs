//! The shared vocabulary of pluggable owner authentication: which providers
//! exist, what a login is trying to do, what a provider must prove, and how a
//! credential is named on the rows that record "this credential signed this
//! in" (`auth_cred`).

use serde::{Deserialize, Serialize};

use super::*;

/// A configured external owner-authentication provider. Compiled in; a
/// provider runs only when its configuration is present.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProviderId {
    Google,
    Apple,
    Siwe,
}

impl ProviderId {
    pub const ALL: [ProviderId; 3] = [ProviderId::Google, ProviderId::Apple, ProviderId::Siwe];

    pub fn as_str(self) -> &'static str {
        match self {
            ProviderId::Google => "google",
            ProviderId::Apple => "apple",
            ProviderId::Siwe => "siwe",
        }
    }

    /// The name a person sees.
    pub fn label(self) -> &'static str {
        match self {
            ProviderId::Google => "Google",
            ProviderId::Apple => "Apple",
            ProviderId::Siwe => "Ethereum",
        }
    }

    pub fn parse(s: &str) -> Option<ProviderId> {
        match s {
            "google" => Some(ProviderId::Google),
            "apple" => Some(ProviderId::Apple),
            "siwe" => Some(ProviderId::Siwe),
            _ => None,
        }
    }

    /// How the browser runs the proof for this provider.
    pub fn presentation(self) -> Presentation {
        match self {
            ProviderId::Google | ProviderId::Apple => Presentation::Redirect,
            ProviderId::Siwe => Presentation::Siwe,
        }
    }

    /// The factor label recorded in the sign-in log and metrics.
    pub fn factor(self) -> &'static str {
        self.as_str()
    }
}

/// How the browser is driven after `/auth/start`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Presentation {
    /// Navigate the browser to the provider's authorization endpoint.
    Redirect,
    /// Hand the browser an EIP-4361 message to sign with a wallet.
    Siwe,
}

/// What a login is for. The coordinator owns the meaning; a provider only
/// proves an identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Intent {
    /// An existing identity: find its account and sign in.
    SignIn,
    /// An unknown identity: collect the missing account fields and create one.
    SignUp,
    /// Attach an identity to the already-authenticated account.
    Link,
    /// Prove the account owner again before a sensitive operation.
    Reauth,
}

impl Intent {
    pub fn as_str(self) -> &'static str {
        match self {
            Intent::SignIn => "sign_in",
            Intent::SignUp => "sign_up",
            Intent::Link => "link",
            Intent::Reauth => "reauth",
        }
    }

    pub fn parse(s: &str) -> Option<Intent> {
        match s {
            "sign_in" | "signin" => Some(Intent::SignIn),
            "sign_up" | "signup" => Some(Intent::SignUp),
            "link" => Some(Intent::Link),
            "reauth" => Some(Intent::Reauth),
            _ => None,
        }
    }

    /// Whether the caller must already be signed in as `did`.
    pub fn needs_owner(self) -> bool {
        matches!(self, Intent::Link | Intent::Reauth)
    }
}

/// A credential reference as recorded on sessions (`auth_cred`): the
/// provider's name, a colon, and a short hash of the identity. Deliberately
/// distinct from passkeys' `pk:` so provenance, display and revocation stay
/// unambiguous.
pub fn cred_ref(provider: ProviderId, subject: &str) -> String {
    format!("{}:{}", provider.as_str(), hex::encode(&crate::oauth::util::sha256(subject.as_bytes())[..8]))
}

/// True for a reference minted by [`cred_ref`] (i.e. not a passkey).
pub fn is_external_cred_ref(r: &str) -> bool {
    !r.starts_with("pk:") && r.split_once(':').is_some_and(|(p, _)| ProviderId::parse(p).is_some())
}

/// The provider a reference belongs to, when it is an external one.
pub fn provider_of_ref(r: &str) -> Option<ProviderId> {
    r.split_once(':').and_then(|(p, _)| ProviderId::parse(p))
}

/// An email address a provider attested, and whether the provider is
/// authoritative for it (Gmail or a Google Workspace hosted domain). Never
/// used to merge accounts; only as contact/recovery material.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedEmail {
    pub address: String,
    /// The provider both owns the address and says it is verified.
    pub authoritative: bool,
}

/// What a provider proves. Not client-writable, carries no tokens and no
/// policy instruction: the coordinator decides what it is worth.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerifiedIdentity {
    pub provider: ProviderId,
    /// The provider's stable identity for this person (Google/Apple `sub`, or
    /// a normalized Ethereum address). Namespaced by `provider`.
    pub subject: String,
    /// Contact material, when the provider supplied it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<VerifiedEmail>,
    /// A human label for the credential list (an email, or `0x…`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// When the proof was accepted (unix seconds).
    pub verified_at: i64,
    /// Provider token material needed for later lifecycle calls (Apple
    /// authorization revocation), already sealed at rest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealed_token: Option<String>,
}

impl VerifiedIdentity {
    pub fn cred_ref(&self) -> String {
        cred_ref(self.provider, &self.subject)
    }
}

/// What a provider returns to the browser to obtain a proof.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum Challenge {
    /// Send the browser here.
    Redirect { url: String },
    /// Have the wallet sign exactly this EIP-4361 message.
    Siwe { message: String, address: Option<String> },
}

/// A rejected proof: the browser is told the attempt failed, never which
/// check failed.
pub fn proof_rejected(message: &str) -> XrpcError {
    XrpcError { status: StatusCode::BAD_REQUEST, error: "AuthProofRejected".into(), message: message.into() }
}

/// A provider that cannot run right now (network, JWKS, configuration).
pub fn provider_unavailable(message: &str) -> XrpcError {
    XrpcError {
        status: StatusCode::SERVICE_UNAVAILABLE,
        error: "AuthProviderUnavailable".into(),
        message: message.into(),
    }
}

/// A request that doesn't fit the contract (unknown provider, expired or
/// already-used transaction, a reply from the wrong browser).
pub fn bad_request(message: &str) -> XrpcError {
    XrpcError { status: StatusCode::BAD_REQUEST, error: "InvalidRequest".into(), message: message.into() }
}
