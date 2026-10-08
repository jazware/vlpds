//! Client attestations (reference PDS `client-attestation-verifier.ts`):
//! which app is asking a space authority for a credential, for an
//! `appAccess` allow list. The attestation is a JWT the client signs with
//! its own authentication key, so verifying it means resolving `iss` (the
//! client_id) to its metadata, taking the JWKS that publishes (inline or
//! `jwks_uri`, through the SSRF-guarded fetch and cache of OAuth clients)
//! and checking the signature with the key its `kid` names. Without that the
//! client_id is just a claim. Single use, at most 300 s.

use super::token::{self, TokenType};
use crate::xrpc::XResult;
use vlsync_atproto::xrpc::XrpcError;

fn invalid(m: impl Into<String>) -> XrpcError {
    XrpcError::bad("InvalidClientAttestation", m)
}

/// The verified client_id. `aud` is the space host it must be addressed to
/// (`{authority}#atproto_space_host`), so one minted for another authority
/// can't be replayed here; `routing` (the authority) is where its `jti` is
/// claimed.
pub async fn verify(app: &crate::xrpc::App, attestation: &str, aud: &str, routing: &str) -> XResult<String> {
    let t = token::parse(TokenType::ClientAttestation, attestation).map_err(|e| invalid(e.message))?;
    let client_id = t.claims.iss.clone();
    let client = crate::oauth::client::get_client(&client_id, app.config.dev_mode, &app.public_url)
        .await
        .map_err(|_| invalid(format!("Could not resolve client metadata for \"{client_id}\"")))?;
    if client.jwks.is_empty() {
        return Err(invalid(format!("Client \"{client_id}\" publishes no keys to verify an attestation against")));
    }
    let bad = || invalid(format!("Invalid client attestation for \"{client_id}\""));
    let jwt = crate::oauth::jose::DecodedJwt::decode(attestation).map_err(|_| bad())?;
    let kid = jwt.header.get("kid").and_then(|k| k.as_str());
    let signed = client
        .jwks
        .iter()
        .filter(|k| kid.is_none_or(|kid| k.get("kid").and_then(|v| v.as_str()) == Some(kid)))
        .filter(|k| k.get("use").and_then(|v| v.as_str()).is_none_or(|u| u == "sig"))
        .filter_map(|k| crate::oauth::jose::jwk_to_key(k).ok())
        .any(|k| jwt.verify_es256(&k));
    if !signed {
        return Err(bad());
    }
    let now = vlsync_atproto::tid::now_micros() as i64 / 1_000_000;
    t.check(now, Some(aud), Some(&client_id)).map_err(|_| bad())?;
    // the signature first: a forged token never spends a jti
    let key = format!("space-attestation:{client_id}:{}", t.claims.jti);
    if !crate::xrpc::internal::claim_replay_anywhere(app, routing, &key, t.claims.exp.ceil() as i64).await? {
        return Err(invalid(format!("Client attestation for \"{client_id}\" has already been used")));
    }
    Ok(client_id)
}
