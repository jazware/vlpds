//! Sign-In with Ethereum (EIP-4361), EOAs only.
//!
//! The server builds an exact message, persists it on the transaction, and
//! later requires the wallet's signature over that byte-for-byte message.
//! The signature is EIP-191 `personal_sign`: Keccak-256 of
//! `"\x19Ethereum Signed Message:\n" + <byte length> + <message>`, recovered
//! with secp256k1. The recovered address — not anything the client claims —
//! is the identity.
//!
//! Smart-contract wallets (EIP-1271) are out of scope: they need an RPC call
//! per verification. The provider boundary does not change if they are added.

use async_trait::async_trait;

use super::super::provider::{Begin, BeginOut, CallbackOut, SiweProof};
use super::super::types::*;
use super::super::*;
use crate::xrpc::owner_auth::SiweConfig;

/// How long a wallet has to sign.
const MESSAGE_TTL_SECS: i64 = 10 * 60;

pub struct SiweProvider {
    cfg: SiweConfig,
}

impl SiweProvider {
    pub fn new(cfg: SiweConfig) -> SiweProvider {
        SiweProvider { cfg }
    }

    fn domain(&self, app: &App) -> String {
        if let Some(d) = &self.cfg.domain {
            return d.clone();
        }
        let u = reqwest::Url::parse(&app.public_url).ok();
        match u {
            Some(u) => match (u.host_str(), u.port()) {
                (Some(h), Some(p)) => format!("{h}:{p}"),
                (Some(h), None) => h.to_string(),
                _ => "localhost".into(),
            },
            None => "localhost".into(),
        }
    }

    fn uri(&self, app: &App) -> String {
        self.cfg.uri.clone().unwrap_or_else(|| format!("{}/auth/siwe", app.public_url.trim_end_matches('/')))
    }
}

/// A nonce: 8+ alphanumeric characters, cryptographically random.
fn new_nonce() -> String {
    let bytes: [u8; 12] = rand::random();
    bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
}

/// RFC 3339 in the `Z` form EIP-4361 examples use.
fn rfc3339(secs: i64) -> String {
    use chrono::{TimeZone, Utc};
    Utc.timestamp_opt(secs, 0).single().unwrap_or_else(Utc::now).format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// The exact EIP-4361 message. Field order and separators are fixed.
// The arguments are the message's own fields, in the spec's order; grouping
// them would only restate the format.
#[allow(clippy::too_many_arguments)]
pub fn build_message(
    domain: &str,
    address: &str,
    statement: &str,
    uri: &str,
    chain_id: u64,
    nonce: &str,
    issued_at: &str,
    expiration: &str,
) -> String {
    format!(
        "{domain} wants you to sign in with your Ethereum account:\n{address}\n\n{statement}\n\n\
URI: {uri}\nVersion: 1\nChain ID: {chain_id}\nNonce: {nonce}\nIssued At: {issued_at}\nExpiration Time: {expiration}"
    )
}

/// Parsed EIP-4361 fields. Only what verification needs.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Parsed {
    pub domain: String,
    pub address: String,
    pub uri: String,
    pub version: String,
    pub chain_id: String,
    pub nonce: String,
    pub issued_at: String,
    pub expiration: Option<String>,
}

impl Parsed {
    pub fn parse(message: &str) -> Result<Parsed, String> {
        let mut lines = message.split('\n');
        let header = lines.next().ok_or("empty message")?;
        let domain = header
            .strip_suffix(" wants you to sign in with your Ethereum account:")
            .ok_or("not an EIP-4361 message")?
            .to_string();
        if domain.is_empty() {
            return Err("empty domain".into());
        }
        let address = lines.next().ok_or("no address line")?.trim().to_string();
        if !is_hex_address(&address) {
            return Err("address line is not an Ethereum address".into());
        }
        let mut p = Parsed { domain, address: address.to_lowercase(), ..Default::default() };
        for line in lines {
            if let Some(v) = line.strip_prefix("URI: ") {
                p.uri = v.to_string();
            } else if let Some(v) = line.strip_prefix("Version: ") {
                p.version = v.to_string();
            } else if let Some(v) = line.strip_prefix("Chain ID: ") {
                p.chain_id = v.to_string();
            } else if let Some(v) = line.strip_prefix("Nonce: ") {
                p.nonce = v.to_string();
            } else if let Some(v) = line.strip_prefix("Issued At: ") {
                p.issued_at = v.to_string();
            } else if let Some(v) = line.strip_prefix("Expiration Time: ") {
                p.expiration = Some(v.to_string());
            }
        }
        Ok(p)
    }

    /// Every field we generated must be echoed, and nothing may be expired
    /// or from the future.
    pub fn validate(&self, expect: &Parsed, chain_id: u64, now: i64) -> Result<(), String> {
        if self.domain != expect.domain
            || self.address != expect.address
            || self.uri != expect.uri
            || self.chain_id != expect.chain_id
            || self.nonce != expect.nonce
            || self.issued_at != expect.issued_at
            || self.version != "1"
        {
            return Err("signed message does not match the challenge".into());
        }
        if self.chain_id != chain_id.to_string() {
            return Err("signed chain id is not the configured one".into());
        }
        if self.nonce.len() < 8 {
            return Err("nonce too short".into());
        }
        let exp = self.expiration.as_deref().ok_or("message has no expiration")?;
        let exp = parse_rfc3339(exp).ok_or("unparseable expiration")?;
        if exp <= now {
            return Err("message expired".into());
        }
        Ok(())
    }
}

fn parse_rfc3339(s: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(s).ok().map(|d| d.timestamp())
}

fn is_hex_address(s: &str) -> bool {
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or("");
    s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// EIP-55 mixed-case checksum for display.
pub fn checksum_address(addr: &str) -> String {
    let lower = addr.trim_start_matches("0x").trim_start_matches("0X").to_ascii_lowercase();
    if lower.len() != 40 {
        return addr.to_string();
    }
    let hash = keccak256(lower.as_bytes());
    let mut out = String::with_capacity(42);
    out.push_str("0x");
    for (i, c) in lower.chars().enumerate() {
        let nibble = if i % 2 == 0 { hash[i / 2] >> 4 } else { hash[i / 2] & 0x0f };
        if c.is_ascii_digit() || nibble < 8 {
            out.push(c);
        } else {
            out.push(c.to_ascii_uppercase());
        }
    }
    out
}

pub fn keccak256(bytes: &[u8]) -> [u8; 32] {
    use tiny_keccak::{Hasher, Keccak};
    let mut k = Keccak::v256();
    k.update(bytes);
    let mut out = [0u8; 32];
    k.finalize(&mut out);
    out
}

/// The EIP-191 `personal_sign` digest.
pub fn personal_sign_digest(message: &str) -> [u8; 32] {
    let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
    let mut buf = Vec::with_capacity(prefix.len() + message.len());
    buf.extend_from_slice(prefix.as_bytes());
    buf.extend_from_slice(message.as_bytes());
    keccak256(&buf)
}

/// Recover the signer's lowercased `0x…` address from a 65-byte signature.
pub fn recover_address(message: &str, signature: &str) -> Result<String, String> {
    let raw = signature.trim();
    let raw = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")).unwrap_or(raw);
    let sig = hex::decode(raw).map_err(|_| "signature is not hex".to_string())?;
    if sig.len() != 65 {
        return Err("signature must be 65 bytes".into());
    }
    let mut rs = [0u8; 64];
    rs.copy_from_slice(&sig[..64]);
    let recid_v = match sig[64] {
        0 | 27 => 0i32,
        1 | 28 => 1i32,
        _ => return Err("signature recovery id is not 0/1 or 27/28".into()),
    };
    let msg = secp256k1::Message::from_digest(personal_sign_digest(message));
    let recid = secp256k1::ecdsa::RecoveryId::from_u8_masked(recid_v as u8);
    let rsig =
        secp256k1::ecdsa::RecoverableSignature::from_compact(&rs, recid).map_err(|_| "bad signature".to_string())?;
    let pk = rsig.recover_ecdsa(msg).map_err(|_| "signature does not recover a key".to_string())?;
    let uncompressed = pk.serialize_uncompressed();
    let hash = keccak256(&uncompressed[1..]);
    Ok(format!("0x{}", hex::encode(&hash[12..])))
}

#[async_trait]
impl AuthProvider for SiweProvider {
    fn id(&self) -> ProviderId {
        ProviderId::Siwe
    }

    async fn begin(&self, app: &App, b: &Begin<'_>) -> Result<BeginOut, XrpcError> {
        let now = now_secs();
        let domain = self.domain(app);
        // EIP-4361 embeds the address, so the browser must have connected its
        // wallet first and told us which account it is signing with.
        let address = b
            .address
            .map(str::trim)
            .filter(|a| is_hex_address(a))
            .ok_or_else(|| bad_request("connect a wallet and send its address to get a message to sign"))?
            .to_lowercase();
        let nonce = new_nonce();
        let message = build_message(
            &domain,
            &address,
            &format!("Sign in to {domain}."),
            &self.uri(app),
            self.cfg.chain_id,
            &nonce,
            &rfc3339(now),
            &rfc3339(now + MESSAGE_TTL_SECS),
        );
        let state = json!({"message": message, "address": address, "nonce": nonce});
        Ok(BeginOut::Siwe { message, state })
    }

    async fn callback(&self, _app: &App, _txn: &Txn, _q: &[(String, String)]) -> Result<CallbackOut, XrpcError> {
        Err(bad_request("Sign in with Ethereum has no callback"))
    }

    async fn verify(&self, app: &App, txn: &Txn, proof: &SiweProof) -> Result<VerifiedIdentity, XrpcError> {
        let state = txn.state.as_ref().ok_or_else(|| bad_request("transaction has no challenge"))?;
        let expected_msg = state.get("message").and_then(J::as_str).ok_or_else(|| bad_request("no message"))?;
        if proof.message != expected_msg {
            return Err(proof_rejected("the signed message is not this challenge"));
        }
        if proof.signature.is_empty() {
            return Err(proof_rejected("no signature"));
        }
        let parsed = Parsed::parse(&proof.message).map_err(|e| proof_rejected(&e))?;
        let expect = Parsed::parse(expected_msg).map_err(|_| XrpcError::internal("stored message is malformed"))?;
        parsed.validate(&expect, self.cfg.chain_id, now_secs()).map_err(|e| proof_rejected(e.as_str()))?;
        if let Some(claimed) = &proof.address {
            if !claimed.eq_ignore_ascii_case(&parsed.address) {
                return Err(proof_rejected("address mismatch"));
            }
        }
        let recovered = recover_address(&proof.message, &proof.signature).map_err(|e| proof_rejected(&e))?;
        if recovered != parsed.address {
            return Err(proof_rejected("signature is not from the claimed address"));
        }
        let _ = app;
        Ok(VerifiedIdentity {
            provider: ProviderId::Siwe,
            subject: recovered.clone(),
            email: None,
            label: Some(checksum_address(&recovered)),
            verified_at: now_secs(),
            sealed_token: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_round_trips() {
        let m = build_message(
            "example.com",
            "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
            "Sign in to example.com.",
            "https://example.com/auth/siwe",
            1,
            "32891756",
            "2021-09-30T16:25:24Z",
            "2021-09-30T16:35:24Z",
        );
        let p = Parsed::parse(&m).unwrap();
        assert_eq!(p.domain, "example.com");
        assert_eq!(p.address, "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266");
        assert_eq!(p.chain_id, "1");
        assert_eq!(p.nonce, "32891756");
        assert_eq!(p.uri, "https://example.com/auth/siwe");
        assert_eq!(p.version, "1");
        assert!(p.validate(&p, 1, 1_633_000_000).is_ok());
    }

    #[test]
    fn rejects_a_tampered_field() {
        let m = build_message(
            "example.com",
            "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
            "Sign in to example.com.",
            "https://example.com/auth/siwe",
            1,
            "32891756",
            "2021-09-30T16:25:24Z",
            "2021-09-30T16:35:24Z",
        );
        let expect = Parsed::parse(&m).unwrap();
        let other =
            "evil.com wants you to sign in with your Ethereum account:\n0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266\n\nx\n\nURI: https://evil.com/auth/siwe\nVersion: 1\nChain ID: 1\nNonce: 32891756\nIssued At: 2021-09-30T16:25:24Z\nExpiration Time: 2021-09-30T16:35:24Z";
        let got = Parsed::parse(other).unwrap();
        assert!(got.validate(&expect, 1, 1_633_000_000).is_err());
    }

    #[test]
    fn checksum_is_eip55() {
        assert_eq!(
            checksum_address("0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"),
            "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
        );
        assert_eq!(
            checksum_address("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"),
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
        );
    }

    #[test]
    fn rejects_malformed_signature() {
        assert!(recover_address("x", "0x00").is_err());
        assert!(recover_address("x", "not-hex").is_err());
    }
}
