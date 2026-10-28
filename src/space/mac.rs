//! Commit and record MACs (@atproto/space `mac.ts`). A space repo's commit
//! carries no signature: the repo host MACs what it returns with a
//! per-request secret ([`super::kem`]) and sends the MAC in a header, so a
//! leaked response proves nothing to a third party.
//!
//! ```text
//! commit: HMAC-SHA256(secret, "atproto-space-repo-v1" || lp(space) || lp(repo) || lp(rev) || data)
//! record: HMAC-SHA256(secret, "atproto-space-record-v1" || lp(uri) || cid bytes)
//! lp(s) = u16be(len(s)) || s
//! ```
//!
//! A syncer asks with `Atproto-Space-Want-Mac: type="…", ver=1,
//! key_share="did:key:…"`; the response answers `Atproto-Space-Mac:
//! type="…", ver=1, mac=:…:` and `Vary: Atproto-Space-Want-Mac`.

use super::kem::MacError;
use super::sfv::{self, Bare, Member};
use base64::Engine;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

pub const WANT_MAC_HEADER: &str = "atproto-space-want-mac";
pub const MAC_HEADER: &str = "atproto-space-mac";
pub const COMMIT_MAC_TYPE: &str = "atproto-space-repo";
pub const RECORD_MAC_TYPE: &str = "atproto-space-record";
pub const RECORD_MAC_VERSION: i64 = 1;

/// The version a MAC type is on: a commit's is the commit format's.
fn version(ty: &str) -> i64 {
    match ty {
        COMMIT_MAC_TYPE => super::commit::COMMIT_VERSION,
        _ => RECORD_MAC_VERSION,
    }
}

fn lp(m: &mut Hmac<Sha256>, s: &str) -> Result<(), MacError> {
    let n = u16::try_from(s.len()).map_err(|_| MacError("MAC context field too long"))?;
    m.update(&n.to_be_bytes());
    m.update(s.as_bytes());
    Ok(())
}

fn keyed(secret: &[u8]) -> Hmac<Sha256> {
    <Hmac<Sha256> as KeyInit>::new_from_slice(secret).expect("HMAC takes any key length")
}

fn commit_hmac(secret: &[u8], c: &super::commit::Commit) -> Result<Hmac<Sha256>, MacError> {
    let mut m = keyed(secret);
    m.update(format!("{COMMIT_MAC_TYPE}-v{}", super::commit::COMMIT_VERSION).as_bytes());
    lp(&mut m, &c.space)?;
    lp(&mut m, &c.repo)?;
    lp(&mut m, &c.rev)?;
    m.update(&c.data);
    Ok(m)
}

pub fn commit_mac(secret: &[u8], c: &super::commit::Commit) -> Result<[u8; 32], MacError> {
    Ok(commit_hmac(secret, c)?.finalize().into_bytes().into())
}

/// In constant time.
pub fn verify_commit_mac(secret: &[u8], c: &super::commit::Commit, mac: &[u8]) -> bool {
    commit_hmac(secret, c).is_ok_and(|m| m.verify_slice(mac).is_ok())
}

fn record_hmac(secret: &[u8], uri: &str, cid: &[u8]) -> Result<Hmac<Sha256>, MacError> {
    let mut m = keyed(secret);
    m.update(format!("{RECORD_MAC_TYPE}-v{RECORD_MAC_VERSION}").as_bytes());
    lp(&mut m, uri)?;
    m.update(cid);
    Ok(m)
}

/// `cid`: the record CID's binary form.
pub fn record_mac(secret: &[u8], uri: &str, cid: &[u8]) -> Result<[u8; 32], MacError> {
    Ok(record_hmac(secret, uri, cid)?.finalize().into_bytes().into())
}

pub fn verify_record_mac(secret: &[u8], uri: &str, cid: &[u8], mac: &[u8]) -> bool {
    record_hmac(secret, uri, cid).is_ok_and(|m| m.verify_slice(mac).is_ok())
}

/// The request header.
pub fn format_want_mac(ty: &str, key_share: &str) -> String {
    format!("type=\"{ty}\", ver={}, key_share=\"{key_share}\"", version(ty))
}

/// The response header; the MAC as padded base64 (RFC 9651 §4.1.8).
pub fn format_mac(ty: &str, mac: &[u8]) -> String {
    format!("type=\"{ty}\", ver={}, mac=:{}:", version(ty), base64::engine::general_purpose::STANDARD.encode(mac))
}

/// Header fields this long are refused before parsing.
const MAX_FIELD: usize = 8 << 10;

/// Either header as bare values, its `type` and `ver` checked.
fn parse(value: Option<&str>, ty: &str) -> Result<Vec<(String, Bare)>, MacError> {
    let value = value.ok_or(MacError("missing or malformed MAC header"))?;
    if value.len() > MAX_FIELD {
        return Err(MacError("malformed MAC header"));
    }
    let dict = sfv::parse_dictionary(value).map_err(|_| MacError("malformed MAC header"))?;
    let mut fields = Vec::with_capacity(dict.len());
    for (k, m) in dict {
        match m {
            Member::Item(b, _) => fields.push((k, b)),
            Member::InnerList(..) => return Err(MacError("malformed MAC header field")),
        }
    }
    if sfv::get(&fields, "type") != Some(&Bare::String(ty.into())) {
        return Err(match ty {
            COMMIT_MAC_TYPE => MacError("unsupported MAC type, expected atproto-space-repo"),
            _ => MacError("unsupported MAC type, expected atproto-space-record"),
        });
    }
    if sfv::get(&fields, "ver") != Some(&Bare::Number(version(ty) as f64)) {
        return Err(MacError("unsupported MAC version"));
    }
    Ok(fields)
}

/// The request header's `key_share`.
pub fn parse_want_mac(value: Option<&str>, ty: &str) -> Result<String, MacError> {
    match sfv::get(&parse(value, ty)?, "key_share") {
        Some(Bare::String(s)) => Ok(s.clone()),
        _ => Err(MacError("missing or malformed key_share")),
    }
}

/// The response header's MAC.
pub fn parse_mac(value: Option<&str>, ty: &str) -> Result<Vec<u8>, MacError> {
    match sfv::get(&parse(value, ty)?, "mac") {
        Some(Bare::Bytes(b)) => B64.decode(b).map_err(|_| MacError("missing or malformed mac")),
        _ => Err(MacError("missing or malformed mac")),
    }
}

/// Standard base64, padding optional, as the reference decodes a byte
/// sequence.
const B64: base64::engine::GeneralPurpose = base64::engine::GeneralPurpose::new(
    &base64::alphabet::STANDARD,
    base64::engine::GeneralPurposeConfig::new()
        .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent)
        .with_decode_allow_trailing_bits(true),
);

/// Every field line of `name`, joined with ", " as Node joins a repeated
/// header.
pub fn header_value(headers: &axum::http::HeaderMap, name: &str) -> Option<String> {
    let lines: Vec<&str> = headers.get_all(name).iter().map(|v| v.to_str().ok()).collect::<Option<_>>()?;
    (!lines.is_empty()).then(|| lines.join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::space::commit::Commit;
    use crate::space::vectors::VECTORS;

    fn commit_of(c: &serde_json::Value) -> Commit {
        Commit {
            ver: 1,
            repo: c["repo"].as_str().unwrap().into(),
            space: c["space"].as_str().unwrap().into(),
            rev: c["rev"].as_str().unwrap().into(),
            data: hex::decode(c["data"].as_str().unwrap()).unwrap(),
        }
    }

    /// testdata/spaces-alpha/vectors.json `macs`: the reference's
    /// `computeCommitMac`/`computeRecordMac` and the headers it writes.
    #[test]
    fn generated_vectors() {
        let m = &VECTORS["macs"];
        for c in m["commits"].as_array().unwrap() {
            let secret = hex::decode(c["secret"].as_str().unwrap()).unwrap();
            let commit = commit_of(&c["commit"]);
            let mac = commit_mac(&secret, &commit).unwrap();
            assert_eq!(hex::encode(mac), c["mac"].as_str().unwrap());
            assert!(verify_commit_mac(&secret, &commit, &mac));
            assert_eq!(format_mac(COMMIT_MAC_TYPE, &mac), c["header"].as_str().unwrap());
            assert_eq!(parse_mac(c["header"].as_str(), COMMIT_MAC_TYPE).unwrap(), mac);
            for (field, other) in [("repo", "did:example:other"), ("space", "at://did:example:x/space/a.b.c/k")] {
                let mut wrong = commit.clone();
                match field {
                    "repo" => wrong.repo = other.into(),
                    _ => wrong.space = other.into(),
                }
                assert!(!verify_commit_mac(&secret, &wrong, &mac), "{field}");
            }
            assert!(!verify_commit_mac(&[9; 32], &commit, &mac));
        }
        for r in m["records"].as_array().unwrap() {
            let secret = hex::decode(r["secret"].as_str().unwrap()).unwrap();
            let uri = r["uri"].as_str().unwrap();
            let cid = vlatproto::cid::Cid::parse(r["cid"].as_str().unwrap()).unwrap().to_bytes();
            let mac = record_mac(&secret, uri, &cid).unwrap();
            assert_eq!(hex::encode(mac), r["mac"].as_str().unwrap());
            assert_eq!(format_mac(RECORD_MAC_TYPE, &mac), r["header"].as_str().unwrap());
            assert!(!verify_record_mac(&secret, &format!("{uri}x"), &cid, &mac));
        }
        for w in m["wantMac"].as_array().unwrap() {
            let ty = w["type"].as_str().unwrap();
            let share = w["keyShare"].as_str().unwrap();
            assert_eq!(format_want_mac(ty, share), w["header"].as_str().unwrap());
            assert_eq!(parse_want_mac(w["header"].as_str(), ty).as_deref(), Ok(share));
        }
    }

    #[test]
    fn headers() {
        let share = "did:key:zDnaeTiq1PdzvZXUaMdezchcMJQpBdH2VN4pgrrEhMCCbmwSb";
        let h = format_want_mac(COMMIT_MAC_TYPE, share);
        assert_eq!(h, format!("type=\"atproto-space-repo\", ver=1, key_share=\"{share}\""));
        assert_eq!(parse_want_mac(Some(&h), COMMIT_MAC_TYPE).as_deref(), Ok(share));
        // the other type, another version, missing pieces
        assert!(parse_want_mac(Some(&h), RECORD_MAC_TYPE).is_err());
        for bad in [
            format!("type=\"atproto-space-repo\", ver=2, key_share=\"{share}\""),
            format!("type=atproto-space-repo, ver=1, key_share=\"{share}\""),
            format!("type=\"atproto-space-repo\", ver=\"1\", key_share=\"{share}\""),
            "type=\"atproto-space-repo\", ver=1".to_string(),
            format!("type=\"atproto-space-repo\", ver=1, key_share={share}"),
            format!("type=\"atproto-space-repo\", ver=1, key_share=(\"{share}\")"),
            "not a dictionary,".to_string(),
            String::new(),
        ] {
            assert!(parse_want_mac(Some(&bad), COMMIT_MAC_TYPE).is_err(), "{bad}");
        }
        assert!(parse_want_mac(None, COMMIT_MAC_TYPE).is_err());
        // parameters and members in another order are fine
        let reordered = format!("key_share=\"{share}\";x=1, ver=1, type=\"atproto-space-repo\"");
        assert_eq!(parse_want_mac(Some(&reordered), COMMIT_MAC_TYPE).as_deref(), Ok(share));
        // a MAC as unpadded base64 too
        let mac = [7u8; 32];
        let f = format_mac(RECORD_MAC_TYPE, &mac);
        assert!(f.ends_with("=:"), "{f}");
        let unpadded = format!("{}:", f.trim_end_matches(':').trim_end_matches('='));
        assert_eq!(parse_mac(Some(&unpadded), RECORD_MAC_TYPE).unwrap(), mac);
        assert!(parse_mac(Some(&f), COMMIT_MAC_TYPE).is_err());
    }

    #[test]
    fn long_fields_refused() {
        let c = Commit { ver: 1, repo: "x".repeat(65_536), space: "s".into(), rev: "r".into(), data: vec![0; 32] };
        assert!(commit_mac(&[0; 32], &c).is_err());
        assert!(!verify_commit_mac(&[0; 32], &c, &[0; 32]));
    }
}
