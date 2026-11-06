//! The RFC 9421 HTTP Message Signatures subset Spaces uses
//! (@atproto/space `http-signature.ts`): a request authorized by a space
//! credential carries one signature, labelled `atproto-space-credential`,
//! by the P-256 did:key the credential is bound to (`cnf.kid`; an optional
//! `keyid` must match it), covering exactly
//! `("authorization" "atproto-space-audience")` with
//! `tag="atproto-space-credential"`.
//!
//! No method, target or time is covered, so a signature may be replayed
//! with the same headers: the credential's expiry bounds that, and the
//! audience header pins it to one repo. The optional `alg` must be
//! `ecdsa-p256-sha256`. Signatures are raw r‖s (64 bytes); high-S is
//! accepted, DER is not. Parameters other than these are signed as they
//! were serialized.

use super::sfv::{self, Bare, Member};
use axum::http::HeaderMap;
use base64::Engine;

pub const LABEL: &str = "atproto-space-credential";
pub const TAG: &str = "atproto-space-credential";
pub const ALG: &str = "ecdsa-p256-sha256";
pub const AUDIENCE_HEADER: &str = "atproto-space-audience";

/// The reference's `SpaceSignatureError`; its XRPC error is
/// `BadSpaceSignature`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigError(pub &'static str);

impl SigError {
    pub const CODE: &str = "BadSpaceSignature";
}

impl std::fmt::Display for SigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

/// Far over what this subset needs (a did:key is ~57 bytes).
const MAX_FIELD: usize = 8 << 10;

const INVALID: SigError = SigError("invalid HTTP message signature");
const MALFORMED: SigError = SigError("missing or malformed atproto-space-credential signature");
const COVERS: &str = "(\"authorization\" \"atproto-space-audience\")";

/// What a request's signature covers, joined into lines.
pub fn signature_base(authorization: &str, audience: &str, signature_params: &str) -> Vec<u8> {
    format!(
        "\"authorization\": {}\n\"{AUDIENCE_HEADER}\": {}\n\"@signature-params\": {signature_params}",
        authorization.trim(),
        audience.trim()
    )
    .into_bytes()
}

/// The `Signature-Input` member the reference's client writes.
pub fn signature_input() -> String {
    format!("{COVERS};tag=\"{TAG}\"")
}

/// The four headers a request with `credential` sends to `audience`,
/// signed by `sign` (the key `cnf.kid` names): the reference's
/// `createSpaceSigHeaders`, its signature as padded base64.
pub fn sign_headers(
    credential: &str,
    audience: &str,
    sign: impl FnOnce(&[u8]) -> [u8; 64],
) -> [(&'static str, String); 4] {
    let authorization = format!("Atproto-Space-Credential {credential}");
    let input = signature_input();
    let sig = sign(&signature_base(&authorization, audience, &input));
    [
        ("authorization", authorization),
        (AUDIENCE_HEADER, audience.to_string()),
        ("signature-input", format!("{LABEL}={input}")),
        ("signature", format!("{LABEL}=:{}:", base64::engine::general_purpose::STANDARD.encode(sig))),
    ]
}

/// Verifies a request's `atproto-space-credential` signature by
/// `credential_key` (the credential's `cnf.kid`). The Authorization value
/// is signed exactly as received.
pub fn verify(headers: &HeaderMap, credential_key: &str) -> Result<(), SigError> {
    let input_header = joined(headers, "signature-input").ok_or(SigError("missing or malformed signature headers"))?;
    let sig_header = joined(headers, "signature").ok_or(SigError("missing or malformed signature headers"))?;
    // the parser's duplicate-key handling is a linear scan per key
    if input_header.len() > MAX_FIELD || sig_header.len() > MAX_FIELD {
        return Err(INVALID);
    }
    let inputs =
        sfv::parse_dictionary(&input_header).map_err(|_| SigError("missing or malformed signature headers"))?;
    let sigs = sfv::parse_dictionary(&sig_header).map_err(|_| SigError("missing or malformed signature headers"))?;
    let (Some(Member::InnerList(components, params)), Some(Member::Item(Bare::Bytes(sig_b64), sig_params))) =
        (sfv::get(&inputs, LABEL), sfv::get(&sigs, LABEL))
    else {
        return Err(MALFORMED);
    };
    if !sig_params.is_empty() {
        return Err(MALFORMED);
    }
    let covered: Vec<String> = components.iter().map(|(b, p)| sfv::serialize_item(b, p)).collect();
    if covered != ["\"authorization\"", "\"atproto-space-audience\""] {
        return Err(SigError("signature must cover exactly (\"authorization\" \"atproto-space-audience\"), in order"));
    }
    if sfv::get(params, "tag") != Some(&Bare::String(TAG.into())) {
        return Err(SigError("signature tag must be \"atproto-space-credential\""));
    }
    if sfv::get(params, "alg").is_some_and(|a| *a != Bare::String(ALG.into())) {
        return Err(SigError("signature algorithm must be ecdsa-p256-sha256"));
    }
    if sfv::get(params, "keyid").is_some_and(|k| *k != Bare::String(credential_key.into())) {
        return Err(SigError("signature keyid does not match the credential key"));
    }
    if super::did_key_alg(credential_key) != Some("ES256") {
        return Err(SigError("signature key must be a P-256 did:key"));
    }
    let authorization = single(headers, "authorization")
        .filter(|a| !a.is_empty())
        .ok_or(SigError("missing or malformed \"authorization\" field"))?;
    let audience = single(headers, AUDIENCE_HEADER)
        .filter(|a| !a.is_empty())
        .ok_or(SigError("missing or malformed \"atproto-space-audience\" field"))?;
    let base = signature_base(authorization, audience, &sfv::serialize_inner_list(components, params));
    let sig = B64.decode(sig_b64).map_err(|_| INVALID)?;
    match super::verify_did_key(credential_key, &base, &sig, true) {
        Ok(true) => Ok(()),
        _ => Err(INVALID),
    }
}

/// Standard base64, `=` padding optional and unused bits ignored, as the
/// reference decodes a byte sequence (`Uint8Array.fromBase64`, "loose").
const B64: base64::engine::GeneralPurpose = base64::engine::GeneralPurpose::new(
    &base64::alphabet::STANDARD,
    base64::engine::GeneralPurposeConfig::new()
        .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent)
        .with_decode_allow_trailing_bits(true),
);

/// Exactly one field line, as text.
fn single<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut v = headers.get_all(name).iter();
    let first = v.next()?.to_str().ok()?;
    v.next().is_none().then_some(first)
}

/// Every field line, combined with ", " (RFC 9110 §5.3, as Node joins a
/// repeated header).
fn joined(headers: &HeaderMap, name: &str) -> Option<String> {
    let lines: Vec<&str> = headers.get_all(name).iter().map(|v| v.to_str().ok()).collect::<Option<_>>()?;
    (!lines.is_empty()).then(|| lines.join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::space::vectors::VECTORS;
    use p256::ecdsa::signature::Signer;

    const CREDENTIAL: &str = "credential";
    const AUDIENCE: &str = "did:example:repo";

    fn key() -> (p256::ecdsa::SigningKey, String) {
        let sk = <p256::ecdsa::SigningKey as p256::elliptic_curve::Generate>::generate();
        let mut mk = vec![0x80, 0x24];
        mk.extend_from_slice(sk.verifying_key().to_sec1_point(true).as_bytes());
        (sk, format!("did:key:z{}", bs58::encode(mk).into_string()))
    }

    fn hm(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(), v.parse().unwrap());
        }
        h
    }

    fn sign(sk: &p256::ecdsa::SigningKey, base: &[u8]) -> String {
        let sig: p256::ecdsa::Signature = sk.sign(base);
        base64::engine::general_purpose::STANDARD.encode(sig.to_bytes())
    }

    /// The reference client's headers (`createSpaceSigHeaders`).
    fn signed(sk: &p256::ecdsa::SigningKey, credential: &str, audience: &str) -> Vec<(String, String)> {
        sign_headers(credential, audience, |b| {
            let sig: p256::ecdsa::Signature = sk.sign(b);
            sig.to_bytes().into()
        })
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect()
    }

    fn to_map(h: &[(String, String)]) -> HeaderMap {
        hm(&h.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect::<Vec<_>>())
    }

    fn set(h: &mut [(String, String)], name: &str, value: String) {
        h.iter_mut().find(|(k, _)| k == name).unwrap().1 = value;
    }

    /// testdata/spaces-alpha/vectors.json `httpsig`: headers the reference
    /// signed (`createSpaceSigHeaders`), byte for byte what this writes.
    #[test]
    fn generated_vectors() {
        let cases = VECTORS["httpsig"].as_array().unwrap();
        assert_eq!(cases.len(), 2);
        for c in cases {
            let pairs: Vec<(String, String)> = c["headers"]
                .as_object()
                .unwrap()
                .iter()
                .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_string()))
                .collect();
            let key = c["keyDid"].as_str().unwrap();
            assert_eq!(verify(&to_map(&pairs), key), Ok(()), "{c}");
            let auth = c["headers"]["authorization"].as_str().unwrap();
            let base = signature_base(auth, c["headers"][AUDIENCE_HEADER].as_str().unwrap(), &signature_input());
            assert_eq!(String::from_utf8(base).unwrap(), c["base"].as_str().unwrap());
            assert_eq!(c["headers"]["signature-input"].as_str().unwrap(), format!("{LABEL}={}", signature_input()));
            // padded base64, as RFC 9651 writes a byte sequence
            assert!(c["headers"]["signature"].as_str().unwrap().ends_with("=:"));
            let (_, other) = key_pair_other();
            assert!(verify(&to_map(&pairs), &other).is_err());
        }
    }

    fn key_pair_other() -> (p256::ecdsa::SigningKey, String) {
        key()
    }

    // The cases below follow the reference's src/http-signature.test.ts.

    #[test]
    fn signs_and_verifies() {
        let (sk, did) = key();
        let h = signed(&sk, CREDENTIAL, AUDIENCE);
        assert_eq!(h[0].1, "Atproto-Space-Credential credential");
        assert_eq!(
            h[2].1,
            "atproto-space-credential=(\"authorization\" \"atproto-space-audience\");tag=\"atproto-space-credential\""
        );
        let base = format!(
            "\"authorization\": Atproto-Space-Credential {CREDENTIAL}\n\"atproto-space-audience\": {AUDIENCE}\n\"@signature-params\": (\"authorization\" \"atproto-space-audience\");tag=\"atproto-space-credential\""
        );
        assert_eq!(
            signature_base(&format!("Atproto-Space-Credential {CREDENTIAL}"), AUDIENCE, &signature_input()),
            base.as_bytes()
        );
        assert_eq!(verify(&to_map(&h), &did), Ok(()));
    }

    /// The scheme is matched case-insensitively by the receiver, but the
    /// base covers the value as sent.
    #[test]
    fn authorization_signed_as_sent() {
        let (sk, did) = key();
        let authorization = format!("atproto-space-credential {CREDENTIAL}");
        let input = signature_input();
        let sig = sign(&sk, &signature_base(&authorization, AUDIENCE, &input));
        let mut h = vec![
            ("authorization".to_string(), authorization),
            (AUDIENCE_HEADER.to_string(), AUDIENCE.to_string()),
            ("signature-input".to_string(), format!("{LABEL}={input}")),
            ("signature".to_string(), format!("{LABEL}=:{sig}:")),
        ];
        assert_eq!(verify(&to_map(&h), &did), Ok(()));
        set(&mut h, "authorization", format!("Atproto-Space-Credential {CREDENTIAL}"));
        assert_eq!(verify(&to_map(&h), &did), Err(INVALID));
    }

    #[test]
    fn tags() {
        let (sk, did) = key();
        for params in ["", ";tag=\"atproto-space\"", ";tag=atproto-space-credential", ";tag", ";tag=\"\""] {
            let input = format!("{COVERS}{params}");
            let base = signature_base(&format!("Atproto-Space-Credential {CREDENTIAL}"), AUDIENCE, &input);
            let mut h = signed(&sk, CREDENTIAL, AUDIENCE);
            set(&mut h, "signature-input", format!("{LABEL}={input}"));
            set(&mut h, "signature", format!("{LABEL}=:{}:", sign(&sk, &base)));
            assert!(verify(&to_map(&h), &did).unwrap_err().0.contains("tag"), "{params}");
        }
        // the old label isn't this one
        let mut h = signed(&sk, CREDENTIAL, AUDIENCE);
        let input = h[2].1.replace(LABEL, "atproto-space");
        let sig = h[3].1.replace(LABEL, "atproto-space");
        set(&mut h, "signature-input", input);
        set(&mut h, "signature", sig);
        assert_eq!(verify(&to_map(&h), &did), Err(MALFORMED));
    }

    #[test]
    fn high_s_accepted_der_refused() {
        let (sk, did) = key();
        let mut h = signed(&sk, CREDENTIAL, AUDIENCE);
        let prefix = format!("{LABEL}=:");
        let b64 = h[3].1.trim_start_matches(&prefix).trim_end_matches(':').to_string();
        let sig = base64::engine::general_purpose::STANDARD.decode(&b64).unwrap();
        let n = hex::decode("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551").unwrap();
        let mut high = sig[..32].to_vec();
        high.extend(crate::space::commit::tests::sub_be(&n, &sig[32..]));
        let enc = base64::engine::general_purpose::STANDARD.encode(&high);
        set(&mut h, "signature", format!("{prefix}{enc}:"));
        assert_eq!(verify(&to_map(&h), &did), Ok(()));

        let der = p256::ecdsa::Signature::from_slice(&sig).unwrap().to_der();
        set(
            &mut h,
            "signature",
            format!("{prefix}{}:", base64::engine::general_purpose::STANDARD.encode(der.as_bytes())),
        );
        assert_eq!(verify(&to_map(&h), &did), Err(INVALID));

        // unpadded base64 is tolerated
        set(&mut h, "signature", format!("{prefix}{}:", b64.trim_end_matches('=')));
        assert_eq!(verify(&to_map(&h), &did), Ok(()));
    }

    #[test]
    fn optional_parameters_and_other_labels() {
        let (sk, did) = key();
        let authorization = format!("Atproto-Space-Credential {CREDENTIAL}");
        let input = format!("{COVERS};alg=\"ecdsa-p256-sha256\";keyid=\"{did}\";tag=\"{TAG}\"");
        let sig = sign(&sk, &signature_base(&authorization, AUDIENCE, &input));
        let h = hm(&[
            ("authorization", &authorization),
            (AUDIENCE_HEADER, AUDIENCE),
            ("signature-input", &format!("other=(\"authorization\");keyid=\"other\", {LABEL}={input}")),
            ("signature", &format!("other=:YWJj:, {LABEL}=:{sig}:")),
        ]);
        assert_eq!(verify(&h, &did), Ok(()));
        // the same members split over two field lines
        let h = hm(&[
            ("authorization", &authorization),
            (AUDIENCE_HEADER, AUDIENCE),
            ("signature-input", "other=(\"authorization\");keyid=\"other\""),
            ("signature-input", &format!("{LABEL}={input}")),
            ("signature", "other=:YWJj:"),
            ("signature", &format!("{LABEL}=:{sig}:")),
        ]);
        assert_eq!(verify(&h, &did), Ok(()));
    }

    #[test]
    fn covered_fields_are_bound() {
        let (sk, did) = key();
        for name in ["authorization", AUDIENCE_HEADER] {
            let mut h = signed(&sk, CREDENTIAL, AUDIENCE);
            let v = h.iter().find(|(k, _)| k == name).unwrap().1.clone();
            set(&mut h, name, format!("{v}-changed"));
            assert_eq!(verify(&to_map(&h), &did), Err(INVALID), "{name}");

            // duplicate fields
            let mut m = to_map(&signed(&sk, CREDENTIAL, AUDIENCE));
            m.append(axum::http::HeaderName::from_static(name), v.parse().unwrap());
            assert!(verify(&m, &did).unwrap_err().0.contains("missing or malformed"), "{name}");
        }
        for name in ["authorization", AUDIENCE_HEADER, "signature-input", "signature"] {
            let mut m = to_map(&signed(&sk, CREDENTIAL, AUDIENCE));
            m.remove(name);
            assert!(verify(&m, &did).is_err(), "{name}");
        }
        // whitespace around a covered value is not part of the base
        let mut m = to_map(&signed(&sk, CREDENTIAL, AUDIENCE));
        m.insert("authorization", format!("Atproto-Space-Credential {CREDENTIAL} ").parse().unwrap());
        assert_eq!(verify(&m, &did), Ok(()));
    }

    #[test]
    fn keys() {
        let (sk, did) = key();
        let (other_sk, _) = key();
        let h = signed(&other_sk, CREDENTIAL, AUDIENCE);
        assert_eq!(verify(&to_map(&h), &did), Err(INVALID));

        let mut h = signed(&sk, CREDENTIAL, AUDIENCE);
        let (_, other) = key();
        let v = h[2].1.clone();
        set(&mut h, "signature-input", format!("{v};keyid=\"{other}\""));
        assert!(verify(&to_map(&h), &did).unwrap_err().0.contains("keyid does not match"));

        let k256 = vlatproto::crypto::Keypair::generate().did_key();
        assert!(verify(&to_map(&signed(&sk, CREDENTIAL, AUDIENCE)), &k256).unwrap_err().0.contains("P-256"));
    }

    #[test]
    fn components_and_params() {
        let (sk, did) = key();
        for components in [
            "(\"authorization\")",
            "(\"atproto-space-audience\" \"authorization\")",
            "(\"authorization\" \"atproto-space-audience\" \"content-type\")",
            "(\"authorization\";sf \"atproto-space-audience\")",
            "(authorization atproto-space-audience)",
            "not-a-list",
        ] {
            let mut h = signed(&sk, CREDENTIAL, AUDIENCE);
            set(&mut h, "signature-input", format!("{LABEL}={components};tag=\"{TAG}\""));
            let e = verify(&to_map(&h), &did).unwrap_err().0;
            assert!(e.contains("must cover exactly") || e.contains("missing or malformed"), "{components}: {e}");
        }
        // parameters are signed
        let mut h = signed(&sk, CREDENTIAL, AUDIENCE);
        let v = h[2].1.clone();
        set(&mut h, "signature-input", format!("{v};alg=\"ecdsa-p256-sha256\""));
        assert_eq!(verify(&to_map(&h), &did), Err(INVALID));
        for alg in [";alg=\"ecdsa-p384-sha384\"", ";alg=ecdsa-p256-sha256", ";alg"] {
            let mut h = signed(&sk, CREDENTIAL, AUDIENCE);
            h[2].1.push_str(alg);
            let e = verify(&to_map(&h), &did).unwrap_err().0;
            assert!(e.contains("algorithm"), "{alg}: {e}");
        }
    }

    #[test]
    fn signature_values() {
        let (sk, did) = key();
        for signature in ["not-a-byte-sequence", ":YWJj:", ":!!!:", "(:YWJj:)"] {
            let mut h = signed(&sk, CREDENTIAL, AUDIENCE);
            set(&mut h, "signature", format!("{LABEL}={signature}"));
            assert!(verify(&to_map(&h), &did).is_err(), "{signature}");
        }
        // a parameter on the signature
        let mut h = signed(&sk, CREDENTIAL, AUDIENCE);
        let v = h[3].1.clone();
        set(&mut h, "signature", format!("{v};x=1"));
        assert_eq!(verify(&to_map(&h), &did), Err(MALFORMED));
        // oversized fields are refused before parsing
        let mut h = signed(&sk, CREDENTIAL, AUDIENCE);
        let input = h[2].1.clone();
        let pad: String = (0..2000).map(|i| format!("k{i}=1, ")).collect();
        set(&mut h, "signature-input", format!("{pad}{input}"));
        assert_eq!(verify(&to_map(&h), &did), Err(INVALID));
        // a later member with the same label replaces the first
        let mut h = signed(&sk, CREDENTIAL, AUDIENCE);
        set(&mut h, "signature", format!("{v}, {LABEL}=:YWJj:"));
        assert_eq!(verify(&to_map(&h), &did), Err(INVALID));
    }
}
