//! The RFC 9421 HTTP Message Signatures subset Spaces uses
//! (@atproto/space `http-signature.ts`). One signature, labelled
//! `atproto-space-credential`, by the P-256 did:key a space credential is
//! bound to (its `cnf.kid`), covering exactly
//! `("authorization" "atproto-space-audience")` with
//! `tag="atproto-space-credential"`.
//!
//! No method, target or time is covered, so a signature may be replayed
//! with the same headers: the credential's expiry bounds that, and the
//! audience header pins it to one repo. The optional `alg` must be
//! `ecdsa-p256-sha256` and an optional `keyid` must be `cnf.kid`.
//! Signatures are raw r‖s (64 bytes); high-S is accepted, DER is not.

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

/// What a request's signature covers, joined into lines.
pub fn signature_base(authorization: &str, signature_params: &str, audience: &str) -> Vec<u8> {
    format!(
        "\"authorization\": {}\n\"{AUDIENCE_HEADER}\": {}\n\"@signature-params\": {signature_params}",
        authorization.trim(),
        audience.trim()
    )
    .into_bytes()
}

/// The `Signature-Input` member the reference's client writes.
pub fn signature_input() -> String {
    format!("(\"authorization\" \"{AUDIENCE_HEADER}\");tag=\"{TAG}\"")
}

/// The four headers of a request with a space credential, signed by
/// `sign` (the credential's bound P-256 key, raw r‖s).
pub fn headers(credential: &str, audience: &str, sign: impl FnOnce(&[u8]) -> [u8; 64]) -> [(&'static str, String); 4] {
    let authorization = format!("Atproto-Space-Credential {credential}");
    let input = signature_input();
    let sig = sign(&signature_base(&authorization, &input, audience));
    [
        ("authorization", authorization),
        (AUDIENCE_HEADER, audience.to_string()),
        ("signature-input", format!("{LABEL}={input}")),
        ("signature", format!("{LABEL}=:{}:", base64::engine::general_purpose::STANDARD.encode(sig))),
    ]
}

/// Verifies a request's `atproto-space-credential` signature by
/// `credential_key`, the credential's `cnf.kid`.
pub fn verify(headers: &HeaderMap, credential_key: &str) -> Result<(), SigError> {
    let authorization = single(headers, "authorization")
        .filter(|a| !a.is_empty())
        .ok_or(SigError("missing or malformed \"authorization\" field"))?;
    let audience = single(headers, AUDIENCE_HEADER)
        .filter(|a| !a.is_empty())
        .ok_or(SigError("missing or malformed \"atproto-space-audience\" field"))?;
    let input_header = joined(headers, "signature-input").ok_or(SigError("missing or malformed signature headers"))?;
    let sig_header = joined(headers, "signature").ok_or(SigError("missing or malformed signature headers"))?;
    // the parser's duplicate-key handling is a linear scan per key
    if input_header.len() > MAX_FIELD || sig_header.len() > MAX_FIELD {
        return Err(INVALID);
    }
    let inputs = sfv::parse_dictionary(&input_header).map_err(|_| SigError("missing or malformed signature headers"))?;
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
    if sfv::get(params, "keyid").is_some_and(|k| *k != Bare::String(credential_key.to_string())) {
        return Err(SigError("signature keyid does not match the credential key"));
    }
    if super::did_key_alg(credential_key) != Some("ES256") {
        return Err(SigError("signature key must be a P-256 did:key"));
    }
    let base = signature_base(authorization, &sfv::serialize_inner_list(components, params), audience);
    let sig = B64.decode(sig_b64).map_err(|_| INVALID)?;
    if sig.len() != 64 {
        return Err(INVALID);
    }
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

    const AUTHORIZATION: &str = "Atproto-Space-Credential credential";
    const AUDIENCE: &str = "did:example:repo";
    const INPUT: &str = "(\"authorization\" \"atproto-space-audience\");tag=\"atproto-space-credential\"";

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
    fn signed(sk: &p256::ecdsa::SigningKey) -> Vec<(String, String)> {
        let sig = sign(sk, &signature_base(AUTHORIZATION, INPUT, AUDIENCE));
        vec![
            ("authorization".into(), AUTHORIZATION.into()),
            (AUDIENCE_HEADER.into(), AUDIENCE.into()),
            ("signature-input".into(), format!("{LABEL}={INPUT}")),
            ("signature".into(), format!("{LABEL}=:{sig}:")),
        ]
    }

    fn to_map(h: &[(String, String)]) -> HeaderMap {
        hm(&h.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect::<Vec<_>>())
    }

    fn set(h: &mut [(String, String)], name: &str, value: String) {
        h.iter_mut().find(|(k, _)| k == name).unwrap().1 = value;
    }

    fn get(h: &[(String, String)], name: &str) -> String {
        h.iter().find(|(k, _)| k == name).unwrap().1.clone()
    }

    /// testdata/spaces-alpha/vectors.json `httpsig`: headers the reference
    /// signed.
    #[test]
    fn generated_vectors() {
        let cases = VECTORS["httpsig"].as_array().unwrap();
        assert!(!cases.is_empty());
        for c in cases {
            let pairs: Vec<(String, String)> = c["headers"]
                .as_object()
                .unwrap()
                .iter()
                .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_string()))
                .collect();
            let key = c["keyDid"].as_str().unwrap();
            assert_eq!(verify(&to_map(&pairs), key), Ok(()), "{c}");
            let (_, other) = self::key();
            assert!(verify(&to_map(&pairs), &other).is_err());
        }
    }

    #[test]
    fn helper_headers_verify() {
        let (sk, did) = key();
        let h = headers("tok", AUDIENCE, |b| {
            let sig: p256::ecdsa::Signature = sk.sign(b);
            sig.to_bytes().into()
        });
        let pairs: Vec<(String, String)> = h.iter().map(|(k, v)| (k.to_string(), v.clone())).collect();
        assert_eq!(get(&pairs, "authorization"), "Atproto-Space-Credential tok");
        assert_eq!(verify(&to_map(&pairs), &did), Ok(()));
    }

    // The cases below are the reference's src/http-signature.test.ts.

    #[test]
    fn signs_and_verifies() {
        let (sk, did) = key();
        let h = signed(&sk);
        assert_eq!(signature_input(), INPUT);
        let base = format!(
            "\"authorization\": {AUTHORIZATION}\n\"atproto-space-audience\": {AUDIENCE}\n\"@signature-params\": {INPUT}"
        );
        assert_eq!(signature_base(AUTHORIZATION, INPUT, AUDIENCE), base.as_bytes());
        assert_eq!(verify(&to_map(&h), &did), Ok(()));
    }

    #[test]
    fn tag_required() {
        let (sk, did) = key();
        for tag in ["", ";tag=\"other\"", ";tag=atproto-space-credential"] {
            let mut h = signed(&sk);
            set(&mut h, "signature-input", format!("{LABEL}={}", INPUT.replace(";tag=\"atproto-space-credential\"", tag)));
            assert!(verify(&to_map(&h), &did).unwrap_err().0.contains("tag must be"), "{tag}");
        }
    }

    #[test]
    fn old_label_refused() {
        let (sk, did) = key();
        let mut h = signed(&sk);
        set(&mut h, "signature-input", format!("atproto-space={INPUT}"));
        let sig = get(&h, "signature").replacen(LABEL, "atproto-space", 1);
        set(&mut h, "signature", sig);
        assert_eq!(verify(&to_map(&h), &did), Err(MALFORMED));
    }

    #[test]
    fn high_s_accepted_der_refused() {
        let (sk, did) = key();
        let mut h = signed(&sk);
        let prefix = format!("{LABEL}=:");
        let b64 = get(&h, "signature").trim_start_matches(&prefix).trim_end_matches(':').to_string();
        let sig = base64::engine::general_purpose::STANDARD.decode(&b64).unwrap();
        let n = hex::decode("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551").unwrap();
        let mut high = sig[..32].to_vec();
        high.extend(crate::space::commit::tests::sub_be(&n, &sig[32..]));
        let enc = base64::engine::general_purpose::STANDARD.encode(&high);
        set(&mut h, "signature", format!("{LABEL}=:{enc}:"));
        assert_eq!(verify(&to_map(&h), &did), Ok(()));

        let der = p256::ecdsa::Signature::from_slice(&sig).unwrap().to_der();
        set(&mut h, "signature", format!("{LABEL}=:{}:", base64::engine::general_purpose::STANDARD.encode(der.as_bytes())));
        assert_eq!(verify(&to_map(&h), &did), Err(INVALID));

        // unpadded base64
        set(&mut h, "signature", format!("{LABEL}=:{}:", b64.trim_end_matches('=')));
        assert_eq!(verify(&to_map(&h), &did), Ok(()));
    }

    #[test]
    fn optional_parameters_and_other_labels() {
        let (sk, did) = key();
        let input = format!(
            "(\"authorization\" \"atproto-space-audience\");alg=\"ecdsa-p256-sha256\";keyid=\"{did}\";tag=\"atproto-space-credential\""
        );
        let base = format!("\"authorization\": {AUTHORIZATION}\n\"atproto-space-audience\": {AUDIENCE}\n\"@signature-params\": {input}");
        let sig = sign(&sk, base.as_bytes());
        let h = hm(&[
            ("authorization", AUTHORIZATION),
            (AUDIENCE_HEADER, AUDIENCE),
            ("signature-input", &format!("other=(\"authorization\");keyid=\"other\", {LABEL}={input}")),
            ("signature", &format!("other=:YWJj:, {LABEL}=:{sig}:")),
        ]);
        assert_eq!(verify(&h, &did), Ok(()));
        // the same members split over two field lines
        let h = hm(&[
            ("authorization", AUTHORIZATION),
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
            let mut h = signed(&sk);
            let v = get(&h, name);
            set(&mut h, name, format!("{v}-changed"));
            assert_eq!(verify(&to_map(&h), &did), Err(INVALID), "{name}");

            let mut m = to_map(&signed(&sk));
            m.append(axum::http::HeaderName::from_static(name), v.parse().unwrap());
            assert!(verify(&m, &did).unwrap_err().0.contains("malformed"), "{name}");
        }
        for name in ["authorization", AUDIENCE_HEADER, "signature-input", "signature"] {
            let mut m = to_map(&signed(&sk));
            m.remove(name);
            assert!(verify(&m, &did).is_err(), "{name}");
        }
        // whitespace around a covered value is not part of the base
        let mut m = to_map(&signed(&sk));
        m.insert("authorization", format!("{AUTHORIZATION} ").parse().unwrap());
        assert_eq!(verify(&m, &did), Ok(()));
        // an audience the signature doesn't cover
        let input = "(\"authorization\");tag=\"atproto-space-credential\"";
        let sig = sign(&sk, format!("\"authorization\": {AUTHORIZATION}\n\"@signature-params\": {input}").as_bytes());
        let h = hm(&[
            ("authorization", AUTHORIZATION),
            (AUDIENCE_HEADER, AUDIENCE),
            ("signature-input", &format!("{LABEL}={input}")),
            ("signature", &format!("{LABEL}=:{sig}:")),
        ]);
        assert!(verify(&h, &did).unwrap_err().0.contains("must cover"));
    }

    #[test]
    fn keys() {
        let (sk, did) = key();
        let (other_sk, other) = key();
        assert_eq!(verify(&to_map(&signed(&other_sk)), &did), Err(INVALID));

        let mut h = signed(&sk);
        let v = get(&h, "signature-input");
        set(&mut h, "signature-input", format!("{v};keyid=\"{other}\""));
        assert!(verify(&to_map(&h), &did).unwrap_err().0.contains("keyid does not match"));

        let k256 = vlatproto::crypto::Keypair::generate().did_key();
        assert!(verify(&to_map(&signed(&sk)), &k256).unwrap_err().0.contains("P-256"));
    }

    #[test]
    fn components_and_params() {
        let (sk, did) = key();
        for components in [
            "(\"atproto-space-audience\")",
            "(\"atproto-space-audience\" \"authorization\")",
            "(\"authorization\" \"atproto-space-audience\" \"content-type\")",
            "(\"authorization\" \"authorization\" \"atproto-space-audience\")",
            "(\"authorization\";sf \"atproto-space-audience\")",
            "(authorization atproto-space-audience)",
            "not-a-list",
        ] {
            let mut h = signed(&sk);
            set(&mut h, "signature-input", format!("{LABEL}={components}"));
            let e = verify(&to_map(&h), &did).unwrap_err().0;
            assert!(e.contains("must cover exactly") || e.contains("missing or malformed"), "{components}: {e}");
        }
        // parameters are signed
        let mut h = signed(&sk);
        let v = get(&h, "signature-input");
        set(&mut h, "signature-input", format!("{v};alg=\"ecdsa-p256-sha256\""));
        assert_eq!(verify(&to_map(&h), &did), Err(INVALID));
        for alg in [";alg=\"ecdsa-p384-sha384\"", ";alg=ecdsa-p256-sha256", ";alg"] {
            let mut h = signed(&sk);
            set(&mut h, "signature-input", format!("{v}{alg}"));
            let e = verify(&to_map(&h), &did).unwrap_err().0;
            assert!(e.contains("algorithm"), "{alg}: {e}");
        }
    }

    #[test]
    fn signature_values() {
        let (sk, did) = key();
        for signature in ["not-a-byte-sequence", ":YWJj:", ":!!!:", "(:YWJj:)"] {
            let mut h = signed(&sk);
            set(&mut h, "signature", format!("{LABEL}={signature}"));
            assert!(verify(&to_map(&h), &did).is_err(), "{signature}");
        }
        let mut h = signed(&sk);
        let v = get(&h, "signature");
        set(&mut h, "signature", format!("{v};x=1"));
        assert_eq!(verify(&to_map(&h), &did), Err(MALFORMED));
        // oversized fields are refused before parsing
        let mut h = signed(&sk);
        let input = get(&h, "signature-input");
        let pad: String = (0..2000).map(|i| format!("k{i}=1, ")).collect();
        set(&mut h, "signature-input", format!("{pad}{input}"));
        assert_eq!(verify(&to_map(&h), &did), Err(INVALID));
        // a later member with the same label replaces the first
        let mut h = signed(&sk);
        set(&mut h, "signature", format!("{v}, {LABEL}=:YWJj:"));
        assert_eq!(verify(&to_map(&h), &did), Err(INVALID));
    }
}
