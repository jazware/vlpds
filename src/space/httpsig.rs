//! The RFC 9421 HTTP Message Signatures subset Spaces uses
//! (@atproto/space `http-signature.ts`). One signature, labelled
//! `atproto-space`, by a P-256 did:key, covering exactly:
//!
//! - `("authorization")` with a `keyid` parameter naming the key: a
//!   delegation token exchange (getSpaceCredential), the key the issued
//!   credential gets bound to;
//! - `("authorization" "atproto-space-audience")`: a request with a space
//!   credential, whose `cnf.kid` is the key (an optional `keyid` must
//!   match it).
//!
//! No method, target or time is covered, so a signature may be replayed
//! with the same headers: the credential's expiry bounds that, and the
//! audience header pins it to one repo. The optional `alg` must be
//! `ecdsa-p256-sha256`. Signatures are raw r‖s (64 bytes); high-S is
//! accepted, DER is not.

use super::sfv::{self, Bare, Member};
use axum::http::HeaderMap;
use base64::Engine;

pub const LABEL: &str = "atproto-space";
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
const MALFORMED: SigError = SigError("missing or malformed atproto-space signature");

/// What a request's signature covers, joined into lines.
pub fn signature_base(authorization: &str, signature_params: &str, audience: Option<&str>) -> Vec<u8> {
    let mut lines = vec![format!("\"authorization\": {}", authorization.trim())];
    if let Some(a) = audience {
        lines.push(format!("\"{AUDIENCE_HEADER}\": {}", a.trim()));
    }
    lines.push(format!("\"@signature-params\": {signature_params}"));
    lines.join("\n").into_bytes()
}

/// The `Signature-Input` member the reference's client writes (`keyid`
/// only without an audience: with one, the credential names the key).
pub fn signature_input(audience: bool, key_did: &str) -> String {
    if audience {
        format!("(\"authorization\" \"{AUDIENCE_HEADER}\")")
    } else {
        format!("(\"authorization\");keyid=\"{key_did}\"")
    }
}

/// Verifies a request's `atproto-space` signature, returning the key's
/// did:key. `credential_key`: the credential's `cnf.kid`, for a request
/// with a credential (the audience header is then covered and required);
/// None for a delegation exchange, whose `keyid` names the key.
pub fn verify(headers: &HeaderMap, credential_key: Option<&str>) -> Result<String, SigError> {
    let input_header = joined(headers, "signature-input").ok_or(SigError("missing or malformed signature headers"))?;
    let sig_header = joined(headers, "signature").ok_or(SigError("missing or malformed signature headers"))?;
    // the parser's duplicate-key handling is a linear scan per key
    if input_header.len() > MAX_FIELD || sig_header.len() > MAX_FIELD {
        return Err(INVALID);
    }
    let inputs = sfv::parse_dictionary(&input_header).map_err(|_| INVALID)?;
    let sigs = sfv::parse_dictionary(&sig_header).map_err(|_| INVALID)?;
    let (Some(Member::InnerList(components, params)), Some(Member::Item(Bare::Bytes(sig_b64), sig_params))) =
        (sfv::get(&inputs, LABEL), sfv::get(&sigs, LABEL))
    else {
        return Err(MALFORMED);
    };
    if !sig_params.is_empty() {
        return Err(MALFORMED);
    }
    let covered: Vec<String> = components.iter().map(|(b, p)| sfv::serialize_item(b, p)).collect();
    let expected: &[&str] = match credential_key {
        None => &["\"authorization\""],
        Some(_) => &["\"authorization\"", "\"atproto-space-audience\""],
    };
    if covered != expected {
        return Err(match credential_key {
            None => SigError("signature must cover exactly \"authorization\", in order"),
            Some(_) => SigError("signature must cover exactly \"authorization\", \"atproto-space-audience\", in order"),
        });
    }
    if sfv::get(params, "alg").is_some_and(|a| *a != Bare::String(ALG.into())) {
        return Err(SigError("signature algorithm must be ecdsa-p256-sha256"));
    }
    let keyid = sfv::get(params, "keyid");
    let key = match (credential_key, keyid) {
        (Some(k), _) => k.to_string(),
        (None, Some(Bare::String(k))) => k.clone(),
        (None, _) => return Err(SigError("signature key must be a P-256 did:key")),
    };
    match super::did_key_alg(&key) {
        Some("ES256") => {}
        Some(_) => return Err(SigError("signature key must be a P-256 did:key")),
        None => return Err(INVALID),
    }
    if credential_key.is_some() && keyid.is_some_and(|k| *k != Bare::String(key.clone())) {
        return Err(SigError("signature keyid does not match the credential key"));
    }
    let authorization = single(headers, "authorization")
        .filter(|a| !a.is_empty())
        .ok_or(SigError("request requires exactly one \"authorization\" field"))?;
    let audience = match credential_key {
        None => None,
        Some(_) => Some(
            single(headers, AUDIENCE_HEADER)
                .filter(|a| !a.is_empty())
                .ok_or(SigError("request requires exactly one \"atproto-space-audience\" field"))?,
        ),
    };
    let base = signature_base(authorization, &sfv::serialize_inner_list(components, params), audience);
    let sig = B64.decode(sig_b64).map_err(|_| INVALID)?;
    match super::verify_did_key(&key, &base, &sig, true) {
        Ok(true) => Ok(key),
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

    const AUTHORIZATION: &str = "Atproto-Space credential";
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
    fn signed(
        sk: &p256::ecdsa::SigningKey,
        did: &str,
        authorization: &str,
        audience: Option<&str>,
    ) -> Vec<(String, String)> {
        let input = signature_input(audience.is_some(), did);
        let sig = sign(sk, &signature_base(authorization, &input, audience));
        let mut h = vec![("authorization".to_string(), authorization.to_string())];
        if let Some(a) = audience {
            h.push((AUDIENCE_HEADER.into(), a.into()));
        }
        h.push(("signature-input".into(), format!("{LABEL}={input}")));
        h.push(("signature".into(), format!("{LABEL}=:{sig}:")));
        h
    }

    fn to_map(h: &[(String, String)]) -> HeaderMap {
        hm(&h.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect::<Vec<_>>())
    }

    fn set(h: &mut [(String, String)], name: &str, value: String) {
        h.iter_mut().find(|(k, _)| k == name).unwrap().1 = value;
    }

    /// testdata/spaces-alpha/vectors.json `httpsig`: headers the reference
    /// signed, with and without an audience.
    #[test]
    fn generated_vectors() {
        let cases = VECTORS["httpsig"].as_array().unwrap();
        assert_eq!(cases.len(), 3);
        for c in cases {
            let pairs: Vec<(String, String)> = c["headers"]
                .as_object()
                .unwrap()
                .iter()
                .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_string()))
                .collect();
            let cred = c["credentialKey"].as_str();
            assert_eq!(verify(&to_map(&pairs), cred).as_deref(), Ok(c["keyDid"].as_str().unwrap()), "{c}");
            // and the same headers fail as the other kind of request
            let other = match cred {
                Some(_) => None,
                None => c["keyDid"].as_str(),
            };
            assert!(verify(&to_map(&pairs), other).is_err());
        }
    }

    // The cases below are the reference's src/http-signature.test.ts.

    #[test]
    fn signs_and_verifies() {
        let (sk, did) = key();
        let h = signed(&sk, &did, AUTHORIZATION, Some(AUDIENCE));
        assert_eq!(h[2].1, "atproto-space=(\"authorization\" \"atproto-space-audience\")");
        let base = format!(
            "\"authorization\": {AUTHORIZATION}\n\"atproto-space-audience\": {AUDIENCE}\n\"@signature-params\": (\"authorization\" \"atproto-space-audience\")"
        );
        assert_eq!(
            signature_base(AUTHORIZATION, "(\"authorization\" \"atproto-space-audience\")", Some(AUDIENCE)),
            base.as_bytes()
        );
        assert_eq!(verify(&to_map(&h), Some(&did)), Ok(did.clone()));

        let d = signed(&sk, &did, "Bearer delegation", None);
        assert_eq!(d[1].1, format!("atproto-space=(\"authorization\");keyid=\"{did}\""));
        assert_eq!(verify(&to_map(&d), None), Ok(did.clone()));
        assert!(verify(&to_map(&d), Some(&did)).unwrap_err().0.contains("cover exactly"));
        // credential signatures don't pass on the delegation exchange
        assert!(verify(&to_map(&h), None).unwrap_err().0.contains("must cover exactly"));
    }

    #[test]
    fn high_s_accepted_der_refused() {
        let (sk, did) = key();
        let mut h = signed(&sk, &did, AUTHORIZATION, Some(AUDIENCE));
        let b64 = h[3].1.trim_start_matches("atproto-space=:").trim_end_matches(':').to_string();
        let sig = base64::engine::general_purpose::STANDARD.decode(&b64).unwrap();
        let n = hex::decode("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551").unwrap();
        let mut high = sig[..32].to_vec();
        high.extend(crate::space::commit::tests::sub_be(&n, &sig[32..]));
        let enc = base64::engine::general_purpose::STANDARD.encode(&high);
        set(&mut h, "signature", format!("atproto-space=:{enc}:"));
        assert_eq!(verify(&to_map(&h), Some(&did)), Ok(did.clone()));

        let der = p256::ecdsa::Signature::from_slice(&sig).unwrap().to_der();
        set(
            &mut h,
            "signature",
            format!("atproto-space=:{}:", base64::engine::general_purpose::STANDARD.encode(der.as_bytes())),
        );
        assert_eq!(verify(&to_map(&h), Some(&did)), Err(INVALID));

        // unpadded base64, as the reference's client writes it
        set(&mut h, "signature", format!("atproto-space=:{}:", b64.trim_end_matches('=')));
        assert_eq!(verify(&to_map(&h), Some(&did)), Ok(did));
    }

    #[test]
    fn optional_parameters_and_other_labels() {
        let (sk, did) = key();
        let input = format!("(\"authorization\");keyid=\"{did}\";alg=\"ecdsa-p256-sha256\"");
        let sig = sign(&sk, format!("\"authorization\": Bearer delegation\n\"@signature-params\": {input}").as_bytes());
        let h = hm(&[
            ("authorization", "Bearer delegation"),
            ("signature-input", &format!("atproto-space={input}")),
            ("signature", &format!("atproto-space=:{sig}:")),
        ]);
        assert_eq!(verify(&h, None), Ok(did.clone()));

        let input = format!("(\"authorization\" \"atproto-space-audience\");alg=\"ecdsa-p256-sha256\";keyid=\"{did}\"");
        let base = format!("\"authorization\": {AUTHORIZATION}\n\"atproto-space-audience\": {AUDIENCE}\n\"@signature-params\": {input}");
        let sig = sign(&sk, base.as_bytes());
        let h = hm(&[
            ("authorization", AUTHORIZATION),
            (AUDIENCE_HEADER, AUDIENCE),
            ("signature-input", &format!("other=(\"authorization\");keyid=\"other\", atproto-space={input}")),
            ("signature", &format!("other=:YWJj:, atproto-space=:{sig}:")),
        ]);
        assert_eq!(verify(&h, Some(&did)), Ok(did.clone()));
        // the same members split over two field lines
        let h = hm(&[
            ("authorization", AUTHORIZATION),
            (AUDIENCE_HEADER, AUDIENCE),
            ("signature-input", "other=(\"authorization\");keyid=\"other\""),
            ("signature-input", &format!("atproto-space={input}")),
            ("signature", "other=:YWJj:"),
            ("signature", &format!("atproto-space=:{sig}:")),
        ]);
        assert_eq!(verify(&h, Some(&did)), Ok(did));
    }

    #[test]
    fn covered_fields_are_bound() {
        let (sk, did) = key();
        for name in ["authorization", AUDIENCE_HEADER] {
            let mut h = signed(&sk, &did, AUTHORIZATION, Some(AUDIENCE));
            let v = h.iter().find(|(k, _)| k == name).unwrap().1.clone();
            set(&mut h, name, format!("{v}-changed"));
            assert_eq!(verify(&to_map(&h), Some(&did)), Err(INVALID), "{name}");

            // duplicate fields
            let mut m = to_map(&signed(&sk, &did, AUTHORIZATION, Some(AUDIENCE)));
            m.append(axum::http::HeaderName::from_static(name), v.parse().unwrap());
            assert!(verify(&m, Some(&did)).unwrap_err().0.contains("exactly one"), "{name}");
        }
        for name in ["authorization", AUDIENCE_HEADER, "signature-input", "signature"] {
            let mut m = to_map(&signed(&sk, &did, AUTHORIZATION, Some(AUDIENCE)));
            m.remove(name);
            assert!(verify(&m, Some(&did)).is_err(), "{name}");
        }
        // whitespace around a covered value is not part of the base
        let mut h = signed(&sk, &did, AUTHORIZATION, Some(AUDIENCE));
        let mut m = to_map(&h);
        m.insert("authorization", format!("{AUTHORIZATION} ").parse().unwrap());
        assert_eq!(verify(&m, Some(&did)), Ok(did.clone()));
        // an audience the signature doesn't cover
        h = signed(&sk, &did, AUTHORIZATION, None);
        h.push((AUDIENCE_HEADER.into(), AUDIENCE.into()));
        assert!(verify(&to_map(&h), Some(&did)).unwrap_err().0.contains("must cover"));
    }

    #[test]
    fn keys() {
        let (sk, did) = key();
        let (other_sk, other) = key();
        let h = signed(&other_sk, &other, AUTHORIZATION, Some(AUDIENCE));
        assert_eq!(verify(&to_map(&h), Some(&did)), Err(INVALID));

        let mut h = signed(&sk, &did, AUTHORIZATION, Some(AUDIENCE));
        let v = h[2].1.clone();
        set(&mut h, "signature-input", format!("{v};keyid=\"{other}\""));
        assert!(verify(&to_map(&h), Some(&did)).unwrap_err().0.contains("keyid does not match"));

        for params in ["", ";keyid", ";keyid=123", ";keyid=\"not-a-key\"", ";keyid=tok"] {
            let mut h = signed(&sk, &did, "Bearer delegation", None);
            set(&mut h, "signature-input", format!("atproto-space=(\"authorization\"){params}"));
            assert!(verify(&to_map(&h), None).is_err(), "{params}");
        }

        let k256 = vlatproto::crypto::Keypair::generate().did_key();
        assert!(verify(&to_map(&signed(&sk, &did, AUTHORIZATION, Some(AUDIENCE))), Some(&k256))
            .unwrap_err()
            .0
            .contains("P-256"));
        let mut h = signed(&sk, &did, "Bearer delegation", None);
        set(&mut h, "signature-input", format!("atproto-space=(\"authorization\");keyid=\"{k256}\""));
        assert!(verify(&to_map(&h), None).unwrap_err().0.contains("P-256"));
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
            let mut h = signed(&sk, &did, AUTHORIZATION, Some(AUDIENCE));
            set(&mut h, "signature-input", format!("atproto-space={components}"));
            let e = verify(&to_map(&h), Some(&did)).unwrap_err().0;
            assert!(e.contains("must cover exactly") || e.contains("missing or malformed"), "{components}: {e}");
        }
        // parameters are signed
        let mut h = signed(&sk, &did, AUTHORIZATION, Some(AUDIENCE));
        let v = h[2].1.clone();
        set(&mut h, "signature-input", format!("{v};alg=\"ecdsa-p256-sha256\""));
        assert_eq!(verify(&to_map(&h), Some(&did)), Err(INVALID));
        // other algorithms, also as a token
        for alg in [";alg=\"ecdsa-p384-sha384\"", ";alg=ecdsa-p256-sha256", ";alg"] {
            for audience in [None, Some(AUDIENCE)] {
                let mut h = signed(&sk, &did, AUTHORIZATION, audience);
                let i = h.iter().position(|(k, _)| k == "signature-input").unwrap();
                h[i].1.push_str(alg);
                let e = verify(&to_map(&h), audience.map(|_| did.as_str())).unwrap_err().0;
                assert!(e.contains("algorithm"), "{alg}: {e}");
            }
        }
    }

    #[test]
    fn signature_values() {
        let (sk, did) = key();
        for signature in ["not-a-byte-sequence", ":YWJj:", ":!!!:", "(:YWJj:)"] {
            let mut h = signed(&sk, &did, AUTHORIZATION, Some(AUDIENCE));
            set(&mut h, "signature", format!("atproto-space={signature}"));
            assert!(verify(&to_map(&h), Some(&did)).is_err(), "{signature}");
        }
        // a parameter on the signature
        let mut h = signed(&sk, &did, AUTHORIZATION, Some(AUDIENCE));
        let v = h[3].1.clone();
        set(&mut h, "signature", format!("{v};x=1"));
        assert_eq!(verify(&to_map(&h), Some(&did)), Err(MALFORMED));
        // oversized fields are refused before parsing
        let mut h = signed(&sk, &did, AUTHORIZATION, Some(AUDIENCE));
        let input = h[2].1.clone();
        let pad: String = (0..2000).map(|i| format!("k{i}=1, ")).collect();
        set(&mut h, "signature-input", format!("{pad}{input}"));
        assert_eq!(verify(&to_map(&h), Some(&did)), Err(INVALID));
        // a later member with the same label replaces the first
        let mut h = signed(&sk, &did, AUTHORIZATION, Some(AUDIENCE));
        set(&mut h, "signature", format!("{v}, atproto-space=:YWJj:"));
        assert_eq!(verify(&to_map(&h), Some(&did)), Err(INVALID));
    }
}
