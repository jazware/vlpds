//! Response MACs (@atproto/space `kem.ts`, `mac.ts`). A syncer and a repo
//! host share a fresh secret per request through HPKE's secret export
//! (RFC 9180 §6.2; DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, the Export-only
//! AEAD, `info` "atproto-mac") between the syncer's ephemeral key (its key
//! share) and the author's `#atproto_kem` key. The MAC is an RFC 9421
//! signature with `hmac-sha256` keyed by that secret, over a header that
//! names what the response carries:
//!
//! ```text
//! Accept-Signature: mac=("atproto-space-commit";sf);keyid="did:key:zDna…";tag="atproto-space-commit"
//!
//! Atproto-Space-Commit: ver=1, repo="did:…", space="at://…", rev="3m…", data=:…=:
//! Signature-Input: mac=("atproto-space-commit";sf);keyid="did:key:zDna…";tag="atproto-space-commit"
//! Signature: mac=:<base64>:
//! ```
//!
//! The host answers under the label and with the parameters the request
//! named; a verifier finds the MAC by its tag.

use super::commit::Commit;
use super::httpsig::{self, FindError, Required};
use super::sfv::{self, Bare, Member, Params};
use base64::Engine;
use hmac::{Hmac, KeyInit, Mac};
use p256::elliptic_curve::sec1::ToSec1Point;
use sha2::Sha256;

pub const ACCEPT_SIGNATURE: &str = "accept-signature";
pub const ALG: &str = "hmac-sha256";
/// The label this host's own requests ask for.
const LABEL: &str = "mac";
/// The parameters a host fulfills.
const REQUEST_PARAMS: [&str; 3] = ["keyid", "tag", "alg"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// getLatestCommit, getRepo, listRepoOps: the commit.
    Commit,
    /// getRecord: the record's URI and CID.
    Record,
}

impl Profile {
    /// The profile's tag, which is also the header its MAC covers.
    pub fn tag(self) -> &'static str {
        match self {
            Profile::Commit => "atproto-space-commit",
            Profile::Record => "atproto-space-record",
        }
    }

    fn components(self) -> Vec<(Bare, Params)> {
        vec![(Bare::String(self.tag().into()), vec![("sf".into(), Bare::Bool(true))])]
    }

    fn components_str(self) -> &'static str {
        match self {
            Profile::Commit => "(\"atproto-space-commit\";sf)",
            Profile::Record => "(\"atproto-space-record\";sf)",
        }
    }
}

/// The reference's `SpaceMacError` and `SpaceKemError`; the XRPC error is
/// `InvalidSpaceMac`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacError(pub &'static str);

impl MacError {
    pub const CODE: &str = "InvalidSpaceMac";
}

impl std::fmt::Display for MacError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

/// The uncompressed point (0x04 ‖ x ‖ y) of a P-256 did:key.
fn p256_point(did_key: &str) -> Result<p256::PublicKey, MacError> {
    if super::did_key_alg(did_key) != Some("ES256") {
        return match super::did_key_alg(did_key) {
            Some(_) => Err(MacError("KEM key must be a P-256 did:key")),
            None => Err(MacError("invalid KEM key")),
        };
    }
    let raw = bs58::decode(&did_key["did:key:z".len()..]).into_vec().map_err(|_| MacError("invalid KEM key"))?;
    p256::PublicKey::from_sec1_bytes(&raw[2..]).map_err(|_| MacError("invalid KEM key"))
}

fn uncompressed(k: &p256::PublicKey) -> Vec<u8> {
    k.to_sec1_point(false).as_bytes().to_vec()
}

pub fn did_key(k: &p256::PublicKey) -> String {
    let mut mk = vec![0x80, 0x24];
    mk.extend_from_slice(k.to_sec1_point(true).as_bytes());
    format!("did:key:z{}", bs58::encode(mk).into_string())
}

fn hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC takes any key length");
    for p in parts {
        m.update(p);
    }
    m.finalize().into_bytes().into()
}

const HPKE_VERSION: &[u8] = b"HPKE-v1";
const KEM_ID: &[u8] = b"KEM\x00\x10";
/// DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, Export-only.
const SUITE_ID: &[u8] = b"HPKE\x00\x10\x00\x01\xff\xff";
const INFO: &[u8] = b"atproto-mac";

/// HKDF-Extract (an empty salt is HMAC's all-zero key).
fn labeled_extract(id: &[u8], salt: &[u8], label: &[u8], ikm: &[u8]) -> [u8; 32] {
    hmac(salt, &[HPKE_VERSION, id, label, ikm])
}

/// HKDF-Expand to 32 bytes: one block.
fn labeled_expand(id: &[u8], prk: &[u8; 32], label: &[u8], info: &[u8]) -> [u8; 32] {
    hmac(prk, &[&32u16.to_be_bytes(), HPKE_VERSION, id, label, info, &[1]])
}

/// HPKE's SetupBase (either side) and an export with an empty exporter
/// context, from the ECDH result.
fn shared_secret(dh: &[u8], enc: &p256::PublicKey, author: &p256::PublicKey) -> [u8; 32] {
    let eae_prk = labeled_extract(KEM_ID, b"", b"eae_prk", dh);
    let kem_secret =
        labeled_expand(KEM_ID, &eae_prk, b"shared_secret", &[uncompressed(enc), uncompressed(author)].concat());
    let psk_id_hash = labeled_extract(SUITE_ID, b"", b"psk_id_hash", b"");
    let info_hash = labeled_extract(SUITE_ID, b"", b"info_hash", INFO);
    let context = [&[0u8][..], &psk_id_hash, &info_hash].concat();
    let secret = labeled_extract(SUITE_ID, &kem_secret, b"secret", b"");
    let exporter = labeled_expand(SUITE_ID, &secret, b"exp", &context);
    labeled_expand(SUITE_ID, &exporter, b"sec", b"")
}

/// Repo host side: the shared secret for the syncer's key share (HPKE's
/// `enc`), from the author's KEM key.
pub fn decapsulate(author: &p256::SecretKey, key_share: &str) -> Result<[u8; 32], MacError> {
    let enc = p256_point(key_share)?;
    let dh = p256::ecdh::diffie_hellman(author.to_nonzero_scalar(), enc.as_affine());
    Ok(shared_secret(dh.raw_secret_bytes(), &enc, &author.public_key()))
}

/// Syncer side: a fresh ephemeral key against the author's `#atproto_kem`
/// key. (key share, shared secret); use one per request.
pub fn encapsulate(author_kem_key: &str) -> Result<(String, [u8; 32]), MacError> {
    let author = p256_point(author_kem_key)?;
    let eph = <p256::SecretKey as p256::elliptic_curve::Generate>::generate();
    let dh = p256::ecdh::diffie_hellman(eph.to_nonzero_scalar(), author.as_affine());
    let enc = eph.public_key();
    Ok((did_key(&enc), shared_secret(dh.raw_secret_bytes(), &enc, &author)))
}

/// The did:key of a DID document's `#atproto_kem` verification method.
pub fn kem_key_of(doc: &serde_json::Value) -> Option<String> {
    let did = doc.get("id").and_then(|v| v.as_str()).unwrap_or("");
    let full = format!("{did}#atproto_kem");
    doc.get("verificationMethod")?.as_array()?.iter().find_map(|m| {
        let id = m.get("id")?.as_str()?;
        (id == "#atproto_kem" || id == full)
            .then(|| m.get("publicKeyMultibase")?.as_str().map(|k| format!("did:key:{k}")))?
    })
}

/// A syncer's `Accept-Signature`, asking for `profile`'s MAC keyed by the
/// shared secret of `key_share` (the reference's `formatMacRequest`).
pub fn format_request(profile: Profile, key_share: &str) -> String {
    let params =
        vec![("keyid".into(), Bare::String(key_share.into())), ("tag".into(), Bare::String(profile.tag().into()))];
    format!("{LABEL}={}", sfv::serialize_inner_list(&profile.components(), &params))
}

/// A MAC request as the host reads it: the label to answer under, the key
/// share, and the requested parameters serialized, which the MAC uses as
/// given.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacRequest {
    pub label: String,
    pub key_share: String,
    pub params: String,
}

/// The MAC requested for `profile` in `Accept-Signature` (every field line,
/// joined), checked as something this host can fulfill. Requests with
/// other tags are ignored: Ok(None) when none is for `profile`.
pub fn parse_request(value: Option<&str>, profile: Profile) -> Result<Option<MacRequest>, MacError> {
    let Some(value) = value else { return Ok(None) };
    if value.len() > httpsig::MAX_FIELD {
        return Err(MacError("malformed Accept-Signature header"));
    }
    let requests = sfv::parse_dictionary(value).map_err(|_| MacError("malformed Accept-Signature header"))?;
    let mut tagged = requests.iter().filter_map(|(label, m)| match m {
        Member::InnerList(items, params) if sfv::get(params, "tag") == Some(&Bare::String(profile.tag().into())) => {
            Some((label, items, params))
        }
        _ => None,
    });
    let Some((label, items, params)) = tagged.next() else { return Ok(None) };
    if tagged.next().is_some() {
        return Err(MacError(match profile {
            Profile::Commit => "more than one MAC requested with tag \"atproto-space-commit\"",
            Profile::Record => "more than one MAC requested with tag \"atproto-space-record\"",
        }));
    }
    if sfv::serialize_inner_list(items, &Vec::new()) != profile.components_str() {
        return Err(MacError(match profile {
            Profile::Commit => "MAC must cover exactly (\"atproto-space-commit\";sf)",
            Profile::Record => "MAC must cover exactly (\"atproto-space-record\";sf)",
        }));
    }
    if params.iter().any(|(k, _)| !REQUEST_PARAMS.contains(&k.as_str())) {
        return Err(MacError("unsupported MAC parameter"));
    }
    if sfv::get(params, "alg").is_some_and(|a| *a != Bare::String(ALG.into())) {
        return Err(MacError("MAC algorithm must be hmac-sha256"));
    }
    let key_share = match sfv::get(params, "keyid") {
        Some(Bare::String(k)) if vlatproto::syntax::valid_did(k) => k.clone(),
        _ => return Err(MacError("missing or malformed keyid")),
    };
    Ok(Some(MacRequest { label: label.clone(), key_share, params: sfv::serialize_inner_list(items, params) }))
}

fn padded(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}

fn dict_str(k: &str, v: &str) -> (String, Member) {
    (k.into(), Member::Item(Bare::String(v.into()), Vec::new()))
}

/// The `Atproto-Space-Commit` header of a commit.
pub fn commit_header(c: &Commit) -> String {
    sfv::serialize_dictionary(&vec![
        ("ver".into(), Member::Item(Bare::Number(c.ver as f64), Vec::new())),
        dict_str("repo", &c.repo),
        dict_str("space", &c.space),
        dict_str("rev", &c.rev),
        ("data".into(), Member::Item(Bare::Bytes(padded(&c.data)), Vec::new())),
    ])
}

/// The `Atproto-Space-Record` header of a record.
pub fn record_header(uri: &str, cid: &str) -> String {
    sfv::serialize_dictionary(&vec![dict_str("uri", uri), dict_str("cid", cid)])
}

/// The three response headers: the covered header and the MAC over it.
pub fn response_headers(
    profile: Profile,
    covered: String,
    req: &MacRequest,
    secret: &[u8; 32],
) -> [(&'static str, String); 3] {
    let base = httpsig::signature_base(&profile.components(), &[&covered], &req.params);
    let mac = hmac(secret, &[&base]);
    [
        (profile.tag(), covered),
        ("signature-input", format!("{}={}", req.label, req.params)),
        ("signature", format!("{}=:{}:", req.label, padded(&mac))),
    ]
}

/// A response's MAC for `profile`, checked as a syncer checks it against
/// the request's key share and secret: the fields of the header it covers.
/// `header` reads a response header (every field line, joined).
fn verify(
    profile: Profile,
    key_share: &str,
    secret: &[u8; 32],
    header: &dyn Fn(&str) -> Option<String>,
) -> Result<Vec<(String, Bare)>, MacError> {
    let req = Required { tag: profile.tag(), components: profile.components_str(), alg: ALG, key_id: key_share };
    let (components, params, mac) =
        httpsig::find_signature(header("signature-input").as_deref(), header("signature").as_deref(), &req).map_err(
            |e| {
                MacError(match e {
                    FindError::Headers => "missing or malformed signature headers",
                    FindError::Several => "more than one MAC with the profile's tag",
                    FindError::Missing => "missing or malformed MAC with the profile's tag",
                    FindError::Components => "MAC must cover exactly the profile's header",
                    FindError::Alg => "MAC algorithm must be hmac-sha256",
                    FindError::KeyId => "signature keyid does not match the expected key",
                })
            },
        )?;
    let covered = header(profile.tag()).ok_or(MacError("missing or malformed MAC header"))?;
    if covered.len() > httpsig::MAX_FIELD {
        return Err(MacError("malformed MAC header"));
    }
    let fields = sfv::parse_dictionary(&covered).map_err(|_| MacError("malformed MAC header"))?;
    // `sf`: the header as re-serialized from its parsed form
    let base = httpsig::signature_base(&components, &[&sfv::serialize_dictionary(&fields)], &params);
    let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(secret).expect("HMAC takes any key length");
    m.update(&base);
    m.verify_slice(&mac).map_err(|_| MacError("MAC does not match"))?;
    Ok(fields
        .into_iter()
        .filter_map(|(k, m)| match m {
            Member::Item(b, _) => Some((k, b)),
            Member::InnerList(..) => None,
        })
        .collect())
}

/// The reference's `verifyCommitMac`: the MAC verifies and the header it
/// covers describes `c`.
pub fn verify_commit(
    c: &Commit,
    key_share: &str,
    secret: &[u8; 32],
    header: &dyn Fn(&str) -> Option<String>,
) -> Result<(), MacError> {
    let fields = verify(Profile::Commit, key_share, secret, header)?;
    let s = |k: &str, v: &str| sfv::get(&fields, k) == Some(&Bare::String(v.into()));
    let data = match sfv::get(&fields, "data") {
        Some(Bare::Bytes(b)) => httpsig::B64.decode(b).ok(),
        _ => None,
    };
    let matches = sfv::get(&fields, "ver") == Some(&Bare::Number(c.ver as f64))
        && s("repo", &c.repo)
        && s("space", &c.space)
        && s("rev", &c.rev)
        && data.as_deref() == Some(&c.data[..]);
    matches.then_some(()).ok_or(MacError("commit does not match its MAC"))
}

/// The reference's `verifyRecordMac`.
pub fn verify_record(
    uri: &str,
    cid: &str,
    key_share: &str,
    secret: &[u8; 32],
    header: &dyn Fn(&str) -> Option<String>,
) -> Result<(), MacError> {
    let fields = verify(Profile::Record, key_share, secret, header)?;
    let s = |k: &str, v: &str| sfv::get(&fields, k) == Some(&Bare::String(v.into()));
    (s("uri", uri) && s("cid", cid)).then_some(()).ok_or(MacError("record does not match its MAC"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::space::vectors::VECTORS;
    use std::collections::HashMap;

    fn secret(hex_key: &str) -> p256::SecretKey {
        p256::SecretKey::from_slice(&hex::decode(hex_key).unwrap()).unwrap()
    }

    fn lookup(h: &HashMap<String, String>) -> impl Fn(&str) -> Option<String> + '_ {
        |k| h.get(k).cloned()
    }

    fn headers_of(v: &serde_json::Value) -> HashMap<String, String> {
        v.as_object().unwrap().iter().map(|(k, v)| (k.clone(), v.as_str().unwrap().to_string())).collect()
    }

    fn h32(v: &serde_json::Value) -> [u8; 32] {
        hex::decode(v.as_str().unwrap()).unwrap().try_into().unwrap()
    }

    /// testdata/spaces-alpha/vectors.json `kem`, `macRequests`, `commitMacs`
    /// and `recordMacs`, all made and checked by the reference.
    #[test]
    fn generated_vectors() {
        for k in VECTORS["kem"].as_array().unwrap() {
            let author = secret(k["authorPrivate"].as_str().unwrap());
            assert_eq!(did_key(&author.public_key()), k["authorKey"].as_str().unwrap());
            let syncer = secret(k["syncerPrivate"].as_str().unwrap());
            let share = k["keyShare"].as_str().unwrap();
            assert_eq!(did_key(&syncer.public_key()), share);
            let want = k["sharedSecret"].as_str().unwrap();
            assert_eq!(hex::encode(decapsulate(&author, share).unwrap()), want);
            // the syncer's side, from its private key
            let dh = p256::ecdh::diffie_hellman(syncer.to_nonzero_scalar(), author.public_key().as_affine());
            let theirs = shared_secret(dh.raw_secret_bytes(), &syncer.public_key(), &author.public_key());
            assert_eq!(hex::encode(theirs), want);
        }
        for r in VECTORS["macRequests"].as_array().unwrap() {
            let profile = if r["profile"] == "atproto-space-commit" { Profile::Commit } else { Profile::Record };
            let share = r["keyShare"].as_str().unwrap();
            let header = r["header"].as_str().unwrap();
            assert_eq!(format_request(profile, share), header);
            let req = parse_request(Some(header), profile).unwrap().unwrap();
            assert_eq!(req.key_share, share);
            assert_eq!(req.label, r["label"].as_str().unwrap());
            assert_eq!(req.params, r["signatureParams"].as_str().unwrap());
        }
        let cases = VECTORS["commitMacs"].as_array().unwrap();
        assert!(!cases.is_empty());
        for c in cases {
            let commit = Commit {
                ver: c["ver"].as_i64().unwrap(),
                repo: c["repo"].as_str().unwrap().into(),
                space: c["space"].as_str().unwrap().into(),
                rev: c["rev"].as_str().unwrap().into(),
                data: h32(&c["data"]),
            };
            let secret = h32(&c["sharedSecret"]);
            let want = headers_of(&c["headers"]);
            let req = parse_request(c["request"].as_str(), Profile::Commit).unwrap().unwrap();
            let got: HashMap<String, String> = response_headers(Profile::Commit, commit_header(&commit), &req, &secret)
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect();
            assert_eq!(got, want);
            verify_commit(&commit, &req.key_share, &secret, &lookup(&want)).unwrap();
            let other = Commit { rev: "3zzzzzzzzzzzz".into(), ..commit.clone() };
            assert!(verify_commit(&other, &req.key_share, &secret, &lookup(&want)).is_err());
            assert!(verify_commit(&commit, &req.key_share, &[0; 32], &lookup(&want)).is_err());
        }
        for c in VECTORS["recordMacs"].as_array().unwrap() {
            let (uri, cid) = (c["uri"].as_str().unwrap(), c["cid"].as_str().unwrap());
            let secret = h32(&c["sharedSecret"]);
            let want = headers_of(&c["headers"]);
            let req = parse_request(c["request"].as_str(), Profile::Record).unwrap().unwrap();
            let got: HashMap<String, String> =
                response_headers(Profile::Record, record_header(uri, cid), &req, &secret)
                    .into_iter()
                    .map(|(k, v)| (k.to_string(), v))
                    .collect();
            assert_eq!(got, want);
            verify_record(uri, cid, &req.key_share, &secret, &lookup(&want)).unwrap();
            assert!(verify_record(&format!("{uri}x"), cid, &req.key_share, &secret, &lookup(&want)).is_err());
        }
    }

    // The cases below follow the reference's tests/kem.test.ts and
    // tests/mac.test.ts.

    #[test]
    fn round_trips() {
        let author = <p256::SecretKey as p256::elliptic_curve::Generate>::generate();
        let (share, a) = encapsulate(&did_key(&author.public_key())).unwrap();
        assert_eq!(decapsulate(&author, &share).unwrap(), a);
        let (share2, b) = encapsulate(&did_key(&author.public_key())).unwrap();
        assert_ne!(share, share2);
        assert_ne!(a, b);
        let other = <p256::SecretKey as p256::elliptic_curve::Generate>::generate();
        assert_ne!(decapsulate(&other, &share).unwrap(), a);
    }

    #[test]
    fn keys_must_be_p256() {
        let k256 = vlatproto::crypto::Keypair::generate().did_key();
        assert_eq!(encapsulate(&k256), Err(MacError("KEM key must be a P-256 did:key")));
        assert_eq!(encapsulate("did:key:znope"), Err(MacError("invalid KEM key")));
        let author = <p256::SecretKey as p256::elliptic_curve::Generate>::generate();
        assert!(decapsulate(&author, &k256).is_err());
        assert!(decapsulate(&author, "not a key").is_err());
    }

    fn commit() -> Commit {
        Commit {
            ver: 1,
            repo: "did:example:alice".into(),
            space: "at:space/did:example:forum/com.atmoboards.forum/general".into(),
            rev: "3mwcj3b6uak2f".into(),
            data: [7; 32],
        }
    }

    fn respond(req: &str, c: &Commit, secret: &[u8; 32]) -> HashMap<String, String> {
        let r = parse_request(Some(req), Profile::Commit).unwrap().unwrap();
        response_headers(Profile::Commit, commit_header(c), &r, secret)
            .into_iter()
            .map(|(k, v)| (k.into(), v))
            .collect()
    }

    #[test]
    fn requests() {
        let req = format_request(Profile::Commit, "did:key:zDnaX");
        assert_eq!(req, "mac=(\"atproto-space-commit\";sf);keyid=\"did:key:zDnaX\";tag=\"atproto-space-commit\"");
        assert_eq!(parse_request(None, Profile::Commit), Ok(None));
        // another profile's request is ignored
        assert_eq!(parse_request(Some(&req), Profile::Record), Ok(None));
        // labels are the requester's, and alg may be named
        let r = parse_request(
            Some("other=(\"x\"), m2=(\"atproto-space-commit\";sf);keyid=\"did:key:zDnaX\";tag=\"atproto-space-commit\";alg=\"hmac-sha256\""),
            Profile::Commit,
        )
        .unwrap()
        .unwrap();
        assert_eq!(r.label, "m2");
        assert!(r.params.ends_with(";alg=\"hmac-sha256\""));
        for bad in [
            "mac=(\"atproto-space-commit\";sf);keyid=\"did:key:zDnaX\";tag=\"atproto-space-commit\", b=(\"atproto-space-commit\";sf);keyid=\"did:key:zDnaY\";tag=\"atproto-space-commit\"",
            "mac=(\"atproto-space-commit\");keyid=\"did:key:zDnaX\";tag=\"atproto-space-commit\"",
            "mac=(\"atproto-space-commit\";sf \"date\");keyid=\"did:key:zDnaX\";tag=\"atproto-space-commit\"",
            "mac=(\"atproto-space-commit\";sf);keyid=\"did:key:zDnaX\";tag=\"atproto-space-commit\";created=1",
            "mac=(\"atproto-space-commit\";sf);keyid=\"did:key:zDnaX\";tag=\"atproto-space-commit\";alg=\"ecdsa-p256-sha256\"",
            "mac=(\"atproto-space-commit\";sf);tag=\"atproto-space-commit\"",
            "mac=(\"atproto-space-commit\";sf);keyid=\"not a did\";tag=\"atproto-space-commit\"",
            "mac=(\"atproto-space-commit\";sf);keyid=did;tag=\"atproto-space-commit\"",
            "???",
        ] {
            assert!(parse_request(Some(bad), Profile::Commit).is_err(), "{bad}");
        }
    }

    #[test]
    fn headers_and_verification() {
        let author = <p256::SecretKey as p256::elliptic_curve::Generate>::generate();
        let (share, secret) = encapsulate(&did_key(&author.public_key())).unwrap();
        let c = commit();
        let h = respond(&format_request(Profile::Commit, &share), &c, &secret);
        assert_eq!(
            h["atproto-space-commit"],
            format!(
                "ver=1, repo=\"did:example:alice\", space=\"{}\", rev=\"3mwcj3b6uak2f\", data=:{}:",
                c.space,
                padded(&c.data)
            )
        );
        assert_eq!(h["signature-input"], format_request(Profile::Commit, &share));
        verify_commit(&c, &share, &secret, &lookup(&h)).unwrap();
        // the commit is bound
        for other in [
            Commit { repo: "did:example:bob".into(), ..c.clone() },
            Commit { space: format!("{}x", c.space), ..c.clone() },
            Commit { data: [8; 32], ..c.clone() },
            Commit { ver: 2, ..c.clone() },
        ] {
            assert!(verify_commit(&other, &share, &secret, &lookup(&h)).is_err());
        }
        // a header changed after the MAC was made
        let mut t = h.clone();
        t.insert("atproto-space-commit".into(), h["atproto-space-commit"].replace("alice", "bob"));
        assert_eq!(verify_commit(&c, &share, &secret, &lookup(&t)), Err(MacError("MAC does not match")));
        // re-serialized: extra whitespace in the header doesn't change the base
        let mut t = h.clone();
        t.insert("atproto-space-commit".into(), h["atproto-space-commit"].replace(", ", ",   "));
        verify_commit(&c, &share, &secret, &lookup(&t)).unwrap();
        // another key share named in the MAC
        assert!(verify_commit(&c, "did:key:zDnaOther", &secret, &lookup(&h)).is_err());
        // relabelled by an intermediary: found by its tag
        let mut t = h.clone();
        t.insert("signature-input".into(), h["signature-input"].replacen("mac=", "x=", 1));
        t.insert("signature".into(), h["signature"].replacen("mac=", "x=", 1));
        verify_commit(&c, &share, &secret, &lookup(&t)).unwrap();
        // missing pieces
        for k in ["atproto-space-commit", "signature-input", "signature"] {
            let mut t = h.clone();
            t.remove(k);
            assert!(verify_commit(&c, &share, &secret, &lookup(&t)).is_err(), "{k}");
        }
    }

    #[test]
    fn record_macs() {
        let author = <p256::SecretKey as p256::elliptic_curve::Generate>::generate();
        let (share, secret) = encapsulate(&did_key(&author.public_key())).unwrap();
        let uri = "at:space/did:example:forum/com.atmoboards.forum/general/did:example:alice/com.atmoboards.thread/3m";
        let cid = "bafyreie5737gdxlw5i64vzichcalba3z2v5n6icifvx5xytvske7mr3hpm";
        let r = parse_request(Some(&format_request(Profile::Record, &share)), Profile::Record).unwrap().unwrap();
        let h: HashMap<String, String> = response_headers(Profile::Record, record_header(uri, cid), &r, &secret)
            .into_iter()
            .map(|(k, v)| (k.into(), v))
            .collect();
        assert_eq!(h["atproto-space-record"], format!("uri=\"{uri}\", cid=\"{cid}\""));
        verify_record(uri, cid, &share, &secret, &lookup(&h)).unwrap();
        assert!(verify_record(uri, "bafyother", &share, &secret, &lookup(&h)).is_err());
        // a record MAC is not a commit MAC
        assert!(verify_commit(&commit(), &share, &secret, &lookup(&h)).is_err());
    }
}
