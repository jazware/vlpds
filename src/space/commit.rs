//! Space repo commits (@atproto/space `repo-commit.ts`). The signature
//! covers a context naming the space, author, rev and a fresh per-reader
//! `ikm`, never the digest; the digest is bound to that context by a MAC
//! keyed from the `ikm`. A reader gets integrity, while a leaked commit
//! proves nothing about what the author wrote to a third party.
//!
//! ```text
//! ctx = "atproto-space-v1" || u16be(len) || space || u16be(len) || author
//!       || u16be(len) || rev || u16be(len) || ikm
//! mac = HMAC-SHA256(HKDF-Expand-SHA256(prk = ikm, info = ctx, L = 32), hash)
//! sig = sign(ctx)
//! ```

use super::lthash::LtHash;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

pub const COMMIT_VERSION: i64 = 1;
const DOMAIN: &[u8] = b"atproto-space-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommitCtx<'a> {
    /// The space URI (`at://{authority}/space/{type}/{skey}`).
    pub space: &'a str,
    pub author: &'a str,
    pub rev: &'a str,
}

/// The fields are bytes as in the reference's `SignedCommit`, whose
/// lengths only the version fixes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedCommit {
    pub ver: i64,
    pub hash: Vec<u8>,
    pub ikm: Vec<u8>,
    pub sig: Vec<u8>,
    pub mac: Vec<u8>,
    pub rev: String,
}

/// The set hash element of a record. Injective without length prefixes:
/// the collection (an NSID) and the CID (base32) contain no `/`, so the
/// first and last slashes delimit the rkey whatever it holds.
pub fn element(collection: &str, rkey: &str, cid: &str) -> String {
    debug_assert!(!collection.contains('/') && !cid.contains('/'));
    format!("{collection}/{rkey}/{cid}")
}

/// None when a field is longer than its u16 length prefix allows.
pub fn encode_ctx(ctx: &CommitCtx, ikm: &[u8]) -> Option<Vec<u8>> {
    let fields = [ctx.space.as_bytes(), ctx.author.as_bytes(), ctx.rev.as_bytes(), ikm];
    let mut out = Vec::with_capacity(DOMAIN.len() + fields.iter().map(|f| 2 + f.len()).sum::<usize>());
    out.extend_from_slice(DOMAIN);
    for f in fields {
        out.extend_from_slice(&u16::try_from(f.len()).ok()?.to_be_bytes());
        out.extend_from_slice(f);
    }
    Some(out)
}

fn mac_of(ikm: &[u8], ctx_bytes: &[u8], hash: &[u8]) -> Hmac<Sha256> {
    // HKDF-Expand to 32 bytes is its first block: T(1) = HMAC(prk, info || 0x01)
    let mut t = <Hmac<Sha256> as KeyInit>::new_from_slice(ikm).expect("HMAC takes any key length");
    t.update(ctx_bytes);
    t.update(&[1]);
    let key = t.finalize().into_bytes();
    let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(&key).expect("HMAC takes any key length");
    m.update(hash);
    m
}

pub fn mac(ikm: &[u8], ctx_bytes: &[u8], hash: &[u8]) -> [u8; 32] {
    mac_of(ikm, ctx_bytes, hash).finalize().into_bytes().into()
}

/// Signs `set`'s current digest for one reader. `ikm` must be fresh
/// random bytes per call (32 in the reference): reusing one across readers
/// gives them the same MAC key. `sign` is the author's signing key over
/// the ctx (low-S compact, as for repo commits).
pub fn sign<E>(
    set: &LtHash,
    ctx: &CommitCtx,
    ikm: [u8; 32],
    sign: impl FnOnce(&[u8]) -> Result<[u8; 64], E>,
) -> Result<SignedCommit, SignError<E>> {
    let hash = set.digest();
    let ctx_bytes = encode_ctx(ctx, &ikm).ok_or(SignError::FieldTooLong)?;
    let sig = sign(&ctx_bytes).map_err(SignError::Sign)?;
    Ok(SignedCommit {
        ver: COMMIT_VERSION,
        hash: hash.to_vec(),
        mac: mac(&ikm, &ctx_bytes, &hash).to_vec(),
        ikm: ikm.to_vec(),
        sig: sig.to_vec(),
        rev: ctx.rev.to_string(),
    })
}

#[derive(Debug)]
pub enum SignError<E> {
    FieldTooLong,
    Sign(E),
}

/// The signature by `did_key` over `ctx` and the MAC over the hash. The
/// MAC key travels in the commit, so whoever holds a commit can rebind it
/// to another hash: `commit.hash` is the author's claim only when the
/// commit came from the author's host over an authenticated channel, never
/// when relayed or stored. That is the deniability the design wants. Low-S compact signatures only, as the reference's default
/// verification. Every failure, a malformed key included, is false.
pub fn verify(commit: &SignedCommit, ctx: &CommitCtx, did_key: &str) -> bool {
    if commit.ver != COMMIT_VERSION || commit.rev != ctx.rev {
        return false;
    }
    let Some(ctx_bytes) = encode_ctx(ctx, &commit.ikm) else {
        return false;
    };
    if mac_of(&commit.ikm, &ctx_bytes, &commit.hash).verify_slice(&commit.mac).is_err() {
        return false;
    }
    super::verify_did_key(did_key, &ctx_bytes, &commit.sig, false) == Ok(true)
}

/// Whether `set` is the repo `commit` describes. Verify the commit first:
/// on its own this says nothing about authenticity.
pub fn matches(set: &LtHash, commit: &SignedCommit) -> bool {
    set.digest()[..] == commit.hash[..]
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::space::vectors::VECTORS;
    use sha2::Digest;

    fn h(v: &serde_json::Value) -> Vec<u8> {
        hex::decode(v.as_str().unwrap()).unwrap()
    }

    fn ctx_of(c: &serde_json::Value) -> CommitCtx<'_> {
        CommitCtx {
            space: c["ctx"]["space"].as_str().unwrap(),
            author: c["ctx"]["author"].as_str().unwrap(),
            rev: c["ctx"]["rev"].as_str().unwrap(),
        }
    }

    fn set_of(c: &serde_json::Value) -> LtHash {
        let mut set = LtHash::default();
        for r in c["records"].as_array().unwrap() {
            let el =
                element(r["collection"].as_str().unwrap(), r["rkey"].as_str().unwrap(), r["cid"].as_str().unwrap());
            assert_eq!(el, r["element"].as_str().unwrap());
            set.add(&el);
        }
        set
    }

    /// testdata/spaces-alpha/vectors.json `commits`: ctx encoding, digest,
    /// MAC and the reference's signature (secp256k1 and P-256 authors).
    #[test]
    fn generated_vectors() {
        let cases = VECTORS["commits"].as_array().unwrap();
        assert_eq!(cases.len(), 3);
        for c in cases {
            let ctx = ctx_of(c);
            let ikm = h(&c["ikm"]);
            let ctx_bytes = encode_ctx(&ctx, &ikm).unwrap();
            assert_eq!(ctx_bytes, h(&c["ctxBytes"]));
            let set = set_of(c);
            assert_eq!(set.digest().to_vec(), h(&c["hash"]));
            assert_eq!(mac(&ikm, &ctx_bytes, &set.digest()).to_vec(), h(&c["mac"]));
            let commit = SignedCommit {
                ver: 1,
                hash: h(&c["hash"]),
                ikm,
                sig: h(&c["sig"]),
                mac: h(&c["mac"]),
                rev: ctx.rev.into(),
            };
            let did_key = c["didKey"].as_str().unwrap();
            assert!(verify(&commit, &ctx, did_key));
            assert!(matches(&set, &commit));
            // high-S is refused on either curve
            let n = match crate::space::did_key_alg(did_key) {
                Some("ES256") => "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
                _ => "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
            };
            let mut high = commit.sig[..32].to_vec();
            high.extend(sub_be(&hex::decode(n).unwrap(), &commit.sig[32..]));
            assert!(!verify(&SignedCommit { sig: high, ..commit.clone() }, &ctx, did_key));
        }
    }

    /// RFC 6979 signing on both sides: vlpds's own commit over a vector's
    /// inputs is byte-identical to the reference's.
    #[test]
    fn signs_like_the_reference() {
        let c = &VECTORS["commits"][0];
        let key = vlsync_atproto::crypto::Keypair::from_bytes(&sha2::Sha256::digest(b"vlpds spaces alpha author k256"))
            .unwrap();
        assert_eq!(key.did_key(), c["didKey"].as_str().unwrap());
        let ikm: [u8; 32] = h(&c["ikm"]).try_into().unwrap();
        let commit = sign(&set_of(c), &ctx_of(c), ikm, |m| Ok::<_, ()>(key.sign_deterministic(m))).unwrap();
        assert_eq!(commit.sig, h(&c["sig"]));
        assert_eq!(commit.mac, h(&c["mac"]));
        assert_eq!(commit.hash, h(&c["hash"]));
    }

    /// The reference's signing cases (tests/repo-commit.test.ts).
    #[test]
    fn verification() {
        let key = vlsync_atproto::crypto::Keypair::generate();
        let other = vlsync_atproto::crypto::Keypair::generate();
        let ctx = CommitCtx {
            space: "at://did:example:space/space/app.bsky.group/test",
            author: "did:example:alice",
            rev: "3kbcq3p7ad400",
        };
        let mut set = LtHash::default();
        set.add(&element("app.bsky.feed.post", "1", "bafyreidefdycgbfy3oglcb6ism3eqhyp5llsrpzxjsuac2gsy4mtrtx244"));
        let signed = |ikm: [u8; 32]| {
            sign(&set, &ctx, ikm, |m| key.sign_verified(vlsync_atproto::crypto::Purpose::Commit, m)).unwrap()
        };
        let commit = signed(rand::random());
        assert_eq!((commit.ver, commit.hash.len(), commit.ikm.len(), commit.mac.len()), (1, 32, 32, 32));
        assert!(verify(&commit, &ctx, &key.did_key()));
        assert!(matches(&set, &commit));
        let again = signed(rand::random());
        assert!(again.ikm != commit.ikm && again.mac != commit.mac && again.sig != commit.sig);
        assert_eq!(again.hash, commit.hash);

        assert!(!verify(&commit, &ctx, &other.did_key()));
        for other_ctx in [
            CommitCtx { space: "at://did:example:space/space/app.bsky.group/other", ..ctx },
            CommitCtx { author: "did:example:bob", ..ctx },
            CommitCtx { rev: "3kbcq3p7ad999", ..ctx },
        ] {
            assert!(!verify(&commit, &other_ctx, &key.did_key()));
        }
        // the signature never covered the hash: the MAC catches this
        let tampered = SignedCommit { hash: LtHash::default().digest().to_vec(), ..commit.clone() };
        assert!(!verify(&tampered, &ctx, &key.did_key()));
        assert!(!verify(&SignedCommit { rev: "3kbcq3p7ad999".into(), ..commit.clone() }, &ctx, &key.did_key()));
        assert!(!verify(&SignedCommit { ver: 2, ..commit.clone() }, &ctx, &key.did_key()));
        let mut mac = commit.mac.clone();
        mac[0] ^= 1;
        assert!(!verify(&SignedCommit { mac, ..commit.clone() }, &ctx, &key.did_key()));
        assert!(!verify(&SignedCommit { mac: commit.mac[..31].to_vec(), ..commit.clone() }, &ctx, &key.did_key()));
        assert!(!verify(&commit, &ctx, "did:key:zNotAKey"));
        assert!(!verify(&commit, &ctx, "did:plc:abc"));

        // high-S is refused, as by the reference's default verification
        let s = &commit.sig[32..];
        let n = hex::decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141").unwrap();
        let mut high = commit.sig[..32].to_vec();
        high.extend(sub_be(&n, s));
        assert!(!verify(&SignedCommit { sig: high, ..commit.clone() }, &ctx, &key.did_key()));

        let mut advanced = set.clone();
        advanced.add(&element(
            "app.bsky.feed.post",
            "2",
            "bafyreidpw4cbv6gr4ukh33z23pvvrpr3wi4gnpmi4doamlsl3sa4rgri2a",
        ));
        assert!(!matches(&advanced, &commit));
    }

    pub(crate) fn sub_be(a: &[u8], b: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; a.len()];
        let mut borrow = 0i16;
        for i in (0..a.len()).rev() {
            let d = a[i] as i16 - b[i] as i16 - borrow;
            borrow = (d < 0) as i16;
            out[i] = d.rem_euclid(256) as u8;
        }
        out
    }

    #[test]
    fn ctx_encoding() {
        let ctx = CommitCtx {
            space: "at://did:example:space/space/app.bsky.group/test",
            author: "did:example:alice",
            rev: "3kbcq3p7ad400",
        };
        let ikm = [7u8; 32];
        let e = encode_ctx(&ctx, &ikm).unwrap();
        assert_eq!(&e[..16], b"atproto-space-v1");
        assert_eq!(u16::from_be_bytes([e[16], e[17]]) as usize, ctx.space.len());
        let a = encode_ctx(&CommitCtx { space: "ab", author: "c", rev: "d" }, &ikm).unwrap();
        let b = encode_ctx(&CommitCtx { space: "a", author: "bc", rev: "d" }, &ikm).unwrap();
        assert_ne!(a, b);
        let long = "x".repeat(65_536);
        assert!(encode_ctx(&CommitCtx { space: &long, ..ctx }, &ikm).is_none());
        assert!(encode_ctx(&CommitCtx { space: &long[1..], ..ctx }, &ikm).is_some());
        assert!(sign(&LtHash::default(), &CommitCtx { space: &long, ..ctx }, ikm, |_| Ok::<_, ()>([0; 64])).is_err());
    }

    #[test]
    fn elements() {
        let cid = "bafyreidefdycgbfy3oglcb6ism3eqhyp5llsrpzxjsuac2gsy4mtrtx244";
        assert_eq!(element("n.c.a", "1", cid), format!("n.c.a/1/{cid}"));
        assert_ne!(element("n.c.a", "b/1", cid), element("n.c.a", "b/2", cid));
        let (mut a, mut b) = (LtHash::default(), LtHash::default());
        a.add(&element("n.c.a", "1", cid));
        b.add(&element("n.c.a", "2", cid));
        assert_ne!(a, b);
    }
}
