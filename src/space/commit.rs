//! Space repo commits and their MACs (@atproto/space `repo-commit.ts`,
//! `mac.ts`). A commit names the repo, space and rev, and carries the
//! LtHash digest as `data`. It has no signature: the repo host
//! authenticates it to one syncer at a time with an HMAC keyed by that
//! request's shared secret ([`super::mac`]), sent in a response header. A
//! leaked response proves nothing about what the author wrote to a third
//! party.
//!
//! ```text
//! commit mac = HMAC-SHA256(secret, "atproto-space-repo-v1"
//!     || u16be(len) || space || u16be(len) || repo || u16be(len) || rev || data)
//! record mac = HMAC-SHA256(secret, "atproto-space-record-v1"
//!     || u16be(len) || uri || cid bytes)
//! ```

use super::lthash::LtHash;
use hmac::{Hmac, KeyInit, Mac};
use serde_json::{json, Value as J};
use sha2::Sha256;

pub const COMMIT_VERSION: i64 = 1;
pub const RECORD_MAC_VERSION: i64 = 1;
const COMMIT_DOMAIN: &[u8] = b"atproto-space-repo-v1";
const RECORD_DOMAIN: &[u8] = b"atproto-space-record-v1";

/// The reference's `Commit`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commit {
    pub ver: i64,
    pub repo: String,
    pub space: String,
    pub rev: String,
    pub data: [u8; 32],
}

impl Commit {
    pub fn new(set: &LtHash, space: &str, repo: &str, rev: &str) -> Commit {
        Commit { ver: COMMIT_VERSION, repo: repo.into(), space: space.into(), rev: rev.into(), data: set.digest() }
    }

    /// `com.atproto.space.defs#commit` as JSON.
    pub fn to_json(&self) -> J {
        use base64::Engine;
        json!({
            "ver": self.ver,
            "repo": self.repo,
            "space": self.space,
            "rev": self.rev,
            "data": {"$bytes": base64::engine::general_purpose::STANDARD_NO_PAD.encode(self.data)},
        })
    }

    pub fn from_json(v: &J) -> Option<Commit> {
        use base64::Engine;
        let data = v["data"]["$bytes"].as_str()?;
        let data = base64::engine::general_purpose::STANDARD_NO_PAD.decode(data.trim_end_matches('=')).ok()?;
        Some(Commit {
            ver: v["ver"].as_i64()?,
            repo: v["repo"].as_str()?.into(),
            space: v["space"].as_str()?.into(),
            rev: v["rev"].as_str()?.into(),
            data: data.try_into().ok()?,
        })
    }
}

/// The set hash element of a record. Injective without length prefixes:
/// the collection (an NSID) and the CID (base32) contain no `/`, so the
/// first and last slashes delimit the rkey whatever it holds.
pub fn element(collection: &str, rkey: &str, cid: &str) -> String {
    debug_assert!(!collection.contains('/') && !cid.contains('/'));
    format!("{collection}/{rkey}/{cid}")
}

/// None when a field is longer than its u16 length prefix allows.
fn keyed(secret: &[u8; 32], domain: &[u8], fields: &[&str]) -> Option<Hmac<Sha256>> {
    let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(secret).expect("HMAC takes any key length");
    m.update(domain);
    for f in fields {
        m.update(&u16::try_from(f.len()).ok()?.to_be_bytes());
        m.update(f.as_bytes());
    }
    Some(m)
}

fn commit_state(secret: &[u8; 32], c: &Commit) -> Option<Hmac<Sha256>> {
    let mut m = keyed(secret, COMMIT_DOMAIN, &[&c.space, &c.repo, &c.rev])?;
    m.update(&c.data);
    Some(m)
}

/// None when a field is longer than its u16 length prefix allows.
pub fn commit_mac(secret: &[u8; 32], c: &Commit) -> Option<[u8; 32]> {
    Some(commit_state(secret, c)?.finalize().into_bytes().into())
}

/// `cid`: the record's binary CID.
pub fn record_mac(secret: &[u8; 32], uri: &str, cid: &[u8]) -> Option<[u8; 32]> {
    let mut m = keyed(secret, RECORD_DOMAIN, &[uri])?;
    m.update(cid);
    Some(m.finalize().into_bytes().into())
}

/// The reference's `verifyCommit`: the commit is for the repo and space
/// asked for, and its MAC verifies (in constant time). Only then is `data`
/// the author's claim.
pub fn verify(c: &Commit, space: &str, repo: &str, secret: &[u8; 32], mac: &[u8]) -> bool {
    if c.ver != COMMIT_VERSION || c.repo != repo || c.space != space {
        return false;
    }
    commit_state(secret, c).is_some_and(|m| m.verify_slice(mac).is_ok())
}

/// The reference's `verifyRecordMac`.
pub fn verify_record(secret: &[u8; 32], uri: &str, cid: &[u8], mac: &[u8]) -> bool {
    keyed(secret, RECORD_DOMAIN, &[uri]).is_some_and(|mut m| {
        m.update(cid);
        m.verify_slice(mac).is_ok()
    })
}

/// Whether `set` is the repo `commit` describes. Verify the commit first:
/// on its own this says nothing about authenticity.
pub fn matches(set: &LtHash, commit: &Commit) -> bool {
    set.digest() == commit.data
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::space::vectors::VECTORS;
    use vlatproto::cid::Cid;

    fn h(v: &J) -> Vec<u8> {
        hex::decode(v.as_str().unwrap()).unwrap()
    }

    fn h32(v: &J) -> [u8; 32] {
        h(v).try_into().unwrap()
    }

    fn set_of(c: &J) -> LtHash {
        let mut set = LtHash::default();
        for r in c["records"].as_array().unwrap() {
            let el =
                element(r["collection"].as_str().unwrap(), r["rkey"].as_str().unwrap(), r["cid"].as_str().unwrap());
            assert_eq!(el, r["element"].as_str().unwrap());
            set.add(&el);
        }
        set
    }

    /// testdata/spaces-alpha/vectors.json `commits` and `recordMacs`: the
    /// digest and MACs the reference computes for a fixed shared secret.
    #[test]
    fn generated_vectors() {
        let cases = VECTORS["commits"].as_array().unwrap();
        assert_eq!(cases.len(), 3);
        for c in cases {
            let ctx = &c["ctx"];
            let (space, repo) = (ctx["space"].as_str().unwrap(), ctx["repo"].as_str().unwrap());
            let commit = Commit::new(&set_of(c), space, repo, ctx["rev"].as_str().unwrap());
            assert_eq!(commit.data[..], h(&c["data"])[..]);
            let secret = h32(&c["sharedSecret"]);
            let mac = commit_mac(&secret, &commit).unwrap();
            assert_eq!(mac[..], h(&c["mac"])[..]);
            assert!(verify(&commit, space, repo, &secret, &mac));
            assert_eq!(Commit::from_json(&commit.to_json()), Some(commit.clone()));
        }
        for r in VECTORS["recordMacs"].as_array().unwrap() {
            let cid = Cid::parse(r["cid"].as_str().unwrap()).unwrap().to_bytes();
            let (secret, uri) = (h32(&r["sharedSecret"]), r["uri"].as_str().unwrap());
            let mac = record_mac(&secret, uri, &cid).unwrap();
            assert_eq!(mac[..], h(&r["mac"])[..]);
            assert!(verify_record(&secret, uri, &cid, &mac));
        }
    }

    // The cases below are the reference's tests/mac.test.ts.

    fn commit() -> Commit {
        Commit {
            ver: 1,
            space: "at://did:example:space/space/app.bsky.group/test".into(),
            repo: "did:example:alice".into(),
            rev: "3kbcq3p7ad400".into(),
            data: [1; 32],
        }
    }

    #[test]
    fn commit_macs() {
        let secret: [u8; 32] = rand::random();
        let c = commit();
        let mac = commit_mac(&secret, &c).unwrap();
        assert!(verify(&c, &c.space, &c.repo, &secret, &mac));
        assert!(!verify(&c, &c.space, &c.repo, &rand::random(), &mac));
        // unambiguous across field boundaries
        let a = Commit { repo: "did:example:alice".into(), rev: "3kbc".into(), ..commit() };
        let b = Commit { repo: "did:example:alice3".into(), rev: "kbc".into(), ..commit() };
        assert_ne!(commit_mac(&secret, &a), commit_mac(&secret, &b));
        // covers the data digest
        assert!(!verify(&Commit { data: [2; 32], ..commit() }, &c.space, &c.repo, &secret, &mac));
        // the requested repo and space, and the version
        assert!(!verify(&c, &c.space, "did:example:bob", &secret, &mac));
        assert!(!verify(&c, "at://did:example:space/space/app.bsky.group/other", &c.repo, &secret, &mac));
        assert!(!verify(&Commit { ver: 2, ..commit() }, &c.space, &c.repo, &secret, &mac));
        assert!(!verify(&c, &c.space, &c.repo, &secret, &mac[..31]));
        // a field too long for its prefix
        assert!(commit_mac(&secret, &Commit { space: "x".repeat(65_536), ..commit() }).is_none());
    }

    #[test]
    fn record_macs() {
        let secret: [u8; 32] = rand::random();
        let uri = "at://did:example:alice/space/app.bsky.group/test/app.bsky.feed.post/1";
        let a = Cid::parse("bafyreidefdycgbfy3oglcb6ism3eqhyp5llsrpzxjsuac2gsy4mtrtx244").unwrap().to_bytes();
        let b = Cid::parse("bafyreidpw4cbv6gr4ukh33z23pvvrpr3wi4gnpmi4doamlsl3sa4rgri2a").unwrap().to_bytes();
        let mac = record_mac(&secret, uri, &a).unwrap();
        assert!(verify_record(&secret, uri, &a, &mac));
        assert!(!verify_record(&rand::random(), uri, &a, &mac));
        assert!(!verify_record(&secret, &format!("{uri}2"), &a, &mac));
        assert!(!verify_record(&secret, uri, &b, &mac));
        // domain-separated from a commit MAC
        assert_ne!(Some(mac), commit_mac(&secret, &commit()));
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
        assert!(matches(&a, &Commit::new(&a, "s", "r", "v")));
        assert!(!matches(&b, &Commit::new(&a, "s", "r", "v")));
    }

    /// The empty repo's digest, which clearRecords leaves.
    #[test]
    fn empty_digest() {
        assert_eq!(
            hex::encode(LtHash::default().digest()),
            "e5a00aa9991ac8a5ee3109844d84a55583bd20572ad3ffcd42792f3c36b183ad"
        );
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
}
