//! Space repo commits (@atproto/space `repo-commit.ts`): which repo, in
//! which space, at which rev, and the digest of its set hash. A commit
//! carries no signature; the repo host authenticates it to a syncer with a
//! MAC in a response header ([`super::mac`]), so a leaked commit proves
//! nothing about what the author wrote to a third party.
//!
//! ```text
//! { ver: 1, repo: <author DID>, space: <space URI>, rev: <TID>, data: sha256(LtHash state) }
//! ```

use super::lthash::LtHash;

pub const COMMIT_VERSION: i64 = 1;

/// The reference's `Commit` (`com.atproto.space.defs#commit`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commit {
    pub ver: i64,
    pub repo: String,
    /// The space URI (`at://{authority}/space/{type}/{skey}`).
    pub space: String,
    pub rev: String,
    pub data: Vec<u8>,
}

impl Commit {
    /// `RepoCommit#toCommit` of `set` at `rev`.
    pub fn of(set: &LtHash, space: &str, repo: &str, rev: &str) -> Commit {
        Commit {
            ver: COMMIT_VERSION,
            repo: repo.into(),
            space: space.into(),
            rev: rev.into(),
            data: set.digest().to_vec(),
        }
    }

    /// The lexicon's JSON (`data` as `$bytes`).
    pub fn to_json(&self) -> serde_json::Value {
        use base64::Engine;
        serde_json::json!({
            "ver": self.ver,
            "repo": self.repo,
            "space": self.space,
            "rev": self.rev,
            "data": {"$bytes": base64::engine::general_purpose::STANDARD_NO_PAD.encode(&self.data)},
        })
    }

    /// From the lexicon's JSON.
    pub fn from_json(c: &serde_json::Value) -> Result<Commit, String> {
        use base64::Engine;
        let s = |k: &str| c[k].as_str().map(String::from).ok_or_else(|| format!("commit.{k} isn't a string"));
        let data = c["data"]["$bytes"].as_str().ok_or("commit.data isn't bytes")?;
        Ok(Commit {
            ver: c["ver"].as_i64().ok_or("commit.ver isn't an integer")?,
            repo: s("repo")?,
            space: s("space")?,
            rev: s("rev")?,
            data: base64::engine::general_purpose::STANDARD_NO_PAD
                .decode(data.trim_end_matches('='))
                .map_err(|_| "commit.data isn't base64")?,
        })
    }

    /// The canonical DRISL map, with `$type` when it's a STAR archive's
    /// metadata (`com.atproto.space.defs#repoStarMeta`).
    pub fn to_cbor(&self, star_type: Option<&str>) -> Vec<u8> {
        let mut b = Vec::with_capacity(256);
        vlatproto::cbor::write_map_head(&mut b, if star_type.is_some() { 6 } else { 5 });
        // canonical key order: by length, then bytes
        vlatproto::cbor::write_text(&mut b, "rev");
        vlatproto::cbor::write_text(&mut b, &self.rev);
        vlatproto::cbor::write_text(&mut b, "ver");
        vlatproto::cbor::write_int(&mut b, self.ver);
        vlatproto::cbor::write_text(&mut b, "data");
        vlatproto::cbor::write_bytes(&mut b, &self.data);
        vlatproto::cbor::write_text(&mut b, "repo");
        vlatproto::cbor::write_text(&mut b, &self.repo);
        if let Some(t) = star_type {
            vlatproto::cbor::write_text(&mut b, "$type");
            vlatproto::cbor::write_text(&mut b, t);
        }
        vlatproto::cbor::write_text(&mut b, "space");
        vlatproto::cbor::write_text(&mut b, &self.space);
        b
    }
}

/// The reference's `verifyCommit`: the version, the requested repo and
/// space, then the response's MAC under the request's secret. Only then is
/// `data` the author's host's claim about the repo.
pub fn verify(commit: &Commit, space: &str, repo: &str, secret: &[u8], mac: &[u8]) -> bool {
    commit.ver == COMMIT_VERSION
        && commit.repo == repo
        && commit.space == space
        && super::mac::verify_commit_mac(secret, commit, mac)
}

/// The set hash element of a record. Injective without length prefixes:
/// the collection (an NSID) and the CID (base32) contain no `/`, so the
/// first and last slashes delimit the rkey whatever it holds.
pub fn element(collection: &str, rkey: &str, cid: &str) -> String {
    debug_assert!(!collection.contains('/') && !cid.contains('/'));
    format!("{collection}/{rkey}/{cid}")
}

/// Whether `set` is the repo `commit` describes. Verify the commit first:
/// on its own this says nothing about authenticity.
pub fn matches(set: &LtHash, commit: &Commit) -> bool {
    set.digest()[..] == commit.data[..]
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::space::vectors::VECTORS;

    /// testdata/spaces-alpha/vectors.json `commits`: the reference's
    /// `toCommit` over a set, its JSON and its STAR metadata bytes.
    #[test]
    fn generated_vectors() {
        let cases = VECTORS["commits"].as_array().unwrap();
        assert_eq!(cases.len(), 3);
        for c in cases {
            let mut set = LtHash::default();
            for r in c["records"].as_array().unwrap() {
                let el =
                    element(r["collection"].as_str().unwrap(), r["rkey"].as_str().unwrap(), r["cid"].as_str().unwrap());
                assert_eq!(el, r["element"].as_str().unwrap());
                set.add(&el);
            }
            let commit =
                Commit::of(&set, c["space"].as_str().unwrap(), c["repo"].as_str().unwrap(), c["rev"].as_str().unwrap());
            assert_eq!(hex::encode(&commit.data), c["data"].as_str().unwrap());
            assert!(matches(&set, &commit));
            assert_eq!(hex::encode(commit.to_cbor(Some("atproto-space-repo"))), c["starMeta"].as_str().unwrap());
            assert_eq!(hex::encode(commit.to_cbor(None)), c["cbor"].as_str().unwrap());
            assert_eq!(Commit::from_json(&commit.to_json()).unwrap(), commit);
        }
    }

    #[test]
    fn verification() {
        let space = "at://did:example:space/space/app.bsky.group/test";
        let mut set = LtHash::default();
        set.add(&element("app.bsky.feed.post", "1", "bafyreidefdycgbfy3oglcb6ism3eqhyp5llsrpzxjsuac2gsy4mtrtx244"));
        let commit = Commit::of(&set, space, "did:example:alice", "3kbcq3p7ad400");
        let secret = [5u8; 32];
        let mac = crate::space::mac::commit_mac(&secret, &commit).unwrap();
        assert!(verify(&commit, space, "did:example:alice", &secret, &mac));
        assert!(!verify(&commit, space, "did:example:bob", &secret, &mac));
        assert!(!verify(
            &commit,
            "at://did:example:space/space/app.bsky.group/other",
            "did:example:alice",
            &secret,
            &mac
        ));
        assert!(!verify(&commit, space, "did:example:alice", &[6; 32], &mac));
        assert!(!verify(&Commit { ver: 2, ..commit.clone() }, space, "did:example:alice", &secret, &mac));
        let tampered = Commit { data: LtHash::default().digest().to_vec(), ..commit.clone() };
        assert!(!verify(&tampered, space, "did:example:alice", &secret, &mac));
        assert!(!verify(
            &Commit { rev: "3kbcq3p7ad999".into(), ..commit.clone() },
            space,
            "did:example:alice",
            &secret,
            &mac
        ));
        assert!(!verify(&commit, space, "did:example:alice", &secret, &mac[..31]));
        let mut advanced = set.clone();
        advanced.add(&element(
            "app.bsky.feed.post",
            "2",
            "bafyreidpw4cbv6gr4ukh33z23pvvrpr3wi4gnpmi4doamlsl3sa4rgri2a",
        ));
        assert!(!matches(&advanced, &commit));
    }

    #[test]
    fn cbor_is_canonical() {
        let c = Commit {
            ver: 1,
            repo: "did:example:alice".into(),
            space: "at://did:example:space/space/a.b.c/k".into(),
            rev: "3jzfcijpj2z2a".into(),
            data: vec![1; 32],
        };
        for t in [None, Some("atproto-space-repo")] {
            let b = c.to_cbor(t);
            let v = vlatproto::cbor::Value::decode(&b).unwrap();
            assert_eq!(v.to_cbor(), b, "decodes and re-encodes to the same bytes");
            assert_eq!(v.get("repo").and_then(|r| r.as_str()), Some("did:example:alice"));
        }
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
