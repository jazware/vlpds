//! Shared pieces of the phase 3 tests (import_repo, backup, takedowns,
//! operator_reads):
//!
//! - raw DPoP calls for STAR bodies (getRepo out, `com.atproto.space.importRepo`
//!   in), on the account's OAuth grant;
//! - [`verify_repo_star`]: the reference's `verifyRepoStarFull`
//!   (packages/space/src/sync/consumer.ts) less the MAC, which a credential
//!   read checks as it's served ([`Cred::get`]), returning why an archive
//!   fails rather than panicking, so refusal tests can build bad archives
//!   and check that the reference would refuse them too;
//! - [`RepoBuilder`]: a space repo archive as the reference's `serializeRepo`
//!   writes it, for synthetic imports;
//! - takedown calls, and [`Syncer`], a client that follows one repo with
//!   listRepoOps and falls back to getRepo on a digest mismatch, as the
//!   spec's syncer does.
//!
//! `com.atproto.space.importRepo` as these tests pin it: `POST
//! /xrpc/com.atproto.space.importRepo` with the getRepo archive
//! (`application/octet-stream`) as the body, on the account's OAuth grant
//! with a `space:` scope allowing `create` in the archive's space and its
//! collections. It answers 200 with no body.

use super::ref_net::*;
use crate::common::spaces::SpaceClient;
use crate::common::*;
use std::collections::BTreeMap;
use std::time::Duration;
use vlpds::space::commit::{self, Commit};
use vlpds::space::lthash::LtHash;
use vlpds::space::star;

pub const IMPORT_REPO: &str = "com.atproto.space.importRepo";
pub const STAR_TYPE: &str = "application/octet-stream";
pub const UPDATE_SUBJECT_STATUS: &str = "com.atproto.admin.updateSubjectStatus";

/// A DPoP-authenticated XRPC call on `sc`'s grant at `base`, with a raw
/// body. Retried once on a fresh DPoP nonce, as clients do.
pub async fn dpop_raw(
    sc: &SpaceClient,
    base: &str,
    method: reqwest::Method,
    nsid: &str,
    query: &[(&str, &str)],
    body: Option<(&[u8], &str)>,
) -> Resp {
    let url = crate::common::spaces::xrpc_url(base, nsid, query);
    for attempt in 0..2 {
        let mut rb = sc
            .srv
            .http
            .request(method.clone(), &url)
            .header("dpop", sc.key.proof(method.as_str(), &url, Some(&sc.access)))
            .header("authorization", format!("DPoP {}", sc.access));
        if let Some((b, ctype)) = body {
            rb = rb.header("content-type", ctype).body(b.to_vec());
        }
        let r = crate::common::spaces::resp(rb.send().await.unwrap()).await;
        if let Some(n) = r.headers.get("dpop-nonce").and_then(|v| v.to_str().ok()) {
            *sc.key.nonce.lock() = Some(n.to_string());
        }
        if attempt == 0 && r.json["error"] == "use_dpop_nonce" {
            continue;
        }
        return r;
    }
    unreachable!()
}

/// getRepo of `repo` on `sc`'s own grant (an owner's `read_self`).
pub async fn get_repo_self(sc: &SpaceClient, space: &str) -> Resp {
    let base = sc.srv.base.clone();
    dpop_raw(sc, &base, reqwest::Method::GET, "com.atproto.space.getRepo", &[("space", space), ("repo", &sc.did)], None)
        .await
}

pub async fn import_repo(sc: &SpaceClient, star: &[u8]) -> Resp {
    let base = sc.srv.base.clone();
    dpop_raw(sc, &base, reqwest::Method::POST, IMPORT_REPO, &[], Some((star, STAR_TYPE))).await
}

/// importRepo with some other `Authorization` (a password session, an app
/// password).
pub async fn import_repo_as(base: &str, auth: &Auth, star: &[u8]) -> Resp {
    Xrpc::new(base).post_bytes(IMPORT_REPO, star.to_vec(), STAR_TYPE, auth).await
}

// ---------------------------------------------------------------------------
// STAR archives
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct VerifiedRepo {
    pub commit: Commit,
    /// (path, CID, bytes), in the archive's (bytewise path) order.
    pub records: Vec<(String, Cid, Vec<u8>)>,
}

impl VerifiedRepo {
    pub fn set(&self) -> BTreeMap<String, String> {
        self.records.iter().map(|(p, c, _)| (p.clone(), c.to_string())).collect()
    }
}

/// `verifyRepoStarFull({space, repo})` less the MAC: repo metadata naming
/// the space and repo asked for, keys in strict bytewise order, each value
/// a canonical DRISL map, and the records folding to the commit's `data`
/// once the archive has ended.
pub fn verify_repo_star(bytes: &[u8], space: &str, repo: &str) -> Result<VerifiedRepo, String> {
    let (meta, pairs) = star::read_all(bytes, star::LIMITS).map_err(|e| format!("invalid STAR: {e}"))?;
    let commit = star::parse_repo_meta(&meta).map_err(|e| e.0)?;
    if commit.repo != repo || commit.space != space {
        return Err(format!("the archive is {} in {}", commit.repo, commit.space));
    }
    let mut set = LtHash::default();
    let mut records: Vec<(String, Cid, Vec<u8>)> = Vec::with_capacity(pairs.len());
    for (key, value) in pairs {
        if records.last().is_some_and(|(p, _, _)| p.as_bytes() >= &key[..]) {
            return Err("duplicate or out-of-order key".into());
        }
        let path = String::from_utf8(key).map_err(|_| "a path that isn't UTF-8".to_string())?;
        let Some((coll, rkey)) = path.split_once('/') else { return Err(format!("bad path {path}")) };
        let v = Value::decode(&value).map_err(|e| format!("invalid record at {path}: {e}"))?;
        if !matches!(v, Value::Map(_)) || v.to_cbor() != value {
            return Err(format!("record at {path} is not canonical DRISL"));
        }
        let cid = Cid::dag_cbor(&value);
        set.add(&commit::element(coll, rkey, &cid.to_string()));
        records.push((path, cid, value));
    }
    if !commit::matches(&set, &commit) {
        return Err("the records do not match the commit's data".into());
    }
    Ok(VerifiedRepo { commit, records })
}

/// An archive of `meta` (its DRISL bytes) and `pairs` as given, so a test
/// can put them out of order; `end`: with the end byte.
pub fn write_star(meta: &[u8], pairs: &[(Vec<u8>, Vec<u8>)], end: bool) -> Vec<u8> {
    let mut out = Vec::new();
    star::write_header(&mut out, meta);
    for (k, v) in pairs {
        star::write_pair(&mut out, k, v);
    }
    if end {
        star::write_end(&mut out);
    }
    out
}

pub fn record_block(record: &J) -> (Cid, Vec<u8>) {
    let b = Value::from_json(record).expect("a data model record").to_cbor();
    (Cid::dag_cbor(&b), b)
}

/// A space repo to serialize: records by path (a `String` map is in
/// bytewise order, as STAR wants), for (space, repo, rev).
pub struct RepoBuilder {
    pub space: String,
    pub author: String,
    pub rev: String,
    pub records: BTreeMap<String, (Cid, Vec<u8>)>,
}

/// A built archive's parts, for tests that take it apart.
pub struct BuiltStar {
    pub commit: Commit,
    /// In path order.
    pub records: Vec<(String, Cid, Vec<u8>)>,
}

impl BuiltStar {
    pub fn meta(&self) -> Vec<u8> {
        star::repo_meta(&self.commit)
    }

    pub fn pairs(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        self.records.iter().map(|(p, _, b)| (p.as_bytes().to_vec(), b.clone())).collect()
    }

    pub fn star(&self) -> Vec<u8> {
        write_star(&self.meta(), &self.pairs(), true)
    }

    /// The archive with `f` applied to its pairs.
    pub fn star_with(&self, f: impl FnOnce(&mut Vec<(Vec<u8>, Vec<u8>)>)) -> Vec<u8> {
        let mut pairs = self.pairs();
        f(&mut pairs);
        write_star(&self.meta(), &pairs, true)
    }
}

impl RepoBuilder {
    pub fn new(space: &str, author: &str, rev: &str) -> RepoBuilder {
        RepoBuilder { space: space.into(), author: author.into(), rev: rev.into(), records: BTreeMap::new() }
    }

    pub fn record(mut self, collection: &str, rkey: &str, value: J) -> RepoBuilder {
        self.records.insert(format!("{collection}/{rkey}"), record_block(&value));
        self
    }

    /// The set hash of the records.
    pub fn set(&self) -> LtHash {
        let mut set = LtHash::default();
        for (p, (c, _)) in &self.records {
            let (coll, rkey) = p.split_once('/').unwrap();
            set.add(&commit::element(coll, rkey, &c.to_string()));
        }
        set
    }

    /// With a commit over `set` (normally [`Self::set`]).
    pub fn build_with(&self, set: &LtHash) -> BuiltStar {
        let commit = Commit::new(set, &self.space, &self.author, &self.rev);
        let records = self.records.iter().map(|(p, (c, b))| (p.clone(), *c, b.clone())).collect();
        BuiltStar { commit, records }
    }

    pub fn build(&self) -> BuiltStar {
        self.build_with(&self.set())
    }
}

/// A TID `ago` before now (an imported repo's rev is from the past).
pub fn rev_ago(ago: Duration) -> String {
    tid_at(-(ago.as_micros() as i64))
}

/// `{space}/{did}/{collection}/{rkey}`: a space record's URI.
pub fn record_uri(space: &str, did: &str, collection: &str, rkey: &str) -> String {
    format!("{space}/{did}/{collection}/{rkey}")
}

/// `sha256(uri)[..16]`, hex: the space id vlpds keys its rows by, and the
/// backup ZIP's directory name for the space.
pub fn sid_hex(space: &str) -> String {
    use sha2::Digest;
    hex::encode(&sha2::Sha256::digest(space.as_bytes())[..16])
}

// ---------------------------------------------------------------------------
// moderation
// ---------------------------------------------------------------------------

pub async fn takedown_record(s: &TestServer, uri: &str, cid: &str, applied: bool) {
    let body = json!({
        "subject": {"$type": "com.atproto.repo.strongRef", "uri": uri, "cid": cid},
        "takedown": {"applied": applied, "ref": "phase3"},
    });
    s.xrpc.post(UPDATE_SUBJECT_STATUS, &body, &Auth::Admin).await.ok();
}

pub async fn takedown_account(s: &TestServer, did: &str, applied: bool) {
    let body = json!({
        "subject": {"$type": "com.atproto.admin.defs#repoRef", "did": did},
        "takedown": {"applied": applied, "ref": "phase3"},
    });
    s.xrpc.post(UPDATE_SUBJECT_STATUS, &body, &Auth::Admin).await.ok();
}

/// A space takedown (a vlpds extension, plan §2.8) through the console's
/// moderation method: kind `space`, the authority's DID and the space URI.
pub async fn takedown_space(s: &TestServer, space: &str, applied: bool) -> Resp {
    let body = json!({
        "kind": "space",
        "did": authority_of(space),
        "uri": space,
        "action": if applied { "takedown" } else { "restore" },
        "reason": "phase 3 space takedown test",
    });
    s.xrpc.post("vlpds.admin.moderate", &body, &Auth::Admin).await
}

// ---------------------------------------------------------------------------
// a syncer
// ---------------------------------------------------------------------------

/// Follows one member's repo in a space the way the spec's syncer does:
/// listRepoOps from its rev, and getRepo when the replayed set doesn't
/// match the (MACed) commit.
pub struct Syncer {
    pub base: String,
    pub space: String,
    pub repo: String,
    pub cred: Cred,
    pub rev: Option<String>,
    pub set: BTreeMap<String, String>,
    pub full_pulls: usize,
}

fn digest(set: &BTreeMap<String, String>) -> [u8; 32] {
    let mut h = LtHash::default();
    for (p, c) in set {
        let (coll, rkey) = p.split_once('/').unwrap();
        h.add(&commit::element(coll, rkey, c));
    }
    h.digest()
}

impl Syncer {
    pub fn new(base: &str, space: &str, repo: &str, cred: Cred) -> Syncer {
        Syncer {
            base: base.into(),
            space: space.into(),
            repo: repo.into(),
            cred,
            rev: None,
            set: BTreeMap::new(),
            full_pulls: 0,
        }
    }

    pub async fn full(&mut self) {
        let q = [("space", self.space.as_str()), ("repo", self.repo.as_str())];
        let r = self.cred.get(&self.base, "com.atproto.space.getRepo", &q).await;
        assert_eq!(r.status, 200, "syncer getRepo: {}", r.text());
        let v = verify_repo_star(&r.body, &self.space, &self.repo)
            .unwrap_or_else(|e| panic!("syncer: getRepo doesn't verify: {e}"));
        self.set = v.set();
        self.rev = Some(v.commit.rev.clone());
        self.full_pulls += 1;
    }

    /// One catch-up; true when it had to fall back to getRepo.
    pub async fn poll(&mut self) -> bool {
        let (mut cursor, mut commit) = (None::<String>, J::Null);
        let mut set = self.set.clone();
        for page in 0.. {
            assert!(page < 1000, "listRepoOps doesn't end");
            let mut q = vec![("space", self.space.as_str()), ("repo", self.repo.as_str()), ("limit", "100")];
            if let Some(s) = &self.rev {
                q.push(("since", s));
            }
            if let Some(c) = &cursor {
                q.push(("cursor", c));
            }
            let r = self.cred.get(&self.base, "com.atproto.space.listRepoOps", &q).await.ok();
            for op in r["ops"].as_array().cloned().unwrap_or_default() {
                let path = format!("{}/{}", op["collection"].as_str().unwrap(), op["rkey"].as_str().unwrap());
                match op["cid"].as_str() {
                    Some(c) => set.insert(path, c.to_string()),
                    None => set.remove(&path),
                };
            }
            cursor = r["cursor"].as_str().map(String::from);
            if r["commit"].is_object() {
                commit = r["commit"].clone();
                break;
            }
            if cursor.is_none() {
                break;
            }
        }
        assert!(commit.is_object(), "listRepoOps ended without a commit");
        let sc = super::fuzz::signed_commit(&commit);
        assert!(sc.space == self.space && sc.repo == self.repo, "listRepoOps' commit is for another repo");
        if digest(&set) == sc.data {
            self.set = set;
            self.rev = Some(sc.rev);
            return false;
        }
        self.full().await;
        true
    }
}

/// Polls until the syncer holds `want`, or panics after ~5 s.
pub async fn converge(s: &mut Syncer, want: &BTreeMap<String, String>, what: &str) {
    for _ in 0..50 {
        s.poll().await;
        if &s.set == want {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("{what}: the syncer holds {:?}, wants {want:?}", s.set);
}

/// `repo`'s records in `space` as `cred` lists them: path -> CID.
pub async fn listed(base: &str, cred: &Cred, space: &str, repo: &str) -> BTreeMap<String, String> {
    let (mut out, mut cursor) = (BTreeMap::new(), None::<String>);
    for _ in 0..1000 {
        let mut q = vec![("space", space), ("repo", repo), ("limit", "100")];
        if let Some(c) = &cursor {
            q.push(("cursor", c));
        }
        let r = cred.get(base, "com.atproto.space.listRecords", &q).await.ok();
        let recs = r["records"].as_array().cloned().unwrap_or_default();
        for rec in &recs {
            out.insert(
                format!("{}/{}", rec["collection"].as_str().unwrap(), rec["rkey"].as_str().unwrap()),
                rec["cid"].as_str().unwrap().to_string(),
            );
        }
        cursor = r["cursor"].as_str().map(String::from);
        if recs.is_empty() || cursor.is_none() {
            break;
        }
    }
    out
}

pub fn set_hash(set: &BTreeMap<String, String>) -> Vec<u8> {
    digest(set).to_vec()
}
