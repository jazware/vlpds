//! Shared pieces of the phase 3 tests (import_repo, backup, takedowns,
//! operator_reads):
//!
//! - raw DPoP calls for CAR bodies (getRepo out, `vlpds.space.importRepo`
//!   in), on the account's OAuth grant;
//! - [`verify_repo_car`]: the reference's `verifyRepoCarFull`
//!   (packages/space/src/sync/consumer.ts at 5b95b2f2), returning why a CAR
//!   fails rather than panicking, so refusal tests can build bad CARs and
//!   check that the reference would refuse them too;
//! - [`RepoBuilder`]: a space repo CAR as the reference's `serializeRepo`
//!   writes it, signed with any key, for synthetic imports;
//! - takedown calls, and [`Syncer`], a client that follows one repo with
//!   listRepoOps and falls back to getRepo on a digest mismatch, as the
//!   spec's syncer does.
//!
//! `vlpds.space.importRepo` (plan §2.7, brief Q8) as these tests pin it:
//! `POST /xrpc/vlpds.space.importRepo?space=<space URI>` with the getRepo CAR
//! (`application/vnd.ipld.car`) as the body, on the account's OAuth grant
//! with a `space:` scope allowing `create` in that space. It answers
//! `{rev, records}`, keeping the CAR's rev.

use super::ref_net::*;
use crate::common::spaces::SpaceClient;
use crate::common::*;
use base64::Engine;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;
use vlpds::space::commit::{self, CommitCtx, SignedCommit};
use vlpds::space::lthash::LtHash;

pub const IMPORT_REPO: &str = "vlpds.space.importRepo";
pub const CAR_TYPE: &str = "application/vnd.ipld.car";
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

pub async fn import_repo(sc: &SpaceClient, space: &str, car: &[u8]) -> Resp {
    let base = sc.srv.base.clone();
    dpop_raw(sc, &base, reqwest::Method::POST, IMPORT_REPO, &[("space", space)], Some((car, CAR_TYPE))).await
}

/// importRepo with some other `Authorization` (a password session, an app
/// password).
pub async fn import_repo_as(base: &str, auth: &Auth, space: &str, car: &[u8]) -> Resp {
    Xrpc::new(base)
        .post_bytes(&format!("{IMPORT_REPO}?space={}", crate::oauth::enc(space)), car.to_vec(), CAR_TYPE, auth)
        .await
}

// ---------------------------------------------------------------------------
// CARs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct VerifiedRepo {
    pub commit: SignedCommit,
    pub index_cid: Cid,
    /// In the index's (canonical) order.
    pub index: Vec<(String, Cid)>,
    /// The record blocks, in CAR order.
    pub records: Vec<(Cid, Vec<u8>)>,
}

impl VerifiedRepo {
    pub fn set(&self) -> BTreeMap<String, String> {
        self.index.iter().map(|(p, c)| (p.clone(), c.to_string())).collect()
    }
}

fn commit_of(v: &Value) -> Result<SignedCommit, String> {
    let bytes = |k: &str| match v.get(k) {
        Some(Value::Bytes(b)) => Ok(b.clone()),
        other => Err(format!("invalid signedCommit: {k} is {other:?}")),
    };
    Ok(SignedCommit {
        ver: match v.get("ver") {
            Some(Value::Int(n)) => *n,
            other => return Err(format!("invalid signedCommit: ver is {other:?}")),
        },
        hash: bytes("hash")?,
        ikm: bytes("ikm")?,
        sig: bytes("sig")?,
        mac: bytes("mac")?,
        rev: match v.get("rev") {
            Some(Value::Text(r)) => r.clone(),
            other => return Err(format!("invalid signedCommit: rev is {other:?}")),
        },
    })
}

/// `verifyRepoCarFull({space, author, didKey, expectValues})`: two roots
/// (commit, index) leading the CAR in that order, every block hashing to its
/// CID, the commit verifying under `did_key` for (space, author, rev), the
/// index folding to the commit's hash, then exactly one record block per
/// index entry in index order (or none, for an index-only CAR when values
/// aren't expected), each a CBOR map.
pub fn verify_repo_car(
    car: &[u8],
    space: &str,
    author: &str,
    did_key: &str,
    expect_values: bool,
) -> Result<VerifiedRepo, String> {
    let (roots, blocks) = vlatproto::car::read_car(car).map_err(|e| format!("not a CAR: {e:#}"))?;
    if roots.len() != 2 {
        return Err(format!("expected 2 car roots (commit, index), got {}", roots.len()));
    }
    for (c, b) in &blocks {
        if !vlatproto::car::block_matches(c, b) {
            return Err(format!("block {c} doesn't hash to its CID"));
        }
    }
    let mut it = blocks.iter();
    let Some((ccid, cbytes)) = it.next().filter(|(c, _)| *c == roots[0]) else {
        return Err("expected the commit block to lead the car".into());
    };
    let _ = ccid;
    let cv = Value::decode(cbytes).map_err(|e| format!("invalid signedCommit: {e}"))?;
    let commit = commit_of(&cv)?;
    if !commit::verify(&commit, &CommitCtx { space, author, rev: &commit.rev }, did_key) {
        return Err("commit failed verification".into());
    }
    let Some((icid, ibytes)) = it.next().filter(|(c, _)| *c == roots[1]) else {
        return Err("expected the index block to follow the commit".into());
    };
    let Ok(Value::Map(entries)) = Value::decode(ibytes) else {
        return Err("invalid repoIndex: not a map".into());
    };
    let mut set = LtHash::default();
    let mut index = Vec::with_capacity(entries.len());
    for (path, link) in entries {
        let Value::Link(cid) = link else { return Err(format!("invalid repoIndex: {path} isn't a link")) };
        let Some((coll, rkey)) = path.split_once('/') else {
            return Err(format!("invalid repoIndex: bad path {path}"));
        };
        set.add(&commit::element(coll, rkey, &cid.to_string()));
        index.push((path, cid));
    }
    if !commit::matches(&set, &commit) {
        return Err("index does not match the commit hash".into());
    }
    let mut records = Vec::new();
    for (i, (c, b)) in it.enumerate() {
        let Some((path, want)) = index.get(i) else { return Err("car has more blocks than index entries".into()) };
        if c != want {
            return Err(format!("expected block {want} at {path}, got {c}"));
        }
        if !matches!(Value::decode(b), Ok(Value::Map(_))) {
            return Err(format!("invalid record at {path}"));
        }
        records.push((*c, b.to_vec()));
    }
    let index_only = !expect_values && records.is_empty();
    if records.len() < index.len() && !index_only {
        return Err(format!("car is missing {} record(s) named in the index", index.len() - records.len()));
    }
    Ok(VerifiedRepo { commit, index_cid: *icid, index, records })
}

pub fn commit_block(c: &SignedCommit) -> Vec<u8> {
    let b64 = |b: &[u8]| json!({"$bytes": base64::engine::general_purpose::STANDARD_NO_PAD.encode(b)});
    let j = json!({"ver": c.ver, "hash": b64(&c.hash), "ikm": b64(&c.ikm), "sig": b64(&c.sig), "mac": b64(&c.mac), "rev": c.rev});
    Value::from_json(&j).unwrap().to_cbor()
}

/// The index block: path -> CID, canonical (length-first) key order.
pub fn index_block(entries: &[(String, Cid)]) -> Vec<u8> {
    let mut m: Vec<(String, Value)> = entries.iter().map(|(p, c)| (p.clone(), Value::Link(*c))).collect();
    m.sort_by(|a, b| vlatproto::cbor::key_cmp(&a.0, &b.0));
    Value::Map(m).to_cbor()
}

/// A CAR with `roots` and `blocks` in the order given, CIDs as given (so a
/// test can make a block lie about its CID).
pub fn write_car(roots: &[Cid], blocks: &[(Cid, Vec<u8>)]) -> Vec<u8> {
    let mut h = Vec::new();
    vlatproto::cbor::write_map_head(&mut h, 2);
    vlatproto::cbor::write_text(&mut h, "roots");
    vlatproto::cbor::write_array_head(&mut h, roots.len());
    for r in roots {
        vlatproto::cbor::write_cid(&mut h, r);
    }
    vlatproto::cbor::write_text(&mut h, "version");
    vlatproto::cbor::write_uint(&mut h, 1);
    let mut out = Vec::new();
    vlatproto::car::write_varint(&mut out, h.len() as u64);
    out.extend_from_slice(&h);
    for (c, b) in blocks {
        vlatproto::car::write_block(&mut out, c, b);
    }
    out
}

pub fn record_block(record: &J) -> (Cid, Vec<u8>) {
    let b = Value::from_json(record).expect("a data model record").to_cbor();
    (Cid::dag_cbor(&b), b)
}

/// A space repo to serialize: records by path, signed for (space, author,
/// rev) by `key`.
pub struct RepoBuilder {
    pub space: String,
    pub author: String,
    pub rev: String,
    pub records: BTreeMap<String, (Cid, Vec<u8>)>,
}

/// The parts of a built CAR, for tests that take it apart.
pub struct BuiltCar {
    pub commit: SignedCommit,
    pub commit_cid: Cid,
    pub commit_block: Vec<u8>,
    pub index_cid: Cid,
    pub index_block: Vec<u8>,
    /// In index order.
    pub records: Vec<(String, Cid, Vec<u8>)>,
}

impl BuiltCar {
    pub fn car(&self) -> Vec<u8> {
        let mut blocks = vec![(self.commit_cid, self.commit_block.clone()), (self.index_cid, self.index_block.clone())];
        blocks.extend(self.records.iter().map(|(_, c, b)| (*c, b.clone())));
        write_car(&[self.commit_cid, self.index_cid], &blocks)
    }

    /// The CAR with `f` applied to its blocks (after the two roots).
    pub fn car_with(&self, f: impl FnOnce(&mut Vec<(Cid, Vec<u8>)>)) -> Vec<u8> {
        let mut blocks = vec![(self.commit_cid, self.commit_block.clone()), (self.index_cid, self.index_block.clone())];
        blocks.extend(self.records.iter().map(|(_, c, b)| (*c, b.clone())));
        f(&mut blocks);
        write_car(&[self.commit_cid, self.index_cid], &blocks)
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

    /// Signed over `set` (normally [`Self::set`]) with `key`.
    pub fn build_with(&self, key: &vlatproto::crypto::Keypair, set: &LtHash) -> BuiltCar {
        let ctx = CommitCtx { space: &self.space, author: &self.author, rev: &self.rev };
        let commit =
            commit::sign(set, &ctx, rand::random(), |b| Ok::<_, std::convert::Infallible>(key.sign(b))).unwrap();
        let cb = commit_block(&commit);
        let mut entries: Vec<(String, Cid)> = self.records.iter().map(|(p, (c, _))| (p.clone(), *c)).collect();
        entries.sort_by(|a, b| vlatproto::cbor::key_cmp(&a.0, &b.0));
        let ib = index_block(&entries);
        let records = entries.iter().map(|(p, c)| (p.clone(), *c, self.records[p].1.clone())).collect();
        BuiltCar {
            commit_cid: Cid::dag_cbor(&cb),
            commit_block: cb,
            commit,
            index_cid: Cid::dag_cbor(&ib),
            index_block: ib,
            records,
        }
    }

    pub fn build(&self, key: &vlatproto::crypto::Keypair) -> BuiltCar {
        self.build_with(key, &self.set())
    }
}

/// The account's repo signing key, read the way the server reads it.
pub async fn account_key(s: &TestServer, did: &str) -> Arc<vlatproto::crypto::Keypair> {
    let a = s.app.account(did).await.ok().expect("an account here");
    s.app.secrets.account_signing_key(&a).await.expect("its signing key")
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
/// match the signed commit.
pub struct Syncer {
    pub base: String,
    pub space: String,
    pub repo: String,
    pub did_key: String,
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
    pub fn new(base: &str, space: &str, repo: &str, did_key: &str, cred: Cred) -> Syncer {
        Syncer {
            base: base.into(),
            space: space.into(),
            repo: repo.into(),
            did_key: did_key.into(),
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
        let v = verify_repo_car(&r.body, &self.space, &self.repo, &self.did_key, true)
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
        let ctx = CommitCtx { space: &self.space, author: &self.repo, rev: &sc.rev };
        assert!(commit::verify(&sc, &ctx, &self.did_key), "listRepoOps' commit doesn't verify");
        if digest(&set)[..] == sc.hash[..] {
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
