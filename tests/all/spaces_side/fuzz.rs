//! Seeded op-sequence fuzz of space repos, over XRPC. Several accounts write
//! to several spaces they govern with createRecord, putRecord, deleteRecord
//! and applyWrites batches (dependent ops in one batch, and batches that
//! must fail whole: a create of an existing path, an update or delete of a
//! missing one, too many ops). A client-side model follows every acked
//! write; at checkpoints each repo must agree with it four ways:
//!
//! - listRecords holds exactly the model's records;
//! - the oplog replayed from empty (listRepoOps, paged) folds to the signed
//!   commit's hash, and a delta pull from the last checkpoint folds onto
//!   the hash kept from then; the commit verifies under the account's key;
//! - vlpds.admin.checkSpace finds nothing wrong;
//! - getRepo's index folds to its commit's hash, and holds the model's
//!   paths and CIDs, its blocks in index order (C4).
//!
//! Then deleteAccount must leave no s* row of the account (C2).
//!
//! `VLPDS_SPACE_FUZZ_SEED` replays one seed; `VLPDS_SPACE_FUZZ_SEEDS` and
//! `VLPDS_SPACE_FUZZ_STEPS` size the runs.

use crate::common::spaces::SpaceClient;
use crate::common::*;
use base64::Engine;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::collections::BTreeMap;
use std::time::Duration;
use vlpds::space::commit::{self, CommitCtx, SignedCommit};
use vlpds::space::lthash::LtHash;

const ACCOUNTS: usize = 3;
const SPACES: usize = 2;
const RKEYS: usize = 10;
const CHECK_EVERY: usize = 25;
/// Every s* family, C5's blob refs included; all keyed `{fam}{did}\0...`.
const SPACE_FAMILIES: &[&[u8]] =
    &[b"sH/", b"sR/", b"sO/", b"sP/", b"sS/", b"sM/", b"sW/", b"sQ/", b"sN/", b"sb/", b"sc/"];

#[derive(Clone, Copy, Default)]
struct Checks {
    get_repo: bool,
    delete_sweep: bool,
}

/// A path's CID and value as the client last wrote it.
type Records = BTreeMap<String, (String, J)>;

struct Repo {
    space: String,
    records: Records,
    /// Whether an acked write has changed the repo (so it has a head).
    written: bool,
    /// (rev, set hash) at the last checkpoint, for the delta pull.
    synced: Option<(String, LtHash)>,
}

struct Account {
    sc: SpaceClient,
    collections: [String; 2],
    repos: Vec<Repo>,
    /// The holder's credential per space, minted on first use.
    credentials: BTreeMap<String, String>,
}

/// What a write does to the model, in order: the n-th op is the call's
/// n-th result (applyWrites) or its only one.
enum MOp {
    /// None: a TID rkey, known from the result.
    Put {
        path: Option<String>,
        value: J,
    },
    Del {
        path: String,
    },
}

/// One write call and what the model says it must answer: Ok(its ops) or
/// the XRPC error name.
struct Planned {
    nsid: &'static str,
    body: J,
    expect: Result<Vec<MOp>, &'static str>,
    what: String,
}

fn rkey(rng: &mut StdRng) -> String {
    format!("k{}", rng.gen_range(0..RKEYS))
}

fn value(collection: &str, rng: &mut StdRng) -> J {
    json!({"$type": collection, "text": format!("v{}", rng.gen::<u32>()), "n": rng.gen_range(0..1000)})
}

fn wop(kind: &str, collection: &str, rkey: Option<&str>, value: Option<J>) -> J {
    let mut o = json!({"$type": format!("com.atproto.space.applyWrites#{kind}"), "collection": collection});
    if let Some(k) = rkey {
        o["rkey"] = json!(k);
    }
    if let Some(v) = value {
        o["value"] = v;
    }
    o
}

impl Account {
    async fn new(s: &TestServer, i: usize) -> Account {
        let t: String = random_bytes(4).iter().map(|b| format!("{b:02x}")).collect();
        let space_type = format!("com.example.fz{t}.space");
        let collections = [format!("com.example.fz{t}.note"), format!("com.example.fz{t}.item")];
        let scope = format!(
            "space:{space_type}?collection={}&collection={}&action=read&action=create&action=update&action=delete&manage=create",
            collections[0], collections[1]
        );
        let sc = SpaceClient::new(s, &unique_name(&format!("fz{i}")), &scope).await;
        let mut repos = Vec::new();
        for k in 0..SPACES {
            let space = sc.create_space(&space_type, &format!("fz{k}")).await;
            repos.push(Repo { space, records: Records::new(), written: false, synced: None });
        }
        Account { sc, collections, repos, credentials: BTreeMap::new() }
    }

    /// The next write for repo `r`: mostly ones that succeed, some that
    /// must fail whole.
    fn plan(&self, r: usize, rng: &mut StdRng) -> Planned {
        let repo = &self.repos[r];
        let coll = self.collections[rng.gen_range(0..2)].clone();
        let mut body = json!({"space": repo.space, "repo": self.sc.did});
        let existing: Vec<&String> = repo.records.keys().collect();
        let pick = |rng: &mut StdRng, p_new: f64| match existing.is_empty() || rng.gen_bool(p_new) {
            true => format!("{coll}/{}", rkey(rng)),
            false => existing[rng.gen_range(0..existing.len())].clone(),
        };
        let fields = |body: &mut J, path: &str, record: Option<&J>| {
            let (c, k) = path.split_once('/').unwrap();
            body["collection"] = json!(c);
            body["rkey"] = json!(k);
            if let Some(v) = record {
                body["record"] = v.clone();
            }
        };
        let (nsid, expect, what) = match rng.gen_range(0..100) {
            0..20 => {
                let path = pick(rng, 0.7);
                let v = value(path.split_once('/').unwrap().0, rng);
                fields(&mut body, &path, Some(&v));
                let expect = match repo.records.contains_key(&path) {
                    true => Err("RecordAlreadyExists"),
                    false => Ok(vec![MOp::Put { path: Some(path.clone()), value: v }]),
                };
                ("com.atproto.space.createRecord", expect, format!("create {path}"))
            }
            20..28 => {
                let v = value(&coll, rng);
                body["collection"] = json!(coll);
                body["record"] = v.clone();
                let expect = Ok(vec![MOp::Put { path: None, value: v }]);
                ("com.atproto.space.createRecord", expect, format!("create {coll}/<tid>"))
            }
            28..50 => {
                let path = pick(rng, 0.3);
                let v = value(path.split_once('/').unwrap().0, rng);
                fields(&mut body, &path, Some(&v));
                let expect = Ok(vec![MOp::Put { path: Some(path.clone()), value: v }]);
                ("com.atproto.space.putRecord", expect, format!("put {path}"))
            }
            50..62 => {
                // a missing record's delete is a no-op that succeeds
                let path = pick(rng, 0.25);
                fields(&mut body, &path, None);
                let expect = match repo.records.contains_key(&path) {
                    true => Ok(vec![MOp::Del { path: path.clone() }]),
                    false => Ok(vec![]),
                };
                ("com.atproto.space.deleteRecord", expect, format!("delete {path}"))
            }
            62..64 => {
                let writes: Vec<J> =
                    (0..201).map(|i| wop("create", &coll, Some(&format!("big{i}")), Some(value(&coll, rng)))).collect();
                body["writes"] = json!(writes);
                ("com.atproto.space.applyWrites", Err("InvalidRequest"), "applyWrites of 201 ops".into())
            }
            _ => {
                let (writes, expect) = self.batch(&repo.records, &coll, rng);
                let what = format!("applyWrites {}", serde_json::to_string(&writes).unwrap());
                body["writes"] = json!(writes);
                ("com.atproto.space.applyWrites", expect, what)
            }
        };
        Planned { nsid, body, expect, what }
    }

    /// 1-8 ops against the state the batch has built so far (so later ops
    /// depend on earlier ones), sometimes with one that can't apply.
    fn batch(&self, records: &Records, coll: &str, rng: &mut StdRng) -> (Vec<J>, Result<Vec<MOp>, &'static str>) {
        let mut live: std::collections::BTreeSet<String> = records.keys().cloned().collect();
        let (mut writes, mut ops, mut fail) = (Vec::new(), Vec::new(), None);
        for _ in 0..rng.gen_range(1..=8) {
            let c = if rng.gen_bool(0.7) { coll.to_string() } else { self.collections[1].clone() };
            let k = rkey(rng);
            let path = format!("{c}/{k}");
            let exists = live.contains(&path);
            let bad = rng.gen_bool(0.06);
            match (exists, bad, rng.gen_range(0..3)) {
                (false, false, _) | (true, true, 0) => {
                    let v = value(&c, rng);
                    writes.push(wop("create", &c, Some(&k), Some(v.clone())));
                    if exists {
                        fail.get_or_insert("RecordAlreadyExists");
                    }
                    live.insert(path.clone());
                    ops.push(MOp::Put { path: Some(path), value: v });
                }
                (true, false, 0 | 1) | (false, true, 0 | 1) => {
                    let v = value(&c, rng);
                    writes.push(wop("update", &c, Some(&k), Some(v.clone())));
                    if !exists {
                        fail.get_or_insert("RecordNotFound");
                    }
                    live.insert(path.clone());
                    ops.push(MOp::Put { path: Some(path), value: v });
                }
                _ => {
                    writes.push(wop("delete", &c, Some(&k), None));
                    if !exists {
                        fail.get_or_insert("RecordNotFound");
                    }
                    live.remove(&path);
                    ops.push(MOp::Del { path });
                }
            }
        }
        if rng.gen_bool(0.15) {
            let v = value(coll, rng);
            writes.push(wop("create", coll, None, Some(v.clone())));
            ops.push(MOp::Put { path: None, value: v });
        }
        (writes, fail.map_or(Ok(ops), Err))
    }

    /// Runs `p` on repo `r` and moves the model on by what was acked.
    async fn apply(&mut self, r: usize, p: Planned, ctx: &str) {
        let resp = self.sc.post(p.nsid, p.body.clone()).await;
        let ops = match p.expect {
            Err(name) => {
                assert_eq!(resp.status, 400, "{ctx}: {} should fail with {name}: {}", p.what, resp.text());
                assert_eq!(resp.json["error"], json!(name), "{ctx}: {}: {}", p.what, resp.text());
                return;
            }
            Ok(ops) => ops,
        };
        assert_eq!(resp.status, 200, "{ctx}: {}: {}", p.what, resp.text());
        let results = match resp.json["results"].as_array() {
            Some(rs) => rs.clone(),
            None => vec![resp.json.clone()],
        };
        let repo = &mut self.repos[r];
        repo.written |= !ops.is_empty();
        for (i, op) in ops.into_iter().enumerate() {
            match op {
                MOp::Del { path } => {
                    repo.records.remove(&path);
                }
                MOp::Put { path, value } => {
                    let res = results.get(i).unwrap_or_else(|| panic!("{ctx}: {}: no result {i}", p.what));
                    let got = uri_path(res["uri"].as_str().unwrap_or_else(|| panic!("{ctx}: {}: {res}", p.what)));
                    if let Some(path) = path {
                        assert_eq!(got, path, "{ctx}: {}: result {i}", p.what);
                    }
                    let cid = res["cid"].as_str().unwrap().to_string();
                    repo.records.insert(got, (cid, value));
                }
            }
        }
    }

    async fn credential(&mut self, space: &str) -> String {
        if let Some(c) = self.credentials.get(space) {
            return c.clone();
        }
        let c = self.sc.credential(space).await;
        self.credentials.insert(space.to_string(), c.clone());
        c
    }

    /// A credential read of this account's repo in `space` (as a syncer).
    async fn read(&mut self, nsid: &str, space: &str, query: &[(&str, &str)]) -> Resp {
        let cred = self.credential(space).await;
        let base = self.sc.srv.base.clone();
        let mut q = vec![("space", space), ("repo", self.sc.did.as_str())];
        q.extend_from_slice(query);
        self.sc.signed_get(&base, nsid, &q, &cred, &self.sc.did).await
    }
}

fn uri_path(uri: &str) -> String {
    // at://{authority}/space/{type}/{skey}/{author}/{collection}/{rkey}
    let parts: Vec<&str> = uri.trim_start_matches("at://").split('/').collect();
    assert!(parts.len() == 7 && parts[1] == "space", "not a space record URI: {uri}");
    format!("{}/{}", parts[5], parts[6])
}

pub(super) fn bytes_field(v: &J) -> Vec<u8> {
    let b = v["$bytes"].as_str().unwrap_or_else(|| panic!("not $bytes: {v}"));
    base64::engine::general_purpose::STANDARD_NO_PAD.decode(b.trim_end_matches('=')).expect("base64")
}

pub(super) fn signed_commit(j: &J) -> SignedCommit {
    SignedCommit {
        ver: j["ver"].as_i64().expect("ver"),
        hash: bytes_field(&j["hash"]),
        ikm: bytes_field(&j["ikm"]),
        sig: bytes_field(&j["sig"]),
        mac: bytes_field(&j["mac"]),
        rev: j["rev"].as_str().expect("rev").to_string(),
    }
}

pub(super) fn fold(set: &mut LtHash, op: &J) {
    let (c, k) = (op["collection"].as_str().unwrap(), op["rkey"].as_str().unwrap());
    if let Some(p) = op["prev"].as_str() {
        set.remove(&commit::element(c, k, p));
    }
    if let Some(n) = op["cid"].as_str() {
        set.add(&commit::element(c, k, n));
    }
}

/// listRepoOps from `since` (None: the retained window) to the head, `limit`
/// per page; the ops and the commit of the last (short) page.
async fn pull(a: &mut Account, space: &str, since: Option<&str>, limit: usize, ctx: &str) -> (Vec<J>, J) {
    let (mut ops, mut cursor) = (Vec::new(), None::<String>);
    let limit = limit.to_string();
    for page in 0.. {
        assert!(page < 10_000, "{ctx}: listRepoOps doesn't end");
        let mut q = vec![("limit", limit.as_str())];
        if let Some(s) = since {
            q.push(("since", s));
        }
        if let Some(c) = &cursor {
            q.push(("cursor", c.as_str()));
        }
        let r = a.read("com.atproto.space.listRepoOps", space, &q).await;
        assert_eq!(r.status, 200, "{ctx}: listRepoOps {q:?}: {}", r.text());
        let page_ops = r.json["ops"].as_array().cloned().unwrap_or_default();
        ops.extend(page_ops);
        if !r.json["commit"].is_null() {
            assert!(r.json["cursor"].is_null(), "{ctx}: a cursor with the commit: {}", r.text());
            return (ops, r.json["commit"].clone());
        }
        cursor = Some(r.json["cursor"].as_str().unwrap_or_else(|| panic!("{ctx}: no commit, no cursor")).into());
    }
    unreachable!()
}

async fn list_records(a: &Account, space: &str, ctx: &str) -> Records {
    let (mut out, mut cursor) = (Records::new(), None::<String>);
    loop {
        let mut q = vec![("space", space), ("repo", a.sc.did.as_str()), ("limit", "7")];
        if let Some(c) = &cursor {
            q.push(("cursor", c.as_str()));
        }
        let r = a.sc.get("com.atproto.space.listRecords", &q).await;
        assert_eq!(r.status, 200, "{ctx}: listRecords: {}", r.text());
        let recs = r.json["records"].as_array().cloned().unwrap_or_default();
        for x in &recs {
            let path = format!("{}/{}", x["collection"].as_str().unwrap(), x["rkey"].as_str().unwrap());
            let prior = out.insert(path.clone(), (x["cid"].as_str().unwrap().to_string(), x["value"].clone()));
            assert!(prior.is_none(), "{ctx}: listRecords repeats {path}");
        }
        match r.json["cursor"].as_str() {
            Some(c) if !recs.is_empty() => cursor = Some(c.into()),
            _ => return out,
        }
    }
}

/// getRepo's two-root CAR: the index folds to the commit's hash, matches
/// `want`, and the record blocks follow in index order, each hashing to its
/// CID (none with `excludeValues`).
async fn check_get_repo(a: &mut Account, space: &str, want: &Records, ctx: &str) {
    for exclude in [false, true] {
        let q: &[(&str, &str)] = if exclude { &[("excludeValues", "true")] } else { &[] };
        let r = a.read("com.atproto.space.getRepo", space, q).await;
        assert_eq!(r.status, 200, "{ctx}: getRepo: {}", r.text());
        let (roots, blocks) = vlatproto::car::read_car(&r.body).expect("getRepo CAR");
        assert_eq!(roots.len(), 2, "{ctx}: getRepo roots");
        assert!(blocks.len() >= 2 && blocks[0].0 == roots[0] && blocks[1].0 == roots[1], "{ctx}: roots first");
        for (c, b) in &blocks {
            assert!(vlatproto::car::block_matches(c, b), "{ctx}: getRepo block {c} doesn't hash");
        }
        let commit = Value::decode(blocks[0].1).expect("commit block");
        let bytes = |k: &str| match commit.get(k) {
            Some(Value::Bytes(b)) => b.clone(),
            other => panic!("{ctx}: commit {k}: {other:?}"),
        };
        let Some(Value::Map(index)) = Value::decode(blocks[1].1).ok() else { panic!("{ctx}: index isn't a map") };
        let mut set = LtHash::default();
        let mut got = BTreeMap::new();
        for (path, link) in &index {
            let Value::Link(cid) = link else { panic!("{ctx}: index {path} isn't a link") };
            let (c, k) = path.split_once('/').expect("index path");
            set.add(&commit::element(c, k, &cid.to_string()));
            got.insert(path.clone(), cid.to_string());
        }
        assert_eq!(set.digest().to_vec(), bytes("hash"), "{ctx}: getRepo index doesn't fold to its commit");
        let want: BTreeMap<String, String> = want.iter().map(|(p, (c, _))| (p.clone(), c.clone())).collect();
        assert_eq!(got, want, "{ctx}: getRepo index");
        match exclude {
            true => assert_eq!(blocks.len(), 2, "{ctx}: excludeValues carries record blocks"),
            false => {
                let order: Vec<String> = blocks[2..].iter().map(|(c, _)| c.to_string()).collect();
                let index_order: Vec<String> = index.iter().map(|(p, _)| got[p].clone()).collect();
                assert_eq!(order, index_order, "{ctx}: record blocks out of index order");
            }
        }
    }
}

async fn checkpoint(s: &TestServer, a: &mut Account, r: usize, checks: Checks, ctx: &str) {
    let space = a.repos[r].space.clone();
    let did = a.sc.did.clone();
    let want = a.repos[r].records.clone();
    let ctx = format!("{ctx} {did} in {space}");

    assert_eq!(list_records(a, &space, &ctx).await, want, "{ctx}: listRecords against the model");

    if !a.repos[r].written {
        let r = a.read("com.atproto.space.getLatestCommit", &space, &[]).await;
        assert_eq!((r.status, r.json["error"].as_str()), (400, Some("RepoNotFound")), "{ctx}: {}", r.text());
        return;
    }

    // the oplog replayed from empty, in small pages
    let limit = 1 + want.len() % 13;
    let (ops, cj) = pull(a, &space, None, limit, &ctx).await;
    let c = signed_commit(&cj);
    let mut set = LtHash::default();
    for op in &ops {
        fold(&mut set, op);
    }
    assert!(commit::matches(&set, &c), "{ctx}: {} op(s) fold to another hash than the commit's", ops.len());
    let Ok(acct) = s.app.account(&did).await else { panic!("{ctx}: no account") };
    let key = format!("did:key:{}", acct.signing_pubkey);
    let cc = CommitCtx { space: &space, author: &did, rev: &c.rev };
    assert!(commit::verify(&c, &cc, &key), "{ctx}: the commit doesn't verify");
    let mut revs: Vec<&str> = ops.iter().map(|o| o["rev"].as_str().unwrap()).collect();
    assert!(revs.is_sorted(), "{ctx}: ops out of rev order");
    revs.dedup();
    assert_eq!(revs.last().copied(), Some(c.rev.as_str()), "{ctx}: the newest op isn't at the commit's rev");

    // the delta from the last checkpoint, onto the hash kept from then
    if let Some((rev, mut held)) = a.repos[r].synced.take() {
        let (delta, dj) = pull(a, &space, Some(&rev), 100, &ctx).await;
        for op in &delta {
            assert!(op["rev"].as_str().unwrap() > rev.as_str(), "{ctx}: an op at or before since {rev}");
            fold(&mut held, op);
        }
        assert!(commit::matches(&held, &signed_commit(&dj)), "{ctx}: the delta since {rev} folds wrong");
    }
    // a no-op poll: nothing, and the commit
    let (none, nj) = pull(a, &space, Some(&c.rev), 100, &ctx).await;
    assert!(none.is_empty(), "{ctx}: ops after the head: {none:?}");
    assert_eq!(nj["rev"], json!(c.rev), "{ctx}: the no-op poll's commit");
    assert_eq!(bytes_field(&nj["hash"]), c.hash, "{ctx}: the no-op poll's hash");
    let latest = a.read("com.atproto.space.getLatestCommit", &space, &[]).await;
    assert_eq!(latest.status, 200, "{ctx}: getLatestCommit: {}", latest.text());
    assert_eq!(signed_commit(&latest.json["commit"]).hash, c.hash, "{ctx}: getLatestCommit's hash");
    a.repos[r].synced = Some((c.rev.clone(), set));

    let chk =
        s.xrpc.get("vlpds.admin.checkSpace", &[("did", did.as_str()), ("space", space.as_str())], &Auth::Admin).await;
    assert_eq!(chk.status, 200, "{ctx}: checkSpace: {}", chk.text());
    assert_eq!(chk.json["ok"], json!(true), "{ctx}: checkSpace: {}", chk.json);
    assert_eq!(chk.json["records"]["count"], json!(want.len()), "{ctx}: checkSpace count");

    if checks.get_repo {
        check_get_repo(a, &space, &want, &ctx).await;
    }
}

/// The account's s* rows in its shard.
async fn space_rows(s: &TestServer, did: &str) -> Vec<String> {
    let p = s.app.partition(did).unwrap_or_else(|_| panic!("{did}'s shard isn't owned here"));
    let slot = vlsync_store::slots::slot_of(did);
    let mut found = Vec::new();
    for fam in SPACE_FAMILIES {
        let mut prefix = vlsync_store::keys::slot_family(slot, fam);
        prefix.extend_from_slice(did.as_bytes());
        prefix.push(0);
        let mut it = p.db.scan(prefix.clone()..vlsync_store::keys::prefix_end(&prefix)).await.unwrap();
        while let Some(kv) = it.next().await.unwrap() {
            found.push(format!("{}{}", String::from_utf8_lossy(fam), hex::encode(&kv.key[prefix.len()..])));
        }
    }
    found
}

async fn run(seed: u64, steps: usize, checks: Checks) {
    let s = TestServer::spawn_with(|c| c.spaces = true).await;
    let mut rng = StdRng::seed_from_u64(seed);
    let mut accounts = Vec::new();
    for i in 0..ACCOUNTS {
        accounts.push(Account::new(&s, i).await);
    }
    for step in 0..steps {
        // one write per account, concurrently: each repo's model only
        // follows its own account
        let plans: Vec<(usize, Planned)> = accounts
            .iter()
            .map(|a| {
                let r = rng.gen_range(0..SPACES);
                (r, a.plan(r, &mut rng))
            })
            .collect();
        let ctx = format!("seed {seed} step {step}");
        futures::future::join_all(accounts.iter_mut().zip(plans).map(|(a, (r, p))| a.apply(r, p, &ctx))).await;
        if (step + 1) % CHECK_EVERY == 0 || step + 1 == steps {
            for a in accounts.iter_mut() {
                for r in 0..SPACES {
                    checkpoint(&s, a, r, checks, &ctx).await;
                }
            }
        }
    }
    let total: usize = accounts.iter().flat_map(|a| a.repos.iter().map(|r| r.records.len())).sum();
    eprintln!("space fuzz seed {seed}: {steps} steps, {total} records left");

    if checks.delete_sweep {
        for a in &accounts {
            assert!(!space_rows(&s, &a.sc.did).await.is_empty(), "seed {seed}: no s* rows before the delete");
            s.xrpc.post("com.atproto.admin.deleteAccount", &json!({"did": a.sc.did}), &Auth::Admin).await.ok();
        }
        for a in &accounts {
            let did = &a.sc.did;
            let deadline = std::time::Instant::now() + Duration::from_secs(20);
            loop {
                let left = space_rows(&s, did).await;
                if left.is_empty() {
                    break;
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "seed {seed}: {} s* row(s) of {did} left after deleteAccount, e.g. {:?}",
                    left.len(),
                    &left[..left.len().min(5)]
                );
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

fn seeds(default: u64) -> Vec<u64> {
    match std::env::var("VLPDS_SPACE_FUZZ_SEED").ok().and_then(|v| v.parse().ok()) {
        Some(seed) => vec![seed],
        None => (0..env_or("VLPDS_SPACE_FUZZ_SEEDS", default)).collect(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn space_op_sequences_replay_to_their_commits() {
    for seed in seeds(2) {
        run(seed, env_or("VLPDS_SPACE_FUZZ_STEPS", 60), Checks::default()).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn space_op_sequences_match_get_repo() {
    for seed in seeds(1) {
        run(1000 + seed, env_or("VLPDS_SPACE_FUZZ_STEPS", 50), Checks { get_repo: true, ..Default::default() }).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delete_account_leaves_no_space_rows() {
    for seed in seeds(1) {
        run(2000 + seed, env_or("VLPDS_SPACE_FUZZ_STEPS", 30), Checks { delete_sweep: true, ..Default::default() })
            .await;
    }
}

/// `cargo test --test all spaces_side::fuzz::soak -- --ignored --nocapture`
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "soak (minutes)"]
async fn soak() {
    for seed in seeds(8) {
        run(3000 + seed, env_or("VLPDS_SPACE_FUZZ_STEPS", 1500), Checks { get_repo: true, delete_sweep: true }).await;
    }
}
