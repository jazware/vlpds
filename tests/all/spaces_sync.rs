//! Space sync at scale (`--spaces`; src/space/car.rs, fanout.rs,
//! retention.rs, outbox.rs): getRepo's streamed 2-root CAR and the record
//! cap behind it, oplog paging and what a pruned oplog does to a syncer,
//! forwards to registered services that one slow service can't hold up,
//! and a writer's notify crossing to the authority's node in a cluster.

use crate::common::spaces::{resp, SpaceClient};
use crate::common::*;
use axum::body::Body;
use axum::extract::Request;
use axum::response::Response;
use base64::Engine;
use parking_lot::Mutex;
use std::sync::Arc;
use std::time::{Duration, Instant};
use vlpds::space::{commit, lthash::LtHash};
use vlsync_atproto::cbor::Value;

const TYPE: &str = "com.example.group";
const COLL: &str = "com.example.post";
const OTHER: &str = "com.example.note";
const OWNER: &str = "space:com.example.group?collection=com.example.post&collection=com.example.note&action=read&action=create&action=update&action=delete&manage=create&manage=update";
const ANY: &str = "space:com.example.group?authority=*&collection=com.example.post&action=read&action=create&action=update&action=delete";

fn rec(text: &str) -> J {
    json!({"$type": COLL, "text": text, "createdAt": "2026-10-01T00:00:00.000Z"})
}

fn note(text: &str) -> J {
    json!({"$type": OTHER, "text": text, "createdAt": "2026-10-01T00:00:00.000Z"})
}

async fn spawn() -> TestServer {
    TestServer::spawn_with(|c| c.spaces = true).await
}

async fn put_member(owner: &SpaceClient, space: &str, did: &str) {
    owner
        .post("com.atproto.simplespace.putMember", json!({"space": space, "did": did, "read": true, "write": true}))
        .await
        .ok();
}

fn bytes(v: &J) -> Vec<u8> {
    let s = v["$bytes"].as_str().unwrap_or_else(|| panic!("not $bytes: {v}"));
    base64::engine::general_purpose::STANDARD_NO_PAD.decode(s.trim_end_matches('=')).unwrap()
}

fn signed_commit(c: &J) -> commit::SignedCommit {
    commit::SignedCommit {
        ver: c["ver"].as_i64().unwrap(),
        hash: bytes(&c["hash"]),
        ikm: bytes(&c["ikm"]),
        sig: bytes(&c["sig"]),
        mac: bytes(&c["mac"]),
        rev: c["rev"].as_str().unwrap().to_string(),
    }
}

/// The account's `#atproto` key as a did:key.
async fn did_key(s: &TestServer, did: &str) -> String {
    let j = s.xrpc.get("com.atproto.repo.describeRepo", &[("repo", did)], &Auth::None).await.ok();
    let vm = j["didDoc"]["verificationMethod"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["id"].as_str().is_some_and(|i| i.ends_with("#atproto")))
        .unwrap()
        .clone();
    format!("did:key:{}", vm["publicKeyMultibase"].as_str().unwrap())
}

fn apply_ops(set: &mut LtHash, ops: &J) {
    for op in ops.as_array().unwrap() {
        let (c, r) = (op["collection"].as_str().unwrap(), op["rkey"].as_str().unwrap());
        if let Some(p) = op["prev"].as_str() {
            set.remove(&commit::element(c, r, p));
        }
        if let Some(n) = op["cid"].as_str() {
            set.add(&commit::element(c, r, n));
        }
    }
}

async fn metrics_text(s: &TestServer) -> String {
    reqwest::get(format!("{}/metrics", s.url)).await.unwrap().text().await.unwrap()
}

fn scraped(text: &str, series: &str) -> f64 {
    text.lines().find_map(|l| l.strip_prefix(series).and_then(|v| v.trim().parse().ok())).unwrap_or(0.0)
}

async fn eventually<F, Fut>(within: Duration, mut f: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = Instant::now() + within;
    loop {
        if f().await {
            return true;
        }
        if Instant::now() > deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// What a verified getRepo CAR holds.
struct Car {
    commit: commit::SignedCommit,
    paths: Vec<String>,
    index_root: vlsync_atproto::cid::Cid,
    blocks: usize,
}

/// Checks a getRepo CAR as the reference's `verifyRepoCar` does: the
/// commit then the index lead, the commit verifies, the index is in
/// canonical order and folds to the commit's hash, and each record block
/// follows the index (`values`) or none do.
fn verify_car(car: &[u8], space: &str, author: &str, key: &str, values: bool) -> Car {
    let (roots, blocks) = vlsync_atproto::car::read_car(car).unwrap();
    assert_eq!(roots.len(), 2, "two roots");
    assert_eq!((blocks[0].0, blocks[1].0), (roots[0], roots[1]), "commit, then index");
    let sc = signed_commit(&Value::decode(blocks[0].1).unwrap().to_json());
    let ctx = commit::CommitCtx { space, author, rev: &sc.rev };
    assert!(commit::verify(&sc, &ctx, key), "the commit verifies");
    let entries: Vec<(String, vlsync_atproto::cid::Cid)> = match Value::decode(blocks[1].1).unwrap() {
        Value::Map(m) => m
            .into_iter()
            .map(|(k, v)| match v {
                Value::Link(c) => (k, c),
                other => panic!("index value {other:?}"),
            })
            .collect(),
        other => panic!("index: {other:?}"),
    };
    let paths: Vec<String> = entries.iter().map(|e| e.0.clone()).collect();
    let mut sorted = paths.clone();
    sorted.sort_by(|a, b| vlsync_atproto::cbor::key_cmp(a, b));
    assert_eq!(paths, sorted, "index in length-first canonical order");
    let mut set = LtHash::default();
    for (p, cid) in &entries {
        let (c, r) = p.split_once('/').unwrap();
        set.add(&commit::element(c, r, &cid.to_string()));
    }
    assert!(commit::matches(&set, &sc), "the index folds to the commit's hash");
    if values {
        assert_eq!(blocks.len(), 2 + entries.len());
        for ((_, cid), (bc, data)) in entries.iter().zip(&blocks[2..]) {
            assert_eq!(cid, bc, "blocks follow the index");
            assert!(vlsync_atproto::car::block_matches(bc, data));
        }
    } else {
        assert_eq!(blocks.len(), 2, "index only");
    }
    Car { commit: sc, paths, index_root: roots[1], blocks: blocks.len() }
}

/// getRepo through a credential: a CAR that verifies like the reference's
/// consumer wants it, index-only with excludeValues, RepoNotFound for a
/// repo never written, and nothing without a credential for the space.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn get_repo_streams_a_verifiable_car() {
    let s = spawn().await;
    let owner = SpaceClient::new(&s, "ssg1", OWNER).await;
    let member = SpaceClient::new(&s, "ssg2", ANY).await;
    let space = owner.create_space(TYPE, "car").await;
    let other = owner.create_space(TYPE, "elsewhere").await;
    put_member(&owner, &space, &member.did).await;
    for rkey in ["b", "aa", "a", "zzzzzz", "c", "3k2abcdefgh2a", "m"] {
        member.create_record(&space, COLL, Some(rkey), rec(rkey)).await.ok();
    }
    member.put_record(&space, COLL, "a", rec("a again")).await.ok();
    member.delete_record(&space, COLL, "c").await.ok();
    let key = did_key(&s, &member.did).await;
    let cred = owner.credential(&space).await;
    let get = |extra: &'static [(&'static str, &'static str)], cred: String, repo: String| {
        let (owner, space, url) = (&owner, space.clone(), s.url.clone());
        async move {
            let mut q = vec![("space", space.as_str()), ("repo", repo.as_str())];
            q.extend_from_slice(extra);
            owner.signed_get(&url, "com.atproto.space.getRepo", &q, &cred, &repo).await
        }
    };
    let r = get(&[], cred.clone(), member.did.clone()).await;
    assert_eq!(r.status, 200, "{r:?}");
    assert_eq!(r.headers["content-type"], "application/vnd.ipld.car");
    let full = verify_car(&r.body, &space, &member.did, &key, true);
    assert_eq!(full.paths.len(), 6);
    assert_eq!(full.paths[0], format!("{COLL}/a"));
    assert_eq!(full.paths.last().unwrap(), &format!("{COLL}/3k2abcdefgh2a"));
    let head = member.get("com.atproto.space.getLatestCommit", &[("space", &space), ("repo", &member.did)]).await;
    assert_eq!(head.ok()["commit"]["rev"], json!(full.commit.rev));
    // the owner's own export, as OAuth read_self
    let (status, _, car) =
        member.get_raw("com.atproto.space.getRepo", &[("space", &space), ("repo", &member.did)]).await;
    assert_eq!(status, 200);
    assert_eq!(verify_car(&car, &space, &member.did, &key, true).index_root, full.index_root);

    let r = get(&[("excludeValues", "true")], cred.clone(), member.did.clone()).await;
    let idx = verify_car(&r.body, &space, &member.did, &key, false);
    assert_eq!((idx.index_root, idx.blocks), (full.index_root, 2));

    // the owner never wrote here
    get(&[], cred.clone(), owner.did.clone()).await.err(400, "RepoNotFound");
    // another space's credential, and none at all
    let foreign = owner.credential(&other).await;
    get(&[], foreign, member.did.clone()).await.err(400, "InvalidCredential");
    let url = crate::common::spaces::xrpc_url(
        &s.url,
        "com.atproto.space.getRepo",
        &[("space", &space), ("repo", &member.did)],
    );
    let r = resp(reqwest::get(&url).await.unwrap()).await;
    assert_eq!(r.status, 401, "{r:?}");
}

/// A syncer's reads of one repo in a space, through a credential.
struct Viewer<'a> {
    s: &'a TestServer,
    owner: &'a SpaceClient,
    cred: String,
    space: String,
    repo: String,
    key: String,
}

impl Viewer<'_> {
    async fn read(&self, nsid: &str, extra: &[(&str, &str)]) -> Resp {
        let mut q = vec![("space", self.space.as_str()), ("repo", self.repo.as_str())];
        q.extend_from_slice(extra);
        self.owner.signed_get(&self.s.url, nsid, &q, &self.cred, &self.repo).await
    }

    /// getRepo, the ops replayed page by page, and the latest commit and an
    /// at-head poll: all must agree.
    async fn view(&self, values: bool) -> Car {
        let extra: &[(&str, &str)] = if values { &[] } else { &[("excludeValues", "true")] };
        let r = self.read("com.atproto.space.getRepo", extra).await;
        assert_eq!(r.status, 200, "{r:?}");
        assert_eq!(r.headers["content-type"], "application/vnd.ipld.car", "{r:?}");
        let car = verify_car(&r.body, &self.space, &self.repo, &self.key, values);
        let mut set = LtHash::default();
        let mut cursor: Option<String> = None;
        let last = loop {
            let mut extra = vec![("limit", "2")];
            if let Some(c) = &cursor {
                extra.push(("cursor", c.as_str()));
            }
            let page = self.read("com.atproto.space.listRepoOps", &extra).await.ok();
            apply_ops(&mut set, &page["ops"]);
            match page["cursor"].as_str() {
                Some(c) => cursor = Some(c.to_string()),
                None => break page["commit"].clone(),
            }
        };
        let ops_commit = signed_commit(&last);
        let ctx = commit::CommitCtx { space: &self.space, author: &self.repo, rev: &ops_commit.rev };
        assert!(commit::verify(&ops_commit, &ctx, &self.key));
        assert!(commit::matches(&set, &ops_commit), "the ops replay to the signed hash");
        assert_eq!(ops_commit.hash, car.commit.hash, "listRepoOps and getRepo agree");
        let latest = self.read("com.atproto.space.getLatestCommit", &[]).await.ok();
        assert_eq!(bytes(&latest["commit"]["hash"]), car.commit.hash);
        let noop = self.read("com.atproto.space.listRepoOps", &[("since", &car.commit.rev)]).await.ok();
        assert_eq!(noop["ops"], json!([]));
        assert_eq!(bytes(&noop["commit"]["hash"]), car.commit.hash, "the at-head poll signs the same view");
        car
    }
}

/// A record takedown (a vlpds extension) serves a view without the record
/// that still verifies: getRepo's index and blocks leave it out and fold
/// to the signed hash, listRepoOps leaves its ops out and replays to the
/// same hash as getLatestCommit, and a syncer holding the old view sees a
/// mismatch at the same rev. Reversing it serves the full repo again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn record_takedown_serves_a_consistent_view() {
    let s = spawn().await;
    let owner = SpaceClient::new(&s, "sstd1", OWNER).await;
    let member = SpaceClient::new(&s, "sstd2", ANY).await;
    let space = owner.create_space(TYPE, "td").await;
    put_member(&owner, &space, &member.did).await;
    for rkey in ["a", "b", "c"] {
        member.create_record(&space, COLL, Some(rkey), rec(rkey)).await.ok();
    }
    member.put_record(&space, COLL, "b", rec("b again")).await.ok();
    let key = did_key(&s, &member.did).await;
    let v = Viewer {
        s: &s,
        owner: &owner,
        cred: owner.credential(&space).await,
        space: space.clone(),
        repo: member.did.clone(),
        key,
    };
    let view = |values: bool| v.view(values);
    let full = view(true).await;
    assert_eq!(full.paths, [format!("{COLL}/a"), format!("{COLL}/b"), format!("{COLL}/c")]);

    let uri = format!("{space}/{}/{COLL}/b", member.did);
    let set = |applied: bool| {
        let body = json!({
            "subject": {"$type": "com.atproto.repo.strongRef", "uri": uri, "cid": "bafyreie5737gdxlw5i64vzichcalba3z2v5n6icifvx5xytvske7mr3hpm"},
            "takedown": {"applied": applied, "ref": "t"},
        });
        let s = &s;
        async move { s.xrpc.post("com.atproto.admin.updateSubjectStatus", &body, &Auth::Admin).await.ok() }
    };
    set(true).await;
    let hidden = view(true).await;
    assert_eq!(hidden.paths, [format!("{COLL}/a"), format!("{COLL}/c")]);
    assert_eq!(hidden.commit.rev, full.commit.rev);
    assert_ne!(hidden.commit.hash, full.commit.hash, "a syncer holding b mismatches at the same rev");
    assert_eq!(view(false).await.paths, hidden.paths);
    // a write while it's hidden keeps the view consistent
    member.create_record(&space, COLL, Some("d"), rec("d")).await.ok();
    assert_eq!(view(true).await.paths, [format!("{COLL}/a"), format!("{COLL}/c"), format!("{COLL}/d")]);
    set(false).await;
    let back = view(true).await;
    assert_eq!(back.paths.len(), 4);
}

/// A 100k-record space repo: the next create is refused, and getRepo
/// streams it holding only its paths and CIDs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_full_repo_streams_under_a_memory_bound() {
    const BOUND: &str = "33554432";
    let s = spawn().await;
    let owner = SpaceClient::new(&s, "ssb1", OWNER).await;
    let space = owner.create_space(TYPE, "big").await;
    let max = vlpds::space::DEFAULT_MAX_RECORDS as usize;
    for batch in 0..max / 200 {
        let writes: Vec<J> = (0..200)
            .map(|i| {
                let n = batch * 200 + i;
                let (coll, value) = if n % 3 == 0 { (OTHER, note("n")) } else { (COLL, rec("r")) };
                json!({"$type": "com.atproto.space.applyWrites#create", "collection": coll, "rkey": format!("k{n}"), "value": value})
            })
            .collect();
        owner.apply_writes(&space, json!(writes)).await.ok();
    }
    let r = owner.create_record(&space, COLL, Some("one-more"), rec("x")).await;
    r.err(400, "InvalidRequest");
    assert!(r.json["message"].as_str().unwrap().contains("limit"), "{r:?}");
    // trimming and replacing still work at the cap
    owner.delete_record(&space, COLL, "k1").await.ok();
    owner.create_record(&space, COLL, Some("k1"), rec("back")).await.ok();

    let before = metrics_text(&s).await;
    let count = "vlpds_space_export_bytes_count";
    let (status, _, car) = owner.get_raw("com.atproto.space.getRepo", &[("space", &space), ("repo", &owner.did)]).await;
    assert_eq!(status, 200);
    let key = did_key(&s, &owner.did).await;
    let got = verify_car(&car, &space, &owner.did, &key, true);
    assert_eq!(got.paths.len(), max);
    let after = metrics_text(&s).await;
    assert!(scraped(&after, count) > scraped(&before, count));
    let bucket = |t: &str, le: &str| scraped(t, &format!("vlpds_space_export_bytes_bucket{{le=\"{le}\"}}"));
    assert_eq!(scraped(&after, count), bucket(&after, BOUND), "an export held more than 32 MiB");
    assert!(bucket(&after, "4194304") < scraped(&after, count), "the big export was measured");
    // it fit the memory plan's estimate for a full repo, and gave its room back
    let planned = vlpds::space::export_bytes(max as u64);
    assert!(planned < 32 << 20 && planned > 8 << 20, "{planned}");
    let sp = s.app.spaces.as_ref().unwrap();
    assert!(eventually(Duration::from_secs(5), || async { sp.export_room_free().0 == sp.export_room_free().1 }).await);
}

/// A space getRepo takes its room from the memory plan's space exports,
/// gives it back when its body is done, and is shed when there's none.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_space_export_holds_its_memory_room() {
    let s = spawn().await;
    let owner = SpaceClient::new(&s, "ssroom", OWNER).await;
    let space = owner.create_space(TYPE, "room").await;
    owner.create_record(&space, COLL, Some("a"), rec("a")).await.ok();
    let sp = s.app.spaces.as_ref().unwrap();
    let (free, total) = sp.export_room_free();
    assert_eq!(free, total);
    assert_eq!(total as u64, vlpds::space::export_budget_bytes(vlpds::space::DEFAULT_MAX_RECORDS).div_ceil(1024));
    // a 1-record export, and a few KiB for its vectors' first growth
    let held = vlpds::space::export_bytes(1).div_ceil(1024) as usize + 8;
    let room = sp.reserve_export((total - held) as u64 * 1024).await.expect("the rest of the room");
    let r = owner.get_raw("com.atproto.space.getRepo", &[("space", &space), ("repo", &owner.did)]).await;
    assert_eq!(r.0, 200, "an export that fits the room left");
    assert!(eventually(Duration::from_secs(5), || async { sp.export_room_free().0 == held }).await);
    drop(room);
    assert_eq!(sp.export_room_free().0, total);
    // with no room at all, the export is shed after a short wait
    let all = sp.reserve_export(total as u64 * 1024).await.unwrap();
    let r = owner.get("com.atproto.space.getRepo", &[("space", &space), ("repo", &owner.did)]).await;
    r.err(503, "Overloaded");
    drop(all);
}

/// listRepoOps pages one big rev without losing an op, holds the commit
/// back until the last page, honours since and cursor together, refuses a
/// malformed cursor, and inlines a value only while it's current.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn oplog_paging() {
    let s = spawn().await;
    let owner = SpaceClient::new(&s, "ssp1", OWNER).await;
    let space = owner.create_space(TYPE, "ops").await;
    let key = did_key(&s, &owner.did).await;
    owner.create_record(&space, COLL, Some("first"), rec("first")).await.ok();
    let since = owner.get("com.atproto.space.getLatestCommit", &[("space", &space), ("repo", &owner.did)]).await.ok()
        ["commit"]["rev"]
        .as_str()
        .unwrap()
        .to_string();
    let writes: Vec<J> = (0..200)
        .map(|i| json!({"$type": "com.atproto.space.applyWrites#create", "collection": COLL, "rkey": format!("r{i:03}"), "value": rec(&format!("v{i}"))}))
        .collect();
    owner.apply_writes(&space, json!(writes)).await.ok();
    owner.put_record(&space, COLL, "r007", rec("newer")).await.ok();

    let mut ops = Vec::new();
    let mut cursor: Option<String> = None;
    let commit = loop {
        let mut q =
            vec![("space", space.as_str()), ("repo", owner.did.as_str()), ("since", since.as_str()), ("limit", "7")];
        if let Some(c) = &cursor {
            q.push(("cursor", c.as_str()));
        }
        let r = owner.get("com.atproto.space.listRepoOps", &q).await.ok();
        let page = r["ops"].as_array().unwrap().clone();
        ops.extend(page.iter().cloned());
        match r.get("cursor").and_then(|c| c.as_str()) {
            Some(c) => {
                assert!(r.get("commit").is_none(), "a full page withholds the commit");
                assert_eq!(page.len(), 7);
                cursor = Some(c.to_string());
            }
            None => break r["commit"].clone(),
        }
    };
    assert_eq!(ops.len(), 201, "every op after since, the first write's not");
    let big_rev = ops[0]["rev"].clone();
    assert!(ops[..200].iter().all(|o| o["rev"] == big_rev), "one rev for the batch");
    let rkeys: Vec<&str> = ops[..200].iter().map(|o| o["rkey"].as_str().unwrap()).collect();
    assert_eq!(rkeys, (0..200).map(|i| format!("r{i:03}")).collect::<Vec<_>>());
    // r007's create is superseded: no value; its update has one
    assert!(ops[7].get("value").is_none(), "{}", ops[7]);
    assert_eq!(ops[200]["value"]["text"], json!("newer"));
    assert_eq!(ops[8]["value"]["text"], json!("v8"));
    // the ops replay onto the state at `since` to the commit's hash
    let mut set = LtHash::default();
    set.add(&commit::element(COLL, "first", ops_cid_of_first(&owner, &space).await.as_str()));
    apply_ops(&mut set, &J::Array(ops));
    let sc = signed_commit(&commit);
    assert!(commit::verify(&sc, &commit::CommitCtx { space: &space, author: &owner.did, rev: &sc.rev }, &key));
    assert!(commit::matches(&set, &sc));

    for bad in ["nope", "3k2abcdefgh2a", "3k2abcdefgh2a/x", "x/1"] {
        let q = [("space", space.as_str()), ("repo", owner.did.as_str()), ("cursor", bad)];
        owner.get("com.atproto.space.listRepoOps", &q).await.err(400, "MalformedCursor");
    }
}

async fn ops_cid_of_first(c: &SpaceClient, space: &str) -> String {
    let q = [("space", space), ("repo", c.did.as_str()), ("collection", COLL), ("rkey", "first")];
    c.get("com.atproto.space.getRecord", &q).await.ok()["cid"].as_str().unwrap().to_string()
}

/// Ops pruned past the retention window: a syncer behind it replays what's
/// left, its hash doesn't match, and getRepo puts it right.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pruned_oplog_sends_syncers_to_get_repo() {
    let s = spawn().await;
    let owner = SpaceClient::new(&s, "ssr1", OWNER).await;
    let space = owner.create_space(TYPE, "ret").await;
    let key = did_key(&s, &owner.did).await;
    let rq = [("space", space.as_str()), ("repo", owner.did.as_str())];
    owner.create_record(&space, COLL, Some("a"), rec("a")).await.ok();
    owner.create_record(&space, COLL, Some("b"), rec("b")).await.ok();
    let r = owner.get("com.atproto.space.listRepoOps", &rq).await.ok();
    let mut synced = LtHash::default();
    apply_ops(&mut synced, &r["ops"]);
    let since = r["commit"]["rev"].as_str().unwrap().to_string();

    // the syncer falls behind; the window passes over its ops and more
    owner.create_record(&space, COLL, Some("c"), rec("c")).await.ok();
    owner.delete_record(&space, COLL, "a").await.ok();
    let pruned = vlpds::space::retention::prune_before(&s.app, vlsync_atproto::tid::now_micros() + 1).await.unwrap();
    assert!(pruned >= 4, "{pruned}");
    owner.create_record(&space, COLL, Some("d"), rec("d")).await.ok();

    let q = [("space", space.as_str()), ("repo", owner.did.as_str()), ("since", since.as_str())];
    let r = owner.get("com.atproto.space.listRepoOps", &q).await.ok();
    assert_eq!(r["ops"].as_array().unwrap().len(), 1, "from the window's start: {r}");
    assert_eq!(r["ops"][0]["rkey"], json!("d"));
    apply_ops(&mut synced, &r["ops"]);
    let sc = signed_commit(&r["commit"]);
    assert!(!commit::matches(&synced, &sc), "the digest mismatches");

    let (status, _, car) = owner.get_raw("com.atproto.space.getRepo", &rq).await;
    assert_eq!(status, 200);
    let got = verify_car(&car, &space, &owner.did, &key, true);
    assert_eq!(got.commit.hash, sc.hash, "getRepo reconciles");
    assert_eq!(got.paths, vec![format!("{COLL}/b"), format!("{COLL}/c"), format!("{COLL}/d")]);
    // nothing is left to prune
    assert_eq!(vlpds::space::retention::prune_before(&s.app, 1).await.unwrap(), 0);
}

#[derive(Clone)]
struct Arrival {
    at: Instant,
    body: J,
}

/// A did:web syncer on loopback recording each notifyWrite as it arrives,
/// then answering after `stall`.
struct Syncer {
    did: String,
    seen: Arc<Mutex<Vec<Arrival>>>,
}

impl Syncer {
    async fn start(stall: Duration) -> Syncer {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let (base, did) = (format!("http://{addr}"), format!("did:web:127.0.0.1%3A{}", addr.port()));
        let seen: Arc<Mutex<Vec<Arrival>>> = Default::default();
        let (s, d) = (seen.clone(), did.clone());
        let router = axum::Router::new().fallback(move |req: Request| {
            let (s, d, b) = (s.clone(), d.clone(), base.clone());
            async move {
                let json = |body: J| {
                    Response::builder()
                        .header("content-type", "application/json")
                        .body(Body::from(body.to_string()))
                        .unwrap()
                };
                if req.uri().path() == "/.well-known/did.json" {
                    return json(
                        json!({"id": d, "service": [{"id": "#sync", "type": "SpaceSyncer", "serviceEndpoint": b}]}),
                    );
                }
                let at = Instant::now();
                let body = axum::body::to_bytes(req.into_body(), 1 << 20).await.unwrap();
                s.lock().push(Arrival { at, body: serde_json::from_slice(&body).unwrap_or(J::Null) });
                tokio::time::sleep(stall).await;
                json(json!({}))
            }
        });
        tokio::spawn(async move { axum::serve(l, router).await.unwrap() });
        Syncer { did, seen }
    }

    fn service(&self) -> String {
        format!("{}#sync", self.did)
    }

    fn arrivals(&self) -> Vec<Arrival> {
        self.seen.lock().clone()
    }

    /// When this syncer first heard of a state at or past `rev`.
    fn learned(&self, rev: &str) -> Option<Instant> {
        self.arrivals().iter().filter(|a| a.body["repoRev"].as_str().is_some_and(|r| r >= rev)).map(|a| a.at).min()
    }
}

/// Three syncers, one answering after 10 s: the other two hear of every
/// write within 200 ms (p99), the slow one gets a few coalesced sends
/// ending at the newest rev, and an expired registration gets nothing and
/// is pruned.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_slow_syncer_holds_up_nobody() {
    let s = spawn().await;
    let owner = SpaceClient::new(&s, "ssf1", OWNER).await;
    let space = owner.create_space(TYPE, "fan").await;
    let cred = owner.credential(&space).await;
    let fast = [Syncer::start(Duration::ZERO).await, Syncer::start(Duration::ZERO).await];
    let slow = Syncer::start(Duration::from_secs(10)).await;
    let expired = Syncer::start(Duration::ZERO).await;
    for sy in fast.iter().chain([&slow, &expired]) {
        let body = json!({"space": space, "service": sy.service()});
        owner.signed_post(&s.url, "com.atproto.space.registerNotify", body, &cred, &owner.did).await.ok();
    }
    let p = s.app.partition(&owner.did).ok().unwrap();
    let sid = vlpds::state::space_id(&space);
    let nkey = vlpds::state::space_notify_key(&owner.did, &sid, &expired.service());
    vlpds::xrpc::space::set_registration_expiry(
        &s.app,
        &space,
        &expired.service(),
        vlsync_atproto::tid::now_micros() - 1,
    )
    .await
    .unwrap();

    // the slow one is stuck on the first write while 50 more land
    let mut acks = Vec::new();
    for i in 0..51 {
        let rkey = format!("w{i:02}");
        owner.create_record(&space, COLL, Some(&rkey), rec(&rkey)).await.ok();
        acks.push((rkey, Instant::now()));
        if i == 0 {
            assert!(eventually(Duration::from_secs(5), || async { !slow.arrivals().is_empty() }).await);
        }
    }
    let ops = owner.get("com.atproto.space.listRepoOps", &[("space", &space), ("repo", &owner.did)]).await.ok();
    let rev_of = |rkey: &str| {
        ops["ops"].as_array().unwrap().iter().find(|o| o["rkey"] == json!(rkey)).unwrap()["rev"]
            .as_str()
            .unwrap()
            .to_string()
    };
    let newest = rev_of("w50");
    for sy in &fast {
        assert!(eventually(Duration::from_secs(5), || async { sy.learned(&newest).is_some() }).await);
        let mut lat: Vec<Duration> =
            acks.iter().map(|(rkey, at)| sy.learned(&rev_of(rkey)).unwrap().saturating_duration_since(*at)).collect();
        lat.sort();
        let p99 = lat[(lat.len() * 99).div_ceil(100) - 1];
        assert!(p99 < Duration::from_millis(200), "a fast syncer waited {p99:?} (p99)");
        // in spaceRev order, each naming the last one it was sent: within
        // one lease, since a new lease's first forward names the true
        // predecessor
        let a = sy.arrivals();
        let chain: Vec<_> = a.iter().map(|x| (x.body["prevSpaceRev"].clone(), x.body["spaceRev"].clone())).collect();
        let epoch = s.app.partition(&owner.did).ok().map(|q| q.epoch);
        let one_lease = epoch == Some(p.epoch);
        for w in a.windows(2) {
            assert!(w[1].body["spaceRev"].as_str() > w[0].body["spaceRev"].as_str(), "out of order: {chain:?}");
            if one_lease {
                assert_eq!(w[1].body["prevSpaceRev"], w[0].body["spaceRev"], "no gap: {chain:?}");
            }
        }
        if !one_lease {
            eprintln!("the shard's lease moved mid-run (epoch {} -> {epoch:?}): gaps allowed", p.epoch);
        }
    }
    assert!(eventually(Duration::from_secs(15), || async { slow.learned(&newest).is_some() }).await);
    let sent = slow.arrivals();
    assert!(sent.len() <= 3, "{} sends to the slow syncer", sent.len());
    assert_eq!(sent.last().unwrap().body["repoRev"], json!(newest), "the last send is the newest");
    assert!(expired.arrivals().is_empty(), "an expired registration got a forward");
    assert!(eventually(Duration::from_secs(5), || async { p.db.get(&nkey).await.unwrap().is_none() }).await);
}

/// A cluster node's account owned by `node`: a fresh one until it lands
/// there (OAuth tokens name the node that issued them).
async fn owned_by(node: &TestServer, nodes: &[&TestServer], name: &str, scope: &str) -> SpaceClient {
    for i in 0..20 {
        let c = SpaceClient::new(node, &format!("{name}{i}"), scope).await;
        if std::ptr::eq(owner_of(nodes, &c.did), node) {
            return c;
        }
    }
    panic!("no account landed on {}", node.url);
}

/// The writer's node tells the authority's node over the peer link (no
/// HTTP, no service auth), and space host methods entering at the wrong
/// node reach the authority's owner.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_notify_crosses_to_the_authoritys_node() {
    let plc = vlpds::plc::mock::MockPlc::start().await;
    let rotation = Arc::new(vlsync_atproto::crypto::Keypair::generate());
    let store: Arc<dyn object_store::ObjectStore> = Arc::new(object_store::memory::InMemory::new());
    let cfg = |c: &mut vlpds::server::Config| {
        use_plc(c, plc.url.clone(), rotation.clone());
        c.spaces = true;
    };
    let x = cluster_node("ssx", store.clone(), 8, cfg).await;
    let y = cluster_node("ssy", store.clone(), 8, cfg).await;
    balanced(&[&x, &y]).await;
    let nodes = [&x, &y];
    let owner = owned_by(&y, &nodes, "ssco", OWNER).await;
    let member = owned_by(&x, &nodes, "sscm", ANY).await;
    let space = owner.create_space(TYPE, "cluster").await;
    put_member(&owner, &space, &member.did).await;

    // getSpaceCredential and credential calls at x, the authority on y
    let cred = member.credential_at(&x.url, &space).await;
    let r =
        member.signed_get(&x.url, "com.atproto.simplespace.getSpace", &[("space", &space)], &cred, &owner.did).await;
    assert_eq!(r.ok()["uri"], json!(space));
    let repos = || async {
        let r = member.signed_get(&x.url, "com.atproto.space.listRepos", &[("space", &space)], &cred, &owner.did).await;
        r.ok()["repos"].as_array().unwrap().clone()
    };
    assert!(repos().await.is_empty());

    member.create_record(&space, COLL, Some("1"), rec("from x")).await.ok();
    let head = member.get("com.atproto.space.getLatestCommit", &[("space", &space), ("repo", &member.did)]).await.ok()
        ["commit"]["rev"]
        .clone();
    assert!(
        eventually(Duration::from_secs(10), || async {
            repos().await.iter().any(|r| r["did"] == json!(member.did) && r["repoRev"] == head)
        })
        .await,
        "the authority's node never heard of the write"
    );
    let outbox = &x.app.spaces.as_ref().unwrap().outbox;
    assert!(eventually(Duration::from_secs(5), || async { outbox.is_empty() }).await);
    let peer = |n: &TestServer| n.app.spaces.as_ref().unwrap().peer_notifies.load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!((peer(&x), peer(&y)), (0, 1), "delivered over the peer link");
}

/// An authority on another PDS whose DID lands in a shard of the writer's
/// cluster owned by another node: the owner is asked once whether the
/// cluster hosts it, and later notifies go straight out over HTTP.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_notify_to_an_authority_elsewhere_asks_the_owner_once() {
    let plc = vlpds::plc::mock::MockPlc::start().await;
    let rotation = Arc::new(vlsync_atproto::crypto::Keypair::generate());
    let store: Arc<dyn object_store::ObjectStore> = Arc::new(object_store::memory::InMemory::new());
    let cfg = |c: &mut vlpds::server::Config| {
        use_plc(c, plc.url.clone(), rotation.clone());
        c.spaces = true;
    };
    let x = cluster_node("ssnx", store.clone(), 8, cfg).await;
    let y = cluster_node("ssny", store.clone(), 8, cfg).await;
    balanced(&[&x, &y]).await;
    let nodes = [&x, &y];
    let z = TestServer::spawn_with(cfg).await;
    let mut owner = None;
    for i in 0..40 {
        let c = SpaceClient::new(&z, &format!("ssnz{i}"), OWNER).await;
        if std::ptr::eq(owner_of(&nodes, &c.did), &y) {
            owner = Some(c);
            break;
        }
    }
    let owner = owner.expect("an authority whose DID y's shard holds");
    let member = owned_by(&x, &nodes, "ssnm", ANY).await;
    let space = owner.create_space(TYPE, "elsewhere").await;
    put_member(&owner, &space, &member.did).await;

    let cred = member.credential_at(&z.url, &space).await;
    let outbox = &x.app.spaces.as_ref().unwrap().outbox;
    for i in 0..4 {
        member.create_record(&space, COLL, Some(&i.to_string()), rec("to z")).await.ok();
        let head =
            member.get("com.atproto.space.getLatestCommit", &[("space", &space), ("repo", &member.did)]).await.ok()
                ["commit"]["rev"]
                .clone();
        assert!(
            eventually(Duration::from_secs(10), || async {
                let r = member
                    .signed_get(&z.url, "com.atproto.space.listRepos", &[("space", &space)], &cred, &owner.did)
                    .await;
                r.ok()["repos"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|r| r["did"] == json!(member.did) && r["repoRev"] == head)
            })
            .await,
            "write {i} never reached the authority"
        );
        assert!(eventually(Duration::from_secs(5), || async { outbox.is_empty() }).await);
    }
    let peer = y.app.spaces.as_ref().unwrap().peer_notifies.load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!(peer, 1, "the owner was asked on every send");
}

/// The expired-registration prune deletes on the authority's worker only
/// if the row is still expired there: a renewal between the prune's read
/// and its delete stays.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_renewal_outlives_a_prune_that_read_it_expired() {
    let s = spawn().await;
    let owner = SpaceClient::new(&s, "ssprune", OWNER).await;
    let space = owner.create_space(TYPE, "prune").await;
    let cred = owner.credential(&space).await;
    let sy = Syncer::start(Duration::ZERO).await;
    let register = || async {
        let body = json!({"space": space, "service": sy.service()});
        owner.signed_post(&s.url, "com.atproto.space.registerNotify", body, &cred, &owner.did).await.ok();
    };
    register().await;
    let p = s.app.partition(&owner.did).ok().unwrap();
    let key = vlpds::state::space_notify_key(&owner.did, &vlpds::state::space_id(&space), &sy.service());
    vlpds::xrpc::space::set_registration_expiry(&s.app, &space, &sy.service(), vlsync_atproto::tid::now_micros() - 1)
        .await
        .unwrap();
    // a prune reads it expired, then the syncer renews before the delete
    let read_at = vlsync_atproto::tid::now_micros();
    register().await;
    vlpds::xrpc::space::unregister_if_expired(&s.app, &space, &sy.service(), read_at).await.unwrap();
    let row = vlpds::space::rows::NotifyRow::decode(&p.db.get(&key).await.unwrap().expect("renewed")).unwrap();
    assert!(row.expires > read_at, "the renewal was deleted");
    // one that's still expired goes
    vlpds::xrpc::space::set_registration_expiry(&s.app, &space, &sy.service(), vlsync_atproto::tid::now_micros() - 1)
        .await
        .unwrap();
    vlpds::xrpc::space::unregister_if_expired(&s.app, &space, &sy.service(), vlsync_atproto::tid::now_micros())
        .await
        .unwrap();
    assert!(p.db.get(&key).await.unwrap().is_none());
}
