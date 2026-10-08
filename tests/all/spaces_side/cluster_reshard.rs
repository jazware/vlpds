//! Shard split and merge with space state (plan §2.6, phase 2): the s*
//! families are slot-prefixed, so a split or merge moves them with their
//! slot like any other row. Three nodes hold space repos, a space a vlpds
//! account governs (sS, sM, sW, sQ, sN) and one a remote authority governs
//! while it refuses every notify (so sP rows stay pending). Across a split,
//! the merge of its children and a merge of two shards on different nodes:
//!
//! - every s* row is in exactly one open shard, and the rows are the same
//!   ones with the same values;
//! - each repo reads the same (records, head, oplog replay) and checks
//!   clean, and the authority's listRepos is unchanged;
//! - afterwards writes carry on from the heads, the authority sequences
//!   them, and once the remote authority accepts, the outbox on the shard's
//!   new owner delivers each writer's newest rev.
//!
//! A second test splits and merges while every writer bursts space writes:
//! nothing acked is lost and every repo stays consistent.

use super::cluster::{client_on, fronted_node, settle_front, Plc};
use super::durability::{
    burst, by_did, consistent, create, latest, list_repos, note, scope, signed_post, Burst, Records,
};
use super::fuzz::bytes_field;
use super::hooks::{Front, StubDid};
use super::leak::SPACE_FAMILIES;
use crate::common::spaces::{space_uri, SpaceClient};
use crate::common::*;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use vlsync_store::slots::{Layout, ShardId};

const SHARDS: u32 = 6;

type Bucket = Arc<object_store::memory::InMemory>;

fn tag() -> String {
    random_bytes(5).iter().map(|b| format!("{b:02x}")).collect()
}

fn layout(n: &TestServer) -> Arc<Layout> {
    cluster(n).layout()
}

/// Every node routes by one layout at `want` or later with no op in flight,
/// each of its shards open on exactly one node.
async fn settled(nodes: &[&TestServer], want: u64) -> Arc<Layout> {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let l = layout(nodes[0]);
        let same = nodes.iter().all(|n| *layout(n) == *l);
        let mut open: Vec<ShardId> = nodes.iter().flat_map(|n| n.app.partitions.owned()).map(|p| p.id).collect();
        let mut ids = l.ids();
        open.sort();
        ids.sort();
        let complete = open == ids;
        if same && l.op.is_none() && l.version >= want && complete {
            return l;
        }
        assert!(Instant::now() < deadline, "never settled at v{want}+: {:?}, open {open:?}", l.ids());
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn admin(n: &TestServer, nsid: &str, body: J) -> J {
    let r = n.xrpc.post(nsid, &body, &Auth::Admin).await.ok();
    assert_eq!(r["done"], json!(true), "{nsid}: {r}");
    r
}

fn children(r: &J) -> Vec<ShardId> {
    r["op"]["children"].as_array().unwrap().iter().map(|c| ShardId(c["id"].as_u64().unwrap() as u32)).collect()
}

/// The shard `did` lives in.
fn shard_of(n: &TestServer, did: &str) -> ShardId {
    n.app.partitions.shard_of(did)
}

fn is_space_key(key: &[u8]) -> bool {
    vlsync_store::keys::key_slot(key).is_some()
        && SPACE_FAMILIES.iter().any(|f| vlsync_store::keys::key_body(key).starts_with(f))
}

fn show(key: &[u8]) -> String {
    let body = vlsync_store::keys::key_body(key);
    let did_end = body.iter().position(|b| *b == 0).unwrap_or(body.len());
    format!("{}…", String::from_utf8_lossy(&body[..did_end]))
}

/// Every s* row of every open shard (only the shard's own slot range: a
/// split child may still carry its sibling's half until compaction), each
/// asserted to be in exactly one shard.
async fn space_rows(nodes: &[&TestServer]) -> BTreeMap<Vec<u8>, Vec<u8>> {
    let (mut rows, mut at) = (BTreeMap::new(), BTreeMap::<Vec<u8>, String>::new());
    for n in nodes {
        let l = layout(n);
        for p in n.app.partitions.owned() {
            let r = l.shards.iter().find(|r| r.id == p.id).expect("an open shard is in the layout");
            let (lo, hi) = vlsync_store::keys::slot_range_keys(r.lo, r.hi);
            let mut it = p.db.scan(lo.to_vec()..hi.to_vec()).await.unwrap();
            let here = format!("{} shard {}", cluster(n).cfg.node_id, p.id.0);
            while let Some(kv) = it.next().await.unwrap() {
                if !is_space_key(&kv.key) {
                    continue;
                }
                if let Some(other) = at.insert(kv.key.to_vec(), here.clone()) {
                    panic!("{} is in {other} and {here}", show(&kv.key));
                }
                rows.insert(kv.key.to_vec(), kv.value.to_vec());
            }
        }
    }
    rows
}

fn family_counts(rows: &BTreeMap<Vec<u8>, Vec<u8>>) -> BTreeMap<String, usize> {
    let mut m = BTreeMap::new();
    for k in rows.keys() {
        *m.entry(String::from_utf8_lossy(&vlsync_store::keys::key_body(k)[..3]).into_owned()).or_default() += 1;
    }
    m
}

fn assert_same_rows(before: &BTreeMap<Vec<u8>, Vec<u8>>, after: &BTreeMap<Vec<u8>, Vec<u8>>, ctx: &str) {
    let (b, a) = (before, after);
    let lost: Vec<String> = b.keys().filter(|k| !a.contains_key(*k)).map(|k| show(k)).take(10).collect();
    let new: Vec<String> = a.keys().filter(|k| !b.contains_key(*k)).map(|k| show(k)).take(10).collect();
    let changed: Vec<String> =
        b.iter().filter(|(k, v)| a.get(*k).is_some_and(|x| x != *v)).map(|(k, _)| show(k)).take(10).collect();
    assert!(
        lost.is_empty() && new.is_empty() && changed.is_empty(),
        "{ctx}: s* rows differ ({:?} before, {:?} after): lost {lost:?}, new {new:?}, changed {changed:?}",
        family_counts(before),
        family_counts(after)
    );
}

/// The rows once nothing moves: two reads 300 ms apart agree.
async fn quiet_rows(nodes: &[&TestServer]) -> BTreeMap<Vec<u8>, Vec<u8>> {
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut prev = space_rows(nodes).await;
    loop {
        tokio::time::sleep(Duration::from_millis(300)).await;
        let rows = space_rows(nodes).await;
        if rows == prev {
            return rows;
        }
        assert!(Instant::now() < deadline, "the s* rows never settled");
        prev = rows;
    }
}

/// What a repo reads as from outside.
#[derive(Debug, PartialEq)]
struct View {
    records: Records,
    rev: String,
    hash: Vec<u8>,
}

struct World {
    /// Every node's public URL; clients go through it to the first node.
    _front: Front,
    nodes: Vec<TestServer>,
    /// The vlpds authority of `local`; also a writer in both spaces.
    auth: usize,
    writers: Vec<SpaceClient>,
    local: String,
    remote: String,
    collection: String,
    stub: StubDid,
    syncer: StubDid,
    credential: String,
}

impl World {
    /// Three nodes; two writers created on each (an account lives where it
    /// was created), the first the local space's authority. Clients all
    /// talk to the first node, which forwards.
    async fn new(prefix: &str) -> World {
        let (bucket, plc, front) = (Bucket::default(), Plc::start().await, Front::new().await);
        let mut nodes = Vec::new();
        for i in 1..=3 {
            nodes.push(fronted_node(&format!("{prefix}-{i}"), &bucket, SHARDS, &plc, &front).await);
        }
        balanced(&nodes.iter().collect::<Vec<_>>()).await;
        let t = tag();
        let (st, collection) = (format!("com.example.rsp{t}.space"), format!("com.example.rsp{t}.note"));
        let mut writers = Vec::new();
        for n in &nodes {
            for _ in 0..2 {
                writers.push(client_on(&front, n, "rsp", &scope(&st, &collection)).await);
            }
        }
        settle_front(&front, &nodes[0], &mut writers.iter_mut().collect::<Vec<_>>());
        let auth = 0;
        let local = writers[auth].create_space(&st, "local").await;
        for w in &writers[1..] {
            let m = json!({"space": local, "did": w.did, "read": true, "write": true});
            writers[auth].post("com.atproto.simplespace.putMember", m).await.ok();
        }
        let (stub, syncer) = (StubDid::spawn().await, StubDid::spawn().await);
        stub.refuse(true);
        let remote = space_uri(&stub.did, &st, "remote");
        let credential = writers[auth].credential(&local).await;
        let reg = json!({"space": local, "service": format!("{}#atproto_space_syncer", syncer.did)});
        let a = &writers[auth];
        signed_post(a, "com.atproto.space.registerNotify", reg, &credential, &a.did).await.ok();
        World { _front: front, nodes, auth, writers, local, remote, collection, stub, syncer, credential }
    }

    fn refs(&self) -> Vec<&TestServer> {
        self.nodes.iter().collect()
    }

    fn spaces(&self) -> [&str; 2] {
        [&self.local, &self.remote]
    }

    /// Creates, an update, a delete and a dependent applyWrites batch from
    /// every writer into both spaces.
    async fn populate(&self, round: &str) {
        let c = &self.collection;
        for (i, w) in self.writers.iter().enumerate() {
            for space in self.spaces() {
                for k in 0..4 {
                    create(w, space, c, &format!("{round}w{i}k{k}"), &format!("{round} {i} {k}")).await.ok();
                }
                w.put_record(space, c, &format!("{round}w{i}k1"), note(c, "updated")).await.ok();
                w.delete_record(space, c, &format!("{round}w{i}k2")).await.ok();
                let op = |kind: &str, rkey: &str, text: Option<&str>| {
                    let mut o = json!({"$type": format!("com.atproto.space.applyWrites#{kind}"), "collection": c, "rkey": rkey});
                    if let Some(t) = text {
                        o["value"] = note(c, t);
                    }
                    o
                };
                let rk = format!("{round}w{i}b");
                let batch = json!([op("create", &rk, Some("batched")), op("update", &rk, Some("batched again"))]);
                w.apply_writes(space, batch).await.ok();
            }
        }
    }

    async fn views(&self, ctx: &str) -> BTreeMap<(String, String), View> {
        let mut out = BTreeMap::new();
        for w in &self.writers {
            for space in self.spaces() {
                let ctx = format!("{ctx}: {} in {space}", w.did);
                let replay = space == self.local;
                let (records, c) = consistent(&self.nodes[0], w, space, replay, &ctx).await;
                out.insert((w.did.clone(), space.to_string()), View { records, rev: c.rev, hash: c.hash });
            }
        }
        out
    }

    /// listRepos of the local space by did: (repoRev, spaceRev, hash).
    async fn host(&self) -> BTreeMap<String, (J, J, Vec<u8>)> {
        let a = &self.writers[self.auth];
        let repos = list_repos(a, &self.local, &self.credential).await.unwrap();
        let rows = by_did(&repos);
        assert_eq!(rows.len(), repos.len(), "listRepos repeats a repo: {repos:?}");
        rows.into_iter()
            .map(|(d, r)| (d, (r["repoRev"].clone(), r["spaceRev"].clone(), bytes_field(&r["hash"]))))
            .collect()
    }

    /// Rows, repo views and host state, checked against `want` if given.
    async fn check(&self, want: Option<&Snapshot>, ctx: &str) -> Snapshot {
        let rows = quiet_rows(&self.refs()).await;
        let fams = family_counts(&rows);
        for f in ["sH/", "sR/", "sO/", "sP/", "sS/", "sM/", "sW/", "sQ/", "sN/"] {
            assert!(fams.get(f).is_some_and(|n| *n > 0), "{ctx}: no {f} rows: {fams:?}");
        }
        let views = self.views(ctx).await;
        let host = self.host().await;
        assert_eq!(host.len(), self.writers.len(), "{ctx}: listRepos {host:?}");
        if let Some(w) = want {
            assert_same_rows(&w.rows, &rows, ctx);
            for (k, v) in &w.views {
                assert_eq!(views.get(k), Some(v), "{ctx}: {k:?} reads differently");
            }
            assert_eq!(host, w.host, "{ctx}: the authority's listRepos changed");
        }
        eprintln!("{ctx}: {fams:?}");
        Snapshot { rows, views, host }
    }
}

struct Snapshot {
    rows: BTreeMap<Vec<u8>, Vec<u8>>,
    views: BTreeMap<(String, String), View>,
    host: BTreeMap<String, (J, J, Vec<u8>)>,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn split_and_merge_keep_every_space_row() {
    let w = World::new("rss").await;
    let nodes = w.refs();
    w.populate("a").await;
    let before = w.check(None, "before").await;
    let pending: Vec<_> = before.rows.keys().filter(|k| vlsync_store::keys::key_body(k).starts_with(b"sP/")).collect();
    assert_eq!(pending.len(), w.writers.len(), "one pending sP row per writer of the remote space");

    // split the shard holding the authority (host rows, its own repos)
    let l1 = layout(nodes[0]);
    let target = shard_of(nodes[0], &w.writers[w.auth].did);
    let r = admin(nodes[1], "vlpds.admin.splitShard", json!({"shard": target, "wait": true})).await;
    let kids = children(&r);
    let l2 = settled(&nodes, l1.version + 1).await;
    assert!(!l2.contains(target) && kids.iter().all(|k| l2.contains(*k)), "{l2:?}");
    let after_split = w.check(Some(&before), "after the split").await;

    admin(nodes[2], "vlpds.admin.mergeShards", json!({"left": kids[0], "right": kids[1], "wait": true})).await;
    let l3 = settled(&nodes, l2.version + 1).await;
    let after_merge = w.check(Some(&after_split), "after merging the children").await;

    // two adjacent shards on different nodes, one holding writers
    let owner = |s: ShardId| nodes.iter().position(|n| n.app.partitions.get(s).is_some());
    let pair = l3.shards.windows(2).find(|p| owner(p[0].id) != owner(p[1].id)).expect("adjacent shards on two nodes");
    let (x, y) = (pair[0].id, pair[1].id);
    admin(nodes[0], "vlpds.admin.mergeShards", json!({"left": x, "right": y, "wait": true})).await;
    let l4 = settled(&nodes, l3.version + 1).await;
    assert_eq!(l4.shards.len(), SHARDS as usize - 1);
    let fin = w.check(Some(&after_merge), "after the cross-node merge").await;
    assert_same_rows(&before.rows, &fin.rows, "before vs after everything");

    // writes carry on from the heads, and the authority sequences them
    w.populate("b").await;
    let host = w.host().await;
    for wr in &w.writers {
        for space in w.spaces() {
            let head = latest(wr, space, "after round b").await;
            let was = &before.views[&(wr.did.clone(), space.to_string())];
            assert!(head.rev > was.rev, "{} in {space}: rev {} after {}", wr.did, head.rev, was.rev);
            if space == w.local {
                let (rr, sr, hash) = &host[&wr.did];
                assert_eq!((rr, hash), (&json!(head.rev), &head.hash), "{}: listRepos lags", wr.did);
                assert!(sr.as_str() > before.host[&wr.did].1.as_str(), "{}: spaceRev didn't move", wr.did);
            }
        }
    }
    w.views("after round b").await;

    // the pending notifies, from wherever each writer's shard is now
    w.stub.refuse(false);
    let heads: Vec<(String, String)> = {
        let mut v = Vec::new();
        for wr in &w.writers {
            v.push((wr.did.clone(), latest(wr, &w.remote, "remote head").await.rev));
        }
        v
    };
    // the first retry after a refusal is up to a minute out
    let t = Instant::now();
    loop {
        let got = w.stub.accepted();
        let done = heads
            .iter()
            .all(|(did, rev)| got.iter().any(|n| n.body["repo"] == json!(did) && n.body["repoRev"] == json!(rev)));
        if done {
            break;
        }
        assert!(t.elapsed() < Duration::from_secs(150), "the remote authority never got every newest rev: {got:?}");
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    eprintln!("remote authority caught up {:?} after it started accepting", t.elapsed());
    assert!(!w.syncer.accepted().is_empty(), "the registered syncer heard nothing");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn split_and_merge_under_space_writes() {
    let w = World::new("rsw").await;
    let nodes = w.refs();
    w.stub.refuse(false);
    w.populate("a").await;
    let stop = AtomicBool::new(false);
    let target = shard_of(nodes[0], &w.writers[w.auth].did);
    let prefixes: Vec<String> = (0..w.writers.len()).map(|i| format!("burst{i}-")).collect();
    let mut jobs = Vec::new();
    for (wr, prefix) in w.writers.iter().zip(&prefixes) {
        for space in w.spaces() {
            jobs.push(burst(wr, space, &w.collection, prefix, &stop));
        }
    }
    let bursts = futures::future::join_all(jobs);
    let reshard = async {
        tokio::time::sleep(Duration::from_millis(500)).await;
        let l1 = layout(nodes[0]);
        let kids = children(&admin(nodes[0], "vlpds.admin.splitShard", json!({"shard": target, "wait": true})).await);
        let l2 = settled(&nodes, l1.version + 1).await;
        tokio::time::sleep(Duration::from_millis(500)).await;
        admin(nodes[1], "vlpds.admin.mergeShards", json!({"left": kids[0], "right": kids[1], "wait": true})).await;
        settled(&nodes, l2.version + 1).await;
        tokio::time::sleep(Duration::from_millis(500)).await;
        stop.store(true, Ordering::SeqCst);
    };
    let (bursts, _) = tokio::join!(bursts, reshard);
    let mut acked = 0;
    let mut it = bursts.iter();
    for (i, wr) in w.writers.iter().enumerate() {
        for space in w.spaces() {
            let b: &Burst = it.next().unwrap();
            acked += b.acked.len();
            let ctx = format!("writer {i} in {space}");
            let (recs, _) = consistent(nodes[0], wr, space, space == w.local, &ctx).await;
            for (path, cid) in &b.acked {
                assert_eq!(recs.get(path).map(|r| &r.0), Some(cid), "{ctx}: acked {path} lost");
            }
            let prefix = format!("{}/burst{i}-", w.collection);
            for path in recs.keys().filter(|p| p.starts_with(&prefix)) {
                assert!(b.acked.contains_key(path) || b.unacked.contains(path), "{ctx}: {path} was never written");
            }
        }
    }
    eprintln!("{acked} space writes acked across the split and merge");
    assert!(acked > 0, "the burst wrote nothing");
    space_rows(&nodes).await;
    // the authority hears every writer's head
    let a = &w.writers[w.auth];
    // a notify that failed while its shard moved waits for its first retry
    let caught_up = eventually(Duration::from_secs(150), || async {
        let rows = by_did(&list_repos(a, &w.local, &w.credential).await.ok()?);
        for wr in &w.writers {
            let head = latest(wr, &w.local, "head").await;
            if rows.get(&wr.did)?["repoRev"] != json!(head.rev) {
                return None;
            }
        }
        Some(())
    })
    .await;
    assert!(caught_up.is_some(), "the authority never caught up with every writer");
}
