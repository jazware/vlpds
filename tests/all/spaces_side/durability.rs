//! Space writes through crashes (plan §2.0 "durable before the 200", §2.5
//! outbox). Nodes run over [`HookedStore`]s on one in-memory bucket, so a
//! test can hold or fail the PUT of the segment carrying a given write and
//! then kill the node (`Node::halt` plus a bucket that stops answering, as
//! kill -9), and restart it or let a peer take over.
//!
//! - Killed around the segment PUT of an applyWrites batch: after a restart
//!   every acked write is there, the batch is there whole or not at all, and
//!   the repo is consistent (the records fold to the commit's hash, the
//!   oplog replays to it, check-space is clean).
//! - Killed after the ack while the remote authority refuses the notify:
//!   the restarted node, or the peer that takes the shard over, finds the
//!   sP row and delivers the newest repoRev exactly once more.
//! - A 2-node takeover in the middle of a write burst: nothing acked is lost,
//!   the outbox resumes on the new owner, and the vlpds authority sequences
//!   each repoRev once, its spaceRevs only moving forward (C3, C4).
//! - An inbound notifyWrite survives a kill right after its 200 (C3).

use super::fuzz::{bytes_field, fold, signed_commit};
use super::hooks::*;
use crate::common::spaces::{space_uri, SpaceClient};
use crate::common::*;
use base64::Engine;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use vlpds::space::commit::{self, SignedCommit};
use vlpds::space::lthash::LtHash;

const SHARDS: u32 = 4;
const NOTIFY: &str = "com.atproto.space.notifyWrite";

type Bucket = Arc<object_store::memory::InMemory>;

/// path -> (cid, value)
pub(super) type Records = BTreeMap<String, (String, J)>;

fn tag() -> String {
    random_bytes(5).iter().map(|b| format!("{b:02x}")).collect()
}

fn names() -> (String, String) {
    let t = tag();
    (format!("com.example.dur{t}.space"), format!("com.example.dur{t}.note"))
}

/// Every space right this harness needs; `authority=*` so the same grant
/// writes into a space someone else governs.
pub(super) fn scope(space_type: &str, collection: &str) -> String {
    format!(
        "space:{space_type}?authority=*&collection={collection}&action=read&action=create&action=update&action=delete&manage=create&manage=update&manage=delete"
    )
}

pub(super) fn note(collection: &str, text: &str) -> J {
    json!({"$type": collection, "text": text, "createdAt": now_iso()})
}

fn b64(b: &[u8]) -> J {
    json!({"$bytes": base64::engine::general_purpose::STANDARD_NO_PAD.encode(b)})
}

/// A space TID `n` µs past `base`.
fn tid(base: u64, n: u64) -> String {
    vlsync_atproto::tid::Tid::from_parts(base + n, 7).to_string()
}

/// `sc` after its node restarted behind the same front.
fn rebind(sc: &mut SpaceClient, s: &TestServer) {
    sc.srv.app = s.app.clone();
}

async fn owns_all(s: &TestServer) {
    wait_until("the shards are open", Duration::from_secs(30), || owned(s) == SHARDS as usize).await;
}

pub(super) async fn create(sc: &SpaceClient, space: &str, collection: &str, rkey: &str, text: &str) -> Resp {
    sc.create_record(space, collection, Some(rkey), note(collection, text)).await
}

/// The account's own repo in `space`, read with its OAuth grant.
pub(super) async fn records(sc: &SpaceClient, space: &str, ctx: &str) -> Records {
    let (mut out, mut cursor) = (Records::new(), None::<String>);
    loop {
        let mut q = vec![("space", space), ("repo", sc.did.as_str()), ("limit", "100")];
        if let Some(c) = &cursor {
            q.push(("cursor", c.as_str()));
        }
        let r = sc.get("com.atproto.space.listRecords", &q).await;
        assert_eq!(r.status, 200, "{ctx}: listRecords: {}", r.text());
        let recs = r.json["records"].as_array().cloned().unwrap_or_default();
        for x in &recs {
            let path = format!("{}/{}", x["collection"].as_str().unwrap(), x["rkey"].as_str().unwrap());
            out.insert(path, (x["cid"].as_str().unwrap().to_string(), x["value"].clone()));
        }
        match r.json["cursor"].as_str() {
            Some(c) if !recs.is_empty() => cursor = Some(c.into()),
            _ => return out,
        }
    }
}

pub(super) async fn latest(sc: &SpaceClient, space: &str, ctx: &str) -> SignedCommit {
    let r = sc.get("com.atproto.space.getLatestCommit", &[("space", space), ("repo", sc.did.as_str())]).await;
    assert_eq!(r.status, 200, "{ctx}: getLatestCommit: {}", r.text());
    signed_commit(&r.json["commit"])
}

/// listRepoOps from empty to the head with `credential`: every op and the
/// commit of the last page.
pub(super) async fn replay(sc: &SpaceClient, space: &str, credential: &str, ctx: &str) -> (Vec<J>, SignedCommit) {
    let (mut ops, mut cursor) = (Vec::new(), None::<String>);
    let base = sc.srv.base.clone();
    for _ in 0..10_000 {
        let mut q = vec![("space", space), ("repo", sc.did.as_str()), ("limit", "7")];
        if let Some(c) = &cursor {
            q.push(("cursor", c.as_str()));
        }
        let r = sc.signed_get(&base, "com.atproto.space.listRepoOps", &q, credential, &sc.did).await;
        assert_eq!(r.status, 200, "{ctx}: listRepoOps: {}", r.text());
        ops.extend(r.json["ops"].as_array().cloned().unwrap_or_default());
        if !r.json["commit"].is_null() {
            return (ops, signed_commit(&r.json["commit"]));
        }
        cursor = Some(r.json["cursor"].as_str().unwrap_or_else(|| panic!("{ctx}: no commit, no cursor")).into());
    }
    panic!("{ctx}: listRepoOps doesn't end")
}

/// The repo agrees with itself: its records fold to the commit's hash, the
/// oplog replays to it (`replay_too`: a credential from the authority at the
/// client's host), and
/// check-space finds nothing wrong (once vlpds.admin.checkSpace is routed;
/// the client-side checks stand alone until then).
pub(super) async fn consistent(
    s: &TestServer,
    sc: &SpaceClient,
    space: &str,
    replay_too: bool,
    ctx: &str,
) -> (Records, SignedCommit) {
    let recs = records(sc, space, ctx).await;
    let c = latest(sc, space, ctx).await;
    let mut set = LtHash::default();
    for (path, (cid, _)) in &recs {
        let (coll, rkey) = path.split_once('/').unwrap();
        set.add(&commit::element(coll, rkey, cid));
    }
    assert!(commit::matches(&set, &c), "{ctx}: {} record(s) fold to another hash than the commit's", recs.len());
    if replay_too {
        let host = sc.srv.base.clone();
        let cred = sc.credential_at(&host, space).await;
        let (ops, rc) = replay(sc, space, &cred, ctx).await;
        let mut set = LtHash::default();
        for op in &ops {
            fold(&mut set, op);
        }
        assert!(commit::matches(&set, &rc), "{ctx}: {} op(s) replay to another hash than the commit's", ops.len());
        assert_eq!(rc.hash, c.hash, "{ctx}: listRepoOps and getLatestCommit disagree");
    }
    let q = [("did", sc.did.as_str()), ("space", space)];
    let chk = s.xrpc.get("vlpds.admin.checkSpace", &q, &Auth::Admin).await;
    assert_eq!(chk.status, 200, "{ctx}: checkSpace: {}", chk.text());
    assert_eq!(chk.json["ok"], json!(true), "{ctx}: checkSpace: {}", chk.json);
    assert_eq!(chk.json["records"]["count"], json!(recs.len()), "{ctx}: checkSpace count");
    (recs, c)
}

/// A space read/host call with `credential`, signed for `audience`.
pub(super) async fn signed_post(sc: &SpaceClient, nsid: &str, body: J, credential: &str, audience: &str) -> Resp {
    let mut rb = sc.srv.http.post(format!("{}/xrpc/{nsid}", sc.srv.base));
    for (k, v) in sc.holder.headers(&format!("Atproto-Space {credential}"), Some(audience)) {
        rb = rb.header(k, v);
    }
    crate::common::spaces::resp(rb.json(&body).send().await.unwrap()).await
}

/// listRepos at the authority `auth`, every page.
pub(super) async fn list_repos(auth: &SpaceClient, space: &str, credential: &str) -> Result<Vec<J>, String> {
    let (mut out, mut cursor) = (Vec::new(), None::<String>);
    let base = auth.srv.base.clone();
    loop {
        let mut q = vec![("space", space), ("limit", "50")];
        if let Some(c) = &cursor {
            q.push(("cursor", c.as_str()));
        }
        let r = auth.signed_get(&base, "com.atproto.space.listRepos", &q, credential, &auth.did).await;
        if r.status != 200 {
            return Err(format!("listRepos: {} {}", r.status, r.text()));
        }
        let repos = r.json["repos"].as_array().cloned().unwrap_or_default();
        if repos.is_empty() {
            return Ok(out);
        }
        out.extend(repos);
        cursor = Some(r.json["cursor"].as_str().expect("a non-empty page has a cursor").into());
    }
}

/// The latest listRepos row of each repo (a repo may reappear across pages).
pub(super) fn by_did(repos: &[J]) -> BTreeMap<String, J> {
    repos.iter().map(|r| (r["did"].as_str().unwrap().to_string(), r.clone())).collect()
}

// ---------- killed around the segment PUT ----------

/// A node behind a front, and a space its fresh account governs with a few
/// acked writes in it.
struct OneNode {
    bucket: Bucket,
    front: Front,
    node: TestServer,
    store: Arc<HookedStore>,
    sc: SpaceClient,
    space: String,
    collection: String,
}

impl OneNode {
    async fn new(id: &str) -> OneNode {
        let (bucket, front) = (Bucket::default(), Front::new().await);
        let (node, store) = hooked_node(id, &bucket, SHARDS, &front).await;
        front.point(&node);
        let (st, collection) = names();
        let sc = SpaceClient::new(&front.view(&node), &unique_name("dur"), &scope(&st, &collection)).await;
        let space = sc.create_space(&st, "dur").await;
        OneNode { bucket, front, node, store, sc, space, collection }
    }

    fn kill(&self) {
        kill9(&self.node, &self.store);
    }

    /// The same node id back on the same bucket, after [`Self::kill`].
    async fn restart(&mut self, id: &str) {
        let (node, store) = hooked_node(id, &self.bucket, SHARDS, &self.front).await;
        self.front.point(&node);
        owns_all(&node).await;
        rebind(&mut self.sc, &node);
        (self.node, self.store) = (node, store);
    }
}

/// An applyWrites batch (three creates, an update and a delete of acked
/// records), its segment PUT caught at `stage` and answered per `act`, then
/// kill -9 and a restart.
async fn kill_around_segment_put(stage: Stage, act: Act) -> (Option<u16>, bool) {
    let mut n = OneNode::new("dur").await;
    let (sc, space, coll) = (&n.sc, n.space.clone(), n.collection.clone());
    for i in 0..6 {
        create(sc, &space, &coll, &format!("a{i}"), &format!("acked {i}")).await.ok();
    }
    sc.put_record(&space, &coll, "a1", note(&coll, "acked again")).await.ok();
    sc.delete_record(&space, &coll, "a2").await.ok();
    let (before, head) = consistent(&n.node, sc, &space, true, "before").await;

    let needle = format!("zqbatch{}", tag());
    let op = |kind: &str, rkey: &str, value: Option<J>| {
        let mut o = json!({"$type": format!("com.atproto.space.applyWrites#{kind}"), "collection": coll, "rkey": rkey});
        if let Some(v) = value {
            o["value"] = v;
        }
        o
    };
    let batch = json!([
        op("create", &format!("{needle}-0"), Some(note(&coll, "b0"))),
        op("create", &format!("{needle}-1"), Some(note(&coll, "b1"))),
        op("create", &format!("{needle}-2"), Some(note(&coll, "b2"))),
        op("update", "a3", Some(note(&coll, &format!("{needle} a3")))),
        op("delete", "a4", None),
    ]);
    let mut armed = n.store.arm(stage, act, &needle);
    let status = {
        let write = sc.apply_writes(&space, batch);
        tokio::pin!(write);
        let mut status = tokio::select! {
            r = &mut write => Some(r.status),
            _ = armed.wait("the batch's segment") => None,
        };
        if act == Act::Fail && status.is_none() {
            // the failed PUT is retried, finds its own object there, and acks
            status = tokio::time::timeout(Duration::from_secs(20), &mut write).await.ok().map(|r| r.status);
        }
        eprintln!("{stage:?}/{act:?}: the batch answered {status:?} before the kill");
        n.kill();
        status
    };
    drop(armed);
    n.restart("dur").await;

    let ctx = format!("{stage:?}/{act:?} after the restart");
    let (after, c) = consistent(&n.node, &n.sc, &space, true, &ctx).await;
    let p = |k: &str| format!("{coll}/{k}");
    let landed = [0, 1, 2].map(|i| after.contains_key(&p(&format!("{needle}-{i}"))));
    let updated = after[&p("a3")].1["text"].as_str().is_some_and(|t| t.contains(&needle));
    let deleted = !after.contains_key(&p("a4"));
    let parts = [landed[0], landed[1], landed[2], updated, deleted];
    let whole = parts.iter().all(|x| *x);
    assert!(whole || parts.iter().all(|x| !x), "{ctx}: a partial batch (creates, update, delete): {parts:?}");
    if status == Some(200) {
        assert!(whole, "{ctx}: an acked batch is gone");
    }
    // everything acked before the batch, as it was (bar what the batch touched)
    for (path, rec) in &before {
        if whole && (path == &p("a3") || path == &p("a4")) {
            continue;
        }
        assert_eq!(after.get(path), Some(rec), "{ctx}: acked record {path}");
    }
    assert_eq!(after.len(), before.len() + if whole { 2 } else { 0 }, "{ctx}: records");
    match whole {
        true => assert!(c.rev > head.rev, "{ctx}: the batch landed but the head is still {}", head.rev),
        false => assert_eq!((c.rev.as_str(), &c.hash), (head.rev.as_str(), &head.hash), "{ctx}: the head moved"),
    }

    // the restarted head takes writes on from where it is
    create(&n.sc, &space, &coll, "after", "after the restart").await.ok();
    let (_, c2) = consistent(&n.node, &n.sc, &space, true, &format!("{ctx}, written again")).await;
    assert!(c2.rev > c.rev, "{ctx}: a write after the restart got rev {} after {}", c2.rev, c.rev);
    (status, whole)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kill_after_the_segment_put_before_the_ack() {
    let (status, whole) = kill_around_segment_put(Stage::AfterPut, Act::Pause).await;
    assert_eq!(status, None, "the batch was answered while its segment PUT was held");
    // replay applies every entry of a segment in the bucket, acked or not
    assert!(whole, "an un-acked batch in a landed segment is gone after the restart");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kill_before_the_segment_put_loses_the_whole_batch() {
    let (status, whole) = kill_around_segment_put(Stage::BeforePut, Act::Pause).await;
    assert_eq!(status, None, "the batch was answered before its segment was PUT");
    assert!(!whole, "a batch whose segment never reached the bucket came back");
}

/// The segment lands but its PUT answers an error: the retry finds the
/// object there and acks; a kill right after the ack keeps the batch.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failed_put_that_landed_acks_and_survives_a_kill() {
    let (status, whole) = kill_around_segment_put(Stage::AfterPut, Act::Fail).await;
    assert_eq!(status, Some(200), "the batch after a retried segment PUT");
    assert!(whole);
}

// ---------- the outbox across a kill ----------

#[derive(Clone, Copy, Debug)]
enum Resume {
    /// The same node id restarts on the bucket.
    Restart,
    /// A peer takes the writer's shard over.
    Takeover,
}

/// A writer on `victim` writes into a space a remote stub authority governs
/// while the stub refuses every notify; after kill -9 the stub accepts, and
/// whoever opens the writer's shard next must deliver its newest repoRev
/// exactly once (then later writes as usual).
async fn outbox_survives_a_kill(resume: Resume) {
    let (bucket, front) = (Bucket::default(), Front::new().await);
    let (st, coll) = names();
    let authority = StubDid::spawn().await;
    authority.refuse(true);
    let space = space_uri(&authority.did, &st, "ob");

    let (victim, vstore) = hooked_node("ob-1", &bucket, SHARDS, &front).await;
    let survivor = match resume {
        Resume::Restart => None,
        Resume::Takeover => {
            let (s, st) = hooked_node("ob-2", &bucket, SHARDS, &front).await;
            balanced(&[&victim, &s]).await;
            Some((s, st))
        }
    };
    let entry = survivor.as_ref().map_or(&victim, |(s, _)| s);
    // a DID lands on the node that creates it
    front.point(&victim);
    let mut sc = SpaceClient::new(&front.view(&victim), &unique_name("ob"), &scope(&st, &coll)).await;
    front.point(entry);
    assert!(std::ptr::eq(owner_of(&[&victim, entry], &sc.did), &victim), "no writer on the victim");

    for i in 0..4 {
        create(&sc, &space, &coll, &format!("w{i}"), &format!("write {i}")).await.ok();
    }
    retry("the outbox tries the refusing authority", || async { (!authority.seen().is_empty()).then_some(()) }).await;
    let head = latest(&sc, &space, "before the kill").await;
    for n in authority.seen() {
        assert!(!n.accepted && n.body["repoRev"].as_str().unwrap() <= head.rev.as_str(), "{n:?}");
    }

    kill9(&victim, &vstore);
    authority.refuse(false);
    let at = Instant::now();
    let node = match &survivor {
        None => {
            let (s, store) = hooked_node("ob-1", &bucket, SHARDS, &front).await;
            front.point(&s);
            rebind(&mut sc, &s);
            Some((s, store))
        }
        Some(_) => None,
    };
    let live = node.as_ref().or(survivor.as_ref()).map(|(s, _)| s).unwrap();
    owns_all(live).await;
    retry("the newest repoRev is delivered", || async { (!authority.accepted().is_empty()).then_some(()) }).await;
    eprintln!("{resume:?}: delivered {:?} after the kill", at.elapsed());
    tokio::time::sleep(Duration::from_secs(2)).await;
    let got = authority.accepted();
    assert_eq!(got.len(), 1, "{resume:?}: delivered more than once: {got:?}");
    let n = &got[0];
    assert_eq!(n.body["space"], json!(space));
    assert_eq!(n.body["repo"], json!(sc.did));
    assert_eq!(n.body["repoRev"], json!(head.rev), "{resume:?}: not the newest rev");
    assert_eq!(bytes_field(&n.body["hash"]), head.hash, "{resume:?}: not the newest hash");
    assert_eq!(n.claims["iss"], json!(sc.did));
    assert_eq!(n.claims["aud"], json!(format!("{}#atproto_space_host", authority.did)));
    assert_eq!(n.claims["lxm"], json!(NOTIFY));

    // the new incarnation's outbox carries on, and the old row stays delivered
    create(&sc, &space, &coll, "w-after", "after the kill").await.ok();
    let next = latest(&sc, &space, "after the kill").await;
    retry("the next write is delivered", || async { (authority.accepted().len() >= 2).then_some(()) }).await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    let got = authority.accepted();
    assert_eq!(got.len(), 2, "{resume:?}: {got:?}");
    assert_eq!(got[1].body["repoRev"], json!(next.rev));
    consistent(live, &sc, &space, false, &format!("{resume:?}")).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn outbox_redelivers_the_newest_rev_after_a_restart() {
    outbox_survives_a_kill(Resume::Restart).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn outbox_redelivers_the_newest_rev_from_the_peer_that_takes_over() {
    outbox_survives_a_kill(Resume::Takeover).await;
}

// ---------- 2-node takeover mid burst ----------

/// What one writer's burst got answered.
#[derive(Default)]
pub(super) struct Burst {
    pub acked: BTreeMap<String, String>,
    /// Timed out or refused while the shard moved: there whole or not at all.
    pub unacked: BTreeSet<String>,
}

pub(super) async fn burst(sc: &SpaceClient, space: &str, coll: &str, prefix: &str, stop: &AtomicBool) -> Burst {
    let mut b = Burst::default();
    for i in 0.. {
        if stop.load(Ordering::SeqCst) {
            break;
        }
        let rkey = format!("{prefix}{i:04}");
        let r = tokio::time::timeout(Duration::from_secs(8), create(sc, space, coll, &rkey, &rkey)).await;
        match r {
            Ok(r) if r.status == 200 => {
                b.acked.insert(format!("{coll}/{rkey}"), r.json["cid"].as_str().unwrap().to_string());
            }
            _ => {
                b.unacked.insert(format!("{coll}/{rkey}"));
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
    b
}

/// Two nodes; writer `wv` on n2 (the victim), `ws` on n1, the authority on
/// n2 or n1. Both write in a burst through n1 while n2 is killed. A stub
/// syncer is registered for the space, and listRepos is polled throughout.
async fn takeover_mid_burst(authority_on_victim: bool) {
    let (bucket, front) = (Bucket::default(), Front::new().await);
    let (n1, _) = hooked_node("tb-1", &bucket, SHARDS, &front).await;
    let (n2, s2) = hooked_node("tb-2", &bucket, SHARDS, &front).await;
    balanced(&[&n1, &n2]).await;
    let (st, coll) = names();
    // a DID lands on the node that creates it
    let on = |node: &TestServer| {
        front.point(node);
        let (view, sc) = (front.view(node), scope(&st, &coll));
        async move { SpaceClient::new(&view, &unique_name("tb"), &sc).await }
    };
    let auth = on(if authority_on_victim { &n2 } else { &n1 }).await;
    let wv = on(&n2).await;
    let ws = on(&n1).await;
    front.point(&n1);
    for (sc, node) in [(&auth, if authority_on_victim { &n2 } else { &n1 }), (&wv, &n2), (&ws, &n1)] {
        assert!(std::ptr::eq(owner_of(&[&n1, &n2], &sc.did), node), "{} isn't on its node", sc.did);
    }
    let space = auth.create_space(&st, "tb").await;
    for w in [&wv, &ws] {
        let m = json!({"space": space, "did": w.did, "read": true, "write": true});
        auth.post("com.atproto.simplespace.putMember", m).await.ok();
    }
    let syncer = StubDid::spawn().await;
    let cred = auth.credential(&space).await;
    let reg = json!({"space": space, "service": format!("{}#atproto_space_syncer", syncer.did)});
    signed_post(&auth, "com.atproto.space.registerNotify", reg, &cred, &auth.did).await.ok();

    let stop = AtomicBool::new(false);
    let killed_at = parking_lot::Mutex::new(None::<Instant>);
    let polls = parking_lot::Mutex::new(Vec::<(Instant, Vec<J>)>::new());
    let (bv, bs, _, _) = tokio::join!(
        burst(&wv, &space, &coll, "v", &stop),
        burst(&ws, &space, &coll, "s", &stop),
        async {
            tokio::time::sleep(Duration::from_millis(1200)).await;
            kill9(&n2, &s2);
            *killed_at.lock() = Some(Instant::now());
            wait_until("n1 takes n2's shards", Duration::from_secs(30), || owned(&n1) == SHARDS as usize).await;
            tokio::time::sleep(Duration::from_secs(2)).await;
            stop.store(true, Ordering::SeqCst);
        },
        async {
            while !stop.load(Ordering::SeqCst) {
                if let Ok(Ok(repos)) =
                    tokio::time::timeout(Duration::from_secs(5), list_repos(&auth, &space, &cred)).await
                {
                    polls.lock().push((Instant::now(), repos));
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        },
    );
    let killed_at = killed_at.lock().unwrap();
    eprintln!(
        "burst: victim writer {} acked / {} not, survivor writer {} / {}",
        bv.acked.len(),
        bv.unacked.len(),
        bs.acked.len(),
        bs.unacked.len()
    );
    assert!(!bv.acked.is_empty() && !bs.acked.is_empty(), "the burst wrote nothing");

    for (w, b, who) in [(&wv, &bv, "victim writer"), (&ws, &bs, "survivor writer")] {
        let ctx = format!("{who} after the takeover");
        let (recs, _) = consistent(&n1, w, &space, true, &ctx).await;
        for (path, cid) in &b.acked {
            assert_eq!(recs.get(path).map(|r| &r.0), Some(cid), "{ctx}: acked {path} lost");
        }
        for path in recs.keys() {
            assert!(b.acked.contains_key(path) || b.unacked.contains(path), "{ctx}: {path} was never written");
        }
        // wakes the outbox past any send that failed while the shards moved
        create(w, &space, &coll, &format!("{who}-final").replace(' ', "-"), "final").await.ok();
    }

    // every writer's head reaches the authority, through the new owner
    let heads = [
        (wv.did.clone(), latest(&wv, &space, "victim writer").await),
        (ws.did.clone(), latest(&ws, &space, "survivor writer").await),
    ];
    let t = Instant::now();
    let fin = loop {
        let repos = list_repos(&auth, &space, &cred).await.unwrap_or_default();
        let rows = by_did(&repos);
        let caught_up = heads.iter().all(|(did, c)| {
            rows.get(did).is_some_and(|r| r["repoRev"] == json!(c.rev) && bytes_field(&r["hash"]) == c.hash)
        });
        if caught_up {
            break repos;
        }
        // the outbox's first retry is 30-60 s out if a send failed mid-move
        assert!(t.elapsed() < Duration::from_secs(90), "the authority never caught up: {repos:?}");
        tokio::time::sleep(Duration::from_millis(200)).await;
    };
    eprintln!("authority caught up {:?} after the burst", t.elapsed());

    // the authority sequenced each (repo, repoRev) once, and spaceRevs only
    // moved forward
    let dids: Vec<&str> = fin.iter().map(|r| r["did"].as_str().unwrap()).collect();
    assert_eq!(dids.len(), dids.iter().collect::<BTreeSet<_>>().len(), "listRepos repeats a repo: {fin:?}");
    let space_revs: BTreeSet<&str> = fin.iter().map(|r| r["spaceRev"].as_str().unwrap()).collect();
    assert_eq!(space_revs.len(), fin.len(), "two repos share a spaceRev: {fin:?}");
    let mut seq: BTreeMap<(String, String), String> = BTreeMap::new();
    let mut last: BTreeMap<String, (String, String)> = BTreeMap::new();
    let polls = std::mem::take(&mut *polls.lock());
    for (at, repos) in polls.iter().map(|(t, r)| (Some(*t), r)).chain(std::iter::once((None, &fin))) {
        for (did, r) in by_did(repos) {
            let (rr, sr) = (r["repoRev"].as_str().unwrap().to_string(), r["spaceRev"].as_str().unwrap().to_string());
            if let Some(prev) = seq.insert((did.clone(), rr.clone()), sr.clone()) {
                assert_eq!(prev, sr, "{did} repoRev {rr} sequenced twice (poll at {at:?}, kill at {killed_at:?})");
            }
            if let Some((prr, psr)) = last.insert(did.clone(), (rr.clone(), sr.clone())) {
                assert!(rr >= prr && sr >= psr, "{did} went back: ({prr}, {psr}) then ({rr}, {sr})");
            }
        }
    }

    // the syncer got the space's updates in spaceRev order; the only repeat
    // allowed is the new owner's one catch-up forward after the takeover
    // (DESIGN.md: a current syncer takes it as a no-op)
    retry("the syncer hears the final writes", || async {
        let got = syncer.accepted();
        heads
            .iter()
            .all(|(did, c)| got.iter().any(|n| n.body["repo"] == json!(did) && n.body["repoRev"] == json!(c.rev)))
            .then_some(())
    })
    .await;
    let got = syncer.accepted();
    let revs: Vec<&str> = got.iter().map(|n| n.body["spaceRev"].as_str().expect("spaceRev")).collect();
    assert!(revs.windows(2).all(|w| w[0] <= w[1]), "fan-out out of order: {revs:?}");
    let repeats: Vec<&Notified> =
        got.windows(2).filter(|w| w[0].body["spaceRev"] == w[1].body["spaceRev"]).map(|w| &w[1]).collect();
    assert!(repeats.len() <= 1, "fan-out repeated {} spaceRevs: {revs:?}", repeats.len());
    assert!(repeats.iter().all(|n| n.at > killed_at), "a spaceRev repeated before the takeover: {revs:?}");
    if authority_on_victim {
        assert!(got.iter().any(|n| n.at > killed_at), "fan-out didn't resume on the new owner");
    }
    for n in &got {
        assert_eq!(n.claims["iss"], json!(auth.did), "{n:?}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn takeover_mid_burst_with_the_authority_on_the_survivor() {
    takeover_mid_burst(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn takeover_mid_burst_with_the_authority_on_the_victim() {
    takeover_mid_burst(true).await;
}

// ---------- inbound notifyWrite across a kill ----------

/// A remote writer's notifyWrite to a vlpds authority, as its PDS sends it.
async fn notify(n: &OneNode, writer: &StubDid, rev: &str, hash: &[u8]) -> Resp {
    let jwt = writer.service_jwt(&format!("{}#atproto_space_host", n.sc.did), NOTIFY);
    let body = json!({"space": n.space, "repo": writer.did, "repoRev": rev, "hash": b64(hash)});
    let r = n.sc.srv.http.post(format!("{}/xrpc/{NOTIFY}", n.front.url)).bearer_auth(jwt).json(&body).send().await;
    crate::common::spaces::resp(r.unwrap()).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn inbound_notifies_survive_a_kill_after_their_200() {
    let mut n = OneNode::new("in").await;
    let writer = StubDid::spawn().await;
    let m = json!({"space": n.space, "did": writer.did, "read": false, "write": true});
    n.sc.post("com.atproto.simplespace.putMember", m).await.ok();
    let base = vlsync_atproto::tid::now_micros();
    let revs: Vec<String> = (0..5).map(|i| tid(base, i * 1000)).collect();
    let hashes: Vec<Vec<u8>> = (0..5).map(|_| random_bytes(32)).collect();

    for i in 0..2 {
        assert_eq!(notify(&n, &writer, &revs[i], &hashes[i]).await.status, 200);
    }
    // the authority's own write is sequenced too
    create(&n.sc, &n.space, &n.collection, "own", "own").await.ok();
    let cred = n.sc.credential(&n.space).await;
    let before = by_did(&list_repos(&n.sc, &n.space, &cred).await.unwrap());
    let s1 = before[&writer.did]["spaceRev"].as_str().unwrap().to_string();
    let own = before[&n.sc.did]["spaceRev"].as_str().unwrap().to_string();

    let r = notify(&n, &writer, &revs[2], &hashes[2]).await;
    assert_eq!(r.status, 200, "{}", r.text());
    n.kill();
    n.restart("in").await;

    let cred = n.sc.credential(&n.space).await;
    let rows = list_repos(&n.sc, &n.space, &cred).await.unwrap();
    let after = by_did(&rows);
    assert_eq!(after.len(), rows.len(), "listRepos repeats a repo: {rows:?}");
    let w = &after[&writer.did];
    assert_eq!(w["repoRev"], json!(revs[2]), "the acked notify is gone: {w}");
    assert_eq!(bytes_field(&w["hash"]), hashes[2]);
    let s2 = w["spaceRev"].as_str().unwrap().to_string();
    assert!(s2 > s1 && s2 > own, "spaceRev {s2} after {s1} and {own}");
    assert_eq!(after[&n.sc.did]["spaceRev"], json!(own), "the authority's own row moved");

    // a resend, or an older rev, is a no-op
    for i in [2, 1] {
        assert_eq!(notify(&n, &writer, &revs[i], &hashes[i]).await.status, 200);
        let row = &by_did(&list_repos(&n.sc, &n.space, &cred).await.unwrap())[&writer.did];
        assert_eq!((&row["repoRev"], &row["spaceRev"]), (&json!(revs[2]), &json!(s2)), "a stale notify moved {row}");
    }
    // and the next one is sequenced past everything from before the kill
    assert_eq!(notify(&n, &writer, &revs[3], &hashes[3]).await.status, 200);
    let row = &by_did(&list_repos(&n.sc, &n.space, &cred).await.unwrap())[&writer.did];
    assert_eq!(row["repoRev"], json!(revs[3]));
    assert!(row["spaceRev"].as_str().unwrap() > s2.as_str(), "spaceRev went back after the restart: {row}");
}

// ---------- the harness itself ----------

/// The hooks, the kill and the restart behind the front, on public writes
/// (so this runs before any space code): OAuth across the restart, a write
/// held before its segment PUT is gone, one whose PUT failed after landing
/// is acked and kept.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_harness_kills_and_restarts_a_node_behind_its_front() {
    let (bucket, front) = (Bucket::default(), Front::new().await);
    let (mut node, mut store) = hooked_node("hk", &bucket, SHARDS, &front).await;
    front.point(&node);
    let mut sc = SpaceClient::new(&front.view(&node), &unique_name("hk"), "atproto transition:generic").await;
    let did = sc.did.clone();
    let body = |text: &str| json!({"repo": did, "collection": "app.bsky.feed.post", "record": post_record(text)});
    let texts = |s: &TestServer| {
        let s = front.view(s);
        let did = did.clone();
        async move {
            let q = [("repo", did.as_str()), ("collection", "app.bsky.feed.post"), ("limit", "100")];
            let r = s.xrpc.get("com.atproto.repo.listRecords", &q, &Auth::None).await.ok();
            let recs = r["records"].as_array().cloned().unwrap_or_default();
            recs.iter().map(|r| r["value"]["text"].as_str().unwrap().to_string()).collect::<BTreeSet<_>>()
        }
    };
    sc.post("com.atproto.repo.createRecord", body("acked")).await.ok();

    for (stage, act) in [(Stage::BeforePut, Act::Pause), (Stage::AfterPut, Act::Fail)] {
        let needle = format!("zqhk{}", tag());
        let mut armed = store.arm(stage, act, &needle);
        let status = {
            let write = sc.post("com.atproto.repo.createRecord", body(&needle));
            tokio::pin!(write);
            let status = tokio::select! {
                r = &mut write => Some(r.status),
                _ = armed.wait("the post's segment") => None,
            };
            let status = match (act, status) {
                (Act::Fail, None) => tokio::time::timeout(Duration::from_secs(20), write).await.ok().map(|r| r.status),
                _ => status,
            };
            kill9(&node, &store);
            status
        };
        drop(armed);
        (node, store) = hooked_node("hk", &bucket, SHARDS, &front).await;
        front.point(&node);
        owns_all(&node).await;
        rebind(&mut sc, &node);
        let got = texts(&node).await;
        assert!(got.contains("acked"), "{stage:?}/{act:?}: {got:?}");
        match act {
            Act::Pause => assert_eq!((status, got.contains(&needle)), (None, false), "{stage:?}/{act:?}"),
            Act::Fail => assert_eq!((status, got.contains(&needle)), (Some(200), true), "{stage:?}/{act:?}"),
        }
        // OAuth still works on the new incarnation, at the same public URL
        sc.post("com.atproto.repo.createRecord", body(&format!("after {needle}"))).await.ok();
    }
}

/// The stub DID resolves through vlpds's resolver to its key and endpoints,
/// and records notifies, refused or not.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_stub_did_resolves_and_records_notifies() {
    let s = TestServer::spawn().await;
    let stub = StubDid::spawn().await;
    let doc = s.app.did_resolver.resolve(&stub.did).await.expect("resolves");
    let key = vlsync_atproto::did_resolver::signing_key_multibase(&doc).expect("#atproto key");
    assert!(stub.key.matches_public(&key), "{doc}");
    let host = vlsync_atproto::did_resolver::service_endpoint(&doc, "atproto_space_host").expect("space host");
    assert_eq!(vlsync_atproto::did_resolver::service_endpoint(&doc, "atproto_pds").as_deref(), Some(host.as_str()));
    let http = reqwest::Client::new();
    for refuse in [true, false] {
        stub.refuse(refuse);
        let jwt = stub.service_jwt(&format!("{}#atproto_space_host", stub.did), NOTIFY);
        let r = http.post(format!("{host}/xrpc/{NOTIFY}")).bearer_auth(jwt).json(&json!({"repoRev": "x"})).send();
        assert_eq!(r.await.unwrap().status().as_u16(), if refuse { 503 } else { 200 });
    }
    let seen = stub.seen();
    assert_eq!(seen.iter().map(|n| n.accepted).collect::<Vec<_>>(), [false, true]);
    assert_eq!((&seen[1].claims["iss"], &seen[1].claims["lxm"]), (&json!(stub.did), &json!(NOTIFY)));
    assert_eq!(stub.accepted().len(), 1);
}
