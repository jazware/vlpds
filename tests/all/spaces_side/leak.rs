//! Space data never leaves the space surface. Space records are written with
//! unique sentinels in their values, field names, rkeys, collection and
//! space URI (type and skey); none of those byte strings, nor the records'
//! CIDs or the space's sid, may show up on a live, sharded or backfilled
//! subscribeRepos, a raw S3 backfill, or the author's public sync and repo
//! endpoints. The author's public rev and commit don't move across space
//! writes, and every log entry that carries s* state has an empty frame
//! (plan §2.0: space writes are private log entries).

use crate::common::spaces::SpaceClient;
use crate::common::*;
use object_store::ObjectStoreExt;
use sha2::Digest;
use std::sync::Arc;
use std::time::Duration;
use vlsync_store::slots::{slot_of, SlotRange};

/// Every state family a space write or the space host may put in the log
/// (plan §2.1, C5's sb/sc blob refs).
pub(super) const SPACE_FAMILIES: &[&[u8]] =
    &[b"sH/", b"sR/", b"sO/", b"sP/", b"sS/", b"sW/", b"sQ/", b"sM/", b"sN/", b"sb/", b"sc/"];

pub(super) const SHARDS: u32 = 4;
const IDLE: Duration = Duration::from_millis(600);

#[derive(Default)]
pub(super) struct Sentinels(Vec<(String, Vec<u8>)>);

impl Sentinels {
    pub(super) fn push(&mut self, what: impl Into<String>, b: impl AsRef<[u8]>) {
        assert!(b.as_ref().len() >= 8, "a short sentinel would match by chance");
        self.0.push((what.into(), b.as_ref().to_vec()));
    }

    pub(super) fn extend(&mut self, other: &Sentinels) {
        self.0.extend(other.0.iter().cloned());
    }

    pub(super) fn push_cid(&mut self, what: &str, cid: &str) {
        self.push(format!("{what} {cid}"), cid);
        self.push(format!("{what} {cid} (binary)"), Cid::parse(cid).expect("cid").to_bytes());
    }

    pub(super) fn find(&self, bytes: &[u8]) -> Option<(&str, usize)> {
        self.0.iter().find_map(|(what, s)| bytes.windows(s.len()).position(|w| w == s).map(|i| (what.as_str(), i)))
    }

    pub(super) fn assert_clean(&self, source: &str, bytes: &[u8]) {
        if let Some((what, at)) = self.find(bytes) {
            let lo = at.saturating_sub(48);
            panic!(
                "{what} leaked into {source} at byte {at}: …{}…",
                String::from_utf8_lossy(&bytes[lo..(at + 96).min(bytes.len())])
            );
        }
    }

    pub(super) fn assert_frames_clean(&self, source: &str, frames: &[Frame]) {
        for f in frames {
            self.assert_clean(&format!("{source} (seq {:?}, {})", f.seq(), f.kind()), &f.raw);
        }
    }
}

/// A space anchored on a fresh OAuth account (authority self) and what was
/// written into it: its sentinels, the space record CIDs and how many space
/// write calls were acked.
pub(super) struct Planted {
    pub sc: SpaceClient,
    /// The space client's account, for public writes with its session.
    pub author: TestAccount,
    pub space: String,
    collection: String,
    rkey: String,
    value: String,
    field: String,
    pub sentinels: Sentinels,
    cids: Vec<String>,
    pub writes: usize,
}

fn tag() -> String {
    random_bytes(6).iter().map(|b| format!("{b:02x}")).collect()
}

fn space_record(collection: &str, value: &str, field: &str, i: usize) -> J {
    json!({"$type": collection, "text": format!("{value} #{i}"), field: value, "createdAt": now_iso()})
}

impl Planted {
    /// The account (with one public post) and its space; nothing written
    /// into the space yet.
    pub(super) async fn new(via: &TestServer) -> Planted {
        let t = tag();
        let space_type = format!("com.example.zqtype{t}.space");
        let skey = format!("zqskey{t}");
        let collection = format!("com.example.zqcol{t}.note");
        let scope = format!(
            "space:{space_type}?collection={collection}&action=read&action=create&action=update&action=delete&manage=create"
        );
        let sc = SpaceClient::new(via, &unique_name("lk"), &scope).await;
        let author = TestAccount {
            did: sc.did.clone(),
            handle: sc.handle.clone(),
            password: crate::oauth::PASSWORD.into(),
            email: String::new(),
            access: sc.session_jwt.clone(),
            refresh: String::new(),
        };
        via.post(&author, "public before").await;
        let space = sc.create_space(&space_type, &skey).await;
        assert!(space.contains(&skey) && space.contains(&space_type), "{space}");

        let (rkey, value, field) = (format!("zqrkey{t}"), format!("zqvalue{t}"), format!("zqfield{t}"));
        let mut s = Sentinels::default();
        s.push("space type", &space_type);
        s.push("skey", &skey);
        s.push("space URI", &space);
        s.push("collection", &collection);
        s.push("rkey", &rkey);
        s.push("record value", &value);
        s.push("record field name", &field);
        let sid = &sha2::Sha256::digest(space.as_bytes())[..16];
        s.push("sid", sid);
        s.push("sid (hex)", sid.iter().map(|b| format!("{b:02x}")).collect::<String>());
        Planted { sc, author, space, collection, rkey, value, field, sentinels: s, cids: Vec::new(), writes: 0 }
    }

    /// One space write through the client, then a public post by `public`
    /// so the log interleaves public commits with private entries.
    async fn write(&mut self, via: &TestServer, public: &TestAccount, nsid: &str, body: J) -> Resp {
        let r = self.sc.post(nsid, body.clone()).await;
        assert_eq!(r.status, 200, "{nsid} {body}: {}", r.text());
        self.writes += 1;
        via.post(public, &format!("public interleave {}", self.writes)).await;
        let results = r.json["results"].as_array().into_iter().flatten();
        for cid in std::iter::once(&r.json).chain(results).filter_map(|j| j["cid"].as_str()) {
            self.sentinels.push_cid(&format!("{nsid} record"), cid);
            self.cids.push(cid.to_string());
        }
        r
    }

    /// `n` + 5 space write calls (create, TID create, put, a dependent
    /// applyWrites batch, delete, then `n` creates), every op carrying
    /// sentinels. `public` must not be the author.
    pub(super) async fn fill(&mut self, via: &TestServer, public: &TestAccount, n: usize) {
        let (c, rk, space, did) = (self.collection.clone(), self.rkey.clone(), self.space.clone(), self.sc.did.clone());
        let body = |extra: J| {
            let mut b = json!({"space": space, "repo": did});
            b.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
            b
        };
        let rec = |i| space_record(&c, &self.value, &self.field, i);
        let op = |kind: &str, rkey: &str, i: Option<usize>| {
            let mut o =
                json!({"$type": format!("com.atproto.space.applyWrites#{kind}"), "collection": c, "rkey": rkey});
            if let Some(i) = i {
                o["value"] = rec(i);
            }
            o
        };
        let (rk0, rk1, rk2) = (format!("{rk}-0"), format!("{rk}-1"), format!("{rk}-2"));
        let mut calls = vec![
            ("com.atproto.space.createRecord", body(json!({"collection": c, "rkey": rk0, "record": rec(0)}))),
            // a TID rkey: only the value, field and collection carry sentinels
            ("com.atproto.space.createRecord", body(json!({"collection": c, "record": rec(1)}))),
            ("com.atproto.space.putRecord", body(json!({"collection": c, "rkey": rk0, "record": rec(2)}))),
            // dependent ops in one batch: create then update rk1, create then delete rk2
            (
                "com.atproto.space.applyWrites",
                body(json!({"writes": [
                    op("create", &rk1, Some(3)),
                    op("update", &rk1, Some(4)),
                    op("create", &rk2, Some(5)),
                    op("delete", &rk2, None),
                ]})),
            ),
            ("com.atproto.space.deleteRecord", body(json!({"collection": c, "rkey": rk0}))),
        ];
        for i in 0..n {
            calls.push((
                "com.atproto.space.createRecord",
                body(json!({"collection": c, "rkey": format!("{rk}-n{i}"), "record": rec(10 + i)})),
            ));
        }
        for (nsid, b) in calls {
            self.write(via, public, nsid, b).await;
        }
    }
}

pub(super) async fn sub_shard(s: &TestServer, cursor: i64, k: u32, n: u32) -> Sub {
    Sub::connect(&format!("ws://{}/xrpc/com.atproto.sync.subscribeRepos?cursor={cursor}&shard={k}/{n}", s.addr)).await
}

fn is_commit(f: &Frame, cid: &Cid) -> bool {
    matches!(f.body.get("commit"), Some(Value::Link(c)) if c == cid)
}

/// Reads `sub` up to and including the #commit `marker`.
pub(super) async fn read_to_commit(sub: &mut Sub, marker: &Cid) -> Vec<Frame> {
    sub.until(FH_TIMEOUT, |fs| fs.last().is_some_and(|f| is_commit(f, marker))).await
}

/// Reads a k/n stream up to the last event of `full` in its slot range
/// (drained until idle when the range has none).
pub(super) async fn read_shard(sub: &mut Sub, full: &[Frame], k: u32) -> Vec<Frame> {
    let range = SlotRange::new(k, SHARDS).unwrap();
    let last = full.iter().rev().find(|f| f.did().is_some_and(|d| range.contains(slot_of(d)))).and_then(|f| f.seq());
    match last {
        Some(last) => sub.until(FH_TIMEOUT, |fs| fs.last().and_then(|f| f.seq()).is_some_and(|q| q >= last)).await,
        None => sub.drain(IDLE).await,
    }
}

/// Every (seq, frame) in S3 under the cluster's logs, through the same
/// segment::events path a cursor older than the ring replays.
pub(super) async fn s3_backfill(s: &TestServer) -> Vec<(i64, Vec<u8>)> {
    let s3 = s.app.firehose.store.read().clone().unwrap();
    let (tx, mut rx) = tokio::sync::mpsc::channel(1 << 16);
    let job = tokio::spawn(async move { vlsync_firehose::backfill::backfill(&s3, 0, i64::MAX, &tx).await });
    let mut all = Vec::new();
    while let Some((seq, frame)) = rx.recv().await {
        all.push((seq, frame.to_vec()));
    }
    job.await.unwrap().unwrap();
    all
}

/// Scans every segment of `s`'s own log: an entry carrying an s* key has an
/// empty frame, and no non-empty frame carries a sentinel. Returns how many
/// entries carried s* keys and whether a sentinel turned up inside their
/// muts (proof the scan sees the space writes at all).
pub(super) async fn scan_log(s: &TestServer, p: &Planted) -> (usize, bool) {
    use futures::StreamExt;
    let store = &s.app.store;
    let prefix = object_store::path::Path::from(format!("{}/log/{}", store.prefix, s.app.log.log_id));
    let metas: Vec<_> = store.raw.list(Some(&prefix)).map(|m| m.unwrap()).collect().await;
    assert!(!metas.is_empty(), "no segments under {prefix}");
    let (mut private, mut seen) = (0, false);
    for m in metas {
        let data = store.raw.get(&m.location).await.unwrap().bytes().await.unwrap();
        let vlsync_store::segment::LogObject::Segment(_, entries) = vlpds::derived::parse(data, None).unwrap() else {
            continue;
        };
        for e in entries {
            let space_keys: Vec<&[u8]> = e
                .muts
                .iter()
                .map(|m| {
                    if vlsync_store::keys::key_slot(&m.key).is_some() {
                        vlsync_store::keys::key_body(&m.key)
                    } else {
                        &m.key[..]
                    }
                })
                .filter(|body| SPACE_FAMILIES.iter().any(|f| body.starts_with(f)))
                .collect();
            if !space_keys.is_empty() {
                private += 1;
                assert!(
                    e.frame.is_empty(),
                    "{}: entry seq {} carries {} s* muts (first {:?}) and a {} B frame",
                    m.location,
                    e.seq,
                    space_keys.len(),
                    String::from_utf8_lossy(&space_keys[0][..3]),
                    e.frame.len()
                );
                seen |= e.muts.iter().any(|m| {
                    p.sentinels.find(&m.key).is_some() || m.val.as_ref().is_some_and(|v| p.sentinels.find(v).is_some())
                });
            }
            if !e.frame.is_empty() {
                p.sentinels.assert_clean(&format!("{} entry seq {} frame", m.location, e.seq), &e.frame);
            }
        }
    }
    (private, seen)
}

/// The author's public sync and repo surface, each response checked for
/// sentinels; the space collection and records are absent from it.
pub(super) async fn check_public_surface(s: &TestServer, did: &str, p: &Planted) {
    let get = |nsid: &'static str, q: Vec<(&'static str, String)>| async move {
        let qs: Vec<(&str, &str)> = q.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let mut r = s.xrpc.get(nsid, &qs, &Auth::None).await;
        // an error message may echo what was asked for: not a leak
        if r.status >= 400 {
            let mut body = String::from_utf8_lossy(&r.body).into_owned();
            for (_, v) in &q {
                body = body.replace(v.as_str(), "");
            }
            r.body = body.into_bytes().into();
        }
        (nsid, r)
    };
    let d = || did.to_string();
    let rk = format!("{}-n0", p.rkey);
    let mut checked = vec![
        get("com.atproto.sync.getRepo", vec![("did", d())]).await,
        get("com.atproto.sync.getLatestCommit", vec![("did", d())]).await,
        get("com.atproto.sync.getRepoStatus", vec![("did", d())]).await,
        get("com.atproto.sync.getHead", vec![("did", d())]).await,
        get("com.atproto.sync.listBlobs", vec![("did", d())]).await,
        get("com.atproto.sync.listReposByCollection", vec![("collection", p.collection.clone())]).await,
        get(
            "com.atproto.sync.getRecord",
            vec![("did", d()), ("collection", p.collection.clone()), ("rkey", rk.clone())],
        )
        .await,
        get("com.atproto.repo.describeRepo", vec![("repo", d())]).await,
        get("com.atproto.repo.listRecords", vec![("repo", d()), ("collection", p.collection.clone())]).await,
        get("com.atproto.repo.getRecord", vec![("repo", d()), ("collection", p.collection.clone()), ("rkey", rk)])
            .await,
    ];
    let mut cursor = None::<String>;
    loop {
        let mut q = vec![("limit", "1000".to_string())];
        q.extend(cursor.clone().map(|c| ("cursor", c)));
        let page = get("com.atproto.sync.listRepos", q).await;
        cursor = page.1.json["cursor"].as_str().map(String::from);
        checked.push(page);
        if cursor.is_none() {
            break;
        }
    }
    for (nsid, r) in &checked {
        assert!(r.status < 500, "{nsid}: {}", r.text());
        p.sentinels.assert_clean(nsid, &r.body);
    }
    let by_nsid = |n: &str| &checked.iter().find(|(x, _)| *x == n).unwrap().1;
    assert_eq!(by_nsid("com.atproto.sync.getRepo").status, 200);
    let collections = &by_nsid("com.atproto.repo.describeRepo").json["collections"];
    assert!(
        !collections.as_array().unwrap().iter().any(|c| c.as_str() == Some(&p.collection)),
        "describeRepo lists the space collection: {collections}"
    );
    let listed = &by_nsid("com.atproto.repo.listRecords").json["records"];
    assert!(listed.as_array().is_none_or(|v| v.is_empty()), "public listRecords returned space records: {listed}");
    assert_ne!(by_nsid("com.atproto.repo.getRecord").status, 200, "public getRecord served a space record");
    let by_coll = &by_nsid("com.atproto.sync.listReposByCollection").json["repos"];
    assert!(
        by_coll.as_array().is_none_or(|v| v.is_empty()),
        "listReposByCollection names a space collection: {by_coll}"
    );

    // a record CID is neither a blob nor a public block
    for cid in &p.cids {
        let r = s.get_blob(did, cid).await;
        assert_ne!(r.status, 200, "sync.getBlob served space record {cid}");
        let r = s.get_blocks(did, &[Cid::parse(cid).unwrap()]).await;
        assert_ne!(r.status, 200, "sync.getBlocks served space record {cid}");
        // the error names the CIDs asked for: not a leak
        let body = String::from_utf8_lossy(&r.body).replace(cid.as_str(), "");
        p.sentinels.assert_clean("sync.getBlocks", body.as_bytes());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn space_writes_never_reach_the_firehose_backfill_or_public_sync() {
    // A 2 KiB ring: a cursor-0 replay comes from the segments in S3
    // (firehose_backfill.rs), not memory.
    let s = TestServer::spawn_with(|c| {
        c.spaces = true;
        c.firehose_ring_bytes = 2048;
    })
    .await;
    let public = s.create_account("lkp").await;
    let mut p = Planted::new(&s).await;
    let a = p.author.clone();

    let mut live = s.subscribe(None).await;
    s.sync_subs(&public, std::slice::from_mut(&mut live)).await;
    let from = s.settled_now().await;
    let mut shards = Vec::new();
    for k in 0..SHARDS {
        shards.push(sub_shard(&s, from, k, SHARDS).await);
    }

    let before = s.latest_commit(&a.did).await;
    let status_before = s.repo_status(&a.did).await.ok();
    p.fill(&s, &public, 12).await;
    assert_eq!(s.latest_commit(&a.did).await, before, "space writes moved the author's public commit/rev");
    assert_eq!(s.repo_status(&a.did).await.ok(), status_before, "space writes changed getRepoStatus");

    let marker = Cid::parse(s.post(&a, "public after").await.commit_cid.as_deref().unwrap()).unwrap();

    let full = read_to_commit(&mut live, &marker).await;
    assert!(full.len() > p.writes, "live stream: {} frames for {} interleaved posts", full.len(), p.writes);
    p.sentinels.assert_frames_clean("live subscribeRepos", &full);
    for (k, sub) in shards.iter_mut().enumerate() {
        let fs = read_shard(sub, &full, k as u32).await;
        p.sentinels.assert_frames_clean(&format!("live subscribeRepos shard {k}/{SHARDS}"), &fs);
    }

    let mut replay = s.subscribe(Some(0)).await;
    let fs = read_to_commit(&mut replay, &marker).await;
    assert!(fs.len() > full.len(), "cursor 0 replays the whole history ({} frames)", fs.len());
    assert!(!fs.iter().any(|f| f.kind() == "#info"), "cursor 0 within retention: no OutdatedCursor");
    p.sentinels.assert_frames_clean("cursor-0 backfill", &fs);
    for k in 0..SHARDS {
        let mut sub = sub_shard(&s, 0, k, SHARDS).await;
        let fs = read_shard(&mut sub, &full, k).await;
        p.sentinels.assert_frames_clean(&format!("cursor-0 backfill shard {k}/{SHARDS}"), &fs);
    }
    for (seq, raw) in s3_backfill(&s).await {
        p.sentinels.assert_clean(&format!("S3 backfill seq {seq}"), &raw);
    }

    check_public_surface(&s, &a.did, &p).await;
    let (private, seen) = scan_log(&s, &p).await;
    assert!(private > p.writes, "{private} log entries carry s* keys for createSpace + {} writes", p.writes);
    assert!(seen, "no sentinel inside any s* mut: the log scan isn't seeing the space writes");
}

/// The same checks on a 2-node cluster: each node's stream merges the
/// peer's log, so a private entry must stay out of the peer stream too.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn space_writes_stay_private_through_the_peer_stream() {
    let store: Arc<dyn object_store::ObjectStore> = Arc::new(object_store::memory::InMemory::new());
    // one public URL for both nodes, so the author's OAuth grant (minted on
    // its home node: a DID lands where it was created) holds on either
    let front = super::hooks::Front::new().await;
    let set = |url: String| {
        move |c: &mut vlpds::server::Config| {
            c.spaces = true;
            c.firehose_ring_bytes = 2048;
            c.public_url = url;
        }
    };
    let n1 = cluster_node("lk-1", store.clone(), 4, set(front.url.clone())).await;
    let n2 = cluster_node("lk-2", store.clone(), 4, set(front.url.clone())).await;
    balanced(&[&n1, &n2]).await;
    let public = n1.create_account("lkcp").await;
    // an author owned by n2, written through n1's forwarding path
    front.point(&n2);
    let mut p = Planted::new(&front.view(&n2)).await;
    front.point(&n1);
    let a = p.author.clone();
    let (owner, other) = (&n2, &n1);
    assert!(std::ptr::eq(owner_of(&[&n1, &n2], &a.did), owner), "no account landed on n2");

    let mut lives = vec![other.subscribe(None).await, owner.subscribe(None).await];
    other.sync_subs(&public, &mut lives).await;
    let before = owner.latest_commit(&a.did).await;
    p.fill(&n1, &public, 6).await;
    assert_eq!(owner.latest_commit(&a.did).await, before, "space writes moved the author's public commit/rev");
    let marker = Cid::parse(owner.post(&a, "public after").await.commit_cid.as_deref().unwrap()).unwrap();

    for (n, live) in [other, owner].into_iter().zip(lives.iter_mut()) {
        let id = &cluster(n).cfg.node_id;
        let full = read_to_commit(live, &marker).await;
        p.sentinels.assert_frames_clean(&format!("{id} live"), &full);
        let mut replay = n.subscribe(Some(0)).await;
        p.sentinels.assert_frames_clean(&format!("{id} cursor 0"), &read_to_commit(&mut replay, &marker).await);
        for k in 0..SHARDS {
            let mut sub = sub_shard(n, 0, k, SHARDS).await;
            let fs = read_shard(&mut sub, &full, k).await;
            p.sentinels.assert_frames_clean(&format!("{id} cursor-0 shard {k}/{SHARDS}"), &fs);
        }
        check_public_surface(n, &a.did, &p).await;
    }
    for (seq, raw) in s3_backfill(owner).await {
        p.sentinels.assert_clean(&format!("S3 backfill seq {seq}"), &raw);
    }
    let (private, seen) = scan_log(owner, &p).await;
    assert!(private > p.writes && seen, "owner log: {private} private entries, sentinel seen {seen}");
    let (_, seen_other) = scan_log(other, &p).await;
    assert!(!seen_other, "the non-owner's own log carries the author's space state");
}

/// A blob referenced only from a space record is never public (the
/// reference's sync.getBlob rule, on with --spaces): not served, not listed,
/// and its CID stays off the firehose and the public repo. A public
/// reference to the same blob then serves it (the control).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn space_only_blobs_stay_off_public_endpoints() {
    let s = TestServer::spawn_with(|c| {
        c.spaces = true;
        c.firehose_ring_bytes = 2048;
    })
    .await;
    let public = s.create_account("lkbp").await;
    let mut p = Planted::new(&s).await;
    let a = p.author.clone();
    let mut live = s.subscribe(None).await;
    s.sync_subs(&public, std::slice::from_mut(&mut live)).await;

    p.fill(&s, &public, 0).await;
    let t = tag();
    let mut bytes = random_png(7);
    bytes.extend_from_slice(format!("zqblobbytes{t}").as_bytes());
    p.sentinels.push("blob bytes", format!("zqblobbytes{t}"));
    let blob = s.upload_blob(&a, &bytes, "image/png").await;
    let cid = blob["ref"]["$link"].as_str().expect("blob cid").to_string();

    let unreferenced = s.get_blob(&a.did, &cid).await;
    assert_eq!(
        (unreferenced.status, unreferenced.error_name()),
        (400, Some("BlobNotFound")),
        "an uploaded, unreferenced blob is served with --spaces on: {}",
        unreferenced.text()
    );

    let rec = json!({"$type": p.collection, "text": "with a blob", "embed": {"$type": "app.bsky.embed.images", "images": [{"alt": "", "image": blob}]}, "createdAt": now_iso()});
    let r = p
        .sc
        .post(
            "com.atproto.space.createRecord",
            json!({"space": p.space, "repo": a.did, "collection": p.collection, "rkey": format!("{}-blob", p.rkey), "record": rec}),
        )
        .await;
    assert_eq!(r.status, 200, "space record with a blob: {}", r.text());
    p.sentinels.push_cid("space record with blob", r.json["cid"].as_str().unwrap());

    let got = s.get_blob(&a.did, &cid).await;
    assert_eq!(
        (got.status, got.error_name()),
        (400, Some("BlobNotFound")),
        "sync.getBlob served a space-only blob: {}",
        got.status
    );
    assert!(!s.list_blobs(&a.did).await.contains(&cid), "sync.listBlobs lists a space-only blob");
    let marker = Cid::parse(s.post(&a, "public after").await.commit_cid.as_deref().unwrap()).unwrap();
    let mut blob_sentinels = Sentinels::default();
    blob_sentinels.push_cid("space-only blob", &cid);
    for f in read_to_commit(&mut live, &marker).await {
        blob_sentinels.assert_clean("live subscribeRepos", &f.raw);
        p.sentinels.assert_clean("live subscribeRepos", &f.raw);
    }
    blob_sentinels.assert_clean("sync.getRepo", &s.get_repo_car(&a.did).await);
    check_public_surface(&s, &a.did, &p).await;

    s.create_record(&a, "app.bsky.feed.post", image_post("now public", &blob)).await;
    let r = s.get_blob(&a.did, &cid).await;
    assert_eq!(r.status, 200, "a publicly referenced blob is served: {}", r.text());
    assert_eq!(&r.body[..], &bytes[..]);
}
