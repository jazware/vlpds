//! Port of packages/pds/tests/sync/sync.test.ts: repo export, diffs, record
//! proofs (inclusion + non-inclusion), status, latest commit, getBlocks,
//! listBlobs and takedown visibility.
use crate::common::*;
use std::collections::BTreeMap;

const POST: &str = "app.bsky.feed.post";

/// Posts `n` records and returns path -> (cid, value) as reported by getRecord.
async fn make_posts(
    s: &TestServer,
    a: &TestAccount,
    n: usize,
    model: &mut BTreeMap<String, (String, J)>,
) -> Vec<RecordRef> {
    let mut out = Vec::new();
    for i in 0..n {
        let r = s.post(a, &format!("post {i} {}", unique_name("t"))).await;
        let g = s.get_record(&a.did, POST, r.rkey()).await.ok();
        assert_eq!(g["cid"].as_str(), Some(r.cid.as_str()), "getRecord cid matches createRecord cid");
        model.insert(format!("{POST}/{}", r.rkey()), (r.cid.clone(), g["value"].clone()));
        out.push(r);
    }
    out
}

/// Checks a full getRepo export against the expected contents.
async fn check_full_export(s: &TestServer, a: &TestAccount, model: &BTreeMap<String, (String, J)>) -> Repo {
    let repo = s.get_repo(&a.did).await;
    repo.check_block_hashes().unwrap();
    let commit = repo.commit();
    assert_eq!(commit.did, a.did);
    assert_eq!(commit.version, 3);
    assert!(commit.prev.is_none(), "v3 commits have prev: null");
    assert!(is_tid(&commit.rev), "rev is a TID: {}", commit.rev);
    let key = s.signing_key(&a.did).await;
    commit.verify(&key).expect("commit signature verifies with the DID doc key");

    let entries = repo.entries();
    let got: BTreeMap<String, String> = entries.iter().map(|(k, v)| (k.clone(), v.to_string())).collect();
    let want: BTreeMap<String, String> = model.iter().map(|(k, (c, _))| (k.clone(), c.clone())).collect();
    assert_eq!(got, want, "MST contents equal the written records");
    for (path, (_, value)) in model {
        let v = repo.record(path).unwrap_or_else(|| panic!("record block for {path} missing from CAR"));
        assert_eq!(&v, value, "record value for {path}");
    }
    // The root of the CAR is the latest commit.
    let (latest, rev) = s.latest_commit(&a.did).await;
    assert_eq!(latest, repo.root);
    assert_eq!(rev, commit.rev);
    repo
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn creates_and_syncs_records_then_deletes() {
    let s = TestServer::spawn().await;
    let a = s.create_account("alice").await;
    let mut model = BTreeMap::new();
    let mut refs = make_posts(&s, &a, 10, &mut model).await;
    check_full_export(&s, &a, &model).await;

    // creates and deletes, including deletes of records from before the last sync
    refs.extend(make_posts(&s, &a, 10, &mut model).await);
    for i in 0..4 {
        let r = &refs[i * 5];
        s.xrpc
            .post(
                "com.atproto.repo.deleteRecord",
                &json!({"repo": a.did, "collection": POST, "rkey": r.rkey()}),
                &a.auth(),
            )
            .await
            .ok();
        model.remove(&format!("{POST}/{}", r.rkey()));
    }
    let repo = check_full_export(&s, &a, &model).await;
    assert_eq!(repo.entries().len(), 16);

    // listRecords agrees with the MST walk
    let lr = s.list_records(&a.did, POST, &[("limit", "100")]).await.ok();
    let mut listed: Vec<(String, String)> = lr["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            let uri = r["uri"].as_str().unwrap();
            (uri.split_once(&format!("at://{}/", a.did)).unwrap().1.to_string(), r["cid"].as_str().unwrap().to_string())
        })
        .collect();
    listed.sort();
    let walked: Vec<(String, String)> = repo.entries().into_iter().map(|(k, v)| (k, v.to_string())).collect();
    assert_eq!(listed, walked);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn repo_status_and_latest_commit() {
    let s = TestServer::spawn().await;
    let a = s.create_account("alice").await;
    let r = s.post(&a, "hi").await;
    let status = s.xrpc.get("com.atproto.sync.getRepoStatus", &[("did", &a.did)], &Auth::None).await.ok();
    assert_eq!(status["did"], json!(a.did));
    assert_eq!(status["active"], json!(true));
    assert!(status.get("status").is_none() || status["status"].is_null(), "no status while active: {status}");
    assert_eq!(status["rev"].as_str(), r.rev.as_deref());

    let (cid, rev) = s.latest_commit(&a.did).await;
    assert_eq!(Some(cid.to_string()), r.commit_cid);
    assert_eq!(Some(rev.clone()), r.rev);
    let lc = s.xrpc.get("com.atproto.sync.getLatestCommit", &[("did", &a.did)], &Auth::None).await.ok();
    assert_eq!(lc["rev"].as_str(), Some(rev.as_str()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unknown_repo_errors() {
    let s = TestServer::spawn().await;
    let did = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";
    for nsid in [
        "com.atproto.sync.getRepo",
        "com.atproto.sync.getLatestCommit",
        "com.atproto.sync.getRepoStatus",
        "com.atproto.sync.listBlobs",
    ] {
        s.xrpc.get(nsid, &[("did", did)], &Auth::None).await.err(400, "RepoNotFound");
    }
    s.xrpc
        .get(
            "com.atproto.sync.getRecord",
            &[("did", did), ("collection", POST), ("rkey", "3jzfcijpj2z2a")],
            &Auth::None,
        )
        .await
        .err(400, "RepoNotFound");
    let r = s
        .xrpc
        .get_multi(
            "com.atproto.sync.getBlocks",
            &[("did", did.to_string()), ("cids", "bafyreie5737gdxlw5i64vzichcalba3z2v5n6icifvx5xytvske7mr3hpm".into())],
            &Auth::None,
        )
        .await;
    r.err(400, "RepoNotFound");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn get_repo_since_returns_diff() {
    let s = TestServer::spawn().await;
    let a = s.create_account("alice").await;
    let mut model = BTreeMap::new();
    make_posts(&s, &a, 20, &mut model).await;
    let full = s.get_repo(&a.did).await;
    let before_rev = full.commit().rev;

    let r = s.post(&a, "after").await;
    let resp = s.xrpc.get("com.atproto.sync.getRepo", &[("did", &a.did), ("since", &before_rev)], &Auth::None).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let diff = Repo::from_car(&resp.body).unwrap();
    diff.check_block_hashes().unwrap();
    assert_eq!(Some(diff.root.to_string()), r.commit_cid, "diff root is the new commit");
    // only new data: no record block from before `since`. vlpds sends the
    // commit, the MST nodes and the new records (a superset of the
    // reference's rev-filtered block set, so the count depends on the MST
    // shape); every other block is an MST node
    let rec_cid = Cid::parse(&r.cid).unwrap();
    for (path, (cid, _)) in &model {
        assert!(!diff.blocks.contains_key(&Cid::parse(cid).unwrap()), "diff carries the unchanged record {path}");
    }
    for (cid, bytes) in &diff.blocks {
        if *cid == diff.root || *cid == rec_cid {
            continue;
        }
        let v = Value::decode(bytes).expect("cbor block");
        let is_mst_node =
            matches!(&v, Value::Map(m) if m.iter().any(|(k, _)| k == "e") && m.iter().any(|(k, _)| k == "l"));
        assert!(is_mst_node, "diff block {cid} is neither the commit, the new record nor an MST node: {v:?}");
    }
    assert!(diff.blocks.len() < full.blocks.len());
    assert!(diff.blocks.contains_key(&rec_cid), "diff contains the new record block");
    // Applying the diff on top of the old block set yields the full new repo.
    let mut merged = full.blocks.clone();
    merged.extend(diff.blocks.clone());
    let tree = vlsync_atproto::mst::Tree::load_from_blocks(&merged, diff.commit().data)
        .expect("diff + old blocks = complete tree");
    let mut n = 0;
    tree.walk(&mut |_, _| n += 1);
    assert_eq!(n, 21);
    assert_eq!(tree.get(format!("{POST}/{}", r.rkey()).as_bytes()).unwrap(), Some(rec_cid));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn record_inclusion_proof() {
    let s = TestServer::spawn().await;
    let a = s.create_account("alice").await;
    let mut model = BTreeMap::new();
    let refs = make_posts(&s, &a, 30, &mut model).await;
    let key = s.signing_key(&a.did).await;
    for r in [&refs[0], &refs[13], &refs[29]] {
        let resp = s
            .xrpc
            .get(
                "com.atproto.sync.getRecord",
                &[("did", &a.did), ("collection", POST), ("rkey", r.rkey())],
                &Auth::None,
            )
            .await;
        assert_eq!(resp.status, 200, "{}", resp.text());
        assert_eq!(resp.header("content-type").as_deref(), Some("application/vnd.ipld.car"));
        let path = format!("{POST}/{}", r.rkey());
        let got = verify_record_proof(&resp.body, &a.did, &path, Some(&key)).expect("proof verifies");
        assert_eq!(got.map(|c| c.to_string()), Some(r.cid.clone()));
        // the record block decodes to the record value
        let repo = Repo::from_car(&resp.body).unwrap();
        let v = Value::decode(&repo.blocks[&got.unwrap()]).unwrap().to_json();
        assert_eq!(v, model[&path].1);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn record_non_inclusion_proof() {
    let s = TestServer::spawn().await;
    let a = s.create_account("alice").await;
    let mut model = BTreeMap::new();
    let refs = make_posts(&s, &a, 30, &mut model).await;
    let key = s.signing_key(&a.did).await;
    // a fresh TID rkey that doesn't exist, and a deleted one
    let missing = vlsync_atproto::tid::TidClock::new().next().to_string();
    s.xrpc
        .post(
            "com.atproto.repo.deleteRecord",
            &json!({"repo": a.did, "collection": POST, "rkey": refs[7].rkey()}),
            &a.auth(),
        )
        .await
        .ok();
    for rkey in [missing.as_str(), refs[7].rkey()] {
        let resp = s
            .xrpc
            .get("com.atproto.sync.getRecord", &[("did", &a.did), ("collection", POST), ("rkey", rkey)], &Auth::None)
            .await;
        assert_eq!(resp.status, 200, "non-existence proof should be served: {}", resp.text());
        let got =
            verify_record_proof(&resp.body, &a.did, &format!("{POST}/{rkey}"), Some(&key)).expect("proof verifies");
        assert_eq!(got, None, "proof shows {rkey} is absent");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn get_blocks() {
    let s = TestServer::spawn().await;
    let a = s.create_account("alice").await;
    let r1 = s.post(&a, "one").await;
    let r2 = s.post(&a, "two").await;
    let commit = r2.commit_cid.clone().unwrap();
    let resp = s
        .xrpc
        .get_multi(
            "com.atproto.sync.getBlocks",
            &[("did", a.did.clone()), ("cids", r1.cid.clone()), ("cids", r2.cid.clone()), ("cids", commit.clone())],
            &Auth::None,
        )
        .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let (_, blocks) = vlsync_atproto::car::read_car(&resp.body).unwrap();
    let got: std::collections::HashSet<String> = blocks.iter().map(|(c, _)| c.to_string()).collect();
    for c in [&r1.cid, &r2.cid, &commit] {
        assert!(got.contains(c), "getBlocks returned {c}");
    }
    for (c, b) in &blocks {
        assert_eq!(*c, Cid::dag_cbor(b), "block content hashes to its cid");
    }

    // a CID that isn't in the repo -> BlockNotFound
    let bogus = Cid::dag_cbor(b"not a block").to_string();
    let resp =
        s.xrpc.get_multi("com.atproto.sync.getBlocks", &[("did", a.did.clone()), ("cids", bogus)], &Auth::None).await;
    resp.err(400, "BlockNotFound");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn list_blobs() {
    let s = TestServer::spawn().await;
    let a = s.create_account("alice").await;
    let up = s.xrpc.post_bytes("com.atproto.repo.uploadBlob", PNG_1X1.to_vec(), "image/png", &a.auth()).await.ok();
    let blob = up["blob"].clone();
    let blob_cid = blob["ref"]["$link"].as_str().unwrap().to_string();
    let before = s.post(&a, "no blob").await;
    s.create_record(
        &a,
        POST,
        json!({"$type": POST, "text": "pic", "createdAt": now_iso(),
               "embed": {"$type": "app.bsky.embed.images", "images": [{"image": blob, "alt": ""}]}}),
    )
    .await;
    let lb = s.xrpc.get("com.atproto.sync.listBlobs", &[("did", &a.did)], &Auth::None).await.ok();
    let cids: Vec<&str> = lb["cids"].as_array().expect("cids").iter().filter_map(|c| c.as_str()).collect();
    assert_eq!(cids, vec![blob_cid.as_str()]);
    // since a rev after the referencing commit -> nothing new
    let (_, rev) = s.latest_commit(&a.did).await;
    let lb = s.xrpc.get("com.atproto.sync.listBlobs", &[("did", &a.did), ("since", &rev)], &Auth::None).await.ok();
    assert_eq!(lb["cids"].as_array().map(|a| a.len()), Some(0), "{lb}");
    // since a rev before it -> the blob
    let lb = s
        .xrpc
        .get("com.atproto.sync.listBlobs", &[("did", &a.did), ("since", before.rev.as_deref().unwrap())], &Auth::None)
        .await
        .ok();
    assert_eq!(lb["cids"], json!([blob_cid]));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn repo_takedown_visibility() {
    let s = TestServer::spawn().await;
    let a = s.create_account("alice").await;
    let r = s.post(&a, "hi").await;
    set_repo_takedown(&s, &a.did, true).await;

    let st = s.xrpc.get("com.atproto.sync.getRepoStatus", &[("did", &a.did)], &Auth::None).await.ok();
    assert_eq!(st["active"], json!(false));
    assert_eq!(st["status"], json!("takendown"));
    assert!(st.get("rev").is_none() || st["rev"].is_null(), "no rev while inactive (matches TS): {st}");

    let lr = s.xrpc.get("com.atproto.sync.listRepos", &[], &Auth::None).await.ok();
    let found = lr["repos"].as_array().unwrap().iter().find(|x| x["did"] == json!(a.did)).cloned().expect("listed");
    assert_eq!(found["active"], json!(false));
    assert_eq!(found["status"], json!("takendown"));

    // unauthenticated reads are refused
    s.xrpc.get("com.atproto.sync.getRepo", &[("did", &a.did)], &Auth::None).await.err(400, "RepoTakendown");
    s.xrpc.get("com.atproto.sync.getLatestCommit", &[("did", &a.did)], &Auth::None).await.err(400, "RepoTakendown");
    s.xrpc
        .get("com.atproto.sync.getRecord", &[("did", &a.did), ("collection", POST), ("rkey", r.rkey())], &Auth::None)
        .await
        .err(400, "RepoTakendown");

    // the owner and admins can still sync
    let owner = s.xrpc.get("com.atproto.sync.getRepo", &[("did", &a.did)], &a.auth()).await;
    assert_eq!(owner.status, 200, "owner getRepo: {}", owner.text());
    let admin = s.xrpc.get("com.atproto.sync.getRepo", &[("did", &a.did)], &Auth::Admin).await;
    assert_eq!(admin.status, 200, "admin getRepo: {}", admin.text());

    // restore
    set_repo_takedown(&s, &a.did, false).await;
    let st = s.xrpc.get("com.atproto.sync.getRepoStatus", &[("did", &a.did)], &Auth::None).await.ok();
    assert_eq!(st["active"], json!(true));
    s.xrpc.get("com.atproto.sync.getRepo", &[("did", &a.did)], &Auth::None).await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn deactivated_repo_visibility() {
    let s = TestServer::spawn().await;
    let a = s.create_account("alice").await;
    s.post(&a, "hi").await;
    s.xrpc.post("com.atproto.server.deactivateAccount", &json!({}), &a.auth()).await.ok();
    let st = s.xrpc.get("com.atproto.sync.getRepoStatus", &[("did", &a.did)], &Auth::None).await.ok();
    assert_eq!(st["active"], json!(false));
    assert_eq!(st["status"], json!("deactivated"));
    s.xrpc.get("com.atproto.sync.getRepo", &[("did", &a.did)], &Auth::None).await.err(400, "RepoDeactivated");
    s.xrpc.get("com.atproto.sync.getLatestCommit", &[("did", &a.did)], &Auth::None).await.err(400, "RepoDeactivated");
}
