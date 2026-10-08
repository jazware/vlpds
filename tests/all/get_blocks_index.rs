//! getBlocks by index: record CIDs through the record CID keys (`c/`,
//! including one CID at several paths), MST node CIDs through the node
//! index (built on first use, advanced by later commits, caught up after
//! importRepo replaces the tree), and BlockNotFound for blocks that only
//! older versions of the repo had.
use crate::common::*;
use std::collections::HashSet;

/// Every CID of the repo export (commit, MST nodes, records) comes back
/// with the exported bytes.
async fn assert_all_served(s: &TestServer, did: &str, repo: &Repo) -> (Vec<Cid>, Vec<Cid>) {
    let tree = repo.tree();
    let mut nodes = Vec::new();
    tree.walk_blocks(&mut |c, _| nodes.push(c)).unwrap();
    let records: Vec<Cid> = repo.entries().into_iter().map(|(_, c)| c).collect::<HashSet<_>>().into_iter().collect();
    let mut all = vec![repo.root];
    all.extend(&nodes);
    all.extend(&records);
    for chunk in all.chunks(50) {
        let r = s.get_blocks(did, chunk).await;
        assert_eq!(r.status, 200, "{}", r.text());
        let (_, blocks) = vlatproto::car::read_car(&r.body).unwrap();
        assert_eq!(blocks.len(), chunk.len());
        for (c, b) in blocks {
            assert_eq!(Some(b), repo.blocks.get(&c).map(|v| &v[..]), "{c}");
        }
    }
    (nodes, records)
}

async fn assert_missing(s: &TestServer, did: &str, cids: &[Cid]) {
    for c in cids {
        s.get_blocks(did, &[*c]).await.err(400, "BlockNotFound");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn get_blocks_by_index() {
    let s = TestServer::spawn().await;
    let a = s.create_account("alice").await;
    for i in 0..60 {
        s.post(&a, &format!("post {i}")).await;
    }
    // one like record at three paths: one CID, three c/ keys
    let like = json!({"$type": "app.bsky.feed.like", "createdAt": "2026-10-01T00:00:00.000Z",
        "subject": {"uri": format!("at://{}/app.bsky.feed.post/3l3qo2vuowo2b", a.did),
                    "cid": "bafyreie5737gdxlw5i64vzichcalba3z2v5n6icifvx5xytvske7mr3hpm"}});
    let mut like_cid = None;
    for rkey in ["3l3qo2vuowo2a", "3l3qo2vuowo2b", "3l3qo2vuowo2c"] {
        let body = json!({"repo": a.did, "collection": "app.bsky.feed.like", "rkey": rkey, "record": like});
        let r = s.xrpc.post("com.atproto.repo.createRecord", &body, &a.auth()).await.ok();
        assert!(like_cid.replace(r["cid"].as_str().unwrap().to_string()).is_none_or(|c| c == r["cid"]));
    }
    let like_cid = Cid::parse(&like_cid.unwrap()).unwrap();
    let car1 = s.xrpc.get("com.atproto.sync.getRepo", &[("did", &a.did)], &Auth::None).await;
    let repo1 = Repo::from_car(&car1.body).unwrap();
    let (nodes1, records1) = assert_all_served(&s, &a.did, &repo1).await;
    assert!(nodes1.len() > 5, "{} nodes", nodes1.len());
    assert_missing(&s, &a.did, &[Cid::dag_cbor(b"nope"), Cid::raw(b"nope")]).await;

    // later commits: the index advances; replaced nodes and records go
    let first_post = repo1.entries().into_iter().find(|(p, _)| p.starts_with("app.bsky.feed.post/")).unwrap();
    for i in 0..20 {
        s.post(&a, &format!("later {i}")).await;
    }
    let rkey = first_post.0.split_once('/').unwrap().1;
    s.put_record(&a, "app.bsky.feed.post", rkey, post_record("edited")).await.ok();
    let delete = |rkey: &'static str| {
        let r = s.delete_record(&a, "app.bsky.feed.like", rkey);
        async move { r.await.ok() }
    };
    delete("3l3qo2vuowo2a").await;
    let repo2 = s.get_repo(&a.did).await;
    let (nodes2, _) = assert_all_served(&s, &a.did, &repo2).await;
    let gone: Vec<Cid> = nodes1.iter().filter(|c| !nodes2.contains(c)).copied().collect();
    assert!(!gone.is_empty());
    assert_missing(&s, &a.did, &gone).await;
    assert_missing(&s, &a.did, &[first_post.1, repo1.root]).await;
    // the like CID is still at two paths, then at none
    assert_eq!(s.get_blocks(&a.did, &[like_cid]).await.status, 200);
    delete("3l3qo2vuowo2b").await;
    assert_eq!(s.get_blocks(&a.did, &[like_cid]).await.status, 200);
    delete("3l3qo2vuowo2c").await;
    assert_missing(&s, &a.did, &[like_cid]).await;

    // importRepo puts the first version back (a tree the worker didn't
    // commit node by node): its nodes and records are served again
    s.import_repo(&a.auth(), car1.body.to_vec()).await.ok();
    let repo3 = s.get_repo(&a.did).await;
    let (nodes3, records3) = assert_all_served(&s, &a.did, &repo3).await;
    assert_eq!(nodes3.iter().collect::<HashSet<_>>(), nodes1.iter().collect::<HashSet<_>>());
    assert_eq!(records3.iter().collect::<HashSet<_>>(), records1.iter().collect::<HashSet<_>>());
    let gone: Vec<Cid> = nodes2.iter().filter(|c| !nodes3.contains(c)).copied().collect();
    assert_missing(&s, &a.did, &gone).await;
}
