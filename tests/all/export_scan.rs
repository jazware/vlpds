//! getRepo reads the repo's `M/` nodes with one scan as far as its memory
//! grant goes (past it: without the height-1 nodes, rebuilt from records;
//! past that, the rest one by one). Every split gives the same CAR bytes as
//! reading every node one by one, and so do nodes missing from `M/`.

use crate::common::*;
use rand::{rngs::StdRng, Rng, SeedableRng};

const COLLS: [&str; 3] = ["com.example.a", "com.example.bb", "app.example.c"];

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn prefetch_splits_give_same_bytes() {
    let s = TestServer::spawn().await;
    let a = s.create_account("exscan").await;
    let mut rng = StdRng::seed_from_u64(7);
    let mut since = String::new();
    // creates, and updates and deletes of records from earlier batches
    let mut live: Vec<(&str, String)> = Vec::new();
    for batch in 0..20usize {
        let mut kept = Vec::new();
        let mut writes = Vec::new();
        for i in 0..200usize {
            let n = batch * 200 + i;
            let roll = rng.gen_range(0..10);
            if roll < 2 && !live.is_empty() {
                let (c, rkey) = live.swap_remove(rng.gen_range(0..live.len()));
                if roll == 0 {
                    writes.push(json!({"$type": "com.atproto.repo.applyWrites#delete", "collection": c, "rkey": rkey}));
                } else {
                    writes.push(json!({"$type": "com.atproto.repo.applyWrites#update", "collection": c, "rkey": rkey, "value": {"$type": c, "n": n, "v": 2}}));
                    kept.push((c, rkey));
                }
                continue;
            }
            let (c, rkey) = (COLLS[n % 3], format!("r{n:05}"));
            writes.push(json!({"$type": "com.atproto.repo.applyWrites#create", "collection": c, "rkey": rkey, "value": {"$type": c, "n": n}}));
            kept.push((c, rkey));
        }
        live.extend(kept);
        let r = s
            .xrpc
            .post("com.atproto.repo.applyWrites", &json!({"repo": a.did, "writes": writes}), &a.auth())
            .await
            .ok();
        if batch == 12 {
            since = r["commit"]["rev"].as_str().unwrap().to_string();
        }
    }
    let get = |since: Option<String>| {
        let (x, did) = (s.xrpc.clone(), a.did.clone());
        async move {
            let mut q = vec![("did", did.as_str())];
            if let Some(s) = since.as_deref() {
                q.push(("since", s));
            }
            let r = x.get("com.atproto.sync.getRepo", &q, &Auth::None).await;
            assert_eq!(r.status, 200, "{}", r.text());
            r.body.to_vec()
        }
    };
    let both = |cap: usize| {
        let get = &get;
        let since = since.clone();
        async move {
            vlpds::xrpc::set_export_prefetch_max_bytes(cap);
            let r = (get(None).await, get(Some(since)).await);
            vlpds::xrpc::set_export_prefetch_max_bytes(usize::MAX);
            r
        }
    };
    // one by one: the walk as it was before the read-ahead
    let (full, diff) = both(0).await;
    let repo = Repo::from_car(&full).unwrap();
    repo.check_block_hashes().unwrap();
    assert!(repo.entries().len() > 2000 && diff.len() < full.len(), "{} records", repo.entries().len());
    let Ok(p) = s.app.partition(&a.did) else { panic!("shard not owned") };
    let prefix = vlpds::state::mst_node_prefix(&a.did, s.app.repo_gen(&a.did).await.ok().unwrap());
    let mut it = p.db.scan(prefix.clone()..vlsync_store::keys::prefix_end(&prefix)).await.unwrap();
    let mut keys = Vec::new();
    let mut node_bytes = 0;
    while let Some(kv) = it.next().await.unwrap() {
        node_bytes += kv.value.len();
        keys.push(kv.key.to_vec());
    }
    assert!(keys.len() > 20, "{} M/ nodes", keys.len());
    for cap in [usize::MAX, node_bytes, node_bytes / 2, 8192, 1] {
        let (f, d) = both(cap).await;
        assert!(f == full, "cap {cap}: full export differs");
        assert!(d == diff, "cap {cap}: since export differs");
    }
    // nodes missing from M/ are rebuilt from records: same bytes
    for k in keys.iter().step_by(3) {
        p.db.delete(k).await.unwrap();
    }
    for cap in [0, usize::MAX, node_bytes / 3] {
        let (f, d) = both(cap).await;
        assert!(f == full, "cap {cap}, a third of M/ missing: full export differs");
        assert!(d == diff, "cap {cap}, a third of M/ missing: since export differs");
    }
}
