//! getRepo streams one pass in the streamable CAR order (`car_order`)
//! (commit, then each MST node followed by its entries: children
//! recursively, records in place), with and without `since`, at every `M/`
//! read-ahead split and with `M/` nodes missing. Its blocks are the set the
//! export carried when it put every node before every record: the commit,
//! every node of the tree, and every `R/` record written after `since`.

use crate::common::*;
use crate::mst_lazy::{streamable, Slot};
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::collections::{BTreeMap, HashSet};
use vlatproto::mst::Tree;

const COLLS: [&str; 3] = ["com.example.a", "com.example.bb", "app.example.c"];

/// Each record's CID, rev and block, by key, as `R/` holds them.
async fn stored_records(s: &TestServer, did: &str) -> BTreeMap<Vec<u8>, (Cid, u64, Vec<u8>)> {
    let Ok(p) = s.app.partition(did) else { panic!("shard not owned") };
    let prefix = vlpds::state::record_prefix(did, s.app.repo_gen(did).await.ok().unwrap());
    let mut it = p.db.scan(prefix.clone()..vlsync_store::keys::prefix_end(&prefix)).await.unwrap();
    let mut out = BTreeMap::new();
    while let Some(kv) = it.next().await.unwrap() {
        let (cid, b) = vlpds::state::record_value_parts(&kv.value).unwrap();
        out.insert(kv.key[prefix.len()..].to_vec(), (cid, vlpds::state::record_value_rev(&kv.value), b.to_vec()));
    }
    out
}

async fn get_repo(s: &TestServer, did: &str, since: Option<&str>) -> Vec<u8> {
    let mut q = vec![("did", did)];
    if let Some(s) = since {
        q.push(("since", s));
    }
    let r = s.xrpc.get("com.atproto.sync.getRepo", &q, &Auth::None).await;
    assert_eq!(r.status, 200, "{}", r.text());
    r.body.to_vec()
}

/// `car` is the export of `tree` (`since`: records after that rev only), in
/// the streamable order, holding the old export's block set.
fn check_export(
    car: &[u8],
    tree: &Tree,
    recs: &BTreeMap<Vec<u8>, (Cid, u64, Vec<u8>)>,
    since: Option<u64>,
    what: &str,
) {
    let (roots, blocks) = vlatproto::car::read_car(car).unwrap();
    assert_eq!(blocks[0].0, roots[0], "{what}: the commit first");
    let carried = |k: &[u8]| since.is_none_or(|s| recs[k].1 > s);
    let want: Vec<Cid> = std::iter::once(roots[0])
        .chain(streamable(tree).into_iter().filter_map(|s| match s {
            Slot::Node(c, _) => Some(c),
            Slot::Record(k, c) => carried(&k).then_some(c),
        }))
        .collect();
    let got: Vec<Cid> = blocks.iter().map(|b| b.0).collect();
    assert!(got == want, "{what}: block order differs ({} blocks, want {})", got.len(), want.len());
    let got: HashSet<(Cid, Vec<u8>)> = blocks.iter().map(|(c, b)| (*c, b.to_vec())).collect();
    let mut old: HashSet<(Cid, Vec<u8>)> = HashSet::new();
    old.insert((roots[0], blocks[0].1.to_vec()));
    tree.walk_blocks(&mut |c, b| {
        old.insert((c, b.to_vec()));
    })
    .unwrap();
    old.extend(recs.values().filter(|r| since.is_none_or(|s| r.1 > s)).map(|r| (r.0, r.2.clone())));
    assert!(got == old, "{what}: block set differs ({} blocks, old export {})", got.len(), old.len());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exports_stream_in_spec_order_with_the_same_blocks() {
    let s = TestServer::spawn().await;
    let a = s.create_account("exorder").await;
    let mut rng = StdRng::seed_from_u64(11);
    let mut since = String::new();
    let mut live: Vec<(&str, String)> = Vec::new();
    for batch in 0..16usize {
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
            // some records share contents (and so a block)
            let value = match n % 7 {
                0 => json!({"$type": c, "same": true}),
                _ => json!({"$type": c, "n": n}),
            };
            writes.push(
                json!({"$type": "com.atproto.repo.applyWrites#create", "collection": c, "rkey": rkey, "value": value}),
            );
            kept.push((c, rkey));
        }
        live.extend(kept);
        let r = s
            .xrpc
            .post("com.atproto.repo.applyWrites", &json!({"repo": a.did, "writes": writes}), &a.auth())
            .await
            .ok();
        if batch == 10 {
            since = r["commit"]["rev"].as_str().unwrap().to_string();
        }
    }
    let since_rev = vlatproto::tid::Tid::parse(&since).unwrap().0;
    let recs = stored_records(&s, &a.did).await;
    let full = get_repo(&s, &a.did, None).await;
    let repo = Repo::from_car(&full).unwrap();
    repo.check_block_hashes().unwrap();
    let tree = repo.tree();
    assert_eq!(repo.entries().len(), recs.len());
    assert!(recs.len() > 2000, "{} records", recs.len());
    let dups = recs.len() - recs.values().map(|r| r.0).collect::<HashSet<_>>().len();
    assert!(dups > 10, "{dups} records sharing a block");
    let carried = recs.values().filter(|r| r.1 > since_rev).count();
    assert!(carried > 0 && carried < recs.len(), "{carried} of {} records after since", recs.len());

    let Ok(p) = s.app.partition(&a.did) else { panic!("shard not owned") };
    let prefix = vlpds::state::mst_node_prefix(&a.did, s.app.repo_gen(&a.did).await.ok().unwrap());
    let mut it = p.db.scan(prefix.clone()..vlsync_store::keys::prefix_end(&prefix)).await.unwrap();
    let (mut keys, mut node_bytes) = (Vec::new(), 0);
    while let Some(kv) = it.next().await.unwrap() {
        node_bytes += kv.value.len();
        keys.push(kv.key.to_vec());
    }
    let check = |label: String| {
        let (s, did, since, tree, recs) = (&s, a.did.clone(), since.clone(), &tree, &recs);
        async move {
            check_export(&get_repo(s, &did, None).await, tree, recs, None, &label);
            check_export(
                &get_repo(s, &did, Some(&since)).await,
                tree,
                recs,
                Some(since_rev),
                &format!("{label}, since"),
            );
        }
    };
    // every read-ahead split: whole, height-1 nodes let go, partial, none
    for cap in [usize::MAX, node_bytes / 2, 8192, 1, 0] {
        vlpds::xrpc::set_export_prefetch_max_bytes(cap);
        check(format!("cap {cap}")).await;
    }
    // nodes missing from M/ are rebuilt from records
    for k in keys.iter().step_by(3) {
        p.db.delete(k).await.unwrap();
    }
    for cap in [usize::MAX, 0] {
        vlpds::xrpc::set_export_prefetch_max_bytes(cap);
        check(format!("cap {cap}, a third of M/ missing")).await;
    }
    vlpds::xrpc::set_export_prefetch_max_bytes(usize::MAX);
}

/// The CAR header and commit go out before the walk starts: a client sees
/// the commit while the rest is still being read.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn commit_streams_before_the_tree() {
    let s = TestServer::spawn_with(|c| c.export_stall = std::time::Duration::from_secs(5)).await;
    let a = s.create_account("exfirst").await;
    let writes: Vec<J> = (0..200).map(|i| json!({"$type": "com.atproto.repo.applyWrites#create", "collection": "com.example.x", "value": {"$type": "com.example.x", "i": i}})).collect();
    s.xrpc.post("com.atproto.repo.applyWrites", &json!({"repo": a.did, "writes": writes}), &a.auth()).await.ok();
    let full = get_repo(&s, &a.did, None).await;
    let (roots, blocks) = vlatproto::car::read_car(&full).unwrap();
    let mut head = Vec::new();
    vlatproto::car::write_header(&mut head, &roots[0]);
    vlatproto::car::write_block(&mut head, &blocks[0].0, blocks[0].1);
    let url = format!("http://{}/xrpc/com.atproto.sync.getRepo?did={}", s.addr, a.did);
    let mut r = reqwest::get(&url).await.unwrap();
    assert_eq!(r.status(), 200);
    let first = r.chunk().await.unwrap().unwrap();
    assert_eq!(&first[..], &head[..], "the first body chunk is the header and the commit alone");
}
