//! Repo data from untrusted CARs: a crafted MST deep enough to overflow the
//! stack of a recursive loader (aborting the whole process) is rejected by
//! both paths that load attacker-chosen CARs: importRepo and the
//! record-proof check behind OAuth `include:` scopes.
use crate::common::*;
use vlatproto::cbor::{self, key_cmp};
use vlatproto::crypto::Keypair;

/// Deep enough to overflow a 2 MiB stack in the unbounded loader.
const DEPTH: usize = 200_000;

/// A signed commit whose MST is a leaf holding `rpath`, under `depth`
/// key-less `{e: [], l: child}` nodes.
fn deep_car(did: &str, kp: &Keypair, rpath: &str, depth: usize) -> Vec<u8> {
    let mut blocks: Vec<(Cid, Vec<u8>)> = Vec::new();
    let rec =
        Value::from_json(&json!({"$type": "com.atproto.lexicon.schema", "id": "com.example.deep"})).unwrap().to_cbor();
    let rec_cid = Cid::dag_cbor(&rec);
    blocks.push((rec_cid, rec));
    let node = |l: Option<Cid>, key: Option<&str>| {
        let mut b = Vec::new();
        cbor::write_map_head(&mut b, 2);
        cbor::write_text(&mut b, "e");
        match key {
            Some(k) => {
                cbor::write_array_head(&mut b, 1);
                cbor::write_map_head(&mut b, 4);
                cbor::write_text(&mut b, "k");
                cbor::write_bytes(&mut b, k.as_bytes());
                cbor::write_text(&mut b, "p");
                cbor::write_uint(&mut b, 0);
                cbor::write_text(&mut b, "t");
                cbor::write_null(&mut b);
                cbor::write_text(&mut b, "v");
                cbor::write_cid(&mut b, &rec_cid);
            }
            None => cbor::write_array_head(&mut b, 0),
        }
        cbor::write_text(&mut b, "l");
        cbor::write_opt_cid(&mut b, l.as_ref());
        b
    };
    let leaf = node(None, Some(rpath));
    let mut c = Cid::dag_cbor(&leaf);
    blocks.push((c, leaf));
    for _ in 0..depth {
        let b = node(Some(c), None);
        c = Cid::dag_cbor(&b);
        blocks.push((c, b));
    }
    signed_car(did, kp, c, &blocks)
}

/// A CAR of a commit for `did` with MST root `data`, signed by `kp`, then
/// `blocks` (in reverse).
fn signed_car(did: &str, kp: &Keypair, data: Cid, blocks: &[(Cid, Vec<u8>)]) -> Vec<u8> {
    let c = data;
    let mut fields = vec![
        ("did".to_string(), Value::Text(did.to_string())),
        ("rev".to_string(), Value::Text("3l3qo2vuowo2b".to_string())),
        ("data".to_string(), Value::Link(c)),
        ("prev".to_string(), Value::Null),
        ("version".to_string(), Value::Int(3)),
    ];
    fields.sort_by(|a, b| key_cmp(&a.0, &b.0));
    let sig = kp.sign(&Value::Map(fields.clone()).to_cbor());
    fields.push(("sig".to_string(), Value::Bytes(sig.to_vec())));
    fields.sort_by(|a, b| key_cmp(&a.0, &b.0));
    let commit = Value::Map(fields).to_cbor();
    let root = Cid::dag_cbor(&commit);
    let mut car = Vec::new();
    vlatproto::car::write_header(&mut car, &root);
    vlatproto::car::write_block(&mut car, &root, &commit);
    for (c, b) in blocks.iter().rev() {
        vlatproto::car::write_block(&mut car, c, b);
    }
    car
}

/// A signed commit whose MST "tree" is a DAG: `levels` nodes above a leaf,
/// each holding `fan` keys of its height and linking the one node below
/// `fan + 1` times (l and every t). The leaf holds `rpath`. Expanded as a
/// tree it has (fan + 1)^levels leaves: fan 40, 4 levels is ~116M entries
/// from ~18 KB, and a few more levels exhaust memory.
fn dag_car(did: &str, kp: &Keypair, rpath: &str, fan: usize, levels: i32) -> Vec<u8> {
    use std::sync::Arc;
    use vlatproto::mst::{encode_node, height_for_key, Entry, Node};
    let rec =
        Value::from_json(&json!({"$type": "com.atproto.lexicon.schema", "id": "com.example.dag"})).unwrap().to_cbor();
    let rec_cid = Cid::dag_cbor(&rec);
    let mut blocks = vec![(rec_cid, rec)];
    assert_eq!(height_for_key(rpath.as_bytes()), 0, "{rpath} must be a leaf key");
    let keys_at = |h: i32| -> Vec<Vec<u8>> {
        let mut ks: Vec<Vec<u8>> = (0..)
            .map(|i| format!("com.example.dag/{h}-{i}").into_bytes())
            .filter(|k| height_for_key(k) == h && (h > 0 || k.as_slice() > rpath.as_bytes()))
            .take(if h == 0 { fan - 1 } else { fan })
            .collect();
        if h == 0 {
            ks.push(rpath.as_bytes().to_vec());
        }
        ks.sort();
        ks
    };
    let mut child: Option<Cid> = None;
    for h in 0..=levels {
        let mut n =
            Node { height: h, entries: Vec::new(), cid: None, dirty: true, stub: false, bytes: None, block_len: 0 };
        let link = |c: Option<Cid>| c.map(|c| Entry::Child { node: None, cid: Some(c) });
        n.entries.extend(link(child));
        for k in keys_at(h) {
            n.entries.push(Entry::Value { key: Arc::from(k), val: rec_cid });
            n.entries.extend(link(child));
        }
        let mut b = Vec::new();
        encode_node(&n, &mut b).unwrap();
        let c = Cid::dag_cbor(&b);
        blocks.push((c, b));
        child = Some(c);
    }
    signed_car(did, kp, child.unwrap(), &blocks)
}

/// Both untrusted-CAR paths reject (or, for a proof, walk only the path
/// of) a DAG-shaped MST in bounded time instead of expanding it.
#[test]
fn record_proof_with_dag_mst_is_bounded() {
    let kp = Keypair::generate();
    let did = "did:plc:dagdagdagdagdagdagdagdag";
    // "com.atproto..." sorts before every "com.example.dag/..." key: the
    // rpath lookup goes down the left edge, a consistent path
    let rpath = "com.atproto.lexicon.schema/com.example.dag";
    let key = kp.public_multibase();
    let car = dag_car(did, &kp, rpath, 40, 4);
    assert!(car.len() < 20_000, "{}", car.len());
    let t = std::time::Instant::now();
    let r = vlpds::oauth::lexicon::verify_record_proof(&car, did, &key, rpath);
    assert!(t.elapsed() < std::time::Duration::from_secs(1), "{:?}", t.elapsed());
    assert_eq!(r.unwrap()["id"], "com.example.dag");
    // a key routed through any other link reaches a leaf outside its range
    let elsewhere = "com.example.dag/1-zzzz";
    let r = vlpds::oauth::lexicon::verify_record_proof(&car, did, &key, elsewhere);
    assert!(r.unwrap_err().contains("outside its parent's range"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn import_repo_with_dag_mst_is_rejected_fast() {
    let s = TestServer::spawn().await;
    let a = s.create_account("dag").await;
    // past the old loader's memory: (41)^6 leaves
    let car = dag_car(&a.did, &Keypair::generate(), "com.example.dag/0", 40, 6);
    let t = std::time::Instant::now();
    let r = s.xrpc.post_bytes("com.atproto.repo.importRepo", car, "application/vnd.ipld.car", &a.auth()).await;
    assert!(t.elapsed() < std::time::Duration::from_secs(5), "{:?}", t.elapsed());
    r.err(400, "InvalidRequest");
    assert!(r.text().contains("more than once"), "{}", r.text());
}

#[test]
fn record_proof_with_deep_mst_is_an_error() {
    let kp = Keypair::generate();
    let did = "did:plc:deepdeepdeepdeepdeepdeep";
    let rpath = "com.atproto.lexicon.schema/com.example.deep";
    let key = kp.public_multibase();
    let shallow = deep_car(did, &kp, rpath, 3);
    let deep = deep_car(did, &kp, rpath, DEPTH);
    // a tokio blocking thread's stack
    let (shallow, deep) = std::thread::Builder::new()
        .stack_size(2 << 20)
        .spawn(move || {
            (
                vlpds::oauth::lexicon::verify_record_proof(&shallow, did, &key, rpath),
                vlpds::oauth::lexicon::verify_record_proof(&deep, did, &key, rpath),
            )
        })
        .unwrap()
        .join()
        .unwrap();
    // a short chain of key-less nodes is a valid tree
    assert_eq!(shallow.unwrap()["id"], "com.example.deep");
    let err = deep.unwrap_err();
    assert!(err.contains("too deep"), "{err}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn import_repo_with_deep_mst_is_rejected() {
    let s = TestServer::spawn().await;
    let a = s.create_account("deep").await;
    let car = deep_car(&a.did, &Keypair::generate(), "com.example.deep/3l3qo2vuowo2b", DEPTH);
    let r = s.xrpc.post_bytes("com.atproto.repo.importRepo", car, "application/vnd.ipld.car", &a.auth()).await;
    r.err(400, "InvalidRequest");
    assert!(r.text().contains("too deep"), "{}", r.text());
    // the server is still up
    s.xrpc.get("com.atproto.server.describeServer", &[], &Auth::None).await.ok();
}
