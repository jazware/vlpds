//! MST interop fixtures: key heights, example keys and the sync 1.1
//! commit-proof fixtures (testdata/interop/{mst,firehose}).
use crate::common::*;
use std::collections::HashMap;
use vlatproto::mst::{height_for_key, Tree};

#[derive(serde::Deserialize)]
struct KeyHeight {
    key: String,
    height: i32,
}

#[test]
fn key_heights() {
    let cases: Vec<KeyHeight> = serde_json::from_str(&read_fixture("interop/mst/key_heights.json")).unwrap();
    for c in cases {
        assert_eq!(height_for_key(c.key.as_bytes()), c.height, "height of {:?}", c.key);
    }
}

#[test]
fn example_keys_encode_their_height() {
    // example_keys.txt names keys "<Letter><height>/<n>" (generated to land at that height).
    let keys = fixture_lines("interop/mst/example_keys.txt");
    assert!(keys.len() > 100);
    for k in keys {
        let want: i32 = k[1..k.find('/').unwrap()].parse().unwrap();
        assert_eq!(height_for_key(k.as_bytes()), want, "height of {k}");
    }
}

#[test]
fn empty_tree_root_cid() {
    let mut t = Tree::new();
    assert_eq!(t.root_cid().unwrap().to_string(), "bafyreie5737gdxlw5i64vzichcalba3z2v5n6icifvx5xytvske7mr3hpm");
}

#[test]
fn invalid_keys_rejected() {
    let leaf = Cid::parse("bafyreie5cvv4h45feadgeuwhbcutmh6t2ceseocckahdoe6uat64zmz454").unwrap();
    let mut t = Tree::new();
    assert!(t.insert(b"", leaf).is_err(), "empty key");
    assert!(t.insert(&vec![b'a'; 1025], leaf).is_err(), "key over 1024 bytes");
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProofFixture {
    comment: String,
    leaf_value: String,
    keys: Vec<String>,
    adds: Vec<String>,
    dels: Vec<String>,
    root_before_commit: String,
    root_after_commit: String,
    blocks_in_proof: Vec<String>,
}

fn proof_fixtures() -> Vec<ProofFixture> {
    serde_json::from_str(&read_fixture("interop/firehose/commit-proof-fixtures.json")).unwrap()
}

#[test]
fn commit_proof_roots() {
    for f in proof_fixtures() {
        let v = Cid::parse(&f.leaf_value).unwrap();
        let mut t = Tree::new();
        for k in &f.keys {
            t.insert_no_proof(k.as_bytes(), v).unwrap();
        }
        assert_eq!(t.root_cid().unwrap().to_string(), f.root_before_commit, "{}: root before", f.comment);
        for k in &f.adds {
            assert_eq!(t.insert(k.as_bytes(), v).unwrap(), None, "{}: add {k}", f.comment);
        }
        for k in &f.dels {
            assert_eq!(t.remove(k.as_bytes()).unwrap(), Some(v), "{}: del {k}", f.comment);
        }
        assert_eq!(t.root_cid().unwrap().to_string(), f.root_after_commit, "{}: root after", f.comment);
    }
}

#[test]
fn commit_proof_blocks_emitted() {
    // The diff of the commit must contain every block the reference proof has.
    for f in proof_fixtures() {
        let v = Cid::parse(&f.leaf_value).unwrap();
        let mut t = Tree::new();
        for k in &f.keys {
            t.insert_no_proof(k.as_bytes(), v).unwrap();
        }
        t.root_cid().unwrap();
        for k in &f.adds {
            t.insert(k.as_bytes(), v).unwrap();
        }
        for k in &f.dels {
            t.remove(k.as_bytes()).unwrap();
        }
        let mut blocks = Vec::new();
        t.write_diff_blocks(&mut blocks).unwrap();
        let have: std::collections::HashSet<String> = blocks.iter().map(|(c, _)| c.to_string()).collect();
        let missing: Vec<_> = f.blocks_in_proof.iter().filter(|b| !have.contains(*b)).collect();
        assert!(missing.is_empty(), "{}: diff is missing proof blocks {missing:?}", f.comment);
    }
}

#[test]
fn commit_proof_reference_blocks_suffice_for_inversion() {
    // Using ONLY the reference proof block set (blocksInProof), the commit
    // inverts to rootBeforeCommit. This checks vlpds's partial-tree loader
    // and inversion against exactly what an indigo-produced #commit carries.
    for f in proof_fixtures() {
        let v = Cid::parse(&f.leaf_value).unwrap();
        // produce the block bytes by building the post-commit tree in full
        let mut full = Tree::new();
        for k in &f.keys {
            full.insert_no_proof(k.as_bytes(), v).unwrap();
        }
        for k in &f.adds {
            full.insert_no_proof(k.as_bytes(), v).unwrap();
        }
        for k in &f.dels {
            full.remove(k.as_bytes()).unwrap();
        }
        let root = full.root_cid().unwrap();
        assert_eq!(root.to_string(), f.root_after_commit);
        let mut all = HashMap::new();
        full.walk_blocks(&mut |c, b| {
            all.insert(c, b.to_vec());
        })
        .unwrap();
        let proof: HashMap<Cid, Vec<u8>> = f
            .blocks_in_proof
            .iter()
            .map(|s| {
                let c = Cid::parse(s).unwrap();
                (c, all.get(&c).unwrap_or_else(|| panic!("{}: proof block {s} not in tree", f.comment)).clone())
            })
            .collect();
        let mut inv = Tree::load_from_blocks(&proof, root).unwrap_or_else(|e| panic!("{}: load: {e}", f.comment));
        // invert in reverse order of application
        for k in f.dels.iter().rev() {
            assert_eq!(
                inv.insert(k.as_bytes(), v).unwrap_or_else(|e| panic!("{}: reinsert {k}: {e}", f.comment)),
                None
            );
        }
        for k in f.adds.iter().rev() {
            assert_eq!(inv.remove(k.as_bytes()).unwrap_or_else(|e| panic!("{}: remove {k}: {e}", f.comment)), Some(v));
        }
        assert_eq!(inv.root_cid().unwrap().to_string(), f.root_before_commit, "{}: inverted root", f.comment);
    }
}

#[test]
fn canonical_shape_independent_of_insertion_order() {
    // Same key set inserted in several orders -> same root.
    let keys = fixture_lines("interop/mst/example_keys.txt");
    let v = Cid::parse("bafyreie5cvv4h45feadgeuwhbcutmh6t2ceseocckahdoe6uat64zmz454").unwrap();
    let mut roots = Vec::new();
    for rot in [0usize, 17, 61, 100] {
        let mut t = Tree::new();
        let mut ks = keys.clone();
        let n = ks.len();
        ks.rotate_left(rot % n);
        if rot % 2 == 1 {
            ks.reverse();
        }
        for k in &ks {
            t.insert_no_proof(k.as_bytes(), v).unwrap();
        }
        roots.push(t.root_cid().unwrap());
    }
    assert!(roots.windows(2).all(|w| w[0] == w[1]), "roots differ by insertion order: {roots:?}");
}
