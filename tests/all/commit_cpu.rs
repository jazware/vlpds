//! The write path's CPU work changed without changing its output: commit
//! signatures (RFC 6979 nonce on hardware SHA-256, src/crypto.rs; hedged
//! with fresh nonce data since) and the getBlocks node index keying each
//! written node by its own first value instead of its subtree's leftmost key
//! (src/mst.rs `subtree_key`).
use crate::common::*;
use std::collections::HashSet;

/// The deterministic path is RFC 6979: equal to RustCrypto k256's
/// (deterministic, low-S) for many keys, and over every message length
/// around the SHA-256 block boundaries. What a worker emits is hedged: the
/// same commit object with a low-S signature k256 verifies, different each
/// time.
#[test]
fn commit_signatures_match_k256_across_keys_and_lengths() {
    use k256::ecdsa::signature::{Signer, Verifier};
    let did = "did:plc:abcdefghijklmnopqrstuvwx";
    for k in 0..64u32 {
        let kp = vlsync_atproto::crypto::Keypair::generate();
        let sk = k256::ecdsa::SigningKey::from_slice(&kp.to_bytes()).unwrap();
        for len in (0..200usize).step_by(if k == 0 { 1 } else { 37 }) {
            let msg: Vec<u8> = (0..len).map(|i| (i as u32 * 31 + k) as u8).collect();
            let theirs: k256::ecdsa::Signature = sk.sign(&msg);
            let theirs = theirs.normalize_s();
            assert_eq!(kp.sign_deterministic(&msg)[..], theirs.to_bytes()[..], "key {k} len {len}");
        }
        // the commit object a worker signs
        let data = vlsync_atproto::cid::Cid::dag_cbor(format!("data {k}").as_bytes());
        let (_, block) = vlpds::worker::sign_commit(did, "3lbcdefghij22", &data, &kp).unwrap();
        let (_, again) = vlpds::worker::sign_commit(did, "3lbcdefghij22", &data, &kp).unwrap();
        assert_ne!(block, again, "hedged signatures repeat");
        let unsigned = vlsync_atproto::events::encode_commit(did, "3lbcdefghij22", &data, None);
        let Some(Value::Bytes(sig)) = Value::decode(&block).unwrap().get("sig").cloned() else {
            panic!("commit without sig")
        };
        let sig: [u8; 64] = sig[..].try_into().unwrap();
        assert_eq!(&block[..], &vlsync_atproto::events::encode_commit(did, "3lbcdefghij22", &data, Some(&sig))[..]);
        let theirs = k256::ecdsa::Signature::from_slice(&sig).unwrap();
        assert!(theirs.normalize_s() == theirs, "high-S");
        sk.verifying_key().verify(&unsigned, &theirs).unwrap();
    }
}

async fn assert_nodes_served(s: &TestServer, did: &str) -> Vec<Cid> {
    let repo = s.get_repo(did).await;
    let mut nodes = Vec::new();
    repo.tree().walk_blocks(&mut |c, _| nodes.push(c)).unwrap();
    for chunk in nodes.chunks(100) {
        let r = s.get_blocks(did, chunk).await;
        assert_eq!(r.status, 200, "{}", r.text());
        let (_, blocks) = vlsync_atproto::car::read_car(&r.body).unwrap();
        assert_eq!(blocks.len(), chunk.len());
        for (c, b) in blocks {
            assert_eq!(Some(b), repo.blocks.get(&c).map(|v| &v[..]), "{c}");
        }
    }
    nodes
}

/// A repo deep enough for internal nodes that start with a child pointer
/// (their subtree key is not their leftmost leaf key): the index built on
/// first use and then advanced by commits finds every node, and nodes the
/// later commits replaced are gone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn node_index_serves_deep_trees_across_commits() {
    let s = TestServer::spawn().await;
    let a = s.create_account("deep").await;
    let write = |rkey: String, del: bool| {
        if del {
            json!({"$type": "com.atproto.repo.applyWrites#delete", "collection": "app.bsky.feed.post", "rkey": rkey})
        } else {
            json!({"$type": "com.atproto.repo.applyWrites#create", "collection": "app.bsky.feed.post", "rkey": rkey, "value": post_record(&rkey)})
        }
    };
    // pseudo-random TID-shaped rkeys, so inserts land all over the tree
    let rkey = |i: u64| {
        vlsync_atproto::tid::Tid::from_parts(1_700_000_000_000_000 + (i * 2_654_435_761) % 100_000_000_000, i % 1024)
            .to_string()
    };
    for batch in 0..8u64 {
        s.apply_writes(&a, (0..150).map(|j| write(rkey(batch * 150 + j), false)).collect()).await.ok();
    }
    let nodes1 = assert_nodes_served(&s, &a.did).await;
    assert!(nodes1.len() > 100, "{} nodes", nodes1.len());
    // commits after the index exists: inserts, deletes, one-op commits
    for round in 0..6u64 {
        let mut writes: Vec<J> = (0..40).map(|j| write(rkey(10_000 + round * 40 + j), false)).collect();
        writes.extend((0..20).map(|j| write(rkey(round * 150 + j * 7), true)));
        s.apply_writes(&a, json!(writes)).await.ok();
        s.post(&a, &format!("single {round}")).await;
    }
    let nodes2 = assert_nodes_served(&s, &a.did).await;
    let now: HashSet<Cid> = nodes2.iter().copied().collect();
    let gone: Vec<Cid> = nodes1.iter().filter(|c| !now.contains(c)).copied().collect();
    assert!(!gone.is_empty());
    for c in gone.iter().take(50) {
        s.get_blocks(&a.did, &[*c]).await.err(400, "BlockNotFound");
    }
}
