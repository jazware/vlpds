//! `cbor::write_json` (streaming DAG-CBOR -> JSON) against the value-tree
//! path `Value::decode(..)?.to_json()`: same output on records, same
//! accept/reject decision on corrupted input.
use crate::common::*;
use rand::{Rng, SeedableRng};
use vlsync_atproto::cbor::write_json;

fn tree_json(b: &[u8]) -> Option<J> {
    Value::decode(b).ok().map(|v| v.to_json())
}

fn stream_json(b: &[u8]) -> Option<J> {
    let mut out = Vec::new();
    write_json(b, &mut out).ok()?;
    Some(serde_json::from_slice(&out).expect("write_json emitted invalid JSON"))
}

/// Records: the data-model fixtures plus random value trees.
fn corpus() -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = data_model_fixtures().into_iter().map(|f| f.cbor).collect();
    let post = json!({
        "$type": "app.bsky.feed.post",
        "text": "Check out this thing @alice.bsky.social wrote https://example.com/mst — neat",
        "createdAt": "2026-10-01T12:34:56.789Z",
        "langs": ["en"],
        "facets": [{"index": {"byteStart": 15, "byteEnd": 34}, "features": [{"$type": "app.bsky.richtext.facet#mention", "did": "did:plc:ewvi7nxzyoun6zhxrhs64oiz"}]}],
        "embed": {"$type": "app.bsky.embed.images", "images": [{"alt": "a tree", "image": {"$type": "blob", "ref": {"$link": "bafkreie5737gdxlw5i64vzichcalba3z2v5n6icifvx5xytvske7mr3hpm"}, "mimeType": "image/jpeg", "size": 123456}, "aspectRatio": {"width": 1200, "height": 800}}]},
    });
    out.push(Value::from_json(&post).unwrap().to_cbor());
    let mut rng = rand::rngs::StdRng::seed_from_u64(42);
    for _ in 0..3000 {
        out.push(rand_cbor(&mut rng, 0).to_cbor());
    }
    out
}

#[test]
fn write_json_equals_decode_to_json() {
    for (i, b) in corpus().iter().enumerate() {
        let want = tree_json(b).unwrap_or_else(|| panic!("record {i} does not decode"));
        assert_eq!(stream_json(b), Some(want), "record {i}: {b:02x?}");
    }
}

/// Corrupted encodings (flipped, inserted, dropped and truncated bytes):
/// both paths accept exactly the same inputs, with the same JSON.
#[test]
fn write_json_is_as_strict_as_decode() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(9);
    let corpus = corpus();
    let mut rejected = 0;
    for i in 0..60_000 {
        let mut b = corpus[rng.gen_range(0..corpus.len())].clone();
        for _ in 0..rng.gen_range(1..3) {
            let at = rng.gen_range(0..=b.len());
            match rng.gen_range(0..4) {
                0 if at < b.len() => b[at] = rng.gen(),
                1 if at < b.len() => b[at] ^= 1 << rng.gen_range(0..8),
                2 => b.insert(at, rng.gen()),
                _ => b.truncate(at),
            }
        }
        let want = tree_json(&b);
        rejected += want.is_none() as usize;
        assert_eq!(stream_json(&b), want, "mutation {i}: {b:02x?}");
    }
    assert!(rejected > 1000, "too few corrupted inputs rejected ({rejected})");
    // around the nesting limit (compared as bytes: serde_json's parser stops
    // at depth 128)
    let raw = |b: &[u8]| {
        let mut out = Vec::new();
        write_json(b, &mut out).ok().map(|()| out)
    };
    let tree_raw = |b: &[u8]| tree_json(b).map(|j| serde_json::to_vec(&j).unwrap());
    for n in [127, 128, 129, 130] {
        let mut b = vec![0x81; n];
        b.push(0x01);
        assert_eq!(raw(&b), tree_raw(&b), "array depth {n}");
        let mut b = vec![0x81; n];
        b.extend_from_slice(&[0xd8, 0x2a, 0x58, 0x25, 0x00]);
        b.extend_from_slice(&Cid::dag_cbor(b"x").to_bytes());
        assert_eq!(raw(&b), tree_raw(&b), "link at depth {n}");
        let mut b = vec![0x81; n];
        b.extend_from_slice(&[0xa1, 0x61, b'a', 0x01]);
        assert_eq!(raw(&b), tree_raw(&b), "map at depth {n}");
    }
}

/// `cargo test --release --test all cbor_transcode::bench -- --ignored --nocapture`
#[test]
#[ignore]
fn bench() {
    use std::time::Instant;
    let post = corpus().into_iter().nth(data_model_fixtures().len()).unwrap();
    let n = 300_000;
    let run = |name: &str, f: &dyn Fn() -> usize| {
        let mut sink = 0;
        for _ in 0..n / 10 {
            sink += f();
        }
        let t = Instant::now();
        for _ in 0..n {
            sink += f();
        }
        let ns = t.elapsed().as_nanos() as f64 / n as f64;
        println!("{name:36} {ns:8.0} ns/op ({sink})");
    };
    run("decode -> to_json -> to_vec", &|| serde_json::to_vec(&Value::decode(&post).unwrap().to_json()).unwrap().len());
    run("write_json", &|| {
        let mut out = Vec::with_capacity(post.len() * 2);
        write_json(&post, &mut out).unwrap();
        out.len()
    });
}
