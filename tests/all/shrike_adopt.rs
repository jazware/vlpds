//! The fast paths adopted from shrike's decoders (bench/results/shrike-perf,
//! "Adopted in vlpds") against the code they replaced, kept as oracles:
//! `Value::decode` / `ValueRef::decode` vs `Value::decode_reference`,
//! `mst::decode_node` vs `mst::decode_node_reference`, the table-driven
//! base32/CID codec vs the old bit-at-a-time one (copied below), and
//! in-place mutation of built MSTs vs the restore-on-error path of loaded
//! ones. Same accepted inputs, same values, same errors, on real, random
//! and corrupted input.
use crate::common::*;
use base64::Engine;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::collections::HashMap;
use std::str::FromStr;
use vlsync_atproto::cbor::{key_cmp, ValueRef};
use vlsync_atproto::mst::{decode_node, decode_node_reference, Entry, Node, Tree};

// ---------- DAG-CBOR ----------

fn rand_text(rng: &mut impl Rng) -> String {
    const PIECES: &[&str] = &[
        "a", "b", "z", "$type", "$link", "text", "\"", "\\", "\n", "\u{0}", "\u{7f}", "é", "😀", "e", "l", "k", "p",
        "t", "v",
    ];
    (0..rng.gen_range(0..5)).map(|_| PIECES[rng.gen_range(0..PIECES.len())]).collect()
}

fn rand_value(rng: &mut impl Rng, depth: usize) -> Value {
    let leaf = depth >= 5 || rng.gen_bool(0.4);
    match rng.gen_range(0..if leaf { 6 } else { 8 }) {
        0 => Value::Null,
        1 => Value::Bool(rng.gen()),
        2 => Value::Int(match rng.gen_range(0..4) {
            0 => rng.gen_range(-30..30),
            1 => rng.gen_range(-70_000..70_000),
            2 => rng.gen(),
            _ => [i64::MIN, i64::MAX, -1 - u32::MAX as i64, u32::MAX as i64][rng.gen_range(0..4)],
        }),
        3 => Value::Bytes((0..rng.gen_range(0..40)).map(|_| rng.gen()).collect()),
        4 => Value::Text(rand_text(rng)),
        5 => {
            Value::Link(if rng.gen() { Cid::dag_cbor(&rng.gen::<[u8; 8]>()) } else { Cid::raw(&rng.gen::<[u8; 8]>()) })
        }
        6 => Value::Array((0..rng.gen_range(0..5)).map(|_| rand_value(rng, depth + 1)).collect()),
        _ => {
            let mut m: Vec<(String, Value)> = Vec::new();
            for _ in 0..rng.gen_range(0..6) {
                let k = rand_text(rng);
                if !m.iter().any(|(x, _)| *x == k) {
                    m.push((k, rand_value(rng, depth + 1)));
                }
            }
            m.sort_by(|a, b| key_cmp(&a.0, &b.0));
            Value::Map(m)
        }
    }
}

fn car_blocks(rel: &str) -> (Vec<Cid>, Vec<(Cid, Vec<u8>)>) {
    let car = std::fs::read(fixture_path(rel)).unwrap();
    let (roots, blocks) = vlsync_atproto::car::read_car(&car).unwrap();
    (roots, blocks.into_iter().map(|(c, b)| (c, b.to_vec())).collect())
}

/// Data-model fixtures, the dag-cbor blocks of two real repos (records,
/// MST nodes, commits) and random value trees.
fn cbor_corpus() -> Vec<Vec<u8>> {
    #[derive(serde::Deserialize)]
    struct Fixture {
        cbor_base64: String,
    }
    let fixtures: Vec<Fixture> =
        serde_json::from_str(&read_fixture("interop/data-model/data-model-fixtures.json")).unwrap();
    let mut out: Vec<Vec<u8>> = fixtures
        .iter()
        .map(|f| base64::engine::general_purpose::STANDARD_NO_PAD.decode(f.cbor_base64.trim_end_matches('=')).unwrap())
        .collect();
    for car in ["shrike/greenground.repo.car", "shrike/repo_slice.car"] {
        let (_, blocks) = car_blocks(car);
        out.extend(
            blocks
                .into_iter()
                .filter(|(c, _)| c.codec == vlsync_atproto::cid::CODEC_DAG_CBOR)
                .map(|(_, b)| b)
                .take(1500),
        );
    }
    let mut rng = StdRng::seed_from_u64(42);
    for _ in 0..3000 {
        out.push(rand_value(&mut rng, 0).to_cbor());
    }
    out
}

fn mutate(rng: &mut impl Rng, b: &mut Vec<u8>) {
    for _ in 0..rng.gen_range(1..3) {
        let at = rng.gen_range(0..=b.len());
        match rng.gen_range(0..4) {
            0 if at < b.len() => b[at] = rng.gen(),
            1 if at < b.len() => b[at] ^= 1 << rng.gen_range(0..8),
            2 => b.insert(at, rng.gen()),
            _ => b.truncate(at),
        }
    }
}

/// Every decoder against the reference, on one input: same verdict, same
/// value, same error text.
fn check_cbor(b: &[u8], what: &str) -> bool {
    let want = Value::decode_reference(b).map_err(|e| e.to_string());
    let owned = Value::decode(b).map_err(|e| e.to_string());
    assert_eq!(owned, want, "Value::decode, {what}: {b:02x?}");
    let borrowed = ValueRef::decode(b).map(|v| v.to_value()).map_err(|e| e.to_string());
    assert_eq!(borrowed, want, "ValueRef::decode, {what}: {b:02x?}");
    // prefixes: the same value and length
    let want_p = Value::decode_prefix_reference(b).map_err(|e| e.to_string());
    assert_eq!(Value::decode_prefix(b).map_err(|e| e.to_string()), want_p, "Value::decode_prefix, {what}: {b:02x?}");
    let got_p = ValueRef::decode_prefix(b).map(|(v, n)| (v.to_value(), n)).map_err(|e| e.to_string());
    assert_eq!(got_p, want_p, "ValueRef::decode_prefix, {what}: {b:02x?}");
    want.is_ok()
}

#[test]
fn cbor_decoders_match_reference() {
    let corpus = cbor_corpus();
    for (i, b) in corpus.iter().enumerate() {
        assert!(check_cbor(b, &format!("record {i}")), "record {i} rejected");
        // and with something after it (prefix decoding; whole-input trailing bytes)
        let mut t = b.clone();
        t.push(0xf6);
        check_cbor(&t, &format!("record {i} + trailing"));
    }
    let mut rng = StdRng::seed_from_u64(7);
    let mut rejected = 0;
    for i in 0..80_000 {
        let mut b = corpus[rng.gen_range(0..corpus.len())].clone();
        mutate(&mut rng, &mut b);
        rejected += !check_cbor(&b, &format!("mutation {i}")) as usize;
    }
    assert!(rejected > 2000, "too few corrupted inputs rejected ({rejected})");
    // random byte strings
    for i in 0..20_000 {
        let b: Vec<u8> = (0..rng.gen_range(0..24)).map(|_| rng.gen()).collect();
        check_cbor(&b, &format!("random {i}"));
    }
}

#[test]
fn cbor_decoders_match_reference_at_the_edges() {
    let link = {
        let mut l = vec![0xd8, 0x2a, 0x58, 0x25, 0x00];
        l.extend_from_slice(&Cid::dag_cbor(b"x").to_bytes());
        l
    };
    // nesting limit: arrays, maps (keys count a level), links (the tag's
    // content counts a level)
    for n in [126, 127, 128, 129, 130] {
        for tail in [vec![0x01], link.clone(), vec![0xa1, 0x61, b'a', 0x01], vec![0xa0], vec![0x80]] {
            let mut b = vec![0x81; n];
            b.extend_from_slice(&tail);
            check_cbor(&b, &format!("depth {n}"));
            let mut b: Vec<u8> = std::iter::repeat_n([0xa1, 0x61, b'k'], n).flatten().collect();
            b.extend_from_slice(&tail);
            check_cbor(&b, &format!("map depth {n}"));
        }
    }
    let cases: &[&[u8]] = &[
        // map keys: non-text (int, bytes, array, map, link, null), out of
        // order, duplicate, non-minimal key length, invalid UTF-8
        &[0xa1, 0x01, 0x01],
        &[0xa1, 0x41, b'a', 0x01],
        &[0xa1, 0x81, 0x01, 0x01],
        &[0xa1, 0xa0, 0x01],
        &[0xa1, 0xf6, 0x01],
        &[0xa1, 0x81, 0xff, 0x01],
        &[0xa2, 0x61, b'b', 0x01, 0x61, b'a', 0x01],
        &[0xa2, 0x62, b'a', b'a', 0x01, 0x61, b'b', 0x01],
        &[0xa2, 0x61, b'a', 0x01, 0x61, b'a', 0x01],
        &[0xa1, 0x78, 0x01, b'a', 0x01],
        &[0xa1, 0x61, 0xff, 0x01],
        &[0xa1, 0x61],
        &[0xa1],
        // tags: other numbers, non-minimal 42, content not bytes, no 0x00, short CID
        &[0xd8, 0x2b, 0x40],
        &[0xd9, 0x00, 0x2a, 0x40],
        &[0xd8, 0x2a, 0x61, b'a'],
        &[0xd8, 0x2a, 0x41, 0x01],
        &[0xd8, 0x2a, 0x40],
        &[0xd8, 0x2a, 0xd8, 0x2a, 0x40],
        // ints at the i64 edges, floats, simple values, indefinite lengths
        &[0x1b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        &[0x1b, 0x80, 0, 0, 0, 0, 0, 0, 0],
        &[0x3b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        &[0x3b, 0x80, 0, 0, 0, 0, 0, 0, 0],
        &[0x18, 0x17],
        &[0xfb, 0, 0, 0, 0, 0, 0, 0, 0],
        &[0xf7],
        &[0x9f, 0xff],
        &[0x5f, 0xff],
        &[0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        &[0xbb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        &[],
    ];
    for b in cases {
        check_cbor(b, "edge case");
    }
    let mut b = vec![0xd8, 0x2a, 0x58, 0x25, 0x00];
    let mut cid = Cid::dag_cbor(b"x").to_bytes();
    cid[1] = 0x70;
    b.extend_from_slice(&cid);
    assert!(!check_cbor(&b, "unsupported codec"));
}

/// `write_json` writes exactly the bytes it wrote before its no-escape fast
/// path (serde_json's escaping), for every kind of string.
#[test]
fn json_strings_are_escaped_as_serde_json_does() {
    let mut rng = StdRng::seed_from_u64(3);
    for i in 0..20_000 {
        let s: String = if i < 256 {
            char::from_u32(i).map(String::from).unwrap_or_default()
        } else {
            (0..rng.gen_range(0..12))
                .map(|_| match rng.gen_range(0..4) {
                    0 => rng.gen_range(0u8..0x80) as char,
                    1 => ['"', '\\', '\n', '\u{1f}', '\u{7f}', '\u{2028}', '/', 'é', '😀'][rng.gen_range(0..9)],
                    _ => rng.gen_range(b'a'..=b'z') as char,
                })
                .collect()
        };
        let cbor = Value::Map(vec![(s.clone(), Value::Text(s.clone()))]).to_cbor();
        let mut out = Vec::new();
        vlsync_atproto::cbor::write_json(&cbor, &mut out).unwrap();
        let q = serde_json::to_string(&s).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), format!("{{{q}:{q}}}"), "{s:?}");
    }
}

// ---------- CIDs and base32 ----------

/// The base32 codec before the table-driven one.
fn old_base32_encode(data: &[u8]) -> String {
    const B32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut out = Vec::new();
    let mut buf: u32 = 0;
    let mut bits = 0;
    for &b in data {
        buf = (buf << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(B32[((buf >> bits) & 31) as usize]);
        }
    }
    if bits > 0 {
        out.push(B32[((buf << (5 - bits)) & 31) as usize]);
    }
    String::from_utf8(out).unwrap()
}

fn old_base32_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf: u32 = 0;
    let mut bits = 0;
    for c in s.bytes() {
        let v = match c {
            b'a'..=b'z' => c - b'a',
            b'2'..=b'7' => c - b'2' + 26,
            _ => return None,
        } as u32;
        buf = (buf << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    if bits >= 5 || buf & ((1 << bits) - 1) != 0 {
        return None;
    }
    Some(out)
}

fn old_cid_parse(s: &str) -> Option<Cid> {
    Cid::from_bytes(&old_base32_decode(s.strip_prefix('b')?)?).ok()
}

#[test]
fn base32_and_cid_codecs_match_the_old_ones() {
    let mut rng = StdRng::seed_from_u64(11);
    for n in 0..64 {
        for _ in 0..50 {
            let data: Vec<u8> = (0..n).map(|_| rng.gen()).collect();
            let s = vlsync_atproto::cid::base32_encode(&data);
            assert_eq!(s, old_base32_encode(&data));
            assert_eq!(vlsync_atproto::cid::base32_decode(&s), Some(data));
        }
    }
    const ALPHA: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut checked = 0;
    for _ in 0..200_000 {
        let c = if rng.gen() { Cid::dag_cbor(&rng.gen::<[u8; 8]>()) } else { Cid::raw(&rng.gen::<[u8; 8]>()) };
        // the string form against the old encoder and shrike's
        let mut s = c.to_string();
        assert_eq!(s, format!("b{}", old_base32_encode(&c.to_bytes())));
        let mut w = Vec::new();
        c.write_string(&mut w);
        assert_eq!(w, s.as_bytes());
        assert_eq!(shrike::cbor::Cid::from_str(&s).unwrap().to_string(), s);
        // corrupt it: any position, any byte (alphabet, uppercase, others),
        // insertions, deletions, and random strings of every length near 59
        let mut b = s.clone().into_bytes();
        match rng.gen_range(0..6) {
            0 => {
                let at = rng.gen_range(0..b.len());
                b[at] = ALPHA[rng.gen_range(0..32)];
            }
            1 => {
                let at = rng.gen_range(0..b.len());
                b[at] = rng.gen_range(0..128);
            }
            2 => b.insert(rng.gen_range(0..=b.len()), ALPHA[rng.gen_range(0..32)]),
            3 => {
                b.remove(rng.gen_range(0..b.len()));
            }
            4 => {
                // the 2 padding bits of the last character
                let last = b.len() - 1;
                b[last] = ALPHA[(ALPHA.iter().position(|&x| x == b[last]).unwrap() & !3) | rng.gen_range(0..4)];
            }
            _ => {
                b = (0..rng.gen_range(56..62)).map(|_| ALPHA[rng.gen_range(0..32)]).collect();
                b[0] = b'b';
            }
        }
        s = String::from_utf8_lossy(&b).into_owned();
        let got = Cid::parse(&s).ok();
        assert_eq!(got, old_cid_parse(&s), "{s}");
        let theirs = shrike::cbor::Cid::from_str(&s).ok().map(|c| Cid::from_bytes(&c.to_bytes()).unwrap());
        assert_eq!(got, theirs, "shrike disagrees on {s}");
        checked += got.is_some() as usize;
    }
    assert!(checked > 10_000, "too few corrupted CIDs still valid ({checked})");
    for s in ["", "b", "B", "bafy", "zQm", "bafyreie5737gdxlw5i64vzichcalba3z2v5n6icifvx5xytvske7mr3hpmé"] {
        assert_eq!(Cid::parse(s).ok(), old_cid_parse(s), "{s}");
    }
}

// ---------- MST ----------

fn old_height_for_key(key: &[u8]) -> i32 {
    use sha2::{Digest, Sha256};
    let mut height = 0;
    for &b in Sha256::digest(key).iter() {
        if b & 0xC0 != 0 {
            break;
        }
        if b == 0 {
            height += 4;
            continue;
        }
        height += if b & 0xFC == 0 {
            3
        } else if b & 0xF0 == 0 {
            2
        } else {
            1
        };
        break;
    }
    height
}

#[test]
fn key_heights_match_the_old_count() {
    let mut rng = StdRng::seed_from_u64(5);
    let mut seen = [0usize; 12];
    for i in 0..300_000u64 {
        let k = format!("app.bsky.feed.post/{i}{}", rng.gen::<u32>());
        let h = vlsync_atproto::mst::height_for_key(k.as_bytes());
        assert_eq!(h, old_height_for_key(k.as_bytes()), "{k}");
        seen[h.min(11) as usize] += 1;
    }
    // heights 0..=6 all occur in 300k keys
    assert!(seen[..7].iter().all(|&n| n > 0), "{seen:?}");
}

fn node_eq(a: &Node, b: &Node) -> bool {
    let entry = |e: &Entry| match e {
        Entry::Value { key, val } => (Some(key.to_vec()), Some(*val), None, false),
        Entry::Child { node, cid } => (None, None, *cid, node.is_some()),
    };
    a.height == b.height
        && a.cid == b.cid
        && a.dirty == b.dirty
        && a.stub == b.stub
        && a.bytes == b.bytes
        && a.entries.len() == b.entries.len()
        && a.entries.iter().zip(&b.entries).all(|(x, y)| entry(x) == entry(y))
}

fn check_node(b: &[u8], what: &str) -> bool {
    let c = Cid::dag_cbor(b);
    match (decode_node(b, c), decode_node_reference(b, c)) {
        (Ok(x), Ok(y)) => {
            assert!(node_eq(&x, &y), "{what}: nodes differ: {x:?} vs {y:?}");
            let mut enc = Vec::new();
            vlsync_atproto::mst::encode_node(&x, &mut enc).unwrap();
            assert_eq!(enc, b, "{what}: re-encoding differs");
            true
        }
        (Err(x), Err(y)) => {
            assert_eq!(x, y, "{what}: {b:02x?}");
            false
        }
        (x, y) => panic!("{what}: fast {:?} vs reference {:?}: {b:02x?}", x.map(|_| ()), y.map(|_| ())),
    }
}

/// MST node blocks: two real repos plus random trees (keys of all heights,
/// shared prefixes, binary keys).
fn node_corpus() -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for car in ["shrike/greenground.repo.car", "shrike/repo_slice.car"] {
        let (_, blocks) = car_blocks(car);
        out.extend(blocks.into_iter().filter(|(c, b)| decode_node_reference(b, *c).is_ok()).map(|(_, b)| b));
    }
    assert!(!out.is_empty(), "no real MST nodes");
    let mut rng = StdRng::seed_from_u64(17);
    for t in 0..40 {
        let mut tree = Tree::new();
        for _ in 0..rng.gen_range(1..400) {
            let k: Vec<u8> = match t % 3 {
                0 => format!("app.bsky.feed.like/{}", rng.gen::<u64>()).into_bytes(),
                1 => format!("c/{}", rng.gen_range(0..2000)).into_bytes(),
                _ => (0..rng.gen_range(1..12)).map(|_| rng.gen_range(b'a'..=b'd')).collect(),
            };
            tree.insert_no_proof(&k, Cid::dag_cbor(&k)).unwrap();
        }
        let mut blocks = Vec::new();
        tree.write_diff_blocks(&mut blocks).unwrap();
        out.extend(blocks.into_iter().map(|(_, b)| b));
    }
    out
}

#[test]
fn mst_node_decoder_matches_reference() {
    let corpus = node_corpus();
    for (i, b) in corpus.iter().enumerate() {
        assert!(check_node(b, &format!("node {i}")), "node {i} rejected");
    }
    let mut rng = StdRng::seed_from_u64(23);
    let mut rejected = 0;
    for i in 0..60_000 {
        let mut b = corpus[rng.gen_range(0..corpus.len())].clone();
        if rng.gen_bool(0.3) {
            // structural edits a byte flip rarely makes: a prefix length,
            // a key suffix byte, t/l swapped between link and null
            let pos: Vec<usize> =
                (0..b.len().saturating_sub(2)).filter(|&j| b[j] == 0x61 && b[j + 1] == b'p').collect();
            if let Some(&j) = pos.get(rng.gen_range(0..pos.len().max(1))) {
                if j + 2 < b.len() {
                    b[j + 2] = rng.gen_range(0..24);
                }
            }
        } else {
            mutate(&mut rng, &mut b);
        }
        rejected += !check_node(&b, &format!("mutation {i}")) as usize;
    }
    assert!(rejected > 10_000, "too few corrupted nodes rejected ({rejected})");
    // hand-built nodes around the checks
    let l = |c: &Cid| {
        let mut v = vec![0xd8, 0x2a, 0x58, 0x25, 0x00];
        v.extend_from_slice(&c.to_bytes());
        v
    };
    let v = Cid::dag_cbor(b"v");
    let raw_v = Cid::raw(b"v");
    let entry = |k: &[u8], p: u8, t: Option<&Cid>, val: &Cid| {
        let mut e = vec![0xa4, 0x61, b'k', 0x40 | k.len() as u8];
        e.extend_from_slice(k);
        e.extend_from_slice(&[0x61, b'p', p, 0x61, b't']);
        match t {
            Some(t) => e.extend(l(t)),
            None => e.push(0xf6),
        }
        e.extend_from_slice(&[0x61, b'v']);
        e.extend(l(val));
        e
    };
    let node = |es: &[Vec<u8>], left: Option<&Cid>| {
        let mut b = vec![0xa2, 0x61, b'e', 0x80 | es.len() as u8];
        for e in es {
            b.extend_from_slice(e);
        }
        b.extend_from_slice(&[0x61, b'l']);
        match left {
            Some(c) => b.extend(l(c)),
            None => b.push(0xf6),
        }
        b
    };
    // keys of height 0 (from the interop vectors): "asdf", "2653ae71"
    let cases = [
        node(&[], None),
        node(&[], Some(&v)),
        node(&[entry(b"asdf", 0, None, &v)], None),
        node(&[entry(b"asdf", 0, None, &raw_v)], None),
        node(&[entry(b"asdf", 0, Some(&v), &v)], None),
        node(&[entry(b"asdf", 0, None, &v)], Some(&v)),
        node(&[entry(b"asdf", 1, None, &v)], None),
        node(&[entry(b"2653ae71", 0, None, &v), entry(b"asdf", 0, None, &v)], None),
        node(&[entry(b"asdf", 0, None, &v), entry(b"2653ae71", 0, None, &v)], None),
        node(&[entry(b"asdf", 0, None, &v), entry(b"", 4, None, &v)], None),
        node(&[entry(b"asdf", 0, None, &v), entry(b"x", 4, None, &v)], None),
        node(&[entry(b"blue", 0, None, &v), entry(b"x", 0, None, &v)], None),
        node(&[entry(b"", 0, None, &v)], None),
    ];
    for (i, b) in cases.iter().enumerate() {
        check_node(b, &format!("case {i}"));
    }
}

/// Built trees mutate in place; loaded ones restore their root on error.
/// Both give the same roots and diffs under random histories with proofs,
/// and snapshots (clones) taken before a mutation keep their root.
#[test]
fn built_trees_mutate_in_place_like_loaded_ones() {
    let mut rng = StdRng::seed_from_u64(29);
    for round in 0..6 {
        let mut built = Tree::new();
        let mut keys: Vec<String> = Vec::new();
        for i in 0..rng.gen_range(50..1500) {
            let k = format!("app.bsky.feed.post/{round}x{i}y{}", rng.gen::<u32>());
            built.insert_no_proof(k.as_bytes(), Cid::dag_cbor(k.as_bytes())).unwrap();
            keys.push(k);
        }
        let mut blocks = Vec::new();
        let root = built.write_diff_blocks(&mut blocks).unwrap();
        let map: HashMap<Cid, Vec<u8>> = blocks.into_iter().collect();
        let mut loaded = Tree::load_from_blocks(&map, root).unwrap();
        assert_eq!(loaded.root_cid().unwrap(), root);
        for step in 0..300 {
            let mut snap = built.clone();
            let before = snap.root_cid().unwrap();
            let insert = keys.is_empty() || rng.gen_bool(0.5);
            let k = if insert {
                let k = format!("app.bsky.feed.post/{round}s{step}z{}", rng.gen::<u32>());
                keys.push(k.clone());
                k
            } else {
                keys.swap_remove(rng.gen_range(0..keys.len()))
            };
            let v = Cid::dag_cbor(&rng.gen::<[u8; 4]>());
            let (a, b) = if insert {
                (built.insert(k.as_bytes(), v).unwrap(), loaded.insert(k.as_bytes(), v).unwrap())
            } else {
                (built.remove(k.as_bytes()).unwrap(), loaded.remove(k.as_bytes()).unwrap())
            };
            assert_eq!(a, b);
            let (mut da, mut db) = (Vec::new(), Vec::new());
            assert_eq!(built.write_diff_blocks(&mut da).unwrap(), loaded.write_diff_blocks(&mut db).unwrap());
            da.sort();
            db.sort();
            assert_eq!(da, db, "round {round} step {step}: diff blocks");
            assert_eq!(snap.root_cid().unwrap(), before, "snapshot changed");
        }
    }
    // a loaded partial tree: Partial errors leave it as it was
    let mut t = Tree::new();
    for i in 0..300 {
        t.insert_no_proof(format!("c/{i:04}").as_bytes(), Cid::dag_cbor(b"x")).unwrap();
    }
    let mut blocks = Vec::new();
    let root = t.write_diff_blocks(&mut blocks).unwrap();
    let mut map: HashMap<Cid, Vec<u8>> = blocks.into_iter().collect();
    let leaf = *map.keys().find(|c| **c != root).unwrap();
    map.remove(&leaf);
    let mut partial = Tree::load_from_blocks(&map, root).unwrap();
    let mut failed = 0;
    for i in 0..300 {
        let before = partial.root.clone();
        if partial.insert(format!("c/{i:04}a").as_bytes(), Cid::dag_cbor(b"y")).is_err() {
            failed += 1;
            assert!(std::sync::Arc::ptr_eq(&partial.root, &before), "failed insert changed the tree");
        }
    }
    assert!(failed > 0);
}

// ---------- lexicon ----------

#[test]
fn table_tid_check_matches_syntax() {
    let mut rng = StdRng::seed_from_u64(31);
    let tid = "3kxyzabcdefgh";
    assert!(vlpds::lexicon::valid_tid(tid));
    // every byte at every position of a valid TID
    for at in 0..13 {
        for c in 0..=255u8 {
            let mut b = tid.as_bytes().to_vec();
            b[at] = c;
            let s = String::from_utf8_lossy(&b);
            assert_eq!(vlpds::lexicon::valid_tid(&s), vlsync_atproto::syntax::valid_tid(&s), "{s:?}");
        }
    }
    const A: &[u8] = b"234567abcdefghijklmnopqrstuvwxyzABZ01-_.";
    for _ in 0..100_000 {
        let s: String = (0..rng.gen_range(11..16)).map(|_| A[rng.gen_range(0..A.len())] as char).collect();
        assert_eq!(vlpds::lexicon::valid_tid(&s), vlsync_atproto::syntax::valid_tid(&s), "{s:?}");
    }
    for s in ["", "é", "3kxyzabcdefgé", "3kxyzabcdefghé"] {
        assert_eq!(vlpds::lexicon::valid_tid(s), vlsync_atproto::syntax::valid_tid(s), "{s:?}");
    }
}
