//! Differential tests: vlpds's own atproto code against shrike 0.7.0, a
//! second, independent Rust implementation (dev-dependency only).
//!
//! Compared: DAG-CBOR decode/encode and JSON <-> CBOR, CID strings and
//! bytes, TIDs, identifier syntax, CAR reading, MST shapes / heights /
//! commit inversion / covering and record proofs / adversarial nodes,
//! K-256 signatures and did:keys, and lexicon record verdicts. Inputs are
//! the atproto interop fixtures, shrike's vectors (testdata/shrike, see its
//! NOTICE.txt: RFC 8949 vectors, lex-json vectors, @atproto/repo commit and
//! proof vectors, real firehose commits), random values, and mutations.
//!
//! Every disagreement is either a failure or one of the documented policy
//! differences below, each pinned by its own test so a change on either
//! side shows up (bench/results/differential/SHRIKE_ISSUES.md has the analysis):
//!
//! - floats: shrike's DRISL decoder accepts 64-bit floats (the DRISL
//!   spec allows them; shrike rejects them one layer up, in JSON
//!   conversion); vlpds rejects them while decoding (atproto data model).
//! - nesting: shrike caps CBOR nesting at 64 levels, vlpds at 128.
//! - lex-json: shrike follows @atproto/lex-json's non-strict mode (a
//!   malformed `$link`/`$bytes` object stays a plain map, and `$link`
//!   accepts base58btc/base36/CIDv0 strings); vlpds rejects those records
//!   like the reference PDS's strict record parsing.
//! - MST loading: shrike's loader (like indigo's) does not check node
//!   heights, canonical prefix compression or field sets; vlpds's
//!   `decode_node` / `load_from_blocks` do. shrike requires UTF-8 keys,
//!   vlpds (like indigo) takes keys as 1-1024 bytes.
//! - datetimes with impossible calendar dates (Feb 30): the TS reference and
//!   shrike accept them, indigo and vlpds reject them.
//!
//! And where shrike departs from the reference (SHRIKE_ISSUES.md, pinned in
//! `identifier_syntax`, `json_policy_differences_pinned` and
//! `shrike_update_inversion_overfetch_pinned`): `%` in DIDs, language tags,
//! AT-URI fragments, partially padded `$bytes`, and update-op inversion.
//!
//! `#[ignore]`d, opt-in: `real_records_from_clickhouse` runs the record
//! checks over a TSV of real records (`VLPDS_REAL_RECORDS=path`), and
//! `syntax_reference_oracle` / `json_reference_oracle` compare vlpds with
//! verdicts from the TypeScript reference (bench/results/differential/*.mjs).
use crate::common::*;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use shrike::cbor as sc;
use shrike::cbor::json::{drisl_to_json, json_to_drisl, Integers};
use shrike::crypto::SigningKey as _;
use shrike::mst::{DetachedTree, NoBlocks};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::str::FromStr;
use vlpds::lexicon;
use vlsync_atproto::cbor::{JsonValue, RecordRefs};
use vlsync_atproto::mst::{height_for_key, Tree};
use vlsync_atproto::{car, crypto, syntax, tid};

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn shrike_fixture(rel: &str) -> String {
    read_fixture(&format!("shrike/{rel}"))
}

fn s_cid(c: &Cid) -> sc::Cid {
    sc::Cid::from_bytes(&c.to_bytes()).unwrap()
}

fn v_cid(c: &sc::Cid) -> Cid {
    Cid::from_bytes(&c.to_bytes()).unwrap()
}

fn rand_cid(rng: &mut impl Rng) -> Cid {
    Cid::dag_cbor(&rng.gen::<[u8; 16]>())
}

// ---------------------------------------------------------------------------
// DAG-CBOR
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq)]
enum Cbor {
    /// both accept with identical canonical re-encodings and JSON, or both reject
    Agree,
    /// only shrike accepts, and the value holds a float (DRISL vs data model)
    FloatShrikeOnly,
    /// only vlpds accepts: nested deeper than shrike's 64-level cap
    DepthVlpdsOnly,
    Disagree(String),
}

fn has_float(v: &sc::Value) -> bool {
    match v {
        sc::Value::Float(_) => true,
        sc::Value::Array(a) => a.iter().any(has_float),
        sc::Value::Map(m) => m.iter().any(|(_, v)| has_float(v)),
        _ => false,
    }
}

fn cbor_compare(b: &[u8]) -> Cbor {
    let v = Value::decode(b);
    let s = sc::decode(b);
    match (v, s) {
        (Err(_), Err(_)) => Cbor::Agree,
        (Ok(v), Ok(s)) => {
            let vb = v.to_cbor();
            let sb = match sc::encode_value(&s) {
                Ok(x) => x,
                Err(e) => return Cbor::Disagree(format!("shrike cannot re-encode what it decoded: {e}")),
            };
            if vb != b || sb != b {
                return Cbor::Disagree(format!(
                    "re-encodings differ from the (canonical) input: vlpds {}, shrike {}",
                    hex::encode(&vb),
                    hex::encode(&sb)
                ));
            }
            // JSON views: vlpds's tree and streaming transcoders vs shrike's
            let sj = drisl_to_json(b);
            let mut stream = Vec::new();
            let streamed = vlsync_atproto::cbor::write_json(b, &mut stream)
                .map(|()| serde_json::from_slice::<J>(&stream).unwrap());
            match (sj, streamed) {
                (Ok(sj), Ok(vj)) if sj == v.to_json() && vj == sj => Cbor::Agree,
                (sj, vj) => Cbor::Disagree(format!("JSON differs: vlpds {vj:?} / {}, shrike {sj:?}", v.to_json())),
            }
        }
        (Err(ve), Ok(s)) if has_float(&s) => {
            let _ = ve;
            Cbor::FloatShrikeOnly
        }
        (Err(ve), Ok(s)) => Cbor::Disagree(format!("vlpds rejects ({ve}), shrike accepts {s:?}")),
        (Ok(_), Err(se)) if se.to_string().contains("nesting depth") => Cbor::DepthVlpdsOnly,
        (Ok(v), Err(se)) => Cbor::Disagree(format!("vlpds accepts {v:?}, shrike rejects ({se})")),
    }
}

/// Byte-level mutations of a valid encoding.
fn mutate(rng: &mut impl Rng, b: &[u8]) -> Vec<u8> {
    let mut m = b.to_vec();
    if m.is_empty() {
        m.push(rng.gen());
        return m;
    }
    let i = rng.gen_range(0..m.len());
    match rng.gen_range(0..8) {
        0 => m[i] ^= 1 << rng.gen_range(0..8),
        1 => m[i] = rng.gen(),
        2 => m.truncate(i),
        3 => m.insert(i, rng.gen()),
        4 => {
            m.remove(i);
        }
        5 => {
            // a byte from the set that matters to heads: majors/infos
            m[i] = [
                0x18, 0x19, 0x1a, 0x1b, 0x1f, 0x3f, 0x5f, 0x7f, 0x9f, 0xbf, 0xd8, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9,
                0xfa, 0xfb, 0xff,
            ][rng.gen_range(0..20)]
        }
        6 => {
            let j = rng.gen_range(i..m.len());
            let dup = m[i..=j].to_vec();
            m.splice(j + 1..j + 1, dup);
        }
        _ => {
            let j = rng.gen_range(0..m.len());
            m.swap(i, j)
        }
    }
    m
}

#[test]
fn cbor_interop_fixtures_identical() {
    let mut d = Diffs::new("data-model fixtures");
    for DataModelFixture { json: j, cbor, cid } in data_model_fixtures() {
        if let o @ (Cbor::Disagree(_) | Cbor::FloatShrikeOnly | Cbor::DepthVlpdsOnly) = cbor_compare(&cbor) {
            d.push(format!("{cid}: {o:?}"));
        }
        // JSON -> CBOR: vlpds's tree and one-pass encoders, shrike's converter
        let v = Value::from_json(&j).unwrap().to_cbor();
        let text = j.to_string();
        let mut jv = JsonValue::parse(text.as_bytes()).unwrap();
        let mut one_pass = Vec::new();
        jv.encode_record(&mut one_pass, &mut RecordRefs::default()).unwrap();
        let s = json_to_drisl(&j, Integers::Any).unwrap();
        if v != cbor || one_pass != cbor || s != cbor {
            d.push(format!(
                "{cid}: JSON->CBOR differs (vlpds {}, one-pass {}, shrike {})",
                v == cbor,
                one_pass == cbor,
                s == cbor
            ));
        }
        if Cid::dag_cbor(&cbor).to_string() != cid || sc::Cid::compute(sc::Codec::Drisl, &cbor).to_string() != cid {
            d.push(format!("{cid}: CID differs"));
        }
    }
    d.assert_none();
}

#[test]
fn cbor_rfc8949_vectors() {
    // shrike's RFC 8949 Appendix A vectors, flagged valid / canonical / float
    #[derive(serde::Deserialize)]
    struct V {
        hex: String,
        flags: Vec<String>,
    }
    let vs: Vec<V> = serde_json::from_str(&shrike_fixture("cbor_rfc8949_vectors.json")).unwrap();
    assert!(vs.len() > 700);
    let mut d = Diffs::new("RFC 8949 vectors");
    let (mut floats, mut accepted) = (0, 0);
    for v in &vs {
        let b = hex::decode(&v.hex).unwrap();
        let flag = |f: &str| v.flags.iter().any(|x| x == f);
        let canonical_dm = flag("valid") && flag("canonical") && !flag("float");
        match cbor_compare(&b) {
            Cbor::Agree => {
                let ok = Value::decode(&b).is_ok();
                accepted += ok as usize;
                // valid canonical CBOR outside the data model: integers beyond
                // i64, tags other than 42, simple values other than false/true/null,
                // maps with non-text keys
                let outside_dm = b[0] >> 5 == 6
                    || b[0] >= 0xe0
                    || ((b[0] == 0x1b || b[0] == 0x3b) && b.get(1).is_some_and(|x| *x >= 0x80))
                    || (b[0] >> 5 == 5 && b.get(1).is_some_and(|x| x >> 5 != 3));
                if ok != canonical_dm && !(canonical_dm && outside_dm) {
                    d.push(format!("{}: both {} but flags {:?}", v.hex, if ok { "accept" } else { "reject" }, v.flags));
                }
            }
            Cbor::FloatShrikeOnly => {
                floats += 1;
                assert!(flag("float") && flag("canonical"), "{}: {:?}", v.hex, v.flags);
            }
            o => d.push(format!("{}: {o:?}", v.hex)),
        }
    }
    d.assert_none();
    // the only split: shrike's DRISL decoder takes the canonical 64-bit
    // floats (f16/f32 are rejected by both), the data model takes none
    assert_eq!(floats, vs.iter().filter(|v| v.flags.iter().any(|f| f == "float") && v.hex.starts_with("fb")).count());
    assert!(floats > 0);
    assert!(accepted >= 30, "{accepted}");
}

#[test]
fn cbor_random_values_and_mutations() {
    let mut rng = StdRng::seed_from_u64(0x5ee_d001);
    let mut corpus: Vec<Vec<u8>> = data_model_fixtures().into_iter().map(|f| f.cbor).collect();
    for _ in 0..500 {
        corpus.push(rand_cbor(&mut rng, 0).to_cbor());
    }
    // MST nodes and commits too
    let mut t = Tree::new();
    for i in 0..300u32 {
        t.insert_no_proof(
            format!("app.bsky.feed.post/{}", tid::Tid((1 << 40) | (i as u64 * 7919))).as_bytes(),
            rand_cid(&mut rng),
        )
        .unwrap();
    }
    t.root_cid().unwrap();
    t.walk_blocks(&mut |_, b| corpus.push(b.to_vec())).unwrap();
    corpus.push(vlsync_atproto::events::encode_commit(
        "did:plc:abc",
        "3jzfcijpj2z2a",
        &rand_cid(&mut rng),
        Some(&[7; 64]),
    ));

    let mut d = Diffs::new("random values + mutations");
    let (mut agreed, mut rejected, mut floats) = (0, 0, 0);
    for b in &corpus {
        if cbor_compare(b) != Cbor::Agree {
            d.push(format!("valid {}: {:?}", hex::encode(b), cbor_compare(b)));
        }
        for _ in 0..24 {
            let m = mutate(&mut rng, b);
            match cbor_compare(&m) {
                Cbor::Agree => {
                    agreed += 1;
                    rejected += Value::decode(&m).is_err() as usize;
                }
                Cbor::FloatShrikeOnly => floats += 1,
                o => d.push(format!("mutant {}: {o:?}", hex::encode(&m))),
            }
        }
    }
    d.assert_none();
    // the mutations do reach both sides of the decision
    assert!(rejected > agreed / 4 && rejected < agreed, "{rejected}/{agreed}");
    eprintln!("cbor mutations: {agreed} agreed ({rejected} rejected by both), {floats} float-only splits");
}

#[test]
fn cbor_policy_differences_pinned() {
    // floats: DRISL (shrike's decoder) allows canonical f64, the atproto data model doesn't
    let pi = [0xfb, 0x40, 0x09, 0x21, 0xfb, 0x54, 0x44, 0x2d, 0x18];
    assert_eq!(cbor_compare(&pi), Cbor::FloatShrikeOnly);
    assert!(drisl_to_json(&pi).is_err(), "shrike rejects the float one layer up");
    // f16/f32, NaN and infinities: rejected by both
    for b in [
        &[0xf9, 0x3c, 0x00][..],
        &[0xfa, 0x3f, 0x80, 0, 0],
        &[0xfb, 0x7f, 0xf8, 0, 0, 0, 0, 0, 0],
        &[0xfb, 0x7f, 0xf0, 0, 0, 0, 0, 0, 0],
    ] {
        assert_eq!(cbor_compare(b), Cbor::Agree);
        assert!(Value::decode(b).is_err());
    }
    // nesting: shrike caps at 64 levels, vlpds at 128 (neither is a spec limit)
    let nested = |n: usize| {
        let mut b = vec![0x81; n];
        b.push(0x00);
        b
    };
    assert_eq!(cbor_compare(&nested(63)), Cbor::Agree);
    assert_eq!(cbor_compare(&nested(64)), Cbor::DepthVlpdsOnly);
    assert_eq!(cbor_compare(&nested(128)), Cbor::DepthVlpdsOnly);
    assert_eq!(cbor_compare(&nested(129)), Cbor::Agree);
    assert!(Value::decode(&nested(129)).is_err());
}

// ---------------------------------------------------------------------------
// JSON -> CBOR (record writes)
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq)]
enum JsonOutcome {
    Agree,
    /// vlpds rejects a malformed or non-base32 `$link` / `$bytes` / `$type` /
    /// blob object that shrike's non-strict lex-json keeps (or converts)
    StrictVlpdsOnly,
    /// `{"$bytes": "AQ="}` (partial padding): vlpds decodes the bytes, as
    /// @atproto/lex-json does; shrike keeps a plain map (SHRIKE_ISSUES.md)
    PartialPaddingShrikeMap,
    Disagree(String),
}

/// A `$bytes` object whose string has partial padding (`"AQ="`).
fn partial_padding(j: &J) -> bool {
    match j {
        J::Object(o) => {
            matches!((o.len(), o.get("$bytes")), (1, Some(J::String(b))) if b.ends_with('=') && b.len() % 4 != 0)
                || o.values().any(partial_padding)
        }
        J::Array(a) => a.iter().any(partial_padding),
        _ => false,
    }
}

/// An object shrike's non-strict mode and vlpds's strict mode treat differently.
fn lex_json_special(j: &J) -> bool {
    match j {
        J::Object(o) => {
            o.contains_key("$link")
                || o.contains_key("$bytes")
                || o.get("$type").is_some_and(|t| !t.is_string() || t == "" || t == "blob")
                || o.values().any(lex_json_special)
        }
        J::Array(a) => a.iter().any(lex_json_special),
        _ => false,
    }
}

fn json_compare(text: &str) -> JsonOutcome {
    let Ok(j) = serde_json::from_str::<J>(text) else {
        return JsonOutcome::Agree;
    };
    let tree = Value::from_json(&j).map(|v| v.to_cbor());
    let one_pass = JsonValue::parse(text.as_bytes()).map_err(|e| e.to_string()).and_then(|mut jv| {
        let mut out = Vec::new();
        jv.encode_record(&mut out, &mut RecordRefs::default()).map(|()| out).map_err(|e| e.to_string())
    });
    if tree.as_ref().ok() != one_pass.as_ref().ok() {
        return JsonOutcome::Disagree(format!("vlpds encoders differ: {tree:?} {one_pass:?}"));
    }
    let s = json_to_drisl(&j, Integers::Safe);
    match (tree, s) {
        (Ok(v), Ok(s)) if v == s => JsonOutcome::Agree,
        (Ok(_), Ok(_)) if partial_padding(&j) => JsonOutcome::PartialPaddingShrikeMap,
        (Ok(v), Ok(s)) => {
            JsonOutcome::Disagree(format!("bytes differ: vlpds {} shrike {}", hex::encode(v), hex::encode(s)))
        }
        (Err(_), Err(_)) => JsonOutcome::Agree,
        (Err(_), Ok(_)) if lex_json_special(&j) => JsonOutcome::StrictVlpdsOnly,
        (Err(e), Ok(_)) => JsonOutcome::Disagree(format!("vlpds rejects ({e}), shrike accepts")),
        (Ok(_), Err(e)) => JsonOutcome::Disagree(format!("vlpds accepts, shrike rejects ({e})")),
    }
}

fn rand_json(rng: &mut impl Rng, depth: usize) -> String {
    let cid = || Cid::dag_cbor(&[depth as u8]).to_string();
    let leaf = depth >= 4 || rng.gen_bool(0.35);
    match rng.gen_range(0..if leaf { 8 } else { 12 }) {
        0 => "null".into(),
        1 => ["true", "false"][rng.gen_range(0..2)].into(),
        2 => [
            "0",
            "-0",
            "1",
            "-1",
            "23",
            "24",
            "-25",
            "123.0",
            "1e3",
            "1.5",
            "-2.5e-3",
            "1E2",
            "9007199254740991",
            "9007199254740992",
            "-9007199254740993",
            "9223372036854775807",
            "9223372036854775808",
            "-9223372036854775808",
            "18446744073709551616",
            "1e400",
            "1.0e1",
        ][rng.gen_range(0..21)]
        .into(),
        3 => serde_json::to_string(&rand_text(rng)).unwrap(),
        4 => format!(
            "{{\"$link\": \"{}\"}}",
            [
                cid(),
                cid().to_uppercase(),
                format!("{}a", cid()),
                "bafy".into(),
                "QmQg1v4o9xdT3Q1R8tNK3z9ZkRmg7FbQfZ1J2Z6Ln8ZAwN".into(),
                "zdj7WhuEjrB52m1BisYCtmjH1hSKa7yZ3jEZ9JcXaFRD51wVz".into()
            ][rng.gen_range(0..6)]
        ),
        5 => format!(
            "{{\"$bytes\": \"{}\"}}",
            ["", "AQ", "AQ==", "AQ=", "AQI", "AQID", "A", "!!", "aGVsbG8gd29ybGQ", "aGk=", "_-8"][rng.gen_range(0..11)]
        ),
        6 => format!(
            "{{\"$type\": \"blob\", \"ref\": {{\"$link\": \"{}\"}}, \"mimeType\": {}, \"size\": {}}}",
            Cid::raw(&[depth as u8]),
            ["\"image/png\"", "1", "null"][rng.gen_range(0..3)],
            ["12", "\"12\"", "1.5", "-1"][rng.gen_range(0..4)]
        ),
        7 => format!(
            "{{\"$type\": {}}}",
            ["\"app.bsky.feed.post\"", "\"\"", "1", "null", "\"blob\""][rng.gen_range(0..5)]
        ),
        8 | 9 => {
            let n = rng.gen_range(0..5);
            let mut parts = Vec::new();
            for _ in 0..n {
                let k = ["a", "b", "$type", "$link", "$bytes", "ref", "text", "aa", "a"][rng.gen_range(0..9)];
                parts.push(format!("\"{k}\": {}", rand_json(rng, depth + 1)));
            }
            format!("{{{}}}", parts.join(", "))
        }
        _ => format!("[{}]", (0..rng.gen_range(0..4)).map(|_| rand_json(rng, depth + 1)).collect::<Vec<_>>().join(",")),
    }
}

#[test]
fn json_to_cbor_random_and_lex_json_vectors() {
    let mut rng = StdRng::seed_from_u64(0x15_0b);
    let mut d = Diffs::new("JSON -> CBOR");
    let (mut agree, mut strict, mut padding) = (0, 0, 0);
    let mut texts: Vec<String> = (0..3000).map(|_| rand_json(&mut rng, 0)).collect();
    // shrike's port of @atproto/lex-json's tests
    let lex: J = serde_json::from_str(&shrike_fixture("lex_json_vectors.json")).unwrap();
    for group in ["special", "plain", "rejected"] {
        for c in lex[group].as_array().unwrap() {
            texts.push(c["json"].to_string());
        }
    }
    // the interop data-model valid/invalid records
    for f in ["valid", "invalid"] {
        let cases: J = serde_json::from_str(&read_fixture(&format!("interop/data-model/data-model-{f}.json"))).unwrap();
        for c in cases.as_array().unwrap() {
            texts.push(c["json"].to_string());
        }
    }
    // VLPDS_JSON_DUMP=<file>: write the corpus out (one JSON text per line)
    // for bench/results/differential/json_oracle.mjs
    if let Ok(path) = std::env::var("VLPDS_JSON_DUMP") {
        let lines: Vec<String> =
            texts.iter().filter_map(|t| serde_json::from_str::<J>(t).ok()).map(|j| j.to_string()).collect();
        std::fs::write(path, lines.join("\n") + "\n").unwrap();
    }
    for t in &texts {
        match json_compare(t) {
            JsonOutcome::Agree => agree += 1,
            JsonOutcome::StrictVlpdsOnly => strict += 1,
            JsonOutcome::PartialPaddingShrikeMap => padding += 1,
            JsonOutcome::Disagree(e) => d.push(format!("{}: {e}", short(t))),
        }
    }
    d.assert_none();
    assert!(padding > 0 && strict > 0);
    // lex-json "special" vectors: both turn every $link/$bytes map into a CID / bytes
    for c in lex["special"].as_array().unwrap() {
        let text = c["json"].to_string();
        assert_eq!(json_compare(&text), JsonOutcome::Agree, "{text}");
        assert!(Value::from_json(&c["json"]).is_ok(), "{text}");
    }
    eprintln!("json->cbor: {agree} agree, {strict} strict-only (vlpds rejects, shrike keeps a plain map), {padding} partial-padding $bytes");
}

#[test]
fn json_policy_differences_pinned() {
    let c = Cid::dag_cbor(b"x");
    for (text, want) in [
        // malformed $link / $bytes objects: shrike keeps a plain map, vlpds rejects the record
        (r#"{"a": {"$link": "bafy"}}"#.to_string(), JsonOutcome::StrictVlpdsOnly),
        (format!(r#"{{"a": {{"$link": "{c}", "x": 1}}}}"#), JsonOutcome::StrictVlpdsOnly),
        (r#"{"a": {"$bytes": "!!"}}"#.to_string(), JsonOutcome::StrictVlpdsOnly),
        (r#"{"$type": ""}"#.to_string(), JsonOutcome::StrictVlpdsOnly),
        // blob shape checked by vlpds only
        (r#"{"a": {"$type": "blob"}}"#.to_string(), JsonOutcome::StrictVlpdsOnly),
        // well-formed: identical bytes
        (format!(r#"{{"a": {{"$link": "{c}"}}, "b": {{"$bytes": "AQI="}}}}"#), JsonOutcome::Agree),
        // $bytes: non-zero trailing bits decode in both, as in @atproto/lex-data
        (r#"{"a": {"$bytes": "AR"}}"#.to_string(), JsonOutcome::Agree),
        // partial padding: vlpds (like the reference) decodes it, shrike keeps a map
        (r#"{"a": {"$bytes": "AQ="}}"#.to_string(), JsonOutcome::PartialPaddingShrikeMap),
        // over-padding and the URL-safe alphabet: invalid $bytes for vlpds and shrike
        (r#"{"a": {"$bytes": "AQID="}}"#.to_string(), JsonOutcome::StrictVlpdsOnly),
        (r#"{"a": {"$bytes": "_-8"}}"#.to_string(), JsonOutcome::StrictVlpdsOnly),
        // floats and out-of-range integers: both reject
        (r#"{"a": 1.5}"#.to_string(), JsonOutcome::Agree),
        (r#"{"a": 18446744073709551615}"#.to_string(), JsonOutcome::Agree),
    ] {
        assert_eq!(json_compare(&text), want, "{text}");
    }
    // $link in a non-base32 multibase: shrike converts it to the same link, vlpds rejects
    let z = format!("z{}", bs58::encode(c.to_bytes()).into_string());
    let j = json!({"a": {"$link": z}});
    assert_eq!(json_compare(&j.to_string()), JsonOutcome::StrictVlpdsOnly);
    assert_eq!(json_to_drisl(&j, Integers::Any).unwrap(), Value::Map(vec![("a".into(), Value::Link(c))]).to_cbor());
}

// ---------------------------------------------------------------------------
// CIDs and TIDs
// ---------------------------------------------------------------------------

fn cid_str_compare(s: &str, d: &mut Diffs) -> bool {
    let v = Cid::parse(s);
    let sh = sc::Cid::from_str(s);
    match (&v, &sh) {
        (Ok(v), Ok(sh)) => {
            if v.to_bytes() != sh.to_bytes() || v.to_string() != sh.to_string() || v.to_string() != s {
                d.push(format!("{s}: parsed differently ({v} / {sh})"));
            }
        }
        (Err(_), Err(_)) => {}
        _ => {
            d.push(format!("{}: vlpds {:?}, shrike {:?}", short(s), v.is_ok(), sh.as_ref().map_err(|e| e.to_string())))
        }
    }
    v.is_ok()
}

#[test]
fn cid_strings_and_bytes() {
    let mut d = Diffs::new("CIDs");
    let mut rng = StdRng::seed_from_u64(42);
    let mut inputs: Vec<String> = Vec::new();
    for f in ["valid", "invalid"] {
        inputs.extend(fixture_lines(&format!("interop/syntax/cid_syntax_{f}.txt")));
    }
    for i in 0..300u32 {
        let c = if i % 3 == 0 { Cid::raw(&i.to_be_bytes()) } else { Cid::dag_cbor(&i.to_be_bytes()) };
        let s = c.to_string();
        let mut b = c.to_bytes().to_vec();
        inputs.push(s.clone());
        inputs.push(s.to_uppercase());
        inputs.push(format!("B{}", &s[1..]));
        inputs.push(format!("z{}", bs58::encode(&b).into_string()));
        inputs.push(s[..s.len() - 1].to_string());
        inputs.push(format!("{s}a"));
        inputs.push(format!("{s}="));
        // every last character: only the canonical (zero padding bits) one parses
        for ch in "abcdefghijklmnopqrstuvwxyz234567".chars() {
            inputs.push(format!("{}{ch}", &s[..s.len() - 1]));
        }
        // header bytes: version, codec, hash code, digest length
        let k = rng.gen_range(0..4);
        b[k] = rng.gen();
        inputs.push(format!("b{}", vlsync_atproto::cid::base32_encode(&b)));
        // other lengths
        let n = rng.gen_range(30..40);
        b.resize(n, 0);
        inputs.push(format!("b{}", vlsync_atproto::cid::base32_encode(&b)));
    }
    let mut ok = 0;
    for s in &inputs {
        ok += cid_str_compare(s, &mut d) as usize;
    }
    // binary CIDs: random headers and lengths
    for _ in 0..3000 {
        let n = [35, 36, 36, 36, 37][rng.gen_range(0..5)];
        let mut b: Vec<u8> = (0..n).map(|_| rng.gen()).collect();
        if rng.gen_bool(0.7) && n >= 4 {
            b[..4].copy_from_slice(&[
                1,
                [0x71, 0x55, 0x70, 0x72][rng.gen_range(0..4)],
                [0x12, 0x13][rng.gen_range(0..2)],
                [0x20, 0x40][rng.gen_range(0..2)],
            ]);
        }
        let (v, s) = (Cid::from_bytes(&b), sc::Cid::from_bytes(&b));
        if v.is_ok() != s.is_ok() || v.as_ref().ok().map(|c| c.to_bytes()) != s.as_ref().ok().map(|c| c.to_bytes()) {
            d.push(format!("bytes {}: vlpds {v:?}, shrike {s:?}", hex::encode(&b)));
        }
    }
    d.assert_none();
    assert!(ok >= 300, "{ok}");
}

#[test]
fn tids() {
    let mut d = Diffs::new("TIDs");
    let mut rng = StdRng::seed_from_u64(7);
    let mut inputs: Vec<(String, Option<bool>)> = Vec::new();
    for (f, want) in [("valid", true), ("invalid", false)] {
        for l in fixture_lines(&format!("interop/syntax/tid_syntax_{f}.txt")) {
            inputs.push((l, Some(want)));
        }
    }
    const A: &[u8] = b"234567abcdefghijklmnopqrstuvwxyzABZ01-_";
    for _ in 0..5000 {
        let n = [12, 13, 13, 13, 14][rng.gen_range(0..5)];
        let pool = if rng.gen_bool(0.8) { 32 } else { A.len() };
        let s: String = (0..n).map(|_| A[rng.gen_range(0..pool)] as char).collect();
        inputs.push((s, None));
    }
    for (s, want) in &inputs {
        let v = syntax::valid_tid(s);
        let vp = tid::Tid::parse(s);
        let sh = shrike::syntax::Tid::from_str(s);
        if v != vp.is_some() {
            d.push(format!("{s}: vlpds valid_tid {v} vs Tid::parse {:?}", vp));
        }
        match (vp, &sh) {
            (Some(a), Ok(b)) if a.0 != b.as_u64() || a.to_string() != b.to_string() => {
                d.push(format!("{s}: values differ"))
            }
            (Some(_), Ok(_)) | (None, Err(_)) => {}
            _ => d.push(format!("{s}: vlpds {v}, shrike {}", sh.is_ok())),
        }
        if let Some(w) = want {
            if v != *w {
                d.push(format!("{s}: vlpds {v}, fixture says {w}"));
            }
            if sh.is_ok() != *w {
                d.push(format!("{s}: shrike {}, fixture says {w}", sh.is_ok()));
            }
        }
    }
    // construction from parts
    for _ in 0..2000 {
        let (us, clock) = (rng.gen_range(0..1u64 << 53), rng.gen_range(0..1024u16));
        let a = tid::Tid::from_parts(us, clock as u64);
        let b = shrike::syntax::Tid::new(us, clock).unwrap();
        if a.0 != b.as_u64() || a.to_string() != b.to_string() || a.micros() != b.timestamp_micros() {
            d.push(format!("parts {us} {clock}: {a} vs {b}"));
        }
    }
    d.assert_none();
}

// ---------------------------------------------------------------------------
// identifier syntax
// ---------------------------------------------------------------------------

struct Kind {
    name: &'static str,
    fixture: &'static str,
    vlpds: fn(&str) -> bool,
    shrike: fn(&str) -> bool,
    /// characters and lengths for generated inputs
    alphabet: &'static str,
    lens: &'static [usize],
}

fn valid_at_identifier(s: &str) -> bool {
    vlpds::xrpc::extract::valid_at_identifier(s)
}

fn kinds() -> Vec<Kind> {
    use shrike::syntax as ss;
    vec![
        Kind {
            name: "did",
            fixture: "did",
            vlpds: syntax::valid_did,
            shrike: |s| ss::Did::try_from(s).is_ok(),
            alphabet: "did:plcweb.%-_:ABZ09az~#/?",
            lens: &[4, 8, 12, 32, 2047, 2048, 2049, 8192],
        },
        Kind {
            name: "handle",
            fixture: "handle",
            vlpds: syntax::valid_handle,
            shrike: |s| ss::Handle::try_from(s).is_ok(),
            alphabet: "ab.-09Z_ ",
            lens: &[1, 3, 6, 12, 63, 64, 252, 253, 254],
        },
        Kind {
            name: "nsid",
            fixture: "nsid",
            vlpds: syntax::valid_nsid,
            shrike: |s| ss::Nsid::try_from(s).is_ok(),
            alphabet: "ab.-09Z_",
            lens: &[5, 8, 14, 63, 64, 253, 317, 318],
        },
        Kind {
            name: "rkey",
            fixture: "recordkey",
            vlpds: syntax::valid_rkey,
            shrike: |s| ss::RecordKey::try_from(s).is_ok(),
            alphabet: "aZ09._:~-/#@ %",
            lens: &[1, 2, 3, 13, 512, 513],
        },
        Kind {
            name: "at-uri",
            fixture: "aturi",
            vlpds: lexicon::valid_at_uri,
            shrike: |s| ss::AtUri::try_from(s).is_ok(),
            alphabet: "at:/.bcom-did:plc:x#?3Z_~",
            lens: &[5, 12, 30, 60, 8192, 8193],
        },
        Kind {
            name: "datetime",
            fixture: "datetime",
            vlpds: lexicon::valid_datetime,
            shrike: |s| ss::Datetime::try_from(s).is_ok(),
            alphabet: "0123456789-T:.Z+z t",
            lens: &[19, 20, 24, 25, 29, 64, 65],
        },
        Kind {
            name: "language",
            fixture: "language",
            vlpds: lexicon::valid_language,
            shrike: |s| ss::Language::try_from(s).is_ok(),
            alphabet: "enUSxi-09_",
            lens: &[1, 2, 3, 5, 9, 13, 20],
        },
        Kind {
            name: "at-identifier",
            fixture: "atidentifier",
            vlpds: valid_at_identifier,
            shrike: |s| ss::AtIdentifier::try_from(s).is_ok(),
            alphabet: "did:plc.ab-09",
            lens: &[3, 8, 20, 253],
        },
        Kind {
            name: "tid",
            fixture: "tid",
            vlpds: syntax::valid_tid,
            shrike: |s| ss::Tid::try_from(s).is_ok(),
            alphabet: "234567abcdefghijklmnopqrstuvwxyz",
            lens: &[12, 13, 14],
        },
    ]
}

/// Valid-ish prefixes the generator splices random tails onto.
fn seeds(kind: &str) -> &'static [&'static str] {
    match kind {
        "did" => &["did:plc:", "did:web:", "did:", "did:key:z", "did:plc:abc", "did:web:a.com%3A3000"],
        "handle" => &["a.", "a.b.", "xn--", "alice.bsky.", ""],
        "nsid" => &["app.bsky.", "com.example.", "a.b.", "a-0.b-1.", "1a.b."],
        "at-uri" => {
            &["at://did:plc:abc/", "at://a.com/", "at://did:plc:abc/app.bsky.feed.post/", "at://", "at://did:web:x.com"]
        }
        "datetime" => &["1985-04-12T23:20:50", "1985-04-12T23:20:50.", "0000-01-01T00:00:00", "2024-02-30T00:00:00"],
        "language" => &["en", "en-", "x-", "i-", "zh-Hant-"],
        "at-identifier" => &["did:plc:", "a.", "did:web:"],
        _ => &[""],
    }
}

/// Known splits where shrike departs from the reference (SHRIKE_ISSUES.md;
/// vlpds matches @atproto/syntax there, see `syntax_reference_oracle`), or
/// where the references themselves split.
fn known_syntax_split(kind: &str, s: &str, vlpds: bool, shrike: bool) -> Option<&'static str> {
    match kind {
        // shrike rejects every `%` in a DID; the spec and the reference allow it
        "did" if s.contains('%') && vlpds && !shrike => Some("shrike rejects % in DIDs"),
        // shrike's simplified BCP 47 check (any 1-8 alnum subtags after a
        // lowercase primary, no private-use-only tags)
        "language" => Some("shrike's simplified language tags"),
        // impossible calendar dates: the TS reference (JS Date) rolls them
        // over and accepts, indigo (Go time.Parse) and vlpds reject
        "datetime"
            if !vlpds
                && shrike
                && s.is_ascii()
                && s.len() > 10
                && lexicon::valid_datetime(&format!("{}01{}", &s[..8], &s[10..])) =>
        {
            Some("impossible calendar date")
        }
        _ => None,
    }
}

#[test]
fn identifier_syntax() {
    let mut d = Diffs::new("identifier syntax");
    let mut rng = StdRng::seed_from_u64(0x5a_17a);
    let mut counts = Vec::new();
    let mut known: BTreeMap<&str, usize> = BTreeMap::new();
    for k in kinds() {
        let mut checked = 0;
        // fixtures: vlpds agrees with every one, shrike outside its known splits
        for (f, want) in [("valid", true), ("invalid", false)] {
            let path = format!("interop/syntax/{}_syntax_{f}.txt", k.fixture);
            if !fixture_path(&path).exists() {
                continue;
            }
            for s in fixture_lines(&path) {
                let (v, sh) = ((k.vlpds)(&s), (k.shrike)(&s));
                checked += 1;
                if v != want {
                    d.push(format!("{} {}: fixture {want}, vlpds {v}", k.name, short(&s)));
                }
                if sh != want {
                    match known_syntax_split(k.name, &s, v, sh) {
                        Some(why) => *known.entry(why).or_default() += 1,
                        None => d.push(format!("{} {}: fixture {want}, shrike {sh}", k.name, short(&s))),
                    }
                }
            }
        }
        // generated: seeds + random tails, at boundary lengths
        for _ in 0..4000 {
            let seed = seeds(k.name)[rng.gen_range(0..seeds(k.name).len())];
            let len = k.lens[rng.gen_range(0..k.lens.len())];
            let al = k.alphabet.as_bytes();
            let mut s = seed.to_string();
            while s.len() < len {
                s.push(al[rng.gen_range(0..al.len())] as char);
            }
            if rng.gen_bool(0.1) {
                s.truncate(len);
            }
            let (v, sh) = ((k.vlpds)(&s), (k.shrike)(&s));
            checked += 1;
            if v != sh {
                match known_syntax_split(k.name, &s, v, sh) {
                    Some(why) => *known.entry(why).or_default() += 1,
                    None => d.push(format!("{} {}: vlpds {v}, shrike {sh}", k.name, short(&s))),
                }
            }
        }
        counts.push(format!("{} {checked}", k.name));
    }
    eprintln!("syntax checked: {}; known splits {known:?}", counts.join(", "));
    d.assert_none();
    // the pinned splits are still there (drop them from known_syntax_split once fixed)
    assert!(
        syntax::valid_did("did:web:localhost%3A1234")
            && shrike::syntax::Did::try_from("did:web:localhost%3A1234").is_err()
    );
    assert!(lexicon::valid_language("X-fr-CH") && shrike::syntax::Language::try_from("X-fr-CH").is_err());
    assert!(
        !lexicon::valid_datetime("2024-02-30T00:00:00Z")
            && shrike::syntax::Datetime::try_from("2024-02-30T00:00:00Z").is_ok()
    );
    // SHRIKE_ISSUES.md repros (vlpds matches @atproto/syntax on each)
    use shrike::syntax as ss;
    for did in ["did:web:localhost%3A1234", "did:method:val%BB"] {
        assert!(syntax::valid_did(did) && ss::Did::try_from(did).is_err(), "{did}");
    }
    for (lang, reference) in
        [("x-foo", true), ("X-fr-CH", true), ("i-foo", false), ("en-a", false), ("sl-rozaj-rozaj", false)]
    {
        assert_eq!(lexicon::valid_language(lang), reference, "{lang}");
        assert_eq!(ss::Language::try_from(lang).is_ok(), !reference, "{lang}");
    }
    let frag = "at://did:plc:abc/app.bsky.feed.post/3jzfcijpj2z2a#/text";
    assert!(lexicon::valid_at_uri(frag) && ss::AtUri::try_from(frag).is_err());
}

// ---------------------------------------------------------------------------
// CAR
// ---------------------------------------------------------------------------

type Blocks = Vec<(Cid, Vec<u8>)>;

fn car_compare(b: &[u8]) -> Result<Option<(Vec<Cid>, Blocks)>, String> {
    let v = car::read_car(b);
    let s = shrike::car::read_all(b);
    match (v, s) {
        (Ok((vr, vb)), Ok((sr, sb))) => {
            let sr: Vec<Cid> = sr.iter().map(v_cid).collect();
            let sb: Blocks = sb.iter().map(|x| (v_cid(&x.cid), x.data.clone())).collect();
            let vb: Blocks = vb.into_iter().map(|(c, d)| (c, d.to_vec())).collect();
            if vr != sr || vb != sb {
                return Err(format!("read differently: roots {vr:?} / {sr:?}, {} / {} blocks", vb.len(), sb.len()));
            }
            Ok(Some((vr, vb)))
        }
        (Err(_), Err(_)) => Ok(None),
        (Ok((r, bl)), Err(e)) => {
            Err(format!("vlpds reads ({} roots, {} blocks), shrike rejects: {e}", r.len(), bl.len()))
        }
        (Err(e), Ok(_)) => Err(format!("vlpds rejects ({e}), shrike reads")),
    }
}

fn tree_car(t: &mut Tree, commit: &[u8]) -> Vec<u8> {
    let c = Cid::dag_cbor(commit);
    let mut out = Vec::new();
    car::write_header(&mut out, &c);
    car::write_block(&mut out, &c, commit);
    t.walk_blocks(&mut |cid, b| car::write_block(&mut out, &cid, b)).unwrap();
    out
}

#[test]
fn car_read_agreement() {
    let mut d = Diffs::new("CAR");
    let mut rng = StdRng::seed_from_u64(0xca7);
    let mut cars: Vec<Vec<u8>> = vec![
        std::fs::read(fixture_path("shrike/repo_slice.car")).unwrap(),
        std::fs::read(fixture_path("shrike/greenground.repo.car")).unwrap(),
    ];
    // vlpds-written CARs of random trees
    for n in [0usize, 1, 5, 40, 200] {
        let mut t = Tree::new();
        for _ in 0..n {
            t.insert_no_proof(
                format!("app.bsky.feed.like/{}", tid::Tid(rng.gen::<u64>() >> 1)).as_bytes(),
                rand_cid(&mut rng),
            )
            .unwrap();
        }
        let root = t.root_cid().unwrap();
        cars.push(tree_car(
            &mut t,
            &vlsync_atproto::events::encode_commit("did:plc:abc", "3jzfcijpj2z2a", &root, Some(&[1; 64])),
        ));
    }
    // shrike-written CARs (roots: none, one, several)
    for roots in [0usize, 1, 3] {
        let blocks: Vec<shrike::car::Block> = (0..20u8)
            .map(|i| {
                let data = Value::Map(vec![("i".into(), Value::Int(i as i64))]).to_cbor();
                shrike::car::Block { cid: sc::Cid::compute(sc::Codec::Drisl, &data), data }
            })
            .collect();
        let rs: Vec<sc::Cid> = blocks.iter().take(roots).map(|b| b.cid).collect();
        cars.push(shrike::car::write_all(&rs, &blocks).unwrap());
    }
    // proof CARs from the reference implementation
    let ts: J = serde_json::from_str(&shrike_fixture("ts_vectors.json")).unwrap();
    for c in ts["cases"].as_array().unwrap().iter().step_by(5) {
        cars.push(b64_decode(c["proof"].as_str().unwrap()));
    }
    let mut read = 0;
    let mut rejected = 0;
    for b in &cars {
        match car_compare(b) {
            Ok(Some(_)) => read += 1,
            Ok(None) => d.push(format!("valid CAR rejected by both ({} bytes)", b.len())),
            Err(e) => d.push(format!("valid CAR: {e}")),
        }
        for _ in 0..200 {
            let m = mutate(&mut rng, b);
            match car_compare(&m) {
                Ok(None) => rejected += 1,
                Ok(Some(_)) => {}
                Err(e) => d.push(format!("mutant {}: {e}", hex::encode(&m[..m.len().min(120)]))),
            }
        }
    }
    d.assert_none();
    assert_eq!(read, cars.len());
    assert!(rejected > 100, "{rejected}");
}

#[test]
fn car_header_rules_agree() {
    // CARv1 header: version 1 and a roots array of CIDs, other keys ignored
    let c = Cid::dag_cbor(b"x");
    let car_with_header = |h: Value| {
        let hb = h.to_cbor();
        let mut out = Vec::new();
        car::write_varint(&mut out, hb.len() as u64);
        out.extend_from_slice(&hb);
        car::write_block(&mut out, &c, b"x");
        out
    };
    let roots = Value::Array(vec![Value::Link(c)]);
    let v1 = ("version".to_string(), Value::Int(1));
    for (h, ok) in [
        (Value::Map(vec![("roots".into(), roots.clone()), v1.clone()]), true),
        (Value::Map(vec![("x".into(), Value::Null), ("roots".into(), roots.clone()), v1.clone()]), true),
        (Value::Map(vec![("roots".into(), Value::Array(vec![])), v1.clone()]), true),
        (Value::Map(vec![("roots".into(), roots.clone())]), false),
        (Value::Map(vec![("roots".into(), roots.clone()), ("version".into(), Value::Int(2))]), false),
        (Value::Map(vec![v1.clone()]), false),
        (Value::Map(vec![("roots".into(), Value::Int(1)), v1.clone()]), false),
        (Value::Map(vec![("roots".into(), Value::Array(vec![Value::Null])), v1.clone()]), false),
    ] {
        let car = car_with_header(h.clone());
        assert_eq!(car_compare(&car).map(|r| r.is_some()), Ok(ok), "{h:?}");
    }
}

// ---------------------------------------------------------------------------
// MST
// ---------------------------------------------------------------------------

fn rand_key(rng: &mut impl Rng) -> String {
    let coll = ["app.bsky.feed.post", "app.bsky.feed.like", "app.bsky.graph.follow", "com.example.k", "a.b.c"]
        [rng.gen_range(0..5)];
    let rkey = match rng.gen_range(0..4) {
        0 => tid::Tid(rng.gen::<u64>() >> 1).to_string(),
        1 => tid::Tid((1 << 60) + rng.gen_range(0..5000u64)).to_string(),
        2 => "self".into(),
        _ => (0..rng.gen_range(1..12)).map(|_| b"abcz019:._~-"[rng.gen_range(0..12)] as char).collect(),
    };
    format!("{coll}/{rkey}")
}

/// shrike's view of a vlpds block set.
fn s_blocks(blocks: &HashMap<Cid, Vec<u8>>) -> HashMap<sc::Cid, Vec<u8>> {
    blocks.iter().map(|(c, b)| (s_cid(c), b.clone())).collect()
}

fn all_blocks(t: &Tree) -> HashMap<Cid, Vec<u8>> {
    let mut m = HashMap::new();
    t.walk_blocks(&mut |c, b| {
        m.insert(c, b.to_vec());
    })
    .unwrap();
    m
}

#[test]
fn mst_heights_agree() {
    let mut rng = StdRng::seed_from_u64(0x4e16);
    let mut keys: Vec<String> = (0..20_000).map(|_| rand_key(&mut rng)).collect();
    keys.extend(fixture_lines("interop/mst/example_keys.txt"));
    for k in &keys {
        assert_eq!(height_for_key(k.as_bytes()), shrike::mst::height_for_key(k) as i32, "{k}");
    }
}

#[test]
fn mst_roots_agree_on_random_histories() {
    let mut rng = StdRng::seed_from_u64(0x7aee);
    for round in 0..40 {
        let mut v = Tree::new();
        let mut s = DetachedTree::new();
        let mut live: Vec<String> = Vec::new();
        let n = [0, 1, 2, 10, 50, 200, 600][round % 7];
        for step in 0..n + 30 {
            if step < n || live.is_empty() || rng.gen_bool(0.6) {
                let k = rand_key(&mut rng);
                let val = rand_cid(&mut rng);
                let a = v.insert_no_proof(k.as_bytes(), val).unwrap();
                let b = s.insert(&NoBlocks, k.clone(), s_cid(&val)).unwrap();
                assert_eq!(a.map(|c| s_cid(&c)), b, "insert {k}");
                if a.is_none() {
                    live.push(k);
                }
            } else {
                let k = live.swap_remove(rng.gen_range(0..live.len()));
                assert_eq!(
                    v.remove(k.as_bytes()).unwrap().map(|c| s_cid(&c)),
                    s.remove(&NoBlocks, &k).unwrap(),
                    "remove {k}"
                );
            }
            if step % 37 == 0 || step == n + 29 {
                let (vr, sr) = (v.root_cid().unwrap(), s.flush().unwrap().root);
                assert_eq!(s_cid(&vr), sr, "round {round} step {step}: roots differ");
            }
        }
        // and shrike reads vlpds's whole block set back to the same entries
        let blocks = s_blocks(&all_blocks(&v));
        let mut loaded = DetachedTree::load(s_cid(&v.root_cid().unwrap()));
        let mut want: Vec<(String, sc::Cid)> = Vec::new();
        v.walk(&mut |k, c| want.push((String::from_utf8(k.to_vec()).unwrap(), s_cid(&c))));
        assert_eq!(loaded.entries(&blocks).unwrap(), want);
    }
}

/// One commit: `ops` applied to `before`; returns (root before, root after,
/// the blocks vlpds emits for the commit, every block of the new tree).
fn vlpds_commit(t: &mut Tree, ops: &[(String, Option<Cid>)]) -> (Cid, Cid, HashMap<Cid, Vec<u8>>) {
    let before = t.root_cid().unwrap();
    for (k, v) in ops {
        match v {
            Some(v) => {
                t.insert(k.as_bytes(), *v).unwrap();
            }
            None => {
                t.remove(k.as_bytes()).unwrap();
            }
        }
    }
    let mut diff = Vec::new();
    let after = t.write_diff_blocks(&mut diff).unwrap();
    (before, after, diff.into_iter().collect())
}

/// Random ops against `live` keys: creates, updates and deletes, each key once.
fn rand_ops(rng: &mut impl Rng, live: &BTreeMap<String, Cid>, n: usize) -> Vec<(String, Option<Cid>, Option<Cid>)> {
    let mut ops: Vec<(String, Option<Cid>, Option<Cid>)> = Vec::new();
    let keys: Vec<&String> = live.keys().collect();
    let mut seen = BTreeSet::new();
    for _ in 0..n {
        let (k, prev) = if !keys.is_empty() && rng.gen_bool(0.5) {
            let k = keys[rng.gen_range(0..keys.len())].clone();
            let p = live[&k];
            (k, Some(p))
        } else {
            (rand_key(rng), None)
        };
        if !seen.insert(k.clone()) || (prev.is_none() && live.contains_key(&k)) {
            continue;
        }
        let new = if prev.is_some() && rng.gen_bool(0.5) { None } else { Some(rand_cid(rng)) };
        ops.push((k, new, prev));
    }
    ops
}

type Op = (String, Option<Cid>, Option<Cid>);

/// Undoes `ops` (path, new value, previous value), newest first, from the
/// tree at `after` with only the blocks in `src`, as an indigo-style sync 1.1
/// verifier does: creates and deletes through shrike's `DetachedTree`; an
/// update only swaps the value at an existing key, so it is rewritten along
/// the key's path with shrike's node codec. (shrike's own `insert` of an
/// existing key also loads the key's neighbour subtrees: SHRIKE_ISSUES.md.)
fn shrike_invert(after: sc::Cid, ops: &[Op], src: &HashMap<sc::Cid, Vec<u8>>) -> Result<sc::Cid, String> {
    let mut store = src.clone();
    let mut root = after;
    for (k, new, prev) in ops.iter().rev() {
        if let (Some(_), Some(p)) = (new, prev) {
            root = set_existing(&mut store, root, k, s_cid(p))?;
            continue;
        }
        let mut t = DetachedTree::load(root);
        match prev {
            Some(p) => t.insert(&store, k.clone(), s_cid(p)).map(drop),
            None => t.remove(&store, k).map(drop),
        }
        .map_err(|e| format!("{k}: {e}"))?;
        let w = t.flush().map_err(|e| e.to_string())?;
        store.extend(w.new_blocks);
        root = w.root;
    }
    Ok(root)
}

/// Sets the value of `key` (which must exist) in the subtree at `node`,
/// re-encoding only the nodes on its path; returns the new subtree CID.
fn set_existing(
    store: &mut HashMap<sc::Cid, Vec<u8>>,
    node: sc::Cid,
    key: &str,
    val: sc::Cid,
) -> Result<sc::Cid, String> {
    use shrike::mst::node::{decode_node_data, encode_node_data};
    let block = store.get(&node).ok_or_else(|| format!("block not found: {node}"))?;
    let mut nd = decode_node_data(block).map_err(|e| e.to_string())?;
    let mut full: Vec<u8> = Vec::new();
    let mut at = Err(nd.entries.len());
    for (i, e) in nd.entries.iter().enumerate() {
        full.truncate(e.prefix_len);
        full.extend_from_slice(&e.key_suffix);
        match key.as_bytes().cmp(&full[..]) {
            std::cmp::Ordering::Equal => at = Ok(i),
            std::cmp::Ordering::Less => at = Err(i),
            std::cmp::Ordering::Greater => continue,
        }
        break;
    }
    match at {
        Ok(i) => nd.entries[i].value = val,
        Err(i) => {
            let slot = if i == 0 { &mut nd.left } else { &mut nd.entries[i - 1].right };
            let c = slot.ok_or_else(|| format!("{key} is not in the tree"))?;
            *slot = Some(set_existing(store, c, key, val)?);
        }
    }
    let bytes = encode_node_data(&nd).map_err(|e| e.to_string())?;
    let c = sc::Cid::compute(sc::Codec::Drisl, &bytes);
    store.insert(c, bytes);
    Ok(c)
}

#[test]
fn mst_vlpds_commits_invert_in_shrike() {
    // sync 1.1: with only the blocks vlpds emits for a commit, shrike undoes
    // its ops and lands on the previous root (prevData), and every node of
    // shrike's covering proof for the changed keys is among those blocks
    let mut rng = StdRng::seed_from_u64(0x1a7e);
    let mut checked = 0;
    for round in 0..30 {
        let mut t = Tree::new();
        let mut live: BTreeMap<String, Cid> = BTreeMap::new();
        for _ in 0..[0, 3, 20, 120, 400][round % 5] {
            let (k, v) = (rand_key(&mut rng), rand_cid(&mut rng));
            t.insert_no_proof(k.as_bytes(), v).unwrap();
            live.insert(k, v);
        }
        for _ in 0..6 {
            let n = rng.gen_range(1..12);
            let ops = rand_ops(&mut rng, &live, n);
            let (before, after, diff) =
                vlpds_commit(&mut t, &ops.iter().map(|(k, n, _)| (k.clone(), *n)).collect::<Vec<_>>());
            let src = s_blocks(&diff);
            let inv =
                shrike_invert(s_cid(&after), &ops, &src).unwrap_or_else(|e| panic!("round {round}: inverting: {e}"));
            assert_eq!(inv, s_cid(&before), "round {round}: inverted root");
            // shrike's covering proof of the created and deleted keys (over the
            // full tree) is among the emitted blocks; an update needs only its path
            let full = s_blocks(&all_blocks(&t));
            let mut st = DetachedTree::load(s_cid(&after));
            let structural = ops.iter().filter(|o| o.1.is_none() || o.2.is_none()).map(|o| o.0.as_str());
            let proof = st.covering_proof(&full, structural).unwrap();
            let missing: Vec<_> = proof.iter().filter(|c| !src.contains_key(c)).collect();
            assert!(missing.is_empty(), "round {round}: covering-proof nodes not emitted: {missing:?}");
            for (k, new, _) in &ops {
                match new {
                    Some(v) => live.insert(k.clone(), *v),
                    None => live.remove(k),
                };
            }
            checked += 1;
        }
    }
    assert_eq!(checked, 180);
}

#[test]
fn mst_shrike_commits_invert_in_vlpds() {
    // the other direction: shrike's covering proof for the changed keys, plus
    // the nodes it wrote, is enough for vlpds's partial-tree loader to invert
    let mut rng = StdRng::seed_from_u64(0xb1a5);
    for round in 0..30 {
        let mut s = DetachedTree::new();
        let mut store: HashMap<sc::Cid, Vec<u8>> = HashMap::new();
        let mut live: BTreeMap<String, Cid> = BTreeMap::new();
        for _ in 0..[0, 3, 20, 120, 400][round % 5] {
            let (k, v) = (rand_key(&mut rng), rand_cid(&mut rng));
            s.insert(&NoBlocks, k.clone(), s_cid(&v)).unwrap();
            live.insert(k, v);
        }
        let w = s.flush().unwrap();
        store.extend(w.new_blocks);
        for _ in 0..6 {
            let n = rng.gen_range(1..12);
            let ops = rand_ops(&mut rng, &live, n);
            let before = v_cid(&s.flush().unwrap().root);
            for (k, new, _) in &ops {
                match new {
                    Some(v) => drop(s.insert(&store, k.clone(), s_cid(v)).unwrap()),
                    None => drop(s.remove(&store, k).unwrap()),
                }
            }
            let w = s.flush().unwrap();
            let after = v_cid(&w.root);
            let mut commit_blocks: HashMap<Cid, Vec<u8>> =
                w.new_blocks.iter().map(|(c, b)| (v_cid(c), b.clone())).collect();
            store.extend(w.new_blocks);
            for c in s.covering_proof(&store, ops.iter().map(|o| o.0.as_str())).unwrap() {
                commit_blocks.insert(v_cid(&c), store[&c].clone());
            }
            let mut inv = Tree::load_from_blocks(&commit_blocks, after).unwrap();
            for (k, new, prev) in ops.iter().rev() {
                let r = match prev {
                    Some(p) => inv.insert(k.as_bytes(), *p).map(|_| ()),
                    None => inv.remove(k.as_bytes()).map(|_| ()),
                };
                r.unwrap_or_else(|e| panic!("round {round}: vlpds inverting {k} ({new:?}): {e}"));
            }
            assert_eq!(inv.root_cid().unwrap(), before, "round {round}: inverted root");
            for (k, new, _) in &ops {
                match new {
                    Some(v) => live.insert(k.clone(), *v),
                    None => live.remove(k),
                };
            }
        }
    }
}

#[test]
fn shrike_update_inversion_overfetch_pinned() {
    // SHRIKE_ISSUES.md: shrike's Tree/DetachedTree insert of an existing key
    // (how its sync verifier inverts an update) loads both neighbour subtrees
    // of the key, which an update's inversion doesn't need and which indigo
    // and vlpds don't put in the commit. With just the key's path it fails.
    let leaf = Cid::dag_cbor(b"leaf");
    let mut t = Tree::new();
    for k in keys_at_height(0, 6).iter().chain(&keys_at_height(1, 3)) {
        t.insert_no_proof(k.as_bytes(), leaf).unwrap();
    }
    let key = keys_at_height(1, 2)[1].clone();
    let before = t.root_cid().unwrap();
    let new = Cid::dag_cbor(b"new");
    let (_, after, diff) = vlpds_commit(&mut t, &[(key.clone(), Some(new))]);
    let src = s_blocks(&diff);
    let mut st = DetachedTree::load(s_cid(&after));
    let missing = st.missing_blocks(&src, [key.as_str()]).unwrap();
    assert!(!missing.is_empty(), "shrike now inverts updates from the key path alone: drop the workaround");
    assert!(st.insert(&src, key.clone(), s_cid(&leaf)).is_err());
    // the path alone suffices
    let inv = shrike_invert(s_cid(&after), &[(key, Some(new), Some(leaf))], &src).unwrap();
    assert_eq!(inv, s_cid(&before));
}

#[derive(serde::Deserialize)]
struct CommitVectors {
    leaf: String,
    #[serde(rename = "coveringProofs")]
    covering_proofs: Vec<CoveringCase>,
    commits: Vec<CommitCase>,
}

#[derive(serde::Deserialize)]
struct CoveringCase {
    name: String,
    keys: Vec<String>,
    root: String,
}

#[derive(serde::Deserialize)]
struct CommitCase {
    name: String,
    car: String,
    #[serde(rename = "dataBefore")]
    data_before: String,
    writes: Vec<CommitWrite>,
    expect: J,
}

#[derive(serde::Deserialize)]
struct CommitWrite {
    action: String,
    key: String,
    v: Option<u64>,
}

#[test]
fn mst_reference_commit_vectors() {
    // @atproto/repo vectors (via shrike): each repo CAR read by both readers,
    // the writes applied by both trees -> the reference's dataAfter, and
    // vlpds's emitted blocks hold the reference's relevant (proof) MST nodes
    let v: CommitVectors = serde_json::from_str(&shrike_fixture("commit_vectors.json")).unwrap();
    let leaf = Cid::parse(&v.leaf).unwrap();
    for c in &v.covering_proofs {
        let mut t = Tree::new();
        let mut s = DetachedTree::new();
        for k in &c.keys {
            t.insert_no_proof(k.as_bytes(), leaf).unwrap();
            s.insert(&NoBlocks, k.clone(), s_cid(&leaf)).unwrap();
        }
        assert_eq!(t.root_cid().unwrap().to_string(), c.root, "{}", c.name);
        assert_eq!(s.flush().unwrap().root.to_string(), c.root, "{}", c.name);
    }
    let mut n = 0;
    for c in &v.commits {
        let car = b64_decode(&c.car);
        let (roots, blocks) = car_compare(&car).unwrap().unwrap();
        let blocks: HashMap<Cid, Vec<u8>> = blocks.into_iter().collect();
        let commit = Value::decode(&blocks[&roots[0]]).unwrap();
        let Some(Value::Link(data)) = commit.get("data") else { panic!() };
        assert_eq!(data.to_string(), c.data_before, "{}", c.name);
        let mut t = Tree::load_from_blocks(&blocks, *data).unwrap();
        let mut s = DetachedTree::load(s_cid(data));
        let src = s_blocks(&blocks);
        let mut ok = true;
        let mut ops: Vec<Op> = Vec::new();
        for w in &c.writes {
            let rec = |v: u64| {
                let (coll, rkey) = w.key.split_once('/').unwrap();
                Cid::dag_cbor(&Value::from_json(&json!({"$type": coll, "rkey": rkey, "v": v})).unwrap().to_cbor())
            };
            let existing = t.get(w.key.as_bytes()).unwrap();
            ok &= match (w.action.as_str(), existing) {
                ("create", None) | ("update", Some(_)) => {
                    t.insert(w.key.as_bytes(), rec(w.v.unwrap())).unwrap();
                    s.insert(&src, w.key.clone(), s_cid(&rec(w.v.unwrap()))).unwrap();
                    ops.push((w.key.clone(), Some(rec(w.v.unwrap())), existing));
                    true
                }
                ("delete", Some(_)) => {
                    t.remove(w.key.as_bytes()).unwrap();
                    s.remove(&src, &w.key).unwrap();
                    ops.push((w.key.clone(), None, existing));
                    true
                }
                _ => false,
            };
        }
        if c.expect == "error" {
            assert!(!ok, "{}: reference rejects the batch", c.name);
            continue;
        }
        assert!(ok, "{}", c.name);
        let mut diff = Vec::new();
        let after = t.write_diff_blocks(&mut diff).unwrap();
        assert_eq!(after.to_string(), c.expect["dataAfter"], "{}: vlpds dataAfter", c.name);
        assert_eq!(s.flush().unwrap().root.to_string(), c.expect["dataAfter"], "{}: shrike dataAfter", c.name);
        // vlpds's emitted blocks invert the commit (shrike-side inverter)
        let emitted: HashMap<Cid, Vec<u8>> = diff.iter().cloned().collect();
        let inv = shrike_invert(s_cid(&after), &ops, &s_blocks(&emitted)).unwrap_or_else(|e| panic!("{}: {e}", c.name));
        assert_eq!(inv.to_string(), c.data_before, "{}: inverted", c.name);
        // and hold the reference's covering proof, except the neighbour
        // subtrees it adds for updates (an update's inversion needs only its path)
        if ops.iter().any(|o| o.1.is_some() && o.2.is_some()) {
            n += 1;
            continue;
        }
        let have: BTreeSet<String> = diff.iter().map(|(c, _)| c.to_string()).collect();
        let records: BTreeSet<String> =
            c.expect["ops"].as_array().unwrap().iter().filter_map(|o| o["cid"].as_str().map(String::from)).collect();
        let missing: Vec<&str> = c.expect["relevantBlocks"]
            .as_array()
            .unwrap()
            .iter()
            .map(|b| b.as_str().unwrap())
            .filter(|b| !records.contains(*b) && !have.contains(*b))
            .collect();
        assert!(missing.is_empty(), "{}: relevant MST nodes vlpds doesn't emit: {missing:?}", c.name);
        n += 1;
    }
    assert!(n >= 10, "{n}");
}

// record proofs

fn did_and_key(rng: &mut impl Rng) -> (String, crypto::Keypair) {
    let _ = rng;
    (crypto::random_plc_did(), crypto::Keypair::generate())
}

fn signed_commit(did: &str, rev: &str, data: &Cid, kp: &crypto::Keypair) -> Vec<u8> {
    let sig = kp.sign(&vlsync_atproto::events::encode_commit(did, rev, data, None));
    vlsync_atproto::events::encode_commit(did, rev, data, Some(&sig))
}

#[test]
fn record_proofs_vlpds_to_shrike() {
    // vlpds's getRecord-style proofs (commit + root-to-key path + record)
    // verify in shrike, for present and absent keys
    let mut rng = StdRng::seed_from_u64(0x9f00f);
    for n in [0usize, 1, 7, 60, 500] {
        let (did, kp) = did_and_key(&mut rng);
        let mut t = Tree::new();
        let mut recs: HashMap<String, Vec<u8>> = HashMap::new();
        for i in 0..n {
            let k = format!("app.bsky.feed.post/{}", tid::Tid((1 << 60) + i as u64 * 9973));
            let rec = Value::from_json(
                &json!({"$type": "app.bsky.feed.post", "text": k, "createdAt": "2026-01-01T00:00:00Z"}),
            )
            .unwrap()
            .to_cbor();
            t.insert_no_proof(k.as_bytes(), Cid::dag_cbor(&rec)).unwrap();
            recs.insert(k, rec);
        }
        let data = t.root_cid().unwrap();
        let commit = signed_commit(&did, "3jzfcijpj2z2a", &data, &kp);
        let vk = shrike::crypto::parse_did_key(&kp.did_key()).unwrap();
        let sdid = shrike::syntax::Did::try_from(did.as_str()).unwrap();
        let mut probes: Vec<String> = recs.keys().take(25).cloned().collect();
        probes.extend((0..10).map(|_| format!("app.bsky.feed.post/{}", tid::Tid(rng.gen::<u64>() >> 1))));
        for k in probes {
            let mut car = Vec::new();
            let cc = Cid::dag_cbor(&commit);
            car::write_header(&mut car, &cc);
            car::write_block(&mut car, &cc, &commit);
            for (c, b) in t.proof_blocks(k.as_bytes()).unwrap() {
                car::write_block(&mut car, &c, &b);
            }
            if let Some(r) = recs.get(&k) {
                car::write_block(&mut car, &Cid::dag_cbor(r), r);
            }
            let (coll, rkey) = k.split_once('/').unwrap();
            let p = shrike::repo::verify_record_proof(
                &car,
                &sdid,
                vk.as_ref(),
                &shrike::syntax::Nsid::try_from(coll).unwrap(),
                &shrike::syntax::RecordKey::try_from(rkey).unwrap(),
            )
            .unwrap_or_else(|e| panic!("n={n} {k}: {e}"));
            assert_eq!(p.record.map(|r| r.1), recs.get(&k).cloned(), "n={n} {k}");
            assert_eq!(p.commit_cid, s_cid(&cc));
        }
    }
}

#[test]
fn record_proofs_reference_and_shrike_to_vlpds() {
    // @atproto/repo record proofs (P-256 and K-256 keys, wrong key / DID
    // variants): vlpds's verifier (lexicon resolution) and shrike agree
    // with the reference's verdicts
    let ts: J = serde_json::from_str(&shrike_fixture("ts_vectors.json")).unwrap();
    let coll = ts["collection"].as_str().unwrap();
    let mut d = Diffs::new("reference record proofs");
    let mut n = 0;
    for c in ts["cases"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        let car = b64_decode(c["proof"].as_str().unwrap());
        let (did, key, rkey) =
            (c["did"].as_str().unwrap(), c["signingKey"].as_str().unwrap(), c["rkey"].as_str().unwrap());
        // expect: "error" (bad proof), null (proves absence) or the record CID
        let want = match &c["expect"] {
            J::Null => Ok(None),
            J::String(e) if e == "error" => Err(()),
            J::String(cid) => Ok(Some(cid.clone())),
            e => panic!("{e}"),
        };
        // vlpds's verifier (lexicon resolution) reports absence as an error
        let v = match vlpds::oauth::lexicon::verify_record_proof(
            &car,
            did,
            key.strip_prefix("did:key:").unwrap(),
            &format!("{coll}/{rkey}"),
        ) {
            Ok(rec) => Ok(Some(Cid::dag_cbor(&Value::from_json(&rec).unwrap().to_cbor()).to_string())),
            Err(e) if e == "Record not found in proof" => Ok(None),
            Err(_) => Err(()),
        };
        let s = shrike::repo::verify_record_proof(
            &car,
            &shrike::syntax::Did::try_from(did).unwrap(),
            shrike::crypto::parse_did_key(key).unwrap().as_ref(),
            &shrike::syntax::Nsid::try_from(coll).unwrap(),
            &shrike::syntax::RecordKey::try_from(rkey).unwrap(),
        );
        let s = s.map(|p| p.record.map(|r| r.0.to_string())).map_err(|_| ());
        if v != want || s != want {
            d.push(format!("{name}: reference {want:?}, vlpds {v:?}, shrike {s:?}"));
        }
        n += 1;
    }
    d.assert_none();
    assert!(n >= 30);

    // shrike-built repos: its proofs verify in vlpds
    let mut rng = StdRng::seed_from_u64(0x5e1f);
    let sk = shrike::crypto::K256SigningKey::generate();
    let did = shrike::syntax::Did::try_from("did:plc:shrikeshrikeshrikeshrik").unwrap();
    let mut repo = shrike::repo::Repo::new(did.clone(), shrike::syntax::TidClock::new(1).unwrap());
    let nsid = shrike::syntax::Nsid::try_from(coll).unwrap();
    let mut keys = Vec::new();
    for i in 0..150 {
        let rkey = format!("com.example.n{i:04}x{}", rng.gen_range(0..1000));
        let rec = json_to_drisl(&json!({"$type": coll, "lexicon": 1, "id": rkey, "defs": {}}), Integers::Safe).unwrap();
        let rk = shrike::syntax::RecordKey::try_from(rkey.as_str()).unwrap();
        repo.create(&nsid, &rk, &rec).unwrap();
        keys.push(rk);
    }
    repo.commit(&sk).unwrap();
    let mb = sk.public_key().multibase();
    for rk in keys.iter().step_by(7) {
        let car = repo.record_proof(&nsid, rk).unwrap();
        let rec =
            vlpds::oauth::lexicon::verify_record_proof(&car, did.as_str(), &mb, &format!("{coll}/{}", rk.as_str()))
                .unwrap_or_else(|e| panic!("{}: {e}", rk.as_str()));
        assert_eq!(rec["id"], rk.as_str());
        // wrong key / wrong DID fail
        let other = shrike::crypto::K256SigningKey::generate().public_key().multibase();
        assert!(vlpds::oauth::lexicon::verify_record_proof(
            &car,
            did.as_str(),
            &other,
            &format!("{coll}/{}", rk.as_str())
        )
        .is_err());
        assert!(vlpds::oauth::lexicon::verify_record_proof(
            &car,
            "did:plc:other",
            &mb,
            &format!("{coll}/{}", rk.as_str())
        )
        .is_err());
    }
}

// adversarial nodes

fn raw_node(l: Option<Cid>, es: &[(&[u8], u64, Option<Cid>)], extra: Option<(&str, Value)>, drop_l: bool) -> Vec<u8> {
    let leaf = Cid::dag_cbor(b"leaf");
    let entries = es
        .iter()
        .map(|(k, p, t)| {
            Value::Map(vec![
                ("k".into(), Value::Bytes(k.to_vec())),
                ("p".into(), Value::Int(*p as i64)),
                ("t".into(), t.map(Value::Link).unwrap_or(Value::Null)),
                ("v".into(), Value::Link(leaf)),
            ])
        })
        .collect();
    let mut m = vec![("e".to_string(), Value::Array(entries))];
    if !drop_l {
        m.push(("l".into(), l.map(Value::Link).unwrap_or(Value::Null)));
    }
    if let Some((k, v)) = extra {
        m.push((k.into(), v));
    }
    m.sort_by(|a, b| vlsync_atproto::cbor::key_cmp(&a.0, &b.0));
    Value::Map(m).to_cbor()
}

/// Loads `root` from `blocks` and walks everything reachable, in both.
fn load_both(blocks: &HashMap<Cid, Vec<u8>>, root: Cid) -> (Result<usize, String>, Result<usize, String>) {
    let v = Tree::load_from_blocks(blocks, root).map_err(|e| e.to_string()).map(|t| {
        let mut n = 0;
        t.walk(&mut |_, _| n += 1);
        n
    });
    let mut st = DetachedTree::load(s_cid(&root));
    let mut n = 0;
    let s = st.walk_reachable(&s_blocks(blocks), |_, _| {
        n += 1;
        Ok(())
    });
    (v, s.map(|()| n).map_err(|e| e.to_string()))
}

fn keys_at_height(h: i32, n: usize) -> Vec<String> {
    (0..).map(|i| format!("com.example.k/{i:06}")).filter(|k| height_for_key(k.as_bytes()) == h).take(n).collect()
}

#[test]
fn mst_adversarial_nodes() {
    let h0 = keys_at_height(0, 4);
    let h1 = keys_at_height(1, 3);
    let add = |m: &mut HashMap<Cid, Vec<u8>>, b: Vec<u8>| {
        let c = Cid::dag_cbor(&b);
        m.insert(c, b);
        c
    };
    // (name, block builder) -> both verdicts; `vlpds_only` marks the checks
    // vlpds makes and shrike's (like indigo's) loader doesn't
    struct Case {
        name: &'static str,
        blocks: HashMap<Cid, Vec<u8>>,
        root: Cid,
        vlpds_only: bool,
    }
    let mut cases = Vec::new();
    let mut mk = |name, vlpds_only, f: &dyn Fn(&mut HashMap<Cid, Vec<u8>>) -> Cid| {
        let mut b = HashMap::new();
        let root = f(&mut b);
        cases.push(Case { name, blocks: b, root, vlpds_only });
    };
    let k = |i: usize| h0[i].as_bytes();
    let p = |a: &[u8], b: &[u8]| a.iter().zip(b).take_while(|(x, y)| x == y).count() as u64;
    // well-formed: both accept
    mk("valid leaf", false, &|b| {
        add(b, raw_node(None, &[(k(0), 0, None), (&k(1)[p(k(0), k(1)) as usize..], p(k(0), k(1)), None)], None, false))
    });
    // both reject
    mk("prefix longer than previous key", false, &|b| {
        add(b, raw_node(None, &[(k(0), 0, None), (&b"x"[..], 40, None)], None, false))
    });
    mk("first entry with a prefix", false, &|b| add(b, raw_node(None, &[(k(0), 3, None)], None, false)));
    mk("keys out of order", false, &|b| add(b, raw_node(None, &[(k(1), 0, None), (k(0), 0, None)], None, false)));
    mk("duplicate keys", false, &|b| add(b, raw_node(None, &[(k(0), 0, None), (k(0), 0, None)], None, false)));
    mk("not a map", false, &|b| add(b, Value::Array(vec![]).to_cbor()));
    mk("e not an array", false, &|b| {
        add(b, Value::Map(vec![("e".into(), Value::Int(1)), ("l".into(), Value::Null)]).to_cbor())
    });
    mk("l not a link", false, &|b| {
        add(b, Value::Map(vec![("e".into(), Value::Array(vec![])), ("l".into(), Value::Int(1))]).to_cbor())
    });
    // vlpds-only checks (canonical structure)
    mk("non-canonical prefix (0 instead of shared)", true, &|b| {
        add(b, raw_node(None, &[(k(0), 0, None), (k(1), 0, None)], None, false))
    });
    mk("keys of different heights in one node", true, &|b| {
        let (a, c) = if h1[0] < h0[0] { (h1[0].as_bytes(), k(0)) } else { (k(0), h1[0].as_bytes()) };
        let pl = p(a, c);
        add(b, raw_node(None, &[(a, 0, None), (&c[pl as usize..], pl, None)], None, false))
    });
    mk("missing l", true, &|b| add(b, raw_node(None, &[(k(0), 0, None)], None, true)));
    mk("extra field", false, &|b| add(b, raw_node(None, &[(k(0), 0, None)], Some(("x", Value::Null)), false)));
    mk("empty key", true, &|b| add(b, raw_node(None, &[(&b""[..], 0, None)], None, false)));
    mk("key over 1024 bytes", true, &|b| add(b, raw_node(None, &[(&[b'a'; 1025][..], 0, None)], None, false)));
    mk("child under a height-0 node", true, &|b| {
        let c = add(b, raw_node(None, &[(k(2), 0, None)], None, false));
        add(b, raw_node(None, &[(k(0), 0, Some(c))], None, false))
    });
    mk("child two levels down", true, &|b| {
        let c = add(b, raw_node(None, &[(k(0), 0, None)], None, false));
        let h2 = keys_at_height(2, 1);
        add(b, raw_node(Some(c), &[(h2[0].as_bytes(), 0, None)], None, false))
    });
    mk("empty intermediate node", true, &|b| {
        let c = add(b, raw_node(None, &[], None, false));
        add(b, raw_node(Some(c), &[(h1[0].as_bytes(), 0, None)], None, false))
    });
    mk("chain of 80 key-less nodes", true, &|b| {
        let mut c = add(b, raw_node(None, &[(k(0), 0, None)], None, false));
        for _ in 0..80 {
            c = add(b, raw_node(Some(c), &[], None, false));
        }
        c
    });
    // keys are bytes in vlpds (as in indigo: 1-1024 bytes); shrike also requires UTF-8
    let non_utf8 = {
        let mut b = HashMap::new();
        let root = add(&mut b, raw_node(None, &[(&[0xff, 0xfe][..], 0, None)], None, false));
        load_both(&b, root)
    };
    assert!(non_utf8.0.is_ok() && non_utf8.1.is_err(), "{non_utf8:?}");
    let mut d = Diffs::new("adversarial MST nodes");
    for c in &cases {
        let (v, s) = load_both(&c.blocks, c.root);
        let want = if c.name == "valid leaf" {
            (true, true)
        } else if c.vlpds_only {
            (false, true)
        } else {
            (false, false)
        };
        if (v.is_ok(), s.is_ok()) != want {
            d.push(format!("{}: vlpds {v:?}, shrike {s:?} (expected ok = {want:?})", c.name));
        }
    }
    d.assert_none();
}

#[test]
fn mst_mutated_nodes() {
    // byte mutations of real nodes: when both load, they read the same entries;
    // when only shrike loads, vlpds's reason is a structural (canonical form) check
    let mut rng = StdRng::seed_from_u64(0xbad_0de);
    let mut t = Tree::new();
    for _ in 0..300 {
        t.insert_no_proof(rand_key(&mut rng).as_bytes(), rand_cid(&mut rng)).unwrap();
    }
    let root = t.root_cid().unwrap();
    let blocks = all_blocks(&t);
    let cids: Vec<Cid> = blocks.keys().copied().collect();
    let mut d = Diffs::new("mutated MST nodes");
    let mut tally: BTreeMap<String, usize> = BTreeMap::new();
    for _ in 0..1500 {
        let c = cids[rng.gen_range(0..cids.len())];
        let m = mutate(&mut rng, &blocks[&c]);
        let shrike_node = shrike::mst::node::decode_node_data(&m);
        let vlpds_node = vlsync_atproto::mst::decode_node(&m, Cid::dag_cbor(&m));
        let key = match (&vlpds_node, &shrike_node) {
            (Ok(_), Ok(_)) => "both decode".to_string(),
            (Err(_), Err(_)) => "both reject".to_string(),
            (Ok(_), Err(e)) => {
                d.push(format!("vlpds decodes, shrike rejects ({e}): {}", hex::encode(&m)));
                continue;
            }
            (Err(e), Ok(_)) => format!("vlpds only rejects: {e}"),
        };
        *tally.entry(key).or_default() += 1;
        if let (Ok(vn), Ok(sn)) = (&vlpds_node, &shrike_node) {
            // same keys and values in the same order
            let mut vk = Vec::new();
            for e in &vn.entries {
                if let vlsync_atproto::mst::Entry::Value { key, val } = e {
                    vk.push((key.to_vec(), *val));
                }
            }
            let mut prev: Vec<u8> = Vec::new();
            let sk: Vec<(Vec<u8>, Cid)> = sn
                .entries
                .iter()
                .map(|e| {
                    prev.truncate(e.prefix_len);
                    prev.extend_from_slice(&e.key_suffix);
                    (prev.clone(), v_cid(&e.value))
                })
                .collect();
            if vk != sk {
                d.push(format!("decoded differently: {}", hex::encode(&m)));
            }
        }
    }
    let _ = root;
    d.assert_none();
    // vlpds-only rejections are all canonical-structure checks (DAG-CBOR is shared)
    for k in tally.keys() {
        if let Some(r) = k.strip_prefix("vlpds only rejects: ") {
            assert!(
                ["invalid MST structure", "invalid MST key"].iter().any(|p| r.starts_with(p))
                    && !r.contains("bad node cbor"),
                "{k}"
            );
        }
    }
    eprintln!("mutated nodes: {tally:?}");
}

// ---------------------------------------------------------------------------
// signatures and did:keys
// ---------------------------------------------------------------------------

#[test]
fn k256_signatures_and_did_keys() {
    let mut rng = StdRng::seed_from_u64(0x5167);
    for i in 0..48 {
        let kp = crypto::Keypair::generate();
        let sk =
            shrike::crypto::K256SigningKey::from_bytes(&<[u8; 32]>::try_from(&kp.to_bytes()[..]).unwrap()).unwrap();
        // did:key / multibase / SEC1 identical; each side parses the other's
        assert_eq!(sk.public_key().did_key(), kp.did_key());
        assert_eq!(sk.public_key().multibase(), kp.public_multibase());
        assert_eq!(sk.public_key().to_bytes(), kp.public_key_sec1());
        let vk = shrike::crypto::parse_did_key(&kp.did_key()).unwrap();
        for j in 0..8 {
            let msg: Vec<u8> = (0..rng.gen_range(0..300)).map(|_| rng.gen()).collect();
            let a = kp.sign_deterministic(&msg);
            let b = sk.sign(&msg).unwrap();
            // RFC 6979 + low-S on both sides: byte-identical
            assert_eq!(&a, b.as_bytes(), "key {i} msg {j}");
            // what a node emits (hedged nonce) verifies on the other side
            let h = kp.sign_verified(crypto::Purpose::Commit, &msg).unwrap();
            vk.verify(&msg, &shrike::crypto::Signature::from_bytes(h)).unwrap();
            vk.verify(&msg, &shrike::crypto::Signature::from_bytes(a)).unwrap();
            assert!(crypto::verify_k256(&kp.public_key_sec1(), &msg, b.as_bytes()).unwrap());
            // a flipped bit fails in both
            let mut bad = a;
            bad[rng.gen_range(0..64)] ^= 1 << rng.gen_range(0..8);
            let sv = vk.verify(&msg, &shrike::crypto::Signature::from_bytes(bad)).is_ok();
            let vv = crypto::verify_k256(&kp.public_key_sec1(), &msg, &bad).unwrap_or(false);
            assert!(!sv && !vv, "key {i} msg {j}: corrupted signature accepted (shrike {sv}, vlpds {vv})");
            // high-S form of a valid signature: both reject
            let hs = k256::ecdsa::Signature::from_slice(&a).unwrap();
            let high = k256::ecdsa::Signature::from_scalars(hs.r(), -*hs.s()).unwrap();
            let high: [u8; 64] = high.to_bytes().into();
            assert!(vk.verify(&msg, &shrike::crypto::Signature::from_bytes(high)).is_err());
            assert!(!crypto::verify_k256(&kp.public_key_sec1(), &msg, &high).unwrap());
            // ...though shrike's malleable mode (service-auth JWTs) takes it
            assert!(vk.verify_malleable(&msg, &shrike::crypto::Signature::from_bytes(high)).is_ok());
        }
    }
}

#[test]
fn signature_fixtures_both_sides() {
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct F {
        comment: String,
        message_base64: String,
        algorithm: String,
        public_key_did: String,
        signature_base64: String,
        valid_signature: bool,
    }
    let fs: Vec<F> = serde_json::from_str(&read_fixture("interop/crypto/signature-fixtures.json")).unwrap();
    for f in fs {
        let (msg, sig) = (b64_decode(&f.message_base64), b64_decode(&f.signature_base64));
        let vk = shrike::crypto::parse_did_key(&f.public_key_did).unwrap();
        let s = <[u8; 64]>::try_from(sig.as_slice())
            .is_ok_and(|a| vk.verify(&msg, &shrike::crypto::Signature::from_bytes(a)).is_ok());
        assert_eq!(s, f.valid_signature, "shrike: {}", f.comment);
        if f.algorithm == "ES256K" {
            let v = crypto::verify_k256(&vk.to_bytes(), &msg, &sig).unwrap_or(false);
            assert_eq!(v, f.valid_signature, "vlpds: {}", f.comment);
        }
    }
    // did:key fixtures: shrike parses each to the fixture key's public point
    for (file, k256) in [("w3c_didkey_K256.json", true), ("w3c_didkey_P256.json", false)] {
        let cases: J = serde_json::from_str(&read_fixture(&format!("interop/crypto/{file}"))).unwrap();
        for c in cases.as_array().unwrap() {
            let did = c["publicDidKey"].as_str().unwrap();
            let vk = shrike::crypto::parse_did_key(did).unwrap();
            assert_eq!(vk.did_key(), did);
            assert_eq!(vk.jwt_alg(), if k256 { "ES256K" } else { "ES256" });
            if k256 {
                let kp = crypto::Keypair::from_bytes(&hex::decode(c["privateKeyBytesHex"].as_str().unwrap()).unwrap())
                    .unwrap();
                assert_eq!(kp.public_key_sec1(), vk.to_bytes());
            }
        }
    }
}

// ---------------------------------------------------------------------------
// lexicons
// ---------------------------------------------------------------------------

fn bundle() -> HashMap<String, J> {
    serde_json::from_str(
        &std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/lexicons/bundle.json")).unwrap(),
    )
    .unwrap()
}

fn shrike_catalog(docs: impl IntoIterator<Item = J>) -> (shrike::lexicon::Catalog, Vec<String>) {
    let mut cat = shrike::lexicon::Catalog::new();
    let mut failed = Vec::new();
    for d in docs {
        if let Err(e) = cat.add_schema(d.to_string().as_bytes()) {
            failed.push(format!("{}: {e}", d["id"]));
        }
    }
    (cat, failed)
}

#[test]
fn lexicon_interop_record_data() {
    // atproto lexicon interop (via shrike): example.lexicon.record, valid and invalid
    let doc: J = serde_json::from_str(&shrike_fixture("lexicon_catalog_record.json")).unwrap();
    let nsid = doc["id"].as_str().unwrap().to_string();
    let resolved = vlpds::lexicon::Lexicons::resolved(&doc);
    let b = bundle();
    let (cat, failed) = shrike_catalog([doc.clone(), b["com.atproto.label.defs"].clone()]);
    assert!(failed.is_empty(), "{failed:?}");
    let mut d = Diffs::new("lexicon interop record data");
    for (f, want) in [("valid", true), ("invalid", false)] {
        let cases: J = serde_json::from_str(&shrike_fixture(&format!("lexicon_record_data_{f}.json"))).unwrap();
        for c in cases.as_array().unwrap() {
            let data = &c["data"];
            let v = lexicon::validate_record(&nsid, c["rkey"].as_str().unwrap(), data, Some(true), Some(&resolved));
            let s = shrike::lexicon::validate_record(&cat, &nsid, data);
            if v.is_ok() != want || s.is_ok() != want {
                d.push(format!("{} ({f}): vlpds {v:?}, shrike {:?}", c["name"], s.err().map(|e| e.to_string())));
            }
        }
    }
    d.assert_none();
}

/// Plausible records for bundled collections, then mutated.
fn rand_record(rng: &mut impl Rng) -> (String, J) {
    let cid = Cid::dag_cbor(&rng.gen::<[u8; 4]>()).to_string();
    let uri = format!("at://did:plc:{}/app.bsky.feed.post/{}", "a".repeat(24), tid::Tid(rng.gen::<u64>() >> 1));
    let sref = json!({"uri": uri, "cid": cid});
    let now = "2026-01-02T03:04:05.678Z";
    let blob = json!({"$type": "blob", "ref": {"$link": Cid::raw(b"img").to_string()}, "mimeType": "image/jpeg", "size": 12345});
    let (coll, rec) = match rng.gen_range(0..10) {
        0 => (
            "app.bsky.feed.post",
            json!({"text": "hello 😀", "createdAt": now, "langs": ["en"],
            "reply": {"root": sref, "parent": sref},
            "facets": [{"index": {"byteStart": 0, "byteEnd": 5}, "features": [{"$type": "app.bsky.richtext.facet#link", "uri": "https://example.com"}]}],
            "embed": {"$type": "app.bsky.embed.images", "images": [{"image": blob, "alt": "a"}]}}),
        ),
        1 => ("app.bsky.feed.like", json!({"subject": sref, "createdAt": now})),
        2 => ("app.bsky.feed.repost", json!({"subject": sref, "createdAt": now})),
        3 => ("app.bsky.graph.follow", json!({"subject": "did:plc:abcdefghijklmnopqrstuvwx", "createdAt": now})),
        4 => ("app.bsky.graph.block", json!({"subject": "did:plc:abcdefghijklmnopqrstuvwx", "createdAt": now})),
        5 => (
            "app.bsky.actor.profile",
            json!({"displayName": "Alice", "description": "hi", "avatar": blob, "createdAt": now}),
        ),
        6 => (
            "app.bsky.graph.list",
            json!({"name": "list", "purpose": "app.bsky.graph.defs#curatelist", "createdAt": now}),
        ),
        7 => (
            "app.bsky.graph.listitem",
            json!({"subject": "did:plc:abcdefghijklmnopqrstuvwx", "list": uri.replace("feed.post", "graph.list"), "createdAt": now}),
        ),
        8 => (
            "app.bsky.feed.threadgate",
            json!({"post": uri, "allow": [{"$type": "app.bsky.feed.threadgate#mentionRule"}], "createdAt": now}),
        ),
        _ => (
            "app.bsky.feed.generator",
            json!({"did": "did:web:feeds.example.com", "displayName": "feed", "createdAt": now}),
        ),
    };
    let mut rec = rec;
    rec["$type"] = json!(coll);
    (coll.to_string(), rec)
}

const BAD_VALUES: &[&str] = &[
    "null", "1", "-1", "true", "\"\"", "\"x\"", "[]", "{}", "\"not a date\"", "\"1985-04-12T23:20:50.123Z\"",
    "\"did:plc:abc\"", "\"at://did:plc:abc/app.bsky.feed.post/3jzfcijpj2z2a\"", "\"https://x.com\"", "\"en\"",
    "\"bafyreie5737gdxlw5i64vzichcalba3z2v5n6icifvx5xytvske7mr3hpm\"", "{\"$type\": \"app.bsky.embed.images\"}",
    "{\"$type\": \"app.bsky.embed.external\", \"external\": {\"uri\": \"https://x.com\", \"title\": \"\", \"description\": \"\"}}",
    "{\"$type\": \"com.example.unknown\"}", "{\"$link\": \"bafyreie5737gdxlw5i64vzichcalba3z2v5n6icifvx5xytvske7mr3hpm\"}",
    "{\"$bytes\": \"AQID\"}", "4000000", "\"app.bsky.graph.defs#modlist\"",
];

fn mutate_json(rng: &mut impl Rng, j: &mut J, depth: usize) {
    match j {
        J::Object(o) if !o.is_empty() => {
            let keys: Vec<String> = o.keys().cloned().collect();
            let k = &keys[rng.gen_range(0..keys.len())];
            match rng.gen_range(0..5) {
                0 if k != "$type" => {
                    o.remove(k);
                }
                1 | 2 if depth < 4 => mutate_json(rng, o.get_mut(k).unwrap(), depth + 1),
                3 => {
                    o.insert(k.clone(), json!("x".repeat([1, 64, 300, 301, 640, 2000, 3001][rng.gen_range(0..7)])));
                }
                _ => {
                    o.insert(k.clone(), serde_json::from_str(BAD_VALUES[rng.gen_range(0..BAD_VALUES.len())]).unwrap());
                }
            }
        }
        J::Array(a) if !a.is_empty() && depth < 4 => {
            let i = rng.gen_range(0..a.len());
            if rng.gen_bool(0.3) {
                a.push(a[i].clone());
            } else {
                mutate_json(rng, &mut a[i], depth + 1);
            }
        }
        _ => *j = serde_json::from_str(BAD_VALUES[rng.gen_range(0..BAD_VALUES.len())]).unwrap(),
    }
}

/// vlpds vs shrike verdict on one record of a bundled collection. vlpds's
/// write path checks the data model (blob shape, `$link`s) while encoding the
/// record and the schema with `validate_record`; shrike's validator does both.
fn lexicon_compare(cat: &shrike::lexicon::Catalog, coll: &str, rkey: &str, rec: &J) -> Option<String> {
    let v = Value::from_json(rec)
        .map_err(|e| e.to_string())
        .and_then(|_| lexicon::validate_record(coll, rkey, rec, Some(true), None));
    let s = shrike::lexicon::validate_record(cat, coll, rec);
    (v.is_ok() != s.is_ok()).then(|| {
        format!("{coll} {}: vlpds {v:?}, shrike {:?}", short(&rec.to_string()), s.err().map(|e| e.to_string()))
    })
}

#[test]
fn lexicon_bundled_records() {
    let (cat, failed) = shrike_catalog(bundle().into_values());
    assert!(failed.is_empty(), "shrike rejects bundled lexicons: {failed:?}");
    let mut rng = StdRng::seed_from_u64(0x1e8);
    let mut d = Diffs::new("lexicon verdicts");
    let (mut ok, mut bad) = (0, 0);
    for i in 0..3000 {
        let (coll, mut rec) = rand_record(&mut rng);
        if i % 4 != 0 {
            for _ in 0..rng.gen_range(1..3) {
                mutate_json(&mut rng, &mut rec, 0);
            }
            rec["$type"] = json!(coll);
        }
        let rkey = tid::Tid((1 << 60) + i).to_string();
        let rkey = if coll == "app.bsky.actor.profile" { "self".to_string() } else { rkey };
        match lexicon_compare(&cat, &coll, &rkey, &rec) {
            Some(e) => d.push(e),
            None if Value::from_json(&rec).is_ok()
                && lexicon::validate_record(&coll, &rkey, &rec, Some(true), None).is_ok() =>
            {
                ok += 1
            }
            None => bad += 1,
        }
    }
    d.assert_none();
    assert!(ok > 500 && bad > 500, "{ok} valid / {bad} invalid");
}

// ---------------------------------------------------------------------------
// real records (opt-in)
// ---------------------------------------------------------------------------

/// Gives every strongRef-shaped `{uri: at://...}` without a `cid` a random one
/// (the ClickHouse crawl stripped them).
fn inject_cids(j: &mut J, rng: &mut impl Rng) {
    match j {
        J::Object(o) => {
            if o.get("uri").and_then(|u| u.as_str()).is_some_and(|u| u.starts_with("at://")) && !o.contains_key("cid") {
                o.insert("cid".into(), json!(rand_cid(rng).to_string()));
            }
            o.values_mut().for_each(|v| inject_cids(v, rng));
        }
        J::Array(a) => a.iter_mut().for_each(|v| inject_cids(v, rng)),
        _ => {}
    }
}

/// `VLPDS_REAL_RECORDS=records.tsv cargo test --test all -- --ignored real_records_from_clickhouse`,
/// with rows `repo \t collection \t rkey \t record_json` (ClickHouse TSV).
#[test]
#[ignore]
fn real_records_from_clickhouse() {
    let path = std::env::var("VLPDS_REAL_RECORDS").expect("VLPDS_REAL_RECORDS=<tsv>");
    let (cat, _) = shrike_catalog(bundle().into_values());
    let mut rng = StdRng::seed_from_u64(1);
    let mut d = Diffs::new("real records");
    let mut tally: BTreeMap<&str, usize> = BTreeMap::new();
    for line in std::fs::read_to_string(path).unwrap().lines() {
        let cols: Vec<&str> = line.splitn(4, '\t').collect();
        let [_, coll, rkey, json] = cols[..] else { continue };
        let unescaped = json
            .replace("\\\\", "\u{0}")
            .replace("\\t", "\t")
            .replace("\\n", "\n")
            .replace("\\'", "'")
            .replace('\u{0}', "\\");
        let Ok(mut j) = serde_json::from_str::<J>(&unescaped) else {
            *tally.entry("unparseable").or_default() += 1;
            continue;
        };
        inject_cids(&mut j, &mut rng);
        let text = j.to_string();
        match json_compare(&text) {
            JsonOutcome::Agree => *tally.entry("cbor agree").or_default() += 1,
            JsonOutcome::StrictVlpdsOnly => {
                let n = tally.entry("cbor strict-only").or_default();
                *n += 1;
                if *n <= 10 {
                    eprintln!("strict-only {coll}/{rkey}: {:?}", Value::from_json(&j).err());
                }
            }
            JsonOutcome::PartialPaddingShrikeMap => *tally.entry("cbor partial-padding").or_default() += 1,
            JsonOutcome::Disagree(e) => d.push(format!("{coll}/{rkey}: {e}")),
        }
        if let Ok(b) = Value::from_json(&j).map(|v| v.to_cbor()) {
            if cbor_compare(&b) != Cbor::Agree {
                d.push(format!("{coll}/{rkey}: decode {:?}", cbor_compare(&b)));
            }
        }
        if cat.get(coll).is_some() {
            match lexicon_compare(&cat, coll, rkey, &j) {
                Some(e) => d.push(e),
                None => *tally.entry("lexicon agree").or_default() += 1,
            }
        }
    }
    eprintln!("real records: {tally:?}");
    d.assert_none();
}

/// Syntax verdicts against the TypeScript reference (@atproto/syntax), from a
/// TSV of `kind \t input \t true|false` produced by running the reference
/// over generated inputs (bench/results/differential/syntax_oracle.mjs):
/// `VLPDS_SYNTAX_ORACLE=oracle.tsv cargo test --test all -- --ignored syntax_reference_oracle`.
#[test]
#[ignore]
fn syntax_reference_oracle() {
    use shrike::syntax as ss;
    let path = std::env::var("VLPDS_SYNTAX_ORACLE").expect("VLPDS_SYNTAX_ORACLE=<tsv>");
    let mut vd = Diffs::new("vlpds vs @atproto/syntax");
    let mut sd = BTreeMap::<String, usize>::new();
    let mut n = 0;
    for line in std::fs::read_to_string(path).unwrap().lines() {
        let [kind, input, want] = line.splitn(3, '\t').collect::<Vec<_>>()[..] else { continue };
        let want = want == "true";
        let (v, s) = match kind {
            "did" => (syntax::valid_did(input), ss::Did::try_from(input).is_ok()),
            "handle" => (syntax::valid_handle(input), ss::Handle::try_from(input).is_ok()),
            "nsid" => (syntax::valid_nsid(input), ss::Nsid::try_from(input).is_ok()),
            "rkey" => (syntax::valid_rkey(input), ss::RecordKey::try_from(input).is_ok()),
            "aturi" => (lexicon::valid_at_uri(input), ss::AtUri::try_from(input).is_ok()),
            "datetime" => (lexicon::valid_datetime(input), ss::Datetime::try_from(input).is_ok()),
            "tid" => (syntax::valid_tid(input), ss::Tid::try_from(input).is_ok()),
            "language" => (lexicon::valid_language(input), ss::Language::try_from(input).is_ok()),
            "atidentifier" => (valid_at_identifier(input), ss::AtIdentifier::try_from(input).is_ok()),
            k => panic!("{k}"),
        };
        n += 1;
        if v != want {
            vd.push(format!("{kind} {}: reference {want}, vlpds {v}", short(input)));
        }
        if s != want {
            *sd.entry(format!("{kind} reference {want} shrike {s}")).or_default() += 1;
        }
    }
    eprintln!("{n} inputs; shrike vs reference: {sd:?}");
    vd.assert_none();
}

/// Record JSON -> DAG-CBOR against the TypeScript reference (@atproto/lex-json
/// strict mode + @atproto/lex-cbor), from a TSV of `json \t cbor-hex|ERR`
/// (bench/results/differential/json_oracle.mjs over the VLPDS_JSON_DUMP corpus):
/// `VLPDS_JSON_ORACLE=oracle.tsv cargo test --test all -- --ignored json_reference_oracle`.
#[test]
#[ignore]
fn json_reference_oracle() {
    let path = std::env::var("VLPDS_JSON_ORACLE").expect("VLPDS_JSON_ORACLE=<tsv>");
    let mut d = Diffs::new("vlpds vs @atproto/lex-json");
    let mut tally: BTreeMap<String, usize> = BTreeMap::new();
    for line in std::fs::read_to_string(path).unwrap().lines() {
        let Some((text, want)) = line.rsplit_once('\t') else { continue };
        let j: J = serde_json::from_str(text).unwrap();
        let v = Value::from_json(&j).map(|v| hex::encode(v.to_cbor())).unwrap_or_else(|_| "ERR".into());
        let s = json_to_drisl(&j, Integers::Any).map(hex::encode).unwrap_or_else(|_| "ERR".into());
        *tally
            .entry(format!(
                "shrike {}",
                if s == want {
                    "agrees"
                } else if want == "ERR" {
                    "accepts (reference rejects)"
                } else if s == "ERR" {
                    "rejects (reference accepts)"
                } else {
                    "encodes differently"
                }
            ))
            .or_default() += 1;
        if v != want {
            // policy split (SHRIKE_ISSUES.md, "policy differences"): vlpds's
            // links are base32 dag-cbor/raw CIDs and its $bytes the standard
            // alphabet only (integers: JS-safe, as the reference)
            fn any(j: &J, f: &dyn Fn(&J) -> bool) -> bool {
                f(j) || match j {
                    J::Object(o) => o.values().any(|v| any(v, f)),
                    J::Array(a) => a.iter().any(|v| any(v, f)),
                    _ => false,
                }
            }
            let foreign = |x: &J| {
                x.get("$link").and_then(|l| l.as_str()).is_some_and(|l| !l.starts_with('b') || Cid::parse(l).is_err())
                    || x.get("$bytes").and_then(|b| b.as_str()).is_some_and(|b| b.contains(['-', '_']))
            };
            let why = if v == "ERR" && any(&j, &foreign) {
                "non-base32 / non-dag-cbor-or-raw link, or URL-safe $bytes"
            } else {
                d.push(format!("{}: reference {want}, vlpds {v}", short(text)));
                continue;
            };
            *tally.entry(format!("vlpds policy: {why}")).or_default() += 1;
        }
    }
    eprintln!("{tally:?}");
    d.assert_none();
}
