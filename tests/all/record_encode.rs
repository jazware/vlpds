//! `cbor::JsonValue` (one-pass JSON -> DAG-CBOR for record writes) against
//! the value-tree path `Value::from_json(&serde_json::Value)?.to_cbor()`:
//! byte-identical encodings, the same accept/reject decision and error, the
//! same blob refs, and the same lexicon verdicts, over the interop fixtures
//! and random JSON text (duplicate keys, floats, escapes, `$link` /
//! `$bytes` / blob / legacy-blob shapes).
use crate::common::*;
use rand::{Rng, SeedableRng};
use vlatproto::cbor::{JsonValue, RecordRefs};
use vlpds::lexicon;

/// The value-tree walks the record path used before `RecordRefs`.
fn old_refs(v: &Value, out: &mut RecordRefs) {
    match v {
        Value::Map(m) => {
            if v.get("$type").and_then(|t| t.as_str()) == Some("blob") {
                if let Some(Value::Link(c)) = v.get("ref") {
                    let mime = v.get("mimeType").and_then(|m| m.as_str()).map(String::from);
                    let size = match v.get("size") {
                        Some(Value::Int(n)) => Some(*n),
                        _ => None,
                    };
                    out.blobs.push((*c, mime, size));
                }
            }
            if out.legacy.is_none() && v.get("$type").is_none() {
                if let (Some(Value::Text(c)), Some(Value::Text(_))) = (v.get("cid"), v.get("mimeType")) {
                    if Cid::parse(c).is_ok() {
                        out.legacy = Some(c.clone());
                    }
                }
            }
            for (_, child) in m {
                old_refs(child, out);
            }
        }
        Value::Array(a) => a.iter().for_each(|c| old_refs(c, out)),
        _ => {}
    }
}

/// Both paths on one JSON text: (encoding or error, refs).
fn both(text: &str) -> (Result<Vec<u8>, String>, Result<Vec<u8>, String>, Option<(Value, JsonValue<'_>)>) {
    let j: Result<J, _> = serde_json::from_str(text);
    let jv: Result<JsonValue, _> = JsonValue::parse(text.as_bytes());
    // same parser: same syntax verdict and message
    match (&j, &jv) {
        (Ok(_), Ok(_)) => {}
        (Err(a), Err(b)) => {
            assert_eq!(a.to_string(), b.to_string(), "{text}");
            return (Err(a.to_string()), Err(b.to_string()), None);
        }
        _ => panic!("parse verdicts differ: {text}"),
    }
    let (j, mut jv) = (j.unwrap(), jv.unwrap());
    assert_eq!(jv.to_json(), j, "tree differs from serde_json::Value: {text}");
    // JSON-semantics lexicon view: the createRecord input schema sees the same
    let body = json!({"repo": "did:plc:abc", "collection": "a.b.c", "record": j.clone()});
    let body_text = body.to_string();
    let body_jv = JsonValue::parse(body_text.as_bytes()).unwrap();
    assert_eq!(
        lexicon::validate_input("com.atproto.repo.createRecord", &body),
        lexicon::validate_input("com.atproto.repo.createRecord", &body_jv),
        "{text}"
    );
    let old = Value::from_json(&j).map(|v| (v.to_cbor(), v)).map_err(|e| e.to_string());
    let mut out = b"prefix".to_vec();
    let mut refs = RecordRefs::default();
    let new = jv.encode_record(&mut out, &mut refs).map(|()| out[6..].to_vec()).map_err(|e| e.to_string());
    if new.is_err() {
        assert_eq!(out, b"prefix", "output not restored on error: {text}");
    }
    match (old, new) {
        (Ok((ob, v)), Ok(nb)) => {
            let mut want = RecordRefs::default();
            old_refs(&v, &mut want);
            assert_eq!(refs, want, "refs differ: {text}");
            (Ok(ob), Ok(nb), Some((v, jv)))
        }
        (o, n) => (o.map(|x| x.0), n, None),
    }
}

/// Lexicon verdicts over the old `Value` and the encoded `JsonValue` agree.
fn same_verdicts(v: &Value, jv: &JsonValue, text: &str) {
    for coll in [
        "app.bsky.feed.post",
        "app.bsky.feed.like",
        "app.bsky.actor.profile",
        "app.bsky.feed.generator",
        "com.example.unknown",
    ] {
        for validate in [None, Some(true)] {
            assert_eq!(
                lexicon::validate_record(coll, "3jui7kd54zh2y", v, validate, None),
                lexicon::validate_record(coll, "3jui7kd54zh2y", jv, validate, None),
                "{coll}: {text}"
            );
        }
    }
}

fn check(text: &str) -> bool {
    let (old, new, vals) = both(text);
    assert_eq!(old, new, "encodings differ: {text}");
    if let Some((v, jv)) = vals {
        same_verdicts(&v, &jv, text);
        return true;
    }
    false
}

#[test]
fn interop_fixtures_byte_identical() {
    #[derive(serde::Deserialize)]
    struct Fixture {
        json: J,
        cbor_base64: String,
    }
    let fixtures: Vec<Fixture> =
        serde_json::from_str(&read_fixture("interop/data-model/data-model-fixtures.json")).unwrap();
    for f in &fixtures {
        let text = f.json.to_string();
        let (_, new, _) = both(&text);
        let want = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD_NO_PAD,
            f.cbor_base64.trim_end_matches('='),
        )
        .unwrap();
        assert_eq!(new, Ok(want), "{text}");
        assert!(check(&text));
    }
    #[derive(serde::Deserialize)]
    struct Case {
        json: J,
    }
    for (name, valid) in [("data-model-valid.json", true), ("data-model-invalid.json", false)] {
        let cases: Vec<Case> = serde_json::from_str(&read_fixture(&format!("interop/data-model/{name}"))).unwrap();
        for c in cases {
            let text = c.json.to_string();
            // the invalid set includes shapes only lexicons reject; the
            // encoder must still agree with from_json on every one
            let ok = check(&text);
            if valid {
                assert!(ok, "valid fixture rejected: {text}");
            }
        }
    }
}

const CIDS: &[&str] = &[
    "bafyreie5737gdxlw5i64vzichcalba3z2v5n6icifvx5xytvske7mr3hpm",
    "bafkreie5737gdxlw5i64vzichcalba3z2v5n6icifvx5xytvske7mr3hpm",
    "bafyreie5737gdxlw5i64vzichcalba3z2v5n6icifvx5xytvske7mr3hp",
    "QmQg1v4o9xdT3Q14wh4S7dxZkDjyZ9ssFzFzyep1YrVJBY",
    "",
];

fn pick<'a>(rng: &mut impl Rng, xs: &[&'a str]) -> &'a str {
    xs[rng.gen_range(0..xs.len())]
}

fn rand_string(rng: &mut impl Rng) -> String {
    const PIECES: &[&str] = &[
        "a",
        "z",
        "text",
        "$type",
        "\\\"",
        "\\\\",
        "\\n",
        "\\u00e9",
        "\\ud83d\\ude00",
        "é",
        "日本",
        "😀",
        "/",
        " ",
        "\\u0000",
        "blob",
        "app.bsky.feed.post",
        "2026-10-01T12:34:56.789Z",
        "did:plc:ewvi7nxzyoun6zhxrhs64oiz",
        "en",
    ];
    let n = rng.gen_range(0..4);
    let s: String = (0..n).map(|_| pick(rng, PIECES)).collect();
    format!("\"{s}\"")
}

fn rand_number(rng: &mut impl Rng) -> String {
    match rng.gen_range(0..12) {
        0 => "1.0".into(),
        1 => "1.5".into(),
        2 => "1e3".into(),
        3 => "-0.0".into(),
        4 => "-0".into(),
        5 => "9007199254740991.0".into(),
        6 => "9007199254740993.0".into(),
        7 => "9223372036854775807".into(),
        8 => "9223372036854775808".into(),
        9 => "-9223372036854775808".into(),
        10 => "18446744073709551615".into(),
        _ => rng.gen_range(-70_000i64..70_000).to_string(),
    }
}

/// Keys drawn from a small pool, so maps repeat keys and hit the special ones.
const KEYS: &[&str] = &[
    "$type",
    "$link",
    "$bytes",
    "text",
    "createdAt",
    "cid",
    "mimeType",
    "ref",
    "size",
    "a",
    "bb",
    "subject",
    "uri",
    "langs",
    "embed",
    "images",
    "image",
    "alt",
    "facets",
    "é",
    "\\u00e9",
];

fn rand_json(rng: &mut impl Rng, depth: usize) -> String {
    let leaf = depth >= 5 || rng.gen_bool(0.35);
    match rng.gen_range(0..if leaf { 5 } else { 14 }) {
        0 => "null".into(),
        1 => if rng.gen() { "true" } else { "false" }.into(),
        2 => rand_number(rng),
        3 | 4 => rand_string(rng),
        5 | 6 => {
            let items: Vec<String> = (0..rng.gen_range(0..4)).map(|_| rand_json(rng, depth + 1)).collect();
            format!("[{}]", items.join(","))
        }
        7 => format!("{{\"$link\":\"{}\"}}", pick(rng, CIDS)),
        8 => {
            format!("{{\"$bytes\":\"{}\"}}", pick(rng, &["", "AQID", "AQID==", "AQIDBA", "AQIDBA=", "A", "!!", "AQ=="]))
        }
        9 => {
            // blob refs, well-formed and not
            let mut f = vec![
                "\"$type\":\"blob\"".to_string(),
                format!("\"ref\":{{\"$link\":\"{}\"}}", pick(rng, CIDS)),
                "\"mimeType\":\"image/jpeg\"".into(),
                format!("\"size\":{}", rand_number(rng)),
            ];
            if rng.gen_bool(0.3) {
                f.remove(rng.gen_range(0..f.len()));
            }
            if rng.gen_bool(0.2) {
                f.push(format!("\"{}\":{}", pick(rng, KEYS), rand_json(rng, depth + 1)));
            }
            format!("{{{}}}", f.join(","))
        }
        10 => format!(
            "{{\"cid\":\"{}\",\"mimeType\":\"image/png\"{}}}",
            pick(rng, CIDS),
            if rng.gen() { ",\"$type\":\"x.y.z\"" } else { "" }
        ),
        _ => {
            let fields: Vec<String> = (0..rng.gen_range(0..6))
                .map(|_| {
                    let k = pick(rng, KEYS);
                    let v = match (k, rng.gen_range(0..3)) {
                        ("$type", 0) => format!(
                            "\"{}\"",
                            pick(
                                rng,
                                &[
                                    "app.bsky.feed.post",
                                    "app.bsky.embed.images",
                                    "blob",
                                    "",
                                    "app.bsky.richtext.facet#mention"
                                ]
                            )
                        ),
                        _ => rand_json(rng, depth + 1),
                    };
                    format!("\"{k}\":{v}")
                })
                .collect();
            format!("{{{}}}", fields.join(","))
        }
    }
}

#[test]
fn random_json_byte_identical() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(5);
    let (mut ok, mut rejected) = (0, 0);
    for _ in 0..40_000 {
        let text = rand_json(&mut rng, 0);
        if check(&text) {
            ok += 1;
        } else {
            rejected += 1;
        }
    }
    assert!(ok > 5000 && rejected > 5000, "ok {ok}, rejected {rejected}");
}

/// Posts with random fields replaced, dropped or added: the lexicon
/// verdicts (and messages) match on mostly-valid records too.
#[test]
fn mutated_posts_same_verdicts() {
    let base = json!({
        "$type": "app.bsky.feed.post",
        "text": "Check out this thing @alice.bsky.social wrote https://example.com/mst",
        "createdAt": "2026-10-01T12:34:56.789Z",
        "langs": ["en"],
        "facets": [{"index": {"byteStart": 15, "byteEnd": 34}, "features": [{"$type": "app.bsky.richtext.facet#mention", "did": "did:plc:ewvi7nxzyoun6zhxrhs64oiz"}]}],
        "reply": {"root": {"uri": "at://did:plc:ewvi7nxzyoun6zhxrhs64oiz/app.bsky.feed.post/3l3qo2vuowo2b", "cid": CIDS[0]},
                  "parent": {"uri": "at://did:plc:ewvi7nxzyoun6zhxrhs64oiz/app.bsky.feed.post/3l3qo2vuowo2b", "cid": CIDS[0]}},
        "embed": {"$type": "app.bsky.embed.images", "images": [{"alt": "a tree", "image": {"$type": "blob", "ref": {"$link": CIDS[1]}, "mimeType": "image/jpeg", "size": 123456}, "aspectRatio": {"width": 1200, "height": 800}}]},
    });
    assert!(check(&base.to_string()));
    let mut rng = rand::rngs::StdRng::seed_from_u64(8);
    let paths: &[&[&str]] = &[
        &["text"],
        &["createdAt"],
        &["langs"],
        &["facets"],
        &["reply"],
        &["reply", "root"],
        &["reply", "root", "cid"],
        &["embed"],
        &["embed", "$type"],
        &["embed", "images"],
        &["$type"],
        &["tags"],
        &["labels"],
    ];
    let mut valid = 0;
    for _ in 0..20_000 {
        let mut r = base.clone();
        for _ in 0..rng.gen_range(1..3) {
            let p = paths[rng.gen_range(0..paths.len())];
            let parent: String = p[..p.len() - 1].iter().map(|s| format!("/{s}")).collect();
            let last = p[p.len() - 1];
            let v: J = serde_json::from_str(&rand_json(&mut rng, 3)).unwrap_or(J::Null);
            if let Some(o) = r.pointer_mut(&parent).and_then(|x| x.as_object_mut()) {
                match rng.gen_range(0..3) {
                    0 => {
                        o.remove(last);
                    }
                    _ => {
                        o.insert(last.to_string(), v);
                    }
                }
            }
        }
        let text = r.to_string();
        let (old, new, vals) = both(&text);
        assert_eq!(old, new, "{text}");
        if let Some((v, jv)) = vals {
            let a = lexicon::validate_record("app.bsky.feed.post", "3jui7kd54zh2y", &v, None, None);
            assert_eq!(a, lexicon::validate_record("app.bsky.feed.post", "3jui7kd54zh2y", &jv, None, None), "{text}");
            valid += a.is_ok() as usize;
        }
    }
    assert!(valid > 1000, "only {valid} valid posts");
}
