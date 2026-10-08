//! atproto data-model interop fixtures: JSON <-> DAG-CBOR <-> CID round trips
//! through `vlsync_atproto::cbor` / `vlsync_atproto::cid`, and the valid/invalid record data
//! fixtures through createRecord / getRecord.
use crate::common::*;

#[test]
fn fixtures_json_to_cbor_to_cid() {
    for (i, f) in data_model_fixtures().iter().enumerate() {
        let v = Value::from_json(&f.json).unwrap_or_else(|e| panic!("fixture {i}: from_json: {e}"));
        let got = v.to_cbor();
        assert_eq!(got, f.cbor, "fixture {i}: DAG-CBOR encoding differs");
        assert_eq!(Cid::dag_cbor(&got).to_string(), f.cid, "fixture {i}: CID differs");
    }
}

#[test]
fn fixtures_cbor_to_json() {
    for (i, f) in data_model_fixtures().iter().enumerate() {
        let v = Value::decode(&f.cbor).unwrap_or_else(|e| panic!("fixture {i}: decode: {e}"));
        assert_eq!(v.to_json(), f.json, "fixture {i}: CBOR -> JSON differs");
        // and re-encoding the decoded value is byte-identical (canonical)
        assert_eq!(v.to_cbor(), f.cbor, "fixture {i}: decode/encode not stable");
    }
}

#[test]
fn cbor_decoder_rejects_non_canonical_or_unsupported() {
    for (b, what) in [
        (&[0xfb, 0x40, 0x09, 0x21, 0xfb, 0x54, 0x44, 0x2d, 0x18][..], "float64"),
        (&[0x9f, 0x01, 0xff], "indefinite-length array"),
        (&[0xf7], "undefined"),
        (&[0xc1, 0x01], "tag 1"),
        (&[0xa1, 0x01, 0x02], "int map key"),
        (&[0x01, 0x02], "trailing bytes"),
    ] {
        assert!(Value::decode(b).is_err(), "{what} accepted");
    }
}

#[test]
fn cbor_decoder_strictness_gaps() {
    // DAG-CBOR requires minimal integer encoding, sorted map keys and no
    // duplicate keys (strictness the reference decoders apply; it matters
    // for importRepo / blocks received from clients, not for records, which
    // vlpds re-encodes from JSON).
    for (b, what) in [
        (&[0x18, 0x01][..], "non-minimal integer encoding"),
        (&[0xa2, 0x61, b'b', 0x01, 0x61, b'a', 0x02], "unsorted map keys"),
        (&[0xa2, 0x61, b'a', 0x01, 0x61, b'a', 0x02], "duplicate map keys"),
    ] {
        assert!(Value::decode(b).is_err(), "{what} accepted");
    }
}

#[test]
fn json_conversion_edge_cases() {
    // $bytes uses unpadded standard base64
    let v = Value::from_json(&json!({"b": {"$bytes": "AQID"}})).unwrap();
    assert_eq!(v.get("b"), Some(&Value::Bytes(vec![1, 2, 3])));
    assert_eq!(v.to_json(), json!({"b": {"$bytes": "AQID"}}));
    let c = "bafyreie5737gdxlw5i64vzichcalba3z2v5n6icifvx5xytvske7mr3hpm";
    let v = Value::from_json(&json!({"l": {"$link": c}})).unwrap();
    assert_eq!(v.get("l"), Some(&Value::Link(Cid::parse(c).unwrap())));
    // canonical key order: length first, then bytewise
    let Value::Map(m) = Value::from_json(&json!({"bb": 1, "a": 2, "c": 3, "aaa": 4})).unwrap() else { panic!() };
    assert_eq!(m.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>(), vec!["a", "c", "bb", "aaa"]);
    for n in [i64::MIN + 1, -1, 0, 23, 24, 255, 256, 65535, 65536, i64::MAX] {
        let v = Value::Int(n);
        assert_eq!(Value::decode(&v.to_cbor()).unwrap(), v);
    }
}

// ---------------------------------------------------------------------------
// valid / invalid record data, through the server
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
struct Case {
    note: String,
    json: J,
}

fn cases(rel: &str) -> Vec<Case> {
    serde_json::from_str(&read_fixture(rel)).unwrap()
}

/// Wraps a fixture's object fields into a record of collection com.example.blah.
fn as_record(j: &J) -> J {
    match j {
        J::Object(o) => {
            let mut rec = serde_json::Map::new();
            rec.insert("$type".into(), json!("com.example.blah"));
            rec.extend(o.clone());
            J::Object(rec)
        }
        // top-level not an object: send it as the record itself
        _ => j.clone(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn valid_record_data_accepted_and_round_trips() {
    let s = TestServer::spawn().await;
    let a = s.create_account("dmv").await;
    let mut bad = Vec::new();
    for (i, c) in cases("interop/data-model/data-model-valid.json").iter().enumerate() {
        let rec = as_record(&c.json);
        let rkey = format!("valid{i}");
        let r = s.put_record(&a, "com.example.blah", &rkey, rec.clone()).await;
        if !r.is_ok() {
            bad.push(format!("{}: rejected: {}", c.note, r.text()));
            continue;
        }
        let g = s.get_record(&a.did, "com.example.blah", &rkey).await.ok();
        // JSON numbers like 123.0 are integers in the data model
        let want = serde_json::from_str::<J>(&rec.to_string().replace("123.0", "123")).unwrap();
        if g["value"] != want {
            bad.push(format!("{}: getRecord value {} != {}", c.note, g["value"], want));
        }
    }
    assert!(bad.is_empty(), "valid data-model fixtures:\n  {}", bad.join("\n  "));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn invalid_record_data_rejected() {
    let s = TestServer::spawn().await;
    let a = s.create_account("dmi").await;
    let mut bad = Vec::new();
    for c in cases("interop/data-model/data-model-invalid.json") {
        let body = json!({"repo": a.did, "collection": "com.example.blah", "record": as_record(&c.json)});
        let r = s.xrpc.post("com.atproto.repo.createRecord", &body, &a.auth()).await;
        if r.status != 400 {
            bad.push(format!("{}: createRecord -> {}", c.note, r.text()));
        }
    }
    let l = s.list_records(&a.did, "com.example.blah", &[]).await;
    let stored = l.json["records"].as_array().map_or(0, |a| a.len());
    assert!(bad.is_empty() && stored == 0, "invalid data-model fixtures ({stored} stored):\n  {}", bad.join("\n  "));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fixture_records_round_trip_through_server_with_matching_cids() {
    // Every data-model fixture (plus a $type) stored via putRecord comes back
    // byte-identical: getRecord JSON equals the input and the returned CID is
    // the DAG-CBOR CID of the canonical encoding; sync.getRecord's block bytes
    // equal our own encoding.
    let s = TestServer::spawn().await;
    let a = s.create_account("dmf").await;
    for (i, f) in data_model_fixtures().iter().enumerate() {
        let mut rec = f.json.clone();
        rec["$type"] = json!("com.example.fixture");
        let want_bytes = Value::from_json(&rec).unwrap().to_cbor();
        let want_cid = json!(Cid::dag_cbor(&want_bytes).to_string());
        let rkey = format!("f{i}");
        let r = s.put_record(&a, "com.example.fixture", &rkey, rec.clone()).await;
        // A fixture referencing a blob this repo never uploaded is refused, as
        // the reference does (actor-store/blob/transactor.ts
        // processWriteBlobs -> "Could not find blob"); its encoding is still
        // covered by fixtures_json_to_cbor_to_cid.
        if rec.to_string().contains(r#""$type":"blob""#) {
            r.err(400, "BlobNotFound");
            continue;
        }
        assert_eq!(r.ok()["cid"], want_cid, "fixture {i}: putRecord cid");
        let g = s.get_record(&a.did, "com.example.fixture", &rkey).await.ok();
        assert_eq!(g["value"], rec, "fixture {i}: getRecord value");
        assert_eq!(g["cid"], want_cid, "fixture {i}: getRecord cid");
        let q = [("did", a.did.as_str()), ("collection", "com.example.fixture"), ("rkey", &rkey)];
        let car = s.xrpc.get("com.atproto.sync.getRecord", &q, &Auth::None).await;
        assert_eq!(car.status, 200, "sync.getRecord: {}", car.text());
        let repo = Repo::from_car(&car.body).unwrap();
        assert_eq!(repo.blocks.get(&Cid::dag_cbor(&want_bytes)), Some(&want_bytes), "fixture {i}: record block bytes");
    }
}
