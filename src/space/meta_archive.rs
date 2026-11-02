//! Space meta archives (@atproto/space `space-meta-archive.ts`): a space
//! authority's host-side state for one space, carried between hosts when
//! the authority's account migrates (exportSpaceMeta, importSpaceMeta). A
//! STAR file (framed as [`super::star`]) with the `atproto-space-meta`
//! profile: metadata `{$type, ver: 1, space}`, then three sections, each in
//! strict bytewise key order with no duplicates:
//!
//! 1. `policy`: the space's policy object.
//! 2. Policy state, keyed like record paths (a member space's member list:
//!    `com.atproto.memberspace.member/{did as rkey}` -> `{$type, read, write}`).
//! 3. `writer/{did}` -> `{rev, data, spaceRev}`: the writer set.
//!
//! Every value is a DRISL map. This layer knows nothing of policies (as the
//! reference's doesn't): what the policy and its state mean is the
//! importer's to check.

use super::star::{read_varint, write_varint, StarError, MAGIC, MAX_KEY_LENGTH, MAX_META_LENGTH};
use vlatproto::cbor::{key_cmp, Value};
use vlatproto::tid::Tid;

pub const SPACE_META_STAR_TYPE: &str = "atproto-space-meta";
pub const SPACE_META_VERSION: i64 = 1;
const POLICY_KEY: &str = "policy";
const WRITER_PREFIX: &str = "writer/";
/// A value (policy, member, writer) is small; this bounds a hostile one.
const MAX_VALUE: u64 = 1 << 20;

fn fail(m: impl Into<String>) -> StarError {
    StarError(m.into())
}

/// One entry of the writer set, as listRepos reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MetaWriter {
    pub did: String,
    pub rev: Tid,
    pub data: Vec<u8>,
    pub space_rev: Tid,
}

/// A space meta archive's contents. `policy_state` is (key, DRISL map).
#[derive(Clone, Debug, PartialEq)]
pub struct SpaceMeta {
    pub space: String,
    pub policy: Value,
    pub policy_state: Vec<(String, Value)>,
    pub writers: Vec<MetaWriter>,
}

/// A map with its keys in canonical order.
pub fn map(mut entries: Vec<(String, Value)>) -> Value {
    entries.sort_by(|a, b| key_cmp(&a.0, &b.0));
    Value::Map(entries)
}

fn writer_value(w: &MetaWriter) -> Value {
    map(vec![
        ("rev".into(), Value::Text(w.rev.to_string())),
        ("data".into(), Value::Bytes(w.data.clone())),
        ("spaceRev".into(), Value::Text(w.space_rev.to_string())),
    ])
}

fn pair(out: &mut Vec<u8>, key: &[u8], value: &[u8]) {
    write_varint(out, key.len() as u64);
    out.extend_from_slice(key);
    write_varint(out, value.len() as u64);
    out.extend_from_slice(value);
}

/// Reference `serializeSpaceMeta`: each section put into key order.
pub fn serialize(a: &SpaceMeta) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(&MAGIC);
    let meta = map(vec![
        ("$type".into(), Value::Text(SPACE_META_STAR_TYPE.into())),
        ("ver".into(), Value::Int(SPACE_META_VERSION)),
        ("space".into(), Value::Text(a.space.clone())),
    ])
    .to_cbor();
    write_varint(&mut out, meta.len() as u64);
    out.extend_from_slice(&meta);
    pair(&mut out, POLICY_KEY.as_bytes(), &a.policy.to_cbor());
    let mut state: Vec<_> = a.policy_state.iter().map(|(k, v)| (k.as_bytes(), v.to_cbor())).collect();
    state.sort_by(|x, y| x.0.cmp(y.0));
    for (k, v) in state {
        pair(&mut out, k, &v);
    }
    let mut writers: Vec<_> =
        a.writers.iter().map(|w| (format!("{WRITER_PREFIX}{}", w.did), writer_value(w))).collect();
    writers.sort_by(|x, y| x.0.as_bytes().cmp(y.0.as_bytes()));
    for (k, v) in writers {
        pair(&mut out, k.as_bytes(), &v.to_cbor());
    }
    out
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum Section {
    Policy,
    PolicyState,
    Writers,
}

fn section_of(key: &str) -> Section {
    if key == POLICY_KEY {
        Section::Policy
    } else if key.starts_with(WRITER_PREFIX) {
        Section::Writers
    } else {
        Section::PolicyState
    }
}

fn decode_map(key: &str, b: &[u8]) -> Result<Value, StarError> {
    let v = Value::decode(b).map_err(|_| fail(format!("invalid cbor at {key}")))?;
    if !matches!(v, Value::Map(_)) {
        return Err(fail(format!("value at {key} is not a map")));
    }
    Ok(v)
}

fn tid_field(v: &Value, key: &str, field: &str) -> Result<Tid, StarError> {
    match v.get(field) {
        Some(Value::Text(t)) => {
            Tid::parse(t).ok_or_else(|| fail(format!("invalid writer at {key}: {field} must be a TID")))
        }
        _ => Err(fail(format!("invalid writer at {key}: {field} must be a TID"))),
    }
}

/// The metadata: a canonical DRISL map of this profile naming a space.
fn parse_meta(b: &[u8]) -> Result<String, StarError> {
    let v = Value::decode(b).map_err(|e| fail(format!("invalid metadata: {e}")))?;
    if v.to_cbor() != b {
        return Err(fail("metadata is not canonical DRISL"));
    }
    let bad = |m: &str| fail(format!("invalid space meta archive metadata: {m}"));
    if v.get("$type").and_then(|t| t.as_str()) != Some(SPACE_META_STAR_TYPE) {
        return Err(bad(&format!("$type must be {SPACE_META_STAR_TYPE}")));
    }
    if !matches!(v.get("ver"), Some(Value::Int(SPACE_META_VERSION))) {
        return Err(bad(&format!("ver must be {SPACE_META_VERSION}")));
    }
    let space = v.get("space").and_then(|s| s.as_str()).ok_or_else(|| bad("space must be a string"))?;
    if vlatproto::syntax::parse_space_uri(space).is_none_or(|u| u.record.is_some()) {
        return Err(bad("space must be a space URI"));
    }
    Ok(space.to_string())
}

/// Reference `readSpaceMetaStar`: read whole, refusing a missing policy, a
/// section or key out of place, a duplicate, and anything that isn't a
/// DRISL map (a writer: a valid DID key, TIDs and bytes).
pub fn parse(b: &[u8]) -> Result<SpaceMeta, StarError> {
    let rest = b.strip_prefix(&MAGIC[..]).ok_or_else(|| fail("invalid magic bytes"))?;
    let mut pos = 0;
    let mut frame = |max: u64, at_eof_ok: bool| -> Result<Option<&[u8]>, StarError> {
        if pos == rest.len() && at_eof_ok {
            return Ok(None);
        }
        let (len, n) = read_varint(&rest[pos..])?.ok_or_else(|| fail("unexpected end of archive"))?;
        if len > max {
            return Err(fail(format!("length {len} exceeds limit of {max}")));
        }
        let start = pos + n;
        let end = start
            .checked_add(len as usize)
            .filter(|e| *e <= rest.len())
            .ok_or_else(|| fail("unexpected end of archive"))?;
        pos = end;
        Ok(Some(&rest[start..end]))
    };
    let meta = frame(MAX_META_LENGTH, false)?.ok_or_else(|| fail("missing metadata"))?;
    let space = parse_meta(meta)?;
    let (mut policy, mut policy_state, mut writers) = (None, Vec::new(), Vec::new());
    let mut section: Option<Section> = None;
    let mut prev: Option<Vec<u8>> = None;
    while let Some(kb) = frame(MAX_KEY_LENGTH, true)? {
        let vb = frame(MAX_VALUE, false)?.ok_or_else(|| fail("missing value for key"))?;
        let key = std::str::from_utf8(kb).map_err(|_| fail("a key isn't UTF-8"))?;
        let s = section_of(key);
        if section != Some(s) {
            if section.is_some_and(|cur| s < cur) {
                return Err(fail(format!("section out of order at {key}")));
            }
            section = Some(s);
            prev = None;
        }
        if prev.as_deref().is_some_and(|p| kb <= p) {
            return Err(fail(format!("duplicate or out-of-order key: {key}")));
        }
        prev = Some(kb.to_vec());
        let value = decode_map(key, vb)?;
        match s {
            Section::Policy => policy = Some(value),
            Section::PolicyState => policy_state.push((key.to_string(), value)),
            Section::Writers => {
                let did = &key[WRITER_PREFIX.len()..];
                if !vlatproto::syntax::valid_did(did) {
                    return Err(fail(format!("invalid DID in writer key: {key}")));
                }
                let data = match value.get("data") {
                    Some(Value::Bytes(d)) => d.clone(),
                    _ => return Err(fail(format!("invalid writer at {key}: data must be bytes"))),
                };
                writers.push(MetaWriter {
                    did: did.to_string(),
                    rev: tid_field(&value, key, "rev")?,
                    data,
                    space_rev: tid_field(&value, key, "spaceRev")?,
                });
            }
        }
    }
    let policy = policy.ok_or_else(|| fail("missing policy"))?;
    Ok(SpaceMeta { space, policy, policy_state, writers })
}

/// A DRISL value as JSON (bytes as `{"$bytes"}`), for a policy that goes
/// through the same normalization as one from a method's input.
pub fn to_json(v: &Value) -> serde_json::Value {
    v.to_json()
}

/// JSON (with no bytes or links) as DRISL.
pub fn from_json(v: &serde_json::Value) -> Value {
    Value::from_json(v).expect("json values encode")
}

/// A borrowed look at a value's boolean field.
pub fn bool_field(v: &Value, field: &str) -> Option<bool> {
    match v.get(field) {
        Some(Value::Bool(b)) => Some(*b),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const SPACE: &str = "at://did:example:forum/space/com.example.forum/general";

    fn writer(did: &str) -> MetaWriter {
        MetaWriter {
            did: did.into(),
            rev: Tid::parse("3kbcq3p7ad42b").unwrap(),
            data: vec![1; 32],
            space_rev: Tid::parse("3kbcq3p7ad42c").unwrap(),
        }
    }

    fn member() -> Value {
        from_json(&json!({"$type": "com.example.member", "read": true, "write": true}))
    }

    fn sample() -> SpaceMeta {
        SpaceMeta {
            space: SPACE.into(),
            policy: from_json(&json!({"$type": "com.example.policy", "readAccess": "members"})),
            policy_state: vec![
                ("com.example.member/did:example:carol".into(), member()),
                ("com.example.member/did:example:alice".into(), member()),
            ],
            writers: vec![writer("did:example:carol"), writer("did:example:alice")],
        }
    }

    /// Frames an archive by hand, in the order given.
    fn raw(meta: serde_json::Value, pairs: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let mut out = MAGIC.to_vec();
        let m = from_json(&meta).to_cbor();
        write_varint(&mut out, m.len() as u64);
        out.extend_from_slice(&m);
        for (k, v) in pairs {
            pair(&mut out, k.as_bytes(), v);
        }
        out
    }

    fn meta() -> serde_json::Value {
        json!({"$type": SPACE_META_STAR_TYPE, "ver": 1, "space": SPACE})
    }

    #[test]
    fn round_trips_in_key_order() {
        let a = sample();
        let b = serialize(&a);
        let p = parse(&b).unwrap();
        let mut want = a.clone();
        want.policy_state.reverse();
        want.writers.reverse();
        assert_eq!(p, want);
        // what it writes it reads, byte for byte
        assert_eq!(serialize(&p), b);
        // the metadata and the key order, as the reference writes them
        let keys = [
            "policy",
            "com.example.member/did:example:alice",
            "com.example.member/did:example:carol",
            "writer/did:example:alice",
            "writer/did:example:carol",
        ];
        let w = writer_value(&writer("x")).to_cbor();
        let pairs: Vec<(&str, Vec<u8>)> = vec![
            (keys[0], a.policy.to_cbor()),
            (keys[1], member().to_cbor()),
            (keys[2], member().to_cbor()),
            (keys[3], w.clone()),
            (keys[4], w),
        ];
        assert_eq!(raw(meta(), &pairs), b);
        // an empty state and writer set
        let bare = SpaceMeta { policy_state: vec![], writers: vec![], ..a };
        assert_eq!(parse(&serialize(&bare)).unwrap(), bare);
    }

    #[test]
    fn refusals() {
        let policy = sample().policy.to_cbor();
        let m = member().to_cbor();
        let w = writer_value(&writer("x")).to_cbor();
        let err = |pairs: &[(&str, Vec<u8>)]| parse(&raw(meta(), pairs)).unwrap_err().0;
        assert!(err(&[]).contains("missing policy"));
        assert!(err(&[("a.b/x", m.clone())]).contains("missing policy"));
        assert!(err(&[("a.b/x", m.clone()), ("policy", policy.clone())]).contains("section out of order"));
        assert!(err(&[("policy", policy.clone()), ("writer/did:example:a", w.clone()), ("a.b/x", m.clone())])
            .contains("section out of order"));
        assert!(
            err(&[("policy", policy.clone()), ("policy", policy.clone())]).contains("section out of order")
                || err(&[("policy", policy.clone()), ("policy", policy.clone())]).contains("duplicate")
        );
        assert!(err(&[("policy", policy.clone()), ("a.b/y", m.clone()), ("a.b/x", m.clone())]).contains("out-of-order"));
        assert!(err(&[("policy", policy.clone()), ("a.b/x", m.clone()), ("a.b/x", m.clone())]).contains("duplicate"));
        assert!(err(&[
            ("policy", policy.clone()),
            ("writer/did:example:b", w.clone()),
            ("writer/did:example:a", w.clone())
        ])
        .contains("out-of-order"));
        assert!(err(&[("policy", Value::Int(5).to_cbor())]).contains("not a map"));
        assert!(err(&[("policy", vec![0xff])]).contains("invalid cbor"));
        assert!(err(&[("policy", policy.clone()), ("writer/nope", w.clone())]).contains("invalid DID"));
        let no_data = from_json(&json!({"rev": "3kbcq3p7ad42b", "spaceRev": "3kbcq3p7ad42c"})).to_cbor();
        assert!(err(&[("policy", policy.clone()), ("writer/did:example:a", no_data)]).contains("data"));
        let bad_rev = map(vec![
            ("rev".into(), Value::Text("nope".into())),
            ("data".into(), Value::Bytes(vec![1; 32])),
            ("spaceRev".into(), Value::Text("3kbcq3p7ad42c".into())),
        ]);
        assert!(err(&[("policy", policy.clone()), ("writer/did:example:a", bad_rev.to_cbor())]).contains("TID"));
        // metadata
        let p = [("policy", policy.clone())];
        assert!(parse(&raw(json!({"$type": "atproto-space-repo", "ver": 1, "space": SPACE}), &p)).is_err());
        assert!(parse(&raw(json!({"$type": SPACE_META_STAR_TYPE, "ver": 2, "space": SPACE}), &p)).is_err());
        assert!(parse(&raw(json!({"$type": SPACE_META_STAR_TYPE, "ver": 1, "space": "nope"}), &p)).is_err());
        // truncation, bad magic
        let b = serialize(&sample());
        for cut in 1..6 {
            assert!(parse(&b[..b.len() - cut]).is_err(), "{cut}");
        }
        assert!(parse(&b[1..]).is_err());
    }
}
