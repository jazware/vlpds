//! The space meta archive (@atproto/space `space-meta-archive.ts`): a space
//! host's state for one space, carried when its authority's account moves
//! (exportSpaceMeta, importSpaceMeta). A STAR archive with the
//! `atproto-space-meta` profile, metadata `{$type, ver: 1, space}`, then
//! three sections in this order, each in strict key order:
//!
//! 1. `policy`: the space's policy object.
//! 2. Policy state, keyed like record paths (`{nsid}/{rkey}`): memberspace's
//!    member list is the only one among the baseline policies.
//! 3. `writer/{did}`: one per writer-set entry, `{rev, data, spaceRev}`.
//!
//! This module is the framing and the profile's checks; which policy state
//! keys a policy defines is the importer's.

use super::star;
use vlatproto::cbor::{self, Value};
use vlatproto::tid::Tid;

pub const VERSION: i64 = 1;
const POLICY_KEY: &str = "policy";
const WRITER_PREFIX: &str = "writer/";

#[derive(Debug, Clone, PartialEq)]
pub struct Writer {
    pub did: String,
    pub rev: Tid,
    pub data: [u8; 32],
    pub space_rev: Tid,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Archive {
    pub space: String,
    pub policy: Value,
    /// (key, value), any order: [`write`] sorts them.
    pub policy_state: Vec<(String, Value)>,
    pub writers: Vec<Writer>,
}

/// The reference's `SpaceMetaArchiveError`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetaError(pub String);

impl std::fmt::Display for MetaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn err<T>(m: impl Into<String>) -> Result<T, MetaError> {
    Err(MetaError(m.into()))
}

fn encode(v: &Value) -> Vec<u8> {
    let mut b = Vec::new();
    v.encode(&mut b);
    b
}

fn meta_bytes(space: &str) -> Vec<u8> {
    let mut b = Vec::with_capacity(64 + space.len());
    cbor::write_map_head(&mut b, 3);
    cbor::write_text(&mut b, "ver");
    cbor::write_int(&mut b, VERSION);
    cbor::write_text(&mut b, "$type");
    cbor::write_text(&mut b, star::META_TYPE);
    cbor::write_text(&mut b, "space");
    cbor::write_text(&mut b, space);
    b
}

fn writer_value(w: &Writer) -> Vec<u8> {
    let mut b = Vec::with_capacity(80);
    cbor::write_map_head(&mut b, 3);
    cbor::write_text(&mut b, "rev");
    cbor::write_text(&mut b, &w.rev.to_string());
    cbor::write_text(&mut b, "data");
    cbor::write_bytes(&mut b, &w.data);
    cbor::write_text(&mut b, "spaceRev");
    cbor::write_text(&mut b, &w.space_rev.to_string());
    b
}

/// `serializeSpaceMeta`, putting each section into key order.
pub fn write(a: &Archive) -> Vec<u8> {
    let mut out = Vec::new();
    star::write_header(&mut out, &meta_bytes(&a.space));
    star::write_pair(&mut out, POLICY_KEY.as_bytes(), &encode(&a.policy));
    let mut state: Vec<(&str, Vec<u8>)> = a.policy_state.iter().map(|(k, v)| (k.as_str(), encode(v))).collect();
    state.sort_by(|x, y| x.0.as_bytes().cmp(y.0.as_bytes()));
    for (k, v) in state {
        star::write_pair(&mut out, k.as_bytes(), &v);
    }
    let mut writers: Vec<(String, Vec<u8>)> =
        a.writers.iter().map(|w| (format!("{WRITER_PREFIX}{}", w.did), writer_value(w))).collect();
    writers.sort_by(|x, y| x.0.as_bytes().cmp(y.0.as_bytes()));
    for (k, v) in writers {
        star::write_pair(&mut out, k.as_bytes(), &v);
    }
    star::write_end(&mut out);
    out
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Section {
    Policy,
    State,
    Writers,
}

fn section_of(key: &str) -> Section {
    if key == POLICY_KEY {
        Section::Policy
    } else if key.starts_with(WRITER_PREFIX) {
        Section::Writers
    } else {
        Section::State
    }
}

fn get<'a>(m: &'a [(String, Value)], k: &str) -> Option<&'a Value> {
    m.iter().find(|(key, _)| key == k).map(|(_, v)| v)
}

fn tid_of(v: Option<&Value>, what: &str) -> Result<Tid, MetaError> {
    match v {
        Some(Value::Text(t)) => Tid::parse(t).ok_or_else(|| MetaError(format!("invalid writer: {what} must be a TID"))),
        _ => err(format!("invalid writer: {what} must be a TID")),
    }
}

/// `readSpaceMetaStar`: the archive whole, rejected on a parse error, an
/// exceeded limit, a section out of place, a duplicate or out-of-order key,
/// or no policy.
pub fn read(bytes: &[u8]) -> Result<Archive, MetaError> {
    let (meta, pairs) = star::read_all(bytes, star::LIMITS).map_err(|e| MetaError(e.0))?;
    let Value::Map(m) = &meta else { return err("invalid space meta archive metadata") };
    if get(m, "$type") != Some(&Value::Text(star::META_TYPE.into())) {
        return err("invalid space meta archive metadata: $type");
    }
    if get(m, "ver") != Some(&Value::Int(VERSION)) {
        return err("invalid space meta archive metadata: ver");
    }
    let space = match get(m, "space") {
        Some(Value::Text(s)) if vlatproto::syntax::parse_space_uri(s).is_some_and(|u| u.record.is_none()) => s.clone(),
        _ => return err("invalid space meta archive metadata: space"),
    };
    let (mut policy, mut policy_state, mut writers) = (None, Vec::new(), Vec::new());
    let mut section: Option<Section> = None;
    let mut prev: Option<Vec<u8>> = None;
    for (key, value) in pairs {
        let k = std::str::from_utf8(&key).map_err(|_| MetaError("a key is not UTF-8".into()))?.to_string();
        let s = section_of(&k);
        if section != Some(s) {
            if section.is_some_and(|cur| s < cur) {
                return err(format!("section out of order at {k}"));
            }
            section = Some(s);
            prev = None;
        }
        if prev.as_ref().is_some_and(|p| key <= *p) {
            return err(format!("duplicate or out-of-order key: {k}"));
        }
        prev = Some(key);
        let v = Value::decode(&value).map_err(|_| MetaError(format!("invalid cbor at {k}")))?;
        if !matches!(v, Value::Map(_)) {
            return err(format!("value at {k} is not a map"));
        }
        match s {
            Section::Policy => policy = Some(v),
            Section::State => policy_state.push((k, v)),
            Section::Writers => {
                let did = &k[WRITER_PREFIX.len()..];
                if !vlatproto::syntax::valid_did(did) {
                    return err(format!("invalid DID in writer key: {k}"));
                }
                let Value::Map(w) = &v else { unreachable!() };
                let data = match get(w, "data") {
                    Some(Value::Bytes(b)) => {
                        <[u8; 32]>::try_from(&b[..]).map_err(|_| MetaError("invalid writer: data".into()))?
                    }
                    _ => return err("invalid writer: data"),
                };
                writers.push(Writer {
                    did: did.to_string(),
                    rev: tid_of(get(w, "rev"), "rev")?,
                    data,
                    space_rev: tid_of(get(w, "spaceRev"), "spaceRev")?,
                });
            }
        }
    }
    let policy = policy.ok_or_else(|| MetaError("missing policy".into()))?;
    Ok(Archive { space, policy, policy_state, writers })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::space::vectors::VECTORS;

    /// testdata/spaces-alpha/vectors.json `star`'s meta archive: read, and
    /// written again to the same bytes.
    #[test]
    fn generated_vectors() {
        let v = VECTORS["star"].as_array().unwrap().iter().find(|s| s["profile"] == star::META_TYPE).unwrap();
        let bytes = hex::decode(v["star"].as_str().unwrap()).unwrap();
        let a = read(&bytes).unwrap();
        assert_eq!(a.space, v["space"].as_str().unwrap());
        assert_eq!(a.policy_state.len(), 2);
        assert_eq!(a.writers.len(), 1);
        assert_eq!(write(&a), bytes);
    }

    fn sample() -> Archive {
        let map = |kv: &[(&str, Value)]| Value::Map(kv.iter().map(|(k, v)| (k.to_string(), v.clone())).collect());
        Archive {
            space: "at://did:plc:x/space/com.example.group/self".into(),
            policy: map(&[("$type", Value::Text("com.atproto.personalspace.policy".into()))]),
            policy_state: vec![(
                "com.atproto.memberspace.member/did:plc:b".into(),
                map(&[("read", Value::Bool(true))]),
            )],
            writers: vec![Writer {
                did: "did:plc:a".into(),
                rev: Tid::from_parts(1_790_000_000_000_000, 1),
                data: [7; 32],
                space_rev: Tid::from_parts(1_790_000_000_000_001, 1),
            }],
        }
    }

    // The cases below are the reference's src/space-meta-archive.test.ts.

    #[test]
    fn round_trips() {
        assert_eq!(read(&write(&sample())).unwrap(), sample());
    }

    #[test]
    fn rejects_bad_archives() {
        let a = sample();
        let mut out = Vec::new();
        star::write_header(&mut out, &meta_bytes(&a.space));
        star::write_pair(&mut out, b"writer/did:plc:a", &writer_value(&a.writers[0]));
        star::write_pair(&mut out, POLICY_KEY.as_bytes(), &encode(&a.policy));
        star::write_end(&mut out);
        assert!(read(&out).unwrap_err().0.contains("section out of order"));
        let mut out = Vec::new();
        star::write_header(&mut out, &meta_bytes(&a.space));
        star::write_end(&mut out);
        assert_eq!(read(&out).unwrap_err().0, "missing policy");
        let mut out = Vec::new();
        star::write_header(&mut out, &meta_bytes(&a.space));
        star::write_pair(&mut out, POLICY_KEY.as_bytes(), &encode(&a.policy));
        star::write_pair(&mut out, b"x.y.z/b", &encode(&a.policy));
        star::write_pair(&mut out, b"x.y.z/a", &encode(&a.policy));
        star::write_end(&mut out);
        assert!(read(&out).unwrap_err().0.contains("out-of-order"));
        let mut out = Vec::new();
        star::write_header(&mut out, &meta_bytes(&a.space));
        star::write_pair(&mut out, POLICY_KEY.as_bytes(), &encode(&a.policy));
        star::write_pair(&mut out, b"writer/not-a-did", &writer_value(&a.writers[0]));
        star::write_end(&mut out);
        assert!(read(&out).unwrap_err().0.contains("invalid DID"));
        // a repo archive isn't a meta archive
        let mut out = Vec::new();
        let c = crate::space::commit::Commit::new(&Default::default(), &a.space, "did:plc:x", "3kbcq3p7ad401");
        star::write_header(&mut out, &star::repo_meta(&c));
        star::write_end(&mut out);
        assert!(read(&out).unwrap_err().0.contains("$type"));
    }
}
