//! Space policies' published records (reference `space-policy/publish.ts`):
//! a policy may ask that its configuration be published to readers, as
//! records in the authority's own repo in the space, which the PDS keeps in
//! step with it. The policy (`sS`) and member list (`sM`) stay the source of
//! truth; these records are written only from them, on the authority's
//! repo worker, in the same entry as the change they publish.

use super::repo::SpaceWrite;
use super::rows::{MemberRow, SpacePolicy};
use bytes::Bytes;
use vlatproto::cid::Cid;

/// `{ policy }` at `self`, while the policy's `publishPolicy` is set.
pub const POLICY_COLLECTION: &str = "com.atproto.space.policy";
pub const POLICY_RKEY: &str = "self";
/// `{ read, write }` per member, keyed by its DID, while `publishMembers`.
pub const MEMBER_COLLECTION: &str = "com.atproto.memberspace.member";

/// The collections only the PDS writes: a direct write to either is
/// refused in any repo (reference `assertNotPolicyRecord`).
pub fn is_published_collection(collection: &str) -> bool {
    collection == POLICY_COLLECTION || collection == MEMBER_COLLECTION
}

/// Reference `didToRecordKey`: a record key can't hold `%`, so a localhost
/// did:web's percent-encoded port goes unencoded (`did:web:localhost%3A2583`
/// is keyed `did:web:localhost:2583`). A stopgap until Lexicon has a record
/// key format for DIDs.
pub fn did_to_rkey(did: &str) -> String {
    did.replacen("%3A", ":", 1)
}

/// Reference `recordKeyToDid`.
pub fn rkey_to_did(rkey: &str) -> String {
    if let Some(rest) = rkey.strip_prefix("did:web:") {
        if let Some((host, port)) = rest.split_once(':') {
            if !host.is_empty() && !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) {
                return format!("did:web:{host}%3A{port}");
            }
        }
    }
    rkey.to_string()
}

pub fn member_path(did: &str) -> String {
    format!("{MEMBER_COLLECTION}/{}", did_to_rkey(did))
}

pub fn policy_path() -> String {
    format!("{POLICY_COLLECTION}/{POLICY_RKEY}")
}

/// A record's DRISL bytes and CID.
fn encode(v: &serde_json::Value) -> (Cid, Bytes) {
    let bytes = vlatproto::cbor::Value::from_json(v).expect("published records encode").to_cbor();
    (Cid::dag_cbor(&bytes), bytes.into())
}

pub fn policy_record(policy: &SpacePolicy) -> serde_json::Value {
    serde_json::json!({"$type": POLICY_COLLECTION, "policy": policy.to_json()})
}

pub fn member_record(m: MemberRow) -> serde_json::Value {
    serde_json::json!({"$type": MEMBER_COLLECTION, "read": m.read, "write": m.write})
}

fn put(collection: &str, rkey: String, v: &serde_json::Value) -> SpaceWrite {
    let (cid, bytes) = encode(v);
    SpaceWrite::Update {
        collection: collection.into(),
        rkey,
        cid,
        bytes,
        blobs: Vec::new(),
        must_exist: false,
        put: None,
    }
}

fn withdraw(collection: &str, rkey: String) -> SpaceWrite {
    SpaceWrite::Delete { collection: collection.into(), rkey, must_exist: false }
}

/// The policy record as `policy` has it: put while published, else gone.
pub fn policy_write(policy: &SpacePolicy) -> SpaceWrite {
    if policy.publishes_policy() {
        put(POLICY_COLLECTION, POLICY_RKEY.into(), &policy_record(policy))
    } else {
        withdraw(POLICY_COLLECTION, POLICY_RKEY.into())
    }
}

/// A member's record as `policy` has it: put while members are published
/// and `access` is Some (a member), else gone.
pub fn member_write(policy: &SpacePolicy, did: &str, access: Option<MemberRow>) -> SpaceWrite {
    match access {
        Some(a) if policy.publishes_members() => put(MEMBER_COLLECTION, did_to_rkey(did), &member_record(a)),
        _ => withdraw(MEMBER_COLLECTION, did_to_rkey(did)),
    }
}

/// The CID a put would leave at its path (None: a withdrawal).
pub fn written_cid(w: &SpaceWrite) -> Option<Cid> {
    match w {
        SpaceWrite::Create { cid, .. } | SpaceWrite::Update { cid, .. } => Some(*cid),
        SpaceWrite::Delete { .. } => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn did_record_keys() {
        for (did, rkey) in [
            ("did:plc:abc", "did:plc:abc"),
            ("did:web:example.com", "did:web:example.com"),
            ("did:web:localhost%3A2583", "did:web:localhost:2583"),
        ] {
            assert_eq!(did_to_rkey(did), rkey);
            assert_eq!(rkey_to_did(rkey), did);
            assert!(vlatproto::syntax::valid_rkey(rkey), "{rkey}");
        }
    }

    #[test]
    fn records_are_lexicon_shaped() {
        let p = SpacePolicy::Member {
            public_read: true,
            public_write: false,
            allowed_apps: None,
            publish_policy: true,
            publish_members: true,
        };
        assert_eq!(
            policy_record(&p),
            serde_json::json!({"$type": "com.atproto.space.policy", "policy": {
                "$type": "com.atproto.memberspace.policy", "publicRead": true, "publicWrite": false,
                "publishPolicy": true, "publishMembers": true}})
        );
        assert!(matches!(policy_write(&p), SpaceWrite::Update { .. }));
        assert!(matches!(
            member_write(&p, "did:plc:m", Some(MemberRow { read: true, write: false })),
            SpaceWrite::Update { .. }
        ));
        assert!(matches!(member_write(&p, "did:plc:m", None), SpaceWrite::Delete { .. }));
        assert!(matches!(policy_write(&SpacePolicy::Personal), SpaceWrite::Delete { .. }));
    }
}
