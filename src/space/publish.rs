//! The records a policy publishes to readers (reference
//! `space-policy/publish.ts`): the policy as `com.atproto.space.policy/self`
//! and each member's entry as `com.atproto.memberspace.member/<did>`, in
//! the authority's own repo in the space. The config stays the source of
//! truth; the space host writes these in the same entry as the change they
//! mirror, and nothing else may write them in any repo.

use super::rows::{MemberRow, Policy};
use bytes::Bytes;
use vlatproto::cid::Cid;

pub const POLICY_COLLECTION: &str = "com.atproto.space.policy";
pub const POLICY_RKEY: &str = "self";
pub const MEMBER_COLLECTION: &str = "com.atproto.memberspace.member";

/// Written only by the space host from a space's config.
pub fn is_published(collection: &str) -> bool {
    collection == POLICY_COLLECTION || collection == MEMBER_COLLECTION
}

/// Reference `assertNotPolicyRecord`'s refusal.
pub fn refusal(collection: &str) -> String {
    format!("{collection} records are published by the PDS from a space's configuration and cannot be written directly")
}

/// Reference `didToRecordKey`: a record key can't hold `%`, so the
/// percent-encoded port of a localhost did:web is left unencoded
/// (`did:web:localhost%3A2583` is keyed `did:web:localhost:2583`), which
/// can't be mistaken for anything since atproto has no did:web paths.
pub fn did_rkey(did: &str) -> String {
    did.replacen("%3A", ":", 1)
}

pub fn policy_path() -> String {
    format!("{POLICY_COLLECTION}/{POLICY_RKEY}")
}

pub fn member_path(did: &str) -> String {
    format!("{MEMBER_COLLECTION}/{}", did_rkey(did))
}

fn encode(v: &serde_json::Value) -> (Cid, Bytes) {
    let bytes = vlatproto::cbor::Value::from_json(v).expect("published records encode").to_cbor();
    (Cid::dag_cbor(&bytes), bytes.into())
}

pub fn policy_record(policy: &Policy) -> (Cid, Bytes) {
    encode(&serde_json::json!({"$type": POLICY_COLLECTION, "policy": policy.to_lex()}))
}

pub fn member_record(access: MemberRow) -> (Cid, Bytes) {
    encode(&serde_json::json!({"$type": MEMBER_COLLECTION, "read": access.read, "write": access.write}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn did_record_keys() {
        assert_eq!(did_rkey("did:web:localhost%3A2583"), "did:web:localhost:2583");
        assert_eq!(did_rkey("did:plc:abc"), "did:plc:abc");
        assert!(vlatproto::syntax::valid_rkey(&did_rkey("did:web:localhost%3A2583")));
        assert_eq!(member_path("did:plc:abc"), "com.atproto.memberspace.member/did:plc:abc");
    }

    #[test]
    fn records_are_drisl() {
        let (cid, bytes) = member_record(MemberRow { read: true, write: false });
        let v = vlatproto::cbor::Value::decode(&bytes).unwrap();
        assert_eq!(v.to_cbor(), bytes.to_vec(), "canonical");
        assert_eq!(cid, Cid::dag_cbor(&bytes));
        assert_eq!(v.to_json(), serde_json::json!({"$type": MEMBER_COLLECTION, "read": true, "write": false}));
        let (_, bytes) = policy_record(&Policy::Personal);
        assert_eq!(
            vlatproto::cbor::Value::decode(&bytes).unwrap().to_json(),
            serde_json::json!({"$type": POLICY_COLLECTION, "policy": {"$type": "com.atproto.personalspace.policy"}})
        );
    }
}
