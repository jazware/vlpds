//! Values of the Spaces state families (keys: `crate::state`, "Spaces").
//! Binary rows are fixed-order fields with u16 length prefixes; `sS` is
//! JSON, as the rows an operator may want to read are. Records (`sR`) use
//! the public `R/` value (`state::record_value`).

use super::lthash::{LtHash, STATE_BYTES};
use anyhow::{bail, ensure, Context};
use bytes::{BufMut, Bytes};
use vlatproto::cid::{Cid, CID_BYTES_LEN};
use vlatproto::tid::Tid;

struct Reader<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Reader { b, at: 0 }
    }
    fn take(&mut self, n: usize) -> anyhow::Result<&'a [u8]> {
        let s = self.b.get(self.at..self.at + n).context("short space row")?;
        self.at += n;
        Ok(s)
    }
    fn u8(&mut self) -> anyhow::Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u64(&mut self) -> anyhow::Result<u64> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into()?))
    }
    fn str(&mut self) -> anyhow::Result<&'a str> {
        let n = u16::from_be_bytes(self.take(2)?.try_into()?) as usize;
        Ok(std::str::from_utf8(self.take(n)?)?)
    }
    fn cid(&mut self) -> anyhow::Result<Cid> {
        Ok(Cid::from_bytes(self.take(CID_BYTES_LEN)?)?)
    }
    fn end(&self) -> anyhow::Result<()> {
        ensure!(self.at == self.b.len(), "{} trailing bytes in space row", self.b.len() - self.at);
        Ok(())
    }
}

fn put_str(b: &mut Vec<u8>, s: &str) {
    let n = u16::try_from(s.len()).expect("space row strings are length-checked");
    b.put_u16(n);
    b.put_slice(s.as_bytes());
}

/// `sH`: the head of one account's repo in one space.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeadRow {
    pub uri: String,
    pub rev: Tid,
    pub hash: LtHash,
    pub records: u64,
    /// Unix microseconds of the first write; 0 for an imported repo, whose
    /// oplog never began at empty.
    pub created: u64,
}

impl HeadRow {
    pub fn encode(&self) -> Bytes {
        let mut b = Vec::with_capacity(2 + self.uri.len() + 24 + STATE_BYTES);
        put_str(&mut b, &self.uri);
        b.put_u64(self.rev.0);
        b.put_u64(self.records);
        b.put_u64(self.created);
        b.put_slice(&self.hash.state());
        b.into()
    }

    pub fn decode(v: &[u8]) -> anyhow::Result<HeadRow> {
        let mut r = Reader::new(v);
        let uri = r.str()?.to_string();
        let (rev, records, created) = (Tid(r.u64()?), r.u64()?, r.u64()?);
        let hash = LtHash::from_state(r.take(STATE_BYTES)?).context("bad LtHash state")?;
        r.end()?;
        Ok(HeadRow { uri, rev, hash, records, created })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpAction {
    Create,
    Update,
    Delete,
}

impl OpAction {
    pub fn as_str(self) -> &'static str {
        match self {
            OpAction::Create => "create",
            OpAction::Update => "update",
            OpAction::Delete => "delete",
        }
    }
}

/// `sO`: one op of the oplog, keyed by (rev, idx).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpRow {
    pub action: OpAction,
    pub collection: String,
    pub rkey: String,
    pub cid: Option<Cid>,
    pub prev: Option<Cid>,
}

impl OpRow {
    pub fn encode(&self) -> Bytes {
        let mut b = Vec::with_capacity(6 + self.collection.len() + self.rkey.len() + 2 * CID_BYTES_LEN);
        b.put_u8(match self.action {
            OpAction::Create => 0,
            OpAction::Update => 1,
            OpAction::Delete => 2,
        });
        put_str(&mut b, &self.collection);
        put_str(&mut b, &self.rkey);
        b.put_u8(self.cid.is_some() as u8 | (self.prev.is_some() as u8) << 1);
        for c in [self.cid, self.prev].into_iter().flatten() {
            b.put_slice(&c.to_bytes());
        }
        b.into()
    }

    pub fn decode(v: &[u8]) -> anyhow::Result<OpRow> {
        let mut r = Reader::new(v);
        let action = match r.u8()? {
            0 => OpAction::Create,
            1 => OpAction::Update,
            2 => OpAction::Delete,
            a => bail!("bad op action {a}"),
        };
        let (collection, rkey) = (r.str()?.to_string(), r.str()?.to_string());
        let flags = r.u8()?;
        ensure!(flags < 4, "bad op flags {flags}");
        let cid = if flags & 1 != 0 { Some(r.cid()?) } else { None };
        let prev = if flags & 2 != 0 { Some(r.cid()?) } else { None };
        r.end()?;
        Ok(OpRow { action, collection, rkey, cid, prev })
    }
}

/// (rev, idx) of an `sO` key: its last 10 bytes.
pub fn oplog_position(key: &[u8]) -> Option<(Tid, u16)> {
    let tail = key.len().checked_sub(10).map(|i| &key[i..])?;
    Some((Tid(u64::from_be_bytes(tail[..8].try_into().ok()?)), u16::from_be_bytes(tail[8..].try_into().ok()?)))
}

/// The spaceRev of an `sQ` key: its last 8 bytes.
pub fn seq_rev(key: &[u8]) -> Option<Tid> {
    let tail = key.get(key.len().checked_sub(8)?..)?;
    Some(Tid(u64::from_be_bytes(tail.try_into().ok()?)))
}

/// `sQ`: a writer in listRepos order, with the spaceRev sequenced just
/// before it. That one's row may be gone (its writer wrote again), and a
/// forward naming anything else as its prevSpaceRev could fork the chain a
/// syncer already heard.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeqRow {
    pub prev: Option<Tid>,
    pub writer: String,
}

impl SeqRow {
    pub fn encode(&self) -> Bytes {
        let mut b = Vec::with_capacity(10 + self.writer.len());
        b.put_u64(self.prev.map_or(0, |t| t.0));
        put_str(&mut b, &self.writer);
        b.into()
    }

    pub fn decode(v: &[u8]) -> anyhow::Result<SeqRow> {
        let mut r = Reader::new(v);
        let prev = Some(Tid(r.u64()?)).filter(|t| t.0 != 0);
        let writer = r.str()?.to_string();
        r.end()?;
        Ok(SeqRow { prev, writer })
    }
}

/// (CID, path) of an `sb` key after its `{did}\0{sid}` prefix.
pub fn blob_ref_parts(rest: &[u8]) -> Option<(&str, &str)> {
    std::str::from_utf8(rest).ok()?.split_once('\0')
}

/// The rev of the write that last named an `sb` ref's blob.
pub fn blob_ref_rev(v: &[u8]) -> Tid {
    Tid(v.get(..8).map_or(0, |b| u64::from_be_bytes(b.try_into().unwrap())))
}

/// `sP`: the newest write of a (repo, space) its authority hasn't
/// acknowledged yet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutboxRow {
    pub uri: String,
    pub repo_rev: Tid,
    /// sha256 of the LtHash state.
    pub hash: [u8; 32],
}

impl OutboxRow {
    pub fn encode(&self) -> Bytes {
        let mut b = Vec::with_capacity(2 + self.uri.len() + 40);
        put_str(&mut b, &self.uri);
        b.put_u64(self.repo_rev.0);
        b.put_slice(&self.hash);
        b.into()
    }

    pub fn decode(v: &[u8]) -> anyhow::Result<OutboxRow> {
        let mut r = Reader::new(v);
        let uri = r.str()?.to_string();
        let repo_rev = Tid(r.u64()?);
        let hash = r.take(32)?.try_into()?;
        r.end()?;
        Ok(OutboxRow { uri, repo_rev, hash })
    }
}

/// (DID, space id) of an `sP` (or `sH`) key.
pub fn did_sid(key: &[u8]) -> Option<(&str, crate::state::SpaceId)> {
    let body = vlsync_store::keys::key_body(key).get(3..)?;
    let at = body.len().checked_sub(crate::state::SPACE_ID_LEN + 1)?;
    (body[at] == 0).then_some(())?;
    Some((std::str::from_utf8(&body[..at]).ok()?, body[at + 1..].try_into().ok()?))
}

/// The DID and space id that begin a key with more after them (`sN`'s
/// service, `sW`'s writer).
pub fn did_sid_head(key: &[u8]) -> Option<(&str, crate::state::SpaceId)> {
    let body = vlsync_store::keys::key_body(key).get(3..)?;
    let at = body.iter().position(|b| *b == 0)?;
    let sid = body.get(at + 1..at + 1 + crate::state::SPACE_ID_LEN)?;
    Some((std::str::from_utf8(&body[..at]).ok()?, sid.try_into().ok()?))
}

/// `sW`: a writer's latest state as its repo host reported it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WriterRow {
    pub repo_rev: Tid,
    pub hash: [u8; 32],
    pub space_rev: Tid,
}

impl WriterRow {
    pub const LEN: usize = 48;

    pub fn encode(&self) -> Bytes {
        let mut b = Vec::with_capacity(Self::LEN);
        b.put_u64(self.repo_rev.0);
        b.put_slice(&self.hash);
        b.put_u64(self.space_rev.0);
        b.into()
    }

    pub fn decode(v: &[u8]) -> anyhow::Result<WriterRow> {
        let mut r = Reader::new(v);
        let repo_rev = Tid(r.u64()?);
        let hash = r.take(32)?.try_into()?;
        let space_rev = Tid(r.u64()?);
        r.end()?;
        Ok(WriterRow { repo_rev, hash, space_rev })
    }
}

/// `sM`: a member's access.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MemberRow {
    pub read: bool,
    pub write: bool,
}

impl MemberRow {
    pub fn encode(&self) -> Bytes {
        Bytes::copy_from_slice(&[self.read as u8 | (self.write as u8) << 1])
    }

    pub fn decode(v: &[u8]) -> anyhow::Result<MemberRow> {
        match v {
            [f] if *f < 4 => Ok(MemberRow { read: f & 1 != 0, write: f & 2 != 0 }),
            _ => bail!("bad member row"),
        }
    }
}

/// `sN`: a service registered for the space's write notifications.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NotifyRow {
    pub endpoint: String,
    /// Unix microseconds.
    pub expires: u64,
}

impl NotifyRow {
    pub fn encode(&self) -> Bytes {
        let mut b = Vec::with_capacity(10 + self.endpoint.len());
        put_str(&mut b, &self.endpoint);
        b.put_u64(self.expires);
        b.into()
    }

    pub fn decode(v: &[u8]) -> anyhow::Result<NotifyRow> {
        let mut r = Reader::new(v);
        let endpoint = r.str()?.to_string();
        let expires = r.u64()?;
        r.end()?;
        Ok(NotifyRow { endpoint, expires })
    }
}

/// The policies this host implements (the baseline ones every PDS
/// supports), normalized: defaults filled in and unknown fields dropped,
/// so that what is stored is what is enforced. Serialized as on the wire.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "$type")]
pub enum Policy {
    #[serde(rename = "com.atproto.personalspace.policy")]
    Personal,
    #[serde(rename = "com.atproto.memberspace.policy", rename_all = "camelCase")]
    Member {
        public_read: bool,
        public_write: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        allowed_apps: Option<Vec<String>>,
        publish_policy: bool,
        publish_members: bool,
    },
    #[serde(rename = "com.atproto.managedspace.policy", rename_all = "camelCase")]
    Managed { managing_app: String, publish_policy: bool },
}

pub const PERSONALSPACE: &str = "com.atproto.personalspace.policy";
pub const MEMBERSPACE: &str = "com.atproto.memberspace.policy";
pub const MANAGEDSPACE: &str = "com.atproto.managedspace.policy";

/// A policy the request names that this host doesn't take.
#[derive(Debug, PartialEq, Eq)]
pub enum PolicyError {
    Unsupported(String),
    Invalid(String),
}

impl Policy {
    /// A memberspace with every flag off: only the authority and members.
    pub fn member_defaults() -> Policy {
        Policy::Member {
            public_read: false,
            public_write: false,
            allowed_apps: None,
            publish_policy: false,
            publish_members: false,
        }
    }

    /// Reference `normalizePolicy` of a policy the lexicon has checked.
    pub fn from_lex(v: &serde_json::Value) -> Result<Policy, PolicyError> {
        let flag = |k: &str| v.get(k).and_then(|b| b.as_bool()).unwrap_or(false);
        let t = v.get("$type").and_then(|t| t.as_str()).unwrap_or("");
        match t {
            PERSONALSPACE => Ok(Policy::Personal),
            MEMBERSPACE => {
                let allowed_apps = match v.get("allowedApps") {
                    None | Some(serde_json::Value::Null) => None,
                    Some(a) => Some(
                        a.as_array()
                            .and_then(|a| a.iter().map(|c| c.as_str().map(String::from)).collect::<Option<Vec<_>>>())
                            .ok_or_else(|| PolicyError::Invalid("allowedApps must be an array of strings".into()))?,
                    ),
                };
                Ok(Policy::Member {
                    public_read: flag("publicRead"),
                    public_write: flag("publicWrite"),
                    allowed_apps,
                    publish_policy: flag("publishPolicy"),
                    publish_members: flag("publishMembers"),
                })
            }
            MANAGEDSPACE => {
                let app = v.get("managingApp").and_then(|a| a.as_str()).unwrap_or("");
                let did = app.split_once('#').map_or(app, |(d, _)| d);
                if !vlatproto::syntax::valid_did(did) {
                    return Err(PolicyError::Invalid(format!(
                        "managingApp must be a DID with an optional service fragment, got: {app}"
                    )));
                }
                Ok(Policy::Managed { managing_app: app.into(), publish_policy: flag("publishPolicy") })
            }
            _ => Err(PolicyError::Unsupported(format!("Unsupported policy: {t}"))),
        }
    }

    pub fn to_lex(&self) -> serde_json::Value {
        serde_json::to_value(self).expect("policies serialize")
    }

    pub fn type_name(&self) -> &'static str {
        match self {
            Policy::Personal => PERSONALSPACE,
            Policy::Member { .. } => MEMBERSPACE,
            Policy::Managed { .. } => MANAGEDSPACE,
        }
    }

    /// Only a memberspace keeps a member list.
    pub fn is_memberspace(&self) -> bool {
        matches!(self, Policy::Member { .. })
    }

    /// Reference `isPublicRead`: only then is a credential minted without a
    /// delegation token saying who the user is.
    pub fn public_read(&self) -> bool {
        matches!(self, Policy::Member { public_read: true, .. })
    }

    pub fn publishes_policy(&self) -> bool {
        matches!(self, Policy::Member { publish_policy: true, .. } | Policy::Managed { publish_policy: true, .. })
    }

    pub fn publishes_members(&self) -> bool {
        matches!(self, Policy::Member { publish_members: true, .. })
    }

    /// Reference `isAppAuthorized`: only a memberspace restricts apps, by
    /// the attested client_id, so an app with no attestation is never one
    /// of the allowed ones.
    pub fn app_authorized(&self, client_id: Option<&str>) -> bool {
        match self {
            Policy::Member { allowed_apps: Some(allowed), .. } => {
                client_id.is_some_and(|c| allowed.iter().any(|a| a == c))
            }
            _ => true,
        }
    }
}

/// An October 1 simplespace user policy (`readPolicy`, `writePolicy`), as
/// rows written before space policies hold it.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
enum LegacyPolicy {
    Public,
    MemberList,
    #[serde(rename_all = "camelCase")]
    ManagingApp {
        managing_app: String,
    },
}

/// A simplespace `appAccess`, as those rows hold it.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
enum LegacyAppAccess {
    Open,
    AllowList { allowed: Vec<String> },
}

/// Reference `006-space-policy` `configToPolicy`: a managing app on either
/// side makes a managedspace, which asks it about reads and writes both and
/// drops any app allow-list; anything else is a memberspace. Nothing is
/// published.
fn legacy_policy(read: LegacyPolicy, write: LegacyPolicy, apps: LegacyAppAccess) -> Policy {
    let managing_app = match (&read, &write) {
        (LegacyPolicy::ManagingApp { managing_app }, _) | (_, LegacyPolicy::ManagingApp { managing_app }) => {
            Some(managing_app.clone())
        }
        _ => None,
    };
    if let Some(managing_app) = managing_app {
        return Policy::Managed { managing_app, publish_policy: false };
    }
    Policy::Member {
        public_read: matches!(read, LegacyPolicy::Public),
        public_write: matches!(write, LegacyPolicy::Public),
        allowed_apps: match apps {
            LegacyAppAccess::Open => None,
            LegacyAppAccess::AllowList { allowed } => Some(allowed),
        },
        publish_policy: false,
        publish_members: false,
    }
}

/// The simplespace config closest to `p`, written next to it so a build
/// from before space policies still reads every row (with that config's
/// meaning: it knows nothing of publishing). A personalspace is a member
/// list with no members, which admits only the authority too.
fn legacy_config(p: &Policy) -> (LegacyPolicy, LegacyPolicy, LegacyAppAccess) {
    let side = |public: bool| if public { LegacyPolicy::Public } else { LegacyPolicy::MemberList };
    match p {
        Policy::Personal => (LegacyPolicy::MemberList, LegacyPolicy::MemberList, LegacyAppAccess::Open),
        Policy::Member { public_read, public_write, allowed_apps, .. } => (
            side(*public_read),
            side(*public_write),
            match allowed_apps {
                Some(allowed) => LegacyAppAccess::AllowList { allowed: allowed.clone() },
                None => LegacyAppAccess::Open,
            },
        ),
        Policy::Managed { managing_app, .. } => (
            LegacyPolicy::ManagingApp { managing_app: managing_app.clone() },
            LegacyPolicy::ManagingApp { managing_app: managing_app.clone() },
            LegacyAppAccess::Open,
        ),
    }
}

/// `sS`: a space this account governs. A deleted one stays as a tombstone
/// (`deleted_at`), so getSpaceCredential can answer `SpaceDeleted`.
///
/// A row written before space policies holds the simplespace config
/// (`readPolicy`, `writePolicy`, `appAccess`) instead of `policy`: it
/// decodes to the policy the reference's migration gives it, and is
/// written back in this form the next time it changes. Every row carries
/// the closest simplespace config as well ([`legacy_config`]), since space
/// rows aren't behind a feature level and a rollback must still read them.
/// Its member list,
/// if it becomes a managedspace, is never consulted again (only a
/// memberspace reads one), and goes when the space changes `$type` or is
/// deleted.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", try_from = "RawSpaceRow", into = "RawSpaceRow")]
pub struct SpaceRow {
    pub uri: String,
    pub policy: Policy,
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawSpaceRow {
    uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy: Option<Policy>,
    read_policy: Option<LegacyPolicy>,
    write_policy: Option<LegacyPolicy>,
    app_access: Option<LegacyAppAccess>,
    created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    deleted_at: Option<String>,
}

impl From<SpaceRow> for RawSpaceRow {
    fn from(r: SpaceRow) -> RawSpaceRow {
        let (read, write, apps) = legacy_config(&r.policy);
        RawSpaceRow {
            uri: r.uri,
            policy: Some(r.policy),
            read_policy: Some(read),
            write_policy: Some(write),
            app_access: Some(apps),
            created_at: r.created_at,
            deleted_at: r.deleted_at,
        }
    }
}

impl TryFrom<RawSpaceRow> for SpaceRow {
    type Error = String;

    fn try_from(r: RawSpaceRow) -> Result<SpaceRow, String> {
        let policy = match (r.policy, r.read_policy, r.write_policy, r.app_access) {
            (Some(p), ..) => p,
            (None, Some(read), Some(write), Some(apps)) => legacy_policy(read, write, apps),
            _ => return Err("space row has no policy".into()),
        };
        Ok(SpaceRow { uri: r.uri, policy, created_at: r.created_at, deleted_at: r.deleted_at })
    }
}

impl SpaceRow {
    /// Before createSpace: governed with the defaults.
    pub fn defaults(uri: &str, created_at: &str) -> SpaceRow {
        SpaceRow { uri: uri.into(), policy: Policy::member_defaults(), created_at: created_at.into(), deleted_at: None }
    }

    pub fn encode(&self) -> Bytes {
        serde_json::to_vec(self).expect("space rows serialize").into()
    }

    pub fn decode(v: &[u8]) -> anyhow::Result<SpaceRow> {
        Ok(serde_json::from_slice(v)?)
    }

    pub fn live(&self) -> bool {
        self.deleted_at.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rows_roundtrip() {
        let mut hash = LtHash::default();
        hash.add("com.example.post/a/bafy");
        let h = HeadRow {
            uri: "at://did:plc:a/space/com.example.group/x".into(),
            rev: Tid(7),
            hash,
            records: 3,
            created: 9,
        };
        assert_eq!(HeadRow::decode(&h.encode()).unwrap(), h);
        assert!(HeadRow::decode(&h.encode()[..100]).is_err());
        let c = Cid::dag_cbor(b"\xa0");
        for op in [
            OpRow { action: OpAction::Create, collection: "a.b.c".into(), rkey: "r".into(), cid: Some(c), prev: None },
            OpRow {
                action: OpAction::Update,
                collection: "a.b.c".into(),
                rkey: "r".into(),
                cid: Some(c),
                prev: Some(c),
            },
            OpRow { action: OpAction::Delete, collection: "a.b.c".into(), rkey: "r".into(), cid: None, prev: Some(c) },
        ] {
            assert_eq!(OpRow::decode(&op.encode()).unwrap(), op);
        }
        let o = OutboxRow { uri: "at://x".into(), repo_rev: Tid(5), hash: [3; 32] };
        assert_eq!(OutboxRow::decode(&o.encode()).unwrap(), o);
        let n = NotifyRow { endpoint: "https://syncer.example".into(), expires: 9 };
        assert_eq!(NotifyRow::decode(&n.encode()).unwrap(), n);
        let w = WriterRow { repo_rev: Tid(1), hash: [2; 32], space_rev: Tid(3) };
        assert_eq!(WriterRow::decode(&w.encode()).unwrap(), w);
        for prev in [None, Some(Tid(4))] {
            let q = SeqRow { prev, writer: "did:plc:w".into() };
            assert_eq!(SeqRow::decode(&q.encode()).unwrap(), q);
        }
        for m in [MemberRow { read: true, write: false }, MemberRow { read: true, write: true }] {
            assert_eq!(MemberRow::decode(&m.encode()).unwrap(), m);
        }
        let s = SpaceRow::defaults("at://did:plc:a/space/com.example.group/x", "2026-10-01T00:00:00.000Z");
        assert_eq!(SpaceRow::decode(&s.encode()).unwrap(), s);
        assert_eq!(
            String::from_utf8(s.encode().to_vec()).unwrap(),
            r#"{"uri":"at://did:plc:a/space/com.example.group/x","policy":{"$type":"com.atproto.memberspace.policy","publicRead":false,"publicWrite":false,"publishPolicy":false,"publishMembers":false},"readPolicy":{"type":"member-list"},"writePolicy":{"type":"member-list"},"appAccess":{"type":"open"},"createdAt":"2026-10-01T00:00:00.000Z"}"#
        );
    }

    /// Rows written before space policies, as that version encoded them,
    /// decode to the policy the reference's `006-space-policy` gives them.
    #[test]
    fn simplespace_rows_convert() {
        let row = |read: &str, write: &str, apps: &str, deleted: &str| {
            format!(
                r#"{{"uri":"at://did:plc:a/space/com.example.group/x","readPolicy":{read},"writePolicy":{write},"appAccess":{apps},"createdAt":"2026-10-01T00:00:00.000Z"{deleted}}}"#
            )
        };
        let (member, public) = (r#"{"type":"member-list"}"#, r#"{"type":"public"}"#);
        let app = r#"{"type":"managing-app","managingApp":"did:web:forum.example#forum"}"#;
        let (open, allow) = (r#"{"type":"open"}"#, r#"{"type":"allowList","allowed":["https://app.example/cm.json"]}"#);
        let managed = Policy::Managed { managing_app: "did:web:forum.example#forum".into(), publish_policy: false };
        let ms = |public_read, public_write, apps: Option<&[&str]>| Policy::Member {
            public_read,
            public_write,
            allowed_apps: apps.map(|a| a.iter().map(|s| s.to_string()).collect()),
            publish_policy: false,
            publish_members: false,
        };
        for (read, write, apps, want) in [
            (member, member, open, ms(false, false, None)),
            (public, member, open, ms(true, false, None)),
            (member, public, open, ms(false, true, None)),
            (public, public, allow, ms(true, true, Some(&["https://app.example/cm.json"]))),
            (member, member, allow, ms(false, false, Some(&["https://app.example/cm.json"]))),
            (app, app, open, managed.clone()),
            // a managing app on one side asks it about both; the allow-list goes
            (app, public, allow, managed.clone()),
            (member, app, open, managed.clone()),
        ] {
            let got = SpaceRow::decode(row(read, write, apps, "").as_bytes()).unwrap();
            assert_eq!(got.policy, want, "{read} {write} {apps}");
            assert_eq!(got.uri, "at://did:plc:a/space/com.example.group/x");
            assert!(got.live());
            // written back in the new form, which decodes the same
            assert_eq!(SpaceRow::decode(&got.encode()).unwrap(), got);
            assert!(String::from_utf8(got.encode().to_vec()).unwrap().contains(r#""policy":"#));
        }
        let tomb = SpaceRow::decode(row(member, member, open, r#","deletedAt":"2026-10-02T00:00:00.000Z""#).as_bytes())
            .unwrap();
        assert_eq!(tomb.deleted_at.as_deref(), Some("2026-10-02T00:00:00.000Z"));
        assert!(SpaceRow::decode(br#"{"uri":"at://x","createdAt":"t"}"#).is_err(), "no policy at all");
    }

    /// The Oct 1 build's `SpaceRow` decode, frozen: every row this build
    /// writes still decodes with it, to the closest simplespace config.
    #[test]
    fn new_rows_read_as_simplespace_rows() {
        #[derive(serde::Deserialize, Debug, PartialEq)]
        #[serde(tag = "type", rename_all = "kebab-case")]
        enum OldPolicy {
            Public,
            MemberList,
            #[serde(rename_all = "camelCase")]
            ManagingApp {
                managing_app: String,
            },
        }
        #[derive(serde::Deserialize, Debug, PartialEq)]
        #[serde(tag = "type", rename_all = "camelCase")]
        enum OldAppAccess {
            Open,
            AllowList { allowed: Vec<String> },
        }
        #[derive(serde::Deserialize, Debug)]
        #[serde(rename_all = "camelCase")]
        #[allow(dead_code)]
        struct OldSpaceRow {
            uri: String,
            read_policy: OldPolicy,
            write_policy: OldPolicy,
            app_access: OldAppAccess,
            created_at: String,
            #[serde(default)]
            deleted_at: Option<String>,
        }
        let app = "did:web:forum.example#forum".to_string();
        let allowed = vec!["https://app.example/cm.json".to_string()];
        let cases = [
            (Policy::Personal, OldPolicy::MemberList, OldPolicy::MemberList, OldAppAccess::Open),
            (Policy::member_defaults(), OldPolicy::MemberList, OldPolicy::MemberList, OldAppAccess::Open),
            (
                Policy::Member {
                    public_read: true,
                    public_write: false,
                    allowed_apps: Some(allowed.clone()),
                    publish_policy: true,
                    publish_members: true,
                },
                OldPolicy::Public,
                OldPolicy::MemberList,
                OldAppAccess::AllowList { allowed: allowed.clone() },
            ),
            (
                Policy::Member {
                    public_read: false,
                    public_write: true,
                    allowed_apps: None,
                    publish_policy: false,
                    publish_members: false,
                },
                OldPolicy::MemberList,
                OldPolicy::Public,
                OldAppAccess::Open,
            ),
            (
                Policy::Managed { managing_app: app.clone(), publish_policy: true },
                OldPolicy::ManagingApp { managing_app: app.clone() },
                OldPolicy::ManagingApp { managing_app: app.clone() },
                OldAppAccess::Open,
            ),
        ];
        for (policy, read, write, apps) in cases {
            let mut row = SpaceRow::defaults("at://did:plc:a/space/com.example.group/x", "t");
            row.policy = policy.clone();
            row.deleted_at = Some("d".into());
            let bytes = row.encode();
            let old: OldSpaceRow = serde_json::from_slice(&bytes).unwrap();
            assert_eq!((&old.read_policy, &old.write_policy, &old.app_access), (&read, &write, &apps), "{policy:?}");
            assert_eq!(old.deleted_at.as_deref(), Some("d"));
            assert_eq!(SpaceRow::decode(&bytes).unwrap(), row, "the new decoder takes the policy over them");
        }
    }

    #[test]
    fn policies_normalize() {
        let p = |v: serde_json::Value| Policy::from_lex(&v);
        assert_eq!(p(serde_json::json!({"$type": PERSONALSPACE, "extra": 1})), Ok(Policy::Personal));
        assert_eq!(p(serde_json::json!({"$type": MEMBERSPACE})), Ok(Policy::member_defaults()));
        assert_eq!(
            p(serde_json::json!({"$type": MANAGEDSPACE, "managingApp": "did:web:x.example#forum", "other": true})),
            Ok(Policy::Managed { managing_app: "did:web:x.example#forum".into(), publish_policy: false })
        );
        assert!(matches!(
            p(serde_json::json!({"$type": MANAGEDSPACE, "managingApp": "nope"})),
            Err(PolicyError::Invalid(_))
        ));
        assert!(matches!(p(serde_json::json!({"$type": "com.example.policy"})), Err(PolicyError::Unsupported(_))));
        assert_eq!(
            Policy::member_defaults().to_lex(),
            serde_json::json!({"$type": MEMBERSPACE, "publicRead": false, "publicWrite": false, "publishPolicy": false, "publishMembers": false})
        );
        assert_eq!(Policy::Personal.to_lex(), serde_json::json!({"$type": PERSONALSPACE}));
    }

    #[test]
    fn key_parts() {
        let sid = crate::state::space_id("at://did:plc:a/space/com.example.group/x");
        let k = crate::state::space_outbox_key("did:plc:abc", &sid);
        assert_eq!(did_sid(&k), Some(("did:plc:abc", sid)));
        let k = crate::state::space_oplog_key("did:plc:abc", &sid, 42, 7);
        assert_eq!(oplog_position(&k), Some((Tid(42), 7)));
        assert_eq!(seq_rev(&crate::state::space_seq_key("did:plc:abc", &sid, 99)), Some(Tid(99)));
        let blob = Cid::raw(b"blob");
        let k = crate::state::space_blob_key("did:plc:abc", &sid, &blob, "com.example.post/1");
        let prefix = crate::state::space_prefix(crate::state::SPACE_BLOB_FAMILY, "did:plc:abc", &sid);
        assert_eq!(blob_ref_parts(&k[prefix.len()..]), Some((blob.to_string().as_str(), "com.example.post/1")));
        assert!(k.starts_with(&crate::state::space_blob_prefix("did:plc:abc", &sid, &blob)));
        let c = crate::state::space_blob_cid_key("did:plc:abc", &blob, &sid, "com.example.post/1");
        assert!(c.starts_with(&crate::state::space_blob_cid_prefix("did:plc:abc", &blob.to_string())));
        assert!(crate::state::is_space_key(&k) && crate::state::is_space_key(&c));
        assert!(crate::state::is_space_key(&k));
        assert!(!crate::state::is_space_key(&crate::state::repo_stats_key("did:plc:abc")));
    }
}
