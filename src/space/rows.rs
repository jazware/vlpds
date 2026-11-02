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

pub const PERSONAL_POLICY: &str = "com.atproto.personalspace.policy";
pub const MEMBER_POLICY: &str = "com.atproto.memberspace.policy";
pub const MANAGED_POLICY: &str = "com.atproto.managedspace.policy";

/// A space's policy (reference `space-policy/policy.ts`): the baseline
/// policies every PDS supports, with their defaults filled in, so what is
/// stored is what is enforced. Serialized, it is the Lexicon object itself
/// (`$type` and its fields), as getSpace returns it and the published
/// `com.atproto.space.policy` record carries it.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "$type")]
pub enum SpacePolicy {
    /// Only the authority reads, and only it writes.
    #[serde(rename = "com.atproto.personalspace.policy")]
    Personal,
    #[serde(rename = "com.atproto.memberspace.policy", rename_all = "camelCase")]
    Member {
        #[serde(default)]
        public_read: bool,
        #[serde(default)]
        public_write: bool,
        /// Reads only by these attested `client_id`s; None: any app.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        allowed_apps: Option<Vec<String>>,
        #[serde(default)]
        publish_policy: bool,
        #[serde(default)]
        publish_members: bool,
    },
    /// Every user decision, read and write, is the managing app's.
    #[serde(rename = "com.atproto.managedspace.policy", rename_all = "camelCase")]
    Managed {
        managing_app: String,
        #[serde(default)]
        publish_policy: bool,
    },
}

impl SpacePolicy {
    /// What a space has before createSpace (its authority wrote first): a
    /// member space with no members, so only the authority gets in.
    pub fn default_member() -> SpacePolicy {
        SpacePolicy::Member {
            public_read: false,
            public_write: false,
            allowed_apps: None,
            publish_policy: false,
            publish_members: false,
        }
    }

    pub fn type_name(&self) -> &'static str {
        match self {
            SpacePolicy::Personal => PERSONAL_POLICY,
            SpacePolicy::Member { .. } => MEMBER_POLICY,
            SpacePolicy::Managed { .. } => MANAGED_POLICY,
        }
    }

    pub fn is_member(&self) -> bool {
        matches!(self, SpacePolicy::Member { .. })
    }

    /// Any user may read: the only way to a credential without a
    /// delegation token.
    pub fn public_read(&self) -> bool {
        matches!(self, SpacePolicy::Member { public_read: true, .. })
    }

    pub fn publishes_policy(&self) -> bool {
        matches!(
            self,
            SpacePolicy::Member { publish_policy: true, .. } | SpacePolicy::Managed { publish_policy: true, .. }
        )
    }

    pub fn publishes_members(&self) -> bool {
        matches!(self, SpacePolicy::Member { publish_members: true, .. })
    }

    /// Reference `isAppAuthorized`: only a member space restricts apps, by
    /// the attested client, so an app with no attestation is never allowed.
    pub fn app_authorized(&self, client_id: Option<&str>) -> bool {
        match self {
            SpacePolicy::Member { allowed_apps: Some(allowed), .. } => {
                client_id.is_some_and(|c| allowed.iter().any(|a| a == c))
            }
            _ => true,
        }
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).expect("policies serialize")
    }
}

/// The October 22 simplespace configuration, the `sS` row's level 1 form:
/// read and converted (reference actor store migration `006-space-policy`),
/// and still written for every policy it can say exactly (see
/// [`SpaceRow::encode`]).
mod legacy {
    #[derive(serde::Deserialize, serde::Serialize)]
    #[serde(tag = "type", rename_all = "kebab-case")]
    pub enum Policy {
        Public,
        MemberList,
        #[serde(rename_all = "camelCase")]
        ManagingApp {
            managing_app: String,
        },
    }

    #[derive(serde::Deserialize, serde::Serialize)]
    #[serde(tag = "type", rename_all = "camelCase")]
    pub enum AppAccess {
        Open,
        AllowList { allowed: Vec<String> },
    }

    /// A managing app on either side makes a managed space (any allow-list
    /// dropped); otherwise a member space, public on the sides that were.
    pub fn convert(read: Policy, write: Policy, apps: AppAccess) -> super::SpacePolicy {
        let app = |p: &Policy| match p {
            Policy::ManagingApp { managing_app } => Some(managing_app.clone()),
            _ => None,
        };
        if let Some(managing_app) = app(&read).or_else(|| app(&write)) {
            return super::SpacePolicy::Managed { managing_app, publish_policy: false };
        }
        super::SpacePolicy::Member {
            public_read: matches!(read, Policy::Public),
            public_write: matches!(write, Policy::Public),
            allowed_apps: match apps {
                AppAccess::AllowList { allowed } => Some(allowed),
                AppAccess::Open => None,
            },
            publish_policy: false,
            publish_members: false,
        }
    }

    /// The level 1 configuration that converts back to exactly `p`, if
    /// there is one: a member space that publishes nothing, or a managed
    /// space that doesn't publish its policy. A personal space, and
    /// anything published, has none.
    pub fn of(p: &super::SpacePolicy) -> Option<(Policy, Policy, AppAccess)> {
        use super::SpacePolicy as P;
        let side = |public: bool| if public { Policy::Public } else { Policy::MemberList };
        match p {
            P::Member { public_read, public_write, allowed_apps, publish_policy: false, publish_members: false } => {
                let apps = match allowed_apps {
                    Some(a) => AppAccess::AllowList { allowed: a.clone() },
                    None => AppAccess::Open,
                };
                Some((side(*public_read), side(*public_write), apps))
            }
            P::Managed { managing_app, publish_policy: false } => Some((
                Policy::ManagingApp { managing_app: managing_app.clone() },
                Policy::ManagingApp { managing_app: managing_app.clone() },
                AppAccess::Open,
            )),
            _ => None,
        }
    }

    /// The level 1 row, field for field.
    #[derive(serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct Row<'a> {
        pub uri: &'a str,
        pub read_policy: Policy,
        pub write_policy: Policy,
        pub app_access: AppAccess,
        pub created_at: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub deleted_at: Option<&'a str>,
    }
}

/// `sS`: a space this account governs. A deleted one stays as a tombstone
/// (`deleted_at`), so getSpaceCredential can answer `SpaceDeleted`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SpaceRow {
    pub uri: String,
    pub policy: SpacePolicy,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<String>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoredSpaceRow {
    uri: String,
    #[serde(default)]
    policy: Option<SpacePolicy>,
    #[serde(default)]
    read_policy: Option<legacy::Policy>,
    #[serde(default)]
    write_policy: Option<legacy::Policy>,
    #[serde(default)]
    app_access: Option<legacy::AppAccess>,
    created_at: String,
    #[serde(default)]
    deleted_at: Option<String>,
}

impl SpaceRow {
    /// Before createSpace: governed with the defaults.
    pub fn defaults(uri: &str, created_at: &str) -> SpaceRow {
        SpaceRow {
            uri: uri.into(),
            policy: SpacePolicy::default_member(),
            created_at: created_at.into(),
            deleted_at: None,
        }
    }

    /// The level 1 form (`readPolicy`, `writePolicy`, `appAccess`) for a
    /// policy it says exactly, so those rows stay byte for byte what builds
    /// before the October 29 alpha write and read; the `policy` form only
    /// for a personal space or a published configuration, which no earlier
    /// build can read (Spaces sits outside the feature levels:
    /// docs/operations/upgrades.md).
    pub fn encode(&self) -> Bytes {
        let v = match legacy::of(&self.policy) {
            Some((read_policy, write_policy, app_access)) => serde_json::to_vec(&legacy::Row {
                uri: &self.uri,
                read_policy,
                write_policy,
                app_access,
                created_at: &self.created_at,
                deleted_at: self.deleted_at.as_deref(),
            }),
            None => serde_json::to_vec(self),
        };
        v.expect("space rows serialize").into()
    }

    /// Either form decodes; the level 1 form as its converted policy.
    pub fn decode(v: &[u8]) -> anyhow::Result<SpaceRow> {
        let r: StoredSpaceRow = serde_json::from_slice(v)?;
        let policy = match (r.policy, r.read_policy, r.write_policy, r.app_access) {
            (Some(p), ..) => p,
            (None, Some(read), Some(write), apps) => {
                legacy::convert(read, write, apps.unwrap_or(legacy::AppAccess::Open))
            }
            _ => bail!("space row has no policy"),
        };
        Ok(SpaceRow { uri: r.uri, policy, created_at: r.created_at, deleted_at: r.deleted_at })
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
            r#"{"uri":"at://did:plc:a/space/com.example.group/x","readPolicy":{"type":"member-list"},"writePolicy":{"type":"member-list"},"appAccess":{"type":"open"},"createdAt":"2026-10-01T00:00:00.000Z"}"#
        );
        // what level 1 can't say is written in the new form, and both read back
        let personal = SpaceRow { policy: SpacePolicy::Personal, ..s.clone() };
        assert_eq!(
            String::from_utf8(personal.encode().to_vec()).unwrap(),
            r#"{"uri":"at://did:plc:a/space/com.example.group/x","policy":{"$type":"com.atproto.personalspace.policy"},"createdAt":"2026-10-01T00:00:00.000Z"}"#
        );
        assert_eq!(SpaceRow::decode(&personal.encode()).unwrap(), personal);
        for policy in [
            SpacePolicy::Member {
                public_read: true,
                public_write: false,
                allowed_apps: Some(vec!["https://a.example/c.json".into()]),
                publish_policy: false,
                publish_members: false,
            },
            SpacePolicy::Member {
                public_read: false,
                public_write: false,
                allowed_apps: None,
                publish_policy: false,
                publish_members: true,
            },
            SpacePolicy::Managed { managing_app: "did:web:a.example#x".into(), publish_policy: false },
            SpacePolicy::Managed { managing_app: "did:web:a.example#x".into(), publish_policy: true },
        ] {
            let r = SpaceRow { policy, deleted_at: Some("d".into()), ..s.clone() };
            assert_eq!(SpaceRow::decode(&r.encode()).unwrap(), r);
        }
    }

    /// Rows from before the October 29 alpha convert as the reference's
    /// `006-space-policy` migration converts them.
    #[test]
    fn simplespace_rows_convert() {
        let row = |read: &str, write: &str, apps: &str| {
            let v = format!(
                r#"{{"uri":"at://did:plc:a/space/x.y.z/k","readPolicy":{read},"writePolicy":{write},"appAccess":{apps},"createdAt":"t","deletedAt":"d"}}"#
            );
            SpaceRow::decode(v.as_bytes()).unwrap()
        };
        let (public, list) = (r#"{"type":"public"}"#, r#"{"type":"member-list"}"#);
        let app = r#"{"type":"managing-app","managingApp":"did:web:app.example#forum"}"#;
        let (open, allow) =
            (r#"{"type":"open"}"#, r#"{"type":"allowList","allowed":["https://app.example/client.json"]}"#);
        let managed = SpacePolicy::Managed { managing_app: "did:web:app.example#forum".into(), publish_policy: false };
        assert_eq!(row(app, list, allow).policy, managed);
        assert_eq!(row(public, app, open).policy, managed);
        let r = row(public, list, allow);
        assert_eq!(
            r.policy,
            SpacePolicy::Member {
                public_read: true,
                public_write: false,
                allowed_apps: Some(vec!["https://app.example/client.json".into()]),
                publish_policy: false,
                publish_members: false,
            }
        );
        assert_eq!(r.deleted_at.as_deref(), Some("d"));
        assert_eq!(
            row(list, public, open).policy,
            SpacePolicy::Member {
                public_read: false,
                public_write: true,
                allowed_apps: None,
                publish_policy: false,
                publish_members: false,
            }
        );
        // and written back as it was read
        assert_eq!(SpaceRow::decode(&r.encode()).unwrap(), r);
    }

    #[test]
    fn policies_are_their_lexicon_objects() {
        for v in [
            serde_json::json!({"$type": PERSONAL_POLICY}),
            serde_json::json!({"$type": MEMBER_POLICY, "publicRead": true, "publicWrite": false, "allowedApps": ["a"], "publishPolicy": true, "publishMembers": false}),
            serde_json::json!({"$type": MANAGED_POLICY, "managingApp": "did:web:x#y", "publishPolicy": false}),
        ] {
            let p: SpacePolicy = serde_json::from_value(v.clone()).unwrap();
            assert_eq!(p.to_json(), v);
        }
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
