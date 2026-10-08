//! The backlink index, for parity with the reference PDS's `backlink` table:
//! createRecord deletes a repo's earlier like / repost / follow / block of
//! the same subject in the new record's commit.
//!
//! `bl/{did}\0{link}` -> the rkeys (sorted, `\0`-separated) with that link.
//! One key per (collection, subject), so the no-conflict check on create is
//! one bloom-filtered point read. A record's put is derived at replay from
//! the #commit frame; removals (which need the old record) and keys holding
//! several rkeys are stored muts that follow and win. See DESIGN.md
//! "Backlinks".

use bytes::Bytes;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use vlsync_atproto::cbor::ValueRef;

/// (collection, key code, subject is `subject.uri` (an AT-URI) rather than
/// `subject` (a DID)).
const LINKED: [(&str, u8, bool); 4] = [
    ("app.bsky.feed.like", b'l', true),
    ("app.bsky.feed.repost", b'r', true),
    ("app.bsky.graph.follow", b'f', false),
    ("app.bsky.graph.block", b'b', false),
];

pub fn linked(collection: &str) -> bool {
    LINKED.iter().any(|(c, ..)| *c == collection)
}

/// Collection code ‖ subject, as the reference's `getBacklinks`: a follow
/// or block whose `subject` is a valid DID, a like or repost whose
/// `subject.uri` is a valid AT-URI, and whose `$type` is its collection.
/// The validators' verdicts are part of the segment format (replay derives
/// with them).
pub fn link(collection: &str, record: &[u8]) -> Option<Vec<u8>> {
    let &(_, code, uri) = LINKED.iter().find(|(c, ..)| *c == collection)?;
    let v = ValueRef::decode(record).ok()?;
    if v.get("$type")?.as_str()? != collection {
        return None;
    }
    let subject = v.get("subject")?;
    let s = match uri {
        true => subject.get("uri")?.as_str().filter(|s| crate::lexicon::valid_at_uri(s))?,
        false => subject.as_str().filter(|s| vlsync_atproto::syntax::valid_did(s))?,
    };
    let mut l = Vec::with_capacity(1 + s.len());
    l.push(code);
    l.extend_from_slice(s.as_bytes());
    Some(l)
}

pub fn collection_of(link: &[u8]) -> Option<&'static str> {
    let code = *link.first()?;
    LINKED.iter().find(|(_, c, _)| *c == code).map(|(c, ..)| *c)
}

/// Sorted.
pub type Rkeys = Vec<Box<str>>;

pub fn encode(rkeys: &[Box<str>]) -> Bytes {
    let mut v = Vec::with_capacity(rkeys.iter().map(|r| r.len() + 1).sum());
    for (i, r) in rkeys.iter().enumerate() {
        if i > 0 {
            v.push(0);
        }
        v.extend_from_slice(r.as_bytes());
    }
    v.into()
}

pub fn decode(v: &[u8]) -> Rkeys {
    v.split(|b| *b == 0).filter(|r| !r.is_empty()).map(|r| String::from_utf8_lossy(r).into()).collect()
}

/// The commit that wrote a cached entry (set once its state is applied);
/// None: read from durable state.
pub type Tag = Option<Arc<AtomicBool>>;

fn settled(t: &Tag) -> bool {
    t.as_ref().is_none_or(|f| f.load(Ordering::Acquire))
}

/// Collection code ‖ subject.
pub type Link = Box<[u8]>;

/// A repo worker's backlink entries beyond durable state: those its
/// in-flight commits wrote (durable state lags them) and those read for the
/// requests it is about to run. [`prune`](Self::prune) after each run leaves
/// only in-flight entries.
#[derive(Default)]
pub struct Cache {
    /// Empty = no key.
    pub vals: HashMap<Link, (Rkeys, Tag)>,
    /// The link of the record at a path (None: no record, or no link).
    pub paths: HashMap<Box<str>, (Option<Link>, Tag)>,
    /// `vals` holds the whole index (an import or account delete read it).
    pub all: bool,
}

impl Cache {
    /// Drops the entries durable state holds.
    pub fn prune(&mut self) {
        if self.vals.is_empty() && self.paths.is_empty() {
            return;
        }
        self.vals.retain(|_, (_, t)| !settled(t));
        self.paths.retain(|_, (_, t)| !settled(t));
        self.all = false;
    }

    /// Entries already held are newer (written by commits in flight) and win.
    pub fn install(&mut self, f: Fetched) {
        for (l, v) in f.vals {
            self.vals.entry(l).or_insert((v, None));
        }
        for (p, l) in f.paths {
            self.paths.entry(p).or_insert((l, None));
        }
        self.all |= f.all;
    }

    pub fn heap_bytes(&self) -> usize {
        (self.vals.len() + self.paths.len()) * 128
    }
}

#[derive(Default)]
pub struct Fetched {
    pub vals: Vec<(Link, Rkeys)>,
    pub paths: Vec<(Box<str>, Option<Link>)>,
    pub all: bool,
}

/// Reads `links`' index values, the links of the records at `paths` (and
/// those links' values), or with `all` the repo's whole index.
pub async fn fetch<R: slatedb::DbReadOps + Sync + ?Sized>(
    db: &R,
    did: &str,
    gen: u64,
    links: &[Vec<u8>],
    paths: &[String],
    all: bool,
) -> anyhow::Result<Fetched> {
    let mut out = Fetched { all, ..Default::default() };
    let mut want: Vec<Vec<u8>> = Vec::new();
    if all {
        let prefix = crate::state::backlink_prefix(did, gen);
        let mut it = db.scan(prefix.clone()..vlsync_store::keys::prefix_end(&prefix)).await?;
        while let Some(kv) = it.next().await? {
            out.vals.push((kv.key[prefix.len()..].into(), decode(&kv.value)));
        }
    } else {
        want.extend(links.iter().cloned());
    }
    for p in paths {
        let l = match db.get(crate::state::record_key(did, gen, p)).await? {
            Some(v) => {
                let (_, bytes) = crate::state::decode_record_value(&v)?;
                link(crate::worker::collection_of(p), &bytes)
            }
            None => None,
        };
        if let Some(l) = l.as_ref().filter(|_| !all) {
            want.push(l.clone());
        }
        out.paths.push((p.as_str().into(), l.map(Into::into)));
    }
    want.sort();
    want.dedup();
    for l in want {
        let v = db.get(crate::state::backlink_key(did, gen, &l)).await?;
        out.vals.push((l.into(), v.map(|v| decode(&v)).unwrap_or_default()));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(j: serde_json::Value) -> Vec<u8> {
        vlsync_atproto::cbor::Value::from_json(&j).unwrap().to_cbor()
    }

    #[test]
    fn links_as_the_reference() {
        let did = "did:plc:abcdefghijklmnopqrstuvwx";
        let post = format!("at://{did}/app.bsky.feed.post/3jzfcijpj2z2a");
        let like = rec(
            serde_json::json!({"$type": "app.bsky.feed.like", "subject": {"uri": post, "cid": "bafyreie5737gdxlw5i64vzichcalba3z2v5n6icifvx5xytvske7mr3hpm"}, "createdAt": "2026-10-01T00:00:00.000Z"}),
        );
        assert_eq!(link("app.bsky.feed.like", &like), Some([b"l", post.as_bytes()].concat()));
        // the record's $type must be its collection
        assert_eq!(link("app.bsky.feed.repost", &like), None);
        let follow = rec(
            serde_json::json!({"$type": "app.bsky.graph.follow", "subject": did, "createdAt": "2026-10-01T00:00:00.000Z"}),
        );
        assert_eq!(link("app.bsky.graph.follow", &follow), Some([b"f", did.as_bytes()].concat()));
        let bad = rec(serde_json::json!({"$type": "app.bsky.graph.block", "subject": "not a did"}));
        assert_eq!(link("app.bsky.graph.block", &bad), None);
        let bad = rec(serde_json::json!({"$type": "app.bsky.feed.like", "subject": {"uri": "https://example.com"}}));
        assert_eq!(link("app.bsky.feed.like", &bad), None);
        assert_eq!(link("app.bsky.feed.post", &follow), None);
        assert_eq!(collection_of(b"fdid:plc:x"), Some("app.bsky.graph.follow"));
        let r: Rkeys = vec!["a".into(), "b".into()];
        assert_eq!(decode(&encode(&r)), r);
        assert_eq!(&encode(&r[..1])[..], b"a");
        assert!(decode(b"").is_empty());
    }
}
