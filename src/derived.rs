//! A #commit's state mutations rebuilt from its firehose frame: what a log
//! segment leaves out of an entry it marks derived (vlsync-store's segment
//! format), and what replay puts back.

use bytes::Bytes;
use vlsync_store::segment::{self, LogObject, Mutation};
use vlsync_store::slots::ShardId;

/// A stored log object with every entry's muts, derived ones included.
pub fn parse(data: Bytes, shard: Option<ShardId>) -> anyhow::Result<LogObject> {
    segment::parse_derived(data, shard, derive_commit_muts_n)
}

/// The state mutations of a #commit, rebuilt from its frame: for each op,
/// the record CID index keys, the record or its delete, and the record's
/// backlink put; then the head. Exactly what the repo worker writes for a
/// commit, in the same order (checked in debug builds). `gen` is the repo's
/// generation, which the frame doesn't carry.
pub fn derive_commit_muts(frame: &[u8], gen: u64) -> anyhow::Result<Vec<Mutation>> {
    derive(frame, None, gen)
}

/// The `n` muts an entry derives from its #commit frame: those of
/// [`derive_commit_muts`], then (when `n` is larger) the `M/` puts of the
/// commit's interior MST nodes in CAR order.
pub fn derive_commit_muts_n(frame: &[u8], n: usize, gen: u64) -> anyhow::Result<Vec<Mutation>> {
    let muts = derive(frame, Some(n), gen)?;
    anyhow::ensure!(muts.len() == n, "{} muts derived from the #commit frame, {n} expected", muts.len());
    Ok(muts)
}

fn derive(frame: &[u8], want: Option<usize>, gen: u64) -> anyhow::Result<Vec<Mutation>> {
    // borrowed decoding: replay runs this for every #commit it applies
    use crate::state;
    use vlatproto::cbor::ValueRef as Value;
    use vlatproto::cid::Cid;
    let (header, n) = Value::decode_prefix(frame)?;
    anyhow::ensure!(header.get("t").and_then(Value::as_str) == Some("#commit"), "not a #commit frame");
    let body = Value::decode(&frame[n..])?;
    let text = |k: &str| body.get(k).and_then(Value::as_str).ok_or_else(|| anyhow::anyhow!("#commit without {k}"));
    let link = |v: Option<&Value>| match v {
        Some(Value::Link(c)) => Some(*c),
        _ => None,
    };
    let did = text("repo")?;
    let rev = vlatproto::tid::Tid::parse(text("rev")?).ok_or_else(|| anyhow::anyhow!("bad #commit rev"))?;
    let commit = link(body.get("commit")).ok_or_else(|| anyhow::anyhow!("#commit without commit"))?;
    let Some(Value::Bytes(car)) = body.get("blocks") else { anyhow::bail!("#commit without blocks") };
    let (_, blocks) = vlatproto::car::read_car(car)?;
    let block = |c: &Cid| {
        blocks
            .iter()
            .find(|(b, _)| b == c)
            .map(|(_, d)| *d)
            .ok_or_else(|| anyhow::anyhow!("#commit CAR lacks block {c}"))
    };
    let Some(Value::Array(ops)) = body.get("ops") else { anyhow::bail!("#commit without ops") };
    let mut muts = Vec::with_capacity(ops.len() * 3 + 1);
    for op in ops {
        let path = op.get("path").and_then(Value::as_str).ok_or_else(|| anyhow::anyhow!("op without path"))?;
        let (prev, new) = (link(op.get("prev")), link(op.get("cid")));
        if let Some(p) = &prev {
            muts.push(Mutation { key: state::record_cid_key(did, gen, p, path).into(), val: None });
        }
        if let Some(c) = &new {
            muts.push(Mutation { key: state::record_cid_key(did, gen, c, path).into(), val: Some(Bytes::new()) });
        }
        let key = Bytes::from(state::record_key(did, gen, path));
        muts.push(match &new {
            Some(c) => Mutation { key, val: Some(state::record_value(c, rev.0, block(c)?)) },
            None => Mutation { key, val: None },
        });
        // the record's backlink as if its subject had no other record (the
        // stored muts that follow correct the rest: crate::backlinks)
        if let Some(c) = &new {
            let coll = crate::worker::collection_of(path);
            if let Some(l) = crate::backlinks::link(coll, block(c)?) {
                let rkey = path.split_once('/').map_or(path, |(_, r)| r);
                muts.push(Mutation {
                    key: state::backlink_key(did, gen, &l).into(),
                    val: Some(Bytes::copy_from_slice(rkey.as_bytes())),
                });
            }
        }
    }
    let commit_block = block(&commit)?;
    let data =
        link(Value::decode(commit_block)?.get("data")).ok_or_else(|| anyhow::anyhow!("commit block without data"))?;
    let head = state::Head { commit, data, rev, commit_block: Bytes::copy_from_slice(commit_block) };
    muts.push(Mutation { key: state::head_key(did).into(), val: Some(head.encode()) });
    if want.is_some_and(|n| n > muts.len()) {
        for (c, b) in crate::mst_lazy::persisted_blocks(&data, &blocks, 1)? {
            muts.push(Mutation { key: state::mst_node_key(did, gen, &c).into(), val: Some(Bytes::copy_from_slice(b)) });
        }
    }
    Ok(muts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vlsync_store::segment::SegmentBuilder;

    /// A builder made `for_log` seals in place (same bytes as prepending the
    /// header), and an entry's derived muts are left out of the segment and
    /// rebuilt from its #commit frame on parse.
    #[test]
    fn seal_in_place_and_derived_muts() {
        use vlatproto::cid::Cid;
        let did = "did:plc:abc";
        let rec = vlatproto::cid::Cid::dag_cbor(b"\xa1aa\x01");
        let mut rec_block = Vec::new();
        rec_block.extend_from_slice(b"\xa1aa\x01");
        let mut commit_block = Vec::new();
        vlatproto::cbor::Value::Map(vec![
            ("did".into(), vlatproto::cbor::Value::Text(did.into())),
            ("data".into(), vlatproto::cbor::Value::Link(rec)),
        ])
        .encode(&mut commit_block);
        let commit = Cid::dag_cbor(&commit_block);
        let mut car = Vec::new();
        vlatproto::car::write_header(&mut car, &commit);
        vlatproto::car::write_block(&mut car, &commit, &commit_block);
        vlatproto::car::write_block(&mut car, &rec, &rec_block);
        let rev = vlatproto::tid::Tid::parse("3l3qo2vutsw2b").unwrap();
        let ops = [vlatproto::events::RepoOp {
            action: "update",
            path: "app.bsky.feed.post/1",
            cid: Some(rec),
            prev: Some(commit),
        }];
        let frame = vlatproto::events::commit_frame(&vlatproto::events::CommitFrame {
            repo: did,
            rev: &rev.to_string(),
            since: None,
            commit,
            prev_data: None,
            blocks: &car,
            ops: &ops,
            time: "2026-10-01T00:00:00.000Z",
        });
        let mut bytes = Vec::new();
        frame.finish(5, &mut bytes);
        let derived = derive_commit_muts(&bytes, 0).unwrap();
        let keys: Vec<&[u8]> = derived.iter().map(|m| &vlsync_store::keys::key_body(&m.key)[..2]).collect();
        assert_eq!(keys, vec![b"c/" as &[u8], b"c/", b"R/", b"h/"]);
        assert_eq!(derived[2].val.as_deref(), Some(&crate::state::record_value(&rec, rev.0, &rec_block)[..]));
        let head = crate::state::Head::decode(derived[3].val.as_ref().unwrap()).unwrap();
        assert_eq!(
            (head.commit, head.data, head.rev.0, &head.commit_block[..]),
            (commit, rec, rev.0, &commit_block[..])
        );

        let extra = Mutation { key: Bytes::from_static(b"C/x"), val: Some(Bytes::new()) };
        let mut all = derived.clone();
        all.push(extra);
        for in_place in [false, true] {
            let mut b = if in_place { SegmentBuilder::for_log("L") } else { SegmentBuilder::new() };
            let r = b.push_derived(5, ShardId(1), 2, |o| frame.finish(5, o), &all, derived.len(), 0);
            b.push(6, ShardId(1), 2, |o| o.extend_from_slice(b"plain"), &all[..1]);
            let level = b.level();
            let obj = b.seal("L", 9, 9);
            let off = if in_place { 0 } else { segment::header_len("L", level) };
            assert_eq!(&obj[r.start + off..r.end + off], &bytes[..]);
            let LogObject::Segment(h, entries) = parse(Bytes::from(obj.clone()), None).unwrap() else { panic!() };
            assert_eq!((h.ordinal, h.count), (9, 2));
            assert_eq!(entries[0].muts.len(), all.len(), "derived + stored");
            for (a, b) in entries[0].muts.iter().zip(&all) {
                assert!(a.key == b.key && a.val == b.val);
            }
            assert_eq!(entries[1].muts.len(), 1);
            // the derived muts aren't stored: the record and commit blocks
            // appear once (in the frame's CAR)
            let n = obj.windows(commit_block.len()).filter(|w| *w == &commit_block[..]).count();
            assert_eq!(n, 1);
        }
    }

    /// Replay derives a commit's `bl/` put with the *replaying* binary's
    /// validators (`backlinks::link` -> `lexicon::valid_at_uri`,
    /// `syntax::valid_did`), so their verdicts are part of the segment
    /// format at its level (DESIGN.md "Rolling upgrades", derived muts): a
    /// verdict that changes would make a replayed index differ from the one
    /// the writer built. This table freezes them on the edge cases; a change
    /// here needs a new feature level that gates the new verdicts.
    #[test]
    fn derivation_validator_verdicts_are_frozen() {
        use vlatproto::cbor::Value;
        let rec = |coll: &str, subject: Value| {
            let mut m = vec![("$type".to_string(), Value::Text(coll.into())), ("subject".to_string(), subject)];
            m.sort_by(|a, b| vlatproto::cbor::key_cmp(&a.0, &b.0));
            Value::Map(m).to_cbor()
        };
        let uri = |u: &str| {
            Value::Map(vec![
                ("cid".into(), Value::Text("bafyreie5cvv4h45feadgeuwhbcutmh6t2ceseocckahdoe6uat64zmz454".into())),
                ("uri".into(), Value::Text(u.into())),
            ])
        };
        let long_did = format!("did:plc:{}", "a".repeat(2040));
        let longer_did = format!("did:plc:{}", "a".repeat(2041));
        let dids: Vec<(&str, bool)> = vec![
            ("did:plc:abc", true),
            ("did:web:example.com", true),
            ("did:web:localhost%3A8080", true),
            ("did:PLC:abc", false),
            ("did:plc:", false),
            ("did:plc:abc:", false),
            ("did:plc:abc#frag", false),
            ("did:plc:abc%", false),
            ("did:plc:abc%zz", true),
            (" did:plc:abc", false),
            ("did:plc:abc\n", false),
            ("did:plc:a.b-c_d:e", true),
            ("did:plc:é", false),
            (&long_did, true),
            (&longer_did, false),
            ("DID:plc:abc", false),
        ];
        for (d, want) in &dids {
            let got = crate::backlinks::link(
                "app.bsky.graph.follow",
                &rec("app.bsky.graph.follow", Value::Text(d.to_string())),
            );
            assert_eq!(got.is_some(), *want, "follow {d:?}");
        }
        let uris: Vec<(&str, bool)> = vec![
            ("at://did:plc:abc/app.bsky.feed.post/3k", true),
            ("at://did:plc:abc", true),
            ("at://did:plc:abc/app.bsky.feed.post", true),
            ("at://alice.test/app.bsky.feed.post/3k", true),
            ("at://did:plc:abc/app.bsky.feed.post/", false),
            ("at://did:plc:abc/app.bsky.feed.post/3k#frag", false),
            ("at://did:plc:abc/app.bsky.feed.post/3k?q=1", false),
            ("at://did:plc:abc/notnsid/3k", false),
            ("at://did:plc:abc/app.bsky.feed.post/3k/extra", false),
            ("AT://did:plc:abc/app.bsky.feed.post/3k", false),
            ("https://example.com", false),
            ("at://", false),
            ("at://did:plc:abc//3k", false),
        ];
        for (u, want) in &uris {
            let got = crate::backlinks::link("app.bsky.feed.like", &rec("app.bsky.feed.like", uri(u)));
            assert_eq!(got.is_some(), *want, "like {u:?}");
        }
        // shape: wrong $type, non-string subject, a like's bare-string subject
        assert!(crate::backlinks::link(
            "app.bsky.graph.follow",
            &rec("app.bsky.graph.block", Value::Text("did:plc:abc".into()))
        )
        .is_none());
        assert!(crate::backlinks::link("app.bsky.graph.follow", &rec("app.bsky.graph.follow", Value::Int(1))).is_none());
        assert!(crate::backlinks::link(
            "app.bsky.feed.like",
            &rec("app.bsky.feed.like", Value::Text("at://did:plc:abc".into()))
        )
        .is_none());
        assert_eq!(
            crate::backlinks::link(
                "app.bsky.feed.repost",
                &rec("app.bsky.feed.repost", uri("at://did:plc:abc/app.bsky.feed.post/3k"))
            )
            .as_deref(),
            Some(&b"rat://did:plc:abc/app.bsky.feed.post/3k"[..])
        );
    }
}
