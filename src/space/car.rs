//! space.getRepo's export (reference `serializeRepo`) in two passes over one
//! snapshot, so the repo is never buffered. Pass 1 reads every path and CID
//! ([`Entries`]); the encoder then knows its whole prelude (for the CAR, the
//! header naming the index's CID). Pass 2 reads the record blocks in the
//! encoder's [`RepoEncoder::order`], one range scan per run.
//!
//! The 2-root CAR puts its record blocks in the index's canonical dag-cbor
//! key order (by length, then bytes), which isn't `sR`'s bytewise order. A
//! run is a stretch of same-length paths in bytewise order; sorting the
//! runs by length gives the canonical order, and a space's rkeys are mostly
//! one length per collection (TIDs), so there are few runs. STAR (proposals
//! #114) is bytewise with no index: one run, and a second encoder.

use sha2::{Digest, Sha256};
use std::ops::Range;
use vlsync_atproto::cbor;
use vlsync_atproto::cid::Cid;

/// A space repo's paths and CIDs in `sR`'s bytewise order, packed.
#[derive(Default)]
pub struct Entries {
    paths: Vec<u8>,
    ends: Vec<u32>,
    cids: Vec<Cid>,
}

impl Entries {
    /// `path` must sort after every path pushed before it.
    pub fn push(&mut self, path: &str, cid: Cid) {
        debug_assert!(self.is_empty() || self.path(self.len() - 1).as_bytes() < path.as_bytes());
        self.paths.extend_from_slice(path.as_bytes());
        self.ends.push(self.paths.len() as u32);
        self.cids.push(cid);
    }

    pub fn len(&self) -> usize {
        self.cids.len()
    }

    pub fn is_empty(&self) -> bool {
        self.cids.is_empty()
    }

    fn span(&self, i: usize) -> Range<usize> {
        let start = if i == 0 { 0 } else { self.ends[i - 1] as usize };
        start..self.ends[i] as usize
    }

    pub fn path(&self, i: usize) -> &str {
        std::str::from_utf8(&self.paths[self.span(i)]).unwrap_or_default()
    }

    pub fn cid(&self, i: usize) -> &Cid {
        &self.cids[i]
    }

    fn path_len(&self, i: usize) -> usize {
        self.span(i).len()
    }

    pub fn heap_bytes(&self) -> usize {
        self.paths.capacity() + self.ends.capacity() * 4 + self.cids.capacity() * std::mem::size_of::<Cid>()
    }
}

/// The canonical dag-cbor key order of `e` as runs of its bytewise order.
pub fn canonical_runs(e: &Entries) -> Vec<Range<usize>> {
    let mut runs = Vec::new();
    let mut start = 0;
    for i in 1..=e.len() {
        if i == e.len() || e.path_len(i) != e.path_len(start) {
            runs.push(start..i);
            start = i;
        }
    }
    // stable: same-length runs stay in bytewise order
    runs.sort_by_key(|r| e.path_len(r.start));
    runs
}

/// A space repo export format.
pub trait RepoEncoder<'a>: Send {
    fn content_type(&self) -> &'static str;
    /// The order record blocks go out in, as runs of `entries`.
    fn order(&self, entries: &Entries) -> Vec<Range<usize>>;
    /// Pass 1 is done: `entries` and the `order` from [`Self::order`].
    fn begin(&mut self, entries: &'a Entries, order: &'a [Range<usize>]);
    /// Appends the next part of what precedes the record blocks to `out`,
    /// stopping once `out` holds `max` bytes; false when there's no more.
    fn prelude(&mut self, out: &mut Vec<u8>, max: usize) -> bool;
    fn record(&mut self, cid: &Cid, bytes: &[u8], out: &mut Vec<u8>);
}

/// The reference's 2-root CAR: roots = the signed commit and the index
/// (path -> CID), then the commit, the index, and one block per record in
/// the index's order.
pub struct Car<'a> {
    commit: Vec<u8>,
    entries: Option<&'a Entries>,
    order: &'a [Range<usize>],
    index_cid: Option<Cid>,
    index_len: usize,
    /// The prelude's position: before the index's entries (None), then the
    /// next (run, entry).
    at: Option<(usize, usize)>,
}

impl<'a> Car<'a> {
    /// `commit`: the signed commit's dag-cbor block.
    pub fn new(commit: Vec<u8>) -> Car<'a> {
        Car { commit, entries: None, order: &[], index_cid: None, index_len: 0, at: None }
    }

    fn index_entries(&self, from: (usize, usize), out: &mut Vec<u8>, max: usize) -> Option<(usize, usize)> {
        let e = self.entries.expect("begun");
        let (mut r, mut i) = from;
        while r < self.order.len() {
            let run = &self.order[r];
            while run.start + i < run.end {
                if out.len() >= max {
                    return Some((r, i));
                }
                cbor::write_text(out, e.path(run.start + i));
                cbor::write_cid(out, e.cid(run.start + i));
                i += 1;
            }
            (r, i) = (r + 1, 0);
        }
        None
    }

    /// The index block's bytes as one buffer (tests).
    #[cfg(test)]
    fn index_block(&self) -> Vec<u8> {
        let mut out = Vec::new();
        cbor::write_map_head(&mut out, self.entries.expect("begun").len());
        self.index_entries((0, 0), &mut out, usize::MAX);
        out
    }
}

const HASH_CHUNK: usize = 64 << 10;

impl<'a> RepoEncoder<'a> for Car<'a> {
    fn content_type(&self) -> &'static str {
        "application/vnd.ipld.car"
    }

    fn order(&self, entries: &Entries) -> Vec<Range<usize>> {
        canonical_runs(entries)
    }

    fn begin(&mut self, entries: &'a Entries, order: &'a [Range<usize>]) {
        self.entries = Some(entries);
        self.order = order;
        // the index's CID is in the header: hashed now, encoded again as it
        // goes out, so its bytes are never all held
        let mut h = Sha256::new();
        let mut buf = Vec::with_capacity(HASH_CHUNK + 1024);
        cbor::write_map_head(&mut buf, entries.len());
        let mut at = Some((0, 0));
        while let Some(from) = at {
            at = self.index_entries(from, &mut buf, HASH_CHUNK);
            h.update(&buf);
            self.index_len += buf.len();
            buf.clear();
        }
        self.index_cid = Some(Cid { codec: vlsync_atproto::cid::CODEC_DAG_CBOR, digest: h.finalize().into() });
    }

    fn prelude(&mut self, out: &mut Vec<u8>, max: usize) -> bool {
        let index_cid = self.index_cid.expect("begun");
        let from = match self.at {
            Some(at) => at,
            None => {
                let commit_cid = Cid::dag_cbor(&self.commit);
                let mut h = Vec::with_capacity(96);
                cbor::write_map_head(&mut h, 2);
                cbor::write_text(&mut h, "roots");
                cbor::write_array_head(&mut h, 2);
                cbor::write_cid(&mut h, &commit_cid);
                cbor::write_cid(&mut h, &index_cid);
                cbor::write_text(&mut h, "version");
                cbor::write_uint(&mut h, 1);
                vlsync_atproto::car::write_varint(out, h.len() as u64);
                out.extend_from_slice(&h);
                vlsync_atproto::car::write_block(out, &commit_cid, &self.commit);
                let cid = index_cid.to_bytes();
                vlsync_atproto::car::write_varint(out, (cid.len() + self.index_len) as u64);
                out.extend_from_slice(&cid);
                cbor::write_map_head(out, self.entries.expect("begun").len());
                (0, 0)
            }
        };
        self.at = self.index_entries(from, out, max);
        self.at.is_some()
    }

    fn record(&mut self, cid: &Cid, bytes: &[u8], out: &mut Vec<u8>) {
        vlsync_atproto::car::write_block(out, cid, bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries(paths: &[&str]) -> Entries {
        let mut sorted: Vec<&str> = paths.to_vec();
        sorted.sort();
        let mut e = Entries::default();
        for p in sorted {
            e.push(p, Cid::dag_cbor(p.as_bytes()));
        }
        e
    }

    fn flat(e: &Entries, runs: &[Range<usize>]) -> Vec<String> {
        runs.iter().flat_map(|r| r.clone()).map(|i| e.path(i).to_string()).collect()
    }

    #[test]
    fn runs_give_the_canonical_order() {
        let paths = ["a.b/ccc", "a.b/c", "a.b/bb", "a.bb/a", "a.b/a", "z/aaaaaaa", "a.b/zz", "a.bb/zzzz", "b/b"];
        let e = entries(&paths);
        let mut want: Vec<String> = paths.iter().map(|s| s.to_string()).collect();
        want.sort_by(|a, b| cbor::key_cmp(a, b));
        assert_eq!(flat(&e, &canonical_runs(&e)), want);
        assert!(canonical_runs(&Entries::default()).is_empty());
        // one collection of TIDs: one run
        let tids: Vec<String> = (0..50).map(|i| format!("c.o/{}", vlsync_atproto::tid::Tid(1_000_000 + i))).collect();
        let e = entries(&tids.iter().map(String::as_str).collect::<Vec<_>>());
        assert_eq!(canonical_runs(&e).len(), 1);
    }

    /// The streamed CAR is the one built in memory: the index block, its
    /// CID in the header, and the records in its order.
    #[test]
    fn streams_the_car_in_pieces() {
        let paths: Vec<String> =
            (0..300).map(|i| format!("com.example.post/{}", "k".repeat(1 + i % 7) + &i.to_string())).collect();
        let e = entries(&paths.iter().map(String::as_str).collect::<Vec<_>>());
        let mut car = Car::new(vec![0xa0]);
        let order = car.order(&e);
        car.begin(&e, &order);
        let (mut sent, mut out) = (Vec::new(), Vec::new());
        while car.prelude(&mut out, 100) {
            sent.append(&mut out);
        }
        sent.append(&mut out);
        let mut out = sent;
        for i in order.iter().flat_map(|r| r.clone()) {
            car.record(e.cid(i), e.path(i).as_bytes(), &mut out);
        }
        let index = car.index_block();
        let (roots, blocks) = vlsync_atproto::car::read_car(&out).unwrap();
        assert_eq!(roots, vec![Cid::dag_cbor(&[0xa0]), Cid::dag_cbor(&index)]);
        assert_eq!(blocks[1].1, &index[..]);
        let decoded = cbor::Value::decode(&index).unwrap();
        let keys: Vec<String> = match decoded {
            cbor::Value::Map(m) => m.into_iter().map(|(k, _)| k).collect(),
            v => panic!("{v:?}"),
        };
        let mut want = paths.clone();
        want.sort_by(|a, b| cbor::key_cmp(a, b));
        assert_eq!(keys, want);
        let got: Vec<&[u8]> = blocks[2..].iter().map(|b| b.1).collect();
        assert_eq!(got, want.iter().map(|p| p.as_bytes()).collect::<Vec<_>>());
    }
}
