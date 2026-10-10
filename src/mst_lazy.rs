//! Partial, lazily loaded MSTs (DESIGN.md "Partial MSTs"): an
//! [`mst::Tree`](vlatproto::mst::Tree) whose unvisited subtrees stay unloaded
//! (`Entry::Child { node: None, cid }`). Nodes of height >= `persist_min`
//! are persisted content-addressed and read by the CID their parent links
//! to; lower subtrees are rebuilt from the records between the parent's
//! separator keys (the MST layout is a pure function of the keys). Both are
//! checked against the parent's link.
//!
//! Mutations, CIDs and proofs are `mst::Tree`'s own code: this module loads
//! every node an operation visits first, namely the search paths of the key
//! and of its two neighbours (the right and left spines a delete merges).
//! Every replaced node lies on those paths, so checking the nodes seen there
//! against the new tree finds all persisted nodes to delete.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::ops::Bound;
use std::sync::Arc;
use vlatproto::cid::Cid;
use vlatproto::mst::{
    decode_node, decode_trusted_node, encode_node, height_for_key, Entry, LeafEncoder, MstError, Node, Tree, MAX_DEPTH,
};

type Result<T> = std::result::Result<T, MstError>;

/// A record key (`collection/rkey`).
pub type Key = Arc<[u8]>;

/// A source that may not do I/O right now fails with [`MstError::NotLoaded`].
pub trait Source {
    /// Content-addressed, so right wherever its CID is linked.
    fn cached(&self, _cid: &Cid) -> Option<Arc<Node>> {
        None
    }
    fn remember(&self, _n: &Arc<Node>) {}
    fn node(&self, cid: &Cid) -> Result<Option<Arc<[u8]>>>;
    /// Records with `lo < key < hi` in key order (`None` bounds are open).
    fn records(&self, lo: Option<&[u8]>, hi: Option<&[u8]>, out: &mut Vec<(Key, Cid)>) -> Result<()>;
    /// [`records`](Source::records) into a cleared `enc`. A source streaming
    /// its records can encode them without a key copy per record.
    fn leaf_records(&self, lo: Option<&[u8]>, hi: Option<&[u8]>, enc: &mut LeafEncoder) -> Result<()> {
        let mut recs = Vec::new();
        self.records(lo, hi, &mut recs)?;
        enc.clear();
        for (k, c) in &recs {
            enc.push(k, c);
        }
        Ok(())
    }
    /// The blocks of the records with keys up to `upto` (None: all) not
    /// given yet, in key order, for [`export_blocks`] to put by their
    /// entries. A source without record blocks gives none.
    fn record_blocks(&self, _upto: Option<&[u8]>, _f: &mut dyn FnMut(Cid, &[u8])) -> Result<()> {
        Ok(())
    }
}

/// Cumulative per [`LazyTree`] or export.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct LoadStats {
    pub node_reads: u64,
    pub node_bytes: u64,
    pub scans: u64,
    pub scanned_records: u64,
    /// Persisted nodes that were missing and rebuilt from records instead.
    pub fallbacks: u64,
}

#[derive(Clone, Debug, Default)]
pub struct Persist {
    /// In write order, re-puts of unchanged proof neighbours included.
    pub puts: Vec<(Cid, Vec<u8>)>,
    pub deletes: Vec<Cid>,
    /// Change in the tree's node count (nodes with entries, leaves
    /// included): written nodes it didn't hold, less the ones it lost.
    pub node_delta: i64,
    /// Bytes of the written nodes it didn't hold, and of the ones it lost
    /// (`state::RepoBytes::commit`).
    pub added_bytes: u64,
    pub gone_bytes: u64,
    /// Lost nodes whose size wasn't known (none expected): they take the
    /// repo's mean node size.
    pub gone_unsized: u64,
}

impl Persist {
    pub fn put_bytes(&self) -> usize {
        self.puts.iter().map(|(_, b)| b.len()).sum()
    }
}

/// Encodes the node and computes its CID. Internal nodes keep their block,
/// as `mst::Tree` does after a write; leaves too with `keep_leaves`, for an
/// export that emits them next.
fn finish(height: i32, entries: Vec<Entry>, keep_leaves: bool) -> Result<Arc<Node>> {
    Ok(finish_sized(height, entries, keep_leaves)?.0)
}

/// [`finish`], and the block's size.
fn finish_sized(height: i32, entries: Vec<Entry>, keep_leaves: bool) -> Result<(Arc<Node>, usize)> {
    let mut n = Node::clean(height, entries, None);
    let mut buf = Vec::with_capacity(64 + n.entries.len() * 80);
    encode_node(&n, &mut buf)?;
    n.cid = Some(Cid::dag_cbor(&buf));
    let len = buf.len();
    n.block_len = vlatproto::mst::block_len(len);
    if height >= 1 || keep_leaves {
        n.bytes = Some(Arc::from(buf));
    }
    Ok((Arc::new(n), len))
}

/// The canonical subtree at `height` holding exactly `recs` (sorted, with
/// `heights[i] = height_for_key(recs[i].0)`, all <= `height`): every key of
/// height `height` is an entry, every non-empty gap between them a child.
fn build(recs: &[(Key, Cid)], heights: &[i32], height: i32, keep_leaves: bool) -> Result<Arc<Node>> {
    if height < 0 || height as usize > 4 * MAX_DEPTH {
        return Err(MstError::Invalid("bad subtree height"));
    }
    let mut entries = Vec::new();
    let mut start = 0;
    for i in 0..recs.len() {
        match heights[i].cmp(&height) {
            std::cmp::Ordering::Less => continue,
            std::cmp::Ordering::Greater => return Err(MstError::Invalid("key above its subtree")),
            std::cmp::Ordering::Equal => {}
        }
        if start < i {
            let c = build(&recs[start..i], &heights[start..i], height - 1, keep_leaves)?;
            entries.push(Entry::Child { cid: c.cid, node: Some(c) });
        }
        entries.push(Entry::Value { key: recs[i].0.clone(), val: recs[i].1 });
        start = i + 1;
    }
    if start < recs.len() {
        let c = build(&recs[start..], &heights[start..], height - 1, keep_leaves)?;
        entries.push(Entry::Child { cid: c.cid, node: Some(c) });
    }
    finish(height, entries, keep_leaves)
}

/// The canonical tree of records pushed in ascending key order, as
/// [`build_tree`] builds it, holding only one open node per height: a key of
/// height h closes every open node below h (its run of lower keys ends
/// there), each becoming a child of the node above. So a node is finished,
/// counted and handed out as soon as it is complete, and memory is the
/// tree's right spine whatever the repo's size (a staged import,
/// `xrpc::staged_import`).
#[derive(Default)]
pub struct StreamBuilder {
    open: Vec<Vec<Entry>>,
    /// Nodes with entries finished so far (`count_tree`'s count), and
    /// their blocks' bytes.
    pub nodes: u64,
    pub node_bytes: u64,
    pub records: u64,
}

impl StreamBuilder {
    /// `key` must be above every key pushed before. Finished nodes of
    /// height >= 1 (the persisted ones) go to `out`.
    pub fn push(&mut self, key: Key, val: Cid, out: &mut Vec<(Cid, Arc<[u8]>)>) -> Result<()> {
        let h = height_for_key(&key) as usize;
        if h > 4 * MAX_DEPTH {
            return Err(MstError::Invalid("key too high"));
        }
        while self.open.len() <= h {
            self.open.push(Vec::new());
        }
        for l in 0..h {
            self.close(l, out)?;
        }
        self.open[h].push(Entry::Value { key, val });
        self.records += 1;
        Ok(())
    }

    fn close(&mut self, l: usize, out: &mut Vec<(Cid, Arc<[u8]>)>) -> Result<()> {
        if self.open[l].is_empty() {
            return Ok(());
        }
        let (n, len) = finish_sized(l as i32, std::mem::take(&mut self.open[l]), false)?;
        self.nodes += 1;
        self.node_bytes += len as u64;
        let cid = n.cid.ok_or(MstError::Invalid("unwritten node"))?;
        if let Some(b) = &n.bytes {
            out.push((cid, b.clone()));
        }
        self.open[l + 1].push(Entry::Child { node: None, cid: Some(cid) });
        Ok(())
    }

    /// The root (its block kept whatever its height), the tree's node
    /// count and its nodes' bytes; a root of height >= 1 goes to `out` too.
    pub fn finish(mut self, out: &mut Vec<(Cid, Arc<[u8]>)>) -> Result<(Arc<Node>, u64, u64)> {
        let Some(top) = self.open.len().checked_sub(1) else { return Ok((finish(0, Vec::new(), true)?, 0, 0)) };
        for l in 0..top {
            self.close(l, out)?;
        }
        let (root, len) = finish_sized(top as i32, std::mem::take(&mut self.open[top]), true)?;
        self.node_bytes += len as u64;
        if top >= 1 {
            out.push((
                root.cid.ok_or(MstError::Invalid("unwritten node"))?,
                root.bytes.clone().ok_or(MstError::Invalid("root without its block"))?,
            ));
        }
        Ok((root, self.nodes + 1, self.node_bytes))
    }
}

/// From all of a repo's records, sorted.
pub fn build_tree(recs: &[(Key, Cid)]) -> Result<Tree> {
    let heights: Vec<i32> = recs.iter().map(|(k, _)| height_for_key(k)).collect();
    let h = heights.iter().copied().max().unwrap_or(0);
    let mut t = Tree::new();
    t.root = build(recs, &heights, h, false)?;
    Ok(t)
}

fn read_node(src: &dyn Source, cid: &Cid, height: Option<i32>, stats: &mut LoadStats) -> Result<Option<Arc<Node>>> {
    let Some(b) = src.node(cid)? else { return Ok(None) };
    stats.node_reads += 1;
    stats.node_bytes += b.len() as u64;
    persisted_node(b, cid, height)
}

/// Hash-checked, with its height fixed (`height`: the parent's minus one;
/// a node without keys takes it). None for a key-less root (the empty
/// tree's).
pub fn persisted_node(b: Arc<[u8]>, cid: &Cid, height: Option<i32>) -> Result<Option<Arc<Node>>> {
    if Cid::dag_cbor(&b) != *cid {
        return Err(MstError::Invalid("persisted node doesn't hash to its cid"));
    }
    let n = decode_node(&b, *cid)?;
    fix_height(b, n, height)
}

/// [`persisted_node`] without the hash check or the keys' heights, for an
/// export's nodes below the root (see [`export_blocks`]).
fn trusted_node(b: Arc<[u8]>, cid: &Cid, height: i32) -> Result<Option<Arc<Node>>> {
    let n = decode_trusted_node(&b, *cid, height)?;
    fix_height(b, n, Some(height))
}

fn fix_height(b: Arc<[u8]>, mut n: Node, height: Option<i32>) -> Result<Option<Arc<Node>>> {
    match height {
        Some(h) if n.height < 0 => n.height = h,
        Some(h) if n.height != h => return Err(MstError::Invalid("persisted node at the wrong height")),
        _ => {}
    }
    if n.height < 0 {
        return Ok(None);
    }
    if n.height >= 1 {
        n.bytes = Some(b);
    }
    Ok(Some(Arc::new(n)))
}

/// The subtree whose keys lie strictly between `lo` and `hi`: read if
/// persisted, else rebuilt from records.
fn load_subtree(
    src: &dyn Source,
    persist_min: i32,
    cid: Cid,
    height: i32,
    lo: Option<&[u8]>,
    hi: Option<&[u8]>,
    stats: &mut LoadStats,
) -> Result<Arc<Node>> {
    if let Some(n) = src.cached(&cid).filter(|n| n.height == height) {
        return Ok(n);
    }
    let n = load_subtree_uncached(src, persist_min, cid, height, lo, hi, stats, false)?;
    src.remember(&n);
    Ok(n)
}

/// `export`: the node is trusted (see [`trusted_node`]) and rebuilt leaves
/// keep their blocks (emitted right after).
#[allow(clippy::too_many_arguments)]
fn load_subtree_uncached(
    src: &dyn Source,
    persist_min: i32,
    cid: Cid,
    height: i32,
    lo: Option<&[u8]>,
    hi: Option<&[u8]>,
    stats: &mut LoadStats,
    export: bool,
) -> Result<Arc<Node>> {
    if height >= persist_min {
        if let Some(b) = src.node(&cid)? {
            stats.node_reads += 1;
            stats.node_bytes += b.len() as u64;
            let n = match export {
                true => trusted_node(b, &cid, height)?,
                false => persisted_node(b, &cid, Some(height))?,
            };
            if let Some(n) = n {
                return Ok(n);
            }
        }
        stats.fallbacks += 1;
    }
    let recs = scan(src, lo, hi, stats)?;
    rebuilt_subtree_with(&recs, height, &cid, export)
}

fn scan(src: &dyn Source, lo: Option<&[u8]>, hi: Option<&[u8]>, stats: &mut LoadStats) -> Result<Vec<(Key, Cid)>> {
    let mut recs = Vec::new();
    src.records(lo, hi, &mut recs)?;
    stats.scans += 1;
    stats.scanned_records += recs.len() as u64;
    Ok(recs)
}

/// The subtree at `height` holding exactly `recs`, checked against its link.
pub fn rebuilt_subtree(recs: &[(Key, Cid)], height: i32, cid: &Cid) -> Result<Arc<Node>> {
    rebuilt_subtree_with(recs, height, cid, false)
}

fn rebuilt_subtree_with(recs: &[(Key, Cid)], height: i32, cid: &Cid, keep_leaves: bool) -> Result<Arc<Node>> {
    let heights: Vec<i32> = recs.iter().map(|(k, _)| height_for_key(k)).collect();
    let n = build(recs, &heights, height, keep_leaves)?;
    if n.cid != Some(*cid) {
        return Err(MstError::Invalid("subtree rebuilt from records doesn't match its link"));
    }
    Ok(n)
}

/// Where a proof walk (`Tree::proof_blocks`) goes from `n`, whose keys lie
/// in (`lo`, `hi`): the child entry to descend to and its key bounds, or
/// None where the path ends (`key` is here, or would be).
pub fn proof_child(
    n: &Node,
    key: &[u8],
    lo: &Option<Key>,
    hi: &Option<Key>,
) -> Option<(usize, Option<Key>, Option<Key>)> {
    let Loc::Gap(Some(i)) = locate(n, key) else { return None };
    let (clo, chi) = child_bounds(n, i, lo, hi);
    Some((i, clo, chi))
}

/// The key bounds of child entry `i` of `n`, whose keys lie in (`lo`, `hi`).
fn child_bounds(n: &Node, i: usize, lo: &Option<Key>, hi: &Option<Key>) -> (Option<Key>, Option<Key>) {
    let clo = if i > 0 { value_key(n.entries.get(i - 1)) } else { lo.clone() };
    let chi = value_key(n.entries.get(i + 1)).or_else(|| hi.clone());
    (clo, chi)
}

pub fn node_block(n: &Node) -> Result<Vec<u8>> {
    Ok(n.block()?.into_owned())
}

enum Loc {
    Found(usize),
    /// The child entry at the key's gap (None: an empty gap).
    Gap(Option<usize>),
}

fn locate(n: &Node, key: &[u8]) -> Loc {
    let mut gap = None;
    for (i, e) in n.entries.iter().enumerate() {
        match e {
            Entry::Value { key: k, .. } => match key.cmp(k) {
                std::cmp::Ordering::Equal => return Loc::Found(i),
                std::cmp::Ordering::Less => return Loc::Gap(gap),
                std::cmp::Ordering::Greater => gap = None,
            },
            Entry::Child { .. } => gap = Some(i),
        }
    }
    Loc::Gap(gap)
}

fn is_child(e: Option<&Entry>) -> bool {
    matches!(e, Some(Entry::Child { .. }))
}

fn value_key(e: Option<&Entry>) -> Option<Key> {
    match e {
        Some(Entry::Value { key, .. }) => Some(key.clone()),
        _ => None,
    }
}

/// To find `n` again by position.
fn any_key(n: &Node) -> Option<Key> {
    for e in &n.entries {
        match e {
            Entry::Value { key, .. } => return Some(key.clone()),
            Entry::Child { node: Some(c), .. } => {
                if let Some(k) = any_key(c) {
                    return Some(k);
                }
            }
            Entry::Child { node: None, .. } => {}
        }
    }
    None
}

/// The child a walk in `mode` goes on to from `n` (None: the path ends at
/// `n`); a neighbour walk turns into a spine walk below the key.
fn step(n: &Node, key: &[u8], mode: &mut Mode) -> Option<usize> {
    let last = n.entries.len().wrapping_sub(1);
    match *mode {
        Mode::Min => is_child(n.entries.first()).then_some(0),
        Mode::Max => is_child(n.entries.last()).then_some(last),
        Mode::Key | Mode::Before | Mode::After => match locate(n, key) {
            Loc::Gap(g) => g,
            Loc::Found(i) => match *mode {
                Mode::Before if i > 0 && is_child(n.entries.get(i - 1)) => {
                    *mode = Mode::Max;
                    Some(i - 1)
                }
                Mode::After if is_child(n.entries.get(i + 1)) => {
                    *mode = Mode::Min;
                    Some(i + 1)
                }
                _ => None,
            },
        },
    }
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Mode {
    /// The key's search path (to the node holding it, or the bottom).
    Key,
    /// The path to the key's predecessor (right spine below the key).
    Before,
    /// The path to the key's successor (left spine below the key).
    After,
    Min,
    Max,
}

/// Approximate heap of the loaded part of a subtree (not allocator-exact).
pub fn heap_bytes(n: &Node) -> usize {
    let mut b = own_heap_bytes(n);
    for e in &n.entries {
        if let Entry::Child { node: Some(c), .. } = e {
            b += heap_bytes(c);
        }
    }
    b
}

fn own_heap_bytes(n: &Node) -> usize {
    const ARC: usize = 16;
    let mut b = ARC + std::mem::size_of::<Node>() + n.entries.capacity() * std::mem::size_of::<Entry>();
    if let Some(bytes) = &n.bytes {
        b += ARC + bytes.len();
    }
    for e in &n.entries {
        if let Entry::Value { key, .. } = e {
            b += (ARC + key.len()).next_multiple_of(16);
        }
    }
    b
}

/// [`heap_bytes`] of successive versions of one tree, walking only what
/// changed since the last call (the worker recharges a repo every commit).
///
/// It keeps the tree it last measured (`root`) and the subtree size of
/// each of its interior nodes by address. Holding `root` freezes every
/// node reachable from it (nodes are `Arc`-shared and only mutated through
/// `Arc::make_mut`, which copies a node held twice, and so every node on
/// the way down to it), so an address found in `sub` is an unchanged,
/// live subtree. A new version is walked down to the nodes it shares with
/// the old one; the old version's nodes the new one dropped are walked
/// once more to forget them. Drop the memo (`HeapMemo::default()`) when
/// unloading, or it keeps the unloaded nodes alive.
#[derive(Default)]
pub struct HeapMemo {
    root: Option<Arc<Node>>,
    total: usize,
    sub: HashMap<usize, usize>,
}

impl HeapMemo {
    pub fn heap_bytes(&mut self, root: &Arc<Node>) -> usize {
        if self.root.as_ref().is_some_and(|r| Arc::ptr_eq(r, root)) {
            return self.total;
        }
        fn walk(
            n: &Arc<Node>,
            sub: &HashMap<usize, usize>,
            fresh: &mut Vec<(usize, usize)>,
            kept: &mut HashSet<usize>,
        ) -> usize {
            let at = Arc::as_ptr(n) as usize;
            if let Some(&b) = sub.get(&at) {
                kept.insert(at);
                return b;
            }
            let mut b = own_heap_bytes(n);
            for e in &n.entries {
                if let Entry::Child { node: Some(c), .. } = e {
                    b += walk(c, sub, fresh, kept);
                }
            }
            if n.height > 0 {
                fresh.push((at, b));
            }
            b
        }
        // the old version's nodes outside the subtrees the new one kept
        fn forget(n: &Arc<Node>, kept: &HashSet<usize>, sub: &mut HashMap<usize, usize>) {
            let at = Arc::as_ptr(n) as usize;
            if kept.contains(&at) {
                return;
            }
            sub.remove(&at);
            for e in &n.entries {
                if let Entry::Child { node: Some(c), .. } = e {
                    forget(c, kept, sub);
                }
            }
        }
        let (mut fresh, mut kept) = (Vec::new(), HashSet::new());
        let total = walk(root, &self.sub, &mut fresh, &mut kept);
        if let Some(old) = self.root.take() {
            forget(&old, &kept, &mut self.sub);
        }
        self.sub.extend(fresh);
        self.root = Some(root.clone());
        self.total = total;
        total
    }
}

/// Blocks of the loaded (written) nodes of `n`'s subtree whose CIDs are in
/// `want`.
pub fn loaded_blocks(n: &Node, want: &HashSet<Cid>, out: &mut Vec<(Cid, Vec<u8>)>) -> Result<()> {
    if let Some(c) = n.cid.filter(|c| want.contains(c)) {
        if !out.iter().any(|(o, _)| *o == c) {
            out.push((c, node_block(n)?));
        }
    }
    for e in &n.entries {
        if let Entry::Child { node: Some(ch), .. } = e {
            loaded_blocks(ch, want, out)?;
        }
    }
    Ok(())
}

pub fn loaded_nodes(n: &Node) -> usize {
    1 + n
        .entries
        .iter()
        .map(|e| match e {
            Entry::Child { node: Some(c), .. } => loaded_nodes(c),
            _ => 0,
        })
        .sum::<usize>()
}

/// A repo's MST, loaded only along the paths operations have visited.
#[derive(Clone)]
pub struct LazyTree {
    pub tree: Tree,
    persist_min: i32,
    /// Nodes (leaves too) on this batch's mutation walks, by their last
    /// written cid: (cid, a key in the node's subtree, height, that
    /// version's block length). Replaced persisted ones are deleted; the
    /// rest of the tree is unchanged.
    seen: Vec<(Cid, Key, i32, u32)>,
    pub stats: LoadStats,
}

impl LazyTree {
    /// Only the root node is loaded. A repo whose root isn't persisted (an
    /// empty one, or one that lost its nodes) is rebuilt from all its
    /// records and checked against `root`.
    pub fn open(root: Cid, persist_min: i32, src: &dyn Source) -> Result<LazyTree> {
        let mut stats = LoadStats::default();
        let tree = match read_node(src, &root, None, &mut stats)? {
            Some(n) => {
                let mut t = Tree::new();
                t.root = n;
                t
            }
            None => {
                let recs = scan(src, None, None, &mut stats)?;
                let t = build_tree(&recs)?;
                if t.root.cid != Some(root) {
                    return Err(MstError::Invalid("tree rebuilt from records doesn't match its root"));
                }
                t
            }
        };
        Ok(LazyTree { tree, persist_min, seen: Vec::new(), stats })
    }

    /// A fully loaded tree whose nodes of height >= `persist_min` are
    /// persisted: it can be unloaded and walked lazily from now on.
    pub fn loaded(tree: Tree, persist_min: i32) -> LazyTree {
        LazyTree { tree, persist_min, seen: Vec::new(), stats: LoadStats::default() }
    }

    pub fn persist_min(&self) -> i32 {
        self.persist_min
    }

    /// With `note` (mutation walks), notes the nodes it passes as candidates
    /// for deletion.
    fn walk(&mut self, key: &[u8], mut mode: Mode, note: bool, src: &dyn Source) -> Result<()> {
        // most walks find their path loaded: check that without
        // `Arc::make_mut`, which copies every node shared with a view
        if let Some(path) = self.loaded_path(key, mode, note) {
            self.seen.extend(path);
            return Ok(());
        }
        let persist_min = self.persist_min;
        let stats = &mut self.stats;
        let seen = &mut self.seen;
        let mut n: &mut Arc<Node> = &mut self.tree.root;
        let (mut lo, mut hi): (Option<Key>, Option<Key>) = (None, None);
        let mut path = Vec::new();
        for _ in 0..=MAX_DEPTH {
            if n.stub {
                return Err(MstError::Partial);
            }
            let idx = step(n, key, &mut mode);
            // a dirty node's cid is its last written (persisted) version's:
            // an earlier op of the batch changed it
            if note {
                if let Some(c) = n.cid {
                    path.push((c, n.height, n.block_len));
                }
            }
            let Some(idx) = idx else {
                // the path ends in a node with keys (one without has a child
                // to go on to): any of them is in every path node's subtree
                if let Some(k) = any_key(n) {
                    seen.extend(path.into_iter().map(|(c, h, l)| (c, k.clone(), h, l)));
                }
                return Ok(());
            };
            let (clo, chi) = child_bounds(n, idx, &lo, &hi);
            if let Entry::Child { node: None, cid } = &n.entries[idx] {
                let c = cid.ok_or(MstError::Partial)?;
                let child = load_subtree(src, persist_min, c, n.height - 1, clo.as_deref(), chi.as_deref(), stats)?;
                Arc::make_mut(n).entries[idx] = Entry::Child { node: Some(child), cid: Some(c) };
            }
            (lo, hi) = (clo, chi);
            let Entry::Child { node: Some(c), .. } = &mut Arc::make_mut(n).entries[idx] else {
                return Err(MstError::Partial);
            };
            n = c;
        }
        Err(MstError::Invalid("tree too deep"))
    }

    /// [`walk`](Self::walk)'s notes if every node on it is loaded, without
    /// `Arc::make_mut`.
    fn loaded_path(&self, key: &[u8], mut mode: Mode, note: bool) -> Option<Vec<(Cid, Key, i32, u32)>> {
        let mut n: &Node = &self.tree.root;
        let mut path = Vec::new();
        for _ in 0..=MAX_DEPTH {
            if n.stub {
                return None;
            }
            let idx = step(n, key, &mut mode);
            if note {
                if let Some(c) = n.cid {
                    path.push((c, n.height, n.block_len));
                }
            }
            let Some(idx) = idx else {
                return Some(match any_key(n) {
                    Some(k) => path.into_iter().map(|(c, h, l)| (c, k.clone(), h, l)).collect(),
                    None => Vec::new(),
                });
            };
            match &n.entries[idx] {
                Entry::Child { node: Some(c), .. } => n = c,
                _ => return None,
            }
        }
        None
    }

    fn prepare(&mut self, key: &[u8], src: &dyn Source) -> Result<()> {
        self.walk(key, Mode::Key, true, src)?;
        self.walk(key, Mode::Before, true, src)?;
        self.walk(key, Mode::After, true, src)
    }

    /// Loads what operations at `keys` will visit, without noting anything.
    /// With a source that may not do I/O, finds what an asynchronous fetch
    /// has to load first ([`MstError::NotLoaded`]).
    pub fn fetch(&mut self, keys: &[&[u8]], probes: &[&[u8]], src: &dyn Source) -> Result<()> {
        for k in keys {
            self.walk(k, Mode::Key, false, src)?;
            self.walk(k, Mode::Before, false, src)?;
            self.walk(k, Mode::After, false, src)?;
        }
        for p in probes {
            self.walk(p, Mode::Key, false, src)?;
        }
        Ok(())
    }

    /// Whether any key starts with `prefix` (a collection's `coll/`): the
    /// smallest key >= `prefix`, found on its loaded search path.
    pub fn has_prefix(&mut self, prefix: &[u8], src: &dyn Source) -> Result<bool> {
        self.walk(prefix, Mode::Key, false, src)?;
        let mut n: &Node = &self.tree.root;
        let mut next: Option<&Key> = None;
        for _ in 0..=MAX_DEPTH {
            if n.stub {
                return Err(MstError::Partial);
            }
            // the first value above `prefix` here bounds every key below it
            let mut gap = None;
            let mut nearer = None;
            for (i, e) in n.entries.iter().enumerate() {
                match e {
                    Entry::Value { key, .. } if &key[..] >= prefix => {
                        nearer = Some(key);
                        break;
                    }
                    Entry::Value { .. } => gap = None,
                    Entry::Child { .. } => gap = Some(i),
                }
            }
            if let Some(k) = nearer {
                if &k[..] == prefix {
                    return Ok(true);
                }
                next = Some(k);
            }
            match gap.map(|i| &n.entries[i]) {
                Some(Entry::Child { node: Some(c), .. }) => n = c,
                Some(_) => return Err(MstError::Partial),
                None => return Ok(next.is_some_and(|k| k.starts_with(prefix))),
            }
        }
        Err(MstError::Invalid("tree too deep"))
    }

    /// Unloaded subtrees are asked for in key order, so a [`Source`] over
    /// one forward record scan serves it.
    pub fn load_all(&mut self, src: &dyn Source) -> Result<()> {
        #[allow(clippy::too_many_arguments)]
        fn rec(
            n: &mut Arc<Node>,
            lo: Option<Key>,
            hi: Option<Key>,
            pm: i32,
            src: &dyn Source,
            stats: &mut LoadStats,
            depth: usize,
        ) -> Result<()> {
            if depth > MAX_DEPTH {
                return Err(MstError::Invalid("tree too deep"));
            }
            if n.stub {
                return Err(MstError::Partial);
            }
            if !n.entries.iter().any(|e| matches!(e, Entry::Child { .. })) {
                return Ok(());
            }
            let nm = Arc::make_mut(n);
            for i in 0..nm.entries.len() {
                let Entry::Child { node, cid } = &nm.entries[i] else { continue };
                let (clo, chi) = child_bounds(nm, i, &lo, &hi);
                if node.is_none() {
                    let c = cid.ok_or(MstError::Partial)?;
                    let child = load_subtree(src, pm, c, nm.height - 1, clo.as_deref(), chi.as_deref(), stats)?;
                    nm.entries[i] = Entry::Child { node: Some(child), cid: Some(c) };
                }
                let Entry::Child { node: Some(c), .. } = &mut nm.entries[i] else { unreachable!() };
                rec(c, clo, chi, pm, src, stats, depth + 1)?;
            }
            Ok(())
        }
        rec(&mut self.tree.root, None, None, self.persist_min, src, &mut self.stats, 0)
    }

    pub fn fully_loaded(&self) -> bool {
        fn rec(n: &Node) -> bool {
            n.entries.iter().all(|e| match e {
                Entry::Child { node: Some(c), .. } => rec(c),
                Entry::Child { node: None, .. } => false,
                Entry::Value { .. } => true,
            })
        }
        rec(&self.tree.root)
    }

    pub fn get(&mut self, key: &[u8], src: &dyn Source) -> Result<Option<Cid>> {
        self.walk(key, Mode::Key, false, src)?;
        self.tree.get(key)
    }

    pub fn insert(&mut self, key: &[u8], val: Cid, src: &dyn Source) -> Result<Option<Cid>> {
        self.prepare(key, src)?;
        self.tree.insert(key, val)
    }

    pub fn remove(&mut self, key: &[u8], src: &dyn Source) -> Result<Option<Cid>> {
        self.prepare(key, src)?;
        self.tree.remove(key)
    }

    /// `Tree::write_diff_blocks` plus the persisted-node changes.
    pub fn write_diff_blocks(&mut self, out: &mut Vec<(Cid, Vec<u8>)>) -> Result<(Cid, Persist)> {
        self.write_diff_blocks_with_refs(out, None)
    }

    /// Also reports where the written nodes sit, leaving out nodes whose
    /// first key is in an unloaded subtree (interior ones, which `M/` finds
    /// by CID).
    pub fn write_diff_blocks_with_refs(
        &mut self,
        out: &mut Vec<(Cid, Vec<u8>)>,
        report: Option<&mut Vec<(Cid, vlatproto::mst::NodeRef)>>,
    ) -> Result<(Cid, Persist)> {
        let start = out.len();
        let mut refs = Vec::new();
        let root = self.tree.write_diff_blocks_with_refs(out, &mut refs)?;
        if let Some(r) = report {
            r.extend(refs.iter().cloned());
        }
        let mut heights: HashMap<Cid, i32> = refs.iter().map(|(c, (_, h))| (*c, *h)).collect();
        if heights.len() < out.len() - start {
            // refs leave out nodes whose first key is in an unloaded subtree:
            // written nodes hang together from the root, so find them there
            let written: HashSet<Cid> = out[start..].iter().map(|(c, _)| *c).collect();
            fn rec(n: &Node, written: &HashSet<Cid>, heights: &mut HashMap<Cid, i32>) {
                // the empty tree's root isn't persisted (it has no height)
                let Some(c) = n.cid.filter(|c| written.contains(c) && !n.entries.is_empty()) else { return };
                heights.insert(c, n.height);
                for e in &n.entries {
                    if let Entry::Child { node: Some(ch), .. } = e {
                        rec(ch, written, heights);
                    }
                }
            }
            rec(&self.tree.root, &written, &mut heights);
        }
        // the empty tree's root isn't counted: a batch's first insert into an
        // empty tree leaves the root dirty under that cid
        let empty = *vlatproto::mst::EMPTY_ROOT;
        let mut kept = HashSet::new();
        let mut gone: HashMap<Cid, i32> = HashMap::new();
        let (mut gone_bytes, mut gone_unsized) = (0u64, 0u64);
        for (c, k, h, len) in std::mem::take(&mut self.seen) {
            if c == empty || kept.contains(&c) || gone.contains_key(&c) {
                continue;
            }
            match self.present(&c, &k, h) {
                true => {
                    kept.insert(c);
                }
                false => {
                    gone.insert(c, h);
                    debug_assert!(len > 0, "replaced node {c} of unknown size");
                    match len {
                        0 => gone_unsized += 1,
                        l => gone_bytes += l as u64,
                    }
                }
            };
        }
        // a written node the tree held before was on a walk (a node changes
        // only below one), and so is in `kept`
        let (mut added, mut added_bytes) = (0usize, 0u64);
        for (_, b) in out[start..].iter().filter(|(c, _)| !kept.contains(c) && *c != empty) {
            added += 1;
            added_bytes += b.len() as u64;
        }
        let node_delta = added as i64 - gone.len() as i64;
        let deletes = gone.into_iter().filter(|(_, h)| *h >= self.persist_min).map(|(c, _)| c).collect();
        // every written node at a persisted height, proof-only neighbours
        // (already stored) included: exactly what replay derives from the
        // commit's CAR (`persisted_blocks`), in the same order
        let puts: Vec<(Cid, Vec<u8>)> = out[start..]
            .iter()
            .filter(|(c, _)| heights.get(c).is_some_and(|h| *h >= self.persist_min))
            .cloned()
            .collect();
        Ok((root, Persist { puts, deletes, node_delta, added_bytes, gone_bytes, gone_unsized }))
    }

    /// Whether the written tree holds node `cid` (at `height`, on the path
    /// to `key`, the one place it can be). Nodes seen by a batch stay
    /// loaded until its write (unloading is between commits), so an
    /// unloaded subtree on the way doesn't hold it.
    fn present(&self, cid: &Cid, key: &[u8], height: i32) -> bool {
        let mut n: &Node = &self.tree.root;
        loop {
            if n.height <= height {
                return n.height == height && n.cid == Some(*cid);
            }
            match locate(n, key) {
                Loc::Gap(Some(i)) => match &n.entries[i] {
                    Entry::Child { node: Some(c), .. } => n = c,
                    _ => return false,
                },
                _ => return false,
            }
        }
    }

    pub fn proof_blocks(&mut self, key: &[u8], src: &dyn Source) -> Result<Vec<(Cid, Vec<u8>)>> {
        self.walk(key, Mode::Key, false, src)?;
        self.tree.proof_blocks(key)
    }

    /// Drops every loaded subtree whose CID isn't in `keep` (call between
    /// writes), keeping the root: with `keep` = the nodes written by
    /// commits still in flight, what remains to read back is durable. A
    /// subtree changed by such a commit has its (new) CID in `keep`, and so
    /// does every node above it, which are kept and descended into.
    pub fn unload_except(&mut self, keep: &HashSet<Cid>) {
        fn rec(n: &mut Arc<Node>, keep: &HashSet<Cid>) {
            if !n.entries.iter().any(|e| matches!(e, Entry::Child { node: Some(_), .. })) {
                return;
            }
            let nm = Arc::make_mut(n);
            for e in nm.entries.iter_mut() {
                if let Entry::Child { node, cid } = e {
                    let Some(c) = node else { continue };
                    match c.cid {
                        Some(cc) if !c.dirty && !keep.contains(&cc) => {
                            *cid = Some(cc);
                            *node = None;
                        }
                        _ => rec(c, keep),
                    }
                }
            }
        }
        rec(&mut self.tree.root, keep);
    }

    /// Drops loaded subtrees more than `depth` levels below the root (clean
    /// ones: call after a write). `unload(0)` keeps just the root.
    pub fn unload(&mut self, depth: usize) {
        fn rec(n: &mut Arc<Node>, depth: usize) {
            if !n.entries.iter().any(|e| matches!(e, Entry::Child { node: Some(_), .. })) {
                return;
            }
            let nm = Arc::make_mut(n);
            for e in nm.entries.iter_mut() {
                if let Entry::Child { node, cid } = e {
                    let Some(c) = node else { continue };
                    if depth == 0 && !c.dirty && c.cid.is_some() {
                        *cid = c.cid;
                        *node = None;
                    } else if depth > 0 {
                        rec(c, depth - 1);
                    }
                }
            }
        }
        rec(&mut self.tree.root, depth);
    }

    pub fn heap_bytes(&self) -> usize {
        heap_bytes(&self.tree.root)
    }

    pub fn loaded_nodes(&self) -> usize {
        loaded_nodes(&self.tree.root)
    }
}

/// A commit's `M/` puts: its blocks that are nodes of the tree at `root`
/// with height >= `persist_min`, in CAR order. The worker and replay
/// (`crate::derived::derive_commit_muts_n`) both derive them with this function, so
/// they agree; the decoder may not get stricter than what a writer at the
/// segment's level emitted. Nodes are found from the root through the links
/// whose blocks the commit carries (record blocks are only ever values).
pub fn persisted_blocks<'a>(root: &Cid, blocks: &[(Cid, &'a [u8])], persist_min: i32) -> Result<Vec<(Cid, &'a [u8])>> {
    let by: HashMap<Cid, &[u8]> = blocks.iter().map(|(c, b)| (*c, *b)).collect();
    let mut seen = HashSet::new();
    let mut keep = HashSet::new();
    let mut stack = vec![(*root, None::<i32>, 0usize)];
    while let Some((c, parent, depth)) = stack.pop() {
        if depth > MAX_DEPTH {
            return Err(MstError::Invalid("tree too deep"));
        }
        let Some(b) = by.get(&c) else { continue };
        if !seen.insert(c) {
            continue;
        }
        let n = decode_node(b, c)?;
        if n.entries.is_empty() {
            continue; // the empty tree's root: no height, never persisted
        }
        let height = match (n.height, parent) {
            (h, None) if h >= 0 => h,
            (h, Some(p)) if h < 0 || h == p - 1 => p - 1,
            _ => return Err(MstError::Invalid("node at the wrong height")),
        };
        if height >= persist_min {
            keep.insert(c);
        }
        for e in &n.entries {
            if let Entry::Child { cid: Some(cc), .. } = e {
                stack.push((*cc, Some(height), depth + 1));
            }
        }
    }
    Ok(blocks.iter().filter(|(c, _)| keep.contains(c)).map(|(c, b)| (*c, *b)).collect())
}

/// The tree at `root` in the streamable CAR order ([`vlatproto::car_order`]):
/// each node block, then its slots in order, a child by recursing and a
/// record by its block, which [`Source::record_blocks`] gives (none from a
/// source without them: node blocks alone, in `Tree::walk_blocks` order).
/// Records come in key order, as a forward `R/` scan reads them, with one
/// root-to-leaf path of nodes in memory. Not driven by
/// [`car_order::Walk`](vlatproto::car_order::Walk): that takes each node
/// decoded, and leaves here are encoded straight from their records. A
/// record the tree doesn't name still comes at its key's place.
///
/// The root is hash-checked against `root`, and every subtree rebuilt from
/// records against its parent's link, so the records exported are the ones
/// the commit signs. Persisted nodes below the root are not re-hashed: this
/// PDS hashed them before writing them under their CIDs, and SlateDB's
/// per-block CRC32 fails a read corrupted at rest. A wrong node (a bug)
/// shows as children not matching their links, or as a block not hashing to
/// its CID in the CAR. Walks that cache what they load keep the check
/// (`persisted_node`).
pub fn export_blocks(
    root: Cid,
    persist_min: i32,
    src: &dyn Source,
    f: &mut dyn FnMut(Cid, &[u8]),
) -> Result<LoadStats> {
    let mut stats = LoadStats::default();
    fn emit(n: &Node, f: &mut dyn FnMut(Cid, &[u8])) -> Result<()> {
        f(n.cid.ok_or(MstError::Invalid("unwritten node"))?, &n.block()?);
        Ok(())
    }
    /// A fully loaded subtree.
    fn walk_loaded(n: &Node, src: &dyn Source, f: &mut dyn FnMut(Cid, &[u8]), depth: usize) -> Result<()> {
        if depth > MAX_DEPTH {
            return Err(MstError::Invalid("tree too deep"));
        }
        emit(n, f)?;
        for e in &n.entries {
            match e {
                Entry::Value { key, .. } => src.record_blocks(Some(key), f)?,
                Entry::Child { node: Some(c), .. } => walk_loaded(c, src, f, depth + 1)?,
                Entry::Child { .. } => return Err(MstError::Partial),
            }
        }
        Ok(())
    }
    #[allow(clippy::too_many_arguments)]
    fn visit(
        n: &Node,
        lo: Option<Key>,
        hi: Option<Key>,
        persist_min: i32,
        src: &dyn Source,
        f: &mut dyn FnMut(Cid, &[u8]),
        stats: &mut LoadStats,
        enc: &mut LeafEncoder,
        depth: usize,
    ) -> Result<()> {
        if depth > MAX_DEPTH {
            return Err(MstError::Invalid("tree too deep"));
        }
        emit(n, f)?;
        for (i, e) in n.entries.iter().enumerate() {
            let c = match e {
                Entry::Value { key, .. } => {
                    src.record_blocks(Some(key), f)?;
                    continue;
                }
                Entry::Child { cid: Some(c), .. } => c,
                Entry::Child { cid: None, .. } => continue,
            };
            let (clo, chi) = child_bounds(n, i, &lo, &hi);
            if n.height == 1 && persist_min >= 1 {
                // a leaf, encoded straight from its records: its link checks
                // it, so no key heights or node to build. Its records' blocks
                // follow with the next key's (or at the end).
                src.leaf_records(clo.as_deref(), chi.as_deref(), enc)?;
                stats.scans += 1;
                stats.scanned_records += enc.len() as u64;
                let block = enc.finish();
                if Cid::dag_cbor(block) != *c {
                    return Err(MstError::Invalid("subtree rebuilt from records doesn't match its link"));
                }
                f(*c, block);
                continue;
            }
            let child =
                load_subtree_uncached(src, persist_min, *c, n.height - 1, clo.as_deref(), chi.as_deref(), stats, true)?;
            if child.height >= persist_min
                && !child.entries.iter().any(|e| matches!(e, Entry::Child { node: Some(_), .. }))
            {
                visit(&child, clo, chi, persist_min, src, f, stats, enc, depth + 1)?;
            } else {
                // rebuilt from records: fully loaded, blocks kept
                walk_loaded(&child, src, f, depth + 1)?;
            }
        }
        Ok(())
    }
    match read_node(src, &root, None, &mut stats)? {
        Some(r) => visit(&r, None, None, persist_min, src, f, &mut stats, &mut LeafEncoder::default(), 0)?,
        None => {
            let t = LazyTree::open(root, persist_min, src)?;
            stats = t.stats;
            walk_loaded(&t.tree.root, src, f, 0)?;
        }
    }
    src.record_blocks(None, f)?;
    Ok(stats)
}

/// `M/` and `R/` of one repo, in memory (tests, benches).
#[derive(Clone, Default)]
pub struct MemStore {
    pub nodes: HashMap<Cid, Arc<[u8]>>,
    pub records: BTreeMap<Key, Cid>,
}

impl MemStore {
    pub fn from_tree(tree: &Tree, persist_min: i32) -> MemStore {
        let mut s = MemStore::default();
        tree.walk(&mut |k, c| {
            s.records.insert(Arc::from(k), c);
        });
        s.nodes = persisted_nodes(tree, persist_min);
        s
    }

    pub fn apply(&mut self, p: &Persist) {
        for c in &p.deletes {
            self.nodes.remove(c);
        }
        for (c, b) in &p.puts {
            self.nodes.insert(*c, Arc::from(&b[..]));
        }
    }

    pub fn node_bytes(&self) -> usize {
        self.nodes.values().map(|b| b.len()).sum()
    }
}

/// An empty root has no height and isn't persisted.
pub fn persisted_nodes(tree: &Tree, persist_min: i32) -> HashMap<Cid, Arc<[u8]>> {
    fn rec(n: &Node, persist_min: i32, out: &mut HashMap<Cid, Arc<[u8]>>) {
        if n.height >= persist_min && !n.entries.is_empty() {
            let b = match &n.bytes {
                Some(b) => b.clone(),
                None => {
                    let mut buf = Vec::new();
                    encode_node(n, &mut buf).expect("written tree");
                    Arc::from(buf)
                }
            };
            out.insert(n.cid.expect("written tree"), b);
        }
        for e in &n.entries {
            if let Entry::Child { node: Some(c), .. } = e {
                rec(c, persist_min, out);
            }
        }
    }
    let mut out = HashMap::new();
    rec(&tree.root, persist_min, &mut out);
    out
}

impl Source for MemStore {
    fn node(&self, cid: &Cid) -> Result<Option<Arc<[u8]>>> {
        Ok(self.nodes.get(cid).cloned())
    }

    fn records(&self, lo: Option<&[u8]>, hi: Option<&[u8]>, out: &mut Vec<(Key, Cid)>) -> Result<()> {
        let lo = lo.map_or(Bound::Unbounded, Bound::Excluded);
        let hi = hi.map_or(Bound::Unbounded, Bound::Excluded);
        out.extend(self.records.range::<[u8], _>((lo, hi)).map(|(k, c)| (k.clone(), *c)));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The streamed build is `build_tree`'s tree: same root, node count and
    /// persisted nodes, whatever the sizes and key heights.
    #[test]
    fn stream_builder_matches_build_tree() {
        for n in [0usize, 1, 2, 3, 5, 17, 100, 1000, 5000] {
            let mut recs: Vec<(Key, Cid)> = (0..n)
                .map(|i| {
                    let k = format!("app.test.c{}/{:08}", i % 3, i.wrapping_mul(2654435761) % 100_000_000);
                    (Key::from(k.as_bytes()), Cid::dag_cbor(k.as_bytes()))
                })
                .collect();
            recs.sort();
            recs.dedup_by(|a, b| a.0 == b.0);
            let mut tree = build_tree(&recs).unwrap();
            let mut sb = StreamBuilder::default();
            let mut out = Vec::new();
            for (k, c) in &recs {
                sb.push(k.clone(), *c, &mut out).unwrap();
            }
            let (root, nodes, node_bytes) = sb.finish(&mut out).unwrap();
            assert_eq!(root.cid, Some(tree.root_cid().unwrap()), "n={n}");
            assert_eq!(nodes, crate::repo_stats::count_tree(&tree).unwrap().1, "n={n}");
            assert_eq!(node_bytes, crate::repo_stats::tree_bytes(&tree).unwrap(), "n={n}");

            let want = persisted_nodes(&tree, 1);
            let got: HashMap<Cid, Arc<[u8]>> = out.into_iter().collect();
            assert_eq!(got.len(), want.len(), "n={n}");
            for (c, b) in &want {
                assert_eq!(got.get(c).map(|b| &b[..]), Some(&b[..]), "n={n}");
            }
            let block = root.bytes.clone().unwrap();
            assert_eq!(Cid::dag_cbor(&block), root.cid.unwrap());
        }
    }
}
