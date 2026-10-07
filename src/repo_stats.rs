//! The counts checkAccountStatus reports (`state::RepoStats`), from scratch:
//! what the repo worker's incremental `S/{did}` must equal. O(repo): tests,
//! `vlpds admin check-repo`, and a repo whose `S/` row is missing.

use crate::mst::{Entry, MstError, Node, Tree};
use crate::state::{self, RepoBytes, RepoStats};
use std::collections::HashSet;

/// (records, nodes with entries) of a fully loaded tree.
pub fn count_tree(tree: &Tree) -> Result<(u64, u64), MstError> {
    fn rec(n: &Node, out: &mut (u64, u64)) -> Result<(), MstError> {
        if n.stub {
            return Err(MstError::Partial);
        }
        if !n.entries.is_empty() {
            out.1 += 1;
        }
        for e in &n.entries {
            match e {
                Entry::Value { .. } => out.0 += 1,
                Entry::Child { node: Some(c), .. } => rec(c, out)?,
                Entry::Child { node: None, .. } => return Err(MstError::Partial),
            }
        }
        Ok(())
    }
    let mut out = (0, 0);
    rec(&tree.root, &mut out)?;
    Ok(out)
}

/// The blocks of every node with entries of a fully loaded tree whose CIDs
/// are computed: kept blocks as they are, the rest (leaves) encoded.
pub fn tree_bytes(tree: &Tree) -> Result<u64, MstError> {
    fn rec(n: &Node, buf: &mut Vec<u8>) -> Result<u64, MstError> {
        if n.stub {
            return Err(MstError::Partial);
        }
        let mut sum = 0;
        if !n.entries.is_empty() {
            sum += match &n.bytes {
                Some(b) => b.len() as u64,
                None => {
                    buf.clear();
                    crate::mst::encode_node(n, buf)?;
                    buf.len() as u64
                }
            };
        }
        for e in &n.entries {
            match e {
                Entry::Child { node: Some(c), .. } => sum += rec(c, buf)?,
                Entry::Child { node: None, .. } => return Err(MstError::Partial),
                Entry::Value { .. } => {}
            }
        }
        Ok(sum)
    }
    rec(&tree.root, &mut Vec::new())
}

/// The stats of a tree and the bytes of its records' blocks.
pub fn of_tree(tree: &Tree, record_bytes: u64, blobs: u64) -> Result<RepoStats, MstError> {
    let (records, nodes) = count_tree(tree)?;
    let bytes = RepoBytes { records: record_bytes, nodes: tree_bytes(tree)? };
    Ok(RepoStats { records, nodes, blobs, bytes: Some(bytes) })
}

/// Records and the tree rebuilt from them (`R/`), distinct blob CIDs (`b/`).
pub async fn walk<R: slatedb::DbReadOps + Sync + ?Sized>(db: &R, did: &str, gen: u64) -> anyhow::Result<RepoStats> {
    let prefix = state::record_prefix(did, gen);
    let mut it = state::BatchedScan::new(db.scan(prefix.clone()..state::prefix_end(&prefix)).await?);
    let mut recs = Vec::new();
    let mut record_bytes = 0u64;
    while let Some(kv) = it.next().await? {
        let (cid, block) = state::record_value_parts(&kv.value)?;
        record_bytes += block.len() as u64;
        recs.push((crate::mst_lazy::Key::from(&kv.key[prefix.len()..]), cid));
    }
    let tree = tokio::task::spawn_blocking(move || -> anyhow::Result<(Tree, u64)> {
        let mut tree = crate::mst_lazy::build_tree(&recs)?;
        tree.root_cid()?;
        let nb = tree_bytes(&tree)?;
        Ok((tree, nb))
    })
    .await??;
    let (tree, node_bytes) = tree;
    let (records, nodes) = count_tree(&tree)?;
    let bprefix = state::blob_ref_prefix(did, gen);
    let mut it = db.scan(bprefix.clone()..state::prefix_end(&bprefix)).await?;
    let mut blobs = HashSet::new();
    while let Some(kv) = it.next().await? {
        let rest = &kv.key[bprefix.len()..];
        let cid = rest.split(|b| *b == 0).next().unwrap_or_default();
        blobs.insert(cid.to_vec());
    }
    Ok(RepoStats {
        records,
        nodes,
        blobs: blobs.len() as u64,
        bytes: Some(RepoBytes { records: record_bytes, nodes: node_bytes }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rows_with_and_without_bytes() {
        let full = RepoStats { records: 3, nodes: 2, blobs: 1, bytes: Some(RepoBytes { records: 900, nodes: 200 }) };
        assert_eq!(full.encode().len(), RepoStats::LEN);
        assert_eq!(RepoStats::decode(&full.encode()).unwrap(), full);
        // a row from before bytes were counted: its next load counts them
        let old = RepoStats { bytes: None, ..full };
        assert_eq!(old.encode().len(), 24);
        assert_eq!(RepoStats::decode(&old.encode()).unwrap(), old);
        assert!(RepoStats::decode(&[0; 32]).is_err());
    }

    #[test]
    fn commits_keep_bytes_close() {
        let before =
            RepoStats { records: 10, nodes: 4, blobs: 0, bytes: Some(RepoBytes { records: 1000, nodes: 400 }) };
        let mut b = before.bytes.unwrap();
        // two creates of 150 bytes and one delete (the mean, 100); a new
        // node of 120 bytes and one replaced (the mean, 100)
        b.commit(&before, 300, 1, 120, 1);
        assert_eq!(b, RepoBytes { records: 1200, nodes: 420 });
        // never below zero
        let mut z = RepoBytes { records: 10, nodes: 0 };
        z.commit(&RepoStats { records: 1, ..Default::default() }, 0, 5, 0, 3);
        assert_eq!(z, RepoBytes::default());
    }

    #[test]
    fn the_empty_tree_has_no_bytes() {
        assert_eq!(tree_bytes(&Tree::new()).unwrap(), 0, "the empty tree's root isn't counted");
    }
}
