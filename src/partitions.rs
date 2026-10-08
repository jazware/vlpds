//! The shards this node has open, and the layout it routes by.

use crate::partition::Partition;
use parking_lot::RwLock;
use std::collections::BTreeMap;
use std::sync::Arc;
use vlsync_store::slots::{Layout, ShardId};

pub struct PartitionTable {
    layout: RwLock<Arc<Layout>>,
    open: RwLock<BTreeMap<ShardId, Arc<Partition>>>,
}

impl PartitionTable {
    /// Starts with the uniform layout of `n` shards until the cluster's is read.
    pub fn new(n: u32) -> Arc<PartitionTable> {
        Arc::new(PartitionTable { layout: RwLock::new(Arc::new(Layout::uniform(n))), open: RwLock::default() })
    }

    pub fn layout(&self) -> Arc<Layout> {
        self.layout.read().clone()
    }

    /// Installs `l` whatever its version.
    pub fn replace_layout(&self, l: Arc<Layout>) {
        *self.layout.write() = l;
    }

    /// Ignores older versions.
    pub fn set_layout(&self, l: Arc<Layout>) {
        let mut cur = self.layout.write();
        if l.version > cur.version || (l.version == cur.version && l.op != cur.op) {
            *cur = l;
        }
    }

    pub fn shard_of(&self, key: &str) -> ShardId {
        self.layout.read().shard_of(key)
    }

    pub fn for_key(&self, key: &str) -> Option<Arc<Partition>> {
        self.get(self.shard_of(key))
    }

    /// Shards in the layout, owned or not.
    pub fn len(&self) -> usize {
        self.layout.read().shards.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn get(&self, id: ShardId) -> Option<Arc<Partition>> {
        self.open.read().get(&id).cloned()
    }

    pub fn set(&self, id: ShardId, part: Option<Arc<Partition>>) {
        let mut open = self.open.write();
        match part {
            Some(p) => open.insert(id, p),
            None => open.remove(&id),
        };
    }

    pub fn owned(&self) -> Vec<Arc<Partition>> {
        self.open.read().values().cloned().collect()
    }
}
