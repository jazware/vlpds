//! Durable space repo heads, for reads: what the last acked write of each
//! (account, space) left, published by the write's ack as `DurableView` is
//! for public repos. A no-op `listRepoOps` (`since` == head) is answered
//! from here without touching SlateDB.
//!
//! Byte-bounded LRU. An entry remembers the shard (and epoch) it was read
//! or written under: one whose shard this node no longer holds at that
//! epoch is never served, and a closing shard's entries are dropped.

use super::lthash::LtHash;
use crate::state::SpaceId;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use vlatproto::tid::Tid;
use vlsync_store::slots::ShardId;

#[derive(Clone, Debug)]
pub struct DurableSpaceHead {
    pub uri: Arc<str>,
    pub rev: Tid,
    pub hash: LtHash,
    pub records: u64,
    pub created: u64,
    pub shard: ShardId,
    pub epoch: u64,
}

impl DurableSpaceHead {
    fn bytes(&self) -> usize {
        std::mem::size_of::<Self>() + self.uri.len() + 64
    }
}

type Key = (Arc<str>, SpaceId);

pub struct Heads {
    inner: parking_lot::Mutex<Inner>,
    max_bytes: usize,
    /// SlateDB reads of `sH` made for readers (tests check no-op polls make none).
    pub loads: AtomicU64,
}

struct Inner {
    map: lru::LruCache<Key, Arc<DurableSpaceHead>>,
    bytes: usize,
}

pub const DEFAULT_HEADS_BYTES: usize = 64 << 20;

impl Heads {
    pub fn new(max_bytes: usize) -> Heads {
        Heads {
            inner: parking_lot::Mutex::new(Inner { map: lru::LruCache::unbounded(), bytes: 0 }),
            max_bytes,
            loads: AtomicU64::new(0),
        }
    }

    /// The cached head, if it was read or written under `(shard, epoch)`.
    pub fn get(&self, did: &str, sid: &SpaceId, shard: ShardId, epoch: u64) -> Option<Arc<DurableSpaceHead>> {
        let mut g = self.inner.lock();
        let key: Key = (did.into(), *sid);
        let h = g.map.get(&key)?.clone();
        if h.shard == shard && h.epoch == epoch {
            return Some(h);
        }
        if let Some(old) = g.map.pop(&key) {
            g.bytes -= old.bytes();
        }
        None
    }

    /// Keeps the newer of `head` and what is cached (a reader's load can
    /// race a write's ack).
    pub fn publish(&self, did: &str, sid: &SpaceId, head: Arc<DurableSpaceHead>) {
        let mut g = self.inner.lock();
        let key: Key = (did.into(), *sid);
        if let Some(cur) = g.map.peek(&key) {
            if cur.shard == head.shard && cur.epoch == head.epoch && cur.rev >= head.rev {
                return;
            }
        }
        g.bytes += head.bytes();
        if let Some(old) = g.map.put(key, head) {
            g.bytes -= old.bytes();
        }
        while g.bytes > self.max_bytes {
            let Some((_, old)) = g.map.pop_lru() else { break };
            g.bytes -= old.bytes();
        }
    }

    pub fn note_load(&self) {
        self.loads.fetch_add(1, Ordering::Relaxed);
    }

    pub fn drop_shard(&self, shard: ShardId) {
        let mut g = self.inner.lock();
        let gone: Vec<Key> = g.map.iter().filter(|(_, h)| h.shard == shard).map(|(k, _)| k.clone()).collect();
        for k in gone {
            if let Some(old) = g.map.pop(&k) {
                g.bytes -= old.bytes();
            }
        }
    }

    pub fn drop_space(&self, did: &str, sid: &SpaceId) {
        let mut g = self.inner.lock();
        if let Some(old) = g.map.pop(&(did.into(), *sid)) {
            g.bytes -= old.bytes();
        }
    }

    pub fn drop_did(&self, did: &str) {
        let mut g = self.inner.lock();
        let gone: Vec<Key> = g.map.iter().filter(|(k, _)| &*k.0 == did).map(|(k, _)| k.clone()).collect();
        for k in gone {
            if let Some(old) = g.map.pop(&k) {
                g.bytes -= old.bytes();
            }
        }
    }

    pub fn len(&self) -> usize {
        self.inner.lock().map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head(rev: u64, shard: u32, epoch: u64) -> Arc<DurableSpaceHead> {
        Arc::new(DurableSpaceHead {
            uri: "at://x".into(),
            rev: Tid(rev),
            hash: LtHash::default(),
            records: 0,
            created: 0,
            shard: ShardId(shard),
            epoch,
        })
    }

    #[test]
    fn newest_wins_and_moved_shards_miss() {
        let h = Heads::new(1 << 20);
        let sid = [1; 16];
        h.publish("did:a", &sid, head(5, 0, 1));
        h.publish("did:a", &sid, head(3, 0, 1));
        assert_eq!(h.get("did:a", &sid, ShardId(0), 1).unwrap().rev, Tid(5));
        // another epoch of the shard: not served, and dropped
        assert!(h.get("did:a", &sid, ShardId(0), 2).is_none());
        assert!(h.is_empty());
        h.publish("did:a", &sid, head(5, 0, 1));
        h.drop_shard(ShardId(0));
        assert!(h.get("did:a", &sid, ShardId(0), 1).is_none());
        // bounded
        let small = Heads::new(head(1, 0, 1).bytes() * 2);
        for i in 0..10u8 {
            small.publish("did:a", &[i; 16], head(1, 0, 1));
        }
        assert_eq!(small.len(), 2);
    }
}
