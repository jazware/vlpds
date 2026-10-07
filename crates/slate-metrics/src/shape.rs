use crate::bridge::{Bridge, Kind};
use serde::{Deserialize, Serialize};
use slatedb::DbStatus;

/// One database's LSM shape and the counters that explain it.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DbShape {
    /// The `db` label it was registered under.
    pub db: String,
    /// `writer` or `reader`.
    pub role: String,
    pub manifest_id: u64,
    pub durable_seq: u64,
    pub l0_ssts: u64,
    pub l0_bytes: u64,
    /// The manifest's order: newest first.
    pub sorted_runs: Vec<RunShape>,
    /// L0 plus every sorted run's.
    pub sst_count: u64,
    /// Estimated from each SST's index offset (SlateDB keeps no exact size).
    pub total_bytes: u64,
    pub checkpoints: u64,
    /// Clones' sources whose SSTs this database still reads.
    pub external_dbs: u64,
    /// Mutable plus immutable memtables (`slatedb_db_total_mem_size_bytes`);
    /// None on a handle that doesn't write.
    pub memtable_bytes: Option<i64>,
    /// WAL buffered but not yet uploaded.
    pub wal_buffer_bytes: Option<i64>,
    /// Block and metadata cache lookups since the handle opened, by entry kind.
    pub cache: Vec<CacheAccess>,
    pub compaction: CompactionShape,
    pub stalls: StallShape,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RunShape {
    pub id: u32,
    pub ssts: u64,
    pub bytes: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CacheAccess {
    /// `data_block`, `index`, `filter` or `stats`.
    pub kind: String,
    pub hits: u64,
    pub misses: u64,
}

/// From the in-process compactor, if this database runs one.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompactionShape {
    pub running: Option<i64>,
    pub bytes_in_flight: Option<i64>,
    pub bytes_compacted: u64,
    /// Unix seconds of the last finished compaction.
    pub last_at_secs: Option<i64>,
}

/// Writes held back since the handle opened.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StallShape {
    /// Writes that waited on the memtable/WAL size limit.
    pub backpressure: u64,
    /// Writes that waited on too many L0 SSTs.
    pub l0_stalls: u64,
}

/// What the manifest alone says, for the shape and the scrape-time series.
pub(crate) struct Totals {
    pub l0_ssts: u64,
    pub l0_bytes: u64,
    pub runs: Vec<RunShape>,
    pub checkpoints: u64,
    pub external_dbs: u64,
    pub manifest_id: u64,
}

impl Totals {
    pub(crate) fn of(status: &DbStatus) -> Totals {
        let m = &status.current_manifest;
        let run = |r: &slatedb::manifest::SortedRun| RunShape {
            id: r.id,
            ssts: r.sst_views().len() as u64,
            bytes: r.estimate_size(),
        };
        let mut l0_ssts = m.l0().len() as u64;
        let mut l0_bytes: u64 = m.l0().iter().map(|v| v.estimate_size()).sum();
        let mut runs: Vec<RunShape> = m.compacted().iter().map(run).collect();
        for s in m.segments() {
            l0_ssts += s.l0().len() as u64;
            l0_bytes += s.l0().iter().map(|v| v.estimate_size()).sum::<u64>();
            runs.extend(s.compacted().iter().map(run));
        }
        Totals {
            l0_ssts,
            l0_bytes,
            runs,
            checkpoints: m.checkpoints().len() as u64,
            external_dbs: m.external_dbs().len() as u64,
            manifest_id: m.id(),
        }
    }

    pub(crate) fn compacted_ssts(&self) -> u64 {
        self.runs.iter().map(|r| r.ssts).sum()
    }

    pub(crate) fn compacted_bytes(&self) -> u64 {
        self.runs.iter().map(|r| r.bytes).sum()
    }
}

pub(crate) fn of(name: &str, role: &str, status: &DbStatus, b: &Bridge) -> DbShape {
    use slatedb::compactor::stats as compactor;
    use slatedb::{db_cache_stats, db_stats, wal_buffer_stats};

    let t = Totals::of(status);
    let db = Some(name);
    let count = |name: &str| b.sum(Kind::Counter, name, db).unwrap_or(0.0) as u64;
    let gauge = |name: &str| b.gauge_sum(name, db);

    let mut cache: Vec<CacheAccess> = Vec::new();
    for (labels, v) in b.series(Kind::Counter, db_cache_stats::ACCESS_COUNT, db) {
        let get = |k: &str| labels.iter().find(|(lk, _)| lk == k).map(|(_, v)| v.as_str()).unwrap_or("");
        let kind = get("entry_kind");
        let i = match cache.iter().position(|c| c.kind == kind) {
            Some(i) => i,
            None => {
                cache.push(CacheAccess { kind: kind.to_string(), ..Default::default() });
                cache.len() - 1
            }
        };
        match get("result") {
            "hit" => cache[i].hits += v as u64,
            _ => cache[i].misses += v as u64,
        }
    }
    cache.sort_by(|a, b| a.kind.cmp(&b.kind));

    DbShape {
        db: name.to_string(),
        role: role.to_string(),
        manifest_id: t.manifest_id,
        durable_seq: status.durable_seq,
        l0_ssts: t.l0_ssts,
        l0_bytes: t.l0_bytes,
        sst_count: t.l0_ssts + t.compacted_ssts(),
        total_bytes: t.l0_bytes + t.compacted_bytes(),
        sorted_runs: t.runs,
        checkpoints: t.checkpoints,
        external_dbs: t.external_dbs,
        memtable_bytes: gauge(db_stats::TOTAL_MEM_SIZE_BYTES),
        wal_buffer_bytes: gauge(wal_buffer_stats::WAL_BUFFER_ESTIMATED_BYTES),
        cache,
        compaction: CompactionShape {
            running: gauge(compactor::RUNNING_COMPACTIONS),
            bytes_in_flight: gauge(compactor::TOTAL_BYTES_BEING_COMPACTED),
            bytes_compacted: count(compactor::BYTES_COMPACTED),
            last_at_secs: gauge(compactor::LAST_COMPACTION_TS_SEC),
        },
        stalls: StallShape {
            backpressure: count(db_stats::BACKPRESSURE_COUNT),
            l0_stalls: count(db_stats::L0_STALL_COUNT),
        },
    }
}
