# slate-metrics

SlateDB's own metrics in Prometheus with a `db` label per database, and each open database's
LSM shape (L0, sorted runs, bytes, memtable, cache, compaction, stalls) as a serializable
`DbShape` for admin views. vlpds labels its shards (`shard_<id>`, `shard_<id>_reader`), vlRelay
its quorum state and PLC seeds.

## Using it

Depend on it by path, with the same SlateDB fork patch as vlpds (`packages/vlpds/Cargo.toml`),
so SlateDB and this crate share one `slatedb-common` and its recorder trait:

```toml
[dependencies]
slate-metrics = { path = "../vlpds/crates/slate-metrics" }

[patch.crates-io]
slatedb = { git = "https://github.com/jazware/slatedb", rev = "<vlpds's rev>" }
slatedb-common = { git = "https://github.com/jazware/slatedb", rev = "<vlpds's rev>" }
```

Give every builder of a database (`Db`, `DbReader`, a standalone compactor or worker) the
recorder for its name, then register the built handle:

```rust
let db = slatedb::Db::builder(path, store)
    .with_metrics_recorder(slate_metrics::recorder("objects"))
    .build()
    .await?;
slate_metrics::register("objects", &db); // a DbReader: register_reader
// a block cache several databases share: slate_metrics::register_cache("node", cache)

// an admin endpoint
let dbs: Vec<slate_metrics::DbShape> = slate_metrics::shapes();
```

The free functions export into Prometheus's default registry (`prometheus::gather()`); a
service with its own registry makes one `slate_metrics::Exporter::new(&registry)` and calls the
same methods on it.

## What it exports

SlateDB's names with dots as underscores, counters with `_total`, `db` first in the labels
(`slatedb_db_l0_sst_count{db}`, `slatedb_db_total_mem_size_bytes{db}`,
`slatedb_db_cache_access_count_total{db,entry_kind,result}`,
`slatedb_compactor_bytes_compacted_total{db}`, `slatedb_db_l0_stall_count_total{db,type}`…).
Labels ending in `_id` are dropped (the compactor worker's ULID is new every start). Two handles
on one series (a reopened database before the old handle drops) add up; a series goes when its
last handle drops.

At scrape time, from each registered handle's manifest in memory (so readers too):
`slatedb_lsm_ssts{db,tier}`, `slatedb_lsm_sst_bytes{db,tier}` (`l0`, `compacted`; estimates),
`slatedb_lsm_sorted_runs{db}`, `slatedb_lsm_largest_run_bytes{db}`,
`slatedb_lsm_checkpoints{db}`, `slatedb_lsm_manifest_id{db}`, and
`slatedb_cache_entries{cache}`.

Cost: nothing polls. SlateDB pushes its values into atomics, and a scrape or `shapes()` walks
each manifest's SST list (microseconds for thousands of SSTs). Each database adds its own copy
of SlateDB's series, about 150 with the object store latency histogram's buckets.
