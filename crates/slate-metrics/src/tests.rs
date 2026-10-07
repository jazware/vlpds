use super::*;
use object_store::memory::InMemory;
use prometheus::proto::MetricFamily;

fn label_sets(fams: &[MetricFamily], name: &str) -> Vec<Vec<(String, String)>> {
    fams.iter()
        .filter(|f| f.name() == name)
        .flat_map(|f| f.get_metric())
        .map(|m| m.get_label().iter().map(|l| (l.name().to_string(), l.value().to_string())).collect())
        .collect()
}

fn dbs_of(fams: &[MetricFamily], name: &str) -> Vec<String> {
    let mut v: Vec<String> = label_sets(fams, name)
        .into_iter()
        .filter_map(|ls| ls.into_iter().find(|(k, _)| k == "db").map(|(_, v)| v))
        .collect();
    v.sort();
    v.dedup();
    v
}

fn value(fams: &[MetricFamily], name: &str, labels: &[(&str, &str)]) -> Option<f64> {
    let f = fams.iter().find(|f| f.name() == name)?;
    f.get_metric()
        .iter()
        .find(|m| labels.iter().all(|(k, v)| m.get_label().iter().any(|l| l.name() == *k && l.value() == *v)))
        .map(|m| m.get_counter().get_value() + m.get_gauge().get_value())
}

#[test]
fn labels_put_db_first_and_drop_instance_ids() {
    let reg = Registry::new();
    let ex = Exporter::new(&reg);
    let r = ex.recorder("seeds");
    let c = r.register_counter("slatedb.compactor.ssts_written", "", &[("worker_id", "01J"), ("kind", "x")]);
    c.increment(3);
    let fams = reg.gather();
    assert_eq!(
        label_sets(&fams, "slatedb_compactor_ssts_written_total"),
        vec![vec![("db".to_string(), "seeds".to_string()), ("kind".to_string(), "x".to_string())]]
    );
    assert_eq!(value(&fams, "slatedb_compactor_ssts_written_total", &[("db", "seeds")]), Some(3.0));
}

#[test]
fn gauges_sum_shares_and_series_leave_with_their_last_handle() {
    let reg = Registry::new();
    let ex = Exporter::new(&reg);
    let (a1, a2, b) = (ex.recorder("a"), ex.recorder("a"), ex.recorder("b"));
    let g1 = a1.register_gauge("slatedb.db.l0_sst_count", "", &[]);
    let g2 = a2.register_gauge("slatedb.db.l0_sst_count", "", &[]);
    let gb = b.register_gauge("slatedb.db.l0_sst_count", "", &[]);
    g1.set(4);
    g2.set(3);
    gb.set(7);
    let fams = reg.gather();
    assert_eq!(value(&fams, "slatedb_db_l0_sst_count", &[("db", "a")]), Some(7.0));
    assert_eq!(value(&fams, "slatedb_db_l0_sst_count", &[("db", "b")]), Some(7.0));
    assert_eq!(ex.gauge_sum("slatedb.db.l0_sst_count"), Some(14));

    drop(g1);
    let fams = reg.gather();
    assert_eq!(value(&fams, "slatedb_db_l0_sst_count", &[("db", "a")]), Some(3.0));
    drop(g2);
    assert_eq!(dbs_of(&reg.gather(), "slatedb_db_l0_sst_count"), vec!["b"]);

    let c = a1.register_counter("slatedb.db.write_ops", "", &[]);
    c.increment(1);
    assert_eq!(dbs_of(&reg.gather(), "slatedb_db_write_ops_total"), vec!["a"]);
    drop(c);
    assert!(dbs_of(&reg.gather(), "slatedb_db_write_ops_total").is_empty());
}

#[test]
fn a_name_registered_with_other_label_keys_gets_a_noop() {
    let reg = Registry::new();
    let ex = Exporter::new(&reg);
    let r = ex.recorder("a");
    let first = r.register_counter("slatedb.db.request_count", "", &[("op", "get")]);
    let other = r.register_counter("slatedb.db.request_count", "", &[]);
    first.increment(1);
    other.increment(5);
    let fams = reg.gather();
    assert_eq!(value(&fams, "slatedb_db_request_count_total", &[("db", "a"), ("op", "get")]), Some(1.0));
    assert_eq!(label_sets(&fams, "slatedb_db_request_count_total").len(), 1);
}

async fn open(store: &Arc<InMemory>, ex: &Exporter, name: &str) -> slatedb::Db {
    let db = slatedb::Db::builder(name, store.clone() as Arc<dyn object_store::ObjectStore>)
        .with_metrics_recorder(ex.recorder(name))
        .build()
        .await
        .unwrap();
    ex.register(name, &db);
    db
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_dbs_in_one_process_get_distinct_series_and_shapes() {
    let reg = Registry::new();
    let ex = Exporter::new(&reg);
    let store = Arc::new(InMemory::new());
    let a = open(&store, &ex, "alpha").await;
    let b = open(&store, &ex, "beta").await;
    for i in 0..10u32 {
        a.put(i.to_be_bytes(), [0u8; 100]).await.unwrap();
    }
    a.flush_with_options(slatedb::config::FlushOptions { flush_type: slatedb::config::FlushType::MemTable })
        .await
        .unwrap();
    b.put(b"k", b"v").await.unwrap();

    let fams = reg.gather();
    assert_eq!(dbs_of(&fams, "slatedb_db_write_ops_total"), vec!["alpha", "beta"]);
    assert_eq!(dbs_of(&fams, "slatedb_db_total_mem_size_bytes"), vec!["alpha", "beta"]);
    assert_eq!(dbs_of(&fams, "slatedb_lsm_ssts"), vec!["alpha", "beta"]);
    assert_eq!(value(&fams, "slatedb_db_write_ops_total", &[("db", "alpha")]), Some(10.0));
    assert_eq!(value(&fams, "slatedb_db_write_ops_total", &[("db", "beta")]), Some(1.0));
    assert_eq!(value(&fams, "slatedb_lsm_ssts", &[("db", "alpha"), ("tier", "l0")]), Some(1.0));
    assert_eq!(value(&fams, "slatedb_lsm_ssts", &[("db", "beta"), ("tier", "l0")]), Some(0.0));
    assert!(value(&fams, "slatedb_lsm_sst_bytes", &[("db", "alpha"), ("tier", "l0")]).unwrap() > 0.0);

    let shapes = ex.shapes();
    assert_eq!(shapes.iter().map(|s| s.db.as_str()).collect::<Vec<_>>(), ["alpha", "beta"]);
    let s = &shapes[0];
    assert_eq!((s.role.as_str(), s.l0_ssts, s.sst_count), ("writer", 1, 1));
    assert!(s.l0_bytes > 0 && s.total_bytes == s.l0_bytes);
    assert!(s.memtable_bytes.is_some());
    let j = serde_json::to_value(&shapes[1]).unwrap();
    assert!(j["l0Ssts"].is_u64() && j["sortedRuns"].is_array() && j["compaction"]["bytesCompacted"].is_u64());

    a.close().await.unwrap();
    drop(a);
    assert_eq!(ex.shapes().iter().map(|s| s.db.as_str()).collect::<Vec<_>>(), ["beta"]);
    let fams = reg.gather();
    assert_eq!(dbs_of(&fams, "slatedb_lsm_ssts"), vec!["beta"]);
    b.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reader_shows_its_manifest_and_one_handle_shows_per_name() {
    let reg = Registry::new();
    let ex = Exporter::new(&reg);
    let store = Arc::new(InMemory::new());
    let w = open(&store, &ex, "seeds").await;
    w.put(b"k", b"v").await.unwrap();
    w.flush_with_options(slatedb::config::FlushOptions { flush_type: slatedb::config::FlushType::MemTable })
        .await
        .unwrap();
    let r = slatedb::DbReader::builder("seeds", store.clone() as Arc<dyn object_store::ObjectStore>)
        .with_metrics_recorder(ex.recorder("seeds_reader"))
        .build()
        .await
        .unwrap();
    ex.register_reader("seeds_reader", &r);
    let shapes = ex.shapes();
    let rs = shapes.iter().find(|s| s.db == "seeds_reader").unwrap();
    assert_eq!((rs.role.as_str(), rs.l0_ssts), ("reader", 1));

    let r2 =
        slatedb::DbReader::builder("seeds", store.clone() as Arc<dyn object_store::ObjectStore>).build().await.unwrap();
    ex.register_reader("seeds_reader", &r2);
    r2.close().await.unwrap();
    drop(r2);
    assert_eq!(ex.shapes().iter().filter(|s| s.db == "seeds_reader").count(), 1, "the older handle shows again");
    ex.register_cache("shared", Arc::new(slatedb::db_cache::SplitCache::new()));
    let fams = reg.gather();
    assert_eq!(label_sets(&fams, "slatedb_lsm_manifest_id").len(), 2);
    assert_eq!(value(&fams, "slatedb_cache_entries", &[("cache", "shared")]), Some(0.0));
    r.close().await.unwrap();
    w.close().await.unwrap();
}
