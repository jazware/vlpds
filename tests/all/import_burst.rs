//! A burst of importRepo calls at once, their repo sizes drawn from the real
//! network's records-per-repo distribution (`vlpds::real_dist`): throughput,
//! peak heap and per-import latency (admission wait included), and how many
//! were refused.
//!
//! ```text
//! IMPORT_BURST_N=400 cargo test --profile dev-release --features bench-jemalloc \
//!   --test all import_burst -- --ignored --nocapture
//! ```
//!
//! `IMPORT_BURST_SEED` picks the draw, `IMPORT_BURST_CAP` caps a repo's
//! records (default 100,000: above p99.9), and `IMPORT_BURST_BIG` adds that
//! many p99.9 repos (62,685 records; default 1). `IMPORT_BURST_LATENCY_MS`
//! (default 25, the median; lognormal, sigma 0.3) delays the commit log's
//! segment writes, as S3 would. `IMPORT_BURST_BUDGET_MB` sets the import
//! budget (default: the memory plan's).
use crate::common::*;
use crate::import_bench::{jemalloc, Sized};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use vlatproto::cbor::key_cmp;

fn env_or<T: std::str::FromStr>(k: &str, d: T) -> T {
    std::env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(d)
}

fn mix(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
}

fn unit(x: u64) -> f64 {
    (x >> 11) as f64 / (1u64 << 53) as f64
}

const S32: &[u8] = b"234567abcdefghijklmnopqrstuvwxyz";

fn tid(t: u64) -> String {
    (0..13).rev().map(|i| S32[((t >> (i * 5)) & 31) as usize] as char).collect()
}

/// A record shaped like the network's mix (likes, follows, posts, reposts,
/// blocks).
fn record(h: u64, i: usize) -> (&'static str, Vec<u8>) {
    let did = |x: u64| format!("did:plc:{}", &tid(mix(x)).repeat(2)[..24]);
    let strong = |x: u64| {
        Value::Map(vec![
            ("cid".to_string(), Value::Text("bafyreie5737gdxlw5i64vzichcalba3z2v5n6icifvx5xytvske7mr3hpm".into())),
            ("uri".to_string(), Value::Text(format!("at://{}/app.bsky.feed.post/{}", did(x), tid(mix(x ^ 1) >> 1)))),
        ])
    };
    let r = unit(h) * 100.0;
    let (coll, mut m) = if r < 65.0 {
        ("app.bsky.feed.like", vec![("subject".to_string(), strong(h))])
    } else if r < 77.0 {
        ("app.bsky.graph.follow", vec![("subject".to_string(), Value::Text(did(h)))])
    } else if r < 88.0 {
        let len = 20 + (h % 260) as usize;
        let text: String =
            (0..len).map(|k| if k % 6 == 5 { ' ' } else { (b'a' + ((h >> (k % 50)) % 26) as u8) as char }).collect();
        (
            "app.bsky.feed.post",
            vec![
                ("text".to_string(), Value::Text(text)),
                ("langs".to_string(), Value::Array(vec![Value::Text("en".into())])),
            ],
        )
    } else if r < 97.0 {
        ("app.bsky.feed.repost", vec![("subject".to_string(), strong(h))])
    } else {
        ("app.bsky.graph.block", vec![("subject".to_string(), Value::Text(did(h)))])
    };
    m.push(("$type".to_string(), Value::Text(coll.into())));
    m.push(("createdAt".to_string(), Value::Text(format!("2025-0{}-1{}T00:00:00.000Z", 1 + i % 9, i % 10))));
    m.sort_by(|a, b| key_cmp(&a.0, &b.0));
    (coll, Value::Map(m).to_cbor())
}

/// A streamable-order CAR of `n` records.
pub(crate) fn repo_car(seed: u64, n: usize) -> Vec<u8> {
    let mut tree = vlatproto::mst::Tree::new();
    let mut blocks: HashMap<Cid, Vec<u8>> = HashMap::with_capacity(n + n / 3);
    let mut t = 0x1_7000_0000_0000u64 + (mix(seed) & 0xffff_ffff);
    for i in 0..n {
        let h = mix(seed.wrapping_mul(1_000_003) ^ i as u64);
        t += 1 + (h & 0xfff_ffff);
        let (coll, rec) = record(h, i);
        let c = Cid::dag_cbor(&rec);
        tree.insert_no_proof(format!("{coll}/{}", tid(t)).as_bytes(), c).unwrap();
        blocks.insert(c, rec);
    }
    let mut extra = Vec::new();
    let data = tree.write_diff_blocks(&mut extra).unwrap();
    blocks.extend(extra);
    let mut f = vec![
        ("did".to_string(), Value::Text("did:plc:burst".into())),
        ("rev".to_string(), Value::Text("3l3qo2vuowo2b".into())),
        ("data".to_string(), Value::Link(data)),
        ("prev".to_string(), Value::Null),
        ("version".to_string(), Value::Int(3)),
        ("sig".to_string(), Value::Bytes(vec![0; 64])),
    ];
    f.sort_by(|a, b| key_cmp(&a.0, &b.0));
    let commit = Value::Map(f).to_cbor();
    vlatproto::car_order::write_car((Cid::dag_cbor(&commit), &commit), data, &blocks).unwrap()
}

/// The sum over a metric family's series, 0 if it doesn't exist.
fn gauge(name: &str, label: Option<(&str, &str)>) -> f64 {
    prometheus::gather()
        .iter()
        .filter(|mf| mf.name() == name)
        .flat_map(|mf| mf.get_metric().iter())
        .filter(|m| label.is_none_or(|(k, v)| m.get_label().iter().any(|l| l.name() == k && l.value() == v)))
        .map(|m| m.get_gauge().get_value())
        .sum()
}

fn pct(v: &mut [f64], q: f64) -> f64 {
    if v.is_empty() {
        return 0.0;
    }
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[((v.len() - 1) as f64 * q).round() as usize]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore]
async fn import_burst() {
    let n: usize = env_or("IMPORT_BURST_N", 400);
    let seed: u64 = env_or("IMPORT_BURST_SEED", 1);
    let cap: u32 = env_or("IMPORT_BURST_CAP", 100_000);
    let big: usize = env_or("IMPORT_BURST_BIG", 1);
    let latency: f64 = env_or("IMPORT_BURST_LATENCY_MS", 25.0);
    let budget: Option<u64> =
        std::env::var("IMPORT_BURST_BUDGET_MB").ok().and_then(|v| v.parse().ok()).map(|m: u64| m << 20);
    let mut sizes: Vec<usize> = (0..n as u64)
        .map(|i| vlpds::real_dist::draw(unit(mix(seed ^ (i << 1))), unit(mix(seed ^ (i << 1 | 1)))).min(cap) as usize)
        .collect();
    sizes.extend(std::iter::repeat_n(62_685, big));
    let total = sizes.len();
    let t = Instant::now();
    let cars: Vec<bytes::Bytes> = {
        let idx: Vec<(usize, usize)> = sizes.iter().copied().enumerate().collect();
        let chunks: Vec<Vec<(usize, usize)>> = idx.chunks(total.div_ceil(8).max(1)).map(|c| c.to_vec()).collect();
        let mut out: Vec<(usize, Vec<u8>)> = std::thread::scope(|s| {
            let hs: Vec<_> = chunks
                .into_iter()
                .map(|c| {
                    s.spawn(move || {
                        c.into_iter().map(|(i, k)| (i, repo_car(seed ^ (i as u64) << 20, k))).collect::<Vec<_>>()
                    })
                })
                .collect();
            hs.into_iter().flat_map(|h| h.join().unwrap()).collect()
        });
        out.sort_by_key(|(i, _)| *i);
        out.into_iter().map(|(_, c)| bytes::Bytes::from(c)).collect()
    };
    let car_bytes: u64 = cars.iter().map(|c| c.len() as u64).sum();
    let records: u64 = sizes.iter().map(|&k| k as u64).sum();
    println!(
        "{total} repos ({records} records, CAR {:.1} MB, {:.0} B/record; max {} records) generated in {:.1}s",
        car_bytes as f64 / 1e6,
        car_bytes as f64 / records.max(1) as f64,
        sizes.iter().max().unwrap(),
        t.elapsed().as_secs_f64()
    );

    let store = Arc::new(Sized::default());
    let held = store.bytes.clone();
    let s = TestServer::spawn_with(move |c| {
        c.memory.block = Some(64 << 20);
        c.memory.meta = Some(16 << 20);
        c.allow_bulk_create = true;
        c.memory_store = Some(store);
        c.inject_latency = (latency > 0.0).then_some((latency, 0.3));
        c.import_memory_bytes = budget;
    })
    .await;
    let start = 9_000_000u64;
    let r = s
        .xrpc
        .post(
            "vlpds.admin.bulkCreate",
            &json!({"start": start, "count": total, "records": 0}),
            &Auth::Bearer(ADMIN_TOKEN.into()),
        )
        .await;
    assert_eq!(r.status, 200, "{}", r.text());
    let tokens: Vec<String> = (0..total as u64).map(|i| s.app.jwt.access(&vlpds::state::bulk_did(start + i))).collect();

    tokio::time::sleep(Duration::from_secs(2)).await;
    let (base_alloc, base_res) = jemalloc();
    let base_held = held.load(Ordering::Relaxed);
    let stop = Arc::new(AtomicBool::new(false));
    let peaks: Arc<[AtomicU64; 4]> = Arc::new(Default::default());
    let sampler = {
        let (stop, peaks, held) = (stop.clone(), peaks.clone(), held.clone());
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                let (al, rs) = jemalloc();
                let bucket = (held.load(Ordering::Relaxed) - base_held).max(0) as u64;
                peaks[0].fetch_max(al.saturating_sub(bucket).saturating_sub(base_alloc), Ordering::Relaxed);
                peaks[1].fetch_max(rs.saturating_sub(bucket).saturating_sub(base_res), Ordering::Relaxed);
                peaks[2].fetch_max(gauge("vlpds_import_reserved_bytes", None) as u64, Ordering::Relaxed);
                peaks[3].fetch_max(gauge("vlpds_imports", Some(("state", "running"))) as u64, Ordering::Relaxed);
                std::thread::sleep(Duration::from_millis(2));
            }
        })
    };
    let url = format!("{}/xrpc/com.atproto.repo.importRepo", s.xrpc.base);
    // the suite's client gives up after 30 s
    let http = reqwest::Client::builder().timeout(Duration::from_secs(600)).build().unwrap();
    let t0 = Instant::now();
    let tasks: Vec<_> = cars
        .into_iter()
        .zip(tokens)
        .map(|(car, tok)| {
            let (http, url) = (http.clone(), url.clone());
            tokio::spawn(async move {
                match http
                    .post(url)
                    .header("content-type", "application/vnd.ipld.car")
                    .bearer_auth(tok)
                    .body(car)
                    .send()
                    .await
                {
                    Ok(r) => {
                        let status = r.status().as_u16();
                        let text = r.text().await.unwrap_or_default();
                        (status, t0.elapsed(), text)
                    }
                    Err(e) => (0, t0.elapsed(), e.to_string()),
                }
            })
        })
        .collect();
    let mut out = Vec::new();
    for t in tasks {
        out.push(t.await.unwrap());
    }
    let wall = t0.elapsed();
    stop.store(true, Ordering::Relaxed);
    sampler.join().unwrap();

    let p90 = vlpds::real_dist::quantile(0.9) as usize;
    let mut by_status: std::collections::BTreeMap<u16, usize> = Default::default();
    let (mut small, mut large) = (Vec::new(), Vec::new());
    let mut ok_records = 0u64;
    for ((status, took, text), &k) in out.iter().zip(&sizes) {
        *by_status.entry(*status).or_default() += 1;
        if *status == 200 {
            ok_records += k as u64;
        } else if by_status[status] <= 2 {
            println!("  {status} ({k} records): {text}");
        }
        let v = if k <= p90 { &mut small } else { &mut large };
        v.push(took.as_secs_f64() * 1e3);
    }
    let mb = |v: u64| v as f64 / (1 << 20) as f64;
    println!(
        "burst of {total}: {:.2}s, {:.0} imports/s, {:.0} records/s; statuses {by_status:?}",
        wall.as_secs_f64(),
        by_status.get(&200).copied().unwrap_or(0) as f64 / wall.as_secs_f64(),
        ok_records as f64 / wall.as_secs_f64(),
    );
    println!(
        "  latency ms, repos <= p90 ({} of them): p50 {:.0} p90 {:.0} p99 {:.0} max {:.0}",
        small.len(),
        pct(&mut small, 0.5),
        pct(&mut small, 0.9),
        pct(&mut small, 0.99),
        pct(&mut small, 1.0)
    );
    println!(
        "  latency ms, repos > p90 ({} of them): p50 {:.0} p90 {:.0} p99 {:.0} max {:.0}",
        large.len(),
        pct(&mut large, 0.5),
        pct(&mut large, 0.9),
        pct(&mut large, 0.99),
        pct(&mut large, 1.0)
    );
    let ld = |i: usize| peaks[i].load(Ordering::Relaxed);
    println!(
        "  peak over baseline (bucket left out): heap {:.0} MB, resident {:.0} MB; peak import reservation {:.0} MB of {:.0}, peak running {}",
        mb(ld(0)),
        mb(ld(1)),
        mb(ld(2)),
        mb(s.app.imports.total()),
        ld(3)
    );
}
