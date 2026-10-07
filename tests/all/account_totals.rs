//! The account totals the dashboard exports (crate::totals) stay equal to
//! a full scan of the account and head rows through random account
//! lifecycles, handle changes, shard splits and merges, and shards moving
//! between nodes; and so do the per-domain counts listHandleDomains reads
//! from them, against its own `recount`.

use crate::common::*;
use rand::{Rng, SeedableRng};
use std::sync::Arc;
use std::time::{Duration, Instant};
use vlpds::slots::ShardId;
use vlpds::totals::{Totals, WINDOWS};

fn cluster(s: &TestServer) -> &vlpds::cluster::Cluster {
    s.app.cluster.as_deref().unwrap()
}

fn same(kept: &Totals, scanned: &Totals) -> Result<(), String> {
    let today = vlpds::totals::today();
    let windows = |t: &Totals| WINDOWS.map(|(_, d)| t.written_within(d, today));
    let heads: i64 = scanned.days.iter().map(|d| d.1).sum();
    if kept.accounts == scanned.accounts
        && windows(kept) == windows(scanned)
        && kept.repos() == heads
        && kept.suffixes == scanned.suffixes
        && (kept.unconfirmed, kept.no2fa) == (scanned.unconfirmed, scanned.no2fa)
    {
        return Ok(());
    }
    Err(format!(
        "kept {:?} {:?} {:?} {:?}, scanned {:?} {:?} {:?} {:?} ({heads} heads)",
        kept.accounts,
        windows(kept),
        kept.suffixes,
        (kept.unconfirmed, kept.no2fa),
        scanned.accounts,
        windows(scanned),
        scanned.suffixes,
        (scanned.unconfirmed, scanned.no2fa),
    ))
}

/// listHandleDomains' (domain, accounts) rows, kept or recounted; None
/// while partial.
async fn domain_counts(s: &TestServer, recount: bool) -> Option<Vec<(String, u64)>> {
    let q: &[(&str, &str)] = if recount { &[("recount", "true")] } else { &[] };
    let l = s.xrpc.get("vlpds.admin.listHandleDomains", q, &Auth::Admin).await.ok();
    if l["countsPartial"] == json!(true) {
        eprintln!("domain counts partial: {l}");
        return None;
    }
    let rows = l["domains"].as_array().unwrap().iter();
    Some(rows.map(|d| (d["domain"].as_str().unwrap().to_string(), d["accounts"].as_u64().unwrap())).collect())
}

/// Once every shard of the layout is open on one of `nodes`: each node's
/// kept totals equal its own scan. Returns their sum.
async fn check(nodes: &[&TestServer], what: &str) -> Totals {
    let r = eventually(Duration::from_secs(20), || async {
        let l = cluster(nodes[0]).layout();
        let open: usize = nodes.iter().map(|n| n.app.partitions.owned().len()).sum();
        if l.op.is_some() || open != l.shards.len() || nodes.iter().any(|n| *cluster(n).layout() != *l) {
            return None;
        }
        let mut sum = Totals::default();
        for n in nodes {
            let kept = vlpds::xrpc::totals(&n.app);
            let scanned = vlpds::xrpc::scan_totals(&n.app).await.ok()?;
            same(&kept, &scanned).map_err(|e| eprintln!("{what}: {e}")).ok()?;
            sum.merge(&kept);
        }
        for n in nodes {
            let (kept, recounted) = (domain_counts(n, false).await?, domain_counts(n, true).await?);
            if kept != recounted {
                eprintln!("{what}: domain counts kept {kept:?}, recounted {recounted:?}");
                return None;
            }
        }
        Some(sum)
    })
    .await;
    r.unwrap_or_else(|| panic!("{what}: kept totals never matched the scan"))
}

async fn admin(s: &TestServer, nsid: &str, body: J) -> J {
    s.xrpc.post(nsid, &body, &Auth::Admin).await.ok()
}

/// Random account ops on one node, with a split or merge now and then,
/// each followed by the comparison with a full scan; then the exported
/// gauges.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn random_lifecycles_match_a_scan() {
    let s = TestServer::spawn().await;
    let seed = rand::random::<u64>();
    eprintln!("seed {seed}");
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
    let mut live: Vec<TestAccount> = Vec::new();
    for _ in 0..4 {
        live.push(s.create_account("tot").await);
    }
    // never changed: what imports copy
    let src = s.create_account("tot").await;
    s.post(&src, "imported").await;
    for d in ["group-a.test", "at.group-a.test"] {
        admin(&s, "vlpds.admin.addHandleDomain", json!({"domain": d})).await;
    }
    check(&[&s], "start").await;
    let mut done = std::collections::BTreeMap::<&str, usize>::new();
    const OPS: usize = 15;
    for step in 0..90 {
        // every op once first, so each kind is exercised whatever the seed
        let op = if live.len() < 3 {
            0
        } else if step < OPS {
            step
        } else {
            rng.gen_range(0..OPS)
        };
        let i = rng.gen_range(0..live.len().max(1));
        let ok = match op {
            0 => {
                live.push(s.create_account("tot").await);
                ("create", true)
            }
            1 | 2 => {
                let r = s
                    .xrpc
                    .post(
                        "com.atproto.repo.createRecord",
                        &json!({"repo": live[i].did, "collection": "app.bsky.feed.post", "record": post_record("x")}),
                        &live[i].auth(),
                    )
                    .await;
                if !r.is_ok() {
                    eprintln!("write refused: {} {}", r.status, r.text());
                }
                ("write", r.is_ok())
            }
            3 => (
                "deactivate",
                s.xrpc.post("com.atproto.server.deactivateAccount", &json!({}), &live[i].auth()).await.is_ok(),
            ),
            4 => ("activate", s.xrpc.post_empty("com.atproto.server.activateAccount", &live[i].auth()).await.is_ok()),
            5 => {
                let applied = step < 12 || rng.gen_bool(0.6);
                set_repo_takedown(&s, &live[i].did, applied).await;
                (if applied { "takedown" } else { "untakedown" }, true)
            }
            6 => {
                let to = if rng.gen_bool(0.5) { Some("suspended".to_string()) } else { None };
                let r = s.app.mutate_account(&live[i].did, false, true, false, move |a| {
                    let changed = a.status != to;
                    a.status = to;
                    Ok(changed)
                });
                ("suspend", r.await.is_ok())
            }
            7 => {
                let a = live.swap_remove(i);
                s.xrpc.post("com.atproto.admin.deleteAccount", &json!({"did": a.did}), &Auth::Admin).await.ok();
                ("delete", true)
            }
            8 => {
                let car = s.xrpc.get("com.atproto.sync.getRepo", &[("did", &src.did)], &Auth::None).await;
                let r = if car.status == 200 {
                    let r = s
                        .xrpc
                        .post_bytes(
                            "com.atproto.repo.importRepo",
                            car.body.to_vec(),
                            "application/vnd.ipld.car",
                            &live[i].auth(),
                        )
                        .await;
                    if !r.is_ok() {
                        eprintln!("import refused: {} {}", r.status, r.text());
                    }
                    r.is_ok()
                } else {
                    eprintln!("getRepo: {}", car.status);
                    false
                };
                ("import", r)
            }
            9 => {
                let l = cluster(&s).layout();
                let sh = l.shards[rng.gen_range(0..l.shards.len())];
                let ok = sh.hi - sh.lo >= 2 && {
                    let r = admin(&s, "vlpds.admin.splitShard", json!({"shard": sh.id, "wait": true})).await;
                    r["done"] == json!(true)
                };
                ("split", ok)
            }
            10 => {
                let l = cluster(&s).layout();
                let ok = l.shards.len() >= 2 && {
                    let k = rng.gen_range(0..l.shards.len() - 1);
                    let r = admin(
                        &s,
                        "vlpds.admin.mergeShards",
                        json!({"left": l.shards[k].id, "right": l.shards[k + 1].id, "wait": true}),
                    )
                    .await;
                    r["done"] == json!(true)
                };
                ("merge", ok)
            }
            11 => {
                let r = s.xrpc.post("com.atproto.repo.createRecord", &json!({"repo": live[i].did, "collection": "app.bsky.actor.profile", "rkey": "self", "record": {"displayName": "t"}}), &live[i].auth()).await;
                ("write", r.is_ok())
            }
            12 => {
                let domain = ["group-a.test", "at.group-a.test", HANDLE_DOMAIN][rng.gen_range(0..3)];
                let handle = format!("{}.{domain}", unique_name("toth"));
                // the first account from `i` on that may (taken down ones may not)
                let mut ok = false;
                for j in (0..live.len()).map(|j| (i + j) % live.len()) {
                    let r = s
                        .xrpc
                        .post("com.atproto.identity.updateHandle", &json!({"handle": handle}), &live[j].auth())
                        .await;
                    ok = r.is_ok();
                    if ok {
                        break;
                    }
                    eprintln!("updateHandle refused: {} {}", r.status, r.text());
                }
                ("handle", ok)
            }
            13 => {
                // bring-your-own, or a handle that is itself a served domain
                let handle = match rng.gen_range(0..3) {
                    0 => "at.group-a.test".to_string(),
                    _ => format!("{}.elsewhere.test", unique_name("byo")),
                };
                let body = json!({"did": live[i].did, "handle": handle});
                let r = s.xrpc.post("com.atproto.admin.updateAccountHandle", &body, &Auth::Admin).await;
                if !r.is_ok() {
                    eprintln!("updateAccountHandle refused: {} {}", r.status, r.text());
                }
                ("byo", r.is_ok())
            }
            _ => {
                // the domains are mapped at read time: no recount
                let served = domain_counts(&s, true).await.is_some_and(|c| c.iter().any(|d| d.0 == "elsewhere.test"));
                let (nsid, body) = match served {
                    true => ("vlpds.admin.removeHandleDomain", json!({"domain": "elsewhere.test", "force": true})),
                    false => ("vlpds.admin.addHandleDomain", json!({"domain": "elsewhere.test"})),
                };
                admin(&s, nsid, body).await;
                ("domains", true)
            }
        };
        if ok.1 {
            *done.entry(ok.0).or_default() += 1;
        }
        check(&[&s], &format!("step {step} ({})", ok.0)).await;
    }
    eprintln!("ops done: {done:?}");
    // the migration-in sequence, whatever the dice did: deactivated, import, activate
    let m = s.create_account("tot").await;
    s.xrpc.post("com.atproto.server.deactivateAccount", &json!({}), &m.auth()).await.ok();
    check(&[&s], "migrating: deactivated").await;
    let car = s.xrpc.get("com.atproto.sync.getRepo", &[("did", &src.did)], &Auth::None).await;
    s.xrpc
        .post_bytes("com.atproto.repo.importRepo", car.body.to_vec(), "application/vnd.ipld.car", &m.auth())
        .await
        .ok();
    *done.entry("import").or_default() += 1;
    check(&[&s], "migrating: imported").await;
    s.xrpc.post_empty("com.atproto.server.activateAccount", &m.auth()).await.ok();
    check(&[&s], "migrating: activated").await;
    for op in
        ["create", "write", "deactivate", "takedown", "delete", "import", "split", "merge", "handle", "byo", "domains"]
    {
        assert!(done.get(op).is_some_and(|n| *n > 0), "no successful {op}: {done:?}");
    }

    let t = check(&[&s], "end").await;
    vlpds::xrpc::export_account_totals(&s.app);
    let text = vlpds::metrics::render();
    let gauge = |series: &str| -> i64 {
        let line = text.lines().find(|l| l.starts_with(series)).unwrap_or_else(|| panic!("{series} not exported"));
        line.rsplit_once(' ').unwrap().1.parse().unwrap()
    };
    assert_eq!(gauge(r#"vlpds_accounts{status="active"}"#), t.accounts[0]);
    assert_eq!(gauge(r#"vlpds_repos_written_within{window="all"}"#), t.repos());
    assert_eq!(gauge(r#"vlpds_repos_written_within{window="1d"}"#), t.repos(), "every repo here was written today");
}

const SHARDS: u32 = 6;

async fn node(id: &str, store: &Arc<object_store::memory::InMemory>) -> TestServer {
    let (id, raw) = (id.to_string(), store.clone() as Arc<dyn object_store::ObjectStore>);
    TestServer::spawn_with(move |c| {
        c.memory_store = Some(raw);
        c.shards = SHARDS;
        c.cluster = Some(vlpds::cluster::ClusterConfig {
            node_id: id,
            addr: peer_url(c),
            shards: SHARDS,
            ttl: Duration::from_millis(1500),
            renew_every: Duration::from_millis(100),
            skew: Duration::from_millis(200),
            ..Default::default()
        });
    })
    .await
}

fn owned(s: &TestServer) -> Vec<ShardId> {
    s.app.partitions.owned().iter().map(|p| p.id).collect()
}

/// Totals move with their shards: one node's accounts spread over a
/// joining node, then a merge of two shards held by different nodes and a
/// split; the cluster's sum never changes and each node matches its scan.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn totals_follow_shards_between_nodes() {
    let store = Arc::new(object_store::memory::InMemory::new());
    let a = node("tot-a", &store).await;
    admin(&a, "vlpds.admin.addHandleDomain", json!({"domain": "group-a.test"})).await;
    let mut accts = Vec::new();
    for i in 0..24 {
        let acct = a.create_account("totm").await;
        match i % 4 {
            1 => _ = a.xrpc.post("com.atproto.server.deactivateAccount", &json!({}), &acct.auth()).await.ok(),
            2 => set_repo_takedown(&a, &acct.did, true).await,
            _ if i % 8 == 3 => {
                let handle = format!("{}.group-a.test", unique_name("totm"));
                a.xrpc.post("com.atproto.identity.updateHandle", &json!({"handle": handle}), &acct.auth()).await.ok();
            }
            _ => _ = a.post(&acct, "hi").await,
        }
        accts.push(acct);
    }
    let want = check(&[&a], "one node").await;
    assert_eq!((want.accounts[0], want.accounts[1], want.accounts[2], want.repos()), (12, 6, 6, 24));
    let l = complete_domain_counts(&a).await;
    let rows: Vec<_> =
        l["domains"].as_array().unwrap().iter().map(|d| (d["domain"].clone(), d["accounts"].clone())).collect();
    assert_eq!(rows, vec![(json!(HANDLE_DOMAIN), json!(9)), (json!("group-a.test"), json!(3))]);

    let b = node("tot-b", &store).await;
    let deadline = Instant::now() + Duration::from_secs(30);
    while owned(&a).is_empty() || owned(&b).is_empty() || owned(&a).len() + owned(&b).len() != SHARDS as usize {
        assert!(Instant::now() < deadline, "never spread: {:?} {:?}", owned(&a), owned(&b));
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let both = check(&[&a, &b], "spread").await;
    assert_eq!(both, want);
    assert!(vlpds::xrpc::totals(&b.app).repos() > 0, "the joiner holds some accounts");

    // a merge across the two nodes
    let l = cluster(&a).layout();
    let pair = l
        .shards
        .windows(2)
        .find(|w| owned(&a).contains(&w[0].id) != owned(&a).contains(&w[1].id))
        .expect("adjacent shards on two nodes");
    let r = admin(&a, "vlpds.admin.mergeShards", json!({"left": pair[0].id, "right": pair[1].id, "wait": true})).await;
    assert_eq!(r["done"], json!(true), "{r}");
    assert_eq!(check(&[&a, &b], "merged").await, want);

    // a split of a shard, and writes to every account after it
    let l = cluster(&a).layout();
    let big = *l.shards.iter().max_by_key(|s| s.hi - s.lo).unwrap();
    let r = admin(&a, "vlpds.admin.splitShard", json!({"shard": big.id, "wait": true})).await;
    assert_eq!(r["done"], json!(true), "{r}");
    assert_eq!(check(&[&a, &b], "split").await, want);
    for (i, acct) in accts.iter().enumerate() {
        if i % 4 == 2 {
            continue; // taken down
        }
        let ok = eventually(Duration::from_secs(10), || async {
            let r = b.xrpc.post("com.atproto.server.deactivateAccount", &json!({}), &acct.auth()).await;
            r.is_ok().then_some(()).or_else(|| {
                eprintln!("deactivate: {} {}", r.status, r.text());
                None
            })
        })
        .await;
        assert!(ok.is_some(), "deactivating {}", acct.did);
    }
    let after = check(&[&a, &b], "all deactivated").await;
    assert_eq!((after.accounts[0], after.accounts[1], after.accounts[2], after.repos()), (0, 18, 6, 24), "{after:?}");
    assert!(after.suffixes.is_empty(), "{:?}", after.suffixes);
    let r = remove_handle_domain_unforced(&b, "group-a.test").await;
    assert_eq!(r.ok()["accounts"], json!(0));
}
