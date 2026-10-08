//! Log bytes per commit for single-record commits: 16 repos of ~300
//! records each, then 100 likes and 100 posts per
//! repo, written concurrently so segments group-commit as under load. Prints
//! log bytes / commit per phase (summed object sizes under the node's log).
//! `cargo test --test all segment_bytes -- --ignored --nocapture`

use crate::common::*;
use object_store::ObjectStoreExt;
use std::sync::Arc;

async fn log_bytes(s: &TestServer) -> u64 {
    use futures::StreamExt;
    let store = &s.app.store;
    let prefix = object_store::path::Path::from(format!("{}/log/{}", store.prefix, s.app.log.log_id));
    store.raw.list(Some(&prefix)).map(|m| m.unwrap().size).fold(0, |a, b| async move { a + b }).await
}

async fn phase(s: &Arc<TestServer>, accts: &[TestAccount], n: usize, like: bool, subject: &RecordRef) -> u64 {
    let before = log_bytes(s).await;
    let jobs = accts.iter().cloned().map(|a| {
        let (s, subject) = (s.clone(), subject.clone());
        tokio::spawn(async move {
            for i in 0..n {
                if like {
                    let rec = json!({"$type": "app.bsky.feed.like", "subject": {"uri": subject.uri, "cid": subject.cid}, "createdAt": now_iso()});
                    s.create_record(&a, "app.bsky.feed.like", rec).await;
                } else {
                    s.post(&a, &format!("a post of a typical length, number {i}: {}", "lorem ipsum dolor sit amet ".repeat(3))).await;
                }
            }
        })
    });
    for j in futures::future::join_all(jobs).await {
        j.unwrap();
    }
    (log_bytes(s).await - before) / (n * accts.len()) as u64
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore]
async fn segment_bytes_per_commit() {
    let s = Arc::new(TestServer::spawn().await);
    let accts: Vec<TestAccount> = futures::future::join_all((0..16).map(|_| s.create_account("sb"))).await;
    let subject = s.post(&accts[0], "the subject").await;
    let warm = phase(&s, &accts, 300, false, &subject).await;
    let likes = phase(&s, &accts, 100, true, &subject).await;
    let posts = phase(&s, &accts, 100, false, &subject).await;
    println!("log bytes per commit: warm-up posts {warm}, likes {likes}, posts {posts} (repos of ~300-500 records)");
    // where the bytes go, over the last segments (the posts phase)
    use futures::StreamExt;
    let store = &s.app.store;
    let prefix = object_store::path::Path::from(format!("{}/log/{}", store.prefix, s.app.log.log_id));
    let metas: Vec<_> = store.raw.list(Some(&prefix)).map(|m| m.unwrap()).collect().await;
    let (mut frames, mut keys, mut vals, mut n, mut total, mut by_prefix) =
        (0usize, 0usize, 0usize, 0usize, 0usize, std::collections::BTreeMap::<String, (usize, usize)>::new());
    for m in metas.iter().rev().take(50) {
        let data = store.raw.get(&m.location).await.unwrap().bytes().await.unwrap();
        total += data.len();
        let vlsync_store::segment::LogObject::Segment(_, entries) = vlpds::derived::parse(data, None).unwrap() else {
            continue;
        };
        for e in entries {
            n += 1;
            frames += e.frame.len();
            for m in &e.muts {
                keys += m.key.len();
                let v = m.val.as_ref().map_or(0, |v| v.len());
                vals += v;
                let p = String::from_utf8_lossy(&m.key[..2]).to_string();
                let x = by_prefix.entry(p).or_default();
                x.0 += m.key.len();
                x.1 += v;
            }
        }
    }
    println!("last 50 segments: {n} entries, {} B/entry: frame {} keys {} vals {}; by key prefix (key B, val B per entry): {:?}",
        total / n, frames / n, keys / n, vals / n, by_prefix.iter().map(|(k, (a, b))| (k.clone(), a / n, b / n)).collect::<Vec<_>>());
}
