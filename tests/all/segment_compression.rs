//! Log storage: segments are stored
//! zstd-compressed and every reader decodes them.

use crate::common::*;
use object_store::path::Path;
use std::time::Duration;

/// Segments are PUT with a zstd body behind an uncompressed header, and
/// decode to the bytes the writer sealed: a cursor-0 backfill (S3 reads)
/// returns every commit.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn segments_stored_compressed() {
    use futures::StreamExt;
    use object_store::ObjectStoreExt;
    let s = TestServer::spawn().await;
    let a = s.create_account("zseg").await;
    let mut last = None;
    for i in 0..20 {
        last = Some(s.post(&a, &format!("a post of a typical length, number {i}: {}", "lorem ipsum ".repeat(8))).await);
    }
    let store = &s.app.store;
    let prefix = Path::from(format!("{}/log/{}", store.prefix, s.app.log.log_id));
    let metas: Vec<_> = store.raw.list(Some(&prefix)).map(|m| m.unwrap()).collect().await;
    let (mut zstd, mut stored, mut raw) = (0, 0u64, 0u64);
    for m in &metas {
        let data = store.raw.get(&m.location).await.unwrap().bytes().await.unwrap();
        let Some((h, hl)) = vlsync_store::segment::parse_header(&data).unwrap() else { continue };
        if h.codec == vlsync_store::segment::CODEC_ZSTD {
            zstd += 1;
        }
        stored += data.len() as u64;
        raw += (hl + h.body_len as usize) as u64;
        let decoded = vlsync_store::segment::decode(data).unwrap();
        assert_eq!(decoded.len(), hl + h.body_len as usize);
        assert!(matches!(vlpds::derived::parse(decoded, None).unwrap(), vlsync_store::segment::LogObject::Segment(..)));
    }
    assert!(zstd > 0 && stored < raw, "{zstd} compressed segments, {stored} B stored for {raw} B");
    let head = Cid::parse(last.unwrap().commit_cid.as_deref().unwrap()).unwrap();
    let mut sub = s.subscribe(Some(0)).await;
    let frames = sub
        .until(Duration::from_secs(10), |fs| fs.last().and_then(|f| f.commit()).is_some_and(|c| c.commit == head))
        .await;
    assert_eq!(frames.iter().filter(|f| f.did() == Some(a.did.as_str()) && f.kind() == "#commit").count(), 20);
}
