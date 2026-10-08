# vlpds storage on real atproto data (2026-10-02)

Sample: every record of every repo with DID in `[did:plc:aa, did:plc:ab)` from the ClickHouse crawl
(`default.crawl_records`): **18,060,061 records, 38,135 repos (33,968 with records)**, ~1/1000 of the
crawl (17.75 B records, 39.0 M repos in `crawl_repos`, 34.9 M with records). The collection mix matches the
full crawl to within ~1 pt (like 65.5% vs 64.9%, follow 11.7/12.8, post 10.3/11.4, repost 10.3/9.1).

## Method
- **strongRef CIDs re-injected.** The crawl stripped `cid` from every strongRef. A walk over
  `lexicons/bundle.json` (ref/union/array/object) adds a random dag-cbor CID wherever the lexicon says
  `com.atproto.repo.strongRef`. That added 16.83 M refs: like 12.74 M (via included), repost 2.13 M,
  post 1.96 M, profile 1.3 k. Each ref costs exactly **65 B of CBOR**, which is **+60.6 B/record** on average
  (like +70, repost +74, post +68). The walk left 586 strongRef-shaped `{uri}` objects without a CID: 299 are
  in non-bundled lexicons, and the rest are junk nested inside `reply.root.record` of malformed posts. Coverage
  of lexicon positions is complete.
- **Encoding.** Records go through vlpds' own handler path: `$type` default/check, `JsonValue::encode_record`,
  then `lexicon::validate_record`. 9 records fail to encode (6 floats, 3 `$type` mismatches). 220 fail
  validation but are still stored, because they're real repo contents.
- **Rows.** Each record writes exact rows: `R/` (`state::record_key`/`record_value`, with the repo's real rev),
  `c/` (`record_cid_key`) and `b/` blob refs. Each repo writes `h/` (`Head` with a real `worker::sign_commit`
  block), `a/` (an `Account` JSON shaped like createAccount's, with a real argon2 PHC and totpEnabled), `n/`
  (24-char handle) and one `C/` per collection.
- **SlateDB.** One SlateDB per run, on `object_store::local`, using `partition::open_db`'s settings (16 KiB
  blocks, 16 MiB L0, 32 L0s, no WAL), plus a codec. Each run flushes and waits until the store stops
  changing. Bytes = the sum of the SSTs in the final manifest (L0 = 0, 5–7 sorted runs). Separate runs per
  component (`R` / `c` / `b+h+a+n+C`) sum to within 0.0004% of the all-in-one run.
- **Log.** An in-process vlpds (`server::spawn`, in-memory store, default 8 shards) gets 1,928 sample
  repos (1,007,366 records, real per-repo proportions) replayed as single-record `createRecord`
  commits in rkey order. A fake store answers blob HEADs with the declared size/mime. Every segment PUT is
  parsed with `segment::parse`. 2 records were rejected by validation.
- **MST.** `worker::load_tree` cold-loads a repo from a freshly opened DB on local FS (CPU-bound lower
  bound, no S3 latency). jemalloc `stats.allocated` deltas are taken with the tree alive and the DB closed.

## State bytes (SST bytes after compaction)
| | raw JSON | JSON +cid | CBOR | R/ | c/ | b/ | **per record** | **per repo** (h,a,n,C) |
|---|---|---|---|---|---|---|---|---|
| logical (key+val) | 191 | 254 | 234 | 346 | 75.6 | 4.5 | 426 | 974 (h 302, a 443, n 58, C 171) |
| SST, no compression | | | | **315.0** | **63.5** | 3.9 | **382.5** | **838** |
| SST, zstd (level 3) | | | | **129.1** | **23.6** | 1.5 | **154.2** | **323** |

SlateDB's key-prefix sharing more than pays for its per-row overhead: SST bytes are 0.90x the logical bytes.
Of the raw SST bytes, bloom filters are 0.7% and indexes 0.5%.

| codec (whole DB) | bytes | ratio |
|---|---|---|
| none | 6.94 GB | 1.00 |
| **zstd** (slatedb hardcodes level 3) | 2.81 GB | **2.47** |
| zlib | 2.82 GB | 2.46 |
| snappy | 3.56 GB | 1.95 |
| lz4 | 3.61 GB | 1.92 |

Offline, on 16 KiB chunks of the uncompressed SSTs: zstd 1 / 3 / 6 / 9 / 19 = 2.45 / 2.48 / 2.54 / 2.55 / 2.59.
A trained dictionary (64–256 KiB) gains nothing at 16 KiB blocks (+1.5% at level 9). By component, zstd
gives R/ 2.44x, c/ 2.69x and per-repo 2.6x.

## Extrapolation (linear: per-record x records + per-repo x repos; S3 $0.023/GiB-month)
| | none | zstd |
|---|---|---|
| real crawl (17.75 B records, 39.0 M repos) | 6.82 TB, $146/mo | 2.75 TB, $59/mo |
| 25 B records / 50 M repos | 9.60 TB, $206/mo | 3.87 TB, $83/mo |

Per-repo rows are under 1% of the total in both cases. The shape of the per-repo distribution doesn't move
the state bytes. It does matter for MST memory and for commit frame size (below).

**Compaction headroom.** Bulk ingest of the sample wrote 28.0 GB of SSTs for 6.94 GB live (4.0x). None of
it was reclaimed during the 80 s settle: the manifest held a 15-minute checkpoint, so GC (min_age 5 s here,
default 300 s) couldn't delete the inputs. The peak on-disk size during a bulk load can therefore reach
~4x live for the checkpoint window. In steady state, size-tiered compaction (≤8 sources) needs at most
+1x of the largest run transiently. Budget ~2x live for S3 bytes in steady state, and more during
imports.

## Log bytes per commit (single-record createRecord, real records)
| | segment bytes/commit | firehose frame | state mutations |
|---|---|---|---|
| **mean (1.007 M commits)** | **5,370** (incl. 69 B/segment headers) | **4,548** | 739 |
| like (67%) | 5,592 | 4,834 | 733 |
| follow (15%) | 3,706 | 3,060 | 620 |
| repost (8.5%) | 5,632 | 4,858 | 748 |
| post (7.9%) | 5,809 | 4,778 | 1,005 |

The frame is mostly MST proof blocks, so it grows with repo size. Commits are weighted like the records,
which skews toward big repos. Segments are uncompressed: **~464 GB/day at 1 k commits/s**, so a 72 h
retention window is ~1.4 TB (~$30/mo).

## MST in memory (cold load from SlateDB, local FS)
| repo | records | tree heap | per record | scan+insert | root CID | NodeIndex |
|---|---|---|---|---|---|---|
| biggest in sample | 254,627 | 63.9 MB | 251 B | 0.33 s | 0.018 s | +8.5 MB |
| synthetic (top-3 sample repos' real records, one DID) | 594,096 | 130–135 MB | 219–227 B | 0.88–0.92 s | 0.04 s | +17 MB |

At ~225 B/record, a 5–10 M-record repo is ~1.1–2.3 GB of heap and takes ~8–15 s of CPU to load, before
S3 latency.

## Raw numbers
```json
{
 "none": {
  "R": 315.035,
  "c": 63.536,
  "b": 3.897,
  "per_repo": 837.99,
  "total_live": 6939369433,
  "sum_split": 6939342926,
  "per_record_all": 382.468
 },
 "zstd": {
  "R": 129.074,
  "c": 23.614,
  "b": 1.5,
  "per_repo": 322.576,
  "total_live": 2805204839,
  "sum_split": 2796959731,
  "per_record_all": 154.189
 },
 "codec_total": {
  "none": 6939369433,
  "zstd": 2805204839,
  "lz4": 3614272428,
  "snappy": 3561676325,
  "zlib": 2822308676
 },
 "ratio": {
  "none": 1.0,
  "zstd": 2.474,
  "lz4": 1.92,
  "snappy": 1.948,
  "zlib": 2.459
 },
 "logical_per_record": {
  "R": 345.851,
  "c": 75.62,
  "b": 4.53
 },
 "logical_per_repo": {
  "h": 302.0,
  "a": 443.0,
  "n": 58.0,
  "C": 171.03
 },
 "raw": {
  "json_orig": 191.033,
  "json_injected": 254.385,
  "cbor": 234.231,
  "records": 18060052,
  "repos": 38135,
  "repos_with_records": 33968
 },
 "inject": {
  "refs": 16825811,
  "per_ref_cbor": 65.0,
  "per_record_cbor": 60.558,
  "by_coll": {
   "app.bsky.actor.profile": 1329,
   "app.bsky.feed.like": 12737456,
   "app.bsky.feed.post": 1955009,
   "app.bsky.feed.repost": 2131947,
   "site.standard.document": 70
  },
  "unclassified": 586
 },
 "full_crawl": {
  "none": {
   "TB": 6.823,
   "usd_month": 146.146
  },
  "zstd": {
   "TB": 2.75,
   "usd_month": 58.905
  }
 },
 "scenario_25B_50M": {
  "none": {
   "TB": 9.604,
   "usd_month": 205.713
  },
  "zstd": {
   "TB": 3.871,
   "usd_month": 82.915
  }
 },
 "log": {
  "per_commit": {
   "entry": 5313.265,
   "frame": 4548.465,
   "muts": 738.8,
   "seg_bytes_incl_headers": 5370.362
  },
  "commits": 1007366,
  "repos": 1928,
  "GB_per_day_at_1000cps": 463.999,
  "GB_per_day_at_2000cps": 927.998,
  "by_collection": {
   "app.bsky.actor.profile": {
    "commits": 1895,
    "entry": 2708,
    "frame": 1732,
    "muts": 950
   },
   "app.bsky.feed.like": {
    "commits": 679123,
    "entry": 5592,
    "frame": 4834,
    "muts": 733
   },
   "app.bsky.feed.post": {
    "commits": 80021,
    "entry": 5809,
    "frame": 4778,
    "muts": 1005
   },
   "app.bsky.feed.postgate": {
    "commits": 1401,
    "entry": 4902,
    "frame": 4193,
    "muts": 683
   },
   "app.bsky.feed.repost": {
    "commits": 85228,
    "entry": 5632,
    "frame": 4858,
    "muts": 748
   },
   "app.bsky.graph.block": {
    "commits": 6230,
    "entry": 4691,
    "frame": 4046,
    "muts": 620
   },
   "app.bsky.graph.follow": {
    "commits": 150376,
    "entry": 3706,
    "frame": 3060,
    "muts": 620
   },
   "app.bsky.graph.listitem": {
    "commits": 1698,
    "entry": 3362,
    "frame": 2632,
    "muts": 704
   }
  }
 },
 "mst": {
  "real": {
   "did": "did:plc:realzzzzzzzzzzzzzzzzzzzz",
   "node_index_alloc_bytes": 8484864,
   "node_index_build_s": 0.011,
   "records": 254627,
   "root_cid_s": 0.018,
   "scan_and_insert_s": 0.33,
   "tree_alloc_bytes": 63868392,
   "tree_bytes_per_record": 250.831
  },
  "synth": {
   "did": "did:plc:synthzzzzzzzzzzzzzzzzzzz",
   "node_index_alloc_bytes": 17081728,
   "node_index_build_s": 0.017,
   "records": 594096,
   "root_cid_s": 0.048,
   "scan_and_insert_s": 0.921,
   "tree_alloc_bytes": 130280872,
   "tree_bytes_per_record": 219.293
  },
  "synth_repeat": {
   "did": "did:plc:synthzzzzzzzzzzzzzzzzzzz",
   "node_index_alloc_bytes": 17047816,
   "node_index_build_s": 0.015,
   "records": 594096,
   "root_cid_s": 0.041,
   "scan_and_insert_s": 0.877,
   "tree_alloc_bytes": 134709648,
   "tree_bytes_per_record": 226.747
  },
  "synth_rows": 594096
 },
 "blocks_offline_zstd": {
  "raw_bytes": 1751601398,
  "sampled_chunks": 106929,
  "zstd1": 2.454,
  "zstd15": 2.588,
  "zstd19": 2.589,
  "zstd3": 2.477,
  "zstd3_dict256k": 2.467,
  "zstd3_dict64k": 2.463,
  "zstd6": 2.541,
  "zstd9": 2.551,
  "zstd9_dict256k": 2.597,
  "zstd9_dict64k": 2.581
 }
}
```
