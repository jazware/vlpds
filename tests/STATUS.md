# vlpds conformance suite: status

## Running it

The integration tests are **one test binary**, `tests/all/main.rs`. Every former `tests/*.rs` file is a
module of it (`tests/all/<name>.rs`), and the shared harness is `tests/all/common/mod.rs` (`use crate::common::*`).
`Cargo.toml` sets `autotests = false` and declares the binary as `[[test]] name = "all"`.
A new test file goes in `tests/all/` plus a `mod <name>;` line in `main.rs`.

One more integration binary lives apart: `tests/level_gating.rs` (`[[test]] name = "level_gating"`,
`required-features = ["test-level"]`), the rolling-upgrade level-gating test, which needs the test-only feature level and
its own process (the active level is process-wide). Plain `cargo test` skips it; run it with
`cargo test --features test-level --test level_gating` (`just upgrade-ci` does, with the two-build scenario).

```bash
cargo test                          # unit tests (src/) + the whole suite (not level_gating)
cargo test --test all               # just the integration suite
cargo test --test all crud::        # one former file (module)
cargo test --test all crud::put_    # name prefix within a module
VLPDS_TEST_LOG=debug cargo test --test all sync:: -- --nocapture   # server logs
```

`cargo test` uses `[profile.test]`: the crate at opt-level 1, dependencies at opt-level 2 (built once and cached),
no LTO, no debuginfo, incremental. Don't run the suite with `--profile dev-release` or `--release`; it only makes the build slower.
`go_checker` needs a Go toolchain (set `VLPDS_SKIP_GO_CHECKER=1` to skip it). It builds the checker once per run into `CARGO_TARGET_TMPDIR`.

Every test boots its own in-process server (`TestServer::spawn`: in-memory store, port 0, `shards: 8`, `workers: 2`,
rate limits off). Boot takes milliseconds; the whole suite took ~3 s in parallel when it was merged into one binary and ~65 s now
(2026-10-02, after the HA, reshard and retention modules grew). Sharing a server per module would
save almost nothing, and each `#[tokio::test]` has its own runtime, which would cost isolation. So it isn't done.
Handles come from `unique_name()` (process-wide counter + random suffix), so tests never collide.

## Build and run times

Measured 2026-10-01 on the 14-core laptop with `CARGO_TARGET_DIR=target/agent-tests`. Other agents were compiling at the same
time (load average 35–75), so treat the numbers as ±30%. The ratios are what matter.

| | Before: 36 binaries, `--profile dev-release` (thin LTO, opt 3) | After: 1 binary, `[profile.test]` |
|---|---:|---:|
| Cold build (`--no-run`, empty target dir) | 1416 s (load 60–75) | **108 s** (load 35) |
| Warm rebuild after `touch src/lib.rs` | 1075 s (36 thin-LTO links) | **2 s** |
| Warm rebuild after a real one-line `src/` edit | (≥ the touch case) | **35 s** (`cargo test --no-run`: lib, lib unit tests, 2 bins, `all`); ~29 s for `--test all` |
| Running the suite | 13.4 s summed over 39 binaries (+ cargo/process overhead) | **2.9–3.1 s** (`--test all`); `cargo test` total 23 s including the rebuild |

**`[profile.dev-release]`** (`cargo build --profile dev-release --bins`, which every agent uses to iterate). It used to inherit release with
thin LTO, opt 3 and debug=1. It is now opt 2, `lto = false`, `debug = "line-tables-only"`, `codegen-units = 256`, incremental,
with dependencies at opt 3:

| | Before | After |
|---|---:|---:|
| Cold `--bins` | 99 s | 107 s (deps now at opt 3 without LTO; about the same) |
| Warm after `touch src/lib.rs` | 33 s | **2 s** |
| Warm after a one-line `src/` edit | ≥ 33 s | **12 s** |

Performance sanity check (`vlpds --memory --no-rate-limits`, 500 accounts, `loadgen run --rate 5000 --duration 8 --warmup 3`, then
`loadgen methods --seconds 4 --concurrency 32`), old and new profile built from the same source, interleaved twice:

| | Old dev-release | New dev-release |
|---|---|---|
| 5000/s open loop | achieved 5000/s both runs, 0 errors | achieved 5000/s both runs, 0 errors |
| Server CPU for the 8 s run | 16.5 s, 17.5 s | 18.8 s, 16.0 s |
| `createRecord` closed loop (4 s) | 39.1k, 47.4k | 50.9k, 43.1k |
| `sync.getRepo` closed loop (4 s) | 14.6k, 12.8k | 13.0k, 12.3k |
| write p50 / p99 | 1.0–1.2 ms / 2.4–57 ms | 1.0–1.2 ms / 8.6–222 ms |

These are equal within the noise of a loaded machine. The tail latencies swing by 10× between runs of the *same* binary.
`sync.getRepo` (CPU-bound MST/CAR code in the crate) may be ~5% slower. Use `--release` (thin LTO) for real benchmarks.

## Results

Last full run: 2026-10-02 (vlpds head 0539d2f + the ops refresh): `cargo test --test all` 586 passed, 0 failed,
21 ignored in 64.6 s; `cargo test --lib` 249 passed, 0 failed, 12 ignored. `level_gating` (separate binary, above) was not
part of this run.

**Totals:** 586 passed, 0 failed, 21 ignored, across 104 modules. The ignored tests are all benchmarks and long-running
scale/fault tests (run them with `--ignored`): `cbor_transcode::bench`, `checkpoint_stall::stall_*`,
`cold_start::restart_window_*`, `compaction_polling::*`, `cost_defaults::deep_l0_ingest_keeps_up`,
`differential_shrike::{json,syntax}_reference_oracle` and `real_records_from_clickhouse`, `interop_crypto::sign_verify_bench`,
`list_repos_scale::enumeration_bench`, `mst_lazy::bench*`, `oauth::bench_dpop_resource_requests`,
`segment_bytes::segment_bytes_per_commit`, `shard_ingest::one_shard_sustains_bulk_ingest`. No reference gap is ignored any
more: `ref_account::ref_signing_key_rotation_resigns_the_repo` and `ref_repo::ref_prevents_duplicate_backlinks` now run
and pass.

The `ref_*` modules port cases from the reference PDS's own test suite; `tests/REFERENCE_COVERAGE.md` maps every reference `it()` case to a
vlpds test, an N/A reason, a documented divergence or a gap.

| Module | Pass | Fail | Ign |
|---|---:|---:|---:|
| account | 17 | 0 | 0 |
| account_deactivation | 6 | 0 | 0 |
| account_races | 5 | 0 | 0 |
| account_status | 8 | 0 | 0 |
| admin_cli | 7 | 0 | 0 |
| admin_cluster | 2 | 0 | 0 |
| app_passwords | 3 | 0 | 0 |
| auth | 15 | 0 | 0 |
| auth_caches | 3 | 0 | 0 |
| backlinks | 6 | 0 | 0 |
| blob_deletes | 7 | 0 | 0 |
| blob_gc_race | 2 | 0 | 0 |
| blobs | 2 | 0 | 0 |
| bulk_create | 2 | 0 | 0 |
| cache_caps | 2 | 0 | 0 |
| cbor_transcode | 2 | 0 | 1 |
| checkpoint_stall | 1 | 0 | 2 |
| cold_start | 3 | 0 | 2 |
| commit_cpu | 2 | 0 | 0 |
| compaction_polling | 0 | 0 | 2 |
| cost_defaults | 2 | 0 | 1 |
| create_post | 2 | 0 | 0 |
| crud | 32 | 0 | 0 |
| differential_shrike | 25 | 0 | 3 |
| e2e_regressions | 7 | 0 | 0 |
| email_2fa | 7 | 0 | 0 |
| email_flows | 6 | 0 | 0 |
| fast_failover | 4 | 0 | 0 |
| feature_levels | 2 | 0 | 0 |
| file_uploads | 11 | 0 | 0 |
| firehose_backfill | 2 | 0 | 0 |
| firehose_fanout | 2 | 0 | 0 |
| firehose_shards | 3 | 0 | 0 |
| firehose_startup | 4 | 0 | 0 |
| formats | 3 | 0 | 0 |
| get_blocks_index | 1 | 0 | 0 |
| go_checker | 3 | 0 | 0 |
| ha_auth | 3 | 0 | 0 |
| ha_liveness | 1 | 0 | 0 |
| handle_validation | 6 | 0 | 0 |
| handles | 14 | 0 | 0 |
| harness | 1 | 0 | 0 |
| internal_auth | 2 | 0 | 0 |
| interop_crypto | 8 | 0 | 1 |
| interop_data_model | 8 | 0 | 0 |
| interop_mst | 8 | 0 | 0 |
| interop_syntax | 15 | 0 | 0 |
| invertible_ops | 1 | 0 | 0 |
| invite_codes | 14 | 0 | 0 |
| invites_optional | 1 | 0 | 0 |
| join_follow | 1 | 0 | 0 |
| key_rotation | 5 | 0 | 0 |
| lexicons | 6 | 0 | 0 |
| list_repos_scale | 2 | 0 | 1 |
| log_pipeline | 2 | 0 | 0 |
| log_retention | 6 | 0 | 0 |
| migration | 2 | 0 | 0 |
| moderation | 7 | 0 | 0 |
| mst_lazy | 10 | 0 | 5 |
| oauth | 26 | 0 | 1 |
| oauth_replay_durable | 2 | 0 | 0 |
| peer_tls | 4 | 0 | 0 |
| ops_metrics | 1 | 0 | 0 |
| plc | 10 | 0 | 0 |
| preferences | 6 | 0 | 0 |
| proxy | 11 | 0 | 0 |
| proxy_fast_path | 4 | 0 | 0 |
| push | 4 | 0 | 0 |
| races | 4 | 0 | 0 |
| rate_limit_config | 2 | 0 | 0 |
| rate_limits | 7 | 0 | 0 |
| read_after_write | 8 | 0 | 0 |
| rebalance_handback | 2 | 0 | 0 |
| record_encode | 3 | 0 | 0 |
| ref_account | 10 | 0 | 0 |
| ref_auth | 5 | 0 | 0 |
| ref_handles | 7 | 0 | 0 |
| ref_invites | 4 | 0 | 0 |
| ref_moderation | 1 | 0 | 0 |
| ref_moderator_auth | 7 | 0 | 0 |
| ref_plc | 1 | 0 | 0 |
| ref_proxy | 9 | 0 | 0 |
| ref_repo | 11 | 0 | 0 |
| ref_ssrf | 2 | 0 | 0 |
| ref_sync | 1 | 0 | 0 |
| reshard | 15 | 0 | 0 |
| revocation_gc | 1 | 0 | 0 |
| secrets_at_rest | 4 | 0 | 0 |
| segment_bytes | 0 | 0 | 1 |
| segment_compression | 1 | 0 | 0 |
| sequencer | 6 | 0 | 0 |
| server_basics | 9 | 0 | 0 |
| service_auth | 7 | 0 | 0 |
| shard_ingest | 0 | 0 | 1 |
| shrike_adopt | 8 | 0 | 0 |
| signature_faults | 1 | 0 | 0 |
| smtp_mail | 6 | 0 | 0 |
| subscribe_repos | 14 | 0 | 0 |
| sync | 10 | 0 | 0 |
| sync11_property | 3 | 0 | 0 |
| sync_list | 4 | 0 | 0 |
| takedown_routes | 1 | 0 | 0 |
| totp | 6 | 0 | 0 |
| untrusted_repo_data | 2 | 0 | 0 |
| user_service_auth | 6 | 0 | 0 |

## Speed pass (2026-10-01): test-side changes

- **One binary.** `tests/*.rs` became `tests/all/*.rs`, `mod common;` became `use crate::common::*`, and there were no name collisions.
- **Flake: `sync::get_repo_since_returns_diff`.** It asserted `diff.blocks.len() < 10`. vlpds answers `getRepo?since=` with the commit, *all* MST
  nodes and the records newer than `since`. That is a deliberate superset of the reference's rev-filtered block set, so the
  block count depends on the shape of an MST over 20 random TIDs, and the test failed in 2 of 3 runs. The test now checks the same
  thing deterministically: no record block from before `since` is in the diff, and every block other than the commit and the new record is an
  MST node. It still checks that the diff is smaller than the full repo and that diff + old blocks = the new tree.
  If the server is ever narrowed to the reference's block set, a `< N` bound on the MST nodes can come back.
- **Fixed sleeps → polling.** `subscribe_repos::{live_tail_without_cursor_has_no_backfill, many_open_connections_see_identical_streams}`
  slept 100 ms "so the subscription registers". They now call `TestServer::sync_subs`, which writes probe posts until every
  subscription has received one, then consumes each stream up to the last probe (with a deadline).
  Two sleeps remain on purpose: `sequencer::buffers_events_that_are_not_being_read` (200 ms of *not reading* is the point of
  the test) and the 20 ms writer delay in `subscribe_repos::cutover_from_backfill_to_live` (it interleaves writes with the backfill).
  The `drain(idle)` calls assert that *nothing more* arrives, so they need an idle window by definition.
- **`go_checker`.** Its two tests ran `go build -o <same path>` concurrently. Now one `OnceLock` builds it once.
- Known harness leak (src-side, harmless in tests): each server's repo-worker threads hold a sender to their own channel, so they
  never exit. That is 2 idle threads per test server, about 540 per full run.

## Earlier pass (2026-09-30): what it fixed (src/)

- **Invite race:** each use of a code is a conditional-create claim object `invite-use/{hex code}/{slot}` (`If-None-Match: *`), released if the signup fails (`admin::claim_invite_use` / `release_invite_use`).
- **Writes:** `applyWrites#update` of a missing record fails (400 InvalidRequest; the reference's MST update throws, which surfaces there as a 500). An identical `putRecord` makes no commit and returns no `commit`. `$type` defaults to the collection, and any other value (including null, non-string or empty) is rejected. `listRecords` limit must be 1..=100. `applyWrites` over 200 writes is rejected.
- **Lexicon validation** (`src/lexicon.rs`, `lexicons/bundle.json`): every record lexicon of the atproto repo and every com.atproto.* method, plus their refs. It covers record keys, required/nullable fields, string formats (datetime, at-uri, did, handle, …), byte and grapheme limits, enum/const, integer ranges, arrays, refs, open/closed unions and blob accept/maxSize. `validate` is honored, and `validationStatus` is `valid`, `unknown` or omitted.
- **Data model:** `cbor::Value::decode` rejects non-minimal heads, unsorted map keys and duplicate map keys. JSON→record rejects malformed `$link`/`$bytes`/blob objects and bad `$type` values, and accepts integer-valued floats (`123.0`). Legacy blob refs are refused. Records may only reference blobs that the repo uploaded and that aren't taken down (400 BlobNotFound). Request bodies with `Content-Encoding` gzip/deflate are decoded, and uploads are hashed over the decoded bytes. Upload MIME types are sniffed from magic bytes.
- **Takedowns:**
  - `uploadBlob` refuses a taken-down blob.
  - `createSession{allowTakendown}` issues a `com.atproto.takendown`-scoped token, which is accepted only by the reference's `additional: [Takendown]` methods.
  - Taking down an account revokes refresh tokens and OAuth sessions but not live access tokens, as the reference's `takedownAccount` does. The owner can still sync, and `verify_dpop` stops accepting the deleted sessions.
- **activateAccount** emits `#account`, `#identity` and `#sync` (new `AccountOp::Activate`).
- **identity:** `resolveHandle` fails for inactive accounts. `updateHandle` applies the service-domain rules, including the reserved names.
- **getServiceAuth:** `aud` must be an atproto DID (did:plc, or did:web without a path), with an optional non-empty `#fragment`.
- **XRPC hygiene:** `Json`/`Query` extractors (`src/xrpc/extract.rs`) return the `{error, message}` envelope:
  - 400 InvalidRequest for malformed input, 413 over the reference's 150 KiB JSON limit;
  - `did`/`repo`/`cid`/`handle` params are syntax-checked;
  - JSON and CAR responses over 1 KiB are gzip-compressed;
  - server-wide CORS (expose DPoP-Nonce, WWW-Authenticate, atproto-*, RateLimit-*, Retry-After).
- **putPreferences** is serialized per account.
- **Rate limits** (`src/ratelimit.rs`): the reference buckets and values, a 429 RateLimitExceeded envelope, `RateLimit-*` headers and `Retry-After`. Admin, internal and bypass-key requests are exempt. `X-Forwarded-For` is trusted only from `trusted_proxies`. `--no-rate-limits` turns them off. They are off in the test harness by default, as in the reference dev env.

## Earlier pass (2026-09-30): test fixes (tests were wrong about the reference)

- **`proxy::target_selection_and_rejections`:** a locally implemented protected method (`listAppPasswords`) with an `atproto-proxy` header is served locally, not refused. In the reference, xrpc-server mounts `this.routes` before the proxy catchall (packages/xrpc-server/src/server.ts: `this.router.use(this.routes); this.router.use(this.catchall)`), and pipethrough.ts's `PROTECTED_METHODS` "Bad token method" check runs only in that catchall. The test now asserts 200 and that the upstream saw nothing.
- **`crud::profile_gets_self_rkey`:** in the reference test the *client* fills in rkey `self`. The server validates the key against the schema (repo/prepare.ts `validateRecord` → `schema.keySchema.safeValidate`), so `createRecord` of a profile without an rkey is a 400. The test now checks both behaviours.
- **`interop_data_model::fixture_records_round_trip_through_server_with_matching_cids`**, **`blobs::upload_get_list_and_gc`:** both referenced never-uploaded blobs, which the reference refuses (blob/transactor.ts processWriteBlobs → "Could not find blob"). The fixture with a blob now expects 400 BlobNotFound. The blobs test uploads its "missing" blob and then deletes the stored object.
- **`sync11_property`, `go_checker`, `races`, `account_deactivation`:** they wrote app.bsky records with non-TID keys or non-schema bodies, which known-lexicon validation now rejects as the reference does. They now use `com.example.*` collections, `validate: false` or rkey `self`. What they test (sync semantics, races) is unchanged.
- **Harness:** `TestServer` runs with `rate_limits_enabled: false`. `rate_limits.rs` turns them on.
