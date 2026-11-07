# Spaces harness

This harness checks that vlpds's Spaces support works end to end and talks to the reference
implementation the same way the reference talks to itself. It also runs a randomized workload, the
same workload under faults, and a sync-cost run, so changes to the Spaces code can be measured.

```
just spaces-e2e                  # the scenario matrix (bench/spaces/run.sh e2e)
just spaces-sim 42 medium        # seeded random workload with invariants
just spaces-fault 42             # the same under faults
just spaces-cost                 # server time, notify latency and bucket ops against the targets
just spaces-cost vlpds warm-writes   # only the warm write-latency step (ref-a for the reference)
```

`just spaces-boards` runs boards, a Reddit-like private board app on Spaces, through its user stories,
and `just spaces-boards-ui` serves its web UI on this stack (boards/README.md).

Everything runs on this machine, and nothing talks to the real PLC, a relay or bsky. Accounts,
passwords and keys are generated per run (or are fixed test values in this directory).

## What runs

`run.sh` starts the stack in docker (`docker-compose.yml`, project `vlpds-spaces`):

- A PLC directory on `127.0.0.1:2860` (the `did-method-plc` image bench/migrate builds).
- Two reference PDSes, `ref-a` on `localhost:2861` and `ref-b` on `localhost:2862`. They're built by
  `refpds.sh` from bluesky-social/atproto at the pin `98ef3a6b` (branch `permissioned-data`, the
  wire of the `0.0.0-spaces-alpha-20261105160032` npm release), cloned blobless into
  `.scratch/atproto`. The published `pds-spaces-alpha` image has the same packages but is amd64
  only, so it doesn't run here. Set `REF_PDS_IMAGE` to use it on a host that can.
- MinIO on `127.0.0.1:2868` (the repo's `vlpds-minio:local` image). vlpds keeps its state there, so a
  `kill -9` loses nothing that was acked and the bucket's request counters are there to read.

Every service URL is `http://localhost:<port>` everywhere. Each reference PDS shares the network
namespace of a small socat container that forwards the other harness ports (2861-2889, or the run's block) to the other
PDS or to the host. So a DID document points at the same URL whether the driver, vlpds or a
reference PDS reads it. Docker Desktop routes `host.docker.internal` to the host's loopback, and
Linux Docker doesn't, so on Linux `run.sh` also starts `lib/hostbridge.mjs`, which listens on the
default bridge's gateway address (reachable only from this host's containers) and forwards each
harness port to 127.0.0.1.

`build-vlpds.sh` builds this checkout's `packages/vlpds` as it is on disk (uncommitted changes
included) with `--profile dev-release`, into the main checkout's `.scratch/target` so worktrees share
compiled dependencies, and copies the binary to `.scratch/vlpds`. It skips the build when the source
is clean and its tree hasn't changed since the last one. `VLPDS_BIN=...` skips it, and
`BRANCH=<ref>` builds a detached checkout of that ref under `.scratch/vlpds-src` instead.
`VLPDS_BIN=none` builds nothing, for the configs that only use the reference (`e2e ref-ref`,
`boards all-ref`, `sim` with `HOSTS=ref-a,ref-b`).

The drivers start vlpds themselves (`lib/vlpds.mjs`) with `--dev-mode --spaces` on port 2863, so the
fault sim can kill it. `CLUSTER=1` starts 3 nodes on MinIO behind a small round-robin balancer on
the same port, as in `tests/E2E.md`. `MEMORY=1` uses `--memory` instead of MinIO.

## Running two at once

Every run takes a block of 40 ports, so two checkouts (or two agents) can run the harness at the
same time. The ports above are the first block, `PORT_BASE=2860`. When it's taken, `run.sh` moves
to 2900, 2940 and so on, and prints the block it got. A run on another block gets its own compose
project (`vlpds-spaces-<base>`), `out/<base>/` and `boards/.local/<base>/`, and its UI is on
`<base>+28` (dev) or `<base>+29` (production) instead of 2888 or 2889. `lib/env.mjs` has the layout.
A block is held by a lock under `$TMPDIR/vlpds-spaces-locks` until its run exits, on Ctrl-C too, and
the exit takes down only that run's stack and volumes. `PORT_BASE=<base>` picks a block, which is
how to reuse a stack left up by `KEEP=1`. One run at a time does the shared setup (the images, the
vlpds build, `npm install`), and each UI run builds the boards web UI into its own `out/` dir.

## Real R2

`STORE=r2` runs vlpds on a real bucket instead of MinIO, so latency and request counts are the
network's and not loopback's. The PLC and the reference PDSes stay local.

The `vlpds-bench` bucket and its key were removed after the 2026-10-05 runs. To run again, bring
back `deploy/cloudflare/r2_bench.tf` from git history (the opentofu token then needs Account API
Tokens read/edit for the bucket key) and write its output to `R2_ENV`.

```
STORE=r2 VLPDS_BIN=... bench/spaces/run.sh cost
STORE=r2 SCALE=r2 bench/spaces/run.sh boards all-vlpds
bench/spaces/r2-clean.sh bench/<run-id>          # afterwards, with the prefix run.sh printed
```

- `run.sh` loads `R2_ENV` (default `~/.config/cloudflare/vlpds-bench-r2.env`, mode 600) with `set -a`.
  It holds `VLPDS_BENCH_ENDPOINT`, `VLPDS_BENCH_BUCKET`, `AWS_ACCESS_KEY_ID` and
  `AWS_SECRET_ACCESS_KEY`. The keys reach vlpds as `VLPDS_S3_ACCESS_KEY` / `VLPDS_S3_SECRET_KEY` in its
  environment, never on the command line the log prints, and vlpds redacts them in its own config
  dump. Nothing here should print the file.
- Each run gets its own prefix, `bench/<utc time>-<mode>` (or `R2_PREFIX`), with `--s3-region auto`.
  A single node runs with `--shards 16` (`R2_SHARDS`), the same as the cluster, since every shard
  polls and checkpoints on its own and idle requests are billed. `CLUSTER=1` uses the vlpds default
  `--lease-ttl-ms 10000` here (3000 on MinIO). Its control-plane deadline is min(TTL, 5 s), and an R2
  GET can take over 3 s.
- The driver samples `vlpds_object_store_requests_total` on every node every 2 s into
  `out/r2-ops.json`, carrying counts over restarts (a `kill -9` loses up to 2 s of them), and logs the
  run's total when it stops vlpds. Past `R2_OPS_LIMIT` (45,000) it kills vlpds and exits 4. MinIO's
  counters don't exist here, so the cost run's `minio_ops_per_write` reads 0.
- `r2-clean.sh` lists and deletes the prefix with the aws CLI and prints the requests that took. The
  bucket's 1-day expiry is only a backstop.
- `SCALE=r2` shrinks boards story 10 to 10 members, 80 posts, 300 comments and 800 votes.

## How the driver acts like an app

The wire is what a real app sends. Calls go through `@atproto/api` at the Spaces alpha
(`0.0.0-spaces-alpha-20261105160032`), which also validates every response against the lexicons.
Credentials, HTTP message signatures, KEM encapsulation, MACs, LtHash and STAR verification come
from `@atproto/space` at the same version.

- On a reference PDS the driver uses a password session, as the reference's own tests do.
- vlpds only takes OAuth for spaces, so each vlpds account also authorizes a loopback client
  headlessly (`lib/oauth.mjs`: PAR, PKCE, the sign-in and consent forms, DPoP). The scope asks for
  every space action on `com.example.group` at any authority, plus `blob:*/*`, `repo:*` and the two
  `rpc:` grants the revocation and notify tests need (`APP_SCOPE` in `lib/actor.mjs`).
- A credential is requested with a body (`space`, `credentialKid`, `delegationToken`) at the
  authority's `#atproto_pds`, and presented as `Authorization: Atproto-Space-Credential` with a
  tagged RFC 9421 signature.
- A syncer (`lib/syncer.mjs`) gets credentials through a read-only member's delegation token. It
  catches up with `listRepos` from a spaceRev checkpoint and pulls each repo from its own host with
  `listRepoOps`. Every getLatestCommit, getRepo, listRepoOps and getRecord it sends carries
  `Atproto-Space-Want-Mac` with a key share encapsulated afresh to the author's `#atproto_kem` key,
  and a commit counts only once the response's `Atproto-Space-Mac` verifies. It keeps a running
  LtHash per repo and checks it against the commit's `data`, falling back to a verified STAR
  `getRepo` on a mismatch (which is also how it sees a `clearRecords`).
- Forwarded notifications land on `lib/notifysvc.mjs`. It's a real did:plc whose
  `#atproto_space_syncer` entry points at it, and it checks each call's service auth against the
  authority's key. It also answers `com.atproto.managedspace.checkUserAccess` as a managing app.

## The matrix (e2e)

Each configuration puts the roles on hosts and runs the same steps against them:

| config | authority | writer 1 | writer 2 | reader (syncer) | outsider |
|---|---|---|---|---|---|
| ref-ref | ref-a | ref-a | ref-b | ref-b | ref-a |
| vlpds-authority | vlpds | vlpds | ref-a | ref-b | ref-b |
| ref-authority | ref-a | ref-b | vlpds | vlpds | vlpds |
| vlpds-only | vlpds | vlpds | vlpds | vlpds | vlpds |

ref-ref runs first. It checks the harness, so a failure in another column points at vlpds. The
steps cover:

- spaces and policies: createSpace with a memberspace policy and its stored defaults,
  `UnsupportedPolicy`, members, publicRead with and without a delegation token, allowedApps,
  managedspace and `checkUserAccess`, personalspace, wholesale `updateSpace` and the member list
  going with a policy change, `PolicyMismatch`, and published policy and member records
- record writes (create, put, delete, applyWrites and its atomicity, direct writes to the published
  collections refused), self-reads with an optional MAC
- the credential chain: claims and `kid`s, `#atproto_pds` audiences, single-use delegation and
  `InvalidDelegationToken`, `SpaceNotFound` for outsiders and token-less requests, a non-P-256
  `credentialKid`; then the request signature (tag, label next to another, DER refused, high-S and
  unpadded base64 accepted, a lower-case scheme, the old `Atproto-Space` scheme refused, wrong
  audience, wrong key) and getSpace refusing a credential
- MACs: commit and record MACs verified against the author's `#atproto_kem` key, `BadSpaceMac`
  without the header or with a bad key share, type or version, `Vary` and
  `Access-Control-Expose-Headers`
- full and incremental sync with LtHash checks, the STAR archive (end byte, path order, a truncated
  archive rejected)
- notify registration and delivery (service auth, `data`, spaceRev and prevSpaceRev order,
  listRepos paging), `FutureRev` and stale notifies sent straight to the space host, the old
  `#atproto_space_host` audience refused
- read-only members not being tracked, blobs (the reference rule for `sync.getBlob`), revocation,
  admin takedowns of a writer and of the authority (`RepoTakendown` while held credentials keep
  reading), app passwords
- the writer set: member removal, `clearRecords` (the empty digest, a syncer resyncing),
  `removeWriter` and re-tracking
- `importRepo` (a new rev with the same data, an older archive replacing the repo),
  `exportSpaceMeta` / `importSpaceMeta`, space deletion and the leak check

Two steps cover vlpds extensions and run only when the writer (and, for the second, the space) is on
vlpds:

- `takedown.record`: an admin takedown of one space record (`updateSubjectStatus` with a strongRef
  to its 7-segment URI). While it's down, credential reads don't see it, `getRepo` verifies without
  it, the commit's data is the LtHash of the remaining records, `listRepoOps` agrees, its blob answers
  `BlobNotFound`, and a syncer converges on that view, then back to the full one after reversal.
  A vlpds that hides the record but keeps it in the digest reports not impl.
- `operator.read`: `vlpds.admin.getSpaceRecord` with admin auth reads a space record, a member's
  OAuth token, an unrelated account and a wrong admin password can't, and the read shows up in
  `vlpds.admin.getAuditLog`. Not impl. while the method is missing.

Every step ends in one of these states:

- pass
- fail, with the checks that failed
- not impl., when a method answered 501, which is how the table tracks progress on vlpds
- blocked, when a step it needs didn't pass
- skip, when it doesn't apply to that placement

The leak check runs in every configuration. Every space write carries the run's sentinel (in
values, record keys and the space's skey). The harness taps each host's `subscribeRepos` from
before the first write, replays it from cursor 0 at the end, and reads `sync.getRepo` and
`sync.listBlobs` for every account. None of them may contain the sentinel, and space-only blobs must
answer `BlobNotFound` on `sync.getBlob`. `LEAK_SELFTEST=1` writes the sentinel into a public record
on purpose, which must fail the step on all three surfaces.

## The sims

`sim.mjs [seed] [scale]` creates N spaces with M writers each and K registered syncers per space,
spread over the hosts in `HOSTS` (default `ref-a,ref-b,vlpds`, or `ref-a,ref-b` without vlpds).
Then it runs random creates, puts, deletes, batches and membership changes from a seeded PRNG. The
scales are `small` (3 spaces × 4 writers × 2 syncers, 300 ops), `medium` (6 × 6 × 3, 1,500 ops),
`large` (12 × 8 × 4, 6,000 ops), or a number of ops. Writes to one repo go one at a time, as an
app's do.

After the workload it checks these invariants:

- I1: each host holds exactly the acked writes for every repo. Writes whose outcome is unknown (a
  crash or a 5xx) may land either way, and the host's answer is taken for those paths.
- I2: the authority's `listRepos` has every active writer at its head. This is notify delivery,
  eventually. With faults it waits up to 4 minutes (`CONVERGE_MS`), since dropped notifies are
  retried with backoff.
- I3: every syncer, after catching up from its checkpoint, holds the acked state of every listed
  repo, and its LtHash matches the listed data.
- I4: no spaceRev is given to two different updates, and the prevSpaceRev chain never forks.
- I5: no syncer saw a protocol violation (cursor rules, ordering, a rev going backwards).

`FAULTS=1` (`just spaces-fault`) adds faults during the workload:

- A fault proxy in front of every syncer drops 20% of forwarded notifies (as a 503), duplicates
  20% and delays them by up to 1.5 s.
- The authority's `#atproto_pds` (its space host) is pointed at a proxy that passes everything
  through but drops 30% of inbound `notifyWrite`s. That exercises the writer's retry path, which is the outbox on
  vlpds.
- vlpds gets a `kill -9` at a third of the ops and a SIGTERM at two thirds, each restarted right
  away. With `CLUSTER=1`, node 1 is killed and stays down 20 s, so its shards move.
- Three syncers restart, two from a stale snapshot and one from nothing.

The proxies heal before the invariants run.

## Cost

`cost.mjs` (`just spaces-cost`) measures each thing against its target:

| what | how | target |
|---|---|---|
| no-op poll | 300 `listRepoOps(since=head)`, server time from `vlpds_http_request_duration_seconds` | mean well under 1 ms, 0 bucket ops |
| delta pull | write one record, then `listRepoOps(since)`, 200 times | a few ms |
| notify | write, then time to the forwarded `notifyWrite` | p50 under 100 ms locally (no linger) |
| bucket ops | `vlpds_object_store_requests_total` and MinIO's counters per write, net of idle | space write ≤ public write |
| public p99 | 300 public writes alone, then with 8 space writers running | within 25% + 2 ms |
| warm writes | after 30 warmup rounds, `WARM_N` (210) rounds of createRecord, putRecord and a one-op applyWrites in turn, one account in one space | reported, not gated |

The warm-writes step reports client p50/p90/p99 per method, and on vlpds the deltas over the run of
`vlpds_http_request_duration_seconds` per method, `vlpds_commit_stage_seconds` per stage (seal_wait,
put, apply_lock, apply, ack; these are per segment, not per write), and `vlpds_commit_durable_seconds`. Histogram quantiles are bucket upper bounds.

Against a reference PDS (`just spaces-cost ref-a`) it reports the client-side numbers only. A
second argument picks steps (a comma list); setup always runs. The report is
`out/cost-<host>[-<steps>].md`.

## Reading the results

Each run writes `out/<mode>.json` (every check) and `out/<mode>.md` (the table, failures, metrics and
notes), and prints the markdown at the end.

Both also carry the driver's client-side latency for every space call, keyed by scope (the e2e
config, the sim phase, the cost step), host (`vlpds`, `ref-a`, `ref-b`, a fault proxy as
`<host>~proxy`) and outcome (`ok`, `refused` for a 4xx, `error` for a 5xx or a dropped connection,
`ni` for 501). The md has a by-host table of ok calls pooled over configs, then the full breakdown
(`client_ms` in the json). A call the auth layer retried (a DPoP nonce, an expired token) is timed
on its final attempt only, and counted in `retried`. The e2e samples are small and include each
host's cold first calls; the cost run's warm-writes step is the latency number to quote. vlpds's log is `out/vlpds-n<i>.log`. The exit code is 0
when nothing failed, 1 on a failure, and 3 for a sim that stopped at a method that isn't implemented.

## Iterating

```
KEEP=1 just spaces-e2e ref-ref              # leave the stack up
cd bench/spaces
VLPDS_BIN=.scratch/target/dev-release/vlpds node e2e.mjs vlpds-only
HOSTS=ref-a,ref-b node sim.mjs 7 small      # all-ref sim
docker compose -p vlpds-spaces down -v      # when done
```

`.scratch/` holds the atproto clone (~50 MB), the vlpds checkout and its target dir (several GB).
Delete `.scratch/target` when you're done with vlpds builds for a while.
