---
title: Blobs
section: vlPDS
order: 5
status: ready
summary: "Images and video: streamed uploads into the bucket, reference tracking with each commit, and a garbage collector that can't race a write."
---

```hero
diagram:
  caption: "Blob bytes live only in the bucket, under their final key from the moment the upload finishes. References are state rows written with the commit that adds them. The GC, run by the account's owner, quarantines unreferenced blobs before deleting them."
  nodes:
    - { id: up, label: uploadBlob, sub: "≤ 100 MiB · streamed", at: [0, 4], size: [8, 3] }
    - { id: tmp, label: "`blob-tmp/{did}/…`", sub: "multipart · ≥ 8 MiB", at: [12, 0], size: [11, 2.6], shape: store, tone: amber }
    - { id: blob, label: "`blob/{did}/{cid}`", sub: bytes · Content-Type, at: [27, 4], size: [11, 3], shape: store, tone: amber }
    - { id: get, label: getBlob, sub: streamed from bucket, at: [42, 4], size: [8, 3], tone: blue }
    - { id: write, label: createRecord, sub: record names the blob, at: [0, 11], size: [8, 3] }
    - { id: refs, label: "`b/` refs", sub: written with the commit, at: [11, 11.2], size: [9, 2.6], shape: store, tone: amber }
    - { id: gc, label: Blob GC, sub: hourly · owner only, at: [27, 11], size: [11, 3], tone: accent }
    - { id: q, label: "`blob-gc/{did}/{cid}`", sub: "quarantine · then delete", at: [27, 17], size: [11, 2.6], shape: store, tone: amber }
  edges:
    - "up.r -> blob.l: < 8 MiB: one PUT"
    - "up.t -> tmp.l: parts"
    - "tmp.r -> blob.t: copy"
    - "blob.r -> get.l"
    - "write.r -> refs.l: commit"
    - "refs.r -> gc.l: referenced?"
    - { from: gc.t, to: blob.b, label: list, dash: true }
    - "gc.b -> q.t: move if not"
facts:
  - { value: "100", unit: MiB, label: largest blob, note: "`--max-blob-mb`, or the account's override (up to `--max-blob-override-mb`)" }
  - { value: "6 h", label: before an unused upload is collected, note: "`--blob-gc-grace-secs`, counted from the upload", tone: violet }
  - { value: "1 day", label: lifecycle rule to add to the bucket, note: "aborts multipart uploads a crash left behind", tone: amber }
  - { value: "~350 TB", label: "of blobs at Bluesky's scale", note: "~$7.8k/mo on S3: more than everything else together", tone: blue }
```

Blobs are the images, videos and other files that records point to. vlpds never keeps them on a
node. An upload streams straight into the bucket under `blob/{did}/{cid}`, a record that names the
blob gets a reference row in the same commit, and a garbage collector deletes uploads nothing
refers to. Blob traffic never touches the commit path or the log.

For an operator, blobs are mostly a storage bill and one bucket setting. At scale they're most of
the bytes in the bucket, and the bucket needs a lifecycle rule that vlpds can't set for itself.

## Upload path

```steps
- title: Authorize
  body: "The upload needs a session or OAuth token (with a `blob:` scope matching the type), or a user service token. The Bluesky video service uses a service token to upload a transcoded video on the user's behalf, and the app gets it from `getServiceAuth`. A cluster sends the upload to the account's owner. Taken-down accounts are refused, but deactivated ones may upload so they can migrate in."
- title: Stream and hash
  body: "The limit is the account's own (`setBlobQuota` `maxBlobBytes`) or `--max-blob-mb`. A `Content-Length` over it gets a 413 before any byte is read, and a body without one is cut off as soon as it passes it. The body is hashed (SHA-256) as it arrives. Its first 64 bytes are checked for a known signature (PNG, JPEG, GIF, WebP, AVIF, HEIC, MP4, QuickTime, WebM, PDF), and a match overrides the client's `Content-Type`."
- title: Store
  body: "Under 8 MiB, the blob is buffered and written with one PUT to `blob/{did}/{cid}`. Anything larger goes up as a multipart upload in 8 MiB parts (4 in flight) to `blob-tmp/{did}/{random}`, since the CID isn't known until the end. Then it's copied to the final key and the temp object is deleted."
- title: Answer
  body: "A private row records that the account stores the blob (checkAccountStatus counts these as `importedBlobs`). The client gets back the blob ref with its CID, MIME type and size."
```

An upload holds at most about 8 MiB in memory before it switches to multipart, and then a few parts
in flight. A failed upload aborts its multipart upload and deletes the temp object. Uploading the
same bytes again rewrites the same key, which restarts the GC grace period.

Each IP may upload 1,000 blobs a day. An account that's moving in (and still deactivated) is exempt
for blobs its imported repo references. That covers the daily budget and the global per-IP limit of
3,000 requests per 5 minutes (the handler gives that point back once it knows the blob is
referenced). So a big account can arrive in one sitting at full speed. Unlike the reference PDS,
vlpds serves a blob through `getBlob` as soon as it's uploaded, before any record names it.

Metrics: `vlpds_blob_uploads_total{kind}` (`image`, `video`, `other`) and
`vlpds_blob_upload_bytes_total`.

## References

```diagram
caption: "Before a write is sequenced, each blob it names is checked in the bucket and held for the GC. The reference rows are written in the commit's own state batch."
nodes:
  - { id: w, label: createRecord, sub: "putRecord · applyWrites", at: [0, 0], size: [8, 3] }
  - { id: chk, label: Blob check, sub: one HEAD per blob, at: [12, 0], size: [9, 3], tone: accent }
  - { id: blob, label: "`blob/{did}/{cid}`", sub: type · size must match, at: [25, 0], size: [11, 3], shape: store, tone: amber }
  - { id: c, label: Commit, sub: repo worker · log, at: [12, 5.5], size: [9, 3], tone: accent }
  - { id: refs, label: "`b/` rows", sub: "{cid} · {record path} → rev", at: [25, 5.5], size: [11, 3], shape: store, tone: amber }
edges:
  - w -> chk
  - "chk -> blob: HEAD"
  - "chk -> c: then sequence"
  - "c -> refs: same batch"
```

A record that names a blob can only be written if the blob is in the bucket for that account, with
a stored MIME type and size that match what the record declares. Otherwise the write fails with
`BlobNotFound`, `InvalidMimeType` or `InvalidSize`. The check makes one HEAD per distinct blob. It
also registers the blob as in flight until the write is acked or fails, and the GC respects that.

References are `b/{did}\0{gen}{cid}\0{record path}` rows in the shard's SlateDB, and each row's
value is the rev of the record that added it. They're written and deleted in the same state batch
as the commit that adds or removes the reference, so they always match the repo. Updating or
deleting a record drops its rows. Deleting an account drops all of them, and then the GC removes
the bytes. The repo worker only reads a repo's reference rows when a write needs them (an update, a
delete, or a create that carries blobs).

Writes refuse the old `{cid, mimeType}` blob form. `importRepo` still indexes it, so an old
migrated repo's images are listed and kept. `sync.listBlobs` pages through the references in CID
order (with `since`, only the ones added after a rev). `repo.listMissingBlobs` HEADs each one to
find what a migration still has to upload. With `--spaces` it also walks the blobs the account's
space records name (`sc/`), in the same CID order. See [Migration](migration.md).

## Garbage collection

```steps
- title: List
  body: "Each node lists the whole `blob/` prefix and skips accounts whose shard it doesn't own. A pass runs every grace ÷ 4, kept between 10 s and 1 h, so it's hourly at the default."
- title: Quarantine
  body: "A blob uploaded more than `--blob-gc-grace-secs` ago (6 h) that no record references gets copied to `blob-gc/{did}/{cid}` and deleted from `blob/`. That counts references in the current repo and in an import being staged. Once it's moved, it isn't served anymore."
- title: Settle
  body: "On a later pass, once the quarantined copy is 60 s old (or the grace period, if that's shorter), the GC checks the references again."
- title: Restore, wait or purge
  body: "If a reference showed up, the blob moves back (logged as a warning). If a write on this node checked the blob and is still in flight, the blob waits for the next pass. Otherwise it's deleted."
```

Quarantine guards against a race. A write checks that its blob exists, and its reference is
applied a moment later. A sweep that read "no reference" in between would delete a blob that's
about to be used. With quarantine, a write that checked before the move gets its blob back at the
settle check. A write that checks after the move fails with `BlobNotFound`, the same as for any
missing blob. A write slower than the settle time (a cold repo load, a store brownout) holds the
blob until it finishes.

The grace period counts from the upload (the object's last-modified time), and not from when the
last reference went away. So an image removed from a post an hour after upload is quarantined on
the next pass and deleted about one pass later. In between it sits in `blob-gc/`, and that's the
only window to recover a blob deleted by mistake.

A blob the operator takes down is handled separately. Its bytes move to `blob-quarantine/` and stay
there for `--blob-quarantine-days` (30) no matter what references it, and the GC never sees them.
See [Email and moderation](operations/email-and-moderation.md#what-a-takedown-does).

The same pass deletes completed temp objects under `blob-tmp/` older than 24 h (or the grace
period, if that's longer). A crash between the multipart upload and the copy leaves these behind.
The GC has no metrics. It logs `blob gc` with the counts at info level when it deleted something,
and logs warnings for failed moves.

## Bucket lifecycle rule

```diagram
caption: "Parts of a multipart upload whose process died mid-way are invisible to LIST, so vlpds can't find them. The bucket's lifecycle rule aborts them; until then they are billed as storage."
nodes:
  - { id: up, label: Large upload, sub: process dies, at: [0, 0], size: [8, 3], tone: danger }
  - { id: parts, label: Orphaned parts, sub: not listable · billed, at: [12, 0], size: [10, 3], shape: store, tone: amber }
  - { id: rule, label: Lifecycle rule, sub: abort after 1 day, at: [26, 0], size: [9, 3], tone: ok }
edges:
  - "up -> parts: leaves"
  - "rule -> parts: aborts"
```

Add this rule when you create the bucket. It only touches uploads that were never completed, so
it's safe on the whole bucket (an empty prefix). On S3:

```json
{"Rules": [{"ID": "abort-incomplete-mpu", "Status": "Enabled", "Filter": {"Prefix": ""},
            "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 1}}]}
```

```bash
aws s3api put-bucket-lifecycle-configuration --bucket <bucket> \
  --lifecycle-configuration file://rule.json
```

On R2, set the same thing in the dashboard (bucket > Settings > Object lifecycle rules > "Abort
incomplete multipart uploads", 1 day) or send the S3 call above to the R2 endpoint. MinIO doesn't
need the rule because it aborts stale uploads itself after 24 h. Other bucket settings (GCS soft
delete, versioning) are in [Object store](operations/object-store.md#lifecycle-rules).

## Serving blobs

```diagram
caption: "getBlob is forwarded to the account's owner, which streams the object out of the bucket. In the Bluesky app, images reach viewers through the AppView's CDN, which fetches them from this PDS."
nodes:
  - { id: cdn, label: AppView CDN, sub: "cdn.bsky.app", at: [0, 0], size: [8, 3], tone: muted }
  - { id: node, label: Account owner, sub: takedown · status checks, at: [12, 0], size: [9, 3], tone: accent }
  - { id: blob, label: "`blob/{did}/{cid}`", sub: one GET per request, at: [25, 0], size: [11, 3], shape: store, tone: amber }
edges:
  - "cdn -> node: getBlob"
  - "node -> blob: stream"
```

`sync.getBlob` streams the object with its stored `Content-Type` and the reference PDS's hardening
headers: `X-Content-Type-Options: nosniff`, `Content-Disposition: attachment` and
`Content-Security-Policy: default-src 'none'; sandbox`. There's no blob cache on the node and no
`Cache-Control` header, so every request is one GET from the bucket (plus egress, except on R2).
If something other than the AppView's CDN fetches blobs heavily, put a CDN or caching proxy in
front.

A blob isn't served (`BlobNotFound`) once an admin has taken it down. A taken-down blob also can't
be uploaded again or referenced by a new record. A taken-down or deactivated account's blobs are
only served to the account itself and to admins. Read-after-write views of a user's own posts link
images through `--bsky-app-view-cdn-url-pattern` when it's set, and through this PDS's `getBlob`
otherwise ([Proxying](proxying.md#read-after-write)).

## Sizing

```facts
- { value: "~350 TB", label: "blobs at Bluesky's scale", note: "~$7.8k/mo on S3 · the rest of the bucket is ~5 TB", tone: amber }
- { value: "~1M", unit: uploads/day, label: at Bluesky's scale, note: "≈ 12 a second, which is light next to commits" }
- { value: "$0", label: "storage for a small PDS on R2", note: "10 GB free tier, then $0.015/GB-month and no egress", tone: blue }
- { value: "1", unit: LIST, label: "per 1,000 blobs, per node, per GC pass", note: "hourly · not in the cost model", tone: rust }
```

Blobs dominate storage. At Bluesky's scale they come to ~350 TB, against ~5 TB for state and 72 h
of log. That's why the cost model prices them separately from the ~$1.7k/mo of requests
([Overview](overview.md#how-big-it-gets)). Upload and serve rates are small next to commits, so
the costs are bytes stored and, off R2, egress.

The GC's listing grows with the blob count times the node count, and traffic doesn't change it. A
personal or community server won't notice it. At Bluesky's scale (~1 B blobs, if the average is
~350 KB) the estimate is ~1M LIST requests per node per hour, and that isn't in the cost model.
Raising the grace period doesn't help, since passes run at least once an hour.
