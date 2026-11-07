// Generates export.star and export.json: a space repo as the reference PDS's
// com.atproto.space.getRepo serves it (packages/pds/src/api/com/atproto/space/
// getRepo.ts: buildCommit, then serializeRepo), for vlpds's importRepo tests
// (tests/all/spaces_side/import_repo.rs). Run in packages/space of a built
// bluesky-social/atproto checkout at the commit in SOURCE, e.g. in the
// harness's reference image (bench/spaces/refpds.sh):
//   docker run --rm --entrypoint node -w /app/packages/space -v "$PWD:/out" \
//     -v "$PWD/gen-export.mjs:/app/packages/space/gen-export.mjs:ro" \
//     vlpds-spaces-refpds:<pin> gen-export.mjs /out
// Deterministic: STAR carries no signature or random field. The archive is
// checked with readRepoStar before it is written.
import { writeFileSync } from 'node:fs'
import { cidForRawBytes } from '@atproto/lex-data'
import { RepoCommit, readRepoStar, serializeRecord, serializeRepo } from './dist/index.js'

const out = process.argv[2] ?? '.'
const hex = (b) => Buffer.from(b).toString('hex')

// s32 TID: 53 bits of microseconds, 10 bits of clock id
const S32 = '234567abcdefghijklmnopqrstuvwxyz'
const tid = (micros, clock) => {
  let n = (BigInt(micros) << 10n) | BigInt(clock)
  let s = ''
  for (let i = 0; i < 13; i++) {
    s = S32[Number(n & 31n)] + s
    n >>= 5n
  }
  return s
}

// A did:plc in syntax only: the tests serve its document from a stub directory.
const did = 'did:plc:vlpdsspacesrefexport2345'
const space = `at://${did}/space/com.example.group/refexport`
const rev = tid(1790000000000000, 7)

const blobBytes = new TextEncoder().encode('\x89PNG\r\n\x1a\n vlpds spaces reference export blob')
const blobCid = await cidForRawBytes(blobBytes)

const C1 = 'com.example.spaceRecord'
const C2 = 'com.example.spaceNote'
const recs = [
  [C1, '3lzzzzzzzzz22', { $type: C1, text: 'first', createdAt: '2026-09-21T12:00:00.000Z' }],
  [C1, 'a', { $type: C1, text: 'short rkey', n: 1 }],
  [C1, 'self', { $type: C1, text: 'with a blob', image: { $type: 'blob', ref: blobCid, mimeType: 'image/png', size: blobBytes.length } }],
  [C2, '3lzzzzzzzzz23', { $type: C2, text: 'a note', tags: ['x', 'y'], nested: { deep: true } }],
  [C2, 'longer-record-key-than-the-others', { $type: C2, text: 'paths in bytewise order' }],
]
const serialized = []
for (const [c, r, v] of recs) serialized.push(await serializeRecord(c, r, v))
// STAR wants strict path order
serialized.sort((a, b) => Buffer.compare(Buffer.from(`${a.collection}/${a.rkey}`), Buffer.from(`${b.collection}/${b.rkey}`)))
const commit = RepoCommit.fromRecords(serialized).toCommit({ space, repo: did, rev })

const chunks = []
for await (const c of serializeRepo(commit, serialized)) chunks.push(c)
const star = Buffer.concat(chunks)

await using read = await readRepoStar([star])
let n = 0
for await (const _ of read.records) n++
if (n !== recs.length) throw new Error('readRepoStar: record count')

writeFileSync(`${out}/export.star`, star)
writeFileSync(
  `${out}/export.json`,
  `${JSON.stringify(
    {
      generatedBy: 'gen-export.mjs: @atproto/space serializeRepo + RepoCommit.toCommit at the commit in SOURCE',
      did,
      space,
      rev,
      data: hex(commit.data),
      blob: { cid: blobCid.toString(), bytesHex: hex(blobBytes), mimeType: 'image/png' },
      records: serialized.map((s) => ({ collection: s.collection, rkey: s.rkey, cid: s.cid.toString() })),
    },
    null,
    2,
  )}\n`,
)
