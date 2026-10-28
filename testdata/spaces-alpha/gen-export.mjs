// Generates export.star and export.json: a space repo as the reference PDS's
// com.atproto.space.getRepo serves it (packages/pds/src/api/com/atproto/space/
// getRepo.ts: buildCommit = RepoCommit.fromState(..).toCommit, then
// serializeRepo), for vlpds's importRepo tests (tests/all/spaces_side/import_repo.rs).
// Run in a directory with the release in SOURCE installed (see gen-vectors.mjs):
// node gen-export.mjs <out dir>
// The output is deterministic. The archive is checked with verifyRepoStarFull
// (under a MAC computed for the purpose) before it is written.
import { writeFileSync } from 'node:fs'
import { Secp256k1Keypair, sha256 } from '@atproto/crypto'
import { cidForRawBytes } from '@atproto/lex-data'
import {
  RepoCommit,
  computeCommitMac,
  serializeRecord,
  serializeRepo,
  verifyRepoStarFull,
} from '@atproto/space'

const out = process.argv[2] ?? '.'
const hex = (b) => Buffer.from(b).toString('hex')
const seed = async (label) => sha256(new TextEncoder().encode(label))

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

const author = await Secp256k1Keypair.import(await seed('vlpds spaces phase 3 export author k256'), {
  exportable: true,
})
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
  [C2, 'longer-record-key-than-the-others', { $type: C2, text: 'the archive is in bytewise path order' }],
]
const serialized = []
for (const [c, r, v] of recs) serialized.push(await serializeRecord(c, r, v))
// the archive's order: bytewise by path
serialized.sort((x, y) => Buffer.compare(Buffer.from(`${x.collection}/${x.rkey}`), Buffer.from(`${y.collection}/${y.rkey}`)))
const repo = RepoCommit.fromRecords(serialized)
const commit = repo.toCommit({ space, repo: did, rev })

const chunks = []
for await (const c of serializeRepo(commit, serialized)) chunks.push(c)
const star = Buffer.concat(chunks)

const sharedSecret = await seed('vlpds spaces export mac')
const mac = computeCommitMac(sharedSecret, commit)
const verified = await verifyRepoStarFull([star], { space, repo: did, sharedSecret, mac })
if (verified.records.length !== recs.length) throw new Error('verifyRepoStarFull: record count')

writeFileSync(`${out}/export.star`, star)
writeFileSync(
  `${out}/export.json`,
  `${JSON.stringify(
    {
      generatedBy: 'gen-export.mjs: @atproto/space serializeRepo + RepoCommit.toCommit at the release in SOURCE',
      did,
      space,
      rev,
      didKey: author.did(),
      privateKeyHex: hex(await author.export()),
      data: hex(commit.data),
      blob: { cid: blobCid.toString(), bytesHex: hex(blobBytes), mimeType: 'image/png' },
      records: serialized.map((s) => ({ collection: s.collection, rkey: s.rkey, cid: s.cid.toString() })),
    },
    null,
    2,
  )}\n`,
)
