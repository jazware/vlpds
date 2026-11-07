// Generates vectors.json from the reference implementation (@atproto/space).
// Run in packages/space of a built bluesky-social/atproto checkout at the
// commit in SOURCE, e.g. in the harness's reference image (bench/spaces/refpds.sh):
//   docker run --rm --entrypoint node -w /app/packages/space \
//     -v "$PWD/gen-vectors.mjs:/app/packages/space/gen-vectors.mjs:ro" \
//     vlpds-spaces-refpds:<pin> gen-vectors.mjs > vectors.json
// Keys are fixed and both curves sign with RFC 6979, so the output is
// deterministic; Date.now is pinned for the tokens (jti stays random).
import { P256Keypair, Secp256k1Keypair, sha256 } from '@atproto/crypto'
import { encode } from '@atproto/lex-cbor'
import { parseCid } from '@atproto/lex-data'
import {
  COMMIT_MAC_TYPE,
  LtHash,
  RECORD_MAC_TYPE,
  RepoCommit,
  computeCommitMac,
  computeRecordMac,
  createSpaceSigHeaders,
  createSpaceToken,
  decapsulate,
  formatMacHeader,
  formatSetHashElement,
  formatWantMacHeader,
  parseMacHeader,
  parseWantMacHeader,
  readSpaceMetaStar,
  serializeRecord,
  serializeRepo,
  serializeSpaceMeta,
  verifyCommit,
  verifyCredentialSig,
  verifyRecordMac,
  verifySpaceToken,
} from './dist/index.js'

const hex = (b) => Buffer.from(b).toString('hex')
const seed = async (label) => sha256(new TextEncoder().encode(label))
const concat = async (gen) => {
  const parts = []
  for await (const p of gen) parts.push(p)
  return Buffer.concat(parts)
}

const NOW_SEC = 1790000000
Date.now = () => NOW_SEC * 1000

const out = { now: NOW_SEC }

// LtHash
const lthash = []
const seq = (ops) => {
  const h = new LtHash()
  for (const [op, el] of ops) op === '+' ? h.add(el) : h.remove(el)
  return h
}
for (const ops of [
  [],
  [['+', 'one'], ['+', 'two']],
  [['+', 'two'], ['+', 'one']],
  [['+', 'a']],
  [['-', 'a']],
  [['+', 'a'], ['+', 'a']],
  [['+', 'a'], ['+', 'b'], ['-', 'a']],
  [['+', ''], ['+', 'é/ü/☃']],
  [['+', 'app.bsky.feed.post/3kbcq3p7ad400/bafyreidefdycgbfy3oglcb6ism3eqhyp5llsrpzxjsuac2gsy4mtrtx244']],
]) {
  const h = seq(ops)
  lthash.push({ ops, state: hex(h.state()), digest: hex(h.digest()), empty: h.isEmpty() })
}
out.lthash = lthash

// KEM: the repo host's side (decapsulate) for fixed keys. The syncer's side
// derives the same secret from the other private key.
const kem = []
for (const label of ['a', 'b']) {
  const authorSeed = await seed(`vlpds spaces kem author ${label}`)
  const syncerSeed = await seed(`vlpds spaces kem syncer ${label}`)
  const author = await P256Keypair.import(authorSeed)
  const syncer = await P256Keypair.import(syncerSeed)
  kem.push({
    authorPrivate: hex(authorSeed),
    authorKey: author.did(),
    syncerPrivate: hex(syncerSeed),
    keyShare: syncer.did(),
    sharedSecret: hex(decapsulate(author, syncer.did())),
  })
}
out.kem = kem

// Commits and their MACs, with a fixed shared secret
const CID_A = parseCid('bafyreidefdycgbfy3oglcb6ism3eqhyp5llsrpzxjsuac2gsy4mtrtx244')
const CID_B = parseCid('bafyreidpw4cbv6gr4ukh33z23pvvrpr3wi4gnpmi4doamlsl3sa4rgri2a')
const commits = []
for (const [ctx, records] of [
  [{ space: 'at://did:example:space/space/app.bsky.group/test', repo: 'did:example:alice', rev: '3kbcq3p7ad400' }, [['app.bsky.feed.post', '1', CID_A]]],
  [
    { space: 'at://did:plc:asdf123/space/com.example.group/default', repo: 'did:plc:user1', rev: '3lzzzzzzzzz22' },
    [['n.c.a', '1', CID_A], ['n.c.b', '2', CID_B]],
  ],
  [{ space: 'at://did:plc:x/space/com.example.group/self', repo: 'did:plc:x', rev: '3kbcq3p7ad401' }, []],
]) {
  const repo = new RepoCommit()
  for (const [c, r, cid] of records) repo.add(c, r, cid)
  const sharedSecret = await seed(`shared secret ${ctx.rev}`)
  const commit = repo.toCommit(ctx)
  const mac = computeCommitMac(sharedSecret, commit)
  if (!verifyCommit(commit, { space: ctx.space, repo: ctx.repo, sharedSecret, mac })) {
    throw new Error('commit vector does not verify')
  }
  const header = formatMacHeader(COMMIT_MAC_TYPE, mac)
  if (hex(parseMacHeader(header, COMMIT_MAC_TYPE)) !== hex(mac)) throw new Error('mac header')
  commits.push({
    ctx,
    records: records.map(([c, r, cid]) => ({ collection: c, rkey: r, cid: cid.toString(), element: formatSetHashElement(c, r, cid) })),
    data: hex(commit.data),
    sharedSecret: hex(sharedSecret),
    mac: hex(mac),
    macHeader: header,
  })
}
out.commits = commits

const recordMacs = []
for (const [uri, cid] of [
  ['at://did:example:alice/space/did:example:space/app.bsky.group/test/app.bsky.feed.post/1', CID_A],
  ['at://did:plc:user1/space/did:plc:asdf123/com.example.group/default/n.c.b/2', CID_B],
]) {
  const sharedSecret = await seed(`record secret ${uri}`)
  const mac = computeRecordMac(sharedSecret, uri, cid)
  if (!verifyRecordMac(sharedSecret, uri, cid, mac)) throw new Error('record mac')
  recordMacs.push({ uri, cid: cid.toString(), sharedSecret: hex(sharedSecret), mac: hex(mac), macHeader: formatMacHeader(RECORD_MAC_TYPE, mac) })
}
out.recordMacs = recordMacs

const wantMac = []
for (const type of [COMMIT_MAC_TYPE, RECORD_MAC_TYPE]) {
  const header = formatWantMacHeader(type, kem[0].keyShare)
  if (parseWantMacHeader(header, type) !== kem[0].keyShare) throw new Error('want-mac header')
  wantMac.push({ type, keyShare: kem[0].keyShare, header })
}
out.wantMac = wantMac

// STAR: a repo archive (getRepo) and a space meta archive (exportSpaceMeta)
const star = []
for (const [ctx, recs] of [
  [{ space: 'at://did:plc:x/space/com.example.group/self', repo: 'did:plc:x', rev: '3kbcq3p7ad401' }, []],
  [
    { space: 'at://did:example:space/space/app.bsky.group/test', repo: 'did:example:alice', rev: '3kbcq3p7ad400' },
    [
      ['app.bsky.feed.post', '1', { $type: 'app.bsky.feed.post', text: 'one', createdAt: '2026-11-07T00:00:00.000Z' }],
      ['app.bsky.feed.post', '2', { $type: 'app.bsky.feed.post', text: 'two', createdAt: '2026-11-07T00:00:01.000Z' }],
      ['com.example.note', 'a', { $type: 'com.example.note', body: 'é ☃' }],
    ],
  ],
]) {
  const records = []
  const repo = new RepoCommit()
  for (const [c, r, v] of recs) {
    const s = await serializeRecord(c, r, v)
    repo.add(c, r, s.cid)
    records.push({ ...s, value: v })
  }
  const commit = repo.toCommit(ctx)
  const bytes = await concat(serializeRepo(commit, records))
  star.push({
    profile: 'atproto-space-repo',
    ctx,
    data: hex(commit.data),
    records: records.map((r) => ({ path: `${r.collection}/${r.rkey}`, cid: r.cid.toString(), bytes: hex(r.bytes) })),
    star: hex(bytes),
  })
}
const metaSpace = 'at://did:plc:x/space/com.example.group/self'
const metaBytes = await concat(
  serializeSpaceMeta({
    space: metaSpace,
    policy: { $type: 'com.atproto.memberspace.policy', publicRead: false, publicWrite: false, publishPolicy: false, publishMembers: false },
    policyState: [
      { key: 'com.atproto.memberspace.member/did:plc:b', value: { $type: 'com.atproto.memberspace.member', read: true, write: false } },
      { key: 'com.atproto.memberspace.member/did:plc:a', value: { $type: 'com.atproto.memberspace.member', read: true, write: true } },
    ],
    writers: [{ did: 'did:plc:a', rev: '3kbcq3p7ad422', data: await seed('writer a'), spaceRev: '3kbcq3p7ad432' }],
  }),
)
const metaBack = await readSpaceMetaStar([metaBytes])
if (metaBack.writers.length !== 1 || metaBack.policyState.length !== 2) throw new Error('space meta vector does not read back')
star.push({ profile: 'atproto-space-meta', space: metaSpace, star: hex(metaBytes) })
out.star = star

// HTTP message signatures (P-256 did:key)
const sigKey = await P256Keypair.import(await seed('vlpds spaces alpha http sig p256'))
const httpsig = []
for (const [authorization, audience] of [
  ['Atproto-Space-Credential credential', 'did:example:repo'],
  ['Atproto-Space-Credential eyJhbGciOiJFUzI1NksifQ.e30.c2ln', 'did:plc:ewvi7nxzyoun6zhxrhs64oiz'],
  ['atproto-space-credential lowercase', 'did:web:example.com'],
]) {
  const headers = await createSpaceSigHeaders(sigKey, { authorization, audience })
  await verifyCredentialSig(headers, sigKey.did())
  httpsig.push({ keyDid: sigKey.did(), headers })
}
out.httpsig = httpsig

// Tokens: ES256K issuers (PDS account keys), and one ES256 credential
const user = await Secp256k1Keypair.import(await seed('vlpds spaces alpha user k256'))
const authority = await Secp256k1Keypair.import(await seed('vlpds spaces alpha authority k256'))
const authorityP256 = await P256Keypair.import(await seed('vlpds spaces alpha authority p256'))
const SPACE = 'at://did:example:space/space/app.bsky.group/test'
const tokens = []
const mk = async (type, opts, kp, verifyOpts) => {
  const jwt = await createSpaceToken(type, opts, kp)
  await verifySpaceToken(type, jwt, { getSigningKey: () => kp.did(), ...verifyOpts })
  tokens.push({ type, jwt, signingKey: kp.did(), opts })
}
await mk('delegation', { iss: 'did:example:alice', sub: SPACE, aud: 'did:example:space#atproto_pds' }, user, {
  aud: 'did:example:space#atproto_pds',
  sub: SPACE,
})
await mk('credential', { iss: 'did:example:space', sub: SPACE, keyId: sigKey.did() }, authority, { sub: SPACE })
await mk('credential', { iss: 'did:example:space', sub: SPACE, keyId: sigKey.did(), expiresInSec: 3600 }, authority, {})
await mk('credential', { iss: 'did:example:space', sub: SPACE, keyId: sigKey.did() }, authorityP256, {})
out.tokens = tokens

console.log(JSON.stringify(out, null, 1))
