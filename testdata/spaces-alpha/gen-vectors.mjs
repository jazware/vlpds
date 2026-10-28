// Generates vectors.json from the reference implementation (@atproto/space).
// Run in a directory with the release in SOURCE installed:
//   npm install --save-exact @atproto/space@<version> @atproto/crypto@<version> \
//     @atproto/lex-data@<version> @atproto/lex-cbor@<version>
//   node gen-vectors.mjs > vectors.json
// Keys are fixed and both curves sign with RFC 6979, so the output is
// deterministic; Date.now is pinned for the tokens (jti stays random).
import { P256Keypair, Secp256k1Keypair, sha256 } from '@atproto/crypto'
import { encode } from '@atproto/lex-cbor'
import { parseCid } from '@atproto/lex-data'
import {
  COMMIT_MAC_TYPE,
  LtHash,
  RECORD_MAC_TYPE,
  REPO_STAR_TYPE,
  RepoCommit,
  computeCommitMac,
  computeRecordMac,
  createSpaceSigHeaders,
  createSpaceToken,
  decapsulate,
  encapsulate,
  formatMacHeader,
  formatSetHashElement,
  formatWantMacHeader,
  serializeRecord,
  serializeRepo,
  verifyCommit,
  verifyCredentialSig,
  verifyRepoStarFull,
  verifySpaceToken,
} from '@atproto/space'

const hex = (b) => Buffer.from(b).toString('hex')
const seed = async (label) => sha256(new TextEncoder().encode(label))
const p256 = async (label) => P256Keypair.import(await seed(label), { exportable: true })

const NOW_SEC = 1790000000
Date.now = () => NOW_SEC * 1000

const out = { now: NOW_SEC }

// LtHash (unchanged since the October 1 release)
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

// Commits: element, toCommit, the commit's DRISL and its STAR metadata
const CID_A = parseCid('bafyreidefdycgbfy3oglcb6ism3eqhyp5llsrpzxjsuac2gsy4mtrtx244')
const CID_B = parseCid('bafyreidpw4cbv6gr4ukh33z23pvvrpr3wi4gnpmi4doamlsl3sa4rgri2a')
const commits = []
const commitObjs = []
for (const [ctx, records] of [
  [
    { space: 'at://did:example:space/space/app.bsky.group/test', repo: 'did:example:alice', rev: '3kbcq3p7ad400' },
    [['app.bsky.feed.post', '1', CID_A]],
  ],
  [
    { space: 'at://did:plc:asdf123/space/com.example.group/default', repo: 'did:plc:user1', rev: '3lzzzzzzzzz22' },
    [['n.c.a', '1', CID_A], ['n.c.b', '2', CID_B]],
  ],
  [{ space: 'at://did:plc:x/space/com.example.group/self', repo: 'did:plc:x', rev: '3kbcq3p7ad401' }, []],
]) {
  const repo = new RepoCommit()
  for (const [c, r, cid] of records) repo.add(c, r, cid)
  const commit = repo.toCommit(ctx)
  commitObjs.push(commit)
  commits.push({
    ...ctx,
    records: records.map(([c, r, cid]) => ({ collection: c, rkey: r, cid: cid.toString(), element: formatSetHashElement(c, r, cid) })),
    data: hex(commit.data),
    cbor: hex(encode(commit)),
    starMeta: hex(encode({ $type: REPO_STAR_TYPE, ...commit })),
  })
}
out.commits = commits

// KEM: the reference's decapsulate with fixed keys on both sides
const kem = []
for (const [a, s] of [
  ['vlpds spaces alpha kem author 1', 'vlpds spaces alpha kem syncer 1'],
  ['vlpds spaces alpha kem author 2', 'vlpds spaces alpha kem syncer 2'],
]) {
  const author = await p256(a)
  const syncer = await p256(s)
  const sharedSecret = decapsulate(author, syncer.did())
  // and the syncer's side agrees, with a fresh key
  const enc = await encapsulate(author.did())
  if (hex(decapsulate(author, enc.keyShare)) !== hex(enc.sharedSecret)) throw new Error('kem round trip')
  kem.push({
    authorPrivate: hex(await author.export()),
    authorKem: author.did(),
    syncerPrivate: hex(await syncer.export()),
    keyShare: syncer.did(),
    sharedSecret: hex(sharedSecret),
  })
}
out.kem = kem

// MACs and their headers
const macs = { commits: [], records: [], wantMac: [] }
for (const [i, commit] of commitObjs.entries()) {
  const secret = await seed(`vlpds spaces alpha mac secret ${i}`)
  const mac = computeCommitMac(secret, commit)
  if (!verifyCommit(commit, { space: commit.space, repo: commit.repo, sharedSecret: secret, mac })) {
    throw new Error('commit mac does not verify')
  }
  macs.commits.push({
    secret: hex(secret),
    commit: { ...commit, data: hex(commit.data) },
    mac: hex(mac),
    header: formatMacHeader(COMMIT_MAC_TYPE, mac),
  })
}
for (const [uri, cid] of [
  ['at://did:example:space/space/app.bsky.group/test/did:example:alice/app.bsky.feed.post/1', CID_A],
  ['at://did:plc:asdf123/space/com.example.group/default/did:plc:user1/n.c.b/2', CID_B],
]) {
  const secret = await seed(`vlpds spaces alpha record secret ${uri}`)
  const mac = computeRecordMac(secret, uri, cid)
  macs.records.push({ secret: hex(secret), uri, cid: cid.toString(), mac: hex(mac), header: formatMacHeader(RECORD_MAC_TYPE, mac) })
}
for (const type of [COMMIT_MAC_TYPE, RECORD_MAC_TYPE]) {
  const keyShare = kem[0].keyShare
  macs.wantMac.push({ type, keyShare, header: formatWantMacHeader(type, keyShare) })
}
out.macs = macs

// HTTP message signatures (P-256 did:key)
const sigKey = await P256Keypair.import(await seed('vlpds spaces alpha http sig p256'))
const httpsig = []
for (const [credential, audience] of [
  ['credential', 'did:example:repo'],
  ['eyJhbGciOiJFUzI1NksifQ.e30.c2ln', 'did:plc:ewvi7nxzyoun6zhxrhs64oiz'],
]) {
  const authorization = `Atproto-Space-Credential ${credential}`
  const headers = await createSpaceSigHeaders(sigKey, { authorization, audience })
  await verifyCredentialSig(headers, sigKey.did())
  const base = [
    `"authorization": ${authorization}`,
    `"atproto-space-audience": ${audience}`,
    `"@signature-params": ("authorization" "atproto-space-audience");tag="atproto-space-credential"`,
  ].join('\n')
  httpsig.push({ keyDid: sigKey.did(), headers, base })
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

// STAR: serializeRepo's archives, read back by verifyRepoStarFull
const star = []
for (const [ctx, records] of [
  [
    { space: 'at://did:example:space/space/app.bsky.group/test', repo: 'did:example:alice', rev: '3kbcq3p7ad400' },
    [
      ['app.bsky.feed.post', '1', { $type: 'app.bsky.feed.post', text: 'one', createdAt: '2026-10-22T00:00:00.000Z' }],
      ['app.bsky.feed.post', '2', { $type: 'app.bsky.feed.post', text: 'two', createdAt: '2026-10-22T00:00:01.000Z' }],
      ['app.bsky.feed.like', '3kbcq3p7ad400', { $type: 'app.bsky.feed.like', n: 1 }],
    ],
  ],
  [{ space: 'at://did:plc:x/space/com.example.group/self', repo: 'did:plc:x', rev: '3kbcq3p7ad401' }, []],
]) {
  const serialized = []
  const repo = new RepoCommit()
  for (const [c, r, v] of records) {
    const s = await serializeRecord(c, r, v)
    repo.add(c, r, s.cid)
    serialized.push(s)
  }
  serialized.sort((a, b) => Buffer.compare(Buffer.from(`${a.collection}/${a.rkey}`), Buffer.from(`${b.collection}/${b.rkey}`)))
  const commit = repo.toCommit(ctx)
  const chunks = []
  for await (const c of serializeRepo(commit, serialized)) chunks.push(c)
  const bytes = Buffer.concat(chunks)
  const secret = await seed(`vlpds spaces alpha star ${ctx.rev}`)
  const mac = computeCommitMac(secret, commit)
  const got = await verifyRepoStarFull([bytes], { space: ctx.space, repo: ctx.repo, sharedSecret: secret, mac })
  if (got.records.length !== records.length) throw new Error('star round trip')
  star.push({ commit: { ...commit, data: { $bytes: Buffer.from(commit.data).toString('base64').replace(/=+$/, '') } }, records: records.length, archive: hex(bytes) })
}
out.star = star

console.log(JSON.stringify(out, null, 1))
