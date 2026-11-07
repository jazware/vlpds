// A one-off Spaces smoke test against a real vlpds (production), as one test
// account: OAuth sign-in with a bare boards grant (the space type resolves
// through real lexicon DNS), a space and a record with a sentinel, a credential
// read with MACs, a verified getRepo (STAR), a leak check on the public firehose and
// repo, then cleanup. Reads the account from ~/.config/vlpds-test-account
// (handle=, password=) and never prints the password.
//
//   node prod-smoke.mjs https://pds.example.com
import { readFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { randomBytes } from 'node:crypto'
import { P256Keypair } from '@atproto/crypto'
import { COMMIT_MAC_TYPE, MAC_HEADER, RECORD_MAC_TYPE, WANT_MAC_HEADER, createSpaceSigHeaders, encapsulate, formatWantMacHeader, parseMacHeader, verifyCommit, verifyRecord, verifyRepoStarFull } from '@atproto/space'
import { oauthLogin } from './lib/oauth.mjs'
import { makeClient, rawXrpc } from './lib/http.mjs'

const BASE = process.argv[2] ?? 'https://pds.example.com'
const TYPE = 'dev.example.boards.board'
const POST = 'dev.example.boards.post'
const acct = Object.fromEntries(
  readFileSync(`${homedir()}/.config/vlpds-test-account`, 'utf8')
    .split('\n')
    .filter((l) => l.includes('='))
    .map((l) => [l.slice(0, l.indexOf('=')), l.slice(l.indexOf('=') + 1).trim()]),
)
const run = randomBytes(4).toString('hex')
const SENTINEL = `prodsmoke${run}`
const results = []
const check = (ok, what, detail = '') => {
  results.push({ ok, what, detail })
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${what}${detail && !ok ? `: ${detail}` : ''}`)
}

async function plcDoc(did) {
  const r = await fetch(`https://plc.directory/${did}`)
  if (!r.ok) throw new Error(`plc ${did}: ${r.status}`)
  return r.json()
}
const service = (doc, id, type) => doc.service?.find((s) => s.id === id || s.type === type)?.serviceEndpoint
async function kemKey(did) {
  const doc = await plcDoc(did)
  const vm = doc.verificationMethod?.find((m) => m.id.endsWith('#atproto_kem'))
  if (!vm) throw new Error(`${did} publishes no #atproto_kem key`)
  return `did:key:${vm.publicKeyMultibase}`
}

// SMOKE_DID wins over the file's handle (the handle may have moved since)
const did =
  process.env.SMOKE_DID ??
  (await fetch(`${BASE}/xrpc/com.atproto.identity.resolveHandle?handle=${acct.handle}`).then((r) => r.json())).did
acct.handle = (await plcDoc(did)).alsoKnownAs?.[0]?.replace('at://', '') ?? acct.handle
const desc = await fetch(`${BASE}/xrpc/com.atproto.server.describeServer`).then((r) => r.json())
check(desc?.vlpds?.spaces === true, 'describeServer says Spaces runs here', JSON.stringify(desc?.vlpds))

// public firehose tap, live from now
const ws = new WebSocket(`${BASE.replace(/^http/, 'ws')}/xrpc/com.atproto.sync.subscribeRepos`)
ws.binaryType = 'arraybuffer'
let frames = 0
const hits = []
ws.onmessage = (ev) => {
  frames++
  if (Buffer.from(ev.data).includes(SENTINEL)) hits.push(frames)
}
await new Promise((r) => (ws.onopen = r))

const scope = `atproto space:${TYPE}?authority=*&action=read&action=create&action=update&action=delete&manage=create&manage=update&manage=delete`
const session = await oauthLogin(BASE, { handle: acct.handle, did, password: acct.password, scope })
check(/space:/.test(session.scope), 'OAuth granted a space: scope (bare grant resolved via _lexicon DNS)', session.scope)
const me = makeClient(BASE, session.signer())

const skey = `smoke${run}`
let space
try {
  const cs = await me.com.atproto.space.createSpace({ spaceType: TYPE, skey, policy: { $type: 'com.atproto.memberspace.policy' } })
  space = cs.data.uri
  check(space === `at://${did}/space/${TYPE}/${skey}`, 'createSpace', space)

  const t0 = performance.now()
  const w = await me.com.atproto.space.createRecord({
    space,
    repo: did,
    collection: POST,
    record: { $type: POST, title: `smoke ${SENTINEL}`, body: `private ${SENTINEL}`, createdAt: new Date().toISOString() },
  })
  const writeMs = performance.now() - t0
  check(!!w.data.cid, `space createRecord (${writeMs.toFixed(0)} ms)`)
  const rkey = w.data.uri.split('/').pop()

  const self = await me.com.atproto.space.listRecords({ space, repo: did, collection: POST })
  check(self.data.records.length === 1, 'listRecords of my own space repo')

  // the credential chain: delegation token here, credential at the authority (also here)
  const dt = await me.com.atproto.space.getDelegationToken({ space })
  const key = await P256Keypair.create()
  const host = service(await plcDoc(did), '#atproto_pds', 'AtprotoPersonalDataServer') ?? BASE
  const ex = makeClient(host)
  const cred = (await ex.com.atproto.space.getSpaceCredential({ space, credentialKid: key.did(), delegationToken: dt.data.token })).data.credential
  check(!!cred, 'delegation token → space credential')
  const credHeaders = await createSpaceSigHeaders(key, { authorization: `Atproto-Space-Credential ${cred}`, audience: did })
  const reader = makeClient(BASE, ({ headers }) => {
    for (const [k, v] of Object.entries(credHeaders)) headers.set(k, v)
  })
  const kem = await kemKey(did)
  // each MAC-bearing read gets its own key share
  const withMac = async (type) => {
    const { keyShare, sharedSecret } = await encapsulate(kem)
    return { sharedSecret, opts: { headers: { [WANT_MAC_HEADER]: formatWantMacHeader(type, keyShare) } } }
  }
  const macOf = (res, type) => parseMacHeader(res.headers[MAC_HEADER], type)
  let m = await withMac(RECORD_MAC_TYPE)
  const got = await reader.com.atproto.space.getRecord({ space, repo: did, collection: POST, rkey }, m.opts)
  check(got.data.value?.body === `private ${SENTINEL}`, 'getRecord with the credential')
  check(await verifyRecord({ uri: got.data.uri, cid: String(got.data.cid), value: got.data.value }, { uri: w.data.uri, sharedSecret: m.sharedSecret, mac: macOf(got, RECORD_MAC_TYPE) }), "and its record MAC verifies against the account's #atproto_kem key")
  m = await withMac(COMMIT_MAC_TYPE)
  const ops = await reader.com.atproto.space.listRepoOps({ space, repo: did }, m.opts)
  check((ops.data.ops ?? []).length >= 1, 'listRepoOps with the credential')
  check(verifyCommit(ops.data.commit, { space, repo: did, sharedSecret: m.sharedSecret, mac: macOf(ops, COMMIT_MAC_TYPE) }), "and its commit's MAC verifies")
  m = await withMac(COMMIT_MAC_TYPE)
  const star = await reader.com.atproto.space.getRepo({ space, repo: did }, m.opts)
  const v = await verifyRepoStarFull([star.data], { space, repo: did, sharedSecret: m.sharedSecret, mac: macOf(star, COMMIT_MAC_TYPE) })
  check(v.records.length === 1, 'getRepo STAR verifies (MAC and digest)', v.records.length)

  // leaks: public repo and firehose
  await new Promise((r) => setTimeout(r, 3000))
  const pub = await rawXrpc(BASE, 'com.atproto.sync.getRepo', { params: { did } })
  check(pub.ok && !Buffer.from(pub.bytes).includes(SENTINEL), 'public sync.getRepo has no space data')
  check(hits.length === 0, `public firehose has no space data (${frames} frames watched)`, `hits at ${hits.join(',')}`)

  await me.com.atproto.space.deleteRecord({ space, repo: did, collection: POST, rkey })
  check(true, 'deleteRecord')
} catch (e) {
  check(false, 'smoke step threw', String(e?.message ?? e))
} finally {
  if (space) {
    try {
      await me.com.atproto.space.deleteSpace({ space })
      check(true, 'deleteSpace (cleanup)')
    } catch (e) {
      check(false, 'deleteSpace (cleanup)', String(e?.message ?? e))
    }
  }
  ws.close()
}
const failed = results.filter((r) => !r.ok).length
console.log(`\n${results.length - failed}/${results.length} passed`)
process.exit(failed ? 1 : 0)
